package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// Input validation tests — no DB required
// ---------------------------------------------------------------------------

func TestProvisionTenantCAHandler_UUIDValidation(t *testing.T) {
	h := ProvisionTenantCAHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/bad-id/ca", nil)
	req = withChiParam(req, "tenantID", "bad-id")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
}

func TestMintBootstrapTokenHandler_UUIDValidation(t *testing.T) {
	h := MintBootstrapTokenHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/bad-id/bootstrap-tokens", nil)
	req = withChiParam(req, "tenantID", "bad-id")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
}

func TestEnrolHandler_MissingToken(t *testing.T) {
	h := EnrolHandler(nil, nil)
	// Neither enrollment_token nor bootstrap_token supplied.
	body, _ := json.Marshal(map[string]any{
		"device_id": "00000000-0000-0000-0000-000000000001",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "enrollment_token required") {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

func TestEnrolHandler_DeviceIDValidation(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
	}{
		// New flat format: missing device_id
		{
			"new format: missing device_id",
			map[string]any{"enrollment_token": "tok"},
		},
		// New flat format: invalid device_id
		{
			"new format: invalid device_id",
			map[string]any{"enrollment_token": "tok", "device_id": "not-a-uuid"},
		},
		// Legacy format: missing hw_uuid
		{
			"legacy: missing hw_uuid",
			map[string]any{"bootstrap_token": "tok", "device": map[string]string{"os": "macos"}},
		},
		// Legacy format: invalid hw_uuid
		{
			"legacy: invalid hw_uuid",
			map[string]any{"bootstrap_token": "tok", "device": map[string]string{"hw_uuid": "not-a-uuid", "os": "macos"}},
		},
		// Legacy format: invalid os (os is validated only when provided)
		{
			"legacy: invalid os",
			map[string]any{"bootstrap_token": "tok", "device": map[string]string{"hw_uuid": "00000000-0000-0000-0000-000000000001", "os": "linux"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := EnrolHandler(nil, nil)
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: got %d, want 400", tc.name, rr.Code)
			}
		})
	}
}

// TestEnrolHandler_NewFlatFormatPassesValidation confirms the PAT-548 format
// reaches the DB step (nil pool panics, meaning validation passed).
func TestEnrolHandler_NewFlatFormatPassesValidation(t *testing.T) {
	h := EnrolHandler(nil, nil)
	body, _ := json.Marshal(map[string]any{
		"enrollment_token": "sometoken",
		"device_id":        "00000000-0000-0000-0000-000000000001",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	// Expect a panic from nil pool — that means we passed validation.
	defer func() {
		if r := recover(); r == nil {
			// No panic: handler returned early with a non-5xx — still OK if 4xx.
			if rr.Code >= 500 || rr.Code == 0 {
				t.Errorf("unexpected status %d without nil-pool panic", rr.Code)
			}
		}
	}()
	h.ServeHTTP(rr, req)
}

// TestEnrolHandler_LegacyFormatOSOptional confirms that omitting device.os
// is allowed in the new format (device_id flat) but invalid os is still rejected.
func TestEnrolHandler_LegacyFormatOSOptional(t *testing.T) {
	h := EnrolHandler(nil, nil)
	// New flat format with no os — should pass validation (panic from nil pool).
	body, _ := json.Marshal(map[string]any{
		"enrollment_token": "sometoken",
		"device_id":        "00000000-0000-0000-0000-000000000001",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	defer func() {
		if r := recover(); r == nil && rr.Code == http.StatusBadRequest {
			t.Errorf("missing os should not be a 400 for flat format")
		}
	}()
	h.ServeHTTP(rr, req)
}

func TestEnrolHandler_InvalidJSON(t *testing.T) {
	h := EnrolHandler(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Crypto tests — no DB required
// ---------------------------------------------------------------------------

func TestGenerateCAKeyPair_Valid(t *testing.T) {
	certPEM, keyPEM, err := generateCAKeyPair("00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("generateCAKeyPair: %v", err)
	}
	if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("certPEM missing CERTIFICATE block")
	}
	if !strings.Contains(keyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Error("keyPEM missing PRIVATE KEY block")
	}
}

func TestIssueDeviceCert_Valid(t *testing.T) {
	caCertPEM, caKeyPEM, err := generateCAKeyPair("00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("generateCAKeyPair: %v", err)
	}

	tenantID := "00000000-0000-0000-0000-000000000001"
	deviceID := "00000000-0000-0000-0000-000000000002"
	certPEM, keyPEM, serial, notAfter, err := issueDeviceCert(caCertPEM, caKeyPEM, tenantID, deviceID)
	if err != nil {
		t.Fatalf("issueDeviceCert: %v", err)
	}

	if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("certPEM missing CERTIFICATE block")
	}
	if !strings.Contains(keyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Error("keyPEM missing PRIVATE KEY block")
	}
	if serial == 0 {
		t.Error("serial is zero")
	}
	if notAfter.IsZero() {
		t.Error("notAfter is zero")
	}
}

func TestIssueDeviceCert_BadCACert(t *testing.T) {
	_, _, _, _, err := issueDeviceCert("not-pem", "not-pem", "tid", "did")
	if err == nil {
		t.Error("expected error for bad CA cert PEM")
	}
}

// ---------------------------------------------------------------------------
// PAT-836: invalidate-on-regenerate, scoped to delivery_path. DB round-trip
// tests — skipped when TEST_DATABASE_URL is not set, mirroring the pattern in
// enrolment_concurrency_test.go / portal_enrolment_test.go.
// ---------------------------------------------------------------------------

// mkSupersedeTestTenant creates a bare tenant for these tests and registers
// cleanup of everything the tests below can write for it.
func mkSupersedeTestTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text`, name).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM enrollment_token_audit WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})
	return tenantID
}

// doEnrolRequest POSTs a plaintext enrolment token + device_id to a real
// EnrolHandler and returns the recorded response.
func doEnrolRequest(t *testing.T, h http.HandlerFunc, token, deviceID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"enrollment_token": token,
		"device_id":        deviceID,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// superseded_at reads bootstrap_tokens.superseded_at for a given token ID —
// used to assert the column is actually set (or not) by mintTenantEnrolmentToken.
func supersededAtFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tokenID string) *time.Time {
	t.Helper()
	var supersededAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT superseded_at FROM bootstrap_tokens WHERE id = $1::uuid`, tokenID,
	).Scan(&supersededAt); err != nil {
		t.Fatalf("query superseded_at for %s: %v", tokenID, err)
	}
	return supersededAt
}

// TestMintTenantEnrolmentToken_EmailLinkSupersedesPriorEmailLink proves the
// core PAT-836 behaviour: minting a second email-link token for a tenant
// supersedes the first. The old token's plaintext must fail POST /v1/enrol
// with the new, distinct "superseded" error/status — not be silently treated
// as generic-invalid — and bootstrap_tokens.superseded_at must actually be
// set on the old row (and NOT on the new one).
func TestMintTenantEnrolmentToken_EmailLinkSupersedesPriorEmailLink(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-836 email-link supersede DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat836-email-link-supersede")

	first, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "email-link", "")
	if err != nil {
		t.Fatalf("mint first email-link token: %v", err)
	}
	second, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "email-link", "")
	if err != nil {
		t.Fatalf("mint second email-link token: %v", err)
	}

	if got := supersededAtFor(t, ctx, pool, first.TokenID); got == nil {
		t.Fatal("expected first (older) email-link token's superseded_at to be set, got NULL")
	}
	if got := supersededAtFor(t, ctx, pool, second.TokenID); got != nil {
		t.Fatalf("expected second (newest) email-link token's superseded_at to be NULL, got %v", *got)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := EnrolHandler(pool, rl)

	rr := doEnrolRequest(t, h, first.PlaintextToken, deviceUUID(8360))
	if rr.Code != http.StatusGone {
		t.Fatalf("superseded token enrol = %d, want 410: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "superseded") {
		t.Fatalf("superseded token enrol body = %q, want it to mention 'superseded'", rr.Body.String())
	}

	rr2 := doEnrolRequest(t, h, second.PlaintextToken, deviceUUID(8361))
	if rr2.Code != http.StatusOK {
		t.Fatalf("newest email-link token enrol = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
}

// TestMintTenantEnrolmentToken_MDMDoesNotSupersedeOutstandingMDM proves the
// other half of the decided scope: minting a second mdm token for a tenant
// must NOT affect a still-outstanding, previously-minted mdm token — both
// must remain independently redeemable, since fleet enrolment legitimately
// needs N outstanding tokens for N devices enrolling concurrently.
func TestMintTenantEnrolmentToken_MDMDoesNotSupersedeOutstandingMDM(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-836 mdm non-supersede DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat836-mdm-no-supersede")

	first, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint first mdm token: %v", err)
	}
	second, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint second mdm token: %v", err)
	}

	if got := supersededAtFor(t, ctx, pool, first.TokenID); got != nil {
		t.Fatalf("first mdm token superseded_at = %v, want NULL (mdm mint must never supersede)", *got)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := EnrolHandler(pool, rl)

	rr1 := doEnrolRequest(t, h, first.PlaintextToken, deviceUUID(8370))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first mdm token enrol = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}
	rr2 := doEnrolRequest(t, h, second.PlaintextToken, deviceUUID(8371))
	if rr2.Code != http.StatusOK {
		t.Fatalf("second mdm token enrol = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
}

// TestMintTenantEnrolmentToken_CrossPathIndependence proves minting on one
// delivery_path never supersedes an outstanding token on the OTHER path, in
// both directions — the two paths are fully independent.
func TestMintTenantEnrolmentToken_CrossPathIndependence(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-836 cross-path independence DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat836-cross-path")

	mdmTok, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint mdm token: %v", err)
	}
	emailTok, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "email-link", "")
	if err != nil {
		t.Fatalf("mint email-link token: %v", err)
	}
	if got := supersededAtFor(t, ctx, pool, mdmTok.TokenID); got != nil {
		t.Fatalf("mdm token superseded_at = %v, want NULL (an email-link mint must not touch mdm tokens)", *got)
	}

	if _, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", ""); err != nil {
		t.Fatalf("mint second mdm token: %v", err)
	}
	if got := supersededAtFor(t, ctx, pool, emailTok.TokenID); got != nil {
		t.Fatalf("email-link token superseded_at = %v, want NULL (an mdm mint must not touch email-link tokens)", *got)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := EnrolHandler(pool, rl)

	rr1 := doEnrolRequest(t, h, mdmTok.PlaintextToken, deviceUUID(8380))
	if rr1.Code != http.StatusOK {
		t.Fatalf("mdm token enrol = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}
	rr2 := doEnrolRequest(t, h, emailTok.PlaintextToken, deviceUUID(8381))
	if rr2.Code != http.StatusOK {
		t.Fatalf("email-link token enrol = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
}

// ---------------------------------------------------------------------------
// PAT-1757: refuse to mint or enrol for a tenant carrying an active
// (non-"none") decommission directive — reusing a decommissioned tenant, or
// re-enrolling a device into one, must not silently let the new agent
// receive the directive on its first config poll and self-uninstall with
// purge. DB round-trip tests — skipped when TEST_DATABASE_URL is not set, same
// convention as the PAT-836 tests above.
// ---------------------------------------------------------------------------

// setTenantDecommissionMode inserts (or replaces) the tenant_decommission row
// for tenantID directly, mirroring the raw-SQL pattern
// agent_decommission_test.go uses (e.g.
// TestLockTenantAndReadDecommissionState_SerializesConcurrentWrites) rather
// than going through TenantDecommissionPutHandler — these tests only care
// about the stored mode, not the PUT handler's own audit/versioning
// behaviour.
func setTenantDecommissionMode(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, mode string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_decommission (tenant_id, mode, purge, set_by, directive_version)
		VALUES ($1::uuid, $2, true, 'pat1757-test', 1)
		ON CONFLICT (tenant_id) DO UPDATE SET
			mode = EXCLUDED.mode, purge = EXCLUDED.purge,
			set_by = EXCLUDED.set_by, directive_version = EXCLUDED.directive_version
	`, tenantID, mode); err != nil {
		t.Fatalf("set tenant_decommission mode=%q: %v", mode, err)
	}
}

func TestMintBootstrapTokenHandler_RejectsDecommissionedTenant(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-1757 mint decommission-gate DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat1757-mint-decommissioned")
	setTenantDecommissionMode(t, ctx, pool, tenantID, "immediate")

	h := MintBootstrapTokenHandler(pool)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/bootstrap-tokens", nil)
	req = withChiParam(req, "tenantID", tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("mint for decommissioned tenant = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "immediate") {
		t.Fatalf("409 body = %q, want it to name the mode %q", rr.Body.String(), "immediate")
	}
}

func TestMintBootstrapTokenHandler_ModeNoneStillSucceeds(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-1757 mint decommission-gate DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat1757-mint-mode-none")
	setTenantDecommissionMode(t, ctx, pool, tenantID, "none")

	h := MintBootstrapTokenHandler(pool)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/bootstrap-tokens", nil)
	req = withChiParam(req, "tenantID", tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("mint for mode=none tenant = %d, want 201: %s", rr.Code, rr.Body.String())
	}
}

func TestEnrolHandler_RejectsDecommissionedTenant(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-1757 enrol decommission-gate DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat1757-enrol-decommissioned")

	// Mint while the tenant is still clean, then decommission it — the
	// scenario the ticket describes: a bootstrap token minted before the
	// directive was set must stay unconsumed and unusable once it is.
	tok, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	setTenantDecommissionMode(t, ctx, pool, tenantID, "immediate")

	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := EnrolHandler(pool, rl)
	rr := doEnrolRequest(t, h, tok.PlaintextToken, deviceUUID(8390))

	if rr.Code != http.StatusConflict {
		t.Fatalf("enrol into decommissioned tenant = %d, want 409: %s", rr.Code, rr.Body.String())
	}

	var consumedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT consumed_at FROM bootstrap_tokens WHERE id = $1::uuid`, tok.TokenID).Scan(&consumedAt); err != nil {
		t.Fatalf("query consumed_at: %v", err)
	}
	if consumedAt != nil {
		t.Fatalf("token consumed_at = %v, want NULL — a rejected enrol must leave the token unconsumed", *consumedAt)
	}

	var credCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID).Scan(&credCount); err != nil {
		t.Fatalf("count tenant_credentials: %v", err)
	}
	if credCount != 0 {
		t.Fatalf("tenant_credentials rows for decommissioned tenant = %d, want 0", credCount)
	}

	var deviceCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if deviceCount != 0 {
		t.Fatalf("devices rows for decommissioned tenant = %d, want 0", deviceCount)
	}
}

func TestEnrolHandler_NormalTenantUnaffectedByDecommissionGuard(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-1757 enrol decommission-gate DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat1757-enrol-normal")

	tok, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := EnrolHandler(pool, rl)
	rr := doEnrolRequest(t, h, tok.PlaintextToken, deviceUUID(8391))

	if rr.Code != http.StatusOK {
		t.Fatalf("enrol into normal tenant = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}
