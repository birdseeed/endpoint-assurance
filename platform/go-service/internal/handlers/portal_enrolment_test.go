package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// Input validation — no DB required. Every rejection below fires BEFORE any
// DB access (pool is nil; a query would panic), proving the handler fails
// closed on bad input without ever reaching mintTenantEnrolmentToken.
// ---------------------------------------------------------------------------

func portalEnrolPost(t *testing.T, tenantID, email, body string, rl *ratelimit.TenantLimiter) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/portal/enrolment", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if tenantID != "" || email != "" {
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
			Email:    email,
			TenantID: tenantID,
		}))
	}
	rr := httptest.NewRecorder()
	PortalEnrolmentGenerateHandler(nil, rl).ServeHTTP(rr, req)
	return rr
}

func TestPortalEnrolmentGenerateHandler_NoIdentityFailsClosed401(t *testing.T) {
	rr := portalEnrolPost(t, "", "", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (fail closed without identity)", rr.Code)
	}
}

func TestPortalEnrolmentGenerateHandler_InvalidJSON400(t *testing.T) {
	rr := portalEnrolPost(t, "5f9c1a2b-0000-0000-0000-000000000001", "customer@example.com", "not json", nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestPortalEnrolmentGenerateHandler_RejectsTenantIDInBody is the IDOR proof:
// a body that tries to smuggle a different tenant_id is rejected outright by
// DisallowUnknownFields — it never reaches the point of being read, let
// alone honoured. pool stays nil throughout, proving no DB call was made.
func TestPortalEnrolmentGenerateHandler_RejectsTenantIDInBody(t *testing.T) {
	rr := portalEnrolPost(t, "5f9c1a2b-0000-0000-0000-000000000001", "customer@example.com",
		`{"tenant_id":"11111111-1111-1111-1111-111111111111"}`, nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (tenant_id in body must be rejected, never honoured)", rr.Code)
	}
}

func TestPortalEnrolmentGenerateHandler_InvalidDeliveryPath400(t *testing.T) {
	cases := []string{
		`{"delivery_path":"email-link"}`, // valid for the admin path, NOT the portal path
		`{"delivery_path":"carrier-pigeon"}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			rr := portalEnrolPost(t, "5f9c1a2b-0000-0000-0000-000000000001", "customer@example.com", body, nil)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("body %s: status = %d, want 400", body, rr.Code)
			}
		})
	}
}

// TestPortalEnrolmentGenerateHandler_EmptyDeliveryPathDefaultsToMDM confirms
// an explicit empty string (distinct from an absent field) still defaults to
// "mdm" and reaches the DB step, rather than being rejected as invalid.
func TestPortalEnrolmentGenerateHandler_EmptyDeliveryPathDefaultsToMDM(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected a nil-pool panic once validation passed")
		}
	}()
	portalEnrolPost(t, "5f9c1a2b-0000-0000-0000-000000000001", "customer@example.com",
		`{"delivery_path":""}`, nil)
}

func TestPortalEnrolmentGenerateHandler_EmptyBodyAcceptedAsDefaults(t *testing.T) {
	// An empty body must pass validation and reach the DB step (nil pool
	// panics there) — proving "{}"/"" defaults delivery_path to "mdm"
	// without requiring the client to send anything.
	for _, body := range []string{``, `{}`} {
		t.Run(body, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("body %q: expected a nil-pool panic once validation passed", body)
				}
			}()
			portalEnrolPost(t, "5f9c1a2b-0000-0000-0000-000000000001", "customer@example.com", body, nil)
		})
	}
}

// The dedicated per-tenant limiter used to be proved here against a nil pool
// ("rate limited before the DB"). PAT-2407 moved the admin role check, which
// reads the database, ahead of the limiter, the same order
// PortalEnrolmentKeyCreateHandler uses, so that proof is now DB-backed:
// TestPortalEnrolmentGenerateHandler_AdminRateLimitedWritesNothing below.

// ---------------------------------------------------------------------------
// DB round-trip — gated on TEST_DATABASE_URL, mirroring the existing pattern in
// enrolment_concurrency_test.go. Skipped locally when no Postgres is
// available; this stays at the package level rather than the integration-tag
// harness so it can call PortalEnrolmentGenerateHandler and EnrolHandler
// directly, in-process.
// ---------------------------------------------------------------------------

func TestPortalEnrolmentGenerateHandler_MintAndRedeemEndToEnd(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping portal enrolment DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('portal-enrol-e2e-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM enrollment_token_audit WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})

	// PAT-2407: only a portal admin may mint, so the caller is one.
	email := seedPortalUser(t, ctx, pool, tenantID, "admin")
	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := PortalEnrolmentGenerateHandler(pool, rl)

	req := httptest.NewRequest(http.MethodPost, "/v1/portal/enrolment", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
		Email: email, TenantID: tenantID,
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("mint = %d, want 201: %s", rr.Code, rr.Body.String())
	}

	var mintResp struct {
		EnrollmentToken string `json:"enrollment_token"`
		TenantID        string `json:"tenant_id"`
		TokenID         string `json:"token_id"`
		ExpiresAt       string `json:"expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &mintResp); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	if mintResp.TenantID != tenantID {
		t.Fatalf("tenant_id = %s, want %s (must come from the session, not the body)", mintResp.TenantID, tenantID)
	}
	if mintResp.EnrollmentToken == "" || mintResp.TokenID == "" || mintResp.ExpiresAt == "" {
		t.Fatalf("mint response missing fields: %+v", mintResp)
	}

	// Audit row records the portal caller's actor_email.
	var actorEmail *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_email FROM enrollment_token_audit WHERE token_id = $1::uuid`, mintResp.TokenID,
	).Scan(&actorEmail); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if actorEmail == nil || *actorEmail != email {
		t.Fatalf("audit actor_email = %v, want %s", actorEmail, email)
	}

	// The minted token redeems via the REAL /v1/enrol path and issues device
	// creds — reusing EnrolHandler directly (enrolment_concurrency_test.go's
	// same package, same helpers).
	enrolRL := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	enrolHandler := EnrolHandler(pool, enrolRL)

	enrolBody, _ := json.Marshal(map[string]any{
		"enrollment_token": mintResp.EnrollmentToken,
		"device_id":        deviceUUID(950),
	})
	ereq := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(enrolBody))
	ereq.Header.Set("Content-Type", "application/json")
	erec := httptest.NewRecorder()
	enrolHandler.ServeHTTP(erec, ereq)
	if erec.Code != http.StatusOK {
		t.Fatalf("redeem = %d, want 200: %s", erec.Code, erec.Body.String())
	}

	var enrolResp struct {
		TenantID    string `json:"tenant_id"`
		DeviceID    string `json:"device_id"`
		BearerToken string `json:"bearer_token"`
		HMACSecret  string `json:"hmac_secret"`
	}
	if err := json.Unmarshal(erec.Body.Bytes(), &enrolResp); err != nil {
		t.Fatalf("decode enrol response: %v", err)
	}
	if enrolResp.TenantID != tenantID || enrolResp.DeviceID == "" ||
		enrolResp.BearerToken == "" || enrolResp.HMACSecret == "" {
		t.Fatalf("enrol response = %+v, want fully-populated device creds for %s", enrolResp, tenantID)
	}

	// Single-use: the same token cannot be redeemed twice.
	ereq2 := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(enrolBody))
	ereq2.Header.Set("Content-Type", "application/json")
	erec2 := httptest.NewRecorder()
	enrolHandler.ServeHTTP(erec2, ereq2)
	if erec2.Code != http.StatusGone {
		t.Fatalf("second redeem = %d, want 410 (single-use)", erec2.Code)
	}
}

// TestPortalEnrolmentGenerateHandler_RejectsDecommissionedTenant is the
// PAT-1757 regression for the portal mint path: it shares
// mintTenantEnrolmentToken with the admin mint (MintBootstrapTokenHandler),
// so a caller's own tenant carrying an active decommission directive must be
// refused here too, with the same 409 shape (mode in the body).
func TestPortalEnrolmentGenerateHandler_RejectsDecommissionedTenant(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping portal enrolment DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat1757-portal-mint-decommissioned")
	setTenantDecommissionMode(t, ctx, pool, tenantID, "immediate")

	// PAT-2407: the role check runs first, so the caller must be an admin to
	// reach the decommission guard.
	email := seedPortalUser(t, ctx, pool, tenantID, "admin")
	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := PortalEnrolmentGenerateHandler(pool, rl)

	req := httptest.NewRequest(http.MethodPost, "/v1/portal/enrolment", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
		Email: email, TenantID: tenantID,
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("mint for decommissioned tenant = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "immediate") {
		t.Fatalf("409 body = %q, want it to name the mode %q", rr.Body.String(), "immediate")
	}
}

// TestMintTenantEnrolmentToken_AdminPathActorEmailIsNull confirms the admin
// call shape (actorEmail == "") writes SQL NULL, not an empty string — the
// admin regression half of the audit-actor requirement.
func TestMintTenantEnrolmentToken_AdminPathActorEmailIsNull(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping admin actor_email DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('portal-enrol-admin-actor-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM enrollment_token_audit WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})

	res, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mintTenantEnrolmentToken: %v", err)
	}

	var actorEmail *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_email FROM enrollment_token_audit WHERE token_id = $1::uuid`, res.TokenID,
	).Scan(&actorEmail); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if actorEmail != nil {
		t.Fatalf("admin-path actor_email = %q, want SQL NULL", *actorEmail)
	}
}

// TestPortalEnrolmentGenerateHandler_RateLimitCapAndTenantIsolation proves
// the dedicated per-tenant limiter (not the general portal per-identity one)
// actually caps mints and that a DIFFERENT tenant is unaffected — the same
// isolation property ratelimit.TestAllow_IsolatesTenants proves at the
// package level, exercised here through the real handler + DB path.
func TestPortalEnrolmentGenerateHandler_RateLimitCapAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping rate limit DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	mk := func(name string) string {
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
			VALUES ($1,
			        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
			        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
			RETURNING id::text`, name).Scan(&id); err != nil {
			t.Fatalf("create tenant %s: %v", name, err)
		}
		return id
	}
	tenantA := mk("portal-enrol-rl-a")
	tenantB := mk("portal-enrol-rl-b")
	t.Cleanup(func() {
		for _, id := range []string{tenantA, tenantB} {
			_, _ = pool.Exec(ctx, `DELETE FROM enrollment_token_audit WHERE tenant_id = $1::uuid`, id)
			_, _ = pool.Exec(ctx, `DELETE FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, id)
			_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, id)
		}
	})

	// Cap of 2 mints (burst == cap; negligible refill within the test).
	rl := ratelimit.New(ratelimit.Config{RPM: 2, Burst: 2})
	h := PortalEnrolmentGenerateHandler(pool, rl)

	// PAT-2407: only a portal admin may mint, so every caller is one. The
	// budget is per tenant, so one admin per tenant is enough.
	adminA := seedPortalUser(t, ctx, pool, tenantA, "admin")
	adminB := seedPortalUser(t, ctx, pool, tenantB, "admin")

	do := func(tenantID, email string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/portal/enrolment", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
			Email: email, TenantID: tenantID,
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if c := do(tenantA, adminA); c != http.StatusCreated {
		t.Fatalf("tenant A req 1 = %d, want 201", c)
	}
	if c := do(tenantA, adminA); c != http.StatusCreated {
		t.Fatalf("tenant A req 2 = %d, want 201", c)
	}
	if c := do(tenantA, adminA); c != http.StatusTooManyRequests {
		t.Fatalf("tenant A req 3 = %d, want 429 (cap of 2 exceeded)", c)
	}

	// A different tenant is on its own bucket — unaffected by A's exhaustion.
	if c := do(tenantB, adminB); c != http.StatusCreated {
		t.Fatalf("tenant B req 1 = %d, want 201 (must be unaffected by tenant A's rate limit)", c)
	}
}

// ---------------------------------------------------------------------------
// PAT-2407: POST /v1/portal/enrolment is admin only, the same rule and the
// same mechanism as POST /v1/portal/enrolment-keys. Each case asserts the
// status, the error code and the database effect.
// ---------------------------------------------------------------------------

func portalEnrolDo(h http.Handler, email, tenantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/portal/enrolment", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// portalEnrolRowCounts returns the tenant's bootstrap_tokens and
// enrollment_token_audit row counts.
func portalEnrolRowCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) (tokens, audits int) {
	t.Helper()
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM bootstrap_tokens WHERE tenant_id = $1::uuid),
		       (SELECT count(*) FROM enrollment_token_audit WHERE tenant_id = $1::uuid)`,
		tenantID).Scan(&tokens, &audits); err != nil {
		t.Fatalf("count token rows: %v", err)
	}
	return tokens, audits
}

// assertPortalEnrolRefusedNonAdmin checks the refusal is the same one the
// enrolment-key create route gives a non-admin, and that it carries no token.
func assertPortalEnrolRefusedNonAdmin(t *testing.T, who string, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Fatalf("%s mint: status %d body %q, want 403", who, rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s mint: 403 body %q is not JSON: %v", who, rr.Body.String(), err)
	}
	if body["error"] != "admin_role_required" {
		t.Fatalf("%s mint: error code %v, want admin_role_required (body %q)", who, body["error"], rr.Body.String())
	}
	if msg, _ := body["message"].(string); msg != "only a portal admin can mint an enrolment token; your role is viewer" {
		t.Fatalf("%s mint: message %q", who, msg)
	}
	if _, has := body["enrollment_token"]; has {
		t.Fatalf("%s mint: 403 body carries an enrollment_token", who)
	}
}

func TestPortalEnrolmentGenerateHandler_AdminMints(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2407-portal-mint-admin")
	admin := seedPortalUser(t, ctx, pool, tenantID, "admin")

	rr := portalEnrolDo(PortalEnrolmentGenerateHandler(pool, nil), admin, tenantID)
	if rr.Code != http.StatusCreated {
		t.Fatalf("admin mint: status %d body %q, want 201", rr.Code, rr.Body.String())
	}
	// Response shape is unchanged: exactly these four string fields.
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp) != 4 {
		t.Fatalf("response has %d fields, want 4: %v", len(resp), resp)
	}
	for _, k := range []string{"enrollment_token", "tenant_id", "token_id", "expires_at"} {
		if v, _ := resp[k].(string); v == "" {
			t.Fatalf("response field %q missing or empty", k)
		}
	}
	if resp["tenant_id"] != tenantID {
		t.Fatalf("tenant_id = %v, want %s", resp["tenant_id"], tenantID)
	}

	// Exactly one token row, the one returned, for this tenant, mdm,
	// unconsumed; and one audit row naming the admin.
	var id, path string
	var consumed bool
	if err := pool.QueryRow(ctx, `
		SELECT id::text, delivery_path, consumed_at IS NOT NULL
		FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, tenantID).Scan(&id, &path, &consumed); err != nil {
		t.Fatalf("read token row (want exactly one): %v", err)
	}
	if id != resp["token_id"] || path != "mdm" || consumed {
		t.Fatalf("token row id=%s path=%s consumed=%v, want id=%v path=mdm unconsumed", id, path, consumed, resp["token_id"])
	}
	if tokens, audits := portalEnrolRowCounts(t, ctx, pool, tenantID); tokens != 1 || audits != 1 {
		t.Fatalf("rows: tokens=%d audits=%d, want 1 and 1", tokens, audits)
	}
	var actor *string
	if err := pool.QueryRow(ctx, `SELECT actor_email FROM enrollment_token_audit WHERE token_id = $1::uuid`, id).Scan(&actor); err != nil || actor == nil || *actor != admin {
		t.Fatalf("audit actor_email = %v (%v), want %s", actor, err, admin)
	}
}

// A viewer is refused and nothing is written. The refusal comes before the
// per-tenant limiter, as on the key-create route, so it does not spend the
// tenant's mint budget: with a budget of one, the admin still mints after.
func TestPortalEnrolmentGenerateHandler_ViewerRefusedWritesNothing(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2407-portal-mint-viewer")
	viewer := seedPortalUser(t, ctx, pool, tenantID, "viewer")
	admin := seedPortalUser(t, ctx, pool, tenantID, "admin")
	h := PortalEnrolmentGenerateHandler(pool, ratelimit.New(ratelimit.Config{RPM: 1, Burst: 1}))

	rr := portalEnrolDo(h, viewer, tenantID)
	assertPortalEnrolRefusedNonAdmin(t, "viewer", rr)
	if tokens, audits := portalEnrolRowCounts(t, ctx, pool, tenantID); tokens != 0 || audits != 0 {
		t.Fatalf("after viewer mint: tokens=%d audits=%d, want 0 and 0", tokens, audits)
	}

	if rr := portalEnrolDo(h, admin, tenantID); rr.Code != http.StatusCreated {
		t.Fatalf("admin mint after the viewer refusal: status %d body %q, want 201 (a refusal must not spend the budget)", rr.Code, rr.Body.String())
	}
}

// A user admitted only through the tenant's email domain has no portal_users
// row, so their role is viewer: refused, nothing written.
func TestPortalEnrolmentGenerateHandler_DomainFallbackUserRefusedWritesNothing(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2407-portal-mint-domain")
	domain := "pat2407-" + tenantID[:8] + ".example"
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_email_domains (tenant_id, domain) VALUES ($1::uuid, $2)`, tenantID, domain); err != nil {
		t.Fatalf("seed tenant email domain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenant_email_domains WHERE tenant_id = $1::uuid`, tenantID) })
	email := "someone@" + domain
	var members int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM portal_users WHERE email = $1`, email).Scan(&members); err != nil || members != 0 {
		t.Fatalf("portal_users rows for %s = %d (%v), want 0", email, members, err)
	}

	rr := portalEnrolDo(PortalEnrolmentGenerateHandler(pool, nil), email, tenantID)
	assertPortalEnrolRefusedNonAdmin(t, "domain-fallback user", rr)
	if tokens, audits := portalEnrolRowCounts(t, ctx, pool, tenantID); tokens != 0 || audits != 0 {
		t.Fatalf("after domain-fallback mint: tokens=%d audits=%d, want 0 and 0", tokens, audits)
	}
}

// An admin of another tenant, and a disabled admin, are not admins here.
func TestPortalEnrolmentGenerateHandler_OtherTenantAndDisabledAdminRefused(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantA := mkSupersedeTestTenant(t, ctx, pool, "pat2407-portal-mint-a")
	tenantB := mkSupersedeTestTenant(t, ctx, pool, "pat2407-portal-mint-b")
	adminB := seedPortalUser(t, ctx, pool, tenantB, "admin")
	disabled := seedPortalUser(t, ctx, pool, tenantA, "admin")
	if _, err := pool.Exec(ctx, `UPDATE portal_users SET disabled_at = now() WHERE email = $1`, disabled); err != nil {
		t.Fatalf("disable admin: %v", err)
	}
	h := PortalEnrolmentGenerateHandler(pool, nil)

	assertPortalEnrolRefusedNonAdmin(t, "other tenant's admin", portalEnrolDo(h, adminB, tenantA))
	assertPortalEnrolRefusedNonAdmin(t, "disabled admin", portalEnrolDo(h, disabled, tenantA))
	for _, id := range []string{tenantA, tenantB} {
		if tokens, audits := portalEnrolRowCounts(t, ctx, pool, id); tokens != 0 || audits != 0 {
			t.Fatalf("tenant %s: tokens=%d audits=%d, want 0 and 0", id, tokens, audits)
		}
	}
}

// The dedicated per-tenant limiter still refuses an admin with 429 and
// Retry-After, and writes nothing.
func TestPortalEnrolmentGenerateHandler_AdminRateLimitedWritesNothing(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2407-portal-mint-ratelimited")
	admin := seedPortalUser(t, ctx, pool, tenantID, "admin")

	rr := portalEnrolDo(PortalEnrolmentGenerateHandler(pool, ratelimit.New(ratelimit.Config{RPM: 0, Burst: 0})), admin, tenantID)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
	if tokens, audits := portalEnrolRowCounts(t, ctx, pool, tenantID); tokens != 0 || audits != 0 {
		t.Fatalf("after a rate-limited mint: tokens=%d audits=%d, want 0 and 0", tokens, audits)
	}
}
