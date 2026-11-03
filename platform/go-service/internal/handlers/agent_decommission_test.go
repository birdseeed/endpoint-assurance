package handlers

// Tests for agent decommissioning (PAT-1108).
//
// Pure-logic (nil-pool) tests run in every environment and cover the
// validation branches that return before any DB access — mirroring
// tenant_platforms_test.go's isPlatformValid pattern and
// device_removals_test.go's nil-pool unauthorized checks. DB-backed tests
// require TEST_DATABASE_URL and are skipped otherwise, matching the convention
// used throughout this package (agent_health_test.go, allowlist_agent_known_path_test.go).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/db"
)

// ---------------------------------------------------------------------------
// Pure-logic tests — no database required
// ---------------------------------------------------------------------------

// TestValidateDecommissionDirectiveReq covers every enum value plus the
// expires_at-required-when-expiry acceptance criterion, mirroring
// TestValidateAgentConfigReq's table-driven style.
func TestValidateDecommissionDirectiveReq(t *testing.T) {
	valid := "2026-09-01T00:00:00Z"
	dateOnly := "2026-09-01"
	empty := ""

	tests := []struct {
		name    string
		req     decommissionDirectiveReq
		wantErr bool
	}{
		{"mode=none, no expires_at", decommissionDirectiveReq{Mode: "none"}, false},
		{"mode=expiry with valid expires_at", decommissionDirectiveReq{Mode: "expiry", ExpiresAt: &valid}, false},
		{"mode=immediate, no expires_at", decommissionDirectiveReq{Mode: "immediate"}, false},
		{"mode=expiry, nil expires_at", decommissionDirectiveReq{Mode: "expiry"}, true},
		{"mode=expiry, empty expires_at", decommissionDirectiveReq{Mode: "expiry", ExpiresAt: &empty}, true},
		{"mode=expiry, date-only (not RFC3339)", decommissionDirectiveReq{Mode: "expiry", ExpiresAt: &dateOnly}, true},
		{"unknown mode", decommissionDirectiveReq{Mode: "wipe"}, true},
		{"empty mode", decommissionDirectiveReq{Mode: ""}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDecommissionDirectiveReq(tc.req)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateDecommissionDirectiveReq(%+v) error = %v, wantErr %v", tc.req, err, tc.wantErr)
			}
		})
	}
}

// TestAgentReportableDecommissionStatuses asserts the closed set the agent
// may report over POST /v1/agent-decommission-status, and specifically that
// "pending" is excluded — it is never written directly, only implied by an
// absent row.
func TestAgentReportableDecommissionStatuses(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"acknowledged", true},
		{"removed", true},
		{"failed", true},
		{"expired_unreachable", true},
		{"pending", false}, // never written directly
		{"", false},
		{"REMOVED", false}, // case-sensitive
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			if got := agentReportableDecommissionStatuses[tc.status]; got != tc.want {
				t.Errorf("agentReportableDecommissionStatuses[%q] = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

func adWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestTenantDecommissionGetHandler_BadUUID(t *testing.T) {
	h := TenantDecommissionGetHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/not-a-uuid/decommission", nil)
	req = adWithTenantID(req, "not-a-uuid")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestTenantDecommissionPutHandler_BadUUID(t *testing.T) {
	h := TenantDecommissionPutHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/not-a-uuid/decommission", strings.NewReader(`{"mode":"none"}`))
	req = adWithTenantID(req, "not-a-uuid")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestTenantDecommissionPutHandler_InvalidModeRejectedBeforeDB proves the
// validation branch runs before any DB call — a nil pool would panic on
// first use, so a clean 400 here proves validation runs first.
func TestTenantDecommissionPutHandler_InvalidModeRejectedBeforeDB(t *testing.T) {
	h := TenantDecommissionPutHandler((*pgxpool.Pool)(nil))
	tenantID := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission", strings.NewReader(`{"mode":"wipe"}`))
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

// TestTenantDecommissionPutHandler_ExpiryMissingExpiresAtRejectedBeforeDB is
// the same before-DB proof for the expires_at-required-when-expiry rule.
func TestTenantDecommissionPutHandler_ExpiryMissingExpiresAtRejectedBeforeDB(t *testing.T) {
	h := TenantDecommissionPutHandler((*pgxpool.Pool)(nil))
	tenantID := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission", strings.NewReader(`{"mode":"expiry"}`))
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestTenantDecommissionDevicesHandler_BadUUID(t *testing.T) {
	h := TenantDecommissionDevicesHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/not-a-uuid/decommission/devices", nil)
	req = adWithTenantID(req, "not-a-uuid")
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestAgentDecommissionStatusHandler_Unauthorized(t *testing.T) {
	h := AgentDecommissionStatusHandler((*pgxpool.Pool)(nil), nil, 0)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-decommission-status", strings.NewReader(`{"status":"removed"}`))
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 with no bearer, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// DB-backed tests — require TEST_DATABASE_URL, skipped otherwise
// ---------------------------------------------------------------------------

// adRequireDB reports whether adConnectOrSkip must fail loudly (not silently
// skip) when TEST_DATABASE_URL is unset, given PATCHED_DB_TESTS_REQUIRED's value.
// Isolated as a pure function so the decision is unit-testable without needing
// to actually invoke t.Fatal from inside a test (PAT-1108 finding 6).
//
// The point of this guard is that every migration/persistence/audit/tenant-
// isolation/status-upsert test in this file would otherwise silently evaporate
// from every PR without failing anything, if the wiring between this package
// and the CI job that supplies a database ever broke.
//
// It deliberately does NOT key on the generic CI env var, which was the first
// attempt and was wrong: GitHub Actions sets CI=true on EVERY job, including
// go-test.yml's build-test-vet, which has no Postgres service and no
// TEST_DATABASE_URL by design. Keying on CI made this whole file fail there rather
// than skip, breaking a job that is not supposed to run DB tests at all. The
// marker instead names the specific thing being asserted — "a database was
// promised to this run" — and is set only by the job that actually provides
// one (go-integration-test.yml's "internal/handlers DB-gated tests" step).
// So: marker set and no TEST_DATABASE_URL means the promise was broken, fail the
// build; marker unset means a developer machine or a deliberately DB-free CI
// job, where skipping is correct.
func adRequireDB(requiredEnv string) bool {
	return requiredEnv != ""
}

func adConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if adRequireDB(os.Getenv("PATCHED_DB_TESTS_REQUIRED")) {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not — agent-decommission DB coverage would silently evaporate; see go-integration-test.yml's \"internal/handlers DB-gated tests\" step")
		}
		t.Skip("TEST_DATABASE_URL not set — skipping agent-decommission DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// TestAdRequireDB pins the decision itself (PAT-1108 finding 6): the marker is
// set only by the CI job that actually provides a Postgres service, so an unset
// marker must stay skip-eligible. The "CI=true but no database" case is the
// regression this guards — build-test-vet runs with CI=true and deliberately
// has no TEST_DATABASE_URL, and an earlier version keyed on CI and failed there.
func TestAdRequireDB(t *testing.T) {
	tests := []struct {
		name        string
		requiredEnv string
		want        bool
	}{
		{"unset (local dev) — skip is fine", "", false},
		{"unset (build-test-vet: CI=true but no Postgres service) — skip is fine", "", false},
		{"set by the DB-gated CI step", "1", true},
		{"set to any non-empty value", "true", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := adRequireDB(tc.requiredEnv); got != tc.want {
				t.Errorf("adRequireDB(%q) = %v, want %v", tc.requiredEnv, got, tc.want)
			}
		})
	}
}

func adSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		            '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`, name).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}

func adSeedDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, hwUUID, hostname string) string {
	t.Helper()
	var deviceID string
	err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hw_uuid, os, hostname)
		VALUES ($1::uuid, $2::uuid, 'macOS', $3)
		RETURNING id::text
	`, tenantID, hwUUID, hostname).Scan(&deviceID)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, deviceID) })
	return deviceID
}

// TestTenantDecommissionPutThenGet_RoundTrip drives the real PUT then GET
// handlers end to end: set a directive, confirm the read path reflects it,
// and confirm exactly one audit row was written.
func TestTenantDecommissionPutThenGet_RoundTrip(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-roundtrip-tenant")

	putReq := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission",
		strings.NewReader(`{"mode":"expiry","expires_at":"2026-09-01T00:00:00Z","purge":true,"reason":"tenant offboarded","actor":"andy@patched.im"}`))
	putReq = adWithTenantID(putReq, tenantID)
	putRR := httptest.NewRecorder()
	TenantDecommissionPutHandler(pool)(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", putRR.Code, putRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/decommission", nil)
	getReq = adWithTenantID(getReq, tenantID)
	getRR := httptest.NewRecorder()
	TenantDecommissionGetHandler(pool)(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", getRR.Code, getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), `"mode":"expiry"`) {
		t.Errorf("GET body missing mode=expiry: %s", getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), `"purge":true`) {
		t.Errorf("GET body missing purge=true: %s", getRR.Body.String())
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`, tenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit row count = %d, want 1", auditCount)
	}

	// A second PUT with a different actor must write a SECOND audit row —
	// every call is audited, not just net changes.
	putReq2 := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission",
		strings.NewReader(`{"mode":"immediate","purge":false,"reason":"escalated","actor":"someone-else@patched.im"}`))
	putReq2 = adWithTenantID(putReq2, tenantID)
	putRR2 := httptest.NewRecorder()
	TenantDecommissionPutHandler(pool)(putRR2, putReq2)
	if putRR2.Code != http.StatusOK {
		t.Fatalf("second PUT status = %d, want 200: %s", putRR2.Code, putRR2.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`, tenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit rows after second PUT: %v", err)
	}
	if auditCount != 2 {
		t.Errorf("audit row count after second PUT = %d, want 2", auditCount)
	}

	// old_mode on the second audit row must be the first PUT's mode.
	var oldMode string
	if err := pool.QueryRow(ctx, `
		SELECT old_mode FROM tenant_decommission_audit
		WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&oldMode); err != nil {
		t.Fatalf("fetch latest audit row: %v", err)
	}
	if oldMode != "expiry" {
		t.Errorf("second audit row old_mode = %q, want %q", oldMode, "expiry")
	}
}

// TestTenantDecommissionGet_NoDirectiveDefaultsToNone proves a tenant that
// has never had a directive set reads back mode=none, not a 404 or an error.
func TestTenantDecommissionGet_NoDirectiveDefaultsToNone(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-no-directive-tenant")

	getReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/decommission", nil)
	getReq = adWithTenantID(getReq, tenantID)
	getRR := httptest.NewRecorder()
	TenantDecommissionGetHandler(pool)(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", getRR.Code, getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), `"mode":"none"`) {
		t.Errorf("body missing mode=none: %s", getRR.Body.String())
	}
}

// TestTenantDecommissionDevices_NeverAcknowledgedDevicesCounted is the core
// acceptance-criterion proof: per-device state must be queryable for a
// tenant INCLUDING devices that have never reported anything. Three devices:
// one reports 'removed', one reports 'failed', one never reports at all —
// the never-reporting device must still appear, as 'pending'. "12 of 40
// removed, 28 pending" must be expressible; this is the 3-device version of
// that same shape.
func TestTenantDecommissionDevices_NeverAcknowledgedDevicesCounted(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-devices-tenant")

	removedDevice := adSeedDevice(t, ctx, pool, tenantID, "11111111-2222-3333-4444-555555555551", "removed-host")
	failedDevice := adSeedDevice(t, ctx, pool, tenantID, "11111111-2222-3333-4444-555555555552", "failed-host")
	pendingDevice := adSeedDevice(t, ctx, pool, tenantID, "11111111-2222-3333-4444-555555555553", "pending-host")
	_ = pendingDevice // never reports — deliberately no device_decommission_state row

	if _, err := pool.Exec(ctx, `
		INSERT INTO device_decommission_state (device_id, status, last_reported_outcome)
		VALUES ($1::uuid, 'removed', 'uploader removed cleanly')
	`, removedDevice); err != nil {
		t.Fatalf("seed removed state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_decommission_state (device_id, status, last_reported_outcome)
		VALUES ($1::uuid, 'failed', 'permission denied removing LaunchDaemon')
	`, failedDevice); err != nil {
		t.Fatalf("seed failed state: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/decommission/devices", nil)
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantDecommissionDevicesHandler(pool)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		TenantID string `json:"tenant_id"`
		Total    int    `json:"total"`
		Devices  []struct {
			DeviceID string `json:"device_id"`
			Hostname string `json:"hostname"`
			Status   string `json:"status"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}

	if resp.Total != 3 {
		t.Fatalf("total = %d, want 3 (all devices counted, including never-reported)", resp.Total)
	}
	byID := map[string]string{}
	for _, d := range resp.Devices {
		byID[d.DeviceID] = d.Status
	}
	if byID[removedDevice] != "removed" {
		t.Errorf("removed device status = %q, want removed", byID[removedDevice])
	}
	if byID[failedDevice] != "failed" {
		t.Errorf("failed device status = %q, want failed", byID[failedDevice])
	}
	if byID[pendingDevice] != "pending" {
		t.Errorf("never-reported device status = %q, want pending (LEFT JOIN default)", byID[pendingDevice])
	}
}

// TestAgentDecommissionStatusHandler_RoundTrip drives the real terminal-status
// endpoint end to end with a device-scoped bearer credential: posts 'removed',
// confirms it lands in device_decommission_state, then posts 'failed' for the
// same device and confirms the row updates in place (not a second row) while
// first_reported_at is preserved.
//
// PAT-1108 third-round: a real directive is set up first, and both reports
// carry directive_version = that directive's version (the envelope
// config_version, which is identical to it here since nothing else has
// bumped agent_config in between) — otherwise every report in this test
// would be superseded by construction (no directive means mode="none",
// which finding B always answers 409 to), and this test is about upsert
// mechanics, not the proceed/superseded gate.
func TestAgentDecommissionStatusHandler_RoundTrip(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-status-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "22222222-3333-4444-5555-666666666666", "status-host")

	bearerToken := "pat1108-device-token"
	hmacSecret := "pat1108-device-hmac-secret-32by!"
	tokenHash := sha256.Sum256([]byte(bearerToken))
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, tenantID, deviceID, tokenHash[:], []byte(hmacSecret)); err != nil {
		t.Fatalf("insert device credential: %v", err)
	}

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion); err != nil {
		t.Fatalf("query directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	req1 := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"acknowledged","detail":"directive received","directive_version":%d}`, directiveVersion))
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first POST status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}

	var status1, detail1 string
	if err := pool.QueryRow(ctx, `SELECT status, last_reported_outcome FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&status1, &detail1); err != nil {
		t.Fatalf("fetch state after first POST: %v", err)
	}
	if status1 != "acknowledged" || detail1 != "directive received" {
		t.Errorf("after first POST: status=%q detail=%q, want acknowledged/directive received", status1, detail1)
	}

	var firstReportedAt1 time.Time
	if err := pool.QueryRow(ctx, `SELECT first_reported_at FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&firstReportedAt1); err != nil {
		t.Fatalf("fetch first_reported_at: %v", err)
	}

	req2 := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"uploader removed, LaunchDaemon unloaded","directive_version":%d}`, directiveVersion))
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second POST status = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}

	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("row count = %d, want 1 (upsert in place, not a second row)", rowCount)
	}

	var status2, detail2 string
	var firstReportedAt2 time.Time
	if err := pool.QueryRow(ctx, `SELECT status, last_reported_outcome, first_reported_at FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&status2, &detail2, &firstReportedAt2); err != nil {
		t.Fatalf("fetch state after second POST: %v", err)
	}
	if status2 != "removed" {
		t.Errorf("after second POST: status = %q, want removed", status2)
	}
	if !firstReportedAt1.Equal(firstReportedAt2) {
		t.Errorf("first_reported_at changed on update: %v -> %v, want unchanged", firstReportedAt1, firstReportedAt2)
	}

	// A tenant-wide (non-device-scoped) credential must NOT be able to call
	// this endpoint — the device_id must come only from a device credential.
	tenantOnlyToken := "pat1108-tenant-only-token"
	tenantOnlyHmac := "pat1108-tenant-only-hmac-sec32b!"
	tenantOnlyHash := sha256.Sum256([]byte(tenantOnlyToken))
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2, $3)
	`, tenantID, tenantOnlyHash[:], []byte(tenantOnlyHmac)); err != nil {
		t.Fatalf("insert tenant-only credential: %v", err)
	}
	req3 := adSignedDecommissionStatusReq(t, tenantOnlyToken, tenantOnlyHmac, `{"status":"removed"}`)
	rr3 := httptest.NewRecorder()
	handler(rr3, req3)
	if rr3.Code != http.StatusUnauthorized {
		t.Errorf("tenant-wide credential status = %d, want 401 (device-scoped only)", rr3.Code)
	}
}

// adSignedDecommissionStatusReq builds a fully-authenticated POST
// /v1/agent-decommission-status request with a v3 signature binding the
// operation, body, timestamp and nonce.
func adSignedDecommissionStatusReq(t *testing.T, bearerToken, hmacSecret, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-decommission-status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", "pat1108-nonce-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	req.Header.Set("X-Patched-Signature", agentV3TestSignature([]byte(hmacSecret), req.Method, "agent_decommission_status", req.Header.Get("X-Patched-Timestamp"), req.Header.Get("X-Patched-Nonce"), []byte(body)))
	return req
}

// ---------------------------------------------------------------------------
// PAT-1108 non-author-review fix regression tests (findings 1, 3, 4, 5)
// ---------------------------------------------------------------------------

// adPutDecommission drives TenantDecommissionPutHandler directly.
func adPutDecommission(pool *pgxpool.Pool, tenantID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission", strings.NewReader(body))
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantDecommissionPutHandler(pool)(rr, req)
	return rr
}

// adFetchDevices drives TenantDecommissionDevicesHandler and returns a
// deviceID -> status map for convenient assertions.
func adFetchDevices(t *testing.T, pool *pgxpool.Pool, tenantID string) map[string]string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/decommission/devices", nil)
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantDecommissionDevicesHandler(pool)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("devices fetch status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			Status   string `json:"status"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode devices response: %v", err)
	}
	out := map[string]string{}
	for _, d := range resp.Devices {
		out[d.DeviceID] = d.Status
	}
	return out
}

// adSeedDeviceCredential inserts a device-scoped tenant_credentials row so
// AgentDecommissionStatusHandler can authenticate as that device.
func adSeedDeviceCredential(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, bearerToken, hmacSecret string) {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(bearerToken))
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, tenantID, deviceID, tokenHash[:], []byte(hmacSecret)); err != nil {
		t.Fatalf("insert device credential: %v", err)
	}
}

// TestTenantDecommissionPut_BumpsAgentConfigVersionOnRealChange is the finding
// 1 regression: a PUT that actually changes the effective directive (here,
// the tenant's first-ever directive, then a mode change) must bump
// agent_config.config_version, and tenant_decommission.directive_version must
// be stamped with that exact same value — reusing the anti-rollback counter,
// not a parallel one. Without the fix, config_version never moves and
// directive_version stays at its schema default (0) forever.
//
// configVersion1 is asserted as 2, not 1 — this is the PAT-1108 second-round
// finding A fix: GET /v1/agent-config already serves config_version=1 as the
// synthetic default for a tenant with no agent_config row (see
// syntheticDefaultConfigVersion, agent_config.go), so the tenant's
// first-EVER persisted directive must land strictly above that value, or an
// agent that already polled the synthetic default once would reject the
// real directive as a same-version replay. See
// TestBumpAgentConfigVersionForDecommission_ExceedsSyntheticDefault for the
// dedicated regression test that drives both code paths together.
func TestTenantDecommissionPut_BumpsAgentConfigVersionOnRealChange(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-f1-bump-tenant")

	rr1 := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}

	var configVersion1, directiveVersion1 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&configVersion1); err != nil {
		t.Fatalf("query agent_config after first PUT: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion1); err != nil {
		t.Fatalf("query tenant_decommission after first PUT: %v", err)
	}
	if configVersion1 != 2 {
		t.Errorf("agent_config.config_version after the tenant's first-ever decommission PUT = %d, want 2 (strictly greater than the synthetic default's config_version=1)", configVersion1)
	}
	if directiveVersion1 != configVersion1 {
		t.Errorf("tenant_decommission.directive_version = %d, want it to equal agent_config.config_version = %d (reuse, not a parallel counter)", directiveVersion1, configVersion1)
	}

	// A materially different second PUT (mode changes from immediate to none
	// — a cancellation) must bump again.
	rr2 := adPutDecommission(pool, tenantID, `{"mode":"none","actor":"andy@patched.im"}`)
	if rr2.Code != http.StatusOK {
		t.Fatalf("cancellation PUT status = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
	var configVersion2, directiveVersion2 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&configVersion2); err != nil {
		t.Fatalf("query agent_config after cancellation: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion2); err != nil {
		t.Fatalf("query tenant_decommission after cancellation: %v", err)
	}
	if configVersion2 != configVersion1+1 {
		t.Errorf("agent_config.config_version after cancellation = %d, want %d (a cancellation is a directive change and must bump it)", configVersion2, configVersion1+1)
	}
	if directiveVersion2 != configVersion2 {
		t.Errorf("tenant_decommission.directive_version after cancellation = %d, want it to equal agent_config.config_version = %d", directiveVersion2, configVersion2)
	}
}

// TestBumpAgentConfigVersionForDecommission_ExceedsSyntheticDefault is the
// PAT-1108 second-round finding A regression. It pins the exact invariant
// the finding requires — "a persisted directive is always served at a
// version strictly greater than the synthetic default's" — by driving BOTH
// code paths for real against the same tenant, not by comparing two
// hardcoded literals:
//
//  1. GET /v1/agent-config for a tenant with NO agent_config row at all
//     (dbGetAgentConfig's not-found branch, exercised through the real
//     newAgentConfigHandler + dbGetAgentConfig) must serve the synthetic
//     default's config_version.
//  2. Setting the tenant's first-ever decommission directive
//     (bumpAgentConfigVersionForDecommission) must then persist an
//     agent_config row whose config_version is STRICTLY GREATER than the
//     value step 1 served — an agent that already accepted the synthetic
//     default at that version must be guaranteed to see the real directive
//     as new information, never as a same-version replay it can ignore.
func TestBumpAgentConfigVersionForDecommission_ExceedsSyntheticDefault(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-fA-synthetic-tenant")

	// Step 1: GET /v1/agent-config against the real DB-backed getFn, for a
	// tenant that genuinely has no agent_config row yet — the exact
	// synthetic-default branch finding A is about.
	key := newTestSigningKey()
	getFn := func(ctx context.Context, tenantID string) (agentConfigRow, bool, error) {
		return dbGetAgentConfig(ctx, pool, tenantID)
	}
	// pool=nil here (mirroring TestAgentConfigGet_SyntheticDefaultWhenNoRow):
	// the stub authFn resolves no deviceID, so ring resolution never touches
	// the pool, and passing nil also skips replay (timestamp/nonce)
	// validation, which this test has no need to exercise.
	getHandler := newAgentConfigHandler(key, acAuthAlways(tenantID), getFn, nil, 0, nil)

	getReq := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	getRR := httptest.NewRecorder()
	getHandler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET /v1/agent-config status = %d, want 200: %s", getRR.Code, getRR.Body.String())
	}
	var getResp agentConfigResp
	if err := json.Unmarshal(getRR.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	raw := decodeSignedPayload(t, getResp, key)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	syntheticVersion, ok := cfg["config_version"].(float64)
	if !ok {
		t.Fatalf("signed_payload missing numeric config_version: %v", cfg["config_version"])
	}

	// Step 2: set the tenant's first-ever decommission directive.
	putRR := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if putRR.Code != http.StatusOK {
		t.Fatalf("PUT decommission status = %d, want 200: %s", putRR.Code, putRR.Body.String())
	}

	var persistedVersion int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&persistedVersion); err != nil {
		t.Fatalf("query agent_config after first directive PUT: %v", err)
	}

	if float64(persistedVersion) <= syntheticVersion {
		t.Errorf("persisted directive's config_version = %d, synthetic default's config_version = %v — want the persisted version STRICTLY GREATER, or an agent that already accepted the synthetic default would silently ignore this tenant's first directive", persistedVersion, syntheticVersion)
	}
}

// TestTenantDecommissionPut_NoOpDoesNotBumpVersion pins the chosen no-op
// behaviour documented in TenantDecommissionPutHandler: an exactly-identical
// repeat PUT (same mode/expires_at/purge/reason) does not bump
// agent_config.config_version, even though it still writes a second audit
// row (every call is audited, per the existing round-trip test).
func TestTenantDecommissionPut_NoOpDoesNotBumpVersion(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-f1-noop-tenant")
	body := `{"mode":"immediate","purge":true,"reason":"first","actor":"andy@patched.im"}`

	rr1 := adPutDecommission(pool, tenantID, body)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}
	var configVersion1 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&configVersion1); err != nil {
		t.Fatalf("query agent_config after first PUT: %v", err)
	}

	rr2 := adPutDecommission(pool, tenantID, body) // byte-identical repeat
	if rr2.Code != http.StatusOK {
		t.Fatalf("second (identical) PUT status = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
	var configVersion2 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&configVersion2); err != nil {
		t.Fatalf("query agent_config after second PUT: %v", err)
	}
	if configVersion2 != configVersion1 {
		t.Errorf("agent_config.config_version changed on an identical repeat PUT: %d -> %d, want unchanged", configVersion1, configVersion2)
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`, tenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if auditCount != 2 {
		t.Errorf("audit row count = %d, want 2 — a no-op PUT still audits the re-confirmation, only the version bump is skipped", auditCount)
	}
}

// TestTenantDecommissionPut_ReasonOnlyChangeBumpsVersion is the PAT-1138
// reversal of the original PAT-1108 choice: reason is now INCLUDED in the
// directiveChanged comparison, so a reason-only edit bumps
// agent_config.config_version exactly like a mode/expires_at/purge change.
// reason's VALUE still never drives control flow anywhere (the agent never
// branches on what it says) — but the signed envelope's decommission block
// includes reason, so a reason-only edit changes the signed bytes, and the
// version must move so a corrected reason reaches an agent that already
// holds the previous version (anti-rollback would otherwise silently drop a
// same-version "correction" on the floor). directive_version is asserted
// equal to config_version after the second PUT: they are the same
// anti-rollback counter, reused, not two parallel counters that happen to
// agree by coincidence.
func TestTenantDecommissionPut_ReasonOnlyChangeBumpsVersion(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1138-reason-bumps-tenant")

	rr1 := adPutDecommission(pool, tenantID, `{"mode":"immediate","reason":"first reason","actor":"a"}`)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}
	var configVersion1 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&configVersion1); err != nil {
		t.Fatalf("query agent_config after first PUT: %v", err)
	}

	rr2 := adPutDecommission(pool, tenantID, `{"mode":"immediate","reason":"a completely different reason","actor":"a"}`)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second PUT status = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}
	var configVersion2 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&configVersion2); err != nil {
		t.Fatalf("query agent_config after second PUT: %v", err)
	}
	if configVersion2 != configVersion1+1 {
		t.Errorf("agent_config.config_version after a reason-only edit = %d, want %d (strictly greater than before — a reason-only change must bump exactly like any other directive change)", configVersion2, configVersion1+1)
	}

	// directive_version and config_version are the SAME counter, reused —
	// not two parallel counters that happen to agree.
	var directiveVersion2 int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion2); err != nil {
		t.Fatalf("query tenant_decommission after second PUT: %v", err)
	}
	if directiveVersion2 != configVersion2 {
		t.Errorf("tenant_decommission.directive_version after a reason-only edit = %d, want it to equal agent_config.config_version = %d (reuse, not a parallel counter)", directiveVersion2, configVersion2)
	}

	// The new reason must be persisted.
	var storedReason *string
	if err := pool.QueryRow(ctx, `SELECT reason FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&storedReason); err != nil {
		t.Fatalf("query stored reason: %v", err)
	}
	if storedReason == nil || *storedReason != "a completely different reason" {
		t.Errorf("stored reason = %v, want %q", storedReason, "a completely different reason")
	}
}

// TestTenantDecommissionPut_ReasonOnlyChangeReachesAgentHoldingPrevVersion
// is the PAT-1138 acceptance criterion itself, proven end to end through the
// real GET /v1/agent-config handler: an agent that already holds the
// PREVIOUS config_version (and therefore the previous ETag, which hashes the
// full canonical signed payload — see newAgentConfigHandler's ETag comment
// in agent_config.go) must be served the NEW config — not a 304 — after a
// reason-only edit, and the new payload's decommission.reason must be the
// corrected value.
//
// Before the PAT-1138 fix, the second GET below would have returned 304 Not
// Modified (the ETag, keyed on config_version, would never have changed for
// a reason-only edit), which is exactly the silent-non-delivery bug this
// ticket fixes: an agent already polling at configVersion1 would never learn
// the reason had been corrected.
func TestTenantDecommissionPut_ReasonOnlyChangeReachesAgentHoldingPrevVersion(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1138-reason-reaches-agent-tenant")

	rr1 := adPutDecommission(pool, tenantID, `{"mode":"immediate","reason":"first reason","actor":"a"}`)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}

	// Simulate an agent that polls GET /v1/agent-config right after the
	// first PUT and caches the ETag it was served — exactly what an agent
	// enforcing anti-rollback / conditional-GET would do.
	key := newTestSigningKey()
	getFn := func(ctx context.Context, tenantID string) (agentConfigRow, bool, error) {
		return dbGetAgentConfig(ctx, pool, tenantID)
	}
	getHandler := newAgentConfigHandler(key, acAuthAlways(tenantID), getFn, nil, 0, nil)

	getReq1 := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	getRR1 := httptest.NewRecorder()
	getHandler.ServeHTTP(getRR1, getReq1)
	if getRR1.Code != http.StatusOK {
		t.Fatalf("first GET /v1/agent-config status = %d, want 200: %s", getRR1.Code, getRR1.Body.String())
	}
	prevETag := getRR1.Header().Get("ETag")
	if prevETag == "" {
		t.Fatalf("first GET /v1/agent-config did not set an ETag header")
	}
	var getResp1 agentConfigResp
	if err := json.Unmarshal(getRR1.Body.Bytes(), &getResp1); err != nil {
		t.Fatalf("decode first GET response: %v", err)
	}
	raw1 := decodeSignedPayload(t, getResp1, key)
	var cfg1 map[string]interface{}
	if err := json.Unmarshal(raw1, &cfg1); err != nil {
		t.Fatalf("unmarshal first signed_payload: %v", err)
	}
	configVersion1, ok := cfg1["config_version"].(float64)
	if !ok {
		t.Fatalf("first signed_payload missing numeric config_version: %v", cfg1["config_version"])
	}

	// A reason-only edit — mode is unchanged.
	rr2 := adPutDecommission(pool, tenantID, `{"mode":"immediate","reason":"a completely different reason","actor":"a"}`)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second (reason-only) PUT status = %d, want 200: %s", rr2.Code, rr2.Body.String())
	}

	// The agent re-polls with If-None-Match set to the PREVIOUS ETag, as any
	// conditional-GET-aware client would. It must be served the new config
	// (200), NOT told nothing changed (304) — that is exactly what anti-
	// rollback requires: the agent cannot learn about the corrected reason
	// any other way.
	getReq2 := httptest.NewRequest(http.MethodGet, "/v1/agent-config", nil)
	getReq2.Header.Set("If-None-Match", prevETag)
	getRR2 := httptest.NewRecorder()
	getHandler.ServeHTTP(getRR2, getReq2)
	if getRR2.Code == http.StatusNotModified {
		t.Fatalf("second GET /v1/agent-config with If-None-Match=%s returned 304 — a reason-only edit must invalidate the agent's cached ETag so the corrected reason is actually delivered, not silently withheld", prevETag)
	}
	if getRR2.Code != http.StatusOK {
		t.Fatalf("second GET /v1/agent-config status = %d, want 200: %s", getRR2.Code, getRR2.Body.String())
	}

	newETag := getRR2.Header().Get("ETag")
	if newETag == prevETag {
		t.Errorf("ETag did not change after a reason-only edit: still %s", newETag)
	}

	var getResp2 agentConfigResp
	if err := json.Unmarshal(getRR2.Body.Bytes(), &getResp2); err != nil {
		t.Fatalf("decode second GET response: %v", err)
	}
	raw2 := decodeSignedPayload(t, getResp2, key)
	var cfg2 map[string]interface{}
	if err := json.Unmarshal(raw2, &cfg2); err != nil {
		t.Fatalf("unmarshal second signed_payload: %v", err)
	}

	configVersion2, ok := cfg2["config_version"].(float64)
	if !ok {
		t.Fatalf("second signed_payload missing numeric config_version: %v", cfg2["config_version"])
	}
	if configVersion2 <= configVersion1 {
		t.Errorf("config_version after a reason-only edit = %v, want strictly greater than %v — an agent holding configVersion1 must see this as new information, not a same-version replay it rejects under anti-rollback", configVersion2, configVersion1)
	}

	decommission, ok := cfg2["decommission"].(map[string]interface{})
	if !ok {
		t.Fatalf("second signed_payload missing decommission object: %v", cfg2["decommission"])
	}
	if got := decommission["reason"]; got != "a completely different reason" {
		t.Errorf("second signed_payload decommission.reason = %v, want %q — the corrected reason must actually reach the agent", got, "a completely different reason")
	}
}

// TestLockTenantAndReadDecommissionState_SerializesConcurrentWrites is the
// finding 3 regression, mirroring TestCheckTrialDeviceCap_SerializesConcurrentEnrol
// (trial_enforcement_test.go): it drives two real transactions with a
// deterministic interleaving instead of relying on goroutine-scheduling luck.
//
// tx1 takes the lock and reads (no directive yet), then inserts a directive
// row but does NOT commit. tx2 then calls the same function. With the
// tenants-row FOR UPDATE lock, tx2 MUST block until tx1 commits, and must
// then observe tx1's write as the "old" state — never race past it and see
// the pre-tx1 state, which is exactly the audit-chain corruption the finding
// describes (two concurrent writers both recording the same prior mode).
func TestLockTenantAndReadDecommissionState_SerializesConcurrentWrites(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-f3-lock-tenant")

	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()

	exists1, oldMode1, _, _, _, _, err := lockTenantAndReadDecommissionState(ctx, tx1, tenantID)
	if err != nil {
		t.Fatalf("tx1 lock and read: %v", err)
	}
	if !exists1 {
		t.Fatalf("tx1: tenant must exist")
	}
	if oldMode1 != nil {
		t.Fatalf("tx1: want no prior directive, got mode=%v", *oldMode1)
	}
	if _, err := tx1.Exec(ctx, `
		INSERT INTO tenant_decommission (tenant_id, mode, purge, set_by, directive_version)
		VALUES ($1::uuid, 'immediate', false, 'tx1', 1)
	`, tenantID); err != nil {
		t.Fatalf("tx1 insert directive: %v", err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()

	type lockRes struct {
		exists  bool
		oldMode *string
		err     error
	}
	done := make(chan lockRes, 1)
	go func() {
		exists2, oldMode2, _, _, _, _, err2 := lockTenantAndReadDecommissionState(ctx, tx2, tenantID)
		done <- lockRes{exists2, oldMode2, err2}
	}()

	select {
	case res := <-done:
		t.Fatalf("tx2 returned (exists=%v, oldMode=%v, err=%v) while tx1 held the lock uncommitted — "+
			"FOR UPDATE is not serialising concurrent decommission writes; the audit-chain race is open",
			res.exists, res.oldMode, res.err)
	case <-time.After(2 * time.Second):
		// Expected: tx2 is blocked on tx1's tenants-row lock.
	}

	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("tx2 lock and read after tx1 commit: %v", res.err)
	}
	if !res.exists {
		t.Fatalf("tx2: tenant must exist")
	}
	if res.oldMode == nil || *res.oldMode != "immediate" {
		t.Errorf("tx2 after tx1 committed: old_mode = %v, want \"immediate\" (tx2 must observe tx1's committed write, not an earlier snapshot)", res.oldMode)
	}
}

// TestAgentDecommissionStatusHandler_TerminalStateIsSticky is the finding 4
// regression: once a device's status reaches a terminal outcome (removed
// here), a later out-of-order report — of a non-terminal status, and of a
// DIFFERENT terminal status — must never regress it. The report is ignored
// (200 OK, no state change) rather than rejected, and the response reflects
// the TRUE persisted status, not the ignored one.
//
// PAT-1108 third-round: a real directive is set up first, and every report
// carries that SAME directive_version, so all three reports resolve to
// "proceed" (the directive stays current throughout this test) — the
// stickiness being tested here is the WITHIN-directive guard, distinct from
// the cross-directive proceed/superseded gate (see
// TestAgentDecommissionStatusHandler_NewDirectiveAcceptsReportDespitePriorTerminal).
func TestAgentDecommissionStatusHandler_TerminalStateIsSticky(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-f4-sticky-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "33333333-4444-5555-6666-777777777771", "sticky-host")
	bearerToken := "pat1108-f4-device-token"
	hmacSecret := "pat1108-f4-device-hmac-sec-32by!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion); err != nil {
		t.Fatalf("query directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	// First report: terminal "removed".
	req1 := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"clean removal","directive_version":%d}`, directiveVersion))
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first (removed) POST status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}

	// Delayed out-of-order "acknowledged" arrives after the removal report,
	// for the SAME directive_version.
	req2 := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"acknowledged","detail":"late ack","directive_version":%d}`, directiveVersion))
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("stale out-of-order POST must still return 200 (ignored, not rejected), got %d: %s", rr2.Code, rr2.Body.String())
	}

	var status2, outcome2 string
	if err := pool.QueryRow(ctx, `SELECT status, last_reported_outcome FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&status2, &outcome2); err != nil {
		t.Fatalf("fetch state after stale report: %v", err)
	}
	if status2 != "removed" {
		t.Errorf("status regressed from removed to %q after a stale out-of-order acknowledged report — terminal states must be sticky", status2)
	}
	if outcome2 != "clean removal" {
		t.Errorf("last_reported_outcome changed to %q after an ignored stale report, want unchanged %q", outcome2, "clean removal")
	}

	var resp2 map[string]string
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp2["recorded_status"] != "removed" {
		t.Errorf("recorded_status in response = %q, want removed — the response must reflect the true persisted status, not the ignored report", resp2["recorded_status"])
	}

	// A second, DIFFERENT terminal report (failed) after removed, for the
	// SAME directive_version, must also be ignored — the first terminal
	// outcome wins, not the last writer.
	req3 := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"failed","detail":"late failure","directive_version":%d}`, directiveVersion))
	rr3 := httptest.NewRecorder()
	handler(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("stale terminal POST must still return 200, got %d: %s", rr3.Code, rr3.Body.String())
	}
	var status3 string
	if err := pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&status3); err != nil {
		t.Fatalf("fetch state after second stale terminal report: %v", err)
	}
	if status3 != "removed" {
		t.Errorf("status changed to %q after a second, different terminal report — the first terminal outcome must win", status3)
	}
}

// TestTenantDecommissionDevices_StaleDirectiveVersionReadsAsPending is the
// finding 5 regression: a device that reported "removed" against an EARLIER
// directive must read as "pending" once the tenant cancels and re-issues —
// its report predates the current directive and describes a state the
// device has never taken with respect to it.
func TestTenantDecommissionDevices_StaleDirectiveVersionReadsAsPending(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-f5-stale-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "44444444-5555-6666-7777-888888888882", "stale-host")
	bearerToken := "pat1108-f5-device-token"
	hmacSecret := "pat1108-f5-device-hmac-sec-32by!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	// First directive.
	rr1 := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first directive PUT status = %d, want 200: %s", rr1.Code, rr1.Body.String())
	}
	var firstDirectiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&firstDirectiveVersion); err != nil {
		t.Fatalf("query directive_version after first directive PUT: %v", err)
	}

	// The device reports "removed" against that first directive, correctly
	// attributed (PAT-1108 second-round finding B: an unattributed report
	// would always read as pending regardless of finding 5's staleness
	// logic, which is not what this test is exercising).
	statusHandler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	statusReq := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"done","directive_version":%d}`, firstDirectiveVersion))
	statusRR := httptest.NewRecorder()
	statusHandler(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("status report POST status = %d, want 200: %s", statusRR.Code, statusRR.Body.String())
	}

	// Sanity: shows as removed under the current (first) directive.
	before := adFetchDevices(t, pool, tenantID)
	if before[deviceID] != "removed" {
		t.Fatalf("precondition failed: want removed under the first directive, got %q", before[deviceID])
	}

	// Cancel, then re-issue — two materially different writes, so
	// directive_version bumps twice past what the device's report carries.
	rrCancel := adPutDecommission(pool, tenantID, `{"mode":"none","actor":"andy@patched.im"}`)
	if rrCancel.Code != http.StatusOK {
		t.Fatalf("cancellation PUT status = %d, want 200: %s", rrCancel.Code, rrCancel.Body.String())
	}
	rrReissue := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrReissue.Code != http.StatusOK {
		t.Fatalf("re-issue PUT status = %d, want 200: %s", rrReissue.Code, rrReissue.Body.String())
	}

	// The device's prior "removed" report predates this new directive.
	after := adFetchDevices(t, pool, tenantID)
	if after[deviceID] != "pending" {
		t.Errorf("device status under the re-issued directive = %q, want pending — its report predates the current directive and must not read as removed", after[deviceID])
	}
}

// ---------------------------------------------------------------------------
// PAT-1108 second-round non-author-review fix regression tests
// (findings A, B, C, D)
// ---------------------------------------------------------------------------

// TestAgentDecommissionStatusHandler_MissingDirectiveVersionRejectedAsSuperseded
// is the finding B regression, updated for the third round's proceed/superseded
// gate: a report that omits directive_version (an agent build that predates
// the field, or a malformed client) can never be confirmed as describing the
// tenant's CURRENT directive, so it must get "decommission":"superseded"
// (409), NOT a bare 200. Without this, an agent that could not say which
// directive it acted on would be told "proceed" and go ahead with an
// irreversible removal the server never actually verified. No terminal
// status may be recorded off it either — see the "do not record a terminal
// removed state off a superseded report" requirement.
func TestAgentDecommissionStatusHandler_MissingDirectiveVersionRejectedAsSuperseded(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-fB-missing-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "55555555-6666-7777-8888-999999999991", "fB-missing-host")
	bearerToken := "pat1108-fB-missing-device-token"
	hmacSecret := "pat1108-fB-missing-device-hmac32!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	req := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret, `{"status":"removed","detail":"no directive_version field"}`)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status report POST status = %d, want 409 (a report the server cannot confirm is current must tell the agent to stop): %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["decommission"] != "superseded" {
		t.Errorf("decommission in response = %q, want superseded", resp["decommission"])
	}
	if _, hasRecordedStatus := resp["recorded_status"]; hasRecordedStatus {
		t.Errorf("response carries recorded_status %q on a superseded report — it must be absent, not just ignorable", resp["recorded_status"])
	}

	// No terminal (or any) status may have been recorded off this report —
	// the "do not record a terminal removed state off a superseded report"
	// requirement. Since this was the device's first-ever report, no row
	// should exist at all.
	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCount); err != nil {
		t.Fatalf("count device_decommission_state rows: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("device_decommission_state row count = %d, want 0 — a superseded report must never create/record a terminal status", rowCount)
	}

	devices := adFetchDevices(t, pool, tenantID)
	if devices[deviceID] != "pending" {
		t.Errorf("device status = %q, want pending — an unattributed, superseded report must never display as the current directive's outcome", devices[deviceID])
	}
}

// TestAgentDecommissionStatusHandler_DirectiveVersionAheadOfCurrentRejected
// is the finding B validation regression: a device cannot have verified an
// envelope config_version the tenant's agent_config has not reached yet.
// Such a report is nonsense (clock skew, a bug, or a forged report) and
// must be REJECTED (400), not stored. In this test envelopeVersion and
// tenant_decommission.directive_version are the same value (nothing else
// has bumped agent_config), so "ahead of current directive_version" and
// "ahead of current envelope config_version" — the third-round finding A
// fix — coincide; TestAgentDecommissionStatusHandler_NewDirectiveAcceptsReportDespiteUnrelatedEnvelopeBump
// is the test that tells them apart.
func TestAgentDecommissionStatusHandler_DirectiveVersionAheadOfCurrentRejected(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-fB-ahead-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "55555555-6666-7777-8888-999999999992", "fB-ahead-host")
	bearerToken := "pat1108-fB-ahead-device-token"
	hmacSecret := "pat1108-fB-ahead-device-hmac32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var currentVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&currentVersion); err != nil {
		t.Fatalf("query current directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	req := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","directive_version":%d}`, currentVersion+100))
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status report POST with directive_version ahead of current = %d, want 400: %s", rr.Code, rr.Body.String())
	}

	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("row count after rejected report = %d, want 0 — a rejected report must not be stored", rowCount)
	}
}

// TestAgentDecommissionStatusHandler_NewDirectiveAcceptsReportDespitePriorTerminal
// is the finding C regression, driving the exact sequence the finding
// specifies: directive N reaches a terminal status ("removed"), a new
// directive N+1 is issued, and the device then reports "acknowledged" for
// N+1 — that report must be ACCEPTED and DISPLAYED, not silently suppressed
// by the terminal-stickiness guard from directive N (which, combined with
// finding 5's stale-read logic, would otherwise leave the device stuck
// showing "pending" forever — the exact "12 of 40 removed" reporting bug the
// feature exists to prevent).
func TestAgentDecommissionStatusHandler_NewDirectiveAcceptsReportDespitePriorTerminal(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-fC-crossversion-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "55555555-6666-7777-8888-999999999993", "fC-crossversion-host")
	bearerToken := "pat1108-fC-device-token"
	hmacSecret := "pat1108-fC-device-hmac-sec-32by!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	// Directive N.
	rrPut1 := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut1.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d, want 200: %s", rrPut1.Code, rrPut1.Body.String())
	}
	var directiveN int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveN); err != nil {
		t.Fatalf("query directive_version N: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	// Device reaches a TERMINAL status ("removed") for directive N.
	reqRemoved := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"clean removal","directive_version":%d}`, directiveN))
	rrRemoved := httptest.NewRecorder()
	handler(rrRemoved, reqRemoved)
	if rrRemoved.Code != http.StatusOK {
		t.Fatalf("removed report for directive N status = %d, want 200: %s", rrRemoved.Code, rrRemoved.Body.String())
	}
	var statusAfterN string
	if err := pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&statusAfterN); err != nil {
		t.Fatalf("fetch status after directive N report: %v", err)
	}
	if statusAfterN != "removed" {
		t.Fatalf("precondition failed: status after directive N report = %q, want removed", statusAfterN)
	}

	// A materially different directive N+1 is issued — same mode, purge
	// flipped true, which still bumps the version once (PAT-1108
	// third-round: this must stay an ACTIONABLE directive, i.e. NOT
	// mode="none", or finding B's cancelled-directive rule would make every
	// report against it superseded regardless of directive_version, which
	// is not what this test — finding C's cross-version acceptance — is
	// about).
	rrPut2 := adPutDecommission(pool, tenantID, `{"mode":"immediate","purge":true,"actor":"andy@patched.im"}`)
	if rrPut2.Code != http.StatusOK {
		t.Fatalf("second PUT status = %d, want 200: %s", rrPut2.Code, rrPut2.Body.String())
	}
	var directiveNPlus1 int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveNPlus1); err != nil {
		t.Fatalf("query directive_version N+1: %v", err)
	}
	if directiveNPlus1 != directiveN+1 {
		t.Fatalf("precondition failed: directive_version after re-issue = %d, want %d", directiveNPlus1, directiveN+1)
	}

	// The device reports "acknowledged" for the NEW directive N+1.
	reqAck := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"acknowledged","detail":"seen the new directive","directive_version":%d}`, directiveNPlus1))
	rrAck := httptest.NewRecorder()
	handler(rrAck, reqAck)
	if rrAck.Code != http.StatusOK {
		t.Fatalf("acknowledged report for directive N+1 status = %d, want 200: %s", rrAck.Code, rrAck.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rrAck.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["decommission"] != "proceed" {
		t.Errorf("decommission in response = %q, want proceed — directive N+1 is the tenant's current, actionable directive", resp["decommission"])
	}
	if resp["recorded_status"] != "acknowledged" {
		t.Errorf("recorded_status in response = %q, want acknowledged — the terminal outcome from directive N must not block directive N+1's report", resp["recorded_status"])
	}

	var statusAfterNPlus1 string
	var storedDirectiveVersion int
	if err := pool.QueryRow(ctx, `SELECT status, directive_version FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&statusAfterNPlus1, &storedDirectiveVersion); err != nil {
		t.Fatalf("fetch state after directive N+1 report: %v", err)
	}
	if statusAfterNPlus1 != "acknowledged" {
		t.Errorf("status after directive N+1 report = %q, want acknowledged — stuck at %q from the superseded directive N would mean the device can never progress again", statusAfterNPlus1, statusAfterN)
	}
	if storedDirectiveVersion != directiveNPlus1 {
		t.Errorf("stored directive_version = %d, want %d (directive N+1)", storedDirectiveVersion, directiveNPlus1)
	}

	// And it must be DISPLAYED as such via the admin read path, not stuck at
	// "pending" (finding 5's stale-read logic) or "removed" (finding 4's
	// pre-fix terminal stickiness).
	devices := adFetchDevices(t, pool, tenantID)
	if devices[deviceID] != "acknowledged" {
		t.Errorf("displayed device status = %q, want acknowledged", devices[deviceID])
	}
}

// TestTenantDecommissionPut_NoPostCommitReadRequired is the finding D
// regression. It proves the handler no longer needs ANY database access
// after its write transaction commits by deliberately poisoning every
// connection acquisition AFTER the first one: BeforeAcquire allows exactly
// one Acquire() (the handler's own tx.BeginTx, held for the whole write) and
// rejects every subsequent one. The OLD code performed a separate read
// through the pool (a second, and even third, Acquire — see
// report.FetchTenantDecommissionDirective's own two queries) AFTER
// tx.Commit to build the response; that would starve against this pool
// (every later Acquire destroyed and retried until the request's context
// deadline) and return 500 even though the write had already committed
// successfully — exactly the false-failure-on-a-committed-irreversible-write
// bug the finding describes. The FIXED code builds its response entirely
// from the write statement's own RETURNING clause, inside the one
// transaction, so it needs no further Acquire and returns 200 promptly.
func TestTenantDecommissionPut_NoPostCommitReadRequired(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if adRequireDB(os.Getenv("PATCHED_DB_TESTS_REQUIRED")) {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not — see TestTenantDecommissionPut_NoPostCommitReadRequired")
		}
		t.Skip("TEST_DATABASE_URL not set — skipping agent-decommission DB tests")
	}

	// Seed the tenant using a normal, unpoisoned pool/connection.
	seedPool := adConnectOrSkip(t)
	t.Cleanup(func() { seedPool.Close() })
	ctx := context.Background()
	tenantID := adSeedTenant(t, ctx, seedPool, "pat1108-fD-nopostcommit-tenant")

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	var acquireCount int32
	cfg.BeforeAcquire = func(_ context.Context, _ *pgx.Conn) bool {
		n := atomic.AddInt32(&acquireCount, 1)
		return n <= 1 // allow only the handler's own transaction; reject every later Acquire
	}
	poisonedPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build poisoned pool: %v", err)
	}
	t.Cleanup(poisonedPool.Close)

	reqCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission",
		strings.NewReader(`{"mode":"immediate","actor":"andy@patched.im"}`)).WithContext(reqCtx)
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()

	start := time.Now()
	TenantDecommissionPutHandler(poisonedPool)(rr, req)
	elapsed := time.Since(start)

	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (the write committed; no further DB access should have been needed to build the response): %s [after %s, %d total Acquire calls]",
			rr.Code, rr.Body.String(), elapsed, atomic.LoadInt32(&acquireCount))
	}
	if elapsed >= 3*time.Second {
		t.Errorf("handler took %s (>= the 3s context deadline) to return 200 — this suggests it retried an Acquire it should not have needed", elapsed)
	}

	var resp decommissionDirectiveResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Mode != "immediate" {
		t.Errorf("response mode = %q, want immediate", resp.Mode)
	}

	// The write really did commit, verified independently via the
	// unpoisoned seed pool.
	var storedMode string
	if err := seedPool.QueryRow(ctx, `SELECT mode FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&storedMode); err != nil {
		t.Fatalf("verify committed write: %v", err)
	}
	if storedMode != "immediate" {
		t.Errorf("committed mode = %q, want immediate", storedMode)
	}
}

// ---------------------------------------------------------------------------
// PAT-1108 third-round non-author-review fix regression tests (findings A, B)
// ---------------------------------------------------------------------------

// TestAgentDecommissionStatusHandler_NewDirectiveAcceptsReportDespiteUnrelatedEnvelopeBump
// is the third-round finding A regression, driving exactly the sequence the
// finding specifies: issue directive at version N, bump the ENVELOPE
// (agent_config.config_version) with an UNRELATED agent-config change (never
// touching tenant_decommission) to N+1, then have the device report with
// N+1 — the only version an agent can actually observe. That report must be
// ACCEPTED (200, "proceed") and correctly attributed to directive N, not
// rejected as "ahead" and not stored under the wrong (N+1) version.
//
// Without the fix, validating the reported value against
// tenant_decommission.directive_version (still N) would reject N+1 as
// "ahead of current directive" with 400 — even though N+1 is a perfectly
// valid envelope version the agent genuinely observed, just one bumped by a
// change that has nothing to do with decommission.
func TestAgentDecommissionStatusHandler_NewDirectiveAcceptsReportDespiteUnrelatedEnvelopeBump(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-r3fA-envelope-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "66666666-7777-8888-9999-aaaaaaaaaaa1", "r3fA-envelope-host")
	bearerToken := "pat1108-r3fA-device-token"
	hmacSecret := "pat1108-r3fA-device-hmac-sec32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	// Directive at version N.
	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveN int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveN); err != nil {
		t.Fatalf("query directive_version N: %v", err)
	}

	// Bump the ENVELOPE via a write that has nothing to do with
	// decommission — the same dbUpsertAgentConfig path PUT
	// /admin/agent-config uses for a tier/app_control/etc. change.
	unrelatedBody := agentconfig.DefaultConfigBody()
	unrelatedBody.Tier = "patch"
	if _, err := dbUpsertAgentConfig(ctx, pool, tenantID, "admin-unrelated-change", unrelatedBody); err != nil {
		t.Fatalf("unrelated agent_config bump: %v", err)
	}
	var envelopeNPlus1 int
	if err := pool.QueryRow(ctx, `SELECT config_version FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&envelopeNPlus1); err != nil {
		t.Fatalf("query bumped envelope config_version: %v", err)
	}
	if envelopeNPlus1 != directiveN+1 {
		t.Fatalf("precondition failed: envelope config_version after unrelated bump = %d, want %d", envelopeNPlus1, directiveN+1)
	}
	// The directive itself must NOT have moved.
	var directiveVersionUnchanged int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersionUnchanged); err != nil {
		t.Fatalf("query directive_version after unrelated bump: %v", err)
	}
	if directiveVersionUnchanged != directiveN {
		t.Fatalf("precondition failed: tenant_decommission.directive_version moved from %d to %d after an UNRELATED agent_config write — the two counters must not be conflated", directiveN, directiveVersionUnchanged)
	}

	// The device reports against the envelope version it actually
	// observed: N+1, NOT the directive's own N.
	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	req := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"clean removal","directive_version":%d}`, envelopeNPlus1))
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status report POST status = %d, want 200 (an unrelated envelope bump must not reject a valid report): %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["decommission"] != "proceed" {
		t.Errorf("decommission in response = %q, want proceed", resp["decommission"])
	}
	if resp["recorded_status"] != "removed" {
		t.Errorf("recorded_status in response = %q, want removed", resp["recorded_status"])
	}

	// Stored directive_version must be the RESOLVED directive N, not the
	// raw envelope value N+1 the agent sent.
	var storedStatus string
	var storedDirectiveVersion int
	if err := pool.QueryRow(ctx, `SELECT status, directive_version FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&storedStatus, &storedDirectiveVersion); err != nil {
		t.Fatalf("query device_decommission_state: %v", err)
	}
	if storedStatus != "removed" {
		t.Errorf("stored status = %q, want removed", storedStatus)
	}
	if storedDirectiveVersion != directiveN {
		t.Errorf("stored directive_version = %d, want %d (resolved directive N, not the raw envelope value %d the agent sent)", storedDirectiveVersion, directiveN, envelopeNPlus1)
	}

	devices := adFetchDevices(t, pool, tenantID)
	if devices[deviceID] != "removed" {
		t.Errorf("displayed device status = %q, want removed", devices[deviceID])
	}
}

// TestAgentDecommissionStatusHandler_SupersededAfterCancellationStopsAgent is
// the third-round finding B regression — the most consequential finding in
// the ticket: the device fetched and acted on a directive, but the tenant
// cancelled it before the device's report arrived. The server already KNOWS
// the acted-on directive is stale; it must NOT answer 200 (which the agent
// would read as "confirmed, proceed with irreversible self-removal"). It
// must answer 409 "superseded", and must NOT record a terminal "removed"
// state off that report. Tests both halves side by side: the superseded
// case (409, no terminal state) and the normal case (200 "proceed", terminal
// state recorded) against the SAME device, so the contrast is exact.
func TestAgentDecommissionStatusHandler_SupersededAfterCancellationStopsAgent(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-r3fB-cancel-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "66666666-7777-8888-9999-aaaaaaaaaaa2", "r3fB-cancel-host")
	bearerToken := "pat1108-r3fB-device-token"
	hmacSecret := "pat1108-r3fB-device-hmac-sec32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	// The device fetches and is about to act on directive N.
	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveN int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveN); err != nil {
		t.Fatalf("query directive_version N: %v", err)
	}

	// The tenant cancels BEFORE the device's report arrives — this is the
	// cancellation path the design otherwise lacks.
	rrCancel := adPutDecommission(pool, tenantID, `{"mode":"none","actor":"andy@patched.im"}`)
	if rrCancel.Code != http.StatusOK {
		t.Fatalf("cancellation PUT status = %d, want 200: %s", rrCancel.Code, rrCancel.Body.String())
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	// The device's last word — "removed", against the now-cancelled
	// directive N — arrives after the cancellation.
	reqRemoved := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"clean removal","directive_version":%d}`, directiveN))
	rrRemoved := httptest.NewRecorder()
	handler(rrRemoved, reqRemoved)
	if rrRemoved.Code != http.StatusConflict {
		t.Fatalf("status report POST for a cancelled directive status = %d, want 409 — the server must tell the agent to STOP, not confirm a removal it knows was called off: %s", rrRemoved.Code, rrRemoved.Body.String())
	}
	var respRemoved map[string]string
	if err := json.Unmarshal(rrRemoved.Body.Bytes(), &respRemoved); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respRemoved["decommission"] != "superseded" {
		t.Errorf("decommission in response = %q, want superseded", respRemoved["decommission"])
	}

	// No terminal "removed" state may have been recorded off this report.
	var rowCountAfterCancel int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCountAfterCancel); err != nil {
		t.Fatalf("count device_decommission_state rows: %v", err)
	}
	if rowCountAfterCancel != 0 {
		var leakedStatus string
		_ = pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&leakedStatus)
		t.Fatalf("device_decommission_state row exists after a superseded report (status=%q) — a terminal state must never be recorded off a cancelled directive's report", leakedStatus)
	}
	devices := adFetchDevices(t, pool, tenantID)
	if devices[deviceID] != "pending" {
		t.Errorf("displayed device status after superseded report = %q, want pending — must never show as removed", devices[deviceID])
	}

	// Contrast: a NEW, live directive M is issued, and the device reports
	// against M correctly. This time it must proceed and the terminal
	// state must actually be recorded.
	rrReissue := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrReissue.Code != http.StatusOK {
		t.Fatalf("re-issue PUT status = %d, want 200: %s", rrReissue.Code, rrReissue.Body.String())
	}
	var directiveM int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveM); err != nil {
		t.Fatalf("query directive_version M: %v", err)
	}

	reqOK := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"clean removal","directive_version":%d}`, directiveM))
	rrOK := httptest.NewRecorder()
	handler(rrOK, reqOK)
	if rrOK.Code != http.StatusOK {
		t.Fatalf("status report POST for the live directive M status = %d, want 200: %s", rrOK.Code, rrOK.Body.String())
	}
	var respOK map[string]string
	if err := json.Unmarshal(rrOK.Body.Bytes(), &respOK); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respOK["decommission"] != "proceed" {
		t.Errorf("decommission in response = %q, want proceed", respOK["decommission"])
	}
	if respOK["recorded_status"] != "removed" {
		t.Errorf("recorded_status in response = %q, want removed", respOK["recorded_status"])
	}

	var statusAfterM string
	if err := pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&statusAfterM); err != nil {
		t.Fatalf("query device_decommission_state after live-directive report: %v", err)
	}
	if statusAfterM != "removed" {
		t.Errorf("stored status after the live-directive report = %q, want removed", statusAfterM)
	}
	devices = adFetchDevices(t, pool, tenantID)
	if devices[deviceID] != "removed" {
		t.Errorf("displayed device status after live-directive report = %q, want removed", devices[deviceID])
	}
}

// ---------------------------------------------------------------------------
// PAT-1108 fourth-round non-author-review fix regression tests (P1-1, P1-2)
// ---------------------------------------------------------------------------

// TestAgentDecommissionStatusHandler_ConcurrentCancellationNeverYieldsProceed
// is the P1-1 regression: the proceed gate must be atomic. It drives a
// deterministic interleaving, mirroring
// TestLockTenantAndReadDecommissionState_SerializesConcurrentWrites, but this
// time the second actor is the REAL AgentDecommissionStatusHandler rather
// than a direct call to the locking helper — proving the fix end to end, not
// just the underlying primitive.
//
// tx1 takes the same tenants-row lock the fixed handler now takes (via
// lockTenantAndReadDecommissionState) and, while still holding it uncommitted,
// flips the tenant's directive to mode="none" — simulating a cancellation
// that is "in flight" for the entire time the status report is trying to
// decide proceed/superseded. Before the fix this handler read the tenant's
// current directive through the pool with no lock at all, so this
// cancellation could commit in the gap between that read and the handler's
// response, and the report would still see the PRE-cancellation state and
// answer "proceed". After the fix, the handler's own transaction blocks on
// tx1's lock and, once tx1 commits, is guaranteed to observe the
// cancellation — so it must answer 409 "superseded", never "proceed", no
// matter how the goroutines are scheduled.
func TestAgentDecommissionStatusHandler_ConcurrentCancellationNeverYieldsProceed(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p1atomic-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "77777777-8888-9999-aaaa-bbbbbbbbbbb1", "p1atomic-host")
	bearerToken := "pat1108-p1atomic-device-token"
	hmacSecret := "pat1108-p1atomic-device-hmac32!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveN int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveN); err != nil {
		t.Fatalf("query directive_version N: %v", err)
	}

	// tx1 simulates a cancellation that has been decided but not yet
	// committed — the exact race window P1-1 closes. It takes the SAME
	// tenants-row lock the fixed handler takes, via the SAME helper.
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()

	exists1, oldMode1, _, _, _, _, err := lockTenantAndReadDecommissionState(ctx, tx1, tenantID)
	if err != nil {
		t.Fatalf("tx1 lock and read: %v", err)
	}
	if !exists1 || oldMode1 == nil || *oldMode1 != "immediate" {
		t.Fatalf("tx1 precondition failed: exists=%v oldMode=%v, want immediate", exists1, oldMode1)
	}
	if _, err := tx1.Exec(ctx, `UPDATE tenant_decommission SET mode = 'none' WHERE tenant_id = $1::uuid`, tenantID); err != nil {
		t.Fatalf("tx1 cancel directive: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	req := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"about to self-destruct","directive_version":%d}`, directiveN))

	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		rr := httptest.NewRecorder()
		handler(rr, req)
		done <- result{rr.Code, rr.Body.String()}
	}()

	select {
	case res := <-done:
		t.Fatalf("status handler returned (code=%d body=%s) while tx1 held the tenants lock with an uncommitted cancellation — "+
			"the proceed gate is not serialising against a concurrent cancellation, exactly the P1-1 race", res.code, res.body)
	case <-time.After(2 * time.Second):
		// Expected: the handler's own transaction is blocked on tx1's
		// tenants-row lock.
	}

	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1 (the cancellation): %v", err)
	}
	res := <-done

	if res.code != http.StatusConflict {
		t.Fatalf("status handler code = %d, want 409 — a cancellation that committed before the handler decided must supersede, NEVER proceed with an irreversible removal: %s", res.code, res.body)
	}
	var resp map[string]string
	if err := json.Unmarshal([]byte(res.body), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["decommission"] != "superseded" {
		t.Errorf("decommission in response = %q, want superseded", resp["decommission"])
	}

	// No terminal "removed" state may have been recorded off this report.
	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCount); err != nil {
		t.Fatalf("count device_decommission_state rows: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("device_decommission_state row count = %d, want 0 — the report must never be recorded once the tenant's directive was cancelled out from under it", rowCount)
	}
}

// TestAgentDecommissionStatusHandler_ExpiryNotYetPassedNeverYieldsProceed is
// the P1-2 regression: the proceed gate for mode="expiry" must compare
// expires_at against the SERVER's own clock, not merely check that mode !=
// "none". A device reporting "removed" against a live expiry directive whose
// deadline has NOT yet passed — including, as here, a device that claims the
// deadline has passed when the server's own clock says otherwise — must get
// "superseded" (409), never "proceed": the untrusted-device-clock problem the
// finding is about. The contrast half of the test then re-issues the SAME
// mode with an expires_at already in the past and confirms the identical
// device DOES get "proceed" — proving the gate is a genuine time check, not
// an expiry-mode directive being unconditionally refused.
func TestAgentDecommissionStatusHandler_ExpiryNotYetPassedNeverYieldsProceed(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p2expiry-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "77777777-8888-9999-aaaa-bbbbbbbbbbb2", "p2expiry-host")
	bearerToken := "pat1108-p2expiry-device-token"
	hmacSecret := "pat1108-p2expiry-device-hmac32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	futureExpiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	rrPut := adPutDecommission(pool, tenantID, fmt.Sprintf(`{"mode":"expiry","expires_at":%q,"actor":"andy@patched.im"}`, futureExpiresAt))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT expiry directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion); err != nil {
		t.Fatalf("query directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	// The device reports "removed" as if its deadline had already passed —
	// exactly what a device with a wrong or deliberately advanced system
	// clock would send. The server must refuse based on ITS OWN clock.
	reqEarly := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"claims deadline passed","directive_version":%d}`, directiveVersion))
	rrEarly := httptest.NewRecorder()
	handler(rrEarly, reqEarly)
	if rrEarly.Code != http.StatusConflict {
		t.Fatalf("status report before expires_at has passed = %d, want 409 — mode=expiry must never authorise removal before the SERVER's clock shows the deadline has passed: %s", rrEarly.Code, rrEarly.Body.String())
	}
	var respEarly map[string]string
	if err := json.Unmarshal(rrEarly.Body.Bytes(), &respEarly); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respEarly["decommission"] != "superseded" {
		t.Errorf("decommission in response = %q, want superseded", respEarly["decommission"])
	}

	var rowCountEarly int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCountEarly); err != nil {
		t.Fatalf("count device_decommission_state rows: %v", err)
	}
	if rowCountEarly != 0 {
		t.Errorf("device_decommission_state row count = %d, want 0 — a premature expiry report must never be recorded as a terminal outcome", rowCountEarly)
	}
	devicesEarly := adFetchDevices(t, pool, tenantID)
	if devicesEarly[deviceID] != "pending" {
		t.Errorf("displayed device status before expiry = %q, want pending", devicesEarly[deviceID])
	}

	// Contrast: the SAME mode, re-issued with expires_at already in the
	// past, must proceed — this is a genuine time check, not mode="expiry"
	// being permanently refused.
	pastExpiresAt := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rrPutPast := adPutDecommission(pool, tenantID, fmt.Sprintf(`{"mode":"expiry","expires_at":%q,"actor":"andy@patched.im"}`, pastExpiresAt))
	if rrPutPast.Code != http.StatusOK {
		t.Fatalf("PUT past-expiry directive status = %d, want 200: %s", rrPutPast.Code, rrPutPast.Body.String())
	}
	var pastDirectiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&pastDirectiveVersion); err != nil {
		t.Fatalf("query directive_version after past-expiry PUT: %v", err)
	}

	reqPast := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"deadline genuinely passed","directive_version":%d}`, pastDirectiveVersion))
	rrPast := httptest.NewRecorder()
	handler(rrPast, reqPast)
	if rrPast.Code != http.StatusOK {
		t.Fatalf("status report after expires_at has passed = %d, want 200 (proceed): %s", rrPast.Code, rrPast.Body.String())
	}
	var respPast map[string]string
	if err := json.Unmarshal(rrPast.Body.Bytes(), &respPast); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respPast["decommission"] != "proceed" {
		t.Errorf("decommission in response = %q, want proceed — expires_at has genuinely passed by the server's clock", respPast["decommission"])
	}
	if respPast["recorded_status"] != "removed" {
		t.Errorf("recorded_status in response = %q, want removed", respPast["recorded_status"])
	}

	devicesPast := adFetchDevices(t, pool, tenantID)
	if devicesPast[deviceID] != "removed" {
		t.Errorf("displayed device status after genuine expiry = %q, want removed", devicesPast[deviceID])
	}
}

// TestAgentDecommissionStatusHandler_AcknowledgedPersistsBeforeExpiryPasses is
// the P1-A regression, found by independent non-author review as a
// regression the P1-2 fix above introduced: the original P1-2 fix folded
// "does the directive currently AUTHORISE REMOVAL" into isSuperseded
// unconditionally, which then gated EVERY reportable status, not just
// terminal ones. That meant a device reporting the non-terminal
// "acknowledged" against a live mode="expiry" directive whose deadline had
// not yet passed got 409 "superseded" and was never persisted — contradicting
// the documented pending -> acknowledged transition (contracts/agent-config-schema.md)
// and making the two-phase report protocol (acknowledged before acting,
// terminal outcome after — PAT-1108 fourth-round finding P1-B) impossible,
// since its first phase could never land.
//
// PAT-1108 sixth-round finding P1-F revises this test's expectations for the
// acknowledged report itself: P1-A's fix correctly separated PERSISTENCE
// (acknowledged should be written whenever the directive is live) from what
// used to be a single "proceed" response, but it left AUTHORISATION
// (whether the response says "proceed") gated on liveness for phase 1 too —
// which is wrong under the two-phase protocol, because the agent's removal
// ATTEMPT happens BETWEEN phase 1 and phase 2. A response that only refuses
// authorisation on the TERMINAL report arrives after removal has already
// happened; it is too late to prevent anything. The only response that can
// actually prevent an irreversible action is the one the agent receives
// BEFORE attempting it — phase 1's. So authorisation must be gated on
// directiveAuthorisesRemoval for EVERY phase, including "acknowledged": this
// test now expects the acknowledged report to PERSIST (proving P1-A's fix)
// while its response says "superseded" (proving P1-F's fix) — the report
// sticking and the response refusing authorisation are not in tension; they
// are exactly the two different questions the fix separates.
func TestAgentDecommissionStatusHandler_AcknowledgedPersistsBeforeExpiryPasses(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p1a-ack-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "77777777-8888-9999-aaaa-bbbbbbbbbbb3", "p1a-ack-host")
	bearerToken := "pat1108-p1a-ack-device-token"
	hmacSecret := "pat1108-p1a-ack-device-hmac32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	futureExpiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	rrPut := adPutDecommission(pool, tenantID, fmt.Sprintf(`{"mode":"expiry","expires_at":%q,"actor":"andy@patched.im"}`, futureExpiresAt))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT expiry directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion); err != nil {
		t.Fatalf("query directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	// Phase one: "acknowledged", well before expires_at. Must PERSIST (P1-A)
	// but its response must NOT authorise removal (P1-F) — the server's
	// clock has not reached expires_at yet, and this is the only response
	// the agent sees before it would attempt removal.
	reqAck := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"acknowledged","detail":"seen the directive, about to act","directive_version":%d}`, directiveVersion))
	rrAck := httptest.NewRecorder()
	handler(rrAck, reqAck)
	if rrAck.Code != http.StatusConflict {
		t.Fatalf("acknowledged report before expiry status = %d, want 409 — phase 1's response is the only one that can prevent an early removal attempt, so it must refuse authorisation before the deadline has passed: %s", rrAck.Code, rrAck.Body.String())
	}
	var respAck map[string]string
	if err := json.Unmarshal(rrAck.Body.Bytes(), &respAck); err != nil {
		t.Fatalf("decode acknowledged response: %v", err)
	}
	if respAck["decommission"] != "superseded" {
		t.Errorf("decommission in acknowledged response = %q, want superseded — persisted does not mean authorised", respAck["decommission"])
	}
	if respAck["recorded_status"] != "acknowledged" {
		t.Errorf("recorded_status in acknowledged response = %q, want acknowledged — the report DID persist, only the response's authorisation is refused", respAck["recorded_status"])
	}

	var storedStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&storedStatus); err != nil {
		t.Fatalf("query device_decommission_state after acknowledged report: %v", err)
	}
	if storedStatus != "acknowledged" {
		t.Errorf("stored status after acknowledged report = %q, want acknowledged", storedStatus)
	}
	devicesAfterAck := adFetchDevices(t, pool, tenantID)
	if devicesAfterAck[deviceID] != "acknowledged" {
		t.Errorf("displayed device status after acknowledged report = %q, want acknowledged (not stuck at pending)", devicesAfterAck[deviceID])
	}

	// Contrast: a TERMINAL report against the SAME still-unexpired directive
	// must still be refused — P1-2's actual guarantee must survive.
	reqRemoved := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"too early","directive_version":%d}`, directiveVersion))
	rrRemoved := httptest.NewRecorder()
	handler(rrRemoved, reqRemoved)
	if rrRemoved.Code != http.StatusConflict {
		t.Fatalf("terminal report before expiry status = %d, want 409 — removal authorisation must still be refused before the deadline passes: %s", rrRemoved.Code, rrRemoved.Body.String())
	}
	var respRemoved map[string]string
	if err := json.Unmarshal(rrRemoved.Body.Bytes(), &respRemoved); err != nil {
		t.Fatalf("decode removed response: %v", err)
	}
	if respRemoved["decommission"] != "superseded" {
		t.Errorf("decommission in premature-removed response = %q, want superseded", respRemoved["decommission"])
	}

	// The device's true stored status must remain "acknowledged" — the
	// refused terminal report must not have been recorded.
	var statusAfterRefusedTerminal string
	if err := pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&statusAfterRefusedTerminal); err != nil {
		t.Fatalf("query device_decommission_state after refused terminal report: %v", err)
	}
	if statusAfterRefusedTerminal != "acknowledged" {
		t.Errorf("stored status after a refused premature terminal report = %q, want acknowledged (unchanged)", statusAfterRefusedTerminal)
	}
}

// TestTenantDecommissionAudit_AppendOnly is the P2 regression: migration
// 0091 runs as role `patched` (see its "Apply with" header), which makes
// `patched` the OWNER of tenant_decommission_audit — and ownership is not
// something GRANT/REVOKE can take away from the owner. Granting only
// SELECT/INSERT documented an append-only intent that enforced nothing
// against the very role making every write in production. This test proves
// migrations/0091_agent_decommission.sql's
// trg_tenant_decommission_audit_append_only trigger actually rejects both
// UPDATE and DELETE against a real audit row written through the real PUT
// handler — using the plain pool (the owning role), not some other,
// lesser-privileged role, so this is exactly the case the finding says was
// previously unenforced.
func TestTenantDecommissionAudit_AppendOnly(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p2-audit-tenant")

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}

	var auditID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`, tenantID).Scan(&auditID); err != nil {
		t.Fatalf("fetch audit row id: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE tenant_decommission_audit SET new_mode = 'none' WHERE id = $1`, auditID); err == nil {
		t.Fatal("UPDATE on tenant_decommission_audit succeeded, want rejected — the audit trail must be append-only even for the table-owning role")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("UPDATE error = %v, want an append-only rejection from trg_tenant_decommission_audit_append_only", err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM tenant_decommission_audit WHERE id = $1`, auditID); err == nil {
		t.Fatal("DELETE on tenant_decommission_audit succeeded, want rejected — the audit trail must be append-only even for the table-owning role")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("DELETE error = %v, want an append-only rejection from trg_tenant_decommission_audit_append_only", err)
	}

	// PAT-1108 fifth-round finding P1-C: the UPDATE/DELETE trigger above is
	// ROW-level and Postgres never fires row-level triggers for TRUNCATE —
	// TRUNCATE has no per-row execution at all — so it bypasses BEFORE
	// UPDATE OR DELETE entirely and could erase the WHOLE audit trail in
	// one statement without this separate STATEMENT-level trigger.
	if _, err := pool.Exec(ctx, `TRUNCATE tenant_decommission_audit`); err == nil {
		t.Fatal("TRUNCATE on tenant_decommission_audit succeeded, want rejected — a row-level trigger alone does not stop TRUNCATE")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("TRUNCATE error = %v, want an append-only rejection from trg_tenant_decommission_audit_append_only_truncate", err)
	}

	// The row must be completely unaffected by any of the three rejected
	// attempts.
	var newMode string
	if err := pool.QueryRow(ctx, `SELECT new_mode FROM tenant_decommission_audit WHERE id = $1`, auditID).Scan(&newMode); err != nil {
		t.Fatalf("re-fetch audit row after rejected mutations: %v", err)
	}
	if newMode != "immediate" {
		t.Errorf("new_mode after rejected UPDATE/DELETE/TRUNCATE attempts = %q, want unchanged %q", newMode, "immediate")
	}
	var auditRowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`, tenantID).Scan(&auditRowCount); err != nil {
		t.Fatalf("count audit rows after rejected TRUNCATE: %v", err)
	}
	if auditRowCount != 1 {
		t.Errorf("audit row count after rejected TRUNCATE = %d, want 1 (unaffected)", auditRowCount)
	}
}

// TestTenantDecommissionPut_AuditAttribution pins the PAT-1135 property: the
// admin surface authenticates with a single shared ADMIN_API_TOKEN and has
// no per-person identity (see requireAdminToken, cmd/patched-api/main.go),
// so a request body that CLAIMS actor="alice" must never land in the
// authoritative actor column of either write this handler makes —
// tenant_decommission.set_by and tenant_decommission_audit.actor. Both must
// always be the server-established constant "admin_shared_token"; the
// caller's claim goes only into tenant_decommission_audit.claimed_actor
// (untrusted, clearly named), and source_addr must be populated from the
// observed request address. This is the FIRST of the two required audit
// tables for PAT-1135's brief; see TestSetTenantTierDB_AuditAttribution
// (admin_tier_test.go) for the second (tenant_tier_changes).
func TestTenantDecommissionPut_AuditAttribution(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1135-audit-attribution-tenant")

	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/decommission",
		strings.NewReader(`{"mode":"immediate","actor":"alice"}`))
	req = adWithTenantID(req, tenantID)
	req.RemoteAddr = "198.51.100.9:12345"
	rr := httptest.NewRecorder()
	TenantDecommissionPutHandler(pool)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	// tenant_decommission.set_by must be the server-established actor, not
	// the caller's claimed "alice".
	var setBy string
	if err := pool.QueryRow(ctx, `SELECT set_by FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&setBy); err != nil {
		t.Fatalf("fetch tenant_decommission.set_by: %v", err)
	}
	if setBy != adminSharedTokenActor {
		t.Errorf("tenant_decommission.set_by = %q, want %q (must never be the caller's claimed name)", setBy, adminSharedTokenActor)
	}

	// tenant_decommission_audit.actor must likewise be the server-established
	// actor; claimed_actor must carry the caller's claim verbatim; source_addr
	// must be populated (port stripped) from the observed request address.
	var auditActor string
	var claimedActor *string
	var sourceAddr *string
	if err := pool.QueryRow(ctx, `
		SELECT actor, claimed_actor, source_addr FROM tenant_decommission_audit
		WHERE tenant_id = $1::uuid ORDER BY changed_at DESC LIMIT 1
	`, tenantID).Scan(&auditActor, &claimedActor, &sourceAddr); err != nil {
		t.Fatalf("fetch tenant_decommission_audit row: %v", err)
	}
	if auditActor != adminSharedTokenActor {
		t.Errorf("tenant_decommission_audit.actor = %q, want %q (must never be the caller's claimed name)", auditActor, adminSharedTokenActor)
	}
	if claimedActor == nil || *claimedActor != "alice" {
		t.Errorf("tenant_decommission_audit.claimed_actor = %v, want \"alice\"", claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "198.51.100.9" {
		t.Errorf("tenant_decommission_audit.source_addr = %v, want \"198.51.100.9\" (port stripped)", sourceAddr)
	}
}

// adDeviceEntryFull mirrors report.TenantDecommissionDeviceEntry for tests
// that need the P1-E flag, unlike adFetchDevices' status-only map.
type adDeviceEntryFull struct {
	DeviceID                       string `json:"device_id"`
	Status                         string `json:"status"`
	TerminalWithoutAcknowledgement bool   `json:"terminal_without_acknowledgement"`
}

// adFetchDevicesFull drives TenantDecommissionDevicesHandler and returns a
// deviceID -> full entry map, for tests that need fields beyond status (see
// adFetchDevices).
func adFetchDevicesFull(t *testing.T, pool *pgxpool.Pool, tenantID string) map[string]adDeviceEntryFull {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/decommission/devices", nil)
	req = adWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantDecommissionDevicesHandler(pool)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("devices fetch status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Devices []adDeviceEntryFull `json:"devices"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode devices response: %v", err)
	}
	out := map[string]adDeviceEntryFull{}
	for _, d := range resp.Devices {
		out[d.DeviceID] = d
	}
	return out
}

// TestAgentDecommissionStatusHandler_TerminalWithoutAcknowledgementFlagged is
// the P1-E regression. The finding: a terminal removed/failed report can
// create a brand-new device row with no prior acknowledged for that
// directive generation, so a buggy or spurious client can manufacture a
// sticky, irreversible false "removed" without phase 1 (acknowledged) ever
// happening. The decision recorded in AgentDecommissionStatusHandler's
// package doc comment is NOT to reject such a report (that would risk
// discarding a genuine last word whose earlier acknowledged call was merely
// lost in transit) but to ACCEPT it while recording that phase 1 was never
// observed, surfaced via device_decommission_state.phase1_observed and
// report.FetchTenantDecommissionDevices' terminal_without_acknowledgement
// field.
//
// Drives two devices side by side under the SAME directive for direct
// contrast: deviceA reports "removed" with NO prior "acknowledged" at all
// (the anomalous case), deviceB reports "acknowledged" then "removed" for
// the SAME directive_version (the clean, documented two-phase case). Both
// must be accepted (200, proceed) — the finding is explicitly not about
// rejection — but only deviceA's entry must come back flagged.
func TestAgentDecommissionStatusHandler_TerminalWithoutAcknowledgementFlagged(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p1e-flag-tenant")
	deviceA := adSeedDevice(t, ctx, pool, tenantID, "88888888-9999-aaaa-bbbb-ccccccccccc1", "p1e-no-phase1-host")
	deviceB := adSeedDevice(t, ctx, pool, tenantID, "88888888-9999-aaaa-bbbb-ccccccccccc2", "p1e-clean-host")
	tokenA, hmacA := "pat1108-p1e-device-a-token", "pat1108-p1e-device-a-hmac32b!"
	tokenB, hmacB := "pat1108-p1e-device-b-token", "pat1108-p1e-device-b-hmac32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceA, tokenA, hmacA)
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceB, tokenB, hmacB)

	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion); err != nil {
		t.Fatalf("query directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)

	// deviceA: straight to "removed", no acknowledged ever reported — the
	// anomalous case the finding describes.
	reqA := adSignedDecommissionStatusReq(t, tokenA, hmacA,
		fmt.Sprintf(`{"status":"removed","detail":"no phase 1 observed","directive_version":%d}`, directiveVersion))
	rrA := httptest.NewRecorder()
	handler(rrA, reqA)
	if rrA.Code != http.StatusOK {
		t.Fatalf("deviceA (no phase 1) report status = %d, want 200 — the finding is that this must be ACCEPTED, not rejected: %s", rrA.Code, rrA.Body.String())
	}
	var respA map[string]string
	if err := json.Unmarshal(rrA.Body.Bytes(), &respA); err != nil {
		t.Fatalf("decode deviceA response: %v", err)
	}
	if respA["decommission"] != "proceed" || respA["recorded_status"] != "removed" {
		t.Errorf("deviceA response = %+v, want proceed/removed", respA)
	}

	// deviceB: "acknowledged" first (phase 1, genuinely observed)...
	reqBAck := adSignedDecommissionStatusReq(t, tokenB, hmacB,
		fmt.Sprintf(`{"status":"acknowledged","detail":"phase 1","directive_version":%d}`, directiveVersion))
	rrBAck := httptest.NewRecorder()
	handler(rrBAck, reqBAck)
	if rrBAck.Code != http.StatusOK {
		t.Fatalf("deviceB acknowledged report status = %d, want 200: %s", rrBAck.Code, rrBAck.Body.String())
	}
	// ...then "removed" for the SAME directive_version — the clean,
	// documented two-phase sequence.
	reqBRemoved := adSignedDecommissionStatusReq(t, tokenB, hmacB,
		fmt.Sprintf(`{"status":"removed","detail":"clean two-phase removal","directive_version":%d}`, directiveVersion))
	rrBRemoved := httptest.NewRecorder()
	handler(rrBRemoved, reqBRemoved)
	if rrBRemoved.Code != http.StatusOK {
		t.Fatalf("deviceB removed report status = %d, want 200: %s", rrBRemoved.Code, rrBRemoved.Body.String())
	}

	// DB-level: phase1_observed must be false for deviceA, true for deviceB.
	var phase1A, phase1B bool
	if err := pool.QueryRow(ctx, `SELECT phase1_observed FROM device_decommission_state WHERE device_id = $1::uuid`, deviceA).Scan(&phase1A); err != nil {
		t.Fatalf("query deviceA phase1_observed: %v", err)
	}
	if phase1A {
		t.Errorf("deviceA phase1_observed = true, want false — no acknowledged report was ever made for this directive")
	}
	if err := pool.QueryRow(ctx, `SELECT phase1_observed FROM device_decommission_state WHERE device_id = $1::uuid`, deviceB).Scan(&phase1B); err != nil {
		t.Fatalf("query deviceB phase1_observed: %v", err)
	}
	if !phase1B {
		t.Errorf("deviceB phase1_observed = false, want true — an acknowledged report for the SAME directive_version was genuinely observed first")
	}

	// Admin-visible read path: only deviceA's entry is flagged.
	devices := adFetchDevicesFull(t, pool, tenantID)
	entryA, ok := devices[deviceA]
	if !ok {
		t.Fatalf("deviceA missing from devices response")
	}
	if entryA.Status != "removed" {
		t.Errorf("deviceA status = %q, want removed", entryA.Status)
	}
	if !entryA.TerminalWithoutAcknowledgement {
		t.Errorf("deviceA terminal_without_acknowledgement = false, want true — a manufactured/short-circuited removal must be visibly anomalous")
	}
	entryB, ok := devices[deviceB]
	if !ok {
		t.Fatalf("deviceB missing from devices response")
	}
	if entryB.Status != "removed" {
		t.Errorf("deviceB status = %q, want removed", entryB.Status)
	}
	if entryB.TerminalWithoutAcknowledgement {
		t.Errorf("deviceB terminal_without_acknowledgement = true, want false — a clean two-phase removal must NOT be flagged")
	}
}

// TestAgentDecommissionStatusHandler_PhaseOneAuthorisationGatedOnExpiryNotLiveness
// is the P1-F regression — the coordinator's own correction of round five's
// P1-A fix, caught by a fresh non-author review pass. Round five gated the
// phase 1 "acknowledged" response's authorisation on mere directive
// liveness, not on whether the directive currently authorises removal. That
// was wrong under the two-phase protocol specifically because the agent's
// removal ATTEMPT happens BETWEEN phase 1 and phase 2: a phase 2 response
// that says "too early" arrives after removal has already happened and
// prevents nothing. Only phase 1's response can actually stop an early
// attempt, so it must carry the SAME authorisation gate a terminal report
// does.
//
// Drives ONE device through the full timeline against a SINGLE mode="expiry"
// directive with a short, real expiry window (no re-issue, no second
// directive — this is deliberately "the same device, the same directive,
// time passing", not a new-directive workaround):
//
//  1. "acknowledged" BEFORE expires_at: must PERSIST (proves P1-A is not
//     regressed) but its response must say "superseded" (proves P1-F) —
//     this is the one response that could have stopped an early removal
//     attempt, so it must refuse.
//  2. After expires_at genuinely passes (a short real sleep, not a
//     re-issued directive), the SAME device reports "acknowledged" again
//     for the SAME directive_version: now authorised, "proceed".
//  3. The device then completes the documented sequence for real: a
//     terminal "removed" report for that SAME directive_version is
//     accepted and authorised, exactly as round five's P1-E/P1-2 tests
//     already establish for the terminal side — included here for an
//     end-to-end contrast against step 1's refusal.
func TestAgentDecommissionStatusHandler_PhaseOneAuthorisationGatedOnExpiryNotLiveness(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p1f-phase1auth-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "99999999-aaaa-bbbb-cccc-ddddddddddd1", "p1f-phase1auth-host")
	bearerToken := "pat1108-p1f-phase1auth-token"
	hmacSecret := "pat1108-p1f-phase1auth-hmac32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)

	// A short, real expiry window — no re-issue, so this is genuinely "the
	// same directive, time advancing", not a workaround via a second PUT.
	// 2s matches this file's other real-time budgets (e.g. the lock tests'
	// 2-second blocking window) rather than a tight margin that would make
	// this test flaky under ordinary DB/CI latency.
	const expiryWindow = 2 * time.Second
	expiresAt := time.Now().Add(expiryWindow).UTC().Format(time.RFC3339)
	rrPut := adPutDecommission(pool, tenantID, fmt.Sprintf(`{"mode":"expiry","expires_at":%q,"actor":"andy@patched.im"}`, expiresAt))
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT expiry directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}
	var directiveVersion int
	if err := pool.QueryRow(ctx, `SELECT directive_version FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&directiveVersion); err != nil {
		t.Fatalf("query directive_version: %v", err)
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	ackReq := func() *http.Request {
		return adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
			fmt.Sprintf(`{"status":"acknowledged","detail":"phase 1","directive_version":%d}`, directiveVersion))
	}

	// Step 1: acknowledged BEFORE expires_at.
	rr1 := httptest.NewRecorder()
	handler(rr1, ackReq())
	if rr1.Code != http.StatusConflict {
		t.Fatalf("acknowledged before expiry status = %d, want 409 — phase 1's response is the only one that can prevent an early removal attempt: %s", rr1.Code, rr1.Body.String())
	}
	var resp1 map[string]string
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("decode step 1 response: %v", err)
	}
	if resp1["decommission"] != "superseded" {
		t.Errorf("step 1 decommission = %q, want superseded", resp1["decommission"])
	}
	if resp1["recorded_status"] != "acknowledged" {
		t.Errorf("step 1 recorded_status = %q, want acknowledged — persisted despite the refused authorisation", resp1["recorded_status"])
	}
	var statusAfterStep1 string
	if err := pool.QueryRow(ctx, `SELECT status FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&statusAfterStep1); err != nil {
		t.Fatalf("query status after step 1: %v", err)
	}
	if statusAfterStep1 != "acknowledged" {
		t.Errorf("stored status after step 1 = %q, want acknowledged", statusAfterStep1)
	}

	// Let the SAME directive's expires_at genuinely pass — no re-issue.
	time.Sleep(expiryWindow + 500*time.Millisecond)

	// Step 2: the SAME device reports "acknowledged" again, for the SAME
	// directive_version — now authorised.
	rr2 := httptest.NewRecorder()
	handler(rr2, ackReq())
	if rr2.Code != http.StatusOK {
		t.Fatalf("acknowledged after expiry status = %d, want 200 — the SAME directive now genuinely authorises removal: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 map[string]string
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode step 2 response: %v", err)
	}
	if resp2["decommission"] != "proceed" {
		t.Errorf("step 2 decommission = %q, want proceed", resp2["decommission"])
	}
	if resp2["recorded_status"] != "acknowledged" {
		t.Errorf("step 2 recorded_status = %q, want acknowledged", resp2["recorded_status"])
	}

	// Step 3: contrast — the device now completes the documented sequence
	// for real, reporting the terminal outcome for the SAME directive_version.
	req3 := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret,
		fmt.Sprintf(`{"status":"removed","detail":"clean removal after genuine expiry","directive_version":%d}`, directiveVersion))
	rr3 := httptest.NewRecorder()
	handler(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("removed after expiry status = %d, want 200: %s", rr3.Code, rr3.Body.String())
	}
	var resp3 map[string]string
	if err := json.Unmarshal(rr3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("decode step 3 response: %v", err)
	}
	if resp3["decommission"] != "proceed" || resp3["recorded_status"] != "removed" {
		t.Errorf("step 3 response = %+v, want proceed/removed", resp3)
	}

	devices := adFetchDevicesFull(t, pool, tenantID)
	entry, ok := devices[deviceID]
	if !ok {
		t.Fatalf("device missing from devices response")
	}
	if entry.Status != "removed" {
		t.Errorf("final displayed status = %q, want removed", entry.Status)
	}
	if entry.TerminalWithoutAcknowledgement {
		t.Errorf("terminal_without_acknowledgement = true, want false — phase 1 was genuinely observed for this directive generation")
	}
}

// TestDirectiveVersionColumns_RejectNegativeValues is the P2 regression:
// migrations/0091_agent_decommission.sql now CHECKs directive_version >= 0
// on all three columns that carry a real directive generation
// (tenant_decommission, tenant_decommission_audit, device_decommission_state).
// Before this constraint, AgentDecommissionStatusHandler's fail-closed
// handling of an unattributed report depended entirely on the in-memory
// sentinel unattributedDirectiveVersion (-1) never being able to equal a
// STORED directive_version — a guarantee the schema itself did not enforce.
// A malformed or hand-written row holding -1 in any of these columns could
// have let an unattributed report resolve as "current" and return
// "proceed" for an immediate directive, defeating fail-closed handling on
// the irreversible removal path. This test proves the schema itself now
// makes that impossible, on all three columns.
func TestDirectiveVersionColumns_RejectNegativeValues(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := adSeedTenant(t, ctx, pool, "pat1108-p2-negative-directive-tenant")
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee1", "p2-negative-directive-host")

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_decommission (tenant_id, mode, purge, set_by, directive_version)
		VALUES ($1::uuid, 'immediate', false, 'test', -1)
	`, tenantID); err == nil {
		t.Error("INSERT into tenant_decommission with directive_version = -1 succeeded, want rejected by tenant_decommission_directive_version_non_negative")
	} else if !strings.Contains(err.Error(), "tenant_decommission_directive_version_non_negative") {
		t.Errorf("tenant_decommission negative-directive_version error = %v, want the non_negative CHECK constraint", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_decommission_audit (tenant_id, actor, old_mode, new_mode, purge, directive_version)
		VALUES ($1::uuid, 'test', NULL, 'immediate', false, -1)
	`, tenantID); err == nil {
		t.Error("INSERT into tenant_decommission_audit with directive_version = -1 succeeded, want rejected by tenant_decommission_audit_directive_version_non_negative")
	} else if !strings.Contains(err.Error(), "tenant_decommission_audit_directive_version_non_negative") {
		t.Errorf("tenant_decommission_audit negative-directive_version error = %v, want the non_negative CHECK constraint", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO device_decommission_state (device_id, status, directive_version)
		VALUES ($1::uuid, 'acknowledged', -1)
	`, deviceID); err == nil {
		t.Error("INSERT into device_decommission_state with directive_version = -1 succeeded, want rejected by device_decommission_state_directive_version_non_negative")
	} else if !strings.Contains(err.Error(), "device_decommission_state_directive_version_non_negative") {
		t.Errorf("device_decommission_state negative-directive_version error = %v, want the non_negative CHECK constraint", err)
	}

	// No row from any of the three rejected inserts may have landed.
	var tdCount, auditCount, ddsCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_decommission WHERE tenant_id = $1::uuid`, tenantID).Scan(&tdCount); err != nil {
		t.Fatalf("count tenant_decommission rows: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_decommission_audit WHERE tenant_id = $1::uuid`, tenantID).Scan(&auditCount); err != nil {
		t.Fatalf("count tenant_decommission_audit rows: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&ddsCount); err != nil {
		t.Fatalf("count device_decommission_state rows: %v", err)
	}
	if tdCount != 0 || auditCount != 0 || ddsCount != 0 {
		t.Errorf("row counts after rejected negative-directive_version inserts = tenant_decommission:%d tenant_decommission_audit:%d device_decommission_state:%d, want all 0", tdCount, auditCount, ddsCount)
	}

	// The unattributed-report path must behave EXACTLY as it did before
	// this migration change: a missing directive_version is superseded and
	// never persisted, regardless of these new constraints (which this
	// path never actually touches — see unattributedDirectiveVersion's doc
	// comment — but the coordinator asked this to be proven, not assumed).
	bearerToken := "pat1108-p2-negative-directive-token"
	hmacSecret := "pat1108-p2-negative-directive-hmac32b!"
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, bearerToken, hmacSecret)
	rrPut := adPutDecommission(pool, tenantID, `{"mode":"immediate","actor":"andy@patched.im"}`)
	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT directive status = %d, want 200: %s", rrPut.Code, rrPut.Body.String())
	}

	handler := AgentDecommissionStatusHandler(pool, nil, 5*time.Minute)
	req := adSignedDecommissionStatusReq(t, bearerToken, hmacSecret, `{"status":"removed","detail":"no directive_version field"}`)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("unattributed report status = %d, want 409 (unchanged behaviour): %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["decommission"] != "superseded" {
		t.Errorf("decommission in response = %q, want superseded (unchanged behaviour)", resp["decommission"])
	}
	if _, hasRecordedStatus := resp["recorded_status"]; hasRecordedStatus {
		t.Errorf("response carries recorded_status %q for an unattributed report, want absent (unchanged behaviour)", resp["recorded_status"])
	}
	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_decommission_state WHERE device_id = $1::uuid`, deviceID).Scan(&rowCount); err != nil {
		t.Fatalf("count device_decommission_state rows after unattributed report: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("device_decommission_state row count after unattributed report = %d, want 0 (unchanged behaviour)", rowCount)
	}
}
