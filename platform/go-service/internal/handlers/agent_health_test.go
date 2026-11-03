package handlers

// DB-backed tests for GET /admin/tenants/{tenantID}/agent-health (PAT-1064).
// Before this file, the route had zero test coverage at any level — no auth
// inheritance, no tenant scoping, no 404/500 behaviour, no grouping, no
// totals, and no check on whether an empty result serialises as `[]` rather
// than `null` (review round 3, FIX 11). The latter matters concretely: the
// dashboard (PAT-1067) is the consumer, and a naive `for (const d of
// resp.devices)` breaks on `null`.
//
// Uses the same TEST_DATABASE_URL-gated, real-schema convention as
// allowlist_agent_known_path_test.go / admin_overview_db_test.go in this
// package (parConnectOrSkip, parSeedTenant) — reused directly rather than
// inventing new helpers. taWithTenantID (tenant_apps_test.go) is reused for
// chi URL-param injection, matching how TenantAppsHandler is tested; this
// route follows TenantBrowserExtensionsHandler's contract (404 via
// report.ErrTenantNotFound, tenantID UUID-shape check before any DB call),
// so the tests below match that convention rather than inventing a new one.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ahtInsertDevice inserts a devices row with an explicit hostname (so
// response assertions aren't stuck asserting against a raw device UUID) and
// registers cleanup.
func ahtInsertDevice(t *testing.T, pool *pgxpool.Pool, tenantID, hwUUID, hostname string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, hw_uuid, os, hostname)
		VALUES ($1::uuid, $2::uuid, 'macOS', $3)
		RETURNING id::text
	`, tenantID, hwUUID, hostname).Scan(&id); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, id) })
	return id
}

// ahtInsertDegraded writes one device_agent_health row directly (the
// extractor's own write path — upsertAgentHealth — is covered by
// internal/extractor's DB round-trip suite; this file's job is the READ
// side, so it seeds data straight into the table it reads from).
func ahtInsertDegraded(t *testing.T, pool *pgxpool.Pool, deviceID, kind, subject, reason string, count int64, everSucceeded bool) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO device_agent_health (device_id, kind, subject, reason, first_seen, last_seen, count, ever_succeeded, collected_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $5, $6, $7, $5)
	`, deviceID, kind, subject, reason, now, count, everSucceeded); err != nil {
		t.Fatalf("insert device_agent_health: %v", err)
	}
}

// TestTenantAgentHealthHandler_BadUUID mirrors
// TestTenantAppsHandlerBadUUID: the tenantID shape check must reject before
// any DB call, so this needs no database at all.
func TestTenantAgentHealthHandler_BadUUID(t *testing.T) {
	h := TenantAgentHealthHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/not-a-uuid/agent-health", nil)
	req = taWithTenantID(req, "not-a-uuid")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestTenantAgentHealthHandler_UnknownTenant proves a well-formed but
// nonexistent tenant UUID returns 404 — matching
// TenantBrowserExtensionsHandler's ErrTenantNotFound contract, not a new
// convention.
func TestTenantAgentHealthHandler_UnknownTenant(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	const unknownButWellFormed = "00000000-0000-0000-0000-000000000000"

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+unknownButWellFormed+"/agent-health", nil)
	req = taWithTenantID(req, unknownButWellFormed)
	rr := httptest.NewRecorder()
	TenantAgentHealthHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d: %s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// TestTenantAgentHealthHandler_EmptyResultIsArrayNotNull proves a tenant
// with zero degraded-capability rows gets back devices: [] — a genuine JSON
// array — not devices: null. This is the review round 3, FIX 11 finding:
// PAT-1067 (the dashboard) is the consumer, and a naive array-iteration
// consumer breaks on null where it would silently no-op on [].
func TestTenantAgentHealthHandler_EmptyResultIsArrayNotNull(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"ah-empty-result-tenant", "ah-empty-result-token", "ah-empty-result-hmac-secret-32b!")

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/agent-health", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAgentHealthHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	// Raw-string check FIRST: a decoded Go slice field can't tell "[]" apart
	// from "null" (both unmarshal to a nil/empty slice), so this is the part
	// of the test that actually proves the JSON shape, not just the Go value.
	body := rr.Body.String()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("decode response envelope: %v (body: %s)", err, body)
	}
	if devicesRaw := string(raw["devices"]); devicesRaw != "[]" {
		t.Errorf(`response "devices" field = %s, want the literal array "[]" (not null)`, devicesRaw)
	}

	var resp struct {
		TenantID string `json:"tenant_id"`
		Total    int    `json:"total"`
		Devices  []any  `json:"devices"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, body)
	}
	if resp.Total != 0 {
		t.Errorf("total = %d, want 0", resp.Total)
	}
	if resp.Devices == nil {
		t.Error("devices decoded to nil — response must serialise an empty array, not omit/null the field")
	}
}

// TestTenantAgentHealthHandler_GroupsAcrossDevicesWithTotal drives the real
// handler end-to-end: two devices, each with degraded entries, and proves
// the response groups entries under the correct device (by hostname and
// device_id), carries every field the dashboard needs to render "what was
// asked, why it could not be done, since when, how many times" without a
// second call, and sums to the right tenant-level total.
func TestTenantAgentHealthHandler_GroupsAcrossDevicesWithTotal(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"ah-grouping-tenant", "ah-grouping-token", "ah-grouping-hmac-secret-32b!!!!")

	deviceA := ahtInsertDevice(t, pool, tenantID, "11111111-2222-3333-4444-555555555555", "device-a-host")
	deviceB := ahtInsertDevice(t, pool, tenantID, "66666666-7777-8888-9999-000000000000", "device-b-host")

	ahtInsertDegraded(t, pool, deviceA, "directive_skipped", "log_upload", "device_id_mismatch", 1119, false)
	ahtInsertDegraded(t, pool, deviceA, "capability_missing", "extension_removal", "lib_not_installed", 1105, false)
	ahtInsertDegraded(t, pool, deviceB, "sync_never_succeeded", "catalogue", "fetch_failed", 40, true)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/agent-health", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantAgentHealthHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		TenantID string `json:"tenant_id"`
		Total    int    `json:"total"`
		Devices  []struct {
			DeviceID string `json:"device_id"`
			Hostname string `json:"hostname"`
			Degraded []struct {
				Kind          string `json:"kind"`
				Subject       string `json:"subject"`
				Reason        string `json:"reason"`
				Count         int64  `json:"count"`
				EverSucceeded bool   `json:"ever_succeeded"`
			} `json:"degraded"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}

	if resp.TenantID != tenantID {
		t.Errorf("tenant_id = %q, want %q", resp.TenantID, tenantID)
	}
	if resp.Total != 3 {
		t.Errorf("total = %d, want 3 (sum across both devices)", resp.Total)
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2: %+v", len(resp.Devices), resp.Devices)
	}

	byDeviceID := map[string]int{}
	for i, d := range resp.Devices {
		byDeviceID[d.DeviceID] = i
	}
	idxA, okA := byDeviceID[deviceA]
	idxB, okB := byDeviceID[deviceB]
	if !okA || !okB {
		t.Fatalf("response did not contain both seeded device IDs: %+v", resp.Devices)
	}

	devA := resp.Devices[idxA]
	if devA.Hostname != "device-a-host" {
		t.Errorf("device A hostname = %q, want device-a-host", devA.Hostname)
	}
	if len(devA.Degraded) != 2 {
		t.Fatalf("device A degraded len = %d, want 2: %+v", len(devA.Degraded), devA.Degraded)
	}

	devB := resp.Devices[idxB]
	if devB.Hostname != "device-b-host" {
		t.Errorf("device B hostname = %q, want device-b-host", devB.Hostname)
	}
	if len(devB.Degraded) != 1 {
		t.Fatalf("device B degraded len = %d, want 1: %+v", len(devB.Degraded), devB.Degraded)
	}
	got := devB.Degraded[0]
	if got.Kind != "sync_never_succeeded" || got.Subject != "catalogue" || got.Reason != "fetch_failed" {
		t.Errorf("device B entry = %+v, want kind=sync_never_succeeded subject=catalogue reason=fetch_failed", got)
	}
	if got.Count != 40 {
		t.Errorf("device B entry count = %d, want 40", got.Count)
	}
	if !got.EverSucceeded {
		t.Error("device B entry ever_succeeded = false, want true")
	}
}
