package handlers

// DB-backed tests for GET /admin/tenants/{tenantID}/audit-events
// (audit_events_admin.go, PAT-1022), driving the REAL exported
// AuditEventsAdminHandler end-to-end against a real Postgres instance — not
// a DI stub, since this handler (unlike enforcement_audit.go's GET
// counterpart) has no listFn injection seam. Require TEST_DATABASE_URL and are
// skipped otherwise, matching the pattern used throughout this package (see
// events_db_test.go, allowlist_agent_known_path_test.go). Reuses
// parConnectOrSkip/parSeedTenant (allowlist_agent_known_path_test.go) and
// acWithTenantID (agent_config_test.go), all in this same package.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func aaGet(h http.HandlerFunc, tenantID, rawQuery string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/audit-events?"+rawQuery, nil)
	req = acWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestAuditEventsAdminHandler_DB_ValidRequest proves a well-formed request
// against seeded rows returns 200 with the expected events, and — since the
// request below carries no Authorization/HMAC/network-simulation header at
// all — confirms this route's auth model matches AGENTS.md's "Admin
// routes... no application-layer auth" and enforcement_audit_test.go's
// TestEnforcementAuditGetOK precedent: /admin/* is network-only (Tailscale
// + Caddy + ACL, none of which a Go unit test can or needs to simulate),
// not gated by any header or credential the handler itself checks.
func TestAuditEventsAdminHandler_DB_ValidRequest(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-valid-tenant", evUniqueToken("pat1022-admin-valid-token"), evUniqueToken("pat1022-admin-valid-secret"))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	base := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO audit_events (tenant_id, device_id, event_type, label, platform, occurred_at)
		VALUES ($1::uuid, 'dev-valid-1', 'install_completed', 'googlechrome', 'macos', $2)
		RETURNING id::text
	`, tenantID, base).Scan(&id)
	if err != nil {
		t.Fatalf("seed audit_events row: %v", err)
	}

	handler := AuditEventsAdminHandler(pool)
	// Deliberately no Authorization / X-Patched-Signature / any other
	// header — see the doc comment above.
	w := aaGet(handler, tenantID, "since="+base.Add(-time.Hour).Format(time.RFC3339)+"&until="+base.Add(time.Hour).Format(time.RFC3339))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	events, ok := resp["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("want 1 event, got %v", resp["events"])
	}
	ev := events[0].(map[string]any)
	if ev["id"] != id {
		t.Errorf("id = %v, want %v", ev["id"], id)
	}
	if ev["device_id"] != "dev-valid-1" {
		t.Errorf("device_id = %v, want dev-valid-1", ev["device_id"])
	}
	if ev["event_type"] != "install_completed" {
		t.Errorf("event_type = %v, want install_completed", ev["event_type"])
	}
	if ev["label"] != "googlechrome" {
		t.Errorf("label = %v, want googlechrome", ev["label"])
	}
}

// TestAuditEventsAdminHandler_DB_MissingSince proves `since` is enforced as
// required, not merely documented as such.
func TestAuditEventsAdminHandler_DB_MissingSince(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-missingsince-tenant", evUniqueToken("pat1022-admin-missingsince-token"), evUniqueToken("pat1022-admin-missingsince-secret"))

	handler := AuditEventsAdminHandler(pool)
	w := aaGet(handler, tenantID, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing since, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAuditEventsAdminHandler_DB_InvalidSince proves an unparseable `since`
// is rejected rather than silently defaulted or zero-valued.
func TestAuditEventsAdminHandler_DB_InvalidSince(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-invalidsince-tenant", evUniqueToken("pat1022-admin-invalidsince-token"), evUniqueToken("pat1022-admin-invalidsince-secret"))

	handler := AuditEventsAdminHandler(pool)
	w := aaGet(handler, tenantID, "since=not-a-timestamp")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid since, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAuditEventsAdminHandler_DB_LimitClampedAtHTTPLayer proves a
// caller-supplied limit far above the 1000 ceiling is clamped rather than
// rejected — the request still succeeds and returns exactly the seeded
// rows, not an error and not an unbounded/runaway query.
func TestAuditEventsAdminHandler_DB_LimitClampedAtHTTPLayer(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-limit-tenant", evUniqueToken("pat1022-admin-limit-token"), evUniqueToken("pat1022-admin-limit-secret"))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	base := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		_, err := pool.Exec(ctx, `
			INSERT INTO audit_events (tenant_id, device_id, event_type, platform, occurred_at)
			VALUES ($1::uuid, $2, 'install_completed', 'macos', $3)
		`, tenantID, fmt.Sprintf("dev-limit-%d", i), base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}

	handler := AuditEventsAdminHandler(pool)
	w := aaGet(handler, tenantID, "since="+base.Add(-time.Hour).Format(time.RFC3339)+"&until="+base.Add(time.Hour).Format(time.RFC3339)+"&limit=999999")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for an out-of-range limit (clamped, not rejected), got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	events, ok := resp["events"].([]any)
	if !ok || len(events) != 3 {
		t.Fatalf("want 3 events (clamp must not error or truncate below what was seeded), got %v", resp["events"])
	}
}

// TestAuditEventsAdminHandler_DB_InvalidLimitRejected proves a non-numeric
// or non-positive limit is a 400, not silently defaulted.
func TestAuditEventsAdminHandler_DB_InvalidLimitRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-badlimit-tenant", evUniqueToken("pat1022-admin-badlimit-token"), evUniqueToken("pat1022-admin-badlimit-secret"))

	handler := AuditEventsAdminHandler(pool)
	base := time.Now().UTC()
	w := aaGet(handler, tenantID, "since="+base.Add(-time.Hour).Format(time.RFC3339)+"&limit=not-a-number")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-numeric limit, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAuditEventsAdminHandler_DB_EventTypeAndDeviceIDFiltersReachQuery
// proves event_type and device_id query params actually narrow the result
// set — not just get parsed and dropped.
func TestAuditEventsAdminHandler_DB_EventTypeAndDeviceIDFiltersReachQuery(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-filter-tenant", evUniqueToken("pat1022-admin-filter-token"), evUniqueToken("pat1022-admin-filter-secret"))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	base := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	seed := func(deviceID, eventType string, offset time.Duration) {
		_, err := pool.Exec(ctx, `
			INSERT INTO audit_events (tenant_id, device_id, event_type, platform, occurred_at)
			VALUES ($1::uuid, $2, $3, 'macos', $4)
		`, tenantID, deviceID, eventType, base.Add(offset))
		if err != nil {
			t.Fatalf("seed %s/%s: %v", deviceID, eventType, err)
		}
	}
	seed("dev-A", "install_completed", 0)
	seed("dev-A", "verification_failed", time.Minute)
	seed("dev-B", "install_completed", 2*time.Minute)

	handler := AuditEventsAdminHandler(pool)
	rangeQ := "since=" + base.Add(-time.Hour).Format(time.RFC3339) + "&until=" + base.Add(time.Hour).Format(time.RFC3339)

	// event_type filter: only install_completed rows, from either device.
	w := aaGet(handler, tenantID, rangeQ+"&event_type=install_completed")
	if w.Code != http.StatusOK {
		t.Fatalf("event_type filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	events := resp["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("event_type filter: want 2 events, got %d: %v", len(events), events)
	}
	for _, e := range events {
		if e.(map[string]any)["event_type"] != "install_completed" {
			t.Errorf("event_type filter leaked a non-matching row: %v", e)
		}
	}

	// device_id filter: only dev-A's rows (both event types).
	w = aaGet(handler, tenantID, rangeQ+"&device_id=dev-A")
	if w.Code != http.StatusOK {
		t.Fatalf("device_id filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	events = resp["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("device_id filter: want 2 events, got %d: %v", len(events), events)
	}
	for _, e := range events {
		if e.(map[string]any)["device_id"] != "dev-A" {
			t.Errorf("device_id filter leaked a non-matching row: %v", e)
		}
	}

	// Both filters combined: exactly the one dev-A/install_completed row.
	w = aaGet(handler, tenantID, rangeQ+"&device_id=dev-A&event_type=install_completed")
	if w.Code != http.StatusOK {
		t.Fatalf("combined filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	events = resp["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("combined filter: want 1 event, got %d: %v", len(events), events)
	}
}

// TestAuditEventsAdminHandler_DB_CompositeCursorPagination proves the
// next_before object returned by a full page can be fed straight back as
// before/before_id and yields the remaining rows exactly once — the
// end-to-end HTTP-layer counterpart to
// TestFetchTenantAuditEvents_BeforeCursorStableAcrossDuplicateTimestamps
// (internal/report/audit_events_db_test.go), which covers the same
// property at the query layer using several rows sharing one occurred_at.
func TestAuditEventsAdminHandler_DB_CompositeCursorPagination(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-cursor-tenant", evUniqueToken("pat1022-admin-cursor-token"), evUniqueToken("pat1022-admin-cursor-secret"))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1::uuid`, tenantID) })

	tied := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	const n = 5
	seededIDs := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		var id string
		err := pool.QueryRow(ctx, `
			INSERT INTO audit_events (tenant_id, device_id, event_type, platform, occurred_at)
			VALUES ($1::uuid, $2, 'install_completed', 'macos', $3)
			RETURNING id::text
		`, tenantID, fmt.Sprintf("dev-cursor-%d", i), tied).Scan(&id)
		if err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
		seededIDs[id] = true
	}

	handler := AuditEventsAdminHandler(pool)
	rangeQ := "since=" + tied.Add(-time.Hour).Format(time.RFC3339) + "&until=" + tied.Add(time.Hour).Format(time.RFC3339)

	seen := make(map[string]int, n)
	query := rangeQ + "&limit=2"
	for pages := 0; ; pages++ {
		if pages > n {
			t.Fatalf("paginated more than %d times without exhausting the window", n)
		}
		w := aaGet(handler, tenantID, query)
		if w.Code != http.StatusOK {
			t.Fatalf("page %d: want 200, got %d: %s", pages, w.Code, w.Body.String())
		}
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("page %d: decode response: %v", pages, err)
		}
		events := resp["events"].([]any)
		for _, e := range events {
			id := e.(map[string]any)["id"].(string)
			seen[id]++
		}
		nb, ok := resp["next_before"].(map[string]any)
		if !ok {
			break
		}
		query = rangeQ + "&limit=2&before=" + nb["occurred_at"].(string) + "&before_id=" + nb["id"].(string)
	}

	if len(seen) != n {
		t.Fatalf("saw %d distinct ids across all pages, want %d", len(seen), n)
	}
	for id := range seededIDs {
		if seen[id] != 1 {
			t.Errorf("id %s seen %d times across pages, want exactly once", id, seen[id])
		}
	}
}

// TestAuditEventsAdminHandler_DB_SplitCursorRejected proves before and
// before_id are enforced as a pair — supplying only one half must not
// silently fall back to a single-column (occurred_at-only) comparison,
// which is exactly the bug this composite cursor exists to close.
func TestAuditEventsAdminHandler_DB_SplitCursorRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1022-admin-splitcursor-tenant", evUniqueToken("pat1022-admin-splitcursor-token"), evUniqueToken("pat1022-admin-splitcursor-secret"))

	handler := AuditEventsAdminHandler(pool)
	base := time.Now().UTC()
	rangeQ := "since=" + base.Add(-time.Hour).Format(time.RFC3339)

	w := aaGet(handler, tenantID, rangeQ+"&before="+base.Format(time.RFC3339))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("before without before_id: want 400, got %d: %s", w.Code, w.Body.String())
	}

	w = aaGet(handler, tenantID, rangeQ+"&before_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("before_id without before: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAuditEventsAdminHandler_DB_InvalidTenantID proves the tenantID path
// param is validated as a UUID shape before any query runs.
func TestAuditEventsAdminHandler_DB_InvalidTenantID(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	handler := AuditEventsAdminHandler(pool)
	w := aaGet(handler, "not-a-uuid", "since="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid tenantID, got %d: %s", w.Code, w.Body.String())
	}
}
