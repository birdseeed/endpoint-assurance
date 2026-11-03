package handlers

// DB-backed tests for GET /admin/tenants/{tenantID}/intune-config-changes
// (intune_config_changes.go, PAT-1684), driving the REAL exported
// IntuneConfigChangesHandler end-to-end against a real Postgres instance —
// same convention as audit_events_admin_db_test.go, this ticket's closest
// precedent (both are tenant-scoped, date-range-filterable admin GETs with
// no DI seam). Require TEST_DATABASE_URL and are skipped otherwise. Reuses
// parConnectOrSkip/parSeedTenant (allowlist_agent_known_path_test.go),
// evUniqueToken (events_db_test.go) and acWithTenantID (agent_config_test.go),
// all in this same package.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func iccGet(h http.HandlerFunc, tenantID, rawQuery string) *httptest.ResponseRecorder {
	url := "/admin/tenants/" + tenantID + "/intune-config-changes"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = acWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

type iccObject struct {
	id                 string
	changeKind         string
	bodyChanged        bool
	assignmentsChanged bool
	rawBody            []byte
	rawAssignments     []byte
}

// iccSeedSnapshot inserts one complete intune_config_snapshots row plus its
// objects directly via SQL, mirroring the shape
// intune.PostgresStore.WriteSnapshot itself writes
// (internal/intune/postgres_store.go) closely enough for these tests
// without depending on that package: this test's job is to prove the HTTP
// surface reads real rows correctly end to end, not to re-test the store,
// which already has its own DB-backed coverage
// (internal/intune/postgres_store_test.go).
func iccSeedSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string, startedAt, completedAt time.Time, objects []iccObject) int64 {
	t.Helper()
	var snapshotID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO intune_config_snapshots
			(tenant_id, object_type, api_version, started_at, completed_at, status, object_count)
		VALUES ($1::uuid, 'compliance_policy', 'v1.0', $2, $3, 'complete', $4)
		RETURNING id
	`, tenantID, startedAt, completedAt, len(objects)).Scan(&snapshotID)
	if err != nil {
		t.Fatalf("seed intune_config_snapshots: %v", err)
	}
	for _, o := range objects {
		_, err := pool.Exec(ctx, `
			INSERT INTO intune_config_objects
				(snapshot_id, graph_object_id, last_modified_date_time, change_kind,
				 body_changed, assignments_changed, raw_body, raw_assignments)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, snapshotID, o.id, completedAt, o.changeKind, o.bodyChanged, o.assignmentsChanged, o.rawBody, o.rawAssignments)
		if err != nil {
			t.Fatalf("seed intune_config_objects %s: %v", o.id, err)
		}
	}
	return snapshotID
}

// iccJSONEqual compares two JSON documents structurally (key order must
// never matter — canonicalisation is the whole point of the fields this
// endpoint returns).
func iccJSONEqual(t *testing.T, got any, wantRaw []byte) bool {
	t.Helper()
	gotBytes, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	var gotVal, wantVal any
	if err := json.Unmarshal(gotBytes, &gotVal); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal(wantRaw, &wantVal); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	return reflect.DeepEqual(gotVal, wantVal)
}

// TestIntuneConfigChangesHandler_DB_NoSnapshotPair proves a tenant with
// fewer than two complete snapshots gets has_snapshot_pair:false and an
// empty entries list, not an error — "nothing to diff yet" is the honest
// and expected state for a tenant PAT-1662's Snapshotter has pulled zero or
// one times.
func TestIntuneConfigChangesHandler_DB_NoSnapshotPair(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1684-nopair-tenant", evUniqueToken("pat1684-nopair-token"), evUniqueToken("pat1684-nopair-secret"))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM intune_config_snapshots WHERE tenant_id = $1::uuid`, tenantID)
	})

	handler := IntuneConfigChangesHandler(pool)
	w := iccGet(handler, tenantID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["has_snapshot_pair"] != false {
		t.Errorf("has_snapshot_pair = %v, want false", resp["has_snapshot_pair"])
	}
	entries, ok := resp["entries"].([]any)
	if !ok || len(entries) != 0 {
		t.Fatalf("entries = %v, want empty", resp["entries"])
	}
}

// TestIntuneConfigChangesHandler_DB_ValidRequest proves the endpoint returns
// PAT-1664's real diff-engine output for a real snapshot pair: kinds,
// per-field setting changes, and — the acceptance-bar addition this ticket
// makes — a way to reach the full before/after object body, not just the
// changed-fields summary.
func TestIntuneConfigChangesHandler_DB_ValidRequest(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1684-valid-tenant", evUniqueToken("pat1684-valid-token"), evUniqueToken("pat1684-valid-secret"))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM intune_config_snapshots WHERE tenant_id = $1::uuid`, tenantID)
	})

	t0 := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)

	priorBody := []byte(`{"id":"pol-1","displayName":"Baseline Policy","passwordRequired":true}`)
	currentBody := []byte(`{"id":"pol-1","displayName":"Baseline Policy Renamed","passwordRequired":false}`)

	iccSeedSnapshot(t, ctx, pool, tenantID, t0, t0.Add(time.Minute), []iccObject{
		{id: "pol-1", changeKind: "appeared", bodyChanged: true, assignmentsChanged: true, rawBody: priorBody, rawAssignments: []byte(`[]`)},
	})
	iccSeedSnapshot(t, ctx, pool, tenantID, t1, t1.Add(time.Minute), []iccObject{
		{id: "pol-1", changeKind: "refreshed", bodyChanged: true, assignmentsChanged: false, rawBody: currentBody, rawAssignments: []byte(`[]`)},
	})

	handler := IntuneConfigChangesHandler(pool)
	w := iccGet(handler, tenantID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["has_snapshot_pair"] != true {
		t.Fatalf("has_snapshot_pair = %v, want true", resp["has_snapshot_pair"])
	}
	entries, ok := resp["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("entries = %v, want exactly 1", resp["entries"])
	}
	entry := entries[0].(map[string]any)

	if entry["graph_object_id"] != "pol-1" {
		t.Errorf("graph_object_id = %v, want pol-1", entry["graph_object_id"])
	}
	if entry["display_name"] != "Baseline Policy Renamed" {
		t.Errorf("display_name = %v, want %q", entry["display_name"], "Baseline Policy Renamed")
	}
	if entry["previous_display_name"] != "Baseline Policy" {
		t.Errorf("previous_display_name = %v, want %q", entry["previous_display_name"], "Baseline Policy")
	}

	kinds, _ := entry["kinds"].([]any)
	kindSet := map[string]bool{}
	for _, k := range kinds {
		kindSet[k.(string)] = true
	}
	if !kindSet["renamed"] || !kindSet["settings_changed"] {
		t.Fatalf("kinds = %v, want renamed and settings_changed", kinds)
	}

	settingChanges, _ := entry["setting_changes"].([]any)
	found := false
	for _, sc := range settingChanges {
		m := sc.(map[string]any)
		if m["key"] != "passwordRequired" {
			continue
		}
		found = true
		if m["before"] != true || m["after"] != false {
			t.Errorf("passwordRequired before/after = %v/%v, want true/false", m["before"], m["after"])
		}
	}
	if !found {
		t.Fatalf("setting_changes missing passwordRequired entry: %v", settingChanges)
	}

	fullPayload, ok := entry["full_payload"].(map[string]any)
	if !ok {
		t.Fatalf("full_payload missing or wrong shape: %v", entry["full_payload"])
	}
	if !iccJSONEqual(t, fullPayload["before"], priorBody) {
		t.Errorf("full_payload.before = %v, want %s", fullPayload["before"], priorBody)
	}
	if !iccJSONEqual(t, fullPayload["after"], currentBody) {
		t.Errorf("full_payload.after = %v, want %s", fullPayload["after"], currentBody)
	}
}

// TestIntuneConfigChangesHandler_DB_ObjectAndKindFiltersReachQuery proves
// graph_object_id and kind actually narrow the returned entries, not just
// get parsed and dropped — the PAT-1684 acceptance bar for "filters work
// against real query params, not just the underlying function signature".
func TestIntuneConfigChangesHandler_DB_ObjectAndKindFiltersReachQuery(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1684-filter-tenant", evUniqueToken("pat1684-filter-token"), evUniqueToken("pat1684-filter-secret"))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM intune_config_snapshots WHERE tenant_id = $1::uuid`, tenantID)
	})

	t0 := time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 9, 4, 6, 0, 0, 0, time.UTC)

	iccSeedSnapshot(t, ctx, pool, tenantID, t0, t0.Add(time.Minute), []iccObject{
		{id: "pol-created-later", changeKind: "appeared", rawBody: []byte(`{"id":"absent-from-prior"}`), rawAssignments: []byte(`[]`)},
	})
	// pol-created-later is dropped from the current snapshot (not written
	// below at all): it "disappears" between the two pulls. pol-renamed
	// changes displayName only.
	iccSeedSnapshot(t, ctx, pool, tenantID, t1, t1.Add(time.Minute), []iccObject{
		{id: "pol-renamed", changeKind: "appeared", rawBody: []byte(`{"id":"pol-renamed","displayName":"After"}`), rawAssignments: []byte(`[]`)},
	})

	handler := IntuneConfigChangesHandler(pool)

	// graph_object_id filter: only the one matching entry.
	w := iccGet(handler, tenantID, "graph_object_id=pol-renamed")
	if w.Code != http.StatusOK {
		t.Fatalf("object filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	entries := resp["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("object filter: want 1 entry, got %d: %v", len(entries), entries)
	}
	if entries[0].(map[string]any)["graph_object_id"] != "pol-renamed" {
		t.Errorf("object filter leaked a non-matching entry: %v", entries[0])
	}

	// object filter matching nothing: empty, not an error.
	w = iccGet(handler, tenantID, "graph_object_id=does-not-exist")
	if w.Code != http.StatusOK {
		t.Fatalf("non-matching object filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	entries = resp["entries"].([]any)
	if len(entries) != 0 {
		t.Fatalf("non-matching object filter: want 0 entries, got %d: %v", len(entries), entries)
	}

	// kind filter: "deleted" should match pol-created-later (present in
	// prior, absent from current) and exclude pol-renamed.
	w = iccGet(handler, tenantID, "kind=deleted")
	if w.Code != http.StatusOK {
		t.Fatalf("kind filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	entries = resp["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("kind=deleted filter: want 1 entry, got %d: %v", len(entries), entries)
	}
	if entries[0].(map[string]any)["graph_object_id"] != "pol-created-later" {
		t.Errorf("kind=deleted filter leaked a non-matching entry: %v", entries[0])
	}

	// kind filter: "created" should match pol-renamed instead.
	w = iccGet(handler, tenantID, "kind=created")
	if w.Code != http.StatusOK {
		t.Fatalf("kind=created filter: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	entries = resp["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["graph_object_id"] != "pol-renamed" {
		t.Fatalf("kind=created filter: want exactly pol-renamed, got %v", entries)
	}
}

// TestIntuneConfigChangesHandler_DB_DateRangeFilterReachesQuery proves
// since/until actually gate the returned entries against the diffed pair's
// detection window, rather than being parsed and ignored: a window entirely
// before the requested since returns zero entries (but still reports
// has_snapshot_pair:true and the real window), and a range that covers the
// window returns the entries.
func TestIntuneConfigChangesHandler_DB_DateRangeFilterReachesQuery(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1684-daterange-tenant", evUniqueToken("pat1684-daterange-token"), evUniqueToken("pat1684-daterange-secret"))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM intune_config_snapshots WHERE tenant_id = $1::uuid`, tenantID)
	})

	t0 := time.Date(2026, 12, 1, 6, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 12, 2, 6, 0, 0, 0, time.UTC)

	iccSeedSnapshot(t, ctx, pool, tenantID, t0, t0.Add(time.Minute), []iccObject{
		{id: "pol-x", changeKind: "appeared", rawBody: []byte(`{"id":"pol-x","displayName":"Before"}`), rawAssignments: []byte(`[]`)},
	})
	iccSeedSnapshot(t, ctx, pool, tenantID, t1, t1.Add(time.Minute), []iccObject{
		{id: "pol-x", changeKind: "refreshed", bodyChanged: true, rawBody: []byte(`{"id":"pol-x","displayName":"After"}`), rawAssignments: []byte(`[]`)},
	})

	handler := IntuneConfigChangesHandler(pool)

	// Requested range entirely after the diffed window: entries empty, but
	// the pair itself was found (has_snapshot_pair stays true).
	w := iccGet(handler, tenantID, "since="+t1.Add(24*time.Hour).Format(time.RFC3339))
	if w.Code != http.StatusOK {
		t.Fatalf("out-of-range since: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["has_snapshot_pair"] != true {
		t.Errorf("out-of-range since: has_snapshot_pair = %v, want true (the pair exists, just outside the window)", resp["has_snapshot_pair"])
	}
	entries := resp["entries"].([]any)
	if len(entries) != 0 {
		t.Fatalf("out-of-range since: want 0 entries, got %d: %v", len(entries), entries)
	}

	// Requested range entirely before the diffed window: also empty.
	w = iccGet(handler, tenantID, "until="+t0.Add(-24*time.Hour).Format(time.RFC3339))
	if w.Code != http.StatusOK {
		t.Fatalf("out-of-range until: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	entries = resp["entries"].([]any)
	if len(entries) != 0 {
		t.Fatalf("out-of-range until: want 0 entries, got %d: %v", len(entries), entries)
	}

	// Requested range covering the window: the real entry comes back.
	w = iccGet(handler, tenantID, "since="+t0.Add(-time.Hour).Format(time.RFC3339)+"&until="+t1.Add(time.Hour).Format(time.RFC3339))
	if w.Code != http.StatusOK {
		t.Fatalf("in-range: want 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = nil
	_ = json.NewDecoder(w.Body).Decode(&resp)
	entries = resp["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("in-range: want 1 entry, got %d: %v", len(entries), entries)
	}
}

// TestIntuneConfigChangesHandler_DB_InvalidTenantID proves the tenantID path
// param is validated as a UUID shape before any query runs.
func TestIntuneConfigChangesHandler_DB_InvalidTenantID(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })

	handler := IntuneConfigChangesHandler(pool)
	w := iccGet(handler, "not-a-uuid", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid tenantID, got %d: %s", w.Code, w.Body.String())
	}
}

// TestIntuneConfigChangesHandler_DB_InvalidKindRejected proves an
// unrecognised kind value is rejected as a 400 rather than silently
// matching nothing.
func TestIntuneConfigChangesHandler_DB_InvalidKindRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1684-badkind-tenant", evUniqueToken("pat1684-badkind-token"), evUniqueToken("pat1684-badkind-secret"))

	handler := IntuneConfigChangesHandler(pool)
	w := iccGet(handler, tenantID, "kind=not-a-real-kind")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid kind, got %d: %s", w.Code, w.Body.String())
	}
}

// TestIntuneConfigChangesHandler_DB_InvalidObjectTypeRejected proves an
// object_type outside the closed set is rejected rather than silently
// falling back to the default.
func TestIntuneConfigChangesHandler_DB_InvalidObjectTypeRejected(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1684-badobjtype-tenant", evUniqueToken("pat1684-badobjtype-token"), evUniqueToken("pat1684-badobjtype-secret"))

	handler := IntuneConfigChangesHandler(pool)
	w := iccGet(handler, tenantID, "object_type=not-a-real-type")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid object_type, got %d: %s", w.Code, w.Body.String())
	}
}
