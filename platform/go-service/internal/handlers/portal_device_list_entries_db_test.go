package handlers

// PAT-2271: finishes PAT-2212's "Your device list" card. DB-backed checks
// for the new `matched` array on GET /v1/portal/device-list and the new
// per-entry DELETE /v1/portal/device-list/entries/{entryID}. Handler-level,
// same shape as portal_device_selfservice_db_test.go: driven directly with
// httptest, not through a live HTTP server. Skipped without
// TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

// putDeviceList uploads entries for tenantID/adminEmail and fails the test
// if the write does not succeed.
func putDeviceList(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, adminEmail, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v1/portal/device-list", strings.NewReader(body))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: adminEmail, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	PortalDeviceListPutHandler(pool).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT device-list = %d %s", rec.Code, rec.Body.String())
	}
}

// getDeviceListResp fetches and decodes GET /v1/portal/device-list for
// tenantID/email (any role).
func getDeviceListResp(t *testing.T, pool *pgxpool.Pool, tenantID, email string) deviceListReadResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/device-list", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rec := httptest.NewRecorder()
	PortalDeviceListGetHandler(pool).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET device-list = %d %s", rec.Code, rec.Body.String())
	}
	var out deviceListReadResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode device-list response: %v", err)
	}
	return out
}

// deleteDeviceListEntry drives DELETE /v1/portal/device-list/entries/{entryID}
// directly against the handler, injecting the chi URL param as the real
// router would.
func deleteDeviceListEntry(pool *pgxpool.Pool, tenantID, email, entryID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/portal/device-list/entries/"+entryID, nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("entryID", entryID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	PortalDeviceListEntryDeleteHandler(pool).ServeHTTP(rec, req)
	return rec
}

// TestPortalDeviceListMatchedArrayAgreesWithCounts is the "matched must
// agree exactly with matched_count" acceptance test: a live match, a
// retired match, and a never-seen entry. Removing the new Matched field
// (or capping it) from PortalDeviceListGetHandler turns this red.
func TestPortalDeviceListMatchedArrayAgreesWithCounts(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2271-matched")
	now := time.Now()
	live := selfServiceDevice(t, ctx, pool, tenantID, "live-box", now)
	retired := selfServiceDevice(t, ctx, pool, tenantID, "retired-box", now)

	// Retire one device so its list match carries retired: true.
	retireReq := httptest.NewRequest(http.MethodPut, "/v1/portal/devices/"+retired+"/retirement", strings.NewReader(`{"retired":true}`))
	retireReq = retireReq.WithContext(portalauth.WithIdentity(retireReq.Context(), portalauth.Identity{Email: adminEmail, TenantID: tenantID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("deviceID", retired)
	retireReq = retireReq.WithContext(context.WithValue(retireReq.Context(), chi.RouteCtxKey, rctx))
	retireRec := httptest.NewRecorder()
	PortalDeviceRetirementPutHandler(pool).ServeHTTP(retireRec, retireReq)
	if retireRec.Code != http.StatusOK {
		t.Fatalf("retire = %d %s", retireRec.Code, retireRec.Body.String())
	}

	putDeviceList(t, ctx, pool, tenantID, adminEmail,
		`{"entries":[{"hostname":"live-box"},{"hostname":"retired-box"},{"hostname":"ghost-box"}]}`)

	got := getDeviceListResp(t, pool, tenantID, adminEmail)
	if got.MatchedCount != 2 || got.MatchedRetiredCount != 1 {
		t.Fatalf("matched = %d (retired %d), want 2 (1): %+v", got.MatchedCount, got.MatchedRetiredCount, got)
	}
	if len(got.Matched) != got.MatchedCount {
		t.Fatalf("len(matched) = %d, want %d (matched_count): %+v", len(got.Matched), got.MatchedCount, got.Matched)
	}
	byHostname := map[string]deviceListMatchOut{}
	for _, m := range got.Matched {
		if m.Hostname == nil {
			t.Fatalf("matched entry has nil hostname: %+v", m)
		}
		byHostname[*m.Hostname] = m
	}
	liveMatch, ok := byHostname["live-box"]
	if !ok || liveMatch.Device.DeviceID != live || liveMatch.Device.Retired {
		t.Fatalf("live-box match = %+v, want device %s not retired", liveMatch, live)
	}
	if liveMatch.EntryID <= 0 {
		t.Fatalf("live-box match has no entry_id: %+v", liveMatch)
	}
	retiredMatch, ok := byHostname["retired-box"]
	if !ok || retiredMatch.Device.DeviceID != retired || !retiredMatch.Device.Retired {
		t.Fatalf("retired-box match = %+v, want device %s retired", retiredMatch, retired)
	}
	if len(got.OnListNeverSeen) != 1 || got.OnListNeverSeen[0].EntryID <= 0 || *got.OnListNeverSeen[0].Hostname != "ghost-box" {
		t.Fatalf("on_list_never_seen = %+v, want one ghost-box row with an entry_id", got.OnListNeverSeen)
	}
}

// TestPortalDeviceListEntryDelete: removing one entry by its entry_id takes
// out exactly that entry, decrements entry_count, and records the deletion
// in device_list_entry_deletions.
func TestPortalDeviceListEntryDelete(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2271-delete")

	putDeviceList(t, ctx, pool, tenantID, adminEmail,
		`{"entries":[{"hostname":"keep-1"},{"hostname":"remove-me","serial":"SN-DEL-1"},{"hostname":"keep-2"}]}`)

	before := getDeviceListResp(t, pool, tenantID, adminEmail)
	if before.List == nil || before.List.EntryCount != 3 {
		t.Fatalf("before = %+v, want entry_count 3", before.List)
	}
	var targetID int64
	for _, e := range before.OnListNeverSeen {
		if e.Hostname != nil && *e.Hostname == "remove-me" {
			targetID = e.EntryID
		}
	}
	if targetID == 0 {
		t.Fatalf("did not find remove-me's entry_id in %+v", before.OnListNeverSeen)
	}

	rec := deleteDeviceListEntry(pool, tenantID, adminEmail, strconv.FormatInt(targetID, 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE entry = %d %s", rec.Code, rec.Body.String())
	}
	var delResp deviceListEntryDeleteResp
	if err := json.Unmarshal(rec.Body.Bytes(), &delResp); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !delResp.Deleted || delResp.EntryID != targetID {
		t.Fatalf("delete response = %+v, want deleted true, entry_id %d", delResp, targetID)
	}

	after := getDeviceListResp(t, pool, tenantID, adminEmail)
	if after.List == nil || after.List.EntryCount != 2 {
		t.Fatalf("after = %+v, want entry_count 2", after.List)
	}
	if len(after.OnListNeverSeen) != 2 {
		t.Fatalf("on_list_never_seen after delete = %+v, want 2 rows", after.OnListNeverSeen)
	}
	for _, e := range after.OnListNeverSeen {
		if e.EntryID == targetID {
			t.Fatalf("deleted entry %d still present: %+v", targetID, after.OnListNeverSeen)
		}
	}

	// The remaining two entries are still there, keep-1 and keep-2, and
	// exactly one entry_count row was decremented in device_list_uploads
	// (checked directly against the DB, not just the read API).
	var entryCount int
	if err := pool.QueryRow(ctx, `
		SELECT entry_count FROM device_list_uploads WHERE tenant_id = $1::uuid ORDER BY id DESC LIMIT 1
	`, tenantID).Scan(&entryCount); err != nil || entryCount != 2 {
		t.Fatalf("device_list_uploads.entry_count = %d (%v), want 2", entryCount, err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM device_list_entries e
		JOIN device_list_uploads u ON u.id = e.upload_id
		WHERE u.tenant_id = $1::uuid
	`, tenantID).Scan(&remaining); err != nil || remaining != 2 {
		t.Fatalf("device_list_entries rows = %d (%v), want 2", remaining, err)
	}

	// Audited the same way as the bulk clear: one append-only row naming
	// the deleted entry, the actor and the deletion time.
	var auditHostname *string
	var auditSerial *string
	var auditActor string
	var auditPosition int
	if err := pool.QueryRow(ctx, `
		SELECT hostname, serial, actor_email, position FROM device_list_entry_deletions
		WHERE tenant_id = $1::uuid AND entry_id = $2
	`, tenantID, targetID).Scan(&auditHostname, &auditSerial, &auditActor, &auditPosition); err != nil {
		t.Fatalf("device_list_entry_deletions lookup: %v", err)
	}
	if auditHostname == nil || *auditHostname != "remove-me" || auditSerial == nil || *auditSerial != "SN-DEL-1" || auditActor != adminEmail {
		t.Fatalf("audit row = hostname=%v serial=%v actor=%s, want remove-me/SN-DEL-1/%s", auditHostname, auditSerial, auditActor, adminEmail)
	}

	// The audit row is append-only: UPDATE and DELETE must be rejected.
	if _, err := pool.Exec(ctx, `UPDATE device_list_entry_deletions SET actor_email = 'x@example.com' WHERE tenant_id = $1::uuid`, tenantID); err == nil {
		t.Fatal("UPDATE on device_list_entry_deletions should have been rejected")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM device_list_entry_deletions WHERE tenant_id = $1::uuid`, tenantID); err == nil {
		t.Fatal("DELETE on device_list_entry_deletions should have been rejected")
	}
}

// TestPortalDeviceListEntryDeleteCrossTenantReturns404: an entry_id that
// exists, but for a different tenant's current list, must not be
// deletable or discoverable by this tenant.
func TestPortalDeviceListEntryDeleteCrossTenantReturns404(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantA, adminA := selfServiceAdmin(t, ctx, pool, "pat2271-xtenant-a")
	tenantB, adminB := selfServiceAdmin(t, ctx, pool, "pat2271-xtenant-b")

	putDeviceList(t, ctx, pool, tenantA, adminA, `{"entries":[{"hostname":"a-only"}]}`)
	putDeviceList(t, ctx, pool, tenantB, adminB, `{"entries":[{"hostname":"b-only"}]}`)

	gotA := getDeviceListResp(t, pool, tenantA, adminA)
	if len(gotA.OnListNeverSeen) != 1 {
		t.Fatalf("tenant A list = %+v", gotA.OnListNeverSeen)
	}
	entryIDFromA := gotA.OnListNeverSeen[0].EntryID

	// Tenant B tries to delete tenant A's entry id.
	rec := deleteDeviceListEntry(pool, tenantB, adminB, strconv.FormatInt(entryIDFromA, 10))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete = %d %s, want 404", rec.Code, rec.Body.String())
	}

	// Tenant A's entry is untouched.
	stillA := getDeviceListResp(t, pool, tenantA, adminA)
	if len(stillA.OnListNeverSeen) != 1 || stillA.OnListNeverSeen[0].EntryID != entryIDFromA {
		t.Fatalf("tenant A list after cross-tenant attempt = %+v, want unchanged", stillA.OnListNeverSeen)
	}
}

// TestPortalDeviceListEntryDeleteViewerRefused: a non-admin role is refused
// exactly like the bulk clear (403 admin_role_required), and nothing is
// deleted.
func TestPortalDeviceListEntryDeleteViewerRefused(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2271-viewer")
	viewerEmail := "viewer-" + tenantID[:8] + "@selfservice.example"

	putDeviceList(t, ctx, pool, tenantID, adminEmail, `{"entries":[{"hostname":"stays"}]}`)
	got := getDeviceListResp(t, pool, tenantID, adminEmail)
	entryID := got.OnListNeverSeen[0].EntryID

	rec := deleteDeviceListEntry(pool, tenantID, viewerEmail, strconv.FormatInt(entryID, 10))
	var e selfServiceErrorOutHandlers
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Code != http.StatusForbidden || e.Error != "admin_role_required" {
		t.Fatalf("viewer delete = %d %s, want 403 admin_role_required", rec.Code, rec.Body.String())
	}

	after := getDeviceListResp(t, pool, tenantID, adminEmail)
	if len(after.OnListNeverSeen) != 1 || after.OnListNeverSeen[0].EntryID != entryID {
		t.Fatalf("list after refused delete = %+v, want unchanged", after.OnListNeverSeen)
	}
}

// TestPortalDeviceListEntryDeleteNoCurrentList404 covers both "never
// uploaded" and "cleared" — neither has a current list, so the entry
// (real or not) can never be found.
func TestPortalDeviceListEntryDeleteNoCurrentList404(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2271-nolist")

	if rec := deleteDeviceListEntry(pool, tenantID, adminEmail, "1"); rec.Code != http.StatusNotFound {
		t.Fatalf("delete with no list ever uploaded = %d %s, want 404", rec.Code, rec.Body.String())
	}

	putDeviceList(t, ctx, pool, tenantID, adminEmail, `{"entries":[{"hostname":"soon-cleared"}]}`)
	got := getDeviceListResp(t, pool, tenantID, adminEmail)
	entryID := got.OnListNeverSeen[0].EntryID

	clearReq := httptest.NewRequest(http.MethodDelete, "/v1/portal/device-list", nil)
	clearReq = clearReq.WithContext(portalauth.WithIdentity(clearReq.Context(), portalauth.Identity{Email: adminEmail, TenantID: tenantID}))
	clearRec := httptest.NewRecorder()
	PortalDeviceListDeleteHandler(pool).ServeHTTP(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear = %d %s", clearRec.Code, clearRec.Body.String())
	}

	if rec := deleteDeviceListEntry(pool, tenantID, adminEmail, strconv.FormatInt(entryID, 10)); rec.Code != http.StatusNotFound {
		t.Fatalf("delete after clear = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

// TestPortalDeviceListEntryDeleteUnknownOrMalformedID404: an entryID that
// parses but does not exist, and one that does not even parse as a
// positive integer, both answer 404 — never a 400 that would distinguish
// "malformed" from "not found".
func TestPortalDeviceListEntryDeleteUnknownOrMalformedID404(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID, adminEmail := selfServiceAdmin(t, ctx, pool, "pat2271-badid")
	putDeviceList(t, ctx, pool, tenantID, adminEmail, `{"entries":[{"hostname":"present"}]}`)

	for _, badID := range []string{"999999999", "not-a-number", "-1", "0"} {
		rec := deleteDeviceListEntry(pool, tenantID, adminEmail, badID)
		if rec.Code != http.StatusNotFound {
			t.Errorf("entryID %q = %d %s, want 404", badID, rec.Code, rec.Body.String())
		}
	}
}

// selfServiceErrorOutHandlers mirrors integration's selfServiceErrorOut for
// this package's own tests (unexported types can't cross packages).
type selfServiceErrorOutHandlers struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
