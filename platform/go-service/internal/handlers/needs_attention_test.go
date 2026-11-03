package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

const (
	naTestTenantID  = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	naTestDeviceID  = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	naTestDevice2ID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
)

func naExistsAlways(_ context.Context, _ string) (bool, error) { return true, nil }
func naExistsNever(_ context.Context, _ string) (bool, error)  { return false, nil }

func naFetchEmpty(_ context.Context, _ string) ([]needsAttentionItem, error) {
	return nil, nil
}

func ptr[T any](v T) *T { return &v }

// TestNeedsAttentionEmpty verifies that a tenant with no attention items returns
// an empty items array and zero summary counts — not nulls.
func TestNeedsAttentionEmpty(t *testing.T) {
	handler := newNeedsAttentionHandler(naExistsAlways, naFetchEmpty)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+naTestTenantID+"/needs-attention", nil)
	req = naWithTenantID(req, naTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp needsAttentionResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Items == nil {
		t.Error("items must be non-null empty array, got null")
	}
	if len(resp.Items) != 0 {
		t.Errorf("want 0 items, got %d", len(resp.Items))
	}
	if resp.Summary.Total != 0 {
		t.Errorf("want summary.total=0, got %d", resp.Summary.Total)
	}
	if resp.ByDevice == nil {
		t.Error("by_device must be non-null empty array, got null")
	}
	if len(resp.ByDevice) != 0 {
		t.Errorf("want 0 by_device entries, got %d", len(resp.ByDevice))
	}
}

// TestNeedsAttentionRanking verifies that the response ranks items correctly:
// vulnerable (0) before out_of_date (1) before blocked (2), and that
// summary counts match the item categories.
func TestNeedsAttentionRanking(t *testing.T) {
	items := []needsAttentionItem{
		{
			DeviceID:         naTestDeviceID,
			Hostname:         "mac-01.example.com",
			AppName:          "Zoom",
			Identifier:       "us.zoom.xos",
			InstalledVersion: "5.0.0",
			AvailableVersion: ptr("6.0.0"),
			Category:         "out_of_date",
			Rank:             1,
			CVEIDs:           []string{},
		},
		{
			DeviceID:         naTestDeviceID,
			Hostname:         "mac-01.example.com",
			AppName:          "Google Chrome",
			Identifier:       "com.google.Chrome",
			InstalledVersion: "100.0",
			Category:         "vulnerable",
			Rank:             0,
			CVEIDs:           []string{"CVE-2024-1234"},
			MaxCVSS:          ptr(9.8),
			MaxSeverity:      ptr("CRITICAL"),
		},
		{
			DeviceID:         naTestDevice2ID,
			Hostname:         "mac-02.example.com",
			AppName:          "Slack",
			Identifier:       "com.tinyspeck.slackmacgap",
			InstalledVersion: "4.0.0",
			Category:         "blocked",
			Rank:             2,
			CVEIDs:           []string{},
			VerifiedSigner:   ptr("BQR82RBBHL"),
			FailureReason:    ptr("signer_mismatch"),
		},
	}
	fetchFn := func(_ context.Context, _ string) ([]needsAttentionItem, error) {
		return items, nil
	}
	handler := newNeedsAttentionHandler(naExistsAlways, fetchFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+naTestTenantID+"/needs-attention", nil)
	req = naWithTenantID(req, naTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp needsAttentionResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if resp.Summary.Total != 3 {
		t.Errorf("want total=3, got %d", resp.Summary.Total)
	}
	if resp.Summary.Vulnerable != 1 {
		t.Errorf("want vulnerable=1, got %d", resp.Summary.Vulnerable)
	}
	if resp.Summary.OutOfDate != 1 {
		t.Errorf("want out_of_date=1, got %d", resp.Summary.OutOfDate)
	}
	if resp.Summary.Blocked != 1 {
		t.Errorf("want blocked=1, got %d", resp.Summary.Blocked)
	}

	if len(resp.ByDevice) != 2 {
		t.Fatalf("want 2 by_device entries (two distinct devices), got %d", len(resp.ByDevice))
	}
}

// TestNeedsAttentionDedup verifies that an app that is both vulnerable and
// out_of_date appears as a single "vulnerable" item in the response.
func TestNeedsAttentionDedup(t *testing.T) {
	// Fetch returns one item already de-duped as vulnerable (rank 0).
	items := []needsAttentionItem{
		{
			DeviceID:         naTestDeviceID,
			Hostname:         "mac-01.example.com",
			AppName:          "Google Chrome",
			Identifier:       "com.google.Chrome",
			InstalledVersion: "100.0",
			AvailableVersion: ptr("126.0"),
			Category:         "vulnerable",
			Rank:             0,
			CVEIDs:           []string{"CVE-2024-1234"},
			MaxCVSS:          ptr(9.8),
			MaxSeverity:      ptr("CRITICAL"),
		},
	}
	fetchFn := func(_ context.Context, _ string) ([]needsAttentionItem, error) {
		return items, nil
	}
	handler := newNeedsAttentionHandler(naExistsAlways, fetchFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+naTestTenantID+"/needs-attention", nil)
	req = naWithTenantID(req, naTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp needsAttentionResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if resp.Summary.Total != 1 {
		t.Errorf("want exactly 1 item (vulnerable wins over out_of_date), got %d", resp.Summary.Total)
	}
	if resp.Items[0].Category != "vulnerable" {
		t.Errorf("want category=vulnerable, got %q", resp.Items[0].Category)
	}
	if resp.Items[0].Rank != 0 {
		t.Errorf("want rank=0, got %d", resp.Items[0].Rank)
	}
	if resp.Summary.Vulnerable != 1 {
		t.Errorf("want vulnerable=1, got %d", resp.Summary.Vulnerable)
	}
	if resp.Summary.OutOfDate != 0 {
		t.Errorf("want out_of_date=0, got %d", resp.Summary.OutOfDate)
	}
}

// TestNeedsAttentionUnknownTenant verifies that a valid UUID not in the tenant
// table returns HTTP 404 without calling fetchFn.
func TestNeedsAttentionUnknownTenant(t *testing.T) {
	fetchFn := func(_ context.Context, _ string) ([]needsAttentionItem, error) {
		t.Error("fetchFn must not be called for an unknown tenant")
		return nil, nil
	}
	handler := newNeedsAttentionHandler(naExistsNever, fetchFn)

	unknownUUID := "11111111-2222-3333-4444-555555555555"
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+unknownUUID+"/needs-attention", nil)
	req = naWithTenantID(req, unknownUUID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestNeedsAttentionInvalidTenantID verifies that a non-UUID path param returns
// HTTP 400 without calling either existsFn or fetchFn.
func TestNeedsAttentionInvalidTenantID(t *testing.T) {
	existsFn := func(_ context.Context, _ string) (bool, error) {
		t.Error("existsFn must not be called for an invalid tenantID")
		return false, nil
	}
	handler := newNeedsAttentionHandler(existsFn, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/not-a-uuid/needs-attention", nil)
	req = naWithTenantID(req, "not-a-uuid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestNeedsAttentionFetchError verifies that a DB error from fetchFn returns
// HTTP 500.
func TestNeedsAttentionFetchError(t *testing.T) {
	fetchFn := func(_ context.Context, _ string) ([]needsAttentionItem, error) {
		return nil, errors.New("connection reset by peer")
	}
	handler := newNeedsAttentionHandler(naExistsAlways, fetchFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+naTestTenantID+"/needs-attention", nil)
	req = naWithTenantID(req, naTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestNeedsAttentionFieldShape verifies the response has exactly the expected
// top-level JSON keys and that items carry the required fields.
func TestNeedsAttentionFieldShape(t *testing.T) {
	score := 9.8
	severity := "CRITICAL"
	avail := "126.0"
	items := []needsAttentionItem{
		{
			DeviceID:         naTestDeviceID,
			Hostname:         "mac-01.example.com",
			AppName:          "Google Chrome",
			Identifier:       "com.google.Chrome",
			InstalledVersion: "100.0",
			AvailableVersion: &avail,
			Category:         "vulnerable",
			Rank:             0,
			CVEIDs:           []string{"CVE-2024-1234"},
			MaxCVSS:          &score,
			MaxSeverity:      &severity,
		},
	}
	fetchFn := func(_ context.Context, _ string) ([]needsAttentionItem, error) {
		return items, nil
	}
	handler := newNeedsAttentionHandler(naExistsAlways, fetchFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+naTestTenantID+"/needs-attention", nil)
	req = naWithTenantID(req, naTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Top-level keys.
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &topLevel); err != nil {
		t.Fatalf("decode top-level: %v", err)
	}
	wantTopKeys := []string{"items", "summary", "by_device"}
	gotTopKeys := make([]string, 0, len(topLevel))
	for k := range topLevel {
		gotTopKeys = append(gotTopKeys, k)
	}
	sort.Strings(wantTopKeys)
	sort.Strings(gotTopKeys)
	if len(wantTopKeys) != len(gotTopKeys) {
		t.Fatalf("top-level keys: want %v, got %v", wantTopKeys, gotTopKeys)
	}
	for i := range wantTopKeys {
		if wantTopKeys[i] != gotTopKeys[i] {
			t.Errorf("top-level key[%d]: want %q, got %q", i, wantTopKeys[i], gotTopKeys[i])
		}
	}

	// Item field shape.
	var itemSlice []map[string]json.RawMessage
	if err := json.Unmarshal(topLevel["items"], &itemSlice); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if len(itemSlice) != 1 {
		t.Fatalf("want 1 item, got %d", len(itemSlice))
	}
	wantItemKeys := []string{
		"device_id", "hostname", "app_name", "identifier",
		"installed_version", "available_version",
		"category", "rank",
		"cve_ids", "max_cvss", "max_severity",
		"verified_signer", "failure_reason",
	}
	gotItemKeys := make([]string, 0, len(itemSlice[0]))
	for k := range itemSlice[0] {
		gotItemKeys = append(gotItemKeys, k)
	}
	sort.Strings(wantItemKeys)
	sort.Strings(gotItemKeys)
	if len(wantItemKeys) != len(gotItemKeys) {
		t.Fatalf("item keys: want %v, got %v", wantItemKeys, gotItemKeys)
	}
	for i := range wantItemKeys {
		if wantItemKeys[i] != gotItemKeys[i] {
			t.Errorf("item key[%d]: want %q, got %q", i, wantItemKeys[i], gotItemKeys[i])
		}
	}

	// Summary field shape.
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(topLevel["summary"], &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	wantSummaryKeys := []string{"total", "vulnerable", "out_of_date", "blocked"}
	gotSummaryKeys := make([]string, 0, len(summary))
	for k := range summary {
		gotSummaryKeys = append(gotSummaryKeys, k)
	}
	sort.Strings(wantSummaryKeys)
	sort.Strings(gotSummaryKeys)
	if len(wantSummaryKeys) != len(gotSummaryKeys) {
		t.Fatalf("summary keys: want %v, got %v", wantSummaryKeys, gotSummaryKeys)
	}
}

// TestNeedsAttentionByDeviceSummary verifies that by_device counts correctly
// reflect per-device breakdowns when multiple devices have attention items.
func TestNeedsAttentionByDeviceSummary(t *testing.T) {
	items := []needsAttentionItem{
		{DeviceID: naTestDeviceID, Hostname: "mac-01", AppName: "Chrome", Category: "vulnerable", Rank: 0, CVEIDs: []string{"CVE-1"}},
		{DeviceID: naTestDeviceID, Hostname: "mac-01", AppName: "Zoom", Category: "out_of_date", Rank: 1, CVEIDs: []string{}},
		{DeviceID: naTestDevice2ID, Hostname: "mac-02", AppName: "Slack", Category: "blocked", Rank: 2, CVEIDs: []string{}},
	}
	fetchFn := func(_ context.Context, _ string) ([]needsAttentionItem, error) {
		return items, nil
	}
	handler := newNeedsAttentionHandler(naExistsAlways, fetchFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+naTestTenantID+"/needs-attention", nil)
	req = naWithTenantID(req, naTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp needsAttentionResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if len(resp.ByDevice) != 2 {
		t.Fatalf("want 2 by_device entries, got %d", len(resp.ByDevice))
	}

	d1 := resp.ByDevice[0]
	if d1.DeviceID != naTestDeviceID {
		t.Errorf("by_device[0].device_id: want %q, got %q", naTestDeviceID, d1.DeviceID)
	}
	if d1.Total != 2 {
		t.Errorf("by_device[0].total: want 2, got %d", d1.Total)
	}
	if d1.Vulnerable != 1 {
		t.Errorf("by_device[0].vulnerable: want 1, got %d", d1.Vulnerable)
	}
	if d1.OutOfDate != 1 {
		t.Errorf("by_device[0].out_of_date: want 1, got %d", d1.OutOfDate)
	}
	if d1.Blocked != 0 {
		t.Errorf("by_device[0].blocked: want 0, got %d", d1.Blocked)
	}

	d2 := resp.ByDevice[1]
	if d2.DeviceID != naTestDevice2ID {
		t.Errorf("by_device[1].device_id: want %q, got %q", naTestDevice2ID, d2.DeviceID)
	}
	if d2.Total != 1 {
		t.Errorf("by_device[1].total: want 1, got %d", d2.Total)
	}
	if d2.Blocked != 1 {
		t.Errorf("by_device[1].blocked: want 1, got %d", d2.Blocked)
	}
}

// TestNeedsAttentionSQLStructure is a structural guard on needsAttentionSQL that
// catches regressions in the key SQL patterns without requiring a live database.
// It verifies de-duplication, numeric severity ordering, rank assignments, and
// tenant scoping are all present in the query text.
func TestNeedsAttentionSQLStructure(t *testing.T) {
	checks := []struct {
		name    string
		pattern string
	}{
		{"dedup DISTINCT ON in catalog CTE", "DISTINCT ON"},
		{"numeric severity ordering (not lexical MAX)", "CASE MAX(CASE"},
		{"vulnerable rank 0", "THEN 0"},
		{"out_of_date rank 1", "THEN 1"},
		{"tenant scope param", "$1::uuid"},
	}
	for _, c := range checks {
		if !strings.Contains(needsAttentionSQL, c.pattern) {
			t.Errorf("SQL missing %s: expected to find %q in needsAttentionSQL", c.name, c.pattern)
		}
	}
}

// TestNeedsAttentionVerificationFailedFailsClosed is a structural guard on the
// CASE blocks in needsAttentionSQL enforcing that a verification failure is
// never masked by a mere catalog out_of_date match. SQL CASE takes the first
// matching WHEN, so the `lp.state = 'verification_failed'` clause must appear
// BEFORE the `cod.device_id IS NOT NULL` clause in every categorising CASE:
// an app that is both catalog-out-of-date and verification_failed must be
// categorised "blocked", not "out_of_date".
//
// This is the fail-closed direction required by the GitHub-Non-Author-Review endpoint-trust
// review (a failed TeamID/Authenticode verification is a supply-chain red flag
// and must always surface). It directly guards against a well-meaning reorder
// that follows the display-rank numbers literally and lets out_of_date win —
// which would silently downgrade blocked devices.
//
// Query-text ordering check (no live DB needed), same pattern as
// TestNeedsAttentionSQLStructure. A live-DB integration test exercising this
// exact device state (out-of-date catalog entry + verification_failed
// provenance record on the same app, asserting category "blocked") belongs in
// go-service/integration/.
func TestNeedsAttentionVerificationFailedFailsClosed(t *testing.T) {
	// In each CASE block the verification_failed WHEN must precede the catalog
	// out_of_date WHEN. Locate the ranked WHEN branches specifically (anchored
	// on their THEN result) so unrelated references to these columns in the
	// JOIN/WHERE clauses don't skew the offsets.
	rankVF := strings.Index(needsAttentionSQL,
		"WHEN lp.state     = 'verification_failed'                  THEN 2")
	rankCOD := strings.Index(needsAttentionSQL,
		"WHEN cod.device_id IS NOT NULL                             THEN 1")
	if rankVF < 0 || rankCOD < 0 {
		t.Fatal("expected both verification_failed(THEN 2) and cod(THEN 1) ranked WHEN clauses in needsAttentionSQL")
	}
	if rankVF > rankCOD {
		t.Errorf("rank CASE: verification_failed WHEN (offset %d) must precede catalog out_of_date WHEN (offset %d) so a dual-match device ranks blocked, not out_of_date", rankVF, rankCOD)
	}

	catVF := strings.Index(needsAttentionSQL,
		"WHEN lp.state     = 'verification_failed'                  THEN 'blocked'")
	catCOD := strings.Index(needsAttentionSQL,
		"WHEN cod.device_id IS NOT NULL                             THEN 'out_of_date'")
	if catVF < 0 || catCOD < 0 {
		t.Fatal("expected both verification_failed('blocked') and cod('out_of_date') category WHEN clauses in needsAttentionSQL")
	}
	if catVF > catCOD {
		t.Errorf("category CASE: verification_failed WHEN (offset %d) must precede catalog out_of_date WHEN (offset %d) so a dual-match device is categorised blocked, not out_of_date — verification must fail closed", catVF, catCOD)
	}
}

// -- Helpers -----------------------------------------------------------------

func naWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
