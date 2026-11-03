package handlers

// PAT-1969: DB-backed tests for the portal-facing finding lifecycle read
// contract. Reuses pat1829Pool/pat1829SeedTenant/pat1829SeedDevice from
// finding_dispositions_test.go (same finding_lifecycle_events table and
// finding_lifecycle_current view, hand-mirrored from
// migrations/0146_finding_dispositions.sql) — only the request-construction
// helper differs, since the portal surface takes its tenant scope from
// portalauth.FromContext rather than a chi {tenantID} path parameter.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

// pat1969Req builds a portal request carrying an authenticated identity for
// tenantID, with no chi route params at all — proving nothing on this
// surface can source tenant scope from the URL.
func pat1969Req(target, tenantID string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	return r.WithContext(portalauth.WithIdentity(r.Context(),
		portalauth.Identity{Email: "portal-user@example.com", TenantID: tenantID}))
}

func pat1969SeedLifecycleEvent(t *testing.T, pool *pgxpool.Pool, tenantID, deviceID, findingKey, eventType string, observedAt time.Time, authoritative bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO finding_lifecycle_events
			(tenant_id, finding_kind, device_id, finding_key, event_type, source_type,
			 actor, observed_at, authoritative, recorded_at)
		VALUES ($1::uuid, 'cis', $2::uuid, $3, $4, 'endpoint_observation',
		        'agent', $5, $6, $5)
	`, tenantID, deviceID, findingKey, eventType, observedAt, authoritative); err != nil {
		t.Fatalf("seed lifecycle event: %v", err)
	}
}

// TestPortalFindingLifecycleCurrent_CrossTenantIsolation is the acceptance
// criterion's named cross-tenant isolation test: a portal JWT for tenant A
// can never retrieve tenant B's lifecycle rows.
func TestPortalFindingLifecycleCurrent_CrossTenantIsolation(t *testing.T) {
	pool := pat1829Pool(t)
	tenantA := pat1829SeedTenant(t, pool)
	tenantB := pat1829SeedTenant(t, pool)
	deviceA := pat1829SeedDevice(t, pool, tenantA, "tenant-a-device")
	deviceB := pat1829SeedDevice(t, pool, tenantB, "tenant-b-device")

	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	pat1969SeedLifecycleEvent(t, pool, tenantA, deviceA, "finding-a", "first_observed", t0, true)
	pat1969SeedLifecycleEvent(t, pool, tenantB, deviceB, "finding-b", "first_observed", t0, true)

	rr := httptest.NewRecorder()
	PortalFindingLifecycleCurrentHandler(pool).ServeHTTP(rr, pat1969Req("/v1/portal/finding-lifecycle", tenantA))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings []findingLifecycleCurrentRow `json:"findings"`
		Total    int                          `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || len(resp.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding for tenant A, got %+v", resp)
	}
	if resp.Findings[0].FindingKey != "finding-a" {
		t.Fatalf("expected tenant A's finding-a, got %q (tenant B's row leaked)", resp.Findings[0].FindingKey)
	}
	if resp.Findings[0].TenantID != tenantA {
		t.Fatalf("TenantID = %q, want %q", resp.Findings[0].TenantID, tenantA)
	}
}

// TestPortalFindingLifecycleHistory_CrossTenantIsolation mirrors the current
// test above for the history/events endpoint.
func TestPortalFindingLifecycleHistory_CrossTenantIsolation(t *testing.T) {
	pool := pat1829Pool(t)
	tenantA := pat1829SeedTenant(t, pool)
	tenantB := pat1829SeedTenant(t, pool)
	deviceA := pat1829SeedDevice(t, pool, tenantA, "tenant-a-device")
	deviceB := pat1829SeedDevice(t, pool, tenantB, "tenant-b-device")

	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	pat1969SeedLifecycleEvent(t, pool, tenantA, deviceA, "finding-a", "first_observed", t0, true)
	pat1969SeedLifecycleEvent(t, pool, tenantB, deviceB, "finding-b", "first_observed", t0, true)

	rr := httptest.NewRecorder()
	PortalFindingLifecycleHistoryHandler(pool).ServeHTTP(rr, pat1969Req("/v1/portal/finding-lifecycle/history", tenantA))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	var resp struct {
		Events []findingLifecycleEventRow `json:"events"`
		Total  int                        `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || len(resp.Events) != 1 {
		t.Fatalf("expected exactly 1 event for tenant A, got %+v", resp)
	}
	if resp.Events[0].FindingKey != "finding-a" {
		t.Fatalf("expected tenant A's finding-a, got %q (tenant B's row leaked)", resp.Events[0].FindingKey)
	}
	if resp.Events[0].TenantID != tenantA {
		t.Fatalf("TenantID = %q, want %q", resp.Events[0].TenantID, tenantA)
	}
}

// TestPortalFindingLifecycleCurrent_TenantQueryParamIgnored confirms no path
// parameter or query string can override the tenant scope: a caller passing
// ?tenant_id=<tenant B> while authenticated as tenant A must still only see
// tenant A's rows — scope comes only from portalauth.FromContext.
func TestPortalFindingLifecycleCurrent_TenantQueryParamIgnored(t *testing.T) {
	pool := pat1829Pool(t)
	tenantA := pat1829SeedTenant(t, pool)
	tenantB := pat1829SeedTenant(t, pool)
	deviceA := pat1829SeedDevice(t, pool, tenantA, "tenant-a-device")
	deviceB := pat1829SeedDevice(t, pool, tenantB, "tenant-b-device")

	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	pat1969SeedLifecycleEvent(t, pool, tenantA, deviceA, "finding-a", "first_observed", t0, true)
	pat1969SeedLifecycleEvent(t, pool, tenantB, deviceB, "finding-b", "first_observed", t0, true)

	req := pat1969Req("/v1/portal/finding-lifecycle?tenant_id="+tenantB+"&tenantID="+tenantB, tenantA)
	rr := httptest.NewRecorder()
	PortalFindingLifecycleCurrentHandler(pool).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	var resp struct {
		Findings []findingLifecycleCurrentRow `json:"findings"`
		Total    int                          `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || len(resp.Findings) != 1 || resp.Findings[0].FindingKey != "finding-a" {
		t.Fatalf("tenant_id/tenantID query params overrode identity scope: got %+v, want only tenant A's finding-a", resp)
	}
}

// TestPortalFindingLifecycleHandlersPagination mirrors
// TestFindingLifecycleHandlersPagination (the admin-side test in
// finding_dispositions_test.go) at the portal surface: same
// parsePagination-driven limit/offset behaviour as the other portal
// endpoints.
func TestPortalFindingLifecycleHandlersPagination(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "lifecycle-pagination")
	t0 := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	for index, key := range []string{"current-a", "current-b", "current-c"} {
		observedAt := t0.Add(time.Duration(index) * time.Hour)
		pat1969SeedLifecycleEvent(t, pool, tenantID, deviceID, key, "first_observed", observedAt, true)
	}

	currentRecorder := httptest.NewRecorder()
	PortalFindingLifecycleCurrentHandler(pool).ServeHTTP(currentRecorder,
		pat1969Req("/v1/portal/finding-lifecycle?limit=1&offset=1", tenantID))
	if currentRecorder.Code != http.StatusOK {
		t.Fatalf("current status=%d body=%q", currentRecorder.Code, currentRecorder.Body.String())
	}
	var currentResponse struct {
		Findings []findingLifecycleCurrentRow `json:"findings"`
		Total    int                          `json:"total"`
		Limit    int                          `json:"limit"`
		Offset   int                          `json:"offset"`
		Returned int                          `json:"returned"`
	}
	if err := json.NewDecoder(currentRecorder.Body).Decode(&currentResponse); err != nil {
		t.Fatal(err)
	}
	if currentResponse.Total != 1 || currentResponse.Returned != 1 || currentResponse.Limit != 1 || currentResponse.Offset != 1 {
		t.Fatalf("current pagination=%+v, want total/returned/limit/offset 1/1/1/1", currentResponse)
	}
	if len(currentResponse.Findings) != 1 || currentResponse.Findings[0].FindingKey != "current-b" {
		t.Fatalf("current findings=%+v, want second ordered finding current-b", currentResponse.Findings)
	}

	for index, eventType := range []string{"acknowledged", "pending_verification", "verified_fixed"} {
		recordedAt := t0.Add(time.Duration(index+4) * time.Hour)
		observedAt := recordedAt
		authoritative := eventType == "verified_fixed"
		pat1969SeedLifecycleEvent(t, pool, tenantID, deviceID, "history-key", eventType, observedAt, authoritative)
	}

	historyRecorder := httptest.NewRecorder()
	PortalFindingLifecycleHistoryHandler(pool).ServeHTTP(historyRecorder,
		pat1969Req("/v1/portal/finding-lifecycle/history?finding_key=history-key&limit=1&offset=1", tenantID))
	if historyRecorder.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%q", historyRecorder.Code, historyRecorder.Body.String())
	}
	var historyResponse struct {
		Events   []findingLifecycleEventRow `json:"events"`
		Total    int                        `json:"total"`
		Limit    int                        `json:"limit"`
		Offset   int                        `json:"offset"`
		Returned int                        `json:"returned"`
	}
	if err := json.NewDecoder(historyRecorder.Body).Decode(&historyResponse); err != nil {
		t.Fatal(err)
	}
	if historyResponse.Total != 1 || historyResponse.Returned != 1 || historyResponse.Limit != 1 || historyResponse.Offset != 1 {
		t.Fatalf("history pagination=%+v, want total/returned/limit/offset 1/1/1/1", historyResponse)
	}
}

// TestPortalFindingLifecycleCurrent_AuthorityFieldsRoundTrip and its history
// counterpart below pin the field-parity acceptance criterion: the current
// row's status_authoritative/status_observed_at/status_recorded_at and the
// event row's authoritative/observed_at/source_type/actor must round-trip,
// not be dropped or flattened, matching finding_lifecycle.go's admin shape
// exactly.
func TestPortalFindingLifecycleCurrent_AuthorityFieldsRoundTrip(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "authority-fields")
	observedAt := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	pat1969SeedLifecycleEvent(t, pool, tenantID, deviceID, "authority-current", "first_observed", observedAt, true)

	rr := httptest.NewRecorder()
	PortalFindingLifecycleCurrentHandler(pool).ServeHTTP(rr, pat1969Req("/v1/portal/finding-lifecycle", tenantID))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}

	var raw struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(raw.Findings))
	}
	for _, key := range []string{"status_authoritative", "status_observed_at", "status_recorded_at"} {
		if _, ok := raw.Findings[0][key]; !ok {
			t.Errorf("raw JSON current row missing authority field %q — field parity with the admin shape broken", key)
		}
	}

	var resp struct {
		Findings []findingLifecycleCurrentRow `json:"findings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Findings[0].StatusAuthoritative {
		t.Errorf("StatusAuthoritative = false, want true")
	}
	if resp.Findings[0].StatusObservedAt == nil || !resp.Findings[0].StatusObservedAt.Equal(observedAt) {
		t.Errorf("StatusObservedAt = %v, want %v", resp.Findings[0].StatusObservedAt, observedAt)
	}
	if resp.Findings[0].StatusRecordedAt.IsZero() {
		t.Errorf("StatusRecordedAt is zero, want populated")
	}
}

func TestPortalFindingLifecycleHistory_AuthorityFieldsRoundTrip(t *testing.T) {
	pool := pat1829Pool(t)
	tenantID := pat1829SeedTenant(t, pool)
	deviceID := pat1829SeedDevice(t, pool, tenantID, "authority-fields-history")
	observedAt := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)
	pat1969SeedLifecycleEvent(t, pool, tenantID, deviceID, "authority-history", "first_observed", observedAt, true)

	rr := httptest.NewRecorder()
	PortalFindingLifecycleHistoryHandler(pool).ServeHTTP(rr, pat1969Req("/v1/portal/finding-lifecycle/history", tenantID))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}

	var raw struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(raw.Events))
	}
	for _, key := range []string{"authoritative", "observed_at", "source_type", "actor"} {
		if _, ok := raw.Events[0][key]; !ok {
			t.Errorf("raw JSON event row missing authority field %q — field parity with the admin shape broken", key)
		}
	}

	var resp struct {
		Events []findingLifecycleEventRow `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Events[0].Authoritative {
		t.Errorf("Authoritative = false, want true")
	}
	if resp.Events[0].ObservedAt == nil || !resp.Events[0].ObservedAt.Equal(observedAt) {
		t.Errorf("ObservedAt = %v, want %v", resp.Events[0].ObservedAt, observedAt)
	}
	if resp.Events[0].SourceType != "endpoint_observation" {
		t.Errorf("SourceType = %q, want endpoint_observation", resp.Events[0].SourceType)
	}
	if resp.Events[0].Actor != "agent" {
		t.Errorf("Actor = %q, want agent", resp.Events[0].Actor)
	}
}
