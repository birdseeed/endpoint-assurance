package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/db"
)

// TestParsePagination checks that limit and offset are correctly parsed,
// defaulted, and clamped. Pure function; no DB required.
func TestParsePagination(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantLimit  int
		wantOffset int
	}{
		{
			name:       "defaults when no params",
			query:      "",
			wantLimit:  defaultPageLimit,
			wantOffset: 0,
		},
		{
			name:       "valid limit and offset",
			query:      "?limit=10&offset=20",
			wantLimit:  10,
			wantOffset: 20,
		},
		{
			name:       "limit capped at maxPageLimit",
			query:      "?limit=9999",
			wantLimit:  maxPageLimit,
			wantOffset: 0,
		},
		{
			name:       "negative limit ignored, default used",
			query:      "?limit=-5",
			wantLimit:  defaultPageLimit,
			wantOffset: 0,
		},
		{
			name:       "zero limit ignored, default used",
			query:      "?limit=0",
			wantLimit:  defaultPageLimit,
			wantOffset: 0,
		},
		{
			name:       "negative offset ignored, default used",
			query:      "?offset=-1",
			wantLimit:  defaultPageLimit,
			wantOffset: 0,
		},
		{
			name:       "non-numeric params ignored",
			query:      "?limit=abc&offset=xyz",
			wantLimit:  defaultPageLimit,
			wantOffset: 0,
		},
		{
			name:       "limit 1 is valid minimum",
			query:      "?limit=1",
			wantLimit:  1,
			wantOffset: 0,
		},
		{
			name:       "offset zero is valid",
			query:      "?offset=0",
			wantLimit:  defaultPageLimit,
			wantOffset: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test"+tc.query, nil)
			gotLimit, gotOffset := parsePagination(req)
			if gotLimit != tc.wantLimit {
				t.Errorf("limit: got %d, want %d", gotLimit, tc.wantLimit)
			}
			if gotOffset != tc.wantOffset {
				t.Errorf("offset: got %d, want %d", gotOffset, tc.wantOffset)
			}
		})
	}
}

// TestTenantOverviewEntryJSONFields verifies that tenantOverviewEntry
// marshals all PAT-677/676 health and engagement fields into JSON correctly,
// including pointer fields serialised as null when nil.
func TestTenantOverviewEntryJSONFields(t *testing.T) {
	score := 82
	bucket := "healthy"
	now := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	cur := 85
	ago := 78

	e := tenantOverviewEntry{
		ID:                      "00000000-0000-0000-0000-000000000001",
		Name:                    "Acme Corp",
		Tier:                    "report_deploy",
		TenantKind:              "customer",
		MacOSEnabled:            true,
		WindowsEnabled:          false,
		DeviceCount:             10,
		ActiveLast7d:            8,
		CompliancePct:           92.5,
		CritHighFails:           0,
		NewAppsAwaitingDecision: 2,
		IsTrial:                 false,
		TrialExpiresAt:          nil,
		HealthScore:             &score,
		HealthBucket:            &bucket,
		HealthScoreComputedAt:   &now,
		ComplianceScoreCurrent:  &cur,
		ComplianceScore30dAgo:   &ago,
		LastDashboardLoginAt:    &now,
		DashboardLoginsLast30d:  5,
		PaymentFailed:           false,
	}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	wantKeys := []string{
		"id", "name", "tier", "tenant_kind", "macos_enabled", "windows_enabled",
		"device_count", "active_last_7d", "compliance_pct",
		"crit_high_fail_count", "new_apps_awaiting_decision",
		"is_trial",
		"health_score", "health_bucket", "health_score_computed_at",
		"compliance_score_current", "compliance_score_30d_ago",
		"last_dashboard_login_at", "dashboard_logins_last_30d", "payment_failed",
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("JSON key %q missing from marshalled output", k)
		}
	}

	// Spot-check values
	if got["tenant_kind"] != "customer" {
		t.Errorf("tenant_kind: got %v, want customer", got["tenant_kind"])
	}
	if got["health_score"] != float64(score) {
		t.Errorf("health_score: got %v, want %v", got["health_score"], score)
	}
	if got["health_bucket"] != bucket {
		t.Errorf("health_bucket: got %v, want %v", got["health_bucket"], bucket)
	}
	if got["compliance_score_current"] != float64(cur) {
		t.Errorf("compliance_score_current: got %v, want %d", got["compliance_score_current"], cur)
	}
	if got["compliance_score_30d_ago"] != float64(ago) {
		t.Errorf("compliance_score_30d_ago: got %v, want %d", got["compliance_score_30d_ago"], ago)
	}
	if got["dashboard_logins_last_30d"] != float64(5) {
		t.Errorf("dashboard_logins_last_30d: got %v, want 5", got["dashboard_logins_last_30d"])
	}
	if got["payment_failed"] != false {
		t.Errorf("payment_failed: got %v, want false", got["payment_failed"])
	}
}

// TestTenantOverviewEntryNullHealthFields verifies that health-score pointer
// fields render as JSON null when not yet computed (pre-first nightly run).
func TestTenantOverviewEntryNullHealthFields(t *testing.T) {
	e := tenantOverviewEntry{
		ID:   "00000000-0000-0000-0000-000000000002",
		Name: "New Tenant",
		Tier: "report_deploy",
		// HealthScore, HealthBucket, etc. intentionally nil
	}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	for _, k := range []string{"health_score", "health_bucket", "health_score_computed_at",
		"compliance_score_current", "compliance_score_30d_ago", "last_dashboard_login_at"} {
		v, ok := got[k]
		if !ok {
			t.Errorf("JSON key %q missing", k)
			continue
		}
		if v != nil {
			t.Errorf("key %q: expected null but got %v", k, v)
		}
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenants/{tenantID}/kind — validation (no DB required: both the
// UUID check and the enum check happen before any DB call, same pattern as
// TestTrialNotifyHandlerUUIDValidation in trial_admin_test.go).
// ---------------------------------------------------------------------------

func TestTenantKindPutHandlerValidation(t *testing.T) {
	validTenantID := "00000000-0000-0000-0000-000000000001"

	cases := []struct {
		name     string
		tenantID string
		body     string
		wantCode int
	}{
		{name: "non-UUID tenant id", tenantID: "not-a-uuid", body: `{"tenant_kind":"customer"}`, wantCode: http.StatusBadRequest},
		{name: "empty tenant id", tenantID: "", body: `{"tenant_kind":"customer"}`, wantCode: http.StatusBadRequest},
		{name: "invalid tenant_kind value", tenantID: validTenantID, body: `{"tenant_kind":"vip"}`, wantCode: http.StatusBadRequest},
		{name: "empty tenant_kind value", tenantID: validTenantID, body: `{"tenant_kind":""}`, wantCode: http.StatusBadRequest},
		{name: "malformed JSON body", tenantID: validTenantID, body: `{not json`, wantCode: http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// nil pool is safe: every case above is rejected before the
			// handler reaches its DB call.
			h := TenantKindPutHandler(nil)
			req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tc.tenantID+"/kind", strings.NewReader(tc.body))
			req = withChiParam(req, "tenantID", tc.tenantID)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantCode {
				t.Errorf("got %d, want %d (body: %s)", rr.Code, tc.wantCode, rr.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenants/{tenantID}/kind — DB round-trip. Skipped when
// TEST_DATABASE_URL is not set, same pattern as TestTrialAdminDB.
// ---------------------------------------------------------------------------

func TestTenantKindPutHandlerDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping tenant_kind PUT DB round-trip test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('PAT-1562 kind-put test', '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		                                   '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

	// New tenant defaults to 'customer' (migration 0119's DEFAULT).
	var initialKind string
	if err := pool.QueryRow(ctx, `SELECT tenant_kind FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&initialKind); err != nil {
		t.Fatalf("read initial tenant_kind: %v", err)
	}
	if initialKind != "customer" {
		t.Fatalf("initial tenant_kind = %q, want customer", initialKind)
	}

	h := TenantKindPutHandler(pool)

	// Valid update: customer -> internal.
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/kind", strings.NewReader(`{"tenant_kind":"internal"}`))
	req = withChiParam(req, "tenantID", tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: got %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	var got string
	if err := pool.QueryRow(ctx, `SELECT tenant_kind FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&got); err != nil {
		t.Fatalf("read updated tenant_kind: %v", err)
	}
	if got != "internal" {
		t.Errorf("tenant_kind after update = %q, want internal", got)
	}

	// Nonexistent tenant -> 404.
	req = httptest.NewRequest(http.MethodPut, "/admin/tenants/00000000-0000-0000-0000-0000000000ff/kind", strings.NewReader(`{"tenant_kind":"customer"}`))
	req = withChiParam(req, "tenantID", "00000000-0000-0000-0000-0000000000ff")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("nonexistent tenant: got %d, want 404", rr.Code)
	}

	// Revoked tenant -> 404 (the UPDATE's own WHERE clause excludes revoked rows).
	if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, tenantID); err != nil {
		t.Fatalf("revoke tenant: %v", err)
	}
	req = httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/kind", strings.NewReader(`{"tenant_kind":"customer"}`))
	req = withChiParam(req, "tenantID", tenantID)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("revoked tenant: got %d, want 404", rr.Code)
	}
}
