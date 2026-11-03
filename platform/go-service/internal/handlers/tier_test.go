package handlers

// PAT-650 — subscription-tier enforcement tests.
//
// All tests here run against a stubbed tierLoader, so they exercise the
// middleware/helper logic (ordering, rejection body, caching, error paths)
// without a database.
//
// PAT-1599 (migration 0138): rewritten for the two-value vocabulary
// (assurance/managed), collapsed from the old three-rung ladder
// (report/patch/full_endpoint). Unknown/retired values still fail closed —
// see the "garbage tier" and unknown-value cases below.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

const (
	tierTestTenantID = "11111111-2222-3333-4444-555555555555"
)

// stubTierLoader returns a tierLoader that serves tiers[tenantID], counting
// calls through *calls. Unknown tenants get errTierTenantNotFound.
func stubTierLoader(tiers map[string]string, calls *int) tierLoader {
	return func(_ context.Context, tenantID string) (string, error) {
		if calls != nil {
			*calls++
		}
		tier, ok := tiers[tenantID]
		if !ok {
			return "", errTierTenantNotFound
		}
		return tier, nil
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// ---------------------------------------------------------------------------
// Pure ordering logic
// ---------------------------------------------------------------------------

func TestTierAtLeast(t *testing.T) {
	cases := []struct {
		tier, minTier string
		want          bool
	}{
		{subTierAssurance, subTierAssurance, true},
		{subTierAssurance, subTierManaged, false},
		{subTierManaged, subTierAssurance, true},
		{subTierManaged, subTierManaged, true},
		// Unknown/retired values fail closed on either side.
		{"", subTierAssurance, false},
		{"enterprise", subTierManaged, false},
		{subTierManaged, "bogus", false},
		{"report", subTierAssurance, false},
		{"patch", subTierManaged, false},
		{"full_endpoint", subTierAssurance, false},
	}
	for _, tc := range cases {
		t.Run(tc.tier+"_vs_"+tc.minTier, func(t *testing.T) {
			if got := tierAtLeast(tc.tier, tc.minTier); got != tc.want {
				t.Errorf("tierAtLeast(%q, %q) = %v, want %v", tc.tier, tc.minTier, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Middleware-level tests — independent of any real handler logic
// ---------------------------------------------------------------------------

// wantTierBody asserts the canonical 403 rejection payload.
func wantTierBody(t *testing.T, rr *httptest.ResponseRecorder, minTier string) {
	t.Helper()
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not JSON: %v (body=%q)", err, rr.Body.String())
	}
	want := "feature requires subscription tier: " + minTier
	if body["error"] != want {
		t.Errorf("error = %q, want %q", body["error"], want)
	}
}

func TestRequireSubscriptionTierMiddleware(t *testing.T) {
	cases := []struct {
		name       string
		tenantTier string
		minTier    string
		wantStatus int
	}{
		{"assurance_below_managed", subTierAssurance, subTierManaged, http.StatusForbidden},
		{"assurance_meets_assurance", subTierAssurance, subTierAssurance, http.StatusOK},
		{"managed_meets_assurance", subTierManaged, subTierAssurance, http.StatusOK},
		{"managed_meets_managed", subTierManaged, subTierManaged, http.StatusOK},
		{"garbage_tier_fails_closed", "enterprise", subTierManaged, http.StatusForbidden},
		{"retired_tier_fails_closed", "patch", subTierAssurance, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			load := stubTierLoader(map[string]string{tierTestTenantID: tc.tenantTier}, nil)
			h := requireSubscriptionTier(load, tc.minTier)(okHandler())

			req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tierTestTenantID+"/x", nil)
			req = withChiParam(req, "tenantID", tierTestTenantID)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%q)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden {
				wantTierBody(t, rr, tc.minTier)
			}
		})
	}
}

func TestRequireSubscriptionTierTenantNotFound(t *testing.T) {
	load := stubTierLoader(map[string]string{}, nil)
	h := requireSubscriptionTier(load, subTierManaged)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tierTestTenantID+"/x", nil)
	req = withChiParam(req, "tenantID", tierTestTenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestRequireSubscriptionTierLoaderError(t *testing.T) {
	load := func(context.Context, string) (string, error) {
		return "", errors.New("db exploded")
	}
	h := requireSubscriptionTier(load, subTierManaged)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tierTestTenantID+"/x", nil)
	req = withChiParam(req, "tenantID", tierTestTenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// A missing or malformed tenantID param must fall through to the handler's
// own validation (which returns 400), never bypass INTO gated logic silently
// and never 500.
func TestRequireSubscriptionTierNonUUIDPassesThrough(t *testing.T) {
	loaderCalls := 0
	load := stubTierLoader(map[string]string{}, &loaderCalls)
	handlerHit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerHit = true
		http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
	})
	h := requireSubscriptionTier(load, subTierManaged)(next)

	for _, id := range []string{"", "not-a-uuid"} {
		handlerHit = false
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/x/x", nil)
		req = withChiParam(req, "tenantID", id)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if !handlerHit {
			t.Errorf("id=%q: handler not reached", id)
		}
		if rr.Code != http.StatusBadRequest {
			t.Errorf("id=%q: status = %d, want 400", id, rr.Code)
		}
	}
	if loaderCalls != 0 {
		t.Errorf("loader called %d times for non-UUID params, want 0", loaderCalls)
	}
}

// The middleware caches the resolved tier in the request context: a
// downstream check for the same tenant must not hit the loader again.
func TestTenantTierContextCache(t *testing.T) {
	loaderCalls := 0
	load := stubTierLoader(map[string]string{tierTestTenantID: subTierManaged}, &loaderCalls)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a handler re-checking the tier via the shared helper.
		if !requireTenantTier(w, r, load, tierTestTenantID, subTierManaged) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := requireSubscriptionTier(load, subTierManaged)(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tierTestTenantID+"/x", nil)
	req = withChiParam(req, "tenantID", tierTestTenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if loaderCalls != 1 {
		t.Errorf("loader called %d times, want 1 (context cache should serve the second check)", loaderCalls)
	}
}

// ---------------------------------------------------------------------------
// Agent-route helper — requireTenantTier
// ---------------------------------------------------------------------------

func TestRequireTenantTierHelper(t *testing.T) {
	cases := []struct {
		name       string
		tenantTier string
		minTier    string
		wantOK     bool
		wantStatus int // only checked when !wantOK
	}{
		{"assurance_blocked_on_managed", subTierAssurance, subTierManaged, false, http.StatusForbidden},
		{"managed_allowed_on_managed", subTierManaged, subTierManaged, true, 0},
		{"managed_allowed_on_assurance", subTierManaged, subTierAssurance, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			load := stubTierLoader(map[string]string{tierTestTenantID: tc.tenantTier}, nil)
			req := httptest.NewRequest(http.MethodGet, "/v1/allowlist/pending-removals", nil)
			rr := httptest.NewRecorder()

			ok := requireTenantTier(rr, req, load, tierTestTenantID, tc.minTier)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				if rr.Code != tc.wantStatus {
					t.Errorf("status = %d, want %d", rr.Code, tc.wantStatus)
				}
				wantTierBody(t, rr, tc.minTier)
			}
		})
	}
}

func TestRequireTenantTierHelperLoaderError(t *testing.T) {
	load := func(context.Context, string) (string, error) {
		return "", errors.New("db exploded")
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/allowlist/pending-removals", nil)
	rr := httptest.NewRecorder()

	if requireTenantTier(rr, req, load, tierTestTenantID, subTierManaged) {
		t.Fatal("ok = true on loader error, want false")
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Route-level tests — the PAT-650 acceptance matrix over a real chi router,
// mirroring the production wiring in cmd/patched-api (r.With(gate).Method(...)).
//
// PAT-1599: production now gates both route classes (app-policy/allowlist
// and app-control) on the same minimum, TierManaged — see needsPatch and
// needsFullEndpoint in cmd/patched-api/main.go, which both resolve to
// RequireSubscriptionTier(pool, handlers.TierManaged). This matrix mirrors
// that: an assurance tenant is forbidden from every gated route, a managed
// tenant is allowed into all of them, and the ungated tenant-management
// routes stay open at any tier.
// ---------------------------------------------------------------------------

func TestTierEnforcementAcceptanceMatrix(t *testing.T) {
	tenants := map[string]string{
		"aaaaaaaa-0000-0000-0000-000000000001": subTierAssurance,
		"aaaaaaaa-0000-0000-0000-000000000002": subTierManaged,
	}
	load := stubTierLoader(tenants, nil)

	r := chi.NewRouter()
	needsManaged := requireSubscriptionTier(load, subTierManaged)
	// Representative routes for each gate class, matching production paths.
	r.With(needsManaged).Get("/admin/tenant-app-policy/{tenantID}", okHandler().ServeHTTP)
	r.With(needsManaged).Post("/admin/tenants/{tenantID}/allowlist", okHandler().ServeHTTP)
	r.With(needsManaged).Get("/admin/tenants/{tenantID}/app-control", okHandler().ServeHTTP)
	// Ungated tenant-management routes must work at any tier.
	r.Put("/admin/tenant-tier/{tenantID}", okHandler().ServeHTTP)
	r.Get("/admin/tenants/{tenantID}/devices", okHandler().ServeHTTP)

	type routeCase struct {
		method, pathTpl string
		want            map[string]int // tier → expected status
	}
	routes := []routeCase{
		{http.MethodGet, "/admin/tenant-app-policy/%s", map[string]int{
			subTierAssurance: http.StatusForbidden,
			subTierManaged:   http.StatusOK,
		}},
		{http.MethodPost, "/admin/tenants/%s/allowlist", map[string]int{
			subTierAssurance: http.StatusForbidden,
			subTierManaged:   http.StatusOK,
		}},
		{http.MethodGet, "/admin/tenants/%s/app-control", map[string]int{
			subTierAssurance: http.StatusForbidden,
			subTierManaged:   http.StatusOK,
		}},
		{http.MethodPut, "/admin/tenant-tier/%s", map[string]int{
			subTierAssurance: http.StatusOK,
			subTierManaged:   http.StatusOK,
		}},
		{http.MethodGet, "/admin/tenants/%s/devices", map[string]int{
			subTierAssurance: http.StatusOK,
			subTierManaged:   http.StatusOK,
		}},
	}

	for tenantID, tier := range tenants {
		for _, rc := range routes {
			path := fmt.Sprintf(rc.pathTpl, tenantID)
			t.Run(tier+"_"+rc.method+"_"+path, func(t *testing.T) {
				req := httptest.NewRequest(rc.method, path, nil)
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, req)
				if rr.Code != rc.want[tier] {
					t.Errorf("tier=%s %s %s: status = %d, want %d (body=%q)",
						tier, rc.method, path, rr.Code, rc.want[tier], rr.Body.String())
				}
			})
		}
	}
}
