package handlers

// Tests for PAT-1121: TenantAppPoliciesPutHandler's validTiers must accept
// both the legacy admin-API vocabulary (report/app_management/managed) and
// the canonical agent-config vocabulary (report_deploy/patch/managed) on
// input, while an unrecognized tier still fails closed with 400.
//
// PAT-1250 (PAT-1121 step 3) flipped the writer: a legacy input is now
// rewritten to its canonical spelling before storage, so it no longer
// round-trips unchanged — see app_policies.go's legacyTierToCanonical and
// canonicalizeTier.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/notify"
)

// TestAppPoliciesPutRefusesAmbiguousWingetIdentityDuringMixedVersionRollout
// proves migration 0110's retained four-field uniqueness arbiter cannot turn
// a second Winget-only policy into a generic 500 (or, worse, let an older
// binary update the first policy). Until every API binary understands
// winget_id, this otherwise-valid second identity is an explicit 409.
func TestAppPoliciesPutRefusesAmbiguousWingetIdentityDuringMixedVersionRollout(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "winget-mixed-version-conflict")
	h := TenantAppPoliciesPutHandler(pool, notify.New())

	put := func(wingetID string) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"winget_id":"` + wingetID + `","platform":"windows","policy":"mandatory","enforcement_tier":"patch"}`
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
		req = catWithTenantID(req, tenantID)
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}

	if w := put("Microsoft.PowerToys"); w.Code != http.StatusOK {
		t.Fatalf("first Winget-only policy: want 200, got %d: %s", w.Code, w.Body.String())
	}
	w := put("Notepad++.Notepad++")
	if w.Code != http.StatusConflict {
		t.Fatalf("second Winget-only policy: want 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mixed-version policy identity") {
		t.Fatalf("second Winget-only policy returned non-diagnostic conflict: %s", w.Body.String())
	}

	var count int
	var storedWingetID string
	if err := pool.QueryRow(ctx, `
		SELECT count(*), min(winget_id)
		FROM tenant_app_policies
		WHERE tenant_id=$1::uuid AND platform='windows'
	`, tenantID).Scan(&count, &storedWingetID); err != nil {
		t.Fatal(err)
	}
	if count != 1 || storedWingetID != "microsoft.powertoys" {
		t.Fatalf("conflicting request mutated policy set: count=%d winget_id=%q", count, storedWingetID)
	}
}

// ---------------------------------------------------------------------------
// Pure-logic (nil-pool) test — unknown tier must still be rejected before any
// DB access, matching the catalogue_test.go nil-pool convention.
// ---------------------------------------------------------------------------

func TestAppPoliciesPutRejectsUnknownEnforcementTier(t *testing.T) {
	h := TenantAppPoliciesPutHandler(nil, notify.New())
	// A syntactically valid UUID so the handler gets past the tenantID
	// format check and reaches enum validation without touching the pool.
	tenantID := "00000000-0000-0000-0000-000000000000"
	body := `{"name":"Some App","platform":"any","policy":"unapproved","enforcement_tier":"bogus"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown enforcement_tier, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAppPoliciesPutRejectsInvalidWingetPackageIdentifierBeforeDatabase(t *testing.T) {
	h := TenantAppPoliciesPutHandler(nil, notify.New())
	for _, id := range []string{"single-segment", "bad..segment", "bad/package.id", " leading.package"} {
		body := `{"winget_id":"` + id + `","platform":"windows","policy":"mandatory","enforcement_tier":"patch"}`
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/00000000-0000-0000-0000-000000000000/app-policies", bytes.NewBufferString(body))
		req = catWithTenantID(req, "00000000-0000-0000-0000-000000000000")
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("winget_id %q status=%d want 400: %s", id, w.Code, w.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// DB-backed test — every one of the five accepted values must round-trip
// through the PUT endpoint as 200, and the RESPONSE (which reflects what was
// actually stored, via RETURNING) must carry the CANONICAL spelling: legacy
// input is rewritten on write (PAT-1250), canonical input round-trips
// unchanged, and "managed" (shared by both vocabularies) is untouched.
// ---------------------------------------------------------------------------

func TestAppPoliciesPutNormalizesLegacyTiersToCanonicalOnWrite(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := catSeedTenant(t, ctx, pool, "tier-vocab-test")
	h := TenantAppPoliciesPutHandler(pool, notify.New())

	cases := []struct {
		name      string
		inputTier string
		wantTier  string
	}{
		{"legacy report maps to canonical report_deploy", "report", "report_deploy"},
		{"canonical report_deploy round-trips unchanged", "report_deploy", "report_deploy"},
		{"legacy app_management maps to canonical patch", "app_management", "patch"},
		{"canonical patch round-trips unchanged", "patch", "patch"},
		{"managed (shared name) round-trips unchanged", "managed", "managed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Distinct app name per case so each PUT is a fresh insert, not
			// an upsert collision on the (team_id, bundle_id, name, platform)
			// identity index.
			appName := "Tier Vocab App " + tc.inputTier
			body := `{"name":"` + appName + `","platform":"any","policy":"approved","enforcement_tier":"` + tc.inputTier + `"}`
			req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
			req = catWithTenantID(req, tenantID)
			w := httptest.NewRecorder()
			h(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("tier %q: want 200, got %d: %s", tc.inputTier, w.Code, w.Body.String())
			}

			var got appPolicyRow
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("tier %q: decode response: %v", tc.inputTier, err)
			}
			if got.EnforcementTier != tc.wantTier {
				t.Fatalf("input tier %q: response enforcement_tier = %q, want %q", tc.inputTier, got.EnforcementTier, tc.wantTier)
			}

			// Confirm the DB row itself (not just the response) holds the
			// canonical value — the response is only trustworthy evidence of
			// storage because it comes from RETURNING, but assert directly
			// against the table too so a future refactor that stops using
			// RETURNING can't silently break this guarantee unnoticed.
			var stored string
			if err := pool.QueryRow(ctx, `SELECT enforcement_tier FROM tenant_app_policies WHERE id = $1`, got.ID).Scan(&stored); err != nil {
				t.Fatalf("tier %q: query stored row: %v", tc.inputTier, err)
			}
			if stored != tc.wantTier {
				t.Fatalf("input tier %q: DB row enforcement_tier = %q, want %q", tc.inputTier, stored, tc.wantTier)
			}
		})
	}
}

// TestAppPoliciesPutDefaultsToCanonicalTier verifies that an omitted
// enforcement_tier (empty string) defaults to canonical "report_deploy", not
// the legacy "report" (PAT-1250).
func TestAppPoliciesPutDefaultsToCanonicalTier(t *testing.T) {
	pool := catConnectOrSkip(t)
	defer pool.Close()

	tenantID := catSeedTenant(t, context.Background(), pool, "tier-default-test")
	h := TenantAppPoliciesPutHandler(pool, notify.New())

	body := `{"name":"Tier Default App","platform":"any","policy":"approved"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+tenantID+"/app-policies", bytes.NewBufferString(body))
	req = catWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var got appPolicyRow
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.EnforcementTier != "report_deploy" {
		t.Fatalf("default enforcement_tier = %q, want canonical %q", got.EnforcementTier, "report_deploy")
	}
}
