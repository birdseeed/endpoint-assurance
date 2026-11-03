package handlers

// PAT-2071 DB-backed tests for the Safari extension-policy vocabulary.
//
// PAT-2064 started storing macOS Safari app-extension rows in
// device_browser_extensions with browser='safari'. Before this ticket the
// only policy row that could ever match a Safari row was one scoped
// browser='any' (extensionValidBrowsers rejected 'safari' outright, and the
// table's CHECK constraint, migration 0071, would have refused the insert
// even if the application layer let it through). These tests drive the real
// handlers end to end against a live Postgres schema so both layers —
// application validation and the DB CHECK constraint widened by migration
// 0178 — are proven together, not just the in-process map lookup.
//
// DB-backed: requires TEST_DATABASE_URL and is skipped otherwise, reusing
// pat1147BoundedPool/parSeedTenant/rrInsertDeviceOS/newExtChiRequest rather
// than inventing new helpers (see posture_app_policy_db_test.go for why a
// bounded pool, allowlist_agent_known_path_test.go for parSeedTenant).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtensionPolicy_SafariPolicyPersistsAndMatchesOnlySafariRows(t *testing.T) {
	pool := pat1147BoundedPool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool,
		"pat2071-safari-policy-tenant", "pat2071-safari-policy-token", "pat2071-safari-policy-hmac-secret32")
	deviceID := rrInsertDeviceOS(t, pool, tenantID, "77777777-8888-9999-aaaa-bbbbbbbbbb01", 0, "macOS")

	const extID = "com.example.safariext"   // gets a safari-scoped policy
	const extID2 = "com.example.chromeonly" // gets a chrome-scoped policy

	// One row per browser, same extension_id per pair, so a browser-scoped
	// policy that leaked across browsers would show up as a false match.
	for _, browser := range []string{"chrome", "safari"} {
		for _, id := range []string{extID, extID2} {
			if _, err := pool.Exec(ctx, `
				INSERT INTO device_browser_extensions
				    (device_id, browser, extension_id, name, version, profile, user_account, permissions, risk_level)
				VALUES ($1::uuid, $2, $3, 'Example Extension', '1.0', 'Default', 'andy', '[]'::jsonb, 'standard')
			`, deviceID, browser, id); err != nil {
				t.Fatalf("seed %s/%s extension row: %v", browser, id, err)
			}
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_browser_extensions WHERE device_id = $1::uuid`, deviceID)
	})

	// --- Add handler: a browser='safari' policy must be accepted, and must
	// actually persist as 'safari' (proves migration 0178 widened the live
	// CHECK constraint, not just the in-process validBrowsers map). ---
	addBody := `{"extension_id":"` + extID + `","browser":"safari","policy":"unapproved","approved_by":"andy"}`
	addReq := newExtChiRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/extension-policies", tenantID, "", addBody)
	addRR := httptest.NewRecorder()
	TenantExtensionPolicyAddHandler(pool).ServeHTTP(addRR, addReq)
	if addRR.Code != http.StatusCreated {
		t.Fatalf("want 201 creating safari policy, got %d: %s", addRR.Code, addRR.Body.String())
	}
	var added extensionPolicyJSON
	if err := json.Unmarshal(addRR.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode add response: %v", err)
	}
	if added.Browser != "safari" {
		t.Fatalf("want browser=safari in response, got %q", added.Browser)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_extension_policies WHERE tenant_id = $1::uuid`, tenantID)
	})

	var storedBrowser string
	if err := pool.QueryRow(ctx, `SELECT browser FROM tenant_extension_policies WHERE id = $1`, added.ID).Scan(&storedBrowser); err != nil {
		t.Fatalf("read back stored policy: %v", err)
	}
	if storedBrowser != "safari" {
		t.Fatalf("want stored browser=safari (CHECK constraint should allow it), got %q", storedBrowser)
	}

	// A chrome-scoped policy on a different extension_id must not match that
	// extension's safari row either — the converse direction of the same
	// browser-exact matching rule.
	chromeAddBody := `{"extension_id":"` + extID2 + `","browser":"chrome","policy":"unapproved","approved_by":"andy"}`
	chromeAddReq := newExtChiRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/extension-policies", tenantID, "", chromeAddBody)
	chromeAddRR := httptest.NewRecorder()
	TenantExtensionPolicyAddHandler(pool).ServeHTTP(chromeAddRR, chromeAddReq)
	if chromeAddRR.Code != http.StatusCreated {
		t.Fatalf("want 201 creating chrome policy, got %d: %s", chromeAddRR.Code, chromeAddRR.Body.String())
	}

	// --- Scan handler: the safari policy must match the safari row and
	// leave the chrome row (same extension_id) unmatched; the chrome policy
	// on extID2 must match only its chrome row and leave its safari row
	// unmatched. ---
	scanReq := newExtChiRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/extension-policies/scan", tenantID, "", "")
	scanRR := httptest.NewRecorder()
	TenantExtensionPolicyScanHandler(pool).ServeHTTP(scanRR, scanReq)
	if scanRR.Code != http.StatusOK {
		t.Fatalf("want 200 scanning, got %d: %s", scanRR.Code, scanRR.Body.String())
	}
	var scan extensionScanResp
	if err := json.Unmarshal(scanRR.Body.Bytes(), &scan); err != nil {
		t.Fatalf("decode scan response: %v", err)
	}
	var gotSafariExt, gotChromeExt, gotSafariExt2, gotChromeExt2 bool
	for _, item := range scan.Extensions {
		switch {
		case item.ExtensionID == extID && item.Browser == "safari":
			gotSafariExt = true
			if item.Status != "unapproved" {
				t.Errorf("safari/%s row: want status=unapproved (matched by the safari policy), got %q", extID, item.Status)
			}
		case item.ExtensionID == extID && item.Browser == "chrome":
			gotChromeExt = true
			if item.Status != "unreviewed" {
				t.Errorf("chrome/%s row: want status=unreviewed (a safari-scoped policy must not match chrome), got %q", extID, item.Status)
			}
		case item.ExtensionID == extID2 && item.Browser == "chrome":
			gotChromeExt2 = true
			if item.Status != "unapproved" {
				t.Errorf("chrome/%s row: want status=unapproved (matched by the chrome policy), got %q", extID2, item.Status)
			}
		case item.ExtensionID == extID2 && item.Browser == "safari":
			gotSafariExt2 = true
			if item.Status != "unreviewed" {
				t.Errorf("safari/%s row: want status=unreviewed (a chrome-scoped policy must not match safari), got %q", extID2, item.Status)
			}
		}
	}
	if !gotSafariExt || !gotChromeExt || !gotSafariExt2 || !gotChromeExt2 {
		t.Fatalf("scan is missing an expected row: safari/extID=%v chrome/extID=%v chrome/extID2=%v safari/extID2=%v",
			gotSafariExt, gotChromeExt, gotChromeExt2, gotSafariExt2)
	}
}
