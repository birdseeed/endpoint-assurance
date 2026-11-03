//go:build integration

package integration

// PAT-2064: Safari app-extension rows end to end. Safari extensions live in
// an app bundle, not a browser user profile, so the macOS agent has always
// sent browser_extensions rows for Safari with user_account: null (and no
// profile). device_browser_extensions.user_account/profile are NOT NULL, so
// browserExtValid silently dropped every one of these rows — Safari never
// reached device_browser_extensions, the portal or reports. These tests go
// through the real POST /v1/inventory handler and the real extractor.

import (
	"context"
	"testing"

	"patched.im/api/internal/extpresence"
)

// beSafariExt builds a Safari browser_extensions row exactly as the macOS
// agent sends it: no profile, no user_account.
func beSafariExt(id, name string) map[string]any {
	return map[string]any{
		"browser": "safari", "profile": nil, "user_account": nil,
		"extension_id": id, "name": name, "version": "1.0", "enabled": true,
		"permissions": []string{}, "host_permissions": []string{}, "from_webstore": false,
	}
}

// extPresent evaluates extpresence.PresentSQL directly against one stored
// device_browser_extensions row. The legacy fallback is pinned to TRUE
// because every test using this helper has already sent a
// browser_extensions_status block, so StatusKnownSQL is true and the legacy
// arm is never reached.
func extPresent(t *testing.T, deviceID, browser, userAccount, profile, extID string) bool {
	t.Helper()
	q := `SELECT ` + extpresence.PresentSQL("dbe", "TRUE") + `
		FROM device_browser_extensions dbe
		WHERE dbe.device_id = $1::uuid AND dbe.browser = $2 AND dbe.user_account = $3
		  AND dbe.profile = $4 AND dbe.extension_id = $5`
	var present bool
	if err := env.pool.QueryRow(context.Background(), q, deviceID, browser, userAccount, profile, extID).Scan(&present); err != nil {
		t.Fatalf("presence query: %v", err)
	}
	return present
}

// A Safari row with a null user_account and profile is stored under the
// fixed _system sentinel, and a second identical ingest upserts the same row
// rather than duplicating it.
func TestSafariExtensionNullUserAccountStoredAndUpserts(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2064-safari-"+sfx)
	hw := newHW(sfx)
	extID := "com.example.safariext." + sfx

	device := bePost(t, tn, hw, []map[string]any{beSafariExt(extID, "Safari Ext "+sfx)}, nil)

	var userAccount, profile string
	if err := env.pool.QueryRow(context.Background(), `
		SELECT user_account, profile FROM device_browser_extensions
		WHERE device_id = $1::uuid AND browser = 'safari' AND extension_id = $2
	`, device, extID).Scan(&userAccount, &profile); err != nil {
		t.Fatalf("select safari ext: %v", err)
	}
	if userAccount != "_system" {
		t.Errorf("user_account = %q, want _system sentinel", userAccount)
	}
	if profile != "_system" {
		t.Errorf("profile = %q, want _system sentinel", profile)
	}

	// Re-ingest the identical row: ON CONFLICT must upsert, not duplicate.
	bePost(t, tn, hw, []map[string]any{beSafariExt(extID, "Safari Ext "+sfx)}, nil)
	if n := countRows(t, `SELECT count(*) FROM device_browser_extensions
		WHERE device_id = $1::uuid AND browser = 'safari' AND extension_id = $2`, device, extID); n != 1 {
		t.Fatalf("row count after re-ingest = %d, want 1 (no duplicate)", n)
	}
}

// The absence-authority regression this fix exists to close: a device-wide
// "complete" browser_extensions_status report is authoritative only for
// chrome/edge/firefox (browser_extensions_status has no Safari vocabulary at
// all), but its device-level authority (browser_extension_device_state) is
// keyed on device_id alone, with no browser column. Left unguarded, that
// report would still count as authority to mark a still-installed Safari
// extension gone — an incomplete report closing a finding it never touched.
// The chrome extension in the same report IS correctly marked absent, to
// prove this test exercises the same "complete report after last_seen"
// mechanism the existing PAT-2055 tests cover, just also carrying a Safari
// row that must survive it.
func TestSafariExtensionNeverRemovedByDeviceLevelAuthority(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2064-absence-"+sfx)
	hw := newHW(sfx)
	chromeExtID := chromeID(t)
	safariExtID := "com.example.safariabsence." + sfx

	device := bePost(t, tn, hw,
		[]map[string]any{
			beExt("chrome", "alice", chromeExtID, "Chrome "+sfx),
			beSafariExt(safariExtID, "Safari "+sfx),
		}, nil)

	if !extPresent(t, device, "chrome", "alice", "Default", chromeExtID) {
		t.Fatal("chrome extension not present after initial ingest")
	}
	if !extPresent(t, device, "safari", "_system", "_system", safariExtID) {
		t.Fatal("safari extension not present after initial ingest")
	}

	ageExtensions(t, device)

	// A device-wide "complete" report for alice's chrome/edge/firefox. It
	// never mentions Safari at all — browser_extensions_status has no key
	// for it — yet it is authoritative for the whole device under
	// browser_extension_device_state.
	bePost(t, tn, hw, nil, beStatus("complete", false, beStatusUser("alice", "complete", "complete", "not_present", "not_present")))

	if extPresent(t, device, "chrome", "alice", "Default", chromeExtID) {
		t.Fatal("chrome extension should be absent: a complete report arrived strictly after its last_seen")
	}
	if !extPresent(t, device, "safari", "_system", "_system", safariExtID) {
		t.Fatal("a device-complete report that never covered Safari made a Safari extension absent without authority")
	}
}
