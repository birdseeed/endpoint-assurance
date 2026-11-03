//go:build integration

package integration

// PAT-2055: browser_extensions_status end to end. Payloads go through
// POST /v1/inventory and the real extractor; presence is read through
// GET /v1/portal/tagged-products, the one reader that turns "not seen
// recently" into "not there".

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

func beStatus(status string, capped bool, users ...map[string]any) map[string]any {
	if users == nil {
		users = []map[string]any{}
	}
	return map[string]any{"browser_extensions_status": map[string]any{
		"collection_status": status, "cap_reached": capped, "users": users,
	}}
}

func beStatusUser(user, status, chrome, edge, firefox string) map[string]any {
	return map[string]any{"user": user, "user_id": nil, "collection_status": status,
		"browsers": map[string]any{"chrome": chrome, "edge": edge, "firefox": firefox}}
}

func beExt(browser, user, id, name string) map[string]any {
	return map[string]any{
		"browser": browser, "profile": "Default", "user_account": user,
		"extension_id": id, "name": name, "version": "1.0", "enabled": true,
		"permissions": []string{}, "host_permissions": []string{}, "from_webstore": true,
	}
}

// bePost posts full.json for one device with these extensions and extra keys.
func bePost(t *testing.T, tn cveTestTenant, hw string, exts []map[string]any, extra map[string]any) string {
	t.Helper()
	return postCategoryFixtureWith(t, tn, "full.json", hw, []map[string]any{}, exts, extra)
}

// beTaggedExtension publishes a rule tagging one Chrome extension ID and
// returns a check for whether it currently counts as present.
func beTaggedExtension(t *testing.T, tn cveTestTenant, extID string) func() bool {
	t.Helper()
	rule := createCategoryRule(t, map[string]any{
		"identifier_type": "browser_extension", "qualifier": "chrome_web_store", "identifier_value": extID,
		"category": "ai_tooling", "subtype": "browser_extension",
	})
	publishCategoryRule(t, rule.ID)
	return func() bool {
		_, ok := findTagged(readTagged(t, tn, ""), extID)
		return ok
	}
}

func ageExtensions(t *testing.T, device string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `UPDATE device_browser_extensions
		SET last_seen = last_seen - interval '40 days' WHERE device_id = $1::uuid`, device); err != nil {
		t.Fatal(err)
	}
}

// Ingest stores the block-level and per-pair status, a failed report records
// only its status, and an older replay writes nothing.
func TestBrowserExtensionStatusStored(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2055-store-"+sfx)
	hw := newHW(sfx)
	device := bePost(t, tn, hw, []map[string]any{beExt("chrome", "alice", chromeID(t), "Store "+sfx)},
		beStatus("partial", false, beStatusUser("alice", "partial", "complete", "failed", "not_present")))

	var status string
	var capped, deviceComplete bool
	if err := env.pool.QueryRow(context.Background(), `
		SELECT collection_status, cap_reached, last_complete_at IS NOT NULL
		FROM browser_extension_device_state WHERE device_id = $1::uuid AND tenant_id = $2::uuid`,
		device, tn.tenantID).Scan(&status, &capped, &deviceComplete); err != nil {
		t.Fatalf("device state: %v", err)
	}
	if status != "partial" || capped || deviceComplete {
		t.Fatalf("device state = %s capped=%v complete=%v, want partial, uncapped, no authority", status, capped, deviceComplete)
	}
	pairs := map[string]bool{}
	rows, err := env.pool.Query(context.Background(), `
		SELECT browser || ':' || collection_status, last_complete_at IS NOT NULL
		FROM browser_extension_collection_state WHERE device_id = $1::uuid AND user_account = 'alice'`, device)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		var auth bool
		if err := rows.Scan(&k, &auth); err != nil {
			t.Fatal(err)
		}
		pairs[k] = auth
	}
	rows.Close()
	want := map[string]bool{"chrome:complete": true, "edge:failed": false, "firefox:not_present": true}
	if len(pairs) != len(want) {
		t.Fatalf("pairs = %v, want %v", pairs, want)
	}
	for k, v := range want {
		if a, ok := pairs[k]; !ok || a != v {
			t.Fatalf("pairs = %v, want %v", pairs, want)
		}
	}

	// failed: only the status moves.
	bePost(t, tn, hw, nil, map[string]any{"browser_extensions_status": map[string]any{"collection_status": "failed"}})
	if n := countRows(t, `SELECT count(*) FROM browser_extension_device_state
		WHERE device_id = $1::uuid AND collection_status = 'failed' AND last_complete_at IS NULL`, device); n != 1 {
		t.Fatal("failed report not recorded as failed, or it granted authority")
	}
	if n := countRows(t, `SELECT count(*) FROM browser_extension_collection_state
		WHERE device_id = $1::uuid AND collection_status IN ('complete','failed','not_present')`, device); n != 3 {
		t.Fatalf("failed report changed the pair rows (%d)", n)
	}

	// A payload received before the newest applied report is a replay.
	if _, err := env.pool.Exec(context.Background(), `UPDATE browser_extension_device_state
		SET reported_at = now() + interval '1 day' WHERE device_id = $1::uuid`, device); err != nil {
		t.Fatal(err)
	}
	bePost(t, tn, hw, nil, beStatus("complete", false, beStatusUser("alice", "complete", "complete", "complete", "complete")))
	if n := countRows(t, `SELECT count(*) FROM browser_extension_device_state
		WHERE device_id = $1::uuid AND collection_status = 'failed' AND last_complete_at IS NULL`, device); n != 1 {
		t.Fatal("an older replay overwrote the device's newer status")
	}
}

// The ticket's acceptance test. The extension was last seen 40 days before
// the device's latest report, which the pre-PAT-2055 window treats as gone.
// A partial report, a capped report and a failed report must each leave it
// present, because none of them proves it is gone.
func TestBrowserExtensionPartialNeverRemoves(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{"partial, pair partial", beStatus("partial", false, beStatusUser("alice", "partial", "partial", "not_present", "not_present"))},
		{"partial, pair failed", beStatus("partial", false, beStatusUser("alice", "partial", "failed", "not_present", "not_present"))},
		{"partial, user missing from roster", beStatus("partial", false, beStatusUser("bob", "complete", "complete", "not_present", "not_present"))},
		{"capped, pair claims complete", beStatus("partial", true, beStatusUser("alice", "partial", "complete", "not_present", "not_present"))},
		{"failed", map[string]any{"browser_extensions_status": map[string]any{"collection_status": "failed"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sfx := randomHex(4)
			tn := newCategoryTenant(t, "pat2055-partial-"+sfx)
			extID := chromeID(t)
			present := beTaggedExtension(t, tn, extID)
			hw := newHW(sfx)
			device := bePost(t, tn, hw, []map[string]any{beExt("chrome", "alice", extID, "Partial "+sfx)}, nil)
			if !present() {
				t.Fatal("reported extension missing")
			}
			ageExtensions(t, device)
			bePost(t, tn, hw, nil, tc.extra)
			if !present() {
				t.Fatal("a report without absence authority made the extension absent")
			}
		})
	}
}

// A complete report after last_seen, for the device or for the extension's
// own user and browser, is what makes it absent, immediately and with no
// window. Re-listing it brings it back.
func TestBrowserExtensionCompleteAfterLastSeenRemoves(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{"complete block", beStatus("complete", false, beStatusUser("alice", "complete", "complete", "not_present", "not_present"))},
		{"not_present block", beStatus("not_present", false)},
		{"partial block, pair complete", beStatus("partial", false, beStatusUser("alice", "partial", "complete", "failed", "partial"))},
		{"partial block, pair not_present", beStatus("partial", false, beStatusUser("alice", "partial", "not_present", "failed", "partial"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sfx := randomHex(4)
			tn := newCategoryTenant(t, "pat2055-complete-"+sfx)
			extID := chromeID(t)
			present := beTaggedExtension(t, tn, extID)
			hw := newHW(sfx)
			ext := []map[string]any{beExt("chrome", "alice", extID, "Complete "+sfx)}
			bePost(t, tn, hw, ext, beStatus("complete", false, beStatusUser("alice", "complete", "complete", "not_present", "not_present")))
			if !present() {
				t.Fatal("an extension listed by a complete report is not present")
			}
			bePost(t, tn, hw, nil, tc.extra)
			if present() {
				t.Fatal("an authoritative report after last_seen left the extension present")
			}
			bePost(t, tn, hw, ext, beStatus("partial", false, beStatusUser("alice", "partial", "partial", "not_present", "not_present")))
			if !present() {
				t.Fatal("a re-listed extension stayed absent")
			}
		})
	}
}

// A device that has never sent the block keeps the pre-PAT-2055 rule
// exactly: present within 30 days of the device's last report, hidden after.
func TestBrowserExtensionNoStatusKeepsLegacyWindow(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2055-legacy-"+sfx)
	extID := chromeID(t)
	present := beTaggedExtension(t, tn, extID)
	hw := newHW(sfx)
	device := bePost(t, tn, hw, []map[string]any{beExt("chrome", "alice", extID, "Legacy "+sfx)}, nil)
	bePost(t, tn, hw, nil, nil)
	if !present() {
		t.Fatal("an extension inside the legacy window is not present")
	}
	if n := countRows(t, `SELECT count(*) FROM browser_extension_device_state WHERE device_id = $1::uuid`, device); n != 0 {
		t.Fatalf("a payload without the block wrote device state (%d rows)", n)
	}
	ageExtensions(t, device)
	if present() {
		t.Fatal("an extension outside the legacy window is still present")
	}
}

// Review P2: a well-formed block that disagrees with itself or with the rows
// must not cost the device its inventory. The payload is accepted, apps and
// extensions are stored, the block is kept as partial with its authority
// withheld, and nothing is treated as removed because of it.
func TestBrowserExtensionInconsistentStatusAcceptedAndWithheld(t *testing.T) {
	manyUsers := make([]map[string]any, 0, 501)
	for i := 0; i < 501; i++ {
		manyUsers = append(manyUsers, beStatusUser(fmt.Sprintf("user%03d", i), "not_present", "not_present", "not_present", "not_present"))
	}
	for _, tc := range []struct {
		name   string
		rows   func(sfx string) []map[string]any
		extra  map[string]any
		reason string
	}{
		{
			// The Windows shape: the block says "alice", the rows say "Alice".
			// Taken at face value, the complete block would prove the device's
			// other extensions gone.
			name: "user case differs from rows",
			rows: func(sfx string) []map[string]any {
				return []map[string]any{beExt("edge", "Alice", "edge-"+sfx, "Other "+sfx)}
			},
			extra:  beStatus("complete", false, beStatusUser("alice", "complete", "not_present", "complete", "not_present")),
			reason: "row_not_reported_complete",
		},
		{
			// A terminal server: over the 500-user bound. The block claims
			// not_present everywhere, which would prove every extension gone.
			name:   "501 users",
			rows:   func(string) []map[string]any { return nil },
			extra:  beStatus("complete", false, manyUsers...),
			reason: "too_many_users",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sfx := randomHex(4)
			tn := newCategoryTenant(t, "pat2055-withheld-"+sfx)
			extID := chromeID(t)
			present := beTaggedExtension(t, tn, extID)
			hw := newHW(sfx)
			bePost(t, tn, hw, []map[string]any{beExt("chrome", "alice", extID, "Kept "+sfx)}, nil)
			if !present() {
				t.Fatal("reported extension missing")
			}

			bundle := "com.pat2055.withheld." + sfx
			apps := []map[string]any{{"name": "Withheld " + sfx, "version": "1.0", "bundle_id": bundle,
				"path": "/Applications/Withheld " + sfx + ".app"}}
			// postCategoryFixtureWith fails the test on anything but 200 and
			// on an extraction error, so reaching the next line is the
			// "accepted" assertion.
			device := postCategoryFixtureWith(t, tn, "full.json", hw, apps, tc.rows(sfx), tc.extra)

			if n := countRows(t, `SELECT count(*) FROM device_apps WHERE device_id = $1::uuid AND name = $2`,
				device, "Withheld "+sfx); n != 1 {
				t.Fatalf("apps from the payload were not stored (%d rows)", n)
			}
			var status string
			var withheld *string
			var authority bool
			if err := env.pool.QueryRow(context.Background(), `
				SELECT collection_status, authority_withheld, last_complete_at IS NOT NULL
				FROM browser_extension_device_state WHERE device_id = $1::uuid`, device).Scan(&status, &withheld, &authority); err != nil {
				t.Fatalf("device state: %v", err)
			}
			if status != "partial" || authority || withheld == nil || *withheld != tc.reason {
				t.Fatalf("device state = %s withheld=%v authority=%v, want partial, %q, no authority", status, withheld, authority, tc.reason)
			}
			if n := countRows(t, `SELECT count(*) FROM browser_extension_collection_state WHERE device_id = $1::uuid`, device); n != 0 {
				t.Fatalf("a withheld block wrote %d pair rows", n)
			}
			if !present() {
				t.Fatal("an inconsistent block made an extension absent")
			}
		})
	}
}

// Malformed STRUCTURE is still refused before storage.
func TestBrowserExtensionMalformedStatusRejected(t *testing.T) {
	var p map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "with-browser-extensions.json"), &p); err != nil {
		t.Fatal(err)
	}
	p["browser_extensions_status"] = map[string]any{"collection_status": "partial", "cap_reached": "yes", "users": []any{}}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	resp := postInventory(t, signedInventoryRequest(t, body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("malformed block: want 400, got %d: %s", resp.StatusCode, raw)
	}
}
