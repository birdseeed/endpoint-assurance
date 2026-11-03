//go:build integration

package integration

// PAT-2067: Safari's own absence authority, collection_status.safari_extensions.
// Payloads go through POST /v1/inventory and the real extractor; presence is
// read with extpresence.PresentSQL (extPresent, safari_extensions_test.go).
//
// Every report carries a browser_extensions_status block whose users and
// browsers are all partial, so the device has a state row (StatusKnownSQL is
// true) while chrome, edge and firefox grant no authority of their own. Only
// the Safari signal under test can make a Safari row absent.

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

const safariSys = "_system"

// safariReport is the extra keys for one schema v3 macOS report. status is
// collection_status.safari_extensions; "" leaves the key out.
func safariReport(status string) map[string]any {
	extra := beStatus("partial", false, beStatusUser("alice", "partial", "partial", "partial", "partial"))
	extra["schema_version"] = 3
	extra["platform"] = "macos"
	if status != "" {
		extra["collection_status"] = map[string]any{"safari_extensions": status}
	}
	return extra
}

func safariPresent(t *testing.T, device, extID string) bool {
	t.Helper()
	return extPresent(t, device, "safari", safariSys, safariSys, extID)
}

// seedTwoSafari ingests two Safari extensions, then ages them so a later
// report's stamp is strictly after their last_seen.
func seedTwoSafari(t *testing.T, name string) (tn cveTestTenant, hw, device, keep, gone string) {
	t.Helper()
	sfx := randomHex(4)
	tn = newCategoryTenant(t, name+"-"+sfx)
	hw = newHW(sfx)
	keep = "com.example.safari.keep." + sfx
	gone = "com.example.safari.gone." + sfx
	device = bePost(t, tn, hw, []map[string]any{beSafariExt(keep, "Keep"), beSafariExt(gone, "Gone")}, safariReport("partial"))
	if !safariPresent(t, device, keep) || !safariPresent(t, device, gone) {
		t.Fatal("precondition: both Safari extensions present after the first report")
	}
	ageExtensions(t, device)
	return tn, hw, device, keep, gone
}

// complete: a Safari row the report did not list is gone; one it listed stays.
func TestSafariCompleteMarksUnlistedAbsent(t *testing.T) {
	tn, hw, device, keep, gone := seedTwoSafari(t, "pat2067-complete")
	bePost(t, tn, hw, []map[string]any{beSafariExt(keep, "Keep")}, safariReport("complete"))
	if !safariPresent(t, device, keep) {
		t.Fatal("a Safari extension the complete report listed reads as gone")
	}
	if safariPresent(t, device, gone) {
		t.Fatal("a Safari extension missing from a complete report is still present")
	}
	var status string
	if err := env.pool.QueryRow(t.Context(), `SELECT collection_status->>'safari_extensions' FROM devices WHERE id = $1::uuid`, device).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "complete" {
		t.Fatalf("devices.collection_status.safari_extensions = %q, want complete", status)
	}
}

// partial and unavailable never grant authority, and a device that never
// sends the key keeps today's behaviour: Safari rows are never absent.
func TestSafariNonCompleteKeepsRows(t *testing.T) {
	for _, status := range []string{"partial", "unavailable", ""} {
		name := status
		if name == "" {
			name = "absent"
		}
		t.Run(name, func(t *testing.T) {
			tn, hw, device, keep, gone := seedTwoSafari(t, "pat2067-"+name)
			exts := []map[string]any{beSafariExt(keep, "Keep")}
			if status == "unavailable" {
				exts = nil
			}
			bePost(t, tn, hw, exts, safariReport(status))
			if !safariPresent(t, device, gone) {
				t.Fatalf("safari_extensions %q made an unlisted Safari extension absent", status)
			}
			if n := countRows(t, `SELECT count(*) FROM browser_extension_device_state
				WHERE device_id = $1::uuid AND safari_complete_at IS NOT NULL`, device); n != 0 {
				t.Fatalf("safari_extensions %q set safari_complete_at", status)
			}
		})
	}
}

// complete with zero Safari rows is a valid claim that there are none.
func TestSafariEmptyCompleteMarksAllAbsent(t *testing.T) {
	tn, hw, device, keep, gone := seedTwoSafari(t, "pat2067-empty")
	bePost(t, tn, hw, []map[string]any{}, safariReport("complete"))
	if safariPresent(t, device, keep) || safariPresent(t, device, gone) {
		t.Fatal("an empty complete Safari report left a stored Safari extension present")
	}
}

// A complete claim that cannot be trusted grants nothing: a schema v2
// payload, and a report whose collector hit its row cap.
func TestSafariCompleteWithheld(t *testing.T) {
	cases := map[string]func(map[string]any){
		"schema v2": func(e map[string]any) { delete(e, "schema_version"); delete(e, "platform") },
		"cap reached": func(e map[string]any) {
			e["browser_extensions_status"] = beStatus("partial", true, beStatusUser("alice", "partial", "partial", "partial", "partial"))["browser_extensions_status"]
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			tn, hw, device, keep, gone := seedTwoSafari(t, "pat2067-withheld")
			extra := safariReport("complete")
			edit(extra)
			bePost(t, tn, hw, []map[string]any{beSafariExt(keep, "Keep")}, extra)
			if !safariPresent(t, device, gone) {
				t.Fatalf("%s: an untrusted complete made a Safari extension absent", name)
			}
		})
	}
}

// PAT-2064's guard still holds with the Safari signal in play: a device-level
// complete for chrome/edge/firefox never marks Safari absent (Safari itself
// says partial here), and a Safari complete never marks chrome absent.
func TestSafariAndChromeAuthorityStaySeparate(t *testing.T) {
	sfx := randomHex(4)
	tn := newCategoryTenant(t, "pat2067-separate-"+sfx)
	hw := newHW(sfx)
	chromeExt := chromeID(t)
	safariExt := "com.example.safari.sep." + sfx
	device := bePost(t, tn, hw, []map[string]any{beExt("chrome", "alice", chromeExt, "C"), beSafariExt(safariExt, "S")}, safariReport("partial"))
	ageExtensions(t, device)

	chromeComplete := beStatus("complete", false, beStatusUser("alice", "complete", "complete", "not_present", "not_present"))
	chromeComplete["schema_version"] = 3
	chromeComplete["platform"] = "macos"
	chromeComplete["collection_status"] = map[string]any{"safari_extensions": "partial"}
	bePost(t, tn, hw, nil, chromeComplete)
	if extPresent(t, device, "chrome", "alice", "Default", chromeExt) {
		t.Fatal("precondition: chrome complete should mark the unlisted chrome extension absent")
	}
	if !safariPresent(t, device, safariExt) {
		t.Fatal("a chrome/edge/firefox device-level complete made a Safari extension absent")
	}

	// And the other way round, on a fresh device.
	sfx2 := randomHex(4)
	hw2 := newHW(sfx2)
	chromeExt2 := chromeID(t)
	device2 := bePost(t, tn, hw2, []map[string]any{beExt("chrome", "alice", chromeExt2, "C2")}, safariReport("partial"))
	ageExtensions(t, device2)
	bePost(t, tn, hw2, []map[string]any{}, safariReport("complete"))
	if !extPresent(t, device2, "chrome", "alice", "Default", chromeExt2) {
		t.Fatal("a Safari complete made a chrome extension absent")
	}
}

// Malformed values and case- or fold-variant keys are refused with a 400
// before storage, through the PAT-2021 raw-key walk.
func TestSafariStatusMalformedRejected(t *testing.T) {
	cases := map[string]map[string]any{
		"unknown value":  {"safari_extensions": "done"},
		"non-string":     {"safari_extensions": true},
		"case variant":   {"Safari_Extensions": "complete"},
		"upper variant":  {"SAFARI_EXTENSIONS": "complete"},
		"fold variant":   {"ſafari_extensions": "complete"},
		"unknown key":    {"safari": "complete"},
		"variant beside": {"safari_extensions": "partial", "Safari_Extensions": "complete"},
	}
	for name, cs := range cases {
		t.Run(name, func(t *testing.T) {
			var p map[string]any
			if err := json.Unmarshal(fixtureData(t, "valid", "with-browser-extensions.json"), &p); err != nil {
				t.Fatal(err)
			}
			p["collection_status"] = cs
			body, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			resp := postInventory(t, signedInventoryRequest(t, body))
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("want 400, got %d: %s", resp.StatusCode, raw)
			}
		})
	}
}
