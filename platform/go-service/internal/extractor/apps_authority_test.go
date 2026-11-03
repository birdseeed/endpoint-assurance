package extractor

import (
	"strings"
	"testing"
)

// PAT-2063: the explicit collection_status.apps signal, resolved against the
// apps array and the schema version.
func TestResolveAppsSignal(t *testing.T) {
	apps := []appPart{{Name: "One", Identifier: "com.example.one"}}
	for _, tc := range []struct {
		name       string
		p          payload
		want       appsSignal
		wantReason string
		wantDetail string
	}{
		{"no collection_status", payload{SchemaVersion: 3, AppsPresent: true, Apps: apps}, appsSignalNone, "", ""},
		{"collection_status without apps", payload{SchemaVersion: 3, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Certificates: "complete"}}, appsSignalNone, "", ""},
		{"complete v3", payload{SchemaVersion: 3, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Apps: "complete"}}, appsSignalComplete, "", ""},
		{"complete v3 empty list", payload{SchemaVersion: 3, AppsPresent: true,
			CollectionStatus: &collectionStatusPart{Apps: "complete"}}, appsSignalComplete, "", ""},
		{"complete on legacy v2 is no signal", payload{SchemaVersion: 2, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Apps: "complete"}}, appsSignalNone, "", ""},
		{"complete without apps array", payload{SchemaVersion: 3,
			CollectionStatus: &collectionStatusPart{Apps: "complete"}}, appsSignalIncomplete, "inconsistent", "complete_without_apps_array"},
		{"partial", payload{SchemaVersion: 3, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Apps: "partial"}}, appsSignalIncomplete, "partial", ""},
		{"partial on v2 still withholds", payload{SchemaVersion: 2, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Apps: "partial"}}, appsSignalIncomplete, "partial", ""},
		{"unavailable empty", payload{SchemaVersion: 3, AppsPresent: true,
			CollectionStatus: &collectionStatusPart{Apps: "unavailable"}}, appsSignalIncomplete, "unavailable", ""},
		{"unavailable with apps listed", payload{SchemaVersion: 3, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Apps: "unavailable"}}, appsSignalIncomplete, "inconsistent", "unavailable_with_apps_listed"},
		{"unrecognised value", payload{SchemaVersion: 3, AppsPresent: true, Apps: apps,
			CollectionStatus: &collectionStatusPart{Apps: "done"}}, appsSignalIncomplete, "inconsistent", "unrecognised_status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason, detail := resolveAppsSignal(&tc.p)
			if got != tc.want || reason != tc.wantReason || detail != tc.wantDetail {
				t.Fatalf("resolveAppsSignal = (%v, %q, %q), want (%v, %q, %q)",
					got, reason, detail, tc.want, tc.wantReason, tc.wantDetail)
			}
		})
	}
}

// The no-signal safety valve: both thresholds must be exceeded, and a report
// that reconfirms nothing never wipes a device.
func TestAppsValveHolds(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		current, vanished, reconfirmed int
		want                           bool
	}{
		{"nothing vanished", 20, 0, 20, false},
		{"one of twenty uninstalled", 20, 1, 19, false},
		{"five of eight: at the absolute floor", 8, 5, 3, false},
		{"six of eight", 8, 6, 2, true},
		{"fifteen of twenty", 20, 15, 5, true},
		{"six of twenty: under half", 20, 6, 14, false},
		{"eleven of twenty: over half", 20, 11, 9, true},
		{"ten of twenty: exactly half", 20, 10, 10, false},
		{"empty list on a small device", 3, 3, 0, true},
		{"everything replaced, nothing reconfirmed", 2, 2, 0, true},
		{"brand new device", 0, 0, 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := appsValveHolds(tc.current, tc.vanished, tc.reconfirmed); got != tc.want {
				t.Fatalf("appsValveHolds(%d, %d, %d) = %v, want %v",
					tc.current, tc.vanished, tc.reconfirmed, got, tc.want)
			}
		})
	}
}

// A withheld report grants no application absence scope on either platform.
func TestAuthoritativeSoftwareScopesWithheld(t *testing.T) {
	mac := &payload{AppsPresent: true, AppsAbsenceWithheld: true}
	if got := authoritativeSoftwareScopes(mac, "macos"); len(got) != 0 {
		t.Fatalf("withheld macOS report kept scopes %v", got)
	}
	win := &payload{
		AppsPresent: true, AppsAbsenceWithheld: true,
		InventoryCapabilities: &inventoryCapabilitiesPart{SchemaVersion: 1, WindowsWingetInventoryComplete: true},
		Apps:                  []appPart{{Name: "Firefox", Identifier: "Mozilla.Firefox", IdentifierKind: "winget"}},
	}
	if got := authoritativeSoftwareScopes(win, "windows"); len(got) != 0 {
		t.Fatalf("withheld Windows report kept scopes %v", got)
	}
}

// collection_status.apps: the enum and type are enforced with a 400, a case
// variant of the key is refused by the PAT-2021 walk, and a duplicated
// collection_status object cannot smuggle a value past the validator.
func TestValidateCollectionStatusApps(t *testing.T) {
	for _, v := range []string{"complete", "partial", "unavailable"} {
		if err := ValidatePayload(fixtureWith(t, "full-v3-windows.json", func(m map[string]any) {
			m["collection_status"] = map[string]any{"apps": v}
		})); err != nil {
			t.Fatalf("apps=%q rejected: %v", v, err)
		}
	}
	for name, edit := range map[string]func(m map[string]any){
		"unknown value":  func(m map[string]any) { m["collection_status"] = map[string]any{"apps": "done"} },
		"wrong case":     func(m map[string]any) { m["collection_status"] = map[string]any{"apps": "Complete"} },
		"not a string":   func(m map[string]any) { m["collection_status"] = map[string]any{"apps": true} },
		"null":           func(m map[string]any) { m["collection_status"] = map[string]any{"apps": nil} },
		"case variant":   func(m map[string]any) { m["collection_status"] = map[string]any{"APPS": "complete"} },
		"fold variant":   func(m map[string]any) { m["collection_status"] = map[string]any{"appſ": "complete"} },
		"unknown key":    func(m map[string]any) { m["collection_status"] = map[string]any{"applications": "complete"} },
		"top level fold": func(m map[string]any) { m["Collection_Status"] = map[string]any{"apps": "complete"} },
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePayload(fixtureWith(t, "full-v3-windows.json", edit)); err == nil {
				t.Fatal("malformed collection_status.apps accepted")
			}
		})
	}

	body := string(readFixture(t, "valid", "full-v3-windows.json"))
	i := strings.Index(body, `"apps"`)
	if i < 0 {
		t.Fatal("fixture has no apps key")
	}
	dup := body[:i] + `"collection_status": {"apps": "complete"}, "collection_status": {"certificates": "complete"}, ` + body[i:]
	if err := ValidatePayload([]byte(dup)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicated collection_status accepted: %v", err)
	}
}
