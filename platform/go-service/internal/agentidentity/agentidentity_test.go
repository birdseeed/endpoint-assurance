package agentidentity

import "testing"

// TestIdentitiesNonEmpty guards against an accidental empty list, which
// would silently turn PAT-1318 off — no identity would ever be seeded.
func TestIdentitiesNonEmpty(t *testing.T) {
	if len(Identities) == 0 {
		t.Fatal("Identities is empty — PAT-1318 auto-approval would seed nothing")
	}
}

// TestIdentitiesCoverBothPlatforms guards against the list drifting to
// cover only one platform (e.g. someone adding a new macOS surface and
// forgetting Windows, or vice versa) — PAT-1318 requires "every Patched
// Agent identity", both platforms.
func TestIdentitiesCoverBothPlatforms(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range Identities {
		seen[id.Platform] = true
	}
	if !seen[PlatformMacOS] {
		t.Error("no Identities entry has Platform == PlatformMacOS")
	}
	if !seen[PlatformWindows] {
		t.Error("no Identities entry has Platform == PlatformWindows")
	}
}

// TestIdentitiesSetExactlyOneIdentityColumn asserts every entry sets
// exactly one of TeamID/BundleID/Name, matching the tenant_app_policies
// has-identity CHECK and — more specifically — the single-axis precedence
// extractor/new_apps.go's doDetectNewTenantApps anti-join relies on (see the
// package doc comment for why setting more than one column would be
// ambiguous).
func TestIdentitiesSetExactlyOneIdentityColumn(t *testing.T) {
	for _, id := range Identities {
		set := 0
		if id.TeamID != "" {
			set++
		}
		if id.BundleID != "" {
			set++
		}
		if id.Name != "" {
			set++
		}
		if set != 1 {
			t.Errorf("identity %+v sets %d identity columns, want exactly 1", id, set)
		}
		if id.Platform != PlatformMacOS && id.Platform != PlatformWindows {
			t.Errorf("identity %+v has unexpected Platform %q", id, id.Platform)
		}
	}
}

// TestIdentitiesUseStableLiteralIdentities pins the exact identity strings
// this list must contain — im.patched.updater.menubar and
// im.patched.updater.selfservice (macOS bundle IDs, updater/menubar/project.yml)
// and "Patched Agent" (Windows MSI ARP DisplayName, updater/windows/installer/Product.wxs).
// Asserting the literals — not just "some macOS bundle_id exists" — means a
// careless edit that mangles or version-qualifies one of these strings
// (e.g. "Patched Agent 1.2") fails this test instead of silently breaking
// the tenant_app_policies match.
func TestIdentitiesUseStableLiteralIdentities(t *testing.T) {
	want := map[string]Identity{
		"im.patched.updater.menubar":     {BundleID: "im.patched.updater.menubar", Platform: PlatformMacOS},
		"im.patched.updater.selfservice": {BundleID: "im.patched.updater.selfservice", Platform: PlatformMacOS},
		"Patched Agent":                  {Name: "Patched Agent", Platform: PlatformWindows},
	}

	got := map[string]bool{}
	for _, id := range Identities {
		switch {
		case id.BundleID != "":
			got[id.BundleID] = true
		case id.Name != "":
			got[id.Name] = true
		case id.TeamID != "":
			got[id.TeamID] = true
		}
	}

	for key, w := range want {
		if !got[key] {
			t.Errorf("Identities is missing expected identity %q (platform %s)", key, w.Platform)
		}
	}
	if len(Identities) != len(want) {
		t.Errorf("Identities has %d entries, want exactly %d known entries: %v", len(Identities), len(want), Identities)
	}
}

// TestNullIfEmpty is a trivial guard on the helper the seed INSERT relies on
// to turn an empty identity column into a genuine SQL NULL rather than an
// empty-string value (which would fail 0032's has-identity CHECK if all
// three were empty, and would NOT collapse to the same COALESCE(..., empty
// string) key as a real NULL row for the unique index otherwise — belt and
// braces since
// Go's zero value for string is "" and it must map to NULL here).
func TestNullIfEmpty(t *testing.T) {
	if got := nullIfEmpty(""); got != nil {
		t.Errorf("nullIfEmpty(\"\") = %#v, want nil", got)
	}
	if got := nullIfEmpty("x"); got != "x" {
		t.Errorf("nullIfEmpty(\"x\") = %#v, want \"x\"", got)
	}
}
