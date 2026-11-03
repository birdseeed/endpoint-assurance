package cvematch

import (
	"reflect"
	"sort"
	"testing"

	"patched.im/api/internal/cvelifecycle"
)

// ─── compareVersions ──────────────────────────────────────────────────────────

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Equal
		{"1.0.0", "1.0.0", 0},
		{"0", "0", 0},
		{"09", "9", 0}, // leading zeros stripped
		{"", "", 0},

		// Less than
		{"1.0.0", "1.0.1", -1},
		{"1.0", "1.0.1", -1}, // shorter is lower
		{"126.0", "126.0.1", -1},
		{"9.9.9", "10.0.0", -1}, // 9 < 10 numerically
		{"", "1.0", -1},         // empty < anything

		// Greater than
		{"1.0.1", "1.0.0", 1},
		{"1.0.1", "1.0", 1},
		{"126.0.1", "126.0", 1},
		{"10.0.0", "9.9.9", 1},
		{"1.0", "", 1},

		// Non-numeric segments are ignored; only numeric components compared
		{"1.2.3-beta", "1.2.3", 0}, // "beta" is non-numeric → same numeric prefix
		{"1.2.3", "1.2.3-beta", 0},
		{"1.2.4-beta", "1.2.3", 1}, // 4 > 3

		// Real-world Chrome-style versions
		{"120.0.6099.130", "120.0.6099.129", 1},
		{"121.0.6167.85", "120.0.6099.130", 1},
		{"120.0.0.0", "121.0.0.0", -1},
	}
	for _, tc := range tests {
		got := compareVersions(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ─── wordTokenMatch ───────────────────────────────────────────────────────────

func TestWordTokenMatch(t *testing.T) {
	tests := []struct {
		appName   string
		matchName string
		want      bool
	}{
		{"Dropbox", "Dropbox", true},
		{"Dropbox", "Box", false}, // substring ≠ token match
		{"Box", "Box", true},
		{"GitHub Desktop", "Git", false}, // "github" ≠ "git"
		{"GitHub Desktop", "GitHub Desktop", true},
		{"Git", "Git", true},
		{"Google Chrome", "Google Chrome", true},
		{"Google Chrome Helper", "Google Chrome", true}, // prefix match
		{"Java", "Java", true},
		{"JavaScript Framework", "Java", false}, // "javascript" ≠ "java"
		{"Python", "Python", true},
		{"Opera", "Opera", true},
		{"Microsoft Teams", "Microsoft Teams", true},
		{"Microsoft Office", "Microsoft Word", false},

		// Non-contiguous subsequence matches (PAT-873): extra interior words
		// between the mapping's key tokens must not block the match.
		{"Adobe Acrobat Reader DC", "Adobe Reader", true},
		{"Microsoft Visual Studio Code", "Visual Studio", true},
		{"Amazon Corretto 17 JDK", "Amazon Corretto", true},

		// Regression: subsequence matching must stay whole-word-token, not
		// substring, so short tokens still can't match inside longer ones.
		{"Dropbox", "Box", false},
		{"GitHub Desktop", "Git", false},

		// Non-contiguous but still unrelated: sharing one token (the vendor)
		// is not enough - all key tokens must appear, in order.
		{"Adobe Photoshop", "Adobe Illustrator", false},
		{"Adobe Photoshop", "Adobe Acrobat Reader", false},

		// Order matters: reversed token order must not match even though
		// both tokens are present.
		{"Reader Adobe", "Adobe Reader", false},
	}
	for _, tc := range tests {
		got := wordTokenMatch(tc.appName, tc.matchName)
		if got != tc.want {
			t.Errorf("wordTokenMatch(%q, %q) = %v, want %v", tc.appName, tc.matchName, got, tc.want)
		}
	}
}

// ─── FixedVersion plumbing (PAT-1205) ─────────────────────────────────────────

func ptrScore(f float64) *float64 { return &f }

// TestVersionInRange_FixedVersion covers the three FixedVersion outcomes
// documented on versionInRange: a matched range with VEndExcl set, no range
// data at all, and a matched range that is open-ended (no VEndExcl).
func TestVersionInRange_FixedVersion(t *testing.T) {
	tests := []struct {
		name             string
		ranges           []CPERange
		wantMatched      bool
		wantHasRanges    bool
		wantFixedVersion string
	}{
		{
			name: "matched range with VEndExcl set",
			ranges: []CPERange{
				{Vendor: "vendor", Product: "app", VStartIncl: "1.0", VEndExcl: "2.0"},
			},
			wantMatched:      true,
			wantHasRanges:    true,
			wantFixedVersion: "2.0",
		},
		{
			name:             "no range data at all",
			ranges:           nil,
			wantMatched:      false,
			wantHasRanges:    false,
			wantFixedVersion: "",
		},
		{
			name: "matched via open-ended range (no VEndExcl)",
			ranges: []CPERange{
				{Vendor: "vendor", Product: "app", VStartIncl: "1.0"},
			},
			wantMatched:      true,
			wantHasRanges:    true,
			wantFixedVersion: "",
		},
		{
			// Installed version 1.5 falls inside two overlapping vulnerable
			// ranges for the same product (e.g. an LTS-branch statement and a
			// current-branch statement in the same CVE's CPE configuration).
			// The customer must clear both, so the target is the highest
			// VEndExcl among every matching range, not just the first one
			// encountered in range order.
			name: "installed version matches two overlapping ranges — highest VEndExcl wins",
			ranges: []CPERange{
				{Vendor: "vendor", Product: "app", VStartIncl: "1.0", VEndExcl: "1.9"},
				{Vendor: "vendor", Product: "app", VStartIncl: "0.1", VEndExcl: "3.5"},
			},
			wantMatched:      true,
			wantHasRanges:    true,
			wantFixedVersion: "3.5",
		},
		{
			// Same as above but with range order reversed, to prove the result
			// doesn't depend on which matching range comes first in the slice.
			name: "overlapping ranges, reverse order — highest VEndExcl still wins",
			ranges: []CPERange{
				{Vendor: "vendor", Product: "app", VStartIncl: "0.1", VEndExcl: "3.5"},
				{Vendor: "vendor", Product: "app", VStartIncl: "1.0", VEndExcl: "1.9"},
			},
			wantMatched:      true,
			wantHasRanges:    true,
			wantFixedVersion: "3.5",
		},
		{
			// One matching range is open-ended (no VEndExcl) and another
			// matching range has a bound — the bounded one's value must win
			// rather than the open-ended range blanking out an otherwise-known
			// fix target.
			name: "one matching range open-ended, another bounded — bounded value wins",
			ranges: []CPERange{
				{Vendor: "vendor", Product: "app", VStartIncl: "1.0"},
				{Vendor: "vendor", Product: "app", VStartIncl: "0.1", VEndExcl: "2.2"},
			},
			wantMatched:      true,
			wantHasRanges:    true,
			wantFixedVersion: "2.2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, hasRanges, fixedVersion := versionInRange("1.5", tc.ranges, "vendor", "app")
			if matched != tc.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tc.wantMatched)
			}
			if hasRanges != tc.wantHasRanges {
				t.Errorf("hasRanges = %v, want %v", hasRanges, tc.wantHasRanges)
			}
			if fixedVersion != tc.wantFixedVersion {
				t.Errorf("fixedVersion = %q, want %q", fixedVersion, tc.wantFixedVersion)
			}
		})
	}
}

// TestMatch_FixedVersion asserts that Match plumbs FixedVersion from
// versionInRange onto the resulting Finding for all three confidence paths.
func TestMatch_FixedVersion(t *testing.T) {
	mappings := []CPEMapping{
		{MatchName: "MyApp", CPEVendor: "vendor", CPEProduct: "myapp"},
	}
	apps := []ScannedApp{{Name: "MyApp", Version: "1.5"}}

	t.Run("confirmed match populates FixedVersion from VEndExcl", func(t *testing.T) {
		feed := []CVEEntry{{
			CVEID: "CVE-2024-1000", Score: ptrScore(9.0), Severity: "CRITICAL",
			Patterns: []string{"vendor:myapp"},
			Ranges:   []CPERange{{Vendor: "vendor", Product: "myapp", VStartIncl: "1.0", VEndExcl: "2.0"}},
		}}
		findings := Match(apps, mappings, feed, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].MatchConfidence != "version_confirmed" {
			t.Fatalf("expected version_confirmed, got %q", findings[0].MatchConfidence)
		}
		if findings[0].FixedVersion != "2.0" {
			t.Errorf("FixedVersion = %q, want %q", findings[0].FixedVersion, "2.0")
		}
	})

	t.Run("unverified match (no range data) leaves FixedVersion empty", func(t *testing.T) {
		feed := []CVEEntry{{
			CVEID: "CVE-2024-1001", Score: ptrScore(7.0), Severity: "HIGH",
			Patterns: []string{"vendor:myapp"},
			Ranges:   []CPERange{},
		}}
		findings := Match(apps, mappings, feed, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].MatchConfidence != "version_unverified" {
			t.Fatalf("expected version_unverified, got %q", findings[0].MatchConfidence)
		}
		if findings[0].FixedVersion != "" {
			t.Errorf("FixedVersion = %q, want empty", findings[0].FixedVersion)
		}
	})

	t.Run("confirmed match via open-ended range leaves FixedVersion empty", func(t *testing.T) {
		feed := []CVEEntry{{
			CVEID: "CVE-2024-1002", Score: ptrScore(6.0), Severity: "MEDIUM",
			Patterns: []string{"vendor:myapp"},
			Ranges:   []CPERange{{Vendor: "vendor", Product: "myapp", VStartIncl: "1.0"}}, // no VEndExcl
		}}
		findings := Match(apps, mappings, feed, "")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].MatchConfidence != "version_confirmed" {
			t.Fatalf("expected version_confirmed, got %q", findings[0].MatchConfidence)
		}
		if findings[0].FixedVersion != "" {
			t.Errorf("FixedVersion = %q, want empty", findings[0].FixedVersion)
		}
	})
}

// ─── OS pseudo-app scoping (PAT-2061) ─────────────────────────────────────────

// TestOSPseudoAppNamesStaysInSyncWithCvelifecycle pins cvematch's local copy
// of the OS pseudo-app name set equal to the canonical list in
// internal/cvelifecycle. cvematch cannot import cvelifecycle's DB/notification
// graph in production code (see the doc comment on osPseudoAppNames), so the
// two lists are two copies of the same fact and must be changed together;
// this test is what catches a drift instead of a silent divergence.
func TestOSPseudoAppNamesStaysInSyncWithCvelifecycle(t *testing.T) {
	canonical := append([]string(nil), cvelifecycle.OSPseudoAppNames...)
	sort.Strings(canonical)

	local := make([]string, 0, len(osPseudoAppNames))
	for name := range osPseudoAppNames {
		local = append(local, name)
	}
	sort.Strings(local)

	if !reflect.DeepEqual(canonical, local) {
		t.Errorf("cvematch.osPseudoAppNames = %v, cvelifecycle.OSPseudoAppNames = %v — keep the two lists in sync", local, canonical)
	}
}

// TestAppMatchesMapping_OSMappingScope is the PAT-2061 regression: an OS
// mapping ("macOS" / "Windows", carrying the NVD OS-build CPE fallback) must
// only match the OS pseudo-app of the same exact name, never a real
// installed application whose name merely contains that word as a token.
func TestAppMatchesMapping_OSMappingScope(t *testing.T) {
	tests := []struct {
		name      string
		appName   string
		matchName string
		want      bool
	}{
		// The regression itself: a real app containing "Windows"/"macOS" as a
		// token must not match the OS mapping via wordTokenMatch.
		{"Windows App vs Windows OS mapping", "Windows App", "Windows", false},
		{"Windows Subsystem for Linux vs Windows OS mapping", "Windows Subsystem for Linux", "Windows", false},
		{"macOS Utility X vs macOS OS mapping", "macOS Utility X", "macOS", false},

		// The fallback this must not break: the OS pseudo-app itself still
		// matches its own OS mapping exactly.
		{"Windows pseudo-app vs Windows OS mapping", "Windows", "Windows", true},
		{"macOS pseudo-app vs macOS OS mapping", "macOS", "macOS", true},

		// Symmetric direction: the OS pseudo-app must not match a
		// differently-named mapping through word tokens either.
		{"macOS pseudo-app vs macOS Server mapping", "macOS", "macOS Server", false},
		{"Windows pseudo-app vs Windows Media Player mapping", "Windows", "Windows Media Player", false},

		// Ordinary (non-OS) pairings are unaffected.
		{"ordinary app matches its own mapping", "MyApp", "MyApp", true},
		{"ordinary substring collision still rejected", "Dropbox", "Box", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := appMatchesMapping(tc.appName, tc.matchName); got != tc.want {
				t.Errorf("appMatchesMapping(%q, %q) = %v, want %v", tc.appName, tc.matchName, got, tc.want)
			}
			// NameMatches is the exported form used by the event-driven
			// matcher and assessment read path; it must agree exactly.
			if got := NameMatches(tc.appName, tc.matchName); got != tc.want {
				t.Errorf("NameMatches(%q, %q) = %v, want %v", tc.appName, tc.matchName, got, tc.want)
			}
		})
	}
}

// TestMatch_WindowsAppNotMatchedAgainstWindowsOSMapping is the Match(, "")-level
// version of the PAT-2061 regression: a device with a real "Windows App" and
// the Windows OS pseudo-app both present. The nightly full match must not
// give "Windows App" a finding from the Windows OS mapping's CPE range, and
// must still give the OS pseudo-app its NVD fallback finding.
func TestMatch_WindowsAppNotMatchedAgainstWindowsOSMapping(t *testing.T) {
	apps := []ScannedApp{
		{Name: "Windows App", Version: "2.0"},
		{Name: "Windows", Version: "10.0.19045.4651"},
	}
	mappings := []CPEMapping{
		{MatchName: "Windows", CPEVendor: "microsoft", CPEProduct: "windows_10"},
	}
	feed := []CVEEntry{{
		CVEID:    "CVE-2024-9001",
		Score:    ptrScore(8.8),
		Severity: "HIGH",
		Patterns: []string{"microsoft:windows_10"},
		// Wide open range so both "2.0" and the OS build both fall inside it
		// if the app-name scoping is broken — this is the case designed to
		// catch a regression, not to be realistic NVD data.
		Ranges: []CPERange{{Vendor: "microsoft", Product: "windows_10", VStartIncl: "0", VEndExcl: "99999"}},
	}}

	findings := Match(apps, mappings, feed, "")

	if hasAppInFindings(findings, "Windows App") {
		t.Errorf("Windows App matched the Windows OS mapping — findings: %+v", findings)
	}
	if !hasAppInFindings(findings, "Windows") {
		t.Errorf("Windows OS pseudo-app did not get its NVD fallback finding — findings: %+v", findings)
	}
}

// TestMatch_MacOSUtilityNotMatchedAgainstMacOSOSMapping mirrors the Windows
// case for macOS: a real "macOS Utility X" app must not match the macOS OS
// mapping, and the macOS OS pseudo-app must still get its fallback finding.
func TestMatch_MacOSUtilityNotMatchedAgainstMacOSOSMapping(t *testing.T) {
	apps := []ScannedApp{
		{Name: "macOS Utility X", Version: "2.0"},
		{Name: "macOS", Version: "14.5"},
	}
	mappings := []CPEMapping{
		{MatchName: "macOS", CPEVendor: "apple", CPEProduct: "macos"},
	}
	feed := []CVEEntry{{
		CVEID:    "CVE-2024-9002",
		Score:    ptrScore(8.8),
		Severity: "HIGH",
		Patterns: []string{"apple:macos"},
		Ranges:   []CPERange{{Vendor: "apple", Product: "macos", VStartIncl: "0", VEndExcl: "99999"}},
	}}

	findings := Match(apps, mappings, feed, "")

	if hasAppInFindings(findings, "macOS Utility X") {
		t.Errorf("macOS Utility X matched the macOS OS mapping — findings: %+v", findings)
	}
	if !hasAppInFindings(findings, "macOS") {
		t.Errorf("macOS OS pseudo-app did not get its NVD fallback finding — findings: %+v", findings)
	}
}

// hasAppInFindings mirrors the small helper already used by
// cmd/patched-cve-sync's e2e tests, kept local to this package's test file
// since cvematch.Finding is the type in scope here.
func hasAppInFindings(findings []Finding, appName string) bool {
	for _, f := range findings {
		if f.AppName == appName {
			return true
		}
	}
	return false
}

// TestCompareVersionsExported asserts the exported wrapper delegates to the
// same logic as compareVersions (TestCompareVersions above covers behaviour).
func TestCompareVersionsExported(t *testing.T) {
	if CompareVersions("2.0", "1.9") != 1 {
		t.Errorf("CompareVersions(2.0, 1.9) = %d, want 1", CompareVersions("2.0", "1.9"))
	}
	if CompareVersions("1.9", "2.0") != -1 {
		t.Errorf("CompareVersions(1.9, 2.0) = %d, want -1", CompareVersions("1.9", "2.0"))
	}
	if CompareVersions("1.0", "1.0") != 0 {
		t.Errorf("CompareVersions(1.0, 1.0) = %d, want 0", CompareVersions("1.0", "1.0"))
	}
}

// PAT-2107: the lifecycle reconciler parses Homebrew finding app names with
// its own copy of ParseHomebrewDisplayName (an import cycle prevents sharing
// it). Both must agree on every name HomebrewDisplayName builds, and on names
// it does not.
func TestHomebrewAppNameParsersAgree(t *testing.T) {
	names := []string{
		HomebrewDisplayName("formula", "openssl@3"),
		HomebrewDisplayName("cask", "firefox"),
		HomebrewDisplayName("formula", ""),
		"Firefox", "", " (Homebrew cask)", "x (Homebrew formula) ",
	}
	for _, n := range names {
		k1, n1, ok1 := ParseHomebrewDisplayName(n)
		k2, n2, ok2 := cvelifecycle.ParseHomebrewAppName(n)
		if k1 != k2 || n1 != n2 || ok1 != ok2 {
			t.Errorf("%q: cvematch=(%q,%q,%v) cvelifecycle=(%q,%q,%v)", n, k1, n1, ok1, k2, n2, ok2)
		}
	}
}

// PAT-2138: an automatic mapping covers only a name with exactly its word
// tokens, so a one-word automatic match_name never silently covers a
// product installed later ("Zoom Helper"). A curated mapping keeps the
// ordered-subsequence rule.
func TestAutoMappingCoversOnlyItsExactName(t *testing.T) {
	auto := CPEMapping{MatchName: "Zoom", CPEVendor: "zoom", CPEProduct: "zoom", Platform: "any", ReviewState: ReviewStateAuto}
	curated := auto
	curated.ReviewState = "curated"
	for _, name := range []string{"Zoom", "zoom", "Zoom.", " ZOOM "} {
		if len(MappingsFor(name, []CPEMapping{auto})) != 1 {
			t.Errorf("auto Zoom does not cover %q", name)
		}
	}
	for _, name := range []string{"Zoom Helper", "Zoom Workplace", "My Zoom"} {
		if len(MappingsFor(name, []CPEMapping{auto})) != 0 {
			t.Errorf("auto Zoom covers %q", name)
		}
		if len(MappingsFor(name, []CPEMapping{curated})) != 1 && name != "My Zoom" {
			t.Errorf("curated Zoom no longer covers %q", name)
		}
	}
	feed := []CVEEntry{{CVEID: "CVE-2099-0001", Patterns: []string{"zoom:zoom"}}}
	apps := []ScannedApp{{Name: "Zoom Helper", Version: "1.0"}}
	if got := Match(apps, []CPEMapping{curated}, feed, PlatformMacOS); len(got) != 1 {
		t.Fatalf("control: curated Zoom produced %d findings on Zoom Helper, want 1", len(got))
	}
	if got := Match(apps, []CPEMapping{auto}, feed, PlatformMacOS); len(got) != 0 {
		t.Fatalf("Match used an auto mapping on a longer name: %+v", got)
	}
}
