package cvematch

import (
	"reflect"
	"testing"
)

func boolp(b bool) *bool { return &b }

func score(f float64) *float64 { return &f }

// Real NVD shapes (checked 2026-09-23): CVE-2023-0286 is filed under
// openssl:openssl 3.0.0 <= v < 3.0.8; CVE-2023-38545 under haxx:libcurl
// 7.69.0 <= v < 8.4.0 only, not haxx:curl.
var brewFeed = []CVEEntry{
	{CVEID: "CVE-2023-0286", Score: score(7.4), Severity: "HIGH", Patterns: []string{"openssl:openssl"},
		Ranges: []CPERange{
			{Vendor: "openssl", Product: "openssl", VStartIncl: "1.1.1", VEndExcl: "1.1.1t"},
			{Vendor: "openssl", Product: "openssl", VStartIncl: "3.0.0", VEndExcl: "3.0.8"},
		}},
	{CVEID: "CVE-2023-38545", Score: score(9.8), Severity: "CRITICAL", Patterns: []string{"haxx:libcurl"},
		Ranges: []CPERange{{Vendor: "haxx", Product: "libcurl", VStartIncl: "7.69.0", VEndExcl: "8.4.0"}}},
	{CVEID: "CVE-TEST-CURL-INCL", Score: score(7.5), Severity: "HIGH", Patterns: []string{"haxx:curl"},
		Ranges: []CPERange{{Vendor: "haxx", Product: "curl", VStartIncl: "8.0.0", VEndIncl: "8.3.0"}}},
}

var brewMappings = []HomebrewMapping{
	{SourceType: HomebrewFormulaSource, Name: "openssl@3", CPEVendor: "openssl", CPEProduct: "openssl", ReviewState: MappingCurated},
	{SourceType: HomebrewFormulaSource, Name: "curl", CPEVendor: "haxx", CPEProduct: "curl", ReviewState: MappingCurated},
	{SourceType: HomebrewFormulaSource, Name: "curl", CPEVendor: "haxx", CPEProduct: "libcurl", ReviewState: MappingCurated},
}

func findingsByKey(fs []HomebrewFinding) map[string]HomebrewFinding {
	out := map[string]HomebrewFinding{}
	for _, f := range fs {
		out[f.CVEID+"|"+f.AppName] = f
	}
	return out
}

func TestNormalizeHomebrewVersion(t *testing.T) {
	cases := []struct {
		kind, raw, want string
		head            bool
	}{
		{"formula", "8.3.0", "8.3.0", false},
		{"formula", "8.3.0_1", "8.3.0", false},
		{"formula", "3.0.7_12", "3.0.7", false},
		{"formula", "HEAD", "", true},
		{"formula", "HEAD-3a0b7c9", "", true},
		{"formula", "head-3a0b7c9", "", true},
		{"formula", "2026-07-15", "2026-07-15", false},
		{"cask", "124.0.2,20240101", "124.0.2", false},
		{"cask", "latest", "", false},
		{"cask", "1.2_3", "1.2_3", false}, // revisions are a formula concept only
	}
	for _, c := range cases {
		got, head := NormalizeHomebrewVersion(c.kind, c.raw)
		if got != c.want || head != c.head {
			t.Errorf("NormalizeHomebrewVersion(%q, %q) = (%q, %v), want (%q, %v)", c.kind, c.raw, got, head, c.want, c.head)
		}
	}
}

// TestMatchHomebrewOldOpensslAndCurl: the ticket's acceptance case. Old
// openssl@3 and curl formulae from homebrew/core produce the expected CVEs,
// version-confirmed, high confidence, with NVD's fixed version, and carry the
// install reason and parent formula.
func TestMatchHomebrewOldOpensslAndCurl(t *testing.T) {
	pkgs := []HomebrewPackage{
		{Kind: "formula", Name: "openssl@3", Tap: "homebrew/core", Version: "3.0.7",
			InstalledOnRequest: boolp(true), InstalledAsDependency: boolp(false)},
		{Kind: "formula", Name: "curl", Tap: "homebrew/core", Version: "8.2.1",
			InstalledOnRequest: boolp(false), InstalledAsDependency: boolp(true), RequiredBy: []string{"wget"}},
	}
	findings, unmapped := MatchHomebrew(pkgs, brewMappings, brewFeed)
	if len(unmapped) != 0 {
		t.Fatalf("unmapped = %+v, want none", unmapped)
	}
	got := findingsByKey(findings)
	ossl, ok := got["CVE-2023-0286|openssl@3 (Homebrew formula)"]
	if !ok {
		t.Fatalf("missing CVE-2023-0286 on openssl@3; findings %+v", findings)
	}
	if ossl.MatchConfidence != "version_confirmed" || ossl.ConfidenceTier != ConfidenceHigh ||
		ossl.FixedVersion != "3.0.8" || ossl.MappingBasis != MappingCurated ||
		ossl.PackageSource != HomebrewFormulaSource || ossl.PackageName != "openssl@3" ||
		ossl.InstallReason != InstallOnRequest || ossl.AppVersion != "3.0.7" {
		t.Fatalf("openssl finding = %+v", ossl)
	}
	curl, ok := got["CVE-2023-38545|curl (Homebrew formula)"]
	if !ok {
		t.Fatalf("missing CVE-2023-38545 on curl (filed under haxx:libcurl); findings %+v", findings)
	}
	if curl.ConfidenceTier != ConfidenceHigh || curl.FixedVersion != "8.4.0" ||
		curl.InstallReason != InstallDependency || !reflect.DeepEqual(curl.RequiredBy, []string{"wget"}) {
		t.Fatalf("curl finding = %+v", curl)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3 (0286, 38545, TEST-CURL-INCL): %+v", len(findings), findings)
	}
}

// TestMatchHomebrewRevisionSuffixIsStripped: "8.3.0_1" is upstream 8.3.0
// plus a Homebrew packaging revision. Against a range ending at 8.3.0
// inclusive it is vulnerable; read literally it would compare as 8.3.0.1 and
// fall outside the range, a silent false negative.
func TestMatchHomebrewRevisionSuffixIsStripped(t *testing.T) {
	pkgs := []HomebrewPackage{{Kind: "formula", Name: "curl", Tap: "homebrew/core", Version: "8.3.0_1"}}
	findings, _ := MatchHomebrew(pkgs, brewMappings, brewFeed)
	f, ok := findingsByKey(findings)["CVE-TEST-CURL-INCL|curl (Homebrew formula)"]
	if !ok {
		t.Fatalf("8.3.0_1 must match a range ending at 8.3.0 inclusive; findings %+v", findings)
	}
	if f.MatchConfidence != "version_confirmed" || f.AppVersion != "8.3.0_1" {
		t.Fatalf("finding = %+v, want version_confirmed reporting the on-disk version", f)
	}
}

// TestMatchHomebrewHeadBuildIsLowConfidenceNeverDropped: a HEAD build has no
// upstream version. Every CVE for the mapped product is kept as
// version_unverified / low, never silently dropped and never confirmed.
// "HEAD-3a0b7c9" is chosen so its hash digits read as 3.0.7, inside the
// CVE-2023-0286 range: reading them as a version would claim a confirmed,
// high-confidence finding from a commit hash.
func TestMatchHomebrewHeadBuildIsLowConfidenceNeverDropped(t *testing.T) {
	pkgs := []HomebrewPackage{{Kind: "formula", Name: "openssl@3", Tap: "homebrew/core", Version: "HEAD-3a0b7c9"}}
	findings, _ := MatchHomebrew(pkgs, brewMappings, brewFeed)
	f, ok := findingsByKey(findings)["CVE-2023-0286|openssl@3 (Homebrew formula)"]
	if !ok {
		t.Fatalf("HEAD build must keep the finding at low confidence; findings %+v", findings)
	}
	if f.MatchConfidence != "version_unverified" || f.ConfidenceTier != ConfidenceLow ||
		f.FixedVersion != "" || f.AppVersion != "HEAD-3a0b7c9" {
		t.Fatalf("HEAD finding = %+v, want version_unverified / low / no fixed version / raw version", f)
	}
}

// TestMatchHomebrewUnmappedFormulaProducesNoFinding: no mapping, no finding,
// and the package comes back for the review queue. A name that happens to
// contain a mapped name as a token ("curl-impersonate") is not a match.
func TestMatchHomebrewUnmappedFormulaProducesNoFinding(t *testing.T) {
	pkgs := []HomebrewPackage{
		{Kind: "formula", Name: "curl-impersonate", Tap: "homebrew/core", Version: "0.6.1"},
		{Kind: "formula", Name: "zzz-unmapped", Tap: "", Version: "1.0"},
	}
	findings, unmapped := MatchHomebrew(pkgs, brewMappings, brewFeed)
	if len(findings) != 0 {
		t.Fatalf("unmapped formulae produced findings: %+v", findings)
	}
	if len(unmapped) != 2 {
		t.Fatalf("unmapped = %+v, want both packages", unmapped)
	}
}

// TestMatchHomebrewThirdPartyTapNeverInheritsCuratedMapping: a formula named
// curl from someone else's tap is not the upstream curl formula.
func TestMatchHomebrewThirdPartyTapNeverInheritsCuratedMapping(t *testing.T) {
	pkgs := []HomebrewPackage{{Kind: "formula", Name: "curl", Tap: "acme/tools", Version: "8.2.1"}}
	findings, unmapped := MatchHomebrew(pkgs, brewMappings, brewFeed)
	if len(findings) != 0 || len(unmapped) != 1 {
		t.Fatalf("findings %+v unmapped %+v, want none and one", findings, unmapped)
	}
}

// TestMatchHomebrewLinkedCaskYieldsNoSecondFinding: a cask linked to an app
// bundle that is itself mapped is skipped; the app is the one finding. It is
// not reported as unmapped either.
func TestMatchHomebrewLinkedCaskYieldsNoSecondFinding(t *testing.T) {
	feed := []CVEEntry{{CVEID: "CVE-TEST-FF", Score: score(8.8), Severity: "HIGH", Patterns: []string{"mozilla:firefox"},
		Ranges: []CPERange{{Vendor: "mozilla", Product: "firefox", VEndExcl: "150.0"}}}}
	mappings := []HomebrewMapping{{SourceType: HomebrewCaskSource, Name: "firefox", CPEVendor: "mozilla", CPEProduct: "firefox", ReviewState: MappingCurated}}
	cask := HomebrewPackage{Kind: "cask", Name: "firefox", Tap: "homebrew/cask", Version: "143.0", LinkedApps: []string{"Firefox"}}

	linked := cask
	linked.LinkedToApp = true
	findings, unmapped := MatchHomebrew([]HomebrewPackage{linked}, mappings, feed)
	if len(findings) != 0 || len(unmapped) != 0 {
		t.Fatalf("linked cask: findings %+v unmapped %+v, want none", findings, unmapped)
	}
	// Unlinked (or linked only to an unmapped app): the cask is its own finding.
	findings, _ = MatchHomebrew([]HomebrewPackage{cask}, mappings, feed)
	if len(findings) != 1 || findings[0].AppName != "firefox (Homebrew cask)" || findings[0].PackageSource != HomebrewCaskSource {
		t.Fatalf("unlinked cask findings = %+v", findings)
	}
}

// TestMatchHomebrewAutoSeededMappingNeverMatches: a non-curated mapping
// produces no finding and leaves the package unmapped (review 2026-09-23:
// endpoint-derived suggestions must never become findings on their own).
func TestMatchHomebrewAutoSeededMappingNeverMatches(t *testing.T) {
	mappings := []HomebrewMapping{{SourceType: HomebrewFormulaSource, Name: "openssl@3", CPEVendor: "openssl", CPEProduct: "openssl", ReviewState: MappingAutoSeeded}}
	pkgs := []HomebrewPackage{{Kind: "formula", Name: "openssl@3", Tap: "homebrew/core", Version: "3.0.7"}}
	findings, unmapped := MatchHomebrew(pkgs, mappings, brewFeed)
	if len(findings) != 0 || len(unmapped) != 1 {
		t.Fatalf("auto_seeded mapping: findings %+v unmapped %+v, want none and one", findings, unmapped)
	}
}

// TestMatchHomebrewLetterSuffixConfirmed (PAT-2044): 1.1.1s sits inside
// CVE-2023-0286's range ending before 1.1.1t. The comparator orders OpenSSL
// letter releases, so it is a confirmed, high-confidence finding with NVD's
// fixed version, and 1.1.1t itself is out of range and produces nothing.
func TestMatchHomebrewLetterSuffixConfirmed(t *testing.T) {
	mappings := []HomebrewMapping{{SourceType: HomebrewFormulaSource, Name: "openssl@1.1", CPEVendor: "openssl", CPEProduct: "openssl", ReviewState: MappingCurated}}
	pkgs := []HomebrewPackage{{Kind: "formula", Name: "openssl@1.1", Tap: "homebrew/core", Version: "1.1.1s_1"}}
	findings, _ := MatchHomebrew(pkgs, mappings, brewFeed)
	byKey := findingsByKey(findings)
	f, ok := byKey["CVE-2023-0286|openssl@1.1 (Homebrew formula)"]
	if !ok {
		t.Fatalf("1.1.1s against a range ending before 1.1.1t produced no finding: %+v", findings)
	}
	if f.MatchConfidence != "version_confirmed" || f.ConfidenceTier != ConfidenceHigh ||
		f.AppVersion != "1.1.1s_1" || f.FixedVersion != "1.1.1t" {
		t.Fatalf("finding = %+v, want version_confirmed / high / raw version / fixed 1.1.1t", f)
	}

	pkgs[0].Version = "1.1.1t"
	if findings, _ := MatchHomebrew(pkgs, mappings, brewFeed); len(findings) != 0 {
		t.Fatalf("1.1.1t is the fixed release but produced %+v", findings)
	}
}

// TestMatchHomebrewNonComparableIsLowNeverDropped: a version the comparator
// cannot order against the bound (a pre-release, a HEAD build, a cask
// "latest") is kept as a low, unverified finding, never dropped.
func TestMatchHomebrewNonComparableIsLowNeverDropped(t *testing.T) {
	feed := []CVEEntry{{CVEID: "CVE-TEST-PRE", Score: score(7.5), Severity: "HIGH", Patterns: []string{"openssl:openssl"},
		Ranges: []CPERange{{Vendor: "openssl", Product: "openssl", VStartIncl: "3.0.0", VEndExcl: "3.0.8"}}}}
	mappings := []HomebrewMapping{{SourceType: HomebrewFormulaSource, Name: "openssl@3", CPEVendor: "openssl", CPEProduct: "openssl", ReviewState: MappingCurated}}
	// 3.0.8p1 agrees with the 3.0.8 bound as far as both go, so it is
	// unknown; 3.0.7p1 is certainly below 3.0.8 and is confirmed (below).
	for _, v := range []string{"3.0.0-rc1", "3.0.0rc1", "3.0.0-beta2", "3.0.8p1", "HEAD-1a2b3c4"} {
		pkgs := []HomebrewPackage{{Kind: "formula", Name: "openssl@3", Tap: "homebrew/core", Version: v}}
		findings, _ := MatchHomebrew(pkgs, mappings, feed)
		if len(findings) != 1 {
			t.Fatalf("%s: non-comparable version was dropped: %+v", v, findings)
		}
		if f := findings[0]; f.MatchConfidence != "version_unverified" || f.ConfidenceTier != ConfidenceLow ||
			f.AppVersion != v || f.FixedVersion != "" {
			t.Fatalf("%s: finding = %+v, want version_unverified / low / raw version / no fixed version", v, f)
		}
	}
}

// TestMatchHomebrewCertainPrefixConfirmed: 3.0.7p1 is outside the grammar,
// but its leading numbers 3.0.7 already sit between 3.0.0 and 3.0.8.
func TestMatchHomebrewCertainPrefixConfirmed(t *testing.T) {
	feed := []CVEEntry{{CVEID: "CVE-TEST-PRE", Score: score(7.5), Severity: "HIGH", Patterns: []string{"openssl:openssl"},
		Ranges: []CPERange{{Vendor: "openssl", Product: "openssl", VStartIncl: "3.0.0", VEndExcl: "3.0.8"}}}}
	mappings := []HomebrewMapping{{SourceType: HomebrewFormulaSource, Name: "openssl@3", CPEVendor: "openssl", CPEProduct: "openssl", ReviewState: MappingCurated}}
	findings, _ := MatchHomebrew([]HomebrewPackage{{Kind: "formula", Name: "openssl@3", Tap: "homebrew/core", Version: "3.0.7p1"}}, mappings, feed)
	if len(findings) != 1 || findings[0].MatchConfidence != "version_confirmed" || findings[0].ConfidenceTier != ConfidenceHigh ||
		findings[0].FixedVersion != "3.0.8" {
		t.Fatalf("3.0.7p1 against 3.0.0..3.0.8: %+v, want one confirmed high finding fixed in 3.0.8", findings)
	}
}

// TestComparableHomebrewVersion: the wrapper only normalises. HEAD and cask
// "latest" have no upstream version; every other shape goes to the range
// gate, which decides what it can compare.
func TestComparableHomebrewVersion(t *testing.T) {
	cases := []struct{ kind, raw, want string }{
		{"formula", "3.0.8", "3.0.8"},
		{"formula", "8.4.0_1", "8.4.0"},
		{"cask", "1.2.3,abc", "1.2.3"},
		{"formula", "1.1.1w", "1.1.1w"},
		{"formula", "1.1.1w_1", "1.1.1w"},
		{"formula", "9.8p1", "9.8p1"},
		{"formula", "3.0.0rc1", "3.0.0rc1"},
		{"formula", "HEAD", ""},
		{"formula", "HEAD-1a2b3c4", ""},
		{"cask", "latest", ""},
	}
	for _, c := range cases {
		if got := comparableHomebrewVersion(c.kind, c.raw); got != c.want {
			t.Errorf("%s %q: comparable = %q, want %q", c.kind, c.raw, got, c.want)
		}
	}
}

func TestHomebrewTapEligibility(t *testing.T) {
	cases := []struct {
		kind, tap        string
		official, queued bool
	}{
		{"formula", "homebrew/core", true, true},
		{"formula", "", true, false}, // may match a curated mapping, never queued
		{"formula", "acme/tools", false, false},
		{"formula", "homebrew/cask", false, false},
		{"cask", "homebrew/cask", true, true},
		{"cask", "", true, false},
	}
	for _, c := range cases {
		p := HomebrewPackage{Kind: c.kind, Tap: c.tap}
		if p.OfficialTap() != c.official || p.ExplicitOfficialTap() != c.queued {
			t.Errorf("%s tap %q: official=%v explicit=%v, want %v %v", c.kind, c.tap,
				p.OfficialTap(), p.ExplicitOfficialTap(), c.official, c.queued)
		}
	}
}

// TestMatchHomebrewSeveralKegsOneFinding: two kegs of one formula yield one
// finding per CVE: the vulnerable keg's version, confirmed.
func TestMatchHomebrewSeveralKegsOneFinding(t *testing.T) {
	pkgs := []HomebrewPackage{
		{Kind: "formula", Name: "openssl@3", Version: "3.0.9"}, // fixed
		{Kind: "formula", Name: "openssl@3", Version: "3.0.7"}, // vulnerable
		{Kind: "formula", Name: "openssl@3", Version: "HEAD"},  // unknown
	}
	findings, _ := MatchHomebrew(pkgs, brewMappings, brewFeed)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	if f := findings[0]; f.AppVersion != "3.0.7" || f.MatchConfidence != "version_confirmed" || f.FixedVersion != "3.0.8" {
		t.Fatalf("finding = %+v", f)
	}
}

func TestHomebrewDisplayNameRoundTrip(t *testing.T) {
	for _, kind := range []string{"formula", "cask"} {
		k, n, ok := ParseHomebrewDisplayName(HomebrewDisplayName(kind, "docker"))
		if !ok || k != kind || n != "docker" {
			t.Fatalf("round trip %s = %q %q %v", kind, k, n, ok)
		}
	}
	if IsHomebrewDisplayName("Docker Desktop") || IsHomebrewDisplayName(" (Homebrew formula)") {
		t.Fatal("application names must not parse as Homebrew")
	}
}

func TestHomebrewSuggestionCandidates(t *testing.T) {
	cases := []struct {
		p    HomebrewPackage
		want []string
	}{
		{HomebrewPackage{Name: "openssl@3", Homepage: "https://www.openssl.org/"}, []string{"openssl:openssl"}},
		{HomebrewPackage{Name: "jq", Homepage: "https://jqlang.github.io/jq/",
			SourceURL: "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-1.7.1.tar.gz"},
			[]string{"jqlang:jq"}},
		// A source URL on a mirror names no vendor.
		{HomebrewPackage{Name: "wget", SourceURL: "https://ftp.gnu.org/gnu/wget/wget-1.24.5.tar.gz"}, []string{}},
		{HomebrewPackage{Name: "x", Homepage: "not a url"}, []string{}},
	}
	for _, c := range cases {
		got := HomebrewSuggestionCandidates(c.p)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("candidates(%+v) = %v, want %v", c.p, got, c.want)
		}
	}
}
