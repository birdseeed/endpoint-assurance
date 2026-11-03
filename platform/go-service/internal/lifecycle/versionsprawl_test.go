package lifecycle

import (
	"testing"
	"time"

	"patched.im/api/internal/cvematch"
)

func TestMajorOf(t *testing.T) {
	cases := []struct {
		version string
		want    int
		ok      bool
	}{
		{"154.0.8037.58", 154, true},
		{"8.0.402.6", 8, true},
		{"v21.0.4+7", 21, true},
		{"3", 3, true},
		{"", 0, false},
		{"latest", 0, false},
		{"HEAD-1a2b3c4", 0, false},
	}
	for _, c := range cases {
		got, ok := majorOf(c.version)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("majorOf(%q) = %d, %v; want %d, %v", c.version, got, ok, c.want, c.ok)
		}
	}
}

func devFacts(ids ...string) map[string]*deviceFacts {
	out := map[string]*deviceFacts{}
	for _, id := range ids {
		out[id] = &deviceFacts{ID: id}
	}
	return out
}

func staleDevFacts(id string) *deviceFacts { return &deviceFacts{ID: id, Stale: true} }

func noLifecycle(identityKey) (*MappingRef, *Product) { return nil, nil }

// TestVersionSprawlOneVersion covers a product with a single live version:
// no sprawl, nobody behind, nobody not comparable (the version parses).
func TestVersionSprawlOneVersion(t *testing.T) {
	k := identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example.one"}
	g := &sprawlGroup{key: k, names: map[string]int{"OneApp": 2}, installs: []sprawlInstall{
		{DeviceID: "d1", Fingerprint: "fp1", Name: "OneApp", Version: "3.0.1"},
		{DeviceID: "d2", Fingerprint: "fp1", Name: "OneApp", Version: "3.0.1"},
	}}
	devices := devFacts("d1", "d2")
	row := buildSprawlProduct(time.Now().UTC(), k, g, devices, noLifecycle, nil, nil, nil, nil)

	if row.DistinctVersions != 1 {
		t.Errorf("distinct versions = %d, want 1", row.DistinctVersions)
	}
	if row.OldestVersion != "3.0.1" || row.NewestVersion != "3.0.1" {
		t.Errorf("oldest/newest = %q/%q, want 3.0.1/3.0.1", row.OldestVersion, row.NewestVersion)
	}
	if row.DevicesMoreThanOneMajorBehind != 0 || row.DevicesNotComparable != 0 {
		t.Errorf("behind=%d notcomparable=%d, want 0/0", row.DevicesMoreThanOneMajorBehind, row.DevicesNotComparable)
	}
	if row.DeviceCount != 2 {
		t.Errorf("device count = %d, want 2", row.DeviceCount)
	}
	if row.LatestReleased != nil {
		t.Errorf("latest released = %v, want nil (no trusted source given)", *row.LatestReleased)
	}
	if !row.CVENotAssessed || row.CVECountOnOldest != nil {
		t.Errorf("cve not assessed = %v, count = %v; want not assessed, no count (no mapping loaded)", row.CVENotAssessed, row.CVECountOnOldest)
	}
}

// TestVersionSprawlManyVersions covers a product spread across several
// versions: the major-behind computation must be against the newest LIVE
// major on the estate, not the vendor's latest, and devices on a version
// that doesn't parse must be "not comparable", never "behind" or "current".
func TestVersionSprawlManyVersions(t *testing.T) {
	k := identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example.many"}
	g := &sprawlGroup{key: k, names: map[string]int{"ManyApp": 5}, installs: []sprawlInstall{
		{DeviceID: "current", Fingerprint: "fp2", Name: "ManyApp", Version: "10.2.0"},          // newest, major 10
		{DeviceID: "onebehind", Fingerprint: "fp2", Name: "ManyApp", Version: "9.5.0"},         // major 9: one behind, not counted
		{DeviceID: "twobehind", Fingerprint: "fp2", Name: "ManyApp", Version: "8.0.0"},         // major 8: two behind
		{DeviceID: "threebehind", Fingerprint: "fp2", Name: "ManyApp", Version: "7.1.0"},       // major 7: three behind
		{DeviceID: "unparseable", Fingerprint: "fp2", Name: "ManyApp", Version: "HEAD-abc123"}, // not comparable
	}}
	devices := devFacts("current", "onebehind", "twobehind", "threebehind", "unparseable")
	row := buildSprawlProduct(time.Now().UTC(), k, g, devices, noLifecycle, nil, nil, nil, nil)

	if row.DistinctVersions != 4 {
		t.Errorf("distinct versions = %d, want 4", row.DistinctVersions)
	}
	if row.OldestVersion != "7.1.0" {
		t.Errorf("oldest = %q, want 7.1.0", row.OldestVersion)
	}
	if row.NewestVersion != "10.2.0" {
		t.Errorf("newest = %q, want 10.2.0", row.NewestVersion)
	}
	if row.DevicesMoreThanOneMajorBehind != 2 {
		t.Errorf("devices more than one major behind = %d, want 2 (majors 8 and 7)", row.DevicesMoreThanOneMajorBehind)
	}
	if row.DevicesNotComparable != 1 {
		t.Errorf("devices not comparable = %d, want 1 (the HEAD build)", row.DevicesNotComparable)
	}
	if row.DeviceCount != 5 {
		t.Errorf("device count = %d, want 5", row.DeviceCount)
	}
}

// TestVersionSprawlNoKnownLatest covers a product with no trusted
// latest-released source at all: latest_released must read nil/unknown, and
// it must never be synthesised from the newest version seen on the estate.
func TestVersionSprawlNoKnownLatest(t *testing.T) {
	k := identityKey{Platform: "windows", Kind: "windows_native", Value: "unknownapp"}
	g := &sprawlGroup{key: k, names: map[string]int{"UnknownApp": 1}, installs: []sprawlInstall{
		{DeviceID: "d1", Fingerprint: "fp3", Name: "UnknownApp", Version: "99.0.0"},
	}}
	devices := devFacts("d1")
	// No lifecycle mapping, no catalogue entries: nothing trusts a "latest".
	row := buildSprawlProduct(time.Now().UTC(), k, g, devices, noLifecycle, nil, nil, nil, nil)

	if row.LatestReleased != nil {
		t.Fatalf("latest released = %q, want nil: the newest version seen on the estate (99.0.0) must never be reported as the vendor's latest", *row.LatestReleased)
	}
	if row.LatestReleasedSource != nil {
		t.Errorf("latest released source = %+v, want nil", row.LatestReleasedSource)
	}
}

// TestVersionSprawlLatestSourcePrecedence: a published lifecycle mapping
// wins over the curated catalogue when both could answer, and each row
// carries the source it actually used.
func TestVersionSprawlLatestSourcePrecedence(t *testing.T) {
	k := identityKey{Platform: "macos", Kind: "macos_bundle_team", Value: "com.example.prec", Companion: "TEAMID1234"}
	g := &sprawlGroup{key: k, names: map[string]int{"PrecApp": 1}, installs: []sprawlInstall{
		{DeviceID: "d1", Fingerprint: "fp4", Name: "PrecApp", Version: "1.0.0"},
	}}
	devices := devFacts("d1")
	now := time.Now().UTC()

	fetchedAt := now.Add(-time.Hour)
	lifecycleLookup := func(identityKey) (*MappingRef, *Product) {
		return &MappingRef{Slug: "precapp", Rule: Rule{Kind: RuleMajor}},
			&Product{Slug: "precapp", FetchedAt: &fetchedAt, Cycles: []Cycle{{Name: "2", LatestVersion: "2.5.0"}}}
	}
	catalogue := []catalogueEntry{{Platform: "macOS", Name: "PrecApp", VerifiedSigner: "TEAMID1234", LatestVersion: "1.9.0", VerifiedAt: now.Add(-time.Hour)}}

	row := buildSprawlProduct(now, k, g, devices, lifecycleLookup, catalogue, nil, nil, nil)
	if row.LatestReleased == nil || *row.LatestReleased != "2.5.0" {
		t.Fatalf("latest released = %v, want 2.5.0 (the lifecycle source should win)", row.LatestReleased)
	}
	if row.LatestReleasedSource == nil || row.LatestReleasedSource.Name != SourceName {
		t.Fatalf("latest released source = %+v, want %s", row.LatestReleasedSource, SourceName)
	}

	// Now the lifecycle data is stale: the catalogue must be used instead.
	staleAt := now.Add(-8 * 24 * time.Hour)
	staleLookup := func(identityKey) (*MappingRef, *Product) {
		return &MappingRef{Slug: "precapp", Rule: Rule{Kind: RuleMajor}},
			&Product{Slug: "precapp", FetchedAt: &staleAt, Cycles: []Cycle{{Name: "2", LatestVersion: "2.5.0"}}}
	}
	row2 := buildSprawlProduct(now, k, g, devices, staleLookup, catalogue, nil, nil, nil)
	if row2.LatestReleased == nil || *row2.LatestReleased != "1.9.0" {
		t.Fatalf("latest released = %v, want 1.9.0 (catalogue fallback once lifecycle data is stale)", row2.LatestReleased)
	}
	if row2.LatestReleasedSource == nil || row2.LatestReleasedSource.Name != SourceCuratedCatalogue {
		t.Fatalf("latest released source = %+v, want %s", row2.LatestReleasedSource, SourceCuratedCatalogue)
	}
}

// TestVersionSprawlCVENotAssessedVsZero: a product with a CPE mapping but no
// matched findings on its oldest version reads a real 0; a product with no
// mapping at all reads not assessed, never 0.
func TestVersionSprawlCVENotAssessedVsZero(t *testing.T) {
	now := time.Now().UTC()

	mapped := identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example.mapped"}
	gMapped := &sprawlGroup{key: mapped, names: map[string]int{"MappedApp": 1}, installs: []sprawlInstall{
		{DeviceID: "d1", Fingerprint: "fpm", Name: "MappedApp", Version: "1.0.0"},
	}}
	cpeMappings := []cvematch.CPEMapping{{MatchName: "MappedApp", CPEVendor: "vendor", CPEProduct: "mappedapp", Platform: "any", ReviewState: "curated"}}
	rowMapped := buildSprawlProduct(now, mapped, gMapped, devFacts("d1"), noLifecycle, nil, cpeMappings, nil, map[findingKey]map[string]bool{})
	if rowMapped.CVENotAssessed {
		t.Errorf("mapped product read not assessed; want a real 0 (mapping exists, matcher just found nothing)")
	}
	if rowMapped.CVECountOnOldest == nil || *rowMapped.CVECountOnOldest != 0 {
		t.Errorf("cve count = %v, want 0", rowMapped.CVECountOnOldest)
	}

	unmapped := identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example.unmapped"}
	gUnmapped := &sprawlGroup{key: unmapped, names: map[string]int{"UnmappedApp": 1}, installs: []sprawlInstall{
		{DeviceID: "d2", Fingerprint: "fpu", Name: "UnmappedApp", Version: "1.0.0"},
	}}
	rowUnmapped := buildSprawlProduct(now, unmapped, gUnmapped, devFacts("d2"), noLifecycle, nil, cpeMappings, nil, map[findingKey]map[string]bool{})
	if !rowUnmapped.CVENotAssessed {
		t.Errorf("unmapped product read assessed; want not assessed (no CPE mapping covers it)")
	}
	if rowUnmapped.CVECountOnOldest != nil {
		t.Errorf("cve count = %v, want nil for an unmapped product", rowUnmapped.CVECountOnOldest)
	}

	// A real finding on the oldest version of the mapped product is counted.
	findings := map[findingKey]map[string]bool{
		{DeviceID: "d1", AppName: "MappedApp", Version: "1.0.0"}: {"CVE-2026-0001": true, "CVE-2026-0002": true},
	}
	rowWithFindings := buildSprawlProduct(now, mapped, gMapped, devFacts("d1"), noLifecycle, nil, cpeMappings, nil, findings)
	if rowWithFindings.CVECountOnOldest == nil || *rowWithFindings.CVECountOnOldest != 2 {
		t.Errorf("cve count = %v, want 2", rowWithFindings.CVECountOnOldest)
	}
}

// TestVersionSprawlHomebrewTrustedLatest: a Homebrew formula resolves a
// trusted "latest released" through the curated catalogue, matched by its
// reported name -- the one trusted path a Homebrew product has today, since
// Patched holds no separate upstream-version feed for Homebrew packages.
func TestVersionSprawlHomebrewTrustedLatest(t *testing.T) {
	k := identityKey{Platform: "macos", Kind: "homebrew_formula", Value: "brewtool", Companion: "homebrew/core"}
	g := &sprawlGroup{key: k, names: map[string]int{"brewtool": 1}, installs: []sprawlInstall{
		{DeviceID: "d1", Fingerprint: "fpb", Name: "brewtool", Version: "2.1.0"},
	}}
	now := time.Now().UTC()
	catalogue := []catalogueEntry{{Platform: "macOS", Name: "brewtool", LatestVersion: "2.3.0", VerifiedAt: now.Add(-time.Hour)}}
	row := buildSprawlProduct(now, k, g, devFacts("d1"), noLifecycle, catalogue, nil, nil, nil)
	if row.LatestReleased == nil || *row.LatestReleased != "2.3.0" {
		t.Fatalf("latest released = %v, want 2.3.0", row.LatestReleased)
	}
	if row.LatestReleasedSource == nil || row.LatestReleasedSource.Name != SourceCuratedCatalogue {
		t.Fatalf("latest released source = %+v, want %s", row.LatestReleasedSource, SourceCuratedCatalogue)
	}

	// With a curated Homebrew CPE mapping and a matched finding, the CVE
	// count on the oldest version is real evidence, not a guess.
	homebrewMappings := []cvematch.HomebrewMapping{{SourceType: "homebrew_formula", Name: "brewtool", CPEVendor: "v", CPEProduct: "p", ReviewState: "curated"}}
	findings := map[findingKey]map[string]bool{
		{DeviceID: "d1", AppName: "brewtool (Homebrew formula)", Version: "2.1.0"}: {"CVE-2026-9999": true},
	}
	rowWithCVE := buildSprawlProduct(now, k, g, devFacts("d1"), noLifecycle, catalogue, nil, homebrewMappings, findings)
	if rowWithCVE.CVENotAssessed {
		t.Errorf("homebrew product with a curated mapping read not assessed")
	}
	if rowWithCVE.CVECountOnOldest == nil || *rowWithCVE.CVECountOnOldest != 1 {
		t.Errorf("cve count = %v, want 1", rowWithCVE.CVECountOnOldest)
	}
}

// TestVersionSprawlStaleDeviceCounted: a stale device's install still counts
// (never silently dropped), and is reflected in the stale device counters.
func TestVersionSprawlStaleDeviceCounted(t *testing.T) {
	k := identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example.stale"}
	g := &sprawlGroup{key: k, names: map[string]int{"StaleApp": 2}, installs: []sprawlInstall{
		{DeviceID: "fresh", Fingerprint: "fps", Name: "StaleApp", Version: "1.0.0"},
		{DeviceID: "stale", Fingerprint: "fps", Name: "StaleApp", Version: "1.0.0"},
	}}
	devices := map[string]*deviceFacts{"fresh": {ID: "fresh"}, "stale": staleDevFacts("stale")}
	row := buildSprawlProduct(time.Now().UTC(), k, g, devices, noLifecycle, nil, nil, nil, nil)
	if row.DeviceCount != 2 {
		t.Errorf("device count = %d, want 2", row.DeviceCount)
	}
	if row.StaleDeviceCount != 1 {
		t.Errorf("stale device count = %d, want 1", row.StaleDeviceCount)
	}
	if len(row.Versions) != 1 || row.Versions[0].StaleDeviceCount != 1 {
		t.Errorf("version breakdown stale count wrong: %+v", row.Versions)
	}
}
