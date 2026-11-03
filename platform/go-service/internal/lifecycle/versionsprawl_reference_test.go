package lifecycle

// PAT-2509: the "Latest released" figure on the version sprawl report is only
// ever shown when Patched can stand behind it. These tests pin the three
// rules that make that true: a reference matches on product identity and
// never on a shared signer alone, a reference is only shown while its source
// is fresh, and a reference that is lower than a version the estate is
// running right now is stale by evidence and is withheld.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	testMicrosoftTeamID = "UBF8T346G9"
	testGoogleTeamID    = "EQHXZ8M8AV"
	testZoomTeamID      = "BJ4HAAB9B3"
)

func bundleTeamKey(bundleID, teamID string) identityKey {
	return identityKey{Platform: "macos", Kind: "macos_bundle_team", Value: bundleID, Companion: teamID}
}

func groupOf(k identityKey, name string, versions ...string) *sprawlGroup {
	g := &sprawlGroup{key: k, names: map[string]int{name: len(versions)}}
	for i, v := range versions {
		g.installs = append(g.installs, sprawlInstall{
			DeviceID: fmt.Sprintf("d%d", i), Fingerprint: "fp-" + k.Value, Name: name, Version: v,
		})
	}
	return g
}

func devicesFor(g *sprawlGroup) map[string]*deviceFacts {
	ids := make([]string, 0, len(g.installs))
	for _, in := range g.installs {
		ids = append(ids, in.DeviceID)
	}
	return devFacts(ids...)
}

func buildWithCatalogue(now time.Time, k identityKey, name string, catalogue []catalogueEntry, versions ...string) SprawlProduct {
	g := groupOf(k, name, versions...)
	return buildSprawlProduct(now, k, g, devicesFor(g), noLifecycle, catalogue, nil, nil, nil)
}

func latestOf(t *testing.T, row SprawlProduct) string {
	t.Helper()
	if row.LatestReleased == nil {
		if row.LatestReleasedSource != nil {
			t.Fatalf("latest_released is null but its source is %+v: they must be null together", row.LatestReleasedSource)
		}
		return ""
	}
	if row.LatestReleasedSource == nil {
		t.Fatalf("latest_released is %q but its source is null: they must be set together", *row.LatestReleased)
	}
	return *row.LatestReleased
}

// Two products from one vendor share a Team ID. Each must get its own
// reference and never the other's, whichever order the catalogue is read in.
func TestVersionSprawlSharedSignerNeverCrossesProducts(t *testing.T) {
	now := time.Now().UTC()
	edge := catalogueEntry{Platform: "macOS", Name: "Microsoft Edge", VerifiedSigner: testMicrosoftTeamID, LatestVersion: "126.0.2592.68", VerifiedAt: now}
	excel := catalogueEntry{Platform: "macOS", Name: "Microsoft Excel", VerifiedSigner: testMicrosoftTeamID, LatestVersion: "16.86.24061613", VerifiedAt: now}

	for _, order := range [][]catalogueEntry{{edge, excel}, {excel, edge}} {
		excelRow := buildWithCatalogue(now, bundleTeamKey("com.microsoft.excel", testMicrosoftTeamID), "Microsoft Excel", order, "16.70.0")
		if got := latestOf(t, excelRow); got != "16.86.24061613" {
			t.Errorf("Excel reference = %q, want 16.86.24061613 (never Edge's 126.0.2592.68), catalogue order %s first", got, order[0].Name)
		}
		edgeRow := buildWithCatalogue(now, bundleTeamKey("com.microsoft.edgemac", testMicrosoftTeamID), "Microsoft Edge", order, "120.0.1")
		if got := latestOf(t, edgeRow); got != "126.0.2592.68" {
			t.Errorf("Edge reference = %q, want 126.0.2592.68, catalogue order %s first", got, order[0].Name)
		}
	}

	// The catalogue holds only another product of the same vendor: Excel gets
	// nothing, not Edge's version. Signer alone is never enough, whether or not
	// a better-named entry is there to outrank it.
	if got := latestOf(t, buildWithCatalogue(now, bundleTeamKey("com.microsoft.excel", testMicrosoftTeamID), "Microsoft Excel", []catalogueEntry{edge}, "16.70.0")); got != "" {
		t.Errorf("Excel with only Edge in the catalogue took reference %q, want none", got)
	}

	// A Microsoft product the catalogue has no entry for gets nothing: the
	// signer alone is never enough.
	rdp := buildWithCatalogue(now, bundleTeamKey("com.microsoft.rdc.macos", testMicrosoftTeamID), "Windows App", []catalogueEntry{edge, excel}, "11.0.0")
	if got := latestOf(t, rdp); got != "" {
		t.Errorf("uncatalogued Microsoft product reference = %q, want none", got)
	}
}

// A product with no team ID cannot satisfy a signed entry, and an unrelated
// product carrying the right team ID still does not match.
func TestVersionSprawlSignedEntryNeedsSignerAndName(t *testing.T) {
	now := time.Now().UTC()
	chrome := catalogueEntry{Platform: "macOS", Name: "Google Chrome", VerifiedSigner: testGoogleTeamID, LatestVersion: "150.0.0.1", VerifiedAt: now}

	cases := []struct {
		label string
		key   identityKey
		name  string
		want  string
	}{
		{"name and signer agree", bundleTeamKey("com.google.chrome", testGoogleTeamID), "Google Chrome", "150.0.0.1"},
		{"right name, no signer evidence", identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.google.chrome"}, "Google Chrome", ""},
		{"right name, someone else's signer", bundleTeamKey("com.google.chrome", "ZZZZZZZZZZ"), "Google Chrome", ""},
		{"Google Drive shares Chrome's signer", bundleTeamKey("com.google.drivefs", testGoogleTeamID), "Google Drive", ""},
		{"Google Docs shares Chrome's signer", bundleTeamKey("com.google.docs", testGoogleTeamID), "Google Docs", ""},
	}
	for _, c := range cases {
		row := buildWithCatalogue(now, c.key, c.name, []catalogueEntry{chrome}, "100.0.0.1")
		if got := latestOf(t, row); got != c.want {
			t.Errorf("%s: reference = %q, want %q", c.label, got, c.want)
		}
	}
}

// A helper or sub-app is not the product it ships inside, and never takes the
// product's reference.
func TestVersionSprawlHelperAppsNeverTakeAProductReference(t *testing.T) {
	now := time.Now().UTC()
	zoom := catalogueEntry{Platform: "macOS", Name: "Zoom", VerifiedSigner: testZoomTeamID, LatestVersion: "7.2.0", VerifiedAt: now}
	for _, id := range []string{"us.zoom.xos.zoomautoupdater", "us.zoom.xos.zoomairhost", "us.zoom.xos.cpthost"} {
		row := buildWithCatalogue(now, bundleTeamKey(id, testZoomTeamID), "Zoom", []catalogueEntry{zoom}, "6.0.0")
		if got := latestOf(t, row); got != "" {
			t.Errorf("%s took reference %q; a helper app must not take its parent product's", id, got)
		}
	}
	zoomApp := buildWithCatalogue(now, bundleTeamKey("us.zoom.xos", testZoomTeamID), "Zoom", []catalogueEntry{zoom}, "6.0.0")
	if got := latestOf(t, zoomApp); got != "7.2.0" {
		t.Errorf("Zoom itself reference = %q, want 7.2.0", got)
	}
}

// A catalogue name that is merely contained in the product's display name (or
// the other way round) is not the same product. "Microsoft Teams classic" has
// its own version line; "zoom.us" against "Zoom" is a guess. Only an exact
// name, with the right signer where the entry has one, gives a reference.
func TestVersionSprawlPartialNameNeverYieldsAReference(t *testing.T) {
	now := time.Now().UTC()
	teams := catalogueEntry{Platform: "macOS", Name: "Microsoft Teams", VerifiedSigner: testMicrosoftTeamID, LatestVersion: "24134.3004.2974", VerifiedAt: now}
	zoomWin := catalogueEntry{Platform: "Windows", Name: "Zoom", LatestVersion: "7.2.0", VerifiedAt: now}
	zoomMac := catalogueEntry{Platform: "macOS", Name: "Zoom", VerifiedSigner: testZoomTeamID, LatestVersion: "7.2.0", VerifiedAt: now}
	winKey := func(v string) identityKey { return identityKey{Platform: "windows", Kind: "windows_native", Value: v} }

	cases := []struct {
		label   string
		key     identityKey
		name    string
		entries []catalogueEntry
		live    string
		want    string
	}{
		{"exact name, right signer", bundleTeamKey("com.microsoft.teams2", testMicrosoftTeamID), "Microsoft Teams", []catalogueEntry{teams}, "24100.1.1", "24134.3004.2974"},
		{"exact name, case and spaces differ", bundleTeamKey("com.microsoft.teams2", testMicrosoftTeamID), "  MICROSOFT teams ", []catalogueEntry{teams}, "24100.1.1", "24134.3004.2974"},
		{"display name contains the entry name", bundleTeamKey("com.microsoft.teams", testMicrosoftTeamID), "Microsoft Teams classic", []catalogueEntry{teams}, "24100.1.1", ""},
		{"entry name contains the display name", bundleTeamKey("com.microsoft.teams", testMicrosoftTeamID), "Teams", []catalogueEntry{teams}, "24100.1.1", ""},
		{"unsigned Windows entry, exact name", winKey("zoom"), "Zoom", []catalogueEntry{zoomWin}, "6.0.0", "7.2.0"},
		{"unsigned Windows entry, Zoom Rooms", winKey("zoom rooms"), "Zoom Rooms", []catalogueEntry{zoomWin}, "6.0.0", ""},
		{"unsigned Windows entry, zoom.us", winKey("zoom.us"), "zoom.us", []catalogueEntry{zoomWin}, "6.0.0", ""},
		{"signed macOS entry, zoom.us", bundleTeamKey("us.zoom.xos", testZoomTeamID), "zoom.us", []catalogueEntry{zoomMac}, "6.0.0", ""},
		{"signed macOS entry, exact name", bundleTeamKey("us.zoom.xos", testZoomTeamID), "Zoom", []catalogueEntry{zoomMac}, "6.0.0", "7.2.0"},
		{"exact name, wrong signer", bundleTeamKey("com.microsoft.teams2", "ZZZZZZZZZZ"), "Microsoft Teams", []catalogueEntry{teams}, "24100.1.1", ""},
	}
	for _, c := range cases {
		row := buildWithCatalogue(now, c.key, c.name, c.entries, c.live)
		if got := latestOf(t, row); got != c.want {
			t.Errorf("%s: reference = %q, want %q", c.label, got, c.want)
		}
	}
}

// A partial match does not hand a product to a weaker entry when the exact
// one is stale either.
func TestVersionSprawlStaleExactEntryIsNotReplacedByAPartialOne(t *testing.T) {
	now := time.Now().UTC()
	exact := catalogueEntry{Platform: "macOS", Name: "Foo", VerifiedSigner: "TEAMFOO123", LatestVersion: "2.0.0", VerifiedAt: now.Add(-30 * 24 * time.Hour)}
	partial := catalogueEntry{Platform: "macOS", Name: "Foo Pro", VerifiedSigner: "TEAMFOO123", LatestVersion: "9.0.0", VerifiedAt: now}
	row := buildWithCatalogue(now, bundleTeamKey("com.example.foo", "TEAMFOO123"), "Foo", []catalogueEntry{exact, partial}, "1.0.0")
	if got := latestOf(t, row); got != "" {
		t.Errorf("stale exact entry gave way to a partial one: reference = %q, want none", got)
	}
}

// Where more than one entry has exactly the product's name and they disagree
// on the version, the product could be either and the catalogue does not
// choose. The answer does not depend on the order the entries are read in.
func TestVersionSprawlDisagreeingExactEntriesAreNotGuessed(t *testing.T) {
	now := time.Now().UTC()
	k := bundleTeamKey("com.example.dup", "TEAMDUP123")
	a := catalogueEntry{Platform: "macOS", Name: "DupApp", VerifiedSigner: "TEAMDUP123", LatestVersion: "2.0.0", VerifiedAt: now}
	b := catalogueEntry{Platform: "macOS", Name: "dupapp", VerifiedSigner: "TEAMDUP123", LatestVersion: "3.0.0", VerifiedAt: now}
	for _, order := range [][]catalogueEntry{{a, b}, {b, a}} {
		if got := latestOf(t, buildWithCatalogue(now, k, "DupApp", order, "1.0.0")); got != "" {
			t.Errorf("disagreeing exact entries gave %q, want none (order %s first)", got, order[0].Name)
		}
	}
	same := b
	same.LatestVersion = "2.0.0"
	if got := latestOf(t, buildWithCatalogue(now, k, "DupApp", []catalogueEntry{a, same}, "1.0.0")); got != "2.0.0" {
		t.Errorf("agreeing exact entries gave %q, want 2.0.0", got)
	}

	// 1Password 7 and 1Password 8 are separate entries: a product just named
	// "1Password" is neither, and one named "1Password 8" is exactly one.
	op7 := catalogueEntry{Platform: "macOS", Name: "1Password 7", VerifiedSigner: "2BUA8C4S2C", LatestVersion: "7.9.11", VerifiedAt: now}
	op8 := catalogueEntry{Platform: "macOS", Name: "1Password 8", VerifiedSigner: "2BUA8C4S2C", LatestVersion: "8.10.44", VerifiedAt: now}
	opKey := bundleTeamKey("com.1password.1password", "2BUA8C4S2C")
	for _, order := range [][]catalogueEntry{{op7, op8}, {op8, op7}} {
		if got := latestOf(t, buildWithCatalogue(now, opKey, "1Password", order, "7.0.0")); got != "" {
			t.Errorf("1Password (could be 7 or 8) took reference %q, want none", got)
		}
		if got := latestOf(t, buildWithCatalogue(now, opKey, "1Password 8", order, "8.1.0")); got != "8.10.44" {
			t.Errorf("1Password 8 reference = %q, want 8.10.44", got)
		}
	}
}

// A reference lower than a version running on the estate right now is stale by
// evidence, whichever source it came from.
func TestVersionSprawlReferenceBelowLiveVersionIsWithheld(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-time.Hour)
	k := bundleTeamKey("com.google.chrome", testGoogleTeamID)

	lifecycleFor := func(latest string) func(identityKey) (*MappingRef, *Product) {
		return func(identityKey) (*MappingRef, *Product) {
			return &MappingRef{Slug: "google-chrome", Rule: Rule{Kind: RuleMajor}},
				&Product{Slug: "google-chrome", FetchedAt: &fresh, Cycles: []Cycle{{Name: "126", LatestVersion: latest}}}
		}
	}
	catalogueFor := func(latest string) []catalogueEntry {
		return []catalogueEntry{{Platform: "macOS", Name: "Google Chrome", VerifiedSigner: testGoogleTeamID, LatestVersion: latest, VerifiedAt: fresh}}
	}

	cases := []struct {
		label     string
		reference string
		live      []string
		want      string // "" means withheld
	}{
		{"production Chrome case", "126.0.6478.127", []string{"149.0.7000.1", "154.0.8037.58"}, ""},
		{"lower than one of several live versions", "150.0.0.1", []string{"140.0.0.1", "154.0.8037.58"}, ""},
		{"equal to the newest live version", "154.0.8037.58", []string{"149.0.7000.1", "154.0.8037.58"}, "154.0.8037.58"},
		{"higher than every live version", "155.0.1.0", []string{"149.0.7000.1", "154.0.8037.58"}, "155.0.1.0"},
		{"comparison not decidable", "1.1a", []string{"1.1.1"}, ""},
	}
	for _, c := range cases {
		g := groupOf(k, "Google Chrome", c.live...)

		rowLC := buildSprawlProduct(now, k, g, devicesFor(g), lifecycleFor(c.reference), nil, nil, nil, nil)
		if got := latestOf(t, rowLC); got != c.want {
			t.Errorf("endoflife.date, %s: reference = %q, want %q", c.label, got, c.want)
		}
		rowCat := buildSprawlProduct(now, k, g, devicesFor(g), noLifecycle, catalogueFor(c.reference), nil, nil, nil)
		if got := latestOf(t, rowCat); got != c.want {
			t.Errorf("catalogue, %s: reference = %q, want %q", c.label, got, c.want)
		}
	}
}

// When the preferred source's figure is contradicted by the estate, no other
// source is allowed to step in: two disagreeing sources are not a reference.
func TestVersionSprawlContradictedLifecycleDoesNotFallThroughToCatalogue(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-time.Hour)
	k := bundleTeamKey("com.google.chrome", testGoogleTeamID)
	lookup := func(identityKey) (*MappingRef, *Product) {
		return &MappingRef{Slug: "google-chrome", Rule: Rule{Kind: RuleMajor}},
			&Product{Slug: "google-chrome", FetchedAt: &fresh, Cycles: []Cycle{{Name: "126", LatestVersion: "126.0.1.0"}}}
	}
	catalogue := []catalogueEntry{{Platform: "macOS", Name: "Google Chrome", VerifiedSigner: testGoogleTeamID, LatestVersion: "160.0.0.0", VerifiedAt: fresh}}
	g := groupOf(k, "Google Chrome", "150.0.0.1")
	row := buildSprawlProduct(now, k, g, devicesFor(g), lookup, catalogue, nil, nil, nil)
	if got := latestOf(t, row); got != "" {
		t.Errorf("reference = %q, want none when the preferred source is contradicted", got)
	}
}

// The catalogue is only a reference while it was verified recently.
func TestVersionSprawlCatalogueFreshnessWindow(t *testing.T) {
	now := time.Now().UTC()
	k := bundleTeamKey("com.example.fresh", "TEAMFRESH1")
	entry := func(verified time.Time) []catalogueEntry {
		return []catalogueEntry{{Platform: "macOS", Name: "FreshApp", VerifiedSigner: "TEAMFRESH1", LatestVersion: "3.0.0", VerifiedAt: verified}}
	}

	cases := []struct {
		label    string
		verified time.Time
		want     string
	}{
		{"verified an hour ago", now.Add(-time.Hour), "3.0.0"},
		{"verified six days ago", now.Add(-6 * 24 * time.Hour), "3.0.0"},
		{"verified exactly seven days ago", now.Add(-7 * 24 * time.Hour), "3.0.0"},
		{"verified eight days ago", now.Add(-8 * 24 * time.Hour), ""},
		{"verified in August, read in October", time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC), ""},
		{"never verified", time.Time{}, ""},
	}
	for _, c := range cases {
		row := buildWithCatalogue(now, k, "FreshApp", entry(c.verified), "1.0.0")
		if got := latestOf(t, row); got != c.want {
			t.Errorf("%s: reference = %q, want %q", c.label, got, c.want)
		}
	}
}

// A shown reference tells the reader what the source is and when it was
// checked. The machine name stays as it was.
func TestVersionSprawlSourceCarriesLabelAndCheckedDate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	verified := now.Add(-48 * time.Hour)
	k := bundleTeamKey("com.example.cat", "TEAMCAT123")
	cat := buildWithCatalogue(now, k, "CatApp",
		[]catalogueEntry{{Platform: "macOS", Name: "CatApp", VerifiedSigner: "TEAMCAT123", LatestVersion: "2.0.0", VerifiedAt: verified}}, "1.0.0")
	if latestOf(t, cat) != "2.0.0" {
		t.Fatalf("catalogue reference missing: %+v", cat.LatestReleased)
	}
	src := cat.LatestReleasedSource
	if src.Name != SourceCuratedCatalogue {
		t.Errorf("catalogue source name = %q, want the unchanged machine name %q", src.Name, SourceCuratedCatalogue)
	}
	if src.Label != "Patched reference list" {
		t.Errorf("catalogue source label = %q, want %q", src.Label, "Patched reference list")
	}
	if src.CheckedAt == nil || !src.CheckedAt.Equal(verified) {
		t.Errorf("catalogue source checked_at = %v, want verified_at %v", src.CheckedAt, verified)
	}

	fetched := now.Add(-3 * time.Hour)
	lk := bundleTeamKey("com.example.lc", "TEAMLC1234")
	lg := groupOf(lk, "LcApp", "1.0.0")
	lc := buildSprawlProduct(now, lk, lg, devicesFor(lg), func(identityKey) (*MappingRef, *Product) {
		return &MappingRef{Slug: "lcapp", Rule: Rule{Kind: RuleMajor}},
			&Product{Slug: "lcapp", FetchedAt: &fetched, Cycles: []Cycle{{Name: "2", LatestVersion: "2.5.0"}}}
	}, nil, nil, nil, nil)
	if latestOf(t, lc) != "2.5.0" {
		t.Fatalf("lifecycle reference missing: %+v", lc.LatestReleased)
	}
	lsrc := lc.LatestReleasedSource
	if lsrc.Name != SourceName || lsrc.Label != "endoflife.date" {
		t.Errorf("lifecycle source name/label = %q/%q, want endoflife.date for both", lsrc.Name, lsrc.Label)
	}
	if lsrc.CheckedAt == nil || !lsrc.CheckedAt.Equal(fetched) {
		t.Errorf("lifecycle source checked_at = %v, want fetch time %v", lsrc.CheckedAt, fetched)
	}
}

func TestVersionSprawlDefinitionStatesTheCatalogueWindow(t *testing.T) {
	if VersionSprawlDefinition.CatalogueMaxAgeDays != 7 {
		t.Errorf("definition catalogue_max_age_days = %d, want 7", VersionSprawlDefinition.CatalogueMaxAgeDays)
	}
	if CatalogueMaxAge != 7*24*time.Hour {
		t.Errorf("CatalogueMaxAge = %v, want 7 days", CatalogueMaxAge)
	}
}

// seedRow is one row of the 0030 catalogue seed.
type seedRow struct {
	Label, Name, Platform, Signer, Latest string
	VerifiedAt                            time.Time
}

var seedRowRE = regexp.MustCompile(
	`\(\s*'([^']*)',\s*'([^']*)',\s*'[^']*',\s*'(macOS|Windows)',\s*(NULL|'[^']*'),\s*'([^']*)',\s*'([^']*)'\s*\)`)

// loadSeedRows reads the real seed out of the migration, so this test follows
// the data and not a copy of it.
func loadSeedRows(t *testing.T) []seedRow {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/0030_app_catalog_entries.sql")
	if err != nil {
		t.Fatalf("read seed migration: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "INSERT INTO app_catalog_entries")
	end := strings.Index(text, "ON CONFLICT (label) DO NOTHING")
	if start < 0 || end < start {
		t.Fatal("seed INSERT not found in migration 0030")
	}
	block := text[start:end]
	// Every row of the VALUES list opens a line with "('". If a format change
	// stops the pattern below recognising some rows, these counts disagree and
	// the test fails outright, instead of passing on fewer rows or on none.
	rowLines := 0
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "('") {
			rowLines++
		}
	}
	var rows []seedRow
	for _, m := range seedRowRE.FindAllStringSubmatch(block, -1) {
		signer := ""
		if m[4] != "NULL" {
			signer = strings.Trim(m[4], "'")
		}
		at, err := time.Parse("2006-01-02 15:04:05-07", m[6])
		if err != nil {
			t.Fatalf("parse verified_at %q: %v", m[6], err)
		}
		rows = append(rows, seedRow{Label: m[1], Name: m[2], Platform: m[3], Signer: signer, Latest: m[5], VerifiedAt: at})
	}
	if len(rows) != 16 || rowLines != 16 {
		t.Fatalf("migration 0030 seed: parsed %d rows and found %d row lines, want exactly 16 of each; "+
			"the file's format may have changed, so this test would otherwise pass on nothing", len(rows), rowLines)
	}
	return rows
}

func (r seedRow) product() (identityKey, string) {
	switch {
	case r.Platform == "Windows":
		return identityKey{Platform: "windows", Kind: "windows_native", Value: strings.ToLower(r.Name)}, r.Name
	case r.Signer != "":
		return bundleTeamKey("com.example."+r.Label, r.Signer), r.Name
	default:
		return identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example." + r.Label}, r.Name
	}
}

// Every catalogue row is shown only against the product it describes. Each
// seed row is given a unique version, so a row resolving to any other row's
// product would surface another row's version.
func TestVersionSprawlEveryCatalogueRowResolvesOnlyToItsOwnProduct(t *testing.T) {
	now := time.Now().UTC()
	seed := loadSeedRows(t)

	entries := make([]catalogueEntry, 0, len(seed))
	unique := map[string]string{} // label -> distinct version
	for i, r := range seed {
		v := fmt.Sprintf("9.%d.0", i+1)
		unique[r.Label] = v
		entries = append(entries, catalogueEntry{Platform: r.Platform, Name: r.Name, VerifiedSigner: r.Signer, LatestVersion: v, VerifiedAt: now})
	}

	for _, r := range seed {
		k, name := r.product()
		row := buildWithCatalogue(now, k, name, entries, "0.0.1")
		if got := latestOf(t, row); got != unique[r.Label] {
			t.Errorf("catalogue row %q (%s, signer %q): its product resolved to %q, want its own %q",
				r.Label, r.Name, r.Signer, got, unique[r.Label])
		}

		if r.Signer == "" {
			continue
		}
		// The same name under a different signer, or with no signer evidence,
		// is not this row's product.
		other := buildWithCatalogue(now, bundleTeamKey("com.example.imposter."+r.Label, "ZZZZZZZZZZ"), r.Name, entries, "0.0.1")
		if got := latestOf(t, other); got != "" {
			t.Errorf("catalogue row %q: %q under another signer resolved to %q, want none", r.Label, r.Name, got)
		}
		unsigned := buildWithCatalogue(now, identityKey{Platform: "macos", Kind: "macos_bundle", Value: "com.example.unsigned." + r.Label}, r.Name, entries, "0.0.1")
		if got := latestOf(t, unsigned); got != "" {
			t.Errorf("catalogue row %q: %q with no signer evidence resolved to %q, want none", r.Label, r.Name, got)
		}
		// An unrelated product under this row's signer is nobody's reference.
		stranger := buildWithCatalogue(now, bundleTeamKey("com.example.stranger."+r.Label, r.Signer), "Unrelated Product Q", entries, "0.0.1")
		if got := latestOf(t, stranger); got != "" {
			t.Errorf("catalogue row %q: an unrelated product under signer %s resolved to %q, want none", r.Label, r.Signer, got)
		}
	}

	// A row is shown only against a product with exactly its name: a longer
	// display name that contains it, or a shorter one it contains, is a
	// different product. The row's own signer is not enough to change that.
	for _, r := range seed {
		k, name := r.product()
		longer := buildWithCatalogue(now, k, name+" classic", entries, "0.0.1")
		if got := latestOf(t, longer); got != "" {
			t.Errorf("catalogue row %q: %q resolved to %q, want none (not exactly %q)", r.Label, name+" classic", got, name)
		}
		if first := strings.Fields(name)[0]; first != name {
			shorter := buildWithCatalogue(now, k, first, entries, "0.0.1")
			if got := latestOf(t, shorter); got != "" {
				t.Errorf("catalogue row %q: %q resolved to %q, want none (not exactly %q)", r.Label, first, got, name)
			}
		}
		// Case and surrounding spaces do not make a different product.
		same := buildWithCatalogue(now, k, "  "+strings.ToUpper(name)+" ", entries, "0.0.1")
		if got := latestOf(t, same); got != unique[r.Label] {
			t.Errorf("catalogue row %q: %q resolved to %q, want its own %q", r.Label, strings.ToUpper(name), got, unique[r.Label])
		}
	}
}

// The frozen 2026-08-10 seed is not a reference in any month after it, even
// for a product it describes correctly.
func TestVersionSprawlFrozenSeedYieldsNothingOnItsOwn(t *testing.T) {
	seed := loadSeedRows(t)
	now := seed[0].VerifiedAt.Add(30 * 24 * time.Hour)
	entries := make([]catalogueEntry, 0, len(seed))
	for _, r := range seed {
		entries = append(entries, catalogueEntry{Platform: r.Platform, Name: r.Name, VerifiedSigner: r.Signer, LatestVersion: r.Latest, VerifiedAt: r.VerifiedAt})
	}
	for _, r := range seed {
		k, name := r.product()
		if got := latestOf(t, buildWithCatalogue(now, k, name, entries, "0.0.1")); got != "" {
			t.Errorf("seed row %q gave %q a month after it was verified, want none", r.Label, got)
		}
	}
}

// The production report: Chrome, Zoom and Excel, each with the stale figure
// the catalogue used to hand out.
func TestVersionSprawlProductionRegression(t *testing.T) {
	now := time.Now().UTC()
	seed := loadSeedRows(t)
	entries := make([]catalogueEntry, 0, len(seed))
	for _, r := range seed {
		entries = append(entries, catalogueEntry{Platform: r.Platform, Name: r.Name, VerifiedSigner: r.Signer, LatestVersion: r.Latest, VerifiedAt: r.VerifiedAt})
	}
	cases := []struct {
		name string
		key  identityKey
		live []string
	}{
		{"Google Chrome", bundleTeamKey("com.google.chrome", testGoogleTeamID), []string{"149.0.7000.1", "154.0.8037.58"}},
		{"zoom.us", bundleTeamKey("us.zoom.xos", testZoomTeamID), []string{"6.1.6.41824", "7.0.5.1"}},
		{"Microsoft Excel", bundleTeamKey("com.microsoft.excel", testMicrosoftTeamID), []string{"16.99.1"}},
	}
	for _, c := range cases {
		if got := latestOf(t, buildWithCatalogue(now, c.key, c.name, entries, c.live...)); got != "" {
			t.Errorf("%s: reference = %q, want none", c.name, got)
		}
	}
}
