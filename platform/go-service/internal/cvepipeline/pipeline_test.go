package cvepipeline

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"patched.im/api/internal/cvematch"
)

func TestChangedProductsDetectsNewChangedAndAuthorisedRemovals(t *testing.T) {
	before := AppVersions{
		"Google Chrome": {"120.0"},
		"Slack":         {"4.38"},
		"Zoom":          {"5.0"},
		"Two Versions":  {"1.0", "2.0"},
	}
	after := AppVersions{
		"Google Chrome": {"121.0"},      // version changed
		"Slack":         {"4.38"},       // unchanged
		"Firefox":       {"130.0"},      // new
		"Two Versions":  {"2.0", "1.0"}, // same set, different order
	}
	got := ChangedProducts(before, after, true)
	want := []string{"Firefox", "Google Chrome", "Zoom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with removals: got %v, want %v", got, want)
	}
	// A payload with no apps array is not evidence of removal.
	got = ChangedProducts(before, after, false)
	want = []string{"Firefox", "Google Chrome"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("without removal authority: got %v, want %v", got, want)
	}
	if got := ChangedProducts(after, after, true); len(got) != 0 {
		t.Fatalf("identical snapshots must yield nothing to re-match, got %v", got)
	}
}

func TestFilterMappedDropsUnmappedProducts(t *testing.T) {
	mappings := []cvematch.CPEMapping{{MatchName: "Google Chrome", CPEVendor: "google", CPEProduct: "chrome"}}
	got := FilterMapped([]string{"Google Chrome", "Chrome Helper Thing", "In-House Tool"}, mappings)
	if !reflect.DeepEqual(got, []string{"Google Chrome"}) {
		t.Fatalf("got %v", got)
	}
}

func TestMappingChangesCoversPublishChangeAndRemoval(t *testing.T) {
	snap := map[int64]snapshotMapping{
		1: {ID: 1, MatchName: "Alpha", CPEVendor: "a", CPEProduct: "alpha"},
		2: {ID: 2, MatchName: "Bravo", CPEVendor: "b", CPEProduct: "bravo"},
		3: {ID: 3, MatchName: "Charlie", CPEVendor: "c", CPEProduct: "charlie"},
	}
	live := map[int64]snapshotMapping{
		1: {ID: 1, MatchName: "Alpha", CPEVendor: "a", CPEProduct: "alpha"},         // unchanged
		2: {ID: 2, MatchName: "Bravo Renamed", CPEVendor: "b", CPEProduct: "bravo"}, // changed
		4: {ID: 4, MatchName: "Delta", CPEVendor: "d", CPEProduct: "delta"},         // published
		// 3 removed
	}
	got := mappingChanges(live, snap)
	want := []mappingTarget{{"app_name", "Bravo"}, {"app_name", "Bravo Renamed"}, {"app_name", "Charlie"}, {"app_name", "Delta"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := mappingChanges(snap, snap); len(got) != 0 {
		t.Fatalf("no change must queue nothing, got %v", got)
	}
}

// PAT-2045: Homebrew mappings are diffed alongside application mappings and
// keep their matcher, including on removal and on a review-state change.
func TestMappingChangesRoutesHomebrewMappingsToTheirMatcher(t *testing.T) {
	curated := func(id int64, source, name string) snapshotMapping {
		return snapshotMapping{ID: id, MatchName: name, CPEVendor: "v", CPEProduct: "p",
			SourceType: source, ReviewState: "curated"}
	}
	snap := map[int64]snapshotMapping{
		1: curated(1, "app_name", "Openssl"),
		2: curated(2, "homebrew_formula", "curl"),         // removed
		3: curated(3, "homebrew_cask", "Firefox"),         // demoted below
		4: curated(4, "homebrew_formula", "unchanged-fm"), // unchanged
	}
	demoted := snap[3]
	demoted.ReviewState = "auto_seeded"
	live := map[int64]snapshotMapping{
		1: snap[1],
		3: demoted,
		4: snap[4],
		5: curated(5, "homebrew_formula", " OpenSSL@3 "), // published
	}
	got := mappingChanges(live, snap)
	want := []mappingTarget{
		{"homebrew_cask", "firefox"},
		{"homebrew_formula", "curl"},
		{"homebrew_formula", "openssl@3"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Rows seeded by 0161, before the snapshot had a source type, read as
	// application mappings.
	legacy := map[int64]snapshotMapping{9: {ID: 9, MatchName: "Legacy App", CPEVendor: "l", CPEProduct: "app"}}
	if got := mappingChanges(map[int64]snapshotMapping{}, legacy); !reflect.DeepEqual(got, []mappingTarget{{"app_name", "Legacy App"}}) {
		t.Fatalf("legacy removal routed to %v", got)
	}
}

func TestHomebrewKeyForSource(t *testing.T) {
	cases := []struct {
		source, name string
		want         homebrewKey
		ok           bool
	}{
		{"homebrew_formula", " OpenSSL@3 ", homebrewKey{"formula", "openssl@3"}, true},
		{"homebrew_cask", "Firefox", homebrewKey{"cask", "firefox"}, true},
		{"app_name", "Firefox", homebrewKey{}, false},
		{"homebrew_formula", "  ", homebrewKey{}, false},
	}
	for _, c := range cases {
		got, ok := homebrewKeyForSource(c.source, c.name)
		if got != c.want || ok != c.ok {
			t.Fatalf("homebrewKeyForSource(%q, %q) = %v, %v; want %v, %v", c.source, c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestFeedDeltaKeysOnlyMatchRelevantChanges(t *testing.T) {
	score := 7.5
	higher := 9.8
	prior := map[string]FeedMatchState{
		"CVE-UNCHANGED": {Patterns: []string{"acme:widget"}, Score: &score, Severity: "HIGH",
			Ranges: []cvematch.CPERange{{Vendor: "acme", Product: "widget", VEndExcl: "2.0"}}},
		"CVE-RESCORED": {Patterns: []string{"acme:gadget"}, Score: &score, Severity: "HIGH"},
		"CVE-MOVED":    {Patterns: []string{"acme:old"}, Score: &score, Severity: "HIGH"},
		"CVE-RANGE": {Patterns: []string{"acme:ranged"}, Score: &score, Severity: "HIGH",
			Ranges: []cvematch.CPERange{{Vendor: "acme", Product: "ranged", VEndExcl: "2.0"}}},
	}
	next := map[string]FeedMatchState{
		"CVE-UNCHANGED": prior["CVE-UNCHANGED"],
		"CVE-RESCORED":  {Patterns: []string{"acme:gadget"}, Score: &higher, Severity: "CRITICAL"},
		"CVE-MOVED":     {Patterns: []string{"acme:new"}, Score: &score, Severity: "HIGH"},
		"CVE-RANGE": {Patterns: []string{"acme:ranged"}, Score: &score, Severity: "HIGH",
			Ranges: []cvematch.CPERange{{Vendor: "acme", Product: "ranged", VEndExcl: "3.0"}}},
		"CVE-NEW": {Patterns: []string{"acme:fresh"}},
	}
	got := FeedDeltaKeys(prior, next)
	want := []string{"acme:fresh", "acme:gadget", "acme:new", "acme:old", "acme:ranged"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// The ranges read back from JSONB and the ranges built from an NVD page must
// compare equal, or every sync would mark every CVE changed and the delta
// would degenerate into a full match.
func TestFeedDeltaKeysRangesSurviveJSONRoundTrip(t *testing.T) {
	ranges := []cvematch.CPERange{{Vendor: "acme", Product: "widget", VStartIncl: "1.0", VEndExcl: "2.0"}}
	raw, err := json.Marshal(ranges)
	if err != nil {
		t.Fatal(err)
	}
	var back []cvematch.CPERange
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	prior := map[string]FeedMatchState{"CVE-1": {Patterns: []string{"acme:widget"}, Ranges: back}}
	next := map[string]FeedMatchState{"CVE-1": {Patterns: []string{"acme:widget"}, Ranges: ranges}}
	if got := FeedDeltaKeys(prior, next); len(got) != 0 {
		t.Fatalf("round-tripped identical ranges read as changed: %v", got)
	}
}

func TestClassifyProductNeverReportsUnmappedAsZeroFindings(t *testing.T) {
	at := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	// Even with a stale assessment row and zero findings on record, an
	// unmapped product has no CVE statement.
	p := classifyProduct("In-House Tool", []string{"1.0"}, false, false,
		&assessmentRow{Versions: []string{"1.0"}, LastMatchedAt: at}, 0)
	if p.State != StateNotAssessed {
		t.Fatalf("state = %q, want not_assessed", p.State)
	}
	if p.FindingCount != nil || p.LastMatchedAt != nil {
		t.Fatalf("not_assessed must carry null finding_count and last_matched_at, got %v / %v", p.FindingCount, p.LastMatchedAt)
	}
	raw, _ := json.Marshal(p)
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	if v, ok := decoded["finding_count"]; !ok || v != nil {
		t.Fatalf("finding_count must serialise as null for not_assessed, got %s", raw)
	}
}

func TestClassifyProductPendingAndAssessed(t *testing.T) {
	at := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	row := &assessmentRow{Versions: []string{"2.0"}, LastMatchedAt: at}
	cases := []struct {
		name     string
		versions []string
		queued   bool
		row      *assessmentRow
		want     string
	}{
		{"queued", []string{"2.0"}, true, row, StatePending},
		{"never matched", []string{"2.0"}, false, nil, StatePending},
		{"version changed since match", []string{"2.1"}, false, row, StatePending},
		{"matched current versions", []string{"2.0"}, false, row, StateAssessed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := classifyProduct("Widget", tc.versions, true, tc.queued, tc.row, 0)
			if p.State != tc.want {
				t.Fatalf("state = %q, want %q", p.State, tc.want)
			}
			if tc.want == StatePending && p.FindingCount != nil {
				t.Fatalf("pending must not carry a finding count, got %d", *p.FindingCount)
			}
			if tc.want == StateAssessed && (p.FindingCount == nil || *p.FindingCount != 0 || p.LastMatchedAt == nil) {
				t.Fatalf("assessed with zero findings must say 0 and carry last_matched_at, got %+v", p)
			}
		})
	}
}

func TestRollUpDevice(t *testing.T) {
	early := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	two, zero := 2, 0
	assessedA := ProductAssessment{App: "A", State: StateAssessed, LastMatchedAt: &late, FindingCount: &two}
	assessedB := ProductAssessment{App: "B", State: StateAssessed, LastMatchedAt: &early, FindingCount: &zero}
	pending := ProductAssessment{App: "C", State: StatePending}
	unmapped := ProductAssessment{App: "D", State: StateNotAssessed}

	d := rollUpDevice([]ProductAssessment{assessedA, assessedB, unmapped})
	if d.State != StateAssessed || d.FindingCount == nil || *d.FindingCount != 2 {
		t.Fatalf("assessed device: %+v", d)
	}
	if !d.LastMatchedAt.Equal(early) {
		t.Fatalf("device last_matched_at must be the oldest assessed product's, got %v", d.LastMatchedAt)
	}
	if d.NotAssessedProducts != 1 || d.AssessedProducts != 2 {
		t.Fatalf("coverage counts wrong: %+v", d)
	}

	d = rollUpDevice([]ProductAssessment{assessedA, pending})
	if d.State != StatePending || d.FindingCount != nil || d.LastMatchedAt != nil {
		t.Fatalf("pending device must carry no count or time: %+v", d)
	}

	d = rollUpDevice([]ProductAssessment{unmapped})
	if d.State != StateNotAssessed || d.FindingCount != nil {
		t.Fatalf("device with only unmapped products must be not_assessed with null count: %+v", d)
	}
	d = rollUpDevice(nil)
	if d.State != StateNotAssessed || d.FindingCount != nil {
		t.Fatalf("device with no products must be not_assessed with null count: %+v", d)
	}
}

// A failed feed load must cache nothing: the next device in the same batch
// has to retry the load and fail too, never see an empty entry list that
// reads as "no CVEs" and prunes its findings.
func TestFeedCacheFailedLoadCachesNothing(t *testing.T) {
	calls := 0
	c := newFeedCache()
	c.load = func(_ context.Context, _ DB, keys []string) (map[string][]cvematch.CVEEntry, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("injected feed load failure")
		}
		return map[string][]cvematch.CVEEntry{"acme:widget": {{CVEID: "CVE-2099-0001", Patterns: []string{"acme:widget"}}}}, nil
	}
	if _, err := c.entries(context.Background(), nil, []string{"acme:widget"}); err == nil {
		t.Fatal("first load must surface the injected error")
	}
	got, err := c.entries(context.Background(), nil, []string{"acme:widget"})
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if calls != 2 {
		t.Fatalf("second device reused the failed load from cache (loads=%d, want 2)", calls)
	}
	if len(got) != 1 {
		t.Fatalf("second device got %d entries, want 1", len(got))
	}
}

func TestOSPseudoAppsNeverQueuedOrMatched(t *testing.T) {
	if got := withoutOSPseudoApps([]string{"Google Chrome", "macOS", "Windows"}); !reflect.DeepEqual(got, []string{"Google Chrome"}) {
		t.Fatalf("withoutOSPseudoApps = %v", got)
	}
	mappings := []cvematch.CPEMapping{{MatchName: "macOS", CPEVendor: "apple", CPEProduct: "macos"}}
	if got := FilterMapped([]string{"macOS"}, mappings); len(got) != 0 {
		t.Fatalf("OS pseudo-app queued: %v", got)
	}
}
