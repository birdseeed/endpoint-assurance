package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ptrFloat(f float64) *float64    { return &f }
func ptrTime(t time.Time) *time.Time { return &t }

func TestCVEDescriptionWithSource(t *testing.T) {
	for _, tc := range []struct {
		description string
		source      string
		want        string
	}{
		{"CVE text", "nvd", "NVD: CVE text"},
		{"Vendor title", "msrc", "MSRC: Vendor title"},
		{"Vendor title", "apple", "Apple: Vendor title"},
		{"", "", ""},
		{"legacy text", "", "legacy text"},
	} {
		if got := cveDescriptionWithSource(tc.description, tc.source); got != tc.want {
			t.Errorf("cveDescriptionWithSource(%q, %q) = %q, want %q", tc.description, tc.source, got, tc.want)
		}
	}
}

// fixtureFreeCVEReport builds a FreeCVEReport by hand covering all four
// severity bands and both confidence levels. Used for renderer smoke tests
// and count-computation tests without DB access.
func fixtureFreeCVEReport() FreeCVEReport {
	pub := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		Tenant:        "Acme Corp",
		CVEs: []CVERecord{
			{
				CVEID:       "CVE-2024-0001",
				Description: "A critical heap buffer overflow in Example Browser allows remote code execution",
				CVSSScore:   ptrFloat(9.8),
				Severity:    "CRITICAL",
				PublishedAt: ptrTime(pub),
				Hits: []CVEHit{
					{Hostname: "alice-mbp", AppName: "Example Browser", AppVersion: "120.0.1", MatchConfidence: "version_confirmed"},
					{Hostname: "bob-mbp", AppName: "Example Browser", AppVersion: "119.0.0", MatchConfidence: "version_confirmed"},
				},
			},
			{
				CVEID:       "CVE-2024-0002",
				Description: "Memory corruption in Example Player via malformed media file",
				CVSSScore:   ptrFloat(7.5),
				Severity:    "HIGH",
				PublishedAt: ptrTime(pub),
				Hits: []CVEHit{
					{Hostname: "alice-mbp", AppName: "Example Player", AppVersion: "4.2.1", MatchConfidence: "version_unverified"},
				},
			},
			{
				CVEID:       "CVE-2024-0003",
				Description: "Privilege escalation in Example SDK via crafted input",
				CVSSScore:   ptrFloat(6.1),
				Severity:    "MEDIUM",
				PublishedAt: ptrTime(pub),
				Hits: []CVEHit{
					{Hostname: "carol-mbp", AppName: "Example SDK", AppVersion: "2.0.0", MatchConfidence: "version_unverified"},
				},
			},
			{
				CVEID:       "CVE-2024-0004",
				Description: "Information disclosure in Example Util",
				CVSSScore:   ptrFloat(3.3),
				Severity:    "LOW",
				PublishedAt: ptrTime(pub),
				Hits: []CVEHit{
					{Hostname: "carol-mbp", AppName: "Example Util", AppVersion: "1.0.0", MatchConfidence: "version_confirmed"},
				},
			},
		},
	}
	FillFreeCVECounts(&r)
	return r
}

// TestFillFreeCVECounts verifies that fillFreeCVECounts computes all summary
// fields correctly from a known fixture.
func TestFillFreeCVECounts(t *testing.T) {
	r := fixtureFreeCVEReport()

	if r.TotalCVEs != 4 {
		t.Errorf("TotalCVEs = %d, want 4", r.TotalCVEs)
	}
	if r.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", r.CriticalCount)
	}
	if r.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", r.HighCount)
	}
	if r.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", r.MediumCount)
	}
	if r.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", r.LowCount)
	}
	// 2 confirmed (CVE-0001 × 2 hits) + 1 confirmed (CVE-0004) = 3 confirmed
	if r.ConfirmedHits != 3 {
		t.Errorf("ConfirmedHits = %d, want 3", r.ConfirmedHits)
	}
	// 1 unverified (CVE-0002) + 1 unverified (CVE-0003) = 2
	if r.UnverifiedHits != 2 {
		t.Errorf("UnverifiedHits = %d, want 2", r.UnverifiedHits)
	}
}

// TestFillFreeCVECounts_Empty ensures fillFreeCVECounts doesn't panic on an
// empty report and leaves all counts at zero.
func TestFillFreeCVECounts_Empty(t *testing.T) {
	r := FreeCVEReport{}
	FillFreeCVECounts(&r)

	if r.TotalCVEs != 0 || r.CriticalCount != 0 || r.HighCount != 0 ||
		r.MediumCount != 0 || r.LowCount != 0 ||
		r.ConfirmedHits != 0 || r.UnverifiedHits != 0 {
		t.Error("expected all counts to be 0 for empty report")
	}
}

// TestSortCVERecords verifies that SortCVERecords produces the canonical
// severity-band ordering (CRITICAL→HIGH→MEDIUM→LOW) with CVE ID tiebreak.
func TestSortCVERecords(t *testing.T) {
	cvs := []CVERecord{
		{CVEID: "CVE-2024-0003", Severity: "MEDIUM"},
		{CVEID: "CVE-2024-0001", Severity: "CRITICAL"},
		{CVEID: "CVE-2024-0005", Severity: "LOW"},
		{CVEID: "CVE-2024-0002", Severity: "CRITICAL"},
		{CVEID: "CVE-2024-0004", Severity: "HIGH"},
	}
	SortCVERecords(cvs)

	want := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0004", "CVE-2024-0003", "CVE-2024-0005"}
	for i, cve := range cvs {
		if cve.CVEID != want[i] {
			t.Errorf("position %d: got %s, want %s", i, cve.CVEID, want[i])
		}
	}
}

// TestFreeCVEFormatVersion asserts the PAT-1871 provenance contract bump and
// that fixtureFreeCVEReport carries it correctly.
func TestFreeCVEFormatVersion(t *testing.T) {
	if FreeCVEFormatVersion != "v2.2" {
		t.Fatalf("FreeCVEFormatVersion = %q, want %q", FreeCVEFormatVersion, "v2.2")
	}
	r := fixtureFreeCVEReport()
	if r.FormatVersion != FreeCVEFormatVersion {
		t.Errorf("report FormatVersion = %q, want %q", r.FormatVersion, FreeCVEFormatVersion)
	}
}

// TestTierStatusDefaults asserts the production defaults: all three tiers are
// live from day one (PAT-443 — Andy declared all tiers available).
func TestTierStatusDefaults(t *testing.T) {
	if TierStatuses.Report != TierStatusAvailable {
		t.Errorf("TierStatuses.Report = %q, want %q", TierStatuses.Report, TierStatusAvailable)
	}
	if TierStatuses.PatchAndDeploy != TierStatusAvailable {
		t.Errorf("TierStatuses.PatchAndDeploy = %q, want %q", TierStatuses.PatchAndDeploy, TierStatusAvailable)
	}
	if TierStatuses.FullEndpointManagement != TierStatusAvailable {
		t.Errorf("TierStatuses.FullEndpointManagement = %q, want %q", TierStatuses.FullEndpointManagement, TierStatusAvailable)
	}
}

// TestCVEClosingRungs asserts that cveClosingRungs returns three rungs with statuses from TierStatuses.
func TestCVEClosingRungs(t *testing.T) {
	rungs := cveClosingRungs()
	if len(rungs) != 3 {
		t.Fatalf("cveClosingRungs: got %d rungs, want 3", len(rungs))
	}
	if rungs[0].Status != TierStatuses.Report {
		t.Errorf("rung[0] status = %q, want %q", rungs[0].Status, TierStatuses.Report)
	}
	if rungs[1].Status != TierStatuses.PatchAndDeploy {
		t.Errorf("rung[1] status = %q, want %q", rungs[1].Status, TierStatuses.PatchAndDeploy)
	}
	if rungs[2].Status != TierStatuses.FullEndpointManagement {
		t.Errorf("rung[2] status = %q, want %q", rungs[2].Status, TierStatuses.FullEndpointManagement)
	}
}

// TestTierStatusOverride asserts that overriding a TierStatuses field changes the badge returned by cveClosingRungs.
func TestTierStatusOverride(t *testing.T) {
	saved := TierStatuses.PatchAndDeploy
	TierStatuses.PatchAndDeploy = TierStatusAvailable
	defer func() { TierStatuses.PatchAndDeploy = saved }()

	rungs := cveClosingRungs()
	if rungs[1].Status != TierStatusAvailable {
		t.Errorf("after override, rung[1] status = %q, want %q", rungs[1].Status, TierStatusAvailable)
	}
}

// TestCVECTAURL asserts the CTA URL constant matches the canonical booking link.
func TestCVECTAURL(t *testing.T) {
	if CVEReportCTAURL != "https://patched.im/#book" {
		t.Errorf("CVEReportCTAURL = %q, want %q", CVEReportCTAURL, "https://patched.im/#book")
	}
}

// TestRenderFreeCVEPDF_ClosingPage asserts that the closing page renders without error
// and that the PDF is larger than a 2-page output (confirming the page was added).
func TestRenderFreeCVEPDF_ClosingPage(t *testing.T) {
	r := fixtureFreeCVEReport()
	pdf, err := RenderFreeCVEPDF(r)
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF error: %v", err)
	}
	// 3-page output (exec + technical + closing) should be well above 8 KB.
	if len(pdf) < 8000 {
		t.Errorf("PDF too small for 3-page output: %d bytes", len(pdf))
	}
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Errorf("output does not start with %%PDF- header")
	}
}

// TestRenderFreeCVEPDF_Smoke verifies that RenderFreeCVEPDF returns a valid
// PDF byte slice from the standard fixture covering all four severity bands.
func TestRenderFreeCVEPDF_Smoke(t *testing.T) {
	r := fixtureFreeCVEReport()
	pdf, err := RenderFreeCVEPDF(r)
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF error: %v", err)
	}
	if len(pdf) < 2000 {
		t.Errorf("PDF too small: %d bytes", len(pdf))
	}
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Errorf("output does not start with %%PDF- header")
	}
}

// TestRenderFreeCVEPDF_Empty verifies that RenderFreeCVEPDF handles a report
// with no CVEs without error, rendering the "no findings" path.
func TestRenderFreeCVEPDF_Empty(t *testing.T) {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "Empty Tenant",
	}
	FillFreeCVECounts(&r)
	pdf, err := RenderFreeCVEPDF(r)
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF (empty) error: %v", err)
	}
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Errorf("empty-report PDF does not start with %%PDF- header")
	}
}

// TestRenderFreeCVEPDF_NilCVSS verifies that a CVE with a nil CVSS score
// (NVD sometimes omits scoring) renders without panic.
func TestRenderFreeCVEPDF_NilCVSS(t *testing.T) {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "Test Co",
		CVEs: []CVERecord{
			{
				CVEID:       "CVE-2024-9999",
				Description: "Unscored vulnerability with no CVSS data",
				CVSSScore:   nil,
				Severity:    "HIGH",
				Hits: []CVEHit{
					{Hostname: "device-1", AppName: "SomeApp", AppVersion: "1.0", MatchConfidence: "version_unverified"},
				},
			},
		},
	}
	FillFreeCVECounts(&r)
	_, err := RenderFreeCVEPDF(r)
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF (nil CVSS) error: %v", err)
	}
}

// ─── BuildCVEActions (PAT-1205) ────────────────────────────────────────────────

// hit builds a confirmed CVEHit with the given fixed version.
func hit(hostname, appVersion, fixedVersion string) CVEHit {
	return CVEHit{
		Hostname:        hostname,
		AppName:         "", // filled in by cveWithHits
		AppVersion:      appVersion,
		MatchConfidence: "version_confirmed",
		FixedVersion:    fixedVersion,
	}
}

// unverifiedHit builds an unverified CVEHit (no FixedVersion — Match never
// populates one for version_unverified findings).
func unverifiedHit(hostname, appVersion string) CVEHit {
	return CVEHit{
		Hostname:        hostname,
		AppVersion:      appVersion,
		MatchConfidence: "version_unverified",
	}
}

// cveWithHits builds a CVERecord for the given app, stamping AppName onto
// every hit.
func cveWithHits(cveID, severity string, cvss *float64, appName string, hits ...CVEHit) CVERecord {
	out := make([]CVEHit, len(hits))
	for i, h := range hits {
		h.AppName = appName
		out[i] = h
	}
	return CVERecord{
		CVEID:     cveID,
		Severity:  severity,
		CVSSScore: cvss,
		Hits:      out,
	}
}

// buildActionsOrderingFixture returns a FreeCVEReport deliberately
// constructed so that every level of BuildCVEActions' ordering tiebreak
// (CriticalCount desc, HighCount desc, total CVE count desc, device count
// desc, AppName asc) is exercised and distinguishable. CVEs are listed out
// of the order the resulting actions should land in, so the test can't pass
// by accident of input ordering.
func buildActionsOrderingFixture() FreeCVEReport {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "Ordering Co",
		CVEs: []CVERecord{
			// Alpha / Zulu: tie on everything except AppName (0 critical, 0 high, 1 CVE, 1 device).
			cveWithHits("CVE-2024-1006", "MEDIUM", nil, "Zulu", hit("host1", "1.0", "")),
			cveWithHits("CVE-2024-1007", "MEDIUM", nil, "Alpha", hit("host1", "1.0", "")),
			// AppFive: 0 critical, 1 high, 1 CVE, 1 device.
			cveWithHits("CVE-2024-1005", "HIGH", nil, "AppFive", hit("host1", "1.0", "")),
			// AppFour: 0 critical, 2 high, 2 CVEs, 3 devices.
			cveWithHits("CVE-2024-1003", "HIGH", nil, "AppFour", hit("host1", "1.0", ""), hit("host2", "1.0", "")),
			cveWithHits("CVE-2024-1004", "HIGH", nil, "AppFour", hit("host3", "1.0", "")),
			// AppThree: 1 critical, 0 high, 1 CVE, 1 device.
			cveWithHits("CVE-2024-1002", "CRITICAL", nil, "AppThree", hit("host1", "1.0", "")),
			// AppOne: 2 critical, 0 high, 2 CVEs, 3 devices.
			cveWithHits("CVE-2024-1000", "CRITICAL", nil, "AppOne", hit("host1", "1.0", ""), hit("host2", "1.0", "")),
			cveWithHits("CVE-2024-1001", "CRITICAL", nil, "AppOne", hit("host3", "1.0", "")),
			// AppTwo: 2 critical, 0 high, 2 CVEs, 4 devices — beats AppOne on device count.
			cveWithHits("CVE-2024-1008", "CRITICAL", nil, "AppTwo",
				hit("host1", "1.0", ""), hit("host2", "1.0", ""), hit("host3", "1.0", ""), hit("host4", "1.0", "")),
			cveWithHits("CVE-2024-1009", "CRITICAL", nil, "AppTwo", hit("host1", "1.0", "")),
		},
	}
	FillFreeCVECounts(&r)
	return r
}

// TestBuildCVEActions_Ordering asserts the full five-level tiebreak order:
// CriticalCount desc, HighCount desc, total CVE count desc, device count
// desc, AppName asc.
func TestBuildCVEActions_Ordering(t *testing.T) {
	actions, _ := BuildCVEActions(buildActionsOrderingFixture())

	want := []string{"AppTwo", "AppOne", "AppThree", "AppFour", "AppFive", "Alpha", "Zulu"}
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(want), actionNames(actions))
	}
	for i, name := range want {
		if actions[i].AppName != name {
			t.Errorf("position %d: got %q, want %q (full order: %v)", i, actions[i].AppName, name, actionNames(actions))
		}
	}

	// Spot-check the metrics driving the AppTwo-over-AppOne device-count tiebreak.
	if actions[0].AppName == "AppTwo" {
		if got := len(actions[0].Devices); got != 4 {
			t.Errorf("AppTwo device count = %d, want 4", got)
		}
	}
	if actions[1].AppName == "AppOne" {
		if got := len(actions[1].Devices); got != 3 {
			t.Errorf("AppOne device count = %d, want 3", got)
		}
	}
}

func actionNames(actions []CVEAction) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = a.AppName
	}
	return out
}

// TestBuildCVEActions_TargetVersionFold asserts TargetVersion folds to the
// maximum FixedVersion (via cvematch.CompareVersions) across every confirmed
// hit under the action's CVEs.
func TestBuildCVEActions_TargetVersionFold(t *testing.T) {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "Fold Co",
		CVEs: []CVERecord{
			cveWithHits("CVE-2024-2000", "HIGH", nil, "FoldApp",
				hit("host1", "2.0.0", "2.1.0"), hit("host2", "2.0.0", "2.3.0")),
			cveWithHits("CVE-2024-2001", "MEDIUM", nil, "FoldApp",
				hit("host3", "2.0.0", "2.2.5")),
		},
	}
	FillFreeCVECounts(&r)
	actions, _ := BuildCVEActions(r)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d: %v", len(actions), actionNames(actions))
	}
	if actions[0].TargetVersion != "2.3.0" {
		t.Errorf("TargetVersion = %q, want %q", actions[0].TargetVersion, "2.3.0")
	}
}

// TestBuildCVEActions_TargetVersionEmptyFallback asserts TargetVersion is ""
// when no hit in the group carries a known FixedVersion (e.g. every matched
// range was open-ended).
func TestBuildCVEActions_TargetVersionEmptyFallback(t *testing.T) {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "NoFix Co",
		CVEs: []CVERecord{
			cveWithHits("CVE-2024-3000", "HIGH", nil, "NoFixApp", hit("host1", "1.0", "")),
		},
	}
	FillFreeCVECounts(&r)
	actions, _ := BuildCVEActions(r)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].TargetVersion != "" {
		t.Errorf("TargetVersion = %q, want empty", actions[0].TargetVersion)
	}
}

// TestBuildCVEActions_ConfirmedUnverifiedSplit asserts that a report mixing
// confidence levels for the same app produces both a CVEAction (confirmed
// hits only) and a CVEUnverifiedGroup (unverified hits only), and that a CVE
// with both confirmed and unverified hits for the app is split across the
// two rather than duplicated whole.
func TestBuildCVEActions_ConfirmedUnverifiedSplit(t *testing.T) {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "Mix Co",
		CVEs: []CVERecord{
			// CVE-Z1: confirmed on host1, unverified on host2 — same CVE, split by hit.
			cveWithHits("CVE-2024-4000", "HIGH", nil, "MixApp",
				hit("host1", "1.0", "1.5"), unverifiedHit("host2", "1.0")),
			// CVE-Z2: purely unverified.
			cveWithHits("CVE-2024-4001", "MEDIUM", nil, "MixApp", unverifiedHit("host3", "1.0")),
		},
	}
	FillFreeCVECounts(&r)
	actions, unverified := BuildCVEActions(r)

	if len(actions) != 1 || actions[0].AppName != "MixApp" {
		t.Fatalf("expected 1 action for MixApp, got %v", actionNames(actions))
	}
	if len(actions[0].CVEs) != 1 || actions[0].CVEs[0].CVEID != "CVE-2024-4000" {
		t.Fatalf("expected action to carry only CVE-2024-4000, got %v", actions[0].CVEs)
	}
	if len(actions[0].CVEs[0].Hits) != 1 || actions[0].CVEs[0].Hits[0].Hostname != "host1" {
		t.Errorf("expected action's CVE-2024-4000 to carry only the host1 confirmed hit, got %v", actions[0].CVEs[0].Hits)
	}

	if len(unverified) != 1 || unverified[0].AppName != "MixApp" {
		t.Fatalf("expected 1 unverified group for MixApp, got %v", unverified)
	}
	if len(unverified[0].CVEs) != 2 {
		t.Fatalf("expected unverified group to carry both CVEs (split hit + pure), got %v", unverified[0].CVEs)
	}
	for _, cve := range unverified[0].CVEs {
		if cve.CVEID == "CVE-2024-4000" {
			if len(cve.Hits) != 1 || cve.Hits[0].Hostname != "host2" {
				t.Errorf("expected unverified CVE-2024-4000 to carry only the host2 hit, got %v", cve.Hits)
			}
		}
	}
}

// TestBuildCVEActions_CVEAcrossTwoApps asserts a CVE with hits against two
// different app names appears in both apps' resulting actions.
func TestBuildCVEActions_CVEAcrossTwoApps(t *testing.T) {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Tenant:        "CrossApp Co",
		CVEs: []CVERecord{
			{
				CVEID:    "CVE-2024-5000",
				Severity: "HIGH",
				Hits: []CVEHit{
					{Hostname: "host1", AppName: "AppP", AppVersion: "1.0", MatchConfidence: "version_confirmed"},
					{Hostname: "host2", AppName: "AppQ", AppVersion: "2.0", MatchConfidence: "version_confirmed"},
				},
			},
		},
	}
	FillFreeCVECounts(&r)
	actions, _ := BuildCVEActions(r)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d: %v", len(actions), actionNames(actions))
	}
	for _, a := range actions {
		if len(a.CVEs) != 1 || a.CVEs[0].CVEID != "CVE-2024-5000" {
			t.Errorf("action %q: expected exactly CVE-2024-5000, got %v", a.AppName, a.CVEs)
		}
	}
}

// TestBuildCVEActions_Determinism guards against any remaining raw map
// iteration reaching the output: calling BuildCVEActions twice on freshly
// constructed (not reused) but identical input must produce deeply equal
// results.
func TestBuildCVEActions_Determinism(t *testing.T) {
	actions1, unverified1 := BuildCVEActions(buildActionsOrderingFixture())
	actions2, unverified2 := BuildCVEActions(buildActionsOrderingFixture())

	if !reflect.DeepEqual(actions1, actions2) {
		t.Errorf("actions differ between runs:\n1: %+v\n2: %+v", actions1, actions2)
	}
	if !reflect.DeepEqual(unverified1, unverified2) {
		t.Errorf("unverified groups differ between runs:\n1: %+v\n2: %+v", unverified1, unverified2)
	}

	// Also exercise a fixture that produces both confirmed and unverified
	// output so the unverified path is covered by the determinism check too.
	mixFixture := func() FreeCVEReport {
		r := FreeCVEReport{
			FormatVersion: FreeCVEFormatVersion,
			GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			Tenant:        "Mix Determinism Co",
			CVEs: []CVERecord{
				cveWithHits("CVE-2024-6000", "HIGH", ptrFloat(7.5), "MixApp",
					hit("host1", "1.0", "1.5"), unverifiedHit("host2", "1.0")),
				cveWithHits("CVE-2024-6001", "MEDIUM", nil, "OtherApp", unverifiedHit("host3", "1.0")),
			},
		}
		FillFreeCVECounts(&r)
		return r
	}
	actions3, unverified3 := BuildCVEActions(mixFixture())
	actions4, unverified4 := BuildCVEActions(mixFixture())
	if !reflect.DeepEqual(actions3, actions4) {
		t.Errorf("mix actions differ between runs:\n3: %+v\n4: %+v", actions3, actions4)
	}
	if !reflect.DeepEqual(unverified3, unverified4) {
		t.Errorf("mix unverified groups differ between runs:\n3: %+v\n4: %+v", unverified3, unverified4)
	}
}

// TestBuildCVEActions_DevicesDeterministicAcrossManyCVEs guards against
// cveAppBucket.devices() picking a hostname's InstalledVersion by iterating
// the byCVE map directly (Go map iteration order is randomised per process,
// not just theoretically) rather than a value derived from a sorted
// sequence. The same physical app install should report one AppVersion
// across every CVE row that names it, so this asserts BuildCVEActions
// returns byte-identical (via reflect.DeepEqual) results across repeated
// runs even with several CVEs — several map buckets — hitting the same host.
func TestBuildCVEActions_DevicesDeterministicAcrossManyCVEs(t *testing.T) {
	fixture := func() FreeCVEReport {
		r := FreeCVEReport{
			FormatVersion: FreeCVEFormatVersion,
			GeneratedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			Tenant:        "Many-CVE Determinism Co",
			CVEs: []CVERecord{
				cveWithHits("CVE-2024-7001", "CRITICAL", ptrFloat(9.8), "SharedApp",
					hit("host-a", "1.0", "2.0"), hit("host-b", "1.0", "2.0")),
				cveWithHits("CVE-2024-7002", "HIGH", ptrFloat(8.1), "SharedApp",
					hit("host-a", "1.0", "2.1"), hit("host-b", "1.0", "2.1")),
				cveWithHits("CVE-2024-7003", "HIGH", ptrFloat(7.9), "SharedApp",
					hit("host-a", "1.0", "1.9"), hit("host-b", "1.0", "1.9")),
				cveWithHits("CVE-2024-7004", "MEDIUM", ptrFloat(5.5), "SharedApp",
					hit("host-a", "1.0", "2.0"), hit("host-b", "1.0", "2.0")),
				cveWithHits("CVE-2024-7005", "MEDIUM", ptrFloat(5.0), "SharedApp",
					hit("host-a", "1.0", "2.0"), hit("host-b", "1.0", "2.0")),
			},
		}
		FillFreeCVECounts(&r)
		return r
	}

	var first []CVEAction
	for i := 0; i < 20; i++ {
		actions, _ := BuildCVEActions(fixture())
		if i == 0 {
			first = actions
			continue
		}
		if !reflect.DeepEqual(first, actions) {
			t.Fatalf("run %d: actions differ from run 0 (devices() is not deterministic):\nrun0: %+v\nrun%d: %+v",
				i, first, i, actions)
		}
	}
	if len(first) != 1 || len(first[0].Devices) != 2 {
		t.Fatalf("fixture setup: expected exactly one action with two devices, got %+v", first)
	}
	for _, d := range first[0].Devices {
		if d.InstalledVersion != "1.0" {
			t.Errorf("device %s: InstalledVersion = %q, want %q", d.Hostname, d.InstalledVersion, "1.0")
		}
	}
}

// ─── PDF section content (PAT-1205) ────────────────────────────────────────────

// extractPDFText returns the visible text of a rendered PDF, so tests can
// assert that expected section headings and body text appear.
//
// PAT-2265: this used to just inflate every FlateDecode stream and
// substring-match the raw bytes, which worked only because core Helvetica
// text landed in the content stream as literal ASCII. Every renderer in
// this package now registers text through registerReportFont, a UTF-8
// TrueType font added via AddUTF8FontFromBytes, so Tj/TJ operands are
// 2-byte-per-character (fpdf's Identity-H encoding with its identity
// ToUnicode CMap: the 2-byte code IS the Unicode code point). Decoding that
// is delegated to extractReportPDFText (pdf_text_extract_test.go), which
// this package's own PAT-2265 UTF-8 round-trip tests also use directly.
func extractPDFText(t *testing.T, pdfBytes []byte) string {
	t.Helper()
	text, err := extractReportPDFText(pdfBytes)
	if err != nil {
		t.Fatalf("extractPDFText: %v", err)
	}
	return text
}

// buildRemediationFixture returns a FreeCVEReport with both confirmed and
// unverified findings across several apps, used to exercise the new Part 2
// sections end to end.
func buildRemediationFixture() FreeCVEReport {
	r := FreeCVEReport{
		FormatVersion: FreeCVEFormatVersion,
		GeneratedAt:   time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		Tenant:        "Remediation Fixture Co",
		CVEs: []CVERecord{
			cveWithHits("CVE-2024-7000", "CRITICAL", ptrFloat(9.8), "Example Browser",
				hit("alice-mbp", "120.0.1", "121.0.0"), hit("bob-mbp", "119.0.0", "121.0.0")),
			cveWithHits("CVE-2024-7001", "HIGH", ptrFloat(7.5), "Example Player",
				unverifiedHit("carol-mbp", "4.2.1")),
		},
	}
	FillFreeCVECounts(&r)
	return r
}

// TestRenderFreeCVEPDF_RemediationPlanSections asserts the new Part 2
// section headings render: Remediation Plan, Possibly Affected, and the
// Appendix A findings table.
func TestRenderFreeCVEPDF_RemediationPlanSections(t *testing.T) {
	pdfBytes, err := RenderFreeCVEPDF(buildRemediationFixture())
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF error: %v", err)
	}
	text := extractPDFText(t, pdfBytes)
	for _, want := range []string{"Remediation Plan", "Possibly Affected", "Appendix A"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered PDF missing expected section text %q", want)
		}
	}
}

// TestRenderFreeCVEPDF_Determinism asserts the documented determinism
// guarantee (go-service/docs/FREE_CVE_REPORT.md): identical input renders to
// byte-for-byte identical output. Each call gets a freshly constructed
// (not reused) FreeCVEReport, so this also guards against any stray map
// iteration reaching the renderer via BuildCVEActions.
func TestRenderFreeCVEPDF_Determinism(t *testing.T) {
	pdf1, err := RenderFreeCVEPDF(buildRemediationFixture())
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF (first) error: %v", err)
	}
	pdf2, err := RenderFreeCVEPDF(buildRemediationFixture())
	if err != nil {
		t.Fatalf("RenderFreeCVEPDF (second) error: %v", err)
	}
	if !bytes.Equal(pdf1, pdf2) {
		t.Errorf("RenderFreeCVEPDF is not deterministic: got %d and %d bytes that differ", len(pdf1), len(pdf2))
	}
}
