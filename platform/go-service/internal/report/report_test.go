package report

import (
	"strings"
	"testing"
	"time"
)

// timePtr is the parallel of strPtr for the *time.Time fields in fixtures.
func timePtr(t time.Time) *time.Time { return &t }
func boolPtr(b bool) *bool           { return &b }

// strPtr is a tiny helper so the test fixtures stay readable.
func strPtr(s string) *string { return &s }

// fixtureReport builds a Report by hand that mirrors the verified Mac extraction
// — 12 pass, 5 fail. Lets us exercise the renderer end-to-end
// without DB access.
func fixtureReport() Report {
	now := time.Date(2026, 11, 14, 9, 24, 31, 0, time.UTC)

	mk := func(key, title, severity, status, observed string, nist, iso []string) EvalRow {
		row := EvalRow{
			RuleKey:          key,
			Title:            title,
			Description:      "Test description: this is what would explain the control to a customer auditor reading the report.",
			Benchmark:        "CIS Apple macOS",
			BenchmarkVersion: "v3.0.0",
			Severity:         severity,
			Status:           status,
			EvaluatedAt:      now,
			NISTMappings:     nist,
			ISOMappings:      iso,
		}
		if observed != "" {
			row.ObservedValue = strPtr(observed)
		}
		return row
	}

	return Report{
		GeneratedAt: now,
		Tenant:      "local-test",
		Device: Device{
			ID:           "00000000-0000-0000-0000-000000000001",
			Serial:       "C02XK1ABJG5J",
			HWUUID:       "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A",
			Hostname:     "andys-macbook",
			ComputerName: "Andy's MacBook Pro",
			HWModel:      "Mac15,9",
			Arch:         "arm64",
			OS:           "macOS",
			OSVersion:    "15.4.1",
			OSBuild:      "24E263",
			AgentVersion: "0.2.0",
			FirstSeen:    now.Add(-72 * time.Hour),
			LastSeen:     now,
		},
		Evaluations: []EvalRow{
			// 5 failing
			mk("cis_macos_2_5_2_2_firewall", "Enable the Application Layer Firewall",
				"high", "fail", "disabled", []string{"SC-7"}, []string{"A.13.1.1"}),
			mk("cis_macos_3_x_audit_logging", "Enable audit logging",
				"medium", "fail", "disabled", []string{"AU-2"}, []string{"A.12.4.1"}),
			mk("cis_macos_5_x_password_policy_non_default", "Password policy must not be Apple-default",
				"medium", "fail", "Yes", []string{"IA-5(1)"}, []string{"A.9.4.3"}),
			mk("patched_mdm_enrolment", "Device is MDM-enrolled",
				"medium", "fail", "dep=No mdm=No", nil, nil),
			mk("cis_macos_1_1_pending_security_updates", "No outstanding macOS security updates",
				"medium", "fail", "1", []string{"SI-2"}, []string{"A.12.6.1"}),
			// 12 passing
			mk("cis_macos_2_5_1_1_filevault", "Enable FileVault",
				"critical", "pass", "On", []string{"SC-28"}, []string{"A.10.1.1"}),
			mk("cis_macos_2_5_3_sip", "Enable System Integrity Protection",
				"high", "pass", "enabled", []string{"SI-7"}, []string{"A.12.5.1"}),
			mk("cis_macos_2_5_2_1_gatekeeper", "Enable Gatekeeper",
				"high", "pass", "enabled", []string{"SI-7"}, []string{"A.12.2.1"}),
			mk("cis_macos_2_5_5_sealed_system_volume", "Sealed System Volume intact",
				"high", "pass", "enabled", []string{"SI-7"}, []string{"A.12.5.1"}),
			mk("cis_macos_1_4_auto_security_updates", "Auto-install security updates",
				"high", "pass", "On", []string{"SI-2"}, []string{"A.12.6.1"}),
			mk("cis_macos_2_4_1_remote_apple_events", "Disable Remote Apple Events",
				"medium", "pass", "Off", []string{"AC-17"}, []string{"A.9.1.2"}),
			mk("cis_macos_2_4_4_remote_login", "Disable Remote Login (SSH)",
				"high", "pass", "Off", []string{"AC-17"}, []string{"A.9.1.2"}),
			mk("cis_macos_2_4_10_screen_sharing", "Disable Screen Sharing",
				"medium", "pass", "Off", []string{"AC-17"}, []string{"A.9.1.2"}),
			mk("cis_macos_2_10_screensaver_password", "Screensaver password required",
				"medium", "pass", "DefaultAssumed", []string{"AC-11"}, []string{"A.11.2.8"}),
			mk("cis_macos_5_1_auto_login_disabled", "Auto-login disabled",
				"high", "pass", "None", []string{"IA-2"}, []string{"A.9.4.2"}),
			mk("cis_macos_5_8_local_admin_count", "Local admin count ≤ 2",
				"medium", "pass", "1", []string{"AC-6"}, []string{"A.9.2.3"}),
			mk("cis_macos_5_x_secure_boot_arm64", "Secure Boot integrity (arm64 only)",
				"high", "pass", "Valid", []string{"SI-7"}, []string{"A.12.5.1"}),
		},
		PendingUpdates: []PendingUpdate{
			{Label: "macOS Sequoia 15.5-15.5", Title: "macOS Sequoia 15.5", Version: "15.5", Action: "shut down", Recommended: true},
			{Label: "Safari18.5-18.5", Title: "Safari", Version: "18.5", Recommended: true},
		},
		PatchHistory: []PatchHistoryItem{
			{Title: "macOS 15.4.1", Identifier: "macOS 15.4.1|15.4.1", InstalledAt: timePtr(now.Add(-72 * time.Hour))},
			{Title: "Safari", Identifier: "Safari|18.4.1", InstalledAt: timePtr(now.Add(-72 * time.Hour))},
			{Title: "macOS 15.4", Identifier: "macOS 15.4|15.4", InstalledAt: timePtr(now.Add(-30 * 24 * time.Hour))},
			{Title: "XProtect Plistservice configuration data", Identifier: "XProtect|2199", InstalledAt: nil},
		},
		Apps: []App{
			{Name: "Slack", Version: "4.38.121", BundleID: "com.tinyspeck.slackmacgap",
				Signer: "Developer ID Application: Slack Technologies, LLC (BQR82RBBHL)",
				TeamID: "BQR82RBBHL", Architecture: "x86_64 arm64", Notarized: boolPtr(true), LastSeen: now},
			{Name: "1Password 7", Version: "7.9.11", BundleID: "com.agilebits.onepassword7",
				Signer: "Developer ID Application: AgileBits Inc. (2BUA8C4S2C)",
				TeamID: "2BUA8C4S2C", Architecture: "x86_64 arm64", Notarized: boolPtr(true), LastSeen: now},
			{Name: "Safari", Version: "18.4", BundleID: "com.apple.Safari",
				Signer: "Software Signing", TeamID: "Software Signing", Architecture: "x86_64 arm64",
				Notarized: boolPtr(false), LastSeen: now},
			{Name: "Terminal", Version: "2.14", BundleID: "com.apple.Terminal",
				Signer: "Software Signing", TeamID: "Software Signing", Architecture: "x86_64 arm64",
				Notarized: boolPtr(false), LastSeen: now},
		},
	}
}

func TestSummary(t *testing.T) {
	rep := fixtureReport()
	s := rep.Summary()
	if s.Total != 17 {
		t.Errorf("total: got %d want 17", s.Total)
	}
	if s.Pass != 12 {
		t.Errorf("pass: got %d want 12", s.Pass)
	}
	if s.Fail != 5 {
		t.Errorf("fail: got %d want 5", s.Fail)
	}
	if s.NotApplicable != 0 {
		t.Errorf("not_applicable: got %d want 0", s.NotApplicable)
	}
	if s.Undetermined != 0 {
		t.Errorf("undetermined: got %d want 0 (fixture has no nil-observed fails)", s.Undetermined)
	}
	// 12 pass / (12+5+0) = 70.588…%
	want := 12.0 / 17.0 * 100.0
	if diff := s.CompliancePct - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("compliance pct: got %.4f want %.4f", s.CompliancePct, want)
	}
}

// TestSummary_UndeterminedFailExcluded is the PAT-1758/PAT-1762 regression
// for the per-device compliance PDF: a 'fail' evaluation with no observed
// value (unreadable evidence — an absent signal, or the collector's
// "Unknown" sentinel) must be counted in Undetermined, not Fail, while still
// counting against CompliancePct's denominator so missing evidence never
// raises the score. A 'fail' with a real observed value (including
// "NotConfigured") stays a real Fail.
func TestSummary_UndeterminedFailExcluded(t *testing.T) {
	rep := fixtureReport()
	rep.Evaluations = []EvalRow{
		{Status: "fail", ObservedValue: strPtr("Off")},           // real fail
		{Status: "fail", ObservedValue: strPtr("NotConfigured")}, // real fail (PAT-1767)
		{Status: "fail", ObservedValue: nil},                     // undetermined
		{Status: "fail", ObservedValue: nil},                     // undetermined
		{Status: "pass", ObservedValue: strPtr("On")},
	}

	s := rep.Summary()
	if s.Fail != 2 {
		t.Errorf("fail: got %d want 2 (the 'Off' and 'NotConfigured' rows only)", s.Fail)
	}
	if s.Undetermined != 2 {
		t.Errorf("undetermined: got %d want 2", s.Undetermined)
	}
	if s.Pass != 1 {
		t.Errorf("pass: got %d want 1", s.Pass)
	}
	// denom = pass(1) + fail(2) + undetermined(2) + error(0) = 5
	// pct = 1/5 * 100 = 20% — NOT 1/3*100=33.3% (which would happen if
	// undetermined were dropped from the denominator, silently raising the
	// score for missing evidence).
	want := 20.0
	if diff := s.CompliancePct - want; diff > 0.01 || diff < -0.01 {
		t.Errorf("compliance pct: got %.4f want %.4f (undetermined must stay in the denominator)", s.CompliancePct, want)
	}
}

func TestRenderPDF_SmokeTest(t *testing.T) {
	pdf, err := RenderPDF(fixtureReport())
	if err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	if len(pdf) < 1000 {
		t.Fatalf("PDF suspiciously small: %d bytes", len(pdf))
	}
	// PDF magic — every valid PDF starts %PDF-<version>
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Errorf("output is not a PDF (first 8 bytes: %q)", pdf[:8])
	}
}

func TestRenderPDF_EmptyEvaluations(t *testing.T) {
	// Device exists but has never been evaluated (e.g. brand-new ingest where
	// the rule-load failed). Renderer must not panic and the summary must
	// degrade cleanly.
	rep := fixtureReport()
	rep.Evaluations = nil

	pdf, err := RenderPDF(rep)
	if err != nil {
		t.Fatalf("RenderPDF on empty evals: %v", err)
	}
	if len(pdf) < 500 {
		t.Errorf("empty-eval PDF too small: %d bytes", len(pdf))
	}

	s := rep.Summary()
	if s.Total != 0 || s.CompliancePct != 0 {
		t.Errorf("empty summary should be all zero, got %+v", s)
	}
}

func TestRenderPDF_AllSectionsEmpty(t *testing.T) {
	// Older-collector ingest path: schema_v2 0.2.0 collector hasn't emitted
	// pending_updates or patches or any apps. Renderer must still produce
	// a valid PDF (the device + evaluations sections still draw).
	rep := fixtureReport()
	rep.PendingUpdates = nil
	rep.PatchHistory = nil
	rep.Apps = nil

	pdf, err := RenderPDF(rep)
	if err != nil {
		t.Fatalf("RenderPDF on no-patching-data: %v", err)
	}
	if len(pdf) < 1000 {
		t.Errorf("PDF too small without patching sections: %d bytes", len(pdf))
	}
}

func TestFilterEvals(t *testing.T) {
	rep := fixtureReport()
	failing := filterEvals(rep.Evaluations, "fail", "error")
	if len(failing) != 5 {
		t.Errorf("failing count: got %d want 5", len(failing))
	}
	passing := filterEvals(rep.Evaluations, "pass")
	if len(passing) != 12 {
		t.Errorf("passing count: got %d want 12", len(passing))
	}
	none := filterEvals(rep.Evaluations, "not_applicable")
	if len(none) != 0 {
		t.Errorf("not_applicable should be empty, got %d", len(none))
	}
}

// TestRealFailingEvalsAndUndeterminedEvals is the PAT-1762 regression for the
// per-device PDF's Failing Controls / Could Not Be Determined split: an
// undetermined fail (no observed value) must land in undeterminedEvals and
// be dropped by realFailingEvals; a real fail (including "NotConfigured")
// and every "error" row must stay in realFailingEvals.
func TestRealFailingEvalsAndUndeterminedEvals(t *testing.T) {
	in := []EvalRow{
		{Title: "real-fail", Status: "fail", ObservedValue: strPtr("Off")},
		{Title: "not-configured-fail", Status: "fail", ObservedValue: strPtr("NotConfigured")},
		{Title: "undetermined-1", Status: "fail", ObservedValue: nil},
		{Title: "undetermined-2", Status: "fail", ObservedValue: nil},
		{Title: "an-error", Status: "error", ObservedValue: nil},
	}

	real := realFailingEvals(in)
	if len(real) != 3 {
		t.Fatalf("realFailingEvals: got %d rows, want 3", len(real))
	}
	for _, ev := range real {
		if ev.Title == "undetermined-1" || ev.Title == "undetermined-2" {
			t.Errorf("realFailingEvals must not include %q", ev.Title)
		}
	}

	undetermined := undeterminedEvals(filterEvals(in, "fail"))
	if len(undetermined) != 2 {
		t.Fatalf("undeterminedEvals: got %d rows, want 2", len(undetermined))
	}
	for _, ev := range undetermined {
		if ev.Title != "undetermined-1" && ev.Title != "undetermined-2" {
			t.Errorf("undeterminedEvals returned unexpected row %q", ev.Title)
		}
	}
}

func TestSortAppsForReport(t *testing.T) {
	rep := fixtureReport()
	sorted := sortAppsForReport(rep.Apps)

	// Third-party Developer ID first; Apple-bundled at the bottom.
	if !strings.HasPrefix(sorted[0].Signer, "Developer ID Application") {
		t.Errorf("first app should be Developer-ID-signed, got signer=%q name=%q",
			sorted[0].Signer, sorted[0].Name)
	}
	lastSigner := sorted[len(sorted)-1].Signer
	if !(lastSigner == "Software Signing" || strings.HasPrefix(lastSigner, "Apple")) {
		t.Errorf("last app should be Apple-signed, got signer=%q", lastSigner)
	}

	// Within each group, names sort alphabetically (case-insensitive).
	// Developer-ID group: 1Password 7 should come before Slack.
	devIdx := -1
	for i, a := range sorted {
		if strings.HasPrefix(a.Signer, "Developer ID") && a.Name == "1Password 7" {
			devIdx = i
			break
		}
	}
	if devIdx < 0 {
		t.Fatal("couldn't find 1Password 7 in sorted list")
	}
	if sorted[devIdx+1].Name != "Slack" {
		t.Errorf("expected Slack after 1Password 7 within Developer-ID group, got %q", sorted[devIdx+1].Name)
	}
}

func TestSignerGroup(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"Developer ID Application: Slack Technologies, LLC (BQR82RBBHL)", 0},
		{"Software Signing", 1},
		{"Apple Mac OS Application Signing", 1},
		{"", 2},
		{"some random signer", 2},
	}
	for _, tc := range cases {
		if got := signerGroup(tc.in); got != tc.want {
			t.Errorf("signerGroup(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 4, "abc…"},
		{"abcdef", 6, "abcdef"},
		{"a", 1, "a"},
	}
	for _, tc := range cases {
		if got := truncate(tc.in, tc.max); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

func TestAfterPipe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"name|1.2.3", "1.2.3"},
		{"name-no-pipe", ""},
		{"|", ""},
		{"a|b|c", "b|c"},
	}
	for _, tc := range cases {
		if got := afterPipe(tc.in); got != tc.want {
			t.Errorf("afterPipe(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestSummariseBenchmarks(t *testing.T) {
	rep := fixtureReport()
	// All evals in the fixture are CIS Apple macOS v3.0.0 except mdm_enrolment
	// which is patched.im baseline — but in this fixture it's tagged the same
	// as the rest for simplicity. Just confirm we get at least one benchmark.
	bm := summariseBenchmarks(rep.Evaluations)
	if !strings.Contains(bm, "CIS Apple macOS v3.0.0") {
		t.Errorf("expected CIS benchmark in summary, got %q", bm)
	}
}

// TestMergePatchHistory_SortsNewestFirstAcrossSources is the PAT-1007
// regression: OS-patch rows (from the patches table) and provenance-sourced
// rows (from provenance_records) are two independently-sorted inputs that
// must interleave into a single newest-first list, not just get
// concatenated. This also proves an outcome/failure_reason carried on a
// provenance row survives the merge untouched.
func TestMergePatchHistory_SortsNewestFirstAcrossSources(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	osHistory := []PatchHistoryItem{
		{Title: "macOS 15.5", Identifier: "macOS 15.5|15.5", InstalledAt: timePtr(now.Add(-1 * time.Hour))},
		{Title: "Safari", Identifier: "Safari|18.5", InstalledAt: timePtr(now.Add(-3 * time.Hour))},
	}
	provHistory := []PatchHistoryItem{
		{
			Title: "1Password", Identifier: "1Password|8.10.0",
			InstalledAt: timePtr(now.Add(-2 * time.Hour)),
			Outcome:     "verification_failed", FailureReason: "checksum mismatch",
		},
		{
			Title: "Slack", Identifier: "Slack|4.50.0",
			InstalledAt: timePtr(now), // most recent of all four
			Outcome:     "installed",
		},
	}

	got := MergePatchHistory(osHistory, provHistory)
	if len(got) != 4 {
		t.Fatalf("merged length = %d, want 4", len(got))
	}

	wantOrder := []string{"Slack|4.50.0", "macOS 15.5|15.5", "1Password|8.10.0", "Safari|18.5"}
	for i, id := range wantOrder {
		if got[i].Identifier != id {
			t.Errorf("position %d: got identifier %q, want %q (full order: %+v)", i, got[i].Identifier, id, got)
		}
	}

	// The provenance-sourced row's outcome/failure_reason must survive the merge.
	if got[2].Outcome != "verification_failed" || got[2].FailureReason != "checksum mismatch" {
		t.Errorf("1Password entry lost outcome/failure_reason after merge: %+v", got[2])
	}
	// OS-patch rows carry no outcome — today's behavior must be unchanged.
	if got[1].Outcome != "" || got[1].FailureReason != "" {
		t.Errorf("OS-patch entry unexpectedly has outcome/failure_reason: %+v", got[1])
	}
}

// TestMergePatchHistory_NilInstalledAtSortsLast covers the locale-unparsed-
// date case documented on PatchHistoryItem: an entry with a nil InstalledAt
// must not panic the comparator and must sort after every entry that does
// have a timestamp.
func TestMergePatchHistory_NilInstalledAtSortsLast(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	osHistory := []PatchHistoryItem{
		{Title: "XProtect", Identifier: "XProtect|2199", InstalledAt: nil},
		{Title: "macOS 15.5", Identifier: "macOS 15.5|15.5", InstalledAt: timePtr(now)},
	}

	got := MergePatchHistory(osHistory, nil)
	if len(got) != 2 {
		t.Fatalf("merged length = %d, want 2", len(got))
	}
	if got[0].Identifier != "macOS 15.5|15.5" || got[1].Identifier != "XProtect|2199" {
		t.Errorf("nil-InstalledAt entry did not sort last: %+v", got)
	}
}
