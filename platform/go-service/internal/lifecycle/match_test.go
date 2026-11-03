package lifecycle

import (
	"testing"
	"time"
)

func d(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func bp(b bool) *bool { return &b }

func TestCycleKey(t *testing.T) {
	cases := []struct {
		rule    Rule
		version string
		want    string
		ok      bool
	}{
		{Rule{Kind: RuleMajor}, "154.0.8037.58", "154", true},
		{Rule{Kind: RuleMajor}, "v21.0.4+7", "21", true},
		{Rule{Kind: RuleMajor}, "8.0.402.6", "8", true},
		{Rule{Kind: RuleMajor}, "026.1", "26", true},
		{Rule{Kind: RuleMajor}, "156", "156", true},
		{Rule{Kind: RuleMajor}, "latest", "", false},
		{Rule{Kind: RuleMajor}, "", "", false},
		{Rule{Kind: RuleMajor}, "154abc", "", false},
		{Rule{Kind: RuleMajorMinor}, "3.12.4", "3.12", true},
		{Rule{Kind: RuleMajorMinor}, "26.2.5.2", "26.2", true},
		{Rule{Kind: RuleMajorMinor}, "7.4", "7.4", true},
		{Rule{Kind: RuleMajorMinor}, "3", "", false},
		{Rule{Kind: RuleRegex, Regex: `^1\.(8)\.`}, "1.8.0.482", "8", true},
		{Rule{Kind: RuleRegex, Regex: `^1\.(8)\.`}, "21.0.4", "", false},
		{Rule{Kind: RuleRegex, Regex: `(\d+)-(\d+)`}, "1-2", "", false}, // two groups: refused
		{Rule{Kind: RuleRegex, Regex: `(`}, "1", "", false},             // does not compile
		{Rule{Kind: RuleMacOSMajor}, "15.4.1", "15", true},
		{Rule{Kind: RuleMacOSMajor}, "26.0", "26", true},
		{Rule{Kind: RuleMacOSMajor}, "10.15.7", "10.15", true},
		{Rule{Kind: RuleMacOSMajor}, "11.7.10", "11", true},
		{Rule{Kind: RuleMacOSMajor}, "14", "14", true},
		{Rule{Kind: RuleMacOSMajor}, "10", "", false}, // 10 alone names no cycle
		{Rule{Kind: "unknown"}, "1.0", "", false},
	}
	for _, c := range cases {
		got, ok := CycleKey(c.rule, c.version)
		if got != c.want || ok != c.ok {
			t.Errorf("CycleKey(%+v, %q) = %q, %v; want %q, %v", c.rule, c.version, got, ok, c.want, c.ok)
		}
	}
}

func TestValidateRegex(t *testing.T) {
	if err := ValidateRegex(`^1\.(8)\.`); err != nil {
		t.Errorf("valid regex refused: %v", err)
	}
	for _, bad := range []string{"", `(`, `^\d+$`, `(\d+)\.(\d+)`} {
		if err := ValidateRegex(bad); err == nil {
			t.Errorf("ValidateRegex(%q) accepted, want refused", bad)
		}
	}
	if err := ValidateRegex(`^(?:v)?(\d+)`); err != nil {
		t.Errorf("non-capturing group plus one capture refused: %v", err)
	}
}

func TestWindowsBuild(t *testing.T) {
	cases := []struct {
		v, b string
		want int
		ok   bool
	}{
		{"10.0.19045", "", 19045, true},
		{"10.0.19045.4529", "", 19045, true},
		{"22H2", "19045.4529", 19045, true},
		{"22H2", "10.0.19045.4000", 19045, true},
		{"", "26100", 26100, true},
		{"6.1.7601", "", 7601, true},
		{"22H2", "", 0, false},
		{"", "", 0, false},
	}
	for _, c := range cases {
		got, ok := WindowsBuild(c.v, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("WindowsBuild(%q, %q) = %d, %v; want %d, %v", c.v, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestWindowsEdition(t *testing.T) {
	cases := []struct {
		caption        string
		edition        string
		known, covered bool
	}{
		{"Microsoft Windows 11 Pro", EditionWorkstation, true, true},
		{"Microsoft Windows 11 Home", EditionWorkstation, true, true},
		{"Microsoft Windows 11 Pro for Workstations", EditionWorkstation, true, true},
		{"Microsoft Windows 11 Pro Education", EditionWorkstation, true, true},
		{"Microsoft Windows 11 Education", EditionEnterprise, true, true},
		{"Microsoft Windows 11 Enterprise", EditionEnterprise, true, true},
		{"Microsoft Windows 10 Enterprise LTSC 2021", EditionEnterpriseLTS, true, true},
		{"Microsoft Windows 10 IoT Enterprise LTSC 2021", EditionIoTLTS, true, true},
		{"Microsoft Windows Server 2022 Standard", "", true, false},
		{"", "", false, true},
		{"Microsoft Windows 11 SE", "", false, true},
	}
	for _, c := range cases {
		e, k, cov := WindowsEdition(c.caption)
		if e != c.edition || k != c.known || cov != c.covered {
			t.Errorf("WindowsEdition(%q) = %q, %v, %v; want %q, %v, %v", c.caption, e, k, cov, c.edition, c.known, c.covered)
		}
	}
}

// windowsCycles mirrors the live endoflife.date shape for three feature
// releases (checked 2026-09-25).
func windowsCycles() []Cycle {
	return []Cycle{
		{Name: "11-24h2-iot-lts", EOLDate: d("2034-10-10"), IsEOL: bp(false), LatestVersion: "10.0.26100"},
		{Name: "11-24h2-e-lts", EOLDate: d("2029-10-09"), IsEOL: bp(false), LatestVersion: "10.0.26100"},
		{Name: "11-24h2-e", EOLDate: d("2027-10-12"), IsEOL: bp(false), LatestVersion: "10.0.26100"},
		{Name: "11-24h2-w", EOLDate: d("2026-10-13"), IsEOL: bp(false), LatestVersion: "10.0.26100"},
		{Name: "10-22h2", EOLDate: d("2025-10-14"), IsEOL: bp(true), ExtendedSupportDate: d("2028-10-10"), LatestVersion: "10.0.19045"},
		{Name: "10-21h2-e-lts", EOLDate: d("2027-01-12"), IsEOL: bp(false), LatestVersion: "10.0.19044"},
		{Name: "10-21h2-e", EOLDate: d("2024-06-11"), IsEOL: bp(true), LatestVersion: "10.0.19044"},
		{Name: "10-21h2-w", EOLDate: d("2023-06-13"), IsEOL: bp(true), LatestVersion: "10.0.19044"},
	}
}

func TestMatchWindows(t *testing.T) {
	cs := windowsCycles()
	cases := []struct {
		name, version, build, caption, wantCycle, wantReason string
	}{
		{"pro 24h2 picks W", "10.0.26100", "", "Microsoft Windows 11 Pro", "11-24h2-w", ""},
		{"enterprise 24h2 picks E", "10.0.26100.1000", "", "Microsoft Windows 11 Enterprise", "11-24h2-e", ""},
		{"ltsc picks e-lts", "10.0.19044", "", "Microsoft Windows 10 Enterprise LTSC 2021", "10-21h2-e-lts", ""},
		{"edition-agnostic cycle for any edition", "22H2", "19045.4529", "Microsoft Windows 10 Pro", "10-22h2", ""},
		{"edition-agnostic cycle with no caption", "10.0.19045", "", "", "10-22h2", ""},
		{"no caption and dates differ: unknown", "10.0.26100", "", "", "", ReasonEditionUnknown},
		{"server: not covered", "10.0.26100", "", "Microsoft Windows Server 2025 Standard", "", ReasonEditionNotCovered},
		{"unknown build", "10.0.99999", "", "Microsoft Windows 11 Pro", "", ReasonVersionUnmatched},
		{"no version at all", "", "", "Microsoft Windows 11 Pro", "", ReasonVersionMissing},
		{"marketing name only", "22H2", "", "Microsoft Windows 10 Pro", "", ReasonVersionUnmatched},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := MatchWindows(cs, c.version, c.build, c.caption)
			got := ""
			if m.Cycle != nil {
				got = m.Cycle.Name
			}
			if got != c.wantCycle || m.Reason != c.wantReason {
				t.Errorf("got cycle %q reason %q; want %q %q", got, m.Reason, c.wantCycle, c.wantReason)
			}
		})
	}
}

func TestCycleStateBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 25, 15, 30, 0, 0, time.UTC)
	cases := []struct {
		name  string
		c     Cycle
		state string
		days  *int
	}{
		{"eol yesterday", Cycle{EOLDate: d("2026-09-24")}, StateUnsupported, ip(-1)},
		{"eol today is unsupported", Cycle{EOLDate: d("2026-09-25")}, StateUnsupported, ip(0)},
		{"eol tomorrow is ending", Cycle{EOLDate: d("2026-09-26")}, StateEndingSoon, ip(1)},
		{"exactly 90 days is ending", Cycle{EOLDate: d("2026-12-24")}, StateEndingSoon, ip(90)},
		{"91 days is supported", Cycle{EOLDate: d("2026-12-25")}, StateSupported, ip(91)},
		{"date wins over a stale flag", Cycle{EOLDate: d("2030-01-01"), IsEOL: bp(true)}, StateSupported, ip(1194)},
		{"no date, flag true", Cycle{IsEOL: bp(true)}, StateUnsupported, nil},
		{"no date, maintained", Cycle{IsEOL: bp(false)}, StateSupported, nil},
		{"no data at all", Cycle{}, StateUnknown, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, days, reason := CycleState(c.c, now)
			if state != c.state {
				t.Errorf("state = %s, want %s", state, c.state)
			}
			if (days == nil) != (c.days == nil) || (days != nil && *days != *c.days) {
				t.Errorf("days = %v, want %v", deref(days), deref(c.days))
			}
			if c.state == StateUnknown && reason != ReasonNoEOLData {
				t.Errorf("reason = %q, want %q", reason, ReasonNoEOLData)
			}
		})
	}
}

func ip(i int) *int { return &i }

func deref(i *int) any {
	if i == nil {
		return nil
	}
	return *i
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-24 * time.Hour)
	old := now.Add(-CacheTTL - time.Minute)
	edge := now.Add(-CacheTTL)
	chrome := &Product{Slug: "chrome", HTMLURL: "https://endoflife.date/chrome", FetchedAt: &fresh, Cycles: []Cycle{
		{Name: "154", EOLDate: d("2026-10-06"), IsEOL: bp(false)},
		{Name: "153", EOLDate: d("2026-09-22"), IsEOL: bp(true)},
		{Name: "150", EOLDate: d("2027-06-01"), IsEOL: bp(false)},
		{Name: "140"},
	}}
	chromeRef := &MappingRef{Slug: "chrome", Rule: Rule{Kind: RuleMajor}}
	stale := *chrome
	stale.FetchedAt = &old
	atEdge := *chrome
	atEdge.FetchedAt = &edge
	never := &Product{Slug: "chrome"}

	cases := []struct {
		name    string
		ref     *MappingRef
		p       *Product
		version string
		state   string
		reason  string
	}{
		{"supported", chromeRef, chrome, "150.0.1", StateSupported, ""},
		{"ending", chromeRef, chrome, "154.0.8037.58", StateEndingSoon, ""},
		{"unsupported", chromeRef, chrome, "153.0.1", StateUnsupported, ""},
		{"no mapping", nil, chrome, "154.0", StateUnknown, ReasonNoMapping},
		{"never fetched", chromeRef, nil, "154.0", StateUnknown, ReasonNotFetched},
		{"fetch never succeeded", chromeRef, never, "154.0", StateUnknown, ReasonNotFetched},
		{"stale cache", chromeRef, &stale, "154.0", StateUnknown, ReasonStale},
		{"exactly the TTL is still fresh", chromeRef, &atEdge, "154.0", StateEndingSoon, ""},
		{"no version", chromeRef, chrome, "", StateUnknown, ReasonVersionMissing},
		{"unparsable version", chromeRef, chrome, "beta", StateUnknown, ReasonVersionUnmatched},
		{"no such cycle", chromeRef, chrome, "99.0", StateUnknown, ReasonVersionUnmatched},
		{"cycle without dates", chromeRef, chrome, "140.1", StateUnknown, ReasonNoEOLData},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := Evaluate(c.ref, c.p, c.version, nil, now)
			if ev.State != c.state || ev.Reason != c.reason {
				t.Fatalf("got %s/%q, want %s/%q", ev.State, ev.Reason, c.state, c.reason)
			}
			if ev.State == StateSupported && ev.Reason != "" {
				t.Fatal("a Supported row must carry no Unknown reason")
			}
			if c.ref != nil && ev.Slug != "chrome" {
				t.Errorf("slug = %q, want chrome on every mapped row", ev.Slug)
			}
			if c.ref != nil && c.p != nil && c.p.FetchedAt != nil && ev.LastCheckedAt == nil {
				t.Error("a row using fetched data must carry last_checked_at")
			}
			if ReasonText[ev.Reason] == "" && ev.Reason != "" {
				t.Errorf("reason %q has no text", ev.Reason)
			}
		})
	}
	if ReasonText[ReasonStale] != "lifecycle data older than 7 days" {
		t.Errorf("stale reason text = %q", ReasonText[ReasonStale])
	}
}

func TestEvaluateOS(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour)
	macos := &Product{Slug: "macos", FetchedAt: &fresh, Cycles: []Cycle{
		{Name: "26", IsEOL: bp(false)},
		{Name: "14", EOLDate: d("2026-09-14"), IsEOL: bp(true)},
		{Name: "10.15", EOLDate: d("2022-09-12"), IsEOL: bp(true)},
	}}
	macRef := &MappingRef{Slug: "macos", Rule: Rule{Kind: RuleMacOSMajor}}
	if ev := Evaluate(macRef, macos, "", &OSInput{Version: "26.0.1"}, now); ev.State != StateSupported || ev.DaysToEOL != nil {
		t.Errorf("macOS 26 = %s days %v, want supported with no date", ev.State, deref(ev.DaysToEOL))
	}
	if ev := Evaluate(macRef, macos, "", &OSInput{Version: "14.8.9"}, now); ev.State != StateUnsupported {
		t.Errorf("macOS 14 = %s, want unsupported", ev.State)
	}
	if ev := Evaluate(macRef, macos, "", &OSInput{Version: "10.15.7"}, now); ev.State != StateUnsupported || ev.Cycle.Name != "10.15" {
		t.Errorf("macOS 10.15 = %s, want unsupported on cycle 10.15", ev.State)
	}

	win := &Product{Slug: "windows", FetchedAt: &fresh, Cycles: windowsCycles()}
	winRef := &MappingRef{Slug: "windows", Rule: Rule{Kind: RuleWindowsBuild}}
	ev := Evaluate(winRef, win, "", &OSInput{Version: "10.0.19045", Caption: "Microsoft Windows 10 Pro"}, now)
	if ev.State != StateUnsupported {
		t.Fatalf("Windows 10 22H2 = %s, want unsupported", ev.State)
	}
	if ev.Note == "" {
		t.Error("an Unsupported cycle with extended support ahead must say ESU exists and is not evidenced")
	}
	ev = Evaluate(winRef, win, "", &OSInput{Version: "10.0.26100", Caption: "Microsoft Windows 11 Pro"}, now)
	if ev.State != StateEndingSoon || deref(ev.DaysToEOL) != 18 {
		t.Errorf("Windows 11 24H2 Pro = %s %v, want ending in 18 days", ev.State, deref(ev.DaysToEOL))
	}
	ev = Evaluate(winRef, win, "", &OSInput{Version: "10.0.26100"}, now)
	if ev.State != StateUnknown || ev.Reason != ReasonEditionUnknown {
		t.Errorf("Windows 11 24H2 with no edition = %s/%s, want unknown/edition_unknown", ev.State, ev.Reason)
	}
}
