package lifecycle

import (
	"strings"
	"testing"
	"time"
)

// PAT-2171: the per-mapping rolling-release rule. Every test uses a fixed
// clock; nothing here reads the wall clock.

// chromeRolling mirrors the live endoflife.date Chrome shape (captured
// 2026-09-29): every major is a plain cycle whose end of support is the next
// major's release, and there is no LTS or extended-stable cycle.
func chromeRolling(fetched time.Time) *Product {
	return &Product{Slug: "chrome", HTMLURL: "https://endoflife.date/chrome", FetchedAt: &fetched, Cycles: []Cycle{
		{Name: "154", ReleaseDate: d("2026-09-22"), EOLDate: d("2026-10-06"), IsEOL: bp(false)},
		{Name: "153", ReleaseDate: d("2026-09-08"), EOLDate: d("2026-09-22"), IsEOL: bp(true)},
		{Name: "152", ReleaseDate: d("2026-08-25"), EOLDate: d("2026-09-08"), IsEOL: bp(true)},
		{Name: "151", ReleaseDate: d("2026-07-28"), EOLDate: d("2026-08-25"), IsEOL: bp(true)},
	}}
}

// firefoxRolling mirrors the live Firefox shape: ESR majors are their own
// cycles, flagged is_lts, and keep their own end of support dates.
func firefoxRolling(fetched time.Time) *Product {
	return &Product{Slug: "firefox", HTMLURL: "https://endoflife.date/firefox", FetchedAt: &fetched, Cycles: []Cycle{
		{Name: "156", ReleaseDate: d("2026-09-15"), EOLDate: d("2026-09-29"), IsEOL: bp(false)},
		{Name: "155", ReleaseDate: d("2026-09-01"), EOLDate: d("2026-09-15"), IsEOL: bp(true)},
		{Name: "154", ReleaseDate: d("2026-08-18"), EOLDate: d("2026-09-01"), IsEOL: bp(true)},
		{Name: "153", ReleaseDate: d("2026-07-21"), IsEOL: bp(false), IsLTS: true},
		{Name: "152", ReleaseDate: d("2026-06-16"), EOLDate: d("2026-07-21"), IsEOL: bp(true)},
		{Name: "140", ReleaseDate: d("2025-06-24"), EOLDate: d("2026-09-29"), IsEOL: bp(false), IsLTS: true},
		{Name: "128", ReleaseDate: d("2024-07-09"), EOLDate: d("2025-09-16"), IsEOL: bp(true), IsLTS: true},
		{Name: "115", ReleaseDate: d("2023-07-04"), EOLDate: d("2027-03-31"), IsEOL: bp(false), IsLTS: true},
	}}
}

func clock(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func rollingRef(slug string) *MappingRef {
	return &MappingRef{Slug: slug, Rule: Rule{Kind: RuleMajor}, RollingWindowDays: DefaultRollingWindowDays}
}

func plainRef(slug string) *MappingRef {
	return &MappingRef{Slug: slug, Rule: Rule{Kind: RuleMajor}}
}

func TestDefaultRollingWindowIsThreeWeeks(t *testing.T) {
	if DefaultRollingWindowDays != 21 {
		t.Fatalf("DefaultRollingWindowDays = %d, want 21", DefaultRollingWindowDays)
	}
}

// The latest major reads Supported, and never "Ending within 90 days" even
// though the source dates it (154 ends on 2026-10-06, 7 days after the clock).
func TestRollingLatestMajorSupported(t *testing.T) {
	now := clock("2026-09-29 12:00")
	p := chromeRolling(now.Add(-time.Hour))
	ev := Evaluate(rollingRef("chrome"), p, "154.0.8037.58", nil, now)
	if ev.State != StateSupported || ev.Reason != "" {
		t.Fatalf("latest major = %s/%q, want supported", ev.State, ev.Reason)
	}
	if ev.DaysToEOL != nil {
		t.Errorf("a rolling row must not carry days_to_eol, got %d", *ev.DaysToEOL)
	}
	if ev.Cycle == nil || ev.Cycle.Name != "154" {
		t.Fatalf("cycle = %+v, want 154", ev.Cycle)
	}
	if ev.Cycle.EOLDate != nil {
		t.Errorf("a supported rolling row must not show the source's next-release date as an end of support date: %v", ev.Cycle.EOLDate)
	}
	if ev.Note == "" {
		t.Error("a rolling row must explain its basis in a note")
	}
	if ev.LastCheckedAt == nil || ev.Slug != "chrome" || ev.SourceURL != "https://endoflife.date/chrome" {
		t.Errorf("source/last checked lost: %+v", ev)
	}
	// The same data under a plain mapping is the noisy reading this rule exists to remove.
	plain := Evaluate(plainRef("chrome"), p, "154.0.8037.58", nil, now)
	if plain.State != StateEndingSoon {
		t.Errorf("control: plain mapping = %s, want ending_within_90_days", plain.State)
	}
}

// The previous major is Supported while the latest major is under N days
// old and Unsupported from N days on, measured in whole UTC days from the
// latest major's release date (154: 2026-09-22).
func TestRollingPreviousMajorWindowBoundary(t *testing.T) {
	cases := []struct {
		now   string
		state string
	}{
		{"2026-09-22 00:00", StateSupported},   // release day, age 0
		{"2026-09-22 23:59", StateSupported},   // still age 0
		{"2026-09-23 12:00", StateSupported},   // age 1
		{"2026-10-12 00:00", StateSupported},   // age 20
		{"2026-10-12 23:59", StateSupported},   // still age 20 at the last minute
		{"2026-10-13 00:00", StateUnsupported}, // age 21: exactly N days, no longer inside the window
		{"2026-10-13 12:00", StateUnsupported}, // age 21
		{"2026-10-14 12:00", StateUnsupported}, // age 22
		{"2026-12-01 12:00", StateUnsupported}, // long after
	}
	for _, c := range cases {
		t.Run(c.now, func(t *testing.T) {
			now := clock(c.now)
			// Fetched an hour before the clock so the 7 day cache never decides.
			p := chromeRolling(now.Add(-time.Hour))
			ev := Evaluate(rollingRef("chrome"), p, "153.0.7100.44", nil, now)
			if ev.State != c.state || ev.Reason != "" {
				t.Fatalf("previous major at %s = %s/%q, want %s", c.now, ev.State, ev.Reason, c.state)
			}
			if ev.DaysToEOL != nil {
				t.Errorf("days_to_eol = %d, want none on a rolling row", *ev.DaysToEOL)
			}
			if ev.Cycle == nil || ev.Cycle.Name != "153" {
				t.Fatalf("cycle = %+v, want 153", ev.Cycle)
			}
			// The latest major stays Supported however old it is.
			latest := Evaluate(rollingRef("chrome"), p, "154.0.1", nil, now)
			if latest.State != StateSupported {
				t.Errorf("latest major at %s = %s, want supported", c.now, latest.State)
			}
		})
	}
}

// The window is a per-mapping value, not a constant baked into the rule.
func TestRollingWindowIsPerMapping(t *testing.T) {
	now := clock("2026-09-29 12:00") // latest is 7 days old
	p := chromeRolling(now.Add(-time.Hour))
	for _, c := range []struct {
		days  int
		state string
	}{{7, StateUnsupported}, {8, StateSupported}, {1, StateUnsupported}, {90, StateSupported}} {
		ref := &MappingRef{Slug: "chrome", Rule: Rule{Kind: RuleMajor}, RollingWindowDays: c.days}
		if got := Evaluate(ref, p, "153.0.1", nil, now).State; got != c.state {
			t.Errorf("window %d days, latest 7 days old: previous major = %s, want %s", c.days, got, c.state)
		}
	}
}

// Every major older than the previous one is Unsupported, inside the window
// or not.
func TestRollingOlderMajorUnsupported(t *testing.T) {
	for _, now := range []time.Time{clock("2026-09-23 12:00"), clock("2026-09-29 12:00"), clock("2026-11-15 12:00")} {
		p := chromeRolling(now.Add(-time.Hour))
		for _, v := range []string{"152.0.1", "151.0.7000.1"} {
			ev := Evaluate(rollingRef("chrome"), p, v, nil, now)
			if ev.State != StateUnsupported || ev.Reason != "" {
				t.Errorf("%s at %s = %s/%q, want unsupported", v, now.Format("2006-01-02"), ev.State, ev.Reason)
			}
			if ev.DaysToEOL != nil {
				t.Errorf("%s: days_to_eol = %d, want none", v, *ev.DaysToEOL)
			}
			// An unsupported row keeps the source's own date: it really did end then.
			if ev.Cycle == nil || ev.Cycle.EOLDate == nil {
				t.Errorf("%s: an unsupported rolling row should keep the source end date", v)
			}
		}
	}
}

// A rolling mapping never reads "Ending within 90 days" for a non-LTS cycle,
// whatever the clock and whichever major is installed.
func TestRollingNeverEndingWithin90Days(t *testing.T) {
	start := clock("2026-09-22 12:00") // the release day of the latest cycle in the fixture
	for day := 0; day < 150; day++ {
		now := start.Add(time.Duration(day) * 24 * time.Hour)
		p := chromeRolling(now.Add(-time.Hour))
		for _, v := range []string{"154.0.1", "153.0.1", "152.0.1", "151.0.1"} {
			ev := Evaluate(rollingRef("chrome"), p, v, nil, now)
			if ev.State == StateEndingSoon {
				t.Fatalf("%s at %s read %s", v, now.Format("2006-01-02"), ev.State)
			}
			if ev.State != StateSupported && ev.State != StateUnsupported {
				t.Fatalf("%s at %s = %s/%q, want supported or unsupported", v, now.Format("2006-01-02"), ev.State, ev.Reason)
			}
		}
	}
}

// ESR cycles are is_lts in the source and keep their own dates and the
// existing rule: a rolling mapping must not swallow them.
func TestRollingESRKeepsOwnDates(t *testing.T) {
	now := clock("2026-09-16 12:00")
	p := firefoxRolling(now.Add(-time.Hour))
	ref := rollingRef("firefox")

	cases := []struct {
		version string
		state   string
		days    *int
		why     string
	}{
		{"156.0", StateSupported, nil, "latest rapid release"},
		{"155.0.1", StateSupported, nil, "previous rapid release, latest is 1 day old"},
		{"154.0.1", StateUnsupported, nil, "older rapid release"},
		{"153.3.0", StateSupported, nil, "ESR 153: no end date, source says maintained"},
		{"140.9.0", StateEndingSoon, ip(13), "ESR 140 ends 2026-09-29: its own date, not swallowed into Unsupported"},
		{"128.20.0", StateUnsupported, ip(-365), "ESR 128 ended 2025-09-16"},
		{"115.30.0", StateSupported, ip(196), "ESR 115 runs to 2027-03-31: its own date, not swallowed into Unsupported"},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			ev := Evaluate(ref, p, c.version, nil, now)
			if ev.State != c.state || ev.Reason != "" {
				t.Fatalf("%s (%s) = %s/%q, want %s", c.version, c.why, ev.State, ev.Reason, c.state)
			}
			if got, want := deref(ev.DaysToEOL), deref(c.days); got != want {
				t.Errorf("%s days_to_eol = %v, want %v", c.version, got, want)
			}
		})
	}

	// Every ESR result is identical to the plain mapping's: same state, same
	// days, same cycle and end date.
	for _, v := range []string{"153.3.0", "140.9.0", "128.20.0", "115.30.0"} {
		a, b := Evaluate(ref, p, v, nil, now), Evaluate(plainRef("firefox"), p, v, nil, now)
		if a.State != b.State || deref(a.DaysToEOL) != deref(b.DaysToEOL) || a.Cycle.Name != b.Cycle.Name ||
			!sameDate(a.Cycle.EOLDate, b.Cycle.EOLDate) || a.Note != b.Note {
			t.Errorf("ESR %s differs between a rolling and a plain mapping: %+v vs %+v", v, a, b)
		}
	}
}

// When the newest release in the source is itself an ESR (the source shows
// one cycle per major, so the ESR designation hides the rapid channel of the
// same major), the ESR is still the latest major: rapid 152 is the previous
// one and gets the grace window, rapid 151 does not.
func TestRollingESRNewestRelease(t *testing.T) {
	cycles := []Cycle{
		{Name: "153", ReleaseDate: d("2026-07-21"), IsEOL: bp(false), IsLTS: true},
		{Name: "152", ReleaseDate: d("2026-06-16"), EOLDate: d("2026-07-21"), IsEOL: bp(true)},
		{Name: "151", ReleaseDate: d("2026-05-18"), EOLDate: d("2026-06-16"), IsEOL: bp(true)},
	}
	for _, c := range []struct {
		now, version, state string
	}{
		{"2026-07-30 12:00", "152.0.1", StateSupported},   // 9 days after 153
		{"2026-08-10 12:00", "152.0.1", StateSupported},   // 20 days
		{"2026-08-11 12:00", "152.0.1", StateUnsupported}, // 21 days
		{"2026-07-30 12:00", "151.0.1", StateUnsupported},
		{"2026-07-30 12:00", "153.1.0", StateSupported}, // the ESR keeps its own state
	} {
		now := clock(c.now)
		fetched := now.Add(-time.Hour)
		p := &Product{Slug: "firefox", FetchedAt: &fetched, Cycles: cycles}
		ev := Evaluate(rollingRef("firefox"), p, c.version, nil, now)
		if ev.State != c.state || ev.Reason != "" {
			t.Errorf("%s at %s = %s/%q, want %s", c.version, c.now, ev.State, ev.Reason, c.state)
		}
	}
}

// A cycle the rule cannot place in release order reads Unknown, never a
// guess: no release date, or a release date after the clock.
func TestRollingUnplaceableCycleIsUnknown(t *testing.T) {
	now := clock("2026-09-29 12:00")
	fetched := now.Add(-time.Hour)
	p := &Product{Slug: "chrome", FetchedAt: &fetched, Cycles: []Cycle{
		{Name: "155", ReleaseDate: d("2026-10-06"), IsEOL: bp(false)}, // announced, not released yet
		{Name: "154", ReleaseDate: d("2026-09-22"), IsEOL: bp(false)},
		{Name: "153", EOLDate: d("2026-09-22"), IsEOL: bp(true)}, // no release date
	}}
	for _, v := range []string{"155.0", "153.0"} {
		ev := Evaluate(rollingRef("chrome"), p, v, nil, now)
		if ev.State != StateUnknown || ev.Reason != ReasonNoReleaseData {
			t.Errorf("%s = %s/%q, want unknown/%s", v, ev.State, ev.Reason, ReasonNoReleaseData)
		}
		if ReasonText[ReasonNoReleaseData] == "" {
			t.Error("the no-release-data reason has no customer text")
		}
	}
	// The unreleased 155 must not become the latest and demote 154.
	if ev := Evaluate(rollingRef("chrome"), p, "154.0", nil, now); ev.State != StateSupported {
		t.Errorf("154 with an unreleased 155 announced = %s, want supported", ev.State)
	}
	// No cycle has a usable release date at all.
	bare := &Product{Slug: "chrome", FetchedAt: &fetched, Cycles: []Cycle{{Name: "154", IsEOL: bp(false)}}}
	if ev := Evaluate(rollingRef("chrome"), bare, "154.0", nil, now); ev.State != StateUnknown || ev.Reason != ReasonNoReleaseData {
		t.Errorf("no release dates = %s/%q, want unknown/%s", ev.State, ev.Reason, ReasonNoReleaseData)
	}
}

// The evidence checks that come before the cycle's own state still decide
// first under a rolling mapping.
func TestRollingKeepsEvidenceGates(t *testing.T) {
	now := clock("2026-09-29 12:00")
	fresh := chromeRolling(now.Add(-time.Hour))
	stale := chromeRolling(now.Add(-CacheTTL - time.Minute))
	ref := rollingRef("chrome")
	cases := []struct {
		name    string
		p       *Product
		version string
		reason  string
	}{
		{"stale cache", stale, "154.0", ReasonStale},
		{"never fetched", nil, "154.0", ReasonNotFetched},
		{"no version", fresh, "", ReasonVersionMissing},
		{"unparsable version", fresh, "beta", ReasonVersionUnmatched},
		{"newer than the data", fresh, "155.0", ReasonVersionUnmatched},
	}
	for _, c := range cases {
		ev := Evaluate(ref, c.p, c.version, nil, now)
		if ev.State != StateUnknown || ev.Reason != c.reason {
			t.Errorf("%s = %s/%q, want unknown/%s", c.name, ev.State, ev.Reason, c.reason)
		}
	}
	// No mapping at all is still Unknown, never Supported.
	if ev := Evaluate(nil, fresh, "154.0", nil, now); ev.State != StateUnknown || ev.Reason != ReasonNoMapping {
		t.Errorf("no mapping = %s/%q", ev.State, ev.Reason)
	}
}

// A mapping without a rolling window is evaluated exactly as before: the
// cycle's own end of support date and the 90 day window.
func TestNonRollingMappingUnchanged(t *testing.T) {
	now := clock("2026-09-29 12:00")
	p := chromeRolling(now.Add(-time.Hour))
	for _, c := range []struct {
		version string
		state   string
		days    int
	}{
		{"154.0.1", StateEndingSoon, 7},
		{"153.0.1", StateUnsupported, -7},
		{"152.0.1", StateUnsupported, -21},
	} {
		ev := Evaluate(plainRef("chrome"), p, c.version, nil, now)
		if ev.State != c.state {
			t.Errorf("%s = %s, want %s", c.version, ev.State, c.state)
		}
		if ev.DaysToEOL == nil || *ev.DaysToEOL != c.days {
			t.Errorf("%s days_to_eol = %v, want %d", c.version, deref(ev.DaysToEOL), c.days)
		}
		if ev.Note != "" {
			t.Errorf("%s: a plain mapping gained a note %q", c.version, ev.Note)
		}
		want, wantDays, _ := CycleState(*ev.Cycle, now)
		if ev.State != want || deref(ev.DaysToEOL) != deref(wantDays) {
			t.Errorf("%s: Evaluate disagrees with CycleState", c.version)
		}
		if ev.Cycle.EOLDate == nil {
			t.Errorf("%s: a plain mapping lost its end date", c.version)
		}
	}
	// An explicit zero window is the same as no window.
	zero := &MappingRef{Slug: "chrome", Rule: Rule{Kind: RuleMajor}, RollingWindowDays: 0}
	if ev := Evaluate(zero, p, "154.0.1", nil, now); ev.State != StateEndingSoon {
		t.Errorf("zero window = %s, want ending_within_90_days", ev.State)
	}
}

func TestProposeInputRolling(t *testing.T) {
	base := func() ProposeInput {
		return ProposeInput{Platform: "windows", IdentityKind: "windows_winget", IdentityValue: "Google.Chrome",
			Slug: "chrome", VersionRule: RuleMajor}
	}
	n := func(i int) *int { return &i }

	in := base()
	if err := in.Validate(); err != nil || in.RollingWindowDays != nil {
		t.Fatalf("plain proposal: err=%v days=%v, want valid and not rolling", err, in.RollingWindowDays)
	}

	in = base()
	in.Rolling = true
	if err := in.Validate(); err != nil {
		t.Fatalf("rolling with the default window refused: %v", err)
	}
	if in.RollingWindowDays == nil || *in.RollingWindowDays != DefaultRollingWindowDays {
		t.Errorf("rolling without a window = %v, want the default %d", in.RollingWindowDays, DefaultRollingWindowDays)
	}

	in = base()
	in.Rolling, in.RollingWindowDays = true, n(14)
	if err := in.Validate(); err != nil || *in.RollingWindowDays != 14 {
		t.Errorf("rolling with 14 days: err=%v days=%v", err, in.RollingWindowDays)
	}

	for _, bad := range []struct {
		name   string
		mutate func(*ProposeInput)
		want   string
	}{
		{"window without rolling", func(p *ProposeInput) { p.RollingWindowDays = n(21) }, "rolling"},
		{"zero window", func(p *ProposeInput) { p.Rolling, p.RollingWindowDays = true, n(0) }, "between 1 and"},
		{"negative window", func(p *ProposeInput) { p.Rolling, p.RollingWindowDays = true, n(-3) }, "between 1 and"},
		{"window over the cap", func(p *ProposeInput) { p.Rolling, p.RollingWindowDays = true, n(MaxRollingWindowDays+1) }, "between 1 and"},
		{"operating system", func(p *ProposeInput) {
			p.IdentityKind, p.VersionRule, p.Rolling = IdentityKindOS, RuleWindowsBuild, true
		}, "application"},
	} {
		in := base()
		bad.mutate(&in)
		err := in.Validate()
		if err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s: err = %v, want one mentioning %q", bad.name, err, bad.want)
		}
	}
}
