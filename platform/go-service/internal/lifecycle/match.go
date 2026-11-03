package lifecycle

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Support states.
const (
	StateSupported   = "supported"
	StateEndingSoon  = "ending_within_90_days"
	StateUnsupported = "unsupported"
	StateUnknown     = "unknown"
)

// States in report order: the worst first.
var States = []string{StateUnsupported, StateEndingSoon, StateUnknown, StateSupported}

// EndingWindowDays is how close an end of support date must be for the
// Ending within 90 days state. A date exactly EndingWindowDays away is
// inside the window; today or earlier is Unsupported.
const EndingWindowDays = 90

// DefaultRollingWindowDays is how long the previous major release of a
// rolling-release product (a browser) keeps reading Supported after a new
// major ships (PAT-2171). Vendors stage a new major over about two weeks and
// auto-update lands within about three, so a device still on the previous
// major inside three weeks is mid-rollout, not neglected; from 21 days on it
// has had every chance to update. Stored per mapping
// (lifecycle_mappings.rolling_window_days); this is the value a mapping gets
// when it opts in without naming its own.
const DefaultRollingWindowDays = 21

// MaxRollingWindowDays caps a mapping's window. A longer grace would make the
// previous major supported for months, which is not a rolling release.
const MaxRollingWindowDays = 90

// CacheTTL is how long fetched lifecycle data may be used. Older data is
// stale and every row relying on it reads Unknown.
const CacheTTL = 7 * 24 * time.Hour

// SourceName names the lifecycle data source on every report row.
const SourceName = "endoflife.date"

// Unknown reasons. The code is stable for clients; ReasonText is the
// customer wording.
const (
	ReasonNoMapping         = "no_published_mapping"
	ReasonNotFetched        = "lifecycle_not_fetched"
	ReasonStale             = "lifecycle_stale"
	ReasonVersionMissing    = "version_not_reported"
	ReasonVersionUnmatched  = "version_not_matched"
	ReasonEditionUnknown    = "edition_unknown"
	ReasonEditionNotCovered = "edition_not_covered"
	ReasonNoEOLData         = "no_end_of_support_data"
	ReasonNoReleaseData     = "no_release_data"
)

// ReasonText is the plain-English reason for each Unknown code.
var ReasonText = map[string]string{
	ReasonNoMapping:         "no published lifecycle mapping for this product",
	ReasonNotFetched:        "lifecycle data not yet fetched",
	ReasonStale:             "lifecycle data older than 7 days",
	ReasonVersionMissing:    "installed version not reported",
	ReasonVersionUnmatched:  "version not matched to a support cycle",
	ReasonEditionUnknown:    "Windows edition not reported, and support dates differ by edition",
	ReasonEditionNotCovered: "this Windows edition is not covered by the lifecycle source",
	ReasonNoEOLData:         "the lifecycle source gives no end of support for this cycle",
	ReasonNoReleaseData:     "the lifecycle source gives no usable release date for this cycle",
}

// Version rules.
const (
	RuleMajor        = "major"
	RuleMajorMinor   = "major_minor"
	RuleRegex        = "regex"
	RuleMacOSMajor   = "macos_major"
	RuleWindowsBuild = "windows_build"
)

// Cycle is one release cycle as fetched.
type Cycle struct {
	Name                string
	Label               string
	ReleaseDate         *time.Time
	EOLDate             *time.Time
	IsEOL               *bool
	SupportDate         *time.Time
	ExtendedSupportDate *time.Time
	LatestVersion       string
	IsLTS               bool
}

// Product is one endoflife.date product with its cycles. FetchedAt is nil
// when no fetch has ever succeeded.
type Product struct {
	Slug      string
	Label     string
	HTMLURL   string
	FetchedAt *time.Time
	Cycles    []Cycle
}

// Rule is a mapping's version-to-cycle rule.
type Rule struct {
	Kind  string
	Regex string // RuleRegex only: one capture group, the cycle name
}

var (
	majorRE      = regexp.MustCompile(`^\s*[vV]?(\d{1,9})(?:[.\-_+ ]|$)`)
	majorMinorRE = regexp.MustCompile(`^\s*[vV]?(\d{1,9})\.(\d{1,9})(?:[.\-_+ ]|$)`)
)

// ValidateRegex checks a regex rule: it must compile and have exactly one
// capture group, whose match is the cycle name.
func ValidateRegex(pattern string) error {
	if strings.TrimSpace(pattern) == "" || len(pattern) > 200 {
		return fmt.Errorf("version_regex must be 1 to 200 characters")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("version_regex does not compile: %v", err)
	}
	if re.NumSubexp() != 1 {
		return fmt.Errorf("version_regex must have exactly one capture group (the cycle), has %d", re.NumSubexp())
	}
	return nil
}

func trimInt(s string) (string, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return "", false
	}
	return strconv.Itoa(n), true
}

// CycleKey maps an installed version to a cycle name under an application
// rule (major, major_minor, regex) or the macOS rule. It reports false when
// the version does not parse; the caller then states Unknown ("version not
// matched to a support cycle"), never a guess.
//
//	major        "154.0.8037.58" -> "154"; "8.0.402.6" -> "8"
//	major_minor  "3.12.4" -> "3.12"; "26.2.5.2" -> "26.2"
//	regex        first capture group, lower-cased ("^1\.(8)\." on "1.8.0.482" -> "8")
//	macos_major  "15.4.1" -> "15"; "10.15.7" -> "10.15" (macOS 10 cycles are major.minor)
func CycleKey(rule Rule, version string) (string, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return "", false
	}
	switch rule.Kind {
	case RuleMajor:
		m := majorRE.FindStringSubmatch(version)
		if m == nil {
			return "", false
		}
		return trimInt(m[1])
	case RuleMajorMinor:
		m := majorMinorRE.FindStringSubmatch(version)
		if m == nil {
			return "", false
		}
		a, ok1 := trimInt(m[1])
		b, ok2 := trimInt(m[2])
		if !ok1 || !ok2 {
			return "", false
		}
		return a + "." + b, true
	case RuleRegex:
		re, err := regexp.Compile(rule.Regex)
		if err != nil || re.NumSubexp() != 1 {
			return "", false
		}
		m := re.FindStringSubmatch(version)
		if m == nil || strings.TrimSpace(m[1]) == "" {
			return "", false
		}
		return strings.ToLower(strings.TrimSpace(m[1])), true
	case RuleMacOSMajor:
		m := majorMinorRE.FindStringSubmatch(version)
		if m == nil {
			// "15" alone is a valid major.
			mm := majorRE.FindStringSubmatch(version)
			if mm == nil {
				return "", false
			}
			major, ok := trimInt(mm[1])
			if !ok || major == "10" {
				return "", false
			}
			return major, true
		}
		major, ok1 := trimInt(m[1])
		minor, ok2 := trimInt(m[2])
		if !ok1 || !ok2 {
			return "", false
		}
		if major == "10" {
			return "10." + minor, true
		}
		return major, true
	}
	return "", false
}

var (
	windowsFullRE  = regexp.MustCompile(`^\s*(\d{1,2})\.(\d{1,2})\.(\d{3,6})(?:\.(\d{1,6}))?\s*$`)
	windowsBuildRE = regexp.MustCompile(`^\s*(\d{4,6})(?:\.(\d{1,6}))?\s*$`)
)

// WindowsBuild extracts the Windows build number from the device's
// os_version or os_build. The agent reports either "10.0.19045" /
// "10.0.19045.4529" or a bare "19045.4529"; a marketing name such as "22H2"
// carries no build and is skipped in favour of the other field.
func WindowsBuild(osVersion, osBuild string) (int, bool) {
	for _, s := range []string{osVersion, osBuild} {
		if m := windowsFullRE.FindStringSubmatch(s); m != nil {
			n, err := strconv.Atoi(m[3])
			if err == nil {
				return n, true
			}
		}
		if m := windowsBuildRE.FindStringSubmatch(s); m != nil {
			n, err := strconv.Atoi(m[1])
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// Windows edition classes, as endoflife.date's cycle suffixes name them.
const (
	EditionAny           = ""        // a cycle with no suffix applies to every edition
	EditionEnterprise    = "e"       // Enterprise, Education, IoT Enterprise (non-LTSC)
	EditionWorkstation   = "w"       // Home, Pro, Pro Education, Pro for Workstations
	EditionEnterpriseLTS = "e-lts"   // Enterprise LTSC / LTSB
	EditionIoTLTS        = "iot-lts" // IoT Enterprise LTSC
)

// WindowsEdition classifies the device's WMI caption into the edition class
// that decides which Windows cycle applies. known is false when the caption
// is absent or unrecognised; covered is false for editions the endoflife.date
// "windows" product does not describe (Windows Server has its own product).
// Microsoft's lifecycle policy gives Enterprise, Education and IoT
// Enterprise 36 months per feature release and Home, Pro, Pro Education and
// Pro for Workstations 24, which is why "Pro Education" is checked before
// "Education".
func WindowsEdition(caption string) (edition string, known, covered bool) {
	c := strings.ToLower(strings.Join(strings.Fields(caption), " "))
	switch {
	case c == "":
		return "", false, true
	case strings.Contains(c, "server"):
		return "", true, false
	case strings.Contains(c, "ltsc") || strings.Contains(c, "ltsb"):
		if strings.Contains(c, "iot") {
			return EditionIoTLTS, true, true
		}
		return EditionEnterpriseLTS, true, true
	case strings.Contains(c, "pro education"):
		return EditionWorkstation, true, true
	case strings.Contains(c, "education"), strings.Contains(c, "enterprise"):
		return EditionEnterprise, true, true
	case strings.Contains(c, "home"), strings.Contains(c, " pro"):
		return EditionWorkstation, true, true
	}
	return "", false, true
}

// windowsCycleEdition reads the edition suffix of an endoflife.date Windows
// cycle name: "11-24h2-e" -> "e", "10-21h2-e-lts" -> "e-lts",
// "11-24h2-iot-lts" -> "iot-lts", "10-22h2" -> "" (every edition).
func windowsCycleEdition(name string) string {
	parts := strings.Split(strings.ToLower(name), "-")
	if len(parts) <= 2 {
		return EditionAny
	}
	return strings.Join(parts[2:], "-")
}

// Match is the outcome of choosing a cycle for one installation.
type Match struct {
	Cycle  *Cycle
	Reason string // set when Cycle is nil
}

// MatchVersion chooses the cycle for an application or macOS version.
func MatchVersion(rule Rule, cycles []Cycle, version string) Match {
	if strings.TrimSpace(version) == "" {
		return Match{Reason: ReasonVersionMissing}
	}
	key, ok := CycleKey(rule, version)
	if !ok {
		return Match{Reason: ReasonVersionUnmatched}
	}
	for i := range cycles {
		if strings.EqualFold(cycles[i].Name, key) {
			return Match{Cycle: &cycles[i]}
		}
	}
	return Match{Reason: ReasonVersionUnmatched}
}

// MatchWindows chooses the Windows cycle for a device: the build number
// selects the feature release (cycles whose latest version is 10.0.BUILD),
// and the edition from the caption selects between that release's edition
// cycles. When the edition is unknown the cycle is used only if every
// candidate has the same end of support; otherwise Unknown, never a guess.
func MatchWindows(cycles []Cycle, osVersion, osBuild, caption string) Match {
	if strings.TrimSpace(osVersion) == "" && strings.TrimSpace(osBuild) == "" {
		return Match{Reason: ReasonVersionMissing}
	}
	build, ok := WindowsBuild(osVersion, osBuild)
	if !ok {
		return Match{Reason: ReasonVersionUnmatched}
	}
	var candidates []*Cycle
	for i := range cycles {
		if b, ok := WindowsBuild(cycles[i].LatestVersion, ""); ok && b == build {
			candidates = append(candidates, &cycles[i])
		}
	}
	if len(candidates) == 0 {
		return Match{Reason: ReasonVersionUnmatched}
	}
	edition, known, covered := WindowsEdition(caption)
	if !covered {
		return Match{Reason: ReasonEditionNotCovered}
	}
	if known {
		var exact, any []*Cycle
		for _, c := range candidates {
			switch windowsCycleEdition(c.Name) {
			case edition:
				exact = append(exact, c)
			case EditionAny:
				any = append(any, c)
			}
		}
		pick := exact
		if len(pick) == 0 {
			pick = any
		}
		if len(pick) == 0 {
			return Match{Reason: ReasonVersionUnmatched}
		}
		if !sameEnd(pick) {
			return Match{Reason: ReasonEditionUnknown}
		}
		return Match{Cycle: pick[0]}
	}
	if !sameEnd(candidates) {
		return Match{Reason: ReasonEditionUnknown}
	}
	return Match{Cycle: candidates[0]}
}

func sameEnd(cs []*Cycle) bool {
	for _, c := range cs[1:] {
		if !sameDate(c.EOLDate, cs[0].EOLDate) || !sameBool(c.IsEOL, cs[0].IsEOL) {
			return false
		}
	}
	return true
}

func sameDate(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func sameBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// dateOnly returns t's calendar date at midnight UTC.
func dateOnly(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// CycleState is the support state of one cycle on the date of now (UTC).
// With an end of support date: that date or earlier is Unsupported (the
// source's date is the first day without support), 1 to EndingWindowDays
// days away is Ending within 90 days, later is Supported. With no date the
// source's own flag decides; with neither, Unknown. daysToEOL is set
// whenever there is a date (negative once passed).
func CycleState(c Cycle, now time.Time) (state string, daysToEOL *int, reason string) {
	today := dateOnly(now)
	if c.EOLDate != nil {
		days := int(dateOnly(*c.EOLDate).Sub(today).Hours() / 24)
		switch {
		case days <= 0:
			return StateUnsupported, &days, ""
		case days <= EndingWindowDays:
			return StateEndingSoon, &days, ""
		default:
			return StateSupported, &days, ""
		}
	}
	if c.IsEOL != nil {
		if *c.IsEOL {
			return StateUnsupported, nil, ""
		}
		return StateSupported, nil, ""
	}
	return StateUnknown, nil, ReasonNoEOLData
}

// releasedByNewest returns the cycles that have a release date on or before
// today, newest release first. A cycle with no release date, or one the
// source has announced but not yet shipped, cannot be placed in release order
// and is left out. Ties on the date fall back to the higher cycle name, so
// the order never depends on how the source happened to list them.
func releasedByNewest(cycles []Cycle, today time.Time) []*Cycle {
	var out []*Cycle
	for i := range cycles {
		if r := cycles[i].ReleaseDate; r != nil && !dateOnly(*r).After(today) {
			out = append(out, &cycles[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := dateOnly(*out[i].ReleaseDate), dateOnly(*out[j].ReleaseDate)
		if !a.Equal(b) {
			return a.After(b)
		}
		return cycleNameGreater(out[i].Name, out[j].Name)
	})
	return out
}

// cycleNameGreater orders cycle names numerically when both are whole
// numbers ("154" above "99"), otherwise as text.
func cycleNameGreater(a, b string) bool {
	x, errA := strconv.Atoi(a)
	y, errB := strconv.Atoi(b)
	if errA == nil && errB == nil && x != y {
		return x > y
	}
	return a > b
}

// RollingCycleState is the support state of one cycle of a rolling-release
// product on the date of now (UTC), for a mapping that opted in with
// windowDays (PAT-2171). The source dates every major release as ending when
// the next one ships, about two to four weeks out, so the ordinary rule would
// read every current install as "Ending within 90 days". Release order
// decides instead:
//
//   - the latest released major is Supported;
//   - the previous major is Supported while the latest is under windowDays
//     old (in whole UTC days from its release date; a day count equal to
//     windowDays is already outside the window), Unsupported after;
//   - every older major is Unsupported.
//
// It never returns Ending within 90 days. Channels the source keeps as their
// own cycles (Firefox ESR, flagged is_lts) are not judged here: the caller
// gives them CycleState. They do count in release order, so a newest release
// that is itself an ESR still ranks as the latest major. A cycle that cannot
// be placed in release order is Unknown with ReasonNoReleaseData, never a
// guess. The note is customer wording that says what the state rests on.
func RollingCycleState(c Cycle, cycles []Cycle, windowDays int, now time.Time) (state, reason, note string) {
	today := dateOnly(now)
	released := releasedByNewest(cycles, today)
	rank := -1
	for i, r := range released {
		if strings.EqualFold(r.Name, c.Name) {
			rank = i
			break
		}
	}
	if rank < 0 {
		return StateUnknown, ReasonNoReleaseData, ""
	}
	const basis = "Support for this product is judged by release order, not an end date: " +
		"the newest major version counts as supported, and so does the previous one for a short time after a new release."
	switch rank {
	case 0:
		return StateSupported, "", "Latest release. " + basis
	case 1:
		age := int(today.Sub(dateOnly(*released[0].ReleaseDate)).Hours() / 24)
		if age < windowDays {
			return StateSupported, "", fmt.Sprintf("Previous release, still inside the %d days after the latest release. %s", windowDays, basis)
		}
		return StateUnsupported, "", fmt.Sprintf("Previous release, outside the %d days after the latest release. %s", windowDays, basis)
	}
	return StateUnsupported, "", "Older than the previous release. " + basis
}

// Evaluation is the full answer for one installation or OS.
type Evaluation struct {
	State         string
	Reason        string // Unknown only
	Cycle         *Cycle
	DaysToEOL     *int
	LastCheckedAt *time.Time // nil when there is no published mapping or no fetch
	Slug          string     // "" when there is no published mapping
	SourceURL     string
	Note          string
}

// MappingRef is what Evaluate needs of a published mapping.
type MappingRef struct {
	Slug string
	Rule Rule
	// RollingWindowDays opts the mapping into the rolling-release rule
	// (PAT-2171) when above zero; zero is the ordinary end of support rule.
	RollingWindowDays int
}

// OSInput carries the device OS facts for an 'os' mapping.
type OSInput struct {
	Version string
	Build   string
	Caption string
}

// Evaluate decides one installation's state. mapping is nil when no
// published mapping covers the product; product is nil when the slug has
// never been fetched. os is used only for the OS rules. The checks run in
// this order so the reason names the first missing piece of evidence: no
// mapping, no data, stale data, version, then the cycle's own dates.
func Evaluate(mapping *MappingRef, product *Product, version string, os *OSInput, now time.Time) Evaluation {
	if mapping == nil {
		return Evaluation{State: StateUnknown, Reason: ReasonNoMapping}
	}
	ev := Evaluation{Slug: mapping.Slug, SourceURL: "https://endoflife.date/" + mapping.Slug}
	if product == nil || product.FetchedAt == nil {
		ev.State, ev.Reason = StateUnknown, ReasonNotFetched
		return ev
	}
	if product.HTMLURL != "" {
		ev.SourceURL = product.HTMLURL
	}
	fetched := product.FetchedAt.UTC()
	ev.LastCheckedAt = &fetched
	if now.Sub(fetched) > CacheTTL {
		ev.State, ev.Reason = StateUnknown, ReasonStale
		return ev
	}
	var m Match
	switch mapping.Rule.Kind {
	case RuleWindowsBuild:
		if os == nil {
			m = Match{Reason: ReasonVersionMissing}
		} else {
			m = MatchWindows(product.Cycles, os.Version, os.Build, os.Caption)
		}
	case RuleMacOSMajor:
		v := version
		if os != nil {
			v = os.Version
		}
		m = MatchVersion(mapping.Rule, product.Cycles, v)
	default:
		m = MatchVersion(mapping.Rule, product.Cycles, version)
	}
	if m.Cycle == nil {
		ev.State, ev.Reason = StateUnknown, m.Reason
		return ev
	}
	ev.Cycle = m.Cycle
	if mapping.RollingWindowDays > 0 && !m.Cycle.IsLTS {
		// A rolling-release product (PAT-2171). An is_lts cycle (Firefox
		// ESR) is a separate channel with its own end of support date and
		// takes the ordinary rule below.
		ev.State, ev.Reason, ev.Note = RollingCycleState(*m.Cycle, product.Cycles, mapping.RollingWindowDays, now)
		if ev.State == StateSupported {
			// The source's date is when the next major ships, not an end of
			// support. Showing it beside Supported would read as a warning.
			c := *m.Cycle
			c.EOLDate = nil
			ev.Cycle = &c
		}
	} else {
		ev.State, ev.DaysToEOL, ev.Reason = CycleState(*m.Cycle, now)
	}
	if ev.State == StateUnsupported && ev.Note == "" && m.Cycle.ExtendedSupportDate != nil &&
		dateOnly(*m.Cycle.ExtendedSupportDate).After(dateOnly(now)) {
		ev.Note = "paid extended security updates are available until " +
			m.Cycle.ExtendedSupportDate.UTC().Format("2006-01-02") + "; enrolment is not evidenced"
	}
	return ev
}
