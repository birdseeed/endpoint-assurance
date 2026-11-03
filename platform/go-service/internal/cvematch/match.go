// Package cvematch implements the pure, stateless CVE match engine used by
// both the agent-fed nightly sync (cmd/patched-cve-sync) and the stateless
// import-fed scan path (cmd/patched-import-scan).
package cvematch

import (
	"regexp"
	"strings"
	"time"
)

// ScannedApp is a name/version pair representing one installed application.
type ScannedApp struct {
	Name    string
	Version string
}

// CPERange holds the version bounds for one (vendor, product) pair in a CVE.
// Empty string means the bound is absent/open-ended.
//
// Version, TargetSW and RunningOn were added by PAT-2107 so the matcher can
// tell an exact-version CPE, and a CPE that only applies on another platform,
// from "every version everywhere". They are omitempty: a cpe_ranges row
// written before PAT-2107 decodes with all three empty and matches exactly as
// it did before.
type CPERange struct {
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	VStartIncl string `json:"vStartIncl"`
	VStartExcl string `json:"vStartExcl"`
	VEndIncl   string `json:"vEndIncl"`
	VEndExcl   string `json:"vEndExcl"`
	// Version is the CPE's own version field (field 5) when it names one
	// exact version, i.e. is neither "*" (any) nor "-" (not applicable).
	Version string `json:"version,omitempty"`
	// TargetSW is the CPE's target_sw field (field 10), lowercased: the
	// software environment the product runs in ("windows", "android",
	// "macos", ...). Empty when the CPE says "*" (any).
	TargetSW string `json:"targetSW,omitempty"`
	// RunningOn lists the "vendor:product" keys of the non-vulnerable
	// operating-system CPEs (cpe:2.3:o:...) this CPE is ANDed with in its NVD
	// configuration: the product is only vulnerable when running on one of
	// them. Empty when the configuration has no such AND.
	RunningOn []string `json:"runningOn,omitempty"`
}

// CPEMapping maps an app display-name key to a CPE (vendor, product) pair.
//
// Platform is app_cpe_mappings.platform's vocabulary: "any", "macos" or
// "windows" (PAT-2029). A zero-value "" is treated the same as "any" by
// MappingApplies so callers that build a CPEMapping without a live platform
// column (e.g. HomebrewMapping.cpe(), which never varies by platform because
// Homebrew is macOS-only by source) are unaffected.
//
// ReviewState is app_cpe_mappings.review_state (PAT-2138): "curated" (or ""
// for a caller that does not load it) for a mapping a person entered or
// approved, "auto" for one the proposer published automatically. It is
// carried through to Finding.MappingBasis so an automatic finding is never
// presented as a curated one.
type CPEMapping struct {
	MatchName   string
	CPEVendor   string
	CPEProduct  string
	Platform    string
	ReviewState string
}

// Mapping bases a Finding can carry (device_cve_findings.mapping_basis).
const (
	MappingBasisCurated = "curated"
	MappingBasisAuto    = "auto"
)

// ReviewStateAuto is app_cpe_mappings.review_state for an automatically
// published mapping (PAT-2138).
const ReviewStateAuto = "auto"

// Basis is the finding basis this mapping produces: auto for an
// automatically published mapping, curated for everything else.
func (m CPEMapping) Basis() string {
	if m.ReviewState == ReviewStateAuto {
		return MappingBasisAuto
	}
	return MappingBasisCurated
}

// CVEEntry is a single CVE from the feed.
type CVEEntry struct {
	CVEID       string
	Description string
	Score       *float64
	Severity    string
	Patterns    []string   // normalised "vendor:product" product-level prefilter keys
	Ranges      []CPERange // per-product version bounds; empty = no usable range data
	// PublishedAt is cve_feed_entries.published_at. Zero when unknown, which
	// never triggers the unverified age cut (unverifiedMaxAge).
	PublishedAt time.Time
}

// Finding is one CVE matched against one installed app.
type Finding struct {
	CVEID           string
	Score           *float64
	Severity        string
	AppName         string
	AppVersion      string
	MatchConfidence string // "version_confirmed" | "version_unverified"
	// FixedVersion is the first version NOT vulnerable (VEndExcl) for the
	// CPE range that matched this finding. Empty when unknown: no range
	// data (MatchConfidence == "version_unverified"), or the matched range
	// was open-ended (no VEndExcl bound).
	FixedVersion string
	// MappingBasis is the Basis of the mapping that produced this finding
	// (PAT-2138): curated or auto. See FindingBases for the per-(CVE, app)
	// rollup a writer must use when several mappings produce one finding.
	MappingBasis string
}

// FindingKey identifies one stored finding row for a device.
type FindingKey struct{ CVEID, AppName string }

// FindingBases rolls the bases of findings up per (CVE, app), the key
// device_cve_findings stores one row under: auto only when every mapping
// that produced it is automatic, curated as soon as one curated mapping
// produced it too. A writer stores MappingBasisAuto for exactly the keys
// that map to it here, so a finding a person's mapping also supports is
// never labelled automatic.
func FindingBases(findings []Finding) map[FindingKey]string {
	out := make(map[FindingKey]string, len(findings))
	for _, f := range findings {
		k := FindingKey{f.CVEID, f.AppName}
		basis := f.MappingBasis
		if basis != MappingBasisAuto {
			basis = MappingBasisCurated
		}
		if prev, ok := out[k]; ok && prev == MappingBasisCurated {
			continue
		}
		out[k] = basis
	}
	return out
}

var nonAlphanumRe = regexp.MustCompile(`[^a-zA-Z0-9]+`)
var digitGroupRe = regexp.MustCompile(`\d+`)

// appNameTokens splits a display name into lowercase word tokens.
// "GitHub Desktop" → ["github", "desktop"]
// "Dropbox"        → ["dropbox"]
func appNameTokens(name string) []string {
	raw := nonAlphanumRe.Split(strings.ToLower(name), -1)
	out := raw[:0]
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// wordTokenMatch returns true when every token of matchName appears in
// appName, in the same relative order, though not necessarily adjacent
// (an ordered subsequence). Matching is whole-word-token, not substring, so
// "Box" still does not match "Dropbox" and "Git" still does not match
// "GitHub Desktop" - "box" and "git" never appear as their own token in
// appTokens, they only exist as parts of the larger tokens "dropbox" and
// "github". Allowing tokens to be non-adjacent lets legitimate names with
// interior words - e.g. matchName "Adobe Reader" against appName "Adobe
// Acrobat Reader DC" - match correctly.
func wordTokenMatch(appName, matchName string) bool {
	appTokens := appNameTokens(appName)
	keyTokens := appNameTokens(matchName)
	if len(keyTokens) == 0 || len(appTokens) < len(keyTokens) {
		return false
	}
	ki := 0
	for _, at := range appTokens {
		if at == keyTokens[ki] {
			ki++
			if ki == len(keyTokens) {
				return true
			}
		}
	}
	return false
}

// osPseudoAppNames are the device_apps / app_cpe_mappings.match_name display
// names that stand in for the device's operating system itself, not an
// installed application (PAT-409, PAT-2024): "macOS" carries the
// apple:macos / apple:mac_os_x CPE mappings, "Windows" the
// microsoft:windows_10 / microsoft:windows_11 ones, so the nightly full match
// (cmd/patched-cve-sync) can give the OS pseudo-app an NVD CPE fallback where
// no vendor advisory (internal/oscve) exists.
//
// This is a second copy of the canonical list in internal/cvelifecycle
// (cvelifecycle.OSPseudoAppNames); cvematch is documented as a pure,
// dependency-free engine shared by the DB-fed and import-scan paths, so it
// does not import cvelifecycle's DB/notification graph for two strings. Any
// change to the canonical set must change this one in the same commit —
// TestOSPseudoAppNamesStaysInSyncWithCvelifecycle in match_test.go pins the
// two lists equal.
var osPseudoAppNames = map[string]bool{"macOS": true, "Windows": true}

func isOSPseudoAppName(name string) bool { return osPseudoAppNames[name] }

// appMatchesMapping decides whether one mapping covers one app display name.
//
// An OS mapping — one whose MatchName is itself an OS pseudo-app name — only
// covers the OS pseudo-app of the same name, by exact equality, never by
// wordTokenMatch's ordered-subsequence rule. Without this, a real installed
// application whose name merely contains the word "Windows" or "macOS" as a
// token — "Windows App", "Windows Subsystem for Linux", a hypothetical
// "macOS Utility" — would satisfy wordTokenMatch against the "Windows" /
// "macOS" mapping and get matched against OS-build CPE version ranges using
// its own, unrelated version number.
//
// The same equality gate applies symmetrically when appName is itself an OS
// pseudo-app name: the OS pseudo-app may only match an OS mapping of the same
// name, never a differently-named mapping through word tokens (e.g. a
// hypothetical "macOS Server" mapping). wordTokenMatch already refuses that
// case on token length (a single-token pseudo-app name can never satisfy a
// longer matchName), but the equality gate makes the rule explicit rather
// than relying on that as an accidental side effect.
//
// Every other pairing (neither side an OS pseudo-app name) is unchanged:
// wordTokenMatch's whole-word, ordered-subsequence rule.
func appMatchesMapping(appName, matchName string) bool {
	if isOSPseudoAppName(matchName) || isOSPseudoAppName(appName) {
		return appName == matchName
	}
	return wordTokenMatch(appName, matchName)
}

// splitVersion extracts numeric components from a version string.
// "120.0.6099.130" → ["120","0","6099","130"]
// "1.2.3-beta"     → ["1","2","3"]  (non-numeric segments ignored)
// ""               → nil
func splitVersion(v string) []string {
	if v == "" {
		return nil
	}
	return digitGroupRe.FindAllString(v, -1)
}

// cmpNumericString compares two strings known to consist of digits only.
// Both inputs must be non-empty. Leading zeros are stripped before compare.
func cmpNumericString(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// CompareVersions is the exported form of compareVersions. Other packages
// (e.g. internal/report, folding multiple FixedVersion values down to a
// "maximum" target version) reuse this comparator rather than duplicating
// version-comparison logic. To fold to a maximum, use MaxVersion, which also
// breaks ties deterministically.
func CompareVersions(a, b string) int {
	return compareVersions(a, b)
}

// CompareVersionsStrict exposes the certainty-preserving comparator for
// security version floors. Unknown or ambiguous version syntax returns false;
// callers must not substitute the total sort order for release authority.
func CompareVersionsStrict(a, b string) (int, bool) { return compareVersionsStrict(a, b) }

// MaxVersion returns the higher of a and b under compareVersions, treating ""
// as absent. Two different strings that compare equal ("2.0" and "2.0.0",
// or "1.2.3" and "1.2.3-beta") go to the lexicographically greater string,
// so folding a set of versions gives the same answer in any order (PAT-2044).
func MaxVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	c := compareVersions(a, b)
	if c > 0 || (c == 0 && a > b) {
		return a
	}
	return b
}

// compareVersions is the total ordering used where a caller needs an answer
// for every pair (folding fixed versions to a maximum, ordering kegs). It is
// a comparison of sort keys, so it is transitive for any mix of inputs:
//
//   - numeric components: the leading dot-separated digits (for a version in
//     the grammar, all of them), with trailing zero components dropped, so
//     2.0 == 2.0.0; compared left to right, a missing component is lower;
//   - then no letter suffix before a letter suffix, then the suffix itself;
//   - then, on a tie, every digit group in the string (compareDigitGroups).
//
// Letters after the leading digits of a version outside the grammar are
// ignored ("1.2.3-beta" == "1.2.3"); digits there are not (1.8.0_391 <
// 1.8.0_401). Wherever compareVersionsStrict gives an
// answer, this gives the same one; where it is unknown, this still picks an
// order, which is fine for folding and wrong for the CVE range gate, so the
// range gate never uses it. Returns -1, 0, or +1.
func compareVersions(a, b string) int {
	ka, kb := versionSortKey(a), versionSortKey(b)
	n := len(ka.nums)
	if len(kb.nums) < n {
		n = len(kb.nums)
	}
	for i := 0; i < n; i++ {
		if c := cmpNumericString(ka.nums[i], kb.nums[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ka.nums) < len(kb.nums):
		return -1
	case len(ka.nums) > len(kb.nums):
		return 1
	case ka.hasSuffix != kb.hasSuffix:
		if ka.hasSuffix {
			return 1
		}
		return -1
	}
	if c := strings.Compare(ka.suffix, kb.suffix); c != 0 {
		return c
	}
	return compareDigitGroups(a, b)
}

// compareDigitGroups breaks a sort-key tie by every digit group in the
// string, left to right, with trailing zero groups dropped, so tails the key
// ignores still order: 1.8.0_391 < 1.8.0_401, 8u391 < 8u401, 2.6.10-I001 <
// 2.6.10-I002, as the pre-PAT-2044 comparator (compareNumericOnly) ordered
// them. Dropping trailing zeros keeps 2.0 == 2.0.0, so two versions in the
// grammar with equal keys always tie here too and the strict comparator's
// equalities hold. Key first, then this, is a lexicographic combination of
// two total preorders, so compareVersions stays transitive.
func compareDigitGroups(a, b string) int {
	ga, gb := trimTrailingZeros(splitVersion(a)), trimTrailingZeros(splitVersion(b))
	for i := 0; i < len(ga) && i < len(gb); i++ {
		if c := cmpNumericString(ga[i], gb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ga) < len(gb):
		return -1
	case len(ga) > len(gb):
		return 1
	}
	return 0
}

type versionKey struct {
	nums      []string // trailing zero components dropped
	hasSuffix bool
	suffix    string
}

var leadingNumericRe = regexp.MustCompile(`^\d+(?:\.\d+)*`)

func versionSortKey(v string) versionKey {
	var k versionKey
	if p, ok := parseComparableVersion(v); ok {
		k.nums, k.hasSuffix, k.suffix = p.nums, p.suffix != "", p.suffix
	} else if m := leadingNumericRe.FindString(v); m != "" {
		k.nums = strings.Split(m, ".")
	}
	k.nums = trimTrailingZeros(k.nums)
	return k
}

func trimTrailingZeros(nums []string) []string {
	for len(nums) > 0 && cmpNumericString(nums[len(nums)-1], "0") == 0 {
		nums = nums[:len(nums)-1]
	}
	return nums
}

// compareNumericOnly is the pre-PAT-2044 comparator: every digit group
// anywhere in the string, left to right, shorter is lower. Nothing in the
// match path uses it; the tests keep it as the "old" side of the measured
// behaviour change.
func compareNumericOnly(a, b string) int {
	aParts := splitVersion(a)
	bParts := splitVersion(b)
	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		var ap, bp string
		if i < len(aParts) {
			ap = aParts[i]
		}
		if i < len(bParts) {
			bp = bParts[i]
		}
		if ap == "" && bp != "" {
			return -1
		}
		if ap != "" && bp == "" {
			return 1
		}
		if ap == "" && bp == "" {
			continue
		}
		if c := cmpNumericString(ap, bp); c != 0 {
			return c
		}
	}
	return 0
}

// comparableVersionRe is the grammar the strict comparator accepts (PAT-2044):
// dot-separated decimal components, optionally followed on the last
// component, with no separator, by one OpenSSL-style letter suffix: a single
// letter ("1.1.1t") or "z" plus one letter ("0.9.8za", used once "z" is
// spent). Case-insensitive.
//
// Everything else is outside the grammar, including every pre-release form:
// separated ("3.0.0-rc1", "1.0.0-beta", "2.0.rc1") and unseparated with a
// trailing number ("3.12.0rc1", "3.12.0b2", "4.2.8p15"). Those are ambiguous
// with the letter-suffix convention (is "b" a beta, before the release, or
// the second patch letter, after it?), so the comparator does not guess. An
// installed version outside the grammar can still be ordered against a bound
// by its leading numbers alone (compareInstalledToBound).
var comparableVersionRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)([A-Za-z]|[Zz][A-Za-z])?$`)

type parsedVersion struct {
	nums   []string
	suffix string // "" or the lowercased letter suffix
}

func parseComparableVersion(v string) (parsedVersion, bool) {
	m := comparableVersionRe.FindStringSubmatch(v)
	if m == nil {
		return parsedVersion{}, false
	}
	return parsedVersion{nums: strings.Split(m[1], "."), suffix: strings.ToLower(m[2])}, true
}

// compareVersionsStrict orders two versions only when the order is certain.
// ok is false ("unknown") when either version is outside comparableVersionRe,
// or in the one grammar case whose order depends on convention.
//
// The rule, for a and b both in the grammar:
//
//  1. Compare the numeric components left to right, a missing trailing
//     component counting as zero (2.0 == 2.0.0, 1.1 == 1.1.0.0). The first
//     difference decides, whatever the suffixes, unless it falls on a
//     padded zero of the side with the letter suffix ("1.1a" against
//     "1.1.1"): the letter may stand for that component, so that is unknown.
//  2. Same component count: no suffix sorts before any suffix, and suffixes
//     sort by letter, with "z" before "za" before "zb" (OpenSSL's order):
//     1.1.1 < 1.1.1a < 1.1.1s < 1.1.1t < 1.1.1z < 1.1.1za.
//  3. Different component count, numbers equal after padding:
//     - neither has a suffix: equal;
//     - only the longer has a suffix: the longer is higher (1.1 < 1.1.0a);
//     - the shorter has a suffix: unknown. "1.1.1a" against "1.1.1.0" is
//     unknown, as is "1.1a" against "1.1.0": the letter is attached to a
//     different component on each side.
func compareVersionsStrict(a, b string) (int, bool) {
	pa, okA := parseComparableVersion(a)
	pb, okB := parseComparableVersion(b)
	if !okA || !okB {
		return 0, false
	}
	n := len(pa.nums)
	if len(pb.nums) > n {
		n = len(pb.nums)
	}
	for i := 0; i < n; i++ {
		ap, bp := "0", "0"
		if i < len(pa.nums) {
			ap = pa.nums[i]
		}
		if i < len(pb.nums) {
			bp = pb.nums[i]
		}
		if c := cmpNumericString(ap, bp); c != 0 {
			// A padded zero standing in for a component the letter-suffixed
			// side does not have is not certain: "1.1a" against "1.1.1".
			if (i >= len(pa.nums) && pa.suffix != "") || (i >= len(pb.nums) && pb.suffix != "") {
				return 0, false
			}
			return c, true
		}
	}
	switch {
	case len(pa.nums) == len(pb.nums):
		return strings.Compare(pa.suffix, pb.suffix), true
	case len(pa.nums) < len(pb.nums):
		if pa.suffix != "" {
			return 0, false
		}
		if pb.suffix != "" {
			return -1, true
		}
		return 0, true
	default:
		if pb.suffix != "" {
			return 0, false
		}
		if pa.suffix != "" {
			return 1, true
		}
		return 0, true
	}
}

// versionPrefixRe matches a version outside the grammar whose leading
// dot-separated numbers are followed by a letter, "-", "+", "_", "~", a
// space, "(" or "." plus a letter: "115.13.0esr", "2.6.10-I001",
// "1.2.3 (x64)", "3.0.0-rc1", "3.12.0rc1", "9.8p1". Any other continuation
// (":" as in a Debian epoch, ",", "/") is not trusted to be a version prefix.
var versionPrefixRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)(?:[A-Za-z\-+_~ (]|\.[A-Za-z])`)

// certainNumbers returns the numeric components that can be trusted for the
// certain-prefix rule: all of them for a version in the grammar, the leading
// ones (versionPrefixRe) for any other, or nil.
func certainNumbers(v string) []string {
	if p, ok := parseComparableVersion(v); ok {
		return p.nums
	}
	if m := versionPrefixRe.FindStringSubmatch(v); m != nil {
		return strings.Split(m[1], ".")
	}
	return nil
}

// compareInstalledToBound is the range gate's comparison (PAT-2044):
//
//  1. identical strings are the same version (equal), whatever their shape:
//     9.8p1 against a bound of 9.8p1;
//  2. compareVersionsStrict, when both are in the grammar;
//  3. otherwise the certain-prefix rule, applied the same way to either
//     side: when the leading numbers (certainNumbers) of the two differ at a
//     position both actually have, that difference decides. "115.13.0esr"
//     is below 116.0, and 9.9p1 is above 9.8p1, whatever "esr" and "p1"
//     mean. When the numbers agree as far as both go (115.13.0esr against
//     115.13.0, 3.0.0-rc1 against 3.0.0, 9.8p2 against 9.8p1) the result is
//     unknown: a pre-release sorts below its release, a build or patch
//     suffix above it. No padding is applied, since the missing part is not
//     known to be zero.
func compareInstalledToBound(installed, bound string) (int, bool) {
	if installed == bound {
		return 0, true
	}
	if c, ok := compareVersionsStrict(installed, bound); ok {
		return c, true
	}
	if _, okI := parseComparableVersion(installed); okI {
		if _, okB := parseComparableVersion(bound); okB {
			return 0, false // both in the grammar and strict said unknown
		}
	}
	ni, nb := certainNumbers(installed), certainNumbers(bound)
	for i := 0; i < len(ni) && i < len(nb); i++ {
		if c := cmpNumericString(ni[i], nb[i]); c != 0 {
			return c, true
		}
	}
	return 0, false
}

var installedBuildSuffixRe = regexp.MustCompile(` \(\d+\)$`)

// normalizeInstalledVersion prepares an installed version (never an NVD
// bound) for the strict grammar. Exactly two rewrites, nothing else:
//
//   - one leading "v" or "V" directly followed by a digit is dropped
//     ("v2.0.3" -> "2.0.3");
//   - one trailing " (<digits>)" build suffix is dropped
//     ("7.0.0 (77593)" -> "7.0.0", Zoom's shape).
//
// "Build 4200", "Unknown" and "7.0.0 (abc)" are left as they are and so stay
// unknown to the comparator.
func normalizeInstalledVersion(v string) string {
	if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return installedBuildSuffixRe.ReplaceAllString(v, "")
}

// versionInRange checks whether installedVersion falls within any of the CPE
// ranges for the given (vendor, product) pair.
//
// The installed version is first put through normalizeInstalledVersion
// (bounds never are). Every bound comparison uses compareInstalledToBound. A range is in, out, or
// unknown: out as soon as one bound comparison certainly excludes the
// version, unknown if no bound excludes it but at least one comparison could
// not be made, in otherwise.
//
// A row with an exact Version (PAT-2107) is checked as the inclusive range
// [Version, Version], alongside any bounds it also has. A row with neither
// bounds nor an exact version is skipped: it cannot confirm or exclude a
// version. Platform filtering happens before this (compatibleRanges).
//
// Returns (matched, hasRanges, fixedVersion):
//   - (true,  true,  v)  → version falls within at least one vulnerable range →
//     version_confirmed; fixedVersion is the highest VEndExcl among every
//     matching range (installed version can legitimately fall inside more
//     than one vulnerable range for the same product — e.g. an LTS branch
//     range and a current branch range — and the customer must clear all of
//     them, so the target is the highest bound, not merely the first
//     matching range encountered), or "" when every matching range is
//     open-ended (no VEndExcl bound)
//   - (false, true,  "") → version certainly outside all ranges → not
//     vulnerable; skip finding
//   - (false, false, "") → no usable range bounds, or no range matched and
//     at least one was unknown (PAT-2044) → version_unverified. An unknown
//     comparison is never read as "not in range".
func versionInRange(installedVersion string, ranges []CPERange, vendor, product string) (matched, hasRanges bool, fixedVersion string) {
	// Unparseable installed version → can't check; emit as unverified
	if len(splitVersion(installedVersion)) == 0 {
		return false, false, ""
	}
	installedVersion = normalizeInstalledVersion(installedVersion)
	vp := strings.ToLower(vendor + ":" + product)
	anyUnknown := false
	for _, r := range ranges {
		if strings.ToLower(r.Vendor+":"+r.Product) != vp {
			continue
		}
		if r.VStartIncl == "" && r.VStartExcl == "" && r.VEndIncl == "" && r.VEndExcl == "" && r.Version == "" {
			// No bounds and no exact version ("-" or "*" in the CPE): the row
			// says nothing about versions, so it cannot confirm or exclude one.
			continue
		}
		hasRanges = true
		excluded, unknown := false, false
		check := func(bound string, outside func(c int) bool) {
			if excluded || bound == "" {
				return
			}
			c, ok := compareInstalledToBound(installedVersion, bound)
			if !ok {
				unknown = true
				return
			}
			if outside(c) {
				excluded = true
			}
		}
		check(r.VStartIncl, func(c int) bool { return c < 0 })
		check(r.VStartExcl, func(c int) bool { return c <= 0 })
		check(r.VEndIncl, func(c int) bool { return c > 0 })
		check(r.VEndExcl, func(c int) bool { return c >= 0 })
		// An exact-version CPE (PAT-2107) is the inclusive range [v, v],
		// through the same bound comparisons as any other range.
		check(r.Version, func(c int) bool { return c < 0 })
		check(r.Version, func(c int) bool { return c > 0 })

		switch {
		case excluded:
			// certainly outside this range
		case unknown:
			anyUnknown = true
		default:
			matched = true
			fixedVersion = MaxVersion(fixedVersion, r.VEndExcl)
			// Keep scanning: a later range may also match with a higher VEndExcl.
		}
	}
	if !matched && anyUnknown {
		return false, false, ""
	}
	return
}

// Match is the pure, stateless match engine. It takes installed apps, the CPE
// mappings table, the CVE feed and the device's platform, and returns the set
// of findings. No device / DB dependency — shared by the agent-fed path
// (cmd/patched-cve-sync, internal/cvepipeline) and the import-fed scan path
// (cmd/patched-import-scan, internal/handlers).
//
// platform is the device's NormalizeDevicePlatform value: "macos", "windows"
// or "" (PlatformUnknown). "" means the platform is unknown, and then no CPE
// range row is filtered by platform. This is independent of the PAT-2029
// mapping-level filter (FilterMappingsForPlatform), which callers apply to
// mappings before calling Match; both use the same platform value.
//
// Filtering:
//   - CVEs with CVSS score < 4.0 are excluded; nil-CVSS entries are included
//     (absence of scoring data is not grounds for exclusion).
//   - App names are word-token matched to prevent short tokens (e.g. "Box") from
//     matching longer names ("Dropbox"), except an OS mapping ("macOS" /
//     "Windows") and an OS pseudo-app of the same name, which only match each
//     other by exact equality (appMatchesMapping) so a real app such as
//     "Windows App" is never matched against OS-build CPE ranges.
//   - Platform (PAT-2107): a CPE range row whose target_sw or AND-ed operating
//     system names another platform (platformCompatible) is ignored. When the
//     CVE has range rows for the matched product and none of them is
//     compatible with the device's platform, the CVE is not reported: NVD says
//     where the product is vulnerable, and it is not here. "OneDrive on
//     Windows" is not a finding on a Mac.
//   - Version: an exact-version CPE is the range [v, v]. If a CVE has
//     version-range data for the matched product and the installed version is
//     outside all ranges, the finding is suppressed. Rows with no bounds and no
//     exact version say nothing about versions and are unverified, as before.
//   - Age cut (PAT-2107): a finding that would be version_unverified is
//     dropped when the CVE was published more than unverifiedMaxAge ago.
//     version_confirmed findings are never age-cut, and a CVE with no
//     published date is never dropped.
func Match(apps []ScannedApp, mappings []CPEMapping, feed []CVEEntry, platform string) []Finding {
	return matchAt(apps, mappings, feed, platform, time.Now())
}

// matchAt is Match with the clock passed in, so the age cut is testable.
func matchAt(apps []ScannedApp, mappings []CPEMapping, feed []CVEEntry, platform string, now time.Time) []Finding {
	cpeIndex := buildCPEIndex(feed)
	opts := matchOptions{platform: platform, now: now}
	var findings []Finding
	for _, app := range apps {
		for _, m := range mappings {
			if !MappingCovers(app.Name, m) {
				continue
			}
			findings = append(findings, matchMapping(app, m, cpeIndex, opts)...)
		}
	}
	return findings
}

// unverifiedMaxAge is how old a CVE can be and still be reported as
// version_unverified ("Possible"). A CVE with no usable version data that was
// published more than three years ago is almost always fixed in any build
// installed today, and reporting it on every current install (Firefox 155
// with CVE-2003-1492) is noise that buries the findings that matter. A CVE
// whose version range does cover the installed version is still reported
// however old it is.
const unverifiedMaxAge = 3 * 365 * 24 * time.Hour

// matchOptions carries the per-device context matchMapping applies. The zero
// value applies no platform filter and no age cut, which is what the Homebrew
// path (MatchHomebrew) uses: it has no platform or clock of its own yet.
type matchOptions struct {
	platform string    // "macos", "windows" or "" (unknown: no filter)
	now      time.Time // zero: no age cut
}

// platformCompatible reports whether a CPE range row can apply on platform.
// An unknown platform ("") is compatible with everything.
//
//   - TargetSW "", "*" or "-" says nothing about the platform and passes.
//     On macOS, any mac*, os_x* or osx* spelling (macos, mac_os_x, macosx,
//     mac_os_x_server, os_x, …), darwin, iphone_os and ipados pass; on
//     Windows, windows*. Anything else (android, linux, the other desktop OS,
//     a runtime such as node.js) is another environment and does not.
//     The macOS test is deliberately broad: NVD's spellings vary, and a
//     missed spelling would hide a real vulnerability, which is worse than a
//     spurious "Possible".
//   - A non-empty RunningOn (the OS CPEs an AND configuration requires) must
//     name the device's OS at least once: apple:mac*, apple:os_x*,
//     apple:osx* or apple:darwin* on macOS, microsoft:windows* on Windows.
func platformCompatible(r CPERange, platform string) bool {
	if platform == "" {
		return true
	}
	if !targetSWCompatible(strings.ToLower(r.TargetSW), platform) {
		return false
	}
	if len(r.RunningOn) == 0 {
		return true
	}
	for _, k := range r.RunningOn {
		if runningOnCompatible(strings.ToLower(k), platform) {
			return true
		}
	}
	return false
}

func targetSWCompatible(t, platform string) bool {
	switch t {
	case "", "*", "-":
		return true
	}
	switch platform {
	case PlatformMacOS:
		switch t {
		case "darwin", "iphone_os", "ipados":
			return true
		}
		return macOSName(t)
	case PlatformWindows:
		return strings.HasPrefix(t, "windows")
	}
	return false
}

// macOSName reports whether a lowercased target_sw or OS product name is a
// macOS spelling: mac*, os_x* or osx*.
func macOSName(s string) bool {
	return strings.HasPrefix(s, "mac") || strings.HasPrefix(s, "os_x") || strings.HasPrefix(s, "osx")
}

func runningOnCompatible(key, platform string) bool {
	switch platform {
	case PlatformMacOS:
		product, ok := strings.CutPrefix(key, "apple:")
		return ok && (macOSName(product) || strings.HasPrefix(product, "darwin"))
	case PlatformWindows:
		return strings.HasPrefix(key, "microsoft:windows")
	}
	return false
}

// compatibleRanges returns the rows of ranges for vendor:product that can
// apply on platform, and whether ranges has any row for that product at all.
// With an unknown platform ranges is returned as it is, and productHasRows is
// not computed (nothing can have been filtered out).
func compatibleRanges(ranges []CPERange, vendor, product, platform string) (out []CPERange, productHasRows bool) {
	if platform == "" {
		return ranges, false // unknown platform: nothing is filtered out
	}
	vp := strings.ToLower(vendor + ":" + product)
	for _, r := range ranges {
		if strings.ToLower(r.Vendor+":"+r.Product) != vp {
			continue
		}
		productHasRows = true
		if platformCompatible(r, platform) {
			out = append(out, r)
		}
	}
	return out, productHasRows
}

// buildCPEIndex builds the product-level index "vendor:product" → entries.
// nil-CVSS entries pass the gate; score < 4.0 is filtered.
func buildCPEIndex(feed []CVEEntry) map[string][]CVEEntry {
	cpeIndex := map[string][]CVEEntry{}
	for _, e := range feed {
		if e.Score != nil && *e.Score < 4.0 {
			continue
		}
		for _, p := range e.Patterns {
			cpeIndex[p] = append(cpeIndex[p], e)
		}
	}
	return cpeIndex
}

// matchMapping applies the platform, version-range and age gates for one app
// against every CVE indexed under one mapping's CPE key. The caller has
// already decided that the mapping covers the app.
func matchMapping(app ScannedApp, m CPEMapping, cpeIndex map[string][]CVEEntry, opts matchOptions) []Finding {
	var findings []Finding
	for _, e := range cpeIndex[m.CPEKey()] {
		ranges, productHasRows := compatibleRanges(e.Ranges, m.CPEVendor, m.CPEProduct, opts.platform)
		if productHasRows && len(ranges) == 0 {
			continue // every row for this product is for another platform
		}
		inRange, hasRanges, fixedVersion := versionInRange(app.Version, ranges, m.CPEVendor, m.CPEProduct)

		var confidence string
		switch {
		case !hasRanges:
			confidence = "version_unverified"
		case inRange:
			confidence = "version_confirmed"
		default:
			continue // version outside all known vulnerable ranges
		}
		if confidence == "version_unverified" && !opts.now.IsZero() && !e.PublishedAt.IsZero() &&
			opts.now.Sub(e.PublishedAt) > unverifiedMaxAge {
			continue // see unverifiedMaxAge
		}

		findings = append(findings, Finding{
			CVEID:           e.CVEID,
			Score:           e.Score,
			Severity:        e.Severity,
			AppName:         app.Name,
			AppVersion:      app.Version,
			MatchConfidence: confidence,
			FixedVersion:    fixedVersion,
			MappingBasis:    m.Basis(),
		})
	}
	return findings
}

// NameMatches reports whether an installed application's display name is
// covered by a mapping's match_name under the same rule Match uses
// (appMatchesMapping: whole-word, ordered-token, with the OS-pseudo-app
// equality gate). Exported so the event-driven matcher (PAT-2024) and the
// assessment read path decide "is this product mapped" exactly as the match
// engine does, rather than with a second, drifting rule.
func NameMatches(appName, matchName string) bool {
	return appMatchesMapping(appName, matchName)
}

// MappingCovers is the rule Match and MappingsFor apply to one mapping: a
// curated mapping covers a name under NameMatches (whole-word, ordered
// subsequence), an automatic one (ReviewState "auto", PAT-2138) only a name
// with exactly its word tokens (ExactNameMatches). An automatic match_name is
// a product's own display name, published without a person reading it, so
// it must never silently cover a product installed later whose name merely
// extends it: an auto "Zoom" covers "zoom" and "Zoom." but not "Zoom Helper"
// or "Zoom Workplace", which are proposed, and judged, on their own.
//
// NameMatches stays the ordered-subsequence rule, so a caller that holds
// only match_name strings (a mapping publish's re-match fan-out, the
// pending-mapping indicator) over-approximates an automatic mapping's reach;
// every such caller only widens a re-match or a transient "pending" flag,
// and the matcher itself decides the findings through this function.
func MappingCovers(appName string, m CPEMapping) bool {
	if m.ReviewState == ReviewStateAuto {
		return ExactNameMatches(appName, m.MatchName)
	}
	return appMatchesMapping(appName, m.MatchName)
}

// ExactNameMatches reports whether appName and matchName have exactly the
// same word tokens in the same order (appNameTokens: case, punctuation and
// spacing ignored), with the same OS-pseudo-app equality gate as
// appMatchesMapping. "Zoom" exactly matches "zoom" and "Zoom." but not
// "Zoom Helper".
func ExactNameMatches(appName, matchName string) bool {
	if isOSPseudoAppName(matchName) || isOSPseudoAppName(appName) {
		return appName == matchName
	}
	a, k := appNameTokens(appName), appNameTokens(matchName)
	if len(k) == 0 || len(a) != len(k) {
		return false
	}
	for i := range a {
		if a[i] != k[i] {
			return false
		}
	}
	return true
}

// MappingsFor returns every mapping whose match_name covers appName. An empty
// result means no CPE mapping exists for the product, so no CVE statement can
// be made about it: callers must report that as not assessed, never as zero
// findings (PAT-2024).
func MappingsFor(appName string, mappings []CPEMapping) []CPEMapping {
	var out []CPEMapping
	for _, m := range mappings {
		if MappingCovers(appName, m) {
			out = append(out, m)
		}
	}
	return out
}

// CPEKey is the normalised "vendor:product" key a mapping resolves to, the
// same form stored in cve_feed_entries.cpe_patterns.
func (m CPEMapping) CPEKey() string {
	return strings.ToLower(m.CPEVendor + ":" + m.CPEProduct)
}

// ActiveDeviceWindow is the CVE matchers' device scope as a Postgres
// interval literal: devices seen in the last 30 days. The one definition
// shared by the event-driven matcher (cvepipeline) and the CPE proposer
// (cpepropose), so both agree on which devices are in scope.
const ActiveDeviceWindow = "30 days"

// Device platform values, matching app_cpe_mappings.platform's vocabulary
// (PAT-2029). PlatformUnknown is never stored on a mapping row — it is the
// zero value NormalizeDevicePlatform returns for a device whose OS it does
// not recognise, so that an unrecognised device only ever matches "any"
// mappings rather than guessing a platform for it.
const (
	PlatformAny     = "any"
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
	PlatformUnknown = ""
)

// NormalizeDevicePlatform maps a device's raw OS string (devices.os: "macOS"
// or "Windows" from the payload, case and exact spelling not guaranteed by
// every caller) to app_cpe_mappings.platform's vocabulary ("macos" /
// "windows"). Returns PlatformUnknown ("") for anything else — including an
// empty string — so a caller applies only "any" mappings to that device
// rather than guessing its platform (PAT-2029 hard constraint: never guess).
//
// This is the one shared helper both app-name CVE matchers
// (cmd/patched-cve-sync and internal/cvepipeline) use to turn a device's OS
// into a mapping-platform value, so they agree on every device exactly the
// same way PAT-2024 already made them agree on everything else.
func NormalizeDevicePlatform(os string) string {
	o := strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.HasPrefix(o, "macos"), strings.HasPrefix(o, "mac os"), strings.HasPrefix(o, "darwin"):
		return PlatformMacOS
	case strings.HasPrefix(o, "windows"):
		return PlatformWindows
	default:
		return PlatformUnknown
	}
}

// MappingApplies reports whether a mapping whose platform is mappingPlatform
// covers a device whose (already normalised, via NormalizeDevicePlatform)
// platform is devicePlatform.
//
// mappingPlatform "" or "any" always applies. Otherwise it applies only when
// it equals devicePlatform exactly — so a device whose platform is unknown
// (devicePlatform == PlatformUnknown) matches no platform-specific mapping at
// all, only "any" ones (PAT-2029: never guess).
func MappingApplies(mappingPlatform, devicePlatform string) bool {
	if mappingPlatform == "" || mappingPlatform == PlatformAny {
		return true
	}
	return mappingPlatform == devicePlatform
}

// FilterMappingsForPlatform returns the subset of mappings that apply to a
// device of the given (already normalised) platform: PAT-2029's fix for the
// app-name matchers loading every app_cpe_mappings row with no platform
// filter, which let a platform-specific mapping (e.g. Microsoft Word's
// windows-only CPE) apply to every device regardless of its own platform.
func FilterMappingsForPlatform(mappings []CPEMapping, devicePlatform string) []CPEMapping {
	out := make([]CPEMapping, 0, len(mappings))
	for _, m := range mappings {
		if MappingApplies(m.Platform, devicePlatform) {
			out = append(out, m)
		}
	}
	return out
}
