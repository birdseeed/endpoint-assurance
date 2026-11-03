package cvematch

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// PAT-2044: letter suffixes and pre-releases in the version comparator.

// TestCompareVersionsStrict covers the grammar and ordering rule documented
// on compareVersionsStrict. ok=false means "unknown".
func TestCompareVersionsStrict(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		// OpenSSL letter releases.
		{"1.1.1s", "1.1.1t", -1, true},
		{"1.1.1t", "1.1.1s", 1, true},
		{"1.1.1", "1.1.1a", -1, true},
		{"1.1.1a", "1.1.1", 1, true},
		{"1.1.1z", "1.1.1za", -1, true},
		{"1.1.1za", "1.1.1z", 1, true},
		{"0.9.8za", "0.9.8zb", -1, true},
		{"1.0.2zf", "1.0.2zg", -1, true},
		{"1.0.2u", "1.0.2zg", -1, true},
		{"1.1.1a", "1.1.1z", -1, true},
		{"1.1.1t", "1.1.1t", 0, true},
		{"1.1.1T", "1.1.1t", 0, true}, // case-insensitive
		{"1.1.1S", "1.1.1t", -1, true},
		// The numeric part decides first, whatever the suffixes.
		{"1.1.1w", "3.0.0", -1, true},
		{"1.0.2zg", "1.1.1", -1, true},
		{"1.1.0l", "1.1.1", -1, true},
		{"1.1.2", "1.1.1z", 1, true},
		// Different component counts, common prefix equal.
		{"1.1", "1.1.1a", -1, true}, // suffix only on the longer side
		{"1.1.1a", "1.1", 1, true},
		{"1.1a", "1.1.1", 0, false}, // suffix on the shorter side: unknown
		{"1.1.1", "1.1a", 0, false},
		// Missing trailing components count as zero.
		{"2.0", "2.0.0", 0, true},
		{"1.1", "1.1.0.0", 0, true},
		{"1.1.0.0", "1.1", 0, true},
		{"2.0.0.1", "2.0", 1, true},
		{"1.1", "1.1.0a", -1, true},     // suffix on the longer side only
		{"1.1.1a", "1.1.1.0", 0, false}, // the letter may stand for the 4th component
		{"1.1a", "1.1.0", 0, false},
		{"1.1.1a", "1.1.1.1", 0, false},
		{"1.1.1a", "1.1.2.0", -1, true}, // difference inside both

		// Pre-releases: never guessed.
		{"3.0.0-rc1", "3.0.0", 0, false},
		{"3.0.0-rc1", "3.0.8", 0, false},
		{"3.12.0rc1", "3.12.0", 0, false},
		{"3.12.0rc1", "3.11.5", 0, false},
		{"3.12.0b4", "3.12.0", 0, false},
		{"3.12.0a7", "3.12.0", 0, false},
		{"1.0.0-beta", "1.0.0", 0, false},
		{"1.0.0-alpha", "1.0.0", 0, false},
		{"2.0.0-pre", "2.0.0", 0, false},
		{"2.0.rc1", "2.0", 0, false},
		{"2.0rc", "2.0", 0, false}, // two letters, not z+letter
		{"3.0.0", "3.0.0-rc1", 0, false},

		// Other mixed shapes: unknown.
		{"4.2.8p15", "4.2.8", 0, false},
		{"9.8p1", "9.9", 0, false},
		{"1.2.3_1", "1.2.3", 0, false},
		{"1.2.3+build.5", "1.2.3", 0, false},
		{"v1.2.3", "1.2.3", 0, false},
		{"1.2.3 (456)", "1.2.3", 0, false},
		{"2024-07-15", "2024.7.15", 0, false},
		{"1..2", "1.2", 0, false},
		{".1", "0.1", 0, false},
		{"1.2.", "1.2", 0, false},
		{"1.1.1zza", "1.1.1", 0, false},
		{"latest", "1.0", 0, false},
		{"", "1.0", 0, false},
	}
	for _, c := range cases {
		got, ok := compareVersionsStrict(c.a, c.b)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("compareVersionsStrict(%q, %q) = (%d, %v), want (%d, %v)", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

// TestCompareVersionsStrictNumericParity: for pure numeric-dotted versions
// the strict comparator and compareVersions agree with the legacy
// numeric-only comparator on every pair except the ones PAT-2044 changes on
// purpose: unequal-length pairs whose extra components are all zero, which
// legacy ordered shorter-lower and which now compare equal (2.0 == 2.0.0).
// That set is listed in full, so any other difference is a regression.
func TestCompareVersionsStrictNumericParity(t *testing.T) {
	vs := []string{
		"0", "00", "1", "1.0", "1.0.0", "1.0.0.0", "1.0.1", "1.1", "1.01", "1.10", "1.9",
		"2", "2.0", "9.9.9", "10.0.0", "010.0.0", "3.0.7", "3.0.8", "3.1.4", "3.39.1", "3.39.2",
		"3.43.2", "7.68.0", "7.69.0", "8.3.0", "8.4.0", "8.10.1", "116.0.5845.96",
		"116.0.5845.187", "116.0.5845.188", "117.0.5938.62", "120.0.6099.130", "121.0.6167.85",
		"2024.7.15", "18446744073709551616", "18446744073709551617",
	}
	// Every ordered pair expected to change, legacy +-1 -> now 0.
	wantChanged := map[string]bool{}
	for _, group := range [][]string{{"1", "1.0", "1.0.0", "1.0.0.0"}, {"2", "2.0"}} {
		for _, a := range group {
			for _, b := range group {
				if a != b {
					wantChanged[a+" vs "+b] = true
				}
			}
		}
	}
	if len(wantChanged) != 14 {
		t.Fatalf("expected-change set has %d pairs, want 14", len(wantChanged))
	}
	pairs, changed := 0, 0
	for _, a := range vs {
		for _, b := range vs {
			pairs++
			got, ok := compareVersionsStrict(a, b)
			legacy := compareNumericOnly(a, b)
			if !ok || compareVersions(a, b) != got {
				t.Errorf("numeric %q vs %q: strict (%d, %v), compareVersions %d", a, b, got, ok, compareVersions(a, b))
			}
			if got == legacy {
				continue
			}
			changed++
			pa, pb := strings.Split(a, "."), strings.Split(b, ".")
			if !wantChanged[a+" vs "+b] || got != 0 || len(pa) == len(pb) ||
				strings.Join(trimTrailingZeros(pa), ".") != strings.Join(trimTrailingZeros(pb), ".") {
				t.Errorf("numeric %q vs %q: now %d, legacy %d; not a trailing-zero pair", a, b, got, legacy)
			}
		}
	}
	if changed != len(wantChanged) {
		t.Errorf("%d numeric pairs changed, want exactly the %d trailing-zero pairs", changed, len(wantChanged))
	}
	if pairs < 1000 {
		t.Fatalf("parity table shrank to %d pairs", pairs)
	}
}

// TestCompareVersionsTotalOrder: compareVersions is a sort-key comparison,
// so over any mix of grammar and non-grammar versions it is antisymmetric
// and transitive, and it agrees with the strict comparator and the range
// gate's certain-prefix rule wherever those give an answer. MaxVersion folds
// to the same string in any order (the fixed-version folds in
// report.targetVersion, the portal findings aggregate and
// strongerHomebrewFinding).
func TestCompareVersionsTotalOrder(t *testing.T) {
	vs := []string{
		"", "Unknown", "Build 4200", "1", "1.0", "1.0.0", "1.1", "1.1a", "1.1.0", "1.1.0a", "1.1.1",
		"1.1.1a", "1.1.1.0", "1.1.1.1", "1.1.1s", "1.1.1t", "1.1.1z", "1.1.1za", "1.1.1-rc1", "1.1.1 (x64)",
		"1.2.3", "1.2.3-beta", "1.2.3.0", "2.0", "2.0.0", "2.0-rc1", "2.6.10-I001", "2.7", "3.0.0-rc1",
		"3.0.0", "3.0.8", "3.12.0rc1", "3.12.0", "115.13.0esr", "115.13.0", "116.0", "4.2.8p15", "4.2.8",
		"1.8.0_391", "1.8.0_401", "1.8.0", "8u391", "8u401", "2.6.10-I002", "9.8p1", "9.9p1", "9.3p2", "8.5p1",
		"9.8", "2.0.0_0", "1:2.3",
	}
	for _, a := range vs {
		for _, b := range vs {
			ab, ba := compareVersions(a, b), compareVersions(b, a)
			if ab != -ba {
				t.Errorf("not antisymmetric: %q vs %q = %d, reverse %d", a, b, ab, ba)
			}
			if c, ok := compareVersionsStrict(a, b); ok && c != ab {
				t.Errorf("%q vs %q: strict %d, compareVersions %d", a, b, c, ab)
			}
			if c, ok := compareInstalledToBound(a, b); ok && c != ab {
				t.Errorf("%q vs %q: range gate %d, compareVersions %d", a, b, c, ab)
			}
			for _, c := range vs {
				if ab <= 0 && compareVersions(b, c) <= 0 && compareVersions(a, c) > 0 {
					t.Errorf("not transitive: %q <= %q <= %q but %q > %q", a, b, c, a, c)
				}
			}
		}
	}
	// Legacy behaviour kept for non-grammar tails; letters still ordered.
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3-beta", "1.2.3", 0}, {"1.2.4-beta", "1.2.3", 1}, {"", "1.0", -1},
		{"1.1.1s", "1.1.1t", -1}, {"2.0", "2.0.0", 0}, {"2.0-rc1", "2.0.1", -1},
		// Digit-group tie-break for tails the key ignores (legacy order).
		{"1.8.0_391", "1.8.0_401", -1}, {"8u391", "8u401", -1}, {"2.6.10-I001", "2.6.10-I002", -1},
		{"1.8.0_401", "1.8.0", 1}, {"2.0.0_0", "2.0", 0},
		// Ordering-only (folds, catalogue gap): an rc's digits sort it after
		// the release, as the pre-PAT-2044 comparator did. The range gate
		// never uses this: there 2.0-rc1 against 2.0.0 is unknown.
		{"2.0-rc1", "2.0.0", 1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}

	// Fold order independence, including across equal-comparing strings.
	set := []string{"1.1.1t", "2.0", "1.2.3-beta", "2.0.0", "1.1.1s", "1.9.9-rc1", "2.0.0.0"}
	fold := func(xs []string) string {
		m := ""
		for _, x := range xs {
			m = MaxVersion(m, x)
		}
		return m
	}
	want := fold(set)
	if want != "2.0.0.0" {
		t.Fatalf("fold = %q, want 2.0.0.0 (equal to 2.0 and 2.0.0; greatest string)", want)
	}
	for i := 0; i < len(set); i++ {
		rot := append(append([]string{}, set[i:]...), set[:i]...)
		for _, order := range [][]string{rot, reversed(rot)} {
			if got := fold(order); got != want {
				t.Errorf("fold of %v = %q, want %q", order, got, want)
			}
		}
	}
	if MaxVersion("", "") != "" || MaxVersion("", "1.0") != "1.0" || MaxVersion("1.0", "") != "1.0" {
		t.Error("MaxVersion does not treat empty as absent")
	}
}

func reversed(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[len(xs)-1-i] = x
	}
	return out
}

// TestCompareInstalledToBoundPrefix: an installed version outside the
// grammar is ordered by its leading numbers only where they already differ
// from the bound's, in either direction; otherwise it stays unknown.
func TestCompareInstalledToBoundPrefix(t *testing.T) {
	cases := []struct {
		installed, bound string
		want             int
		ok               bool
	}{
		{"115.13.0esr", "116.0", -1, true},
		{"115.13.0esr", "115.12", 1, true},
		{"115.13.0esr", "115.13.0", 0, false},
		{"115.13.0esr", "115.13", 0, false},
		{"115.13.0esr", "115.13.0.1", 0, false}, // not padded: the tail is not known to be zero
		{"2.6.10-I001", "2.7", -1, true},
		{"2.6.10-I001", "2.6.9", 1, true},
		{"1.2.3 (x64)", "1.2.4", -1, true},
		{"3.0.0-rc1", "3.0.0", 0, false},
		{"3.0.0-rc1", "3.0.8", -1, true},
		{"3.12.0rc1", "3.11.5", 1, true},
		{"2.0.rc1", "2.1", -1, true},
		{"1.1.2-rc", "1.1.1t", 1, true},
		{"1:2.3", "2.0", 0, false}, // Debian epoch: not a version prefix
		{"1,2", "2.0", 0, false},
		{"Build 4200", "5000", 0, false},
		{"Unknown", "1.0", 0, false},
		// Symmetric: bounds outside the grammar too (OpenSSH p releases).
		{"115.13.0esr", "116.0-rc1", -1, true},
		{"1.1.1s", "1.1.2-rc1", -1, true},
		{"9.9p1", "9.8p1", 1, true},
		{"9.3p2", "9.8p1", -1, true},
		{"9.3p2", "8.5p1", 1, true},
		{"9.8p1", "9.8p1", 0, true}, // identical strings are the same version
		{"9.8p2", "9.8p1", 0, false},
		{"9.8", "9.8p1", 0, false},
		{"9.8p1", "9.8", 0, false},
		{"3.0.7", "3.0.7-alpha1", 0, false},
		{"1:2.3", "1:2.3", 0, true},
		{"Unknown", "Unknown", 0, true},
	}
	for _, c := range cases {
		got, ok := compareInstalledToBound(c.installed, c.bound)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("compareInstalledToBound(%q, %q) = (%d, %v), want (%d, %v)", c.installed, c.bound, got, ok, c.want, c.ok)
		}
	}
}

// TestNormalizeInstalledVersion: only a leading v before a digit and one
// trailing " (<digits>)" are removed.
func TestNormalizeInstalledVersion(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"7.0.0 (77593)", "7.0.0"}, {"v2.0.3", "2.0.3"}, {"V2.0.3", "2.0.3"},
		{"v7.0.0 (1)", "7.0.0"}, {"7.0.0 (abc)", "7.0.0 (abc)"}, {"7.0.0(77593)", "7.0.0(77593)"},
		{"7.0.0 (1) (2)", "7.0.0 (1)"}, {"Build 4200", "Build 4200"}, {"Unknown", "Unknown"},
		{"vv2.0", "vv2.0"}, {"v", "v"}, {"version 2", "version 2"}, {"1.2.3", "1.2.3"},
	} {
		if got := normalizeInstalledVersion(c.in); got != c.want {
			t.Errorf("normalizeInstalledVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Bounds are never normalised: a bound in the build-suffix shape is unknown.
	// Normalised, "7.0.2 (1)" would equal 7.0.2 and exclude it; raw, it only
	// agrees with 7.0.2 as far as both go, which is unknown.
	if _, h, _ := versionInRange("7.0.2", []CPERange{{Vendor: "v", Product: "p", VEndExcl: "7.0.2 (1)"}}, "v", "p"); h {
		t.Error("an NVD bound was normalised")
	}
}

// TestVersionInRangeUnknownIsUnverified: an unknown comparison routes to
// hasRanges=false (version_unverified), never to "not in range", and a
// certain exclusion or a certain match elsewhere still wins.
func TestVersionInRangeUnknownIsUnverified(t *testing.T) {
	r := func(si, se, ei, ee string) CPERange {
		return CPERange{Vendor: "v", Product: "p", VStartIncl: si, VStartExcl: se, VEndIncl: ei, VEndExcl: ee}
	}
	cases := []struct {
		name, installed string
		ranges          []CPERange
		matched, has    bool
		fixed           string
	}{
		{"1.1.1s before 1.1.1t is in", "1.1.1s", []CPERange{r("1.1.1", "", "", "1.1.1t")}, true, true, "1.1.1t"},
		{"1.1.1t at the fix is out", "1.1.1t", []CPERange{r("1.1.1", "", "", "1.1.1t")}, false, true, ""},
		{"1.1.1 bare is in", "1.1.1", []CPERange{r("1.1.1", "", "", "1.1.1t")}, true, true, "1.1.1t"},
		{"1.1.1za past 1.1.1z incl is out", "1.1.1za", []CPERange{r("", "", "1.1.1z", "")}, false, true, ""},
		{"rc against its own release bound is unknown", "3.0.0-rc1", []CPERange{r("3.0.0", "", "", "3.0.8")}, false, false, ""},
		{"python rc is unknown", "3.12.0rc1", []CPERange{r("3.12.0", "", "", "3.12.1")}, false, false, ""},
		{"unknown bound in a range is unknown", "3.0.7", []CPERange{r("3.0.7-alpha1", "", "", "3.0.8")}, false, false, ""},
		{"prefix-decided bound outside the grammar", "3.0.7", []CPERange{r("3.0.0-alpha1", "", "", "3.0.8")}, true, true, "3.0.8"},
		{"openssh 9.9p1 past CVE-2024-6387 is out", "9.9p1", []CPERange{r("8.5p1", "", "", "9.8p1")}, false, true, ""},
		{"openssh 9.3p2 inside CVE-2024-6387 is in", "9.3p2", []CPERange{r("8.5p1", "", "", "9.8p1")}, true, true, "9.8p1"},
		{"openssh 9.8p1 is the fix, identical to the bound", "9.8p1", []CPERange{r("8.5p1", "", "", "9.8p1")}, false, true, ""},
		{"openssh 9.8p2 agrees with 9.8p1 as far as both go", "9.8p2", []CPERange{r("8.5p1", "", "", "9.8p1")}, false, false, ""},
		{"certain exclusion beats an unknown bound", "2.9.0", []CPERange{r("3.0.0", "", "", "3.0.0-rc5")}, false, true, ""},
		{"certain match elsewhere beats an unknown range", "1.1.1s",
			[]CPERange{r("1.1a", "", "", "1.1.1"), r("1.1.1", "", "", "1.1.1t")}, true, true, "1.1.1t"},
		{"one certain-out range and one unknown range is unknown", "3.12.0rc1",
			[]CPERange{r("", "", "", "3.8.18"), r("3.12.0", "", "", "3.12.1")}, false, false, ""},
		{"zoom build suffix compares as 7.0.0", "7.0.0 (77593)", []CPERange{r("", "", "", "7.0.2")}, true, true, "7.0.2"},
		{"zoom build suffix past the fix is out", "7.0.5 (81138)", []CPERange{r("", "", "", "7.0.2")}, false, true, ""},
		{"leading v compares as 2.0.3", "v2.0.3", []CPERange{r("2.0.0", "", "", "2.0.4")}, true, true, "2.0.4"},
		{"non-numeric build suffix is ordered by its prefix", "7.0.0 (abc)", []CPERange{r("", "", "", "7.0.2")}, true, true, "7.0.2"},
		{"non-numeric build suffix at its own bound stays unknown", "7.0.0 (abc)", []CPERange{r("", "", "", "7.0.0")}, false, false, ""},
		{"esr below the next major is in", "115.13.0esr", []CPERange{r("", "", "", "116.0")}, true, true, "116.0"},
		{"esr at its own release bound is unknown", "115.13.0esr", []CPERange{r("", "", "", "115.13.0")}, false, false, ""},
		{"I001 build below the start is certainly out", "2.6.10-I001", []CPERange{r("2.7", "", "", "2.9")}, false, true, ""},
		{"x64 tail below the fix is in", "1.2.3 (x64)", []CPERange{r("", "", "", "1.2.4")}, true, true, "1.2.4"},
		{"2.0 is 2.0.0, inside 2.0.0 to 2.0.5", "2.0", []CPERange{r("2.0.0", "", "", "2.0.5")}, true, true, "2.0.5"},
		{"2.0.5.0 is the fix", "2.0.5.0", []CPERange{r("2.0.0", "", "", "2.0.5")}, false, true, ""},
		{"Build 4200 stays unknown", "Build 4200", []CPERange{r("", "", "", "7.0.2")}, false, false, ""},
		{"pure numeric unchanged: in", "3.0.7", []CPERange{r("3.0.0", "", "", "3.0.8")}, true, true, "3.0.8"},
		{"pure numeric unchanged: out", "3.0.8", []CPERange{r("3.0.0", "", "", "3.0.8")}, false, true, ""},
	}
	for _, c := range cases {
		m, h, f := versionInRange(c.installed, c.ranges, "v", "p")
		if m != c.matched || h != c.has || f != c.fixed {
			t.Errorf("%s: versionInRange(%q) = (%v, %v, %q), want (%v, %v, %q)", c.name, c.installed, m, h, f, c.matched, c.has, c.fixed)
		}
	}
}

// legacyVersionInRange is versionInRange as it was before PAT-2044, verbatim
// but for the comparator name. It is the "old" side of the measurement below.
func legacyVersionInRange(installedVersion string, ranges []CPERange, vendor, product string) (matched, hasRanges bool) {
	if len(splitVersion(installedVersion)) == 0 {
		return false, false
	}
	vp := strings.ToLower(vendor + ":" + product)
	for _, r := range ranges {
		if strings.ToLower(r.Vendor+":"+r.Product) != vp {
			continue
		}
		if r.VStartIncl == "" && r.VStartExcl == "" && r.VEndIncl == "" && r.VEndExcl == "" {
			continue
		}
		hasRanges = true
		in := true
		if r.VStartIncl != "" && compareNumericOnly(installedVersion, r.VStartIncl) < 0 {
			in = false
		}
		if in && r.VStartExcl != "" && compareNumericOnly(installedVersion, r.VStartExcl) <= 0 {
			in = false
		}
		if in && r.VEndIncl != "" && compareNumericOnly(installedVersion, r.VEndIncl) > 0 {
			in = false
		}
		if in && r.VEndExcl != "" && compareNumericOnly(installedVersion, r.VEndExcl) >= 0 {
			in = false
		}
		if in {
			matched = true
		}
	}
	return
}

// numericOnly: the installed version and every bound are pure numeric-dotted.
func numericOnly(installed string, rs []CPERange) bool {
	vs := []string{installed}
	for _, r := range rs {
		vs = append(vs, r.VStartIncl, r.VStartExcl, r.VEndIncl, r.VEndExcl)
	}
	for _, v := range vs {
		if v == "" {
			continue
		}
		if p, ok := parseComparableVersion(v); !ok || p.suffix != "" {
			return false
		}
	}
	return true
}

// trailingZeroOfBound: the installed version equals one of the bounds once
// trailing zeros are ignored, the one numeric-only case PAT-2044 changes.
func trailingZeroOfBound(installed string, rs []CPERange) bool {
	for _, r := range rs {
		for _, b := range []string{r.VStartIncl, r.VStartExcl, r.VEndIncl, r.VEndExcl} {
			if b != "" && b != installed && strings.Join(trimTrailingZeros(strings.Split(b, ".")), ".") ==
				strings.Join(trimTrailingZeros(strings.Split(installed, ".")), ".") {
				return true
			}
		}
	}
	return false
}

func verdict(matched, has bool) string {
	switch {
	case !has:
		return "unknown"
	case matched:
		return "in"
	default:
		return "out"
	}
}

// TestComparatorChangeMeasurement runs the old and new range gates over a
// realistic sample of installed versions against NVD-shaped ranges and pins
// every verdict, so the change in behaviour is measured and fixed rather
// than asserted in prose. Numeric-only rows must be unchanged. Run with -v
// to print the table.
//
// Ranges (NVD configurations, as filed):
//
//	CVE-2023-0286 openssl  1.0.2 <= v < 1.0.2zg; 1.1.1 <= v < 1.1.1t; 3.0.0 <= v < 3.0.8
//	CVE-2022-0778 openssl  1.0.2 <= v < 1.0.2zd; 1.1.1 <= v < 1.1.1n; 3.0.0 <= v < 3.0.2
//	CVE-2014-0160 openssl  1.0.1 <= v <= 1.0.1f (NVD lists each release; one inclusive range here)
//	CVE-2025-TEST-ZOOM zoom  v < 7.0.2 (synthetic, Zoom-shaped bound)
//	CVE-2023-38545 libcurl 7.69.0 <= v < 8.4.0
//	CVE-2022-35737 sqlite  v < 3.39.2
//	CVE-2023-4863 chrome   v < 116.0.5845.187
//	CVE-2023-40217 python  v < 3.8.18; 3.9.0 <= v < 3.9.18; 3.10.0 <= v < 3.10.13; 3.11.0 <= v < 3.11.5
func TestComparatorChangeMeasurement(t *testing.T) {
	rr := func(p string, pairs ...string) []CPERange {
		var out []CPERange
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, CPERange{Vendor: "x", Product: p, VStartIncl: pairs[i], VEndExcl: pairs[i+1]})
		}
		return out
	}
	ranges := map[string][]CPERange{
		"CVE-2023-0286":      rr("openssl", "1.0.2", "1.0.2zg", "1.1.1", "1.1.1t", "3.0.0", "3.0.8"),
		"CVE-2022-0778":      rr("openssl", "1.0.2", "1.0.2zd", "1.1.1", "1.1.1n", "3.0.0", "3.0.2"),
		"CVE-2014-0160":      {{Vendor: "x", Product: "openssl", VStartIncl: "1.0.1", VEndIncl: "1.0.1f"}},
		"CVE-2023-38545":     rr("libcurl", "7.69.0", "8.4.0"),
		"CVE-2025-TEST-ZOOM": rr("zoom", "", "7.0.2"),
		"CVE-TEST-FX-116":    rr("firefox", "", "116.0"),
		"CVE-TEST-FX-11513":  rr("firefox", "", "115.13.0"),
		"CVE-TEST-START27":   rr("app27", "2.7", "2.9"),
		"CVE-TEST-124":       rr("app124", "", "1.2.4"),
		"CVE-TEST-TZ":        rr("tz", "2.0.0", "2.0.5"),
		"CVE-2022-35737":     rr("sqlite", "", "3.39.2"),
		"CVE-2023-4863":      rr("chrome", "", "116.0.5845.187"),
		"CVE-2023-40217":     rr("python", "", "3.8.18", "3.9.0", "3.9.18", "3.10.0", "3.10.13", "3.11.0", "3.11.5"),
	}
	product := func(cve string) string { return ranges[cve][0].Product }

	cases := []struct {
		cve, installed string
		old, new       string
	}{
		// OpenSSL 1.0.2 / 1.1.1 letter releases: the reason for the ticket.
		{"CVE-2023-0286", "1.0.2k", "out", "in"},  // was hidden
		{"CVE-2023-0286", "1.0.2u", "out", "in"},  // was hidden
		{"CVE-2023-0286", "1.0.2zf", "out", "in"}, // was hidden
		{"CVE-2023-0286", "1.0.2zg", "out", "out"},
		{"CVE-2023-0286", "1.1.1", "out", "in"},  // was hidden: 1.1.1 read equal to the 1.1.1t fix
		{"CVE-2023-0286", "1.1.1k", "out", "in"}, // was hidden
		{"CVE-2023-0286", "1.1.1n", "out", "in"}, // was hidden
		{"CVE-2023-0286", "1.1.1s", "out", "in"}, // was hidden: the ticket's case
		{"CVE-2023-0286", "1.1.1t", "out", "out"},
		{"CVE-2023-0286", "1.1.1w", "out", "out"},
		{"CVE-2022-0778", "1.0.2zc", "out", "in"}, // was hidden
		{"CVE-2022-0778", "1.0.2zd", "out", "out"},
		{"CVE-2022-0778", "1.1.1m", "out", "in"}, // was hidden
		{"CVE-2022-0778", "1.1.1n", "out", "out"},
		{"CVE-2022-0778", "1.1.1s", "out", "out"},
		// Heartbleed's inclusive letter bound: the old gate invented findings
		// on fixed releases (1.0.1g read as 1.0.1, inside 1.0.1..1.0.1f).
		{"CVE-2014-0160", "1.0.1", "in", "in"},
		{"CVE-2014-0160", "1.0.1f", "in", "in"},
		{"CVE-2014-0160", "1.0.1g", "in", "out"},
		{"CVE-2014-0160", "1.0.1u", "in", "out"},
		{"CVE-2014-0160", "1.0.2", "out", "out"},
		// OpenSSL 3.x numerics: unchanged.
		{"CVE-2023-0286", "3.0.0", "in", "in"},
		{"CVE-2023-0286", "3.0.7", "in", "in"},
		{"CVE-2023-0286", "3.0.8", "out", "out"},
		{"CVE-2023-0286", "3.1.4", "out", "out"},
		{"CVE-2022-0778", "3.0.1", "in", "in"},
		{"CVE-2022-0778", "3.0.2", "out", "out"},
		// OpenSSL 3.x pre-releases: were read as releases.
		{"CVE-2023-0286", "3.0.0-alpha17", "in", "unknown"},
		{"CVE-2023-0286", "3.0.0-beta2", "in", "unknown"},
		// Installed-version normalisation (prod device_apps shapes). The
		// old comparator read the digits anyway; the build number in
		// parentheses made "7.0.0 (77593)" read as 7.0.0.77593.
		{"CVE-2025-TEST-ZOOM", "7.0.0 (77593)", "in", "in"},
		{"CVE-2025-TEST-ZOOM", "7.0.5 (81138)", "out", "out"},
		{"CVE-2025-TEST-ZOOM", "7.1.5 (84650)", "out", "out"},
		{"CVE-2025-TEST-ZOOM", "v2.0.3", "in", "in"},
		{"CVE-2025-TEST-ZOOM", "7.0.0 (abc)", "in", "in"}, // certain prefix: 7.0.0 < 7.0.2
		{"CVE-2025-TEST-ZOOM", "Build 4200", "out", "unknown"},
		{"CVE-2025-TEST-ZOOM", "Unknown", "unknown", "unknown"},
		// Certain-prefix rule for installed versions outside the grammar
		// (synthetic bounds).
		{"CVE-TEST-FX-116", "115.13.0esr", "in", "in"},
		{"CVE-TEST-FX-11513", "115.13.0esr", "out", "unknown"},
		{"CVE-TEST-START27", "2.6.10-I001", "out", "out"},
		{"CVE-TEST-124", "1.2.3 (x64)", "in", "in"},
		// Trailing zeros (synthetic bound): 2.0 is 2.0.0.
		{"CVE-TEST-TZ", "2.0", "out", "in"},
		{"CVE-TEST-TZ", "2.0.0", "in", "in"},
		{"CVE-TEST-TZ", "2.0.5.0", "out", "out"},
		{"CVE-TEST-TZ", "2.0.4.0", "in", "in"},
		// curl: unchanged.
		{"CVE-2023-38545", "7.68.0", "out", "out"},
		{"CVE-2023-38545", "7.88.1", "in", "in"},
		{"CVE-2023-38545", "8.3.0", "in", "in"},
		{"CVE-2023-38545", "8.4.0", "out", "out"},
		{"CVE-2023-38545", "8.5.0", "out", "out"},
		// sqlite: unchanged.
		{"CVE-2022-35737", "3.39.1", "in", "in"},
		{"CVE-2022-35737", "3.39.2", "out", "out"},
		{"CVE-2022-35737", "3.43.2", "out", "out"},
		// Chrome-style 4-part numerics: unchanged.
		{"CVE-2023-4863", "116.0.5845.96", "in", "in"},
		{"CVE-2023-4863", "116.0.5845.187", "out", "out"},
		{"CVE-2023-4863", "116.0.5845.188", "out", "out"},
		{"CVE-2023-4863", "117.0.5938.62", "out", "out"},
		{"CVE-2023-4863", "115.0.5790.170", "in", "in"},
		// Python: numerics unchanged; rc/b were read as releases.
		{"CVE-2023-40217", "3.9.6", "in", "in"},
		{"CVE-2023-40217", "3.11.4", "in", "in"},
		{"CVE-2023-40217", "3.11.5", "out", "out"},
		{"CVE-2023-40217", "3.12.0", "out", "out"},
		{"CVE-2023-40217", "3.11.0rc1", "in", "unknown"},
		{"CVE-2023-40217", "3.12.0rc1", "out", "out"}, // certain prefix: 3.12 is past every range
		{"CVE-2023-40217", "3.12.0b4", "out", "out"},
		{"CVE-2023-40217", "3.8.18rc1", "out", "unknown"},
	}

	changes := map[string]int{}
	var table []string
	for _, c := range cases {
		p := product(c.cve)
		old := verdict(legacyVersionInRange(c.installed, ranges[c.cve], "x", p))
		m, h, _ := versionInRange(c.installed, ranges[c.cve], "x", p)
		now := verdict(m, h)
		if old != c.old || now != c.new {
			t.Errorf("%s %s %s: old %s new %s, fixture says old %s new %s", c.cve, p, c.installed, old, now, c.old, c.new)
		}
		if numericOnly(c.installed, ranges[c.cve]) && old != now && !trailingZeroOfBound(c.installed, ranges[c.cve]) {
			t.Errorf("numeric-only %s %s changed verdict %s -> %s", c.cve, c.installed, old, now)
		}
		mark := ""
		if old != now {
			changes[old+" -> "+now]++
			mark = "  CHANGED"
		}
		table = append(table, fmt.Sprintf("%-15s %-8s %-15s %-7s %-7s%s", c.cve, p, c.installed, old, now, mark))
	}
	t.Logf("cve             product  installed       old     new\n%s", strings.Join(table, "\n"))
	t.Logf("verdict changes over %d cases: %v", len(cases), changes)
}

// TestVersionOrderProperties is a seeded random property check over
// generated versions of every shape the comparators see: pure numeric,
// OpenSSL letters, pre-releases, OpenSSH p releases, Java update tails,
// build suffixes and junk. compareVersions must be antisymmetric and
// transitive (200k random triples), and the strict comparator and the range
// gate must agree with it on every pair they decide.
func TestVersionOrderProperties(t *testing.T) {
	rng := rand.New(rand.NewSource(2044))
	num := func() string { return strconv.Itoa([]int{0, 0, 1, 2, 3, 9, 10, 391, 401}[rng.Intn(9)]) }
	gen := func() string {
		n := 1 + rng.Intn(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = num()
		}
		v := strings.Join(parts, ".")
		switch rng.Intn(12) {
		case 0:
			v += string(rune('a' + rng.Intn(26)))
		case 1:
			v += "z" + string(rune('a'+rng.Intn(26)))
		case 2:
			v += "-rc" + num()
		case 3:
			v += "p" + num()
		case 4:
			v += "_" + num()
		case 5:
			v += "u" + num()
		case 6:
			v += " (x64)"
		case 7:
			v += "esr"
		case 8:
			v = []string{"", "Unknown", "Build " + num(), "1:" + v, "HEAD"}[rng.Intn(5)]
		}
		return v
	}
	vs := make([]string, 300)
	for i := range vs {
		vs[i] = gen()
	}
	for _, a := range vs {
		for _, b := range vs {
			ab := compareVersions(a, b)
			if ab != -compareVersions(b, a) {
				t.Fatalf("not antisymmetric: %q vs %q", a, b)
			}
			if c, ok := compareVersionsStrict(a, b); ok && c != ab {
				t.Fatalf("%q vs %q: strict %d, compareVersions %d", a, b, c, ab)
			}
			if c, ok := compareInstalledToBound(a, b); ok && c != ab {
				t.Fatalf("%q vs %q: range gate %d, compareVersions %d", a, b, c, ab)
			}
		}
	}
	for i := 0; i < 200000; i++ {
		a, b, c := vs[rng.Intn(len(vs))], vs[rng.Intn(len(vs))], vs[rng.Intn(len(vs))]
		if compareVersions(a, b) <= 0 && compareVersions(b, c) <= 0 && compareVersions(a, c) > 0 {
			t.Fatalf("not transitive: %q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
	}
}
