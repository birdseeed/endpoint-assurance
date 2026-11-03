package cvematch

// PAT-2029: app_cpe_mappings carries a platform column ('any' | 'macos' |
// 'windows'), but the app-name matchers loaded mappings without it, so a
// platform-specific mapping (e.g. Microsoft Word's windows-only CPE) applied
// to every device regardless of its own platform. This file tests the shared
// helpers both matchers (cmd/patched-cve-sync and internal/cvepipeline) now
// use to scope mappings to a device's platform.

import (
	"reflect"
	"sort"
	"testing"
)

func TestNormalizeDevicePlatform(t *testing.T) {
	cases := []struct {
		os, want string
	}{
		{"macOS", PlatformMacOS},
		{"Windows", PlatformWindows},
		{"macos", PlatformMacOS}, // case-insensitive
		{"windows", PlatformWindows},
		{"Darwin", PlatformMacOS}, // internal report package's toolingPlatform accepts this too
		{"", PlatformUnknown},     // never-reported OS: unknown, not a guess
		{"Mac OS X", PlatformMacOS},
		{"Windows 11 Pro", PlatformWindows},
		{"machine", PlatformUnknown}, // a bare "mac" prefix must not match
		{"macro", PlatformUnknown},
		{"Linux", PlatformUnknown}, // a real but unsupported OS: unknown, never mapped to macos/windows
		{"BeOS", PlatformUnknown},
		{"  macOS  ", PlatformMacOS}, // trimmed
	}
	for _, c := range cases {
		if got := NormalizeDevicePlatform(c.os); got != c.want {
			t.Errorf("NormalizeDevicePlatform(%q) = %q, want %q", c.os, got, c.want)
		}
	}
}

func TestMappingApplies(t *testing.T) {
	cases := []struct {
		mappingPlatform, devicePlatform string
		want                            bool
	}{
		{PlatformAny, PlatformMacOS, true},
		{PlatformAny, PlatformWindows, true},
		{PlatformAny, PlatformUnknown, true},
		{"", PlatformMacOS, true}, // zero-value mapping platform treated as "any"
		{"", PlatformUnknown, true},
		{PlatformMacOS, PlatformMacOS, true},
		{PlatformMacOS, PlatformWindows, false},
		{PlatformMacOS, PlatformUnknown, false}, // never guess: unknown device gets no platform-specific mapping
		{PlatformWindows, PlatformWindows, true},
		{PlatformWindows, PlatformMacOS, false},
		{PlatformWindows, PlatformUnknown, false},
	}
	for _, c := range cases {
		if got := MappingApplies(c.mappingPlatform, c.devicePlatform); got != c.want {
			t.Errorf("MappingApplies(%q, %q) = %v, want %v", c.mappingPlatform, c.devicePlatform, got, c.want)
		}
	}
}

func TestFilterMappingsForPlatform(t *testing.T) {
	winWord := CPEMapping{MatchName: "Test Word", CPEVendor: "microsoft", CPEProduct: "word", Platform: PlatformWindows}
	macWord := CPEMapping{MatchName: "Test Word", CPEVendor: "microsoft", CPEProduct: "word-mac", Platform: PlatformMacOS}
	anyApp := CPEMapping{MatchName: "Test AnyApp", CPEVendor: "acme", CPEProduct: "anyapp", Platform: PlatformAny}
	mappings := []CPEMapping{winWord, macWord, anyApp}

	cases := []struct {
		name           string
		devicePlatform string
		want           []CPEMapping
	}{
		{"windows device", PlatformWindows, []CPEMapping{winWord, anyApp}},
		{"macos device", PlatformMacOS, []CPEMapping{macWord, anyApp}},
		{"unknown platform device gets only any", PlatformUnknown, []CPEMapping{anyApp}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FilterMappingsForPlatform(mappings, c.devicePlatform)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("FilterMappingsForPlatform(%q) = %+v, want %+v", c.devicePlatform, got, c.want)
			}
		})
	}
}

// TestMatchRespectsPlatformScoping is the shared-engine-level version of the
// PAT-2029 scenario: one product ("Test Word") has different mappings on
// Windows and macOS, plus an "any" mapping for a second product. Calling
// Match with the platform-filtered mapping list (as both matchers now do)
// must never let a wrong-platform mapping produce a finding.
func TestMatchRespectsPlatformScoping(t *testing.T) {
	winWord := CPEMapping{MatchName: "Test Word", CPEVendor: "microsoft", CPEProduct: "word", Platform: PlatformWindows}
	macWord := CPEMapping{MatchName: "Test Word", CPEVendor: "microsoft", CPEProduct: "word-mac", Platform: PlatformMacOS}
	anyApp := CPEMapping{MatchName: "Test AnyApp", CPEVendor: "acme", CPEProduct: "anyapp", Platform: PlatformAny}
	mappings := []CPEMapping{winWord, macWord, anyApp}

	feed := []CVEEntry{
		{CVEID: "CVE-WORD-WIN", Score: score(9.0), Severity: "CRITICAL", Patterns: []string{"microsoft:word"}},
		{CVEID: "CVE-WORD-MAC", Score: score(8.0), Severity: "HIGH", Patterns: []string{"microsoft:word-mac"}},
		{CVEID: "CVE-ANY", Score: score(7.0), Severity: "HIGH", Patterns: []string{"acme:anyapp"}},
	}
	apps := []ScannedApp{{Name: "Test Word", Version: "1.0"}, {Name: "Test AnyApp", Version: "1.0"}}

	cveIDs := func(findings []Finding) []string {
		var out []string
		for _, f := range findings {
			out = append(out, f.CVEID)
		}
		sort.Strings(out)
		return out
	}

	t.Run("windows device", func(t *testing.T) {
		filtered := FilterMappingsForPlatform(mappings, PlatformWindows)
		got := cveIDs(Match(apps, filtered, feed, PlatformWindows))
		want := []string{"CVE-ANY", "CVE-WORD-WIN"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("windows device findings = %v, want %v", got, want)
		}
	})

	t.Run("macos device", func(t *testing.T) {
		filtered := FilterMappingsForPlatform(mappings, PlatformMacOS)
		got := cveIDs(Match(apps, filtered, feed, PlatformMacOS))
		want := []string{"CVE-ANY", "CVE-WORD-MAC"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("macos device findings = %v, want %v", got, want)
		}
	})

	t.Run("unknown platform device", func(t *testing.T) {
		filtered := FilterMappingsForPlatform(mappings, PlatformUnknown)
		got := cveIDs(Match(apps, filtered, feed, PlatformUnknown))
		want := []string{"CVE-ANY"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unknown-platform device findings = %v, want %v", got, want)
		}
	})

	t.Run("unfiltered mappings leak cross platform (documents the pre-PAT-2029 bug)", func(t *testing.T) {
		// Calling Match with the raw, unfiltered mapping list — the shape
		// both matchers used before PAT-2029 — matches the Windows-only CPE
		// against a macOS device's install (or vice versa). This is exactly
		// the bug: FilterMappingsForPlatform is what call sites must apply
		// before Match, not something Match itself guards against.
		got := cveIDs(Match(apps, mappings, feed, PlatformUnknown))
		want := []string{"CVE-ANY", "CVE-WORD-MAC", "CVE-WORD-WIN"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unfiltered findings = %v, want %v", got, want)
		}
	})
}
