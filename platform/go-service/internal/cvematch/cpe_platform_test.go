package cvematch

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// PAT-2107: the matcher ignored the CPE platform and exact versions, so a
// current OneDrive on macOS showed nine Windows and Android CVEs as
// "Possible", and Firefox 155 showed CVE-2003-* entries.

var pat2107Now = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func oneDriveMappings() []CPEMapping {
	return []CPEMapping{{MatchName: "OneDrive", CPEVendor: "microsoft", CPEProduct: "onedrive"}}
}

func oneDriveApps() []ScannedApp {
	return []ScannedApp{{Name: "OneDrive", Version: "26.163.0823"}}
}

// published is recent enough that the age cut never interferes with the
// platform and version assertions.
var published = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

func oneDriveCVE(id, targetSW string) CVEEntry {
	return CVEEntry{
		CVEID: id, Score: ptrScore(9.8), Severity: "CRITICAL",
		Patterns:    []string{"microsoft:onedrive"},
		Ranges:      []CPERange{{Vendor: "microsoft", Product: "onedrive", TargetSW: targetSW}},
		PublishedAt: published,
	}
}

func confidences(fs []Finding) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		out[f.CVEID] = f.MatchConfidence
	}
	return out
}

func TestMatch_PlatformFilter_TargetSW(t *testing.T) {
	feed := []CVEEntry{oneDriveCVE("CVE-2020-0935", "windows")}
	cases := []struct {
		platform string
		want     map[string]string
	}{
		{"macos", map[string]string{}},
		{"windows", map[string]string{"CVE-2020-0935": "version_unverified"}},
		{"", map[string]string{"CVE-2020-0935": "version_unverified"}}, // unknown platform: no filtering
	}
	for _, tc := range cases {
		t.Run("platform="+tc.platform, func(t *testing.T) {
			got := confidences(matchAt(oneDriveApps(), oneDriveMappings(), feed, tc.platform, pat2107Now))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("findings = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatch_PlatformFilter_Android(t *testing.T) {
	feed := []CVEEntry{oneDriveCVE("CVE-2022-23255", "android")}
	for _, platform := range []string{"macos", "windows"} {
		if got := matchAt(oneDriveApps(), oneDriveMappings(), feed, platform, pat2107Now); len(got) != 0 {
			t.Errorf("platform %s: android-only CVE produced %v, want none", platform, got)
		}
	}
}

func TestMatch_PlatformFilter_MixedRows(t *testing.T) {
	// One row for Windows and one for any platform: the any-platform row still
	// applies on macOS, so the CVE is reported there (unverified).
	e := oneDriveCVE("CVE-2099-0001", "windows")
	e.Ranges = append(e.Ranges, CPERange{Vendor: "microsoft", Product: "onedrive"})
	got := confidences(matchAt(oneDriveApps(), oneDriveMappings(), []CVEEntry{e}, "macos", pat2107Now))
	if want := map[string]string{"CVE-2099-0001": "version_unverified"}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}

	// A bounded Windows row that would confirm, and a macOS-compatible
	// exact-version row that excludes: on macOS only the latter counts.
	e2 := CVEEntry{CVEID: "CVE-2099-0002", Score: ptrScore(7), Patterns: []string{"microsoft:onedrive"}, PublishedAt: published,
		Ranges: []CPERange{
			{Vendor: "microsoft", Product: "onedrive", VEndExcl: "99.0", TargetSW: "windows"},
			{Vendor: "microsoft", Product: "onedrive", Version: "1.0", TargetSW: "mac_os_x"},
		}}
	if got := matchAt(oneDriveApps(), oneDriveMappings(), []CVEEntry{e2}, "macos", pat2107Now); len(got) != 0 {
		t.Errorf("macos: findings = %v, want none", got)
	}
	if got := confidences(matchAt(oneDriveApps(), oneDriveMappings(), []CVEEntry{e2}, "windows", pat2107Now)); got["CVE-2099-0002"] != "version_confirmed" {
		t.Errorf("windows: findings = %v, want CVE-2099-0002 confirmed", got)
	}
}

func TestMatch_ExactVersion(t *testing.T) {
	mappings := []CPEMapping{{MatchName: "Firefox", CPEVendor: "mozilla", CPEProduct: "firefox"}}
	feed := []CVEEntry{{
		CVEID: "CVE-2003-1492", Score: ptrScore(7.5), Severity: "HIGH",
		Patterns: []string{"mozilla:firefox"},
		Ranges:   []CPERange{{Vendor: "mozilla", Product: "firefox", Version: "0.8"}},
		// No PublishedAt: the exact version alone must decide.
	}}
	if got := matchAt([]ScannedApp{{Name: "Firefox", Version: "155.0.1"}}, mappings, feed, "macos", pat2107Now); len(got) != 0 {
		t.Errorf("Firefox 155.0.1: findings = %v, want none", got)
	}
	got := matchAt([]ScannedApp{{Name: "Firefox", Version: "0.8"}}, mappings, feed, "macos", pat2107Now)
	if len(got) != 1 || got[0].MatchConfidence != "version_confirmed" || got[0].FixedVersion != "" {
		t.Errorf("Firefox 0.8: findings = %+v, want one version_confirmed with no fixed version", got)
	}
}

func TestMatch_RunningOn(t *testing.T) {
	mappings := []CPEMapping{{MatchName: "Agent", CPEVendor: "acme", CPEProduct: "agent"}}
	apps := []ScannedApp{{Name: "Agent", Version: "1.5"}}
	feed := []CVEEntry{{
		CVEID: "CVE-2099-0100", Score: ptrScore(8), Patterns: []string{"acme:agent"}, PublishedAt: published,
		Ranges: []CPERange{{Vendor: "acme", Product: "agent", VEndExcl: "2.0", RunningOn: []string{"microsoft:windows"}}},
	}}
	if got := matchAt(apps, mappings, feed, "macos", pat2107Now); len(got) != 0 {
		t.Errorf("macos: findings = %v, want none", got)
	}
	if got := confidences(matchAt(apps, mappings, feed, "windows", pat2107Now)); got["CVE-2099-0100"] != "version_confirmed" {
		t.Errorf("windows: findings = %v, want confirmed", got)
	}
	if got := confidences(matchAt(apps, mappings, feed, "", pat2107Now)); got["CVE-2099-0100"] != "version_confirmed" {
		t.Errorf("unknown platform: findings = %v, want confirmed", got)
	}
}

func TestMatch_UnverifiedAgeCut(t *testing.T) {
	mappings := []CPEMapping{{MatchName: "MyApp", CPEVendor: "vendor", CPEProduct: "myapp"}}
	apps := []ScannedApp{{Name: "MyApp", Version: "1.5"}}
	entry := func(id string, pub time.Time, ranges []CPERange) CVEEntry {
		return CVEEntry{CVEID: id, Score: ptrScore(7), Patterns: []string{"vendor:myapp"}, Ranges: ranges, PublishedAt: pub}
	}
	feed := []CVEEntry{
		entry("CVE-2018-0001", time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC), nil),
		entry("CVE-2025-0002", time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC), nil),
		entry("CVE-0000-0003", time.Time{}, nil),
		entry("CVE-2018-0004", time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC),
			[]CPERange{{Vendor: "vendor", Product: "myapp", VStartIncl: "1.0", VEndExcl: "2.0"}}),
	}
	got := confidences(matchAt(apps, mappings, feed, "macos", pat2107Now))
	want := map[string]string{
		"CVE-2025-0002": "version_unverified", // unbounded, recent: kept
		"CVE-0000-0003": "version_unverified", // no published date: never dropped
		"CVE-2018-0004": "version_confirmed",  // confirmed: never age-cut
		// CVE-2018-0001: unbounded and over three years old: dropped
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

func TestMatch_LegacyRangesUnchanged(t *testing.T) {
	// cpe_ranges JSON as written before PAT-2107: no version, targetSW or
	// runningOn keys. Every platform must give exactly the old result, and
	// Match with no published date must equal the pre-PAT-2107 semantics.
	raw := `[{"vendor":"vendor","product":"myapp","vStartIncl":"1.0","vStartExcl":"","vEndIncl":"","vEndExcl":"2.0"},
	         {"vendor":"vendor","product":"other","vStartIncl":"","vStartExcl":"","vEndIncl":"","vEndExcl":"9.0"}]`
	var ranges []CPERange
	if err := json.Unmarshal([]byte(raw), &ranges); err != nil {
		t.Fatal(err)
	}
	mappings := []CPEMapping{{MatchName: "MyApp", CPEVendor: "vendor", CPEProduct: "myapp"}}
	feed := []CVEEntry{
		{CVEID: "CVE-L-1", Score: ptrScore(7), Patterns: []string{"vendor:myapp"}, Ranges: ranges},
		{CVEID: "CVE-L-2", Score: ptrScore(7), Patterns: []string{"vendor:myapp"}}, // no ranges at all
	}
	for _, v := range []string{"1.5", "2.5", "unknown"} {
		apps := []ScannedApp{{Name: "MyApp", Version: v}}
		base := matchAt(apps, mappings, feed, "", pat2107Now)
		for _, platform := range []string{"macos", "windows"} {
			if got := matchAt(apps, mappings, feed, platform, pat2107Now); !reflect.DeepEqual(got, base) {
				t.Errorf("version %s platform %s: %+v, want %+v", v, platform, got, base)
			}
		}
	}
	want := map[string]string{"CVE-L-1": "version_confirmed", "CVE-L-2": "version_unverified"}
	if got := confidences(matchAt([]ScannedApp{{Name: "MyApp", Version: "1.5"}}, mappings, feed, "macos", pat2107Now)); !reflect.DeepEqual(got, want) {
		t.Errorf("legacy 1.5: %v, want %v", got, want)
	}
}

func TestPlatformCompatible(t *testing.T) {
	cases := []struct {
		r        CPERange
		platform string
		want     bool
	}{
		{CPERange{}, "macos", true},
		{CPERange{TargetSW: "*"}, "windows", true},
		{CPERange{TargetSW: "-"}, "macos", true},
		{CPERange{TargetSW: "macos"}, "macos", true},
		{CPERange{TargetSW: "mac_os_x"}, "macos", true},
		{CPERange{TargetSW: "mac_os"}, "macos", true},
		{CPERange{TargetSW: "macos_sonoma"}, "macos", true},
		{CPERange{TargetSW: "iphone_os"}, "macos", true},
		{CPERange{TargetSW: "ipados"}, "macos", true},
		{CPERange{TargetSW: "windows"}, "macos", false},
		{CPERange{TargetSW: "android"}, "macos", false},
		{CPERange{TargetSW: "linux"}, "macos", false},
		{CPERange{TargetSW: "windows"}, "windows", true},
		{CPERange{TargetSW: "windows_10"}, "windows", true},
		{CPERange{TargetSW: "mac_os_x"}, "windows", false},
		{CPERange{TargetSW: "iphone_os"}, "windows", false},
		{CPERange{TargetSW: "android"}, "", true},
		{CPERange{RunningOn: []string{"apple:mac_os_x", "microsoft:windows_10"}}, "macos", true},
		{CPERange{RunningOn: []string{"apple:mac_os_x", "microsoft:windows_10"}}, "windows", true},
		{CPERange{RunningOn: []string{"apple:iphone_os"}}, "macos", false},
		{CPERange{RunningOn: []string{"linux:linux_kernel"}}, "windows", false},
		{CPERange{TargetSW: "mac_os_x", RunningOn: []string{"microsoft:windows"}}, "macos", false},
	}
	for _, tc := range cases {
		if got := platformCompatible(tc.r, tc.platform); got != tc.want {
			t.Errorf("platformCompatible(%+v, %q) = %v, want %v", tc.r, tc.platform, got, tc.want)
		}
	}
}

// NVD spells macOS several ways in target_sw. Missing one would hide a real
// vulnerability, so every mac*, os_x*, osx* spelling and darwin is macOS.
// "machine" is not a real target_sw; it is accepted by the mac* prefix, which
// is the deliberate direction of error (a spurious "Possible", never a hidden
// finding).
func TestTargetSWMacOSSpellings(t *testing.T) {
	macOS := []string{
		"macos", "mac_os", "mac_os_x", "macosx", "mac_os_x_server", "macos_sonoma",
		"os_x", "os_x_server", "osx", "darwin", "iphone_os", "ipados", "MacOSX", "machine",
	}
	for _, sw := range macOS {
		if !platformCompatible(CPERange{TargetSW: sw}, PlatformMacOS) {
			t.Errorf("target_sw %q should apply on macOS", sw)
		}
		if platformCompatible(CPERange{TargetSW: sw}, PlatformWindows) {
			t.Errorf("target_sw %q should not apply on Windows", sw)
		}
	}
	for _, sw := range []string{"windows", "windows_10", "windows_server_2019"} {
		if !platformCompatible(CPERange{TargetSW: sw}, PlatformWindows) || platformCompatible(CPERange{TargetSW: sw}, PlatformMacOS) {
			t.Errorf("target_sw %q should apply on Windows only", sw)
		}
	}
	// Only the exact "darwin" is a target_sw spelling; "darwin_x" is not.
	for _, sw := range []string{"android", "linux", "node.js", "ios", "chrome_os", "x64", "darwin_x"} {
		for _, p := range []string{PlatformMacOS, PlatformWindows} {
			if platformCompatible(CPERange{TargetSW: sw}, p) {
				t.Errorf("target_sw %q should not apply on %s", sw, p)
			}
		}
	}
}

// The same breadth applies to the OS CPEs an AND configuration requires.
func TestRunningOnMacOSSpellings(t *testing.T) {
	for _, k := range []string{
		"apple:macos", "apple:mac_os", "apple:mac_os_x", "apple:macosx", "apple:mac_os_x_server",
		"apple:os_x", "apple:osx", "apple:darwin", "apple:darwin_kernel", "Apple:Mac_OS_X",
	} {
		r := CPERange{RunningOn: []string{k}}
		if !platformCompatible(r, PlatformMacOS) {
			t.Errorf("running on %q should apply on macOS", k)
		}
		if platformCompatible(r, PlatformWindows) {
			t.Errorf("running on %q should not apply on Windows", k)
		}
	}
	for _, k := range []string{"microsoft:windows", "microsoft:windows_10", "microsoft:windows_server_2022"} {
		r := CPERange{RunningOn: []string{k}}
		if !platformCompatible(r, PlatformWindows) || platformCompatible(r, PlatformMacOS) {
			t.Errorf("running on %q should apply on Windows only", k)
		}
	}
	for _, k := range []string{
		"apple:iphone_os", "apple:ipados", "google:android", "linux:linux_kernel",
		"microsoft:macos", "mac:os_x", "apple:", "microsoft:xbox_os",
	} {
		r := CPERange{RunningOn: []string{k}}
		for _, p := range []string{PlatformMacOS, PlatformWindows} {
			if platformCompatible(r, p) {
				t.Errorf("running on %q should not apply on %s", k, p)
			}
		}
	}
}
