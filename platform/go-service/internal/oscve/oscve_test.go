package oscve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ptrF(f float64) *float64 { return &f }

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// ─── Apple parser ──────────────────────────────────────────────────────────────

func TestParseApple(t *testing.T) {
	advisories, err := ParseApple(readFixture(t, "apple_security_releases.json"))
	if err != nil {
		t.Fatalf("ParseApple: %v", err)
	}

	// 3 macOS CVEs from Sonoma + 1 from Ventura = 4. iOS release is filtered out.
	if len(advisories) != 4 {
		t.Fatalf("expected 4 macOS advisories, got %d: %+v", len(advisories), advisories)
	}
	for _, a := range advisories {
		if a.Platform != PlatformMacOS {
			t.Errorf("non-macos advisory leaked through filter: %+v", a)
		}
		if a.Source != SourceApple {
			t.Errorf("expected source apple, got %q", a.Source)
		}
		if a.VendorTitle != "" {
			t.Errorf("Apple feed supplied no per-CVE title, got %q", a.VendorTitle)
		}
	}

	// Spot-check the Sonoma 14.5 / build 23F79 record carries score + url.
	var found bool
	for _, a := range advisories {
		if a.CVEID == "CVE-2024-23296" {
			found = true
			if a.OSVersion != "14.5" || a.OSBuild != "23F79" {
				t.Errorf("bad version/build: %q/%q", a.OSVersion, a.OSBuild)
			}
			if a.Score == nil || *a.Score != 7.8 {
				t.Errorf("expected score 7.8, got %v", a.Score)
			}
			if a.Severity != "HIGH" {
				t.Errorf("expected HIGH, got %q", a.Severity)
			}
			if a.AdvisoryURL == "" {
				t.Errorf("expected advisory url")
			}
			if a.FixedInBuild != "23F79" {
				t.Errorf("expected fixed-in build 23F79, got %q", a.FixedInBuild)
			}
		}
	}
	if !found {
		t.Errorf("CVE-2024-23296 not found")
	}
}

func TestParseAppleOfficialHTMLAndGDMF(t *testing.T) {
	index := []byte(`<html><table><tr><td><a href="/en-us/120903">macOS Sonoma 14.5</a></td><td>13 May 2024</td></tr><tr><td><a href="/x">iOS 17.5</a></td></tr></table></html>`)
	releases, err := ParseAppleSecurityIndex(index, AppleSecurityReleasesURL)
	if err != nil || len(releases) != 1 {
		t.Fatalf("ParseAppleSecurityIndex = %+v, %v", releases, err)
	}
	if releases[0].Version != "14.5" || releases[0].DocumentID != "en-us/120903" {
		t.Fatalf("unexpected release: %+v", releases[0])
	}
	builds, err := ParseAppleGDMF([]byte(`{"AssetSets":{"macOS":[{"ProductVersion":"14.5","Build":"23F79"}]},"PublicAssetSets":{"macOS":[]}}`))
	if err != nil || builds["14.5"] != "23F79" {
		t.Fatalf("ParseAppleGDMF = %v, %v", builds, err)
	}
	advisories, err := ParseAppleAdvisoryHTML([]byte(`<h1>About macOS Sonoma 14.5</h1><p>CVE-2024-23296</p><p>cve-2024-23296</p>`), releases[0], builds["14.5"])
	if err != nil || len(advisories) != 1 {
		t.Fatalf("ParseAppleAdvisoryHTML = %+v, %v", advisories, err)
	}
	if advisories[0].FixedInBuild != "23F79" || advisories[0].SourceDocumentID != "en-us/120903" {
		t.Fatalf("unexpected advisory: %+v", advisories[0])
	}
}

func TestParseAppleGDMFWithholdsAmbiguousBuild(t *testing.T) {
	builds, err := ParseAppleGDMF([]byte(`{"AssetSets":{"macOS":[{"ProductVersion":"14.5","Build":"23F79"}]},"PublicAssetSets":{"macOS":[{"ProductVersion":"14.5","Build":"23F80"}]}}`))
	build, present := builds["14.5"]
	if err != nil || !present || build != "" {
		t.Fatalf("ambiguous GDMF = %v, %v", builds, err)
	}
}

// ─── MSRC parser ───────────────────────────────────────────────────────────────

func TestParseMSRC(t *testing.T) {
	advisories, err := ParseMSRC(readFixture(t, "msrc_cvrf.json"))
	if err != nil {
		t.Fatalf("ParseMSRC: %v", err)
	}

	// CVE-2024-30080 affects Win10 22H2 + Win11 23H2 (Server filtered) = 2.
	// CVE-2024-30078 affects Win10 22H2 only = 1. Total 3.
	if len(advisories) != 3 {
		t.Fatalf("expected 3 windows advisories, got %d: %+v", len(advisories), advisories)
	}
	for _, a := range advisories {
		if a.Platform != PlatformWindows {
			t.Errorf("non-windows advisory: %+v", a)
		}
		if a.Source != SourceMSRC {
			t.Errorf("expected source msrc, got %q", a.Source)
		}
	}

	// Spot-check Win10 22H2 / CVE-2024-30080: dotted build is the
	// comparable value; KB is retained as provenance only.
	var checked bool
	for _, a := range advisories {
		if a.CVEID == "CVE-2024-30080" && a.OSVersion == "22H2" {
			checked = true
			if a.OSBuild != "10.0.19045.4651" {
				t.Errorf("expected dotted fixed build, got %q", a.OSBuild)
			}
			if a.VendorReference != "KB5039217" {
				t.Errorf("expected KB provenance, got %q", a.VendorReference)
			}
			if a.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL, got %q", a.Severity)
			}
			if a.Score == nil || *a.Score != 9.8 {
				t.Errorf("expected 9.8, got %v", a.Score)
			}
			if a.FixedInBuild != "10.0.19045.4651" {
				t.Errorf("expected fixed build, got %q", a.FixedInBuild)
			}
			if a.VendorTitle != "Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability" {
				t.Errorf("unexpected vendor title %q", a.VendorTitle)
			}
		}
	}
	if !checked {
		t.Errorf("Win10 22H2 CVE-2024-30080 not found")
	}

	// KB-prefixed remediation remains provenance and never becomes a build.
	for _, a := range advisories {
		if a.CVEID == "CVE-2024-30078" && (a.OSBuild != "10.0.19045.4651" || a.VendorReference != "KB5039217") {
			t.Errorf("MSRC build/provenance not separated: %+v", a)
		}
	}
}

func TestParseMSRCExcludesProductsRunningOnWindows(t *testing.T) {
	payload := []byte(`{
		"ProductTree":{"FullProductName":[
			{"ProductID":"os","Value":"Windows 11 Version 24H2 for x64-based Systems"},
			{"ProductID":"app","Value":"Raw Image Extension on Windows 11 Version 24H2 for x64-based Systems"}
		]},
		"Vulnerability":[{"CVE":"CVE-2026-1918","ProductStatuses":[{"Type":3,"ProductID":["os","app"]}],
			"Remediations":[{"Type":2,"Description":{"Value":"5001918"},"ProductID":["os","app"],"FixedBuild":"10.0.26100.5000"}]}]
	}`)
	advisories, err := ParseMSRC(payload)
	if err != nil {
		t.Fatalf("ParseMSRC: %v", err)
	}
	if len(advisories) != 1 || advisories[0].OSVersion != "24H2" {
		t.Fatalf("non-OS Windows product leaked into OS advisories: %+v", advisories)
	}
}

func TestParseMSRCUpdatesUsesCatalogueURL(t *testing.T) {
	updates, err := ParseMSRCUpdates([]byte(`{"value":[{"ID":"2026-Sep","CurrentReleaseDate":"2026-09-19T00:00:00Z","CvrfUrl":"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep"}]}`))
	if err != nil || len(updates) != 1 {
		t.Fatalf("ParseMSRCUpdates = %+v, %v", updates, err)
	}
	if updates[0].CvrfURL != "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep" {
		t.Fatalf("catalogue URL lost: %+v", updates[0])
	}
}

// ─── KEV parser ────────────────────────────────────────────────────────────────

func TestParseKEV(t *testing.T) {
	set, err := ParseKEV(readFixture(t, "kev.json"))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if !set["CVE-2024-23296"] || !set["CVE-2024-30080"] {
		t.Errorf("expected both KEV CVEs present, got %v", set)
	}
	if set["CVE-2024-27834"] {
		t.Errorf("non-KEV CVE flagged")
	}
}

// ─── Matcher ───────────────────────────────────────────────────────────────────

func TestMatchOS(t *testing.T) {
	advisories := []Advisory{
		{Platform: PlatformMacOS, OSVersion: "14.5", OSBuild: "23F79", FixedInBuild: "23F79", CVEID: "CVE-2024-23296", Score: ptrF(7.8), Severity: "HIGH", Source: SourceApple},
		{Platform: PlatformMacOS, OSVersion: "14.5", OSBuild: "23F79", FixedInBuild: "23F79", CVEID: "CVE-2024-27834", Severity: "HIGH", Source: SourceApple},
		{Platform: PlatformMacOS, OSVersion: "13.6.7", OSBuild: "22G720", FixedInBuild: "22G720", CVEID: "CVE-2024-27834", Severity: "HIGH", Source: SourceApple},
		{Platform: PlatformWindows, OSVersion: "22H2", OSBuild: "10.0.19045.4651", FixedInBuild: "10.0.19045.4651", CVEID: "CVE-2024-30080", Score: ptrF(9.8), Severity: "CRITICAL", Source: SourceMSRC},
	}

	tests := []struct {
		name     string
		dev      DeviceOS
		wantCVEs []string
	}{
		{
			name:     "macos build-precise match",
			dev:      DeviceOS{Platform: "macos", OSVersion: "14.4", OSBuild: "23E214"},
			wantCVEs: []string{"CVE-2024-23296", "CVE-2024-27834"},
		},
		{
			name:     "macos version fallback when no build reported",
			dev:      DeviceOS{Platform: "macos", OSVersion: "13.6.6"},
			wantCVEs: []string{"CVE-2024-27834"},
		},
		{
			name:     "build mismatch yields nothing even on same version family",
			dev:      DeviceOS{Platform: "macos", OSVersion: "14.5", OSBuild: "23F99"},
			wantCVEs: nil,
		},
		{
			name:     "windows version match",
			dev:      DeviceOS{Platform: "windows", OSVersion: "10.0.19045.4500", OSBuild: "19045"},
			wantCVEs: []string{"CVE-2024-30080"},
		},
		{
			name:     "platform mismatch",
			dev:      DeviceOS{Platform: "windows", OSVersion: "14.5", OSBuild: "23F79"},
			wantCVEs: nil,
		},
		{
			name:     "case-insensitive build match",
			dev:      DeviceOS{Platform: "macos", OSVersion: "14.4", OSBuild: "23e214"},
			wantCVEs: []string{"CVE-2024-23296", "CVE-2024-27834"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := MatchOS(tt.dev, advisories)
			if len(findings) != len(tt.wantCVEs) {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), len(tt.wantCVEs), findings)
			}
			for i, want := range tt.wantCVEs {
				if findings[i].CVEID != want {
					t.Errorf("finding[%d] = %q, want %q", i, findings[i].CVEID, want)
				}
				if findings[i].MatchConfidence != MatchConfidenceVendorConfirmed {
					t.Errorf("expected vendor-confirmed confidence, got %q", findings[i].MatchConfidence)
				}
			}
		})
	}
}

func TestMatchOS_AppNameAndVersion(t *testing.T) {
	advisories := []Advisory{
		{Platform: PlatformMacOS, OSVersion: "14.5", OSBuild: "23F79", CVEID: "CVE-2024-23296", FixedInBuild: "23F80", Source: SourceApple},
	}
	f := MatchOS(DeviceOS{Platform: "macos", OSVersion: "14.5", OSBuild: "23F70"}, advisories)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].AppName != "macOS" {
		t.Errorf("expected AppName macOS, got %q", f[0].AppName)
	}
	if f[0].AppVersion != "23F70" {
		t.Errorf("expected device AppVersion 23F70, got %q", f[0].AppVersion)
	}
	if f[0].FixedVersion != "23F80" {
		t.Errorf("expected FixedVersion 23F80 from advisory, got %q", f[0].FixedVersion)
	}
	if f[0].Source != SourceApple {
		t.Errorf("expected source apple, got %q", f[0].Source)
	}
}

func TestMatchOS_AbsentWindowsFixedBuildDoesNotGuess(t *testing.T) {
	advisories := []Advisory{
		{Platform: PlatformWindows, OSVersion: "22H2", OSBuild: "19045.1", CVEID: "CVE-2024-9999", Source: SourceMSRC},
	}
	findings := MatchOS(DeviceOS{Platform: PlatformWindows, OSVersion: "10.0.19045.1", OSBuild: "19045"}, advisories)
	if len(findings) != 0 {
		t.Fatalf("incomparable advisory produced findings: %+v", findings)
	}
}

func TestMatchOSFixedBeforeBoundaries(t *testing.T) {
	mac := Advisory{Platform: PlatformMacOS, OSVersion: "15.7.1", OSBuild: "24G231", FixedInBuild: "24G231", CVEID: "CVE-2026-1000", Source: SourceApple}
	for _, tc := range []struct {
		name string
		dev  DeviceOS
		want int
	}{
		{"apple older release", DeviceOS{Platform: PlatformMacOS, OSVersion: "15.7", OSBuild: "24G200"}, 1},
		{"apple exact fixed release", DeviceOS{Platform: PlatformMacOS, OSVersion: "15.7.1", OSBuild: "24G231"}, 0},
		{"apple newer release", DeviceOS{Platform: PlatformMacOS, OSVersion: "15.7.2", OSBuild: "24G300"}, 0},
		{"apple different train", DeviceOS{Platform: PlatformMacOS, OSVersion: "26.0", OSBuild: "25A1"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(MatchOS(tc.dev, []Advisory{mac})); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
	win := Advisory{Platform: PlatformWindows, OSVersion: "24H2", OSBuild: "10.0.26100.5000", FixedInBuild: "10.0.26100.5000", VendorReference: "KB5000000", CVEID: "CVE-2026-1001", Source: SourceMSRC}
	for _, tc := range []struct {
		name, version string
		want          int
	}{
		{"windows older", "10.0.26100.4999", 1},
		{"windows exact", "10.0.26100.5000", 0},
		{"windows newer", "10.0.26100.5001", 0},
		{"windows different train", "10.0.22631.9999", 0},
		{"windows missing revision", "10.0.26100", 0},
		{"windows annotated build fails closed", "Version 10.0.26100.4999", 0},
		{"windows extra build segment fails closed", "10.0.26100.4999.1", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := MatchOS(DeviceOS{Platform: PlatformWindows, OSVersion: tc.version}, []Advisory{win})
			if len(findings) != tc.want {
				t.Fatalf("got %+v, want %d", findings, tc.want)
			}
			if len(findings) > 0 && strings.HasPrefix(findings[0].FixedVersion, "KB") {
				t.Fatalf("KB leaked as fixed version: %+v", findings[0])
			}
		})
	}
}

// ─── Reconciliation ─────────────────────────────────────────────────────────────

func TestReconcileWithNVD(t *testing.T) {
	nvd := []NVDOSFinding{
		// OS finding that a vendor advisory will supersede.
		{CVEID: "CVE-2024-23296", AppName: "macOS", AppVersion: "14.5", MatchConfidence: "version_unverified", IsOS: true},
		// OS finding with NO vendor advisory — must survive as fallback.
		{CVEID: "CVE-2024-99999", AppName: "macOS", AppVersion: "14.5", MatchConfidence: "version_unverified", IsOS: true},
		// Non-OS app finding — must never be touched even if CVE collides.
		{CVEID: "CVE-2024-23296", AppName: "Google Chrome", AppVersion: "120.0", MatchConfidence: "version_confirmed", IsOS: false},
	}
	vendor := []Finding{
		{CVEID: "CVE-2024-23296", AppName: "macOS", AppVersion: "23F79", MatchConfidence: MatchConfidenceVendorConfirmed, Source: SourceApple},
	}

	out := ReconcileWithNVD(nvd, vendor)

	// Expected: NVD app finding kept, NVD fallback OS finding kept, NVD OS finding
	// for CVE-2024-23296 dropped, vendor finding appended. Total 3.
	if len(out) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(out), out)
	}

	var sawVendor, sawFallback, sawApp, sawDroppedNVDOS bool
	for _, f := range out {
		switch {
		case f.CVEID == "CVE-2024-23296" && f.IsOS && f.MatchConfidence == MatchConfidenceVendorConfirmed:
			sawVendor = true
		case f.CVEID == "CVE-2024-99999" && f.IsOS:
			sawFallback = true
		case f.CVEID == "CVE-2024-23296" && !f.IsOS:
			sawApp = true
		case f.CVEID == "CVE-2024-23296" && f.IsOS && f.MatchConfidence != MatchConfidenceVendorConfirmed:
			sawDroppedNVDOS = true
		}
	}
	if !sawVendor {
		t.Errorf("vendor finding not present")
	}
	if !sawFallback {
		t.Errorf("NVD fallback OS finding dropped")
	}
	if !sawApp {
		t.Errorf("non-OS app finding dropped")
	}
	if sawDroppedNVDOS {
		t.Errorf("superseded NVD OS finding was not dropped")
	}
}
