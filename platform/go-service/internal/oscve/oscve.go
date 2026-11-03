// Package oscve implements authoritative OS-build → CVE matching (PAT-409).
//
// The launch path (PAT-335, internal/cvematch) feeds the device OS to the generic
// CVE match engine as a pseudo-app (apple:macos / microsoft:windows_*) using NVD
// CPE data with version-range gating. NVD's OS-build coverage is coarse and noisy.
//
// This package adds vendor-grade sources — Apple security releases and Microsoft
// MSRC — parsed into per-(os version/build → CVE) Advisory records, and a matcher
// that prefers those vendor advisories over NVD for OS findings. NVD CPE remains
// the fallback where no vendor advisory exists.
//
// The package is pure and stateless (no DB / network dependency), mirroring
// internal/cvematch: the fetcher/parser produce []Advisory, storage and matching
// are separate seams. This keeps it unit-testable against committed fixtures
// without live HTTP.
package oscve

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Source identifies where an advisory came from.
type Source string

const (
	SourceApple Source = "apple" // Apple security-releases feed
	SourceMSRC  Source = "msrc"  // Microsoft Security Update Guide (CVRF)
)

// Platform values stored in os_cve_advisories.os_platform and matched against the
// device platform.
const (
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
)

// MatchConfidenceVendorConfirmed is the confidence value emitted for OS findings
// backed by a vendor advisory. It is distinct from the NVD CPE engine's
// "version_confirmed" / "version_unverified" (internal/cvematch) so the report can
// render OS CVEs as vendor-grade. Persisted to device_cve_findings.match_confidence.
const MatchConfidenceVendorConfirmed = "version_vendor_confirmed"

// Advisory is one vendor-confirmed (OS version/build → CVE) record. It is the
// parsed, source-agnostic shape that both the Apple and MSRC parsers produce and
// that is persisted to os_cve_advisories.
type Advisory struct {
	Platform         string   // "macos" | "windows"
	OSVersion        string   // marketing version, e.g. "14.5" / "10.0.19045"
	OSBuild          string   // build / KB, e.g. "23F79" / "19045.4651" / "KB5040442"
	CVEID            string   // CVE-YYYY-NNNN
	Score            *float64 // CVSS base score; nil when the feed omits it
	Severity         string   // CRITICAL/HIGH/MEDIUM/LOW/NONE (best-effort)
	FixedInBuild     string   // build/KB that remediates, where the feed states it
	Source           Source   // "apple" | "msrc"
	VendorTitle      string   // source-supplied advisory title; empty when absent
	AdvisoryURL      string   // source advisory page
	VendorReference  string   // vendor reference such as a KB; never a comparable build
	SourceDocumentID string   // stable vendor document identifier used for reconciliation
	PublishedAt      *time.Time
}

// DeviceOS describes the OS of a single device to match against vendor advisories.
type DeviceOS struct {
	Platform  string // "macos" | "windows"
	OSVersion string // marketing version reported by the agent
	OSBuild   string // build reported by the agent (may be empty)
}

// Finding is one OS CVE matched to a device from a vendor advisory.
//
// It is intentionally shaped to drop straight into the existing
// device_cve_findings persistence (cmd/patched-cve-sync) and the report read path
// (internal/report.CVEHit): AppName carries the OS display name ("macOS" /
// "Windows"), AppVersion the build/version, MatchConfidence the vendor value,
// and FixedVersion the vendor-stated remediation build when one exists.
type Finding struct {
	CVEID           string
	Score           *float64
	Severity        string
	AppName         string // "macOS" | "Windows" — surfaced as the affected "app"
	AppVersion      string // OS build / version string
	MatchConfidence string // MatchConfidenceVendorConfirmed
	FixedVersion    string // vendor-stated remediation build; empty when absent
	Source          Source
	VendorTitle     string
	AdvisoryURL     string
}

// osDisplayName maps an internal platform key to the display name used in reports,
// matching the app_cpe_mappings match_name rows ("macOS" / "Windows").
func osDisplayName(platform string) string {
	switch strings.ToLower(platform) {
	case PlatformMacOS:
		return "macOS"
	case PlatformWindows:
		return "Windows"
	default:
		return platform
	}
}

// MatchOS returns the vendor-confirmed OS CVE findings for one device.
//
// An advisory matches the device when:
//   - the platform matches, AND
//   - the device build matches the advisory build (exact), OR — when the device
//     reports no build, or the advisory carries no build — the marketing version
//     matches.
//
// Build match is preferred because Apple/MSRC advisories are build-precise; the
// version fallback covers agents that only report a marketing version. Results are
// de-duplicated per CVE (a CVE listed against several builds yields one finding)
// and sorted by CVE ID for deterministic output.
func MatchOS(dev DeviceOS, advisories []Advisory) []Finding {
	devPlatform := strings.ToLower(dev.Platform)
	devBuild := strings.TrimSpace(dev.OSBuild)
	devVersion := strings.TrimSpace(dev.OSVersion)

	seen := map[string]bool{}
	var findings []Finding
	for _, a := range advisories {
		if strings.ToLower(a.Platform) != devPlatform {
			continue
		}
		if !advisoryAppliesToDevice(a, devBuild, devVersion) {
			continue
		}
		if seen[a.CVEID] {
			continue
		}
		seen[a.CVEID] = true

		appVersion := devBuild
		if appVersion == "" {
			appVersion = devVersion
		}
		fixedVersion := a.FixedInBuild
		if fixedVersion == "" && devPlatform == PlatformMacOS {
			fixedVersion = a.OSVersion
		}
		findings = append(findings, Finding{
			CVEID:           a.CVEID,
			Score:           a.Score,
			Severity:        a.Severity,
			AppName:         osDisplayName(a.Platform),
			AppVersion:      appVersion,
			MatchConfidence: MatchConfidenceVendorConfirmed,
			FixedVersion:    fixedVersion,
			Source:          a.Source,
			VendorTitle:     a.VendorTitle,
			AdvisoryURL:     a.AdvisoryURL,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].CVEID < findings[j].CVEID })
	return findings
}

// advisoryAppliesToDevice decides whether one advisory applies to the device's
// build / version. Both build and version comparisons are case-insensitive and
// whitespace-trimmed.
func advisoryAppliesToDevice(a Advisory, devBuild, devVersion string) bool {
	switch strings.ToLower(a.Platform) {
	case PlatformMacOS:
		return appleFixedAfterDevice(devVersion, devBuild, a.OSVersion, a.OSBuild)
	case PlatformWindows:
		return windowsFixedAfterDevice(devVersion, devBuild, a.FixedInBuild)
	default:
		return false
	}
}

var dottedVersionRE = regexp.MustCompile(`\d+(?:\.\d+)+`)
var exactWindowsBuildRE = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
var appleBuildRE = regexp.MustCompile(`(?i)^(\d+)([a-z]+)(\d+)$`)

func numericVersion(s string) ([]int, bool) {
	token := dottedVersionRE.FindString(strings.TrimSpace(s))
	if token == "" {
		return nil, false
	}
	parts := strings.Split(token, ".")
	out := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func compareNumericVersion(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func appleBuildParts(s string) (int, string, int, bool) {
	m := appleBuildRE.FindStringSubmatch(strings.TrimSpace(s))
	if len(m) != 4 {
		return 0, "", 0, false
	}
	major, err1 := strconv.Atoi(m[1])
	suffix, err2 := strconv.Atoi(m[3])
	if err1 != nil || err2 != nil {
		return 0, "", 0, false
	}
	return major, strings.ToUpper(m[2]), suffix, true
}

func appleFixedAfterDevice(deviceVersion, deviceBuild, fixedVersion, fixedBuild string) bool {
	dv, dok := numericVersion(deviceVersion)
	fv, fok := numericVersion(fixedVersion)
	if dok && fok {
		if dv[0] != fv[0] {
			return false
		}
		switch compareNumericVersion(dv, fv) {
		case -1:
			return true
		case 1:
			return false
		}
		// Equal release is fixed. A strictly older comparable build is the
		// sole exception (for supplemental builds sharing a marketing version).
	}
	dMajor, dTrain, dSuffix, dbok := appleBuildParts(deviceBuild)
	fMajor, fTrain, fSuffix, fbok := appleBuildParts(fixedBuild)
	if !dbok || !fbok || dMajor != fMajor {
		return false
	}
	if dTrain != fTrain {
		return dTrain < fTrain
	}
	return dSuffix < fSuffix
}

func windowsFixedAfterDevice(deviceVersion, deviceBuild, fixedBuild string) bool {
	dv, dok := exactWindowsBuild(deviceVersion)
	if !dok {
		dv, dok = exactWindowsBuild(deviceBuild)
	}
	fv, fok := exactWindowsBuild(fixedBuild)
	// A full Windows build has major.minor.build.revision. A base build or KB
	// is not enough evidence to call an endpoint vulnerable.
	if !dok || !fok || len(dv) < 4 || len(fv) < 4 {
		return false
	}
	for i := 0; i < 3; i++ {
		if dv[i] != fv[i] {
			return false
		}
	}
	return compareNumericVersion(dv, fv) < 0
}

func exactWindowsBuild(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if !exactWindowsBuildRE.MatchString(s) {
		return nil, false
	}
	return numericVersion(s)
}

// ReconcileWithNVD removes NVD CPE OS findings that are superseded by a vendor
// advisory for the same CVE, then appends the vendor findings. This is the
// "prefer vendor data" step: for any CVE present in both the NVD CPE findings and
// the vendor findings, the vendor finding wins and the NVD one is dropped. NVD CPE
// findings for CVEs with no vendor advisory are kept as the fallback.
//
// nvdAppNames is the set of OS pseudo-app display names the NVD engine emits for
// the OS (e.g. {"macOS", "Windows"}); only findings for those app names are
// considered OS findings and eligible for supersession. App (non-OS) NVD findings
// are never touched.
//
// nvdFindings carries the same fields as report-layer hits; we operate on the
// minimal shape via NVDOSFinding to keep this package free of the report import.
func ReconcileWithNVD(nvdFindings []NVDOSFinding, vendorFindings []Finding) []NVDOSFinding {
	vendorCVEs := map[string]bool{}
	for _, f := range vendorFindings {
		vendorCVEs[f.CVEID] = true
	}

	out := make([]NVDOSFinding, 0, len(nvdFindings)+len(vendorFindings))
	for _, nf := range nvdFindings {
		// Drop an NVD OS finding only when it is an OS finding (matched app name)
		// AND a vendor advisory covers the same CVE.
		if nf.IsOS && vendorCVEs[nf.CVEID] {
			continue
		}
		out = append(out, nf)
	}
	for _, vf := range vendorFindings {
		out = append(out, NVDOSFinding{
			CVEID:           vf.CVEID,
			Score:           vf.Score,
			Severity:        vf.Severity,
			AppName:         vf.AppName,
			AppVersion:      vf.AppVersion,
			MatchConfidence: vf.MatchConfidence,
			IsOS:            true,
			Source:          string(vf.Source),
		})
	}
	return out
}

// NVDOSFinding is a thin, report-agnostic view of a finding used by
// ReconcileWithNVD so this package does not import internal/report or
// internal/cvematch. The reconciler caller adapts its own finding type to/from
// this shape.
type NVDOSFinding struct {
	CVEID           string
	Score           *float64
	Severity        string
	AppName         string
	AppVersion      string
	MatchConfidence string
	IsOS            bool   // true when this finding is for the OS pseudo-app
	Source          string // "" for NVD CPE, "apple"/"msrc" for vendor
}
