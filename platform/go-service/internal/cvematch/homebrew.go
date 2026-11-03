package cvematch

// PAT-2023: CVE matching for Homebrew formulae and casks.
//
// Homebrew has no CPE or OSV ecosystem of its own, and a formula name or cask
// token is package-namespace evidence, not a product identity. A Homebrew
// package therefore reaches a CVE only through an explicit mapping keyed by
// its exact formula name or cask token (app_cpe_mappings rows with
// source_type homebrew_formula / homebrew_cask). There is no word-token or
// fuzzy name match on this path: a package with no mapping produces no
// finding and is reported back as unmapped for the review queue.
//
// The range gate, CVSS floor and fixed-version rule are the ones Match uses,
// through the same matchMapping helper.

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	HomebrewFormulaSource = "homebrew_formula"
	HomebrewCaskSource    = "homebrew_cask"

	// Mapping review states. A curated mapping was entered or approved by a
	// person and is the only kind that matches. MappingAutoSeeded is kept in
	// the enum for the review work in PAT-2046 but nothing writes it, and a
	// row carrying it is never matched (see HomebrewMappingsFor).
	//
	// Deviation from PAT-2023 as written, for security (review 2026-09-23):
	// the ticket auto-accepts exact homepage/source-URL matches as mappings.
	// Those URLs come from the endpoint, and a mapping is global, so one
	// tenant's payload could re-map a formula for every tenant. Candidates are
	// therefore suggestions on the review queue only, never mappings.
	MappingCurated    = "curated"
	MappingAutoSeeded = "auto_seeded"

	// Confidence tiers. Matching produces only high and low; medium stays in
	// the stored enum but nothing produces it now that auto-seeded mappings
	// never match.
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"

	InstallOnRequest  = "on_request"
	InstallDependency = "dependency"
	InstallUnknown    = "unknown"

	homebrewCoreTap = "homebrew/core"
	homebrewCaskTap = "homebrew/cask"
)

// HomebrewPackage is one formula keg or cask currently on a device.
type HomebrewPackage struct {
	Kind    string // "formula" or "cask"
	Name    string // formula name or cask token, as reported
	Tap     string // "" when the receipt did not say
	Version string // raw, as reported ("3.0.7_1", "HEAD-1a2b3c4", "latest")

	InstalledOnRequest    *bool
	InstalledAsDependency *bool
	// RequiredBy lists other formulae on the same device whose receipts name
	// this one as a runtime dependency. Sorted.
	RequiredBy []string

	Homepage, SourceURL string

	// LinkedApps are the display names of the application bundles this cask
	// is linked to on the device (PAT-2013 homebrew_cask_app_links).
	LinkedApps []string
	// LinkedToApp is true when one of LinkedApps is itself covered by an
	// application CPE mapping. That app bundle is matched on the application
	// path from the version on disk, so the cask is skipped to keep one
	// finding per install. The caller sets it; see
	// cvepipeline.loadHomebrewPackages.
	LinkedToApp bool
}

// SourceType is the app_cpe_mappings source_type this package is keyed by.
func (p HomebrewPackage) SourceType() string {
	if p.Kind == "cask" {
		return HomebrewCaskSource
	}
	return HomebrewFormulaSource
}

// DisplayName is the device_cve_findings.app_name for this package. The kind
// is part of it so a formula and a cask with the same token, or a formula
// and an application with the same name, never share a finding row.
func (p HomebrewPackage) DisplayName() string { return HomebrewDisplayName(p.Kind, p.Name) }

// HomebrewDisplayName builds the finding app_name for a formula or cask.
func HomebrewDisplayName(kind, name string) string {
	if kind == "cask" {
		return name + " (Homebrew cask)"
	}
	return name + " (Homebrew formula)"
}

// ParseHomebrewDisplayName is the inverse of HomebrewDisplayName.
func ParseHomebrewDisplayName(s string) (kind, name string, ok bool) {
	switch {
	case strings.HasSuffix(s, " (Homebrew formula)"):
		kind, name = "formula", strings.TrimSuffix(s, " (Homebrew formula)")
	case strings.HasSuffix(s, " (Homebrew cask)"):
		kind, name = "cask", strings.TrimSuffix(s, " (Homebrew cask)")
	default:
		return "", "", false
	}
	return kind, name, name != ""
}

// IsHomebrewDisplayName reports whether s names a Homebrew finding.
func IsHomebrewDisplayName(s string) bool {
	_, _, ok := ParseHomebrewDisplayName(s)
	return ok
}

// InstallReason says whether the package was installed on request or pulled
// in as a dependency, from the receipt flags. A package installed as a
// dependency and later requested explicitly reads as on_request, as Homebrew
// itself treats it.
func (p HomebrewPackage) InstallReason() string {
	switch {
	case p.InstalledOnRequest != nil && *p.InstalledOnRequest:
		return InstallOnRequest
	case p.Kind == "formula" && p.InstalledAsDependency != nil && *p.InstalledAsDependency:
		return InstallDependency
	default:
		return InstallUnknown
	}
}

// OfficialTap is true when the package comes from Homebrew's own tap for its
// kind, or when the receipt did not name a tap. It decides whether a curated
// mapping may apply: curated mappings describe the official formula or cask,
// and a third-party tap may ship anything under the same name, so it never
// inherits one. An unnamed tap may still match a curated mapping.
func (p HomebrewPackage) OfficialTap() bool {
	return strings.TrimSpace(p.Tap) == "" || p.ExplicitOfficialTap()
}

// ExplicitOfficialTap is true only when the receipt names homebrew/core (a
// formula) or homebrew/cask (a cask). It decides whether an unmapped package
// may enter the global review queue: a package with no recorded tap can be a
// local or private formula, whose name and homepage must not leave the
// tenant.
func (p HomebrewPackage) ExplicitOfficialTap() bool {
	tap := strings.ToLower(strings.TrimSpace(p.Tap))
	if p.Kind == "cask" {
		return tap == homebrewCaskTap
	}
	return tap == homebrewCoreTap
}

// HomebrewMapping is one app_cpe_mappings row with a Homebrew source type.
type HomebrewMapping struct {
	SourceType  string // homebrew_formula or homebrew_cask
	Name        string // formula name or cask token
	CPEVendor   string
	CPEProduct  string
	ReviewState string // curated; any other value never matches
}

func (m HomebrewMapping) cpe() CPEMapping {
	return CPEMapping{MatchName: m.Name, CPEVendor: m.CPEVendor, CPEProduct: m.CPEProduct}
}

// CPEKey is the normalised "vendor:product" key the mapping resolves to.
func (m HomebrewMapping) CPEKey() string { return m.cpe().CPEKey() }

// HomebrewFinding is a Finding plus the Homebrew evidence it rests on.
type HomebrewFinding struct {
	Finding
	PackageSource  string   // homebrew_formula or homebrew_cask
	PackageName    string   // formula name or cask token
	InstallReason  string   // on_request, dependency or unknown
	RequiredBy     []string // parent formulae on the device, where receipts say so
	MappingBasis   string   // curated (the only basis that matches)
	ConfidenceTier string   // high or low; medium is never produced
}

var homebrewRevisionRe = regexp.MustCompile(`_\d+$`)

// NormalizeHomebrewVersion turns a reported keg or cask version into the
// upstream version the NVD ranges are written against.
//
//   - A formula's "_N" suffix is a Homebrew packaging revision, not an
//     upstream version, and is stripped ("8.3.0_1" -> "8.3.0").
//   - A HEAD build ("HEAD", "HEAD-1a2b3c4") has no upstream version. It is
//     returned as "" with head=true, so the range gate cannot compare it and
//     every match is version_unverified (low confidence). The digits in a
//     commit hash are never read as a version.
//   - A cask's ",build" suffix is vendor build metadata and is dropped; a
//     cask version of "latest" is unknown and returned as "".
func NormalizeHomebrewVersion(kind, raw string) (version string, head bool) {
	v := strings.TrimSpace(raw)
	if kind == "cask" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		if strings.EqualFold(v, "latest") {
			return "", false
		}
		return v, false
	}
	if strings.HasPrefix(strings.ToUpper(v), "HEAD") {
		return "", true
	}
	return homebrewRevisionRe.ReplaceAllString(v, ""), false
}

// HomebrewMappingsFor returns every curated mapping keyed by this package's
// exact formula name or cask token (case-insensitive). A package from a
// third-party tap, or a cask linked to its app bundle, has none. A mapping
// that is not curated never matches.
func HomebrewMappingsFor(p HomebrewPackage, mappings []HomebrewMapping) []HomebrewMapping {
	if p.LinkedToApp || !p.OfficialTap() {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	var out []HomebrewMapping
	for _, m := range mappings {
		if m.ReviewState == MappingCurated && m.SourceType == p.SourceType() &&
			strings.ToLower(strings.TrimSpace(m.Name)) == name {
			out = append(out, m)
		}
	}
	return out
}

// HomebrewCPEKeys is the set of CPE keys the packages' mappings resolve to,
// sorted, for loading only the relevant feed entries.
func HomebrewCPEKeys(pkgs []HomebrewPackage, mappings []HomebrewMapping) []string {
	seen := map[string]bool{}
	var keys []string
	for _, p := range pkgs {
		for _, m := range HomebrewMappingsFor(p, mappings) {
			if k := m.CPEKey(); !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// confidenceTier grades a Homebrew finding (PAT-2023). Only curated mappings
// match, so there are two outcomes: the installed version inside an NVD range
// is high; anything the range gate could not confirm (no range data, a HEAD
// build, a pre-release or other version the strict comparator cannot order
// against the bound) is low. A non-curated
// mapping is graded low defensively, although HomebrewMappingsFor never
// returns one.
func confidenceTier(matchConfidence, reviewState string) string {
	if matchConfidence == "version_confirmed" && reviewState == MappingCurated {
		return ConfidenceHigh
	}
	return ConfidenceLow
}

// comparableHomebrewVersion is the version handed to the range gate: the
// normalised upstream version, or "" for a HEAD build or a cask "latest",
// which have no upstream version at all. The range gate itself decides what
// it can compare (compareVersionsStrict, PAT-2044): OpenSSL-style letter
// releases such as 1.1.1w compare exactly, while a pre-release or any other
// shape it cannot order with certainty ("3.0.0rc1", "1.0.0-beta", "9.8p1")
// is unknown against the bound, so the match is version_unverified, kept at
// low confidence and never dropped.
func comparableHomebrewVersion(kind, raw string) string {
	v, _ := NormalizeHomebrewVersion(kind, raw)
	return v
}

var tierRank = map[string]int{ConfidenceLow: 0, ConfidenceMedium: 1, ConfidenceHigh: 2}

// MatchHomebrew matches Homebrew packages against their exact mappings.
//
// Returns the findings, at most one per (CVE, package display name), and the
// packages that have no mapping (for the review queue). A cask linked to its
// app bundle is neither matched nor reported as unmapped: its app is matched
// through the app mapping, which is the one finding for that install. A
// package from a third-party tap is reported as unmapped; the caller decides
// whether to queue it.
//
// When several kegs of one formula match the same CVE, the kept finding is
// the strongest evidence (confirmed over unverified, then the higher tier),
// then the lowest installed version, and the fixed version is the highest
// across the matching kegs.
func MatchHomebrew(pkgs []HomebrewPackage, mappings []HomebrewMapping, feed []CVEEntry) (findings []HomebrewFinding, unmapped []HomebrewPackage) {
	return MatchHomebrewIndexed(pkgs, mappings, NewCPEIndex(feed))
}

// CPEIndex is the product-level feed index Match builds internally, exposed so
// a caller matching many devices against one feed builds it once.
type CPEIndex map[string][]CVEEntry

// NewCPEIndex indexes feed by "vendor:product", applying the CVSS floor.
func NewCPEIndex(feed []CVEEntry) CPEIndex { return buildCPEIndex(feed) }

// MatchHomebrewIndexed is MatchHomebrew against a prebuilt index.
func MatchHomebrewIndexed(pkgs []HomebrewPackage, mappings []HomebrewMapping, cpeIndex CPEIndex) (findings []HomebrewFinding, unmapped []HomebrewPackage) {
	type key struct{ cve, app string }
	best := map[key]int{}
	for _, p := range pkgs {
		if p.LinkedToApp {
			continue
		}
		ms := HomebrewMappingsFor(p, mappings)
		if len(ms) == 0 {
			unmapped = append(unmapped, p)
			continue
		}
		app := ScannedApp{Name: p.DisplayName(), Version: comparableHomebrewVersion(p.Kind, p.Version)}
		for _, m := range ms {
			// Zero matchOptions: no platform filter and no age cut; PAT-2107
			// scoped those to Match. Exact-version rows do apply here too.
			for _, f := range matchMapping(app, m.cpe(), cpeIndex, matchOptions{}) {
				f.AppVersion = p.Version // report what is on disk, not the normalised form
				hf := HomebrewFinding{
					Finding:        f,
					PackageSource:  p.SourceType(),
					PackageName:    p.Name,
					InstallReason:  p.InstallReason(),
					RequiredBy:     p.RequiredBy,
					MappingBasis:   m.ReviewState,
					ConfidenceTier: confidenceTier(f.MatchConfidence, m.ReviewState),
				}
				k := key{f.CVEID, f.AppName}
				i, ok := best[k]
				if !ok {
					best[k] = len(findings)
					findings = append(findings, hf)
					continue
				}
				findings[i] = strongerHomebrewFinding(findings[i], hf)
			}
		}
	}
	return findings, unmapped
}

func strongerHomebrewFinding(a, b HomebrewFinding) HomebrewFinding {
	fixed := MaxVersion(a.FixedVersion, b.FixedVersion)
	keep := a
	switch {
	case a.MatchConfidence != b.MatchConfidence:
		if b.MatchConfidence == "version_confirmed" {
			keep = b
		}
	case tierRank[a.ConfidenceTier] != tierRank[b.ConfidenceTier]:
		if tierRank[b.ConfidenceTier] > tierRank[a.ConfidenceTier] {
			keep = b
		}
	default:
		av, _ := NormalizeHomebrewVersion(kindOf(a.PackageSource), a.AppVersion)
		bv, _ := NormalizeHomebrewVersion(kindOf(b.PackageSource), b.AppVersion)
		// Lower version wins; an equal-comparing pair ("8.3.0" and
		// "8.3.0_1") goes to the smaller string, so the kept keg does not
		// depend on receipt order.
		if c := compareVersions(bv, av); c < 0 || (c == 0 && b.AppVersion < a.AppVersion) {
			keep = b
		}
	}
	if keep.MatchConfidence == "version_confirmed" {
		keep.FixedVersion = fixed
	}
	return keep
}

func kindOf(source string) string {
	if source == HomebrewCaskSource {
		return "cask"
	}
	return "formula"
}

// HomebrewSuggestionCandidates derives NVD "vendor:product" keys a package's
// own metadata points at, for a review-queue suggestion:
//
//   - a GitHub or GitLab homepage or source URL "host/<owner>/<repo>" gives
//     "<owner>:<repo>";
//   - a "<owner>.github.io" or "<owner>.gitlab.io" homepage gives
//     "<owner>:<name>";
//   - a homepage on the project's own domain gives "<domain label>:<name>",
//     where name is the formula name without any "@version" suffix
//     ("https://www.openssl.org" + "openssl@3" -> "openssl:openssl").
//
// The metadata is endpoint-reported, so a candidate is never a mapping. The
// caller records one as a suggestion only when it exists, exactly, among the
// CPE keys of the local NVD store, and only when exactly one candidate does.
// A person decides. Lowercased, deduplicated, sorted.
func HomebrewSuggestionCandidates(p HomebrewPackage) []string {
	seen := map[string]bool{}
	add := func(vendor, product string) {
		vendor, product = strings.ToLower(strings.TrimSpace(vendor)), strings.ToLower(strings.TrimSpace(product))
		if vendor == "" || product == "" || strings.ContainsAny(vendor+product, ": /") {
			return
		}
		seen[vendor+":"+product] = true
	}
	base := p.Name
	if i := strings.IndexByte(base, '@'); i > 0 {
		base = base[:i]
	}
	for i, raw := range []string{p.Homepage, p.SourceURL} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		switch host {
		case "github.com", "gitlab.com":
			if len(parts) >= 2 {
				add(parts[0], strings.TrimSuffix(parts[1], ".git"))
			}
			continue
		}
		// The project-domain rule reads only the homepage: a source URL on a
		// mirror or CDN says nothing about who the vendor is.
		if i != 0 {
			continue
		}
		labels := strings.Split(host, ".")
		// A project page on a code host ("jqlang.github.io") names its owner
		// in the first label, not the host's own name.
		if strings.HasSuffix(host, ".github.io") || strings.HasSuffix(host, ".gitlab.io") {
			if len(labels) == 3 {
				add(labels[0], base)
			}
			continue
		}
		if len(labels) >= 2 {
			add(labels[len(labels)-2], base)
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
