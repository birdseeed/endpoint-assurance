package oscve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// AppleSecurityReleasesURL is the canonical Apple "security releases" index.
// It is an HTML page; Apple also exposes the same data via the gdmf/HT pages.
// The fetcher (FetchApple) is the live seam — parsing is driven off a saved
// payload so the matcher is unit-testable offline.
const AppleSecurityReleasesURL = "https://support.apple.com/en-us/100100"
const AppleGDMFURL = "https://gdmf.apple.com/v2/pmv"

// AppleReleasesFeed is the parsed shape of the Apple security-releases data.
//
// Apple's index page lists, per product release, a name (e.g. "macOS Sonoma
// 14.5"), the build (where shown), and a link to the per-release advisory which
// enumerates CVEs. We model the already-extracted-per-release JSON shape that an
// upstream extraction step (or Apple's structured data) produces:
//
//	{
//	  "releases": [
//	    {
//	      "name": "macOS Sonoma 14.5",
//	      "product": "macOS Sonoma",
//	      "version": "14.5",
//	      "build": "23F79",
//	      "advisory_url": "https://support.apple.com/en-us/120903",
//	      "published": "2024-05-13",
//	      "cves": [
//	        {"id": "CVE-2024-23296", "severity": "HIGH", "score": 7.8},
//	        {"id": "CVE-2024-27834"}
//	      ]
//	    }
//	  ]
//	}
//
// Only macOS releases are retained by ParseApple (the index also lists iOS,
// watchOS, etc., which are out of scope for endpoint OS matching).
type AppleReleasesFeed struct {
	Releases []AppleRelease `json:"releases"`
}

// AppleRelease is one product release from the Apple feed.
type AppleRelease struct {
	Name        string     `json:"name"`
	Product     string     `json:"product"`
	Version     string     `json:"version"`
	Build       string     `json:"build"`
	AdvisoryURL string     `json:"advisory_url"`
	Published   string     `json:"published"`
	CVEs        []AppleCVE `json:"cves"`
}

// AppleCVE is one CVE listed against a release.
type AppleCVE struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Score    *float64 `json:"score"`
}

// macReleaseRe matches "macOS Sonoma 14.5" / "macOS 14.5" / "macOS Sequoia 15"
// and is also used as the is-macOS gate. We key off the "macOS" product family.
var macReleaseRe = regexp.MustCompile(`(?i)^macos\b`)

// ParseApple converts a saved Apple security-releases payload into source-agnostic
// Advisory records, retaining only macOS releases. One Advisory is produced per
// (release, CVE) pair. Releases that carry no CVEs (or are not macOS) are skipped.
//
// The version is taken from Version when present, else extracted from Name. The
// build is carried through verbatim (Apple builds are the precise match key).
func ParseApple(data []byte) ([]Advisory, error) {
	var feed AppleReleasesFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse apple feed: %w", err)
	}

	var out []Advisory
	for _, r := range feed.Releases {
		if !isMacRelease(r) {
			continue
		}
		version := strings.TrimSpace(r.Version)
		if version == "" {
			version = versionFromName(r.Name)
		}
		for _, c := range r.CVEs {
			id := strings.TrimSpace(c.ID)
			if id == "" {
				continue
			}
			out = append(out, Advisory{
				Platform:     PlatformMacOS,
				OSVersion:    version,
				OSBuild:      strings.TrimSpace(r.Build),
				CVEID:        id,
				Score:        c.Score,
				Severity:     normaliseSeverity(c.Severity),
				FixedInBuild: strings.TrimSpace(r.Build), // the release build is the fix
				Source:       SourceApple,
				AdvisoryURL:  strings.TrimSpace(r.AdvisoryURL),
			})
		}
	}
	return out, nil
}

// isMacRelease reports whether a release is a macOS release (vs iOS/watchOS/etc).
func isMacRelease(r AppleRelease) bool {
	if strings.EqualFold(strings.TrimSpace(r.Product), "macos") {
		return true
	}
	if macReleaseRe.MatchString(strings.TrimSpace(r.Product)) {
		return true
	}
	return macReleaseRe.MatchString(strings.TrimSpace(r.Name))
}

var versionTokenRe = regexp.MustCompile(`\d+(?:\.\d+)*`)
var cveTokenRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// versionFromName pulls the dotted version out of a release name like
// "macOS Sonoma 14.5" → "14.5".
func versionFromName(name string) string {
	return versionTokenRe.FindString(name)
}

// normaliseSeverity upper-cases vendor severity strings into the bands the report
// uses; unknown / empty values are returned empty so downstream count logic
// (FillFreeCVECounts) treats them as unbanded.
func normaliseSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH", "IMPORTANT":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return ""
	}
}

// AppleReleaseDocument is one macOS row from Apple's official security release
// index. The linked page is the authority for the CVE list; GDMF supplies the
// exact build for the release when Apple publishes an unambiguous mapping.
type AppleReleaseDocument struct {
	DocumentID      string
	Name            string
	Version         string
	AdvisoryURL     string
	NoPublishedCVEs bool
}

func ParseAppleSecurityIndex(data []byte, baseURL string) ([]AppleReleaseDocument, error) {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse apple security index html: %w", err)
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse apple base url: %w", err)
	}
	var out []AppleReleaseDocument
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			text := strings.Join(nodeText(n), " ")
			if macReleaseRe.MatchString(strings.TrimSpace(text)) {
				if href, label := firstLink(n); href != "" {
					u, parseErr := url.Parse(href)
					if parseErr == nil {
						u = base.ResolveReference(u)
						version := versionFromName(label)
						if version == "" {
							version = versionFromName(text)
						}
						id := strings.Trim(strings.TrimSpace(u.Path), "/")
						if version != "" && id != "" && !seen[u.String()] {
							seen[u.String()] = true
							out = append(out, AppleReleaseDocument{DocumentID: id, Name: strings.TrimSpace(label), Version: version, AdvisoryURL: u.String(), NoPublishedCVEs: strings.Contains(strings.ToLower(text), "no published cve")})
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if len(out) == 0 {
		return nil, fmt.Errorf("apple security index contained no macOS release links")
	}
	return out, nil
}

func nodeText(n *html.Node) []string {
	var out []string
	var walk func(*html.Node)
	walk = func(cur *html.Node) {
		if cur.Type == html.TextNode {
			if s := strings.TrimSpace(cur.Data); s != "" {
				out = append(out, s)
			}
		}
		for child := cur.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return out
}

func firstLink(n *html.Node) (string, string) {
	var walk func(*html.Node) (string, string)
	walk = func(cur *html.Node) (string, string) {
		if cur.Type == html.ElementNode && cur.Data == "a" {
			for _, attr := range cur.Attr {
				if attr.Key == "href" {
					return attr.Val, strings.Join(nodeText(cur), " ")
				}
			}
		}
		for child := cur.FirstChild; child != nil; child = child.NextSibling {
			if href, label := walk(child); href != "" {
				return href, label
			}
		}
		return "", ""
	}
	return walk(n)
}

func ParseAppleAdvisoryHTML(data []byte, release AppleReleaseDocument, build string) ([]Advisory, error) {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse apple advisory html: %w", err)
	}
	text := strings.Join(nodeText(doc), " ")
	ids := cveTokenRe.FindAllString(text, -1)
	seen := map[string]bool{}
	out := make([]Advisory, 0, len(ids))
	for _, raw := range ids {
		id := strings.ToUpper(raw)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Advisory{
			Platform: PlatformMacOS, OSVersion: release.Version,
			OSBuild: build, CVEID: id, FixedInBuild: build,
			Source: SourceApple, AdvisoryURL: release.AdvisoryURL,
			SourceDocumentID: release.DocumentID,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("apple advisory %s contained no CVE identifiers", release.DocumentID)
	}
	return out, nil
}

type appleGDMFFeed struct {
	AssetSets       map[string][]appleGDMFAsset `json:"AssetSets"`
	PublicAssetSets map[string][]appleGDMFAsset `json:"PublicAssetSets"`
}

type appleGDMFAsset struct {
	ProductVersion string `json:"ProductVersion"`
	Build          string `json:"Build"`
}

func ParseAppleGDMF(data []byte) (map[string]string, error) {
	var feed appleGDMFFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse apple gdmf: %w", err)
	}
	all := append(append([]appleGDMFAsset{}, feed.AssetSets["macOS"]...), feed.PublicAssetSets["macOS"]...)
	builds := map[string]string{}
	ambiguous := map[string]bool{}
	for _, asset := range all {
		version, build := strings.TrimSpace(asset.ProductVersion), strings.TrimSpace(asset.Build)
		if version == "" || build == "" {
			continue
		}
		if previous, ok := builds[version]; ok && !strings.EqualFold(previous, build) {
			ambiguous[version] = true
		}
		builds[version] = build
	}
	for version := range ambiguous {
		// Retain the version as a supported release but withhold a build. This
		// lets the official index ingest its advisory document without choosing
		// between hardware-specific build variants. Equal-version matching then
		// fails closed until GDMF publishes an unambiguous comparable build.
		builds[version] = ""
	}
	if len(builds) == 0 {
		return nil, fmt.Errorf("apple gdmf contained no macOS version/build records")
	}
	return builds, nil
}
