package oscve

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// MSRCBaseURL is the Microsoft Security Update Guide CVRF v3.0 API base. Documents
// are fetched per monthly release id, e.g. .../cvrf/v3.0/document/2024-Jun.
const MSRCBaseURL = "https://api.msrc.microsoft.com/cvrf/v3.0"

// MSRCUpdatesURL lists the available CVRF document ids (one per Patch Tuesday).
const MSRCUpdatesURL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"

// cvrfDocument models the subset of the MSRC CVRF v3.0 JSON we consume.
//
// CVRF nests product definitions in a ProductTree and vulnerabilities in
// Vulnerability[]. Each Vulnerability lists ProductStatuses (which ProductIDs are
// affected) and Remediations (which KB / fixed build remediates which ProductIDs).
// We resolve ProductID → product full name (which carries the Windows version /
// build, e.g. "Windows 10 Version 22H2 for x64-based Systems") and join with the
// remediation KB to produce per-(version → CVE, fixed-in KB) advisories.
//
// This is the documented CVRF v3.0 shape; see MSRC's OpenAPI. Parsing is driven
// off a committed fixture so the matcher is testable offline.
type cvrfDocument struct {
	ProductTree   cvrfProductTree     `json:"ProductTree"`
	Vulnerability []cvrfVulnerability `json:"Vulnerability"`
}

type cvrfProductTree struct {
	FullProductName []cvrfFullProductName `json:"FullProductName"`
}

type cvrfFullProductName struct {
	ProductID string `json:"ProductID"`
	CPE       string `json:"CPE"`
	Value     string `json:"Value"`
}

type cvrfVulnerability struct {
	CVE             string              `json:"CVE"`
	Title           cvrfValue           `json:"Title"`
	CVSSScoreSets   []cvrfCVSSScoreSet  `json:"CVSSScoreSets"`
	ProductStatuses []cvrfProductStatus `json:"ProductStatuses"`
	Threats         []cvrfThreat        `json:"Threats"`
	Remediations    []cvrfRemediation   `json:"Remediations"`
}

type cvrfValue struct {
	Value string `json:"Value"`
}

type cvrfCVSSScoreSet struct {
	BaseScore float64  `json:"BaseScore"`
	Vector    string   `json:"Vector"`
	ProductID []string `json:"ProductID"`
}

type cvrfProductStatus struct {
	Type      int      `json:"Type"` // 3 = "Known Affected"
	ProductID []string `json:"ProductID"`
}

type cvrfThreat struct {
	Type        int       `json:"Type"` // 3 = Severity
	Description cvrfValue `json:"Description"`
	ProductID   []string  `json:"ProductID"`
}

type cvrfRemediation struct {
	Type        int       `json:"Type"`        // 2 = Vendor Fix
	Description cvrfValue `json:"Description"` // KB number, e.g. "5040442"
	ProductID   []string  `json:"ProductID"`
	FixedBuild  string    `json:"FixedBuild"`
}

const (
	cvrfStatusKnownAffected  = 3
	cvrfThreatSeverity       = 3
	cvrfRemediationVendorFix = 2
)

// windowsProductRe gates ProductTree entries to client Windows OS products (the
// endpoint scope), excluding Server, Office and products whose names merely end
// with "on Windows 10/11" such as .NET or codec extensions.
var windowsProductRe = regexp.MustCompile(`(?i)^windows\s+1[01]\s+version\b`)

// winVersionRe extracts the marketing version token from an MSRC product full
// name, e.g. "Windows 10 Version 22H2 for x64-based Systems" → "22H2".
var winVersionRe = regexp.MustCompile(`(?i)version\s+([0-9]+H[0-9]+|[0-9]{4})`)

// kbRe normalises a KB reference to "KB#######". Accepts a bare number
// ("5039217"), "KB5039217", or "kb 5039217"; the KB prefix is optional.
var kbRe = regexp.MustCompile(`(?i)(?:kb)?\s*([0-9]{6,7})`)

// ParseMSRC converts a saved MSRC CVRF v3.0 document into source-agnostic Advisory
// records for client Windows OS products. One Advisory is produced per affected
// (Windows product, CVE) pair. A dotted FixedBuild is the only value used for
// version comparison; the remediation KB is retained separately as provenance.
func ParseMSRC(data []byte) ([]Advisory, error) {
	var doc cvrfDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse msrc cvrf: %w", err)
	}

	// ProductID → product full name, restricted to client Windows.
	products := map[string]string{}
	for _, p := range doc.ProductTree.FullProductName {
		if windowsProductRe.MatchString(p.Value) {
			products[p.ProductID] = p.Value
		}
	}

	var out []Advisory
	for _, v := range doc.Vulnerability {
		cve := strings.TrimSpace(v.CVE)
		if cve == "" {
			continue
		}
		vendorTitle := strings.TrimSpace(v.Title.Value)

		// CVSS base score: take the max across score sets (a CVE may carry several).
		var score *float64
		for _, ss := range v.CVSSScoreSets {
			s := ss.BaseScore
			if score == nil || s > *score {
				sv := s
				score = &sv
			}
		}

		// Severity per ProductID from the Threats (Type 3) block.
		severityByProduct := map[string]string{}
		for _, t := range v.Threats {
			if t.Type != cvrfThreatSeverity {
				continue
			}
			sev := normaliseSeverity(t.Description.Value)
			for _, pid := range t.ProductID {
				severityByProduct[pid] = sev
			}
		}

		// Remediation (Vendor Fix, Type 2) per ProductID. KB identifiers are
		// provenance only; only a dotted FixedBuild is comparable to endpoint OS
		// evidence and eligible to become fixed_version.
		kbByProduct := map[string]string{}
		fixedBuildByProduct := map[string]string{}
		for _, rem := range v.Remediations {
			if rem.Type != cvrfRemediationVendorFix {
				continue
			}
			kb := normaliseKB(rem.Description.Value)
			for _, pid := range rem.ProductID {
				if kb != "" {
					kbByProduct[pid] = kb
				}
				if isDottedWindowsBuild(rem.FixedBuild) {
					fixedBuildByProduct[pid] = strings.TrimSpace(rem.FixedBuild)
				}
			}
		}

		// Emit one advisory per affected (Known Affected, Type 3) Windows product.
		seenProduct := map[string]bool{}
		for _, ps := range v.ProductStatuses {
			if ps.Type != cvrfStatusKnownAffected {
				continue
			}
			for _, pid := range ps.ProductID {
				name, ok := products[pid]
				if !ok || seenProduct[pid] {
					continue
				}
				seenProduct[pid] = true

				fixed := fixedBuildByProduct[pid]
				out = append(out, Advisory{
					Platform:        PlatformWindows,
					OSVersion:       winVersionFromName(name),
					OSBuild:         fixed,
					CVEID:           cve,
					Score:           score,
					Severity:        severityByProduct[pid],
					FixedInBuild:    fixed,
					Source:          SourceMSRC,
					VendorTitle:     vendorTitle,
					AdvisoryURL:     msrcAdvisoryURL(cve),
					VendorReference: kbByProduct[pid],
				})
			}
		}
	}
	return out, nil
}

func isDottedWindowsBuild(s string) bool {
	_, ok := exactWindowsBuild(s)
	return ok
}

type MSRCUpdate struct {
	ID                 string `json:"ID"`
	CurrentReleaseDate string `json:"CurrentReleaseDate"`
	CvrfURL            string `json:"CvrfUrl"`
}

type msrcUpdatesResponse struct {
	Value []MSRCUpdate `json:"value"`
}

func ParseMSRCUpdates(data []byte) ([]MSRCUpdate, error) {
	var response msrcUpdatesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("parse msrc updates: %w", err)
	}
	var out []MSRCUpdate
	for _, update := range response.Value {
		update.ID = strings.TrimSpace(update.ID)
		update.CvrfURL = strings.TrimSpace(update.CvrfURL)
		if update.ID == "" || update.CvrfURL == "" {
			continue
		}
		out = append(out, update)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("msrc updates catalogue contained no documents")
	}
	return out, nil
}

// winVersionFromName extracts the marketing version from an MSRC product name,
// e.g. "Windows 11 Version 23H2 for x64-based Systems" → "23H2".
func winVersionFromName(name string) string {
	if m := winVersionRe.FindStringSubmatch(name); len(m) == 2 {
		return strings.ToUpper(m[1])
	}
	return ""
}

// normaliseKB returns "KB#######" for a KB reference, or "" when none is present.
func normaliseKB(s string) string {
	if m := kbRe.FindStringSubmatch(s); len(m) == 2 {
		return "KB" + m[1]
	}
	return ""
}

// msrcAdvisoryURL builds the Security Update Guide deep link for a CVE.
func msrcAdvisoryURL(cve string) string {
	return "https://msrc.microsoft.com/update-guide/vulnerability/" + cve
}
