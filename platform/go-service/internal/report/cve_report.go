package report

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/exploitation"
)

// FreeCVEFormatVersion is the wire-format version embedded in the PDF footer and spec doc.
// Bumped to v1.1 at PAT-439 (closing page added), v2.0 at PAT-1205 (ranked
// remediation plan), v2.1 at PAT-1853 (per-description source attribution),
// and v2.2 at PAT-1871 (tri-state exploitation evidence provenance).
// A rendered-report contract change requires a new version.
const FreeCVEFormatVersion = "v2.2"

// CVEReportCTAURL is the booking link printed on the closing page CTA block.
const CVEReportCTAURL = "https://patched.im/#book"

// TierStatusAvailable and TierStatusComingSoon are the two badge states for closing-page rungs.
// PAT-440 is the go-live checklist; flip a TierStatuses field to TierStatusAvailable when that tier ships.
const (
	TierStatusAvailable  = "Available now"
	TierStatusComingSoon = "Coming soon"
)

// TierStatuses controls which tiers show "Available now" on the "What happens next" closing page.
//
// PAT-443: the values are no longer hardcoded here — they're loaded from the
// canonical source tier_status.json (embedded below). That JSON is the single
// source of truth for tier availability; the website tier cards and the
// buyer-facing tier doc should sync from it so the surfaces can't drift. To flip
// a tier live, change its status in tier_status.json (one place), not here.
// See PAT-440 for the go-live checklist gate.
//
// It remains a package var (not a const) so tests can flip a field to assert
// badge changes at render time.
var TierStatuses = loadTierStatuses()

//go:embed tier_status.json
var tierStatusJSON []byte

// loadTierStatuses parses the canonical tier_status.json into the struct the
// renderer reads. Panics on a malformed or incomplete file — a bad canonical
// source is a build-time/start-time error, not something to silently degrade.
func loadTierStatuses() struct {
	Report                 string
	PatchAndDeploy         string
	FullEndpointManagement string
} {
	var doc struct {
		Tiers map[string]struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"tiers"`
	}
	if err := json.Unmarshal(tierStatusJSON, &doc); err != nil {
		panic(fmt.Sprintf("report: parse tier_status.json: %v", err))
	}
	out := struct {
		Report                 string
		PatchAndDeploy         string
		FullEndpointManagement string
	}{
		Report:                 doc.Tiers["report"].Status,
		PatchAndDeploy:         doc.Tiers["patch"].Status,
		FullEndpointManagement: doc.Tiers["full_endpoint_management"].Status,
	}
	for tier, v := range map[string]string{
		"report":                   out.Report,
		"patch":                    out.PatchAndDeploy,
		"full_endpoint_management": out.FullEndpointManagement,
	} {
		if v != TierStatusAvailable && v != TierStatusComingSoon {
			panic(fmt.Sprintf("report: tier_status.json: tier %q has invalid status %q (want %q or %q)",
				tier, v, TierStatusAvailable, TierStatusComingSoon))
		}
	}
	return out
}

// CVEHit is one (device, app) pair matched to a CVE.
type CVEHit struct {
	Hostname        string
	AppName         string
	AppVersion      string
	MatchConfidence string // "version_confirmed" | "version_unverified"
	// FixedVersion is the first version NOT vulnerable for the CPE range that
	// matched this hit (cvematch.Finding.FixedVersion). Empty when unknown.
	FixedVersion string
}

// CVERecord is one CVE and all the (device, app) pairs matched to it.
type CVERecord struct {
	CVEID             string
	Description       string
	DescriptionSource string
	CVSSScore         *float64
	Severity          string // CRITICAL / HIGH / MEDIUM / LOW
	PublishedAt       *time.Time
	Exploitation      exploitation.Assessment
	Hits              []CVEHit // ordered by hostname, then AppName
}

// FreeCVEReport is the v1-format input to RenderFreeCVEPDF.
// FormatVersion is always FreeCVEFormatVersion. Adding a field at this level
// requires a new version constant and a matching spec update in FREE_CVE_REPORT.md.
type FreeCVEReport struct {
	FormatVersion string
	GeneratedAt   time.Time
	Tenant        string

	// CVEs sorted by severity band (CRITICAL→HIGH→MEDIUM→LOW), then CVE ID asc.
	CVEs []CVERecord

	// Pre-computed counts. Populated by fillFreeCVECounts; expose them so callers
	// (handlers, import paths) can surface stats without re-iterating CVEs.
	TotalCVEs      int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	ConfirmedHits  int // (device,CVE) pairs with version_confirmed
	UnverifiedHits int // (device,CVE) pairs with version_unverified
}

// FetchFreeCVEReport loads the tenant's CVE findings from the DB and assembles
// a FreeCVEReport ready for RenderFreeCVEPDF. Returns ErrTenantNotFound when
// the tenant ID doesn't resolve.
func FetchFreeCVEReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (FreeCVEReport, error) {
	var r FreeCVEReport
	r.FormatVersion = FreeCVEFormatVersion
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT
			f.cve_id,
			e.description,
			e.description_source,
			e.cvss_v3_score,
			e.severity,
			e.published_at,
			f.app_name,
			f.app_version,
			f.match_confidence,
			f.fixed_version,
			COALESCE(d.hostname, '')
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id  = f.cve_id
		JOIN devices d          ON d.id      = f.device_id
		WHERE d.tenant_id = $1::uuid
		ORDER BY
			CASE UPPER(e.severity)
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH'     THEN 2
				WHEN 'MEDIUM'   THEN 3
				WHEN 'LOW'      THEN 4
				ELSE 5
			END,
			f.cve_id,
			d.hostname
	`, tenantID)
	if err != nil {
		return r, fmt.Errorf("query cve findings: %w", err)
	}
	defer rows.Close()

	// Group rows into CVERecord entries, preserving the ORDER BY ordering.
	cveOrder := []string{}
	byID := map[string]*CVERecord{}
	for rows.Next() {
		var (
			cveID, desc, descriptionSource, severity, appName, appVersion, confidence, fixedVersion, hostname string
			score                                                                                             *float64
			publishedAt                                                                                       *time.Time
		)
		if err := rows.Scan(&cveID, &desc, &descriptionSource, &score, &severity, &publishedAt,
			&appName, &appVersion, &confidence, &fixedVersion, &hostname); err != nil {
			return r, fmt.Errorf("scan cve row: %w", err)
		}
		if _, ok := byID[cveID]; !ok {
			byID[cveID] = &CVERecord{
				CVEID:             cveID,
				Description:       desc,
				DescriptionSource: descriptionSource,
				CVSSScore:         score,
				Severity:          severity,
				PublishedAt:       publishedAt,
			}
			cveOrder = append(cveOrder, cveID)
		}
		byID[cveID].Hits = append(byID[cveID].Hits, CVEHit{
			Hostname:        hostname,
			AppName:         appName,
			AppVersion:      appVersion,
			MatchConfidence: confidence,
			FixedVersion:    fixedVersion,
		})
	}
	if err := rows.Err(); err != nil {
		return r, fmt.Errorf("iterate cve rows: %w", err)
	}

	r.CVEs = make([]CVERecord, 0, len(cveOrder))
	for _, id := range cveOrder {
		r.CVEs = append(r.CVEs, *byID[id])
	}
	assessments, err := exploitation.FetchAssessments(ctx, pool, cveOrder, r.GeneratedAt)
	if err != nil {
		return r, fmt.Errorf("fetch exploitation evidence: %w", err)
	}
	for i := range r.CVEs {
		r.CVEs[i].Exploitation = assessments[r.CVEs[i].CVEID]
	}
	FillFreeCVECounts(&r)
	return r, nil
}

// SortCVERecords sorts CVEs by severity band (CRITICAL first) then CVE ID asc.
// Used by import-fed paths that build FreeCVEReport without DB-side ordering.
func SortCVERecords(cvs []CVERecord) {
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.SliceStable(cvs, func(i, j int) bool {
		oi := order[cvs[i].Severity]
		oj := order[cvs[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return cvs[i].CVEID < cvs[j].CVEID
	})
}

// FillFreeCVECounts populates the summary count fields from r.CVEs.
// Called by FetchFreeCVEReport; also called directly by tests and import paths
// that build FreeCVEReport structs without going through the DB.
func FillFreeCVECounts(r *FreeCVEReport) {
	r.TotalCVEs = len(r.CVEs)
	r.CriticalCount = 0
	r.HighCount = 0
	r.MediumCount = 0
	r.LowCount = 0
	r.ConfirmedHits = 0
	r.UnverifiedHits = 0
	for _, cve := range r.CVEs {
		switch cve.Severity {
		case "CRITICAL":
			r.CriticalCount++
		case "HIGH":
			r.HighCount++
		case "MEDIUM":
			r.MediumCount++
		case "LOW":
			r.LowCount++
		}
		for _, h := range cve.Hits {
			// version_vendor_confirmed (Apple security releases / MSRC, PAT-409)
			// counts as confirmed alongside NVD version_confirmed; only
			// version_unverified is treated as unverified.
			if h.MatchConfidence == "version_unverified" {
				r.UnverifiedHits++
			} else {
				r.ConfirmedHits++
			}
		}
	}
}

// ─── Remediation plan (PAT-1205) ───────────────────────────────────────────────
//
// BuildCVEActions folds the flat, per-hit CVERecord list into a ranked,
// per-app remediation plan: one CVEAction per affected app (confirmed
// findings), plus a shorter CVEUnverifiedGroup list for findings NVD can't
// confirm a version range for. This is what the "Remediation Plan" and
// "Possibly Affected" sections of the PDF render from; the old flat table
// is retained verbatim as Appendix A.

// CVEActionDevice is one device carrying a finding within a CVEAction or
// CVEUnverifiedGroup.
type CVEActionDevice struct {
	Hostname         string
	InstalledVersion string
}

// CVEAction is one ranked remediation item: "update AppName to TargetVersion
// on these Devices to close these CVEs".
type CVEAction struct {
	AppName string
	// TargetVersion is max(FixedVersion) across every confirmed hit backing
	// this action, via cvematch.CompareVersions. "" when no hit in the group
	// carries a known FixedVersion — render as "latest vendor release".
	TargetVersion string
	// Devices is deduped by hostname and sorted by hostname ascending.
	Devices []CVEActionDevice
	// CVEs is the subset of each touching CVERecord's Hits that belong to
	// this app, sorted by severity band (CRITICAL,HIGH,MEDIUM,LOW) then CVE
	// ID ascending (see SortCVERecords).
	CVEs                                            []CVERecord
	CriticalCount, HighCount, MediumCount, LowCount int
	// TopCVSS is the highest CVSSScore among CVEs in this action, nil if
	// none of them carry a score.
	TopCVSS *float64
}

// CVEUnverifiedGroup is one app with findings NVD provides no usable
// version-range data for — split out of the confirmed remediation plan
// because we cannot responsibly tell someone to upgrade when we don't know
// they are actually vulnerable.
type CVEUnverifiedGroup struct {
	AppName string
	Devices []CVEActionDevice
	CVEs    []CVERecord
}

// confirmedConfidence reports whether a hit's MatchConfidence counts as
// confirmed for remediation-plan purposes. Mirrors FillFreeCVECounts: only
// "version_unverified" is unverified; "version_confirmed" and
// "version_vendor_confirmed" (PAT-409, Apple security releases / MSRC) are
// both confirmed.
func confirmedConfidence(matchConfidence string) bool {
	return matchConfidence != "version_unverified"
}

// cveAppBucket accumulates, for one app and one confidence class (confirmed
// or unverified), the per-CVE record built from only that app's hits.
type cveAppBucket struct {
	byCVE map[string]*CVERecord
}

func (b *cveAppBucket) addHit(cve CVERecord, hit CVEHit) {
	if b.byCVE == nil {
		b.byCVE = map[string]*CVERecord{}
	}
	rec, ok := b.byCVE[cve.CVEID]
	if !ok {
		rec = &CVERecord{
			CVEID:             cve.CVEID,
			Description:       cve.Description,
			DescriptionSource: cve.DescriptionSource,
			CVSSScore:         cve.CVSSScore,
			Severity:          cve.Severity,
			PublishedAt:       cve.PublishedAt,
			Exploitation:      cve.Exploitation,
		}
		b.byCVE[cve.CVEID] = rec
	}
	rec.Hits = append(rec.Hits, hit)
}

// records returns the bucket's CVERecords, sorted deterministically by
// severity band then CVE ID (SortCVERecords) — map iteration order never
// reaches the caller.
func (b *cveAppBucket) records() []CVERecord {
	cves := make([]CVERecord, 0, len(b.byCVE))
	for _, rec := range b.byCVE {
		cves = append(cves, *rec)
	}
	SortCVERecords(cves)
	return cves
}

// devices returns the bucket's affected devices, deduped by hostname and
// sorted by hostname ascending. Iterates b.records() (already deterministically
// sorted by severity/CVE ID) rather than the raw byCVE map, so that if a
// hostname's AppVersion ever genuinely disagreed across hit records — it
// shouldn't: the same physical install has one version — the picked value
// would still be reproducible run to run instead of depending on Go's
// randomised map iteration order.
func (b *cveAppBucket) devices() []CVEActionDevice {
	byHost := map[string]string{} // hostname -> installed version
	seen := make([]string, 0)
	for _, rec := range b.records() {
		for _, h := range rec.Hits {
			if _, ok := byHost[h.Hostname]; !ok {
				seen = append(seen, h.Hostname)
			}
			byHost[h.Hostname] = h.AppVersion
		}
	}
	devices := make([]CVEActionDevice, 0, len(seen))
	for _, host := range seen {
		devices = append(devices, CVEActionDevice{Hostname: host, InstalledVersion: byHost[host]})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Hostname < devices[j].Hostname })
	return devices
}

// targetVersion folds max(FixedVersion) across every hit in the bucket,
// skipping empty strings. Returns "" when no hit carries a known
// FixedVersion.
func (b *cveAppBucket) targetVersion() string {
	var max string
	for _, rec := range b.byCVE {
		for _, h := range rec.Hits {
			if h.FixedVersion == "" {
				continue
			}
			max = cvematch.MaxVersion(max, h.FixedVersion)
		}
	}
	return max
}

// BuildCVEActions folds a FreeCVEReport's CVEs into per-app remediation
// actions. Confirmed findings (match_confidence == "version_confirmed" or
// "version_vendor_confirmed") produce CVEActions. Unverified findings
// (match_confidence == "version_unverified") are split out into
// CVEUnverifiedGroup entries instead, since we cannot responsibly tell
// someone to upgrade when we don't know they are actually vulnerable.
//
// A CVE that has hits against two different apps (e.g. matched under two CPE
// mappings) appears in both apps' groups — this is correct: the customer has
// two separate things to fix. Likewise, a single CVE can be confirmed for
// one device (parseable, in-range installed version) and unverified for
// another (unparseable installed version) — its hits are split accordingly,
// so the same CVE can appear in both an app's CVEAction and its
// CVEUnverifiedGroup.
//
// Ordering is fully deterministic (no map iteration reaches the output):
// actions are sorted by CriticalCount desc, then HighCount desc, then total
// CVE count desc, then device count desc, then AppName asc. Unverified
// groups are sorted by AppName asc. Devices within an action/group are
// sorted by hostname asc. CVEs within an action/group are sorted by severity
// band (CRITICAL,HIGH,MEDIUM,LOW) then CVE ID asc (SortCVERecords).
func BuildCVEActions(r FreeCVEReport) (actions []CVEAction, unverified []CVEUnverifiedGroup) {
	confirmedByApp := map[string]*cveAppBucket{}
	unverifiedByApp := map[string]*cveAppBucket{}

	for _, cve := range r.CVEs {
		for _, hit := range cve.Hits {
			target := confirmedByApp
			if !confirmedConfidence(hit.MatchConfidence) {
				target = unverifiedByApp
			}
			b, ok := target[hit.AppName]
			if !ok {
				b = &cveAppBucket{}
				target[hit.AppName] = b
			}
			b.addHit(cve, hit)
		}
	}

	for appName, bucket := range confirmedByApp {
		cves := bucket.records()
		action := CVEAction{
			AppName:       appName,
			TargetVersion: bucket.targetVersion(),
			Devices:       bucket.devices(),
			CVEs:          cves,
		}
		for _, c := range cves {
			switch c.Severity {
			case "CRITICAL":
				action.CriticalCount++
			case "HIGH":
				action.HighCount++
			case "MEDIUM":
				action.MediumCount++
			case "LOW":
				action.LowCount++
			}
			if c.CVSSScore != nil && (action.TopCVSS == nil || *c.CVSSScore > *action.TopCVSS) {
				v := *c.CVSSScore
				action.TopCVSS = &v
			}
		}
		actions = append(actions, action)
	}
	sort.Slice(actions, func(i, j int) bool {
		a, b := actions[i], actions[j]
		if a.CriticalCount != b.CriticalCount {
			return a.CriticalCount > b.CriticalCount
		}
		if a.HighCount != b.HighCount {
			return a.HighCount > b.HighCount
		}
		if len(a.CVEs) != len(b.CVEs) {
			return len(a.CVEs) > len(b.CVEs)
		}
		if len(a.Devices) != len(b.Devices) {
			return len(a.Devices) > len(b.Devices)
		}
		return a.AppName < b.AppName
	})

	for appName, bucket := range unverifiedByApp {
		unverified = append(unverified, CVEUnverifiedGroup{
			AppName: appName,
			Devices: bucket.devices(),
			CVEs:    bucket.records(),
		})
	}
	sort.Slice(unverified, func(i, j int) bool { return unverified[i].AppName < unverified[j].AppName })

	return actions, unverified
}
