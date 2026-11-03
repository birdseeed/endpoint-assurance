package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// severityRankSQL maps a lowercased severity string to an integer rank for
// threshold comparisons (min_severity filter) and default sort order.
// Kept in one place so the WHERE and ORDER BY clauses agree.
const severityRankSQL = `CASE LOWER(COALESCE(e.severity, ''))
	WHEN 'critical' THEN 4
	WHEN 'high'     THEN 3
	WHEN 'medium'   THEN 2
	WHEN 'low'      THEN 1
	ELSE 0
END`

var minSeverityRank = map[string]int{
	"all": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// tenantCVESeverityCounts returns the tenant's unfiltered, per-severity count
// of distinct CVEs currently affecting the estate — the same query and
// predicate TenantCVEFindingsHandler uses for its severity_counts summary bar
// (PAT-402). Extracted so a second consumer (the coverage_snapshot findings
// figure frozen at report issuance, PAT-1685) reads from the identical query
// rather than a second, possibly-diverging count of its own.
//
// unknown is the count of distinct CVEs whose severity falls outside the four
// known buckets — NULL, an empty string, or any value cve_feed_entries.severity
// carries that isn't critical/high/medium/low (e.g. "info" from a future feed
// change). TenantCVEFindingsHandler's summary bar has always silently
// dropped these; a live display gap is tolerable there, but a caller that
// sums counts into a total (PAT-1685's findings_total, frozen as evidence)
// cannot drop rows and still call the result a total, so this value exists
// for that caller to add back in rather than re-deriving it from scratch.
func tenantCVESeverityCounts(ctx context.Context, pool *pgxpool.Pool, tenantID string) (counts map[string]int, unknown int, err error) {
	counts = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	rows, err := pool.Query(ctx, `
		SELECT LOWER(COALESCE(e.severity, '')) AS severity,
		       COUNT(DISTINCT f.cve_id)::int
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id = f.cve_id
		JOIN devices d          ON d.id     = f.device_id
		WHERE d.tenant_id = $1::uuid
		GROUP BY LOWER(COALESCE(e.severity, ''))
	`, tenantID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, 0, err
		}
		if _, ok := counts[sev]; ok {
			counts[sev] = count
		} else {
			unknown += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return counts, unknown, nil
}

// TenantCVEFindingsHandler returns the estate-wide, per-CVE CVE findings list
// for a tenant, matching the PAT-402 frontend contract documented in
// console.html (search "PAT-402: CVE findings proxy"):
//
//	GET /admin/tenants/{tenantID}/cve-findings
//	     ?limit=&offset=&min_severity=&os_family=&has_patch=&sort=&dir=
//	  -> { tenant_id, total, severity_counts:{critical,high,medium,low},
//	       findings: [{ cve_id, severity, cvss, affected_device_count,
//	                    first_seen, last_seen, patch_available, os_families:[..],
//	                    match_confidence }] }
//
// `total` reflects the count AFTER filters (drives pagination). `severity_counts`
// is the UNFILTERED per-tenant estate breakdown (drives the summary bar) — it is
// computed separately from the filtered/paginated findings query.
func TenantCVEFindingsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := chi.URLParam(r, "tenantID")
		if tenantID == "" {
			http.Error(w, "missing tenantID", http.StatusBadRequest)
			return
		}

		q := r.URL.Query()
		limit := parseIntDefault(q.Get("limit"), 100, 1, 1000)
		offset := parseIntDefault(q.Get("offset"), 0, 0, 1_000_000_000)

		minSeverity := strings.ToLower(strings.TrimSpace(q.Get("min_severity")))
		if _, ok := minSeverityRank[minSeverity]; !ok {
			minSeverity = "all"
		}
		minSevRank := minSeverityRank[minSeverity]

		osFamily := strings.TrimSpace(q.Get("os_family"))
		if strings.EqualFold(osFamily, "all") {
			osFamily = ""
		}

		hasPatch := strings.ToLower(strings.TrimSpace(q.Get("has_patch")))
		if hasPatch != "yes" && hasPatch != "no" {
			hasPatch = "all"
		}

		sortField := q.Get("sort")
		dir := "DESC"
		if strings.EqualFold(q.Get("dir"), "asc") {
			dir = "ASC"
		}
		var orderExpr string
		switch sortField {
		case "affected":
			orderExpr = "affected_device_count " + dir
		case "first_seen":
			orderExpr = "first_seen " + dir
		default: // "severity" and anything unrecognised
			orderExpr = "sev_rank " + dir
		}
		// Stable secondary sort so pagination doesn't reorder ties across pages.
		orderExpr += ", cve_id ASC"

		// severity_counts — unfiltered, per-tenant distinct-CVE breakdown.
		// unknown (CVEs outside the four known severities) is intentionally
		// dropped here: this endpoint's response shape is unchanged by
		// PAT-1685 — only the frozen findings_total in coverage_snapshot
		// (addFindingsSnapshot) needs it to stay a true total.
		sevCounts, _, err := tenantCVESeverityCounts(r.Context(), pool, tenantID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		// Filtered + paginated findings, one row per CVE aggregated across the
		// tenant's affected devices.
		//
		// patch_available has no direct backing column in cve_feed_entries (no
		// fix-version field — only cpe_ranges JSONB / cpe_patterns). This derives
		// a rough boolean from whether any cpe_ranges row carries a version
		// bound, which is an approximation, not a real "is there a fix" signal.
		// Flagged as an open question — revisit once NVD fix-version data is
		// available in the feed.
		rows, err := pool.Query(r.Context(), `
			WITH agg AS (
				SELECT
					f.cve_id,
					LOWER(COALESCE(e.severity, '')) AS severity,
					`+severityRankSQL+` AS sev_rank,
					e.cvss_v3_score AS cvss,
					COUNT(DISTINCT f.device_id)::int AS affected_device_count,
					MIN(f.first_seen_at) AS first_seen,
					MAX(f.last_seen_at)  AS last_seen,
					ARRAY_AGG(DISTINCT d.os) AS os_families,
					-- cpe_ranges is NOT NULL DEFAULT '[]' but can hold the JSON scalar
					-- null value (not SQL NULL) for unmatched CVEs, so a non-array
					-- reads as no rows. PAT-2107: since then cpe_ranges also holds
					-- rows with no version bounds (exact-version and platform-only
					-- CPEs), so "any row" no longer means "version-bound data";
					-- test the bound fields themselves, which is what a non-empty
					-- array meant before.
					COALESCE((
						SELECT BOOL_OR(COALESCE(r->>'vStartIncl', '') <> '' OR COALESCE(r->>'vStartExcl', '') <> ''
						            OR COALESCE(r->>'vEndIncl', '') <> '' OR COALESCE(r->>'vEndExcl', '') <> '')
						FROM jsonb_array_elements(CASE WHEN jsonb_typeof(e.cpe_ranges) = 'array'
						                               THEN e.cpe_ranges ELSE '[]'::jsonb END) AS r
					), false) AS patch_available,
					-- PAT-1831: worst-case match_confidence across every device
					-- backing this CVE. "version_confirmed" and
					-- "version_vendor_confirmed" (PAT-409, Apple/MSRC vendor
					-- releases) are both "confirmed" per confirmedConfidence
					-- (internal/report/cve_report.go) and per the console's
					-- own cveEvidenceBasis() -- only "version_unverified" is
					-- weak -- so a single unverified device is enough to
					-- make the whole aggregate row unverified, never
					-- averaged or majority-voted away (root AGENTS.md: CVE
					-- claims require evidence, and the weakest real signal
					-- wins, not the most common one). When every device is
					-- confirmed by one route or the other, this CASE
					-- reports "version_confirmed" as the representative
					-- value -- an arbitrary but deterministic pick between
					-- two callers that both read as "confirmed" downstream,
					-- not a claim that one route is stronger than the other.
					(CASE
					     WHEN BOOL_OR(f.match_confidence = 'version_unverified' OR f.match_confidence IS NULL)
					         THEN 'version_unverified'
					     WHEN BOOL_OR(f.match_confidence = 'version_confirmed')
					         THEN 'version_confirmed'
					     ELSE 'version_vendor_confirmed'
					END) AS match_confidence
				FROM device_cve_findings f
				JOIN cve_feed_entries e ON e.cve_id = f.cve_id
				JOIN devices d          ON d.id     = f.device_id
				WHERE d.tenant_id = $1::uuid
				  AND ($2 = '' OR d.os = $2)
				GROUP BY f.cve_id, e.severity, e.cvss_v3_score, e.cpe_ranges
			)
			SELECT cve_id, severity, cvss, affected_device_count, first_seen, last_seen,
			       os_families, patch_available, match_confidence, COUNT(*) OVER()::int AS total
			FROM agg
			WHERE sev_rank >= $3
			  AND ($4 = 'all' OR ($4 = 'yes' AND patch_available) OR ($4 = 'no' AND NOT patch_available))
			ORDER BY `+orderExpr+`
			LIMIT $5 OFFSET $6
		`, tenantID, osFamily, minSevRank, hasPatch, limit, offset)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type cveFinding struct {
			CVEID               string    `json:"cve_id"`
			Severity            string    `json:"severity"`
			CVSS                *float64  `json:"cvss"`
			AffectedDeviceCount int       `json:"affected_device_count"`
			FirstSeen           time.Time `json:"first_seen"`
			LastSeen            time.Time `json:"last_seen"`
			OSFamilies          []string  `json:"os_families"`
			PatchAvailable      bool      `json:"patch_available"`
			MatchConfidence     string    `json:"match_confidence"`
		}

		findings := []cveFinding{}
		total := 0
		for rows.Next() {
			var f cveFinding
			if err := rows.Scan(&f.CVEID, &f.Severity, &f.CVSS, &f.AffectedDeviceCount,
				&f.FirstSeen, &f.LastSeen, &f.OSFamilies, &f.PatchAvailable, &f.MatchConfidence, &total); err != nil {
				http.Error(w, "scan error", http.StatusInternalServerError)
				return
			}
			findings = append(findings, f)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":       tenantID,
			"total":           total,
			"severity_counts": sevCounts,
			"findings":        findings,
		})
	}
}

// TenantCVEFindingDevicesHandler returns the devices affected by one CVE for
// a tenant — the per-CVE drill-in used by console.html's _cveOpenDetail /
// fetchTenantCveDevices:
//
//	GET /admin/tenants/{tenantID}/cve-findings/{cveID}/devices
//	  -> { tenant_id, cve_id,
//	       devices: [{ device_id, hostname, os, installed_version, agent_last_seen }] }
func TenantCVEFindingDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := chi.URLParam(r, "tenantID")
		cveID := chi.URLParam(r, "cveID")
		if tenantID == "" || cveID == "" {
			http.Error(w, "missing tenantID or cveID", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT d.id::text, COALESCE(d.hostname, ''), d.os, f.app_version, f.last_seen_at
			FROM device_cve_findings f
			JOIN devices d ON d.id = f.device_id
			WHERE d.tenant_id = $1::uuid AND f.cve_id = $2
			ORDER BY d.hostname
		`, tenantID, cveID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type deviceEntry struct {
			DeviceID         string    `json:"device_id"`
			Hostname         string    `json:"hostname"`
			OS               string    `json:"os"`
			InstalledVersion string    `json:"installed_version"`
			AgentLastSeen    time.Time `json:"agent_last_seen"`
		}

		devices := []deviceEntry{}
		for rows.Next() {
			var d deviceEntry
			if err := rows.Scan(&d.DeviceID, &d.Hostname, &d.OS, &d.InstalledVersion, &d.AgentLastSeen); err != nil {
				http.Error(w, "scan error", http.StatusInternalServerError)
				return
			}
			devices = append(devices, d)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": tenantID,
			"cve_id":    cveID,
			"devices":   devices,
		})
	}
}

// parseIntDefault parses s as an int, clamped to [min, max]; returns def if s
// is empty or unparseable.
func parseIntDefault(s string, def, min, max int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// DeviceCVEFindingsHandler returns pre-matched CVE findings for a single device.
func DeviceCVEFindingsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceID := chi.URLParam(r, "deviceID")
		if deviceID == "" {
			http.Error(w, "missing deviceID", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(r.Context(), `
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
				f.last_seen_at,
				f.fixed_version,
				f.package_source,
				f.package_name,
				f.install_reason,
				f.required_by,
				f.mapping_basis,
				f.confidence_tier
			FROM device_cve_findings f
			JOIN cve_feed_entries e ON e.cve_id = f.cve_id
			WHERE f.device_id = $1::uuid
			ORDER BY e.cvss_v3_score DESC NULLS LAST, f.cve_id
		`, deviceID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type finding struct {
			CVEID             string     `json:"cve_id"`
			Description       string     `json:"description"`
			DescriptionSource string     `json:"description_source"`
			CVSSScore         *float64   `json:"cvss_v3_score"`
			Severity          string     `json:"severity"`
			PublishedAt       *time.Time `json:"published_at"`
			AppName           string     `json:"app_name"`
			AppVersion        string     `json:"app_version"`
			MatchConfidence   string     `json:"match_confidence"`
			LastSeenAt        time.Time  `json:"last_seen_at"`
			FixedVersion      string     `json:"fixed_version"`
			// PAT-2023: Homebrew package evidence. Omitted for application
			// and OS findings, which leave these columns NULL.
			PackageSource  *string  `json:"package_source,omitempty"`
			PackageName    *string  `json:"package_name,omitempty"`
			InstallReason  *string  `json:"install_reason,omitempty"`
			RequiredBy     []string `json:"required_by,omitempty"`
			MappingBasis   *string  `json:"mapping_basis,omitempty"`
			ConfidenceTier *string  `json:"confidence_tier,omitempty"`
		}

		findings := []finding{}
		for rows.Next() {
			var f finding
			if err := rows.Scan(&f.CVEID, &f.Description, &f.DescriptionSource, &f.CVSSScore, &f.Severity,
				&f.PublishedAt, &f.AppName, &f.AppVersion, &f.MatchConfidence, &f.LastSeenAt,
				&f.FixedVersion, &f.PackageSource, &f.PackageName, &f.InstallReason, &f.RequiredBy,
				&f.MappingBasis, &f.ConfidenceTier); err != nil {
				http.Error(w, "scan error", http.StatusInternalServerError)
				return
			}
			findings = append(findings, f)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"findings": findings,
			"total":    len(findings),
		})
	}
}
