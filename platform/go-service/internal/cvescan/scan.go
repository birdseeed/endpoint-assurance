// Package cvescan contains the shared logic for running a CVE assessment
// against a device-app inventory. Used by both cmd/patched-import-scan
// (CLI path) and the POST /admin/import-scan/cve.pdf HTTP handler.
package cvescan

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/csvparse"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/report"
)

// LoadMappings reads the curated application CPE mappings. PAT-2138: an
// automatically published mapping is deliberately not used here, because the
// import scan's output carries no mapping basis to label it with.
func LoadMappings(ctx context.Context, pool *pgxpool.Pool) ([]cvematch.CPEMapping, error) {
	rows, err := pool.Query(ctx, `SELECT match_name, cpe_vendor, cpe_product FROM app_cpe_mappings WHERE source_type = 'app_name' AND review_state = 'curated'`)
	if err != nil {
		return nil, fmt.Errorf("query mappings: %w", err)
	}
	defer rows.Close()
	var out []cvematch.CPEMapping
	for rows.Next() {
		var m cvematch.CPEMapping
		if err := rows.Scan(&m.MatchName, &m.CPEVendor, &m.CPEProduct); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// LoadFeed reads the full CVE feed from the database.
func LoadFeed(ctx context.Context, pool *pgxpool.Pool) ([]cvematch.CVEEntry, error) {
	rows, err := pool.Query(ctx, `
		SELECT cve_id, COALESCE(description,''), cvss_v3_score, severity, cpe_patterns, cpe_ranges,
		       published_at
		FROM cve_feed_entries
	`)
	if err != nil {
		return nil, fmt.Errorf("query feed: %w", err)
	}
	defer rows.Close()
	var out []cvematch.CVEEntry
	for rows.Next() {
		var e cvematch.CVEEntry
		var rangesRaw []byte
		var published *time.Time
		if err := rows.Scan(&e.CVEID, &e.Description, &e.Score, &e.Severity, &e.Patterns, &rangesRaw, &published); err != nil {
			return nil, fmt.Errorf("scan feed entry: %w", err)
		}
		if published != nil {
			e.PublishedAt = *published // NULL stays zero: never age-cut
		}
		if len(rangesRaw) > 0 && string(rangesRaw) != "null" {
			if err := json.Unmarshal(rangesRaw, &e.Ranges); err != nil {
				return nil, fmt.Errorf("unmarshal cpe_ranges for %s: %w", e.CVEID, err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GroupByDevice converts a flat app list into a per-device map of ScannedApps.
func GroupByDevice(apps []csvparse.App) map[string][]cvematch.ScannedApp {
	out := map[string][]cvematch.ScannedApp{}
	for _, a := range apps {
		out[a.DeviceName] = append(out[a.DeviceName], cvematch.ScannedApp{
			Name:    a.AppName,
			Version: a.AppVersion,
		})
	}
	return out
}

// BuildReport assembles a FreeCVEReport from per-device findings.
// Devices are iterated in sorted order for deterministic PDF output.
func BuildReport(
	deviceFindings map[string][]cvematch.Finding,
	feed []cvematch.CVEEntry,
	tenant string,
	now time.Time,
) report.FreeCVEReport {
	feedMeta := map[string]cvematch.CVEEntry{}
	for _, e := range feed {
		feedMeta[e.CVEID] = e
	}

	devices := make([]string, 0, len(deviceFindings))
	for d := range deviceFindings {
		devices = append(devices, d)
	}
	sort.Strings(devices)

	var cveOrder []string
	byID := map[string]*report.CVERecord{}

	for _, hostname := range devices {
		for _, f := range deviceFindings[hostname] {
			if _, ok := byID[f.CVEID]; !ok {
				e := feedMeta[f.CVEID]
				byID[f.CVEID] = &report.CVERecord{
					CVEID:       f.CVEID,
					Description: e.Description,
					CVSSScore:   f.Score,
					Severity:    f.Severity,
				}
				cveOrder = append(cveOrder, f.CVEID)
			}
			byID[f.CVEID].Hits = append(byID[f.CVEID].Hits, report.CVEHit{
				Hostname:        hostname,
				AppName:         f.AppName,
				AppVersion:      f.AppVersion,
				MatchConfidence: f.MatchConfidence,
				FixedVersion:    f.FixedVersion,
			})
		}
	}

	cvs := make([]report.CVERecord, 0, len(cveOrder))
	for _, id := range cveOrder {
		cvs = append(cvs, *byID[id])
	}
	report.SortCVERecords(cvs)

	r := report.FreeCVEReport{
		FormatVersion: report.FreeCVEFormatVersion,
		GeneratedAt:   now,
		Tenant:        tenant,
		CVEs:          cvs,
	}
	report.FillFreeCVECounts(&r)
	return r
}
