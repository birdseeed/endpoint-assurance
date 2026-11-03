// PAT-1728: per-product "devices behind" comparison for GET /v1/portal/applications'
// approved/mandatory policy rows, added alongside the version_count/signing
// fields PAT-1799 already put on this endpoint.
package report

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvematch"
)

// catalogGapKey identifies one AppPolicyRow group precisely enough to attach
// a devices-behind-catalog computation to the matching PortalApplication
// row — the same (name, policy, enforcement_tier, platform) tuple
// FetchAppPolicyDriftReport's GROUP BY already uses.
type catalogGapKey struct {
	Name            string
	Policy          string
	EnforcementTier string
	Platform        string
}

// catalogGap is one policy group's catalog comparison: the canonical
// "latest known version" chosen for the group and the distinct device count
// running something older than it.
type catalogGap struct {
	LatestVersion      string
	DevicesBehindCount int
}

// fetchApprovedCatalogGapSQL joins tenant_app_policies -> devices ->
// device_apps exactly as FetchAppPolicyDriftReport's own query does (same
// platform scoping, same name/bundle_id/team_id OR match), restricted here
// to approved/mandatory policies, then attaches each matched device_apps
// row's app_catalog_entries match using the EXACT identity rule
// needs_attention.go's catalog_out_of_date CTE established for PAT-458:
// platform (device OS -> "macOS"/"Windows"), then verified_signer if the
// catalog entry has one, else case-insensitive name. The LATERAL join picks
// one canonical catalog row per matched device_apps row the same
// deterministic way catalog_out_of_date does (highest latest_version wins
// on a tie), so a data-quality duplicate in app_catalog_entries can't fan
// out one device into two counted rows.
//
// Deliberately does NOT filter or compare on da.version < ace.latest_version
// in SQL — that would be a string comparison ("9" > "10"), which is wrong
// for real version numbers. This query only resolves identity and returns
// the raw (installed_version, catalog_latest_version) pair per matched
// device; fetchApprovedCatalogGaps does the actual comparison in Go via
// cvematch.CompareVersions (root AGENTS.md: "CVE and usage claims require
// evidence" — verify version semantics, don't guess).
const fetchApprovedCatalogGapSQL = `
SELECT
    COALESCE(tap.name, tap.bundle_id, tap.team_id, '—') AS group_name,
    tap.policy, tap.enforcement_tier, tap.platform,
    da.device_id::text AS device_id,
    da.version          AS installed_version,
    ace.latest_version   AS catalog_latest_version
FROM effective_tenant_app_policies($1::uuid) tap
JOIN devices dv ON dv.tenant_id = tap.tenant_id
    AND (tap.platform = 'any' OR lower(dv.os) = tap.platform)
JOIN device_apps da ON da.device_id = dv.id AND (
    (tap.name IS NOT NULL AND lower(da.name) = lower(tap.name))
    OR (tap.bundle_id IS NOT NULL AND da.identifier = tap.bundle_id)
    OR (tap.team_id IS NOT NULL AND da.team_id = tap.team_id)
)
JOIN LATERAL (
    SELECT ace.latest_version
    FROM app_catalog_entries ace
    WHERE ace.platform = CASE WHEN dv.os ILIKE '%windows%' THEN 'Windows' ELSE 'macOS' END
      AND (
        (ace.verified_signer IS NOT NULL AND da.team_id = ace.verified_signer)
        OR (ace.verified_signer IS NULL AND lower(da.name) = lower(ace.name))
      )
    ORDER BY ace.latest_version DESC
    LIMIT 1
) ace ON true
WHERE tap.tenant_id = $1
  AND tap.policy IN ('approved', 'mandatory')
  AND da.version IS NOT NULL
`

// fetchApprovedCatalogGaps computes the PAT-1728 "devices behind" comparison
// for approved/mandatory tenant_app_policies rows only. Scoped to those two
// policy values (not every row FetchPortalApplications returns) because:
//   - the ticket's own need is the portal's "Approved" group;
//   - undecided rows are grouped by device_apps.identifier/name directly
//     (portalApplicationsUndecidedQuery), a different grouping key than the
//     tap identity (name/bundle_id/team_id) this query keys on, so folding
//     them in would need a second, differently-shaped join rather than
//     reusing this one; and
//   - it avoids running the extra catalog join over every unapproved/
//     unmanaged/undecided row that will never render a behind-count.
//
// A product with no matching app_catalog_entries row is absent from the
// returned map entirely — callers must treat a missing key as "no
// evidence" and leave both response fields null, never a guessed zero
// (root AGENTS.md: "absence requires authority").
func fetchApprovedCatalogGaps(ctx context.Context, pool *pgxpool.Pool, tenantID string) (map[catalogGapKey]catalogGap, error) {
	rows, err := pool.Query(ctx, fetchApprovedCatalogGapSQL, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			// tenant_app_policies or app_catalog_entries not migrated yet in
			// this environment — same fail-open convention
			// FetchAppPolicyDriftReport uses for tenant_app_policies.
			return nil, nil
		}
		return nil, fmt.Errorf("fetch approved catalog gaps: %w", err)
	}
	defer rows.Close()

	type gapRow struct {
		key       catalogGapKey
		deviceID  string
		installed string
		latest    string
	}
	byKey := map[catalogGapKey][]gapRow{}
	for rows.Next() {
		var r gapRow
		if err := rows.Scan(&r.key.Name, &r.key.Policy, &r.key.EnforcementTier, &r.key.Platform,
			&r.deviceID, &r.installed, &r.latest); err != nil {
			return nil, fmt.Errorf("scan approved catalog gap row: %w", err)
		}
		byKey[r.key] = append(byKey[r.key], r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approved catalog gap rows: %w", err)
	}

	result := make(map[catalogGapKey]catalogGap, len(byKey))
	for key, group := range byKey {
		// Canonical latest version for the group: the highest catalog
		// latest_version any matched device resolved to, by real semantic
		// comparison. In practice every device in a group resolves to the
		// same single catalog entry (one product = one catalog row); taking
		// the max is a deliberate, documented fallback for the rare case a
		// policy's OR-matched devices land on more than one.
		canonical := ""
		for _, r := range group {
			canonical = cvematch.MaxVersion(canonical, r.latest)
		}
		behind := map[string]struct{}{}
		for _, r := range group {
			if cvematch.CompareVersions(r.installed, canonical) < 0 {
				behind[r.deviceID] = struct{}{}
			}
		}
		result[key] = catalogGap{LatestVersion: canonical, DevicesBehindCount: len(behind)}
	}
	return result, nil
}
