// GET /v1/portal/software (PAT-1869). This is deliberately separate from
// portal_applications.go: it is an inventory and usage-evidence view over
// device_apps, not a policy queue. In particular, it has no estate-size cap.
package report

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/apppolicy"
	"patched.im/api/internal/softwaregov"
)

const (
	// SoftwareMeteringEvidenceFreshness is intentionally distinct from the
	// unused horizon. A device must have reported an `ok` metering result in
	// this window, with fresh per-app evidence, before its last-use value can
	// support an unused conclusion. Legacy rows use the app's last_seen when
	// no explicit usage receipt exists; a device heartbeat cannot renew it.
	// Even then only a recorded last_used_at older than the horizon counts: a
	// NULL last_used_at is absence of a launch record, never evidence of
	// non-use (PAT-2327).
	SoftwareMeteringEvidenceFreshness = 30 * 24 * time.Hour
	softwareUnusedHorizon             = 90 * 24 * time.Hour
)

type SoftwareMeteringCoverage struct {
	InstallationCount int
	MeteredCount      int
	UnmeteredCount    int
	StaleCount        int
	UnusedCount       int
	// NoEvidenceCount (PAT-2327) counts fresh, metered installations that
	// carry no usable last-use evidence: last_used_at is NULL, or the device
	// is a server or domain controller and last_used_at is older than the
	// unused horizon (software there runs as services, so an old or missing
	// launch record is not a verdict). It is not unused; it is the metered
	// counterpart of unmetered.
	NoEvidenceCount int
}

type PortalSoftwareProduct struct {
	Name                            string
	Names                           []string
	Identifier                      string
	Platform                        string
	Versions                        []string
	UnknownVersionInstallationCount int
	DeviceCount                     int
	InstallationCount               int
	EvidenceAt                      time.Time
	LastUsedAt                      *time.Time
	MeteredInstallationCount        int
	UnmeteredInstallationCount      int
	StaleInstallationCount          int
	UnusedInstallationCount         int
	// NoEvidenceInstallationCount (PAT-2327) is the number of fresh, metered
	// installations with no usable last-use evidence (see
	// SoftwareMeteringCoverage.NoEvidenceCount). Disjoint from
	// UnusedInstallationCount and UnmeteredInstallationCount, and rolled up
	// on the unmetered side of softwareUsageState.
	NoEvidenceInstallationCount int
	UsageState                  string
	RemovalCandidate            bool
	CanonicalKey                *string
	CanonicalName               *string
	// TeamID (PAT-2104) is the macOS Team ID identity a write to
	// PUT /v1/portal/software-approvals needs for this product: nil on
	// Windows (PAT-2007 carries no team_id for a Windows item), and nil on
	// macOS whenever the group's current installations disagree on team_id
	// (never guessed — root AGENTS.md: "absence requires authority") or none
	// carries one at all.
	TeamID *string
	// ProductKey (PAT-2104) is exactly the key PAT-2007's write path
	// computes for this identity (softwaregov.ApplicationKey) — nil for a
	// product whose platform is neither "macos" nor "windows" (the write
	// schema has no other platform value).
	ProductKey *string
	// PolicyState (PAT-2104) is this product's current governance state,
	// resolved with the SAME resolver the write path and the PAT-2009
	// alerts use (apppolicy.Index.Resolve), so this never disagrees with
	// GET /v1/portal/applications or the unapproved-software alert for the
	// same product. One of "approved", "unapproved", "mandatory", "ignored"
	// (tenant_app_policies "unmanaged", relabelled to the PAT-2007
	// vocabulary), or nil when no policy resolves for this product at all
	// (undecided) or the platform cannot be resolved.
	PolicyState *string
	// FirstSeenOnDevice (PAT-2156) is the earliest device_apps.first_seen
	// across this group's rows for the caller's ?device_id= filter. Only
	// populated when the page is device-scoped (deviceID != "" in
	// fetchPortalSoftwareAt); nil otherwise, so the unfiltered response
	// stays byte-identical to before PAT-2156. Cheaply available: first_seen
	// is a plain column on device_apps (0001_initial.sql), so this is a
	// MIN() over the same grouped rows already being aggregated, not an
	// extra query.
	FirstSeenOnDevice *time.Time
}

type PortalSoftwarePage struct {
	GeneratedAt time.Time
	Total       int
	Coverage    SoftwareMeteringCoverage
	Products    []PortalSoftwareProduct
}

// softwareInventorySearchWhere is shared by the grouped count and page
// queries. Keeping one predicate prevents an empty or later page from
// disagreeing with total about which products the caller searched for.
const softwareInventorySearchWhere = `
		WHERE $5 = '' OR name ILIKE $6 OR identifier ILIKE $6
		   OR canonical_key ILIKE $6 OR canonical_name ILIKE $6
		   OR EXISTS (SELECT 1 FROM unnest(names) AS observed_name WHERE observed_name ILIKE $6)`

// FetchPortalSoftware returns one exact, deterministically ordered page of
// raw current-inventory products. `search` affects the product page and total,
// not Coverage: coverage is intentionally estate-wide so a narrow search can
// never make metering completeness look better than it is.
func FetchPortalSoftware(ctx context.Context, pool *pgxpool.Pool, tenantID, search string, limit, offset int) (PortalSoftwarePage, error) {
	return fetchPortalSoftwareAt(ctx, pool, tenantID, "", search, limit, offset, time.Now().UTC())
}

// FetchPortalSoftwareForDevice is FetchPortalSoftware narrowed to one
// device's own current installations (PAT-2156's GET /v1/portal/software
// ?device_id= filter). deviceID must already be validated as a well-formed
// UUID owned by tenantID (report.DeviceTenant) by the caller — this function
// does not itself check ownership, the same division of responsibility
// FetchHomebrewDeviceDetail's caller (PortalHomebrewDeviceHandler) follows.
//
// Rows are that device's device_apps rows only (same (identifier, platform)
// grouping as the estate-wide page), and Coverage is scoped to the device
// too — both fall out of the same `inventory` CTE device filter below, so
// there is exactly one place this endpoint's "coverage is scoped to the
// device" contract line is implemented. search/limit/offset keep their
// normal meaning, scoped to this device's rows.
func FetchPortalSoftwareForDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, search string, limit, offset int) (PortalSoftwarePage, error) {
	return fetchPortalSoftwareAt(ctx, pool, tenantID, deviceID, search, limit, offset, time.Now().UTC())
}

// fetchPortalSoftwareAt is shared by FetchPortalSoftware and
// FetchPortalSoftwareForDevice. deviceID == "" means unfiltered — the
// `$4 = ” OR da.device_id = $4::uuid` predicate below then always takes
// its first branch, so the unfiltered query text and result are unchanged
// from before PAT-2156's device_id filter existed.
func fetchPortalSoftwareAt(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, search string, limit, offset int, asOf time.Time) (PortalSoftwarePage, error) {
	// asOf is captured once per request and also becomes the response's
	// generated_at. No response timestamp can therefore imply evidence newer
	// than the freshness/unused cut-offs that produced it.
	var page PortalSoftwarePage
	page.GeneratedAt = asOf
	freshAfter := asOf.Add(-SoftwareMeteringEvidenceFreshness)
	unusedBefore := asOf.Add(-softwareUnusedHorizon)

	// device_apps is the source of truth here. The alias lateral join is only
	// a reviewed canonical-identity enrichment; no software_installations row
	// is read, because that projection does not carry metering evidence.
	const base = `
		WITH inventory AS (
			SELECT da.device_id, da.name, da.identifier, da.version, da.last_seen,
			       CASE WHEN da.usage_evidence IS NULL OR da.usage_evidence = 'recorded' THEN da.last_used_at END AS last_used_at,
			       da.usage_evidence, da.usage_evidence_at, da.usage_evidence_complete, da.team_id, da.publisher, da.signer, da.identifier_kind,
			       COALESCE(da.usage_evidence_at, da.last_seen) AS app_evidence_at,
			       da.first_seen,
			       d.last_seen AS device_last_seen,
			       CASE WHEN da.usage_evidence IN ('unmapped', 'unavailable') THEN 'unavailable' ELSE d.metering_status END AS metering_status, d.device_class,
			       CASE WHEN d.os ILIKE '%windows%' THEN 'windows'
			            WHEN d.os ILIKE '%macos%' THEN 'macos'
			            ELSE 'unknown' END AS platform
			FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE d.tenant_id = $1::uuid
			  AND (NULLIF($4, '') IS NULL OR da.device_id = NULLIF($4, '')::uuid)
		), base AS (
			SELECT i.device_id, i.name, i.identifier, i.version, i.last_seen,
			       i.last_used_at, i.device_last_seen, i.metering_status, i.platform,
			       i.team_id, i.identifier_kind, i.first_seen,
			       ci.canonical_key, ci.canonical_name,
			       (i.device_last_seen < $2 OR i.app_evidence_at < $2) AS is_stale,
			       -- PAT-2327: the one place a per-installation usage verdict is
			       -- decided, so the coverage query and the grouped rollup can
			       -- never disagree. Both require a metered, fresh device. Unused
			       -- also requires fresh app evidence and a RECORDED last_used_at
			       -- older than the horizon on a non-server. Legacy rows use the
			       -- app observation, never an unrelated device heartbeat.
			       -- NULL is a missing launch record, not
			       -- evidence of non-use. Servers and domain controllers run
			       -- software as services and rarely produce a user launch record,
			       -- so a NULL or old value there is no-evidence, never unused;
			       -- a recorded use inside the horizon is still positive evidence
			       -- of use and counts as used (neither flag). The two are disjoint.
			       (i.metering_status = 'ok' AND i.device_last_seen >= $2
			        AND i.app_evidence_at >= $2
			        AND i.device_class NOT IN ('server', 'domain_controller')
			        AND (i.usage_evidence_at IS NULL OR ((i.usage_evidence IS NULL OR i.usage_evidence = 'recorded')
			             AND i.usage_evidence_at >= $2 AND i.usage_evidence_complete IS TRUE))
			        AND i.last_used_at IS NOT NULL AND i.last_used_at < $3) AS is_unused,
			       (i.metering_status = 'ok' AND i.device_last_seen >= $2
			        AND (i.last_used_at IS NULL
			             OR (i.usage_evidence_at IS NOT NULL AND (i.usage_evidence_at < $2 OR i.usage_evidence_complete IS NOT TRUE))
			             OR (i.device_class IN ('server', 'domain_controller')
			                 AND i.last_used_at < $3))) AS is_no_evidence
			FROM inventory i
			LEFT JOIN LATERAL (
				SELECT sp.canonical_key, sp.canonical_name
				FROM software_product_aliases spa
				JOIN software_products sp ON sp.id = spa.product_id
				WHERE spa.provenance = 'reviewed'
				  AND spa.retired_at IS NULL
				  AND spa.platform = i.platform
				  AND (
					(spa.identity_kind = 'macos_bundle_team'
					 AND lower(btrim(i.identifier)) = spa.identity_value_normalized
					 AND upper(btrim(COALESCE(i.team_id, ''))) = spa.companion_value_normalized)
					OR (spa.identity_kind = 'macos_bundle'
					 AND lower(btrim(i.identifier)) = spa.identity_value_normalized
					 AND spa.companion_value_normalized = '')
					OR (spa.identity_kind = 'windows_native_publisher'
					 AND lower(btrim(i.identifier)) = spa.identity_value_normalized
					 AND lower(COALESCE(NULLIF(btrim(i.publisher), ''), NULLIF(btrim(i.signer), ''), '')) = spa.companion_value_normalized)
					OR (spa.identity_kind = 'windows_native'
					 AND lower(btrim(i.identifier)) = spa.identity_value_normalized
					 AND spa.companion_value_normalized = '')
				)
				ORDER BY CASE spa.identity_kind
					WHEN 'macos_bundle_team' THEN 1 WHEN 'windows_native_publisher' THEN 1 ELSE 2 END,
					 spa.match_confidence DESC, spa.id
				LIMIT 1
			) ci ON true
		), grouped AS (
			SELECT identifier, platform, min(name) AS name,
			       array_agg(DISTINCT name ORDER BY name) AS names,
			       array_agg(DISTINCT version ORDER BY version) FILTER (WHERE version IS NOT NULL AND btrim(version) <> '') AS versions,
			       count(*) FILTER (WHERE version IS NULL OR btrim(version) = '')::int AS unknown_version_installation_count,
			       count(DISTINCT device_id)::int AS device_count,
			       count(*)::int AS installation_count,
			       max(last_seen) AS evidence_at,
			       max(last_used_at) AS last_used_at,
			       count(*) FILTER (WHERE metering_status = 'ok')::int AS metered_installation_count,
			       count(*) FILTER (WHERE metering_status IS DISTINCT FROM 'ok')::int AS unmetered_installation_count,
			       count(*) FILTER (WHERE is_stale)::int AS stale_installation_count,
			       count(*) FILTER (WHERE is_unused)::int AS unused_installation_count,
			       count(*) FILTER (WHERE is_no_evidence)::int AS no_evidence_installation_count,
			       count(*) FILTER (WHERE canonical_key IS NOT NULL)::int AS canonical_installation_count,
			       count(DISTINCT canonical_key)::int AS canonical_product_count,
			       min(canonical_key) AS canonical_key, min(canonical_name) AS canonical_name,
			       min(first_seen) AS first_seen_on_device,
			       count(DISTINCT upper(btrim(team_id))) FILTER (
			           WHERE platform = 'macos' AND team_id IS NOT NULL AND btrim(team_id) <> ''
			       )::int AS team_id_variant_count,
			       max(upper(btrim(team_id))) FILTER (
			           WHERE platform = 'macos' AND team_id IS NOT NULL AND btrim(team_id) <> ''
			       ) AS team_id_value,
			       max(identifier_kind) FILTER (WHERE identifier_kind IS NOT NULL AND btrim(identifier_kind) <> '') AS identifier_kind_value
			FROM base
			GROUP BY identifier, platform
		)`

	if err := pool.QueryRow(ctx, base+`
		SELECT count(*)::int,
		       count(*) FILTER (WHERE metering_status = 'ok')::int,
		       count(*) FILTER (WHERE metering_status IS DISTINCT FROM 'ok')::int,
		       count(*) FILTER (WHERE is_stale)::int,
		       count(*) FILTER (WHERE is_unused)::int,
		       count(*) FILTER (WHERE is_no_evidence)::int
		FROM base`, tenantID, freshAfter, unusedBefore, deviceID).Scan(
		&page.Coverage.InstallationCount, &page.Coverage.MeteredCount,
		&page.Coverage.UnmeteredCount, &page.Coverage.StaleCount, &page.Coverage.UnusedCount,
		&page.Coverage.NoEvidenceCount,
	); err != nil {
		return page, fmt.Errorf("software inventory coverage: %w", err)
	}

	search = strings.TrimSpace(search)
	pattern := "%" + search + "%"
	if err := pool.QueryRow(ctx, base+`
		SELECT count(*)::int
		FROM grouped`+softwareInventorySearchWhere,
		tenantID, freshAfter, unusedBefore, deviceID, search, pattern).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("software inventory total: %w", err)
	}
	// PAT-2104: the tenant's policy index, loaded once per page and resolved
	// per product below with apppolicy.Index.Resolve — the identical
	// resolver the write path (currentAppDecision's neighbours) and the
	// PAT-2009 unapproved-software alert use, so policy_state here can never
	// disagree with GET /v1/portal/applications or the alert for the same
	// product.
	policyIndex, err := loadAppPolicyIndexForSoftware(ctx, pool, tenantID)
	if err != nil {
		return page, fmt.Errorf("software inventory: load app policy index: %w", err)
	}

	rows, err := pool.Query(ctx, base+`
		SELECT identifier, platform, name, names, COALESCE(versions, ARRAY[]::text[]),
		       unknown_version_installation_count, device_count, installation_count,
		       evidence_at, last_used_at, metered_installation_count,
		       unmetered_installation_count, stale_installation_count,
		       unused_installation_count, no_evidence_installation_count,
		       canonical_installation_count, canonical_product_count, canonical_key, canonical_name,
		       team_id_variant_count, team_id_value, identifier_kind_value,
		       first_seen_on_device
		FROM grouped`+softwareInventorySearchWhere+`
		ORDER BY name ASC, identifier ASC, platform ASC
		LIMIT $7 OFFSET $8`, tenantID, freshAfter, unusedBefore, deviceID, search, pattern, limit, offset)
	if err != nil {
		return page, fmt.Errorf("software inventory page: %w", err)
	}
	defer rows.Close()

	page.Products = []PortalSoftwareProduct{}
	for rows.Next() {
		var product PortalSoftwareProduct
		var matchedCanonicalInstallationCount, canonicalProductCount, teamIDVariantCount int
		var teamIDValue, identifierKindValue *string
		var firstSeenOnDevice *time.Time
		if err := rows.Scan(&product.Identifier, &product.Platform, &product.Name, &product.Names,
			&product.Versions, &product.UnknownVersionInstallationCount, &product.DeviceCount,
			&product.InstallationCount, &product.EvidenceAt, &product.LastUsedAt,
			&product.MeteredInstallationCount, &product.UnmeteredInstallationCount,
			&product.StaleInstallationCount, &product.UnusedInstallationCount,
			&product.NoEvidenceInstallationCount, &matchedCanonicalInstallationCount, &canonicalProductCount, &product.CanonicalKey,
			&product.CanonicalName, &teamIDVariantCount, &teamIDValue, &identifierKindValue,
			&firstSeenOnDevice); err != nil {
			return page, fmt.Errorf("scan software inventory product: %w", err)
		}
		// Only surfaced for a device-scoped page (see FirstSeenOnDevice's doc
		// comment) — an unfiltered page must stay byte-identical to before
		// PAT-2156, so the column is scanned unconditionally but only kept
		// when deviceID was actually supplied.
		if deviceID != "" {
			product.FirstSeenOnDevice = firstSeenOnDevice
		}
		// A canonical identity is emitted only when every current installation
		// in the group directly resolves to the same reviewed product. A label
		// or a partial match must not manufacture an estate-wide identity.
		if matchedCanonicalInstallationCount != product.InstallationCount || canonicalProductCount != 1 {
			product.CanonicalKey = nil
			product.CanonicalName = nil
		}
		// team_id (PAT-2104): only when every current macOS installation in
		// the group agrees. A disagreement is genuine ambiguity, not
		// evidence to average away — never guess which one write should key.
		if product.Platform == "macos" && teamIDVariantCount == 1 {
			product.TeamID = teamIDValue
		}
		identifierKind := ""
		if identifierKindValue != nil {
			identifierKind = *identifierKindValue
		}
		product.PolicyState, product.ProductKey = resolveInventoryPolicy(policyIndex, product, identifierKind)
		product.UsageState, product.RemovalCandidate = softwareUsageState(product)
		page.Products = append(page.Products, product)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("iterate software inventory products: %w", err)
	}
	return page, nil
}

// resolveInventoryPolicy (PAT-2104) computes a software-inventory row's
// current governance state and PAT-2007 product_key, using the SAME
// resolver the write path and the unapproved-software alert use
// (apppolicy.Index.Resolve) so this endpoint never disagrees with
// GET /v1/portal/applications or the alert for the same product.
//
// Only "macos" and "windows" products are resolved: PUT
// /v1/portal/software-approvals has no "any"/"unknown" platform item, so a
// product whose platform this endpoint could not classify gets no
// product_key and no policy_state — never a guessed one (root AGENTS.md:
// "absence requires authority").
func resolveInventoryPolicy(index apppolicy.Index, product PortalSoftwareProduct, identifierKind string) (policyState, productKey *string) {
	if product.Platform != "macos" && product.Platform != "windows" {
		return nil, nil
	}
	teamID := ""
	if product.TeamID != nil {
		teamID = *product.TeamID
	}
	// product_key mirrors policyRoundTripIdentity's addressability rule: a
	// macOS team_id that does not have the write schema's required shape
	// (10 character Apple Team ID) cannot be echoed back through
	// PUT /v1/portal/software-approvals without failing its own 400
	// validation, so no product_key is emitted for this row at all — never
	// a key built from a team_id the write path would reject. policy_state
	// is unaffected: it is read-only evidence, resolved independently of
	// whether this row can be round-tripped through a write.
	if product.Platform == "macos" && teamID != "" && !policyRoundTripTeamIDPattern.MatchString(teamID) {
		productKey = nil
	} else {
		key := softwaregov.ApplicationKey(product.Platform, product.Identifier, teamID)
		productKey = &key
	}
	policy, ok := index.Resolve(teamID, product.Identifier, identifierKind, product.Name, product.Platform)
	if !ok {
		return nil, productKey
	}
	state := softwaregov.AppPolicyState(policy.Policy)
	return &state, productKey
}

// loadAppPolicyIndexForSoftware (PAT-2104) loads this tenant's
// tenant_app_policies rows into an apppolicy.Index, the same shape
// internal/softwaregov's own (unexported) loadPolicies builds for the
// PAT-2009 alert path. Duplicated rather than shared: softwaregov's loader
// is unexported and this endpoint has no other reason to depend on that
// package's internal Querier plumbing. Returns an empty (always
// non-matching) index, not an error, if tenant_app_policies has not been
// migrated yet — the same degrade-gracefully convention
// FetchAppPolicyDriftReport uses.
func loadAppPolicyIndexForSoftware(ctx context.Context, pool *pgxpool.Pool, tenantID string) (apppolicy.Index, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version, source
		FROM effective_tenant_app_policies($1::uuid)
		WHERE tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return apppolicy.BuildIndex(nil), nil
		}
		return apppolicy.Index{}, fmt.Errorf("query tenant app policies: %w", err)
	}
	defer rows.Close()
	var list []apppolicy.Policy
	for rows.Next() {
		var p apppolicy.Policy
		if err := rows.Scan(&p.ID, &p.TeamID, &p.BundleID, &p.WingetID, &p.Name, &p.Platform,
			&p.Policy, &p.EnforcementTier, &p.MinVersion, &p.Source); err != nil {
			return apppolicy.Index{}, fmt.Errorf("scan tenant app policy: %w", err)
		}
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		return apppolicy.Index{}, fmt.Errorf("iterate tenant app policies: %w", err)
	}
	return apppolicy.BuildIndex(list), nil
}

// softwareUsageState rolls a product's installation counts up to one
// usage_state and removal_candidate. Absence of evidence is never evidence of
// non-use (PAT-2327): a product is "unused" only when every installation is
// positively unused (a recorded last_used_at older than the horizon on a
// fresh, metered, non-server device). Installations with no usable last-use
// evidence sit on the unmetered side: nothing was observed about their use,
// whether the collector was unavailable or it ran and found no launch record.
// The set of returned states is unchanged, because the portal rejects any
// usage_state it does not know.
func softwareUsageState(product PortalSoftwareProduct) (string, bool) {
	// Stale and unmetered dimensions intentionally take priority over a
	// possible old last_used_at. They are coverage, not a verdict.
	if product.StaleInstallationCount > 0 {
		return "stale", false
	}
	unobserved := product.UnmeteredInstallationCount + product.NoEvidenceInstallationCount
	if unobserved == product.InstallationCount {
		return "unmetered", false
	}
	if product.UnusedInstallationCount == product.InstallationCount {
		return "unused", true
	}
	if product.UnusedInstallationCount > 0 || unobserved > 0 {
		return "mixed", false
	}
	if product.MeteredInstallationCount == product.InstallationCount {
		return "used", false
	}
	return "unknown", false
}
