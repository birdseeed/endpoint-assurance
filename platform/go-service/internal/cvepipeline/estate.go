package cvepipeline

import (
	"context"
	"fmt"
	"time"

	"patched.im/api/internal/cvematch"
)

// EstateProductKey identifies one product row on GET /v1/portal/software
// (PAT-2028): the same (identifier, platform) grouping
// report.FetchPortalSoftware uses. Several observed device_apps.name values
// can fold into one key (differing display names sharing one identifier);
// AssessEstateProducts rediscovers them from device_apps itself rather than
// taking them as input, so the inventory query and the assessment query can
// never disagree about which observations belong to a product.
type EstateProductKey struct {
	Identifier string
	Platform   string
}

// EstateAssessment is one product's estate-wide CVE assessment, returned by
// AssessEstateProducts. It follows the same three-state rule as
// ProductAssessment, rolled up across every installation of the product in
// the tenant instead of one device:
//
//   - not_assessed: no observed name for this product resolves to a CPE
//     mapping anywhere in the tenant. FindingCount is nil, never zero
//     (absence requires authority: incomplete mapping coverage must never
//     read as "no known CVEs").
//   - pending: the product is mapped, and at least one installation of it is
//     queued for matching or has not been matched at its current version.
//   - assessed: the product is mapped and every installation is current.
//     LastMatchedAt is the OLDEST last_matched_at across those
//     installations, so it is a floor: every installation was matched at
//     least that recently.
//
// FindingCount is the distinct-CVE count across every mapped installation of
// the product in the tenant (device_cve_findings), the same definition
// ProductAssessment.FindingCount uses. It is set whenever the product has
// any mapping coverage at all, not only when fully assessed, so a pending
// product still reports the findings its last successful match found; it is
// nil only for not_assessed.
type EstateAssessment struct {
	State         string     `json:"state"`
	LastMatchedAt *time.Time `json:"last_matched_at"`
	FindingCount  *int       `json:"finding_count"`
	// Severity (PAT-2093) breaks FindingCount down by the finding's recorded
	// severity, over exactly the same finding set. It is not serialised on
	// GET /v1/portal/software (json:"-"), which keeps that contract
	// unchanged; the new software urgency on the overview reads it. Zero
	// valued, and meaningless, when State is not_assessed: callers must
	// check State first.
	Severity SeverityCounts `json:"-"`
	// MappingBasis and Reason (PAT-2138) follow ProductAssessment: basis
	// "auto" when every mapping covering the product's names is automatic,
	// "curated" otherwise, set only when mapped; reason mapping_under_review
	// or no_mapping, set only when not_assessed.
	MappingBasis string `json:"mapping_basis,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// SeverityCounts is a distinct-CVE count per recorded severity. Unrated is a
// finding with no severity, or one outside the four NVD ratings: it is still
// a known CVE, never a clean result. VersionUnverified counts the findings
// (of any severity) whose match_confidence is "version_unverified", the one
// value the findings surfaces treat as not version-confirmed.
type SeverityCounts struct {
	Critical          int `json:"critical"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Low               int `json:"low"`
	Unrated           int `json:"unrated"`
	VersionUnverified int `json:"version_unverified"`
}

// AssessEstateProducts assesses each of the given product groups across the
// whole tenant in one bounded set of set-based queries (not one query per
// product), for GET /v1/portal/software (PAT-2028). The portal is stateless
// and cannot build an estate-wide state for a page of products from
// per-device calls, which is why this exists alongside AssessDevices and
// AssessTenant rather than being derived from them.
//
// On a database without the PAT-2024 tables (binary ahead of migration
// 0161) it degrades to not_assessed for every key, the same "degrade, don't
// 500" contract AssessDevices and AssessTenant follow. A query that fails
// for any other reason returns the error; the caller turns that into a 500,
// which is not a "clean" or "assessed" result either.
func AssessEstateProducts(ctx context.Context, q DB, tenantID string, keys []EstateProductKey) (map[EstateProductKey]EstateAssessment, error) {
	return assessEstateProductsOrDegrade(ctx, q, tenantID, "", keys, identifierExact)
}

// AssessEstateProductsNormalized is AssessEstateProducts for keys whose
// Identifier is a normalised software identity value
// (software_installations.identity_value_normalized: whitespace runs
// collapsed to one space, trimmed, lower-cased), as the new software view
// groups products (PAT-2093). device_apps.identifier is normalised the same
// way before it is compared, so every raw spelling of one identity folds into
// its key. Every other rule is AssessEstateProducts' own, unchanged: the same
// mappings, queue, assessment rows and findings, and the same degrade to
// not_assessed. A normalised key with no device_apps row at all (a name-only
// product, which device_apps never stores) reads not_assessed, never clean.
func AssessEstateProductsNormalized(ctx context.Context, q DB, tenantID string, keys []EstateProductKey) (map[EstateProductKey]EstateAssessment, error) {
	return assessEstateProductsOrDegrade(ctx, q, tenantID, "", keys, identifierNormalized)
}

// The two ways a key's Identifier is compared with device_apps.identifier.
// Constants, never caller input: they are spliced into the SQL text.
const (
	identifierExact      = `da.identifier`
	identifierNormalized = `lower(btrim(regexp_replace(da.identifier, '\s+', ' ', 'g')))`
)

func assessEstateProductsOrDegrade(ctx context.Context, q DB, tenantID, deviceID string, keys []EstateProductKey, identExpr string) (map[EstateProductKey]EstateAssessment, error) {
	out, err := assessEstateProducts(ctx, q, tenantID, deviceID, keys, identExpr)
	if isUndefinedTable(err) {
		out = make(map[EstateProductKey]EstateAssessment, len(keys))
		for _, k := range keys {
			out[k] = EstateAssessment{State: StateNotAssessed}
		}
		return out, nil
	}
	return out, err
}

// EstateAssessmentOrNotAssessed defaults a missing key to not_assessed, the
// same fallback deviceAssessmentOrNotAssessed applies on the device path.
// AssessEstateProducts already fills every requested key, but callers that
// look a key up individually (rather than iterating the returned map) get
// the same "absence requires authority" default either way.
func EstateAssessmentOrNotAssessed(m map[EstateProductKey]EstateAssessment, key EstateProductKey) EstateAssessment {
	if a, ok := m[key]; ok {
		return a
	}
	return EstateAssessment{State: StateNotAssessed}
}

// assessEstateProducts is the one implementation behind the estate and the
// device-scoped views: deviceID "" assesses every installation in the
// tenant; a device id narrows every inventory query to that device's own
// installations (PAT-2156), with every other rule identical.
func assessEstateProducts(ctx context.Context, q DB, tenantID, deviceID string, keys []EstateProductKey, identExpr string) (map[EstateProductKey]EstateAssessment, error) {
	out := map[EstateProductKey]EstateAssessment{}
	if len(keys) == 0 {
		return out, nil
	}
	for _, k := range keys {
		out[k] = EstateAssessment{State: StateNotAssessed}
	}

	identifiers := make([]string, len(keys))
	platforms := make([]string, len(keys))
	for i, k := range keys {
		identifiers[i], platforms[i] = k.Identifier, k.Platform
	}

	// The set of observed device_apps.name values covered by these product
	// groups, needed to run the real CPE mapping check (cvematch, via
	// FilterMapped/CoveredByAny below) in Go rather than reimplementing its
	// word-token rule in SQL.
	var names []string
	keyNames := map[EstateProductKey][]string{}
	rows, err := q.Query(ctx, fmt.Sprintf(`
		WITH page_products AS (
			SELECT identifier, platform FROM unnest($2::text[], $3::text[]) AS t(identifier, platform)
		)
		SELECT DISTINCT da.name, pp.identifier, pp.platform
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		JOIN page_products pp ON pp.identifier = %s
		 AND pp.platform = (CASE WHEN d.os ILIKE '%%windows%%' THEN 'windows'
		                          WHEN d.os ILIKE '%%macos%%' THEN 'macos'
		                          ELSE 'unknown' END)
		WHERE d.tenant_id = $1::uuid
		  AND (NULLIF($4::text, '') IS NULL OR da.device_id = NULLIF($4::text, '')::uuid)
	`, identExpr), tenantID, identifiers, platforms, deviceID)
	if err != nil {
		return nil, fmt.Errorf("load estate product names: %w", err)
	}
	seenName := map[string]bool{}
	for rows.Next() {
		var n string
		var k EstateProductKey
		if err := rows.Scan(&n, &k.Identifier, &k.Platform); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan estate product name: %w", err)
		}
		if !seenName[n] {
			seenName[n] = true
			names = append(names, n)
		}
		keyNames[k] = append(keyNames[k], n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate estate product names: %w", err)
	}
	var refs []ProductRef
	for _, k := range keys {
		for _, n := range keyNames[k] {
			refs = append(refs, ProductRef{k.Platform, n})
		}
	}
	open, err := OpenProposals(ctx, q, refs)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		a := out[k]
		a.Reason = ReasonNoMapping
		for _, n := range keyNames[k] {
			if open.UnderReview(k.Platform, n) {
				a.Reason = ReasonMappingUnderReview
				break
			}
		}
		out[k] = a
	}
	if len(names) == 0 {
		return out, nil
	}

	mappings, err := LoadMappings(ctx, q)
	if err != nil {
		return nil, err
	}
	pendingMatchNames, err := PendingMappingNames(ctx, q)
	if err != nil {
		return nil, err
	}

	// Non-nil so pgx sends '{}' rather than NULL: "= ANY(NULL)" is NULL, and
	// a NULL predicate would silently drop rows from every query below (same
	// footgun assessTenant documents).
	//
	// Mapped is decided per (name, platform) with the matcher's platform
	// filter, so a product mapped only for Windows is not assessed on a Mac.
	ixMapped := newMappingIndex(mappings)
	mappedNames, mappedPlatforms := []string{}, []string{}
	mappingPendingNames, pendingPlatforms := []string{}, []string{}
	for _, k := range keys {
		devicePlatform := cvematch.NormalizeDevicePlatform(k.Platform)
		for _, n := range keyNames[k] {
			if !ixMapped.MappedOn(n, devicePlatform) || isOSPseudoApp(n) {
				continue
			}
			mappedNames, mappedPlatforms = append(mappedNames, n), append(mappedPlatforms, k.Platform)
			if CoveredByAny(n, pendingMatchNames) {
				mappingPendingNames, pendingPlatforms = append(mappingPendingNames, n), append(pendingPlatforms, k.Platform)
			}
		}
	}

	type row struct {
		identifier, platform  string
		anyMapped, anyPending bool
		lastMatchedAt         *time.Time
		findingCount          int
		severity              SeverityCounts
	}
	var results []row
	qrows, err := q.Query(ctx, fmt.Sprintf(`
		WITH inventory AS (
			SELECT da.device_id, da.name, %s AS identifier, da.version,
			       CASE WHEN d.os ILIKE '%%windows%%' THEN 'windows'
			            WHEN d.os ILIKE '%%macos%%' THEN 'macos'
			            ELSE 'unknown' END AS platform
			FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE d.tenant_id = $1::uuid
			  AND (NULLIF($8::text, '') IS NULL OR da.device_id = NULLIF($8::text, '')::uuid)
		), page_products AS (
			SELECT identifier, platform FROM unnest($2::text[], $3::text[]) AS t(identifier, platform)
		), obs AS (
			SELECT i.device_id, i.name, i.identifier, i.platform,
			       array_agg(DISTINCT COALESCE(i.version, '') COLLATE "C"
			                 ORDER BY COALESCE(i.version, '') COLLATE "C") AS versions
			FROM inventory i
			JOIN page_products pp ON pp.identifier = i.identifier AND pp.platform = i.platform
			GROUP BY i.device_id, i.name, i.identifier, i.platform
		), classified AS (
			SELECT o.device_id, o.name, o.identifier, o.platform,
			       EXISTS (SELECT 1 FROM unnest($4::text[], $6::text[]) AS m(n, p)
			               WHERE m.n = o.name AND m.p = o.platform) AS mapped,
			       COALESCE(EXISTS (SELECT 1 FROM unnest($5::text[], $7::text[]) AS m(n, p)
			               WHERE m.n = o.name AND m.p = o.platform)
			        OR q.device_id IS NOT NULL
			        OR a.device_id IS NULL
			        OR a.app_versions::text[] <> o.versions::text[], true) AS not_current,
			       a.last_matched_at
			FROM obs o
			LEFT JOIN cve_match_assessments a ON a.device_id = o.device_id AND a.app_name = o.name
			LEFT JOIN cve_match_queue q
			       ON q.kind = 'observation' AND q.device_id = o.device_id AND q.app_name = o.name
		), findings AS (
			SELECT c.identifier, c.platform, count(DISTINCT f.cve_id)::int AS finding_count,
			       count(DISTINCT f.cve_id) FILTER (WHERE lower(f.severity) = 'critical')::int AS sev_critical,
			       count(DISTINCT f.cve_id) FILTER (WHERE lower(f.severity) = 'high')::int AS sev_high,
			       count(DISTINCT f.cve_id) FILTER (WHERE lower(f.severity) = 'medium')::int AS sev_medium,
			       count(DISTINCT f.cve_id) FILTER (WHERE lower(f.severity) = 'low')::int AS sev_low,
			       count(DISTINCT f.cve_id) FILTER (WHERE f.severity IS NULL
			           OR lower(f.severity) NOT IN ('critical', 'high', 'medium', 'low'))::int AS sev_unrated,
			       count(DISTINCT f.cve_id) FILTER (WHERE f.match_confidence = 'version_unverified')::int AS unverified
			FROM classified c
			JOIN device_cve_findings f ON f.device_id = c.device_id AND f.app_name = c.name
			WHERE c.mapped
			GROUP BY c.identifier, c.platform
		)
		SELECT c.identifier, c.platform,
		       bool_or(c.mapped) AS any_mapped,
		       bool_or(c.mapped AND c.not_current) AS any_pending,
		       min(c.last_matched_at) FILTER (WHERE c.mapped AND NOT c.not_current) AS last_matched_at,
		       COALESCE(f.finding_count, 0) AS finding_count,
		       COALESCE(f.sev_critical, 0), COALESCE(f.sev_high, 0), COALESCE(f.sev_medium, 0),
		       COALESCE(f.sev_low, 0), COALESCE(f.sev_unrated, 0), COALESCE(f.unverified, 0)
		FROM classified c
		LEFT JOIN findings f ON f.identifier = c.identifier AND f.platform = c.platform
		GROUP BY c.identifier, c.platform, f.finding_count, f.sev_critical, f.sev_high, f.sev_medium,
		         f.sev_low, f.sev_unrated, f.unverified
	`, identExpr), tenantID, identifiers, platforms, mappedNames, mappingPendingNames, mappedPlatforms, pendingPlatforms, deviceID)
	if err != nil {
		return nil, fmt.Errorf("assess estate products: %w", err)
	}
	for qrows.Next() {
		var r row
		if err := qrows.Scan(&r.identifier, &r.platform, &r.anyMapped, &r.anyPending, &r.lastMatchedAt, &r.findingCount,
			&r.severity.Critical, &r.severity.High, &r.severity.Medium, &r.severity.Low,
			&r.severity.Unrated, &r.severity.VersionUnverified); err != nil {
			qrows.Close()
			return nil, fmt.Errorf("scan estate product assessment: %w", err)
		}
		results = append(results, r)
	}
	qrows.Close()
	if err := qrows.Err(); err != nil {
		return nil, fmt.Errorf("iterate estate product assessments: %w", err)
	}

	ix := newMappingIndex(mappings)
	for _, r := range results {
		k := EstateProductKey{Identifier: r.identifier, Platform: r.platform}
		a := EstateAssessment{}
		switch {
		case !r.anyMapped:
			a.State = StateNotAssessed
			a.Reason = out[k].Reason
		case r.anyPending:
			a.State = StatePending
			n := r.findingCount
			a.FindingCount = &n
			a.Severity = r.severity
		default:
			a.State = StateAssessed
			a.LastMatchedAt = r.lastMatchedAt
			n := r.findingCount
			a.FindingCount = &n
			a.Severity = r.severity
		}
		if a.State != StateNotAssessed {
			var covering []cvematch.CPEMapping
			for _, n := range keyNames[k] {
				covering = append(covering, cvematch.FilterMappingsForPlatform(ix.For(n), k.Platform)...)
			}
			if a.MappingBasis = mappingBasis(covering); a.MappingBasis == "" {
				a.MappingBasis = cvematch.MappingBasisCurated
			}
		}
		out[k] = a
	}
	return out, nil
}
