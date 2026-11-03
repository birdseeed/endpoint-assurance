package cvepipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"patched.im/api/internal/cpepropose"
	"patched.im/api/internal/cvematch"
)

// Assessment states reported on the portal API (PAT-2024).
const (
	// StateAssessed: a CPE mapping covers the product and the matcher has
	// matched its currently installed versions. finding_count is the number of
	// known CVEs; zero means no known CVEs for that product.
	StateAssessed = "assessed"
	// StatePending: the product is mapped but its current versions have not
	// been matched yet (queued, or awaiting the next match run).
	StatePending = "pending"
	// StateNotAssessed: no CPE mapping covers the product, so no CVE statement
	// can be made. finding_count is null, never zero.
	StateNotAssessed = "not_assessed"
)

// Reasons a product is not_assessed (PAT-2138). Set only with
// StateNotAssessed; finding_count stays null either way.
const (
	// ReasonMappingUnderReview: an automatic CPE mapping proposal for the
	// product is pending or waiting for staff review.
	ReasonMappingUnderReview = "mapping_under_review"
	// ReasonNoMapping: no mapping and no open proposal (never proposed yet,
	// rejected, or no CPE exists for it).
	ReasonNoMapping = "no_mapping"
)

// ProductAssessment is one observed product on one device.
type ProductAssessment struct {
	App           string     `json:"app"`
	Versions      []string   `json:"versions"`
	State         string     `json:"state"`
	LastMatchedAt *time.Time `json:"last_matched_at"`
	// FindingCount is set only when State is assessed. It is a pointer so
	// that pending and not_assessed serialise as null, never as 0. It counts
	// the product's current CVE matches (distinct CVE IDs in
	// device_cve_findings), the same set /v1/portal/findings and
	// apps_with_findings list. A risk-accepted or acknowledged CVE that is
	// still installed is still counted; its disposition is reported by
	// /v1/portal/finding-lifecycle, not by this count.
	FindingCount *int `json:"finding_count"`
	// MappingBasis (PAT-2138) is set whenever the product is mapped: "auto"
	// when only automatically published mappings cover it on this device's
	// platform, "curated" otherwise. An assessed product with basis auto and
	// finding_count 0 means "assessed via automatic mapping, no known CVEs",
	// never an unqualified "no known CVEs".
	MappingBasis string `json:"mapping_basis,omitempty"`
	// Reason (PAT-2138) is set only when State is not_assessed:
	// mapping_under_review or no_mapping.
	Reason string `json:"reason,omitempty"`
}

// DeviceAssessment rolls a device's products up into one state.
//
//   - pending when any mapped product is pending;
//   - otherwise assessed when at least one product is assessed;
//   - otherwise not_assessed (no mapped product at all).
//
// finding_count is the sum over assessed products and is set only when the
// device is assessed. last_matched_at is the OLDEST last_matched_at across
// assessed products, so it is a floor: every assessed product was matched at
// least that recently. not_assessed_products says how much of the device the
// CVE statement does not cover, so an assessed device with zero findings is
// never read as "the whole device has no CVEs".
type DeviceAssessment struct {
	State               string     `json:"state"`
	LastMatchedAt       *time.Time `json:"last_matched_at"`
	FindingCount        *int       `json:"finding_count"`
	AssessedProducts    int        `json:"assessed_products"`
	PendingProducts     int        `json:"pending_products"`
	NotAssessedProducts int        `json:"not_assessed_products"`
	// AutoMappedProducts (PAT-2138): of the assessed and pending products,
	// how many are covered only by automatic mappings.
	AutoMappedProducts int `json:"auto_mapped_products"`
	// UnderReviewProducts (PAT-2138): of the not_assessed products, how many
	// have a mapping proposal waiting.
	UnderReviewProducts int                 `json:"under_review_products"`
	Products            []ProductAssessment `json:"products,omitempty"`
}

// TenantAssessment is the tenant-level summary. The CVE feed and the full
// match are estate-wide jobs, so last_feed_sync_at and last_full_match_at are
// the same for every tenant; they are null until the first run records them.
type TenantAssessment struct {
	LastFeedSyncAt      *time.Time `json:"last_feed_sync_at"`
	LastFullMatchAt     *time.Time `json:"last_full_match_at"`
	QueuedObservations  int        `json:"queued_observations"`
	AssessedProducts    int        `json:"assessed_products"`
	PendingProducts     int        `json:"pending_products"`
	NotAssessedProducts int        `json:"not_assessed_products"`
	// Coverage (PAT-2138) counts distinct products, not device
	// observations: "N of M installed products assessed".
	Coverage Coverage `json:"coverage"`
}

// Coverage is the tenant's CVE coverage over distinct installed products,
// each (platform, normalised name) counted once. AssessedProducts are those
// a CPE mapping covers on their platform (assessed or pending in the
// per-device view); the rest are not_assessed, split into under review and
// not. CoverageRatio is AssessedProducts / InstalledProducts, null when
// nothing is installed.
type Coverage struct {
	InstalledProducts   int      `json:"installed_products"`
	AssessedProducts    int      `json:"assessed_products"`
	AutoMappedProducts  int      `json:"auto_mapped_products"`
	UnderReviewProducts int      `json:"under_review_products"`
	NotAssessedProducts int      `json:"not_assessed_products"`
	CoverageRatio       *float64 `json:"coverage_ratio"`
}

// mappingBasis is the basis of the mappings covering a product: "" when
// none, "auto" when every one is automatic, else "curated".
func mappingBasis(ms []cvematch.CPEMapping) string {
	if len(ms) == 0 {
		return ""
	}
	for _, m := range ms {
		if m.Basis() != cvematch.MappingBasisAuto {
			return cvematch.MappingBasisCurated
		}
	}
	return cvematch.MappingBasisAuto
}

// reviewKey identifies an open proposal: platform + normalised name.
type reviewKey struct{ platform, name string }

// OpenProposalSet is the set OpenProposals returns.
type OpenProposalSet map[reviewKey]bool

// ProductRef names one product for OpenProposals: a device platform
// (cvematch vocabulary) and a display name.
type ProductRef struct{ Platform, Name string }

// OpenProposals returns which of the given products have a pending or
// needs_review CPE mapping proposal (PAT-2138). Only the products the caller
// is about to report are looked up, never every open proposal. A database
// without the 0192 table returns an empty set, checked with to_regclass so
// the query never aborts a caller's transaction.
func OpenProposals(ctx context.Context, q DB, products []ProductRef) (OpenProposalSet, error) {
	out := OpenProposalSet{}
	seen := map[reviewKey]bool{}
	platforms, names := []string{}, []string{}
	for _, p := range products {
		k := reviewKey{p.Platform, cpepropose.NormalizeName(p.Name)}
		if k.platform == "" || k.name == "" || seen[k] {
			continue
		}
		seen[k] = true
		platforms = append(platforms, k.platform)
		names = append(names, k.name)
	}
	if len(names) == 0 {
		return out, nil
	}
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('cpe_mapping_proposals') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, fmt.Errorf("check proposals table: %w", err)
	}
	if !exists {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		SELECT p.platform, p.normalized_name
		FROM cpe_mapping_proposals p
		JOIN unnest($1::text[], $2::text[]) AS w(platform, name)
		  ON p.platform = w.platform AND p.normalized_name = w.name
		WHERE p.state IN ('pending', 'needs_review')`, platforms, names)
	if err != nil {
		return nil, fmt.Errorf("load open proposals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k reviewKey
		if err := rows.Scan(&k.platform, &k.name); err != nil {
			return nil, fmt.Errorf("scan open proposal: %w", err)
		}
		out[k] = true
	}
	return out, rows.Err()
}

// UnderReview reports whether name, on a device of platform (cvematch
// vocabulary), has an open proposal.
func (open OpenProposalSet) UnderReview(platform, name string) bool {
	return open[reviewKey{platform, cpepropose.NormalizeName(name)}]
}

type assessmentRow struct {
	Versions      []string
	LastMatchedAt time.Time
}

// classifyProduct is the single rule that decides a product's state. Pure.
//
// The not_assessed branch is the hard constraint: an unmapped product returns
// a nil FindingCount whatever findings or assessment rows exist, because a
// CVE statement about it has no authority.
func classifyProduct(app string, versions []string, mapped, queued bool, row *assessmentRow, findingCount int) ProductAssessment {
	versions = uniqueSorted(versions)
	p := ProductAssessment{App: app, Versions: versions}
	switch {
	case !mapped:
		p.State = StateNotAssessed
	case queued, row == nil, !equalStrings(uniqueSorted(row.Versions), versions):
		p.State = StatePending
	default:
		p.State = StateAssessed
		at := row.LastMatchedAt
		p.LastMatchedAt = &at
		n := findingCount
		p.FindingCount = &n
	}
	return p
}

// annotateProduct adds PAT-2138's mapping basis (mapped products) or
// not_assessed reason to a classified product.
func annotateProduct(p *ProductAssessment, ix *mappingIndex, open OpenProposalSet, platform string) {
	if p.State == StateNotAssessed {
		p.Reason = ReasonNoMapping
		if open.UnderReview(platform, p.App) {
			p.Reason = ReasonMappingUnderReview
		}
		return
	}
	p.MappingBasis = mappingBasis(cvematch.FilterMappingsForPlatform(ix.For(p.App), platform))
}

func rollUpDevice(products []ProductAssessment) DeviceAssessment {
	d := DeviceAssessment{}
	total := 0
	for _, p := range products {
		switch p.State {
		case StateAssessed:
			d.AssessedProducts++
			total += *p.FindingCount
			if d.LastMatchedAt == nil || p.LastMatchedAt.Before(*d.LastMatchedAt) {
				at := *p.LastMatchedAt
				d.LastMatchedAt = &at
			}
		case StatePending:
			d.PendingProducts++
		default:
			d.NotAssessedProducts++
			if p.Reason == ReasonMappingUnderReview {
				d.UnderReviewProducts++
			}
		}
		if p.State != StateNotAssessed && p.MappingBasis == cvematch.MappingBasisAuto {
			d.AutoMappedProducts++
		}
	}
	switch {
	case d.PendingProducts > 0:
		d.State = StatePending
		d.LastMatchedAt = nil
	case d.AssessedProducts > 0:
		d.State = StateAssessed
		d.FindingCount = &total
	default:
		d.State = StateNotAssessed
	}
	return d
}

// AssessDevices returns the assessment of each listed device that belongs to
// tenantID. Devices of another tenant are silently excluded (the query is
// tenant-scoped, not only device-scoped). includeProducts adds the
// per-product list.
//
// On a database without the PAT-2024 tables (binary ahead of migration 0161)
// it degrades to an empty map, the same "degrade, don't 500" contract the
// portal's other CVE reads follow; callers must then report each device as
// not_assessed, never as clean.
func AssessDevices(ctx context.Context, q DB, tenantID string, deviceIDs []string, includeProducts bool) (map[string]DeviceAssessment, error) {
	out, err := assessDevices(ctx, q, tenantID, deviceIDs, includeProducts)
	if isUndefinedTable(err) {
		return map[string]DeviceAssessment{}, nil
	}
	return out, err
}

func assessDevices(ctx context.Context, q DB, tenantID string, deviceIDs []string, includeProducts bool) (map[string]DeviceAssessment, error) {
	out := map[string]DeviceAssessment{}
	if len(deviceIDs) == 0 {
		return out, nil
	}
	mappings, err := LoadMappings(ctx, q)
	if err != nil {
		return nil, err
	}
	ix := newMappingIndex(mappings)

	pendingMatchNames, err := PendingMappingNames(ctx, q)
	if err != nil {
		return nil, err
	}
	type key struct{ device, app string }
	apps := map[string]map[string][]string{}
	rows, err := q.Query(ctx, `
		SELECT da.device_id::text, da.name, COALESCE(da.version, '')
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1::uuid AND d.id = ANY($2::uuid[])
	`, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("load device products: %w", err)
	}
	for rows.Next() {
		var deviceID, name, version string
		if err := rows.Scan(&deviceID, &name, &version); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan device product: %w", err)
		}
		if apps[deviceID] == nil {
			apps[deviceID] = map[string][]string{}
		}
		apps[deviceID][name] = append(apps[deviceID][name], version)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device products: %w", err)
	}

	assessed := map[key]*assessmentRow{}
	rows, err = q.Query(ctx, `
		SELECT device_id::text, app_name, app_versions, last_matched_at
		FROM cve_match_assessments
		WHERE tenant_id = $1::uuid AND device_id = ANY($2::uuid[])
	`, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("load assessments: %w", err)
	}
	for rows.Next() {
		var k key
		var r assessmentRow
		if err := rows.Scan(&k.device, &k.app, &r.Versions, &r.LastMatchedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan assessment: %w", err)
		}
		assessed[k] = &r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assessments: %w", err)
	}

	queued := map[key]bool{}
	rows, err = q.Query(ctx, `
		SELECT device_id::text, app_name FROM cve_match_queue
		WHERE kind = 'observation' AND tenant_id = $1::uuid AND device_id = ANY($2::uuid[])
	`, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("load queued observations: %w", err)
	}
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.device, &k.app); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan queued observation: %w", err)
		}
		queued[k] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate queued observations: %w", err)
	}

	counts := map[key]int{}
	rows, err = q.Query(ctx, `
		SELECT f.device_id::text, f.app_name, count(DISTINCT f.cve_id)::int
		FROM device_cve_findings f
		JOIN devices d ON d.id = f.device_id
		WHERE d.tenant_id = $1::uuid AND f.device_id = ANY($2::uuid[])
		GROUP BY 1, 2
	`, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("load finding counts: %w", err)
	}
	for rows.Next() {
		var k key
		var n int
		if err := rows.Scan(&k.device, &k.app, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan finding count: %w", err)
		}
		counts[k] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding counts: %w", err)
	}

	// Tenant ownership for every requested device in one query; a device of
	// another tenant is never reported, not even as not_assessed.
	owned := map[string]bool{}
	devicePlatform := map[string]string{}
	rows, err = q.Query(ctx, `SELECT id::text, COALESCE(os, '') FROM devices WHERE tenant_id = $1::uuid AND id = ANY($2::uuid[])`, tenantID, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("check device tenancy: %w", err)
	}
	for rows.Next() {
		var id, os string
		if err := rows.Scan(&id, &os); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan device tenancy: %w", err)
		}
		owned[id] = true
		devicePlatform[id] = cvematch.NormalizeDevicePlatform(os)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device tenancy: %w", err)
	}
	var refs []ProductRef
	for _, deviceID := range deviceIDs {
		if !owned[deviceID] {
			continue
		}
		for name := range apps[deviceID] {
			if !ix.MappedOn(name, devicePlatform[deviceID]) {
				refs = append(refs, ProductRef{devicePlatform[deviceID], name})
			}
		}
	}
	openProposals, err := OpenProposals(ctx, q, refs)
	if err != nil {
		return nil, err
	}

	for _, deviceID := range deviceIDs {
		if !owned[deviceID] {
			continue
		}
		byName := apps[deviceID]
		products := make([]ProductAssessment, 0, len(byName))
		for _, name := range sortedKeys(byName) {
			k := key{deviceID, name}
			// Mapped exactly as the matcher decides it for this device: the
			// word-token rule, then the PAT-2029 platform filter. A product
			// mapped only for another platform is not_assessed here, never
			// assessed with a count the matcher never produced.
			platform := devicePlatform[deviceID]
			mapped := ix.MappedOn(name, platform)
			isQueued := queued[k] || (mapped && CoveredByAny(name, pendingMatchNames))
			p := classifyProduct(name, byName[name], mapped, isQueued, assessed[k], counts[k])
			annotateProduct(&p, ix, openProposals, platform)
			products = append(products, p)
		}
		d := rollUpDevice(products)
		if includeProducts {
			d.Products = products
		}
		out[deviceID] = d
	}
	return out, nil
}

// AssessTenant summarises the tenant's observed products and the estate-wide
// feed and full-match timestamps. Without the PAT-2024 tables it degrades to
// the zero value: no timestamps and nothing counted as assessed.
func AssessTenant(ctx context.Context, q DB, tenantID string) (TenantAssessment, error) {
	t, err := assessTenant(ctx, q, tenantID)
	if isUndefinedTable(err) {
		return TenantAssessment{}, nil
	}
	return t, err
}

func assessTenant(ctx context.Context, q DB, tenantID string) (TenantAssessment, error) {
	var t TenantAssessment
	rows, err := q.Query(ctx, `SELECT run_kind, completed_at FROM cve_match_runs`)
	if err != nil {
		return t, fmt.Errorf("load match runs: %w", err)
	}
	for rows.Next() {
		var kind string
		var at time.Time
		if err := rows.Scan(&kind, &at); err != nil {
			rows.Close()
			return t, fmt.Errorf("scan match run: %w", err)
		}
		at = at.UTC()
		switch kind {
		case "feed_sync":
			t.LastFeedSyncAt = &at
		case "full_match":
			t.LastFullMatchAt = &at
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, fmt.Errorf("iterate match runs: %w", err)
	}
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int FROM cve_match_queue WHERE kind = 'observation' AND tenant_id = $1::uuid
	`, tenantID).Scan(&t.QueuedObservations); err != nil {
		return t, fmt.Errorf("count queued observations: %w", err)
	}

	// Product counts in one aggregate. Only the distinct product names are
	// brought into Go, because "is this name mapped" is the word-token rule
	// of the match engine and must not be re-implemented in SQL.
	// Each (name, device OS) pair is judged with the platform filter the
	// matcher applies, so a product mapped only for Windows is not counted
	// as assessed on a Mac.
	type nameOS struct{ name, os string }
	var names []nameOS
	rows, err = q.Query(ctx, `
		SELECT DISTINCT da.name, COALESCE(d.os, '')
		FROM device_apps da JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return t, fmt.Errorf("list tenant products: %w", err)
	}
	for rows.Next() {
		var n nameOS
		if err := rows.Scan(&n.name, &n.os); err != nil {
			rows.Close()
			return t, fmt.Errorf("scan tenant product: %w", err)
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, fmt.Errorf("iterate tenant products: %w", err)
	}
	mappings, err := LoadMappings(ctx, q)
	if err != nil {
		return t, err
	}
	pendingMatchNames, err := PendingMappingNames(ctx, q)
	if err != nil {
		return t, err
	}
	ix := newMappingIndex(mappings)
	// Non-nil so pgx sends '{}' rather than NULL: "= ANY(NULL)" is NULL, and a
	// NULL predicate would silently drop rows from every FILTER count below.
	mappedNames, mappedOS, pendingNames, pendingOS := []string{}, []string{}, []string{}, []string{}
	for _, n := range names {
		if !ix.MappedOn(n.name, cvematch.NormalizeDevicePlatform(n.os)) {
			continue
		}
		mappedNames, mappedOS = append(mappedNames, n.name), append(mappedOS, n.os)
		if CoveredByAny(n.name, pendingMatchNames) {
			pendingNames, pendingOS = append(pendingNames, n.name), append(pendingOS, n.os)
		}
	}
	// Same rule as classifyProduct: unmapped is not_assessed; mapped and
	// (queued, never matched, versions changed since the match, or covered
	// by a pending mapping job) is pending; otherwise assessed. Versions are
	// compared as sorted distinct sets under the "C" collation, matching the
	// byte order Go's sort.Strings wrote into app_versions.
	if err := q.QueryRow(ctx, `
		WITH obs AS (
			SELECT da.device_id, da.name, COALESCE(d.os, '') AS os,
			       array_agg(DISTINCT COALESCE(da.version, '') COLLATE "C"
			                 ORDER BY COALESCE(da.version, '') COLLATE "C") AS versions
			FROM device_apps da JOIN devices d ON d.id = da.device_id
			WHERE d.tenant_id = $1::uuid
			GROUP BY da.device_id, da.name, COALESCE(d.os, '')
		), mapped_pairs AS (
			SELECT DISTINCT n, os FROM unnest($2::text[], $4::text[]) AS m(n, os)
		), pending_pairs AS (
			SELECT DISTINCT n, os FROM unnest($3::text[], $5::text[]) AS m(n, os)
		), classified AS (
			SELECT EXISTS (SELECT 1 FROM mapped_pairs m WHERE m.n = o.name AND m.os = o.os) AS mapped,
			       COALESCE(EXISTS (SELECT 1 FROM pending_pairs m WHERE m.n = o.name AND m.os = o.os)
			        OR q.device_id IS NOT NULL
			        OR a.device_id IS NULL
			        OR a.app_versions::text[] <> o.versions::text[], true) AS not_current
			FROM obs o
			LEFT JOIN cve_match_assessments a ON a.device_id = o.device_id AND a.app_name = o.name
			LEFT JOIN cve_match_queue q
			       ON q.kind = 'observation' AND q.device_id = o.device_id AND q.app_name = o.name
		)
		SELECT count(*) FILTER (WHERE mapped AND NOT not_current)::int,
		       count(*) FILTER (WHERE mapped AND not_current)::int,
		       count(*) FILTER (WHERE NOT mapped)::int
		FROM classified
	`, tenantID, mappedNames, pendingNames, mappedOS, pendingOS).Scan(&t.AssessedProducts, &t.PendingProducts, &t.NotAssessedProducts); err != nil {
		return t, fmt.Errorf("aggregate tenant assessment: %w", err)
	}
	cov, err := tenantCoverage(ctx, q, tenantID, ix)
	if err != nil {
		return t, err
	}
	t.Coverage = cov
	return t, nil
}

// tenantCoverage counts the tenant's distinct installed products, each
// (platform, normalised name) once, and how many a mapping covers on that
// platform. A device whose OS is not recognised counts under platform "",
// where only "any" mappings apply, exactly as the matcher treats it.
func tenantCoverage(ctx context.Context, q DB, tenantID string, ix *mappingIndex) (Coverage, error) {
	var c Coverage
	rows, err := q.Query(ctx, `
		SELECT DISTINCT da.name, COALESCE(d.os, '')
		FROM device_apps da JOIN devices d ON d.id = da.device_id
		WHERE d.tenant_id = $1::uuid
	`, tenantID)
	if err != nil {
		return c, fmt.Errorf("list tenant products for coverage: %w", err)
	}
	type product struct{ platform, name string }
	seen := map[product]bool{}
	type sample struct{ name, platform string }
	var products []sample
	for rows.Next() {
		var name, os string
		if err := rows.Scan(&name, &os); err != nil {
			rows.Close()
			return c, fmt.Errorf("scan tenant product for coverage: %w", err)
		}
		if isOSPseudoApp(name) {
			continue
		}
		platform := cvematch.NormalizeDevicePlatform(os)
		k := product{platform, cpepropose.NormalizeName(name)}
		if k.name == "" || seen[k] {
			continue
		}
		seen[k] = true
		products = append(products, sample{name, platform})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return c, fmt.Errorf("iterate tenant products for coverage: %w", err)
	}
	var refs []ProductRef
	for _, p := range products {
		if len(cvematch.FilterMappingsForPlatform(ix.For(p.name), p.platform)) == 0 {
			refs = append(refs, ProductRef{p.platform, p.name})
		}
	}
	open, err := OpenProposals(ctx, q, refs)
	if err != nil {
		return c, err
	}
	for _, p := range products {
		c.InstalledProducts++
		ms := cvematch.FilterMappingsForPlatform(ix.For(p.name), p.platform)
		if len(ms) == 0 {
			c.NotAssessedProducts++
			if open.UnderReview(p.platform, p.name) {
				c.UnderReviewProducts++
			}
			continue
		}
		c.AssessedProducts++
		if mappingBasis(ms) == cvematch.MappingBasisAuto {
			c.AutoMappedProducts++
		}
	}
	if c.InstalledProducts > 0 {
		r := float64(c.AssessedProducts) / float64(c.InstalledProducts)
		c.CoverageRatio = &r
	}
	return c, nil
}

// PendingMappingNames lists the match_name values with an outstanding mapping
// publish job (kind = 'mapping' in cve_match_queue): a mapping was
// published or changed but its observations have not all been re-matched
// yet. Exported for report.FetchPortalSoftware's estate-wide assessment
// (PAT-2028), which reuses this instead of re-deriving it.
func PendingMappingNames(ctx context.Context, q DB) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT match_name FROM cve_match_queue WHERE kind = 'mapping'`)
	if err != nil {
		return nil, fmt.Errorf("load pending mapping jobs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan pending mapping job: %w", err)
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out, rows.Err()
}

// CoveredByAny reports whether name is covered by any of matchNames under the
// same fuzzy match rule the CPE matcher itself uses. Exported for the same
// reason as PendingMappingNames.
func CoveredByAny(name string, matchNames []string) bool {
	for _, mn := range matchNames {
		if cvematch.NameMatches(name, mn) {
			return true
		}
	}
	return false
}

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
