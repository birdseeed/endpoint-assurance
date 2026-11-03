package lifecycle

// PAT-2150 (child of PAT-2146): version sprawl per product. For each product
// installed anywhere in the tenant's estate: how many distinct versions are
// live, the oldest and newest of them, the latest the vendor has released
// (where Patched holds a trusted source for it), and how many devices are
// more than one major version behind the newest version live in the
// estate. The CVE count shown against the oldest live version is only ever
// evidence Patched already holds (a matched finding on a device running that
// version) -- never a guess, and never zero when there is simply no mapping
// to assess it by.
//
// Scope is applications only (ReportIdentityKinds, the same boundary the
// PAT-2147 unsupported-software report uses): operating systems are not a
// "product" for sprawl purposes and are left out entirely.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"patched.im/api/internal/catalogmatch"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/deviceretirement"
	"patched.im/api/internal/softwaregov"
)

// Latest-released sources this report can cite. Every product row that
// carries a latest_released value names exactly one of these; a row with no
// trusted source reads latest_released: null, never the newest version seen
// on the estate.
//
// A source only answers while it can be stood behind (PAT-2509): endoflife.date
// within CacheTTL, the catalogue within CatalogueMaxAge, and neither once the
// estate is running something newer than it (referenceHoldsAgainstEstate).
const (
	// SourceCuratedCatalogue is app_catalog_entries (PAT-472/PAT-1728): a
	// staff-curated "known-good latest version" per product. An entry is
	// matched to a product by an exact product name, never by signer alone and
	// never by a name that only contains the other: the display name must
	// equal the entry's name (case-insensitive, trimmed) and, where the entry
	// has a verified signer, the Team ID must agree too (the rule is
	// catalogmatch.ExactProductMatches, which also excludes helper apps).
	// The entry must also have been verified inside
	// CatalogueMaxAge. It applies uniformly across identity kinds, so a
	// Homebrew formula or cask whose reported name matches a catalogue entry is
	// covered by it too -- Patched holds no separate "latest available
	// Homebrew version" feed (PAT-2013 is inventory evidence only: what is
	// installed, never what the tap currently offers), so the catalogue is the
	// one trusted source a Homebrew product can resolve through today.
	SourceCuratedCatalogue = "curated_catalogue"

	// SourceVendorFeed is reserved for a per-vendor release feed. No such
	// feed exists in this codebase yet, so this source is never produced;
	// it is named here so a future feed has a slot to report through
	// without a client-visible shape change.
	SourceVendorFeed = "vendor_feed"
)

// SourceLabelCuratedCatalogue is the plain wording a person reads in place of
// the machine name SourceCuratedCatalogue, which stays on the wire for
// compatibility but is not for display.
const SourceLabelCuratedCatalogue = "Patched reference list"

// CatalogueMaxAge is how old a catalogue entry's verified_at may be before it
// stops being a reference. It is the same window the endoflife.date source
// gets (CacheTTL): a figure is only shown while the source it came from was
// checked inside the last week. Nothing refreshes app_catalog_entries today
// (migration 0030 describes the sync worker that was never built), so until
// something does, no catalogue row can clear this window and the catalogue
// source yields nothing, which is the point: a snapshot that is months old is
// not "the latest released".
const CatalogueMaxAge = CacheTTL

// SprawlMajorVersionRule documents the one version-comparison rule the
// report applies everywhere it needs a "version": distinct version counting,
// the oldest and newest live version, and the devices-behind figure. It is
// deliberately the same rule PAT-2147's application lifecycle mappings
// already use (lifecycle.RuleMajor / CycleKey), so this report and the
// unsupported software report never silently disagree about what a
// product's major version is.
const SprawlMajorVersionRule = "A version's major is the leading run of digits before the first separator " +
	"('.', '-', '_', '+' or space), optionally prefixed \"v\": \"154.0.8037.58\" -> 154, \"8.0.402.6\" -> 8, " +
	"\"v3.12.4\" -> 3. A version that does not start that way, or is empty (a Homebrew HEAD build, \"latest\", or " +
	"no version reported), has no major: it is not a comparable point on a version line, so it is excluded from " +
	"the distinct-version count and can never be reported as the oldest or the newest, and its device is counted " +
	"as not comparable rather than behind or current. \"More than one major version behind\" itself compares a " +
	"device's major against the newest live major version of the same product across the estate -- not the " +
	"vendor's latest release, which is a separate, independently sourced figure."

// SprawlStatement is the report's standing caveat.
const SprawlStatement = "A count of the distinct software versions your devices reported, per product, and how " +
	"far apart they are. It is not a vulnerability assessment or a compliance position. The CVE count on a " +
	"product's oldest live version is only ever a finding Patched has already matched; where Patched holds no " +
	"CVE mapping for the product it reads not assessed, never zero. The vendor's latest release is shown only " +
	"where Patched holds a trusted source for it that was checked recently, and never when a version your " +
	"devices already run is newer than it. It is never the newest version merely seen on the estate."

// SprawlDefinition names the one saved version-sprawl report definition.
type SprawlDefinition struct {
	ID                     string   `json:"id"`
	Version                int      `json:"version"`
	Title                  string   `json:"title"`
	StaleAfterDays         int      `json:"stale_after_days"`
	LifecycleCacheTTLDays  int      `json:"lifecycle_cache_ttl_days"`
	CatalogueMaxAgeDays    int      `json:"catalogue_max_age_days"`
	MajorVersionRule       string   `json:"major_version_rule"`
	LatestSourcePrecedence []string `json:"latest_source_precedence"`
}

// VersionSprawlDefinition is the one saved definition of this report.
//
// Version 2 (PAT-2509): the latest-released reference follows three rules the
// first version did not. A catalogue entry matches on product identity,
// never on signer alone and needs an exact product name, a catalogue entry
// older than CatalogueMaxAge yields nothing, and a reference lower than a
// version live on the estate is withheld.
var VersionSprawlDefinition = SprawlDefinition{
	ID: "sam.version-sprawl", Version: 2, Title: "Version sprawl",
	StaleAfterDays:        int(softwaregov.StaleAfter / (24 * time.Hour)),
	LifecycleCacheTTLDays: int(CacheTTL / (24 * time.Hour)),
	CatalogueMaxAgeDays:   int(CatalogueMaxAge / (24 * time.Hour)),
	MajorVersionRule:      SprawlMajorVersionRule,
	// Preference order when more than one trusted source could answer for
	// the same product: a staff-published endoflife.date mapping (reviewed,
	// refreshed daily, discarded once older than CacheTTL) before the curated
	// catalogue (PAT-472's known-good snapshot, discarded once its entry is
	// older than CatalogueMaxAge). A vendor feed would slot in ahead of the
	// catalogue once one exists; today it never produces a value. The first
	// source to answer is the one used: if the estate then contradicts it, the
	// row reads null rather than falling through to a source that disagrees.
	LatestSourcePrecedence: []string{SourceName, SourceCuratedCatalogue, SourceVendorFeed},
}

// SprawlSource is the source of a row's latest_released value. Name, Slug and
// URL are the machine fields every client already reads (unchanged). Label is
// the plain display wording a person reads in place of Name, and CheckedAt is
// when the source was last refreshed (the endoflife.date fetch time, or the
// catalogue entry's verified_at), so a reader can see how old the figure is.
type SprawlSource struct {
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	URL       string     `json:"url"`
	Label     string     `json:"label"`
	CheckedAt *time.Time `json:"checked_at"`
}

// SprawlVersion is one live version of a product and how many devices run
// it.
type SprawlVersion struct {
	Version          string `json:"version"`
	DeviceCount      int    `json:"device_count"`
	StaleDeviceCount int    `json:"stale_device_count"`
}

// SprawlProduct is one product's version sprawl across the estate.
type SprawlProduct struct {
	ProductKey                    string          `json:"product_key"`
	Name                          string          `json:"name"`
	Platform                      string          `json:"platform"`
	DistinctVersions              int             `json:"distinct_versions"`
	OldestVersion                 string          `json:"oldest_version"`
	NewestVersion                 string          `json:"newest_version"`
	LatestReleased                *string         `json:"latest_released"`
	LatestReleasedSource          *SprawlSource   `json:"latest_released_source"`
	DevicesMoreThanOneMajorBehind int             `json:"devices_more_than_one_major_behind"`
	DevicesNotComparable          int             `json:"devices_not_comparable"`
	CVECountOnOldest              *int            `json:"cve_count_on_oldest_version"`
	CVENotAssessed                bool            `json:"cve_not_assessed_on_oldest_version"`
	DeviceCount                   int             `json:"device_count"`
	StaleDeviceCount              int             `json:"stale_device_count"`
	Versions                      []SprawlVersion `json:"versions"`
}

// SprawlBasis states what the version sprawl report rests on.
type SprawlBasis struct {
	GeneratedAt            time.Time    `json:"generated_at"`
	DevicesTotal           int          `json:"devices_total"`
	DevicesAssessed        int          `json:"devices_assessed"`
	DevicesStale           int          `json:"devices_stale"`
	StaleAfterDays         int          `json:"stale_after_days"`
	RetiredDevicesExcluded bool         `json:"retired_devices_excluded"`
	DevicesRetired         int          `json:"devices_retired"`
	NotCounted             []NotCounted `json:"not_counted"`
	Complete               bool         `json:"complete"`
	Statement              string       `json:"statement"`
	Notes                  []string     `json:"notes"`
}

// SprawlReport is one tenant's version sprawl report.
type SprawlReport struct {
	Definition  SprawlDefinition `json:"definition"`
	GeneratedAt time.Time        `json:"generated_at"`
	Basis       SprawlBasis      `json:"basis"`
	Products    []SprawlProduct  `json:"-"`
}

// catalogueEntry is one app_catalog_entries row as this report reads it.
type catalogueEntry struct {
	Platform, Name, VerifiedSigner, LatestVersion string
	VerifiedAt                                    time.Time
}

func loadCatalogueEntries(ctx context.Context, db DB) ([]catalogueEntry, error) {
	// label is UNIQUE, so this is a total order: the same table always reads
	// back the same way, whatever order Postgres would otherwise return rows in.
	rows, err := db.Query(ctx, `
		SELECT platform, name, COALESCE(verified_signer, ''), latest_version, verified_at
		FROM app_catalog_entries
		ORDER BY platform, lower(name), label`)
	if err != nil {
		return nil, fmt.Errorf("load app catalogue entries: %w", err)
	}
	defer rows.Close()
	var out []catalogueEntry
	for rows.Next() {
		var e catalogueEntry
		if err := rows.Scan(&e.Platform, &e.Name, &e.VerifiedSigner, &e.LatestVersion, &e.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func loadCPEMappings(ctx context.Context, db DB) ([]cvematch.CPEMapping, error) {
	rows, err := db.Query(ctx, `
		SELECT match_name, cpe_vendor, cpe_product, platform, review_state
		FROM app_cpe_mappings WHERE source_type = 'app_name' AND review_state IN ('curated', 'auto')`)
	if err != nil {
		return nil, fmt.Errorf("load cpe mappings: %w", err)
	}
	defer rows.Close()
	var out []cvematch.CPEMapping
	for rows.Next() {
		var m cvematch.CPEMapping
		if err := rows.Scan(&m.MatchName, &m.CPEVendor, &m.CPEProduct, &m.Platform, &m.ReviewState); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func loadHomebrewCPEMappings(ctx context.Context, db DB) ([]cvematch.HomebrewMapping, error) {
	rows, err := db.Query(ctx, `
		SELECT source_type, match_name, cpe_vendor, cpe_product, review_state
		FROM app_cpe_mappings WHERE source_type IN ('homebrew_formula', 'homebrew_cask')`)
	if err != nil {
		return nil, fmt.Errorf("load homebrew cpe mappings: %w", err)
	}
	defer rows.Close()
	var out []cvematch.HomebrewMapping
	for rows.Next() {
		var m cvematch.HomebrewMapping
		if err := rows.Scan(&m.SourceType, &m.Name, &m.CPEVendor, &m.CPEProduct, &m.ReviewState); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// findingKey identifies one device's matched CVEs for one product version,
// exactly as device_cve_findings records it.
type findingKey struct{ DeviceID, AppName, Version string }

// loadFindingCVEs loads every CVE finding for the tenant's devices, indexed
// by (device, app name, version) -- the same evidence
// GET /v1/portal/reports/software/unsupported's Cyber Essentials block and
// every other findings read model draw from. It is the whole tenant's
// findings in one query rather than one query per product row.
func loadFindingCVEs(ctx context.Context, db DB, tenantID string) (map[findingKey]map[string]bool, error) {
	rows, err := db.Query(ctx, `
		SELECT f.device_id::text, f.app_name, f.app_version, f.cve_id
		FROM device_cve_findings f
		JOIN devices d ON d.id = f.device_id
		WHERE d.tenant_id = $1::uuid`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load device cve findings: %w", err)
	}
	defer rows.Close()
	out := map[findingKey]map[string]bool{}
	for rows.Next() {
		var k findingKey
		var cve string
		if err := rows.Scan(&k.DeviceID, &k.AppName, &k.Version, &cve); err != nil {
			return nil, err
		}
		set := out[k]
		if set == nil {
			set = map[string]bool{}
			out[k] = set
		}
		set[cve] = true
	}
	return out, rows.Err()
}

// majorOf extracts a version's major under SprawlMajorVersionRule, reusing
// the same regex PAT-2147's "major" lifecycle rule already applies
// (CycleKey / RuleMajor), so the two reports agree on what a major version
// is. ok is false when the version does not parse, never a guessed 0.
func majorOf(version string) (int, bool) {
	key, ok := CycleKey(Rule{Kind: RuleMajor}, version)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(key)
	if err != nil {
		return 0, false
	}
	return n, true
}

// lifecycleLatest returns the trusted "latest released" version from a
// staff-published endoflife.date mapping: the latest_version of whichever
// cycle is newest, provided the fetch is not older than CacheTTL. "Newest"
// is decided by release date where the source gives one (the normal case);
// among cycles with no release date, or a tie, the numerically greater
// latest_version wins (cvematch.CompareVersions), never document order.
// Stale or never-fetched data never produces a value here -- it is simply
// not this row's source, and the caller falls through to the next one.
func lifecycleLatest(ref *MappingRef, prod *Product, now time.Time) (string, SprawlSource) {
	if ref == nil || prod == nil || prod.FetchedAt == nil {
		return "", SprawlSource{}
	}
	if now.Sub(prod.FetchedAt.UTC()) > CacheTTL {
		return "", SprawlSource{}
	}
	type candidate struct {
		version string
		release *time.Time
	}
	var candidates []candidate
	for _, c := range prod.Cycles {
		if v := strings.TrimSpace(c.LatestVersion); v != "" {
			candidates = append(candidates, candidate{version: v, release: c.ReleaseDate})
		}
	}
	if len(candidates) == 0 {
		return "", SprawlSource{}
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if (a.release == nil) != (b.release == nil) {
			return a.release != nil // a dated cycle outranks an undated one
		}
		if a.release != nil && !a.release.Equal(*b.release) {
			return a.release.After(*b.release)
		}
		return cvematch.CompareVersions(a.version, b.version) > 0
	})
	url := prod.HTMLURL
	if url == "" {
		url = "https://endoflife.date/" + ref.Slug
	}
	checked := prod.FetchedAt.UTC()
	return candidates[0].version, SprawlSource{
		Name: SourceName, Slug: ref.Slug, URL: url, Label: SourceName, CheckedAt: &checked,
	}
}

// catalogueLatest returns the trusted "latest released" version from the
// curated catalogue (app_catalog_entries) for one product, or false when the
// catalogue cannot answer for it.
//
// A reference needs an exact product name (PAT-2509). The product's display
// name must equal the entry's name, ignoring case and surrounding spaces, and
// where the entry has a verified signer the product's Team ID must be that
// signer too. A name that merely contains another is not the same product
// ("Microsoft Teams classic" is not "Microsoft Teams" and has its own version
// line; "zoom.us" against a "Zoom" entry is a guess), and a vendor's Team ID
// signs many products, so a signer alone is never enough. "Not known" is the
// answer to a partial match. The rule is catalogmatch.ExactProductMatches,
// which also supplies the signer check and the helper and sub-app exclusion. It
// is deliberately stricter than catalogmatch.ProductMatches, the substring
// rule the staff tenant apps view uses.
//
// If the entries that match disagree on the version, the product could be any
// of them and the catalogue does not choose, so the result never depends on
// the order of entries.
//
// The matching entry must have been verified within CatalogueMaxAge.
func catalogueLatest(entries []catalogueEntry, k identityKey, name string, now time.Time) (string, SprawlSource, bool) {
	plat := "macOS"
	if k.Platform == "windows" {
		plat = "Windows"
	}
	teamID := ""
	if k.Kind == "macos_bundle_team" {
		teamID = k.Companion
	}
	var matched []catalogueEntry
	for _, e := range entries {
		if e.Platform != plat {
			continue
		}
		var signer *string
		if e.VerifiedSigner != "" {
			s := e.VerifiedSigner
			signer = &s
		}
		if !catalogmatch.ExactProductMatches(k.Value, name, teamID, e.Name, signer) {
			continue
		}
		matched = append(matched, e)
	}
	if len(matched) == 0 {
		return "", SprawlSource{}, false
	}
	best := matched[0]
	for _, e := range matched[1:] {
		if e.LatestVersion != best.LatestVersion {
			return "", SprawlSource{}, false
		}
		if e.VerifiedAt.After(best.VerifiedAt) {
			best = e
		}
	}
	if best.VerifiedAt.IsZero() || now.Sub(best.VerifiedAt.UTC()) > CatalogueMaxAge {
		return "", SprawlSource{}, false
	}
	checked := best.VerifiedAt.UTC()
	return best.LatestVersion, SprawlSource{
		Name: SourceCuratedCatalogue, Label: SourceLabelCuratedCatalogue, CheckedAt: &checked,
	}, true
}

// referenceHoldsAgainstEstate reports whether a reference version may be
// shown beside the versions the estate is running. A reference lower than the
// newest version live on the estate is stale by evidence, whatever its source
// claims, so it is withheld; so is one that cannot be ordered against it with
// certainty (cvematch.CompareVersionsStrict), because guessing an order is how
// a stale figure gets shown as current. With no comparable live version there
// is nothing to contradict it.
func referenceHoldsAgainstEstate(reference, newestLive string) bool {
	if newestLive == "" {
		return true
	}
	c, ok := cvematch.CompareVersionsStrict(reference, newestLive)
	return ok && c >= 0
}

type sprawlInstall struct{ DeviceID, Fingerprint, Name, Version string }

type sprawlGroup struct {
	key      identityKey
	installs []sprawlInstall
	names    map[string]int
}

// BuildVersionSprawl computes the version-sprawl report (PAT-2150, child of
// PAT-2146) for one tenant. tenantID must come from an authenticated
// identity; every query is scoped to it. Scope is applications only
// (ReportIdentityKinds, the same boundary the unsupported-software report
// uses): operating systems are not a "product" for sprawl purposes.
func BuildVersionSprawl(ctx context.Context, db DB, tenantID string, now time.Time) (SprawlReport, error) {
	now = now.UTC()
	rep := SprawlReport{Definition: VersionSprawlDefinition, GeneratedAt: now}
	staleCut := now.Add(-softwaregov.StaleAfter)

	total, err := countInstallations(ctx, db, tenantID)
	if err != nil {
		return rep, err
	}
	if total > MaxReportRows {
		return rep, ErrEstateTooLarge
	}

	devices, _, unrecognised, retired, err := loadDeviceFacts(ctx, db, tenantID, staleCut)
	if err != nil {
		return rep, err
	}

	irows, err := db.Query(ctx, `
		SELECT si.device_id::text, si.platform, si.identity_kind, si.identity_value_normalized,
		       si.companion_value_normalized, si.identity_fingerprint, si.current_name,
		       COALESCE(si.current_version, '')
		FROM software_installations si
		WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL AND si.identity_kind = ANY($2)
		ORDER BY si.device_id, si.identity_fingerprint`, tenantID, ReportIdentityKinds)
	if err != nil {
		return rep, fmt.Errorf("load installations: %w", err)
	}
	groups := map[identityKey]*sprawlGroup{}
	var order []identityKey
	for irows.Next() {
		var deviceID, platform, kind, value, companion, fp, name, version string
		if err := irows.Scan(&deviceID, &platform, &kind, &value, &companion, &fp, &name, &version); err != nil {
			irows.Close()
			return rep, fmt.Errorf("scan installation: %w", err)
		}
		if devices[deviceID] == nil {
			continue // a retired or unrecognised-platform device, counted in basis
		}
		k := identityKey{Platform: platform, Kind: kind, Value: value, Companion: companion}
		g := groups[k]
		if g == nil {
			g = &sprawlGroup{key: k, names: map[string]int{}}
			groups[k] = g
			order = append(order, k)
		}
		g.installs = append(g.installs, sprawlInstall{DeviceID: deviceID, Fingerprint: fp, Name: name, Version: version})
		g.names[name]++
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return rep, err
	}

	var tooling, taps int
	if err := db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE si.identity_kind <> 'homebrew_tap')::int,
		       count(*) FILTER (WHERE si.identity_kind = 'homebrew_tap')::int
		FROM software_installations si
		JOIN devices d ON d.id = si.device_id AND d.tenant_id = si.tenant_id
		WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL AND NOT (si.identity_kind = ANY($2))
		  AND NOT (`+deviceretirement.RetiredSQL("d")+`)`,
		tenantID, ReportIdentityKinds).Scan(&tooling, &taps); err != nil {
		return rep, fmt.Errorf("count excluded installations: %w", err)
	}

	mappings, slugs, err := loadPublished(ctx, db)
	if err != nil {
		return rep, err
	}
	lcProducts, err := LoadProducts(ctx, db, slugs)
	if err != nil {
		return rep, err
	}
	lookupLifecycle := func(k identityKey) (*MappingRef, *Product) {
		pm, ok := mappings[k]
		if !ok {
			return nil, nil
		}
		ref := pm.Ref
		return &ref, lcProducts[ref.Slug]
	}
	catalogue, err := loadCatalogueEntries(ctx, db)
	if err != nil {
		return rep, err
	}
	cpeMappings, err := loadCPEMappings(ctx, db)
	if err != nil {
		return rep, err
	}
	homebrewMappings, err := loadHomebrewCPEMappings(ctx, db)
	if err != nil {
		return rep, err
	}
	findingIndex, err := loadFindingCVEs(ctx, db, tenantID)
	if err != nil {
		return rep, err
	}

	for _, k := range order {
		g := groups[k]
		row := buildSprawlProduct(now, k, g, devices, lookupLifecycle, catalogue, cpeMappings, homebrewMappings, findingIndex)
		rep.Products = append(rep.Products, row)
	}

	sort.SliceStable(rep.Products, func(i, j int) bool {
		a, b := rep.Products[i], rep.Products[j]
		if a.DistinctVersions != b.DistinctVersions {
			return a.DistinctVersions > b.DistinctVersions
		}
		if a.DevicesMoreThanOneMajorBehind != b.DevicesMoreThanOneMajorBehind {
			return a.DevicesMoreThanOneMajorBehind > b.DevicesMoreThanOneMajorBehind
		}
		if !strings.EqualFold(a.Name, b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return a.ProductKey < b.ProductKey
	})

	basis := SprawlBasis{
		GeneratedAt: now, StaleAfterDays: int(softwaregov.StaleAfter / (24 * time.Hour)),
		DevicesTotal:           len(devices) + unrecognised + retired,
		RetiredDevicesExcluded: true, DevicesRetired: retired,
		Statement: SprawlStatement,
		Notes: []string{
			"Devices your organisation has retired are left out of every figure and listed here as not counted.",
			SprawlMajorVersionRule,
			"The CVE count on a product's oldest live version is shown only where Patched already holds a CVE mapping for that product; otherwise it reads not assessed, never zero.",
			fmt.Sprintf("The vendor's latest release is left blank when its source was not checked recently (endoflife.date within %d days, the Patched reference list within %d days) or when a version running on your devices is newer than it, rather than showing a figure that may be out of date.",
				int(CacheTTL/(24*time.Hour)), int(CatalogueMaxAge/(24*time.Hour))),
		},
	}
	for _, d := range devices {
		basis.DevicesAssessed++
		if d.Stale {
			basis.DevicesStale++
		}
	}
	basis.NotCounted = []NotCounted{
		{Reason: "retired_devices", Description: "devices your organisation has retired", Count: retired},
		{Reason: "unrecognised_platform", Description: "devices reporting an operating system other than macOS or Windows", Count: unrecognised},
		{Reason: "developer_tooling", Description: "IDE extensions, language packages, local models and MCP servers are not assessed by this report", Count: tooling},
		{Reason: "homebrew_taps", Description: "Homebrew taps are package sources, not installed software", Count: taps},
	}
	basis.Complete = basis.DevicesAssessed > 0 && basis.DevicesStale == 0 && unrecognised == 0
	rep.Basis = basis
	return rep, nil
}

func buildSprawlProduct(
	now time.Time, k identityKey, g *sprawlGroup, devices map[string]*deviceFacts,
	lookupLifecycle func(identityKey) (*MappingRef, *Product),
	catalogue []catalogueEntry, cpeMappings []cvematch.CPEMapping, homebrewMappings []cvematch.HomebrewMapping,
	findingIndex map[findingKey]map[string]bool,
) SprawlProduct {
	bestName, bestN := "", -1
	for n, c := range g.names {
		if c > bestN || (c == bestN && n < bestName) {
			bestName, bestN = n, c
		}
	}
	fingerprint := ""
	if len(g.installs) > 0 {
		fingerprint = g.installs[0].Fingerprint
	}

	// Distinct versions, oldest and newest are computed only over versions
	// that parse under SprawlMajorVersionRule: a version too irregular to
	// order (empty, "latest", a Homebrew HEAD build) is not a comparable
	// point on a version line, so it is never "the oldest" or "the newest"
	// by construction. Its device is still counted in DeviceCount and in
	// DevicesNotComparable below -- the version itself just does not appear
	// in the estate's version list. This keeps a single documented
	// comparability rule for every figure the report derives from it.
	versionDevices := map[string]map[string]bool{}
	deviceVersion := map[string]string{}
	for _, in := range g.installs {
		deviceVersion[in.DeviceID] = in.Version
		if _, ok := majorOf(in.Version); !ok {
			continue
		}
		set := versionDevices[in.Version]
		if set == nil {
			set = map[string]bool{}
			versionDevices[in.Version] = set
		}
		set[in.DeviceID] = true
	}
	versions := make([]string, 0, len(versionDevices))
	for v := range versionDevices {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return cvematch.CompareVersions(versions[i], versions[j]) < 0 })

	row := SprawlProduct{
		ProductKey: "app:" + fingerprint, Name: bestName, Platform: k.Platform,
		DistinctVersions: len(versions),
	}
	for _, v := range versions {
		set := versionDevices[v]
		stale := 0
		for d := range set {
			if devices[d] != nil && devices[d].Stale {
				stale++
			}
		}
		row.Versions = append(row.Versions, SprawlVersion{Version: v, DeviceCount: len(set), StaleDeviceCount: stale})
	}
	if len(versions) > 0 {
		row.OldestVersion = versions[0]
		row.NewestVersion = versions[len(versions)-1]
	}
	row.DeviceCount = len(deviceVersion)
	for d := range deviceVersion {
		if devices[d] != nil && devices[d].Stale {
			row.StaleDeviceCount++
		}
	}

	newestMajor, haveNewestMajor := 0, false
	for i := len(versions) - 1; i >= 0; i-- {
		if maj, ok := majorOf(versions[i]); ok {
			newestMajor, haveNewestMajor = maj, true
			break
		}
	}
	for _, v := range deviceVersion {
		maj, ok := majorOf(v)
		switch {
		case !ok || !haveNewestMajor:
			row.DevicesNotComparable++
		case newestMajor-maj >= 2:
			row.DevicesMoreThanOneMajorBehind++
		}
	}

	// The first source to answer is the one used. Its figure is then checked
	// against what the estate is running: if the estate contradicts it, the
	// row reads null. A second source is not consulted to overrule the first.
	ref, prod := lookupLifecycle(k)
	refVersion, refSource := lifecycleLatest(ref, prod, now)
	haveRef := refVersion != ""
	if !haveRef {
		refVersion, refSource, haveRef = catalogueLatest(catalogue, k, bestName, now)
	}
	if haveRef && referenceHoldsAgainstEstate(refVersion, row.NewestVersion) {
		vv, ss := refVersion, refSource
		row.LatestReleased, row.LatestReleasedSource = &vv, &ss
	}

	if row.OldestVersion != "" {
		covered := false
		cves := map[string]bool{}
		if k.Kind == "homebrew_formula" || k.Kind == "homebrew_cask" {
			kind := "formula"
			if k.Kind == "homebrew_cask" {
				kind = "cask"
			}
			pkg := cvematch.HomebrewPackage{Kind: kind, Name: k.Value, Tap: k.Companion}
			if len(cvematch.HomebrewMappingsFor(pkg, homebrewMappings)) > 0 {
				covered = true
			}
			for _, in := range g.installs {
				if in.Version != row.OldestVersion {
					continue
				}
				appName := cvematch.HomebrewDisplayName(kind, in.Name)
				for cve := range findingIndex[findingKey{DeviceID: in.DeviceID, AppName: appName, Version: in.Version}] {
					cves[cve] = true
				}
			}
		} else {
			devPlatform := cvematch.PlatformMacOS
			if k.Platform == "windows" {
				devPlatform = cvematch.PlatformWindows
			}
			platformMappings := cvematch.FilterMappingsForPlatform(cpeMappings, devPlatform)
			for _, in := range g.installs {
				if in.Version != row.OldestVersion {
					continue
				}
				if len(cvematch.MappingsFor(in.Name, platformMappings)) > 0 {
					covered = true
				}
				for cve := range findingIndex[findingKey{DeviceID: in.DeviceID, AppName: in.Name, Version: in.Version}] {
					cves[cve] = true
				}
			}
		}
		if covered {
			n := len(cves)
			row.CVECountOnOldest = &n
		} else {
			row.CVENotAssessed = true
		}
	} else {
		row.CVENotAssessed = true
	}

	return row
}
