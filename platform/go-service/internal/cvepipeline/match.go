// Package cvepipeline is the change-driven half of CVE matching (PAT-2024).
//
// The nightly patched-cve-sync run re-matches every active device against the
// whole local CVE store. This package re-matches only what changed, using the
// same pure engine (internal/cvematch) and the same lifecycle reducer
// (internal/cvelifecycle):
//
//   - ingest delta: the extractor enqueues (device, product) observations whose
//     installed versions changed in a payload, and drains the queue on its
//     polling loop (Drain);
//   - mapping publish: a new, changed or removed app_cpe_mappings row is
//     detected by diffing against cve_mapping_snapshot and expanded into
//     observation jobs for every active device carrying that product;
//   - feed-sync delta: patched-cve-sync records the CPE keys a sync touched
//     (RecordFeedDelta) and re-matches only observations whose mapping
//     resolves to one of them (MatchFeedDelta).
//
// Matching reads the local CVE store only. Nothing here calls NVD.
//
// Absence requires authority: a product with no CPE mapping is never given an
// assessment row, so the read path (assess.go) reports it as not_assessed and
// never as zero findings.
package cvepipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvelifecycle"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/webhook"
)

const (
	// MaxAttempts is how many times one observation is retried before the
	// worker stops claiming it. A stuck row stays in the queue on purpose so
	// the depth and oldest-age metrics, and therefore the backlog alert, keep
	// reporting it.
	MaxAttempts = 5

	// activeDeviceWindow matches the nightly matcher's scope (devices seen in
	// the last 30 days), so both paths agree on which devices are in scope.
	activeDeviceWindow = cvematch.ActiveDeviceWindow

	SourceIngest         = "ingest"
	SourceMappingPublish = "mapping_publish"
	SourceFeedSync       = "feed_sync"
	SourceFullMatch      = "full_match"
)

// QueueCapacity bounds cve_match_queue. Each enqueue statement admits new
// rows only up to the room left under it (see enqueueJobs); it is soft only
// in that two concurrent statements can see the same room. A request refused
// at the cap is counted (patched_cve_match_queue_dropped_total); the product
// then reads as pending until the nightly full match covers it, because its
// assessment no longer matches its installed versions. A var, not a const,
// so tests can exercise the cap without inserting 50,000 rows.
//
// PAT-2030: QueueCapacity is now the global safety bound, and
// TenantQueueCapacity is each tenant's fair share of it.
var QueueCapacity = 50000

// TenantQueueCapacity bounds one tenant's observation rows in
// cve_match_queue (PAT-2030). A tenant that onboards a large estate, or a
// mapping change that fans out across one large tenant, fills only its own
// share: every other tenant still has room under QueueCapacity, and Drain
// takes rows round-robin across tenants, so their changes are matched in the
// next cycle rather than refused or queued behind the backlog. Five tenants
// at their cap together fill the global bound. A request refused at this cap
// behaves exactly like one refused at QueueCapacity: counted as dropped, the
// product reads pending until the nightly full match. Soft in the same way
// as QueueCapacity (two concurrent statements can see the same room). A var
// so tests can lower it.
var TenantQueueCapacity = 10000

// DB is the subset of pgx shared by *pgxpool.Pool, *pgxpool.Conn and pgx.Tx.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// LoadMappings reads every CPE mapping. The table is small and curated.
// platform is loaded alongside so callers can scope a device to only the
// mappings that apply to it (PAT-2029) via cvematch.FilterMappingsForPlatform
// — see matchDevice, the write path that must never apply a
// platform-specific mapping (e.g. Microsoft Word's windows-only CPE) to a
// device of a different platform.
func LoadMappings(ctx context.Context, q DB) ([]cvematch.CPEMapping, error) {
	// PAT-2138: review_state is loaded so an automatic mapping's findings
	// carry mapping_basis auto. Only curated and auto application mappings
	// match; auto_seeded (never written for applications) is a proposal, not
	// a mapping.
	rows, err := q.Query(ctx, `SELECT match_name, cpe_vendor, cpe_product, platform, review_state FROM app_cpe_mappings WHERE source_type = 'app_name' AND review_state IN ('curated', 'auto') ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load cpe mappings: %w", err)
	}
	defer rows.Close()
	var out []cvematch.CPEMapping
	for rows.Next() {
		var m cvematch.CPEMapping
		if err := rows.Scan(&m.MatchName, &m.CPEVendor, &m.CPEProduct, &m.Platform, &m.ReviewState); err != nil {
			return nil, fmt.Errorf("scan cpe mapping: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cpe mappings: %w", err)
	}
	return out, nil
}

// mappingIndex memoises "which mappings cover this display name" so a read or
// match over thousands of observations tokenises each distinct name once.
type mappingIndex struct {
	mappings []cvematch.CPEMapping
	byName   map[string][]cvematch.CPEMapping
}

func newMappingIndex(mappings []cvematch.CPEMapping) *mappingIndex {
	return &mappingIndex{mappings: mappings, byName: map[string][]cvematch.CPEMapping{}}
}

func (ix *mappingIndex) For(name string) []cvematch.CPEMapping {
	if got, ok := ix.byName[name]; ok {
		return got
	}
	got := cvematch.MappingsFor(name, ix.mappings)
	ix.byName[name] = got
	return got
}

func (ix *mappingIndex) Mapped(name string) bool { return len(ix.For(name)) > 0 }

// MappedOn reports whether a mapping covers name on a device of platform
// (cvematch vocabulary), exactly as the matcher filters mappings.
func (ix *mappingIndex) MappedOn(name, platform string) bool {
	return len(cvematch.FilterMappingsForPlatform(ix.For(name), platform)) > 0
}

// feedCache loads CVE entries per CPE key from the local store, once per key
// per drain, through the cpe_patterns GIN index.
//
// A key is cached only after its whole load succeeded. Any query, scan or
// cpe_ranges decode failure returns an error and caches nothing, so a later
// device in the same batch can never see an empty or partial entry list and
// read it as "no CVEs" (which would prune its findings and record a false
// assessed-zero). The caller aborts that device's match and leaves it queued.
type feedCache struct {
	byKey map[string][]cvematch.CVEEntry
	// load is the database read; tests replace it to inject failures.
	load func(ctx context.Context, q DB, keys []string) (map[string][]cvematch.CVEEntry, error)
}

func newFeedCache() *feedCache {
	return &feedCache{byKey: map[string][]cvematch.CVEEntry{}, load: loadFeedEntries}
}

func loadFeedEntries(ctx context.Context, q DB, keys []string) (map[string][]cvematch.CVEEntry, error) {
	want := make(map[string]bool, len(keys))
	loaded := make(map[string][]cvematch.CVEEntry, len(keys))
	for _, k := range keys {
		want[k] = true
		loaded[k] = nil
	}
	rows, err := q.Query(ctx, `
		SELECT cve_id, COALESCE(description, ''), cvss_v3_score::float8, COALESCE(severity, ''),
		       cpe_patterns, cpe_ranges, published_at
		FROM cve_feed_entries
		WHERE cpe_patterns && $1::text[]
	`, keys)
	if err != nil {
		return nil, fmt.Errorf("load cve entries for %d cpe keys: %w", len(keys), err)
	}
	defer rows.Close()
	for rows.Next() {
		var e cvematch.CVEEntry
		var rangesRaw []byte
		var published *time.Time
		if err := rows.Scan(&e.CVEID, &e.Description, &e.Score, &e.Severity, &e.Patterns, &rangesRaw, &published); err != nil {
			return nil, fmt.Errorf("scan cve entry: %w", err)
		}
		if published != nil {
			e.PublishedAt = *published // NULL stays zero: never age-cut
		}
		if len(rangesRaw) > 0 && string(rangesRaw) != "null" {
			if err := json.Unmarshal(rangesRaw, &e.Ranges); err != nil {
				return nil, fmt.Errorf("unmarshal cpe_ranges for %s: %w", e.CVEID, err)
			}
		}
		for _, p := range e.Patterns {
			if want[p] {
				loaded[p] = append(loaded[p], e)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cve entries: %w", err)
	}
	return loaded, nil
}

func (c *feedCache) entries(ctx context.Context, q DB, keys []string) ([]cvematch.CVEEntry, error) {
	var missing []string
	for _, k := range keys {
		if _, ok := c.byKey[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		loaded, err := c.load(ctx, q, missing)
		if err != nil {
			return nil, err
		}
		for _, k := range missing {
			c.byKey[k] = loaded[k]
		}
	}
	seen := map[string]bool{}
	var out []cvematch.CVEEntry
	for _, k := range keys {
		for _, e := range c.byKey[k] {
			if !seen[e.CVEID] {
				seen[e.CVEID] = true
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// newFinding is a device_cve_findings row this match inserted for the first
// time, used for the vulnerability.discovered webhook.
type newFinding struct {
	TenantID, DeviceID, Hostname string
	CVE                          webhook.VulnCVE
}

// matchOutcome is what one device re-match changed.
type matchOutcome struct {
	Observations int
	Findings     int
	Identities   []cvelifecycle.Identity
	New          []newFinding
}

func (o *matchOutcome) add(other matchOutcome) {
	o.Observations += other.Observations
	o.Findings += other.Findings
	o.Identities = append(o.Identities, other.Identities...)
	o.New = append(o.New, other.New...)
}

// matchDevice re-matches the named products on one device inside tx and
// makes device_cve_findings and cve_match_assessments agree with the result
// for exactly those products. Other products on the device, and the OS
// pseudo-app findings owned by the vendor-advisory matcher, are untouched.
//
// Idempotent: running it twice over unchanged inventory and feed writes the
// same findings (first_seen_at preserved by the upsert) and returns no new
// findings the second time. It never writes finding_dispositions or lifecycle
// events itself; the caller hands the touched identities to cvelifecycle,
// whose reducer is what keeps closed and accepted findings from reopening.
func matchDevice(ctx context.Context, tx pgx.Tx, ix *mappingIndex, feed *feedCache,
	deviceID string, names []string, source string) (matchOutcome, error) {
	var out matchOutcome
	// OS pseudo-apps are owned by the vendor-advisory matcher (os_match.go)
	// and the nightly run. This path never matches, upserts, prunes or
	// assesses them.
	names = withoutOSPseudoApps(uniqueSorted(names))
	// PAT-2023: Homebrew packages are queued under their display name
	// ("openssl@3 (Homebrew formula)") and matched by exact mapping in
	// matchDeviceHomebrew. They never go through the application path below.
	names, brewNames := splitHomebrewNames(names)
	if len(names) == 0 && len(brewNames) == 0 {
		return out, nil
	}

	var tenantID, hostname, deviceOS string
	err := tx.QueryRow(ctx, `SELECT tenant_id::text, COALESCE(hostname, ''), COALESCE(os, '') FROM devices WHERE id = $1::uuid`,
		deviceID).Scan(&tenantID, &hostname, &deviceOS)
	if err == pgx.ErrNoRows {
		return out, nil // device deleted; its queue rows went with it
	}
	if err != nil {
		return out, fmt.Errorf("load device %s: %w", deviceID, err)
	}
	// PAT-2029: this device's platform, in app_cpe_mappings.platform's
	// vocabulary. An unrecognised os normalises to "" (PlatformUnknown), so
	// every ix.For(name) lookup below applies only "any" mappings to it,
	// never a guessed platform.
	devicePlatform := cvematch.NormalizeDevicePlatform(deviceOS)

	if len(brewNames) > 0 {
		brew, err := matchDeviceHomebrew(ctx, tx, feed, deviceID, tenantID, hostname, brewNames)
		if err != nil {
			return out, err
		}
		out.add(brew)
	}
	if len(names) == 0 {
		sortIdentities(out.Identities)
		return out, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT name, COALESCE(version, '')
		FROM device_apps
		WHERE device_id = $1::uuid AND name = ANY($2::text[])
		ORDER BY name, version
	`, deviceID, names)
	if err != nil {
		return out, fmt.Errorf("load device apps for %s: %w", deviceID, err)
	}
	var apps []cvematch.ScannedApp
	versions := map[string][]string{}
	for rows.Next() {
		var a cvematch.ScannedApp
		if err := rows.Scan(&a.Name, &a.Version); err != nil {
			rows.Close()
			return out, fmt.Errorf("scan device app: %w", err)
		}
		apps = append(apps, a)
		versions[a.Name] = append(versions[a.Name], a.Version)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate device apps: %w", err)
	}

	var relevant []cvematch.CPEMapping
	seenMapping := map[cvematch.CPEMapping]bool{}
	var keys []string
	seenKey := map[string]bool{}
	for _, name := range names {
		if len(versions[name]) == 0 {
			continue
		}
		// PAT-2029: scope to mappings that apply to this device's platform
		// before indexing by CPE key, so a platform-specific mapping never
		// produces a finding for a device of a different platform.
		for _, m := range cvematch.FilterMappingsForPlatform(ix.For(name), devicePlatform) {
			if !seenMapping[m] {
				seenMapping[m] = true
				relevant = append(relevant, m)
			}
			if k := m.CPEKey(); !seenKey[k] {
				seenKey[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)

	var findings []cvematch.Finding
	if len(keys) > 0 {
		entries, err := feed.entries(ctx, tx, keys)
		if err != nil {
			return out, err
		}
		// PAT-2107: filter by the device's platform, as the nightly full
		// match does, so the two paths agree on every finding.
		findings = cvematch.Match(apps, relevant, entries, devicePlatform)
	}

	bases := cvematch.FindingBases(findings)
	touched := map[string]bool{}
	perApp := map[string]map[string]bool{}
	keepCVE := make([]string, 0, len(findings))
	keepApp := make([]string, 0, len(findings))
	for _, f := range findings {
		var inserted bool
		if err := tx.QueryRow(ctx, `
			INSERT INTO device_cve_findings
				(device_id, cve_id, app_name, app_version,
				 cvss_v3_score, severity, match_confidence, fixed_version, last_seen_at, mapping_basis)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
			ON CONFLICT (device_id, cve_id, app_name) DO UPDATE SET
				app_version      = EXCLUDED.app_version,
				cvss_v3_score    = EXCLUDED.cvss_v3_score,
				severity         = EXCLUDED.severity,
				match_confidence = EXCLUDED.match_confidence,
				fixed_version    = EXCLUDED.fixed_version,
				last_seen_at     = NOW(),
				mapping_basis    = EXCLUDED.mapping_basis
			-- A vendor-confirmed row is stronger evidence than a CPE-range
			-- match and belongs to the vendor-advisory matcher: never
			-- overwrite it from this path.
			WHERE device_cve_findings.match_confidence <> 'version_vendor_confirmed'
			RETURNING (xmax = 0)
		`, deviceID, f.CVEID, f.AppName, f.AppVersion, f.Score, f.Severity, f.MatchConfidence, f.FixedVersion,
			AppFindingBasis(bases[cvematch.FindingKey{CVEID: f.CVEID, AppName: f.AppName}])).Scan(&inserted); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, fmt.Errorf("upsert finding %s/%s on %s: %w", f.CVEID, f.AppName, deviceID, err)
		}
		touched[f.CVEID] = true
		if perApp[f.AppName] == nil {
			perApp[f.AppName] = map[string]bool{}
		}
		if !perApp[f.AppName][f.CVEID] {
			perApp[f.AppName][f.CVEID] = true
			keepCVE = append(keepCVE, f.CVEID)
			keepApp = append(keepApp, f.AppName)
			out.Findings++
		}
		if inserted {
			out.New = append(out.New, newFinding{TenantID: tenantID, DeviceID: deviceID, Hostname: hostname,
				CVE: webhook.VulnCVE{CVEID: f.CVEID, Severity: f.Severity, Score: f.Score, AppName: f.AppName}})
		}
	}

	// Prune findings for the re-matched products that this match no longer
	// produces: a fixed version, a removed app, a withdrawn mapping or a CVE
	// whose ranges no longer cover the version. Lifecycle closure is NOT
	// decided here: the reducer only closes a CVE from fresh authoritative
	// inventory, so pruning a row can never on its own verify a fix.
	pruned, err := tx.Query(ctx, `
		DELETE FROM device_cve_findings f
		WHERE f.device_id = $1::uuid
		  AND f.app_name = ANY($2::text[])
		  AND NOT (f.app_name = ANY($3::text[]))
		  AND f.match_confidence <> 'version_vendor_confirmed'
		  AND NOT EXISTS (
			  SELECT 1 FROM unnest($4::text[], $5::text[]) AS keep(cve_id, app_name)
			  WHERE keep.cve_id = f.cve_id AND keep.app_name = f.app_name
		  )
		RETURNING f.cve_id
	`, deviceID, names, cvelifecycle.OSPseudoAppNames, keepCVE, keepApp)
	if err != nil {
		return out, fmt.Errorf("prune findings on %s: %w", deviceID, err)
	}
	for pruned.Next() {
		var cveID string
		if err := pruned.Scan(&cveID); err != nil {
			pruned.Close()
			return out, fmt.Errorf("scan pruned finding: %w", err)
		}
		touched[cveID] = true
	}
	pruned.Close()
	if err := pruned.Err(); err != nil {
		return out, fmt.Errorf("prune findings on %s: %w", deviceID, err)
	}

	var assessedNames, unassessedNames []string
	for _, name := range names {
		// PAT-2029: a product mapped only for a different platform is not
		// assessed on this device — ix.Mapped(name) alone would say "mapped"
		// off a mapping that can never produce a finding here, misreporting
		// the product as assessed-with-zero rather than not_assessed.
		if len(versions[name]) > 0 && len(cvematch.FilterMappingsForPlatform(ix.For(name), devicePlatform)) > 0 {
			assessedNames = append(assessedNames, name)
			if err := upsertAssessment(ctx, tx, deviceID, tenantID, name, versions[name],
				len(perApp[name]), source); err != nil {
				return out, err
			}
			continue
		}
		unassessedNames = append(unassessedNames, name)
	}
	// An absent or unmapped product has no assessment. Removing the row is
	// what keeps a stale "0 findings" from outliving the mapping or install.
	if len(unassessedNames) > 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM cve_match_assessments
			WHERE device_id = $1::uuid AND app_name = ANY($2::text[])
		`, deviceID, unassessedNames); err != nil {
			return out, fmt.Errorf("clear assessments on %s: %w", deviceID, err)
		}
	}

	out.Observations += len(names)
	for cveID := range touched {
		out.Identities = append(out.Identities, cvelifecycle.Identity{TenantID: tenantID, CVEID: cveID})
	}
	sortIdentities(out.Identities)
	return out, nil
}

// AppFindingBasis is the device_cve_findings.mapping_basis an application
// finding is stored with (PAT-2138): "auto" when only automatic mappings
// produced it, NULL otherwise. NULL keeps the established meaning of an
// application finding (a hand-curated mapping produced it), and writing it
// explicitly clears "auto" once a person approves the mapping.
func AppFindingBasis(basis string) *string {
	if basis == cvematch.MappingBasisAuto {
		b := cvematch.MappingBasisAuto
		return &b
	}
	return nil
}

func sortIdentities(ids []cvelifecycle.Identity) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].CVEID < ids[j].CVEID })
}

func upsertAssessment(ctx context.Context, q DB, deviceID, tenantID, name string, versions []string,
	findingCount int, source string) error {
	if _, err := q.Exec(ctx, `
		INSERT INTO cve_match_assessments
			(device_id, tenant_id, app_name, app_versions, finding_count, last_matched_at, match_source)
		VALUES ($1::uuid, $2::uuid, $3, $4::text[], $5, now(), $6)
		ON CONFLICT (device_id, app_name) DO UPDATE SET
			app_versions    = EXCLUDED.app_versions,
			finding_count   = EXCLUDED.finding_count,
			last_matched_at = EXCLUDED.last_matched_at,
			match_source    = EXCLUDED.match_source
	`, deviceID, tenantID, name, uniqueSorted(versions), findingCount, source); err != nil {
		return fmt.Errorf("record assessment %s on %s: %w", name, deviceID, err)
	}
	return nil
}

// FullMatchDevice is one device's input to RecordFullMatchAssessments.
type FullMatchDevice struct {
	DeviceID, TenantID string
	Apps               []cvematch.ScannedApp
	Findings           []cvematch.Finding
}

// RecordFullMatchAssessments records the nightly full match's result as
// assessment rows for every MAPPED product on the device. Unmapped products
// get no row. Called by patched-cve-sync after it has written the device's
// findings; rows it did not refresh are cleared by PruneFullMatchAssessments.
func RecordFullMatchAssessments(ctx context.Context, q DB, mappings []cvematch.CPEMapping, device FullMatchDevice) error {
	ix := newMappingIndex(mappings)
	versions := map[string][]string{}
	for _, a := range device.Apps {
		versions[a.Name] = append(versions[a.Name], a.Version)
	}
	perApp := map[string]map[string]bool{}
	for _, f := range device.Findings {
		if perApp[f.AppName] == nil {
			perApp[f.AppName] = map[string]bool{}
		}
		perApp[f.AppName][f.CVEID] = true
	}
	for _, name := range sortedKeys(versions) {
		if !ix.Mapped(name) {
			continue
		}
		if err := upsertAssessment(ctx, q, device.DeviceID, device.TenantID, name, versions[name],
			len(perApp[name]), SourceFullMatch); err != nil {
			return err
		}
	}
	return nil
}

// PruneFullMatchAssessments removes assessment rows on in-scope (active)
// devices that a full match started at runStart did not refresh: products
// that were uninstalled or lost their mapping since they were last matched.
func PruneFullMatchAssessments(ctx context.Context, q DB, runStart time.Time) error {
	if _, err := q.Exec(ctx, `
		DELETE FROM cve_match_assessments a
		WHERE a.last_matched_at < $1
		  AND EXISTS (
			  SELECT 1 FROM devices d
			  WHERE d.id = a.device_id AND d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		  )
	`, runStart); err != nil {
		return fmt.Errorf("prune full-match assessments: %w", err)
	}
	return nil
}

// RecordRun stamps cve_match_runs for run kind feed_sync, full_match or
// delta_match.
func RecordRun(ctx context.Context, q DB, kind string, at time.Time) error {
	if _, err := q.Exec(ctx, `
		INSERT INTO cve_match_runs (run_kind, completed_at) VALUES ($1, $2)
		ON CONFLICT (run_kind) DO UPDATE SET completed_at = GREATEST(cve_match_runs.completed_at, EXCLUDED.completed_at)
	`, kind, at); err != nil {
		return fmt.Errorf("record %s run: %w", kind, err)
	}
	return nil
}

// fireNewFindingWebhooks raises vulnerability.discovered for findings this
// path inserted for the first time, grouped per device, mirroring the nightly
// matcher's event. Best-effort, after commit.
func fireNewFindingWebhooks(pool *pgxpool.Pool, found []newFinding) {
	if pool == nil || len(found) == 0 {
		return
	}
	type key struct{ tenant, device string }
	grouped := map[key]*webhook.VulnDiscoveredData{}
	var order []key
	for _, f := range found {
		k := key{f.TenantID, f.DeviceID}
		if grouped[k] == nil {
			grouped[k] = &webhook.VulnDiscoveredData{DeviceID: f.DeviceID, Hostname: f.Hostname}
			order = append(order, k)
		}
		grouped[k].NewCVEs = append(grouped[k].NewCVEs, f.CVE)
	}
	for _, k := range order {
		webhook.Fire(pool, k.tenant, webhook.EventVulnerabilityDiscovered, *grouped[k], "")
	}
}

func withoutOSPseudoApps(names []string) []string {
	out := names[:0:0]
	for _, n := range names {
		if !isOSPseudoApp(n) {
			out = append(out, n)
		}
	}
	return out
}

func isOSPseudoApp(name string) bool {
	for _, os := range cvelifecycle.OSPseudoAppNames {
		if name == os {
			return true
		}
	}
	return false
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
