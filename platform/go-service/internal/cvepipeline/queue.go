package cvepipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvelifecycle"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/metrics"
)

// AppVersions is one device's installed products: display name to the sorted
// distinct versions of it currently in device_apps.
type AppVersions map[string][]string

// SnapshotDeviceApps reads the device's current products. The extractor calls
// it inside its ingest transaction before and after upsertApps; the two
// snapshots are diffed by ChangedProducts.
func SnapshotDeviceApps(ctx context.Context, q DB, deviceID string) (AppVersions, error) {
	rows, err := q.Query(ctx, `
		SELECT name, COALESCE(version, '')
		FROM device_apps WHERE device_id = $1::uuid
	`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("snapshot device apps: %w", err)
	}
	defer rows.Close()
	out := AppVersions{}
	for rows.Next() {
		var name, version string
		if err := rows.Scan(&name, &version); err != nil {
			return nil, fmt.Errorf("scan device app snapshot: %w", err)
		}
		out[name] = append(out[name], version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate device app snapshot: %w", err)
	}
	for name, versions := range out {
		out[name] = uniqueSorted(versions)
	}
	return out, nil
}

// ChangedProducts returns the product names whose installed version set
// differs between two snapshots of the same device: newly installed, version
// changed, or (only when includeRemovals) no longer present. Sorted.
//
// includeRemovals is false when the payload carried no apps array at all. A
// missing inventory section is not evidence that software was removed, so it
// must not trigger a re-match that prunes findings (absence requires
// authority).
func ChangedProducts(before, after AppVersions, includeRemovals bool) []string {
	var out []string
	for name, versions := range after {
		if !equalStrings(uniqueSorted(before[name]), uniqueSorted(versions)) {
			out = append(out, name)
		}
	}
	if includeRemovals {
		for name := range before {
			if _, still := after[name]; !still {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FilterMapped keeps only names at least one CPE mapping covers. Unmapped
// products are never queued: there is nothing to match, and the read path
// reports them as not_assessed from the mapping table directly.
func FilterMapped(names []string, mappings []cvematch.CPEMapping) []string {
	ix := newMappingIndex(mappings)
	var out []string
	for _, n := range names {
		if ix.Mapped(n) && !isOSPseudoApp(n) {
			out = append(out, n)
		}
	}
	return out
}

// EnqueueObservations requests a re-match of the named products on one
// device. See enqueueJobs for the capacity and conflict semantics.
func EnqueueObservations(ctx context.Context, q DB, tenantID, deviceID string, names []string, reason string) (enqueued, dropped int, err error) {
	names = uniqueSorted(names)
	jobs := make([]observationJob, 0, len(names))
	for _, n := range names {
		jobs = append(jobs, observationJob{TenantID: tenantID, DeviceID: deviceID, AppName: n})
	}
	return enqueueJobs(ctx, q, jobs, reason)
}

type observationJob struct {
	TenantID, DeviceID, AppName string
}

// enqueueJobs inserts observation jobs in one statement. A product already
// queued has its request refreshed rather than duplicated. New rows are
// admitted only up to the room left under both caps, counted once per
// statement, so a large mapping publish cannot blow through either: first
// each tenant's room under TenantQueueCapacity, then the global room under
// QueueCapacity, shared round-robin across the tenants in the statement (each
// tenant's first new row, then each tenant's second, ...) so one large
// tenant in a mapping expansion cannot take all of it. Two concurrent
// statements can each see the same room, which is why the caps are
// documented as soft. Refused jobs are returned as dropped and counted.
//
// ON CONFLICT ... DO UPDATE (not DO NOTHING) is deliberate: it waits for a
// worker currently holding that row, so a change committed while the worker
// is matching the old inventory re-queues the product instead of being
// silently absorbed by a row the worker is about to delete.
func enqueueJobs(ctx context.Context, q DB, jobs []observationJob, reason string) (enqueued, dropped int, err error) {
	if len(jobs) == 0 {
		return 0, 0, nil
	}
	seen := map[observationJob]bool{}
	tenants := make([]string, 0, len(jobs))
	devices := make([]string, 0, len(jobs))
	names := make([]string, 0, len(jobs))
	for _, j := range jobs {
		if seen[j] || isOSPseudoApp(j.AppName) {
			continue
		}
		seen[j] = true
		tenants = append(tenants, j.TenantID)
		devices = append(devices, j.DeviceID)
		names = append(names, j.AppName)
	}
	if len(names) == 0 {
		return 0, 0, nil
	}
	// Mapping expansion deliberately preserves a row's retry state. A mapping
	// job is retained while a tenant is at its cap and re-expands on every
	// extractor cycle; treating that as a fresh observation would otherwise
	// make a permanently failing row evade MaxAttempts. An ingest refresh is a
	// new observation of device state and continues to reset the retry state.
	preserveRetryState := reason == SourceMappingPublish
	rows, err := q.Query(ctx, `
		WITH room AS (
			SELECT GREATEST($5::int - count(*)::int, 0) AS n FROM cve_match_queue
		), wanted AS (
			SELECT w.tenant_id, w.device_id, w.app_name,
			       EXISTS (
				   SELECT 1 FROM cve_match_queue q
				   WHERE q.kind = 'observation' AND q.device_id = w.device_id AND q.app_name = w.app_name
			       ) AS already
			FROM unnest($2::uuid[], $3::uuid[], $4::text[]) AS w(tenant_id, device_id, app_name)
		), tenant_room AS (
			SELECT t.tenant_id,
			       GREATEST($6::int - (
				   SELECT count(*)::int FROM cve_match_queue q
				   WHERE q.kind = 'observation' AND q.tenant_id = t.tenant_id
			       ), 0) AS n
			FROM (SELECT DISTINCT tenant_id FROM wanted) t
		), per_tenant AS (
			SELECT w.tenant_id, w.device_id, w.app_name, w.already,
			       row_number() OVER (PARTITION BY w.already, w.tenant_id ORDER BY w.device_id, w.app_name) AS trn
			FROM wanted w
		), ranked AS (
			-- Only rows inside their tenant's room compete for the global
			-- room, in round-robin order across tenants.
			SELECT p.tenant_id, p.device_id, p.app_name, p.already,
			       row_number() OVER (PARTITION BY p.already ORDER BY p.trn, p.device_id, p.app_name) AS rn
			FROM per_tenant p
			JOIN tenant_room tr ON tr.tenant_id = p.tenant_id
			WHERE p.already OR p.trn <= tr.n
		)
		INSERT INTO cve_match_queue (kind, reason, tenant_id, device_id, app_name)
		SELECT 'observation', $1, r.tenant_id, r.device_id, r.app_name
		FROM ranked r, room
		WHERE r.already OR r.rn <= room.n
		-- Every enqueuer takes queue-row locks in (device_id, app_name)
		-- order, so two statements with overlapping rows cannot deadlock.
		ORDER BY r.device_id, r.app_name
		ON CONFLICT (device_id, app_name) WHERE kind = 'observation' DO UPDATE SET
			requested_at = now(),
			reason       = EXCLUDED.reason,
			attempts     = CASE WHEN $7 THEN cve_match_queue.attempts ELSE 0 END,
			last_error   = CASE WHEN $7 THEN cve_match_queue.last_error ELSE NULL END
		RETURNING tenant_id::text
	`, reason, tenants, devices, names, QueueCapacity, TenantQueueCapacity, preserveRetryState)
	if err != nil {
		return 0, 0, fmt.Errorf("enqueue cve match observations: %w", err)
	}
	defer rows.Close()
	admittedByTenant := make(map[string]int)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return 0, 0, fmt.Errorf("scan enqueued cve match observation: %w", err)
		}
		enqueued++
		admittedByTenant[tenantID]++
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate enqueued cve match observations: %w", err)
	}
	dropped = len(names) - enqueued
	if dropped > 0 {
		metrics.CVEMatchQueueDropped.Add(float64(dropped))
		wantedByTenant := make(map[string]int)
		for _, tenantID := range tenants {
			wantedByTenant[tenantID]++
		}
		for tenantID, wanted := range wantedByTenant {
			if rejected := wanted - admittedByTenant[tenantID]; rejected > 0 {
				metrics.CVEMatchQueueTenantDropped.WithLabelValues(tenantID).Add(float64(rejected))
			}
		}
	}
	return enqueued, dropped, nil
}

type snapshotMapping struct {
	ID                               int64
	MatchName, CPEVendor, CPEProduct string
	// SourceType routes the mapping to its matcher: app_name mappings to the
	// application path, homebrew_formula and homebrew_cask to the Homebrew
	// path (PAT-2045). ReviewState matters only to Homebrew, where a mapping
	// matches only while curated, so moving into or out of curated is a
	// change.
	SourceType, ReviewState string
}

// mappingTarget is one match_name a mapping job re-matches, and the matcher
// it belongs to. A Homebrew name is lowercased and trimmed, because Homebrew
// mappings match the formula name or cask token case-insensitively.
type mappingTarget struct {
	SourceType, Name string
}

func newMappingTarget(m snapshotMapping) mappingTarget {
	if m.SourceType == "" || m.SourceType == sourceTypeAppName {
		return mappingTarget{SourceType: sourceTypeAppName, Name: m.MatchName}
	}
	return mappingTarget{SourceType: m.SourceType, Name: strings.ToLower(strings.TrimSpace(m.MatchName))}
}

// mappingChanges diffs the live mapping table against the snapshot the
// matcher last acted on and returns the match_names whose observations need
// re-matching: every name of a new mapping, both the old and new names of a
// changed one, and the name of a removed one, each with the matcher it
// belongs to. A mapping that moves between source types re-matches under
// both. Sorted by source type, then name. Pure; unit-tested.
func mappingChanges(live, snapshot map[int64]snapshotMapping) []mappingTarget {
	targets := map[mappingTarget]bool{}
	for id, m := range live {
		old, ok := snapshot[id]
		if !ok {
			targets[newMappingTarget(m)] = true
			continue
		}
		if old != m {
			targets[newMappingTarget(m)] = true
			targets[newMappingTarget(old)] = true
		}
	}
	for id, old := range snapshot {
		if _, ok := live[id]; !ok {
			targets[newMappingTarget(old)] = true
		}
	}
	out := make([]mappingTarget, 0, len(targets))
	for t := range targets {
		if strings.TrimSpace(t.Name) != "" {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceType != out[j].SourceType {
			return out[i].SourceType < out[j].SourceType
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// SyncMappingSnapshot detects published, changed and removed CPE mappings by
// diffing app_cpe_mappings against cve_mapping_snapshot, queues one mapping
// job per affected match_name and advances the snapshot, all in one
// transaction. Detecting by diff rather than by trigger means every write
// path is covered: a migration, manual SQL, or a future admin endpoint.
//
// Application and Homebrew mappings share the snapshot (PAT-2045). Each job
// carries its mapping_source_type, so expandMappingJobs routes a Homebrew
// name to the devices whose current Homebrew list includes it, never to the
// application word-token matcher.
func SyncMappingSnapshot(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin mapping snapshot sync: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// One syncer at a time; a second extractor just skips this cycle.
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('cvepipeline.mapping_snapshot', 0))`).Scan(&locked); err != nil {
		return 0, fmt.Errorf("lock mapping snapshot: %w", err)
	}
	if !locked {
		return 0, nil
	}
	load := func(sql string) (map[int64]snapshotMapping, error) {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[int64]snapshotMapping{}
		for rows.Next() {
			var m snapshotMapping
			if err := rows.Scan(&m.ID, &m.MatchName, &m.CPEVendor, &m.CPEProduct, &m.SourceType, &m.ReviewState); err != nil {
				return nil, err
			}
			out[m.ID] = m
		}
		return out, rows.Err()
	}
	live, err := load(`SELECT id, match_name, cpe_vendor, cpe_product, source_type, review_state FROM app_cpe_mappings`)
	if err != nil {
		return 0, fmt.Errorf("load live mappings: %w", err)
	}
	snap, err := load(`SELECT mapping_id, match_name, cpe_vendor, cpe_product, source_type, review_state FROM cve_mapping_snapshot`)
	if err != nil {
		return 0, fmt.Errorf("load mapping snapshot: %w", err)
	}
	targets := mappingChanges(live, snap)
	if len(targets) == 0 {
		return 0, nil
	}
	sources := make([]string, len(targets))
	names := make([]string, len(targets))
	for i, t := range targets {
		sources[i], names[i] = t.SourceType, t.Name
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_match_queue (kind, reason, match_name, mapping_source_type)
		SELECT 'mapping', 'mapping_publish', n, s FROM unnest($1::text[], $2::text[]) AS u(s, n)
		WHERE btrim(n) <> ''
	`, sources, names); err != nil {
		return 0, fmt.Errorf("enqueue mapping jobs: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cve_mapping_snapshot`); err != nil {
		return 0, fmt.Errorf("reset mapping snapshot: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO cve_mapping_snapshot (mapping_id, match_name, cpe_vendor, cpe_product, source_type, review_state)
		SELECT id, match_name, cpe_vendor, cpe_product, source_type, review_state FROM app_cpe_mappings
	`); err != nil {
		return 0, fmt.Errorf("advance mapping snapshot: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit mapping snapshot: %w", err)
	}
	return len(targets), nil
}

// activeObservationsMatching lists every (tenant, device, product) on an
// in-scope device whose display name is covered by one of matchNames.
func activeObservationsMatching(ctx context.Context, q DB, matchNames []string) ([]observationJob, error) {
	if len(matchNames) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT da.name
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
	`)
	if err != nil {
		return nil, fmt.Errorf("load active product names: %w", err)
	}
	var covered []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan active product name: %w", err)
		}
		for _, mn := range matchNames {
			if cvematch.NameMatches(name, mn) {
				covered = append(covered, name)
				break
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active product names: %w", err)
	}
	if len(covered) == 0 {
		return nil, nil
	}
	rows, err = q.Query(ctx, `
		SELECT DISTINCT d.tenant_id::text, d.id::text, da.name
		FROM device_apps da
		JOIN devices d ON d.id = da.device_id
		WHERE da.name = ANY($1::text[])
		  AND d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		ORDER BY 2, 3
	`, covered)
	if err != nil {
		return nil, fmt.Errorf("load observations for mapped products: %w", err)
	}
	defer rows.Close()
	var out []observationJob
	for rows.Next() {
		var j observationJob
		if err := rows.Scan(&j.TenantID, &j.DeviceID, &j.AppName); err != nil {
			return nil, fmt.Errorf("scan observation: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// expandMappingJobs turns queued mapping jobs into observation jobs for every
// active device carrying a covered product, then deletes the mapping jobs,
// in one transaction.
func expandMappingJobs(ctx context.Context, pool *pgxpool.Pool, limit int) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin mapping expansion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		SELECT id, match_name, mapping_source_type FROM cve_match_queue
		WHERE kind = 'mapping'
		ORDER BY enqueued_at, id
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, limit)
	if err != nil {
		return 0, fmt.Errorf("claim mapping jobs: %w", err)
	}
	var ids []int64
	var appNames []string
	var brewKeys []homebrewKey
	for rows.Next() {
		var id int64
		var name, sourceType string
		if err := rows.Scan(&id, &name, &sourceType); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan mapping job: %w", err)
		}
		ids = append(ids, id)
		if sourceType == sourceTypeAppName {
			appNames = append(appNames, name)
		} else if k, ok := homebrewKeyForSource(sourceType, name); ok {
			brewKeys = append(brewKeys, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate mapping jobs: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	jobs, err := activeObservationsMatching(ctx, tx, uniqueSorted(appNames))
	if err != nil {
		return 0, err
	}
	// PAT-2045: a Homebrew mapping re-matches the devices whose current
	// Homebrew list includes that formula or cask, through the Homebrew
	// matcher (the observation is queued under its Homebrew display name).
	brewJobs, err := activeHomebrewObservations(ctx, tx, brewKeys)
	if err != nil {
		return 0, err
	}
	jobs = append(jobs, brewJobs...)
	// PAT-2057: an application mapping also decides whether a cask linked to
	// that app counts as linked to a mapped app (LinkedToApp), and so whether
	// the cask's own mapping or the app's is the install's finding. Re-match
	// those casks in the same pass, or a removed app mapping leaves the
	// install with no finding, and a published one with a duplicate, until
	// the nightly run.
	linkedCasks, err := activeCasksLinkedToApps(ctx, tx, uniqueSorted(appNames))
	if err != nil {
		return 0, err
	}
	jobs = append(jobs, linkedCasks...)
	// One insert statement for every kind, sorted by (device_id, app_name)
	// inside enqueueJobs, so expansion takes queue-row locks in one order.
	_, dropped, err := enqueueJobs(ctx, tx, jobs, SourceMappingPublish)
	if err != nil {
		return 0, err
	}
	if dropped > 0 {
		// Queue full: keep the mapping jobs so the next cycle expands them
		// again (already-queued observations are refreshed, not duplicated).
		// Deleting them now would leave the dropped products reading
		// assessed against the old mapping until the nightly run.
		slog.Warn("cve match queue at capacity (global or a tenant's share) during mapping expansion; mapping jobs kept for retry",
			"dropped", dropped, "capacity", QueueCapacity, "tenant_capacity", TenantQueueCapacity, "mapping_jobs", len(ids))
	} else if _, err := tx.Exec(ctx, `DELETE FROM cve_match_queue WHERE id = ANY($1::bigint[])`, ids); err != nil {
		return 0, fmt.Errorf("delete expanded mapping jobs: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit mapping expansion: %w", err)
	}
	return len(jobs), nil
}

// DrainResult summarises one Drain call.
type DrainResult struct {
	MappingJobs  int // match_names newly detected as published/changed/removed
	Expanded     int // observation jobs created from mapping jobs
	Observations int // (device, product) observations re-matched
	Findings     int // current findings for those observations after the match
	NewFindings  int // findings inserted for the first time
	Failed       int // observations whose match failed and will be retried
	// SkippedForFullMatch is true when the nightly full match held the match
	// lock, so this cycle matched nothing and left the queue untouched.
	SkippedForFullMatch bool
}

// drainSelectSQL picks the observations one Drain cycle matches (PAT-2030):
// round-robin across tenants, oldest first within each tenant. Every tenant
// with a claimable row gets its oldest row into the batch before any tenant
// gets its second, and so on, so a tenant with a deep backlog takes only the
// slots nobody else wants. Within one round, tenants are ordered by the age
// of that row, so the batch is still oldest-first when only one tenant has
// work.
//
// Cost is bounded by the number of tenants with queued rows, not by queue
// depth: the recursive CTE is a loose index scan that visits each distinct
// tenant_id once, and the LATERAL reads at most $2 rows per tenant along
// idx_cve_match_queue_tenant_order (0194), already in order. A window
// function over the whole queue would sort every row, up to QueueCapacity,
// every cycle.
//
// Known limit: if more tenants have work than one batch holds ($2, 500 in
// production), a batch takes the $2 tenants with the oldest heads and the
// others wait for a later cycle. Fairness then degrades to oldest-head-first
// across tenants rather than one row each per cycle.
const drainSelectSQL = `
	WITH RECURSIVE tenants AS (
		(SELECT tenant_id FROM cve_match_queue
		 WHERE kind = 'observation'
		 ORDER BY tenant_id LIMIT 1)
		UNION ALL
		SELECT (SELECT q.tenant_id FROM cve_match_queue q
		        WHERE q.kind = 'observation' AND q.tenant_id > t.tenant_id
		        ORDER BY q.tenant_id LIMIT 1)
		FROM tenants t
		WHERE t.tenant_id IS NOT NULL
	)
	SELECT p.id, p.device_id::text, p.app_name
	FROM tenants t
	CROSS JOIN LATERAL (
		SELECT h.id, h.device_id, h.app_name, h.enqueued_at,
		       row_number() OVER (ORDER BY h.enqueued_at, h.id) AS rn
		FROM (
			SELECT q.id, q.device_id, q.app_name, q.enqueued_at
			FROM cve_match_queue q
			WHERE q.kind = 'observation' AND q.tenant_id = t.tenant_id AND q.attempts < $1
			ORDER BY q.enqueued_at, q.id
			LIMIT $2
		) h
	) p
	WHERE t.tenant_id IS NOT NULL
	ORDER BY p.rn, p.enqueued_at, p.id
	LIMIT $2
`

// Drain runs one bounded pass of the event-driven matcher: detect mapping
// publishes, expand mapping jobs, then re-match up to maxObservations queued
// observations against the local CVE store, one device per transaction.
// Observations are taken round-robin across tenants (see drainSelectSQL).
// Touched finding identities go through the shared lifecycle reducer after
// commit. Safe to run concurrently with itself and with the nightly run.
func Drain(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, maxObservations int) (DrainResult, error) {
	var res DrainResult
	if logger == nil {
		logger = slog.Default()
	}
	if maxObservations <= 0 {
		maxObservations = 500
	}
	release, ok, err := tryTargetedMatchLock(ctx, pool)
	if err != nil {
		return res, err
	}
	if !ok {
		res.SkippedForFullMatch = true
		return res, nil
	}
	defer release()
	n, err := SyncMappingSnapshot(ctx, pool)
	if err != nil {
		return res, err
	}
	res.MappingJobs = n
	if res.Expanded, err = expandMappingJobs(ctx, pool, 20); err != nil {
		return res, err
	}

	rows, err := pool.Query(ctx, drainSelectSQL, MaxAttempts, maxObservations)
	if err != nil {
		return res, fmt.Errorf("list queued observations: %w", err)
	}
	byDevice := map[string][]int64{}
	var devices []string
	for rows.Next() {
		var id int64
		var deviceID, name string
		if err := rows.Scan(&id, &deviceID, &name); err != nil {
			rows.Close()
			return res, fmt.Errorf("scan queued observation: %w", err)
		}
		if byDevice[deviceID] == nil {
			devices = append(devices, deviceID)
		}
		byDevice[deviceID] = append(byDevice[deviceID], id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("iterate queued observations: %w", err)
	}
	if len(devices) == 0 {
		return res, nil
	}

	mappings, err := LoadMappings(ctx, pool)
	if err != nil {
		return res, err
	}
	ix := newMappingIndex(mappings)
	feed := newFeedCache()
	var total matchOutcome
	var errs []error
	for _, deviceID := range devices {
		ids := byDevice[deviceID]
		outcome, err := drainDevice(ctx, pool, ix, feed, deviceID, ids)
		if err != nil {
			res.Failed += len(ids)
			metrics.CVEMatchObservations.WithLabelValues("error").Add(float64(len(ids)))
			if _, uerr := pool.Exec(ctx, `
				UPDATE cve_match_queue SET attempts = attempts + 1, last_error = left($2, 500)
				WHERE id = ANY($1::bigint[])
			`, ids, err.Error()); uerr != nil {
				err = errors.Join(err, fmt.Errorf("record attempt: %w", uerr))
			}
			logger.Warn("cve match observation failed; will retry", "device_id", deviceID, "err", err)
			errs = append(errs, err)
			continue
		}
		metrics.CVEMatchObservations.WithLabelValues("matched").Add(float64(outcome.Observations))
		total.add(outcome)
	}
	res.Observations = total.Observations
	res.Findings = total.Findings
	res.NewFindings = len(total.New)

	if err := cvelifecycle.ReconcileIdentities(ctx, pool, total.Identities, logger); err != nil {
		errs = append(errs, fmt.Errorf("reconcile CVE lifecycle after queue match: %w", err))
	}
	fireNewFindingWebhooks(pool, total.New)
	if res.Observations > 0 || res.Failed > 0 {
		logger.Info("cve match queue drained", "observations", res.Observations, "findings", res.Findings,
			"new_findings", res.NewFindings, "failed", res.Failed, "mapping_jobs", res.MappingJobs, "expanded", res.Expanded)
	}
	return res, errors.Join(errs...)
}

func drainDevice(ctx context.Context, pool *pgxpool.Pool, ix *mappingIndex, feed *feedCache,
	deviceID string, ids []int64) (matchOutcome, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return matchOutcome{}, fmt.Errorf("begin device match: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Hold the rows for the whole match. A concurrent re-request for the same
	// observation waits on this lock (see EnqueueObservations) and lands as a
	// fresh row after the delete below, so no change is lost.
	rows, err := tx.Query(ctx, `
		SELECT id, app_name, reason FROM cve_match_queue
		WHERE id = ANY($1::bigint[]) AND attempts < $2
		FOR UPDATE SKIP LOCKED
	`, ids, MaxAttempts)
	if err != nil {
		return matchOutcome{}, fmt.Errorf("lock queued observations: %w", err)
	}
	var locked []int64
	var names []string
	source := SourceMappingPublish
	for rows.Next() {
		var id int64
		var name, reason string
		if err := rows.Scan(&id, &name, &reason); err != nil {
			rows.Close()
			return matchOutcome{}, fmt.Errorf("scan locked observation: %w", err)
		}
		locked = append(locked, id)
		names = append(names, name)
		if reason == SourceIngest {
			source = SourceIngest
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return matchOutcome{}, fmt.Errorf("iterate locked observations: %w", err)
	}
	if len(locked) == 0 {
		return matchOutcome{}, nil // another worker has them
	}
	outcome, err := matchDevice(ctx, tx, ix, feed, deviceID, names, source)
	if err != nil {
		return matchOutcome{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cve_match_queue WHERE id = ANY($1::bigint[])`, locked); err != nil {
		return matchOutcome{}, fmt.Errorf("delete matched observations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return matchOutcome{}, fmt.Errorf("commit device match: %w", err)
	}
	return outcome, nil
}

// QueueStats is the backlog the Prometheus gauges report.
type QueueStats struct {
	Depth            int
	Stuck            int
	OldestAgeSeconds float64
	// Tenants is the per-tenant observation backlog (PAT-2030), sorted by
	// tenant ID; tenants with nothing queued are absent.
	Tenants []TenantQueueStats
}

// TenantQueueStats is one tenant's observation backlog in cve_match_queue.
type TenantQueueStats struct {
	TenantID         string
	Depth            int
	OldestAgeSeconds float64
}

// reportedTenants is the tenant_id label set the per-tenant gauges carried
// after the last refresh, so a tenant whose backlog cleared has its series
// deleted rather than left frozen at its last value.
var (
	reportedTenantsMu sync.Mutex
	reportedTenants   = map[string]bool{}
)

// RefreshQueueMetrics reads queue depth and oldest-item age and publishes
// them as gauges, globally and per tenant. Stuck rows (attempts exhausted)
// are included on purpose so the backlog alert keeps firing until someone
// looks.
func RefreshQueueMetrics(ctx context.Context, q DB) (QueueStats, error) {
	var s QueueStats
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int,
		       count(*) FILTER (WHERE attempts >= $1)::int,
		       COALESCE(EXTRACT(EPOCH FROM now() - min(enqueued_at)), 0)::float8
		FROM cve_match_queue
	`, MaxAttempts).Scan(&s.Depth, &s.Stuck, &s.OldestAgeSeconds); err != nil {
		return s, fmt.Errorf("read cve match queue stats: %w", err)
	}
	if s.OldestAgeSeconds < 0 {
		s.OldestAgeSeconds = 0
	}
	rows, err := q.Query(ctx, `
		SELECT tenant_id::text, count(*)::int,
		       GREATEST(EXTRACT(EPOCH FROM now() - min(enqueued_at)), 0)::float8
		FROM cve_match_queue
		WHERE kind = 'observation'
		GROUP BY tenant_id
		ORDER BY tenant_id
	`)
	if err != nil {
		return s, fmt.Errorf("read cve match queue tenant stats: %w", err)
	}
	for rows.Next() {
		var t TenantQueueStats
		if err := rows.Scan(&t.TenantID, &t.Depth, &t.OldestAgeSeconds); err != nil {
			rows.Close()
			return s, fmt.Errorf("scan cve match queue tenant stats: %w", err)
		}
		s.Tenants = append(s.Tenants, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("iterate cve match queue tenant stats: %w", err)
	}
	metrics.CVEMatchQueueDepth.Set(float64(s.Depth))
	metrics.CVEMatchQueueStuck.Set(float64(s.Stuck))
	metrics.CVEMatchQueueOldestAge.Set(s.OldestAgeSeconds)
	publishTenantQueueMetrics(s.Tenants)
	metrics.CVEMatchQueueRefreshed.Set(float64(time.Now().Unix()))
	return s, nil
}

func publishTenantQueueMetrics(tenants []TenantQueueStats) {
	reportedTenantsMu.Lock()
	defer reportedTenantsMu.Unlock()
	now := make(map[string]bool, len(tenants))
	for _, t := range tenants {
		now[t.TenantID] = true
		metrics.CVEMatchQueueTenantDepth.WithLabelValues(t.TenantID).Set(float64(t.Depth))
		metrics.CVEMatchQueueTenantOldestAge.WithLabelValues(t.TenantID).Set(t.OldestAgeSeconds)
	}
	for id := range reportedTenants {
		if !now[id] {
			metrics.CVEMatchQueueTenantDepth.DeleteLabelValues(id)
			metrics.CVEMatchQueueTenantOldestAge.DeleteLabelValues(id)
		}
	}
	reportedTenants = now
}
