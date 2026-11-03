package softwaregov

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/apppolicy"
)

// The Unapproved-present summary (PAT-2095, migration 0202).
//
// The portal overview and the marked alert used to resolve the whole tenant
// estate on every call. They now read software_unapproved_presence: one row
// per (device, Unapproved assessment), written by the same resolution path
// as the full load (scanInventory), one device at a time.
//
// Three things keep it exact.
//
//   - Inventory. Triggers mark a device dirty (software_unapproved_presence_
//     dirty) in the same transaction as any change to a resolver input on
//     it. A refresh recomputes the device's rows and clears the mark only if
//     no write landed since it read the mark. Readers never trust a dirty
//     device's rows: they resolve its inventory live in the same snapshot.
//   - Policies. Triggers bump the tenant's policy_version inside the policy
//     transaction. The summary is usable only when summary_version (the
//     policy version of the last full rebuild) has caught up; until then the
//     overview falls back to the full computation and the raise rebuilds
//     first. A refresh reads policies under FOR SHARE of the state row, so it
//     never mixes two policy versions.
//   - Rebuild. ReconcileTenant refreshes every device of the tenant in
//     chunks, each its own short transaction, then records the policy
//     version it started from.
//
// Locking, in the only order anything takes them:
//
//	presence_devices row (per device)  ->  presence_state row (per tenant)
//
// A policy write takes the state row exclusively (the trigger) and never a
// presence_devices row. The ingest refresh takes neither lock if it would
// wait for more than a millisecond (lock_timeout, SKIP LOCKED, NOWAIT): it
// leaves the device dirty and the runner catches up. Nothing here
// takes the tenant alert lock (lockTenantAlerts).

// presenceChunk is the number of devices one rebuild transaction refreshes.
const presenceChunk = 200

// MaxLiveDirtyDevices bounds how many dirty devices a reader resolves live.
// Beyond it the overview falls back to the full computation.
const MaxLiveDirtyDevices = 500

// errPresenceBusy means a non-waiting refresh found its lock taken.
var errPresenceBusy = errors.New("softwaregov: presence refresh skipped, lock busy")

// presenceRow is one (device, Unapproved assessment) summary row.
type presenceRow struct {
	deviceID      string
	product       Product
	policyKind    string
	policyID      int64
	observedSince time.Time
}

// hasUnapproved reports whether any policy row resolves to Unapproved. With
// none, no device can carry an Unapproved product.
func (p policies) hasUnapproved() bool {
	for _, r := range p.apps {
		if r.policy.Policy == StateUnapproved {
			return true
		}
	}
	for _, r := range p.exts {
		if r.policy == StateUnapproved {
			return true
		}
	}
	for _, r := range p.homebrew {
		if r.policy == StateUnapproved {
			return true
		}
	}
	for _, r := range p.observations {
		if r.policy == StateUnapproved {
			return true
		}
	}
	return false
}

// unapprovedRows flattens the builder's Unapproved assessments into one row
// per (device, assessment).
func (b *builder) unapprovedRows() []presenceRow {
	var out []presenceRow
	for k, a := range b.assessments {
		if a.State != StateUnapproved || a.PolicyID == 0 {
			continue
		}
		for deviceID, pr := range b.presence[k] {
			out = append(out, presenceRow{deviceID: deviceID, product: *b.devProduct[k][deviceID],
				policyKind: a.PolicyKind, policyID: a.PolicyID, observedSince: pr.ObservedSince})
		}
	}
	return out
}

type presenceState struct {
	initialized    bool
	policyVersion  int64
	summaryVersion int64
}

func (s presenceState) current() bool { return s.initialized && s.summaryVersion >= s.policyVersion }

func readPresenceState(ctx context.Context, q Querier, tenantID string) (presenceState, error) {
	var s presenceState
	err := q.QueryRow(ctx, `
		SELECT policy_version, summary_version FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&s.policyVersion, &s.summaryVersion)
	if isNoRows(err) {
		return presenceState{}, nil
	}
	if err != nil {
		return s, fmt.Errorf("presence state: %w", err)
	}
	s.initialized = true
	return s, nil
}

func isLockNotAvailable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

// refreshDevices recomputes the summary rows of the given devices of one
// tenant in one transaction. With wait false it takes nothing it would have
// to wait for: busy devices are skipped and a policy write in flight makes
// the whole call return errPresenceBusy. Devices it skips, or whose
// inventory changed while it ran, stay dirty.
func refreshDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, deviceIDs []string, wait bool, asOf time.Time) (int, error) {
	ids := dedupeSorted(deviceIDs)
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if !wait {
		// INSERT ON CONFLICT and foreign-key checks can wait before the
		// explicit SKIP LOCKED/NOWAIT queries. Bound those waits too.
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1ms'`); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_unapproved_presence_devices (device_id)
		SELECT d.id FROM devices d
		WHERE d.id = ANY($1::uuid[]) AND d.tenant_id = $2::uuid
		ORDER BY d.id
		ON CONFLICT (device_id) DO NOTHING
	`, ids, tenantID); err != nil {
		return 0, fmt.Errorf("presence device rows: %w", err)
	}
	lockSQL := `
		SELECT pd.device_id::text
		FROM software_unapproved_presence_devices pd
		JOIN devices d ON d.id = pd.device_id AND d.tenant_id = $2::uuid
		WHERE pd.device_id = ANY($1::uuid[])
		ORDER BY pd.device_id
		FOR UPDATE OF pd`
	if !wait {
		lockSQL += " SKIP LOCKED"
	}
	locked, err := scanStrings(tx.Query(ctx, lockSQL, ids, tenantID))
	if err != nil {
		return 0, fmt.Errorf("lock presence devices: %w", err)
	}
	if len(locked) == 0 {
		return 0, tx.Commit(ctx)
	}

	// The dirty marks, read before the inventory: a write committing after
	// this read changes seq, so the clear below leaves it dirty.
	type mark struct {
		device string
		seq    int64
	}
	var marks []mark
	rows, err := tx.Query(ctx, `
		SELECT device_id::text, seq FROM software_unapproved_presence_dirty WHERE device_id = ANY($1::uuid[])
	`, locked)
	if err != nil {
		return 0, fmt.Errorf("read dirty marks: %w", err)
	}
	for rows.Next() {
		var m mark
		if err := rows.Scan(&m.device, &m.seq); err != nil {
			rows.Close()
			return 0, err
		}
		marks = append(marks, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	// The policy version, held against a policy write until commit.
	stateSQL := `SELECT policy_version FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid FOR SHARE`
	if !wait {
		stateSQL += " NOWAIT"
	}
	var version int64
	if err := tx.QueryRow(ctx, stateSQL, tenantID).Scan(&version); err != nil && !isNoRows(err) {
		if isLockNotAvailable(err) {
			return 0, errPresenceBusy
		}
		return 0, fmt.Errorf("presence policy version: %w", err)
	}

	pol, err := loadPolicies(ctx, tx, tenantID)
	if err != nil {
		return 0, err
	}
	var out []presenceRow
	if pol.hasUnapproved() {
		b, err := scanInventory(ctx, tx, tenantID, locked, pol, asOf)
		if err != nil {
			return 0, err
		}
		out = b.unapprovedRows()
	}

	if _, err := tx.Exec(ctx, `DELETE FROM software_unapproved_presence WHERE device_id = ANY($1::uuid[])`, locked); err != nil {
		return 0, fmt.Errorf("clear presence rows: %w", err)
	}
	if len(out) > 0 {
		if err := insertPresenceRows(ctx, tx, tenantID, out); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE software_unapproved_presence_devices SET policy_version = $2, refreshed_at = now()
		WHERE device_id = ANY($1::uuid[])
	`, locked, version); err != nil {
		return 0, fmt.Errorf("stamp presence devices: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	// Clear marks after commit, so the computation holds no dirty-row lock.
	// SKIP LOCKED leaves busy marks alone; a sequence change, cleanup failure
	// or crash retains the mark for exact live reads and a later repair.
	// Only this short cleanup statement can contend with a dirty-row write.
	if len(marks) > 0 {
		devs := make([]string, len(marks))
		seqs := make([]int64, len(marks))
		for i, m := range marks {
			devs[i], seqs[i] = m.device, m.seq
		}
		if _, err := pool.Exec(ctx, `
			DELETE FROM software_unapproved_presence_dirty
			WHERE device_id IN (
				SELECT dd.device_id
				FROM software_unapproved_presence_dirty dd
				JOIN unnest($1::uuid[], $2::bigint[]) AS u(device_id, seq)
				  ON u.device_id = dd.device_id AND u.seq = dd.seq
				FOR UPDATE OF dd SKIP LOCKED
			)
		`, devs, seqs); err != nil {
			return len(locked), fmt.Errorf("clear dirty marks: %w", err)
		}
	}
	return len(locked), nil
}

func insertPresenceRows(ctx context.Context, tx pgx.Tx, tenantID string, rows []presenceRow) error {
	n := len(rows)
	dev, key, kind, typ := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	name, platform, ident, team := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	browser, ext, tap := make([]string, n), make([]string, n), make([]string, n)
	observationKind, observationSource := make([]string, n), make([]string, n)
	pid := make([]int64, n)
	since := make([]time.Time, n)
	for i, r := range rows {
		dev[i], key[i], kind[i], pid[i], typ[i] = r.deviceID, r.product.ProductKey, r.policyKind, r.policyID, r.product.Type
		name[i], platform[i], ident[i], team[i] = r.product.Name, r.product.Platform, r.product.Identifier, r.product.TeamID
		browser[i], ext[i], tap[i], since[i] = r.product.Browser, r.product.ExtensionID, r.product.Tap, r.observedSince
		observationKind[i], observationSource[i] = r.product.ObservationKind, r.product.ObservationSource
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_unapproved_presence
		    (tenant_id, device_id, product_key, policy_kind, policy_id, product_type, name, platform,
		     identifier, team_id, browser, extension_id, tap, observation_kind, observation_source, observed_since)
		SELECT $1::uuid, u.*
		FROM unnest($2::uuid[], $3::text[], $4::text[], $5::bigint[], $6::text[], $7::text[], $8::text[],
		            $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::timestamptz[]) AS u
	`, tenantID, dev, key, kind, pid, typ, name, platform, ident, team, browser, ext, tap, observationKind, observationSource, since); err != nil {
		return fmt.Errorf("insert presence rows: %w", err)
	}
	return nil
}

// RefreshDevice brings one device's summary rows up to date after its
// inventory committed. It is opportunistic, with a 250ms work budget and a
// 1ms database lock budget: contention returns without error, leaving the device
// dirty for the next reader and the runner. Call it from the extractor's
// post-commit hook; its failure never affects the extraction.
func RefreshDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time) error {
	budget, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	_, err := refreshDevices(budget, pool, tenantID, []string{deviceID}, false, now.UTC())
	// Only our own opportunistic work deadline is suppressed. Cancellation
	// or timeout of the caller still propagates; its queue remains durable.
	if errors.Is(err, errPresenceBusy) || isLockNotAvailable(err) || (ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded)) {
		return nil
	}
	return err
}

// ReconcileTenant rebuilds the tenant's whole summary, a chunk of devices
// per transaction, and records the policy version it started from as the
// summary version. It is the repair path and the rebuild after a policy
// change; it never holds a lock across chunks.
func ReconcileTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) error {
	now = now.UTC()
	st, err := readPresenceState(ctx, pool, tenantID)
	if err != nil {
		return err
	}
	after := "00000000-0000-0000-0000-000000000000"
	for {
		ids, err := scanStrings(pool.Query(ctx, `
			SELECT id::text FROM devices WHERE tenant_id = $1::uuid AND id > $2::uuid ORDER BY id LIMIT $3
		`, tenantID, after, presenceChunk))
		if err != nil {
			return fmt.Errorf("list tenant devices: %w", err)
		}
		if len(ids) == 0 {
			break
		}
		if _, err := refreshDevices(ctx, pool, tenantID, ids, true, now); err != nil {
			return err
		}
		after = ids[len(ids)-1]
	}
	tag, err := pool.Exec(ctx, `
		INSERT INTO software_unapproved_presence_state (tenant_id, policy_version, summary_version, reconciled_at)
		VALUES ($1::uuid, $2, $2, now())
		ON CONFLICT (tenant_id) DO UPDATE
		    SET summary_version = EXCLUDED.summary_version,
		        reconciled_at = now()
		    WHERE software_unapproved_presence_state.policy_version = EXCLUDED.policy_version
		      AND software_unapproved_presence_state.summary_version <= EXCLUDED.summary_version
	`, tenantID, st.policyVersion)
	if err != nil {
		return fmt.Errorf("record summary version: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSummaryUnusable
	}
	return nil
}

// StaleSummaryTenants lists tenants whose summary lags a policy change.
func StaleSummaryTenants(ctx context.Context, q Querier, limit int) ([]string, error) {
	return scanStrings(q.Query(ctx, `
		SELECT s.tenant_id::text FROM software_unapproved_presence_state s
		JOIN tenants t ON t.id = s.tenant_id
		LEFT JOIN software_unapproved_runner_attempts a
		  ON a.work_kind = 'summary' AND a.tenant_id = s.tenant_id AND a.batch_key = ''
		WHERE s.summary_version < s.policy_version
		ORDER BY a.attempted_at NULLS FIRST, s.policy_changed_at NULLS FIRST, s.tenant_id
		LIMIT $1
	`, limit))
}

// RefreshDirty refreshes up to limit dirty devices across tenants, oldest
// mark first, and drops marks of devices that no longer exist.
func RefreshDirty(ctx context.Context, pool *pgxpool.Pool, limit int, now time.Time) (int, error) {
	if _, err := pool.Exec(ctx, `
		DELETE FROM software_unapproved_presence_dirty dd
		WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.id = dd.device_id)
	`); err != nil {
		return 0, fmt.Errorf("drop orphan dirty marks: %w", err)
	}
	rows, err := pool.Query(ctx, `
		SELECT d.tenant_id::text, dd.device_id::text
		FROM software_unapproved_presence_dirty dd
		JOIN devices d ON d.id = dd.device_id
		ORDER BY dd.dirtied_at, dd.device_id
		LIMIT $1
	`, limit)
	if err != nil {
		return 0, fmt.Errorf("list dirty devices: %w", err)
	}
	byTenant := map[string][]string{}
	var order []string
	for rows.Next() {
		var t, d string
		if err := rows.Scan(&t, &d); err != nil {
			rows.Close()
			return 0, err
		}
		if _, ok := byTenant[t]; !ok {
			order = append(order, t)
		}
		byTenant[t] = append(byTenant[t], d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	total := 0
	for _, t := range order {
		n, err := refreshTenantDevices(ctx, pool, t, byTenant[t], now)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// RefreshTenantDirty refreshes every dirty device of one tenant.
func RefreshTenantDirty(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) (int, error) {
	ids, err := dirtyDevices(ctx, pool, tenantID, 0)
	if err != nil {
		return 0, err
	}
	return refreshTenantDevices(ctx, pool, tenantID, ids, now)
}

func refreshTenantDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, ids []string, now time.Time) (int, error) {
	ids = dedupeSorted(ids)
	total := 0
	for start := 0; start < len(ids); start += presenceChunk {
		end := start + presenceChunk
		if end > len(ids) {
			end = len(ids)
		}
		n, err := refreshDevices(ctx, pool, tenantID, ids[start:end], true, now.UTC())
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// dirtyDevices lists the tenant's dirty devices; limit <= 0 means all.
func dirtyDevices(ctx context.Context, q Querier, tenantID string, limit int) ([]string, error) {
	sql := `
		SELECT dd.device_id::text
		FROM software_unapproved_presence_dirty dd
		JOIN devices d ON d.id = dd.device_id AND d.tenant_id = $1::uuid
		ORDER BY dd.device_id`
	args := []any{tenantID}
	if limit > 0 {
		sql += " LIMIT $2"
		args = append(args, limit)
	}
	out, err := scanStrings(q.Query(ctx, sql, args...))
	if err != nil {
		return nil, fmt.Errorf("list dirty devices: %w", err)
	}
	if out == nil {
		// Never NULL: "NOT (id = ANY(NULL))" would exclude every row.
		out = []string{}
	}
	return out, nil
}

// liveDirty resolves the dirty devices' inventory in the caller's snapshot.
func liveDirty(ctx context.Context, q Querier, tenantID string, dirty []string, asOf time.Time) (*builder, error) {
	pol, err := loadPolicies(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	if !pol.hasUnapproved() {
		return newBuilder(asOf), nil
	}
	return scanInventory(ctx, q, tenantID, dirty, pol, asOf)
}

// ErrSummaryUnusable means the summary cannot answer exactly right now: it
// lags a policy change or too many devices are dirty. UnapprovedOverview then
// falls back to the full computation.
var ErrSummaryUnusable = errors.New("softwaregov: unapproved summary not usable")

// policyAssessments returns the tenant's Unapproved assessments under one
// policy row, from the summary for clean devices and live for dirty ones, in
// the order loadAssessments gives them. The caller's snapshot must be
// consistent (the raise runs it under the tenant alert lock, after making
// the summary current).
func policyAssessments(ctx context.Context, q Querier, tenantID, kind string, policyID int64, asOf time.Time) ([]Assessment, error) {
	dirty, err := dirtyDevices(ctx, q, tenantID, MaxLiveDirtyDevices+1)
	if err != nil {
		return nil, err
	}
	if len(dirty) > MaxLiveDirtyDevices {
		// The caller releases the alert lock and refreshes outside it. Never
		// truncate this list: that would silently drop installed devices.
		return nil, ErrSummaryUnusable
	}
	updated, err := policyUpdatedAt(ctx, q, tenantID, kind, policyID)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `
		SELECT p.device_id::text, p.product_key, p.product_type, p.name, p.platform, p.identifier, p.team_id,
		       p.browser, p.extension_id, p.tap, p.observation_kind, p.observation_source, p.observed_since,
		       COALESCE(d.hostname, ''), COALESCE(d.os, ''), d.last_seen
		FROM software_unapproved_presence p
		JOIN devices d ON d.id = p.device_id AND d.tenant_id = p.tenant_id
		WHERE p.tenant_id = $1::uuid AND p.policy_kind = $2 AND p.policy_id = $3
		  AND NOT (p.device_id = ANY($4::uuid[]))
	`, tenantID, kind, policyID, dirty)
	if err != nil {
		return nil, fmt.Errorf("load policy presence: %w", err)
	}
	b := newBuilder(asOf)
	for rows.Next() {
		var devID, host, osName string
		var p Product
		var since, lastSeen time.Time
		if err := rows.Scan(&devID, &p.ProductKey, &p.Type, &p.Name, &p.Platform, &p.Identifier, &p.TeamID,
			&p.Browser, &p.ExtensionID, &p.Tap, &p.ObservationKind, &p.ObservationSource, &since, &host, &osName, &lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		b.add(p, StateUnapproved, kind, policyID, updated, devID, host, presencePlatform(p, osName), lastSeen, since)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(dirty) > 0 {
		live, err := liveDirty(ctx, q, tenantID, dirty, asOf)
		if err != nil {
			return nil, err
		}
		for k, a := range live.assessments {
			if a.State != StateUnapproved || a.PolicyKind != kind || a.PolicyID != policyID {
				continue
			}
			for devID, pr := range live.presence[k] {
				p := *live.devProduct[k][devID]
				b.add(p, StateUnapproved, kind, policyID, updated, devID, pr.Hostname, pr.Platform, pr.LastSeen, pr.ObservedSince)
			}
		}
	}
	return b.result(), nil
}

// presencePlatform is the Presence.Platform scanInventory records: the
// device platform, "macos" for Homebrew.
func presencePlatform(p Product, osName string) string {
	if p.Type == TypeHomebrewFormula || p.Type == TypeHomebrewCask {
		return "macos"
	}
	return apppolicy.DevicePlatform(osName)
}

// overviewGroup is one Unapproved assessment, aggregated across devices.
type overviewGroup struct {
	product      Product
	policyKind   string
	policyID     int64
	devices      int
	presentSince time.Time
}

type groupKey struct {
	productKey string
	policyKind string
	policyID   int64
}

// summaryOverview answers UnapprovedOverview from the summary, or returns
// ErrSummaryUnusable. q should be a consistent snapshot.
func summaryOverview(ctx context.Context, q Querier, tenantID string, asOf time.Time, limit int) (OverviewSummary, error) {
	out := OverviewSummary{Items: []OverviewItem{}}
	st, err := readPresenceState(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	if !st.current() {
		return out, ErrSummaryUnusable
	}
	dirty, err := dirtyDevices(ctx, q, tenantID, MaxLiveDirtyDevices+1)
	if err != nil {
		return out, err
	}
	if len(dirty) > MaxLiveDirtyDevices {
		return out, ErrSummaryUnusable
	}

	groups := map[groupKey]*overviewGroup{}
	rows, err := q.Query(ctx, `
		SELECT product_key, policy_kind, policy_id, min(product_type), min(name COLLATE "C"),
		       min(platform), min(browser), count(*)::int, min(observed_since)
		FROM software_unapproved_presence
		WHERE tenant_id = $1::uuid AND NOT (device_id = ANY($2::uuid[]))
		GROUP BY product_key, policy_kind, policy_id
	`, tenantID, dirty)
	if err != nil {
		return out, fmt.Errorf("summary groups: %w", err)
	}
	for rows.Next() {
		g := &overviewGroup{}
		if err := rows.Scan(&g.product.ProductKey, &g.policyKind, &g.policyID, &g.product.Type, &g.product.Name,
			&g.product.Platform, &g.product.Browser, &g.devices, &g.presentSince); err != nil {
			rows.Close()
			return out, err
		}
		g.presentSince = g.presentSince.UTC()
		groups[groupKey{g.product.ProductKey, g.policyKind, g.policyID}] = g
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	var devices int
	// GROUP BY permits hash deduplication of the much smaller device set.
	// COUNT(DISTINCT device_id) sorts every product row and can spill to disk
	// once a large policy mark puts many products on each device.
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int FROM (
			SELECT device_id FROM software_unapproved_presence
			WHERE tenant_id = $1::uuid AND NOT (device_id = ANY($2::uuid[]))
			GROUP BY device_id
		) present_devices
	`, tenantID, dirty).Scan(&devices); err != nil {
		return out, fmt.Errorf("summary devices: %w", err)
	}

	if len(dirty) > 0 {
		live, err := liveDirty(ctx, q, tenantID, dirty, asOf)
		if err != nil {
			return out, err
		}
		liveDevices := map[string]bool{}
		for k, a := range live.assessments {
			if a.State != StateUnapproved || len(live.presence[k]) == 0 {
				continue
			}
			gk := groupKey{a.ProductKey, a.PolicyKind, a.PolicyID}
			g, ok := groups[gk]
			if !ok {
				g = &overviewGroup{product: a.Product, policyKind: a.PolicyKind, policyID: a.PolicyID}
				groups[gk] = g
			} else if a.Name < g.product.Name {
				g.product.Name = a.Name
			}
			for devID, pr := range live.presence[k] {
				liveDevices[devID] = true
				g.devices++
				if g.presentSince.IsZero() || pr.ObservedSince.Before(g.presentSince) {
					g.presentSince = pr.ObservedSince
				}
			}
		}
		devices += len(liveDevices)
	}

	products := map[string]bool{}
	list := make([]*overviewGroup, 0, len(groups))
	for _, g := range groups {
		products[g.product.ProductKey] = true
		list = append(list, g)
	}
	out.Products, out.Devices = len(products), devices
	// The order loadAssessments gives Unapproved assessments.
	sort.Slice(list, func(i, j int) bool {
		if list[i].devices != list[j].devices {
			return list[i].devices > list[j].devices
		}
		if list[i].product.Name != list[j].product.Name {
			return list[i].product.Name < list[j].product.Name
		}
		if list[i].product.ProductKey != list[j].product.ProductKey {
			return list[i].product.ProductKey < list[j].product.ProductKey
		}
		return list[i].policyID < list[j].policyID
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	for _, g := range list {
		updated, err := policyUpdatedAt(ctx, q, tenantID, g.policyKind, g.policyID)
		if err != nil {
			return out, err
		}
		mark, err := markInfoFor(ctx, q, tenantID, Assessment{Product: g.product, State: StateUnapproved,
			PolicyKind: g.policyKind, PolicyID: g.policyID, PolicyUpdatedAt: updated})
		if err != nil {
			return out, err
		}
		since := g.presentSince
		if mark.MarkedAt.After(since) {
			since = mark.MarkedAt
		}
		out.Items = append(out.Items, OverviewItem{Type: g.product.Type, ProductKey: g.product.ProductKey,
			Name: g.product.Name, Platform: g.product.Platform, Browser: g.product.Browser,
			DeviceCount: g.devices, Since: since})
	}
	return out, nil
}

// policyUpdatedAt reads a policy row's updated_at, as loadPolicies does.
func policyUpdatedAt(ctx context.Context, q Querier, tenantID, kind string, id int64) (*time.Time, error) {
	var sql string
	switch kind {
	case TypeApplication:
		sql = `SELECT updated_at FROM tenant_app_policies WHERE id = $1 AND tenant_id = $2::uuid`
	case TypeBrowserExtension:
		sql = `SELECT updated_at FROM tenant_extension_policies WHERE id = $1 AND tenant_id = $2::uuid`
	case TypeHomebrewFormula, TypeHomebrewCask:
		sql = `SELECT updated_at FROM tenant_homebrew_policies WHERE id = $1 AND tenant_id = $2::uuid`
	case TypeObservation:
		sql = `SELECT updated_at FROM tenant_observation_policies WHERE id = $1 AND tenant_id = $2::uuid`
	default:
		return nil, fmt.Errorf("softwaregov: unknown policy kind %q", kind)
	}
	var t time.Time
	err := q.QueryRow(ctx, sql, id, tenantID).Scan(&t)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy updated_at: %w", err)
	}
	return &t, nil
}

// txBeginner is satisfied by *pgxpool.Pool.
type txBeginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// inSnapshot runs fn in one read-only repeatable-read transaction when q can
// begin one, so every statement fn issues sees the same committed state.
// Otherwise (q is already a transaction) fn runs on q as is.
func inSnapshot(ctx context.Context, q Querier, fn func(Querier) error) error {
	b, ok := q.(txBeginner)
	if !ok {
		return fn(q)
	}
	tx, err := b.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read-only
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func scanStrings(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func dedupeSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// UnapprovedOverviewFromSummary answers UnapprovedOverview from the summary
// only, never falling back: ErrSummaryUnusable when it cannot. For the
// equivalence tests and diagnostics.
func UnapprovedOverviewFromSummary(ctx context.Context, q Querier, tenantID string, asOf time.Time, limit int) (OverviewSummary, error) {
	var out OverviewSummary
	err := inSnapshot(ctx, q, func(s Querier) error {
		exists, err := hasUnapprovedPolicy(ctx, s, tenantID)
		if err != nil || !exists {
			out = OverviewSummary{Items: []OverviewItem{}}
			return err
		}
		out, err = summaryOverview(ctx, s, tenantID, asOf, limit)
		return err
	})
	return out, err
}

// PolicyPresence is the Unapproved assessments under one policy row as the
// marked alert reads them: the summary for clean devices, live for dirty
// ones. ErrSummaryUnusable when the summary lags a policy change.
func PolicyPresence(ctx context.Context, q Querier, tenantID, kind string, policyID int64, asOf time.Time) ([]Assessment, error) {
	var out []Assessment
	err := inSnapshot(ctx, q, func(s Querier) error {
		st, err := readPresenceState(ctx, s, tenantID)
		if err != nil {
			return err
		}
		if !st.current() {
			return ErrSummaryUnusable
		}
		out, err = policyAssessments(ctx, s, tenantID, kind, policyID, asOf)
		return err
	})
	return out, err
}

// PolicyPresenceFull is PolicyPresence by the full computation: the oracle.
func PolicyPresenceFull(ctx context.Context, q Querier, tenantID, kind string, policyID int64, asOf time.Time) ([]Assessment, error) {
	all, err := loadAssessments(ctx, q, tenantID, "", asOf)
	if err != nil {
		return nil, err
	}
	var out []Assessment
	for _, a := range all {
		if a.State == StateUnapproved && a.PolicyKind == kind && a.PolicyID == policyID && len(a.Devices) > 0 {
			out = append(out, a)
		}
	}
	return out, nil
}
