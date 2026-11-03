//go:build integration

package integration

// PAT-2095 concurrency: ingest never waits on a mark or a summary rebuild, a
// policy change racing a rebuild never leaves a summary that claims to be
// current, and concurrent marks and raises alert each (episode, device) once.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/softwaregov"
)

func presenceTestContext(t *testing.T, budget time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	t.Cleanup(cancel)
	return ctx
}

func rollbackPresenceTestTx(t *testing.T, tx pgx.Tx) {
	t.Helper()
	// Cleanup must work even after the test's context is cancelled. Keep
	// it independent but bounded, and surface a real rollback failure.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Errorf("transaction cleanup failed: %v", err)
	}
}

func presenceDirty(t *testing.T, dev string) bool {
	t.Helper()
	var ok bool
	if err := env.pool.QueryRow(presenceTestContext(t, 5*time.Second),
		`SELECT EXISTS (SELECT 1 FROM software_unapproved_presence_dirty WHERE device_id = $1::uuid)`, dev).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// pg_locks exposes lock state without pg_stat_activity query-text visibility
// or pg_read_all_stats. Wait for a real transaction blocked by our own xid.
func waitForPresenceTransactionWait(t *testing.T, ctx context.Context, blocker pgx.Tx) {
	t.Helper()
	var xid string
	// pg_locks exposes xid (32 bit), while txid_current includes its epoch.
	if err := blocker.QueryRow(ctx, `SELECT (txid_current() % 4294967296)::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := env.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks WHERE locktype = 'transactionid'
			AND transactionid = $1::xid AND NOT granted)`, xid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh never reached the held transaction lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForPresenceAlertLock(t *testing.T, ctx context.Context, blocker pgx.Tx) {
	t.Helper()
	var pid int
	if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := env.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks b JOIN pg_locks w
			ON w.locktype = b.locktype AND w.database = b.database
			AND w.classid = b.classid AND w.objid = b.objid AND w.objsubid = b.objsubid
			WHERE b.pid = $1 AND b.locktype = 'advisory' AND b.granted AND NOT w.granted)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("raise never reached the held alert lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertPresenceAlertUnlocked(t *testing.T, tenantID string) {
	t.Helper()
	// pgx cancellation marks the connection closed synchronously, so the
	// pool destroys it instead of releasing it for reuse. CancelRequest and
	// socket cleanup finish asynchronously: the server may briefly grant its
	// queued lock after the blocker commits, before processing Terminate.
	// Require that server-side ownership disappears within a bounded window.
	ctx := presenceTestContext(t, 5*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	retries := 0
	for {
		var held bool
		err := env.pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks, (SELECT hashtextextended('softwaregov-alerts:' || $1, 0) AS k) key
			WHERE locktype = 'advisory' AND granted AND objsubid = 1
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			AND classid::bigint = ((key.k >> 32) & 4294967295)
			AND objid::bigint = (key.k & 4294967295))`, tenantID).Scan(&held)
		if err != nil || (held && time.Now().After(deadline)) {
			t.Fatalf("raise retained a tenant advisory lock after cleanup: held=%v err=%v", held, err)
		}
		if !held {
			if retries > 0 {
				t.Logf("cancelled backend released its advisory lock after %d cleanup polls", retries)
			}
			return
		}
		retries++
		time.Sleep(10 * time.Millisecond)
	}
}

// within runs fn and fails if it takes longer than d, which here means it
// waited on a lock it must never wait on.
func within(t *testing.T, d time.Duration, what string, fn func(ctx context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := fn(ctx); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if took := time.Since(start); took > d {
		t.Fatalf("%s took %s: it waited on a lock", what, took)
	}
}

func assertSummaryMatchesFull(t *testing.T, tenantID, label string) {
	t.Helper()
	ctx := presenceTestContext(t, 20*time.Second)
	asOf := time.Now()
	full, err := softwaregov.UnapprovedOverviewFull(ctx, env.pool, tenantID, asOf, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := softwaregov.UnapprovedOverview(ctx, env.pool, tenantID, asOf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := overviewString(full), overviewString(got); a != b {
		t.Fatalf("%s: overview differs from the full computation\nfull:\n%s\ngot:\n%s", label, a, b)
	}
}

func TestUnapprovedPresenceIngestNeverWaits(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "nowait", "")
	dev := govDevice(t, g.id, "nowait-mac", "macOS", time.Now())
	govApp(t, dev, "Nowait App", "com.nowait.app", "NOWAITTEAM")
	var pid int64
	if err := env.pool.QueryRow(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.nowait.app', 'any', 'unapproved') RETURNING id`, g.id).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}

	// 1. A policy write in flight (a mark's transaction holds the tenant's
	// state row until it commits).
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx)
	if _, err := tx.Exec(ctx, `UPDATE tenant_app_policies SET policy = 'approved' WHERE id = $1`, pid); err != nil {
		t.Fatal(err)
	}
	within(t, 500*time.Millisecond, "inventory write during a policy write", func(ctx context.Context) error {
		_, err := env.pool.Exec(ctx, `INSERT INTO device_apps (device_id, name, identifier, version) VALUES ($1::uuid, 'Two', 'com.nowait.two', '1')`, dev)
		return err
	})
	within(t, 500*time.Millisecond, "ingest refresh during a policy write", func(ctx context.Context) error {
		return softwaregov.RefreshDevice(ctx, env.pool, g.id, dev, time.Now())
	})
	if !presenceDirty(t, dev) {
		t.Fatal("a refresh that could not read a stable policy version cleared the dirty mark")
	}
	if _, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// 2. A summary rebuild holding the device.
	tx2, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx2)
	if _, err := tx2.Exec(ctx, `SELECT 1 FROM software_unapproved_presence_devices WHERE device_id = $1::uuid FOR UPDATE`, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := tx2.Exec(ctx, `DELETE FROM software_unapproved_presence WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	within(t, 500*time.Millisecond, "inventory write during a rebuild", func(ctx context.Context) error {
		_, err := env.pool.Exec(ctx, `UPDATE device_apps SET name = 'Nowait App Renamed' WHERE device_id = $1::uuid AND identifier = 'com.nowait.app'`, dev)
		return err
	})
	within(t, 500*time.Millisecond, "ingest refresh during a rebuild", func(ctx context.Context) error {
		return softwaregov.RefreshDevice(ctx, env.pool, g.id, dev, time.Now())
	})
	if !presenceDirty(t, dev) {
		t.Fatal("a skipped refresh cleared the dirty mark")
	}
	// Readers stay exact meanwhile: the dirty device is resolved live.
	assertSummaryMatchesFull(t, g.id, "rebuild in flight")
	if err := tx2.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// 3. INSERT ON CONFLICT can wait before SKIP LOCKED, for example on
	// an uncommitted deletion of the per-device serialisation row.
	tx3, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx3)
	if _, err := tx3.Exec(ctx, `DELETE FROM software_unapproved_presence_devices WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	within(t, 500*time.Millisecond, "ingest refresh during insert conflict", func(ctx context.Context) error {
		return softwaregov.RefreshDevice(ctx, env.pool, g.id, dev, time.Now())
	})
	if !presenceDirty(t, dev) {
		t.Fatal("a refresh with an insert conflict cleared the dirty mark")
	}
	if err := tx3.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	if err := softwaregov.RefreshDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
		t.Fatal(err)
	}
	if presenceDirty(t, dev) {
		t.Fatal("an unobstructed refresh left the device dirty")
	}
	if _, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, g.id, time.Now(), 0); err != nil {
		t.Fatalf("summary unusable after refresh: %v", err)
	}
	assertSummaryMatchesFull(t, g.id, "after refresh")
}

// A rebuild that starts before a policy write commits reads policies the
// write changes; it must not then record the summary as current.
func TestUnapprovedPresencePolicyChangeDuringRebuild(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	g := newGovTenant(t, "pcrace", "")
	var devs []string
	for i := 0; i < 3; i++ {
		d := govDevice(t, g.id, "pcrace-"+strings.Repeat("x", i+1), "macOS", time.Now())
		govApp(t, d, "Race Target", "com.pcrace.target", "")
		devs = append(devs, d)
	}
	govApp(t, devs[0], "Race Other", "com.pcrace.other", "")
	if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.pcrace.other', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}

	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx)
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.pcrace.target', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()) }()
	waitForPresenceTransactionWait(t, ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, softwaregov.ErrSummaryUnusable) {
		t.Fatalf("rebuild did not surface its rejected version guard: %v", err)
	}
	if _, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, g.id, time.Now(), 0); !errors.Is(err, softwaregov.ErrSummaryUnusable) {
		t.Fatalf("a rebuild that started before the policy write claims to be current: %v", err)
	}
	assertSummaryMatchesFull(t, g.id, "fallback while stale")
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	sum, err := softwaregov.UnapprovedOverviewFromSummary(ctx, env.pool, g.id, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Products != 2 || sum.Devices != 3 {
		t.Fatalf("after the second rebuild: %s", overviewString(sum))
	}
	assertSummaryMatchesFull(t, g.id, "after rebuild")
}

// A real inventory transaction commits after refresh read the dirty sequence
// and inventory, but before it can publish its summary rows. The refresh must
// retain the new dirty mark, and readers must resolve the committed write.
func TestUnapprovedPresenceInventoryWriteDuringRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	g := newGovTenant(t, "inventoryrace", "")
	dev := govDevice(t, g.id, "inventoryrace", "macOS", time.Now())
	govApp(t, dev, "Before", "com.inventoryrace.app", "")
	if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.inventoryrace.app', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Leave an older committed dirty mark for the refresh to read.
	if _, err := env.pool.Exec(ctx, `UPDATE device_apps SET name = 'During' WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM software_unapproved_presence WHERE device_id = $1::uuid FOR UPDATE`, dev); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := softwaregov.RefreshTenantDirty(ctx, env.pool, g.id, time.Now())
		errc <- err
	}()
	// The only row held by blocker is the old presence row. Waiting on it
	// proves the refresh has finished reading both dirty marks and inventory.
	waitForPresenceTransactionWait(t, ctx, blocker)
	within(t, 500*time.Millisecond, "inventory write during active refresh", func(ctx context.Context) error {
		_, err := env.pool.Exec(ctx, `UPDATE device_apps SET name = 'After' WHERE device_id = $1::uuid`, dev)
		return err
	})
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !presenceDirty(t, dev) {
		t.Fatal("refresh cleared the mark from a concurrent inventory transaction")
	}
	assertSummaryMatchesFull(t, g.id, "inventory committed during refresh")
	if _, err := softwaregov.RefreshTenantDirty(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if presenceDirty(t, dev) {
		t.Fatal("repair retained the dirty mark without another writer")
	}
	assertSummaryMatchesFull(t, g.id, "after inventory race repair")
}

// A policy change commits after summary preparation but before the raise
// acquires its alert lock. Revalidation must prevent the stale summary from
// sending an alert about a now-approved product.
func TestUnapprovedPresencePolicyChangeBeforeRaiseLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	g := newGovTenant(t, "raisepolicyrace", "")
	dev := govDevice(t, g.id, "raisepolicyrace", "macOS", time.Now())
	govApp(t, dev, "Race App", "com.raisepolicyrace.app", "RACETEAM01")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.raisepolicyrace.app", "RACETEAM01"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	var episodeID int64
	if err := env.pool.QueryRow(ctx, `SELECT id FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND raised_at IS NULL`, g.id).Scan(&episodeID); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, g.id); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := softwaregov.RaiseEpisodes(ctx, env.pool, g.id, []int64{episodeID}, time.Now())
		errc <- err
	}()
	waitForPresenceAlertLock(t, ctx, blocker)
	if _, err := env.pool.Exec(ctx, `UPDATE tenant_app_policies SET policy = 'approved'
		WHERE tenant_id = $1::uuid`, g.id); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if got := govAlerts(t, g.id); len(got) != 0 {
		t.Fatalf("stale presence raised alerts after approval: %+v", got)
	}
}

func TestUnapprovedPresenceDirtyBurstBeforeRaiseLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	g := newGovTenant(t, "raisedirtyburst", "")
	dev := govDevice(t, g.id, "raisedirtyburst", "macOS", time.Now())
	govApp(t, dev, "Burst App", "com.raisedirtyburst.app", "BURSTTEAM1")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.raisedirtyburst.app", "BURSTTEAM1"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	var episodeID int64
	if err := env.pool.QueryRow(ctx, `SELECT id FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND raised_at IS NULL`, g.id).Scan(&episodeID); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, g.id); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := softwaregov.RaiseEpisodes(ctx, env.pool, g.id, []int64{episodeID}, time.Now())
		errc <- err
	}()
	waitForPresenceAlertLock(t, ctx, blocker)
	const burst = softwaregov.MaxLiveDirtyDevices + 1
	if _, err := env.pool.Exec(ctx, `WITH inserted AS (
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, last_seen)
		SELECT $1::uuid, 'BURST-' || $1 || '-' || n, gen_random_uuid(), 'burst-' || n, 'macOS', '15.1', now()
		FROM generate_series(1, $2::int) n RETURNING id)
		INSERT INTO device_apps (device_id, name, identifier, version, team_id)
		SELECT id, 'Burst App', 'com.raisedirtyburst.app', '1', 'BURSTTEAM1' FROM inserted`, g.id, burst); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	alerts := govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].Payload.DeviceCount != burst+1 {
		t.Fatalf("dirty burst omitted devices: %+v", alerts)
	}
	var dirty, tracked int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM software_unapproved_presence_dirty dd
		JOIN devices d ON d.id = dd.device_id WHERE d.tenant_id = $1::uuid`, g.id).Scan(&dirty); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM software_unapproved_alerted_devices
		WHERE episode_id = $1`, episodeID).Scan(&tracked); err != nil {
		t.Fatal(err)
	}
	if dirty != 0 || tracked != burst+1 {
		t.Fatalf("burst was not repaired before raise or tracked completely: dirty=%d tracked=%d", dirty, tracked)
	}
}

func TestUnapprovedPresenceDetectDefersBehindMark(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "deferdetect", "")
	dev := govDevice(t, g.id, "deferdetect", "macOS", time.Now())
	govApp(t, dev, "Deferred App", "com.deferdetect.app", "DEFERTEAM1")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.deferdetect.app", "DEFERTEAM1"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	drainUnapprovedRaises(t)
	newDev := govDevice(t, g.id, "deferdetect-new", "macOS", time.Now())
	govApp(t, newDev, "Deferred App", "com.deferdetect.app", "DEFERTEAM1")
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, g.id); err != nil {
		t.Fatal(err)
	}
	within(t, 500*time.Millisecond, "DetectOnDevice during marked raise", func(ctx context.Context) error {
		got, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, newDev, time.Now())
		if err == nil && got.Skipped != "alerts_busy" {
			t.Fatalf("busy detect was not deferred: %+v", got)
		}
		return err
	})
	var queued bool
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid)`, newDev).Scan(&queued); err != nil || !queued {
		t.Fatalf("busy detection was not durable: queued=%v err=%v", queued, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 5000, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 5000, time.Now()); err != nil {
		t.Fatal(err)
	}
	alerts := govAlerts(t, g.id)
	if len(alerts) != 2 || alerts[1].Trigger != "observed" || alerts[1].DeviceID == nil || *alerts[1].DeviceID != newDev {
		t.Fatalf("deferred inventory was lost or duplicated: %+v", alerts)
	}
}

func TestUnapprovedPresenceRunnerFailureThenRetry(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	drainUnapprovedRaises(t)
	g := newGovTenant(t, "runnerretry", "it@runnerretry.example")
	dev := govDevice(t, g.id, "runnerretry", "macOS", time.Now())
	govApp(t, dev, "Retry App", "com.runnerretry.app", "RETRYTEAM1")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.runnerretry.app", "RETRYTEAM1"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, g.id); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Minute)
	mail := &fakeMailer{}
	runner := softwaregov.NewRunner(env.pool, mail, softwaregov.WithClock(func() time.Time { return now }))
	failed, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- runner.RunMarked(failed) }()
	waitForPresenceAlertLock(t, failed, blocker)
	cancel()
	err = <-errc
	if err == nil {
		t.Fatal("runner did not report cancellation while acquiring the alert lock")
	}
	if got := govAlerts(t, g.id); len(got) != 0 {
		t.Fatalf("failed raise committed alerts: %+v", got)
	}
	var pending bool
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND raised_at IS NULL)`, g.id).Scan(&pending); err != nil || !pending {
		t.Fatalf("failed runner lost the pending episode: pending=%v err=%v", pending, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertPresenceAlertUnlocked(t, g.id)
	mail.err = errors.New("temporary mail failure")
	if err := runner.RunMarked(ctx); err != nil {
		t.Fatal(err)
	}
	alerts := govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].EmailState != "pending" || len(mail.to("it@runnerretry.example")) != 0 {
		t.Fatalf("failed delivery was not retained for retry: %+v", alerts)
	}
	mail.err = nil
	now = now.Add(time.Hour)
	if err := runner.RunMarked(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.RunMarked(ctx); err != nil {
		t.Fatal(err)
	}
	alerts = govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].EmailState != "sent" || len(mail.to("it@runnerretry.example")) != 1 {
		t.Fatalf("retry lost or duplicated alert delivery: %+v", alerts)
	}
	assertPresenceAlertUnlocked(t, g.id)
}

func TestUnapprovedPresenceMigrationPrerequisites(t *testing.T) {
	var composite, identifier, authority bool
	err := env.pool.QueryRow(presenceTestContext(t, 5*time.Second), `SELECT
		EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'devices'::regclass AND conname = 'devices_id_tenant_uq' AND contype = 'u'),
		EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'device_apps' AND column_name = 'identifier_kind'),
		EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'homebrew_device_state' AND column_name = 'authority_at')`).Scan(&composite, &identifier, &authority)
	if err != nil || !composite || !identifier || !authority {
		t.Fatalf("0202 prerequisites: 0111 composite=%v 0110 identifier=%v 0164 authority=%v err=%v", composite, identifier, authority, err)
	}
	var orderedIndexes int
	if err := env.pool.QueryRow(presenceTestContext(t, 5*time.Second), `SELECT count(*) FROM pg_indexes
		WHERE schemaname = current_schema() AND indexname IN
		('software_unapproved_presence_dirty_order_idx', 'software_unapproved_detection_queue_order_idx')`).Scan(&orderedIndexes); err != nil || orderedIndexes != 2 {
		t.Fatalf("ordered sweep indexes=%d err=%v", orderedIndexes, err)
	}
}

func TestUnapprovedPresenceLifecycleDeferredAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	g := newGovTenant(t, "deferredauthority", "")
	dev := govDevice(t, g.id, "deferredauthority", "macOS", time.Now())
	govApp(t, dev, "Authority App", "com.deferredauthority.app", "AUTHTEAM01")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.deferredauthority.app", "AUTHTEAM01"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	drainUnapprovedRaises(t)
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx)
	if _, err := tx.Exec(ctx, `DELETE FROM device_apps WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.QueueDeviceCheckTx(ctx, tx, dev, true, true); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('softwaregov-alerts:' || $1, 0))`, g.id); err != nil {
		t.Fatal(err)
	}
	within(t, 500*time.Millisecond, "lifecycle during marked raise", func(ctx context.Context) error {
		got, err := softwaregov.ReconcileDevice(ctx, env.pool, g.id, dev, softwaregov.DeviceAuthority{AppsComplete: true}, time.Now())
		if err == nil && got.Skipped != "alerts_busy" {
			t.Fatalf("busy lifecycle was not deferred: %+v", got)
		}
		return err
	})
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 5000, time.Now()); err != nil {
		t.Fatal(err)
	}
	var status, reason string
	if err := env.pool.QueryRow(ctx, `SELECT status, COALESCE(resolved_reason, '')
		FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid`, dev).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "resolved" || reason != "not_observed" {
		t.Fatalf("deferred authoritative absence was lost: status=%s reason=%s", status, reason)
	}
}

func TestUnapprovedPresenceQueueSequencePreservesNewWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	g := newGovTenant(t, "queuesequence", "")
	dev := govDevice(t, g.id, "queuesequence", "macOS", time.Now())
	govApp(t, dev, "Sequence App", "com.queuesequence.app", "SEQTEAM001")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.queuesequence.app", "SEQTEAM001"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	drainUnapprovedRaises(t)
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx)
	if _, err := tx.Exec(ctx, `DELETE FROM device_apps WHERE device_id = $1::uuid`, dev); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.QueueDeviceCheckTx(ctx, tx, dev, true, true); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid FOR UPDATE`, dev); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := softwaregov.ProcessDeviceCheck(ctx, env.pool, g.id, dev, softwaregov.DeviceAuthority{}, time.Now())
		errc <- err
	}()
	waitForPresenceTransactionWait(t, ctx, blocker)
	// A newer partial report supersedes the old complete report's authority.
	newer, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, newer)
	if err := softwaregov.QueueDeviceCheckTx(ctx, newer, dev, false, true); err != nil {
		t.Fatal(err)
	}
	if err := newer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	var queued bool
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid)`, dev).Scan(&queued); err != nil || !queued {
		t.Fatalf("old acknowledgement deleted newer work: queued=%v err=%v", queued, err)
	}
	if _, _, err := softwaregov.ProcessDeviceCheck(ctx, env.pool, g.id, dev, softwaregov.DeviceAuthority{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := env.pool.QueryRow(ctx, `SELECT status FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid`, dev).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid)`, dev).Scan(&queued); err != nil || queued || status != "open" {
		t.Fatalf("stable queue did not drain or stale authority closed alert: queued=%v status=%s err=%v", queued, status, err)
	}
}

func TestUnapprovedPresenceQueueHonoursEvidenceGate(t *testing.T) {
	ctx := presenceTestContext(t, 15*time.Second)
	g := newGovTenant(t, "queueevidence", "")
	dev := govDevice(t, g.id, "queueevidence", "macOS", time.Now())
	govApp(t, dev, "Evidence App", "com.queueevidence.app", "EVTEAM0001")
	if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.queueevidence.app', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	tx, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, tx)
	if err := softwaregov.QueueDeviceCheckTx(ctx, tx, dev, false, false); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	raised, _, err := softwaregov.ProcessDeviceCheck(ctx, env.pool, g.id, dev, softwaregov.DeviceAuthority{}, time.Now())
	if err != nil || raised.Skipped != "evidence_not_authoritative" || len(govAlerts(t, g.id)) != 0 {
		t.Fatalf("deferred check announced non-authoritative evidence: result=%+v err=%v", raised, err)
	}
}

func TestUnapprovedPresencePolicyTimestampAndMissingState(t *testing.T) {
	ctx := presenceTestContext(t, 15*time.Second)
	g := newGovTenant(t, "presencestamp", "")
	dev := govDevice(t, g.id, "presencestamp", "macOS", time.Now())
	govApp(t, dev, "Stamp App", "com.presencestamp.app", "STAMPTEAM1")
	stamp := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	var pid int64
	if err := env.pool.QueryRow(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, updated_at)
		VALUES ($1::uuid, 'com.presencestamp.app', 'any', 'unapproved', $2) RETURNING id`, g.id, stamp).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, dirty := range []bool{false, true} {
		if dirty {
			if _, err := env.pool.Exec(ctx, `UPDATE device_apps SET name = 'Stamp App Renamed' WHERE device_id = $1::uuid`, dev); err != nil {
				t.Fatal(err)
			}
		}
		got, err := softwaregov.PolicyPresence(ctx, env.pool, g.id, "application", pid, time.Now())
		if err != nil || len(got) != 1 || got[0].PolicyUpdatedAt == nil || !got[0].PolicyUpdatedAt.Equal(stamp) {
			t.Fatalf("dirty=%v: timestamp not preserved: %+v, %v", dirty, got, err)
		}
	}
	if _, err := env.pool.Exec(ctx, `DELETE FROM software_unapproved_presence_state WHERE tenant_id = $1::uuid`, g.id); err != nil {
		t.Fatal(err)
	}
	if _, err := softwaregov.PolicyPresence(ctx, env.pool, g.id, "application", pid, time.Now()); !errors.Is(err, softwaregov.ErrSummaryUnusable) {
		t.Fatalf("missing state was treated as current: %v", err)
	}
	if err := softwaregov.ReconcileTenant(ctx, env.pool, g.id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := softwaregov.PolicyPresence(ctx, env.pool, g.id, "application", pid, time.Now()); err != nil {
		t.Fatalf("rebuilt missing state unusable: %v", err)
	}
}

func TestUnapprovedDeferredFailureDoesNotStarve(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "deferredpoison", "")
	bad := govDevice(t, g.id, "deferredpoison-bad", "macOS", time.Now())
	good := govDevice(t, g.id, "deferredpoison-good", "macOS", time.Now())
	if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.deferredpoison.app', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{bad, good} {
		govApp(t, dev, "Poison App", "com.deferredpoison.app", "POISONTEAM")
		if _, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	var product []byte
	if err := env.pool.QueryRow(ctx, `SELECT product FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid`, bad).Scan(&product); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := env.pool.Exec(cleanupCtx, `UPDATE software_unapproved_alerted_devices
			SET product = $2::jsonb WHERE device_id = $1::uuid`, bad, string(product)); err != nil {
			t.Errorf("poison product cleanup: %v", err)
		}
	})
	// Respect the DB's object-shape constraint while giving Product's
	// string Name field a numeric value its decoder must reject.
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_alerted_devices SET product = '{"name":123}'::jsonb WHERE device_id = $1::uuid`, bad); err != nil {
		t.Fatal(err)
	}
	for i, dev := range []string{bad, good} {
		if _, err := env.pool.Exec(ctx, `INSERT INTO software_unapproved_detection_queue (device_id, seq, queued_at)
			VALUES ($1::uuid, txid_current(), $2) ON CONFLICT (device_id) DO UPDATE
			SET seq = EXCLUDED.seq, queued_at = EXCLUDED.queued_at`, dev, time.Date(1900, 1, 1, 0, 0, i, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 2, time.Now()); err == nil || !strings.Contains(err.Error(), bad) {
		t.Fatalf("failed device not reported: %v", err)
	}
	var retained, drained, rotated bool
	if err := env.pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid),
		NOT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $2::uuid),
		EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid AND queued_at > '2000-01-01')`, bad, good).Scan(&retained, &drained, &rotated); err != nil || !retained || !drained || !rotated {
		t.Fatalf("failure lost work or starved healthy check: retained=%v drained=%v rotated=%v err=%v", retained, drained, rotated, err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_alerted_devices SET product = $2::jsonb WHERE device_id = $1::uuid`, bad, string(product)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_detection_queue SET queued_at = '1900-01-01' WHERE device_id = $1::uuid`, bad); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 1, time.Now()); err != nil {
		t.Fatalf("retained failed work could not retry: %v", err)
	}
}

func TestUnapprovedDeferredRowLockDoesNotStarve(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "deferredrowlock", "")
	bad := govDevice(t, g.id, "deferredrowlock-bad", "macOS", time.Now())
	good := govDevice(t, g.id, "deferredrowlock-good", "macOS", time.Now())
	if _, err := env.pool.Exec(ctx, `INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, 'com.deferredrowlock.app', 'any', 'unapproved')`, g.id); err != nil {
		t.Fatal(err)
	}
	for i, dev := range []string{bad, good} {
		govApp(t, dev, "Row Lock App", "com.deferredrowlock.app", "ROWLOCKTEAM")
		if _, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
			t.Fatal(err)
		}
		tx, err := env.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackPresenceTestTx(t, tx)
		if _, err := tx.Exec(ctx, `DELETE FROM device_apps WHERE device_id = $1::uuid`, dev); err != nil {
			t.Fatal(err)
		}
		if err := softwaregov.QueueDeviceCheckTx(ctx, tx, dev, true, true); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE software_unapproved_detection_queue SET queued_at = $2 WHERE device_id = $1::uuid`,
			dev, time.Date(1900, 1, 1, 0, 0, i, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var originalSeq int64
	if err := env.pool.QueryRow(ctx, `SELECT seq FROM software_unapproved_detection_queue WHERE device_id = $1::uuid`, bad).Scan(&originalSeq); err != nil {
		t.Fatal(err)
	}
	blocker, err := env.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackPresenceTestTx(t, blocker)
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM software_unapproved_alerted_devices WHERE device_id = $1::uuid FOR UPDATE`, bad); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- softwaregov.DetectDeferred(ctx, env.pool, 2, time.Now()) }()
	waitForPresenceTransactionWait(t, ctx, blocker)
	if err := <-errc; !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), bad) {
		t.Fatalf("blocked device not reported: %v", err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("deferred pass exhausted its parent context: %v", err)
	}
	var retained, drained, rotated, resolved bool
	if err := env.pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid AND seq = $3),
		NOT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $2::uuid),
		EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid AND queued_at > '2000-01-01'),
		EXISTS (SELECT 1 FROM software_unapproved_alerted_devices WHERE device_id = $2::uuid AND status = 'resolved' AND resolved_reason = 'not_observed')`,
		bad, good, originalSeq).Scan(&retained, &drained, &rotated, &resolved); err != nil || !retained || !drained || !rotated || !resolved {
		t.Fatalf("blocked check lost work or starved healthy lifecycle: retained=%v drained=%v rotated=%v resolved=%v err=%v", retained, drained, rotated, resolved, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `UPDATE software_unapproved_detection_queue SET queued_at = '1900-01-01' WHERE device_id = $1::uuid`, bad); err != nil {
		t.Fatal(err)
	}
	if err := softwaregov.DetectDeferred(ctx, env.pool, 1, time.Now()); err != nil {
		t.Fatalf("timed-out work could not retry after unlock: %v", err)
	}
	var pending bool
	if err := env.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM software_unapproved_detection_queue WHERE device_id = $1::uuid)`, bad).Scan(&pending); err != nil || pending {
		t.Fatalf("unlocked check remained queued: pending=%v err=%v", pending, err)
	}
}

func TestUnapprovedMarkedBatchWaitsForAllRaises(t *testing.T) {
	ctx := presenceTestContext(t, 25*time.Second)
	drainUnapprovedRaises(t)
	g := newGovTenant(t, "batchfailure", "it@batchfailure.example")
	dev := govDevice(t, g.id, "batchfailure", "macOS", time.Now())
	govApp(t, dev, "Batch A", "com.batchfailure.a", "BATCHFAILA")
	govApp(t, dev, "Batch B", "com.batchfailure.b", "BATCHFAILB")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.batchfailure.a", "BATCHFAILA"), macApp("com.batchfailure.b", "BATCHFAILB"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	rows, err := env.pool.Query(ctx, `SELECT id FROM software_unapproved_episodes WHERE tenant_id = $1::uuid ORDER BY id`, g.id)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) != 2 {
		t.Fatalf("episodes=%v err=%v", ids, err)
	}
	now := time.Now().Add(time.Minute)
	first, err := softwaregov.RaiseEpisodes(ctx, env.pool, g.id, ids[:1], now)
	if err != nil || first.Devices != 1 {
		t.Fatalf("initial raise=%+v err=%v", first, err)
	}
	// Force only the remaining episode to fail, without cancelling the
	// runner's context (which would also prevent exercising email delivery).
	name := "pat2095_batch_failure_" + randomHex(4)
	ident := pgx.Identifier{name}.Sanitize()
	ddl := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.id = %d AND NEW.raised_at IS NOT NULL THEN RAISE EXCEPTION 'test raise failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER %s BEFORE UPDATE ON software_unapproved_episodes FOR EACH ROW EXECUTE FUNCTION %s()`, ident, ids[1], ident, ident)
	if _, err := env.pool.Exec(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := env.pool.Exec(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON software_unapproved_episodes; DROP FUNCTION IF EXISTS %s()`, ident, ident))
		return err
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("failure trigger cleanup: %v", err)
		}
	})
	mail := &fakeMailer{}
	runner := softwaregov.NewRunner(env.pool, mail, softwaregov.WithClock(func() time.Time { return now }))
	if err := runner.RunMarked(ctx); err == nil {
		t.Fatal("runner did not surface failed remaining raise")
	}
	if len(mail.to("it@batchfailure.example")) != 0 {
		t.Fatal("partial marked batch was emailed before all raises completed")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	// Seed a pre-existing ledger pair for the still-unraised second
	// episode. Do not reset a completed episode: its existing marked
	// alert would (correctly) violate marked_uq on a forced second raise.
	if _, err := env.pool.Exec(ctx, `INSERT INTO software_unapproved_alerted_devices
		(episode_id, device_id, tenant_id, alert_id, alerted_at, status_changed_at, product)
		SELECT $2, device_id, tenant_id, alert_id, alerted_at, status_changed_at, product
		FROM software_unapproved_alerted_devices WHERE episode_id = $1`, ids[0], ids[1]); err != nil {
		t.Fatal(err)
	}
	replay, err := softwaregov.RaiseEpisodes(ctx, env.pool, g.id, ids[1:], now)
	if err != nil || replay.Devices != 0 || len(replay.AlertIDs) != 1 {
		t.Fatalf("conflicting ledger insert counted: %+v err=%v", replay, err)
	}
	if err := runner.RunMarked(ctx); err != nil {
		t.Fatal(err)
	}
	if len(mail.to("it@batchfailure.example")) != 1 {
		t.Fatal("complete marked batch did not produce exactly one email")
	}
}

// Two marks at once, raised by two runners at once while ingest runs: one
// marked alert per product, each (episode, device) tracked exactly once.
func TestUnapprovedConcurrentMarksAndRaises(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "twomarks", "it@twomarks.example")
	d := make([]string, 4)
	for i := range d {
		d[i] = govDevice(t, g.id, "twomarks-0"+string(rune('1'+i)), "macOS", time.Now())
	}
	govApp(t, d[0], "Mark A", "com.twomarks.a", "TWOMARKSAA")
	govApp(t, d[1], "Mark A", "com.twomarks.a", "TWOMARKSAA")
	govApp(t, d[1], "Mark B", "com.twomarks.b", "TWOMARKSBB")
	govApp(t, d[2], "Mark B", "com.twomarks.b", "TWOMARKSBB")
	govApp(t, d[3], "Mark C", "com.twomarks.c", "TWOMARKSCC")

	var wg sync.WaitGroup
	bodies := []string{
		approvalBody("unapproved", "", macApp("com.twomarks.a", "TWOMARKSAA")),
		approvalBody("unapproved", "", macApp("com.twomarks.b", "TWOMARKSBB"), macApp("com.twomarks.c", "TWOMARKSCC")),
	}
	statuses := make([]int, len(bodies))
	for i, b := range bodies {
		wg.Add(1)
		go func(i int, b string) {
			defer wg.Done()
			statuses[i], _ = putApprovals(t, g.adminToken, b)
		}(i, b)
	}
	wg.Wait()
	for i, s := range statuses {
		if s != http.StatusOK {
			t.Fatalf("mark %d = %d", i, s)
		}
	}
	if n := len(govAlerts(t, g.id)); n != 0 {
		t.Fatalf("the request path raised %d alerts", n)
	}

	// Two raises and an ingest, all at once.
	errs := make(chan error, 3)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- softwaregov.RaiseUnraised(ctx, env.pool, time.Now())
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := softwaregov.RefreshDevice(ctx, env.pool, g.id, d[1], time.Now()); err != nil {
			errs <- err
			return
		}
		_, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, d[1], time.Now())
		errs <- err
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Whatever ran first, a later ingest and raise add nothing.
	for _, dev := range d {
		if _, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	drainUnapprovedRaises(t)

	alerts := govAlerts(t, g.id)
	marked := map[string]int{}
	for _, a := range alerts {
		if a.Trigger != "marked" {
			t.Fatalf("unexpected %s alert: %+v", a.Trigger, a)
		}
		for _, p := range a.Payload.Products {
			marked[p.ProductKey]++
		}
	}
	if len(alerts) != 3 || len(marked) != 3 {
		t.Fatalf("alerts = %d, products = %v", len(alerts), marked)
	}
	rows, err := env.pool.Query(ctx, `
		SELECT ad.device_id::text, ad.product->>'product_key'
		FROM software_unapproved_alerted_devices ad WHERE ad.tenant_id = $1::uuid`, g.id)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var dev, key string
		if err := rows.Scan(&dev, &key); err != nil {
			t.Fatal(err)
		}
		got = append(got, key+"@"+dev)
	}
	rows.Close()
	want := []string{
		"application:macos:com.twomarks.a:TWOMARKSAA@" + d[0], "application:macos:com.twomarks.a:TWOMARKSAA@" + d[1],
		"application:macos:com.twomarks.b:TWOMARKSBB@" + d[1], "application:macos:com.twomarks.b:TWOMARKSBB@" + d[2],
		"application:macos:com.twomarks.c:TWOMARKSCC@" + d[3],
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("tracked alerts\n got %v\nwant %v", got, want)
	}
}

// A device that reports the product while its marked alert is still queued
// is deferred by DetectOnDevice and then listed by the marked alert, dirty
// or not, and never alerted twice.
func TestUnapprovedRaiseListsDevicesIngestedWhileQueued(t *testing.T) {
	ctx := presenceTestContext(t, 20*time.Second)
	g := newGovTenant(t, "queued", "")
	d1 := govDevice(t, g.id, "queued-01", "macOS", time.Now())
	d2 := govDevice(t, g.id, "queued-02", "macOS", time.Now())
	d3 := govDevice(t, g.id, "queued-03", "macOS", time.Now())
	govApp(t, d1, "Queued App", "com.queued.app", "QUEUEDTEAM")
	if status, b := putApprovals(t, g.adminToken, approvalBody("unapproved", "", macApp("com.queued.app", "QUEUEDTEAM"))); status != http.StatusOK {
		t.Fatalf("mark = %d: %s", status, b)
	}
	// d2 reports it and stays dirty (its refresh has not run); d3 reports
	// it and is refreshed. Both ingest checks defer to the queued alert.
	govApp(t, d2, "Queued App", "com.queued.app", "QUEUEDTEAM")
	govApp(t, d3, "Queued App", "com.queued.app", "QUEUEDTEAM")
	if err := softwaregov.RefreshDevice(ctx, env.pool, g.id, d3, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{d2, d3} {
		res, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now())
		if err != nil || len(res.AlertIDs) != 0 {
			t.Fatalf("ingest while the marked alert is queued: %+v %v", res, err)
		}
	}
	drainUnapprovedRaises(t)
	alerts := govAlerts(t, g.id)
	if len(alerts) != 1 || alerts[0].Trigger != "marked" || alerts[0].Payload.DeviceCount != 3 {
		t.Fatalf("marked alert = %+v", alerts)
	}
	for _, dev := range []string{d1, d2, d3} {
		res, err := softwaregov.DetectOnDevice(ctx, env.pool, g.id, dev, time.Now())
		if err != nil || len(res.AlertIDs) != 0 {
			t.Fatalf("ingest after the marked alert re-alerted: %+v %v", res, err)
		}
	}
	assertSummaryMatchesFull(t, g.id, "after raise")
}
