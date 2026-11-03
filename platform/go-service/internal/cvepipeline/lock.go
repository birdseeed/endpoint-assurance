package cvepipeline

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// matchLockKey serialises the nightly full match against the event-driven
// matcher. The full match reads device_apps once and writes every device from
// that snapshot; if the queue ran in between, the full match could re-insert
// a finding the queue had just cleared from newer inventory (new first_seen_at,
// a second vulnerability.discovered webhook, a spurious "recurred"), and the
// queue's own inserts would be re-announced by the full match's
// first_seen_at >= runStart webhook sweep.
//
// The full match holds the lock EXCLUSIVE for its whole run; every targeted
// matcher try-locks it SHARED and skips its cycle when it cannot. Postgres
// queues a new shared request behind a waiting exclusive one, so a busy queue
// cannot starve the nightly run.
//
// Lock order (PAT-2045; re-verified the way PAT-2023 was). Every writer
// takes its locks in this order and never reaches back up it:
//
//  1. matchLockKey (session advisory). Nightly (runMatch, which includes
//     MatchHomebrewFull and the review queue) holds it EXCLUSIVE; Drain and
//     MatchFeedDelta try it SHARED and skip their cycle on failure, so they
//     never wait on it and never run beside the nightly run. Ingest never
//     takes it.
//  2. 'cvepipeline.mapping_snapshot' (transaction advisory, try-only), in
//     SyncMappingSnapshot for its own short transaction. Covers application
//     and Homebrew mappings alike.
//  3. cve_match_queue rows. expandMappingJobs claims 'mapping' rows
//     FOR UPDATE SKIP LOCKED, then inserts 'observation' rows; drainDevice
//     claims one device's 'observation' rows FOR UPDATE SKIP LOCKED. Ingest
//     (EnqueueObservations / QueueHomebrewDelta, inside the ingest
//     transaction) and expansion upsert observation rows ON CONFLICT DO
//     UPDATE, which waits for a drain holding the same row. Expansion
//     inserts every kind in one (device_id, app_name)-sorted statement
//     (application observations, Homebrew observations, and since PAT-2057
//     the casks linked to an app whose mapping changed, which it finds with
//     plain reads that take no row locks), but
//     ingest uses two (application names, then Homebrew names), so ingest
//     and a concurrent expansion on the same device can still deadlock on
//     queue rows. Postgres aborts one side: an aborted expansion retries on
//     the next drain, and an aborted ingest rolls back its CVE-queue
//     savepoint with a warning, leaving that payload's changes to the
//     nightly run. Nothing is lost or corrupted. SKIP LOCKED means no
//     claimer ever waits on a queue row.
//  4. device_cve_findings and cve_match_assessments rows of ONE device, in
//     one transaction per device (drainDevice, matchDeviceTx). Homebrew
//     findings are upserted in (cve_id, app_name) order. Ingest writes
//     neither table, so an ingest waiting on a queue row (3) can never be
//     waited on in turn by the drain that holds it.
//  5. homebrew_cpe_review_queue rows, sorted by (package_kind, name). Only
//     the nightly run writes them, under the exclusive lock (1); ingest,
//     drain, mapping expansion and the feed delta never do.
//
// Lifecycle reduction (cvelifecycle.ReconcileIdentities) and webhooks run
// after the per-device transactions commit, holding none of 2 to 5.
//
// The one pair that can still meet on the same rows is a Drain and a
// MatchFeedDelta re-matching the same device concurrently (both hold 1
// shared). Both take 4 for that device only, in the order above; if a
// prune and an upsert still cross, Postgres aborts one transaction as a
// deadlock, the drain retries the observation (attempts) and the feed
// delta leaves its keys for the next run. Neither loses work.
const matchLockKey int64 = 0x70617432303234 // "pat2024"

// AcquireFullMatchLock blocks until the exclusive match lock is held on a
// dedicated connection. The returned release must be called.
func AcquireFullMatchLock(ctx context.Context, pool *pgxpool.Pool) (func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for full-match lock: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, matchLockKey); err != nil {
		conn.Release()
		return nil, fmt.Errorf("take full-match lock: %w", err)
	}
	return func() { releaseMatchLock(conn, `SELECT pg_advisory_unlock($1)`) }, nil
}

// tryTargetedMatchLock takes the shared side of the match lock without
// waiting. ok is false while a full match holds (or is waiting for) it.
func tryTargetedMatchLock(ctx context.Context, pool *pgxpool.Pool) (release func(), ok bool, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire connection for match lock: %w", err)
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock_shared($1)`, matchLockKey).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("try match lock: %w", err)
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() { releaseMatchLock(conn, `SELECT pg_advisory_unlock_shared($1)`) }, true, nil
}

// releaseMatchLock unlocks and returns the connection to the pool. Advisory
// locks are session-scoped, so if the unlock fails or reports the lock was not
// held, the connection is closed rather than pooled: a pooled session still
// holding the lock would block the nightly full match forever (shared side
// leaked) or skip every targeted cycle (exclusive side leaked).
func releaseMatchLock(conn *pgxpool.Conn, unlockSQL string) {
	var released bool
	if err := conn.QueryRow(context.Background(), unlockSQL, matchLockKey).Scan(&released); err != nil || !released {
		_ = conn.Conn().Close(context.Background())
	}
	conn.Release()
}
