package softwaregov

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Budgets bound database work under the runner's process-lifetime context.
// Preparation includes the full rebuild after a large policy mark while
// ingest is active. CI can exceed 30 seconds here, so allow 90 seconds within
// the existing two-minute marked batch budget. Maintenance's one-minute phase
// and any shorter caller deadline still take precedence. Each episode gets
// only five seconds.
// Separate stage contexts let delivery proceed after maintenance times out.
const (
	summaryWorkTimeout   = 90 * time.Second
	markedEpisodeTimeout = 5 * time.Second
	markedBatchTimeout   = 2 * time.Minute
	runnerStageTimeout   = 30 * time.Second
	workScheduleTimeout  = 5 * time.Second
)

func boundedWork(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	workCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(workCtx)
}

// A cancelled query can mark its connection closed before pgx's asynchronous
// CancelRequest/Terminate cleanup has ended the server transaction. Wait for
// that cleanup before the next same-tenant device tries its advisory lock.
// Closed sessions remain unusable and are destroyed by the pool throughout.
func rollbackDeviceCheckTx(tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.Background(), workScheduleTimeout)
	defer cancel()
	conn := tx.Conn().PgConn()
	_ = tx.Rollback(cleanup)
	if conn.IsClosed() {
		select {
		case <-conn.CleanupDone():
		case <-cleanup.Done():
		}
	}
}

// Attempt stamps live apart from policy and episode rows, so rotating a
// blocked item does not require its held lock. They survive process restarts.
func recordRunnerAttempt(ctx context.Context, pool *pgxpool.Pool, kind, tenantID, batchKey string) error {
	return boundedWork(ctx, workScheduleTimeout, func(workCtx context.Context) error {
		_, err := pool.Exec(workCtx, `INSERT INTO software_unapproved_runner_attempts (work_kind, tenant_id, batch_key)
			VALUES ($1, $2::uuid, $3) ON CONFLICT (work_kind, tenant_id, batch_key)
			DO UPDATE SET attempted_at = clock_timestamp()`, kind, tenantID, batchKey)
		return err
	})
}

func finishRunnerAttempt(ctx context.Context, pool *pgxpool.Pool, kind, tenantID, batchKey string) error {
	return boundedWork(ctx, workScheduleTimeout, func(workCtx context.Context) error {
		_, err := pool.Exec(workCtx, `DELETE FROM software_unapproved_runner_attempts
			WHERE work_kind = $1 AND tenant_id = $2::uuid AND batch_key = $3`, kind, tenantID, batchKey)
		return err
	})
}

// A crash after completion can miss its stamp deletion. Prune these derived
// stamps too; the tenant FK removes them during tenant deletion.
func pruneRunnerAttempts(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `DELETE FROM software_unapproved_runner_attempts a
		WHERE (a.work_kind = 'summary' AND NOT EXISTS (
			SELECT 1 FROM software_unapproved_presence_state s WHERE s.tenant_id = a.tenant_id
			AND s.summary_version < s.policy_version))
		OR (a.work_kind = 'marked' AND NOT EXISTS (
			SELECT 1 FROM software_unapproved_episodes e WHERE e.tenant_id = a.tenant_id
			AND COALESCE(e.batch_id::text, '') = a.batch_key
			AND e.raised_at IS NULL AND e.source IN ('portal', 'operator')))`)
	return err
}
