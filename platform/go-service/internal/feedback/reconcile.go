package feedback

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const reconcileBatchSize = 50

type Reconciler struct {
	pool    *pgxpool.Pool
	client  *LinearClient
	enabled bool
	once    sync.Once
}

func NewReconciler(pool *pgxpool.Pool, key string, enabled bool) *Reconciler {
	return &Reconciler{pool: pool, client: NewLinearClient(key), enabled: enabled}
}

func (r *Reconciler) Start(ctx context.Context) {
	if !r.enabled {
		r.once.Do(func() { slog.Info("feedback reconciliation disabled: FEEDBACK_ENABLED is false") })
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		r.run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Reconciler) run(ctx context.Context) {
	if !r.enabled {
		return
	}
	if r.client == nil {
		r.once.Do(func() { slog.Warn("feedback reconciliation pending: LINEAR_API_KEY unset") })
		return
	}
	rows, err := r.pool.Query(ctx, `WITH due AS (
 SELECT id FROM feedback
 WHERE linear_issue_id IS NOT NULL
   AND status NOT IN ('shipped','closed_not_planned','closed_merged')
   AND coalesce(linear_checked_at,synced_at,created_at) <= clock_timestamp()-interval '24 hours'
   AND next_reconcile_at <= clock_timestamp()
 ORDER BY next_reconcile_at,id
 LIMIT $1 FOR UPDATE SKIP LOCKED
) UPDATE feedback f SET reconcile_attempts=reconcile_attempts+1,next_reconcile_at=clock_timestamp()+interval '1 hour',updated_at=clock_timestamp()
FROM due WHERE f.id=due.id RETURNING f.id,f.linear_issue_id,f.reconcile_attempts`, reconcileBatchSize)
	if err != nil {
		slog.Warn("feedback reconciliation claim failed", "err", err)
		return
	}
	type claim struct {
		id      int64
		issueID string
		attempt int
	}
	claims := make([]claim, 0, reconcileBatchSize)
	for rows.Next() {
		var c claim
		if err := rows.Scan(&c.id, &c.issueID, &c.attempt); err != nil {
			slog.Warn("feedback reconciliation claim scan failed", "err", err)
			continue
		}
		claims = append(claims, c)
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		slog.Warn("feedback reconciliation claim rows failed", "err", scanErr)
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, c := range claims {
		c := c
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			update, err := r.client.FetchIssue(callCtx, c.issueID)
			if err == nil {
				_, err = ApplyLinearUpdate(callCtx, r.pool, update)
			}
			cancel()
			if err != nil {
				// Preserve the durable backoff even when shutdown cancelled the
				// worker context that caused the Linear call to fail.
				recordCtx, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
				recordReconcileFailure(recordCtx, r.pool, c.id, c.attempt, err)
				recordCancel()
			}
		}()
	}
	wg.Wait()
}
