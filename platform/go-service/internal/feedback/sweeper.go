package feedback

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"sync"
	"time"
)

const maxSyncAttempts = 10
const feedbackLeaseDuration = 10 * time.Minute

func syncRetryDecision(attempt int) (state string, delay time.Duration) {
	if attempt >= maxSyncAttempts {
		return "failed", 0
	}
	state, delay = "pending", time.Minute
	for i := 1; i < attempt && delay < time.Hour; i++ {
		delay *= 2
	}
	return state, min(delay, time.Hour)
}

type Sweeper struct {
	pool   *pgxpool.Pool
	client *LinearClient
	once   sync.Once
}

func NewSweeper(p *pgxpool.Pool, key string) *Sweeper {
	return &Sweeper{pool: p, client: NewLinearClient(key)}
}
func (s *Sweeper) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		s.run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Sweeper) run(ctx context.Context) {
	if s.client == nil {
		s.once.Do(func() { slog.Warn("feedback pending: LINEAR_API_KEY unset") })
		return
	}
	rows, e := s.pool.Query(ctx, `WITH exhausted AS (
 UPDATE feedback SET sync_state='failed',lease_until=NULL,last_error=coalesce(last_error,'sync attempt budget exhausted after lease expiry'),updated_at=clock_timestamp()
 WHERE sync_attempts >= $1 AND (sync_state='pending' OR (sync_state='syncing' AND lease_until<now()))
), c AS (
 SELECT id FROM feedback WHERE sync_attempts < $1 AND ((sync_state='pending' AND next_sync_at<=now()) OR (sync_state='syncing' AND lease_until<now()))
 ORDER BY next_sync_at LIMIT 4 FOR UPDATE SKIP LOCKED
) UPDATE feedback f SET sync_state='syncing',sync_attempts=sync_attempts+1,lease_until=now()+$2 * interval '1 microsecond',updated_at=clock_timestamp() FROM c WHERE f.id=c.id RETURNING f.id,f.sync_attempts`, maxSyncAttempts, feedbackLeaseDuration.Microseconds())
	if e != nil {
		slog.Warn("feedback claim failed", "err", e)
		return
	}
	defer rows.Close()
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for rows.Next() {
		var id int64
		var attempt int
		if err := rows.Scan(&id, &attempt); err != nil {
			slog.Warn("feedback claim scan", "err", err)
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(id int64, attempt int) {
			defer wg.Done()
			defer func() {
				<-sem
				if r := recover(); r != nil {
					slog.Error("feedback worker panic", "panic", r)
					s.retry(id, attempt, "worker panic")
				}
			}()
			s.process(ctx, id, attempt)
		}(id, attempt)
	}
	wg.Wait()
	if err := rows.Err(); err != nil {
		slog.Warn("feedback claim rows", "err", err)
	}
}
func (s *Sweeper) process(ctx context.Context, id int64, attempt int) {
	e := deliverFeedback(ctx, postgresDeliveryStore{pool: s.pool}, s.client, id, attempt)
	if errors.Is(e, ErrStaleFeedbackClaim) {
		slog.Warn("feedback worker lost claim", "id", id, "attempt", attempt)
		return
	}
	if e != nil {
		s.retry(id, attempt, e.Error())
	}
}

// logSyncFailure puts every failed delivery attempt in the journal, not only
// in last_error (PAT-2216: a morning of Linear rejections was invisible from
// the box). The error text is Linear's or the network's, never customer
// text, and is bounded like last_error's own display.
func logSyncFailure(id int64, attempt int, state string, delay time.Duration, msg string) {
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if state == "failed" {
		slog.Error("feedback sync failed permanently", "id", id, "attempt", attempt, "err", msg)
		return
	}
	slog.Warn("feedback sync attempt failed", "id", id, "attempt", attempt, "retry_in", delay.String(), "err", msg)
}

func (s *Sweeper) retry(id int64, attempt int, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, delay := syncRetryDecision(attempt)
	logSyncFailure(id, attempt, state, delay, msg)
	// Do not overwrite a newer claimant or a completed delivery if this worker
	// finished after its lease. The durable claim owns the attempt increment.
	tag, err := s.pool.Exec(ctx, `UPDATE feedback SET sync_state=$3,lease_until=NULL,next_sync_at=CASE WHEN $3='failed' THEN next_sync_at ELSE now()+$4 * interval '1 microsecond' END,last_error=left($2,1000),updated_at=clock_timestamp() WHERE id=$1 AND sync_state='syncing' AND sync_attempts=$5 AND lease_until>clock_timestamp()`, id, msg, state, delay.Microseconds(), attempt)
	err = requireFeedbackClaim(tag, err)
	if err != nil {
		slog.Warn("feedback retry update failed", "id", id, "err", err)
	}
}
