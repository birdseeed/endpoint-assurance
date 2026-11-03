package notifications

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The delivery sweeper is the only thing that sends a queued notification.
// Enqueue and delivery are separated by the database on purpose: the process
// that establishes a finding never makes a network call, and a restart in the
// middle of a backoff loses nothing, because the schedule lives in
// next_attempt_at rather than in a timer.

const (
	defaultSweepInterval = 20 * time.Second
	defaultSweepBatch    = 100
	defaultSweepWorkers  = 8

	// sweepQueryTimeout bounds the due-rows SELECT on one tick.
	sweepQueryTimeout = 15 * time.Second
	// attemptTimeout bounds one delivery attempt.
	attemptTimeout = 15 * time.Second
	// recordTimeout bounds the write that persists an attempt's outcome.
	recordTimeout = 5 * time.Second
)

// Sweeper polls due deliveries and dispatches them through a bounded worker
// pool.
type Sweeper struct {
	dispatcher *Dispatcher
	interval   time.Duration
	batch      int
	workers    int

	mu       sync.Mutex
	inflight map[int64]struct{}
}

// SweeperOption customises a Sweeper at construction time.
type SweeperOption func(*Sweeper)

// WithInterval sets the poll interval. Non-positive values are ignored.
func WithInterval(d time.Duration) SweeperOption {
	return func(s *Sweeper) {
		if d > 0 {
			s.interval = d
		}
	}
}

// WithBatchSize caps how many due deliveries are pulled per tick. Non-positive
// values are ignored.
func WithBatchSize(n int) SweeperOption {
	return func(s *Sweeper) {
		if n > 0 {
			s.batch = n
		}
	}
}

// WithWorkers bounds concurrent deliveries. Non-positive values are ignored.
func WithWorkers(n int) SweeperOption {
	return func(s *Sweeper) {
		if n > 0 {
			s.workers = n
		}
	}
}

// NewSweeper builds a Sweeper driven by d.
func NewSweeper(d *Dispatcher, opts ...SweeperOption) *Sweeper {
	s := &Sweeper{
		dispatcher: d,
		interval:   defaultSweepInterval,
		batch:      defaultSweepBatch,
		workers:    defaultSweepWorkers,
		inflight:   make(map[int64]struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start runs the poll loop until ctx is cancelled, then waits for in-flight
// deliveries to drain. It blocks, so callers run it in a goroutine. An initial
// sweep runs immediately so a restart recovers overdue retries without waiting
// a full interval.
func (s *Sweeper) Start(ctx context.Context) {
	slog.Info("notifications: sweeper starting",
		"interval", s.interval.String(), "batch", s.batch, "workers", s.workers)

	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.safeSweep(ctx, sem, &wg)

	for {
		select {
		case <-ctx.Done():
			slog.Info("notifications: sweeper stopping, draining in-flight deliveries")
			wg.Wait()
			slog.Info("notifications: sweeper stopped")
			return
		case <-ticker.C:
			s.safeSweep(ctx, sem, &wg)
		}
	}
}

// safeSweep runs one tick with panic recovery. This goroutine has no
// middleware.Recoverer above it, so an unrecovered panic here would take down
// the whole patched-api process rather than one delivery.
func (s *Sweeper) safeSweep(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("notifications: sweeper tick panicked, recovered and will retry next tick", "panic", r)
		}
	}()
	s.sweep(ctx, sem, wg)
}

// SweepOnce runs exactly one tick and waits for it to finish. It exists for
// tests and for any caller that wants a deterministic drain rather than a
// ticker.
func (s *Sweeper) SweepOnce(ctx context.Context) {
	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup
	s.sweep(ctx, sem, &wg)
	wg.Wait()
}

func (s *Sweeper) sweep(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	due, err := s.loadDue(ctx)
	if err != nil {
		slog.Warn("notifications: sweeper query failed", "err", err)
		return
	}
	if len(due) == 0 {
		return
	}

	for _, p := range due {
		if !s.claim(p.id) {
			continue
		}
		select {
		case <-ctx.Done():
			s.release(p.id)
			return
		case sem <- struct{}{}:
		}
		s.dispatchOne(ctx, p, sem, wg)
	}
}

// loadDue reads the pending rows whose retry time has arrived, joined with the
// channel that owns them. A disabled channel is excluded, which is exactly what
// makes `enabled = false` a working per-tenant rollback: queued work stops
// being delivered while the rows and their history stay put.
func (s *Sweeper) loadDue(ctx context.Context) ([]pendingDelivery, error) {
	queryCtx, cancel := context.WithTimeout(ctx, sweepQueryTimeout)
	defer cancel()

	rows, err := s.dispatcher.pool.Query(queryCtx, `
		SELECT d.id, d.channel_id::text, d.tenant_id::text, d.event_type,
		       d.idempotency_key, d.payload, d.attempt_count,
		       c.channel_type, coalesce(c.destination_url, ''), c.secret, c.recipients
		FROM notification_deliveries d
		JOIN notification_channels c ON c.id = d.channel_id
		WHERE d.state = 'pending'
		  AND d.next_attempt_at IS NOT NULL
		  AND d.next_attempt_at <= now()
		  AND c.enabled = true
		ORDER BY d.next_attempt_at
		LIMIT $1
	`, s.batch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var due []pendingDelivery
	var undeliverable []pendingDelivery
	for rows.Next() {
		var p pendingDelivery
		var secret *string
		if err := rows.Scan(&p.id, &p.channelID, &p.tenantID, &p.eventType,
			&p.idempotency, &p.payload, &p.attemptCount,
			&p.channelType, &p.url, &secret, &p.recipients); err != nil {
			slog.Warn("notifications: sweeper scan failed", "err", err)
			continue
		}
		if secret != nil {
			plain, err := decryptSecret(*secret)
			if err != nil {
				// A secret we cannot unwrap is a configuration fault, not a
				// transient one. Skipping the row would leave it pending with
				// its next_attempt_at unchanged, so it would be re-selected
				// every tick forever, and because the due query is ordered by
				// next_attempt_at with a LIMIT, enough of these at the head of
				// the queue would starve healthy deliveries behind them.
				undeliverable = append(undeliverable, p)
				continue
			}
			p.secret = plain
		}
		due = append(due, p)
	}
	scanErr := rows.Err()

	// Release the connection before writing: the dead-letter updates below each
	// acquire their own, and holding this cursor open while they run is a
	// needless second connection per tick.
	rows.Close()
	s.deadLetterUndeliverable(undeliverable)

	return due, scanErr
}

// errUndecryptableSecret is the stored explanation for a channel whose signing
// secret cannot be unwrapped, usually because PATCHED_KEK has changed or is
// absent. It is a fixed string on purpose: it carries no ciphertext, no key
// material and nothing derived from either.
var errUndecryptableSecret = errors.New("channel secret could not be decrypted")

// deadLetterUndeliverable moves deliveries whose channel configuration cannot
// be used into their terminal state, through the same path every other
// configuration fault takes. The row stops being selected because record()
// clears next_attempt_at on a terminal state, and it becomes visible to the
// tenant owner in the dead-letter listing.
//
// A background context is used so a sweeper shutdown mid-tick still persists
// the outcome rather than leaving the row to be re-selected on the next start.
func (s *Sweeper) deadLetterUndeliverable(rows []pendingDelivery) {
	for _, p := range rows {
		recordCtx, cancel := context.WithTimeout(context.Background(), recordTimeout)
		_, err := s.dispatcher.record(recordCtx, p, attemptResult{
			permanent: true,
			reason:    ReasonUndeliverable,
			err:       errUndecryptableSecret,
		})
		cancel()
		if err != nil {
			slog.Warn("notifications: could not dead-letter an undeliverable channel secret",
				"delivery_id", p.id, "channel_id", p.channelID, "err", err)
			continue
		}
		slog.Warn("notifications: dead-lettered, channel secret could not be decrypted",
			"delivery_id", p.id, "channel_id", p.channelID)
	}
}

func (s *Sweeper) dispatchOne(ctx context.Context, p pendingDelivery, sem chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(p pendingDelivery) {
		defer wg.Done()
		defer func() { <-sem }()
		defer s.release(p.id)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("notifications: delivery panicked, recovered",
					"delivery_id", p.id, "channel_id", p.channelID, "panic", r)
			}
		}()
		s.dispatcher.process(ctx, p)
	}(p)
}

// claim marks a delivery in-flight so overlapping ticks cannot double-send it
// within one process.
func (s *Sweeper) claim(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.inflight[id]; ok {
		return false
	}
	s.inflight[id] = struct{}{}
	return true
}

func (s *Sweeper) release(id int64) {
	s.mu.Lock()
	delete(s.inflight, id)
	s.mu.Unlock()
}

// PruneDelivered removes delivered rows older than retain, in one bounded
// statement, and returns how many went. Dead-lettered and pending rows are
// never pruned: those are the ones an owner needs to be able to look at.
func PruneDelivered(ctx context.Context, pool *pgxpool.Pool, retain time.Duration, limit int) (int64, error) {
	if retain <= 0 {
		retain = 30 * 24 * time.Hour
	}
	if limit <= 0 {
		limit = 5000
	}
	tag, err := pool.Exec(ctx, `
		DELETE FROM notification_deliveries
		WHERE id IN (
			SELECT id FROM notification_deliveries
			WHERE state = 'delivered'
			  AND succeeded_at < now() - make_interval(secs => $1)
			ORDER BY id
			LIMIT $2
		)
	`, retain.Seconds(), limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
