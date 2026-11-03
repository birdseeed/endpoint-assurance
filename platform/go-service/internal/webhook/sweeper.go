package webhook

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
)

// Database-backed webhook retry sweeper (PAT-687).
//
// The in-memory attempt()/time.AfterFunc retry schedule in dispatcher.go is
// lost whenever the process restarts: any delivery that was waiting out its
// backoff simply never fires again. The Sweeper closes that gap. It polls
// webhook_deliveries for rows that are due for a retry
// (succeeded_at IS NULL AND next_attempt_at <= now()), re-dispatches each via
// the same SSRF-hardened httpClient, and persists the outcome with the exact
// same decision logic as attempt() (shared via decideOutcome). Concurrency is
// bounded by a worker-pool semaphore, and an in-flight set prevents the same
// delivery being picked up twice across overlapping ticks.

// Default sweeper tuning.
const (
	defaultSweepInterval = 30 * time.Second
	defaultSweepBatch    = 100
	defaultSweepWorkers  = 8

	// sweepQueryTimeout bounds the due-rows SELECT on each tick.
	sweepQueryTimeout = 15 * time.Second
	// sweepPostTimeout bounds a single re-dispatch HTTP POST (matches attempt()).
	sweepPostTimeout = 10 * time.Second
	// sweepRecordTimeout bounds the recordAttempt write; uses a background
	// context so a shutdown mid-flight still persists the outcome.
	sweepRecordTimeout = 5 * time.Second
)

// Sweeper re-dispatches due webhook_deliveries from the database. Construct one
// with NewSweeper and run it with Start (typically in its own goroutine tied to
// a context that is cancelled on shutdown).
type Sweeper struct {
	pool     *pgxpool.Pool
	interval time.Duration
	batch    int
	workers  int

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

// WithWorkers bounds the number of concurrent re-dispatch goroutines.
// Non-positive values are ignored.
func WithWorkers(n int) SweeperOption {
	return func(s *Sweeper) {
		if n > 0 {
			s.workers = n
		}
	}
}

// NewSweeper builds a Sweeper with sensible defaults (30s interval, batch 100,
// 8 workers), overridable via options.
func NewSweeper(pool *pgxpool.Pool, opts ...SweeperOption) *Sweeper {
	s := &Sweeper{
		pool:     pool,
		interval: defaultSweepInterval,
		batch:    defaultSweepBatch,
		workers:  defaultSweepWorkers,
		inflight: make(map[int64]struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start runs the poll loop until ctx is cancelled, then waits for in-flight
// re-dispatches to drain before returning. It blocks, so callers usually run it
// in a goroutine. An initial sweep runs immediately so a freshly-started
// process recovers overdue retries without waiting a full interval.
func (s *Sweeper) Start(ctx context.Context) {
	slog.Info("webhook: sweeper starting",
		"interval", s.interval.String(), "batch", s.batch, "workers", s.workers)

	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.safeSweep(ctx, sem, &wg)

	for {
		select {
		case <-ctx.Done():
			slog.Info("webhook: sweeper stopping, draining in-flight retries")
			wg.Wait()
			slog.Info("webhook: sweeper stopped")
			return
		case <-ticker.C:
			s.safeSweep(ctx, sem, &wg)
		}
	}
}

// safeSweep runs one sweep tick with panic recovery. chi's middleware.Recoverer
// only protects HTTP handler goroutines — this background ticker has no
// equivalent, so an unrecovered panic here (e.g. a bad row, a nil dependency)
// would take down the entire patched-api process, not just this job. A
// recovered panic is logged and the tick is skipped; the ticker loop keeps
// running and retries on the next tick.
func (s *Sweeper) safeSweep(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("webhook: sweeper tick panicked — recovered, will retry next tick", "panic", r)
		}
	}()
	s.sweep(ctx, sem, wg)
}

// dueDelivery is one pending delivery joined with its hook's URL + secret.
type dueDelivery struct {
	id           int64
	webhookID    string
	payload      []byte
	attemptCount int
	url          string
	secret       string
}

// sweep queries due deliveries and dispatches each through the worker pool.
func (s *Sweeper) sweep(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	queryCtx, cancel := context.WithTimeout(ctx, sweepQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(queryCtx, `
		SELECT d.id, d.webhook_id::text, d.payload, d.attempt_count, w.url, w.secret
		FROM webhook_deliveries d
		JOIN tenant_webhooks w ON w.id = d.webhook_id
		WHERE d.succeeded_at IS NULL
		  AND d.next_attempt_at IS NOT NULL
		  AND d.next_attempt_at <= now()
		  AND w.enabled = true
		ORDER BY d.next_attempt_at
		LIMIT $1
	`, s.batch)
	if err != nil {
		slog.Warn("webhook: sweeper query failed", "err", err)
		return
	}

	// Drain rows fully before dispatching so the pooled connection is released
	// promptly (each re-dispatch acquires its own connection for recordAttempt).
	var due []dueDelivery
	for rows.Next() {
		var d dueDelivery
		if err := rows.Scan(&d.id, &d.webhookID, &d.payload, &d.attemptCount, &d.url, &d.secret); err != nil {
			slog.Warn("webhook: sweeper scan failed", "err", err)
			continue
		}
		due = append(due, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		slog.Warn("webhook: sweeper rows error", "err", err)
	}
	if len(due) == 0 {
		return
	}

	dispatched := 0
	for _, d := range due {
		// Skip anything already being processed by an earlier tick.
		if !s.claim(d.id) {
			continue
		}
		// Acquire a worker slot, honouring cancellation.
		select {
		case <-ctx.Done():
			s.release(d.id)
			return
		case sem <- struct{}{}:
		}
		dispatched++
		s.dispatchOne(ctx, d, sem, wg)
	}
	slog.Debug("webhook: sweeper tick", "due", len(due), "dispatched", dispatched)
}

// dispatchOne launches d's re-dispatch in its own goroutine, bounded by sem
// and tracked by wg. A panic during processing is recovered and logged so one
// bad delivery can't take down the whole process — chi's Recoverer only
// protects HTTP handler goroutines, not this background worker pool.
func (s *Sweeper) dispatchOne(ctx context.Context, d dueDelivery, sem chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(d dueDelivery) {
		defer wg.Done()
		defer func() { <-sem }()
		defer s.release(d.id)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("webhook: sweeper delivery processing panicked — recovered",
					"delivery_id", d.id, "hook_id", d.webhookID, "panic", r)
			}
		}()
		s.process(ctx, d)
	}(d)
}

// process re-dispatches one delivery and records the outcome. It mirrors
// attempt(): 2xx = success, 4xx = permanent (no retry), otherwise retry with
// backoff until maxAttempts is reached.
func (s *Sweeper) process(ctx context.Context, d dueDelivery) {
	// PAT-2009: the stored secret is envelope-encrypted (penc1:) whenever
	// PATCHED_KEK is set (PAT-687). Signing with the stored value would sign
	// with the ciphertext and every receiver would reject the delivery, so
	// decrypt it exactly as listForEvent and FireDirect do, with the same
	// plaintext fallback for rows written before encryption.
	secret, err := resolveHookSecret(envelope.Default(), d.secret)
	if err != nil {
		// Retrying cannot fix an undecryptable secret; stop the row rather
		// than let it be picked up every tick.
		slog.Warn("webhook: sweeper cannot decrypt hook secret, not retrying",
			"delivery_id", d.id, "hook_id", d.webhookID)
		recCtx, recCancel := context.WithTimeout(context.Background(), sweepRecordTimeout)
		defer recCancel()
		_ = recordAttempt(recCtx, s.pool, d.id, 0, false, nil)
		return
	}
	h := hookWithSecret{id: d.webhookID, url: d.url, secret: secret}
	// attempt_count is the number of attempts already made; this is the next.
	n := d.attemptCount + 1

	postCtx, cancel := context.WithTimeout(ctx, sweepPostTimeout)
	defer cancel()

	status, httpErr := post(postCtx, h, d.payload)
	if httpErr != nil {
		slog.Warn("webhook: sweeper delivery failed (network)",
			"delivery_id", d.id, "hook_id", d.webhookID, "attempt", n, "err", httpErr)
	} else if status < 200 || status >= 300 {
		slog.Warn("webhook: sweeper delivery failed (non-2xx)",
			"delivery_id", d.id, "hook_id", d.webhookID, "attempt", n, "status", status)
	}

	outcome, backoff := decideOutcome(status, httpErr != nil, n)

	// Persist on a background context so a cancellation during shutdown does not
	// leave the attempt unrecorded (which would otherwise re-fire next tick).
	recCtx, recCancel := context.WithTimeout(context.Background(), sweepRecordTimeout)
	defer recCancel()

	switch outcome {
	case outcomeSuccess:
		_ = recordAttempt(recCtx, s.pool, d.id, status, true, nil)
		slog.Info("webhook: sweeper delivered",
			"delivery_id", d.id, "hook_id", d.webhookID, "status", status, "attempt", n)
	case outcomePermanent:
		slog.Warn("webhook: sweeper permanent failure, not retrying",
			"delivery_id", d.id, "hook_id", d.webhookID, "status", status)
		_ = recordAttempt(recCtx, s.pool, d.id, status, false, nil)
	case outcomeGiveUp:
		slog.Warn("webhook: sweeper max attempts reached, giving up",
			"delivery_id", d.id, "hook_id", d.webhookID, "attempts", n)
		_ = recordAttempt(recCtx, s.pool, d.id, status, false, nil)
	case outcomeRetry:
		nextAt := time.Now().Add(backoff)
		_ = recordAttempt(recCtx, s.pool, d.id, status, false, &nextAt)
		slog.Info("webhook: sweeper scheduling retry",
			"delivery_id", d.id, "hook_id", d.webhookID, "attempt", n, "next_in", backoff.String())
	}
}

// claim marks a delivery id as in-flight. It returns false if the id is already
// being processed (so the caller should skip it this tick).
func (s *Sweeper) claim(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.inflight[id]; ok {
		return false
	}
	s.inflight[id] = struct{}{}
	return true
}

// release clears the in-flight marker once processing completes.
func (s *Sweeper) release(id int64) {
	s.mu.Lock()
	delete(s.inflight, id)
	s.mu.Unlock()
}

// retryOutcome classifies the result of a delivery attempt.
type retryOutcome int

const (
	outcomeSuccess   retryOutcome = iota // 2xx — delivered
	outcomePermanent                     // 4xx — client error, do not retry
	outcomeGiveUp                        // retriable but max attempts reached
	outcomeRetry                         // retriable — schedule another attempt
)

// decideOutcome is the shared, pure retry-decision used by both attempt() (the
// in-memory path) and the Sweeper (the DB-backed path), so their semantics stay
// identical. status is the HTTP status (0 = network error); netErr indicates a
// transport failure; attempt is the 1-indexed number of THIS attempt. When the
// outcome is outcomeRetry, the returned duration is the backoff before the next
// attempt.
//
// It delegates to the exported ClassifyAttempt so the PAT-134 paths and the
// PAT-1888 notification channels share one retry decision rather than two that
// can drift. Permanent client errors (4xx) are never retried.
func decideOutcome(status int, netErr bool, attempt int) (retryOutcome, time.Duration) {
	outcome, backoff := ClassifyAttempt(status, netErr, attempt, maxAttempts)
	switch outcome {
	case AttemptDelivered:
		return outcomeSuccess, 0
	case AttemptPermanent:
		return outcomePermanent, 0
	case AttemptExhausted:
		return outcomeGiveUp, 0
	default:
		return outcomeRetry, backoff
	}
}

// resolveHookSecret turns a stored tenant_webhooks.secret into the HMAC key:
// the decrypted secret for an envelope-encrypted (penc1:) row, the stored
// value itself for a row written before encryption (PAT-687).
func resolveHookSecret(env *envelope.Envelope, stored string) ([]byte, error) {
	plain, err := env.DecryptString(stored)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}
