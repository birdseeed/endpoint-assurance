package reportsched

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Customer-scheduled report sweeper (PAT-703).
//
// Every tick the Sweeper claims due rows from portal_report_schedules
// (enabled AND next_run_at <= now(), FOR UPDATE SKIP LOCKED — safe against a
// second patched-api instance or an overlapping tick) and generates the
// customer-layout report through the SAME path as POST /v1/portal/reports
// (handlers.GeneratePortalReport, injected as GenerateFunc so this package
// stays free of an import cycle and unit-testable with a stub).
//
// Semantics per claimed row:
//   - skip-if-already-ran-this-period: next_run_at is the slot; if
//     last_run_at >= next_run_at the slot already produced a report (e.g. a
//     restart replaying an old row), so only the pointer advances.
//   - success: last_run_at = now, next_run_at = NextRun(..., now).
//   - generation failure: next_run_at = now + retryDelay (last_run_at
//     untouched) so a transient failure retries without hot-looping, and a
//     permanently failing tenant cannot wedge the sweep.
//
// Crash-safety (PAT-874): s.generate() durably commits its report_records row
// on its own connection, separate from this package's claim transaction. If
// the process crashes after that commit but before processOne's own commit
// (the one advancing last_run_at/next_run_at below), the schedule row is left
// exactly as it was before generation, so the skip-if-already-ran guard above
// does not trip, because last_run_at was never advanced past next_run_at. A
// restart would otherwise call s.generate() a second time for the same slot,
// producing a duplicate report. processOne guards against this by checking
// report_records for a row already carrying this exact slot as its
// schedule_slot before calling s.generate() again; see
// reportAlreadyGeneratedForSlot. schedule_slot (migration 0082) is a real
// idempotency key set only by this package's GenerateFunc call, not a
// timing heuristic, so it can't be confused with a customer's own
// manually-triggered report landing in the same window.

// Default sweeper tuning.
const (
	defaultInterval = time.Minute
	defaultBatch    = 25 // max schedules processed per tick

	// claimTimeout bounds the claim+update transaction bookkeeping.
	claimTimeout = 15 * time.Second
	// generateTimeout bounds one report generation (queries + PDF render).
	generateTimeout = 2 * time.Minute
	// retryDelay is how far next_run_at is pushed after a generation failure.
	retryDelay = 15 * time.Minute
)

// GenerateFunc produces the customer-layout report for a tenant and stores it
// in report history, returning the new report_records id. slot is the
// schedule's next_run_at, threaded through so the stored report_records row
// carries it as schedule_slot (PAT-874's idempotency key). Production wiring
// passes handlers.PortalReportGenerator(pool).
type GenerateFunc func(ctx context.Context, tenantID, reportType, name string, slot time.Time) (recordID string, err error)

// Sweeper polls portal_report_schedules and runs due schedules.
type Sweeper struct {
	pool     *pgxpool.Pool
	generate GenerateFunc
	interval time.Duration
	batch    int
	now      func() time.Time // injectable for tests
}

// Option customises a Sweeper at construction time.
type Option func(*Sweeper)

// WithInterval sets the poll interval. Non-positive values are ignored.
func WithInterval(d time.Duration) Option {
	return func(s *Sweeper) {
		if d > 0 {
			s.interval = d
		}
	}
}

// WithNow overrides the clock (tests only).
func WithNow(now func() time.Time) Option {
	return func(s *Sweeper) {
		if now != nil {
			s.now = now
		}
	}
}

// New builds a Sweeper (1-minute interval, batch 25 by default).
func New(pool *pgxpool.Pool, generate GenerateFunc, opts ...Option) *Sweeper {
	s := &Sweeper{
		pool:     pool,
		generate: generate,
		interval: defaultInterval,
		batch:    defaultBatch,
		now:      func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start runs the poll loop until ctx is cancelled. It blocks, so callers run
// it in a goroutine. An initial sweep runs immediately so overdue schedules
// recover straight after a restart.
func (s *Sweeper) Start(ctx context.Context) {
	slog.Info("reportsched: sweeper starting", "interval", s.interval.String(), "batch", s.batch)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.safeSweep(ctx)
	for {
		select {
		case <-ctx.Done():
			slog.Info("reportsched: sweeper stopped")
			return
		case <-ticker.C:
			s.safeSweep(ctx)
		}
	}
}

// safeSweep runs one Sweep tick with panic recovery. chi's middleware.Recoverer
// only protects HTTP handler goroutines — this background ticker has no
// equivalent, so a bug in report generation (or a malformed schedule row)
// panicking here would otherwise take down the entire patched-api process.
// A recovered panic is logged and the tick is skipped; the ticker loop keeps
// running and retries on the next tick.
func (s *Sweeper) safeSweep(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("reportsched: sweep tick panicked — recovered, will retry next tick", "panic", r)
		}
	}()
	s.Sweep(ctx)
}

// Sweep processes due schedules one at a time until none remain or the batch
// cap is hit. Exported so integration tests can drive a sweep synchronously.
func (s *Sweeper) Sweep(ctx context.Context) {
	for i := 0; i < s.batch; i++ {
		processed, err := s.processOne(ctx)
		if err != nil {
			slog.Error("reportsched: sweep failed", "err", err)
			return
		}
		if !processed {
			return
		}
	}
}

// processOne claims the single most-overdue due schedule, generates its
// report (unless the slot already ran), and advances next_run_at. The row
// stays locked for the duration, so a concurrent sweep skips it. Returns
// false when no due schedule exists.
func (s *Sweeper) processOne(ctx context.Context) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck // no-op after commit

	var (
		tenantID          string
		reportType        string
		cadence           string
		weekday, monthDay *int
		hourUTC           int
		lastRunAt         *time.Time
		nextRunAt         time.Time
	)
	claimCtx, cancel := context.WithTimeout(ctx, claimTimeout)
	err = tx.QueryRow(claimCtx, `
		SELECT tenant_id::text, report_type, cadence, weekday, month_day, hour_utc, last_run_at, next_run_at
		FROM portal_report_schedules
		WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= now()
		ORDER BY next_run_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`).Scan(&tenantID, &reportType, &cadence, &weekday, &monthDay, &hourUTC, &lastRunAt, &nextRunAt)
	cancel()
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	now := s.now()
	logger := slog.With("component", "reportsched", "tenant_id", tenantID, "report_type", reportType,
		"cadence", cadence, "slot", nextRunAt.UTC().Format(time.RFC3339))

	next, err := NextRun(cadence, intOrZero(weekday), intOr(monthDay, 1), hourUTC, now)
	if err != nil {
		// Row violates the API/DB validation invariants (manual SQL edit).
		// Disable it rather than retrying forever.
		logger.Error("reportsched: invalid schedule row — disabling", "err", err)
		if _, uerr := tx.Exec(ctx, `
			UPDATE portal_report_schedules
			SET enabled = FALSE, updated_at = now()
			WHERE tenant_id = $1::uuid AND report_type = $2
		`, tenantID, reportType); uerr != nil {
			return false, uerr
		}
		return true, tx.Commit(ctx)
	}

	// Skip-if-already-ran-this-period: the stored next_run_at is the slot.
	if lastRunAt != nil && !lastRunAt.Before(nextRunAt) {
		logger.Info("reportsched: slot already ran, advancing without generating",
			"last_run_at", lastRunAt.UTC().Format(time.RFC3339),
			"next_run_at", next.Format(time.RFC3339))
		if _, err := tx.Exec(ctx, `
			UPDATE portal_report_schedules
			SET next_run_at = $2, updated_at = now()
			WHERE tenant_id = $1::uuid AND report_type = $3
		`, tenantID, next, reportType); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}

	// PAT-874 crash-recovery guard: a prior attempt for this exact slot may
	// have already called s.generate() successfully and crashed before this
	// function's own commit advanced last_run_at (see the package doc
	// comment above). Detect that durable side effect before regenerating.
	alreadyGenerated, err := s.reportAlreadyGeneratedForSlot(ctx, tx, tenantID, reportType, nextRunAt)
	if err != nil {
		return false, err
	}
	if alreadyGenerated {
		logger.Info("reportsched: recovered after crash, report for this slot already exists, advancing without regenerating",
			"next_run_at", next.Format(time.RFC3339))
		if err := markRunAndAdvance(ctx, tx, tenantID, reportType, now, next); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}

	name := "Scheduled security report " + now.Format("2006-01-02")
	if reportType != "executive-summary" {
		name = "Scheduled " + reportType + " report " + now.Format("2006-01-02")
	}
	genCtx, genCancel := context.WithTimeout(ctx, generateTimeout)
	recordID, genErr := s.generate(genCtx, tenantID, reportType, name, nextRunAt)
	genCancel()

	if genErr != nil {
		retryAt := now.Add(retryDelay)
		logger.Error("reportsched: generation failed, scheduling retry",
			"err", genErr, "retry_at", retryAt.Format(time.RFC3339))
		if _, err := tx.Exec(ctx, `
			UPDATE portal_report_schedules
			SET next_run_at = $2, updated_at = now()
			WHERE tenant_id = $1::uuid AND report_type = $3
		`, tenantID, retryAt, reportType); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}

	if err := markRunAndAdvance(ctx, tx, tenantID, reportType, now, next); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	logger.Info("reportsched: scheduled report generated",
		"record_id", recordID, "next_run_at", next.Format(time.RFC3339))
	return true, nil
}

// markRunAndAdvance records a completed run (last_run_at = ranAt) and moves
// the schedule's slot forward to next. Shared by the normal success path and
// the PAT-874 crash-recovery path, which both reach the exact same
// bookkeeping state by different routes.
func markRunAndAdvance(ctx context.Context, tx pgx.Tx, tenantID, reportType string, ranAt, next time.Time) error {
	_, err := tx.Exec(ctx, `
		UPDATE portal_report_schedules
		SET last_run_at = $2, next_run_at = $3, updated_at = now()
		WHERE tenant_id = $1::uuid AND report_type = $4
	`, tenantID, ranAt, next, reportType)
	return err
}

// reportAlreadyGeneratedForSlot reports whether a portal report already
// exists for tenantID carrying schedule_slot = slot exactly. s.generate()
// commits report_records durably on its own connection, independent of this
// function's tx, so after a crash between that commit and this function's
// own commit, this is the only way to tell "already generated, don't repeat"
// apart from "never attempted, safe to generate" using the schedule row
// alone (see the package doc comment).
//
// schedule_slot (migration 0082) is set ONLY by this package's GenerateFunc
// call, holding the exact next_run_at value passed to s.generate(). It is
// NULL on every ad-hoc/customer-triggered/admin report, so an exact equality
// match here can never be satisfied by an unrelated report a customer
// generated manually around the same time; there is no timing-window
// ambiguity to reason about.
//
// slot is next_run_at as read at the top of processOne: the due time of the
// period being processed right now (or, on a post-failure retry tick, the
// retryAt value from the failed attempt), not yet advanced.
func (s *Sweeper) reportAlreadyGeneratedForSlot(ctx context.Context, tx pgx.Tx, tenantID, reportType string, slot time.Time) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM report_records
			WHERE tenant_id = $1::uuid AND report_type = $2
			  AND source = 'portal' AND schedule_slot = $3
		)
	`, tenantID, reportType, slot).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func intOrZero(p *int) int { return intOr(p, 0) }

func intOr(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}
