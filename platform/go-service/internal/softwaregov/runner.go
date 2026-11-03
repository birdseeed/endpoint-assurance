package softwaregov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/notifications"
	"patched.im/api/internal/webhook"
)

// Runner is the one background component of this package, run inside
// patched-api. Each tick it:
//
//  0. keeps the PAT-2095 Unapproved-present summary current: rebuilds any
//     tenant whose summary lags a policy change, then refreshes devices left
//     dirty (an ingest refresh that was skipped or failed);
//  1. raises the marked alert for every episode a policy write opened. The
//     policy writers do not raise on the request path; they wake the runner
//     (WakeRunner), which runs steps 0, 1 and 2 straight away;
//     after raises, retries observed checks deferred by a busy alert lock;
//  2. emails pending 'marked' alerts to the tenant contact, immediately, one
//     email per policy-write request (email_batch_id), however many products;
//  3. emails each tenant's pending 'observed' alerts as one daily digest,
//     at most once per daily slot;
//  4. raises the daily software.first_seen digest into PAT-1888 channels for
//     tenants that turned the new software notification on;
//  5. independently raises ai_tooling.first_seen for its explicit opt-in;
//  6. records this week's governance counts for the drift trend.
//
// Steps 1 and 2 run in the same goroutine, one after the other, so a batch's
// episodes are all raised before its one email is assembled.
//
// Webhook deliveries are not sent here: they were enqueued with the alert
// and the PAT-134 sweeper sends them.
//
// patched-api runs as one process on patched-api-01, so there is exactly one
// Runner. Every step is idempotent against its own table state, so a restart
// mid-tick resends nothing that was recorded as sent.
type Runner struct {
	pool          *pgxpool.Pool
	mail          graphmail.Sender
	now           func() time.Time
	interval      time.Duration
	digestHourUTC int
}

// RunnerOption customises a Runner.
type RunnerOption func(*Runner)

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) RunnerOption {
	return func(r *Runner) {
		if now != nil {
			r.now = now
		}
	}
}

// WithRunnerInterval sets the tick interval.
func WithRunnerInterval(d time.Duration) RunnerOption {
	return func(r *Runner) {
		if d > 0 {
			r.interval = d
		}
	}
}

// DigestHourUTC is the daily slot for both digests: 07:00 UTC, which is
// 07:00 GMT or 08:00 BST for an Isle of Man or UK customer.
const DigestHourUTC = 7

// EmailMaxAttempts bounds retries of one email.
const EmailMaxAttempts = 6

const (
	markedBatch       = 50
	markedBatchAlerts = 2000
	unraisedBatches   = 50
	// UnraisedGrace is how old an unraised episode must be before the runner
	// raises it. PAT-2095 moved the raise off the request path into the
	// runner, so there is no writer's own raise left to wait for.
	UnraisedGrace time.Duration = 0
	// staleSummaryTenants and dirtyDevicesPerTick bound step 0 of one tick.
	staleSummaryTenants = 20
	dirtyDevicesPerTick = 5000
	digestTenantsBatch  = 50
	digestAlertLimit    = 500
	snapshotBatch       = 20
	notifyTenantsBatch  = 50
	maxNotifyProducts   = 200
	maxEmailErrorLen    = 300
	notifyCursorMaxAge  = 7 * 24 * time.Hour
)

// NewRunner builds a Runner. mail may be nil when the Graph mailer is not
// configured: emails then dead-letter with a stated reason instead of
// disappearing, and webhooks are unaffected.
func NewRunner(pool *pgxpool.Pool, mail graphmail.Sender, opts ...RunnerOption) *Runner {
	r := &Runner{pool: pool, mail: mail, now: time.Now, interval: time.Minute, digestHourUTC: DigestHourUTC}
	for _, o := range opts {
		o(r)
	}
	return r
}

// runnerWake carries WakeRunner's signal to the one Runner in this process.
// Buffered by one: a wake that arrives while a pass runs queues exactly one
// more pass, and further wakes coalesce into it.
var runnerWake = make(chan struct{}, 1)

// WakeRunner asks the Runner to raise pending marked alerts now rather than
// at its next tick (PAT-2095). It never blocks or executes runner work
// synchronously: a buffered wake only requests a pass. Episodes
// and device checks are durable, so coalescing signals or having no running
// Runner loses no work; a later pass or periodic tick scans them again.
func WakeRunner() {
	select {
	case runnerWake <- struct{}{}:
	default:
	}
}

// Start runs the loop until ctx is cancelled.
func (r *Runner) Start(ctx context.Context) {
	slog.Info("softwaregov: runner starting", "interval", r.interval.String())
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.safeRun(ctx, r.RunOnce)
	for {
		select {
		case <-ctx.Done():
			slog.Info("softwaregov: runner stopped")
			return
		case <-ticker.C:
			r.safeRun(ctx, r.RunOnce)
		case <-runnerWake:
			r.safeRun(ctx, r.RunMarked)
		}
	}
}

func (r *Runner) safeRun(ctx context.Context, step func(context.Context) error) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("softwaregov: runner tick panicked, recovered", "panic", p)
		}
	}()
	if err := step(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn("softwaregov: runner tick failed", "err", err)
	}
}

// RunMarked is the woken pass: keep the summary current, raise pending
// marked alerts, and email them. Each step runs even if an earlier one
// failed; their errors are returned together. Every stage has its own budget.
func (r *Runner) RunMarked(ctx context.Context) error {
	return r.runPass(ctx, false)
}

// refreshSummaries is step 0: rebuild tenants whose summary lags a policy
// change, then refresh devices left dirty.
func (r *Runner) refreshSummaries(ctx context.Context, now time.Time) error {
	// Rebuilds share a one-minute phase budget. The dirty sweep gets a fresh
	// budget from the parent even when that phase expires or a tenant fails.
	failures := boundedWork(ctx, time.Minute, func(phaseCtx context.Context) error {
		var failures error
		failures = errors.Join(failures, pruneRunnerAttempts(phaseCtx, r.pool))
		tenants, err := StaleSummaryTenants(phaseCtx, r.pool, staleSummaryTenants)
		if err != nil {
			return errors.Join(failures, err)
		}
		for _, tenantID := range tenants {
			if phaseCtx.Err() != nil {
				return errors.Join(failures, phaseCtx.Err())
			}
			if err := recordRunnerAttempt(phaseCtx, r.pool, "summary", tenantID, ""); err != nil {
				failures = errors.Join(failures, err)
				continue
			}
			start := time.Now()
			if err := boundedWork(phaseCtx, summaryWorkTimeout, func(workCtx context.Context) error {
				return ReconcileTenant(workCtx, r.pool, tenantID, now)
			}); err != nil {
				failures = errors.Join(failures, fmt.Errorf("rebuild unapproved summary for %s: %w", tenantID, err))
				continue
			}
			failures = errors.Join(failures, finishRunnerAttempt(phaseCtx, r.pool, "summary", tenantID, ""))
			slog.Info("softwaregov: unapproved summary rebuilt", "tenant_id", tenantID, "took", time.Since(start).String())
		}
		return failures
	})
	if ctx.Err() == nil {
		failures = errors.Join(failures, boundedWork(ctx, runnerStageTimeout, func(workCtx context.Context) error {
			_, err := RefreshDirty(workCtx, r.pool, dirtyDevicesPerTick, now)
			return err
		}))
	}
	return failures
}

// RunOnce performs one tick. Each step runs even if an earlier one failed;
// their errors are returned together, with a separate budget for each stage.
func (r *Runner) RunOnce(ctx context.Context) error {
	return r.runPass(ctx, true)
}

func (r *Runner) runPass(ctx context.Context, periodic bool) error {
	now := r.now().UTC()
	var failures error
	keep := func(step func(context.Context) error) {
		if ctx.Err() == nil {
			failures = errors.Join(failures, step(ctx))
		}
	}
	keep(func(ctx context.Context) error { return r.refreshSummaries(ctx, now) })
	keep(func(ctx context.Context) error { return r.raiseUnraised(ctx, now) })
	keep(func(ctx context.Context) error { return DetectDeferred(ctx, r.pool, dirtyDevicesPerTick, now) })
	keep(func(ctx context.Context) error {
		return boundedWork(ctx, runnerStageTimeout, func(ctx context.Context) error { return r.sendMarked(ctx, now) })
	})
	if periodic {
		for _, step := range []func(context.Context) error{
			func(ctx context.Context) error { return r.sendDigests(ctx, now) },
			func(ctx context.Context) error { return r.notifyNewSoftware(ctx, now) },
			func(ctx context.Context) error { return r.notifyNewAITooling(ctx, now) },
			func(ctx context.Context) error { return r.recordWeeks(ctx, now) },
		} {
			keep(func(ctx context.Context) error { return boundedWork(ctx, runnerStageTimeout, step) })
		}
	}
	return errors.Join(failures, ctx.Err())
}

// DailySlot is the most recent digest slot at or before now.
func DailySlot(now time.Time, hourUTC int) time.Time {
	now = now.UTC()
	slot := time.Date(now.Year(), now.Month(), now.Day(), hourUTC, 0, 0, 0, time.UTC)
	if now.Before(slot) {
		slot = slot.AddDate(0, 0, -1)
	}
	return slot
}

type pendingAlert struct {
	id       int64
	tenantID string
	attempts int
	payload  AlertPayload
}

func tenantName(ctx context.Context, q Querier, tenantID string) string {
	var name string
	_ = q.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&name)
	return name
}

// classifyMailError reports whether a failed send may be retried.
func classifyMailError(err error) (retriable bool) {
	if errors.Is(err, graphmail.ErrNotConfigured) {
		return false
	}
	var sendErr *graphmail.SendError
	if errors.As(err, &sendErr) {
		return sendErr.Retriable()
	}
	var tokenErr *graphmail.TokenError
	if errors.As(err, &tokenErr) {
		return tokenErr.Retriable()
	}
	// Software-governance alerts deliberately retain at-least-once delivery.
	// An uncertain Graph acceptance therefore retries and may duplicate rather
	// than silently omit the alert.
	return true
}

func storedMailError(err error) string {
	msg := err.Error()
	if len(msg) > maxEmailErrorLen {
		msg = msg[:maxEmailErrorLen] + "..."
	}
	return msg
}

// send delivers one message and returns nil, or the error to record.
func (r *Runner) send(ctx context.Context, to, subject, body string) error {
	if r.mail == nil {
		return graphmail.ErrNotConfigured
	}
	if err := graphmail.ValidateRecipients([]string{to}); err != nil {
		return fmt.Errorf("recipient rejected: %w", err)
	}
	sendCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return r.mail.Send(sendCtx, graphmail.Message{To: []string{to}, Subject: subject, Body: body})
}

// recordEmail writes the outcome for a set of alerts that shared one email.
func (r *Runner) recordEmail(ctx context.Context, ids []int64, attempts int, sendErr error, now time.Time) error {
	if sendErr == nil {
		_, err := r.pool.Exec(ctx, `
			UPDATE software_unapproved_alerts
			SET email_state = 'sent', email_sent_at = $2, email_attempts = email_attempts + 1, email_last_error = NULL
			WHERE id = ANY($1) AND email_state = 'pending'
		`, ids, now)
		return err
	}
	next := attempts + 1
	if !classifyMailError(sendErr) || next >= EmailMaxAttempts {
		_, err := r.pool.Exec(ctx, `
			UPDATE software_unapproved_alerts
			SET email_state = 'dead_letter', email_attempts = email_attempts + 1, email_last_error = $2
			WHERE id = ANY($1) AND email_state = 'pending'
		`, ids, storedMailError(sendErr))
		return err
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE software_unapproved_alerts
		SET email_attempts = email_attempts + 1, email_last_error = $2, email_next_attempt_at = $3
		WHERE id = ANY($1) AND email_state = 'pending'
	`, ids, storedMailError(sendErr), now.Add(webhook.RetryBackoff(next+1)))
	return err
}

func (r *Runner) markNoRecipient(ctx context.Context, ids []int64) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE software_unapproved_alerts
		SET email_state = 'no_recipient', email_last_error = 'the tenant has no contact email address configured'
		WHERE id = ANY($1) AND email_state = 'pending'
	`, ids)
	return err
}

func scanPending(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) ([]pendingAlert, error) {
	defer rows.Close()
	var out []pendingAlert
	for rows.Next() {
		var p pendingAlert
		var raw []byte
		if err := rows.Scan(&p.id, &p.tenantID, &p.attempts, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &p.payload); err != nil {
			return nil, fmt.Errorf("decode alert %d payload: %w", p.id, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *Runner) raiseUnraised(ctx context.Context, now time.Time) error {
	return RaiseUnraised(ctx, r.pool, now)
}

// RaiseUnraised raises every pending marked alert, a batch at a time: step 1
// of the Runner. It sends nothing; the Runner's next step emails the result.
func RaiseUnraised(ctx context.Context, pool *pgxpool.Pool, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, markedBatchTimeout)
	defer cancel()
	batches, err := UnraisedBatches(ctx, pool, now, UnraisedGrace, unraisedBatches)
	if err != nil {
		return err
	}
	var failures error
	for _, b := range batches {
		if ctx.Err() != nil {
			return errors.Join(failures, ctx.Err())
		}
		if err := recordRunnerAttempt(ctx, pool, "marked", b.TenantID, b.BatchKey); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		res, err := RaiseEpisodes(ctx, pool, b.TenantID, b.EpisodeIDs, now)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("raise batch %s for %s: %w", b.BatchKey, b.TenantID, err))
			continue
		}
		failures = errors.Join(failures, finishRunnerAttempt(ctx, pool, "marked", b.TenantID, b.BatchKey))
		slog.Info("softwaregov: raised marked unapproved alerts",
			"tenant_id", b.TenantID, "episodes", len(b.EpisodeIDs), "alerts", len(res.AlertIDs))
	}
	return failures
}

// sendMarked sends one email per policy-write request: every pending marked
// alert sharing an email_batch_id is listed in the same message.
// A failed raise must not cause a partial batch to be sent before the retry.
func (r *Runner) sendMarked(ctx context.Context, now time.Time) error {
	rows, err := r.pool.Query(ctx, `
		SELECT a.tenant_id::text, COALESCE(a.email_batch_id::text, 'alert-' || a.id::text) AS batch
		FROM software_unapproved_alerts a
		JOIN tenants t ON t.id = a.tenant_id AND t.revoked_at IS NULL
		WHERE a.email_state = 'pending' AND a.trigger = 'marked' AND a.email_next_attempt_at <= $1
		  AND NOT EXISTS (
		      SELECT 1 FROM software_unapproved_episodes e
		      WHERE e.tenant_id = a.tenant_id AND e.batch_id = a.email_batch_id
		        AND e.raised_at IS NULL AND e.source IN ('portal', 'operator'))
		GROUP BY 1, 2
		ORDER BY min(a.email_next_attempt_at)
		LIMIT $2
	`, now, markedBatch)
	if err != nil {
		return fmt.Errorf("pending marked batches: %w", err)
	}
	type batchKey struct{ tenantID, batch string }
	var batches []batchKey
	for rows.Next() {
		var b batchKey
		if err := rows.Scan(&b.tenantID, &b.batch); err != nil {
			rows.Close()
			return err
		}
		batches = append(batches, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, b := range batches {
		arows, err := r.pool.Query(ctx, `
			SELECT id, tenant_id::text, email_attempts, payload
			FROM software_unapproved_alerts
			WHERE tenant_id = $1::uuid AND email_state = 'pending' AND trigger = 'marked'
			  AND email_next_attempt_at <= $2
			  AND COALESCE(email_batch_id::text, 'alert-' || id::text) = $3
			ORDER BY id
			LIMIT $4
		`, b.tenantID, now, b.batch, markedBatchAlerts)
		if err != nil {
			return fmt.Errorf("pending marked alerts: %w", err)
		}
		pending, err := scanPending(arows)
		if err != nil || len(pending) == 0 {
			if err != nil {
				return err
			}
			continue
		}
		ids := make([]int64, 0, len(pending))
		payloads := make([]AlertPayload, 0, len(pending))
		attempts := 0
		for _, p := range pending {
			ids = append(ids, p.id)
			payloads = append(payloads, p.payload)
			if p.attempts > attempts {
				attempts = p.attempts
			}
		}
		rcpt, err := TenantRecipient(ctx, r.pool, b.tenantID)
		if err != nil {
			return err
		}
		if !rcpt.Configured {
			if err := r.markNoRecipient(ctx, ids); err != nil {
				return err
			}
			continue
		}
		subject, body := RenderMarkedEmail(mergeMarked(payloads), tenantName(ctx, r.pool, b.tenantID), *rcpt.Email)
		sendErr := r.send(ctx, *rcpt.Email, subject, body)
		if sendErr != nil {
			slog.Warn("softwaregov: unapproved alert email failed", "alerts", len(ids), "tenant_id", b.tenantID, "err", sendErr)
		}
		if err := r.recordEmail(ctx, ids, attempts, sendErr, now); err != nil {
			return err
		}
	}
	return nil
}

// mergeMarked folds the marked alerts of one request into one payload for
// the email: every product, the distinct device count, and the actor and
// time of the request (shared by every alert in it).
func mergeMarked(payloads []AlertPayload) AlertPayload {
	if len(payloads) == 1 {
		return payloads[0]
	}
	out := payloads[0]
	out.Products = nil
	devices := map[string]bool{}
	for _, p := range payloads {
		out.Products = append(out.Products, p.Products...)
		for _, prod := range p.Products {
			for _, d := range prod.Devices {
				devices[d.DeviceID] = true
			}
		}
		if p.Truncated {
			out.Truncated = true
		}
		if p.MarkedAt.Before(out.MarkedAt) {
			out.MarkedAt = p.MarkedAt
		}
	}
	out.DeviceCount = len(devices)
	return out
}

func (r *Runner) sendDigests(ctx context.Context, now time.Time) error {
	slot := DailySlot(now, r.digestHourUTC)
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT due.tenant_id::text
		FROM (
			SELECT a.tenant_id FROM software_unapproved_alerts a
			WHERE a.email_state = 'pending' AND a.trigger = 'observed' AND a.email_next_attempt_at <= $1
			  AND a.created_at < $2
			UNION
			-- PAT-2097: re-opened alerts waiting for the digest.
			SELECT ad.tenant_id FROM software_unapproved_alerted_devices ad
			WHERE ad.reopen_digest_pending AND ad.status = 'open' AND ad.last_reopened_at < $2
			  AND (ad.reopen_digest_next_attempt_at IS NULL OR ad.reopen_digest_next_attempt_at <= $1)
		) due
		JOIN tenants t ON t.id = due.tenant_id AND t.revoked_at IS NULL
		LEFT JOIN tenant_software_notification_settings s ON s.tenant_id = due.tenant_id
		WHERE (s.unapproved_digest_sent_at IS NULL OR s.unapproved_digest_sent_at < $2)
		LIMIT $3
	`, now, slot, digestTenantsBatch)
	if err != nil {
		return fmt.Errorf("digest tenants: %w", err)
	}
	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, tenantID := range tenants {
		if err := r.sendDigest(ctx, tenantID, slot, now); err != nil {
			return err
		}
	}
	return nil
}

// sendDigest sends the digest due at slot: the observed alerts raised before
// that slot. An alert raised after 07:00 UTC waits for the next day's slot,
// including a tenant's very first digest.
func (r *Runner) sendDigest(ctx context.Context, tenantID string, slot, now time.Time) error {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id::text, email_attempts, payload
		FROM software_unapproved_alerts
		WHERE tenant_id = $1::uuid AND email_state = 'pending' AND trigger = 'observed' AND email_next_attempt_at <= $2
		  AND created_at < $4
		ORDER BY id
		LIMIT $3
	`, tenantID, now, digestAlertLimit, slot)
	if err != nil {
		return fmt.Errorf("digest alerts: %w", err)
	}
	pending, err := scanPending(rows)
	if err != nil {
		return err
	}
	reopenIDs, reopened, reopenAttempts, err := pendingReopens(ctx, r.pool, tenantID, slot, now)
	if err != nil {
		return err
	}
	if len(pending) == 0 && len(reopenIDs) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(pending))
	payloads := make([]AlertPayload, 0, len(pending))
	attempts := 0
	for _, p := range pending {
		ids = append(ids, p.id)
		payloads = append(payloads, p.payload)
		if p.attempts > attempts {
			attempts = p.attempts
		}
	}
	rcpt, err := TenantRecipient(ctx, r.pool, tenantID)
	if err != nil {
		return err
	}
	// Re-opens are reported once: cleared when the digest was sent or there
	// is nobody to send it to. A transient failure retries with backoff
	// exactly as pending alerts do, without spending the slot; a permanent
	// failure or exhausted retries spends it and leaves them for the next.
	reopensDone := false
	if !rcpt.Configured {
		if len(ids) > 0 {
			if err := r.markNoRecipient(ctx, ids); err != nil {
				return err
			}
		}
		reopensDone = true
	} else {
		subject, body := RenderDigestEmail(payloads, reopened, tenantName(ctx, r.pool, tenantID), *rcpt.Email)
		sendErr := r.send(ctx, *rcpt.Email, subject, body)
		if sendErr != nil {
			slog.Warn("softwaregov: unapproved digest email failed", "tenant_id", tenantID, "alerts", len(ids),
				"reopened", len(reopenIDs), "err", sendErr)
		}
		tries := attempts
		if len(ids) > 0 {
			if err := r.recordEmail(ctx, ids, attempts, sendErr, now); err != nil {
				return err
			}
		} else {
			tries = reopenAttempts
		}
		if sendErr != nil && classifyMailError(sendErr) && tries+1 < EmailMaxAttempts {
			// Retrying: the slot is not spent until the digest is sent. The
			// re-opens wait for the same retry time as the alerts.
			if len(reopenIDs) > 0 {
				if _, err := r.pool.Exec(ctx, `
					UPDATE software_unapproved_alerted_devices
					SET reopen_digest_attempts = $2, reopen_digest_next_attempt_at = $3
					WHERE id = ANY($1) AND reopen_digest_pending
				`, reopenIDs, tries+1, now.Add(webhook.RetryBackoff(tries+2))); err != nil {
					return err
				}
			}
			return nil
		}
		reopensDone = sendErr == nil
	}
	if len(reopenIDs) > 0 {
		// A re-open newer than this digest's slot stays pending.
		if _, err := r.pool.Exec(ctx, `
			UPDATE software_unapproved_alerted_devices
			SET reopen_digest_pending = reopen_digest_pending AND NOT $3,
			    reopen_digest_attempts = 0, reopen_digest_next_attempt_at = NULL
			WHERE id = ANY($1) AND last_reopened_at < $2
		`, reopenIDs, slot, reopensDone); err != nil {
			return err
		}
	}
	if err := ensureSettingsRow(ctx, r.pool, tenantID); err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE tenant_software_notification_settings SET unapproved_digest_sent_at = $2 WHERE tenant_id = $1::uuid
	`, tenantID, now)
	return err
}

func (r *Runner) notifyNewSoftware(ctx context.Context, now time.Time) error {
	slot := DailySlot(now, r.digestHourUTC)
	rows, err := r.pool.Query(ctx, `
		SELECT s.tenant_id::text, s.new_software_notified_through
		FROM tenant_software_notification_settings s
		JOIN tenants t ON t.id = s.tenant_id AND t.revoked_at IS NULL
		WHERE s.new_software_enabled
		  AND (s.new_software_notified_through IS NULL OR s.new_software_notified_through < $1)
		LIMIT $2
	`, slot, notifyTenantsBatch)
	if err != nil {
		return fmt.Errorf("new software tenants: %w", err)
	}
	type due struct {
		tenantID string
		through  *time.Time
	}
	var dues []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.tenantID, &d.through); err != nil {
			rows.Close()
			return err
		}
		dues = append(dues, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range dues {
		// The first window after the setting is turned on is the day before
		// the slot; after that each window starts where the last ended.
		from := slot.Add(-24 * time.Hour)
		if d.through != nil && d.through.After(from.Add(-notifyCursorMaxAge)) {
			from = d.through.UTC()
		}
		ns, err := FetchNewSoftwareWindow(ctx, r.pool, d.tenantID, from, slot)
		if err != nil {
			return err
		}
		if len(ns.Products) > 0 {
			if err := raiseFirstSeen(ctx, r.pool, d.tenantID, ns); err != nil {
				return err
			}
		}
		if _, err := r.pool.Exec(ctx, `
			UPDATE tenant_software_notification_settings SET new_software_notified_through = $2 WHERE tenant_id = $1::uuid
		`, d.tenantID, slot); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) notifyNewAITooling(ctx context.Context, now time.Time) error {
	slot := DailySlot(now, r.digestHourUTC)
	rows, err := r.pool.Query(ctx, `
		SELECT s.tenant_id::text,s.ai_tooling_notified_through
		FROM tenant_software_notification_settings s
		JOIN tenants t ON t.id=s.tenant_id AND t.revoked_at IS NULL
		WHERE s.ai_tooling_notifications_enabled
		  AND (s.ai_tooling_notified_through IS NULL OR s.ai_tooling_notified_through < $1)
		LIMIT $2`, slot, notifyTenantsBatch)
	if err != nil {
		return fmt.Errorf("AI tooling notification tenants: %w", err)
	}
	type due struct {
		tenantID string
		through  *time.Time
	}
	var dues []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.tenantID, &d.through); err != nil {
			rows.Close()
			return err
		}
		dues = append(dues, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range dues {
		from := slot.Add(-24 * time.Hour)
		if d.through != nil && d.through.After(from.Add(-notifyCursorMaxAge)) {
			from = d.through.UTC()
		}
		ns, err := FetchNewAIToolingWindow(ctx, r.pool, d.tenantID, from, slot)
		if err != nil {
			return err
		}
		if len(ns.Products) > 0 {
			if err := raiseAIToolingFirstSeen(ctx, r.pool, d.tenantID, ns); err != nil {
				return err
			}
		}
		if _, err := r.pool.Exec(ctx, `UPDATE tenant_software_notification_settings
			SET ai_tooling_notified_through=$2 WHERE tenant_id=$1::uuid`, d.tenantID, slot); err != nil {
			return err
		}
	}
	return nil
}

// raiseFirstSeen enqueues the digest into every enabled channel subscribed to
// software.first_seen. The subject is the window end, so a replayed window is
// deduplicated by the channel idempotency key.
func raiseFirstSeen(ctx context.Context, pool *pgxpool.Pool, tenantID string, ns NewSoftware) error {
	products := make([]map[string]any, 0, len(ns.Products))
	for i, p := range ns.Products {
		if i >= maxNotifyProducts {
			break
		}
		products = append(products, map[string]any{
			"name": p.Name, "platform": p.Platform, "identifier": p.Identifier, "team_id": p.TeamID,
			"identity_basis": p.IdentityBasis, "product_key": p.ProductKey, "approval_state": p.ApprovalState,
			"first_seen_at": p.FirstSeenAt, "device_count": p.DeviceCount,
			"first_device_hostname": p.FirstDevice.Hostname,
		})
	}
	var since any
	if ns.Since != nil {
		since = ns.Since.UTC()
	}
	_, err := notifications.Notify(ctx, pool, notifications.Event{
		TenantID:  tenantID,
		Type:      webhook.EventSoftwareFirstSeen,
		Subject:   "software.first_seen/" + ns.Until.UTC().Format(time.RFC3339),
		Timestamp: ns.Until.UTC(),
		Data: map[string]any{
			"window_start":  since,
			"window_end":    ns.Until.UTC(),
			"product_count": ns.Total,
			"truncated":     ns.Total > len(products),
			"products":      products,
			"coverage":      ns.Coverage,
		},
	})
	if err != nil {
		return fmt.Errorf("raise software.first_seen: %w", err)
	}
	return nil
}

func raiseAIToolingFirstSeen(ctx context.Context, pool *pgxpool.Pool, tenantID string, ns NewSoftware) error {
	products := make([]map[string]any, 0, len(ns.Products))
	for i, p := range ns.Products {
		if i >= maxNotifyProducts {
			break
		}
		products = append(products, map[string]any{
			"name": p.Name, "identity": p.Identifier, "identity_kind": p.ObservationKind,
			"source": p.ObservationSource, "product_key": p.ProductKey,
			"approval_state": p.ApprovalState, "first_seen_at": p.FirstSeenAt,
			"device_count": p.DeviceCount, "first_device_hostname": p.FirstDevice.Hostname,
		})
	}
	_, err := notifications.Notify(ctx, pool, notifications.Event{
		TenantID: tenantID, Type: webhook.EventAIToolingFirstSeen,
		Subject: "ai_tooling.first_seen/" + ns.Until.UTC().Format(time.RFC3339), Timestamp: ns.Until.UTC(),
		Data: map[string]any{"window_start": ns.Since, "window_end": ns.Until.UTC(), "product_count": ns.Total,
			"truncated": ns.Total > len(products), "products": products, "coverage": ns.Coverage},
	})
	if err != nil {
		return fmt.Errorf("raise ai_tooling.first_seen: %w", err)
	}
	return nil
}

func (r *Runner) recordWeeks(ctx context.Context, now time.Time) error {
	week := WeekStart(now)
	rows, err := r.pool.Query(ctx, `
		SELECT t.id::text
		FROM tenants t
		LEFT JOIN software_governance_weekly w ON w.tenant_id = t.id AND w.week_start = $1::date
		WHERE t.revoked_at IS NULL
		  AND (w.captured_at IS NULL OR w.captured_at < $2)
		ORDER BY w.captured_at NULLS FIRST, t.id
		LIMIT $3
	`, week, now.Add(-24*time.Hour), snapshotBatch)
	if err != nil {
		return fmt.Errorf("weekly capture tenants: %w", err)
	}
	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range tenants {
		e, err := LoadEstate(ctx, r.pool, t, now)
		if errors.Is(err, ErrEstateTooLarge) {
			slog.Warn("softwaregov: weekly capture skipped, estate over load cap", "tenant_id", t)
			continue
		}
		if err != nil {
			return err
		}
		if err := RecordWeek(ctx, r.pool, t, e); err != nil {
			return err
		}
	}
	return nil
}

// pendingReopens returns the tenant's re-opened alerts waiting for the digest
// due at slot, with the payload each re-open recorded (PAT-2097).
func pendingReopens(ctx context.Context, q Querier, tenantID string, slot, now time.Time) ([]int64, []AlertPayload, int, error) {
	rows, err := q.Query(ctx, `
		SELECT ad.id, ad.reopen_digest_attempts, tr.detail->'payload'
		FROM software_unapproved_alerted_devices ad
		JOIN LATERAL (
			SELECT t.detail FROM software_unapproved_alert_transitions t
			WHERE t.alert_device_id = ad.id AND t.tenant_id = ad.tenant_id
			  AND t.from_status = 'resolved' AND t.to_status = 'open'
			ORDER BY t.id DESC LIMIT 1
		) tr ON true
		WHERE ad.tenant_id = $1::uuid AND ad.reopen_digest_pending AND ad.status = 'open'
		  AND ad.last_reopened_at < $2
		  AND (ad.reopen_digest_next_attempt_at IS NULL OR ad.reopen_digest_next_attempt_at <= $4)
		ORDER BY ad.id
		LIMIT $3
	`, tenantID, slot, digestAlertLimit, now)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("digest reopened alerts: %w", err)
	}
	defer rows.Close()
	var ids []int64
	var payloads []AlertPayload
	maxAttempts := 0
	for rows.Next() {
		var id int64
		var attempts int
		var raw []byte
		if err := rows.Scan(&id, &attempts, &raw); err != nil {
			return nil, nil, 0, err
		}
		if attempts > maxAttempts {
			maxAttempts = attempts
		}
		ids = append(ids, id)
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var p AlertPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, nil, 0, fmt.Errorf("decode reopen %d payload: %w", id, err)
		}
		payloads = append(payloads, p)
	}
	return ids, payloads, maxAttempts, rows.Err()
}
