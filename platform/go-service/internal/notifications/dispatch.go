package notifications

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/webhook"
)

// Notify records one event against every matching channel for the tenant.
//
// It performs database writes only. It is safe to call from a hot path and
// MUST be called after the transaction that established the finding has
// committed, never inside it: an event that is enqueued and then rolled back
// would be a notification about a finding that does not exist, and an enqueue
// failure inside the transaction would roll back the finding itself.
//
// It returns the number of deliveries enqueued. A duplicate trigger enqueues
// nothing and is not an error.
func Notify(ctx context.Context, pool *pgxpool.Pool, ev Event) (int, error) {
	if pool == nil {
		return 0, errors.New("notifications: nil pool")
	}
	if strings.TrimSpace(ev.TenantID) == "" || strings.TrimSpace(ev.Subject) == "" || ev.Type == "" {
		return 0, errors.New("notifications: event requires tenant_id, type and subject")
	}

	channelIDs, skipped, err := matchingChannels(ctx, pool, ev)
	if err != nil {
		return 0, fmt.Errorf("match notification channels: %w", err)
	}
	if len(skipped) > 0 {
		slog.Debug("notifications: event below channel severity threshold",
			"event", string(ev.Type), "severity", ev.Severity, "channels", len(skipped))
	}

	enqueued := 0
	for _, channelID := range channelIDs {
		payload, err := BuildPayload(channelID, ev)
		if err != nil {
			return enqueued, fmt.Errorf("build notification payload: %w", err)
		}
		inserted, err := enqueue(ctx, pool, channelID, ev, payload)
		if err != nil {
			return enqueued, fmt.Errorf("enqueue notification delivery: %w", err)
		}
		if inserted {
			enqueued++
		}
	}
	return enqueued, nil
}

// NotifyAsync raises an event without blocking or failing the caller. It is the
// form used from extraction and CVE reconciliation: notification is a reporting
// side effect of a finding, never a precondition for one, so every error here
// is logged and dropped.
func NotifyAsync(pool *pgxpool.Pool, ev Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := Notify(ctx, pool, ev); err != nil {
			slog.Warn("notifications: enqueue failed, finding state unaffected",
				"tenant_id", ev.TenantID, "event", string(ev.Type), "err", err)
		}
	}()
}

// WebhookTransport posts one signed body to one destination and returns the
// HTTP status.
type WebhookTransport func(ctx context.Context, url string, headers map[string]string, body []byte) (int, error)

// Dispatcher performs the actual sends. It is the only part of this package
// that touches the network.
type Dispatcher struct {
	pool      *pgxpool.Pool
	mail      graphmail.Sender
	transport WebhookTransport
}

// DispatcherOption customises a Dispatcher at construction time.
type DispatcherOption func(*Dispatcher)

// WithTransport replaces the webhook transport.
//
// This exists for tests, and only because the production transport is doing its
// job: webhook.PostHardened refuses loopback, which is exactly where an
// httptest server lives, so a delivery test cannot use the real one. Production
// wiring never calls this, and the SSRF behaviour it bypasses is covered
// directly in internal/webhook rather than through this seam.
func WithTransport(t WebhookTransport) DispatcherOption {
	return func(d *Dispatcher) {
		if t != nil {
			d.transport = t
		}
	}
}

// NewDispatcher builds a Dispatcher. mail may be nil when the Graph mailer is
// not configured; email deliveries then dead-letter with an explicit reason
// instead of disappearing.
func NewDispatcher(pool *pgxpool.Pool, mail graphmail.Sender, opts ...DispatcherOption) *Dispatcher {
	d := &Dispatcher{pool: pool, mail: mail, transport: webhook.PostHardened}
	for _, o := range opts {
		o(d)
	}
	return d
}

// pendingDelivery is one due row joined with its channel.
type pendingDelivery struct {
	id           int64
	channelID    string
	tenantID     string
	eventType    string
	idempotency  string
	payload      []byte
	attemptCount int
	channelType  string
	url          string
	secret       []byte
	recipients   []string
}

// attemptResult is the outcome of exactly one send.
type attemptResult struct {
	status    int
	transport bool   // the send failed before any response
	permanent bool   // retrying cannot help, whatever the attempt budget says
	reason    string // dead-letter reason to use when permanent
	err       error
}

// deliver performs one attempt for one row and returns what happened. It never
// writes to the database and never touches finding state.
func (d *Dispatcher) deliver(ctx context.Context, p pendingDelivery) attemptResult {
	switch p.channelType {
	case ChannelWebhook:
		return d.deliverWebhook(ctx, p)
	case ChannelEmail:
		return d.deliverEmail(ctx, p)
	default:
		return attemptResult{
			permanent: true,
			reason:    ReasonUndeliverable,
			err:       fmt.Errorf("unknown channel type %q", p.channelType),
		}
	}
}

func (d *Dispatcher) deliverWebhook(ctx context.Context, p pendingDelivery) attemptResult {
	if len(p.secret) == 0 || strings.TrimSpace(p.url) == "" {
		return attemptResult{
			permanent: true,
			reason:    ReasonUndeliverable,
			err:       errors.New("webhook channel has no destination or signing secret"),
		}
	}
	ts := time.Now().UTC().Unix()
	headers := map[string]string{
		"X-Patched-Event":           p.eventType,
		"X-Patched-Timestamp":       strconv.FormatInt(ts, 10),
		"X-Patched-Signature":       webhook.SignWithTimestamp(p.secret, ts, p.payload),
		"X-Patched-Idempotency-Key": p.idempotency,
	}
	status, err := d.transport(ctx, p.url, headers, p.payload)
	if err != nil {
		// A blocked destination is a configuration fault, not a transient one:
		// retrying an address we will always refuse just burns the budget and
		// delays the dead-letter the owner needs to see.
		if errors.Is(err, webhook.ErrBlockedDestination) {
			return attemptResult{permanent: true, reason: ReasonUndeliverable, err: err}
		}
		return attemptResult{transport: true, err: err}
	}
	return attemptResult{status: status}
}

func (d *Dispatcher) deliverEmail(ctx context.Context, p pendingDelivery) attemptResult {
	if d.mail == nil {
		return attemptResult{
			permanent: true,
			reason:    ReasonUndeliverable,
			err:       graphmail.ErrNotConfigured,
		}
	}
	if len(p.recipients) == 0 {
		return attemptResult{
			permanent: true,
			reason:    ReasonUndeliverable,
			err:       errors.New("email channel has no recipients"),
		}
	}

	subject, body := RenderEmail(p.eventType, p.payload)
	err := d.mail.Send(ctx, graphmail.Message{To: p.recipients, Subject: subject, Body: body})
	if err == nil {
		return attemptResult{status: 202}
	}
	if errors.Is(err, graphmail.ErrNotConfigured) {
		return attemptResult{permanent: true, reason: ReasonUndeliverable, err: err}
	}
	// A rejected token is our own mailer credential or tenant configuration
	// being wrong, not this message being unacceptable. It dead-letters as a
	// configuration fault so the owner sees what to fix, and it never spends
	// the retry budget: the next five attempts would present the same bad
	// credential and fail identically.
	var tokenErr *graphmail.TokenError
	if errors.As(err, &tokenErr) {
		if tokenErr.Retriable() {
			return attemptResult{status: tokenErr.Status, err: err}
		}
		return attemptResult{status: tokenErr.Status, permanent: true, reason: ReasonUndeliverable, err: err}
	}
	var sendErr *graphmail.SendError
	if errors.As(err, &sendErr) {
		if sendErr.Retriable() {
			return attemptResult{status: sendErr.Status, err: err}
		}
		return attemptResult{status: sendErr.Status, permanent: true, reason: ReasonPermanent, err: err}
	}
	// This channel deliberately provides at-least-once delivery. In particular,
	// DeliveryUncertainError remains a retriable transport result and may cause
	// a duplicate if Graph accepted the response-less attempt.
	return attemptResult{transport: true, err: err}
}

// record persists the outcome of one attempt. Terminal states clear
// next_attempt_at so a dead-lettered row is never picked up again.
func (d *Dispatcher) record(ctx context.Context, p pendingDelivery, res attemptResult) (string, error) {
	attempt := p.attemptCount + 1

	state := StatePending
	var reason *string
	var nextAttemptAt *time.Time

	switch {
	case res.permanent:
		state = StateDeadLetter
		r := res.reason
		if r == "" {
			r = ReasonPermanent
		}
		reason = &r
	default:
		outcome, backoff := webhook.ClassifyAttempt(res.status, res.transport, attempt, MaxAttempts)
		switch outcome {
		case webhook.AttemptDelivered:
			state = StateDelivered
		case webhook.AttemptPermanent:
			state = StateDeadLetter
			r := ReasonPermanent
			reason = &r
		case webhook.AttemptExhausted:
			state = StateDeadLetter
			r := ReasonMaxAttempts
			reason = &r
		default:
			next := time.Now().Add(backoff)
			nextAttemptAt = &next
		}
	}

	// Every non-delivered attempt leaves a reason behind. A rejection that
	// arrived as a bare status carries no error value, so one is written here:
	// a dead-lettered row with an empty last_error tells an owner nothing, and
	// "it failed, look elsewhere" is the shape of an unauditable trail.
	//
	// storedDeliveryError (not redactError) is deliberate here: a transport
	// error can carry the destination host or resolved address, which
	// redactError does not strip, and this column is the owner-visible one
	// (PAT-1956). The unredacted res.err still reaches the server log in
	// process() below, correlated with the delivery id.
	var lastError *string
	if msg := storedDeliveryError(res.err); msg != "" {
		lastError = &msg
	} else if state != StateDelivered && res.status != 0 {
		msg := "destination returned status " + strconv.Itoa(res.status)
		lastError = &msg
	}
	var status *int
	if res.status != 0 {
		s := res.status
		status = &s
	}

	_, err := d.pool.Exec(ctx, `
		UPDATE notification_deliveries
		SET attempt_count   = attempt_count + 1,
		    last_attempt_at = now(),
		    response_status = $2,
		    last_error      = $3,
		    state           = $4,
		    failure_reason  = $5,
		    succeeded_at    = CASE WHEN $4 = 'delivered' THEN now() ELSE succeeded_at END,
		    next_attempt_at = $6
		WHERE id = $1
	`, p.id, status, lastError, state, reason, nextAttemptAt)
	if err != nil {
		return state, fmt.Errorf("record notification attempt: %w", err)
	}
	return state, nil
}

// process runs one attempt and records it.
func (d *Dispatcher) process(ctx context.Context, p pendingDelivery) {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	res := d.deliver(attemptCtx, p)

	// Persist on a background context so a shutdown mid-flight still records
	// the attempt, rather than leaving a row that re-fires immediately.
	recordCtx, recordCancel := context.WithTimeout(context.Background(), recordTimeout)
	defer recordCancel()

	state, err := d.record(recordCtx, p, res)
	if err != nil {
		slog.Warn("notifications: recording attempt failed",
			"delivery_id", p.id, "channel_id", p.channelID, "err", err)
		return
	}
	switch state {
	case StateDelivered:
		slog.Info("notifications: delivered",
			"delivery_id", p.id, "channel_id", p.channelID, "event", p.eventType, "status", res.status)
	case StateDeadLetter:
		slog.Warn("notifications: dead-lettered",
			"delivery_id", p.id, "channel_id", p.channelID, "event", p.eventType,
			"status", res.status, "err", redactError(res.err))
	default:
		// The error is logged here as well as on the dead-letter branch: since
		// PAT-1956 the stored last_error is a fixed generic string, so for a
		// retryable transport failure this log line is the only place the
		// destination address still appears. redactError removes secrets and
		// bounds the length; it keeps the host and address on purpose.
		slog.Info("notifications: retry scheduled",
			"delivery_id", p.id, "channel_id", p.channelID, "attempt", p.attemptCount+1,
			"err", redactError(res.err))
	}
}

// SendTest delivers a clearly labelled synthetic test.ping to one channel and
// returns the delivery row id and the resulting state.
//
// It proves a configuration end to end without fabricating anything: it writes
// a notification_deliveries row and nothing else. No finding, no
// finding_lifecycle_events row, no compliance evaluation. The payload is
// explicitly marked as a test so a receiver cannot mistake it for evidence.
//
// Each call uses a fresh subject, so repeated tests are each delivered rather
// than deduplicated against the first.
func (d *Dispatcher) SendTest(ctx context.Context, channelID, tenantID string) (int64, string, error) {
	target, err := loadChannelTarget(ctx, d.pool, channelID, tenantID)
	if err != nil {
		return 0, "", err
	}

	now := time.Now().UTC()
	ev := Event{
		TenantID:  tenantID,
		Type:      webhook.EventTestPing,
		Subject:   "test/" + strconv.FormatInt(now.UnixNano(), 10),
		Timestamp: now,
		Data: map[string]any{
			"test":    true,
			"message": "Test notification from Patched. This is not a finding and no evidence was assessed.",
		},
	}
	payload, err := BuildPayload(channelID, ev)
	if err != nil {
		return 0, "", err
	}

	key := IdempotencyKey(channelID, ev.Type, ev.Subject)
	var deliveryID int64
	if err := d.pool.QueryRow(ctx, `
		INSERT INTO notification_deliveries
			(channel_id, tenant_id, event_type, subject, idempotency_key, payload, next_attempt_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, now())
		RETURNING id
	`, channelID, tenantID, string(ev.Type), ev.Subject, key, string(payload)).Scan(&deliveryID); err != nil {
		return 0, "", err
	}

	p := pendingDelivery{
		id:          deliveryID,
		channelID:   channelID,
		tenantID:    tenantID,
		eventType:   string(ev.Type),
		idempotency: key,
		payload:     payload,
		channelType: target.kind,
		url:         target.url,
		secret:      target.secret,
		recipients:  target.recipients,
	}

	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	res := d.deliver(attemptCtx, p)

	recordCtx, recordCancel := context.WithTimeout(context.Background(), recordTimeout)
	defer recordCancel()
	state, err := d.record(recordCtx, p, res)
	if err != nil {
		return deliveryID, "", err
	}
	return deliveryID, state, nil
}

// RenderEmail builds the subject and plain-text body for one event payload.
//
// The wording is constrained by what the evidence supports: a stale-evidence
// event says verification could not be completed, never that the finding is
// resolved.
func RenderEmail(eventType string, payload []byte) (subject, body string) {
	headline := map[string]string{
		string(webhook.EventFindingOpened):      "New finding observed",
		string(webhook.EventFindingRecurred):    "Finding has recurred",
		string(webhook.EventEvidenceStale):      "Verification could not be confirmed",
		string(webhook.EventVerificationPassed): "Finding verified as fixed",
		string(webhook.EventVerificationFailed): "Finding still failing after verification",
		string(webhook.EventTestPing):           "Test notification",
		string(webhook.EventSoftwareFirstSeen):  "New software seen in your estate",
		string(webhook.EventAIToolingFirstSeen): "New AI tooling seen in your estate",
	}[eventType]
	if headline == "" {
		headline = "Patched notification"
	}

	explanation := map[string]string{
		string(webhook.EventEvidenceStale):      "Patched asked for verification but the endpoint evidence needed to judge it was missing or older than one collection cycle. The finding has not been cleared.",
		string(webhook.EventVerificationPassed): "Fresh endpoint evidence shows this finding now passes.",
		string(webhook.EventVerificationFailed): "Fresh endpoint evidence shows this finding still fails.",
		string(webhook.EventTestPing):           "This message confirms your notification channel is configured. It is not a finding and no evidence was assessed.",
		string(webhook.EventSoftwareFirstSeen):  "These products were reported by your devices for the first time in the period below. Being new is not a judgement on the software. Review them in the Patched portal and mark each one Approved, Unapproved or Ignored.",
		string(webhook.EventAIToolingFirstSeen): "These AI tooling identities were reported by your devices for the first time in the period below. Partial collection is a lower bound and unavailable collection remains unknown. Review them in the Patched portal before recording an approval decision.",
	}[eventType]

	var b strings.Builder
	b.WriteString(headline)
	b.WriteString("\n\n")
	if explanation != "" {
		b.WriteString(explanation)
		b.WriteString("\n\n")
	}
	b.WriteString("Event: ")
	b.WriteString(eventType)
	b.WriteString("\n\nDetail:\n")
	b.Write(payload)
	b.WriteString("\n")

	return "Patched: " + headline, b.String()
}
