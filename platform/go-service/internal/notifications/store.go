package notifications

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/webhook"
)

// Every statement in this file is scoped by tenant_id. A row belonging to
// another tenant is indistinguishable from a row that does not exist: the
// queries return pgx.ErrNoRows, which handlers turn into 404. There is no path
// that returns 403 for a cross-tenant id, because a 403 would confirm the id
// exists.

// ValidationError marks a caller configuration mistake, as opposed to a
// database or transport failure. Handlers turn it into 400 with the message
// attached; anything else becomes an opaque 500, so an internal failure cannot
// leak its detail through an error string.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// ChannelSpec is the validated configuration for one channel.
type ChannelSpec struct {
	Type        string
	Name        string
	Enabled     bool
	Events      []string
	MinSeverity string
	URL         string
	Recipients  []string
}

// Validate checks a spec against the event catalogue, the severity vocabulary
// and the per-type destination rules. It is the single validation entry point,
// used by both create and update so the two cannot diverge.
func (s *ChannelSpec) Validate() error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return invalid("name is required")
	}
	if len(s.Name) > 120 {
		return invalid("name must be 120 characters or fewer")
	}

	if s.MinSeverity == "" {
		s.MinSeverity = SeverityLow
	}
	s.MinSeverity = strings.ToLower(strings.TrimSpace(s.MinSeverity))
	if !ValidSeverity(s.MinSeverity) {
		return invalid("min_severity must be one of low, medium, high, critical")
	}

	if len(s.Events) == 0 {
		return invalid("events must not be empty")
	}
	if err := ValidateEvents(s.Events); err != nil {
		return err
	}

	switch s.Type {
	case ChannelWebhook:
		if err := webhook.ValidateDestination(s.URL); err != nil {
			return invalid("%s", err.Error())
		}
		if len(s.Recipients) > 0 {
			return invalid("recipients are not valid for a webhook channel")
		}
	case ChannelEmail:
		if strings.TrimSpace(s.URL) != "" {
			return invalid("destination_url is not valid for an email channel")
		}
		if err := graphmail.ValidateRecipients(s.Recipients); err != nil {
			return invalid("%s", err.Error())
		}
	default:
		return invalid("channel_type must be webhook or email")
	}
	return nil
}

// ValidateEvents checks that every entry is in the PAT-1888 event catalogue.
// test.ping is not subscribable: it is sent explicitly by the test endpoint and
// a subscription to it would never be matched by a real event.
func ValidateEvents(events []string) error {
	channelEvents := webhook.ChannelEvents()
	known := make(map[string]bool, len(channelEvents))
	for _, e := range channelEvents {
		known[e] = true
	}
	seen := make(map[string]bool, len(events))
	for _, e := range events {
		e = strings.TrimSpace(e)
		if !known[e] {
			return invalid("unknown event type: %s", e)
		}
		if seen[e] {
			return invalid("event type listed twice: %s", e)
		}
		seen[e] = true
	}
	return nil
}

// ListChannels returns every channel for a tenant, without secrets.
func ListChannels(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]Channel, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text, tenant_id::text, channel_type, name, enabled, events,
		       min_severity, coalesce(destination_url, ''), recipients,
		       created_at, updated_at
		FROM notification_channels
		WHERE tenant_id = $1::uuid
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	channels := []Channel{}
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Type, &c.Name, &c.Enabled, &c.Events,
			&c.MinSeverity, &c.URL, &c.Recipients, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		channels = append(channels, c)
	}
	return channels, rows.Err()
}

// GetChannel returns one channel by (id, tenantID), without the secret.
// Returns pgx.ErrNoRows when it does not exist or belongs to another tenant.
func GetChannel(ctx context.Context, pool *pgxpool.Pool, id, tenantID string) (Channel, error) {
	var c Channel
	err := pool.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, channel_type, name, enabled, events,
		       min_severity, coalesce(destination_url, ''), recipients,
		       created_at, updated_at
		FROM notification_channels
		WHERE id = $1::uuid AND tenant_id = $2::uuid
	`, id, tenantID).Scan(&c.ID, &c.TenantID, &c.Type, &c.Name, &c.Enabled, &c.Events,
		&c.MinSeverity, &c.URL, &c.Recipients, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return Channel{}, err
	}
	return c, nil
}

// CreateChannel inserts a channel and, for a webhook channel, returns the
// generated signing secret. That return value is the only time the plaintext
// secret exists outside this function: the stored copy is envelope-encrypted
// and no read path decrypts it into any response.
func CreateChannel(ctx context.Context, pool *pgxpool.Pool, tenantID string, spec ChannelSpec) (id, secret string, err error) {
	if err := spec.Validate(); err != nil {
		return "", "", err
	}

	var storedSecret, storedURL any
	if spec.Type == ChannelWebhook {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", "", fmt.Errorf("generate channel secret: %w", err)
		}
		secret = hex.EncodeToString(raw)
		enc, err := envelope.Default().EncryptString(secret)
		if err != nil {
			return "", "", fmt.Errorf("encrypt channel secret: %w", err)
		}
		storedSecret = enc
		storedURL = spec.URL
	}
	if spec.Recipients == nil {
		spec.Recipients = []string{}
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO notification_channels
			(tenant_id, channel_type, name, enabled, events, min_severity,
			 destination_url, secret, recipients)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id::text
	`, tenantID, spec.Type, spec.Name, spec.Enabled, spec.Events, spec.MinSeverity,
		storedURL, storedSecret, spec.Recipients).Scan(&id); err != nil {
		return "", "", err
	}
	return id, secret, nil
}

// UpdateChannel applies a validated spec to an existing channel. The secret is
// never touched: there is no rotation path through this call, so an update can
// never overwrite or expose it. channel_type is also immutable, because
// changing it would leave the destination columns describing a different shape
// than the stored secret implies.
func UpdateChannel(ctx context.Context, pool *pgxpool.Pool, id, tenantID string, spec ChannelSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if spec.Recipients == nil {
		spec.Recipients = []string{}
	}

	var storedURL any
	if spec.Type == ChannelWebhook {
		storedURL = spec.URL
	}

	tag, err := pool.Exec(ctx, `
		UPDATE notification_channels
		SET name = $1, enabled = $2, events = $3, min_severity = $4,
		    destination_url = $5, recipients = $6, updated_at = now()
		WHERE id = $7::uuid AND tenant_id = $8::uuid AND channel_type = $9
	`, spec.Name, spec.Enabled, spec.Events, spec.MinSeverity, storedURL,
		spec.Recipients, id, tenantID, spec.Type)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// DeleteChannel removes a channel and cascades to its deliveries.
//
// Disabling is the documented rollback, not this. Deleting discards the audit
// trail, which the ticket explicitly wants retained, so the handler for it is
// there for genuine removal of a configuration that was created in error.
func DeleteChannel(ctx context.Context, pool *pgxpool.Pool, id, tenantID string) error {
	tag, err := pool.Exec(ctx, `
		DELETE FROM notification_channels WHERE id = $1::uuid AND tenant_id = $2::uuid
	`, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// channelTarget is a channel loaded for delivery, including the decrypted
// secret. It never leaves this package.
type channelTarget struct {
	id         string
	tenantID   string
	kind       string
	url        string
	secret     []byte
	recipients []string
}

// matchingChannels returns the enabled channels for a tenant that subscribe to
// this event type and whose severity threshold the event clears.
//
// The severity filter runs in Go rather than SQL so MeetsThreshold is the one
// place that decides what an ungraded event does.
func matchingChannels(ctx context.Context, pool *pgxpool.Pool, ev Event) ([]string, []string, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text, min_severity
		FROM notification_channels
		WHERE tenant_id = $1::uuid
		  AND enabled = true
		  AND events @> ARRAY[$2::text]
		ORDER BY id
	`, ev.TenantID, string(ev.Type))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var ids, skipped []string
	for rows.Next() {
		var id, minSeverity string
		if err := rows.Scan(&id, &minSeverity); err != nil {
			return nil, nil, err
		}
		if !MeetsThreshold(ev.Severity, minSeverity) {
			skipped = append(skipped, id)
			continue
		}
		ids = append(ids, id)
	}
	return ids, skipped, rows.Err()
}

// enqueue writes one pending delivery for one channel, or reports that an
// identical one already exists. The unique index on
// (channel_id, idempotency_key) is what makes this idempotent, so two
// concurrent callers racing on the same event cannot both win.
func enqueue(ctx context.Context, pool *pgxpool.Pool, channelID string, ev Event, payload []byte) (inserted bool, err error) {
	key := IdempotencyKey(channelID, ev.Type, ev.Subject)
	tag, err := pool.Exec(ctx, `
		INSERT INTO notification_deliveries
			(channel_id, tenant_id, event_type, subject, idempotency_key, payload, next_attempt_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, now())
		ON CONFLICT (channel_id, idempotency_key) DO NOTHING
	`, channelID, ev.TenantID, string(ev.Type), ev.Subject, key, string(payload))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// BuildPayload renders the wire body for one event and channel. The idempotency
// key is inside the body as well as in a header, so a receiver that only reads
// the body can still deduplicate.
func BuildPayload(channelID string, ev Event) ([]byte, error) {
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return json.Marshal(Payload{
		EventType:      string(ev.Type),
		TenantID:       ev.TenantID,
		Subject:        ev.Subject,
		Severity:       ev.Severity,
		IdempotencyKey: IdempotencyKey(channelID, ev.Type, ev.Subject),
		Timestamp:      ts.UTC(),
		Data:           ev.Data,
	})
}

// ListDeliveries returns a bounded page of delivery records for one channel,
// newest first, optionally filtered to one state.
//
// Ownership is checked first so a delivery listing cannot confirm the existence
// of another tenant's channel.
func ListDeliveries(ctx context.Context, pool *pgxpool.Pool, channelID, tenantID, state string, limit int) ([]Delivery, error) {
	var exists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notification_channels WHERE id = $1::uuid AND tenant_id = $2::uuid
		)
	`, channelID, tenantID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, pgx.ErrNoRows
	}

	rows, err := pool.Query(ctx, `
		SELECT id, channel_id::text, event_type, subject, idempotency_key, state,
		       failure_reason, response_status, attempt_count, last_error,
		       next_attempt_at, last_attempt_at, succeeded_at, created_at
		FROM notification_deliveries
		WHERE channel_id = $1::uuid
		  AND tenant_id = $2::uuid
		  AND ($3::text = '' OR state = $3::text)
		ORDER BY created_at DESC, id DESC
		LIMIT $4
	`, channelID, tenantID, state, ClampPageSize(limit))
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// ListTenantDeliveries returns a bounded page across every channel of one
// tenant, newest first, optionally filtered to one state. This is the
// dead-letter view: state = StateDeadLetter.
func ListTenantDeliveries(ctx context.Context, pool *pgxpool.Pool, tenantID, state string, limit int) ([]Delivery, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, channel_id::text, event_type, subject, idempotency_key, state,
		       failure_reason, response_status, attempt_count, last_error,
		       next_attempt_at, last_attempt_at, succeeded_at, created_at
		FROM notification_deliveries
		WHERE tenant_id = $1::uuid
		  AND ($2::text = '' OR state = $2::text)
		ORDER BY created_at DESC, id DESC
		LIMIT $3
	`, tenantID, state, ClampPageSize(limit))
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

func scanDeliveries(rows pgx.Rows) ([]Delivery, error) {
	defer rows.Close()
	deliveries := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.EventType, &d.Subject, &d.IdempotencyKey,
			&d.State, &d.FailureReason, &d.ResponseStatus, &d.AttemptCount, &d.LastError,
			&d.NextAttemptAt, &d.LastAttemptAt, &d.SucceededAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

// ClampPageSize bounds a requested page size into [1, MaxDeliveryPageSize].
func ClampPageSize(limit int) int {
	if limit <= 0 {
		return DefaultDeliveryPageSize
	}
	if limit > MaxDeliveryPageSize {
		return MaxDeliveryPageSize
	}
	return limit
}

// ValidDeliveryState reports whether s is a state a listing may filter on. The
// empty string means "no filter".
func ValidDeliveryState(s string) bool {
	switch s {
	case "", StatePending, StateDelivered, StateDeadLetter:
		return true
	default:
		return false
	}
}

// loadChannelTarget loads one channel with its decrypted secret, for delivery
// only. Callers must not put the returned secret into a response or a log.
//
// tenantID is optional, and which callers pass it is a tenancy decision, not a
// convenience:
//
//   - Any handler-reachable path MUST pass it. There the channel id arrives
//     from a URL supplied by the caller, so the tenant scope is the only thing
//     standing between one tenant and another's channel, and omitting it would
//     turn a guessed id into a cross-tenant read. SendTest passes it for
//     exactly this reason.
//   - The sweeper path does not, because it has no untrusted id to check: it
//     is acting on a delivery row it already selected, and that row carries its
//     own denormalised tenant_id (migration 0157 copies it from the channel at
//     enqueue time, which is why the dead-letter listing can be tenant-scoped
//     without trusting a join).
//
// If in doubt, pass it. A redundant tenant scope costs one predicate.
func loadChannelTarget(ctx context.Context, pool *pgxpool.Pool, channelID, tenantID string) (channelTarget, error) {
	var t channelTarget
	var secret *string
	var url *string
	query := `
		SELECT id::text, tenant_id::text, channel_type, destination_url, secret, recipients
		FROM notification_channels
		WHERE id = $1::uuid
	`
	args := []any{channelID}
	if tenantID != "" {
		query += ` AND tenant_id = $2::uuid`
		args = append(args, tenantID)
	}
	if err := pool.QueryRow(ctx, query, args...).Scan(
		&t.id, &t.tenantID, &t.kind, &url, &secret, &t.recipients); err != nil {
		return channelTarget{}, err
	}
	if url != nil {
		t.url = *url
	}
	if secret != nil {
		plain, err := decryptSecret(*secret)
		if err != nil {
			return channelTarget{}, err
		}
		t.secret = plain
	}
	return t, nil
}

// decryptSecret unwraps a stored channel secret.
//
// Decrypt-with-plaintext-fallback, matching internal/webhook: a row written
// while PATCHED_KEK was unset is returned verbatim. The error deliberately
// carries no part of the stored value.
func decryptSecret(stored string) ([]byte, error) {
	plain, err := envelope.Default().DecryptString(stored)
	if err != nil {
		return nil, errors.New("decrypt channel secret failed")
	}
	return []byte(plain), nil
}
