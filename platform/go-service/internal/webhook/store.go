package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
)

// hookWithSecret is the internal hook row including the secret bytes; never
// serialised to JSON. Used only within the dispatcher.
type hookWithSecret struct {
	id     string
	url    string
	secret []byte // UTF-8 bytes of the hex secret string
}

// List returns all webhooks for a tenant, without secrets.
func List(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]Hook, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text, tenant_id::text, url, events, enabled, created_at, updated_at
		FROM tenant_webhooks
		WHERE tenant_id = $1::uuid
		ORDER BY created_at
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hooks []Hook
	for rows.Next() {
		var h Hook
		if err := rows.Scan(&h.ID, &h.TenantID, &h.URL, &h.Events,
			&h.Enabled, &h.CreatedAt, &h.UpdatedAt); err != nil {
			return nil, err
		}
		hooks = append(hooks, h)
	}
	if hooks == nil {
		hooks = []Hook{}
	}
	return hooks, rows.Err()
}

// Get returns one webhook by (id, tenantID), without the secret.
// Returns pgx.ErrNoRows when the row does not exist or belongs to another tenant.
func Get(ctx context.Context, pool *pgxpool.Pool, id, tenantID string) (Hook, error) {
	var h Hook
	err := pool.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, url, events, enabled, created_at, updated_at
		FROM tenant_webhooks
		WHERE id = $1::uuid AND tenant_id = $2::uuid
	`, id, tenantID).Scan(
		&h.ID, &h.TenantID, &h.URL, &h.Events,
		&h.Enabled, &h.CreatedAt, &h.UpdatedAt,
	)
	if err != nil {
		return Hook{}, err
	}
	return h, nil
}

// Create inserts a new webhook and returns the generated ID and plaintext
// secret. The secret is a 64-char hex string shown only at creation time;
// subsequent reads never expose it. Store the secret now — it cannot be
// recovered later.
func Create(ctx context.Context, pool *pgxpool.Pool, tenantID, url string, events []string) (id, secret string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate webhook secret: %w", err)
	}
	secret = hex.EncodeToString(raw) // 64-char hex string

	// PAT-687: encrypt the webhook secret at rest. No-op passthrough when
	// PATCHED_KEK is unset. The plaintext secret is still returned to the caller
	// (shown once at creation); only the stored copy is encrypted.
	encSecret, err := envelope.Default().EncryptString(secret)
	if err != nil {
		return "", "", fmt.Errorf("encrypt webhook secret: %w", err)
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_webhooks (tenant_id, url, secret, events)
		VALUES ($1::uuid, $2, $3, $4)
		RETURNING id::text
	`, tenantID, url, encSecret, events).Scan(&id); err != nil {
		return "", "", err
	}
	return id, secret, nil
}

// Update modifies a webhook's URL, event subscriptions, and enabled flag.
// Returns pgx.ErrNoRows when no matching row exists.
func Update(ctx context.Context, pool *pgxpool.Pool, id, tenantID, url string, events []string, enabled bool) error {
	tag, err := pool.Exec(ctx, `
		UPDATE tenant_webhooks
		SET url = $1, events = $2, enabled = $3, updated_at = now()
		WHERE id = $4::uuid AND tenant_id = $5::uuid
	`, url, events, enabled, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Delete removes a webhook and cascades to its delivery records.
// Returns pgx.ErrNoRows when no matching row exists.
func Delete(ctx context.Context, pool *pgxpool.Pool, id, tenantID string) error {
	tag, err := pool.Exec(ctx, `
		DELETE FROM tenant_webhooks WHERE id = $1::uuid AND tenant_id = $2::uuid
	`, id, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ListDeliveries returns the last limit delivery records for a webhook.
// Returns pgx.ErrNoRows when the webhook does not belong to tenantID.
func ListDeliveries(ctx context.Context, pool *pgxpool.Pool, webhookID, tenantID string, limit int) ([]Delivery, error) {
	// Ownership check — prevents information leak across tenants.
	var exists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM tenant_webhooks WHERE id = $1::uuid AND tenant_id = $2::uuid
		)
	`, webhookID, tenantID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, pgx.ErrNoRows
	}

	rows, err := pool.Query(ctx, `
		SELECT id, webhook_id::text, event_type, response_status,
		       attempt_count, last_attempt_at, succeeded_at, created_at
		FROM webhook_deliveries
		WHERE webhook_id = $1::uuid
		ORDER BY created_at DESC
		LIMIT $2
	`, webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []Delivery
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventType,
			&d.ResponseStatus, &d.AttemptCount,
			&d.LastAttemptAt, &d.SucceededAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	if deliveries == nil {
		deliveries = []Delivery{}
	}
	return deliveries, rows.Err()
}

// listForEvent returns enabled hooks (with secrets) for the given tenant+event.
// Internal use only — secrets must not be exposed via the API.
func listForEvent(ctx context.Context, pool *pgxpool.Pool, tenantID string, event EventKind) ([]hookWithSecret, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text, url, secret
		FROM tenant_webhooks
		WHERE tenant_id = $1::uuid
		  AND enabled = true
		  AND events @> ARRAY[$2::text]
	`, tenantID, string(event))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hooks []hookWithSecret
	for rows.Next() {
		var h hookWithSecret
		var secretStr string
		if err := rows.Scan(&h.id, &h.url, &secretStr); err != nil {
			return nil, err
		}
		// PAT-687: decrypt-with-plaintext-fallback. Rows written before envelope
		// encryption (or while PATCHED_KEK was unset) are returned verbatim.
		secretStr, err = envelope.Default().DecryptString(secretStr)
		if err != nil {
			return nil, fmt.Errorf("decrypt webhook secret: %w", err)
		}
		// The secret is a 64-char hex string. Use the UTF-8 bytes of that string
		// as the HMAC key — matches the convention shown to users.
		h.secret = []byte(secretStr)
		hooks = append(hooks, h)
	}
	return hooks, rows.Err()
}

// createDelivery inserts a pending delivery record (next_attempt_at = now).
func createDelivery(ctx context.Context, pool *pgxpool.Pool, webhookID, eventType string, body []byte) (int64, error) {
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO webhook_deliveries (webhook_id, event_type, payload, next_attempt_at)
		VALUES ($1::uuid, $2, $3::jsonb, now())
		RETURNING id
	`, webhookID, eventType, string(body)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// recordAttempt updates a delivery row after one attempt.
// status is the HTTP response status (0 = network error).
// succeeded marks a successful delivery.
// nextAttemptAt is nil when no retry is scheduled (permanent failure or success).
func recordAttempt(ctx context.Context, pool *pgxpool.Pool, deliveryID int64, status int, succeeded bool, nextAttemptAt *time.Time) error {
	_, err := pool.Exec(ctx, `
		UPDATE webhook_deliveries
		SET
			attempt_count   = attempt_count + 1,
			last_attempt_at = now(),
			response_status = NULLIF($2, 0),
			succeeded_at    = CASE WHEN $3 THEN now() ELSE NULL END,
			next_attempt_at = $4
		WHERE id = $1
	`, deliveryID, status, succeeded, nextAttemptAt)
	return err
}

// Execer is the subset of pgx shared by a pool and a transaction, so an event
// can be enqueued inside the caller's transaction.
type Execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Enqueue writes one pending webhook_deliveries row for every enabled hook of
// tenantID subscribed to event, and returns how many it wrote. It makes no
// network call: the DB-backed Sweeper delivers the rows, signed with the
// hook's secret at send time.
//
// Unlike Fire, this runs on the caller's connection, so a caller holding a
// transaction gets outbox semantics (PAT-2009): the deliveries exist if and
// only if the caller's own record of the event commits. That is what lets a
// dedupe ledger and its webhook deliveries never disagree.
func Enqueue(ctx context.Context, q Execer, tenantID string, event EventKind, data any, now time.Time) (int, error) {
	body, err := json.Marshal(Payload{
		EventType: string(event),
		TenantID:  tenantID,
		Timestamp: now.UTC(),
		Data:      data,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal webhook payload: %w", err)
	}
	tag, err := q.Exec(ctx, `
		INSERT INTO webhook_deliveries (webhook_id, event_type, payload, next_attempt_at)
		SELECT w.id, $2, $3::jsonb, now()
		FROM tenant_webhooks w
		WHERE w.tenant_id = $1::uuid
		  AND w.enabled = true
		  AND w.events @> ARRAY[$2::text]
	`, tenantID, string(event), string(body))
	if err != nil {
		return 0, fmt.Errorf("enqueue webhook deliveries: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
