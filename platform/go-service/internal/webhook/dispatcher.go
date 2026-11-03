package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/envelope"
)

// The outbound httpClient is defined in safedial.go — it is SSRF-hardened
// (blocks internal destinations at dial time; does not follow redirects).

// Fire looks up enabled webhooks for tenantID that subscribe to event, builds
// the signed payload, and dispatches each in a goroutine. Errors are logged;
// this function never blocks the caller and never returns an error. Use it
// as a best-effort fire-and-forget from hot paths (inventory ingestion, CVE sync).
//
// dashboardLink is included in the payload when non-empty (e.g.
// "https://dashboard.patched.im/tenants/<id>"). Pass "" to omit.
func Fire(pool *pgxpool.Pool, tenantID string, event EventKind, data any, dashboardLink string) {
	go fireAsync(pool, tenantID, event, data, dashboardLink)
}

func fireAsync(pool *pgxpool.Pool, tenantID string, event EventKind, data any, dashboardLink string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hooks, err := listForEvent(ctx, pool, tenantID, event)
	if err != nil {
		slog.Warn("webhook: list hooks failed", "tenant_id", tenantID, "event", event, "err", err)
		return
	}
	if len(hooks) == 0 {
		return
	}

	pl := Payload{
		EventType:     string(event),
		TenantID:      tenantID,
		Timestamp:     time.Now().UTC(),
		Data:          data,
		DashboardLink: dashboardLink,
	}
	body, err := json.Marshal(pl)
	if err != nil {
		slog.Error("webhook: marshal payload failed", "event", event, "err", err)
		return
	}

	for _, h := range hooks {
		h := h // capture
		go func() {
			deliveryID, err := createDelivery(context.Background(), pool, h.id, string(event), body)
			if err != nil {
				slog.Warn("webhook: create delivery record failed", "hook_id", h.id, "err", err)
				return
			}
			attempt(pool, h, deliveryID, body, 1)
		}()
	}
}

// FireDirect signs and posts body to a single hook immediately (used by the
// test-ping handler). It records the attempt and returns the HTTP status.
// The caller should pass a pre-marshalled payload.
func FireDirect(ctx context.Context, pool *pgxpool.Pool, webhookID, tenantID string, body []byte, event EventKind) (int, error) {
	// Load the hook with its secret.
	var secretStr string
	var url string
	if err := pool.QueryRow(ctx, `
		SELECT url, secret FROM tenant_webhooks WHERE id = $1::uuid AND tenant_id = $2::uuid
	`, webhookID, tenantID).Scan(&url, &secretStr); err != nil {
		return 0, err
	}
	// PAT-687: decrypt-with-plaintext-fallback (see store.go listForEvent).
	secretStr, err := envelope.Default().DecryptString(secretStr)
	if err != nil {
		return 0, err
	}
	h := hookWithSecret{id: webhookID, url: url, secret: []byte(secretStr)}

	deliveryID, err := createDelivery(ctx, pool, webhookID, string(event), body)
	if err != nil {
		return 0, err
	}

	status, httpErr := post(ctx, h, body)
	succeeded := httpErr == nil && status >= 200 && status < 300
	_ = recordAttempt(context.Background(), pool, deliveryID, status, succeeded, nil)
	if httpErr != nil {
		return 0, httpErr
	}
	return status, nil
}

// attempt sends one delivery attempt for the given hook + delivery record.
// On retriable failure it schedules a retry using time.AfterFunc.
// attempt is 1-indexed.
//
// NOTE: the in-memory time.AfterFunc retry schedule is lost if the process
// restarts mid-backoff. The DB-backed Sweeper (sweeper.go) recovers those
// pending deliveries by polling next_attempt_at. Both paths share
// decideOutcome so their retry semantics stay identical.
func attempt(pool *pgxpool.Pool, h hookWithSecret, deliveryID int64, body []byte, n int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, httpErr := post(ctx, h, body)

	if httpErr != nil {
		slog.Warn("webhook: delivery failed (network)",
			"hook_id", h.id, "attempt", n, "err", httpErr)
	} else if status < 200 || status >= 300 {
		slog.Warn("webhook: delivery failed (non-2xx)",
			"hook_id", h.id, "attempt", n, "status", status)
	}

	outcome, backoff := decideOutcome(status, httpErr != nil, n)
	switch outcome {
	case outcomeSuccess:
		_ = recordAttempt(context.Background(), pool, deliveryID, status, true, nil)
		slog.Info("webhook: delivered", "hook_id", h.id, "status", status, "attempt", n)
	case outcomePermanent:
		slog.Warn("webhook: permanent failure, not retrying",
			"hook_id", h.id, "status", status)
		_ = recordAttempt(context.Background(), pool, deliveryID, status, false, nil)
	case outcomeGiveUp:
		slog.Warn("webhook: max attempts reached, giving up",
			"hook_id", h.id, "attempts", n)
		_ = recordAttempt(context.Background(), pool, deliveryID, status, false, nil)
	case outcomeRetry:
		nextAt := time.Now().Add(backoff)
		_ = recordAttempt(context.Background(), pool, deliveryID, status, false, &nextAt)
		slog.Info("webhook: scheduling retry",
			"hook_id", h.id, "attempt", n, "next_in", backoff.String())
		time.AfterFunc(backoff, func() {
			attempt(pool, h, deliveryID, body, n+1)
		})
	}
}

// post signs and sends a single HTTP POST to the hook URL. Returns the HTTP
// status code and any transport error. A status of 0 means no response was
// received (network / timeout failure).
func post(ctx context.Context, h hookWithSecret, body []byte) (int, error) {
	sig := Sign(h.secret, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Patched-Signature", sig)
	req.Header.Set("User-Agent", "Patched-Webhook/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
