package handlers

// Outbound webhook configuration and delivery log for tenant integrations (PAT-134).
//
// Routes (all on the internal Tailscale-bound listener):
//
//	GET    /admin/tenants/{tenantID}/webhooks
//	POST   /admin/tenants/{tenantID}/webhooks
//	PUT    /admin/tenants/{tenantID}/webhooks/{webhookID}
//	DELETE /admin/tenants/{tenantID}/webhooks/{webhookID}
//	GET    /admin/tenants/{tenantID}/webhooks/{webhookID}/deliveries
//	POST   /admin/tenants/{tenantID}/webhooks/{webhookID}/test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/webhook"
)

const deliveryLogLimit = 50

// WebhookListHandler serves GET /admin/tenants/{tenantID}/webhooks.
// Returns all webhooks for the tenant; secrets are never included.
func WebhookListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, `{"error":"tenantID must be a UUID"}`, http.StatusBadRequest)
			return
		}
		hooks, err := webhook.List(r.Context(), pool, tenantID)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"webhooks": hooks})
	}
}

// WebhookCreateHandler serves POST /admin/tenants/{tenantID}/webhooks.
// Generates a random secret and returns it once in the response — it is never
// retrievable afterwards. The caller must copy it immediately.
//
// Request body:
//
//	{ "url": "https://example.com/hook", "events": ["score.changed"] }
//
// Response on success (201):
//
//	{
//	  "id":     "<uuid>",
//	  "secret": "<64-char hex>",          // shown ONCE — store it now
//	  "note":   "Store this secret now ..."
//	}
func WebhookCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, `{"error":"tenantID must be a UUID"}`, http.StatusBadRequest)
			return
		}

		var body struct {
			URL    string   `json:"url"`
			Events []string `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := webhook.ValidateDestination(body.URL); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		if len(body.Events) == 0 {
			http.Error(w, `{"error":"events must not be empty"}`, http.StatusBadRequest)
			return
		}
		if err := validateEvents(body.Events); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		id, secret, err := webhook.Create(r.Context(), pool, tenantID, body.URL, body.Events)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     id,
			"secret": secret,
			"note":   "Store this secret now — it is shown only once and cannot be retrieved later.",
		})
	}
}

// WebhookUpdateHandler serves PUT /admin/tenants/{tenantID}/webhooks/{webhookID}.
//
// Request body (all fields optional; absent fields retain current values):
//
//	{ "url": "https://...", "events": [...], "enabled": true }
func WebhookUpdateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		webhookID := strings.TrimSpace(chi.URLParam(r, "webhookID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, `{"error":"tenantID must be a UUID"}`, http.StatusBadRequest)
			return
		}

		// Load current values so the caller can send a partial update.
		current, err := webhook.Get(r.Context(), pool, webhookID, tenantID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		var body struct {
			URL     *string  `json:"url"`
			Events  []string `json:"events"`
			Enabled *bool    `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}

		newURL := current.URL
		if body.URL != nil {
			if err := webhook.ValidateDestination(*body.URL); err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			newURL = *body.URL
		}
		newEvents := current.Events
		if len(body.Events) > 0 {
			if err := validateEvents(body.Events); err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			newEvents = body.Events
		}
		newEnabled := current.Enabled
		if body.Enabled != nil {
			newEnabled = *body.Enabled
		}

		if err := webhook.Update(r.Context(), pool, webhookID, tenantID, newURL, newEvents, newEnabled); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"updated": true})
	}
}

// WebhookDeleteHandler serves DELETE /admin/tenants/{tenantID}/webhooks/{webhookID}.
func WebhookDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		webhookID := strings.TrimSpace(chi.URLParam(r, "webhookID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, `{"error":"tenantID must be a UUID"}`, http.StatusBadRequest)
			return
		}

		if err := webhook.Delete(r.Context(), pool, webhookID, tenantID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	}
}

// WebhookDeliveriesHandler serves GET /admin/tenants/{tenantID}/webhooks/{webhookID}/deliveries.
// Returns the last 50 delivery records for the webhook, newest first.
func WebhookDeliveriesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		webhookID := strings.TrimSpace(chi.URLParam(r, "webhookID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, `{"error":"tenantID must be a UUID"}`, http.StatusBadRequest)
			return
		}

		deliveries, err := webhook.ListDeliveries(r.Context(), pool, webhookID, tenantID, deliveryLogLimit)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deliveries": deliveries})
	}
}

// WebhookTestHandler serves POST /admin/tenants/{tenantID}/webhooks/{webhookID}/test.
// Fires a test.ping event to the endpoint and returns the HTTP status received.
func WebhookTestHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		webhookID := strings.TrimSpace(chi.URLParam(r, "webhookID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, `{"error":"tenantID must be a UUID"}`, http.StatusBadRequest)
			return
		}

		pl := webhook.Payload{
			EventType: string(webhook.EventTestPing),
			TenantID:  tenantID,
			Timestamp: time.Now().UTC(),
			Data:      map[string]string{"message": "This is a test ping from Patched."},
		}
		body, err := json.Marshal(pl)
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}

		status, err := webhook.FireDirect(r.Context(), pool, webhookID, tenantID, body, webhook.EventTestPing)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"delivery failed: `+err.Error()+`"}`, http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sent":            true,
			"response_status": status,
		})
	}
}

// validateEvents checks that every element of events is a recognised event kind.
func validateEvents(events []string) error {
	known := map[string]bool{}
	for _, e := range webhook.KnownEvents {
		known[e] = true
	}
	for _, e := range events {
		if !known[e] {
			return errors.New("unknown event type: " + e)
		}
	}
	return nil
}
