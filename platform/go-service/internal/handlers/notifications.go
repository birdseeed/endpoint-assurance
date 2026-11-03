package handlers

// Tenant notification channels (PAT-1888).
//
// Routes (all on the internal Tailscale-bound listener, behind the admin token):
//
//	GET    /admin/tenants/{tenantID}/notification-channels
//	POST   /admin/tenants/{tenantID}/notification-channels
//	PUT    /admin/tenants/{tenantID}/notification-channels/{channelID}
//	DELETE /admin/tenants/{tenantID}/notification-channels/{channelID}
//	GET    /admin/tenants/{tenantID}/notification-channels/{channelID}/deliveries
//	POST   /admin/tenants/{tenantID}/notification-channels/{channelID}/test
//	GET    /admin/tenants/{tenantID}/notification-deliveries
//
// Two rules hold across every handler here:
//
//  1. Tenant isolation is by query, not by check. Every statement is scoped to
//     the tenant in the path, and a channel belonging to another tenant returns
//     404, identical to one that does not exist. A 403 would confirm the id is
//     real, so there is deliberately no 403 anywhere in this file.
//
//  2. The signing secret is returned exactly once, by the create handler. No
//     read, list, update or test response carries it, and the Channel type it
//     would have to travel in has no field for it.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/notifications"
)

// NotificationChannelListHandler serves GET .../notification-channels.
func NotificationChannelListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID must be a UUID")
			return
		}
		channels, err := notifications.ListChannels(r.Context(), pool, tenantID)
		if err != nil {
			writeNotificationError(w, http.StatusInternalServerError, "db error")
			return
		}
		writeNotificationJSON(w, http.StatusOK, map[string]any{"channels": channels})
	}
}

// channelRequest is the create/update body.
type channelRequest struct {
	Type        string   `json:"channel_type"`
	Name        string   `json:"name"`
	Enabled     *bool    `json:"enabled"`
	Events      []string `json:"events"`
	MinSeverity string   `json:"min_severity"`
	URL         string   `json:"destination_url"`
	Recipients  []string `json:"recipients"`
}

// NotificationChannelCreateHandler serves POST .../notification-channels.
//
// For a webhook channel the response carries the signing secret. That is the
// only time it is ever readable: it is stored envelope-encrypted and no other
// response exposes it.
func NotificationChannelCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID must be a UUID")
			return
		}

		var body channelRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeNotificationError(w, http.StatusBadRequest, "invalid json")
			return
		}

		enabled := true
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		spec := notifications.ChannelSpec{
			Type:        strings.TrimSpace(body.Type),
			Name:        body.Name,
			Enabled:     enabled,
			Events:      body.Events,
			MinSeverity: body.MinSeverity,
			URL:         strings.TrimSpace(body.URL),
			Recipients:  body.Recipients,
		}

		id, secret, err := notifications.CreateChannel(r.Context(), pool, tenantID, spec)
		if err != nil {
			if isNotificationValidationError(err) {
				writeNotificationError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeNotificationError(w, http.StatusInternalServerError, "db error")
			return
		}

		resp := map[string]any{"id": id}
		if secret != "" {
			resp["secret"] = secret
			resp["note"] = "Store this secret now. It is shown only once and cannot be retrieved later."
		}
		writeNotificationJSON(w, http.StatusCreated, resp)
	}
}

// NotificationChannelUpdateHandler serves PUT .../notification-channels/{channelID}.
//
// Absent fields keep their current value, so `{"enabled": false}` is the
// documented per-tenant rollback: delivery stops, configuration and history
// stay. channel_type cannot be changed.
func NotificationChannelUpdateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		channelID := strings.TrimSpace(chi.URLParam(r, "channelID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(channelID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID and channelID must be UUIDs")
			return
		}

		current, err := notifications.GetChannel(r.Context(), pool, channelID, tenantID)
		if err != nil {
			writeNotificationLookupError(w, err)
			return
		}

		var body channelRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeNotificationError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if strings.TrimSpace(body.Type) != "" && strings.TrimSpace(body.Type) != current.Type {
			writeNotificationError(w, http.StatusBadRequest, "channel_type cannot be changed")
			return
		}

		spec := notifications.ChannelSpec{
			Type:        current.Type,
			Name:        current.Name,
			Enabled:     current.Enabled,
			Events:      current.Events,
			MinSeverity: current.MinSeverity,
			URL:         current.URL,
			Recipients:  current.Recipients,
		}
		if strings.TrimSpace(body.Name) != "" {
			spec.Name = body.Name
		}
		if body.Enabled != nil {
			spec.Enabled = *body.Enabled
		}
		if len(body.Events) > 0 {
			spec.Events = body.Events
		}
		if strings.TrimSpace(body.MinSeverity) != "" {
			spec.MinSeverity = body.MinSeverity
		}
		if strings.TrimSpace(body.URL) != "" {
			spec.URL = strings.TrimSpace(body.URL)
		}
		if len(body.Recipients) > 0 {
			spec.Recipients = body.Recipients
		}

		if err := notifications.UpdateChannel(r.Context(), pool, channelID, tenantID, spec); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeNotificationError(w, http.StatusNotFound, "not found")
				return
			}
			if isNotificationValidationError(err) {
				writeNotificationError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeNotificationError(w, http.StatusInternalServerError, "db error")
			return
		}
		writeNotificationJSON(w, http.StatusOK, map[string]any{"updated": true})
	}
}

// NotificationChannelDeleteHandler serves DELETE .../notification-channels/{channelID}.
func NotificationChannelDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		channelID := strings.TrimSpace(chi.URLParam(r, "channelID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(channelID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID and channelID must be UUIDs")
			return
		}
		if err := notifications.DeleteChannel(r.Context(), pool, channelID, tenantID); err != nil {
			writeNotificationLookupError(w, err)
			return
		}
		writeNotificationJSON(w, http.StatusOK, map[string]any{"deleted": true})
	}
}

// NotificationChannelDeliveriesHandler serves
// GET .../notification-channels/{channelID}/deliveries?state=&limit=.
func NotificationChannelDeliveriesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		channelID := strings.TrimSpace(chi.URLParam(r, "channelID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(channelID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID and channelID must be UUIDs")
			return
		}
		state, limit, ok := notificationListingParams(w, r)
		if !ok {
			return
		}

		deliveries, err := notifications.ListDeliveries(r.Context(), pool, channelID, tenantID, state, limit)
		if err != nil {
			writeNotificationLookupError(w, err)
			return
		}
		writeNotificationJSON(w, http.StatusOK, map[string]any{
			"deliveries": deliveries,
			"limit":      notifications.ClampPageSize(limit),
		})
	}
}

// NotificationDeliveriesHandler serves
// GET .../notification-deliveries?state=dead_letter&limit=.
//
// This is the dead-letter view: one bounded page across every channel the
// tenant owns.
func NotificationDeliveriesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID must be a UUID")
			return
		}
		state, limit, ok := notificationListingParams(w, r)
		if !ok {
			return
		}

		deliveries, err := notifications.ListTenantDeliveries(r.Context(), pool, tenantID, state, limit)
		if err != nil {
			writeNotificationError(w, http.StatusInternalServerError, "db error")
			return
		}
		writeNotificationJSON(w, http.StatusOK, map[string]any{
			"deliveries": deliveries,
			"limit":      notifications.ClampPageSize(limit),
		})
	}
}

// NotificationChannelTestHandler serves POST .../notification-channels/{channelID}/test.
//
// It sends one synthetic, clearly labelled test.ping. It creates no finding and
// no finding lifecycle event: the only row it writes is the delivery record
// itself, so a channel can be proven without inventing evidence.
func NotificationChannelTestHandler(pool *pgxpool.Pool, dispatcher *notifications.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		channelID := strings.TrimSpace(chi.URLParam(r, "channelID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(channelID) {
			writeNotificationError(w, http.StatusBadRequest, "tenantID and channelID must be UUIDs")
			return
		}
		if dispatcher == nil {
			writeNotificationError(w, http.StatusServiceUnavailable, "notification delivery is not configured")
			return
		}

		deliveryID, state, err := dispatcher.SendTest(r.Context(), channelID, tenantID)
		if err != nil {
			writeNotificationLookupError(w, err)
			return
		}

		// A failed test is a successful test-event request that reports a
		// failure: the delivery row records what happened either way, and the
		// caller reads the state rather than an HTTP status.
		writeNotificationJSON(w, http.StatusOK, map[string]any{
			"delivery_id": deliveryID,
			"state":       state,
			"note":        "Synthetic test event. No finding or lifecycle record was created.",
		})
	}
}

// notificationListingParams reads and validates the shared state/limit query
// parameters.
func notificationListingParams(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if !notifications.ValidDeliveryState(state) {
		writeNotificationError(w, http.StatusBadRequest, "state must be pending, delivered or dead_letter")
		return "", 0, false
	}
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeNotificationError(w, http.StatusBadRequest, "limit must be a positive integer")
			return "", 0, false
		}
		limit = parsed
	}
	return state, limit, true
}

// isNotificationValidationError reports whether err is a configuration mistake
// the caller can fix. Only those carry their message into the response; every
// other failure becomes an opaque 500 so internal detail stays internal.
func isNotificationValidationError(err error) bool {
	var ve *notifications.ValidationError
	return errors.As(err, &ve)
}

func writeNotificationLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeNotificationError(w, http.StatusNotFound, "not found")
		return
	}
	writeNotificationError(w, http.StatusInternalServerError, "db error")
}

func writeNotificationJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeNotificationError emits a JSON error. The message is encoded rather than
// concatenated so a validation string containing a quote cannot break the body.
func writeNotificationError(w http.ResponseWriter, status int, message string) {
	writeNotificationJSON(w, status, map[string]string{"error": message})
}
