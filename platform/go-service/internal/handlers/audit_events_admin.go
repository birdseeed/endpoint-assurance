package handlers

// GET /admin/tenants/{tenantID}/audit-events — tenant-wide, date-range-bounded
// read over audit_events (PAT-1022 item 4: "who installed what, over what
// period"). Internal listener only (:8081) — no application-layer auth,
// same three-network-layer posture as every other /admin/* route (see
// AGENTS.md "Auth model"). Intended consumer: a report generator or a
// downstream CSV export (the PAT-701 pattern — portal repo's
// GET /devices.csv builds CSV statelessly from a JSON API response, so this
// endpoint returns JSON and leaves CSV serialisation to that downstream
// consumer rather than inventing Go-side CSV output that has no precedent
// anywhere in this repo).
//
// Shape mirrors GET /admin/tenants/{tenantID}/enforcement-audit
// (enforcement_audit.go) — same limit/before cursor convention, but with
// two differences: (1) required since/until query params, because a
// fleet-wide report over a table fed continuously by every device on the
// estate needs an explicit date window, not just a cursor with no lower
// bound; and (2) the before cursor here is a composite (before, before_id)
// pair rather than a bare timestamp — see report.AuditEventCursor for why
// occurred_at alone cannot safely disambiguate a page boundary.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

type auditEventEntryResponse struct {
	ID             string `json:"id"`
	DeviceID       string `json:"device_id"`
	EventType      string `json:"event_type"`
	Label          string `json:"label,omitempty"`
	Version        string `json:"version,omitempty"`
	VerifiedSigner string `json:"verified_signer,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Platform       string `json:"platform"`
	OccurredAt     string `json:"occurred_at"`
}

// AuditEventsAdminHandler serves GET /admin/tenants/{tenantID}/audit-events.
func AuditEventsAdminHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "audit_events_admin", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		q := r.URL.Query()

		since, err := time.Parse(time.RFC3339, q.Get("since"))
		if err != nil {
			http.Error(w, "since is required and must be RFC3339", http.StatusBadRequest)
			return
		}

		until := time.Now().UTC()
		if s := q.Get("until"); s != "" {
			until, err = time.Parse(time.RFC3339, s)
			if err != nil {
				http.Error(w, "until must be RFC3339", http.StatusBadRequest)
				return
			}
		}
		if !until.After(since) {
			http.Error(w, "until must be after since", http.StatusBadRequest)
			return
		}

		limit := 500
		if s := q.Get("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			if n > 1000 {
				n = 1000
			}
			limit = n
		}

		var before *report.AuditEventCursor
		beforeStr := q.Get("before")
		beforeIDStr := strings.TrimSpace(q.Get("before_id"))
		if beforeStr != "" || beforeIDStr != "" {
			// Composite cursor: both halves are required together, or
			// pagination can silently degenerate back to the single-column
			// comparison this fix exists to avoid.
			if beforeStr == "" || beforeIDStr == "" {
				http.Error(w, "before and before_id must be supplied together", http.StatusBadRequest)
				return
			}
			t, err := time.Parse(time.RFC3339, beforeStr)
			if err != nil {
				http.Error(w, "before must be RFC3339", http.StatusBadRequest)
				return
			}
			if !looksLikeUUID(beforeIDStr) {
				http.Error(w, "before_id must be a UUID", http.StatusBadRequest)
				return
			}
			before = &report.AuditEventCursor{OccurredAt: t, ID: beforeIDStr}
		}

		eventType := strings.TrimSpace(q.Get("event_type"))
		deviceFilter := strings.TrimSpace(q.Get("device_id"))

		items, err := report.FetchTenantAuditEvents(r.Context(), pool, tenantID, since, until, limit, before, eventType, deviceFilter)
		if err != nil {
			logger.Error("fetch tenant audit events failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		out := make([]auditEventEntryResponse, 0, len(items))
		for _, it := range items {
			out = append(out, auditEventEntryResponse{
				ID:             it.ID,
				DeviceID:       it.DeviceID,
				EventType:      it.EventType,
				Label:          it.Label,
				Version:        it.Version,
				VerifiedSigner: it.VerifiedSigner,
				Reason:         it.Reason,
				Platform:       it.Platform,
				OccurredAt:     it.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}

		// Compute next_before cursor: the (occurred_at, id) of the last
		// returned row — a composite object, not a bare timestamp, so a
		// caller can round-trip both halves back as before/before_id on the
		// next request. See report.AuditEventCursor.
		var nextBefore any
		if len(out) == limit {
			last := out[len(out)-1]
			nextBefore = map[string]string{
				"occurred_at": last.OccurredAt,
				"id":          last.ID,
			}
		}

		logger.Info("audit events listed", "count", len(out))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events":      out,
			"next_before": nextBefore,
		})
	}
}
