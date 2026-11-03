package handlers

// new_apps.go — admin handlers for tenant_new_apps (PAT-167).
//
// Routes (all on the internal admin listener :8081):
//   GET  /admin/tenants/{tenantID}/new-apps          — list new-app rows
//   PUT  /admin/tenants/{tenantID}/new-apps/{id}     — set decision

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newAppRow mirrors a tenant_new_apps row for JSON serialisation.
type newAppRow struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	AppIdentity        string     `json:"app_identity"`
	Name               string     `json:"name"`
	PublisherSignature *string    `json:"publisher_signature,omitempty"`
	Platform           string     `json:"platform"`
	FirstSeen          time.Time  `json:"first_seen"`
	HostCount          int        `json:"host_count"`
	Decision           *string    `json:"decision"`
	SuggestedAction    *string    `json:"suggested_action,omitempty"`
	DecidedBy          *string    `json:"decided_by,omitempty"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	DeferUntil         *time.Time `json:"defer_until,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// TenantNewAppsGetHandler lists tenant_new_apps rows for a tenant.
//
// GET /admin/tenants/{tenantID}/new-apps
// Query params:
//
//	?status=pending  (default) — rows with decision IS NULL
//	?status=all                — all rows regardless of decision
//
// 200 { "new_apps": [...] } | 400 bad tenantID | 404 unknown tenant
func TenantNewAppsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_new_apps_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify tenant exists.
		var exists bool
		if err := pool.QueryRow(r.Context(), `
			SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)
		`, tenantID).Scan(&exists); err != nil || !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		statusFilter := r.URL.Query().Get("status")
		if statusFilter == "" {
			statusFilter = "pending"
		}

		var querySQL string
		switch statusFilter {
		case "all":
			querySQL = `
				SELECT id::text, tenant_id::text, app_identity, name,
				       publisher_signature, platform, first_seen, host_count,
				       decision, suggested_action, decided_by, decided_at,
				       defer_until, created_at, updated_at
				FROM tenant_new_apps
				WHERE tenant_id = $1::uuid
				ORDER BY first_seen DESC
			`
		default: // "pending"
			querySQL = `
				SELECT id::text, tenant_id::text, app_identity, name,
				       publisher_signature, platform, first_seen, host_count,
				       decision, suggested_action, decided_by, decided_at,
				       defer_until, created_at, updated_at
				FROM tenant_new_apps
				WHERE tenant_id = $1::uuid
				  AND decision IS NULL
				ORDER BY first_seen DESC
			`
		}

		rows, err := pool.Query(r.Context(), querySQL, tenantID)
		if err != nil {
			logger.Error("query tenant_new_apps", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var apps []newAppRow
		for rows.Next() {
			var a newAppRow
			if err := rows.Scan(
				&a.ID, &a.TenantID, &a.AppIdentity, &a.Name,
				&a.PublisherSignature, &a.Platform, &a.FirstSeen, &a.HostCount,
				&a.Decision, &a.SuggestedAction, &a.DecidedBy, &a.DecidedAt,
				&a.DeferUntil, &a.CreatedAt, &a.UpdatedAt,
			); err != nil {
				logger.Error("scan new_app row", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			apps = append(apps, a)
		}
		if err := rows.Err(); err != nil {
			logger.Error("rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if apps == nil {
			apps = []newAppRow{} // never null in JSON
		}

		logger.Info("tenant new apps listed",
			"tenant_id", tenantID,
			"count", len(apps),
			"status_filter", statusFilter,
		)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"new_apps": apps})
	}
}

// newAppDecisionRequest is the body accepted by TenantNewAppsPutHandler.
type newAppDecisionRequest struct {
	Decision  string `json:"decision"`   // approve|approve_no_patch|remove|defer
	DecidedBy string `json:"decided_by"` // admin identifier (email, username, etc.)
}

// TenantNewAppsPutHandler sets the decision on a tenant_new_apps row.
//
// PUT /admin/tenants/{tenantID}/new-apps/{id}
// Body: { "decision": "approve|approve_no_patch|remove|defer", "decided_by": "..." }
//
// When decision = "defer", sets defer_until = now() + 90 days.
//
// 200 newAppRow | 400 bad input | 404 not found
func TenantNewAppsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_new_apps_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		rowID := strings.TrimSpace(chi.URLParam(r, "id"))
		if !looksLikeUUID(rowID) {
			http.Error(w, "id must be a UUID", http.StatusBadRequest)
			return
		}

		var req newAppDecisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		validDecisions := map[string]bool{
			"approve":          true,
			"approve_no_patch": true,
			"remove":           true,
			"defer":            true,
		}
		if !validDecisions[req.Decision] {
			http.Error(w, "decision must be approve|approve_no_patch|remove|defer", http.StatusBadRequest)
			return
		}
		if req.DecidedBy == "" {
			http.Error(w, "decided_by is required", http.StatusBadRequest)
			return
		}

		// For defer decisions, set defer_until = now() + 90 days.
		// For all other decisions, clear defer_until.
		const updateSQL = `
			UPDATE tenant_new_apps
			SET decision    = $1,
			    decided_by  = $2,
			    decided_at  = now(),
			    defer_until = CASE WHEN $1 = 'defer' THEN now() + interval '90 days' ELSE NULL END,
			    updated_at  = now()
			WHERE id = $3::uuid
			  AND tenant_id = $4::uuid
			RETURNING
				id::text, tenant_id::text, app_identity, name,
				publisher_signature, platform, first_seen, host_count,
				decision, suggested_action, decided_by, decided_at,
				defer_until, created_at, updated_at
		`

		var a newAppRow
		if err := pool.QueryRow(r.Context(), updateSQL,
			req.Decision, req.DecidedBy, rowID, tenantID,
		).Scan(
			&a.ID, &a.TenantID, &a.AppIdentity, &a.Name,
			&a.PublisherSignature, &a.Platform, &a.FirstSeen, &a.HostCount,
			&a.Decision, &a.SuggestedAction, &a.DecidedBy, &a.DecidedAt,
			&a.DeferUntil, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "new app entry not found", http.StatusNotFound)
				return
			}
			logger.Error("update new_app decision", "err", err, "row_id", rowID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("new app decision set",
			"tenant_id", tenantID,
			"row_id", rowID,
			"decision", req.Decision,
			"decided_by", req.DecidedBy,
		)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	}
}
