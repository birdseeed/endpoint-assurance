package handlers

// PUT /admin/tenant/{tenantID}/signal (PAT-676, platform half).
//
// Records a dashboard login event for the given tenant:
//   - Sets last_dashboard_login_at = now()
//   - Increments dashboard_logins_last_30d by 1
//
// This endpoint is called by the dashboard on each successful CF-Access login.
// The nightly recompute (internal/healthsignals.Recompute, wired into the
// extractor's automation loop) updates staleness and compliance-score fields.
//
// Auth posture: network-only (Tailscale-bound :8081), same as all /admin/* routes.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HealthSignalHandler serves PUT /admin/tenant/{tenantID}/signal on :8081.
// Records a dashboard login event for the tenant.
func HealthSignalHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "health_signal", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE tenants
			SET last_dashboard_login_at   = now(),
			    dashboard_logins_last_30d = dashboard_logins_last_30d + 1
			WHERE id = $1::uuid AND revoked_at IS NULL
		`, tenantID)
		if err != nil {
			logger.Error("health signal update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		logger.Info("health signal recorded")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}
