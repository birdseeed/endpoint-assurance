package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// TenantAgentHealthHandler returns the tenant's degraded-capability entries
// (PAT-1064), grouped per device, plus a tenant-level total. Consumed by the
// dashboard (PAT-1067) to render "what was asked, why it could not be done,
// since when, how many times" per device without a second call.
//
// GET /admin/tenants/{tenantID}/agent-health
func TenantAgentHealthHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_agent_health")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		resp, err := report.FetchTenantAgentHealth(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch tenant agent health failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant agent health fetched", "tenant_id", tenantID, "total", resp.Total)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
