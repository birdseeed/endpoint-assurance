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

// osUpdateStatusResp is the JSON shape for GET /admin/tenants/{tenantID}/os-update-status.
type osUpdateStatusResp struct {
	Tenant                        string `json:"tenant"`
	DevicesCurrent                int    `json:"devices_current"`
	DevicesBehind                 int    `json:"devices_behind"`
	DevicesBehindSecurityRelevant int    `json:"devices_behind_security_relevant"`
	DevicesNotReported            int    `json:"devices_not_reported"`
}

// TenantOSUpdateStatusHandler serves the tenant-level OS-update-currency
// rollup (PAT-1806): how many devices are current, how many are behind, how
// many of those behind devices carry a security-relevant update outstanding,
// and how many are not reported: no os_update block at all, a verdict of
// "unknown", or a state outside the agents' vocabulary (PAT-2295). This is a new,
// small, JSON-only endpoint rather than a field bolted onto the existing PDF
// executive summary — ExecutiveSummary's only consumers today render PDFs
// (ExecutiveSummaryHandler, generateSummaryPDF), and adding a rendered band
// there is presentation work outside this ticket's server-side platform
// slice. This mirrors the existing small per-tenant JSON GET handlers
// (TenantCEStatusHandler, TenantAgentHealthHandler) rather than the
// multi-tenant fleet overview (TenantsOverviewHandler) — narrower, single-
// tenant scope, lower risk to extend later.
//
// Route: GET /admin/tenants/{tenantID}/os-update-status   (internal listener :8081)
func TenantOSUpdateStatusHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_os_update_status")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		status, err := report.FetchOSUpdateStatus(r.Context(), pool, tenantID)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch os update status failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := osUpdateStatusResp{
			Tenant:                        status.Tenant,
			DevicesCurrent:                status.DevicesCurrent,
			DevicesBehind:                 status.DevicesBehind,
			DevicesBehindSecurityRelevant: status.DevicesBehindSecurityRelevant,
			DevicesNotReported:            status.DevicesNotReported,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Warn("encode os update status response failed", "err", err)
		}
	}
}
