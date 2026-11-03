// Portal vulnerable driver findings (PAT-2263).
//
// GET /v1/portal/driver-findings: the tenant's kernel drivers whose reported
// hash is on Microsoft's recommended driver block rules or loldrivers.io,
// one row per (device, driver), with every matching list entry, the list's
// version and fetch time, and the device's blocklist enforcement state.
// GET /v1/portal/devices/{deviceID} carries the same evidence for one device
// as kernel_drivers (see fetchPortalDeviceDetail wiring in portal.go).
//
// Matching is by hash only (package driverblock). A driver that is not listed
// is not claimed safe: Microsoft's signer rules are not evaluated, a list can
// be stale (lists[].stale, matches[].list_stale), and a driver the agent
// could not hash is Unknown, which the device view reports.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/driverblock"
)

type portalDriverFindingsResp struct {
	GeneratedAt time.Time                 `json:"generated_at"`
	Limit       int                       `json:"limit"`
	Offset      int                       `json:"offset"`
	Total       int                       `json:"total"`
	Lists       []driverblock.ListState   `json:"lists"`
	Summary     driverblock.EstateSummary `json:"summary"`
	Findings    []driverblock.Finding     `json:"findings"`
}

// PortalDriverFindingsHandler serves GET /v1/portal/driver-findings, scoped
// to the caller's tenant. Every role reads. Paginated with ?limit/?offset
// (parsePagination).
func PortalDriverFindingsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_driver_findings", "tenant_id", id.TenantID)

		limit, offset := parsePagination(r)
		now := time.Now().UTC()
		page, err := driverblock.FetchEstate(r.Context(), pool, id.TenantID, limit, offset, now)
		if err != nil {
			logger.Error("fetch driver findings failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalDriverFindingsResp{
			GeneratedAt: now,
			Limit:       limit,
			Offset:      offset,
			Total:       page.Total,
			Lists:       page.Lists,
			Summary:     page.Summary,
			Findings:    page.Findings,
		})
	}
}
