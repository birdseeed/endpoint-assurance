package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// ReportCatalogueHandler returns the complete internal report registry. The
// internal router's admin-token middleware authenticates this route.
func ReportCatalogueHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"reports": report.ReportCatalogue(),
		})
	}
}

// PortalReportCatalogueHandler returns only customer-facing, customer-safe
// registry fields. Tenant identity is still required even though the current
// product catalogue is not tier-gated. This is the seam for a future
// entitlement filter based on the authenticated tenant's capabilities.
//
// An admin-only report (PAT-2406) is offered to a tenant admin only, where it
// carries "admin_only": true. Every other caller gets the catalogue without
// it, so no client offers a viewer a report type it cannot generate.
func PortalReportCatalogueHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return portalReportCatalogueHandler(portalDBRoleLookup(pool))
}

func portalReportCatalogueHandler(roleLookup portalRoleLookup) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_report_catalogue", "tenant_id", id.TenantID)

		entries := report.PortalReportCatalogue()
		restricted := false
		for _, entry := range entries {
			restricted = restricted || entry.AdminOnly
		}
		if restricted {
			admin, _, ok := portalReportCallerIsAdmin(w, r, roleLookup, id, logger)
			if !ok {
				return
			}
			if !admin {
				visible := make([]report.PortalReportDefinition, 0, len(entries))
				for _, entry := range entries {
					if !entry.AdminOnly {
						visible = append(visible, entry)
					}
				}
				entries = visible
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"reports": entries,
		})
	}
}
