package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

// PortalOverviewCardsHandler serves GET /v1/portal/overview/cards (PAT-2207):
// the Overview information cards read model. It is a separate route so
// GET /v1/portal/overview and its consumers are untouched.
//
// The tenant comes only from the portalauth identity; no query parameter,
// header or body is read. Only a failure of the base device query is a 500:
// every other card degrades to unavailable inside
// report.FetchPortalOverviewCards. Contract: contracts/portal-api.md.
func PortalOverviewCardsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_overview_cards", "tenant_id", id.TenantID)

		cards, err := report.FetchPortalOverviewCards(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch portal overview cards failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cards)
	}
}
