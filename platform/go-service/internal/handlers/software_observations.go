package handlers

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

type softwareObservationComparisonRun struct {
	ReceivedAt          time.Time `json:"received_at"`
	Provenance          string    `json:"provenance"`
	AuthoritativeScopes []string  `json:"authoritative_scopes"`
}

type softwareObservationComparisonResponse struct {
	TenantID                    string                            `json:"tenant_id"`
	DeviceID                    string                            `json:"device_id"`
	LegacyCurrent               int                               `json:"legacy_current"`
	ObservationCurrent          int                               `json:"observation_current"`
	ResolvedCurrent             int                               `json:"resolved_current"`
	UnresolvedCurrent           int                               `json:"unresolved_current"`
	LegacyOnly                  int                               `json:"legacy_only"`
	ObservationOnly             int                               `json:"observation_only"`
	LatestRun                   *softwareObservationComparisonRun `json:"latest_run,omitempty"`
	ReadOnlyCompatibilityStatus string                            `json:"read_only_compatibility_status"`
}

// SoftwareObservationComparisonHandler exposes the PAT-1461 migration seam to
// operators. It is deliberately diagnostic: it cannot create products,
// resolve identities, mutate policy, or trigger remediation.
func SoftwareObservationComparisonHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "software_observation_comparison")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(deviceID) {
			http.Error(w, "tenantID and deviceID must be UUIDs", http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(r.Context(), `
			SELECT EXISTS (
				SELECT 1 FROM devices WHERE id = $1::uuid AND tenant_id = $2::uuid
			)
		`, deviceID, tenantID).Scan(&exists); err != nil {
			logger.Error("check device tenant failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}

		response := softwareObservationComparisonResponse{
			TenantID:                    tenantID,
			DeviceID:                    deviceID,
			ReadOnlyCompatibilityStatus: "comparison_only",
		}
		if err := pool.QueryRow(r.Context(), `
			WITH legacy AS (
				SELECT da.identifier
				FROM device_apps da
				JOIN devices d ON d.id = da.device_id
				WHERE d.tenant_id = $1::uuid AND d.id = $2::uuid
			), current_installations AS (
				SELECT identity_value_normalized, product_id
				FROM software_installations
				WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND removed_at IS NULL
				  -- PAT-2013: Homebrew packages have no device_apps
				  -- counterpart; comparing them would report every one as
				  -- observation-only drift.
				  AND identity_kind NOT IN ('homebrew_formula','homebrew_cask','homebrew_tap')
				  -- PAT-2021: nor do IDE extensions, packages, local models
				  -- or MCP servers.
				  AND identity_kind NOT IN ('ide_extension','ide_extension_unidentified',
				      'npm_package','npm_package_unidentified','pip_package','pip_package_unidentified',
				      'local_model','local_model_unidentified','local_model_runtime',
				      'mcp_server','mcp_server_unnamed')
			)
			SELECT
				(SELECT count(*) FROM legacy),
				(SELECT count(*) FROM current_installations),
				(SELECT count(*) FROM current_installations WHERE product_id IS NOT NULL),
				(SELECT count(*) FROM current_installations WHERE product_id IS NULL),
				(SELECT count(*) FROM legacy l WHERE NOT EXISTS (
					SELECT 1 FROM current_installations ci
					WHERE ci.identity_value_normalized = lower(btrim(l.identifier))
				)),
				(SELECT count(*) FROM current_installations ci WHERE NOT EXISTS (
					SELECT 1 FROM legacy l
					WHERE lower(btrim(l.identifier)) = ci.identity_value_normalized
				))
		`, tenantID, deviceID).Scan(
			&response.LegacyCurrent, &response.ObservationCurrent,
			&response.ResolvedCurrent, &response.UnresolvedCurrent,
			&response.LegacyOnly, &response.ObservationOnly,
		); err != nil {
			logger.Error("query software observation comparison failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var latest softwareObservationComparisonRun
		if err := pool.QueryRow(r.Context(), `
			SELECT received_at, provenance, authoritative_scopes
			FROM software_inventory_runs
			WHERE tenant_id = $1::uuid AND device_id = $2::uuid
			ORDER BY received_at DESC, created_at DESC
			LIMIT 1
		`, tenantID, deviceID).Scan(&latest.ReceivedAt, &latest.Provenance, &latest.AuthoritativeScopes); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				logger.Error("query latest software inventory run failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		} else {
			response.LatestRun = &latest
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
