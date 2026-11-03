package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Metering handlers expose per-tenant software-usage aggregates derived from
// device_apps.last_used_at and device_apps.launch_count (populated by PAT-356).
// All routes live on the internal Tailscale-bound listener (:8081). Read-only.
//
// Routes:
//
//	GET /admin/tenants/{tenantID}/metering             — per-app fleet aggregate
//	GET /admin/tenants/{tenantID}/metering/{appName}   — per-device breakdown for one app
//
// Collection health (PAT-1320): devices.metering_status records whether a
// device's own usage read was reliable ('ok'), unreliable
// ('spotlight_disabled' | 'no_user_session'), or never reported (NULL — old
// agent, Windows). Both routes below surface that status so a caller can
// distinguish "no usage record because the collector said so" from
// "no usage record because we don't actually know". See metering_status /
// metering_status_at doc comments on each row type for the exact contract.

// ---------------------------------------------------------------------------
// Fleet aggregate
// ---------------------------------------------------------------------------

type meteringAppRow struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Platform         string     `json:"platform"`
	DeviceCount      int        `json:"device_count"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	TotalLaunchCount *int64     `json:"total_launch_count"`
	DaysSinceLastUse *int       `json:"days_since_last_use"`

	// MeteringStatus is the honest rollup of devices.metering_status across
	// every device that reports this (name, platform) row. Always one of:
	//   "ok"                  — every contributing device reported 'ok'
	//   "spotlight_disabled"  — every contributing device reported this same
	//                           non-ok status
	//   "no_user_session"     — ditto
	//   "unknown"             — no contributing device has ever reported a
	//                           metering_status (old agent / Windows)
	//   "mixed"               — contributing devices disagree (including the
	//                           case where some reported a status and others
	//                           never have) — never silently collapsed to a
	//                           single device's value
	MeteringStatus string `json:"metering_status"`
	// MeteringStatusAt is the freshest devices.last_seen among devices that
	// contributed a non-NULL metering_status to this row (nil when
	// MeteringStatus is "unknown", since no device has ever reported one).
	MeteringStatusAt *time.Time `json:"metering_status_at"`
}

type meteringFleetResp struct {
	TenantID string           `json:"tenant_id"`
	Total    int              `json:"total"`
	Apps     []meteringAppRow `json:"apps"`
}

// MeteringFleetHandler returns per-app software-metering aggregates rolled up
// across all devices in a tenant's fleet. One row per (app name, platform pair).
//
// fleet_last_used_at is MAX(last_used_at) across all devices that have the app.
// fleet_launch_count is SUM(launch_count) across devices with metering_status='ok'.
//
// NULL fields mean no metering data was collected (Spotlight disabled, old
// agent, or Windows endpoint where metering is not yet implemented).
func MeteringFleetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "metering_fleet")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
			tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		var total int
		if err := pool.QueryRow(r.Context(), `
			SELECT COUNT(*)
			FROM (
				SELECT DISTINCT da.name, d.os
				FROM device_apps da
				JOIN devices d ON da.device_id = d.id
				WHERE d.tenant_id = $1::uuid
			) sub
		`, tenantID).Scan(&total); err != nil {
			logger.Error("metering total count failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		rows, err := pool.Query(r.Context(), `
			WITH latest_apps AS (
			    SELECT DISTINCT ON (da.device_id, da.name)
			        da.device_id, da.name,
			        CASE WHEN da.usage_evidence IS NULL OR da.usage_evidence = 'recorded' THEN da.last_used_at END AS last_used_at,
			        CASE WHEN da.usage_evidence IS NULL OR da.usage_evidence = 'recorded' THEN da.launch_count END AS launch_count,
			        CASE WHEN da.usage_evidence IN ('unmapped', 'unavailable') THEN 'unavailable' ELSE d.metering_status END AS metering_status
			    FROM device_apps da
			    JOIN devices d ON da.device_id = d.id
			    WHERE d.tenant_id = $1::uuid
			    ORDER BY da.device_id, da.name, da.last_seen DESC
			)
			SELECT
			    la.name,
			    d.os                                                            AS platform,
			    COUNT(DISTINCT la.device_id)                                    AS device_count,
			    MAX(la.last_used_at)                                            AS fleet_last_used_at,
			    SUM(la.launch_count) FILTER (WHERE la.metering_status = 'ok')   AS fleet_launch_count,
			    COUNT(DISTINCT la.metering_status)                               AS distinct_status_count,
			    BOOL_OR(la.metering_status IS NULL)                              AS has_unreported,
			    MIN(la.metering_status) FILTER (WHERE la.metering_status IS NOT NULL) AS sole_status,
			    MAX(d.last_seen) FILTER (WHERE la.metering_status IS NOT NULL)  AS status_at
			FROM latest_apps la
			JOIN devices d ON d.id = la.device_id
			GROUP BY la.name, d.os
			ORDER BY fleet_last_used_at DESC NULLS LAST, la.name ASC
		`, tenantID)
		if err != nil {
			logger.Error("metering fleet query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		apps := []meteringAppRow{}
		for rows.Next() {
			var row meteringAppRow
			var (
				distinctStatusCount int
				hasUnreported       bool
				soleStatus          *string
				statusAt            *time.Time
			)
			if err := rows.Scan(
				&row.Name, &row.Platform,
				&row.DeviceCount,
				&row.LastUsedAt, &row.TotalLaunchCount,
				&distinctStatusCount, &hasUnreported, &soleStatus, &statusAt,
			); err != nil {
				logger.Error("scan metering row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			row.ID = row.Name
			if row.LastUsedAt != nil {
				days := int(time.Since(*row.LastUsedAt).Hours() / 24)
				row.DaysSinceLastUse = &days
			}
			switch {
			case distinctStatusCount == 0:
				// No contributing device has ever reported a metering_status.
				row.MeteringStatus = "unknown"
			case distinctStatusCount == 1 && !hasUnreported:
				// Every contributing device agrees on the same reported status.
				row.MeteringStatus = *soleStatus
				row.MeteringStatusAt = statusAt
			default:
				// Devices disagree — including "some reported, some never
				// have" — never silently collapse to one device's value.
				row.MeteringStatus = "mixed"
				row.MeteringStatusAt = statusAt
			}
			apps = append(apps, row)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate metering rows failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("metering fleet fetched", "tenant_id", tenantID, "app_count", len(apps))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meteringFleetResp{
			TenantID: tenantID,
			Total:    total,
			Apps:     apps,
		})
	}
}

// ---------------------------------------------------------------------------
// Per-device breakdown
// ---------------------------------------------------------------------------

type meteringDeviceRow struct {
	DeviceID              string     `json:"device_id"`
	Hostname              string     `json:"hostname"`
	OS                    string     `json:"os"`
	LastUsedAt            *time.Time `json:"last_used_at"`
	LaunchCount           *int       `json:"launch_count"`
	UsageEvidence         *string    `json:"usage_evidence"`
	UsageEvidenceAt       *time.Time `json:"usage_evidence_at"`
	UsageEvidenceComplete *bool      `json:"usage_evidence_complete"`
	MeteringUserHiveCount *int       `json:"metering_user_hive_count"`
	MeteringRecordCount   *int       `json:"metering_record_count"`
	DaysSinceLastUse      *int       `json:"days_since_last_use"`

	// MeteringStatus is this single device's raw devices.metering_status:
	// "ok" | "spotlight_disabled" | "no_user_session" | nil (never reported —
	// old agent or Windows). Unlike the fleet row this is one device, so
	// there is nothing to aggregate — it is a direct passthrough.
	MeteringStatus *string `json:"metering_status"`
	// MeteringStatusAt is devices.last_seen, the inventory timestamp that
	// most recently set/confirmed this status; nil when MeteringStatus is
	// nil.
	MeteringStatusAt *time.Time `json:"metering_status_at"`
}

type meteringBreakdownResp struct {
	TenantID string              `json:"tenant_id"`
	AppName  string              `json:"app_name"`
	Total    int                 `json:"total"`
	Devices  []meteringDeviceRow `json:"devices"`
}

// MeteringBreakdownHandler returns the per-device usage breakdown for a single
// named app within a tenant's fleet. The app name is taken from the {appName}
// URL parameter (URL-decoded). Use the fleet aggregate endpoint first to
// discover app names, then drill down here.
//
// Ordered by last_used_at DESC NULLS LAST, then hostname.
func MeteringBreakdownHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "metering_breakdown")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		rawAppName := chi.URLParam(r, "appName")
		appName, err := url.PathUnescape(rawAppName)
		if err != nil {
			appName = rawAppName
		}
		appName = strings.TrimSpace(appName)
		if appName == "" {
			http.Error(w, "appName URL param is required", http.StatusBadRequest)
			return
		}

		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
			tenantID,
		).Scan(&exists); err != nil {
			logger.Error("tenant existence check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		var total int
		if err := pool.QueryRow(r.Context(), `
			SELECT COUNT(DISTINCT da.device_id)
			FROM device_apps da
			JOIN devices d ON da.device_id = d.id
			WHERE d.tenant_id = $1::uuid
			  AND da.name = $2
		`, tenantID, appName).Scan(&total); err != nil {
			logger.Error("metering breakdown count failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		rows, err := pool.Query(r.Context(), `
			WITH latest_apps AS (
			    SELECT DISTINCT ON (da.device_id)
			        da.device_id, da.last_used_at, da.launch_count, da.usage_evidence, da.usage_evidence_at, da.usage_evidence_complete
			    FROM device_apps da
			    JOIN devices d ON da.device_id = d.id
			    WHERE d.tenant_id = $1::uuid AND da.name = $2
			    ORDER BY da.device_id, da.last_seen DESC
			)
			SELECT
			    d.id::text,
			    d.hostname,
			    d.os,
			    la.last_used_at,
			    la.launch_count, la.usage_evidence, la.usage_evidence_at, la.usage_evidence_complete, d.metering_user_hive_count, d.metering_record_count,
			    d.metering_status,
			    CASE WHEN d.metering_status IS NOT NULL THEN d.last_seen END AS metering_status_at
			FROM latest_apps la
			JOIN devices d ON d.id = la.device_id
			ORDER BY la.last_used_at DESC NULLS LAST, d.hostname ASC
		`, tenantID, appName)
		if err != nil {
			logger.Error("metering breakdown query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		devices := []meteringDeviceRow{}
		for rows.Next() {
			var row meteringDeviceRow
			if err := rows.Scan(
				&row.DeviceID, &row.Hostname, &row.OS,
				&row.LastUsedAt, &row.LaunchCount, &row.UsageEvidence, &row.UsageEvidenceAt, &row.UsageEvidenceComplete, &row.MeteringUserHiveCount, &row.MeteringRecordCount,
				&row.MeteringStatus, &row.MeteringStatusAt,
			); err != nil {
				logger.Error("scan metering breakdown row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if row.LastUsedAt != nil && (row.UsageEvidence == nil || *row.UsageEvidence == "recorded") {
				days := int(time.Since(*row.LastUsedAt).Hours() / 24)
				row.DaysSinceLastUse = &days
			}
			devices = append(devices, row)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate metering breakdown rows failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("metering breakdown fetched",
			"tenant_id", tenantID,
			"app_name", appName,
			"device_count", len(devices),
		)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meteringBreakdownResp{
			TenantID: tenantID,
			AppName:  appName,
			Total:    total,
			Devices:  devices,
		})
	}
}
