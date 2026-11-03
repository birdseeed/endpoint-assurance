package handlers

// Ring configuration handlers (PAT-117) — per-tenant patching ring setup and
// per-device ring override management.
//
// All routes live on the internal Tailscale-bound listener (:8081). Network-only
// auth — same posture as other /admin/* endpoints.
//
// Routes:
//
//	GET  /admin/tenants/{tenantID}/ring-config
//	PUT  /admin/tenants/{tenantID}/ring-config
//	GET  /admin/tenants/{tenantID}/ring-devices
//	PUT  /admin/tenants/{tenantID}/ring-devices/{deviceID}

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/rings"
)

// -- Response / request types -------------------------------------------------

type ringConfigResp struct {
	TenantID            string    `json:"tenant_id"`
	Enabled             bool      `json:"enabled"`
	RingCount           int       `json:"ring_count"`
	Percentages         []int     `json:"percentages"`
	SoakGapHours        int       `json:"soak_gap_hours"`
	FailureThresholdPct float64   `json:"failure_threshold_pct"`
	MinFailuresToPause  int       `json:"min_failures_to_pause"`
	MinEstateSize       int       `json:"min_estate_size"`
	ConfigVersion       int       `json:"config_version"`
	DeviceCount         int       `json:"device_count"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type ringConfigPutReq struct {
	Enabled             bool    `json:"enabled"`
	RingCount           int     `json:"ring_count"`
	Percentages         []int   `json:"percentages"`
	SoakGapHours        int     `json:"soak_gap_hours"`
	FailureThresholdPct float64 `json:"failure_threshold_pct"`
	MinFailuresToPause  int     `json:"min_failures_to_pause"`
	MinEstateSize       int     `json:"min_estate_size"`
	UpdatedBy           string  `json:"updated_by"`
}

type ringDeviceEntry struct {
	DeviceID      string `json:"device_id"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	PrimaryUser   string `json:"primary_user_display"`
	ComputedRing  *int   `json:"computed_ring"`
	OverrideRing  *int   `json:"override_ring"`
	EffectiveRing int    `json:"effective_ring"`
}

type ringDevicesResp struct {
	TenantID string            `json:"tenant_id"`
	Devices  []ringDeviceEntry `json:"devices"`
}

type ringDeviceOverridePutReq struct {
	Ring      *int   `json:"ring"` // null = clear override
	ChangedBy string `json:"changed_by"`
}

// -- Handlers -----------------------------------------------------------------

// RingConfigGetHandler returns the ring configuration for a tenant.
func RingConfigGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_config_get")

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
			logger.Error("tenant check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		resp := ringConfigResp{
			TenantID:            tenantID,
			Enabled:             false,
			RingCount:           3,
			Percentages:         []int{10, 30, 60},
			SoakGapHours:        24,
			FailureThresholdPct: 5.0,
			MinFailuresToPause:  2,
			MinEstateSize:       10,
			ConfigVersion:       0,
		}

		var pctInts []int16
		err := pool.QueryRow(r.Context(), `
			SELECT enabled, ring_count, percentages, soak_gap_hours,
			       failure_threshold_pct, min_failures_to_pause, min_estate_size,
			       config_version, updated_at
			FROM tenant_ring_config
			WHERE tenant_id = $1::uuid
		`, tenantID).Scan(
			&resp.Enabled, &resp.RingCount, &pctInts, &resp.SoakGapHours,
			&resp.FailureThresholdPct, &resp.MinFailuresToPause, &resp.MinEstateSize,
			&resp.ConfigVersion, &resp.UpdatedAt,
		)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("query ring config failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(pctInts) > 0 {
			resp.Percentages = make([]int, len(pctInts))
			for i, p := range pctInts {
				resp.Percentages[i] = int(p)
			}
		}

		deviceCount, _ := rings.DeviceCount(r.Context(), pool, tenantID)
		resp.DeviceCount = deviceCount

		logger.Info("ring config loaded", "tenant_id", tenantID, "enabled", resp.Enabled)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// RingConfigPutHandler creates or updates the ring configuration for a tenant.
// Validates percentages sum to 100 and len == ring_count; recomputes fleet assignments.
func RingConfigPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return ringConfigPutHandler(pool, false)
}

// RingConfigPutHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func RingConfigPutHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool) http.HandlerFunc {
	return ringConfigPutHandler(pool, true)
}

func ringConfigPutHandler(pool *pgxpool.Pool, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_config_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req ringConfigPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if err := validateRingConfigReq(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !legacyExecutionEnabled && req.Enabled {
			legacyExecutionDisabledHandler(w, r)
			return
		}
		if req.UpdatedBy == "" {
			req.UpdatedBy = "system"
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var tenantExists bool
		if err := tx.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
			tenantID,
		).Scan(&tenantExists); err != nil {
			logger.Error("tenant check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		// Convert percentages to int16 for the smallint[] column.
		pctInts := make([]int16, len(req.Percentages))
		for i, p := range req.Percentages {
			pctInts[i] = int16(p)
		}

		var configVersion int
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO tenant_ring_config
				(tenant_id, enabled, ring_count, percentages, soak_gap_hours,
				 failure_threshold_pct, min_failures_to_pause, min_estate_size, updated_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id) DO UPDATE
				SET enabled               = EXCLUDED.enabled,
				    ring_count            = EXCLUDED.ring_count,
				    percentages           = EXCLUDED.percentages,
				    soak_gap_hours        = EXCLUDED.soak_gap_hours,
				    failure_threshold_pct = EXCLUDED.failure_threshold_pct,
				    min_failures_to_pause = EXCLUDED.min_failures_to_pause,
				    min_estate_size       = EXCLUDED.min_estate_size,
				    updated_by            = EXCLUDED.updated_by,
				    config_version        = tenant_ring_config.config_version + 1,
				    updated_at            = now()
			RETURNING config_version
		`, tenantID, req.Enabled, req.RingCount, pctInts, req.SoakGapHours,
			req.FailureThresholdPct, req.MinFailuresToPause, req.MinEstateSize, req.UpdatedBy,
		).Scan(&configVersion); err != nil {
			logger.Error("upsert ring config failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Recompute fleet assignments inside the same transaction.
		deviceCount, _ := rings.DeviceCount(r.Context(), pool, tenantID)
		if req.Enabled && deviceCount >= req.MinEstateSize {
			if err := rings.RecomputeFleet(r.Context(), tx, tenantID, req.Percentages, req.RingCount); err != nil {
				logger.Error("recompute fleet failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		} else if req.Enabled {
			// Below min estate size — assign everyone GA.
			if err := rings.RecomputeFleetGA(r.Context(), tx, tenantID); err != nil {
				logger.Error("recompute fleet GA failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO ring_config_changes (tenant_id, change_type, changed_by, new_value)
			VALUES ($1::uuid, 'config_updated', $2, $3::jsonb)
		`, tenantID, req.UpdatedBy, body); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("ring config updated",
			"tenant_id", tenantID, "enabled", req.Enabled,
			"ring_count", req.RingCount, "config_version", configVersion)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id":      tenantID,
			"config_version": configVersion,
		})
	}
}

// RingDevicesListHandler returns per-device ring assignments for a tenant.
func RingDevicesListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_devices_list")

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
			logger.Error("tenant check failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id::text,
			       COALESCE(hostname, serial, hw_uuid::text, 'unknown') AS hostname,
			       COALESCE(os, '') AS os,
			       COALESCE(primary_user_display, primary_user_account, '') AS primary_user_display,
			       ring_computed, ring_override
			FROM devices
			WHERE tenant_id = $1::uuid
			ORDER BY hostname
		`, tenantID)
		if err != nil {
			logger.Error("query devices failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var devices []ringDeviceEntry
		for rows.Next() {
			var e ringDeviceEntry
			var comp, over *int16
			if err := rows.Scan(&e.DeviceID, &e.Hostname, &e.OS, &e.PrimaryUser, &comp, &over); err != nil {
				logger.Error("scan device row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if comp != nil {
				v := int(*comp)
				e.ComputedRing = &v
			}
			if over != nil {
				v := int(*over)
				e.OverrideRing = &v
			}
			e.EffectiveRing = rings.EffectiveAgentRing(over, comp)
			devices = append(devices, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate devices failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if devices == nil {
			devices = []ringDeviceEntry{}
		}

		logger.Info("ring devices listed", "tenant_id", tenantID, "count", len(devices))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ringDevicesResp{
			TenantID: tenantID,
			Devices:  devices,
		})
	}
}

// RingDeviceOverridePutHandler sets or clears the ring override for a device.
func RingDeviceOverridePutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return ringDeviceOverridePutHandler(pool, false)
}

// RingDeviceOverridePutHandlerForLegacyExecutionCompatibility exists only for
// retained compatibility tests. It must never be used in production wiring.
func RingDeviceOverridePutHandlerForLegacyExecutionCompatibility(pool *pgxpool.Pool) http.HandlerFunc {
	return ringDeviceOverridePutHandler(pool, true)
}

func ringDeviceOverridePutHandler(pool *pgxpool.Pool, legacyExecutionEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "ring_device_override_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req ringDeviceOverridePutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.Ring != nil && (*req.Ring < 0 || *req.Ring > 3) {
			http.Error(w, "ring must be 0-3 or null to clear", http.StatusBadRequest)
			return
		}
		if !legacyExecutionEnabled && req.Ring != nil {
			legacyExecutionDisabledHandler(w, r)
			return
		}
		if req.ChangedBy == "" {
			req.ChangedBy = "system"
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var prevOverride *int16
		err = tx.QueryRow(r.Context(),
			`SELECT ring_override FROM devices WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			deviceID, tenantID,
		).Scan(&prevOverride)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch device failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var newOverride *int16
		if req.Ring != nil {
			v := int16(*req.Ring)
			newOverride = &v
		}
		if _, err := tx.Exec(r.Context(),
			`UPDATE devices SET ring_override = $1 WHERE id = $2::uuid`,
			newOverride, deviceID,
		); err != nil {
			logger.Error("update ring override failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		changeType := "device_override_set"
		if req.Ring == nil {
			changeType = "device_override_cleared"
		}
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO ring_config_changes
				(tenant_id, change_type, device_id, changed_by, old_value, new_value)
			VALUES ($1::uuid, $2, $3::uuid, $4, $5::jsonb, $6::jsonb)
		`, tenantID, changeType, deviceID, req.ChangedBy,
			jsonOrNull(prevOverride), jsonOrNull(newOverride),
		); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("ring override updated",
			"tenant_id", tenantID, "device_id", deviceID,
			"old", prevOverride, "new", newOverride)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_id":     deviceID,
			"ring_override": newOverride,
		})
	}
}

// -- Validation ---------------------------------------------------------------

func validateRingConfigReq(req ringConfigPutReq) error {
	if req.RingCount < 2 || req.RingCount > 5 {
		return errors.New("ring_count must be between 2 and 5")
	}
	if len(req.Percentages) != req.RingCount {
		return errors.New("len(percentages) must equal ring_count")
	}
	sum := 0
	for _, p := range req.Percentages {
		if p <= 0 {
			return errors.New("each percentage must be > 0")
		}
		sum += p
	}
	if sum != 100 {
		return errors.New("percentages must sum to 100")
	}
	if req.SoakGapHours < 0 {
		return errors.New("soak_gap_hours must be >= 0")
	}
	if req.FailureThresholdPct < 0 || req.FailureThresholdPct > 100 {
		return errors.New("failure_threshold_pct must be between 0 and 100")
	}
	if req.MinFailuresToPause < 1 {
		return errors.New("min_failures_to_pause must be >= 1")
	}
	if req.MinEstateSize < 1 {
		return errors.New("min_estate_size must be >= 1")
	}
	return nil
}

// jsonOrNull marshals v to JSON or returns nil (SQL NULL) if v is nil.
func jsonOrNull(v interface{}) *string {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	s := string(b)
	return &s
}
