package handlers

// PAT-1595: device lifecycle and reconciliation — platform layer.
//
// Patched cannot see the customer's MDM. Principle: Patched is never the
// authority on what devices exist, only on what it observed and when (root
// AGENTS.md "Absence requires authority"). These handlers let a tenant
// upload their own device list, at any time, and reconcile it against the
// agent's own observed devices (the existing `devices` table) into the
// three buckets and six states internal/devicelifecycle defines.
//
// Routes (all on the internal admin listener):
//
//	POST /admin/tenants/{tenantID}/device-uploads
//	    Upload a device list. Append-only — every upload is kept
//	    (migrations/0140_device_lifecycle.sql), the latest by uploaded_at is
//	    the live list.
//	GET  /admin/tenants/{tenantID}/device-lifecycle
//	    The three-bucket reconciliation plus per-device six-state
//	    classification, computed live against the latest upload and the
//	    thresholds in effect. Always states which threshold values produced
//	    its figures.
//	GET  /admin/tenants/{tenantID}/device-lifecycle/thresholds
//	PUT  /admin/tenants/{tenantID}/device-lifecycle/thresholds
//	    Read/set the tenant's quiet/stale/dormant day overrides. Absence of
//	    an override row means the hardcoded defaults apply.
//
// PAT-1825 wired the deferred piece back in: DeviceLifecycleHandler now
// loads each tenant's live (non-superseded) device_dispositions rows (see
// device_dispositions.go's loadActiveDispositionDeviceIDs) and passes
// activeDisposition through to ClassifyState for every Normal/Untracked
// device — a CoverageGap device has no devices row to hang a disposition
// off, so it is never eligible.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/devicelifecycle"
)

const maxDeviceUploadBytes = 10 << 20 // 10 MiB; generous for a JSON device list, bounded against abuse
const maxDeviceUploadEntries = 100000

type deviceUploadEntry struct {
	ExternalID string `json:"external_id"`
	Serial     string `json:"serial"`
	HWUUID     string `json:"hw_uuid"`
	Hostname   string `json:"hostname"`
}

type deviceUploadReq struct {
	UploadedBy string              `json:"uploaded_by"`
	Devices    []deviceUploadEntry `json:"devices"`
}

// DeviceUploadListHandler serves POST /admin/tenants/{tenantID}/device-uploads.
//
// 201 upload summary | 400 bad input | 404 unknown tenant
func DeviceUploadListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_upload_list")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxDeviceUploadBytes+1))
		if err != nil || len(body) > maxDeviceUploadBytes {
			http.Error(w, "cannot read body or body too large", http.StatusBadRequest)
			return
		}
		var req deviceUploadReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.UploadedBy = strings.TrimSpace(req.UploadedBy)
		if req.UploadedBy == "" {
			http.Error(w, "uploaded_by is required", http.StatusBadRequest)
			return
		}
		if len(req.Devices) > maxDeviceUploadEntries {
			http.Error(w, "device list too large", http.StatusBadRequest)
			return
		}
		// An upload with zero entries is accepted deliberately — a tenant
		// that has genuinely decommissioned its whole estate, or is
		// clearing a bad prior upload, must be able to say "the list is now
		// empty" rather than being forced to keep a stale non-empty one.
		// A nil slice (omitted or null "devices" in the request) must still
		// marshal to JSON "[]", not "null", so the stored column always
		// reads back as an empty list rather than an absent one.
		if req.Devices == nil {
			req.Devices = []deviceUploadEntry{}
		}
		devicesJSON, err := json.Marshal(req.Devices)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		var id int64
		var uploadedAt time.Time
		err = pool.QueryRow(r.Context(), `
			INSERT INTO device_upload_lists (tenant_id, uploaded_by, device_count, devices)
			VALUES ($1::uuid, $2, $3, $4)
			RETURNING id, uploaded_at
		`, tenantID, req.UploadedBy, len(req.Devices), devicesJSON).Scan(&id, &uploadedAt)
		if err != nil {
			logger.Error("device upload insert failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device list uploaded", "tenant_id", tenantID, "upload_id", id, "device_count", len(req.Devices))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":           id,
			"tenant_id":    tenantID,
			"uploaded_at":  uploadedAt,
			"uploaded_by":  req.UploadedBy,
			"device_count": len(req.Devices),
		})
	}
}

type deviceLifecycleEntry struct {
	Bucket     devicelifecycle.Bucket `json:"bucket"`
	State      devicelifecycle.State  `json:"state"`
	ExternalID string                 `json:"external_id,omitempty"`
	DeviceID   string                 `json:"device_id,omitempty"`
	Hostname   string                 `json:"hostname,omitempty"`
	LastSeen   *time.Time             `json:"last_seen,omitempty"`
}

// DeviceLifecycleHandler serves GET /admin/tenants/{tenantID}/device-lifecycle.
//
// Computes the three-bucket reconciliation against the tenant's latest
// uploaded device list and classifies every device into one of the six
// lifecycle states, live, on every call. There is deliberately no cached
// snapshot yet — an issued-report freeze of these figures is a follow-up
// once this feature has a report to freeze into (see the implementer's
// PAT-1595 report).
//
// 200 reconciliation | 400 bad input | 404 unknown tenant
func DeviceLifecycleHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_lifecycle")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		th, err := loadThresholds(r.Context(), pool, tenantID)
		if err != nil {
			logger.Error("load thresholds failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var uploadID *int64
		var uploadedAt *time.Time
		var uploadedBy *string
		var rawDevices []byte
		err = pool.QueryRow(r.Context(), `
			SELECT id, uploaded_at, uploaded_by, devices FROM device_upload_lists
			WHERE tenant_id = $1::uuid ORDER BY uploaded_at DESC, id DESC LIMIT 1
		`, tenantID).Scan(&uploadID, &uploadedAt, &uploadedBy, &rawDevices)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.Error("load latest upload failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var uploaded []deviceUploadEntry
		if rawDevices != nil {
			if err := json.Unmarshal(rawDevices, &uploaded); err != nil {
				logger.Error("decode stored upload failed", "err", err, "tenant_id", tenantID, "upload_id", uploadID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id::text, serial, hw_uuid::text, hostname, last_seen FROM devices WHERE tenant_id = $1::uuid
		`, tenantID)
		if err != nil {
			logger.Error("load devices failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var observed []devicelifecycle.ObservedDevice
		for rows.Next() {
			var d devicelifecycle.ObservedDevice
			var serial, hwUUID, hostname *string
			if err := rows.Scan(&d.ID, &serial, &hwUUID, &hostname, &d.LastSeen); err != nil {
				rows.Close()
				logger.Error("scan device failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if serial != nil {
				d.Serial = *serial
			}
			if hwUUID != nil {
				d.HWUUID = *hwUUID
			}
			if hostname != nil {
				d.Hostname = *hostname
			}
			observed = append(observed, d)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate devices failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		uploadedForReconcile := make([]devicelifecycle.UploadedDevice, len(uploaded))
		for i, u := range uploaded {
			uploadedForReconcile[i] = devicelifecycle.UploadedDevice{
				ExternalID: u.ExternalID, Serial: u.Serial, HWUUID: u.HWUUID, Hostname: u.Hostname,
			}
		}
		recon := devicelifecycle.Reconcile(uploadedForReconcile, observed)
		now := time.Now().UTC()

		// PAT-1825: live disposition records for this tenant. A device on
		// this set classifies as StateRemoved regardless of its last_seen
		// age — see internal/devicelifecycle.ClassifyState.
		activeDispositions, err := loadActiveDispositionDeviceIDs(r.Context(), pool, tenantID)
		if err != nil {
			logger.Error("load active dispositions failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var entries []deviceLifecycleEntry
		for _, m := range recon.Normal {
			ls := m.Observed.LastSeen
			entries = append(entries, deviceLifecycleEntry{
				Bucket:     devicelifecycle.BucketNormal,
				State:      devicelifecycle.ClassifyState(&ls, now, false, activeDispositions[m.Observed.ID], th),
				ExternalID: m.Uploaded.ExternalID, DeviceID: m.Observed.ID,
				Hostname: m.Observed.Hostname, LastSeen: &ls,
			})
		}
		for _, u := range recon.CoverageGap {
			entries = append(entries, deviceLifecycleEntry{
				Bucket:     devicelifecycle.BucketCoverageGap,
				State:      devicelifecycle.ClassifyState(nil, now, true, false, th),
				ExternalID: u.ExternalID, Hostname: u.Hostname,
			})
		}
		for _, o := range recon.Untracked {
			ls := o.LastSeen
			entries = append(entries, deviceLifecycleEntry{
				Bucket:   devicelifecycle.BucketUntracked,
				State:    devicelifecycle.ClassifyState(&ls, now, false, activeDispositions[o.ID], th),
				DeviceID: o.ID, Hostname: o.Hostname, LastSeen: &ls,
			})
		}
		if entries == nil {
			entries = []deviceLifecycleEntry{}
		}

		resp := map[string]any{
			"tenant_id":   tenantID,
			"computed_at": now,
			"thresholds": map[string]int{
				"quiet_days":   th.QuietDays,
				"stale_days":   th.StaleDays,
				"dormant_days": th.DormantDays,
			},
			"reconciliation": map[string]int{
				"normal_count":       len(recon.Normal),
				"coverage_gap_count": len(recon.CoverageGap),
				"untracked_count":    len(recon.Untracked),
				"unmatchable_count":  len(recon.Unmatchable),
			},
			"devices": entries,
		}
		if uploadID != nil {
			resp["upload"] = map[string]any{
				"id": *uploadID, "uploaded_at": *uploadedAt, "uploaded_by": *uploadedBy, "device_count": len(uploaded),
			}
		} else {
			resp["upload"] = nil
		}

		logger.Info("device lifecycle reconciliation served", "tenant_id", tenantID,
			"normal", len(recon.Normal), "coverage_gap", len(recon.CoverageGap), "untracked", len(recon.Untracked))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// loadThresholds returns the tenant's threshold overrides, or the hardcoded
// defaults if no override row exists.
func loadThresholds(ctx context.Context, pool *pgxpool.Pool, tenantID string) (devicelifecycle.Thresholds, error) {
	th := devicelifecycle.DefaultThresholds()
	err := pool.QueryRow(ctx, `
		SELECT quiet_days, stale_days, dormant_days FROM device_lifecycle_thresholds WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&th.QuietDays, &th.StaleDays, &th.DormantDays)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return devicelifecycle.Thresholds{}, err
	}
	return th, nil
}

type thresholdsGetPutReq struct {
	QuietDays   int    `json:"quiet_days"`
	StaleDays   int    `json:"stale_days"`
	DormantDays int    `json:"dormant_days"`
	UpdatedBy   string `json:"updated_by"`
}

// DeviceLifecycleThresholdsGetHandler serves
// GET /admin/tenants/{tenantID}/device-lifecycle/thresholds.
//
// Always returns concrete numbers — the hardcoded defaults if the tenant has
// no override row — so a caller never has to know the fallback rule itself.
func DeviceLifecycleThresholdsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		th, err := loadThresholds(r.Context(), pool, tenantID)
		if err != nil {
			slog.Error("load thresholds failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": tenantID, "quiet_days": th.QuietDays, "stale_days": th.StaleDays, "dormant_days": th.DormantDays,
		})
	}
}

// DeviceLifecycleThresholdsPutHandler serves
// PUT /admin/tenants/{tenantID}/device-lifecycle/thresholds.
//
// 200 thresholds | 400 bad input (also the ordering CHECK the migration
// enforces: quiet < stale < dormant) | 404 unknown tenant
func DeviceLifecycleThresholdsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_lifecycle_thresholds_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req thresholdsGetPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.UpdatedBy = strings.TrimSpace(req.UpdatedBy)
		if req.UpdatedBy == "" {
			http.Error(w, "updated_by is required", http.StatusBadRequest)
			return
		}
		if !(req.QuietDays > 0 && req.QuietDays < req.StaleDays && req.StaleDays < req.DormantDays) {
			http.Error(w, "thresholds must satisfy 0 < quiet_days < stale_days < dormant_days", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		_, err = pool.Exec(r.Context(), `
			INSERT INTO device_lifecycle_thresholds (tenant_id, quiet_days, stale_days, dormant_days, updated_by)
			VALUES ($1::uuid, $2, $3, $4, $5)
			ON CONFLICT (tenant_id) DO UPDATE SET
			    quiet_days = EXCLUDED.quiet_days, stale_days = EXCLUDED.stale_days,
			    dormant_days = EXCLUDED.dormant_days, updated_at = now(), updated_by = EXCLUDED.updated_by
		`, tenantID, req.QuietDays, req.StaleDays, req.DormantDays, req.UpdatedBy)
		if err != nil {
			logger.Error("threshold upsert failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device lifecycle thresholds updated", "tenant_id", tenantID,
			"quiet_days", req.QuietDays, "stale_days", req.StaleDays, "dormant_days", req.DormantDays)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": tenantID, "quiet_days": req.QuietDays, "stale_days": req.StaleDays, "dormant_days": req.DormantDays,
		})
	}
}
