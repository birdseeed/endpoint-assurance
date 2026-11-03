package handlers

// Enrolled-device management endpoints (PAT-549).
//
// GET  /admin/tenants/{tenantID}/enrolled-devices  — list enrolled devices for a tenant.
// POST /admin/devices/{deviceID}/revoke            — revoke a device (pull-based: no push).
//
// Revocation is pull-based: the device is NOT notified. On the next agent API
// call (inventory, posture, agent-config, etc.) the bearer-token auth middleware
// returns 401 because all tenant_credentials rows for that device now have
// revoked_at set. The agent should enter a suspended/offboarded state when it
// receives 401 on subsequent retries.
//
// Scope guard: the revoke endpoint resolves tenant_id from the devices table
// and refuses to revoke a device that belongs to a different tenant — identical
// to the pattern used by IssueDeviceCredentialHandler.
//
// Audit trail: each revoke action inserts one row into device_revocations
// (append-only, never updated/deleted).

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/enrolled-devices
// ---------------------------------------------------------------------------

type enrolledDeviceEntry struct {
	DeviceID   string     `json:"device_id"`
	Hostname   string     `json:"hostname"`
	Serial     string     `json:"serial"`
	OS         *string    `json:"os"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeen   *time.Time `json:"last_seen"`
	Status     string     `json:"status"`     // "active" | "revoked"
	RevokedAt  *time.Time `json:"revoked_at"` // non-null when status = "revoked"
}

type enrolledDevicesResp struct {
	TenantID string                `json:"tenant_id"`
	Total    int                   `json:"total"`
	Devices  []enrolledDeviceEntry `json:"devices"`
}

// TenantEnrolledDevicesHandler lists all enrolled devices for a tenant, including
// revoked devices (they stay visible with their revoked_at timestamp).
//
// "Enrolled" means the device has at least one per-device credential row in
// tenant_credentials (device_id IS NOT NULL). A device is "revoked" when all
// its credential rows have revoked_at set.
//
// Route: GET /admin/tenants/{tenantID}/enrolled-devices  (internal listener :8081)
func TenantEnrolledDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "tenant_enrolled_devices", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		// Verify tenant exists.
		var exists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`,
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

		// One row per device. enrolled_at = earliest credential issued for that device.
		// last_seen = devices.last_seen (updated on each inventory upload).
		// status = "revoked" when ALL credentials for the device are revoked; "active" otherwise.
		// revoked_at = timestamp from device_revocations (most recent revoke action), if any.
		rows, err := pool.Query(r.Context(), `
			SELECT
				d.id::text                                      AS device_id,
				COALESCE(d.hostname, '')                        AS hostname,
				COALESCE(d.serial, '')                         AS serial,
				d.os,
				MIN(tc.created_at)                             AS enrolled_at,
				d.last_seen,
				CASE
					WHEN COUNT(*) FILTER (WHERE tc.revoked_at IS NULL) = 0 THEN 'revoked'
					ELSE 'active'
				END                                            AS status,
				MAX(dr.revoked_at)                             AS revoked_at
			FROM devices d
			JOIN tenant_credentials tc ON tc.device_id = d.id
			LEFT JOIN device_revocations dr ON dr.device_id = d.id
			WHERE d.tenant_id = $1::uuid
			  AND tc.device_id IS NOT NULL
			GROUP BY d.id, d.hostname, d.serial, d.os, d.last_seen
			ORDER BY enrolled_at DESC
		`, tenantID)
		if err != nil {
			logger.Error("enrolled devices query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var devices []enrolledDeviceEntry
		for rows.Next() {
			var e enrolledDeviceEntry
			if err := rows.Scan(
				&e.DeviceID, &e.Hostname, &e.Serial, &e.OS,
				&e.EnrolledAt, &e.LastSeen,
				&e.Status, &e.RevokedAt,
			); err != nil {
				logger.Error("scan enrolled device failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			devices = append(devices, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate enrolled devices failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if devices == nil {
			devices = []enrolledDeviceEntry{}
		}

		logger.Info("enrolled devices listed", "count", len(devices))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enrolledDevicesResp{
			TenantID: tenantID,
			Total:    len(devices),
			Devices:  devices,
		})
	}
}

// ---------------------------------------------------------------------------
// POST /admin/devices/{deviceID}/revoke
// ---------------------------------------------------------------------------

type revokeDeviceResp struct {
	DeviceID  string    `json:"device_id"`
	TenantID  string    `json:"tenant_id"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevokeDeviceHandler revokes a device by setting revoked_at = now() on all
// active tenant_credentials rows for that device, then recording an audit entry
// in device_revocations.
//
// Pull-based: the device is not contacted. On the next API call its bearer
// token will fail LookupDeviceByBearer (which gates on tc.revoked_at IS NULL)
// and the agent will receive 401.
//
// Idempotent: if all credentials are already revoked, returns 200 with the
// existing revoke timestamp from device_revocations.
//
// Scope guard: resolves tenant_id from the devices row — a request cannot
// revoke a device on a different tenant even if the caller supplies the right
// device_id.
//
// Route: POST /admin/devices/{deviceID}/revoke  (internal listener :8081)
func RevokeDeviceHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		logger := slog.With("req_id", reqID, "handler", "revoke_device", "device_id", deviceID)

		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		// Resolve device → tenant_id. 404 if not found.
		var tenantID string
		err := pool.QueryRow(r.Context(),
			`SELECT tenant_id::text FROM devices WHERE id = $1::uuid`,
			deviceID,
		).Scan(&tenantID)
		if err != nil {
			if isNoRowsErr(err) {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			logger.Error("device lookup failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Idempotent: check whether already fully revoked. If all credential rows
		// for this device are already revoked, return the existing audit timestamp.
		var activeCount int
		if err := pool.QueryRow(r.Context(), `
			SELECT COUNT(*)
			FROM tenant_credentials
			WHERE device_id = $1::uuid
			  AND revoked_at IS NULL
		`, deviceID).Scan(&activeCount); err != nil {
			logger.Error("active credential count failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if activeCount == 0 {
			// Already fully revoked — return the most recent audit record.
			var existingRevokedAt time.Time
			if err := pool.QueryRow(r.Context(), `
				SELECT revoked_at FROM device_revocations
				WHERE device_id = $1::uuid
				ORDER BY revoked_at DESC LIMIT 1
			`, deviceID).Scan(&existingRevokedAt); err != nil {
				// No audit row — use the credential revoked_at as fallback.
				if err2 := pool.QueryRow(r.Context(), `
					SELECT MAX(revoked_at) FROM tenant_credentials WHERE device_id = $1::uuid
				`, deviceID).Scan(&existingRevokedAt); err2 != nil {
					logger.Error("existing revoke timestamp lookup failed", "err", err2)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}
			logger.Info("device already revoked", "revoked_at", existingRevokedAt.UTC().Format(time.RFC3339))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(revokeDeviceResp{
				DeviceID:  deviceID,
				TenantID:  tenantID,
				RevokedAt: existingRevokedAt,
			})
			return
		}

		// Revoke all active credentials for this device in a single transaction.
		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck

		var revokedAt time.Time
		if err := tx.QueryRow(r.Context(), `
			UPDATE tenant_credentials
			SET revoked_at = now()
			WHERE device_id = $1::uuid
			  AND revoked_at IS NULL
			RETURNING now()
		`, deviceID).Scan(&revokedAt); err != nil {
			logger.Error("credential revocation failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Append to audit log.
		//
		// PAT-1135: admin_id records the server-established shared-token
		// principal, never a hardcoded 'admin' literal — the admin surface
		// has no per-person identity to attribute this to. This handler
		// takes no request body today, so there is no caller-supplied
		// string to put in claimed_actor; it stays NULL. source_addr
		// records the observed client IP. See
		// internal/handlers/audit_attribution.go.
		actor, claimedActor, sourceAddr := auditAttribution(r, "")
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO device_revocations (tenant_id, device_id, admin_id, action, revoked_at, claimed_actor, source_addr)
			VALUES ($1::uuid, $2::uuid, $3, 'revoke', $4, $5, $6)
		`, tenantID, deviceID, actor, revokedAt, claimedActor, sourceAddr); err != nil {
			logger.Error("audit log insert failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("device revoked", "tenant_id", tenantID, "revoked_at", revokedAt.UTC().Format(time.RFC3339))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(revokeDeviceResp{
			DeviceID:  deviceID,
			TenantID:  tenantID,
			RevokedAt: revokedAt,
		})
	}
}
