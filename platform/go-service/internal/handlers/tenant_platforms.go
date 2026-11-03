package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantPlatforms* handlers manage the per-tenant, per-OS master switch.
// All live on the internal Tailscale-bound listener.
//
// Auth posture: network-only at MVP — same as other admin handlers. See admin.go.
//
// Routes:
//
//	GET  /admin/tenant-platforms/{tenantID}  — return { macos_enabled, windows_enabled }
//	PUT  /admin/tenant-platforms/{tenantID}  — flip one platform switch; audit-logged

type tenantPlatformsResp struct {
	TenantID       string `json:"tenant_id"`
	MacOSEnabled   bool   `json:"macos_enabled"`
	WindowsEnabled bool   `json:"windows_enabled"`
}

// TenantPlatformsGetHandler returns the current master-switch state for a tenant.
func TenantPlatformsGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_platforms_get")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var resp tenantPlatformsResp
		resp.TenantID = tenantID
		err := pool.QueryRow(r.Context(), `
			SELECT macos_enabled, windows_enabled
			FROM tenants
			WHERE id = $1::uuid
		`, tenantID).Scan(&resp.MacOSEnabled, &resp.WindowsEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("query tenant platforms failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant platforms fetched", "tenant_id", tenantID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// tenantPlatformPutReq is the PUT request body.
type tenantPlatformPutReq struct {
	Platform string `json:"platform"` // "macos" or "windows"
	Enabled  bool   `json:"enabled"`
}

// TenantPlatformsPutHandler flips one platform's master switch and records the
// change in tenant_platform_changes. Rejects unknown platform values.
func TenantPlatformsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_platforms_put")

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
		var req tenantPlatformPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		// Map the platform to a fixed column literal rather than concatenating
		// the request-supplied value into SQL. Defence in depth against
		// identifier injection on top of the allowlist below.
		var col string
		switch req.Platform {
		case "macos":
			col = "macos_enabled"
		case "windows":
			col = "windows_enabled"
		default:
			http.Error(w, `platform must be "macos" or "windows"`, http.StatusBadRequest)
			return
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		// Read current state for change detection and to confirm tenant exists.
		var oldEnabled bool
		err = tx.QueryRow(r.Context(),
			"SELECT "+col+" FROM tenants WHERE id = $1::uuid",
			tenantID,
		).Scan(&oldEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch current platform state failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Update the column.
		if _, err := tx.Exec(r.Context(),
			"UPDATE tenants SET "+col+" = $1, updated_at = now() WHERE id = $2::uuid",
			req.Enabled, tenantID,
		); err != nil {
			logger.Error("update platform switch failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Write audit row — always, even when the value doesn't change, so the
		// operator has a full history of who touched what.
		// PAT-1135: changed_by (via actor below) records the server-
		// established shared-token principal — this request body carries no
		// actor field at all today, so there is no caller-supplied claim to
		// record; claimed_actor stays NULL. source_addr records the
		// observed client IP. See internal/handlers/audit_attribution.go.
		actor, claimedActor, sourceAddr := auditAttribution(r, "")
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_platform_changes
				(tenant_id, platform, old_enabled, new_enabled, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		`, tenantID, req.Platform, oldEnabled, req.Enabled, actor, claimedActor, sourceAddr); err != nil {
			logger.Error("insert platform change log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant platform switch updated",
			"tenant_id", tenantID,
			"platform", req.Platform,
			"old_enabled", oldEnabled,
			"new_enabled", req.Enabled,
		)

		// Re-read the committed row for the authoritative state rather than
		// reconstructing it from the request — the other platform's value
		// isn't known here without a fresh read.
		var resp tenantPlatformsResp
		resp.TenantID = tenantID
		resp.MacOSEnabled, resp.WindowsEnabled, err = rereadTenantPlatformState(r.Context(), pool, tenantID)
		if err != nil {
			// The write already committed; a failure here means we can't confirm
			// the resulting state, so surface it rather than returning a guess.
			logger.Error("post-commit re-read failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// rereadTenantPlatformState re-reads the committed macos_enabled/windows_enabled
// values for tenantID. Takes a rowQuerier (satisfied by *pgxpool.Pool) rather
// than the concrete pool type so tests can exercise the error path — including
// a transient failure on this specific query — without a live database.
func rereadTenantPlatformState(ctx context.Context, q rowQuerier, tenantID string) (macosEnabled, windowsEnabled bool, err error) {
	err = q.QueryRow(ctx, `
		SELECT macos_enabled, windows_enabled FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&macosEnabled, &windowsEnabled)
	return
}
