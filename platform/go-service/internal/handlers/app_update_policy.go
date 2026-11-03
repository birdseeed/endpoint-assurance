package handlers

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
)

// AppUpdatePolicy* handlers manage the per-tenant app-update policy store.
// All live on the internal Tailscale-bound listener (:8081).
//
// Auth posture: network-only at MVP — same as other admin handlers. See admin.go.
//
// ⚠️  These handlers drive agent behaviour on customer endpoints.
// GitHub-Non-Author-Review applies before first customer ship.
//
// Routes:
//
//	GET    /admin/tenant-app-policy/{tenantID}              — fleet default + per-app list
//	PUT    /admin/tenant-app-policy/{tenantID}/default      — flip the fleet default
//	PUT    /admin/tenant-app-policy/{tenantID}/apps         — upsert a per-app override
//	DELETE /admin/tenant-app-policy/{tenantID}/apps/{id}    — remove a per-app override

// appPolicyEntry is one row from tenant_app_update_policies in the GET response.
type appPolicyEntry struct {
	ID         string    `json:"id"`
	Platform   string    `json:"platform"`
	Identifier string    `json:"identifier"`
	Name       *string   `json:"name"`
	Publisher  *string   `json:"publisher"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type appPolicyListResp struct {
	TenantID       string           `json:"tenant_id"`
	DefaultEnabled bool             `json:"default_enabled"`
	Policies       []appPolicyEntry `json:"policies"`
}

// AppUpdatePolicyListHandler returns the fleet default and all per-app overrides
// for a tenant. Policies are ordered by platform then identifier.
func AppUpdatePolicyListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_update_policy_list")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var defaultEnabled bool
		err := pool.QueryRow(r.Context(),
			`SELECT app_updates_default_enabled FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL`,
			tenantID,
		).Scan(&defaultEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("query tenant default failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT id::text, platform, identifier, name, publisher, enabled, created_at, updated_at
			FROM tenant_app_update_policies
			WHERE tenant_id = $1::uuid
			ORDER BY platform, identifier
		`, tenantID)
		if err != nil {
			logger.Error("query per-app policies failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		policies := []appPolicyEntry{}
		for rows.Next() {
			var e appPolicyEntry
			if err := rows.Scan(
				&e.ID, &e.Platform, &e.Identifier, &e.Name, &e.Publisher,
				&e.Enabled, &e.CreatedAt, &e.UpdatedAt,
			); err != nil {
				logger.Error("scan app policy row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			policies = append(policies, e)
		}
		if err := rows.Err(); err != nil {
			logger.Error("iterate app policies failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("app policies listed", "tenant_id", tenantID, "count", len(policies))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(appPolicyListResp{
			TenantID:       tenantID,
			DefaultEnabled: defaultEnabled,
			Policies:       policies,
		})
	}
}

// appPolicyDefaultPutReq is the PUT /default request body.
type appPolicyDefaultPutReq struct {
	Enabled   bool   `json:"enabled"`
	ChangedBy string `json:"changed_by"`
}

type appPolicyDefaultPutResp struct {
	TenantID       string `json:"tenant_id"`
	DefaultEnabled bool   `json:"default_enabled"`
}

// AppUpdatePolicyDefaultPutHandler flips the fleet-wide default
// (tenants.app_updates_default_enabled) and records the change in
// tenant_app_policy_changes.
func AppUpdatePolicyDefaultPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_update_policy_default_put")

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
		var req appPolicyDefaultPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
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

		var oldEnabled bool
		err = tx.QueryRow(r.Context(),
			`SELECT app_updates_default_enabled FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL`,
			tenantID,
		).Scan(&oldEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch current default failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(r.Context(),
			`UPDATE tenants SET app_updates_default_enabled = $1, updated_at = now() WHERE id = $2::uuid`,
			req.Enabled, tenantID,
		); err != nil {
			logger.Error("update default failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-1135: changed_by records the server-established shared-token
		// principal, never req.ChangedBy — the admin surface has no
		// per-person identity to verify that string against. req.ChangedBy
		// still flows into claimed_actor, untrusted. See
		// internal/handlers/audit_attribution.go.
		actor, claimedActor, sourceAddr := auditAttribution(r, req.ChangedBy)
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_app_policy_changes
				(tenant_id, change_type, old_enabled, new_enabled, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, 'default_changed', $2, $3, $4, $5, $6)
		`, tenantID, oldEnabled, req.Enabled, actor, claimedActor, sourceAddr); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("app update default changed",
			"tenant_id", tenantID,
			"old", oldEnabled,
			"new", req.Enabled,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(appPolicyDefaultPutResp{
			TenantID:       tenantID,
			DefaultEnabled: req.Enabled,
		})
	}
}

// appPolicyAppPutReq is the PUT /apps request body.
type appPolicyAppPutReq struct {
	Platform   string  `json:"platform"`
	Identifier string  `json:"identifier"`
	Name       *string `json:"name"`
	Publisher  *string `json:"publisher"`
	Enabled    bool    `json:"enabled"`
	ChangedBy  string  `json:"changed_by"`
}

// AppUpdatePolicyAppPutHandler upserts one per-app override. On conflict
// (same tenant, platform, identifier) it updates the existing row. The change
// is recorded in tenant_app_policy_changes.
func AppUpdatePolicyAppPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_update_policy_app_put")

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
		var req appPolicyAppPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		switch req.Platform {
		case "macos", "windows":
		default:
			http.Error(w, `platform must be "macos" or "windows"`, http.StatusBadRequest)
			return
		}
		if req.Identifier == "" {
			http.Error(w, "identifier is required", http.StatusBadRequest)
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

		// Confirm tenant exists.
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

		// Read previous state for the audit log (may not exist yet).
		var prevEnabled *bool
		_ = tx.QueryRow(r.Context(),
			`SELECT enabled FROM tenant_app_update_policies WHERE tenant_id = $1::uuid AND platform = $2 AND identifier = $3`,
			tenantID, req.Platform, req.Identifier,
		).Scan(&prevEnabled)

		var resp appPolicyEntry
		err = tx.QueryRow(r.Context(), `
			INSERT INTO tenant_app_update_policies
				(tenant_id, platform, identifier, name, publisher, enabled)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, platform, identifier) DO UPDATE
				SET name       = EXCLUDED.name,
				    publisher  = EXCLUDED.publisher,
				    enabled    = EXCLUDED.enabled,
				    updated_at = now()
			RETURNING id::text, platform, identifier, name, publisher, enabled, created_at, updated_at
		`, tenantID, req.Platform, req.Identifier, req.Name, req.Publisher, req.Enabled,
		).Scan(
			&resp.ID, &resp.Platform, &resp.Identifier, &resp.Name, &resp.Publisher,
			&resp.Enabled, &resp.CreatedAt, &resp.UpdatedAt,
		)
		if err != nil {
			logger.Error("upsert app policy failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		changeType := "app_enabled"
		if !req.Enabled {
			changeType = "app_disabled"
		}
		// PAT-1135: changed_by records the server-established shared-token
		// principal, never req.ChangedBy — see the identical note above in
		// AppUpdatePolicyDefaultPutHandler.
		actor, claimedActor, sourceAddr := auditAttribution(r, req.ChangedBy)
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_app_policy_changes
				(tenant_id, platform, identifier, change_type, old_enabled, new_enabled, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
		`, tenantID, req.Platform, req.Identifier, changeType, prevEnabled, req.Enabled, actor, claimedActor, sourceAddr,
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

		logger.Info("app policy upserted",
			"tenant_id", tenantID,
			"platform", req.Platform,
			"identifier", req.Identifier,
			"enabled", req.Enabled,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// AppUpdatePolicyAppDeleteHandler removes a per-app override and records the
// removal in tenant_app_policy_changes. After deletion the app inherits the
// fleet default again. The policy ID comes from the GET list.
func AppUpdatePolicyAppDeleteHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "app_update_policy_app_delete")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		policyID := strings.TrimSpace(chi.URLParam(r, "policyID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(policyID) {
			http.Error(w, "policyID must be a UUID", http.StatusBadRequest)
			return
		}

		tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			logger.Error("begin tx failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		var platform, identifier string
		var prevEnabled bool
		err = tx.QueryRow(r.Context(),
			`SELECT platform, identifier, enabled FROM tenant_app_update_policies WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			policyID, tenantID,
		).Scan(&platform, &identifier, &prevEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			var tenantExists bool
			_ = pool.QueryRow(r.Context(),
				`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`,
				tenantID,
			).Scan(&tenantExists)
			if !tenantExists {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			http.Error(w, "policy not found", http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("fetch policy failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if _, err := tx.Exec(r.Context(),
			`DELETE FROM tenant_app_update_policies WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			policyID, tenantID,
		); err != nil {
			logger.Error("delete app policy failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// PAT-1135: changed_by records the server-established shared-token
		// principal, not a hardcoded 'system' literal — this handler takes
		// no request body, so there is no caller-supplied claim to record;
		// claimed_actor stays NULL. See internal/handlers/audit_attribution.go.
		actor, claimedActor, sourceAddr := auditAttribution(r, "")
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_app_policy_changes
				(tenant_id, platform, identifier, change_type, old_enabled, new_enabled, changed_by, claimed_actor, source_addr)
			VALUES ($1::uuid, $2, $3, 'app_removed', $4, NULL, $5, $6, $7)
		`, tenantID, platform, identifier, prevEnabled, actor, claimedActor, sourceAddr); err != nil {
			logger.Error("insert audit log failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("app policy deleted",
			"tenant_id", tenantID,
			"policy_id", policyID,
			"platform", platform,
			"identifier", identifier,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"deleted": true})
	}
}
