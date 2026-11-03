package handlers

// Application Control policy endpoints (PAT-602).
//
// GET /admin/tenants/{tenantID}/app-control
//   Return the current app_control policy for a tenant.
//
// PUT /admin/tenants/{tenantID}/app-control/admins
//   Replace the approved-admins list. Validates that every entry is a non-empty string.
//
// PUT /admin/tenants/{tenantID}/app-control/allowlist
//   Replace the app allowlist. Validates that every entry is a non-empty string.
//
// All three endpoints are on the internal Tailscale-bound listener (:8081).
// Auth: network-only (no application-layer auth, same posture as all /admin/* routes).

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

type appControlPolicy struct {
	TenantID          string   `json:"tenant_id"`
	AppControlEnabled bool     `json:"app_control_enabled"`
	ApprovedAdmins    []string `json:"approved_admins"`
	AppAllowlist      []string `json:"app_allowlist"`
}

// dbGetAppControlPolicy reads the app_control policy for tenantID.
// Returns (policy, found, err). found=false when the tenant row doesn't exist.
func dbGetAppControlPolicy(r *http.Request, pool *pgxpool.Pool, tenantID string) (appControlPolicy, bool, error) {
	var p appControlPolicy
	var adminsBytes, allowlistBytes []byte
	err := pool.QueryRow(r.Context(), `
		SELECT id::text,
		       app_control_enabled,
		       app_control_approved_admins,
		       app_control_app_allowlist
		FROM tenants
		WHERE id = $1::uuid
	`, tenantID).Scan(&p.TenantID, &p.AppControlEnabled, &adminsBytes, &allowlistBytes)
	if err != nil {
		if isNoRowsErr(err) {
			return appControlPolicy{}, false, nil
		}
		return appControlPolicy{}, false, err
	}
	if err := json.Unmarshal(adminsBytes, &p.ApprovedAdmins); err != nil {
		return appControlPolicy{}, false, fmt.Errorf("unmarshal approved_admins: %w", err)
	}
	if err := json.Unmarshal(allowlistBytes, &p.AppAllowlist); err != nil {
		return appControlPolicy{}, false, fmt.Errorf("unmarshal app_allowlist: %w", err)
	}
	if p.ApprovedAdmins == nil {
		p.ApprovedAdmins = []string{}
	}
	if p.AppAllowlist == nil {
		p.AppAllowlist = []string{}
	}
	return p, true, nil
}

// validateStringSlice returns an error if any element of ss is empty or if ss itself is nil.
// An empty slice (len 0) is valid — it means "clear the list".
func validateStringSlice(fieldName string, ss []string) error {
	for i, s := range ss {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s[%d] must not be empty", fieldName, i)
		}
	}
	return nil
}

// AppControlGetHandler returns the current app_control policy for a tenant.
//
// Route: GET /admin/tenants/{tenantID}/app-control
func AppControlGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "app_control_get", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		policy, found, err := dbGetAppControlPolicy(r, pool, tenantID)
		if err != nil {
			logger.Error("app_control policy read failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		logger.Info("app_control policy read")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy)
	}
}

// AppControlAdminsPutHandler replaces the approved-admins list for a tenant.
//
// Route: PUT /admin/tenants/{tenantID}/app-control/admins
func AppControlAdminsPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "app_control_admins_put", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var req struct {
			ApprovedAdmins []string `json:"approved_admins"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ApprovedAdmins == nil {
			req.ApprovedAdmins = []string{}
		}
		if err := validateStringSlice("approved_admins", req.ApprovedAdmins); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		adminsJSON, err := json.Marshal(req.ApprovedAdmins)
		if err != nil {
			logger.Error("marshal approved_admins failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE tenants
			SET app_control_approved_admins = $2::jsonb
			WHERE id = $1::uuid
		`, tenantID, adminsJSON)
		if err != nil {
			logger.Error("approved_admins update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		policy, _, err := dbGetAppControlPolicy(r, pool, tenantID)
		if err != nil {
			logger.Error("policy re-read after update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("approved_admins updated", "count", len(req.ApprovedAdmins))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy)
	}
}

// AppControlAllowlistPutHandler replaces the app allowlist for a tenant.
//
// Route: PUT /admin/tenants/{tenantID}/app-control/allowlist
func AppControlAllowlistPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "app_control_allowlist_put", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var req struct {
			AppAllowlist []string `json:"app_allowlist"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.AppAllowlist == nil {
			req.AppAllowlist = []string{}
		}
		if err := validateStringSlice("app_allowlist", req.AppAllowlist); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		allowlistJSON, err := json.Marshal(req.AppAllowlist)
		if err != nil {
			logger.Error("marshal app_allowlist failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE tenants
			SET app_control_app_allowlist = $2::jsonb
			WHERE id = $1::uuid
		`, tenantID, allowlistJSON)
		if err != nil {
			logger.Error("app_allowlist update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		policy, _, err := dbGetAppControlPolicy(r, pool, tenantID)
		if err != nil {
			logger.Error("policy re-read after update failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("app_allowlist updated", "count", len(req.AppAllowlist))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policy)
	}
}
