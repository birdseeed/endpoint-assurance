// Admin CRUD for portal_users (PAT-693) — the email → tenant mapping behind
// the customer portal. INTERNAL listener only, behind ADMIN_API_TOKEN.
package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

type portalUserEntry struct {
	Email      string     `json:"email"`
	TenantID   string     `json:"tenant_id"`
	TenantName string     `json:"tenant_name"`
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
}

// PortalUsersListHandler lists portal users, optionally filtered by tenant.
// Route: GET /admin/portal-users[?tenant_id=<uuid>]   (internal :8081)
func PortalUsersListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantFilter := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if tenantFilter != "" && !looksLikeUUID(tenantFilter) {
			http.Error(w, "tenant_id must be a UUID", http.StatusBadRequest)
			return
		}

		query := `
			SELECT pu.email, pu.tenant_id::text, t.name, pu.role, pu.created_at, pu.disabled_at
			FROM portal_users pu
			JOIN tenants t ON t.id = pu.tenant_id
		`
		args := []any{}
		if tenantFilter != "" {
			query += ` WHERE pu.tenant_id = $1::uuid`
			args = append(args, tenantFilter)
		}
		query += ` ORDER BY t.name, pu.email`

		rows, err := pool.Query(r.Context(), query, args...)
		if err != nil {
			slog.Error("list portal users failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []portalUserEntry{}
		for rows.Next() {
			var u portalUserEntry
			if err := rows.Scan(&u.Email, &u.TenantID, &u.TenantName, &u.Role, &u.CreatedAt, &u.DisabledAt); err != nil {
				slog.Error("scan portal user failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			users = append(users, u)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"users": users, "total": len(users)})
	}
}

// PortalUserCreateHandler creates (or re-enables) a portal user mapping.
// Re-POSTing an existing email re-enables it and moves it to the given
// tenant — idempotent by design so onboarding scripts can re-run. Re-enabling
// clears disabled_by with disabled_at, whoever disabled the row: the operator
// can undo an owner's disable, never the other way round (PAT-1883).
//
// role (PAT-2007) is optional: "owner", "admin" or "viewer". Omitted, a new
// row is a viewer, an existing row on the same tenant keeps its role, and an
// existing row moved to a different tenant drops to viewer (admin or owner on
// one tenant never carries over to another). "owner" (PAT-1883) is how an
// operator designates an owner for a tenant that was not created by
// self-service sign-up. The body is decoded strictly: an unknown key, a case
// variant of a real key or a duplicate key is a 400.
//
// ownerRoleEnabled is SELF_SERVICE_SIGNUP_ENABLED. While it is false a request
// that names the role "owner" is refused 400 and changes nothing, because the
// customer portal does not yet treat an owner as admin-level: making an
// existing admin an owner would take their write screens away. This gates
// only what the route will newly grant. A row that is already an owner is
// untouched, keeps its role on a re-post that names none, and is honoured by
// every portal route whatever the flag says.
// Route: POST /admin/portal-users {"email": ..., "tenant_id": ..., "role"?: ...}
func PortalUserCreateHandler(pool *pgxpool.Pool, ownerRoleEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<12+1))
		if err != nil || len(body) > 1<<12 {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var req struct {
			Email    string  `json:"email"`
			TenantID string  `json:"tenant_id"`
			Role     *string `json:"role"`
		}
		if err := decodeStrictJSON(body, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		email := strings.ToLower(strings.TrimSpace(req.Email))
		if _, err := mail.ParseAddress(email); err != nil || email == "" {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(strings.TrimSpace(req.TenantID)) {
			http.Error(w, "tenant_id must be a UUID", http.StatusBadRequest)
			return
		}
		if req.Role != nil && !portalauth.ValidRole(*req.Role) {
			msg := "role must be owner, admin or viewer"
			if !ownerRoleEnabled {
				msg = "role must be admin or viewer (owner needs self-service sign-up enabled)"
			}
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		if req.Role != nil && portalauth.IsOwner(*req.Role) && !ownerRoleEnabled {
			http.Error(w, "role owner needs self-service sign-up enabled (SELF_SERVICE_SIGNUP_ENABLED); use admin or viewer", http.StatusBadRequest)
			return
		}

		var u portalUserEntry
		err = pool.QueryRow(r.Context(), `
			INSERT INTO portal_users (email, tenant_id, role)
			VALUES ($1, $2::uuid, COALESCE($3::text, 'viewer'))
			ON CONFLICT (email) DO UPDATE
				SET tenant_id   = EXCLUDED.tenant_id,
				    disabled_at = NULL,
				    disabled_by = NULL,
				    role        = COALESCE($3::text,
				                    CASE WHEN portal_users.tenant_id = EXCLUDED.tenant_id
				                         THEN portal_users.role ELSE 'viewer' END)
			RETURNING email, tenant_id::text, role, created_at, disabled_at
		`, email, req.TenantID, req.Role).Scan(&u.Email, &u.TenantID, &u.Role, &u.CreatedAt, &u.DisabledAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK violation
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			slog.Error("create portal user failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("portal user upserted", "email", email, "tenant_id", req.TenantID, "role", u.Role)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(u)
	}
}

// PortalUserDisableHandler soft-disables a portal user (sets disabled_at).
// The row survives for audit-trail linkage; re-POSTing the email re-enables.
// It records the disable as the operator's (disabled_by, PAT-1883), also on
// a row an owner had already disabled, so that the tenant's owner cannot
// enable the member again through /v1/portal/access. The first disabled_at
// is kept.
// Route: DELETE /admin/portal-users/{email}
func PortalUserDisableHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "email")))
		if email == "" {
			http.Error(w, "missing email", http.StatusBadRequest)
			return
		}

		var disabledAt time.Time
		err := pool.QueryRow(r.Context(), `
			UPDATE portal_users
			SET disabled_at = COALESCE(disabled_at, NOW()),
			    disabled_by = $2
			WHERE email = $1
			RETURNING disabled_at
		`, email, disabledByOperator).Scan(&disabledAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "portal user not found", http.StatusNotFound)
				return
			}
			slog.Error("disable portal user failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("portal user disabled", "email", email)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"email": email, "disabled_at": disabledAt})
	}
}
