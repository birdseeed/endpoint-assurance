// Admin CRUD for tenant_email_domains (PAT-127) — the email-domain -> tenant
// auto-binding a customer portal SSO login resolves against when there is no
// explicit portal_users override (migration 0059). INTERNAL listener only,
// behind ADMIN_API_TOKEN.
//
// This is deliberately the same shape as portal_users.go (PAT-693): list,
// idempotent upsert-by-re-POST, soft-disable. Domains are stored lowercased;
// a domain can only be actively claimed by one tenant at a time (enforced by
// the partial unique index in migration 0075 — the DB is the source of
// truth for that invariant, this handler just surfaces a clean 409 instead
// of a raw constraint-violation error).
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type tenantEmailDomainEntry struct {
	Domain     string     `json:"domain"`
	TenantID   string     `json:"tenant_id"`
	TenantName string     `json:"tenant_name"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
}

// looksLikeDomain is a light sanity check, not a full RFC validation — this
// gate exists to reject obvious junk (emails pasted whole, empty strings,
// stray whitespace), not to be the authority on what a valid domain is.
func looksLikeDomain(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\n@/\\") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	return true
}

// TenantEmailDomainsListHandler lists registered domains, optionally
// filtered by tenant.
// Route: GET /admin/tenant-email-domains[?tenant_id=<uuid>]   (internal :8081)
func TenantEmailDomainsListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantFilter := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if tenantFilter != "" && !looksLikeUUID(tenantFilter) {
			http.Error(w, "tenant_id must be a UUID", http.StatusBadRequest)
			return
		}

		query := `
			SELECT ted.domain, ted.tenant_id::text, t.name, ted.created_at, ted.disabled_at
			FROM tenant_email_domains ted
			JOIN tenants t ON t.id = ted.tenant_id
		`
		args := []any{}
		if tenantFilter != "" {
			query += ` WHERE ted.tenant_id = $1::uuid`
			args = append(args, tenantFilter)
		}
		query += ` ORDER BY t.name, ted.domain`

		rows, err := pool.Query(r.Context(), query, args...)
		if err != nil {
			slog.Error("list tenant email domains failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		domains := []tenantEmailDomainEntry{}
		for rows.Next() {
			var d tenantEmailDomainEntry
			if err := rows.Scan(&d.Domain, &d.TenantID, &d.TenantName, &d.CreatedAt, &d.DisabledAt); err != nil {
				slog.Error("scan tenant email domain failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			domains = append(domains, d)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"domains": domains, "total": len(domains)})
	}
}

// TenantEmailDomainCreateHandler registers (or re-enables) a domain for a
// tenant. Re-POSTing an already-registered-elsewhere domain is rejected
// with 409 rather than silently reassigning it — moving a domain between
// tenants must be an explicit disable-then-create, not an accidental upsert,
// since it changes who a whole domain's users resolve to.
// Route: POST /admin/tenant-email-domains {"domain": ..., "tenant_id": ...}
func TenantEmailDomainCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<12))
		var req struct {
			Domain   string `json:"domain"`
			TenantID string `json:"tenant_id"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(req.Domain))
		if !looksLikeDomain(domain) {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}
		tenantID := strings.TrimSpace(req.TenantID)
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenant_id must be a UUID", http.StatusBadRequest)
			return
		}

		var d tenantEmailDomainEntry
		err := pool.QueryRow(r.Context(), `
			INSERT INTO tenant_email_domains (domain, tenant_id)
			VALUES ($1, $2::uuid)
			ON CONFLICT (domain) WHERE disabled_at IS NULL
				DO UPDATE SET domain = EXCLUDED.domain
				WHERE tenant_email_domains.tenant_id = EXCLUDED.tenant_id
			RETURNING domain, tenant_id::text, created_at, disabled_at
		`, domain, tenantID).Scan(&d.Domain, &d.TenantID, &d.CreatedAt, &d.DisabledAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK violation
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, pgx.ErrNoRows) {
				// The ON CONFLICT ... DO UPDATE ... WHERE matched zero rows:
				// the domain is already actively claimed by a DIFFERENT
				// tenant. Refuse rather than silently reassigning it.
				http.Error(w, "domain already registered to another tenant", http.StatusConflict)
				return
			}
			slog.Error("create tenant email domain failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("tenant email domain registered", "domain", domain, "tenant_id", tenantID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(d)
	}
}

// TenantEmailDomainDisableHandler soft-disables a domain mapping. The row
// survives (audit trail); re-POSTing the domain (to the same or a different
// tenant) re-registers it.
// Route: DELETE /admin/tenant-email-domains/{domain}
func TenantEmailDomainDisableHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "domain")))
		if domain == "" {
			http.Error(w, "missing domain", http.StatusBadRequest)
			return
		}

		var disabledAt time.Time
		err := pool.QueryRow(r.Context(), `
			UPDATE tenant_email_domains
			SET disabled_at = COALESCE(disabled_at, NOW())
			WHERE domain = $1 AND disabled_at IS NULL
			RETURNING disabled_at
		`, domain).Scan(&disabledAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "tenant email domain not found (or already disabled)", http.StatusNotFound)
				return
			}
			slog.Error("disable tenant email domain failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("tenant email domain disabled", "domain", domain)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "disabled_at": disabledAt})
	}
}
