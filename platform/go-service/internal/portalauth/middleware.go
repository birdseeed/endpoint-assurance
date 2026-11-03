package portalauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/ratelimit"
)

// Header carries the Cloudflare Access identity JWT. Set by CF Access when it
// fronts the route directly, and forwarded verbatim by the portal server.
const Header = "Cf-Access-Jwt-Assertion"

// Identity is the authenticated portal caller. TenantID comes exclusively
// from the portal_users mapping — handlers must scope every query with it and
// must never accept a tenant identifier from the client.
//
// Service is set (to the allowlisted common name) only for the read-only
// service identity (PAT-2257); Email is then empty. See service.go.
type Identity struct {
	Email    string
	TenantID string
	Service  string
}

type ctxKey struct{}

// FromContext returns the authenticated Identity placed by Middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// WithIdentity returns a context carrying the given identity. Exported for
// handler tests; production code only ever goes through Middleware.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// ErrNoPortalUser means the JWT verified fine but the email has no active
// portal_users mapping. Maps to 403 (authenticated, not authorised).
var ErrNoPortalUser = errors.New("no active portal user for email")

// LookupFunc resolves a verified email to a tenant ID. Implementations must
// return ErrNoPortalUser when the email is unmapped or disabled.
type LookupFunc func(ctx context.Context, email string) (tenantID string, err error)

// DBLookup is the production LookupFunc. Resolution order (PAT-127):
//
//  1. portal_users — an explicit email -> tenant mapping. This is the
//     manual-override path: it always wins over domain matching, which is
//     how a cross-domain edge case (e.g. a consultant using a shared admin
//     email that doesn't belong to any one tenant's domain) gets handled —
//     add one override row, independent of the email's domain.
//  2. tenant_email_domains — falls back to the tenant that has registered
//     the email's domain (migration 0075), so an SSO login from a domain a
//     tenant has claimed resolves without needing a per-user portal_users
//     row first. A domain claimed by more than one active tenant (should be
//     prevented at write time by a partial unique index, but checked here
//     too — defence in depth against any DB-level inconsistency) never
//     resolves; that is a misconfiguration to fix, not silently arbitrated.
//
// An explicit row is authoritative even when disabled or its tenant is revoked:
// deny access, never retry through the domain. Only an absent row permits fallback.
// Domain matching excludes disabled rows and revoked tenants.
func DBLookup(pool *pgxpool.Pool) LookupFunc {
	return func(ctx context.Context, email string) (string, error) {
		email = strings.ToLower(strings.TrimSpace(email))

		var tenantID string
		var active bool
		err := pool.QueryRow(ctx, `
			SELECT pu.tenant_id::text,
			       pu.disabled_at IS NULL AND t.revoked_at IS NULL
			FROM portal_users pu
			JOIN tenants t ON t.id = pu.tenant_id
			WHERE pu.email = $1
		`, email).Scan(&tenantID, &active)
		if err == nil {
			if !active {
				return "", ErrNoPortalUser
			}
			return tenantID, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}

		domain := emailDomain(email)
		if domain == "" {
			return "", ErrNoPortalUser
		}

		rows, err := pool.Query(ctx, `
			SELECT ted.tenant_id::text
			FROM tenant_email_domains ted
			JOIN tenants t ON t.id = ted.tenant_id
			WHERE ted.domain = $1
			  AND ted.disabled_at IS NULL
			  AND t.revoked_at IS NULL
		`, domain)
		if err != nil {
			return "", err
		}
		defer rows.Close()

		var matches []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return "", err
			}
			matches = append(matches, id)
		}
		if err := rows.Err(); err != nil {
			return "", err
		}
		if len(matches) != 1 {
			if len(matches) > 1 {
				slog.Warn("ambiguous tenant email domain match — refusing to resolve",
					"domain", domain, "candidates", len(matches))
			}
			return "", ErrNoPortalUser
		}
		return matches[0], nil
	}
}

// emailDomain returns the part of email after the last "@", or "" if the
// address has no domain part (defensive — the JWT verifier already requires
// a non-empty email claim, but this function must never panic on garbage).
func emailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// AuditFunc records one portal request outcome. tenantID is empty when the
// identity didn't resolve to a tenant.
type AuditFunc func(email, tenantID, method, route string, status int)

// DBAudit is the production AuditFunc: best-effort insert into
// portal_access_log. Uses its own timeout context (not the request's, which
// is already done by the time the response status is known); failures are
// logged, never surfaced — audit must not take the read path down.
func DBAudit(pool *pgxpool.Pool) AuditFunc {
	if pool == nil {
		return nil
	}
	return func(email, tenantID, method, route string, status int) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var tenantArg any
		if tenantID != "" {
			tenantArg = tenantID
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO portal_access_log (email, tenant_id, method, route, status)
			VALUES ($1, $2, $3, $4, $5)
		`, email, tenantArg, method, route, status); err != nil {
			slog.Error("portal audit insert failed", "err", err, "email", email)
		}
	}
}

// Middleware authenticates every request on the portal surface:
//
//	verifier nil (env unset)      → 503 fail closed
//	missing/invalid/expired JWT   → 401
//	verified but unmapped email   → 403
//	per-identity rate exceeded    → 429 + Retry-After
//
// On success the Identity is placed in the request context, and the outcome
// (including denials past JWT verification) is audit-logged.
func Middleware(v *Verifier, lookup LookupFunc, rl *ratelimit.TenantLimiter, audit AuditFunc, opts ...Option) func(http.Handler) http.Handler {
	var o middlewareOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v == nil {
				http.Error(w, "portal API not configured", http.StatusServiceUnavailable)
				return
			}

			principal, err := v.VerifyPrincipal(r.Header.Get(Header))
			if err != nil {
				// Not audit-logged: unverified callers have no trustworthy
				// identity to attribute, and logging them would let anyone
				// spam the audit table.
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if principal.Email == "" {
				serveService(w, r, next, v, principal.CommonName, rl, audit, o)
				return
			}
			email := principal.Email

			// Per-identity rate limit, before any DB work.
			if rl != nil {
				if ok, retryAfter := rl.Allow(email); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
					http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
					return
				}
			}

			tenantID, err := lookup(r.Context(), email)
			if err != nil {
				status := http.StatusInternalServerError
				msg := "internal error"
				if errors.Is(err, ErrNoPortalUser) {
					status = http.StatusForbidden
					msg = "forbidden"
				} else {
					slog.Error("portal user lookup failed", "err", err)
				}
				if audit != nil {
					audit(email, "", r.Method, r.URL.Path, status)
				}
				http.Error(w, msg, status)
				return
			}

			serveIdentity(w, r, next, Identity{Email: email, TenantID: tenantID}, audit)
		})
	}
}

// serveService handles a verified email-less (service-token) JWT (PAT-2257).
// An unallowlisted common name is 401 exactly as an email-less token always
// was. The allowlisted one is refused every non-GET/HEAD method here, before
// rate limiting, DB work or any handler: this is the single write guard for
// the service identity, so no write handler has to remember it.
func serveService(w http.ResponseWriter, r *http.Request, next http.Handler, v *Verifier,
	commonName string, rl *ratelimit.TenantLimiter, audit AuditFunc, o middlewareOptions) {
	svc := v.serviceFor(commonName)
	if svc == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := ServiceAuditPrefix + svc.CommonName
	if !ServiceMethodAllowed(r.Method) {
		slog.Warn("portal service identity write refused",
			"identity", name, "method", r.Method, "path", r.URL.Path)
		if audit != nil {
			audit(name, svc.TenantID, r.Method, r.URL.Path, http.StatusForbidden)
		}
		http.Error(w, "forbidden: the service identity is read-only", http.StatusForbidden)
		return
	}
	if rl != nil {
		if ok, retryAfter := rl.Allow(name); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}
	check := o.serviceTenantCheck
	if check == nil {
		slog.Error("portal service identity refused: no tenant check configured", "identity", name)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := check(r.Context(), svc.TenantID); err != nil {
		status := http.StatusInternalServerError
		msg := "internal error"
		if errors.Is(err, ErrServiceTenantInactive) || errors.Is(err, ErrServiceNotConfigured) {
			status, msg = http.StatusForbidden, "forbidden"
		}
		slog.Error("portal service identity tenant check failed", "identity", name, "err", err)
		if audit != nil {
			audit(name, "", r.Method, r.URL.Path, status)
		}
		http.Error(w, msg, status)
		return
	}
	serveIdentity(w, r, next, Identity{TenantID: svc.TenantID, Service: svc.CommonName}, audit)
}

// serveIdentity runs next with id in the context and audit-logs the outcome.
func serveIdentity(w http.ResponseWriter, r *http.Request, next http.Handler, id Identity, audit AuditFunc) {
	ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
	next.ServeHTTP(ww, r.WithContext(WithIdentity(r.Context(), id)))

	if audit != nil {
		route := r.URL.Path
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		audit(id.AuditName(), id.TenantID, r.Method, route, ww.Status())
	}
}
