package portalauth

// PAT-1883: the pre-membership route group (/v1/portal/signup).
//
// Every other /v1/portal route requires the verified email to resolve to a
// tenant (Middleware, DBLookup). A person creating their first organisation,
// or accepting an invitation, has no tenant yet, so those few routes sit
// behind SignupMiddleware instead. It applies exactly the same Cloudflare
// Access JWT verification and the same per-email rate limit, and then stops:
// it resolves no tenant.
//
// What it puts in the request context is an Applicant, a different type under
// a different context key from Identity. That is deliberate. Every
// tenant-scoped handler reads Identity (FromContext) and fails closed when it
// is absent, so a tenant handler mounted in this group by mistake answers 401
// rather than serving someone who belongs to no tenant. The reverse holds
// too: a sign-up handler reads only the Applicant and never a tenant id.

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"patched.im/api/internal/ratelimit"
)

// Applicant is a person whose Cloudflare Access JWT verified, with no claim
// about tenant membership. Email is the verified, lower-cased address and is
// the only identity a sign-up handler may act on: nothing in a request body,
// query or other header names the caller.
type Applicant struct {
	Email string
}

type applicantKey struct{}

// ApplicantFromContext returns the Applicant placed by SignupMiddleware.
func ApplicantFromContext(ctx context.Context) (Applicant, bool) {
	a, ok := ctx.Value(applicantKey{}).(Applicant)
	return a, ok && a.Email != ""
}

// WithApplicant returns a context carrying the given applicant. Exported for
// handler tests; production code only ever goes through SignupMiddleware.
func WithApplicant(ctx context.Context, a Applicant) context.Context {
	return context.WithValue(ctx, applicantKey{}, a)
}

// SignupMiddleware authenticates the pre-membership routes:
//
//	verifier nil (env unset)        → 503 fail closed
//	missing/invalid/expired JWT     → 401
//	service identity (no email)     → 403, never served
//	per-identity rate exceeded      → 429 + Retry-After
//
// On success the Applicant is placed in the request context. Every outcome
// past JWT verification is audit-logged with no tenant (portal_access_log
// tenant_id NULL): the caller is not acting as a member of any tenant here.
//
// rl is the same limiter instance the rest of /v1/portal uses, keyed by the
// same verified email, so the two groups share one budget per person.
func SignupMiddleware(v *Verifier, rl *ratelimit.TenantLimiter, audit AuditFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v == nil {
				http.Error(w, "portal API not configured", http.StatusServiceUnavailable)
				return
			}
			principal, err := v.VerifyPrincipal(r.Header.Get(Header))
			if err != nil {
				// Not audit-logged, as in Middleware: an unverified caller has
				// no identity to attribute.
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if principal.Email == "" {
				refuseServiceSignup(w, r, v, principal.CommonName, audit)
				return
			}
			email := principal.Email

			if rl != nil {
				if ok, retryAfter := rl.Allow(email); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
					http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
					return
				}
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r.WithContext(WithApplicant(r.Context(), Applicant{Email: email})))

			if audit != nil {
				route := r.URL.Path
				if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
					route = rc.RoutePattern()
				}
				audit(email, "", r.Method, route, ww.Status())
			}
		})
	}
}

// refuseServiceSignup handles a verified email-less (service-token) JWT on
// the pre-membership routes. An unallowlisted common name is 401, exactly as
// in Middleware. The allowlisted read-only service identity is refused every
// method: it is fixed to one tenant and has no email, so it can neither
// create an organisation nor hold an invitation. A write gets the same
// "read-only" refusal the central guard gives on every other portal write.
func refuseServiceSignup(w http.ResponseWriter, r *http.Request, v *Verifier, commonName string, audit AuditFunc) {
	svc := v.serviceFor(commonName)
	if svc == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := ServiceAuditPrefix + svc.CommonName
	msg := "forbidden: sign-up needs a person's verified email"
	if !ServiceMethodAllowed(r.Method) {
		msg = "forbidden: the service identity is read-only"
	}
	slog.Warn("portal service identity refused on a sign-up route",
		"identity", name, "method", r.Method, "path", r.URL.Path)
	if audit != nil {
		audit(name, "", r.Method, r.URL.Path, http.StatusForbidden)
	}
	http.Error(w, msg, http.StatusForbidden)
}
