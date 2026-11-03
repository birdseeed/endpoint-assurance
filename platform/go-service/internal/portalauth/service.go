package portalauth

// PAT-2257: the read-only service identity.
//
// A Cloudflare Access service token's JWT carries `common_name` (the token's
// client id) and no `email`. The platform accepts one ONLY when it has passed
// exactly the same signature / issuer / audience / expiry validation as a
// person's token (Verifier.VerifyPrincipal) AND its common_name equals the
// configured PORTAL_SERVICE_TOKEN_COMMON_NAME. It then maps to a fixed
// identity:
//
//   - tenant: PORTAL_SERVICE_TOKEN_TENANT_ID only (tenant zero in prod), never
//     resolved through portal_users or tenant_email_domains, and refused if
//     that tenant is revoked;
//   - role: RoleServiceReadOnly. The middleware refuses every method other
//     than GET and HEAD for it before any handler runs, so no write handler,
//     current or future, can be reached by it. Reads behave like a viewer
//     (DBRole finds no portal_users row for it).
//
// Both env vars unset = the feature is off. Setting only one, or a tenant
// id that is not a UUID, is a configuration error the caller logs; the
// feature then stays off (fail closed) rather than taking the API down.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RoleServiceReadOnly is the service identity's role: a viewer for reads,
// and below viewer for writes (it can make none at all).
const RoleServiceReadOnly = "service_readonly"

// ServiceAuditPrefix marks portal_access_log rows written for the service
// identity, so the audit trail names it by common name and never records it
// as a person's email.
const ServiceAuditPrefix = "service:"

// ErrServiceNotConfigured is returned by a missing tenant check; the
// middleware treats the service identity as unauthorised in that case.
var ErrServiceNotConfigured = errors.New("service identity tenant check not configured")

// ErrServiceTenantInactive means the configured service tenant does not
// exist or is revoked.
var ErrServiceTenantInactive = errors.New("service identity tenant is not active")

// ServiceIdentity is the allowlisted service token and the single tenant it
// may read.
type ServiceIdentity struct {
	CommonName string
	TenantID   string
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ServiceIdentityFromEnv reads PORTAL_SERVICE_TOKEN_COMMON_NAME and
// PORTAL_SERVICE_TOKEN_TENANT_ID. (nil, nil) when both are unset.
func ServiceIdentityFromEnv() (*ServiceIdentity, error) {
	cn := strings.TrimSpace(os.Getenv("PORTAL_SERVICE_TOKEN_COMMON_NAME"))
	tenant := strings.ToLower(strings.TrimSpace(os.Getenv("PORTAL_SERVICE_TOKEN_TENANT_ID")))
	if cn == "" && tenant == "" {
		return nil, nil
	}
	if cn == "" || tenant == "" {
		return nil, errors.New("PORTAL_SERVICE_TOKEN_COMMON_NAME and PORTAL_SERVICE_TOKEN_TENANT_ID must both be set")
	}
	if !uuidRe.MatchString(tenant) {
		return nil, fmt.Errorf("PORTAL_SERVICE_TOKEN_TENANT_ID is not a UUID")
	}
	return &ServiceIdentity{CommonName: cn, TenantID: tenant}, nil
}

// WithService attaches the allowlisted service identity to the verifier and
// returns it. Call once at startup, before serving. nil turns it off.
func (v *Verifier) WithService(s *ServiceIdentity) *Verifier {
	if v != nil {
		v.service = s
	}
	return v
}

// serviceFor returns the configured service identity when commonName is
// exactly its common name (constant-time), else nil.
func (v *Verifier) serviceFor(commonName string) *ServiceIdentity {
	if v == nil || v.service == nil || commonName == "" || v.service.CommonName == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(commonName), []byte(v.service.CommonName)) != 1 {
		return nil
	}
	return v.service
}

// ServiceMethodAllowed reports whether the read-only service identity may
// use method. Only GET and HEAD: everything else is a write or unknown.
func ServiceMethodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// IsService reports whether id is the read-only service identity.
func (id Identity) IsService() bool { return id.Service != "" }

// AuditName is how this identity is recorded in audit and log lines: the
// verified email for a person, "service:<common name>" for the service
// identity.
func (id Identity) AuditName() string {
	if id.IsService() {
		return ServiceAuditPrefix + id.Service
	}
	return id.Email
}

// TenantCheckFunc confirms the service identity's configured tenant is live.
type TenantCheckFunc func(ctx context.Context, tenantID string) error

// DBTenantLive is the production TenantCheckFunc: the tenant must exist and
// not be revoked, the same condition DBLookup applies to a person.
func DBTenantLive(pool *pgxpool.Pool) TenantCheckFunc {
	return func(ctx context.Context, tenantID string) error {
		if pool == nil {
			return ErrServiceNotConfigured
		}
		var one int
		err := pool.QueryRow(ctx,
			`SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL`, tenantID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrServiceTenantInactive
		}
		return err
	}
}

// Option configures Middleware.
type Option func(*middlewareOptions)

type middlewareOptions struct {
	serviceTenantCheck TenantCheckFunc
}

// WithServiceTenantCheck supplies the tenant liveness check for the service
// identity. Without it the service identity is refused (fail closed).
func WithServiceTenantCheck(f TenantCheckFunc) Option {
	return func(o *middlewareOptions) { o.serviceTenantCheck = f }
}
