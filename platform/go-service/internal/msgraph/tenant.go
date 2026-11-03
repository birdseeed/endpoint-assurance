package msgraph

import (
	"fmt"
	"strings"
)

// TenantConfig identifies one customer tenant for Graph access. There is no
// secret field here by design: the whole integration authenticates with one
// certificate shared across every tenant (see Certificate), not a
// per-tenant credential. Adding a new tenant is exactly one TenantConfig
// value; nothing else needs to change.
type TenantConfig struct {
	// TenantID is the customer's Entra directory (tenant) id, used verbatim
	// in the token endpoint path.
	TenantID string
	// DisplayName is a human-readable label for logs and admin UI. Not sent
	// to Microsoft.
	DisplayName string
	// Enabled gates whether this tenant should be polled at all. Callers
	// (a later ticket's reconciliation job) are expected to skip disabled
	// tenants rather than this package refusing to serve a token for one —
	// the client stays a generic tool, and "should we poll this tenant" is
	// scheduling policy, not auth.
	Enabled bool
}

// Validate reports whether tc is well-formed enough to use. It does not
// check reachability or consent — those can only be discovered by calling
// Entra.
func (tc TenantConfig) Validate() error {
	return validateTenantID(tc.TenantID)
}

// validateTenantID is the single source of truth for what makes a tenant id
// safe to use, shared by TenantConfig.Validate() and TokenSource.Token() so
// the two paths can never drift into different error messages for the same
// invalid input. TenantID is used verbatim as a URL path segment in the
// token endpoint (see TokenSource.fetchToken) and isn't parsed or escaped
// there, so a value carrying a path separator, whitespace, or control
// character would silently reshape the request rather than fail loudly.
// Entra tenant ids are GUIDs or verified domain names in practice; neither
// ever contains these characters, so rejecting them costs nothing real.
func validateTenantID(id string) error {
	if id == "" {
		return fmt.Errorf("msgraph: tenant id required")
	}
	if strings.ContainsAny(id, "/\\?#") || strings.TrimSpace(id) != id {
		return fmt.Errorf("msgraph: tenant id %q contains characters not valid in a URL path segment", id)
	}
	return nil
}
