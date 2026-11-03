// Package msgraph is a read-only Microsoft Graph client for MDM coverage
// reconciliation (PAT-1653, foundation ticket for a new integration area).
//
// The model is one multi-tenant Entra app registration, authenticated with a
// single certificate owned by Patched, used against N customer tenants. Only
// the tenant id varies per customer:
//
//	POST https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token
//	  grant_type=client_credentials
//	  client_id={our single app id}
//	  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//	  client_assertion={signed JWT, our certificate}
//	  scope=https://graph.microsoft.com/.default
//
// There is deliberately no per-tenant secret anywhere in this package. A
// per-tenant credential store was removed from this codebase in PAT-572
// ("Configured-Clients"); TenantConfig must never grow a secret field, and
// Certificate is a single value shared across every tenant, not stored
// per-tenant.
//
// This package builds the client only: token acquisition, caching, and a
// generic paged request helper. It does not call any Graph resource
// endpoint (no /devices, no /managedDevices) — that is endpoint-specific
// logic for a later ticket.
package msgraph

import (
	"context"
	"time"
)

// contextSleep waits for d, returning early with ctx.Err() if ctx is
// cancelled first. Used by both the token endpoint and the Graph request
// helper to respect Retry-After without blocking shutdown.
func contextSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
