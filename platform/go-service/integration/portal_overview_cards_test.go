//go:build integration

// PAT-2207: GET /v1/portal/overview/cards through the real router and the
// real portalauth.Middleware. The handler-level contract tests live in
// internal/handlers/portal_overview_cards_db_test.go; this file proves the
// route is mounted behind the same middleware as /v1/portal/overview and that
// the tenant comes only from the verified identity.
package integration

import (
	"net/http"
	"testing"
)

type overviewCardsResp struct {
	Cards map[string]struct {
		State  string         `json:"state"`
		Values map[string]any `json:"values"`
	} `json:"cards"`
}

func TestPortalOverviewCardsTenantScoped(t *testing.T) {
	a := seedPortalTenant(t, "portal-cards-a", "alice@cards-a.example", "CVE-2099-22071")
	b := seedPortalTenant(t, "portal-cards-b", "bob@cards-b.example", "CVE-2099-22072")
	// Tenant B gets a second device so the two tenants' counts differ.
	if _, err := env.pool.Exec(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-cards-b-2', gen_random_uuid(), 'host-cards-b-2', 'macOS', '15.5', '24F74', 'arm64', now())
	`, b.tenantID); err != nil {
		t.Fatalf("seed second device for B: %v", err)
	}

	for _, tc := range []struct {
		who       *portalTenant
		path      string
		wantTotal int
	}{
		{a, "/v1/portal/overview/cards", 1},
		{b, "/v1/portal/overview/cards", 2},
		// A client-supplied tenant is ignored: A still sees only A.
		{a, "/v1/portal/overview/cards?tenant_id=" + b.tenantID, 1},
	} {
		resp := portalDo(t, http.MethodGet, tc.path, tc.who.token, nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("%s as %s = %d, want 200", tc.path, tc.who.name, resp.StatusCode)
		}
		var out overviewCardsResp
		decodeJSON(t, resp, &out)
		devices, ok := out.Cards["devices"]
		if !ok {
			t.Fatalf("%s as %s: no devices card", tc.path, tc.who.name)
		}
		if got, _ := devices.Values["total"].(float64); int(got) != tc.wantTotal {
			t.Errorf("%s as %s: devices.total = %v, want %d", tc.path, tc.who.name, devices.Values["total"], tc.wantTotal)
		}
		if got, _ := out.Cards["browser_extensions"].Values["elevated"].(float64); got != 1 {
			t.Errorf("%s as %s: browser_extensions.elevated = %v, want 1 (own tenant's extension only)", tc.path, tc.who.name, out.Cards["browser_extensions"].Values["elevated"])
		}
	}

	t.Run("unauthenticated is refused", func(t *testing.T) {
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview/cards", "", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("no token = %d, want 401", resp.StatusCode)
		}
	})
}
