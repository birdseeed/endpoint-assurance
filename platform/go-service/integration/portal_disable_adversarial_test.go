//go:build integration

package integration

import (
	"io"
	"net/http"
	"testing"
)

// PAT-2379: an explicit disable must deny access even with a matching domain.
// This originally opt-in reproducer is now part of ordinary integration coverage.
func TestPAT2367DisabledUserCannotRebindThroughDomain(t *testing.T) {
	for _, crossTenant := range []bool{false, true} {
		name := "same-tenant"
		if crossTenant {
			name = "cross-tenant"
		}
		t.Run(name, func(t *testing.T) {
			a, _, _, err := createTestTenant(env.internalSrv.URL, "disable-a-"+randomHex(4))
			if err != nil {
				t.Fatal(err)
			}
			cleanupTestTenant(t, a)
			domainTenant := a
			if crossTenant {
				b, _, _, err := createTestTenant(env.internalSrv.URL, "disable-b-"+randomHex(4))
				if err != nil {
					t.Fatal(err)
				}
				cleanupTestTenant(t, b)
				domainTenant = b
			}
			domain := "disable-" + randomHex(4) + ".example"
			email := "former-admin@" + domain
			marker := "private-device-" + randomHex(4)
			if _, err := env.pool.Exec(t.Context(), `
				INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
				VALUES ($1::uuid, $2, gen_random_uuid(), $2, 'macOS', '15.5', '24F74', 'arm64', now())
			`, domainTenant, marker); err != nil {
				t.Fatal(err)
			}
			mapEmailDomain(t, domain, domainTenant, http.StatusCreated)
			mapPortalUserWithRole(t, email, a, "admin")
			token := env.idp.token(t, email)
			before := portalDo(t, http.MethodGet, "/v1/portal/me", token, nil)
			if before.StatusCode != http.StatusOK {
				before.Body.Close()
				t.Fatalf("precondition: %d", before.StatusCode)
			}
			var identity map[string]string
			decodeJSON(t, before, &identity)
			if identity["tenant_id"] != a || identity["role"] != "admin" {
				t.Fatalf("precondition identity: %v", identity)
			}
			disablePortalUser(t, email)
			for _, route := range []string{"/v1/portal/me", "/v1/portal/devices"} {
				resp := portalDo(t, http.MethodGet, route, token, nil)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("disabled explicit mapping must deny %s: got %d %s; domain tenant=%s", route, resp.StatusCode, body, domainTenant)
				}
			}
		})
	}
}
