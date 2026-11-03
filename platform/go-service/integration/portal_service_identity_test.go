//go:build integration

// PAT-2257: the read-only service identity against a live Postgres. The unit
// half (verification, allowlist, method guard) is in
// internal/portalauth/service_test.go, and the every-write-route enumeration
// is in cmd/patched-api/portal_service_identity_test.go. This half proves the
// DB-backed parts: the service identity reads its configured tenant and no
// other, /me reports its fixed role, a write changes nothing, the audit trail
// names it by common name, and a revoked tenant shuts it out.
package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/portalauth"
)

const integrationServiceCN = "walker-integration.access" // placeholder

func TestPortalServiceIdentityIsReadOnlyAndTenantScoped(t *testing.T) {
	suffix := randomHex(4)
	a := seedPortalTenant(t, "svc-a-"+suffix, "alice-"+suffix+"@svc-a.example", "CVE-2099-7"+suffix[:3])
	b := seedPortalTenant(t, "svc-b-"+suffix, "bob-"+suffix+"@svc-b.example", "CVE-2099-8"+suffix[:3])

	v := portalauth.New(env.idp.issuer, env.idp.audience, env.idp.srv.URL).
		WithService(&portalauth.ServiceIdentity{CommonName: integrationServiceCN, TenantID: a.tenantID})
	r := chi.NewRouter()
	r.Route("/v1/portal", func(pr chi.Router) {
		pr.Use(portalauth.Middleware(v, portalauth.DBLookup(env.pool), nil, portalauth.DBAudit(env.pool),
			portalauth.WithServiceTenantCheck(portalauth.DBTenantLive(env.pool))))
		pr.Get("/devices", handlers.PortalDevicesHandler(env.pool))
		pr.Get("/devices/{deviceID}", handlers.PortalDeviceDetailHandler(env.pool))
		pr.Get("/me", handlers.PortalMeHandler(env.pool))
		pr.Put("/software-approvals", handlers.PortalSoftwareApprovalsPutHandler(env.pool))
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	token := env.idp.tokenWith(t, jwt.MapClaims{
		"iss": env.idp.issuer, "aud": env.idp.audience, "common_name": integrationServiceCN,
		"sub": "", "type": "app",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set(portalauth.Header, token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", b.tenantID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	t.Run("reads its configured tenant only", func(t *testing.T) {
		code, body := do(http.MethodGet, "/v1/portal/devices?tenant_id="+b.tenantID, "")
		if code != http.StatusOK {
			t.Fatalf("GET devices = %d %s", code, body)
		}
		if !strings.Contains(body, a.deviceID) {
			t.Errorf("tenant A's device missing from the service identity's roster")
		}
		if strings.Contains(body, b.deviceID) {
			t.Errorf("tenant B's device leaked to the service identity")
		}
		if code, _ := do(http.MethodGet, "/v1/portal/devices/"+b.deviceID, ""); code != http.StatusNotFound {
			t.Errorf("GET tenant B device = %d, want 404", code)
		}
		if code, _ := do(http.MethodGet, "/v1/portal/devices/"+a.deviceID, ""); code != http.StatusOK {
			t.Errorf("GET tenant A device = %d, want 200", code)
		}
	})

	t.Run("me reports the fixed read-only role", func(t *testing.T) {
		code, body := do(http.MethodGet, "/v1/portal/me", "")
		if code != http.StatusOK || !strings.Contains(body, `"role":"service_readonly"`) ||
			!strings.Contains(body, a.tenantID) {
			t.Fatalf("GET me = %d %s", code, body)
		}
	})

	t.Run("an approve write is refused and changes nothing", func(t *testing.T) {
		var before int
		if err := env.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM tenant_app_policies WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		code, body := do(http.MethodPut, "/v1/portal/software-approvals",
			`{"state":"approved","items":[{"type":"application","platform":"macos","identifier":"com.example.x","name":"X"}]}`)
		if code != http.StatusForbidden || !strings.Contains(body, "read-only") {
			t.Fatalf("PUT software-approvals = %d %s, want 403 read-only", code, body)
		}
		var after int
		if err := env.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM tenant_app_policies WHERE tenant_id = $1::uuid`, a.tenantID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != before {
			t.Errorf("policies changed %d -> %d", before, after)
		}
	})

	t.Run("audit rows name the service by common name", func(t *testing.T) {
		var n, refused int
		if err := env.pool.QueryRow(context.Background(), `
			SELECT count(*), count(*) FILTER (WHERE status = 403 AND method = 'PUT')
			FROM portal_access_log WHERE email = $1 AND tenant_id = $2::uuid`,
			"service:"+integrationServiceCN, a.tenantID).Scan(&n, &refused); err != nil {
			t.Fatal(err)
		}
		if n < 4 || refused != 1 {
			t.Errorf("audit rows = %d (refused writes %d), want >= 4 and 1", n, refused)
		}
		var personRows int
		if err := env.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM portal_access_log WHERE tenant_id = $1::uuid AND email = ''`,
			a.tenantID).Scan(&personRows); err != nil {
			t.Fatal(err)
		}
		if personRows != 0 {
			t.Errorf("%d audit rows recorded with an empty email", personRows)
		}
	})

	t.Run("a revoked tenant shuts the service identity out", func(t *testing.T) {
		if _, err := env.pool.Exec(context.Background(),
			`UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, a.tenantID); err != nil {
			t.Fatal(err)
		}
		if code, _ := do(http.MethodGet, "/v1/portal/devices", ""); code != http.StatusForbidden {
			t.Errorf("GET devices on a revoked tenant = %d, want 403", code)
		}
	})
}
