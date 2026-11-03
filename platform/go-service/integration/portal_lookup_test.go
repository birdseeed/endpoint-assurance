//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

func TestPortalRevokedExplicitTenantCannotRebindThroughDomain(t *testing.T) {
	for _, crossTenant := range []bool{false, true} {
		name := "same-tenant"
		if crossTenant {
			name = "cross-tenant"
		}
		t.Run(name, func(t *testing.T) {
			a, _, _, err := createTestTenant(env.internalSrv.URL, "revoked-explicit-"+randomHex(4))
			if err != nil {
				t.Fatal(err)
			}
			cleanupTestTenant(t, a)
			b := a
			if crossTenant {
				b, _, _, err = createTestTenant(env.internalSrv.URL, "revoked-domain-"+randomHex(4))
				if err != nil {
					t.Fatal(err)
				}
				cleanupTestTenant(t, b)
			}
			domain := "revoked-" + randomHex(4) + ".example"
			email := "admin@" + domain
			mapEmailDomain(t, domain, b, http.StatusCreated)
			mapPortalUserWithRole(t, email, a, "admin")
			token := env.idp.token(t, email)
			if _, err := env.pool.Exec(t.Context(), `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, a); err != nil {
				t.Fatal(err)
			}
			for _, route := range []string{"/v1/portal/me", "/v1/portal/devices"} {
				resp := portalDo(t, http.MethodGet, route, token, nil)
				resp.Body.Close()
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("revoked explicit tenant must deny %s: got %d", route, resp.StatusCode)
				}
			}
		})
	}
}

func TestPortalDBLookupPrecedenceAndFailures(t *testing.T) {
	// Private schema lets us exercise inconsistent domain data and query failures
	// without dropping production-schema constraints or changing other tests' data.
	schema := "portal_lookup_" + randomHex(8)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := env.pool.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.pool.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Copy actual column types, but omit uniqueness so ambiguity is testable.
	exec(`CREATE TABLE tenants AS SELECT id, revoked_at FROM public.tenants WITH NO DATA;
		CREATE TABLE portal_users AS SELECT email, tenant_id, disabled_at FROM public.portal_users WITH NO DATA;
		CREATE TABLE tenant_email_domains AS SELECT domain, tenant_id, disabled_at FROM public.tenant_email_domains WITH NO DATA`)
	const a = "00000000-0000-0000-0000-000000000001"
	const b = "00000000-0000-0000-0000-000000000002"
	for _, tc := range []struct {
		name, explicit, domain, want                            string
		disabled, revokedA, disabledDomain, revokedB, ambiguous bool
	}{
		{name: "enabled same tenant", explicit: a, domain: a, want: a},
		{name: "enabled cross tenant override", explicit: a, domain: b, want: a},
		{name: "disabled same tenant", explicit: a, domain: a, disabled: true},
		{name: "disabled cross tenant", explicit: a, domain: b, disabled: true},
		{name: "revoked explicit same tenant", explicit: a, domain: a, revokedA: true},
		{name: "revoked explicit cross tenant", explicit: a, domain: b, revokedA: true},
		{name: "absent explicit uses domain", domain: b, want: b},
		{name: "absent explicit and domain"},
		{name: "disabled domain", domain: b, disabledDomain: true},
		{name: "revoked domain tenant", domain: b, revokedB: true},
		{name: "ambiguous domain", domain: b, ambiguous: true},
		{name: "explicit overrides disabled domain", explicit: a, domain: b, disabledDomain: true, want: a},
		{name: "explicit overrides revoked domain", explicit: a, domain: b, revokedB: true, want: a},
		{name: "explicit overrides ambiguous domain", explicit: a, domain: b, ambiguous: true, want: a},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(`TRUNCATE tenants, portal_users, tenant_email_domains`)
			exec(`INSERT INTO tenants VALUES ($1::uuid, CASE WHEN $3 THEN now() END), ($2::uuid, CASE WHEN $4 THEN now() END)`, a, b, tc.revokedA, tc.revokedB)
			if tc.explicit != "" {
				exec(`INSERT INTO portal_users VALUES ('person@lookup.example', $1::uuid, CASE WHEN $2 THEN now() END)`, tc.explicit, tc.disabled)
			}
			if tc.domain != "" {
				exec(`INSERT INTO tenant_email_domains VALUES ('lookup.example', $1::uuid, CASE WHEN $2 THEN now() END)`, tc.domain, tc.disabledDomain)
			}
			if tc.ambiguous {
				exec(`INSERT INTO tenant_email_domains VALUES ('lookup.example', $1::uuid, NULL)`, a)
			}
			for _, email := range []string{"person@lookup.example", " \tPERSON@LOOKUP.EXAMPLE\n"} {
				got, err := portalauth.DBLookup(pool)(t.Context(), email)
				if got != tc.want || (tc.want == "" && !errors.Is(err, portalauth.ErrNoPortalUser)) || (tc.want != "" && err != nil) {
					t.Errorf("lookup(%q) = %q, %v; want %q (denied if empty)", email, got, err, tc.want)
				}
			}
		})
	}
	// A valid domain fallback is available, but a failed explicit query must
	// propagate its error rather than treat the row as absent and grant access.
	exec(`TRUNCATE portal_users, tenant_email_domains`)
	exec(`INSERT INTO tenant_email_domains VALUES ('lookup.example', $1::uuid, NULL)`, b)
	exec(`ALTER TABLE portal_users DROP COLUMN disabled_at`)
	got, err := portalauth.DBLookup(pool)(t.Context(), "person@lookup.example")
	if got != "" || err == nil || errors.Is(err, portalauth.ErrNoPortalUser) || !strings.Contains(err.Error(), "disabled_at") {
		t.Fatalf("failed explicit lookup = %q, %v; want database error and no tenant", got, err)
	}

	// Exercise the real failed lookup through middleware: it must neither grant
	// access nor mistake a database fault for an ordinary membership denial.
	verifier := portalauth.New(env.idp.issuer, env.idp.audience, env.idp.srv.URL)
	for _, route := range []string{"/v1/portal/me", "/v1/portal/devices"} {
		t.Run("database failure "+route, func(t *testing.T) {
			handlerCalled := false
			auditCalls, auditStatus := 0, 0
			var auditEmail, auditTenant string
			audit := func(email, tenantID, method, path string, status int) {
				auditCalls++
				auditEmail, auditTenant, auditStatus = email, tenantID, status
				if method != http.MethodGet || path != route {
					t.Errorf("audit request = %s %s; want GET %s", method, path, route)
				}
			}
			h := portalauth.Middleware(verifier, portalauth.DBLookup(pool), nil, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, route, nil)
			req.Header.Set(portalauth.Header, env.idp.token(t, "person@lookup.example"))
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != http.StatusInternalServerError {
				t.Errorf("database failure status = %d; want 500", response.Code)
			}
			if handlerCalled {
				t.Error("database failure reached protected handler")
			}
			if auditCalls != 1 || auditStatus != http.StatusInternalServerError || auditTenant != "" || auditEmail != "person@lookup.example" {
				t.Errorf("audit = calls %d, status %d, tenant %q, email %q; want one 500 with no tenant", auditCalls, auditStatus, auditTenant, auditEmail)
			}
			if response.Body.String() != "internal error\n" {
				t.Errorf("database failure response = %q; want generic internal error", response.Body.String())
			}
		})
	}
}
