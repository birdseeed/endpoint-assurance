package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Walk the actual shipping constructors, not integration's copied router.
// A newly mounted route inherits these credential-denial checks automatically.
// No authorised request reaches a handler or database in this sweep.
func TestTenantReadinessEveryRouteAuthBoundary(t *testing.T) {
	v, _ := serviceTestVerifier(t)
	public := newPublicRouter(nil, nil, nil, 0, v, nil, nil, "", "", nil, nil, "", nil, "", nil)
	publicOff := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
	internal := newInternalRouter(nil, nil, 0, "", "synthetic-admin", "", nil, "", nil)
	internalOff := newInternalRouter(nil, nil, 0, "", "", "", nil, "", nil)
	parameter := regexp.MustCompile(`\{[^}]+\}`)
	for _, surface := range []struct {
		name        string
		router, off http.Handler
	}{
		{"public", public, publicOff}, {"internal", internal, internalOff},
	} {
		count := 0
		err := chi.Walk(surface.router.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if surface.name == "public" && !strings.HasPrefix(route, "/v1/portal/") {
				return nil
			}
			if route == "/health" || route == "/metrics" {
				return nil
			}
			count++
			t.Logf("inventory %s %s %s", surface.name, method, route)
			path := parameter.ReplaceAllString(route, "00000000-0000-4000-8000-000000000001")
			for _, credential := range []string{"", "synthetic-invalid"} {
				req := httptest.NewRequest(method, path, strings.NewReader(`{"tenant_id":"hostile"}`))
				if surface.name == "public" {
					req.Header.Set("Cf-Access-Jwt-Assertion", credential)
				} else {
					req.Header.Set("Authorization", "Bearer "+credential)
				}
				rr := httptest.NewRecorder()
				surface.router.ServeHTTP(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Errorf("%s %s %s unauthorised credential: %d, want 401", surface.name, method, route, rr.Code)
				}
			}
			rr := httptest.NewRecorder()
			surface.off.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s %s unconfigured auth: %d, want 503", surface.name, method, route, rr.Code)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("empty %s route inventory", surface.name)
		}
		t.Logf("audited %d %s mounted credential boundaries", count, surface.name)
	}
}
