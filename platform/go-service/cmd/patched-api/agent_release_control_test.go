package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Production wiring and auth are exercised before handler validation. A nil
// pool proves rejected credentials and malformed requests never reach the DB.
func TestAgentReleaseInternalRoutesRequireAdminToken(t *testing.T) {
	paths := []string{"/admin/agent-releases/evidence", "/admin/agent-releases/observations", "/admin/agent-releases/promote", "/admin/tenants/00000000-0000-0000-0000-000000002004/agent-releases/p0"}
	for _, path := range paths {
		for _, tc := range []struct {
			configured, credential string
			want                   int
		}{{"admin-token", "", 401}, {"admin-token", "wrong-token", 401}, {"admin-token", "publisher-token", 401}, {"", "admin-token", 503}, {"admin-token", "admin-token", 400}} {
			t.Run(path+"/"+tc.credential, func(t *testing.T) {
				router := newInternalRouter(nil, nil, 0, "", tc.configured, "", nil, "", nil)
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
				if tc.credential != "" {
					req.Header.Set("Authorization", "Bearer "+tc.credential)
				}
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, req)
				if rr.Code != tc.want {
					t.Fatalf("route %s status %d want %d: %s", path, rr.Code, tc.want, rr.Body.String())
				}
			})
		}
	}
}
