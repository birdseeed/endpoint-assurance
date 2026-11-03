package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServiceExceptionsProductionBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, configured, presented, method string
		want                                int
	}{
		{"missing token", "fixture-admin", "", "GET", 401},
		{"wrong token", "fixture-admin", "fixture-wrong", "GET", 401},
		{"unconfigured", "", "fixture-admin", "GET", 503},
		{"authenticated", "fixture-admin", "fixture-admin", "GET", 200},
		{"no mutation route", "fixture-admin", "fixture-admin", "POST", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := newInternalRouter(nil, nil, 0, "", tc.configured, "", nil, "", nil)
			req := httptest.NewRequest(tc.method, "/admin/service-exceptions", nil)
			if tc.presented != "" {
				req.Header.Set("Authorization", "Bearer "+tc.presented)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("got %d want %d", rr.Code, tc.want)
			}
		})
	}
	public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
	rr := httptest.NewRecorder()
	public.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/service-exceptions", nil))
	if rr.Code != 404 {
		t.Fatalf("public route exposed: %d", rr.Code)
	}
}
