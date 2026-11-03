package main

// Overlay test: dumps the mounted route inventory of the real public and
// internal routers (the shipping constructors) as JSON for the harness.

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestIBRouteInventory(t *testing.T) {
	out := os.Getenv("IB_ROUTES_OUT")
	if out == "" {
		t.Skip("IB_ROUTES_OUT not set")
	}
	public := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
	internal := newInternalRouter(nil, nil, 0, "", "synthetic-admin", "", nil, "", nil)
	type route struct {
		Surface string `json:"surface"`
		Method  string `json:"method"`
		Path    string `json:"path"`
	}
	var routes []route
	for _, s := range []struct {
		name string
		r    http.Handler
	}{{"public", public}, {"internal", internal}} {
		err := chi.Walk(s.r.(chi.Routes), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			routes = append(routes, route{s.name, method, path})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	b, _ := json.MarshalIndent(routes, "", " ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d routes", len(routes))
}
