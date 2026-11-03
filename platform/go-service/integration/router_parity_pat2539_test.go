//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
)

// Compare runtime route sets, so changes to grouping, HTTP methods, or mounted
// routes cannot hide behind an AST/source-text comparison of the constructors.
func TestPAT2539IntegrationRoutesMatchProduction(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "production-routes.json")
	cmd := exec.CommandContext(t.Context(), "go", "test", "-p=1", "-count=1", "./cmd/patched-api", "-run", "^TestPAT2539ProductionRouteManifest$")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "PAT2539_ROUTE_MANIFEST="+manifest)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production route enumeration: %v\n%s", err, output)
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var production []string
	if err := json.Unmarshal(data, &production); err != nil {
		t.Fatal(err)
	}
	limiter := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	router := buildPublicRouter(nil, nil, limiter, 5*time.Minute, portalauth.New("https://fixture.invalid", "fixture", "https://fixture.invalid"), limiter)
	var integration []string
	if err := chi.Walk(router.(chi.Routes), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		integration = append(integration, method+" "+path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(integration)
	p, i := map[string]bool{}, map[string]bool{}
	for _, route := range production {
		p[route] = true
	}
	for _, route := range integration {
		i[route] = true
	}
	if len(production) < 50 || len(integration) < 50 {
		t.Fatal("route enumeration did not cover the full public surface")
	}
	for _, route := range production {
		if !i[route] {
			t.Errorf("missing from integration: %s", route)
		}
	}
	for _, route := range integration {
		if !p[route] {
			t.Errorf("integration-only: %s", route)
		}
	}
	t.Logf("production routes=%d integration routes=%d", len(production), len(integration))
}
