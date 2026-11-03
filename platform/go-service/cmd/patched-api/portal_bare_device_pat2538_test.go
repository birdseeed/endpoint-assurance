package main

// PAT-2538: the route half of the guard that one device carrying only its
// required columns must never take a tenant's portal down. The report half is
// TestPortalSurvivesADeviceWithOnlyRequiredColumns in go-service/integration,
// which cannot reach this package's production router: its own router is a
// hand-kept copy that lacks routes such as /v1/portal/local-admins.
//
// A tenant holds two devices, one normal and one inserted with only the columns
// the schema requires (every nullable column NULL). Every GET route on the real
// /v1/portal router, enumerated with chi.Walk so a route added later is covered
// without editing this file, is then requested as a tenant admin, and the
// per-device routes are requested for both devices. Every request must answer
// below 500; all failures are reported together.
//
// Needs a migrated disposable TEST_DATABASE_URL and skips without one, like
// the PAT-2393 acceptance tests whose fixture it reuses.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/portalauth"
)

// pat2538RequiredDeviceColumns is the set of devices columns the schema forces
// a writer to supply (NOT NULL, no default). Determined from the migrations:
// 0001_initial.sql makes tenant_id NOT NULL and leaves serial, hostname,
// computer_name and the rest nullable; os was NOT NULL until
// 0039_nullable_os.sql dropped it; id, first_seen and last_seen have defaults.
// The test re-reads the set from information_schema and fails if it drifts.
var pat2538RequiredDeviceColumns = []string{"tenant_id"}

// pat2538SeedDevices inserts one normal device and one bare device for the
// fixture's tenant and returns their ids.
func pat2538SeedDevices(t *testing.T, f *declarationFixture) (normalID, bareID string) {
	t.Helper()
	pat2393Owner(t)

	rows, err := f.pool.Query(t.Context(), `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'devices'
		  AND is_nullable = 'NO' AND column_default IS NULL
		  AND is_generated = 'NEVER' AND is_identity = 'NO'
		ORDER BY column_name`)
	if err != nil {
		t.Fatal(err)
	}
	var required []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		required = append(required, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(required, pat2538RequiredDeviceColumns) {
		t.Fatalf("devices requires columns %v but the test supplies %v: supply the new required column and keep every nullable column NULL",
			required, pat2538RequiredDeviceColumns)
	}

	if err := f.pool.QueryRow(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.1', $4) RETURNING id::text`,
		f.tenant, "PAT2538-"+pat2393Random(), "normal-"+pat2393Random(), time.Now().UTC(),
	).Scan(&normalID); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(),
		`INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, f.tenant).Scan(&bareID); err != nil {
		t.Fatal(err)
	}

	var hostname, computerName, serial, osName *string
	if err := f.pool.QueryRow(t.Context(),
		`SELECT hostname, computer_name, serial, os FROM devices WHERE id = $1::uuid`, bareID,
	).Scan(&hostname, &computerName, &serial, &osName); err != nil {
		t.Fatal(err)
	}
	if hostname != nil || computerName != nil || serial != nil || osName != nil {
		t.Fatalf("bare device is not bare: hostname=%v computer_name=%v serial=%v os=%v", hostname, computerName, serial, osName)
	}
	children, err := os.ReadFile("../../testdata/bare-device-children.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), string(children), f.tenant, bareID); err != nil {
		t.Fatalf("seed bare child rows: %v", err)
	}
	t.Log("bare device child rows: application, compliance signal, Homebrew formula/state, npm tooling entry/state")
	return normalID, bareID
}

// pat2538GetRoutes lists every GET route under /v1/portal on the real router.
func pat2538GetRoutes(t *testing.T, r http.Handler) []string {
	t.Helper()
	routes, ok := r.(chi.Routes)
	if !ok {
		t.Fatal("public router is not a chi router")
	}
	var out []string
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet && strings.HasPrefix(route, "/v1/portal/") {
			out = append(out, route)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestPortalRoutesSurviveADeviceWithOnlyRequiredColumns(t *testing.T) {
	f := pat2393Fixture(t)
	normalID, bareID := pat2538SeedDevices(t, f)

	get := func(path string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set(portalauth.Header, f.admin)
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		return rr.Code, rr.Body.String()
	}

	// Prove the child joins returned the seeded evidence, rather than passing
	// because an OS filter silently omitted the NULL-OS device.
	for _, child := range []struct{ path, evidence string }{
		{"/v1/portal/applications", "Bare Fixture App"},
		{"/v1/portal/homebrew/devices/" + bareID, "bare-formula"},
		{"/v1/portal/ai-tooling/devices/" + bareID + "/items", "bare-package"},
	} {
		code, body := get(child.path)
		if code != http.StatusOK || !strings.Contains(body, child.evidence) {
			t.Errorf("child evidence %q missing from GET %s = %d: %s", child.evidence, child.path, code, body)
		} else {
			t.Logf("NULL hostname/OS child join returns %q through %s", child.evidence, child.path)
		}
	}

	// Report types for the {reportType} schedule route come from the catalogue
	// the API serves, not from a list kept here.
	code, body := get("/v1/portal/reports/catalogue")
	if code != http.StatusOK {
		t.Fatalf("GET catalogue = %d: %s", code, body)
	}
	var catalogue struct {
		Reports []struct {
			Type string `json:"type"`
		} `json:"reports"`
	}
	if err := json.Unmarshal([]byte(body), &catalogue); err != nil || len(catalogue.Reports) == 0 {
		t.Fatalf("decode catalogue: %v (%s)", err, body)
	}
	var reportTypes []string
	for _, r := range catalogue.Reports {
		reportTypes = append(reportTypes, r.Type)
	}

	routes := pat2538GetRoutes(t, f.router)
	// Guard the enumeration itself: if the walk silently found nothing, or lost
	// the routes that read device columns, the test would pass for the wrong
	// reason.
	have := map[string]bool{}
	for _, r := range routes {
		have[r] = true
	}
	for _, must := range []string{
		"/v1/portal/devices", "/v1/portal/devices/{deviceID}", "/v1/portal/local-admins",
		"/v1/portal/findings", "/v1/portal/software", "/v1/portal/overview",
	} {
		if !have[must] {
			t.Errorf("route walk did not find %s (enumeration broken?)", must)
		}
	}
	if len(routes) < 40 {
		t.Errorf("route walk found only %d GET routes under /v1/portal, expected the whole surface", len(routes))
	}

	type failure struct {
		path   string
		status int
		body   string
	}
	var failures []failure
	requests := 0
	request := func(path string) {
		requests++
		code, body := get(path)
		if code >= http.StatusInternalServerError {
			if len(body) > 300 {
				body = body[:300] + "..."
			}
			failures = append(failures, failure{path: path, status: code, body: strings.TrimSpace(body)})
		}
	}

	const unknownUUID = "00000000-0000-4000-8000-000000000001"
	for _, route := range routes {
		var paths []string
		switch {
		case strings.Contains(route, "{deviceID}"):
			// Per-device routes run once for each of the two devices.
			paths = []string{
				strings.ReplaceAll(route, "{deviceID}", normalID),
				strings.ReplaceAll(route, "{deviceID}", bareID),
			}
		case strings.Contains(route, "{reportType}"):
			for _, rt := range reportTypes {
				paths = append(paths, strings.ReplaceAll(route, "{reportType}", rt))
			}
		default:
			p := strings.NewReplacer(
				"{id}", "1", "{entryID}", "1", "{keyID}", unknownUUID,
				"{declarationID}", unknownUUID,
			).Replace(route)
			if strings.Contains(p, "{") {
				// A path parameter this test does not know how to fill: fail
				// rather than skip, so a new route is never silently uncovered.
				t.Errorf("route %s has a path parameter the walk cannot fill; teach pat2538 about it", route)
				continue
			}
			paths = []string{p}
		}
		for _, p := range paths {
			request(p)
		}
	}

	t.Logf("walked %d GET routes under /v1/portal, %d requests, devices normal=%s bare=%s", len(routes), requests, normalID, bareID)
	if len(failures) > 0 {
		lines := make([]string, len(failures))
		for i, fl := range failures {
			lines[i] = fmt.Sprintf("GET %s = %d: %s", fl.path, fl.status, fl.body)
		}
		t.Errorf("%d request(s) answered 5xx for a tenant holding a device with only the required columns:\n  %s",
			len(failures), strings.Join(lines, "\n  "))
	}
}
