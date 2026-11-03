package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// taWithTenantID injects a chi tenantID URL param into the request context.
func taWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestTenantAppCatalogMatchRequiresProductNameBeforeSigner(t *testing.T) {
	sharedSigner := "UBF8T346G9"
	catalog := tenantAppCatalogEntry{
		label:          "microsoftword",
		name:           "Microsoft Word",
		platform:       "macOS",
		verifiedSigner: &sharedSigner,
		latestVersion:  "16.86",
	}

	word := tenantAppInstalledDevice{name: "Microsoft Word", teamID: sharedSigner}
	if !tenantAppCatalogMatches("com.microsoft.Word", word, catalog) {
		t.Fatal("matching product name and signer should match")
	}

	edge := tenantAppInstalledDevice{name: "Microsoft Edge", teamID: sharedSigner}
	if tenantAppCatalogMatches("com.microsoft.edgemac", edge, catalog) {
		t.Fatal("shared signer must not cross-match unrelated products")
	}

	unsignedCatalog := catalog
	unsignedCatalog.verifiedSigner = nil
	if tenantAppCatalogMatches("com.microsoft.Word", tenantAppInstalledDevice{name: "Word"}, unsignedCatalog) == false {
		t.Fatal("non-empty product substring match in either direction should match when catalog signer is null")
	}

	if tenantAppCatalogMatches("com.microsoft.Word", tenantAppInstalledDevice{name: "", teamID: sharedSigner}, catalog) {
		t.Fatal("empty installed product name must never match by signer alone")
	}
}

func TestTenantAppHelpersAndSubAppsNeverMatchCatalogue(t *testing.T) {
	mozilla := "43AQ936H96"
	zoomSigner := "BJ4HAAB9B3"
	cases := []struct {
		name       string
		identifier string
		signer     string
		catalog    tenantAppCatalogEntry
	}{
		{"Firefox Crash Reporter", "org.mozilla.crashreporter", mozilla, tenantAppCatalogEntry{name: "Firefox", verifiedSigner: &mozilla}},
		{"Firefox Updater", "org.mozilla.updater", mozilla, tenantAppCatalogEntry{name: "Firefox", verifiedSigner: &mozilla}},
		{"Zoom", "us.zoom.xos.ZoomAutoUpdater", zoomSigner, tenantAppCatalogEntry{name: "Zoom", verifiedSigner: &zoomSigner}},
		{"Zoom", "us.zoom.xos.ZoomAirHost", zoomSigner, tenantAppCatalogEntry{name: "Zoom", verifiedSigner: &zoomSigner}},
		{"Zoom", "us.zoom.xos.CptHost", zoomSigner, tenantAppCatalogEntry{name: "Zoom", verifiedSigner: &zoomSigner}},
	}
	for _, tc := range cases {
		t.Run(tc.identifier, func(t *testing.T) {
			installed := tenantAppInstalledDevice{name: tc.name, teamID: tc.signer}
			if tenantAppCatalogMatches(tc.identifier, installed, tc.catalog) {
				t.Fatal("helper/sub-app must not become catalogued or actionable")
			}
		})
	}
}

func TestTenantAppTruthfulEvidenceStates(t *testing.T) {
	if got := tenantAppDeviceState("", "2.0", true); got != tenantAppStateEvidenceUnavailable {
		t.Fatalf("unknown installed version: got %q", got)
	}
	if got := tenantAppDeviceState("1.0", "2.0", true); got != tenantAppStateUpdateAvailable {
		t.Fatalf("known mismatch: got %q", got)
	}
	if got := tenantAppDeviceState("2.0", "2.0", true); got != tenantAppStateCurrent {
		t.Fatalf("matching known version: got %q", got)
	}
	if got := tenantAppDeviceState("150.0.7871.187", "126.0.6478.127", true); got != tenantAppStateCurrent {
		t.Fatalf("newer installed version must not be offered a backwards update: got %q", got)
	}
	if got := tenantAppDeviceState("126.0.6478.127", "150.0.7871.187", true); got != tenantAppStateUpdateAvailable {
		t.Fatalf("older installed version must remain a verified update: got %q", got)
	}
	if got := tenantAppDeviceState("1.0", "", false); got != tenantAppStateNotCatalogued {
		t.Fatalf("no catalog match: got %q", got)
	}

	mixed := []tenantAppDeviceEntry{
		{UpdateState: tenantAppStateCurrent},
		{UpdateState: tenantAppStateEvidenceUnavailable},
	}
	if got := tenantAppEvidenceState(mixed, true); got != tenantAppStateEvidenceUnavailable {
		t.Fatalf("incomplete aggregate evidence: got %q", got)
	}
	mixed = append(mixed, tenantAppDeviceEntry{UpdateState: tenantAppStateUpdateAvailable})
	if got := tenantAppEvidenceState(mixed, true); got != tenantAppStateUpdateAvailable {
		t.Fatalf("confirmed mismatch must win aggregate state: got %q", got)
	}
	if got := tenantAppEvidenceState([]tenantAppDeviceEntry{{UpdateState: tenantAppStateCurrent}, {UpdateState: tenantAppStateNotCatalogued}}, true); got != tenantAppStateEvidenceUnavailable {
		t.Fatalf("mixed verified/unmatched devices must not report fully current: got %q", got)
	}
}

// TestTenantAppsHandlerBadUUID verifies the handler rejects non-UUID tenantID
// values before any DB call. Pure-logic test; no database required.
func TestTenantAppsHandlerBadUUID(t *testing.T) {
	// TenantAppsHandler with a nil pool is safe here because the UUID check
	// short-circuits before the pool is ever used.
	h := TenantAppsHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/not-a-uuid/apps", nil)
	rr := httptest.NewRecorder()

	req = taWithTenantID(req, "not-a-uuid")
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestTenantAppsHandlerValidUUIDShape checks that a well-formed UUID passes
// the shape check. The handler will fail at the DB call (nil pool), but the
// 400 path should not be triggered.
func TestTenantAppsHandlerValidUUIDShape(t *testing.T) {
	const validUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	// We expect a panic from the nil pool, but NOT a 400.
	// Wrap in recover so the test doesn't crash the suite.
	defer func() { recover() }() //nolint:errcheck

	h := TenantAppsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+validUUID+"/apps", nil)
	rr := httptest.NewRecorder()
	req = taWithTenantID(req, validUUID)
	h.ServeHTTP(rr, req)

	// If we reach here without a panic, the handler must not have returned 400.
	if rr.Code == http.StatusBadRequest {
		t.Errorf("valid UUID was rejected with 400")
	}
}

func TestTenantAppsHandlerTruthfulCatalogueAndDeviceEvidence(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat1160-tenant-apps")

	type seededDevice struct {
		id       string
		hostname string
	}
	seedDevice := func(hostname string) seededDevice {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, os, hw_uuid, hostname)
			VALUES ($1::uuid, 'macOS', gen_random_uuid(), $2)
			RETURNING id::text`, tenantID, hostname).Scan(&id); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return seededDevice{id: id, hostname: hostname}
	}
	mac1 := seedDevice("pat1160-mac-01")
	mac2 := seedDevice("pat1160-mac-02")

	seedApp := func(device seededDevice, name, identifier, version, signer string, seen time.Time) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version, team_id, last_seen)
			VALUES ($1::uuid, $2, $3, NULLIF($4, ''), $5, $6)`,
			device.id, name, identifier, version, signer, seen); err != nil {
			t.Fatalf("insert app %s/%s: %v", name, identifier, err)
		}
	}
	latestEvidence := time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)
	olderEvidence := latestEvidence.Add(-time.Hour)
	seedApp(mac1, "PAT1160 Browser", "im.patched.pat1160.browser", "1.0", "SHAREDTEAM", olderEvidence)
	seedApp(mac2, "PAT1160 Browser", "im.patched.pat1160.browser", "2.0", "SHAREDTEAM", latestEvidence)
	seedApp(mac1, "PAT1160 Unrelated", "im.patched.pat1160.unrelated", "1.0", "SHAREDTEAM", latestEvidence)
	seedApp(mac1, "PAT1160 Unknown", "im.patched.pat1160.unknown", "", "UNKNOWNTEAM", latestEvidence)
	seedApp(mac1, "PAT1160 Current", "im.patched.pat1160.current", "3.0", "CURRENTTEAM", latestEvidence)
	seedApp(mac1, "Firefox Crash Reporter", "org.mozilla.crashreporter", "1.0", "43AQ936H96", latestEvidence)
	seedApp(mac1, "Zoom", "us.zoom.xos.ZoomAutoUpdater", "1.0", "BJ4HAAB9B3", latestEvidence)

	labels := []string{"pat1160-browser", "pat1160-unknown", "pat1160-current", "pat1160-firefox", "pat1160-zoom"}
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_catalog_entries
		    (label, name, platform, verified_signer, latest_version, verified_at, updated_at)
		VALUES
		    ('pat1160-browser', 'PAT1160 Browser', 'macOS', 'SHAREDTEAM', '2.0', '2099-01-01', '2099-01-01'),
		    ('pat1160-unknown', 'PAT1160 Unknown', 'macOS', 'UNKNOWNTEAM', '2.0', '2099-01-01', '2099-01-01'),
		    ('pat1160-current', 'PAT1160 Current', 'macOS', 'CURRENTTEAM', '3.0', '2099-01-01', '2099-01-01'),
		    ('pat1160-firefox', 'Firefox', 'macOS', '43AQ936H96', '127.0', '2099-01-01', '2099-01-01'),
		    ('pat1160-zoom', 'Zoom', 'macOS', 'BJ4HAAB9B3', '6.1', '2099-01-01', '2099-01-01')
	`); err != nil {
		t.Fatalf("insert catalogue fixtures: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM app_catalog_entries WHERE label = ANY($1)`, labels)
	})

	h := TenantAppsHandler(pool)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/apps", nil)
	req = taWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handler: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got tenantAppsResp
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	find := func(identifier string) tenantAppEntry {
		t.Helper()
		for _, app := range got.Apps {
			if app.ID == identifier {
				return app
			}
		}
		t.Fatalf("app %s missing from response", identifier)
		return tenantAppEntry{}
	}

	browser := find("im.patched.pat1160.browser")
	if !browser.UpdateAvailable || browser.EvidenceState != tenantAppStateUpdateAvailable || browser.TargetVersion != "2.0" || browser.CatalogLabel != "pat1160-browser" {
		t.Fatalf("browser catalogue/evidence contract: %+v", browser)
	}
	if browser.EvidenceAt == nil || !browser.EvidenceAt.Equal(latestEvidence) {
		t.Fatalf("evidence_at: got %v, want %v", browser.EvidenceAt, latestEvidence)
	}
	if len(browser.Devices) != 2 || browser.Devices[0].DeviceID == "" || browser.Devices[0].Hostname == "" || browser.Devices[0].LastSeen.IsZero() {
		t.Fatalf("device evidence shape: %+v", browser.Devices)
	}
	states := map[string]string{}
	for _, device := range browser.Devices {
		states[device.Hostname] = device.UpdateState
	}
	if states[mac1.hostname] != tenantAppStateUpdateAvailable || states[mac2.hostname] != tenantAppStateCurrent {
		t.Fatalf("per-device states: %+v", states)
	}

	unknown := find("im.patched.pat1160.unknown")
	if unknown.UpdateAvailable || unknown.EvidenceState != tenantAppStateEvidenceUnavailable || unknown.TargetVersion != "2.0" {
		t.Fatalf("unknown version must not confirm update: %+v", unknown)
	}
	current := find("im.patched.pat1160.current")
	if current.UpdateAvailable || current.EvidenceState != tenantAppStateCurrent || current.TargetVersion != "3.0" || len(current.Devices) != 1 || current.Devices[0].UpdateState != tenantAppStateCurrent {
		t.Fatalf("current app contract: %+v", current)
	}

	for _, identifier := range []string{"im.patched.pat1160.unrelated", "org.mozilla.crashreporter", "us.zoom.xos.ZoomAutoUpdater"} {
		app := find(identifier)
		if app.UpdateAvailable || app.EvidenceState != tenantAppStateNotCatalogued || app.TargetVersion != "" || app.CatalogLabel != "" {
			t.Fatalf("%s must remain non-actionable/not_catalogued: %+v", identifier, app)
		}
	}
}
