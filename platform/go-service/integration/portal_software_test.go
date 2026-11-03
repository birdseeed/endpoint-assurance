//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

type portalSoftwareCoverageOut struct {
	InstallationCount int `json:"installation_count"`
	MeteredCount      int `json:"metered_installation_count"`
	UnmeteredCount    int `json:"unmetered_installation_count"`
	StaleCount        int `json:"stale_installation_count"`
	UnusedCount       int `json:"unused_installation_count"`
	NoEvidenceCount   int `json:"no_evidence_installation_count"`
}

type portalSoftwareProductOut struct {
	Name                        string   `json:"name"`
	Names                       []string `json:"names"`
	Identifier                  string   `json:"identifier"`
	Platform                    string   `json:"platform"`
	DeviceCount                 int      `json:"device_count"`
	InstallationCount           int      `json:"installation_count"`
	UsageState                  string   `json:"usage_state"`
	RemovalCandidate            bool     `json:"removal_candidate"`
	MeteredInstallationCount    int      `json:"metered_installation_count"`
	UnmeteredInstallationCount  int      `json:"unmetered_installation_count"`
	StaleInstallationCount      int      `json:"stale_installation_count"`
	UnusedInstallationCount     int      `json:"unused_installation_count"`
	NoEvidenceInstallationCount int      `json:"no_evidence_installation_count"`
	CanonicalKey                *string  `json:"canonical_key"`
	CanonicalName               *string  `json:"canonical_name"`
	TeamID                      *string  `json:"team_id"`
	ProductKey                  *string  `json:"product_key"`
	PolicyState                 *string  `json:"policy_state"`
	// FirstSeenOnDevice (PAT-2156) is only present on a ?device_id= page.
	FirstSeenOnDevice *time.Time `json:"first_seen_on_device"`
	CVEAssessment     struct {
		State         string     `json:"state"`
		LastMatchedAt *time.Time `json:"last_matched_at"`
		FindingCount  *int       `json:"finding_count"`
	} `json:"cve_assessment"`
}

type portalSoftwareOut struct {
	Total    int                        `json:"total"`
	Limit    int                        `json:"limit"`
	Offset   int                        `json:"offset"`
	Coverage portalSoftwareCoverageOut  `json:"coverage"`
	Products []portalSoftwareProductOut `json:"products"`
}

func findPortalSoftware(products []portalSoftwareProductOut, identifier string) (portalSoftwareProductOut, bool) {
	for _, product := range products {
		if product.Identifier == identifier {
			return product, true
		}
	}
	return portalSoftwareProductOut{}, false
}

func seedPortalSoftwareDevice(t *testing.T, tenantID, suffix, meteringStatus string, lastSeen time.Time) string {
	t.Helper()
	var deviceID string
	err := env.pool.QueryRow(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, metering_status, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', NULLIF($4, ''), $5)
		RETURNING id::text
	`, tenantID, "SER-software-"+suffix, "host-software-"+suffix, meteringStatus, lastSeen).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device %s: %v", suffix, err)
	}
	return deviceID
}

// seedPortalSoftwareDeviceOf seeds a device with an explicit OS string and
// PAT-1960 device_class, for the PAT-2327 usage-verdict tests that need Windows
// workstations, servers and domain controllers alongside macOS.
func seedPortalSoftwareDeviceOf(t *testing.T, tenantID, suffix, osName, deviceClass, meteringStatus string, lastSeen time.Time) string {
	t.Helper()
	var deviceID string
	err := env.pool.QueryRow(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, metering_status, last_seen, device_class)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, $4, '1', '1', 'x64', NULLIF($5, ''), $6, $7)
		RETURNING id::text
	`, tenantID, "SER-software-"+suffix, "host-software-"+suffix, osName, meteringStatus, lastSeen, deviceClass).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device %s: %v", suffix, err)
	}
	return deviceID
}

func seedPortalSoftwareApp(t *testing.T, deviceID, name, identifier, version string, lastSeen time.Time, lastUsedAt *time.Time) {
	t.Helper()
	_, err := env.pool.Exec(t.Context(), `
		INSERT INTO device_apps (device_id, name, identifier, version, last_seen, last_used_at)
		VALUES ($1::uuid, $2, $3, NULLIF($4, ''), $5, $6)
	`, deviceID, name, identifier, version, lastSeen, lastUsedAt)
	if err != nil {
		t.Fatalf("seed app %s: %v", identifier, err)
	}
}

func TestPortalSoftwareUsageCoverageIsolationSearchAndPagination(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-coverage")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	otherTenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-other")
	if err != nil {
		t.Fatalf("create other tenant: %v", err)
	}
	cleanupTestTenant(t, otherTenantID)

	usedAt := now.Add(-24 * time.Hour)
	oldUse := now.Add(-91 * 24 * time.Hour)
	fresh := now.Add(-time.Hour)
	stale := now.Add(-31 * 24 * time.Hour)
	alphaDevice := seedPortalSoftwareDevice(t, tenantID, "alpha", "ok", fresh)
	seedPortalSoftwareApp(t, alphaDevice, "Alpha", "com.example.alpha", "1.0", fresh, &usedAt)
	betaDevice := seedPortalSoftwareDevice(t, tenantID, "beta", "ok", fresh)
	seedPortalSoftwareApp(t, betaDevice, "Beta", "com.example.beta", "2.0", fresh, &oldUse)
	gammaDevice := seedPortalSoftwareDevice(t, tenantID, "gamma", "", fresh)
	seedPortalSoftwareApp(t, gammaDevice, "Gamma", "com.example.gamma", "1.0", fresh, nil)
	deltaDevice := seedPortalSoftwareDevice(t, tenantID, "delta", "ok", stale)
	seedPortalSoftwareApp(t, deltaDevice, "Delta", "com.example.delta", "1.0", stale, &oldUse)
	mixedUsedDevice := seedPortalSoftwareDevice(t, tenantID, "mixed-used", "ok", fresh)
	seedPortalSoftwareApp(t, mixedUsedDevice, "Mixed", "com.example.mixed", "1.0", fresh, &usedAt)
	mixedUnmeteredDevice := seedPortalSoftwareDevice(t, tenantID, "mixed-unmetered", "", fresh)
	seedPortalSoftwareApp(t, mixedUnmeteredDevice, "Mixed", "com.example.mixed", "1.0", fresh, nil)

	// The reviewed alias is an enrichment only. It must appear for Alpha,
	// while the same raw app inserted for another tenant must never leak.
	_, err = env.pool.Exec(t.Context(), `
		WITH product AS (
			INSERT INTO software_products (canonical_key, canonical_name)
			VALUES ('alpha-product', 'Alpha Product') RETURNING id
		)
		INSERT INTO software_product_aliases (
			product_id, platform, identity_kind, identity_value_normalized,
			companion_value_normalized, match_confidence, provenance
		)
		SELECT id, 'macos', 'macos_bundle', 'com.example.alpha', '', 'exact', 'reviewed' FROM product
	`)
	if err != nil {
		t.Fatalf("seed canonical alias: %v", err)
	}
	otherDevice := seedPortalSoftwareDevice(t, otherTenantID, "other", "ok", fresh)
	seedPortalSoftwareApp(t, otherDevice, "Other Tenant Only", "com.example.other", "1.0", fresh, &usedAt)

	email := "software-coverage@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/software?limit=2&offset=0", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("software = %d: %s", resp.StatusCode, body)
	}
	var firstPage portalSoftwareOut
	decodeJSON(t, resp, &firstPage)
	if firstPage.Total != 5 || firstPage.Limit != 2 || firstPage.Offset != 0 || len(firstPage.Products) != 2 {
		t.Fatalf("first page = %+v, want total=5 limit=2 offset=0 products=2", firstPage)
	}
	if firstPage.Coverage.InstallationCount != 6 || firstPage.Coverage.MeteredCount != 4 ||
		firstPage.Coverage.UnmeteredCount != 2 || firstPage.Coverage.StaleCount != 1 || firstPage.Coverage.UnusedCount != 1 {
		t.Errorf("coverage = %+v, want installations=6 metered=4 unmetered=2 stale=1 unused=1", firstPage.Coverage)
	}
	alpha, ok := findPortalSoftware(firstPage.Products, "com.example.alpha")
	if !ok || alpha.UsageState != "used" || alpha.RemovalCandidate || alpha.CanonicalKey == nil || *alpha.CanonicalKey != "alpha-product" {
		t.Errorf("alpha = %+v, want used non-candidate with direct canonical identity", alpha)
	}
	beta, ok := findPortalSoftware(firstPage.Products, "com.example.beta")
	if !ok || beta.UsageState != "unused" || !beta.RemovalCandidate || beta.UnusedInstallationCount != 1 {
		t.Errorf("beta = %+v, want fresh authoritative unused removal candidate", beta)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/software?limit=2&offset=2", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("second page = %d: %s", resp.StatusCode, body)
	}
	var secondPage portalSoftwareOut
	decodeJSON(t, resp, &secondPage)
	delta, ok := findPortalSoftware(secondPage.Products, "com.example.delta")
	if !ok || delta.UsageState != "stale" || delta.RemovalCandidate {
		t.Errorf("delta = %+v, want stale non-candidate", delta)
	}
	gamma, ok := findPortalSoftware(secondPage.Products, "com.example.gamma")
	if !ok || gamma.UsageState != "unmetered" || gamma.RemovalCandidate {
		t.Errorf("gamma = %+v, want unmetered non-candidate", gamma)
	}

	// The exact searched total belongs to the result set, not to a row in the
	// current page. An offset beyond the end must therefore retain total=5.
	resp = portalDo(t, http.MethodGet, "/v1/portal/software?limit=2&offset=100", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("beyond-end page = %d: %s", resp.StatusCode, body)
	}
	var beyondEnd portalSoftwareOut
	decodeJSON(t, resp, &beyondEnd)
	if beyondEnd.Total != 5 || len(beyondEnd.Products) != 0 || beyondEnd.Coverage.InstallationCount != 6 {
		t.Errorf("beyond-end page = %+v, want total=5 empty products and whole-estate coverage", beyondEnd)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/software?search=Mixed", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("search = %d: %s", resp.StatusCode, body)
	}
	var searched portalSoftwareOut
	decodeJSON(t, resp, &searched)
	mixed, ok := findPortalSoftware(searched.Products, "com.example.mixed")
	if searched.Total != 1 || !ok || mixed.UsageState != "mixed" || mixed.RemovalCandidate ||
		mixed.MeteredInstallationCount != 1 || mixed.UnmeteredInstallationCount != 1 || searched.Coverage.InstallationCount != 6 {
		t.Errorf("search result = %+v, want one mixed product and whole-estate coverage", searched)
	}
}

func TestPortalSoftwareLargeEstatePaginationIsNotPolicyCapped(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-large")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	deviceID := seedPortalSoftwareDevice(t, tenantID, "large", "ok", now)
	for i := 0; i < 501; i++ {
		seedPortalSoftwareApp(t, deviceID, fmt.Sprintf("Large %03d", i), fmt.Sprintf("com.example.large.%03d", i), "1.0", now, nil)
	}
	email := "software-large@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/software?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("large first page = %d: %s", resp.StatusCode, body)
	}
	var first portalSoftwareOut
	decodeJSON(t, resp, &first)
	if first.Total != 501 || len(first.Products) != 500 {
		t.Fatalf("large first page total/products = %d/%d, want 501/500", first.Total, len(first.Products))
	}
	resp = portalDo(t, http.MethodGet, "/v1/portal/software?limit=500&offset=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("large second page = %d: %s", resp.StatusCode, body)
	}
	var second portalSoftwareOut
	decodeJSON(t, resp, &second)
	if second.Total != 501 || len(second.Products) != 1 {
		t.Errorf("large second page total/products = %d/%d, want 501/1", second.Total, len(second.Products))
	}
}

func TestPortalSoftwareCanonicalIdentityRequiresReviewedAliasAndUnknownOSStaysUnknown(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-alias-provenance")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	macDevice := seedPortalSoftwareDevice(t, tenantID, "system-alias", "ok", now)
	seedPortalSoftwareApp(t, macDevice, "System Alias Only", "com.example.system-alias", "1.0", now, nil)
	_, err = env.pool.Exec(t.Context(), `
		WITH product AS (
			INSERT INTO software_products (canonical_key, canonical_name)
			VALUES ('migration-only-product', 'Migration Only Product') RETURNING id
		)
		INSERT INTO software_product_aliases (
			product_id, platform, identity_kind, identity_value_normalized,
			companion_value_normalized, match_confidence, provenance
		)
		SELECT id, 'macos', 'macos_bundle', 'com.example.system-alias', '', 'exact', 'migration' FROM product
	`)
	if err != nil {
		t.Fatalf("seed migration alias: %v", err)
	}

	var unknownDeviceID string
	err = env.pool.QueryRow(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, metering_status, last_seen)
		VALUES ($1::uuid, 'SER-software-unknown-os', gen_random_uuid(), 'host-software-unknown-os',
		        'Solaris', '11', 'unknown', 'sparc', 'ok', $2)
		RETURNING id::text
	`, tenantID, now).Scan(&unknownDeviceID)
	if err != nil {
		t.Fatalf("seed unknown-os device: %v", err)
	}
	seedPortalSoftwareApp(t, unknownDeviceID, "Unknown OS App", "com.example.unknown-os", "1.0", now, nil)

	email := "software-alias-provenance@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	// Migration aliases must neither enrich a response nor make an otherwise
	// unmatched app discoverable through canonical identity search.
	resp := portalDo(t, http.MethodGet, "/v1/portal/software?search=migration-only-product", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("canonical search = %d: %s", resp.StatusCode, body)
	}
	var canonicalSearch portalSoftwareOut
	decodeJSON(t, resp, &canonicalSearch)
	if canonicalSearch.Total != 0 || len(canonicalSearch.Products) != 0 {
		t.Errorf("migration-alias canonical search = %+v, want no results", canonicalSearch)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/software", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("software = %d: %s", resp.StatusCode, body)
	}
	var inventory portalSoftwareOut
	decodeJSON(t, resp, &inventory)
	systemOnly, ok := findPortalSoftware(inventory.Products, "com.example.system-alias")
	if !ok || systemOnly.CanonicalKey != nil || systemOnly.CanonicalName != nil {
		t.Errorf("system alias row = %+v, want no canonical identity from migration alias", systemOnly)
	}
	unknownOS, ok := findPortalSoftware(inventory.Products, "com.example.unknown-os")
	if !ok || unknownOS.Platform != "unknown" || unknownOS.CanonicalKey != nil {
		t.Errorf("unknown-OS row = %+v, want explicit unknown platform and no canonical identity", unknownOS)
	}
}

func TestPortalSoftwareSearchMatchesEveryObservedName(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-secondary-name-search")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	firstDevice := seedPortalSoftwareDevice(t, tenantID, "secondary-name-first", "ok", now)
	seedPortalSoftwareApp(t, firstDevice, "Primary Product Name", "com.example.secondary-name", "1.0", now, nil)
	secondDevice := seedPortalSoftwareDevice(t, tenantID, "secondary-name-second", "ok", now)
	seedPortalSoftwareApp(t, secondDevice, "Secondary Product Name", "com.example.secondary-name", "1.0", now, nil)

	email := "software-secondary-name@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	resp := portalDo(t, http.MethodGet, "/v1/portal/software?search=Secondary%20Product%20Name", env.idp.token(t, email), nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("secondary-name search = %d: %s", resp.StatusCode, body)
	}
	var out portalSoftwareOut
	decodeJSON(t, resp, &out)
	product, ok := findPortalSoftware(out.Products, "com.example.secondary-name")
	if out.Total != 1 || !ok || len(product.Names) != 2 {
		t.Errorf("secondary-name search = %+v, want one group retaining both observed names", out)
	}
}

func TestPortalSoftwareCanonicalAliasPrecedenceAndWindowsPublisherEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-canonical-precedence")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	macDevice := seedPortalSoftwareDevice(t, tenantID, "alias-precedence-mac", "ok", now)
	_, err = env.pool.Exec(t.Context(), `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id, last_seen)
		VALUES ($1::uuid, 'Alias Precedence Mac', 'com.example.alias-precedence', '1.0', 'TEAM123', $2)
	`, macDevice, now)
	if err != nil {
		t.Fatalf("seed macOS precedence app: %v", err)
	}

	var windowsDevice string
	err = env.pool.QueryRow(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, metering_status, last_seen)
		VALUES ($1::uuid, 'SER-software-alias-windows', gen_random_uuid(), 'host-software-alias-windows',
		        'Windows 11', '24H2', '26100', 'amd64', 'ok', $2)
		RETURNING id::text
	`, tenantID, now).Scan(&windowsDevice)
	if err != nil {
		t.Fatalf("seed windows device: %v", err)
	}
	_, err = env.pool.Exec(t.Context(), `
		INSERT INTO device_apps (device_id, name, identifier, version, team_id, last_seen)
		VALUES ($1::uuid, 'Coincidental Team ID', 'com.example.windows-publisher', '1.0', 'Coincidental Publisher', $2)
	`, windowsDevice, now)
	if err != nil {
		t.Fatalf("seed windows app: %v", err)
	}

	_, err = env.pool.Exec(t.Context(), `
		WITH bare_product AS (
			INSERT INTO software_products (canonical_key, canonical_name)
			VALUES ('bare-bundle-product', 'Bare Bundle Product') RETURNING id
		), team_product AS (
			INSERT INTO software_products (canonical_key, canonical_name)
			VALUES ('team-bundle-product', 'Team Bundle Product') RETURNING id
		), windows_product AS (
			INSERT INTO software_products (canonical_key, canonical_name)
			VALUES ('windows-publisher-product', 'Windows Publisher Product') RETURNING id
		)
		INSERT INTO software_product_aliases (
			product_id, platform, identity_kind, identity_value_normalized,
			companion_value_normalized, match_confidence, provenance
		)
		SELECT id, 'macos', 'macos_bundle', 'com.example.alias-precedence', '', 'exact', 'reviewed' FROM bare_product
		UNION ALL
		SELECT id, 'macos', 'macos_bundle_team', 'com.example.alias-precedence', 'TEAM123', 'exact', 'reviewed' FROM team_product
		UNION ALL
		SELECT id, 'windows', 'windows_native_publisher', 'com.example.windows-publisher', 'coincidental publisher', 'exact', 'reviewed' FROM windows_product
	`)
	if err != nil {
		t.Fatalf("seed canonical aliases: %v", err)
	}

	email := "software-canonical-precedence@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	resp := portalDo(t, http.MethodGet, "/v1/portal/software", env.idp.token(t, email), nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("software = %d: %s", resp.StatusCode, body)
	}
	var out portalSoftwareOut
	decodeJSON(t, resp, &out)
	mac, ok := findPortalSoftware(out.Products, "com.example.alias-precedence")
	if !ok || mac.CanonicalKey == nil || *mac.CanonicalKey != "team-bundle-product" {
		t.Errorf("macOS alias precedence = %+v, want macos_bundle_team canonical identity", mac)
	}
	windows, ok := findPortalSoftware(out.Products, "com.example.windows-publisher")
	if !ok || windows.Platform != "windows" || windows.CanonicalKey != nil || windows.CanonicalName != nil {
		t.Errorf("windows publisher evidence = %+v, want no canonical identity from team_id alone", windows)
	}

	// PAT-2404: a retired alias names nothing. With the Team ID alias retired
	// the product falls back to the bundle-only alias, which is still live.
	if _, err = env.pool.Exec(t.Context(), `
		UPDATE software_product_aliases SET retired_at = now()
		WHERE identity_kind = 'macos_bundle_team' AND identity_value_normalized = 'com.example.alias-precedence'`); err != nil {
		t.Fatalf("retire alias: %v", err)
	}
	resp = portalDo(t, http.MethodGet, "/v1/portal/software", env.idp.token(t, email), nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("software after retirement = %d: %s", resp.StatusCode, body)
	}
	out = portalSoftwareOut{}
	decodeJSON(t, resp, &out)
	mac, ok = findPortalSoftware(out.Products, "com.example.alias-precedence")
	if !ok || mac.CanonicalKey == nil || *mac.CanonicalKey != "bare-bundle-product" {
		t.Errorf("after retiring the Team ID alias = %+v, want the live bundle-only alias", mac)
	}
}

// TestPortalSoftwareUnusedRequiresPositiveEvidence (PAT-2327): unused is a
// verdict, and a verdict needs evidence. A missing last_used_at is a missing
// launch record, never proof of non-use, and a server rarely produces a
// user launch record at all. Only a recorded last_used_at older than the
// 90-day horizon on a fresh, metered, non-server device is unused; a server
// is no-evidence when its value is NULL or old, and used when it is recent.
func TestPortalSoftwareUnusedRequiresPositiveEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-positive-evidence")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	fresh := now.Add(-time.Hour)
	stale := now.Add(-31 * 24 * time.Hour)
	recent := now.Add(-24 * time.Hour)
	old := now.Add(-91 * 24 * time.Hour)

	winWs := seedPortalSoftwareDeviceOf(t, tenantID, "pe-win-ws", "Windows", "workstation", "ok", fresh)
	winWs2 := seedPortalSoftwareDeviceOf(t, tenantID, "pe-win-ws2", "Windows", "workstation", "ok", fresh)
	macWs := seedPortalSoftwareDeviceOf(t, tenantID, "pe-mac-ws", "macOS", "unknown", "ok", fresh)
	winSrv := seedPortalSoftwareDeviceOf(t, tenantID, "pe-win-srv", "Windows", "server", "ok", fresh)
	winDC := seedPortalSoftwareDeviceOf(t, tenantID, "pe-win-dc", "Windows", "domain_controller", "ok", fresh)
	winStale := seedPortalSoftwareDeviceOf(t, tenantID, "pe-win-stale", "Windows", "workstation", "ok", stale)
	winNoSession := seedPortalSoftwareDeviceOf(t, tenantID, "pe-no-session", "Windows", "workstation", "no_user_session", fresh)
	macSpotlightOff := seedPortalSoftwareDeviceOf(t, tenantID, "pe-spotlight", "macOS", "unknown", "spotlight_disabled", fresh)
	winNoUserAssist := seedPortalSoftwareDeviceOf(t, tenantID, "pe-userassist", "Windows", "workstation", "userassist_unavailable", fresh)

	const prefix = "com.example.pe."
	seed := func(device, id string, usedAt *time.Time) {
		t.Helper()
		seedPortalSoftwareApp(t, device, id, prefix+id, "1.0", fresh, usedAt)
	}
	// No usage evidence on a metered, fresh, non-server device.
	seed(winWs, "win-null", nil)
	seed(macWs, "mac-null", nil)
	// Servers and domain controllers are never unused: an old value is
	// no-evidence, while a recorded use inside the horizon is positive
	// evidence of use.
	seed(winSrv, "srv-old", &old)
	seed(winDC, "dc-old", &old)
	seed(winSrv, "srv-recent", &recent)
	seed(winDC, "dc-recent", &recent)
	// Devices that could not meter at all are unmetered whatever the value.
	for _, unmetered := range []struct{ tag, device string }{
		{"no-session", winNoSession}, {"spotlight-off", macSpotlightOff}, {"no-userassist", winNoUserAssist},
	} {
		seed(unmetered.device, unmetered.tag+"-null", nil)
		seed(unmetered.device, unmetered.tag+"-old", &old)
	}
	// Positive evidence on workstations.
	seed(winWs, "win-old", &old)
	seed(macWs, "mac-old", &old)
	seed(winWs, "win-recent", &recent)
	seed(macWs, "mac-recent", &recent)
	// A device that has not reported inside the freshness window is stale.
	seed(winStale, "stale-old", &old)
	seed(winStale, "stale-null", nil)
	// Rollups: one unused + one server install is mixed; two unused is a
	// candidate; a no-evidence + an unmetered install stay unmetered.
	seed(winWs, "mixed", &old)
	seed(winSrv, "mixed", &old)
	seed(winWs, "all-unused", &old)
	seed(winWs2, "all-unused", &old)
	seed(winWs, "unobserved", nil)
	seed(winNoSession, "unobserved", nil)

	email := "software-positive-evidence@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/software?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("software = %d: %s", resp.StatusCode, body)
	}
	var out portalSoftwareOut
	decodeJSON(t, resp, &out)

	type want struct {
		state                            string
		candidate                        bool
		unused, noEvidence, unmetered, n int
	}
	wants := map[string]want{
		"win-null":   {"unmetered", false, 0, 1, 0, 1},
		"mac-null":   {"unmetered", false, 0, 1, 0, 1},
		"srv-old":    {"unmetered", false, 0, 1, 0, 1},
		"dc-old":     {"unmetered", false, 0, 1, 0, 1},
		"srv-recent": {"used", false, 0, 0, 0, 1},
		"dc-recent":  {"used", false, 0, 0, 0, 1},

		"no-session-null":    {"unmetered", false, 0, 0, 1, 1},
		"no-session-old":     {"unmetered", false, 0, 0, 1, 1},
		"spotlight-off-null": {"unmetered", false, 0, 0, 1, 1},
		"spotlight-off-old":  {"unmetered", false, 0, 0, 1, 1},
		"no-userassist-null": {"unmetered", false, 0, 0, 1, 1},
		"no-userassist-old":  {"unmetered", false, 0, 0, 1, 1},

		"win-old":    {"unused", true, 1, 0, 0, 1},
		"mac-old":    {"unused", true, 1, 0, 0, 1},
		"win-recent": {"used", false, 0, 0, 0, 1},
		"mac-recent": {"used", false, 0, 0, 0, 1},

		"stale-old":  {"stale", false, 0, 0, 0, 1},
		"stale-null": {"stale", false, 0, 0, 0, 1},

		"mixed":      {"mixed", false, 1, 1, 0, 2},
		"all-unused": {"unused", true, 2, 0, 0, 2},
		"unobserved": {"unmetered", false, 0, 1, 1, 2},
	}
	if out.Total != len(wants) {
		t.Errorf("total = %d, want %d products", out.Total, len(wants))
	}
	for id, w := range wants {
		p, ok := findPortalSoftware(out.Products, prefix+id)
		if !ok {
			t.Errorf("%s: product missing", id)
			continue
		}
		if p.UsageState != w.state || p.RemovalCandidate != w.candidate ||
			p.UnusedInstallationCount != w.unused || p.NoEvidenceInstallationCount != w.noEvidence ||
			p.UnmeteredInstallationCount != w.unmetered || p.InstallationCount != w.n {
			t.Errorf("%s = state %q candidate %v unused %d no_evidence %d unmetered %d installations %d; want state %q candidate %v unused %d no_evidence %d unmetered %d installations %d",
				id, p.UsageState, p.RemovalCandidate, p.UnusedInstallationCount, p.NoEvidenceInstallationCount,
				p.UnmeteredInstallationCount, p.InstallationCount,
				w.state, w.candidate, w.unused, w.noEvidence, w.unmetered, w.n)
		}
	}

	// Estate coverage: 24 installations, of which 17 are metered (7 are not),
	// 2 stale. The 17 metered split exactly into 5 unused, 6 no-evidence,
	// 4 used (two on servers) and 2 stale, so nothing is lost or double counted.
	c := out.Coverage
	if c.InstallationCount != 24 || c.MeteredCount != 17 || c.UnmeteredCount != 7 || c.StaleCount != 2 ||
		c.UnusedCount != 5 || c.NoEvidenceCount != 6 {
		t.Errorf("coverage = %+v, want installations=24 metered=17 unmetered=7 stale=2 unused=5 no_evidence=6", c)
	}

	// The device page for the server: an old or missing launch record is
	// no-evidence, a recent one is used, none is unused, and no product on it
	// can be a removal candidate.
	resp = portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+winSrv, token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("server device software = %d: %s", resp.StatusCode, body)
	}
	var server portalSoftwareOut
	decodeJSON(t, resp, &server)
	if server.Coverage.InstallationCount != 3 || server.Coverage.UnusedCount != 0 || server.Coverage.NoEvidenceCount != 2 {
		t.Errorf("server coverage = %+v, want 3 installations, 0 unused, 2 no_evidence (srv-old, mixed) and 1 used (srv-recent)", server.Coverage)
	}
	for _, p := range server.Products {
		if p.UsageState == "unused" || p.RemovalCandidate || p.UnusedInstallationCount != 0 {
			t.Errorf("server product %s = state %q candidate %v unused %d; a server install is never unused",
				p.Identifier, p.UsageState, p.RemovalCandidate, p.UnusedInstallationCount)
		}
	}
}
