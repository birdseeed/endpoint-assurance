//go:build integration

// PAT-2156: GET /v1/portal/software?device_id=<uuid>. Platform half of the
// device-page Software view. Every assertion in this file is a red-proof
// against the pre-PAT-2156 handler: that handler has no device_id parameter
// at all, so (a) an unknown query key is silently ignored by net/url,
// meaning a device-scoped request would just run the unfiltered page and
// return every device's rows (failing the isolation/coverage/count
// assertions below), (b) there is no ownership check at all, so the
// cross-tenant and malformed-id cases would both fall through to the same
// unfiltered 200 instead of 404/400, and (c) first_seen_on_device and the
// device-scoped cve_assessment do not exist in the response shape at all.
package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestPortalSoftwareDeviceIDFilterReturnsOnlyThatDevicesRows seeds two
// devices on one tenant with disjoint products and asserts the device_id
// filter returns only the targeted device's rows, with coverage scoped to
// the device and first_seen_on_device populated — while the unfiltered page
// (no device_id) still sees both devices and never carries
// first_seen_on_device at all, proving the unfiltered path is unchanged.
func TestPortalSoftwareDeviceIDFilterReturnsOnlyThatDevicesRows(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-device-filter")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	deviceA := seedPortalSoftwareDevice(t, tenantID, "device-filter-a", "ok", now)
	seedPortalSoftwareApp(t, deviceA, "Alpha On A", "com.example.device-filter.alpha", "1.0", now, nil)
	deviceB := seedPortalSoftwareDevice(t, tenantID, "device-filter-b", "ok", now)
	seedPortalSoftwareApp(t, deviceB, "Beta On B", "com.example.device-filter.beta", "1.0", now, nil)

	email := "software-device-filter@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	// Unfiltered baseline: both devices' products, and the raw JSON must
	// never carry a first_seen_on_device key (shape proof, not just a nil
	// value check — the field must be OMITTED, per omitempty).
	baseResp := portalDo(t, http.MethodGet, "/v1/portal/software", token, nil)
	if baseResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(baseResp.Body)
		t.Fatalf("baseline software = %d: %s", baseResp.StatusCode, body)
	}
	baseRaw, err := io.ReadAll(baseResp.Body)
	if err != nil {
		t.Fatalf("read baseline body: %v", err)
	}
	if strings.Contains(string(baseRaw), "first_seen_on_device") {
		t.Errorf("unfiltered /v1/portal/software carries first_seen_on_device; want the field entirely absent, byte-identical to before PAT-2156: %s", baseRaw)
	}
	var baseline portalSoftwareOut
	if err := json.Unmarshal(baseRaw, &baseline); err != nil {
		t.Fatalf("decode baseline: %v", err)
	}
	if baseline.Total != 2 {
		t.Fatalf("baseline total = %d, want 2 (both devices' products)", baseline.Total)
	}
	if baseline.Coverage.InstallationCount != 2 {
		t.Fatalf("baseline coverage.installation_count = %d, want 2 (whole tenant estate)", baseline.Coverage.InstallationCount)
	}

	// device_id=deviceA: only Alpha, never Beta.
	filteredResp := portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+deviceA, token, nil)
	if filteredResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(filteredResp.Body)
		t.Fatalf("device-filtered software = %d: %s", filteredResp.StatusCode, body)
	}
	var filtered portalSoftwareOut
	decodeJSON(t, filteredResp, &filtered)
	if filtered.Total != 1 {
		t.Fatalf("device-filtered total = %d, want 1 (device A's own product only)", filtered.Total)
	}
	if filtered.Coverage.InstallationCount != 1 {
		t.Errorf("device-filtered coverage.installation_count = %d, want 1 (scoped to the device, not the whole tenant)", filtered.Coverage.InstallationCount)
	}
	alpha, ok := findPortalSoftware(filtered.Products, "com.example.device-filter.alpha")
	if !ok {
		t.Fatalf("device-filtered page missing device A's own product: %+v", filtered.Products)
	}
	if alpha.FirstSeenOnDevice == nil {
		t.Errorf("first_seen_on_device is null on a device-scoped row; want it populated from device_apps.first_seen")
	}
	if _, leaked := findPortalSoftware(filtered.Products, "com.example.device-filter.beta"); leaked {
		t.Errorf("device_id=%s leaked device B's product into the response", deviceA)
	}

	// device_id=deviceB: only Beta, symmetric proof the filter isn't
	// accidentally always returning device A.
	otherResp := portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+deviceB, token, nil)
	if otherResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(otherResp.Body)
		t.Fatalf("device B filtered software = %d: %s", otherResp.StatusCode, body)
	}
	var otherPage portalSoftwareOut
	decodeJSON(t, otherResp, &otherPage)
	if otherPage.Total != 1 {
		t.Fatalf("device B filtered total = %d, want 1", otherPage.Total)
	}
	if _, ok := findPortalSoftware(otherPage.Products, "com.example.device-filter.beta"); !ok {
		t.Errorf("device B filtered page missing its own product: %+v", otherPage.Products)
	}
}

// TestPortalSoftwareDeviceIDCrossTenantIs404WithNoRowData proves a
// well-formed device_id belonging to another tenant answers 404 with no
// inventory data in the body — the same "not found" a nonexistent device_id
// gets, so this parameter can never be used as a cross-tenant existence
// oracle.
func TestPortalSoftwareDeviceIDCrossTenantIs404WithNoRowData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-device-cross-a")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	otherTenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-device-cross-b")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	cleanupTestTenant(t, otherTenantID)

	otherDevice := seedPortalSoftwareDevice(t, otherTenantID, "device-cross-other", "ok", now)
	seedPortalSoftwareApp(t, otherDevice, "Other Tenant Secret App", "com.example.device-cross.secret", "9.9", now, nil)

	email := "software-device-cross@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+otherDevice, token, nil)
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("cross-tenant device_id = %d, want 404: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "com.example.device-cross.secret") ||
		strings.Contains(string(body), "Other Tenant Secret App") ||
		strings.Contains(string(body), "\"products\"") {
		t.Errorf("404 response leaks the other tenant's inventory: %s", body)
	}

	// A syntactically valid but wholly nonexistent device gets the SAME 404
	// — deliberately indistinguishable from the cross-tenant case above.
	unknownDevice := "00000000-0000-0000-0000-000000000000"
	resp2 := portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+unknownDevice, token, nil)
	if resp2.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("nonexistent device_id = %d, want 404: %s", resp2.StatusCode, body)
	}
}

// TestPortalSoftwareDeviceIDMalformedIs400 proves a device_id that isn't a
// UUID at all is rejected before any ownership or inventory query runs.
func TestPortalSoftwareDeviceIDMalformedIs400(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-software-device-malformed")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	email := "software-device-malformed@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	for _, bad := range []string{"not-a-uuid", "12345", "'; DROP TABLE devices; --", strings.Repeat("a", 40)} {
		resp := portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+bad, token, nil)
		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("device_id=%q = %d, want 400: %s", bad, resp.StatusCode, body)
		}
	}
}

// TestPortalSoftwareDeviceIDCVEAssessmentScopedToDeviceNotEstate (PAT-2156 +
// PAT-2028) proves the device-filtered cve_assessment reflects THAT
// device's own installed version, not an estate-wide rollup: the same
// product is matched (assessed) on device 1 but still queued (pending) on
// device 2. Querying device 1 with device_id must read "assessed" even
// though device 2 elsewhere in the tenant is pending — a rollup implemented
// by naively reusing AssessEstateProducts would incorrectly read "pending"
// here (bleeding device 2's incompleteness onto device 1's own, complete,
// assessment), or conversely let device 2's page borrow device 1's clean
// state.
func TestPortalSoftwareDeviceIDCVEAssessmentScopedToDeviceNotEstate(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2156-device-cve-"+sfx)
	vendor, product := "pat2156v"+sfx, "widget"
	appName := "Pat2156 Widget " + sfx
	bundleID := "com.example.pat2156.widget." + sfx
	cveID := "CVE-2099-" + sfx + "5"

	seedFeedEntry(t, cveID, vendor, product, "2.0", false)
	seedCVEMapping(t, appName, vendor, product)
	drainCVEQueue(t) // absorb the mapping publish; no observation exists yet

	// Canonical 8-4-4-4-12 hex form required: internal/extractor/upsert.go's
	// uuidRegex rejects anything else and silently blanks hw_uuid instead of
	// erroring, which would make the deviceIDByHW lookups below fail
	// confusingly. Each device needs a distinct leading 8-hex group both for
	// uniqueness and because postAppsPayloadAt derives the device serial
	// from hwUUID[:8].
	hw1 := strings.ToUpper(sfx + "-1111-2222-3333-444444445551")
	hw2 := strings.ToUpper(randomHex(4) + "-1111-2222-3333-444444445552")
	postAppsPayload(t, tn, hw1, []cveTestApp{{appName, "1.5", bundleID}})
	drainCVEQueue(t) // device 1 is now assessed

	device1 := deviceIDByHW(t, tn.tenantID, hw1)

	row1 := fetchPortalSoftwareProductForDevice(t, tn, device1, bundleID)
	if row1.CVEAssessment.State != "assessed" {
		t.Fatalf("device 1 state before device 2 exists = %q, want assessed", row1.CVEAssessment.State)
	}

	// Device 2 installs the same product but is never drained: it stays
	// queued/pending.
	postAppsPayload(t, tn, hw2, []cveTestApp{{appName, "1.5", bundleID}})
	device2 := deviceIDByHW(t, tn.tenantID, hw2)

	// Device 1's own device-scoped assessment must still read assessed —
	// device 2's incompleteness must not leak onto device 1's page.
	row1Again := fetchPortalSoftwareProductForDevice(t, tn, device1, bundleID)
	if row1Again.CVEAssessment.State != "assessed" {
		t.Fatalf("device 1 state after device 2 joined queued = %q, want still assessed (device-scoped, not estate rollup)", row1Again.CVEAssessment.State)
	}

	// Device 2's own device-scoped assessment must read pending — it must
	// not borrow device 1's clean, matched state.
	row2 := fetchPortalSoftwareProductForDevice(t, tn, device2, bundleID)
	if row2.CVEAssessment.State != "pending" {
		t.Fatalf("device 2 state = %q, want pending (its own installation is still queued)", row2.CVEAssessment.State)
	}
}

// TestPortalSoftwareDeviceIDCVEAssessmentUnmappedStaysNotAssessedNullCount
// (PAT-2156 + PAT-2028) proves a device-scoped row for a product with no CPE
// mapping anywhere reads not_assessed with a NULL finding_count, never 0 —
// "absence requires authority" applies identically on the device-scoped
// path as it does on the estate-wide one (see
// TestPortalSoftwareCVEAssessmentUnmappedProductNotAssessedWithNullCount in
// portal_software_cve_test.go).
func TestPortalSoftwareDeviceIDCVEAssessmentUnmappedStaysNotAssessedNullCount(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2156-device-unmapped-"+sfx)
	appName := "Pat2156 Inhouse " + sfx
	bundleID := "com.example.pat2156.inhouse." + sfx

	hw := strings.ToUpper(sfx + "-eeee-1111-2222-333344445555")
	postAppsPayload(t, tn, hw, []cveTestApp{{appName, "3.1", bundleID}})
	drainCVEQueue(t) // nothing to drain; unmapped products are never queued

	device := deviceIDByHW(t, tn.tenantID, hw)
	row := fetchPortalSoftwareProductForDevice(t, tn, device, bundleID)
	if row.CVEAssessment.State != "not_assessed" {
		t.Fatalf("state = %q, want not_assessed", row.CVEAssessment.State)
	}
	if row.CVEAssessment.FindingCount != nil {
		t.Fatalf("finding_count = %v, want null for not_assessed, never 0", row.CVEAssessment.FindingCount)
	}
}

// fetchPortalSoftwareProductForDevice is fetchPortalSoftwareProduct
// (portal_software_cve_test.go) with an added device_id filter.
func fetchPortalSoftwareProductForDevice(t *testing.T, tn cveTestTenant, deviceID, bundleID string) portalSoftwareCVERow {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/software?device_id="+deviceID+"&search="+bundleID, tn.token, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/portal/software?device_id=%s: %d %s", deviceID, resp.StatusCode, raw)
	}
	var out struct {
		Products []portalSoftwareCVERow `json:"products"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode /v1/portal/software: %v; body %s", err, raw)
	}
	var matches []portalSoftwareCVERow
	for _, p := range out.Products {
		if p.Identifier == bundleID {
			matches = append(matches, p)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("GET /v1/portal/software?device_id=%s&search=%s returned %d rows for that identifier, want 1; body %s", deviceID, bundleID, len(matches), raw)
	}
	return matches[0]
}
