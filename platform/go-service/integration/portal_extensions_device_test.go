//go:build integration

// PAT-2156: GET /v1/portal/extensions?device_id=<uuid>. Platform half of the
// device-page Software view's Browser extensions tab. Red-proof against the
// pre-PAT-2156 handler: it has no device_id parameter, no ownership check,
// and portalExtensionsQuery has no device predicate at all — every
// assertion below fails against that code (an unknown query key is ignored,
// so the request would just run the unfiltered, whole-tenant aggregation
// and return both devices; a malformed or cross-tenant id would 200 the
// same unfiltered page instead of 400/404).
package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type portalExtensionDeviceFilterOut struct {
	Total      int `json:"total"`
	Extensions []struct {
		ExtensionID   string   `json:"extension_id"`
		Name          string   `json:"name"`
		Browser       string   `json:"browser"`
		DeviceCount   int      `json:"device_count"`
		Versions      []string `json:"versions"`
		ApprovalState string   `json:"approval_state"`
		Devices       []struct {
			DeviceID string `json:"device_id"`
			Hostname string `json:"hostname"`
		} `json:"devices"`
	} `json:"extensions"`
}

func seedPortalExtensionDevice(t *testing.T, tenantID, hostname string) string {
	t.Helper()
	ctx := context.Background()
	var deviceID string
	err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $2, 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID, "SER-ext-device-"+hostname).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device %s: %v", hostname, err)
	}
	return deviceID
}

func seedPortalExtension(t *testing.T, deviceID, extensionID, name, browser, version string) {
	t.Helper()
	_, err := env.pool.Exec(context.Background(), `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, $2, 'user', 'Default', $3, $4, $5, 'normal')
	`, deviceID, browser, extensionID, name, version)
	if err != nil {
		t.Fatalf("seed extension %s on device %s: %v", extensionID, deviceID, err)
	}
}

// TestPortalExtensionsDeviceIDFilterReturnsOnlyThatDevicesRows seeds two
// devices with disjoint extensions and asserts the device_id filter returns
// only the targeted device's extensions, while the unfiltered page still
// sees both.
func TestPortalExtensionsDeviceIDFilterReturnsOnlyThatDevicesRows(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-device-filter")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	deviceA := seedPortalExtensionDevice(t, tenantID, "ext-filter-a")
	seedPortalExtension(t, deviceA, "ext-filter-alpha-id", "AlphaExtension", "chrome", "1.0.0")
	deviceB := seedPortalExtensionDevice(t, tenantID, "ext-filter-b")
	seedPortalExtension(t, deviceB, "ext-filter-beta-id", "BetaExtension", "chrome", "2.0.0")

	email := "ext-device-filter@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	// Unfiltered baseline: both extensions visible.
	baseResp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if baseResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(baseResp.Body)
		t.Fatalf("baseline extensions = %d: %s", baseResp.StatusCode, body)
	}
	var baseline portalExtensionDeviceFilterOut
	decodeJSON(t, baseResp, &baseline)
	if baseline.Total != 2 {
		t.Fatalf("baseline total = %d, want 2 (both devices' extensions)", baseline.Total)
	}

	// device_id=deviceA: only AlphaExtension.
	filteredResp := portalDo(t, http.MethodGet, "/v1/portal/extensions?device_id="+deviceA, token, nil)
	if filteredResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(filteredResp.Body)
		t.Fatalf("device-filtered extensions = %d: %s", filteredResp.StatusCode, body)
	}
	var filtered portalExtensionDeviceFilterOut
	decodeJSON(t, filteredResp, &filtered)
	if filtered.Total != 1 || len(filtered.Extensions) != 1 {
		t.Fatalf("device-filtered total/len = %d/%d, want 1/1", filtered.Total, len(filtered.Extensions))
	}
	ext := filtered.Extensions[0]
	if ext.ExtensionID != "ext-filter-alpha-id" {
		t.Errorf("extension_id = %q, want ext-filter-alpha-id (device A's own extension)", ext.ExtensionID)
	}
	if ext.DeviceCount != 1 {
		t.Errorf("device_count = %d, want 1 (scoped to the filtered device)", ext.DeviceCount)
	}
	for _, d := range ext.Devices {
		if d.DeviceID != deviceA {
			t.Errorf("devices drill-down leaked device %s into a device_id=%s filtered response", d.DeviceID, deviceA)
		}
	}

	// device_id=deviceB: symmetric proof, only BetaExtension.
	otherResp := portalDo(t, http.MethodGet, "/v1/portal/extensions?device_id="+deviceB, token, nil)
	if otherResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(otherResp.Body)
		t.Fatalf("device B filtered extensions = %d: %s", otherResp.StatusCode, body)
	}
	var otherPage portalExtensionDeviceFilterOut
	decodeJSON(t, otherResp, &otherPage)
	if otherPage.Total != 1 || len(otherPage.Extensions) != 1 || otherPage.Extensions[0].ExtensionID != "ext-filter-beta-id" {
		t.Fatalf("device B filtered page = %+v, want exactly ext-filter-beta-id", otherPage)
	}
}

// TestPortalExtensionsDeviceIDCrossTenantIs404WithNoRowData mirrors the
// software endpoint's cross-tenant proof: another tenant's device_id (and a
// syntactically valid but wholly nonexistent one) both answer 404 with no
// extension data leaked into the body.
func TestPortalExtensionsDeviceIDCrossTenantIs404WithNoRowData(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-device-cross-a")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	otherTenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-device-cross-b")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	cleanupTestTenant(t, otherTenantID)

	otherDevice := seedPortalExtensionDevice(t, otherTenantID, "ext-cross-other")
	seedPortalExtension(t, otherDevice, "ext-cross-secret-id", "OtherTenantSecretExtension", "chrome", "1.0.0")

	email := "ext-device-cross@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions?device_id="+otherDevice, token, nil)
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("cross-tenant device_id = %d, want 404: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "ext-cross-secret-id") || strings.Contains(string(body), "OtherTenantSecretExtension") {
		t.Errorf("404 response leaks the other tenant's extension data: %s", body)
	}

	unknownDevice := "00000000-0000-0000-0000-000000000000"
	resp2 := portalDo(t, http.MethodGet, "/v1/portal/extensions?device_id="+unknownDevice, token, nil)
	if resp2.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("nonexistent device_id = %d, want 404: %s", resp2.StatusCode, body)
	}
}

// TestPortalExtensionsDeviceIDMalformedIs400 proves a non-UUID device_id is
// rejected before any ownership or extensions query runs.
func TestPortalExtensionsDeviceIDMalformedIs400(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-device-malformed")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	email := "ext-device-malformed@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	for _, bad := range []string{"not-a-uuid", "12345", "'; DROP TABLE device_browser_extensions; --"} {
		resp := portalDo(t, http.MethodGet, "/v1/portal/extensions?device_id="+bad, token, nil)
		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("device_id=%q = %d, want 400: %s", bad, resp.StatusCode, body)
		}
	}
}

// TestPortalExtensionsDeviceIDVersionAndDeviceCountsScopedToDevice proves
// device_count/versions for a device-filtered row reflect only that
// device's own reported version, not an estate-wide aggregate — the same
// extension_id/browser pair reported at two different versions on two
// devices must NOT show both versions or device_count=2 when the request is
// scoped to just one of them.
func TestPortalExtensionsDeviceIDVersionAndDeviceCountsScopedToDevice(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-device-scoped-counts")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)

	deviceA := seedPortalExtensionDevice(t, tenantID, "ext-scoped-a")
	seedPortalExtension(t, deviceA, "ext-scoped-shared-id", "SharedExtension", "chrome", "1.0.0")
	deviceB := seedPortalExtensionDevice(t, tenantID, "ext-scoped-b")
	seedPortalExtension(t, deviceB, "ext-scoped-shared-id", "SharedExtension", "chrome", "2.0.0")

	email := fmt.Sprintf("ext-device-scoped-%p@example.test", t)
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	// Sanity: unfiltered page aggregates both devices onto one row.
	baseResp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	var baseline portalExtensionDeviceFilterOut
	decodeJSON(t, baseResp, &baseline)
	if baseline.Total != 1 || len(baseline.Extensions) != 1 || baseline.Extensions[0].DeviceCount != 2 {
		t.Fatalf("baseline = %+v, want one aggregated row with device_count=2", baseline)
	}

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions?device_id="+deviceA, token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("device-filtered extensions = %d: %s", resp.StatusCode, body)
	}
	var out portalExtensionDeviceFilterOut
	decodeJSON(t, resp, &out)
	if out.Total != 1 || len(out.Extensions) != 1 {
		t.Fatalf("device-filtered total/len = %d/%d, want 1/1", out.Total, len(out.Extensions))
	}
	ext := out.Extensions[0]
	if ext.DeviceCount != 1 {
		t.Errorf("device_count = %d, want 1 (device A only, not the tenant-wide 2)", ext.DeviceCount)
	}
	if len(ext.Versions) != 1 || ext.Versions[0] != "1.0.0" {
		t.Errorf("versions = %v, want exactly [\"1.0.0\"] (device A's own version, not device B's 2.0.0 too)", ext.Versions)
	}
}
