//go:build integration

package integration

// PAT-2324: the portal tells servers from workstations. Both
// GET /v1/portal/devices and GET /v1/portal/devices/{id} carry device_class
// (server, workstation or unknown) and os_caption (string or null), from one
// derivation. These tests drive the real routes against seeded rows and lock:
//
//   - a stored server or workstation is returned as stored, with its caption;
//   - a Mac with no stored class reads workstation, with a null caption,
//     because macOS has no server edition (derived by OS family, not collected);
//   - a Windows device with no stored class stays unknown;
//   - the device page and the roster agree for every device;
//   - a Mac's existing response fields are unchanged.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

type deviceClassSeed struct {
	hostname string
	os       string
	class    string  // stored devices.device_class
	caption  *string // stored devices.os_caption, nil = SQL NULL
	wantCls  string
	wantCap  *string
}

func deviceClassSeeds() []deviceClassSeed {
	s := func(v string) *string { return &v }
	return []deviceClassSeed{
		{"dc-win-server", "Windows", "server", s("Microsoft Windows Server 2022 Standard"), "server", s("Microsoft Windows Server 2022 Standard")},
		{"dc-win-workstation", "Windows", "workstation", s("Microsoft Windows 11 Enterprise"), "workstation", s("Microsoft Windows 11 Enterprise")},
		{"dc-mac-unknown", "macOS", "unknown", nil, "workstation", nil},
		{"dc-win-unknown", "Windows", "unknown", nil, "unknown", nil},
	}
}

type deviceClassFields struct {
	DeviceClass *string `json:"device_class"`
	OSCaption   *string `json:"os_caption"`
}

func seedDeviceClassTenant(t *testing.T, name string) (token string, deviceIDs map[string]string) {
	t.Helper()
	ctx := context.Background()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	cleanupTestTenant(t, tenantID)
	email := "viewer@" + name + ".example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)

	deviceIDs = map[string]string{}
	now := time.Now().UTC()
	for _, sd := range deviceClassSeeds() {
		var id string
		if err := env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen, device_class, os_caption)
			VALUES ($1::uuid, $2, gen_random_uuid(), $2, $3, '15.5', '24F74', 'arm64', $4, $5, $6)
			RETURNING id::text
		`, tenantID, sd.hostname, sd.os, now.Add(-time.Minute), sd.class, sd.caption).Scan(&id); err != nil {
			t.Fatalf("seed device %s: %v", sd.hostname, err)
		}
		deviceIDs[sd.hostname] = id
	}
	return env.idp.token(t, email), deviceIDs
}

func sameStrPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func strPtrStr(p *string) string {
	if p == nil {
		return "null"
	}
	return `"` + *p + `"`
}

// TestPortalDevicesCarryDeviceClassAndCaption covers the roster half.
func TestPortalDevicesCarryDeviceClassAndCaption(t *testing.T) {
	token, _ := seedDeviceClassTenant(t, "pat2324-roster")

	resp := portalDo(t, http.MethodGet, "/v1/portal/devices?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET /v1/portal/devices = %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Devices []map[string]json.RawMessage `json:"devices"`
	}
	decodeJSON(t, resp, &out)
	byHost := map[string]map[string]json.RawMessage{}
	for _, d := range out.Devices {
		var host string
		if err := json.Unmarshal(d["hostname"], &host); err != nil {
			t.Fatalf("decode hostname: %v", err)
		}
		byHost[host] = d
	}

	for _, sd := range deviceClassSeeds() {
		row, ok := byHost[sd.hostname]
		if !ok {
			t.Errorf("%s missing from roster", sd.hostname)
			continue
		}
		// null is allowed for os_caption, absent is not.
		for _, key := range []string{"device_class", "os_caption"} {
			if _, ok := row[key]; !ok {
				t.Errorf("roster %s: %s is absent, want present", sd.hostname, key)
			}
		}
		var got deviceClassFields
		if err := json.Unmarshal(row["device_class"], &got.DeviceClass); err != nil {
			t.Errorf("roster %s: decode device_class %s: %v", sd.hostname, row["device_class"], err)
		}
		if err := json.Unmarshal(row["os_caption"], &got.OSCaption); err != nil {
			t.Errorf("roster %s: decode os_caption %s: %v", sd.hostname, row["os_caption"], err)
		}
		if got.DeviceClass == nil || *got.DeviceClass != sd.wantCls {
			t.Errorf("roster %s device_class = %s, want %q", sd.hostname, strPtrStr(got.DeviceClass), sd.wantCls)
		}
		if !sameStrPtr(got.OSCaption, sd.wantCap) {
			t.Errorf("roster %s os_caption = %s, want %s", sd.hostname, strPtrStr(got.OSCaption), strPtrStr(sd.wantCap))
		}
	}
}

// TestPortalDeviceDetailCarriesDeviceClassAndCaption covers the device page:
// each device's device_class and os_caption equal the expected values and the
// same device's roster row.
func TestPortalDeviceDetailCarriesDeviceClassAndCaption(t *testing.T) {
	token, ids := seedDeviceClassTenant(t, "pat2324-detail")

	resp := portalDo(t, http.MethodGet, "/v1/portal/devices?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET /v1/portal/devices = %d: %s", resp.StatusCode, body)
	}
	var roster struct {
		Devices []struct {
			Hostname string `json:"hostname"`
			deviceClassFields
		} `json:"devices"`
	}
	decodeJSON(t, resp, &roster)
	rosterByHost := map[string]deviceClassFields{}
	for _, d := range roster.Devices {
		rosterByHost[d.Hostname] = d.deviceClassFields
	}

	for _, sd := range deviceClassSeeds() {
		resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+ids[sd.hostname], token, nil)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("GET detail %s = %d: %s", sd.hostname, resp.StatusCode, body)
		}
		var detail struct {
			Device map[string]json.RawMessage `json:"device"`
		}
		decodeJSON(t, resp, &detail)

		for _, key := range []string{"device_class", "os_caption"} {
			if _, ok := detail.Device[key]; !ok {
				t.Errorf("detail %s: device.%s is absent, want present (null is allowed for os_caption, absent is not)", sd.hostname, key)
			}
		}
		var got deviceClassFields
		if raw, ok := detail.Device["device_class"]; ok {
			if err := json.Unmarshal(raw, &got.DeviceClass); err != nil {
				t.Errorf("detail %s: decode device_class %s: %v", sd.hostname, raw, err)
			}
		}
		if raw, ok := detail.Device["os_caption"]; ok {
			if err := json.Unmarshal(raw, &got.OSCaption); err != nil {
				t.Errorf("detail %s: decode os_caption %s: %v", sd.hostname, raw, err)
			}
		}
		if got.DeviceClass == nil || *got.DeviceClass != sd.wantCls {
			t.Errorf("detail %s device_class = %s, want %q", sd.hostname, strPtrStr(got.DeviceClass), sd.wantCls)
		}
		if !sameStrPtr(got.OSCaption, sd.wantCap) {
			t.Errorf("detail %s os_caption = %s, want %s", sd.hostname, strPtrStr(got.OSCaption), strPtrStr(sd.wantCap))
		}

		want := rosterByHost[sd.hostname]
		if !sameStrPtr(got.DeviceClass, want.DeviceClass) {
			t.Errorf("detail %s device_class = %s, roster says %s", sd.hostname, strPtrStr(got.DeviceClass), strPtrStr(want.DeviceClass))
		}
		if !sameStrPtr(got.OSCaption, want.OSCaption) {
			t.Errorf("detail %s os_caption = %s, roster says %s", sd.hostname, strPtrStr(got.OSCaption), strPtrStr(want.OSCaption))
		}
	}
}

// TestPortalMacDeviceResponseOtherwiseUnchanged pins a Mac's pre-existing
// fields on both endpoints, so adding device_class and os_caption changed
// nothing else about the response.
func TestPortalMacDeviceResponseOtherwiseUnchanged(t *testing.T) {
	token, ids := seedDeviceClassTenant(t, "pat2324-mac")

	type macFields struct {
		DeviceID     string          `json:"device_id"`
		Hostname     string          `json:"hostname"`
		Platform     string          `json:"platform"`
		OSVersion    string          `json:"os_version"`
		CISScore     float64         `json:"cis_score"`
		FindingsOpen *int            `json:"findings_open"`
		EncryptionOK *bool           `json:"encryption_ok"`
		PatchPending *bool           `json:"patch_pending"`
		Retirement   json.RawMessage `json:"retirement"`
	}
	check := func(where string, got macFields) {
		t.Helper()
		if got.DeviceID != ids["dc-mac-unknown"] {
			t.Errorf("%s device_id = %q, want %q", where, got.DeviceID, ids["dc-mac-unknown"])
		}
		if got.Hostname != "dc-mac-unknown" {
			t.Errorf("%s hostname = %q", where, got.Hostname)
		}
		if got.Platform != "macOS" {
			t.Errorf("%s platform = %q, want macOS", where, got.Platform)
		}
		if got.OSVersion != "15.5" {
			t.Errorf("%s os_version = %q, want 15.5", where, got.OSVersion)
		}
		if got.CISScore != 0 {
			t.Errorf("%s cis_score = %v, want 0 (no evaluations)", where, got.CISScore)
		}
		if got.FindingsOpen == nil || *got.FindingsOpen != 0 {
			t.Errorf("%s findings_open = %s, want 0", where, intStr(got.FindingsOpen))
		}
		if got.EncryptionOK != nil {
			t.Errorf("%s encryption_ok = %s, want null", where, boolStr(got.EncryptionOK))
		}
		if got.PatchPending != nil {
			t.Errorf("%s patch_pending = %s, want null", where, boolStr(got.PatchPending))
		}
		if string(got.Retirement) != "null" {
			t.Errorf("%s retirement = %s, want null", where, got.Retirement)
		}
	}

	resp := portalDo(t, http.MethodGet, "/v1/portal/devices?limit=500", token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET /v1/portal/devices = %d: %s", resp.StatusCode, body)
	}
	var roster struct {
		Devices []macFields `json:"devices"`
	}
	decodeJSON(t, resp, &roster)
	found := false
	for _, d := range roster.Devices {
		if d.Hostname == "dc-mac-unknown" {
			found = true
			check("roster", d)
		}
	}
	if !found {
		t.Fatal("mac device missing from roster")
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/devices/"+ids["dc-mac-unknown"], token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET detail = %d: %s", resp.StatusCode, body)
	}
	var detail struct {
		Device macFields `json:"device"`
	}
	decodeJSON(t, resp, &detail)
	check("detail", detail.Device)
}
