//go:build integration

package integration

// PAT-2013: a real-shaped Homebrew block goes in through POST /v1/inventory,
// through the extractor, and comes back out through every
// /v1/portal/homebrew/* view, tenant-scoped.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"patched.im/api/internal/extractor"
)

// homebrewPayload returns the complete-block fixture with its device renamed
// and a Firefox app bundle added at the path Homebrew moves the cask to.
func homebrewPayload(t *testing.T, serial, hostname string, mutate func(hb map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixtureData(t, "valid", "with-homebrew-complete-macos.json"), &m); err != nil {
		t.Fatal(err)
	}
	device := m["device"].(map[string]any)
	device["serial"], device["hostname"] = serial, hostname
	device["hw_uuid"] = "PAT2013-" + serial
	m["apps"] = append(m["apps"].([]any), map[string]any{
		"name": "Firefox", "version": "143.0", "bundle_id": "org.mozilla.firefox",
		"team_id": "43AQ936H96", "path": "/Applications/Firefox.app",
	})
	if mutate != nil {
		mutate(m["homebrew"].(map[string]any))
	}
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// postInventoryAs signs body with another tenant's credentials.
func postInventoryAs(t *testing.T, bearer string, secret []byte, body []byte) int64 {
	t.Helper()
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", randomHex(16))
	resp := postInventory(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/inventory = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		RawPayloadID int64 `json:"raw_payload_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if err := extractor.ProcessOnce(context.Background(), env.pool); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	assertNoExtractionError(t, out.RawPayloadID)
	return out.RawPayloadID
}

func portalGetJSON(t *testing.T, token, path string, out any) {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, body)
	}
	decodeJSON(t, resp, out)
}

type hbIdentityOut struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Tap  string `json:"tap"`
}

type hbSummaryOut struct {
	MacOSDeviceCount    int `json:"macos_device_count"`
	DevicesWithHomebrew int `json:"devices_with_homebrew"`
	DeviceStatus        struct {
		Complete    int `json:"complete"`
		Partial     int `json:"partial"`
		NotPresent  int `json:"not_present"`
		Failed      int `json:"failed"`
		NotReported int `json:"not_reported"`
	} `json:"device_status"`
	FormulaCount                    int `json:"formula_count"`
	FormulaOnRequestCount           int `json:"formula_on_request_count"`
	CaskCount                       int `json:"cask_count"`
	CaskInstallationCount           int `json:"cask_installation_count"`
	LinkedCaskInstallationCount     int `json:"linked_cask_installation_count"`
	TapCount                        int `json:"tap_count"`
	ThirdPartyTapCount              int `json:"third_party_tap_count"`
	EstateSoftwareInstallationCount int `json:"estate_software_installation_count"`
}

type hbFormulaeOut struct {
	Total               int  `json:"total"`
	Limit               int  `json:"limit"`
	Offset              int  `json:"offset"`
	IncludeDependencies bool `json:"include_dependencies"`
	Formulae            []struct {
		Identity             hbIdentityOut `json:"identity"`
		Name                 string        `json:"name"`
		Tap                  *string       `json:"tap"`
		ThirdPartyTap        bool          `json:"third_party_tap"`
		Versions             []string      `json:"versions"`
		DeviceCount          int           `json:"device_count"`
		OnRequestDeviceCount int           `json:"on_request_device_count"`
		Homepage             *string       `json:"homepage"`
		SourceURL            *string       `json:"source_url"`
		FirstSeenAt          *time.Time    `json:"first_seen_at"`
	} `json:"formulae"`
}

type hbCasksOut struct {
	Total int `json:"total"`
	Casks []struct {
		Identity             hbIdentityOut `json:"identity"`
		Token                string        `json:"token"`
		Versions             []string      `json:"versions"`
		DeviceCount          int           `json:"device_count"`
		LinkedAppDeviceCount int           `json:"linked_app_device_count"`
		AppNames             []string      `json:"app_names"`
	} `json:"casks"`
}

type hbTapsOut struct {
	Total int `json:"total"`
	Taps  []struct {
		Name        string   `json:"name"`
		ThirdParty  bool     `json:"third_party"`
		RemoteURLs  []string `json:"remote_urls"`
		DeviceCount int      `json:"device_count"`
	} `json:"taps"`
}

type hbDevicesOut struct {
	Total   int `json:"total"`
	Devices []struct {
		DeviceID         string          `json:"device_id"`
		Hostname         *string         `json:"hostname"`
		CollectionStatus string          `json:"collection_status"`
		Prefixes         json.RawMessage `json:"prefixes"`
		FormulaCount     int             `json:"formula_count"`
		CaskCount        int             `json:"cask_count"`
		TapCount         int             `json:"tap_count"`
	} `json:"devices"`
}

type hbDeviceOut struct {
	Total int `json:"total"`
	State struct {
		CollectionStatus string `json:"collection_status"`
	} `json:"state"`
	Entries []struct {
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Prefix     string `json:"prefix"`
		LinkedApps []struct {
			Path      string `json:"path"`
			LinkBasis string `json:"link_basis"`
		} `json:"linked_apps"`
	} `json:"entries"`
}

func TestHomebrewIngestToPortalEndToEnd(t *testing.T) {
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, "pat2013-homebrew")
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantID)
	otherTenantID, otherBearer, otherSecret, err := createTestTenant(env.internalSrv.URL, "pat2013-homebrew-other")
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, otherTenantID)

	// Device A: the complete fixture plus Firefox.app. Device B: failed.
	postInventoryAs(t, bearer, secret, homebrewPayload(t, "PAT2013-A", "pat2013-a", nil))
	postInventoryAs(t, bearer, secret, homebrewPayload(t, "PAT2013-B", "pat2013-b", func(hb map[string]any) {
		for k := range hb {
			delete(hb, k)
		}
		hb["collection_status"] = "failed"
	}))
	// Another tenant with a formula that must never leak.
	postInventoryAs(t, otherBearer, otherSecret, homebrewPayload(t, "PAT2013-X", "pat2013-x", func(hb map[string]any) {
		hb["formulae"] = []any{map[string]any{
			"prefix": "/opt/homebrew", "name": "leaky-secret-tool", "version": "1.0", "tap": "evil/tap",
			"installed_on_request": true, "installed_as_dependency": false, "installed_at": nil,
			"runtime_dependencies": []any{}, "homepage": nil, "source_url": nil, "opt_linked": true,
			"receipt_status": "read", "formula_file_status": "missing",
		}}
		hb["taps"] = []any{map[string]any{"prefix": "/opt/homebrew", "name": "evil/tap",
			"directory": "evil/homebrew-tap", "remote_url": nil, "config_status": "missing"}}
	}))

	email := "pat2013-homebrew@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)
	otherEmail := "pat2013-homebrew-other@example.test"
	mapPortalUser(t, otherEmail, otherTenantID, http.StatusCreated)
	otherToken := env.idp.token(t, otherEmail)

	// Summary: one Mac with Homebrew, one failed; the linked cask counts once.
	var summary hbSummaryOut
	portalGetJSON(t, token, "/v1/portal/homebrew/summary", &summary)
	if summary.DevicesWithHomebrew != 1 || summary.DeviceStatus.Complete != 1 || summary.DeviceStatus.Failed != 1 ||
		summary.DeviceStatus.NotPresent != 0 || summary.MacOSDeviceCount != 2 {
		t.Fatalf("summary devices = %+v", summary)
	}
	if summary.FormulaCount != 3 || summary.FormulaOnRequestCount != 2 || summary.CaskCount != 1 ||
		summary.LinkedCaskInstallationCount != 1 || summary.TapCount != 1 || summary.ThirdPartyTapCount != 1 {
		t.Fatalf("summary packages = %+v", summary)
	}
	// Device A: Safari, Firefox, 3 formulae and the firefox cask. Device B:
	// Safari, Firefox. Taps are not software. PAT-2032: the cask's link to
	// Firefox.app is a default_appdir guess, so it is shown (linked count 1)
	// but the cask is still counted rather than hidden.
	if summary.EstateSoftwareInstallationCount != 2+3+1+2 {
		t.Fatalf("estate software installations = %d, want 8 (a default_appdir link never hides the cask)", summary.EstateSoftwareInstallationCount)
	}

	// Formulae: dependencies hidden by default, visible with the flag.
	var formulae hbFormulaeOut
	portalGetJSON(t, token, "/v1/portal/homebrew/formulae", &formulae)
	if formulae.Total != 2 || formulae.IncludeDependencies {
		t.Fatalf("default formulae = %+v, want 2 on-request only", formulae)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/formulae?include_dependencies=true&limit=1&offset=0", &formulae)
	if formulae.Total != 3 || len(formulae.Formulae) != 1 || formulae.Limit != 1 {
		t.Fatalf("paged formulae with dependencies = %+v", formulae)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/formulae?include_dependencies=true", &formulae)
	byName := map[string]int{}
	for i, f := range formulae.Formulae {
		byName[f.Name] = i
	}
	acme := formulae.Formulae[byName["acme-cli"]]
	if !acme.ThirdPartyTap || acme.Tap == nil || *acme.Tap != "acme/tools" ||
		acme.Identity != (hbIdentityOut{Kind: "homebrew_formula", Name: "acme-cli", Tap: "acme/tools"}) ||
		acme.SourceURL == nil || acme.FirstSeenAt == nil {
		t.Fatalf("acme-cli = %+v", acme)
	}
	openssl := formulae.Formulae[byName["openssl@3"]]
	if openssl.ThirdPartyTap || len(openssl.Versions) != 1 || openssl.Versions[0] != "3.5.2" || openssl.DeviceCount != 1 {
		t.Fatalf("openssl@3 = %+v", openssl)
	}
	resp := portalDo(t, http.MethodGet, "/v1/portal/homebrew/formulae?include_dependencies=maybe", token, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad include_dependencies = %d, want 400", resp.StatusCode)
	}

	// Casks: linked to the Firefox bundle.
	var casks hbCasksOut
	portalGetJSON(t, token, "/v1/portal/homebrew/casks", &casks)
	if casks.Total != 1 || casks.Casks[0].Token != "firefox" || casks.Casks[0].LinkedAppDeviceCount != 1 ||
		len(casks.Casks[0].AppNames) != 1 || casks.Casks[0].AppNames[0] != "Firefox.app" {
		t.Fatalf("casks = %+v", casks)
	}

	// Taps: core hidden by default, third party flagged.
	var taps hbTapsOut
	portalGetJSON(t, token, "/v1/portal/homebrew/taps", &taps)
	if taps.Total != 1 || taps.Taps[0].Name != "acme/tools" || !taps.Taps[0].ThirdParty ||
		len(taps.Taps[0].RemoteURLs) != 1 {
		t.Fatalf("taps = %+v", taps)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/taps?include_core=true", &taps)
	if taps.Total != 2 {
		t.Fatalf("taps with core = %+v", taps)
	}

	// Per device: both Macs listed with distinct statuses; A has its list.
	var devices hbDevicesOut
	portalGetJSON(t, token, "/v1/portal/homebrew/devices", &devices)
	if devices.Total != 2 {
		t.Fatalf("devices = %+v", devices)
	}
	var deviceA string
	statuses := map[string]string{}
	for _, d := range devices.Devices {
		statuses[*d.Hostname] = d.CollectionStatus
		if *d.Hostname == "pat2013-a" {
			deviceA = d.DeviceID
			if d.FormulaCount != 3 || d.CaskCount != 1 || d.TapCount != 2 || !bytes.Contains(d.Prefixes, []byte(`"owner":"alice"`)) {
				t.Fatalf("device A = %+v (prefixes %s)", d, d.Prefixes)
			}
		}
	}
	if statuses["pat2013-a"] != "complete" || statuses["pat2013-b"] != "failed" {
		t.Fatalf("device statuses = %v", statuses)
	}
	var detail hbDeviceOut
	portalGetJSON(t, token, "/v1/portal/homebrew/devices/"+deviceA, &detail)
	if detail.Total != 6 || detail.State.CollectionStatus != "complete" {
		t.Fatalf("device A detail total=%d status=%s", detail.Total, detail.State.CollectionStatus)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/devices/"+deviceA+"?kind=cask", &detail)
	if detail.Total != 1 || len(detail.Entries[0].LinkedApps) != 1 ||
		detail.Entries[0].LinkedApps[0].Path != "/Applications/Firefox.app" ||
		detail.Entries[0].LinkedApps[0].LinkBasis != "default_appdir" {
		t.Fatalf("device A casks = %+v", detail)
	}

	// Tenant isolation: the other tenant sees only its own formula, and
	// neither tenant can open the other's device.
	var otherFormulae hbFormulaeOut
	portalGetJSON(t, otherToken, "/v1/portal/homebrew/formulae", &otherFormulae)
	if otherFormulae.Total != 1 || otherFormulae.Formulae[0].Name != "leaky-secret-tool" {
		t.Fatalf("other tenant formulae = %+v", otherFormulae)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/formulae?include_dependencies=true&search=leaky", &formulae)
	if formulae.Total != 0 {
		t.Fatalf("tenant saw another tenant's formula: %+v", formulae)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/taps?include_core=true", &taps)
	for _, tp := range taps.Taps {
		if tp.Name == "evil/tap" {
			t.Fatal("tenant saw another tenant's tap")
		}
	}
	var otherSummary hbSummaryOut
	portalGetJSON(t, otherToken, "/v1/portal/homebrew/summary", &otherSummary)
	if otherSummary.DevicesWithHomebrew != 1 || otherSummary.DeviceStatus.Failed != 0 || otherSummary.CaskCount != 1 {
		t.Fatalf("other tenant summary = %+v", otherSummary)
	}
	resp = portalDo(t, http.MethodGet, "/v1/portal/homebrew/devices/"+deviceA, otherToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant device detail = %d, want 404", resp.StatusCode)
	}
	resp = portalDo(t, http.MethodGet, "/v1/portal/homebrew/summary", "", nil)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("unauthenticated summary returned 200")
	}

	// A later partial report that omits packages removes nothing from the
	// portal view; a not_present report clears it.
	postInventoryAs(t, bearer, secret, homebrewPayload(t, "PAT2013-A", "pat2013-a", func(hb map[string]any) {
		hb["collection_status"] = "partial"
		hb["truncated"] = true
		hb["truncation_reason"] = "time_limit"
		hb["formulae"] = []any{}
		hb["casks"] = []any{}
		hb["taps"] = []any{}
	}))
	portalGetJSON(t, token, "/v1/portal/homebrew/devices/"+deviceA, &detail)
	if detail.Total != 6 || detail.State.CollectionStatus != "partial" {
		t.Fatalf("partial report changed the device list: total=%d status=%s", detail.Total, detail.State.CollectionStatus)
	}
	postInventoryAs(t, bearer, secret, homebrewPayload(t, "PAT2013-A", "pat2013-a", func(hb map[string]any) {
		hb["collection_status"] = "not_present"
		hb["prefixes"] = []any{}
		hb["formulae"] = []any{}
		hb["casks"] = []any{}
		hb["taps"] = []any{}
	}))
	portalGetJSON(t, token, "/v1/portal/homebrew/summary", &summary)
	if summary.DeviceStatus.NotPresent != 1 || summary.DevicesWithHomebrew != 0 || summary.FormulaCount != 0 ||
		summary.EstateSoftwareInstallationCount != 4 {
		t.Fatalf("summary after not_present = %+v", summary)
	}
	portalGetJSON(t, token, "/v1/portal/homebrew/devices/"+deviceA, &detail)
	if detail.Total != 0 || detail.State.CollectionStatus != "not_present" {
		t.Fatalf("not_present device detail = %+v", detail)
	}

}

// hbFormula is one real-shaped formula keg for a payload.
func hbFormula(name, version string, tap any, linked bool) map[string]any {
	return map[string]any{
		"prefix": "/opt/homebrew", "name": name, "version": version, "tap": tap,
		"installed_on_request": true, "installed_as_dependency": false, "installed_at": nil,
		"runtime_dependencies": []any{}, "homepage": nil, "source_url": nil, "opt_linked": linked,
		"receipt_status": "read", "formula_file_status": "read",
	}
}

// TestHomebrewPartialReportsNeverHideKegs (PAT-2032): a partial report
// only adds or refreshes kegs, since it may list a formula without having
// read every keg; a Mac that only ever reports partial shows every keg seen
// since its last authority. A complete report prunes. The byte-budget
// truncation reason is accepted end to end, and the portal read ignores any
// current entry older than the device's authority.
func TestHomebrewPartialReportsNeverHideKegs(t *testing.T) {
	ctx := context.Background()
	tenantID, bearer, secret, err := createTestTenant(env.internalSrv.URL, "pat2032-homebrew")
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantID)
	email := "pat2032-homebrew@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	block := func(status, reason string, formulae ...any) []byte {
		return homebrewPayload(t, "PAT2032-P", "pat2032-p", func(hb map[string]any) {
			hb["collection_status"] = status
			hb["truncated"] = reason != ""
			if reason != "" {
				hb["truncation_reason"] = reason
				hb["prefixes"].([]any)[0].(map[string]any)["collection_status"] = "partial"
			}
			hb["formulae"] = formulae
			hb["casks"] = []any{}
			hb["taps"] = []any{}
		})
	}
	versionsOf := func() map[string][]string {
		var formulae hbFormulaeOut
		portalGetJSON(t, token, "/v1/portal/homebrew/formulae?include_dependencies=true", &formulae)
		out := map[string][]string{}
		for _, f := range formulae.Formulae {
			out[f.Name] = f.Versions
		}
		return out
	}

	postInventoryAs(t, bearer, secret, block("partial", "time_limit",
		hbFormula("openssl@3", "3.5.1", "homebrew/core", true), hbFormula("curl", "8.0", "homebrew/core", true)))
	postInventoryAs(t, bearer, secret, block("partial", "size_limit", hbFormula("openssl@3", "3.5.2", "homebrew/core", true)))
	got := versionsOf()
	if fmt.Sprint(got["openssl@3"]) != "[3.5.1 3.5.2]" || fmt.Sprint(got["curl"]) != "[8.0]" || len(got) != 2 {
		t.Fatalf("partial-only device formulae = %v, want openssl@3 [3.5.1 3.5.2] and curl, nothing hidden", got)
	}

	// complete prunes what it did not list.
	postInventoryAs(t, bearer, secret, block("complete", "", hbFormula("openssl@3", "3.5.2", "homebrew/core", true)))
	got = versionsOf()
	if fmt.Sprint(got["openssl@3"]) != "[3.5.2]" || len(got) != 1 {
		t.Fatalf("after complete formulae = %v, want only openssl@3 [3.5.2]", got)
	}

	// A current entry older than the authority (what a race without the
	// ingest lock would leave) is never served.
	var deviceID string
	if err := env.pool.QueryRow(ctx, `SELECT id::text FROM devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO homebrew_current_entries (tenant_id, device_id, package_kind, prefix, name, version_key, observed_at, inventory_run_id)
		SELECT h.tenant_id, h.device_id, h.package_kind, h.prefix, h.name, h.version, h.observed_at, h.inventory_run_id
		FROM homebrew_observation_details h
		WHERE h.device_id = $1::uuid AND h.name = 'curl'
	`, deviceID); err != nil {
		t.Fatal(err)
	}
	if got := versionsOf(); len(got) != 1 {
		t.Fatalf("stale pre-authority entry served: %v", got)
	}
}
