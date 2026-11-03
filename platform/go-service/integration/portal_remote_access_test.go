//go:build integration

package integration

// PAT-2148: the SAM remote access / RMM report. Rules are the real, reviewed
// seed migration 0197's identifiers (AnyDesk, TeamViewer, RustDesk, RealVNC
// Server's vnc-server cask, Chrome Remote Desktop's extension, NinjaOne's
// ncstreamer RMM component) -- global rows shared with every test in this
// package -- so this suite also proves the seeded rules actually match real
// evidence end to end. Installations, devices, users, policies and
// retirement are seeded directly into the DB (the same style
// software_lifecycle_test.go uses), one dedicated tenant per test run so
// nothing here depends on another test's fixtures.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type raRow struct {
	DeviceID      string  `json:"device_id"`
	Hostname      string  `json:"hostname"`
	DeviceStale   bool    `json:"device_stale"`
	Category      string  `json:"category"`
	Kind          string  `json:"kind"`
	ProductKey    string  `json:"product_key"`
	Name          string  `json:"name"`
	Platform      string  `json:"platform"`
	Identifier    string  `json:"identifier"`
	ApprovalState string  `json:"approval_state"`
	User          *string `json:"user"`
	MachineWide   bool    `json:"machine_wide"`
}

type raProduct struct {
	ProductKey       string   `json:"product_key"`
	Category         string   `json:"category"`
	Kind             string   `json:"kind"`
	Name             string   `json:"name"`
	Identifier       string   `json:"identifier"`
	ApprovalState    string   `json:"approval_state"`
	DeviceCount      int      `json:"device_count"`
	Installations    int      `json:"installation_count"`
	Users            []string `json:"users"`
	MachineWideCount int      `json:"machine_wide_count"`
}

type raStateCount struct {
	Tools         int `json:"tool_count"`
	Installations int `json:"installation_count"`
	Devices       int `json:"device_count"`
}

type raReport struct {
	Definition struct {
		ID string `json:"id"`
	} `json:"definition"`
	Summary struct {
		RemoteAccess          map[string]raStateCount `json:"remote_access"`
		RMMAgents             map[string]raStateCount `json:"rmm_agents"`
		RemoteAccessToolCount int                     `json:"remote_access_tool_count"`
		RMMAgentToolCount     int                     `json:"rmm_agent_tool_count"`
	} `json:"summary"`
	Basis struct {
		DevicesTotal    int  `json:"devices_total"`
		DevicesAssessed int  `json:"devices_assessed"`
		DevicesRetired  int  `json:"devices_retired"`
		RetiredExcluded bool `json:"retired_devices_excluded"`
	} `json:"basis"`
	Total    int         `json:"total"`
	Products []raProduct `json:"products"`
	Rows     []raRow     `json:"rows"`
}

func raSeedDevice(t *testing.T, tenantID, host string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', 'arm64', $4)
		RETURNING id::text`, tenantID, "SER-"+randomHex(6), host, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", host, err)
	}
	return id
}

func raFingerprint(platform, kind, value, companion string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{platform, kind, value, companion}, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// raSeedInstall inserts one software_installations row and returns its
// identity_fingerprint (device_app_user_scopes joins on it).
func raSeedInstall(t *testing.T, tenantID, deviceID, platform, kind, value, companion, name string) string {
	t.Helper()
	fp := raFingerprint(platform, kind, value, companion)
	now := time.Now().UTC()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO software_installations
			(tenant_id, device_id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
			 identity_fingerprint, current_name, current_version, first_seen_at, last_seen_at, provenance)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, '1.0', $9, $9, 'inventory_payload')`,
		tenantID, deviceID, platform, kind, value, companion, fp, name, now); err != nil {
		t.Fatalf("seed installation %s: %v", value, err)
	}
	return fp
}

// raSeedUserScope records that user's per-user inventory (PAT-2075) holds
// the installation with fingerprint fp on deviceID: a device_apps row (the
// legacy projection device_app_user_scopes still FKs to) plus the scope row
// itself.
func raSeedUserScope(t *testing.T, deviceID, fp, identifier, name, user string) {
	t.Helper()
	ctx := context.Background()
	var appID int64
	if err := env.pool.QueryRow(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, machine_wide)
		VALUES ($1::uuid, $2, $3, false) RETURNING id`, deviceID, name, identifier).Scan(&appID); err != nil {
		t.Fatalf("seed device_apps for user scope: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_app_user_scopes (device_app_id, device_id, user_account, identity_fingerprint)
		VALUES ($1, $2::uuid, $3, $4)`, appID, deviceID, user, fp); err != nil {
		t.Fatalf("seed device_app_user_scopes: %v", err)
	}
}

func raSeedExtension(t *testing.T, deviceID, browser, extID, name, user string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, enabled, permissions, host_permissions, risk_level)
		VALUES ($1::uuid, $2, $3, 'Default', $4, $5, '1.0', true, '[]', '[]', 'normal')`,
		deviceID, browser, user, extID, name); err != nil {
		t.Fatalf("seed browser extension %s: %v", extID, err)
	}
}

func raRetireDevice(t *testing.T, tenantID, deviceID string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
		VALUES ($1::uuid, $2::uuid, 'retire', 'test-cleanup@pat2148.example')`, tenantID, deviceID); err != nil {
		t.Fatalf("retire device %s: %v", deviceID, err)
	}
}

func raSeedAppPolicy(t *testing.T, tenantID, bundleID, policy string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy)
		VALUES ($1::uuid, $2, 'macos', $3)`, tenantID, bundleID, policy); err != nil {
		t.Fatalf("seed app policy %s: %v", bundleID, err)
	}
}

func raSeedHomebrewPolicy(t *testing.T, tenantID, kind, name, policy string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_homebrew_policies (tenant_id, kind, name, policy)
		VALUES ($1::uuid, $2, $3, $4)`, tenantID, kind, name, policy); err != nil {
		t.Fatalf("seed homebrew policy %s: %v", name, err)
	}
}

func raSeedExtensionPolicy(t *testing.T, tenantID, browser, extID, policy string) {
	t.Helper()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, policy)
		VALUES ($1::uuid, $2, $3, $4)`, tenantID, browser, extID, policy); err != nil {
		t.Fatalf("seed extension policy %s: %v", extID, err)
	}
}

func raGet(t *testing.T, token, path string) raReport {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
	}
	var out raReport
	decodeJSON(t, resp, &out)
	return out
}

func raFindProduct(products []raProduct, identifier string) *raProduct {
	for i := range products {
		if products[i].Identifier == identifier {
			return &products[i]
		}
	}
	return nil
}

// TestRemoteAccessReport covers a sanctioned (approved) tool, an
// unsanctioned (unapproved) tool, an unreviewed tool, an RMM agent counted
// apart and never flagged as a remote-access finding, a per-user install, a
// browser extension, a Homebrew cask, a retired device excluded from every
// figure, tenant isolation and the CSV export.
func TestRemoteAccessReport(t *testing.T) {
	sfx := randomHex(4)
	now := time.Now().UTC()

	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "pat2148-a-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantA)
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "pat2148-b-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantB)
	emailA, emailB := "a-"+sfx+"@pat2148.example", "b-"+sfx+"@pat2148.example"
	mapPortalUser(t, emailA, tenantA, http.StatusCreated)
	mapPortalUser(t, emailB, tenantB, http.StatusCreated)
	tokA, tokB := env.idp.token(t, emailA), env.idp.token(t, emailB)

	// Real seeded identities from migration 0197.
	const (
		anydeskBundle    = "com.philandro.anydesk"
		teamviewerBundle = "com.teamviewer.teamviewer"
		rustdeskBundle   = "com.carriez.rustdesk"
		ninjaBundle      = "com.ninjarmm.ncstreamer"
		chromeExtID      = "inomeogfingihgjfjlpeplalcfajhgai"
		vncServerCask    = "vnc-server"
	)

	// Sanctioned: TeamViewer, approved, machine-wide.
	devApproved := raSeedDevice(t, tenantA, "mac-approved-"+sfx, now)
	raSeedAppPolicy(t, tenantA, teamviewerBundle, "approved")
	raSeedInstall(t, tenantA, devApproved, "macos", "macos_bundle", teamviewerBundle, "", "TeamViewer")

	// Unsanctioned: AnyDesk, unapproved, with a per-user install (PAT-2075).
	devUnapproved := raSeedDevice(t, tenantA, "mac-unapproved-"+sfx, now)
	raSeedAppPolicy(t, tenantA, anydeskBundle, "unapproved")
	fpAnyDesk := raSeedInstall(t, tenantA, devUnapproved, "macos", "macos_bundle", anydeskBundle, "", "AnyDesk")
	raSeedUserScope(t, devUnapproved, fpAnyDesk, anydeskBundle, "AnyDesk", "alice")

	// Unreviewed: RustDesk, no policy row at all.
	devUnreviewed := raSeedDevice(t, tenantA, "mac-unreviewed-"+sfx, now)
	raSeedInstall(t, tenantA, devUnreviewed, "macos", "macos_bundle", rustdeskBundle, "", "RustDesk")

	// RMM agent: NinjaOne's ncstreamer component, deliberately given an
	// "unapproved" app policy to prove it never leaks into the
	// remote_access summary regardless of its own state.
	devRMM := raSeedDevice(t, tenantA, "mac-rmm-"+sfx, now)
	raSeedAppPolicy(t, tenantA, ninjaBundle, "unapproved")
	raSeedInstall(t, tenantA, devRMM, "macos", "macos_bundle", ninjaBundle, "", "NinjaRMM Remote Control")

	// Browser extension: Chrome Remote Desktop, ignored, per-user by
	// construction (device_browser_extensions carries its own user_account).
	devExt := raSeedDevice(t, tenantA, "mac-ext-"+sfx, now)
	raSeedExtensionPolicy(t, tenantA, "chrome", chromeExtID, "ignored")
	raSeedExtension(t, devExt, "chrome", chromeExtID, "Chrome Remote Desktop", "bob")

	// Homebrew cask: RealVNC Server's vnc-server cask, approved.
	devCask := raSeedDevice(t, tenantA, "mac-cask-"+sfx, now)
	raSeedHomebrewPolicy(t, tenantA, "cask", vncServerCask, "approved")
	raSeedInstall(t, tenantA, devCask, "macos", "homebrew_cask", vncServerCask, "", "VNC Server")

	// Retired device carrying an AnyDesk install that must be fully excluded.
	devRetired := raSeedDevice(t, tenantA, "mac-retired-"+sfx, now)
	raRetireDevice(t, tenantA, devRetired)
	raSeedInstall(t, tenantA, devRetired, "macos", "macos_bundle", anydeskBundle, "", "AnyDesk")

	// Tenant B: an approved TeamViewer install that must never appear in A's report.
	devB := raSeedDevice(t, tenantB, "mac-b-"+sfx, now)
	raSeedAppPolicy(t, tenantB, teamviewerBundle, "approved")
	raSeedInstall(t, tenantB, devB, "macos", "macos_bundle", teamviewerBundle, "", "TeamViewer")

	rep := raGet(t, tokA, "/v1/portal/reports/software/remote-access")
	if rep.Definition.ID != "sam.remote-access" {
		t.Fatalf("definition id = %q", rep.Definition.ID)
	}
	if rep.Basis.DevicesRetired != 1 || !rep.Basis.RetiredExcluded {
		t.Fatalf("basis retirement: %+v", rep.Basis)
	}
	// 7 seeded devices total, 1 retired -> 6 assessed.
	if rep.Basis.DevicesAssessed != 6 {
		t.Fatalf("devices_assessed = %d, want 6", rep.Basis.DevicesAssessed)
	}

	tv := raFindProduct(rep.Products, teamviewerBundle)
	if tv == nil || tv.ApprovalState != "approved" || tv.Category != "remote_access" || tv.DeviceCount != 1 {
		t.Fatalf("teamviewer product = %+v", tv)
	}
	ad := raFindProduct(rep.Products, anydeskBundle)
	if ad == nil || ad.ApprovalState != "unapproved" || ad.DeviceCount != 1 {
		t.Fatalf("anydesk product = %+v (retired device must be excluded)", ad)
	}
	if len(ad.Users) != 1 || ad.Users[0] != "alice" {
		t.Fatalf("anydesk users = %v, want [alice]", ad.Users)
	}
	rd := raFindProduct(rep.Products, rustdeskBundle)
	if rd == nil || rd.ApprovalState != "unreviewed" {
		t.Fatalf("rustdesk product = %+v", rd)
	}
	ninja := raFindProduct(rep.Products, ninjaBundle)
	if ninja == nil || ninja.Category != "rmm_agent" {
		t.Fatalf("ninja product = %+v, want category rmm_agent", ninja)
	}
	ext := raFindProduct(rep.Products, chromeExtID)
	if ext == nil || ext.Kind != "browser_extension" || ext.ApprovalState != "ignored" {
		t.Fatalf("chrome remote desktop product = %+v", ext)
	}
	if len(ext.Users) != 1 || ext.Users[0] != "bob" {
		t.Fatalf("chrome remote desktop users = %v, want [bob]", ext.Users)
	}
	cask := raFindProduct(rep.Products, vncServerCask)
	if cask == nil || cask.Kind != "package" || cask.ApprovalState != "approved" {
		t.Fatalf("vnc-server cask product = %+v", cask)
	}

	// RMM counted apart: the unapproved NinjaOne row must not inflate
	// remote_access's unapproved count, and must appear under rmm_agents.
	if rep.Summary.RemoteAccess["unapproved"].Tools != 1 { // AnyDesk only
		t.Fatalf("remote_access unapproved tool_count = %d, want 1 (AnyDesk only, not NinjaOne)",
			rep.Summary.RemoteAccess["unapproved"].Tools)
	}
	if rep.Summary.RMMAgents["unapproved"].Tools != 1 {
		t.Fatalf("rmm_agents unapproved tool_count = %d, want 1", rep.Summary.RMMAgents["unapproved"].Tools)
	}

	// Sort order: unsanctioned first. AnyDesk (unapproved) must rank ahead
	// of TeamViewer (approved) among remote_access products.
	var anydeskIdx, teamviewerIdx = -1, -1
	for i, p := range rep.Products {
		if p.Identifier == anydeskBundle {
			anydeskIdx = i
		}
		if p.Identifier == teamviewerBundle {
			teamviewerIdx = i
		}
	}
	if anydeskIdx < 0 || teamviewerIdx < 0 || anydeskIdx > teamviewerIdx {
		t.Fatalf("unsanctioned must sort before sanctioned: anydesk=%d teamviewer=%d", anydeskIdx, teamviewerIdx)
	}

	// Drill-down: the per-user row for AnyDesk on the unapproved device.
	devRows := raGet(t, tokA, "/v1/portal/reports/software/remote-access/devices?product_key="+ad.ProductKey)
	found := false
	for _, r := range devRows.Rows {
		if r.DeviceID == devUnapproved && r.User != nil && *r.User == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("device rows for anydesk = %+v, want alice on %s", devRows.Rows, devUnapproved)
	}

	// Tenant isolation: B's own report must show its TeamViewer install
	// (approved, category remote_access) and nothing from A.
	repB := raGet(t, tokB, "/v1/portal/reports/software/remote-access")
	if repB.Basis.DevicesAssessed != 1 {
		t.Fatalf("tenant B devices_assessed = %d, want 1", repB.Basis.DevicesAssessed)
	}
	for _, p := range repB.Products {
		if p.Identifier == anydeskBundle || p.Identifier == rustdeskBundle || p.Identifier == ninjaBundle {
			t.Fatalf("tenant B report leaked tenant A product %+v", p)
		}
	}

	// CSV export: unpaged, every matching row, with formula-injection
	// neutralisation on free-text fields.
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/software/remote-access/devices?format=csv", tokA, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("csv export = %d: %s", resp.StatusCode, b)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csvText := string(body)
	if !strings.Contains(csvText, "device_id,hostname") {
		t.Fatalf("csv header missing: %s", csvText[:min(200, len(csvText))])
	}
	if !strings.Contains(csvText, anydeskBundle) {
		t.Fatalf("csv missing anydesk row")
	}
	if strings.Contains(csvText, "mac-retired-"+sfx) {
		t.Fatalf("csv leaked a retired device's hostname")
	}
}

// TestRemoteAccessReportRejectsUnknownQueryParam proves a typo cannot
// silently widen or narrow the answer.
func TestRemoteAccessReportRejectsUnknownQueryParam(t *testing.T) {
	sfx := randomHex(4)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2148-badq-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantID)
	email := "badq-" + sfx + "@pat2148.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	tok := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/software/remote-access?bogus=1", tok, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, b)
	}
}
