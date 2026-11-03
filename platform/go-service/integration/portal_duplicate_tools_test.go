//go:build integration

package integration

// PAT-2151: the SAM duplicate-tools-by-category report. Rules are the real,
// reviewed seed migration 0198's identifiers (1Password, Bitwarden, LastPass
// for password_manager; Zoom for video_conferencing) -- global rows shared
// with every test in this package -- so this suite also proves the seeded
// rules actually match real evidence end to end, and that a product's macOS
// and Windows identities are counted as one product, never two. Installations,
// devices, users, policies and retirement are seeded directly into the DB,
// reusing portal_remote_access_test.go's ra* helpers (same package), one
// dedicated tenant per test run.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// dtSeedDevice seeds a device with an explicit OS, unlike portal_remote_
// access_test.go's raSeedDevice (hardcoded to macOS) -- this report needs a
// real Windows device to prove a product's macOS and Windows identities are
// counted as one product.
func dtSeedDevice(t *testing.T, tenantID, host, os string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, $4, 'arm64', $5)
		RETURNING id::text`, tenantID, "SER-"+randomHex(6), host, os, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", host, err)
	}
	return id
}

type dtProduct struct {
	ProductKey       string   `json:"product_key"`
	Category         string   `json:"category"`
	Name             string   `json:"name"`
	Platforms        []string `json:"platforms"`
	Identifiers      []string `json:"identifiers"`
	ApprovalState    string   `json:"approval_state"`
	DeviceCount      int      `json:"device_count"`
	StaleDeviceCount int      `json:"stale_device_count"`
	Installations    int      `json:"installation_count"`
	Users            []string `json:"users"`
	MachineWideCount int      `json:"machine_wide_count"`
}

type dtCategory struct {
	Category     string      `json:"category"`
	DisplayName  string      `json:"display_name"`
	Flagged      bool        `json:"flagged"`
	ProductCount int         `json:"product_count"`
	Products     []dtProduct `json:"products"`
}

type dtReport struct {
	Definition struct {
		ID string `json:"id"`
	} `json:"definition"`
	Summary struct {
		CategoriesAssessed     int `json:"categories_assessed"`
		CategoriesWithProducts int `json:"categories_with_products"`
		CategoriesFlagged      int `json:"categories_flagged"`
		ProductCount           int `json:"product_count"`
		InstallationCount      int `json:"installation_count"`
	} `json:"summary"`
	Basis struct {
		DevicesTotal    int  `json:"devices_total"`
		DevicesAssessed int  `json:"devices_assessed"`
		DevicesRetired  int  `json:"devices_retired"`
		RetiredExcluded bool `json:"retired_devices_excluded"`
		PaidRulePending bool `json:"paid_products_rule_pending"`
	} `json:"basis"`
	Total      int          `json:"total"`
	Categories []dtCategory `json:"categories"`
}

func dtGet(t *testing.T, token, path string) dtReport {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
	}
	var out dtReport
	decodeJSON(t, resp, &out)
	return out
}

func dtFindCategory(cats []dtCategory, key string) *dtCategory {
	for i := range cats {
		if cats[i].Category == key {
			return &cats[i]
		}
	}
	return nil
}

func dtFindProduct(products []dtProduct, productKey string) *dtProduct {
	for i := range products {
		if products[i].ProductKey == productKey {
			return &products[i]
		}
	}
	return nil
}

// TestDuplicateToolsReport covers: a flagged category (three distinct
// products, one of them spanning macOS and Windows and counted once), a
// single-product category that is not flagged, an uncategorised product that
// never appears, a retired device excluded from every figure, tenant
// isolation and the CSV export.
func TestDuplicateToolsReport(t *testing.T) {
	sfx := randomHex(4)
	now := time.Now().UTC()

	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "pat2151-a-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantA)
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "pat2151-b-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantB)
	emailA, emailB := "a-"+sfx+"@pat2151.example", "b-"+sfx+"@pat2151.example"
	mapPortalUser(t, emailA, tenantA, http.StatusCreated)
	mapPortalUser(t, emailB, tenantB, http.StatusCreated)
	tokA, tokB := env.idp.token(t, emailA), env.idp.token(t, emailB)

	// Real seeded identities from migration 0198.
	const (
		onePasswordBundle = "com.1password.1password"
		onePasswordWinget = "agilebits.1password"
		bitwardenBundle   = "com.bitwarden.desktop"
		lastpassWinget    = "lastpass.lastpass"
		zoomBundle        = "us.zoom.xos"
	)

	// Product 1 (1Password): approved on a macOS device, machine-wide, AND
	// present on a separate Windows device via winget with no policy set --
	// must count as ONE product, not two, with devices/installations from
	// both, and its approval_state must be the least favourable of the two
	// (unreviewed), never silently shown as approved.
	devMac := raSeedDevice(t, tenantA, "mac-1password-"+sfx, now)
	raSeedAppPolicy(t, tenantA, onePasswordBundle, "approved")
	raSeedInstall(t, tenantA, devMac, "macos", "macos_bundle", onePasswordBundle, "", "1Password")

	devWin := dtSeedDevice(t, tenantA, "win-1password-"+sfx, "Windows", now)
	raSeedInstall(t, tenantA, devWin, "windows", "windows_winget", onePasswordWinget, "", "1Password")

	// Product 2 (Bitwarden): unapproved, with a per-user install (PAT-2075).
	devBW := raSeedDevice(t, tenantA, "mac-bitwarden-"+sfx, now)
	raSeedAppPolicy(t, tenantA, bitwardenBundle, "unapproved")
	fpBW := raSeedInstall(t, tenantA, devBW, "macos", "macos_bundle", bitwardenBundle, "", "Bitwarden")
	raSeedUserScope(t, devBW, fpBW, bitwardenBundle, "Bitwarden", "alice")

	// Product 3 (LastPass): no policy row at all -> unreviewed.
	devLP := dtSeedDevice(t, tenantA, "win-lastpass-"+sfx, "Windows", now)
	raSeedInstall(t, tenantA, devLP, "windows", "windows_winget", lastpassWinget, "", "LastPass")

	// Retired device carrying a second 1Password install that must be fully
	// excluded from every figure.
	devRetired := raSeedDevice(t, tenantA, "mac-retired-"+sfx, now)
	raRetireDevice(t, tenantA, devRetired)
	raSeedInstall(t, tenantA, devRetired, "macos", "macos_bundle", onePasswordBundle, "", "1Password")

	// Single-product category: Zoom only, must not be flagged.
	devZoom := raSeedDevice(t, tenantA, "mac-zoom-"+sfx, now)
	raSeedAppPolicy(t, tenantA, zoomBundle, "approved")
	raSeedInstall(t, tenantA, devZoom, "macos", "macos_bundle", zoomBundle, "", "Zoom")

	// Uncategorised product: matches no category rule at all -- must never
	// appear in any category or row.
	devUncat := raSeedDevice(t, tenantA, "mac-uncat-"+sfx, now)
	raSeedInstall(t, tenantA, devUncat, "macos", "macos_bundle", "com.example.uncategorised-notepad", "", "Uncategorised Notepad")

	// Tenant B: an approved LastPass install that must never appear in A's report.
	devB := dtSeedDevice(t, tenantB, "win-b-"+sfx, "Windows", now)
	raSeedAppPolicy(t, tenantB, lastpassWinget, "approved")
	raSeedInstall(t, tenantB, devB, "windows", "windows_winget", lastpassWinget, "", "LastPass")

	rep := dtGet(t, tokA, "/v1/portal/reports/software/duplicate-tools")
	if rep.Definition.ID != "sam.duplicate-tools" {
		t.Fatalf("definition id = %q", rep.Definition.ID)
	}
	if rep.Basis.DevicesRetired != 1 || !rep.Basis.RetiredExcluded {
		t.Fatalf("basis retirement: %+v", rep.Basis)
	}
	if !rep.Basis.PaidRulePending {
		t.Fatalf("basis.paid_products_rule_pending must be true (PAT-2143 not landed yet)")
	}
	// 7 seeded devices for tenant A, 1 retired -> 6 assessed.
	if rep.Basis.DevicesAssessed != 6 {
		t.Fatalf("devices_assessed = %d, want 6", rep.Basis.DevicesAssessed)
	}

	pm := dtFindCategory(rep.Categories, "password_manager")
	if pm == nil {
		t.Fatalf("password_manager category missing: %+v", rep.Categories)
	}
	if !pm.Flagged {
		t.Fatalf("password_manager with 3 distinct products must be flagged: %+v", pm)
	}
	if pm.ProductCount != 3 {
		t.Fatalf("password_manager product_count = %d, want 3", pm.ProductCount)
	}

	op := dtFindProduct(pm.Products, "password_manager:onepassword")
	if op == nil {
		t.Fatalf("onepassword product missing: %+v", pm.Products)
	}
	if op.DeviceCount != 2 || op.Installations != 2 {
		t.Fatalf("onepassword device/install count = %d/%d, want 2/2 (retired device excluded, both platforms counted)",
			op.DeviceCount, op.Installations)
	}
	if len(op.Platforms) != 2 {
		t.Fatalf("onepassword platforms = %v, want macos and windows counted as one product", op.Platforms)
	}
	if op.ApprovalState != "unreviewed" {
		t.Fatalf("onepassword approval_state = %q, want unreviewed (least favourable of approved-mac + unreviewed-windows)", op.ApprovalState)
	}

	bw := dtFindProduct(pm.Products, "password_manager:bitwarden")
	if bw == nil || bw.ApprovalState != "unapproved" {
		t.Fatalf("bitwarden product = %+v", bw)
	}
	if len(bw.Users) != 1 || bw.Users[0] != "alice" {
		t.Fatalf("bitwarden users = %v, want [alice]", bw.Users)
	}

	lp := dtFindProduct(pm.Products, "password_manager:lastpass")
	if lp == nil || lp.ApprovalState != "unreviewed" {
		t.Fatalf("lastpass product = %+v", lp)
	}
	if lp.DeviceCount != 1 {
		t.Fatalf("lastpass device_count = %d, want 1 (tenant B's LastPass must not leak into A)", lp.DeviceCount)
	}

	vc := dtFindCategory(rep.Categories, "video_conferencing")
	if vc == nil {
		t.Fatalf("video_conferencing category missing")
	}
	if vc.Flagged {
		t.Fatalf("video_conferencing with 1 product (Zoom only) must not be flagged: %+v", vc)
	}
	if vc.ProductCount != 1 {
		t.Fatalf("video_conferencing product_count = %d, want 1", vc.ProductCount)
	}

	// Uncategorised product: must not appear anywhere.
	for _, c := range rep.Categories {
		for _, p := range c.Products {
			for _, ident := range p.Identifiers {
				if ident == "com.example.uncategorised-notepad" {
					t.Fatalf("uncategorised product leaked into %s/%s", c.Category, p.ProductKey)
				}
			}
		}
	}

	// Tenant isolation: B's own report must show its own LastPass install
	// and nothing from A.
	repB := dtGet(t, tokB, "/v1/portal/reports/software/duplicate-tools")
	if repB.Basis.DevicesAssessed != 1 {
		t.Fatalf("tenant B devices_assessed = %d, want 1", repB.Basis.DevicesAssessed)
	}
	pmB := dtFindCategory(repB.Categories, "password_manager")
	if pmB == nil || pmB.ProductCount != 1 {
		t.Fatalf("tenant B password_manager = %+v, want 1 product (LastPass only)", pmB)
	}

	// category filter.
	repFiltered := dtGet(t, tokA, "/v1/portal/reports/software/duplicate-tools?category=video_conferencing")
	if len(repFiltered.Categories) != 1 || repFiltered.Categories[0].Category != "video_conferencing" {
		t.Fatalf("category filter = %+v, want only video_conferencing", repFiltered.Categories)
	}

	// CSV export: unpaged, every matching row, with formula-injection
	// neutralisation on free-text fields, retired device excluded.
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/software/duplicate-tools?format=csv", tokA, nil)
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
	if !strings.Contains(csvText, onePasswordBundle) {
		t.Fatalf("csv missing onepassword row")
	}
	if strings.Contains(csvText, "mac-retired-"+sfx) {
		t.Fatalf("csv leaked a retired device's hostname")
	}
}

// TestDuplicateToolsReportRejectsUnknownQueryParam proves a typo cannot
// silently widen or narrow the answer.
func TestDuplicateToolsReportRejectsUnknownQueryParam(t *testing.T) {
	sfx := randomHex(4)
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "pat2151-badq-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantID)
	email := "badq-" + sfx + "@pat2151.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	tok := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/software/duplicate-tools?bogus=1", tok, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, b)
	}
}
