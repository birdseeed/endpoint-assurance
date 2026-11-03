//go:build integration

package integration

// PAT-2147: the SAM unsupported software report. Lifecycle products are
// global tables shared with every test in this package, so each test uses
// its own random slug and identifiers, except the two OS slugs (macos,
// windows), whose migration-seeded published mappings only this file reads.

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/lifecycle"
)

type slcRow struct {
	DeviceID      string     `json:"device_id"`
	Hostname      string     `json:"hostname"`
	Kind          string     `json:"kind"`
	ProductKey    string     `json:"product_key"`
	Name          string     `json:"name"`
	Platform      string     `json:"platform"`
	Version       string     `json:"version"`
	State         string     `json:"state"`
	Cycle         *string    `json:"cycle"`
	EOLDate       *string    `json:"eol_date"`
	DaysToEOL     *int       `json:"days_to_eol"`
	DeviceCount   int        `json:"device_count"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	Source        *struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		URL  string `json:"url"`
	} `json:"source"`
	Reason *string `json:"unknown_reason"`
	Note   *string `json:"note"`
}

type slcReport struct {
	Definition struct {
		ID string `json:"id"`
	} `json:"definition"`
	Summary struct {
		States map[string]struct {
			Installations int `json:"installation_count"`
			Devices       int `json:"device_count"`
		} `json:"states"`
		UnknownByReason map[string]int `json:"unknown_by_reason"`
	} `json:"summary"`
	Basis struct {
		DevicesTotal    int    `json:"devices_total"`
		DevicesStale    int    `json:"devices_stale"`
		DevicesAssessed int    `json:"devices_assessed"`
		DevicesRetired  int    `json:"devices_retired"`
		RetiredExcluded bool   `json:"retired_devices_excluded"`
		Complete        bool   `json:"complete"`
		Statement       string `json:"statement"`
		NotCounted      []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"not_counted"`
	} `json:"basis"`
	CyberEssentials struct {
		Position                       string `json:"position"`
		DevicesWithUnsupportedSoftware int    `json:"devices_with_unsupported_software"`
		UnsupportedInstallationCount   int    `json:"unsupported_installation_count"`
		Devices                        []struct {
			DeviceID    string `json:"device_id"`
			Unsupported []struct {
				ProductKey string `json:"product_key"`
			} `json:"unsupported"`
		} `json:"devices"`
	} `json:"cyber_essentials"`
	Total    int      `json:"total"`
	Products []slcRow `json:"products"`
	Rows     []slcRow `json:"rows"`
}

func slcDate(t time.Time) *time.Time {
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return &d
}

func slcBool(b bool) *bool { return &b }

// slcStore writes one product's cycles as if fetched at fetchedAt.
func slcStore(t *testing.T, slug string, fetchedAt time.Time, cycles []lifecycle.Cycle) {
	t.Helper()
	if err := lifecycle.Store(context.Background(), env.pool, lifecycle.FetchedProduct{
		Slug: slug, Label: slug, APIURL: "https://endoflife.date/api/v1/products/" + slug + "/",
		HTMLURL: "https://endoflife.date/" + slug, SchemaVersion: "1.2.1", Cycles: cycles,
	}, fetchedAt); err != nil {
		t.Fatalf("store lifecycle product %s: %v", slug, err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM lifecycle_products WHERE slug = $1`, slug)
	})
}

func slcSeedDevice(t *testing.T, tenantID, host, os, version, build, caption string, lastSeen time.Time) string {
	t.Helper()
	var id string
	if err := env.pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, os_caption, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, $4, $5, $6, NULLIF($7, ''), 'arm64', $8)
		RETURNING id::text`, tenantID, "SER-"+randomHex(6), host, os, version, build, caption, lastSeen).Scan(&id); err != nil {
		t.Fatalf("seed device %s: %v", host, err)
	}
	return id
}

func slcSeedInstall(t *testing.T, tenantID, deviceID, platform, kind, value, companion, name, version string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(strings.Join([]string{platform, kind, value, companion}, "\x1f")))
	fp := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO software_installations
			(tenant_id, device_id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
			 identity_fingerprint, current_name, current_version, first_seen_at, last_seen_at, provenance)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $10, 'inventory_payload')`,
		tenantID, deviceID, platform, kind, value, companion, fp, name, version, now); err != nil {
		t.Fatalf("seed installation %s: %v", value, err)
	}
	return "app:" + fp
}

type slcMappingResp struct {
	Mapping struct {
		ID         int64   `json:"id"`
		Status     string  `json:"status"`
		ReviewedBy *string `json:"reviewed_by"`
	} `json:"mapping"`
}

func slcPropose(t *testing.T, body map[string]any, want int) slcMappingResp {
	t.Helper()
	var out slcMappingResp
	adminJSON(t, http.MethodPost, "/admin/lifecycle/mappings", body, want, &out)
	if want == http.StatusCreated {
		id := out.Mapping.ID
		t.Cleanup(func() {
			// Rejected rows free the identity; the audit stays append-only.
			_, _ = env.pool.Exec(context.Background(),
				`UPDATE lifecycle_mappings SET status = 'rejected', reviewed_by = 'test-cleanup', reviewed_at = now() WHERE id = $1 AND status <> 'rejected'`, id)
		})
	}
	return out
}

func slcGet(t *testing.T, token, path string) slcReport {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
	}
	var out slcReport
	decodeJSON(t, resp, &out)
	return out
}

func slcFind(rows []slcRow, key, version string) *slcRow {
	for i := range rows {
		if rows[i].ProductKey == key && (version == "" || rows[i].Version == version) {
			return &rows[i]
		}
	}
	return nil
}

// TestUnsupportedSoftwareReport covers every state, every Unknown reason the
// data can produce, the OS rows on both platforms, a proposed mapping having
// no effect, the Cyber Essentials evidence, the device drill-down, the CSV
// (with formula injection neutralised) and tenant isolation.
func TestUnsupportedSoftwareReport(t *testing.T) {
	sfx := randomHex(4)
	now := time.Now().UTC()
	day := 24 * time.Hour

	// Lifecycle data, fetched an hour ago. The OS slugs are the migration's
	// published mappings.
	slug := "pat2147-app-" + sfx
	staleSlug := "pat2147-stale-" + sfx
	slcStore(t, slug, now.Add(-time.Hour), []lifecycle.Cycle{
		{Name: "1", EOLDate: slcDate(now.Add(-30 * day)), IsEOL: slcBool(true)},
		{Name: "2", EOLDate: slcDate(now.Add(30 * day)), IsEOL: slcBool(false)},
		{Name: "3", EOLDate: slcDate(now.Add(400 * day)), IsEOL: slcBool(false)},
	})
	slcStore(t, staleSlug, now.Add(-8*day), []lifecycle.Cycle{{Name: "5", EOLDate: slcDate(now.Add(400 * day))}})
	slcStore(t, "macos", now.Add(-time.Hour), []lifecycle.Cycle{
		{Name: "26", IsEOL: slcBool(false), LatestVersion: "26.1"},
		{Name: "13", EOLDate: slcDate(now.Add(-100 * day)), IsEOL: slcBool(true), LatestVersion: "13.7.8"},
	})
	slcStore(t, "windows", now.Add(-time.Hour), []lifecycle.Cycle{
		{Name: "10-22h2", EOLDate: slcDate(now.Add(-300 * day)), IsEOL: slcBool(true),
			ExtendedSupportDate: slcDate(now.Add(700 * day)), LatestVersion: "10.0.19045"},
		{Name: "11-24h2-e", EOLDate: slcDate(now.Add(700 * day)), IsEOL: slcBool(false), LatestVersion: "10.0.26100"},
		{Name: "11-24h2-w", EOLDate: slcDate(now.Add(200 * day)), IsEOL: slcBool(false), LatestVersion: "10.0.26100"},
	})

	// Mappings: one published through the admin API, one stale, one only
	// proposed (must never affect customer output).
	appID := "com.pat2147.app" + sfx
	team := strings.ToUpper("T" + sfx + "XYZ")[:10]
	pub := slcPropose(t, map[string]any{"platform": "macos", "identity_kind": "macos_bundle_team",
		"identity_value": appID, "companion_value": team, "eol_slug": slug, "version_rule": "major"}, http.StatusCreated)
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/publish", pub.Mapping.ID), nil, http.StatusOK, nil)
	staleID := "com.pat2147.stale" + sfx
	st := slcPropose(t, map[string]any{"platform": "macos", "identity_kind": "macos_bundle",
		"identity_value": staleID, "eol_slug": staleSlug, "version_rule": "major"}, http.StatusCreated)
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/publish", st.Mapping.ID), nil, http.StatusOK, nil)
	proposedID := "pat2147.proposed" + sfx
	slcPropose(t, map[string]any{"platform": "windows", "identity_kind": "windows_winget",
		"identity_value": proposedID, "eol_slug": slug, "version_rule": "major"}, http.StatusCreated)

	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "pat2147-a-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantA)
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "pat2147-b-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantB)
	emailA, emailB := "a-"+sfx+"@pat2147.example", "b-"+sfx+"@pat2147.example"
	mapPortalUser(t, emailA, tenantA, http.StatusCreated)
	mapPortalUser(t, emailB, tenantB, http.StatusCreated)
	tokA, tokB := env.idp.token(t, emailA), env.idp.token(t, emailB)

	fresh := now.Add(-time.Hour)
	mac1 := slcSeedDevice(t, tenantA, "=cmd|' /C calc'!A0", "macOS", "13.6.1", "22G313", "", fresh)
	mac2 := slcSeedDevice(t, tenantA, "mac-two-"+sfx, "macOS", "26.0.1", "25A362", "", fresh)
	win1 := slcSeedDevice(t, tenantA, "win-one-"+sfx, "Windows", "22H2", "19045.4529", "Microsoft Windows 10 Pro", fresh)
	slcSeedDevice(t, tenantA, "win-two-"+sfx, "Windows", "10.0.26100", "26100.1", "", now.Add(-20*day))
	macB := slcSeedDevice(t, tenantB, "mac-b-"+sfx, "macOS", "26.0", "25A1", "", fresh)

	keyApp := slcSeedInstall(t, tenantA, mac1, "macos", "macos_bundle_team", appID, team, "Pat App", "1.4.2") // unsupported
	slcSeedInstall(t, tenantA, mac2, "macos", "macos_bundle_team", appID, team, "Pat App", "2.0")             // ending
	slcSeedInstall(t, tenantA, mac2, "macos", "macos_bundle_team", strings.Replace(appID, "app", "ap3", 1), team, "Other", "3.0")
	keyUnmatched := slcSeedInstall(t, tenantA, mac1, "macos", "macos_bundle", "com.pat2147.nover"+sfx, "", "NoVer", "")
	slcSeedInstall(t, tenantA, mac1, "macos", "macos_bundle", staleID, "", "Stale App", "5.1") // stale
	keyProposed := slcSeedInstall(t, tenantA, win1, "windows", "windows_winget", proposedID, "", "Proposed App", "1.0")
	slcSeedInstall(t, tenantA, win1, "windows", "display_name", "name only "+sfx, "", "Name Only", "1.0")
	slcSeedInstall(t, tenantA, mac1, "macos", "ide_extension", "ext.pat2147"+sfx, "vscode", "Ext", "1.0") // not counted
	// The same unsupported app on tenant B.
	slcSeedInstall(t, tenantB, macB, "macos", "macos_bundle_team", appID, team, "Pat App", "1.0")

	rep := slcGet(t, tokA, "/v1/portal/reports/software/unsupported?limit=500")
	if rep.Definition.ID != "sam.unsupported-software" {
		t.Errorf("definition id = %q", rep.Definition.ID)
	}

	// Applications.
	if r := slcFind(rep.Products, keyApp, "1.4.2"); r == nil || r.State != "unsupported" || r.Source == nil ||
		r.Source.Slug != slug || r.LastCheckedAt == nil || r.Cycle == nil || *r.Cycle != "1" || r.DaysToEOL == nil || *r.DaysToEOL != -30 {
		t.Errorf("unsupported app row = %+v", r)
	}
	if r := slcFind(rep.Products, keyApp, "2.0"); r == nil || r.State != "ending_within_90_days" || r.DaysToEOL == nil || *r.DaysToEOL != 30 {
		t.Errorf("ending app row = %+v", r)
	}
	if r := slcFind(rep.Products, keyUnmatched, ""); r == nil || r.State != "unknown" || r.Reason == nil || *r.Reason != "no_published_mapping" {
		t.Errorf("unmapped app row = %+v", r)
	}
	if r := slcFind(rep.Products, keyProposed, ""); r == nil || r.State != "unknown" || r.Reason == nil ||
		*r.Reason != "no_published_mapping" || r.Source != nil {
		t.Errorf("a proposed mapping changed customer output: %+v", r)
	}
	var sawStale, sawSupported bool
	for _, r := range rep.Products {
		if r.Name == "Stale App" {
			sawStale = r.State == "unknown" && r.Reason != nil && *r.Reason == "lifecycle_stale" && r.LastCheckedAt != nil
		}
		if r.Name == "Pat App" && r.State == "supported" {
			sawSupported = true
		}
		if r.State != "unknown" && (r.Source == nil || r.LastCheckedAt == nil) {
			t.Errorf("row %s %s is %s without a source and last checked date", r.Name, r.Version, r.State)
		}
		if r.State == "supported" && r.Reason != nil {
			t.Errorf("supported row carries an unknown reason: %+v", r)
		}
	}
	if !sawStale {
		t.Error("the stale-cache product did not read Unknown with reason lifecycle_stale")
	}
	if sawSupported {
		t.Error("an app on a supported cycle 3 was never installed, but a supported Pat App row appeared")
	}

	// Operating systems.
	if r := slcFind(rep.Products, "os:macos", "13.6.1"); r == nil || r.State != "unsupported" || r.Kind != "operating_system" {
		t.Errorf("macOS 13 row = %+v", r)
	}
	if r := slcFind(rep.Products, "os:macos", "26.0.1"); r == nil || r.State != "supported" || r.EOLDate != nil {
		t.Errorf("macOS 26 row = %+v", r)
	}
	if r := slcFind(rep.Products, "os:windows", "10.0.19045"); r == nil || r.State != "unsupported" || r.Note == nil ||
		!strings.Contains(*r.Note, "not evidenced") {
		t.Errorf("Windows 10 22H2 row = %+v (want unsupported with the ESU note)", r)
	}
	if r := slcFind(rep.Products, "os:windows", "10.0.26100"); r == nil || r.State != "unknown" || r.Reason == nil || *r.Reason != "edition_unknown" {
		t.Errorf("Windows 11 24H2 with no caption = %+v (want unknown/edition_unknown, never a guessed edition)", r)
	}

	// Summary: unsupported = app 1.x + macOS 13 + Windows 10; ending = app 2.0.
	if s := rep.Summary.States["unsupported"]; s.Installations != 3 || s.Devices != 2 {
		t.Errorf("unsupported summary = %+v, want 3 installations on 2 devices", s)
	}
	if s := rep.Summary.States["ending_within_90_days"]; s.Installations != 1 {
		t.Errorf("ending summary = %+v", s)
	}
	if s := rep.Summary.States["supported"]; s.Installations != 1 {
		t.Errorf("supported summary = %+v (want macOS 26 only)", s)
	}
	// unknown: Other (no mapping), NoVer, Stale App, Proposed App, Name Only, Windows 11.
	if s := rep.Summary.States["unknown"]; s.Installations != 6 {
		t.Errorf("unknown summary = %+v, want 6; by reason %v", s, rep.Summary.UnknownByReason)
	}

	// Basis: four devices, one stale, the IDE extension not counted, and
	// never complete while anything is Unknown or stale.
	if rep.Basis.DevicesTotal != 4 || rep.Basis.DevicesStale != 1 || rep.Basis.Complete || rep.Basis.Statement == "" {
		t.Errorf("basis = %+v", rep.Basis)
	}
	var tooling int
	for _, nc := range rep.Basis.NotCounted {
		if nc.Reason == "developer_tooling" {
			tooling = nc.Count
		}
	}
	if tooling != 1 {
		t.Errorf("developer_tooling not counted = %d, want 1", tooling)
	}

	// Cyber Essentials evidence.
	ce := rep.CyberEssentials
	if ce.Position != "evidence_only" || ce.DevicesWithUnsupportedSoftware != 2 || ce.UnsupportedInstallationCount != 3 {
		t.Errorf("cyber essentials = %+v", ce)
	}

	// Filters and paging on the product rows.
	unsup := slcGet(t, tokA, "/v1/portal/reports/software/unsupported?state=unsupported&kind=operating_system")
	if unsup.Total != 2 {
		t.Errorf("state=unsupported&kind=operating_system total = %d, want 2", unsup.Total)
	}
	paged := slcGet(t, tokA, "/v1/portal/reports/software/unsupported?limit=2&offset=1")
	if len(paged.Products) != 2 || paged.Total != len(rep.Products) {
		t.Errorf("paging: got %d rows of total %d", len(paged.Products), paged.Total)
	}

	// Device drill-down.
	dev := slcGet(t, tokA, "/v1/portal/reports/software/unsupported/devices?device_id="+mac1)
	if dev.Total != 4 { // macOS, Pat App 1.4.2, NoVer, Stale App (the IDE extension is excluded)
		t.Errorf("mac1 drill-down total = %d, want 4 rows", dev.Total)
	}
	for _, r := range dev.Rows {
		if r.DeviceID != mac1 {
			t.Errorf("device filter leaked %s", r.DeviceID)
		}
	}
	byProduct := slcGet(t, tokA, "/v1/portal/reports/software/unsupported/devices?product_key="+keyApp)
	if byProduct.Total != 2 {
		t.Errorf("product drill-down total = %d, want 2 (tenant A only)", byProduct.Total)
	}

	// Unknown query parameters are refused.
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/software/unsupported?stat=unsupported", tokA, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("typo parameter = %d, want 400", resp.StatusCode)
	}

	// CSV: every installation row, formula injection neutralised.
	resp = portalDo(t, http.MethodGet, "/v1/portal/reports/software/unsupported?format=csv", tokA, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	records, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1+11 { // header + 4 OS rows + 7 application rows
		t.Errorf("csv rows = %d, want 12", len(records))
	}
	for _, rec := range records[1:] {
		if rec[0] == mac1 && !strings.HasPrefix(rec[1], "'=") {
			t.Errorf("hostname cell %q not neutralised", rec[1])
		}
		for _, cell := range rec {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) && !strings.HasPrefix(cell, "-") {
				t.Errorf("unneutralised cell %q", cell)
			}
		}
	}

	// Tenant isolation: B sees only its own device, A's figures are
	// untouched by B's unsupported install.
	repB := slcGet(t, tokB, "/v1/portal/reports/software/unsupported?limit=500")
	devB := slcGet(t, tokB, "/v1/portal/reports/software/unsupported/devices?limit=500")
	for _, r := range devB.Rows {
		if r.DeviceID != macB {
			t.Fatalf("tenant B saw device %s", r.DeviceID)
		}
	}
	if repB.Basis.DevicesTotal != 1 || repB.Summary.States["unsupported"].Installations != 1 {
		t.Errorf("tenant B report = %+v %+v", repB.Basis, repB.Summary)
	}
	crossA := slcGet(t, tokB, "/v1/portal/reports/software/unsupported/devices?device_id="+mac1)
	if crossA.Total != 0 {
		t.Errorf("tenant B filtering on tenant A's device got %d rows", crossA.Total)
	}

	// Withdrawing the published mapping returns its rows to Unknown.
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/reject", pub.Mapping.ID), nil, http.StatusOK, nil)
	after := slcGet(t, tokA, "/v1/portal/reports/software/unsupported?limit=500")
	if r := slcFind(after.Products, keyApp, "1.4.2"); r == nil || r.State != "unknown" {
		t.Errorf("after withdraw, app row = %+v, want unknown", r)
	}
}

// TestLifecycleAdminPublishFlow: propose, validation, duplicate, the fetched
// data gate on publish, publish, withdraw, and the audit trail.
func TestLifecycleAdminPublishFlow(t *testing.T) {
	sfx := randomHex(4)
	slug := "pat2147-flow-" + sfx
	body := map[string]any{"platform": "windows", "identity_kind": "windows_winget",
		"identity_value": "Pat2147.Flow" + sfx, "eol_slug": slug, "version_rule": "major_minor", "actor": "reviewer@example"}
	m := slcPropose(t, body, http.StatusCreated)
	if m.Mapping.Status != "proposed" {
		t.Fatalf("status = %s", m.Mapping.Status)
	}
	slcPropose(t, body, http.StatusConflict) // one live mapping per identity

	for name, bad := range map[string]map[string]any{
		"display name is not identity": {"platform": "windows", "identity_kind": "display_name", "identity_value": "x", "eol_slug": slug, "version_rule": "major"},
		"bad slug":                     {"platform": "windows", "identity_kind": "windows_winget", "identity_value": "y" + sfx, "eol_slug": "Bad Slug", "version_rule": "major"},
		"regex with two groups":        {"platform": "windows", "identity_kind": "windows_winget", "identity_value": "z" + sfx, "eol_slug": slug, "version_rule": "regex", "version_regex": `(\d)(\d)`},
		"platform mismatch":            {"platform": "macos", "identity_kind": "windows_winget", "identity_value": "w" + sfx, "eol_slug": slug, "version_rule": "major"},
		"team id missing":              {"platform": "macos", "identity_kind": "macos_bundle_team", "identity_value": "v" + sfx, "eol_slug": slug, "version_rule": "major"},
	} {
		t.Run(name, func(t *testing.T) { slcPropose(t, bad, http.StatusBadRequest) })
	}

	path := fmt.Sprintf("/admin/lifecycle/mappings/%d/publish", m.Mapping.ID)
	adminJSON(t, http.MethodPost, path, nil, http.StatusConflict, nil) // never fetched

	slcStore(t, slug, time.Now().UTC(), []lifecycle.Cycle{{Name: "1.2"}})
	var pub slcMappingResp
	adminJSON(t, http.MethodPost, path, map[string]any{"actor": "reviewer@example"}, http.StatusOK, &pub)
	if pub.Mapping.Status != "published" || pub.Mapping.ReviewedBy == nil {
		t.Fatalf("published = %+v", pub.Mapping)
	}
	adminJSON(t, http.MethodPost, path, nil, http.StatusConflict, nil) // already published

	var list struct {
		Mappings []struct {
			ID                int64  `json:"id"`
			Status            string `json:"status"`
			IdentityValue     string `json:"identity_value"`
			LifecycleCycles   *int   `json:"lifecycle_cycle_count"`
			InstallationCount *int   `json:"estate_installation_count"`
		} `json:"mappings"`
	}
	adminJSON(t, http.MethodGet, "/admin/lifecycle/mappings?status=published", nil, http.StatusOK, &list)
	var found bool
	for _, x := range list.Mappings {
		if x.ID == m.Mapping.ID {
			found = x.IdentityValue == strings.ToLower("pat2147.flow"+sfx) && x.LifecycleCycles != nil && *x.LifecycleCycles == 1 && x.InstallationCount != nil
		}
		if x.Status != "published" {
			t.Errorf("status filter leaked %s", x.Status)
		}
	}
	if !found {
		t.Error("published mapping missing from the list, or its identity was not normalised")
	}

	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/reject", m.Mapping.ID), nil, http.StatusOK, nil)
	rows, err := env.pool.Query(context.Background(),
		`SELECT action, actor, claimed_actor FROM lifecycle_mapping_audit WHERE mapping_id = $1 ORDER BY id`, m.Mapping.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var a, actor string
		var claimed *string
		if err := rows.Scan(&a, &actor, &claimed); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
		if actor == "reviewer@example" {
			t.Error("the body's actor claim was stored as the authoritative actor")
		}
	}
	if strings.Join(actions, ",") != "propose,publish,withdraw" {
		t.Errorf("audit actions = %v", actions)
	}
	if _, err := env.pool.Exec(context.Background(), `DELETE FROM lifecycle_mapping_audit WHERE mapping_id = $1`, m.Mapping.ID); err == nil {
		t.Error("lifecycle_mapping_audit accepted a DELETE")
	}

	// The migration seed: the two OS mappings published, every application
	// mapping proposed except the five Chrome and Firefox rows that 0219
	// publishes under the rolling-release rule (PAT-2171).
	var osPublished, appPublished, browsersPublished int
	if err := env.pool.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE identity_kind = 'os' AND status = 'published'),
		       count(*) FILTER (WHERE identity_kind <> 'os' AND status = 'published'),
		       count(*) FILTER (WHERE identity_kind <> 'os' AND status = 'published' AND eol_slug IN ('chrome', 'firefox'))
		FROM lifecycle_mappings WHERE proposed_by = 'migration:0196'`).Scan(&osPublished, &appPublished, &browsersPublished); err != nil {
		t.Fatal(err)
	}
	if osPublished != 2 || appPublished != 5 || browsersPublished != 5 {
		t.Errorf("seed: %d OS published, %d apps published (%d of them Chrome or Firefox); want 2, 5 and 5",
			osPublished, appPublished, browsersPublished)
	}
}

// TestLifecycleFetcherAgainstLocalServer runs the real fetcher, store and
// admin refresh against a local server standing in for endoflife.date:
// success, a transient 503 retried, a 404 recorded without losing the
// previous data, and no tenant data in any request.
func TestLifecycleFetcherAgainstLocalServer(t *testing.T) {
	sfx := randomHex(4)
	good, gone := "pat2147-good-"+sfx, "pat2147-gone-"+sfx
	var calls atomic.Int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("request carried more than the slug: %s %v", r.URL, r.Header)
		}
		switch r.URL.Path {
		case "/api/v1/products/" + good + "/":
			if n == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if fail.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"schema_version":"1.2.1","last_modified":"2026-09-24T00:00:00+00:00","result":{"name":"` + good +
				`","label":"Good","links":{"html":"https://endoflife.date/` + good + `"},"releases":[` +
				`{"name":"2","releaseDate":"2025-01-01","isEol":false,"eolFrom":"2030-01-01","latest":{"name":"2.4"}},` +
				`{"name":"1","releaseDate":"2020-01-01","isEol":true,"eolFrom":"2024-01-01","latest":null}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM lifecycle_products WHERE slug = ANY($1)`, []string{good, gone})
	})

	f := &lifecycle.Fetcher{BaseURL: srv.URL + "/api/v1/products/", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sleep: func(context.Context, time.Duration) error { return nil }}
	res, err := f.Refresh(context.Background(), env.pool, []string{good, gone})
	if err != nil {
		t.Fatal(err)
	}
	if res.Succeeded != 1 || res.Failed != 1 {
		t.Fatalf("refresh = %+v", res)
	}
	var fetched *time.Time
	var cycles int
	var lastErr *string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT fetched_at, cycle_count, last_error FROM lifecycle_products WHERE slug = $1`, good).Scan(&fetched, &cycles, &lastErr); err != nil {
		t.Fatal(err)
	}
	if fetched == nil || cycles != 2 || lastErr != nil {
		t.Errorf("good slug: fetched %v cycles %d err %v", fetched, cycles, lastErr)
	}
	var eol time.Time
	var latest *string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT eol_date, latest_version FROM lifecycle_cycles WHERE slug = $1 AND cycle = '2'`, good).Scan(&eol, &latest); err != nil {
		t.Fatal(err)
	}
	if eol.Format("2006-01-02") != "2030-01-01" || latest == nil || *latest != "2.4" {
		t.Errorf("cycle 2 = %s %v", eol, latest)
	}
	if err := env.pool.QueryRow(context.Background(),
		`SELECT fetched_at, last_error FROM lifecycle_products WHERE slug = $1`, gone).Scan(&fetched, &lastErr); err != nil {
		t.Fatal(err)
	}
	if fetched != nil || lastErr == nil {
		t.Errorf("404 slug: fetched %v err %v, want no fetch and an error", fetched, lastErr)
	}

	// A later failure keeps the previous cycles and records the error.
	fail.Store(true)
	if _, err := f.Refresh(context.Background(), env.pool, []string{good}); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(context.Background(),
		`SELECT cycle_count, last_error FROM lifecycle_products WHERE slug = $1`, good).Scan(&cycles, &lastErr); err != nil {
		t.Fatal(err)
	}
	if cycles != 2 || lastErr == nil {
		t.Errorf("after a failed refresh: cycles %d err %v, want the old data kept and the error recorded", cycles, lastErr)
	}

	// The admin trigger runs the same fetcher, detached, under the lock.
	fail.Store(false)
	restore := handlers.SetLifecycleFetcherForTest(f)
	defer restore()
	var started struct {
		Status string   `json:"status"`
		Slugs  []string `json:"slugs"`
	}
	adminJSON(t, http.MethodPost, "/admin/lifecycle/refresh", map[string]any{"slug": good}, http.StatusAccepted, &started)
	if started.Status != "started" || len(started.Slugs) != 1 {
		t.Fatalf("refresh response = %+v", started)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := env.pool.QueryRow(context.Background(),
			`SELECT last_error FROM lifecycle_products WHERE slug = $1`, good).Scan(&lastErr); err != nil {
			t.Fatal(err)
		}
		if lastErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin refresh did not clear the error within 10 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Wait for the detached refresh to release the lock before the next test.
	for {
		release, err := lifecycle.Lock(context.Background(), env.pool)
		if err == nil {
			release()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh lock not released")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestUnsupportedSoftwareReportExcludesRetiredDevices (PAT-2135 review
// finding): a retired device's unsupported software is not counted anywhere,
// and the basis says how many devices were excluded as retired.
func TestUnsupportedSoftwareReportExcludesRetiredDevices(t *testing.T) {
	sfx := randomHex(4)
	now := time.Now().UTC()
	slug := "pat2147-ret-" + sfx
	slcStore(t, slug, now.Add(-time.Hour), []lifecycle.Cycle{{Name: "1", EOLDate: slcDate(now.Add(-30 * 24 * time.Hour))}})
	appID := "pat2147.retired" + sfx
	m := slcPropose(t, map[string]any{"platform": "windows", "identity_kind": "windows_winget",
		"identity_value": appID, "eol_slug": slug, "version_rule": "major"}, http.StatusCreated)
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/publish", m.Mapping.ID), nil, http.StatusOK, nil)

	tenant, _, _, err := createTestTenant(env.internalSrv.URL, "pat2147-ret-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenant)
	email := "ret-" + sfx + "@pat2147.example"
	mapPortalUser(t, email, tenant, http.StatusCreated)
	tok := env.idp.token(t, email)

	fresh := now.Add(-time.Hour)
	live := slcSeedDevice(t, tenant, "live-"+sfx, "Windows", "10.0.26100", "", "Microsoft Windows 11 Enterprise", fresh)
	gone := slcSeedDevice(t, tenant, "gone-"+sfx, "Windows", "10.0.26100", "", "Microsoft Windows 11 Enterprise", fresh)
	key := slcSeedInstall(t, tenant, live, "windows", "windows_winget", appID, "", "Retired Test", "1.2")
	slcSeedInstall(t, tenant, gone, "windows", "windows_winget", appID, "", "Retired Test", "1.2")
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
		VALUES ($1::uuid, $2::uuid, 'retire', 'admin@pat2147.example')`, tenant, gone); err != nil {
		t.Fatal(err)
	}

	rep := slcGet(t, tok, "/v1/portal/reports/software/unsupported?limit=500")
	basis := rep.Basis
	if basis.DevicesTotal != 2 || basis.DevicesAssessed != 1 || basis.DevicesRetired != 1 || !basis.RetiredExcluded {
		t.Errorf("basis = %+v, want 2 total, 1 assessed, 1 retired, excluded", basis)
	}
	var retiredNC int
	for _, nc := range rep.Basis.NotCounted {
		if nc.Reason == "retired_devices" {
			retiredNC = nc.Count
		}
	}
	if retiredNC != 1 {
		t.Errorf("retired_devices not counted = %d, want 1", retiredNC)
	}
	if r := slcFind(rep.Products, key, "1.2"); r == nil || r.State != "unsupported" || r.DeviceCount != 1 {
		t.Errorf("unsupported row = %+v, want 1 device (the retired one excluded)", r)
	}
	if s := rep.Summary.States["unsupported"]; s.Installations != 1 || s.Devices != 1 {
		t.Errorf("unsupported summary = %+v, want 1 installation on 1 device", s)
	}
	if rep.CyberEssentials.DevicesWithUnsupportedSoftware != 1 {
		t.Errorf("cyber essentials devices = %d, want 1", rep.CyberEssentials.DevicesWithUnsupportedSoftware)
	}
	dev := slcGet(t, tok, "/v1/portal/reports/software/unsupported/devices?device_id="+gone)
	if dev.Total != 0 {
		t.Errorf("retired device drill-down returned %d rows, want 0", dev.Total)
	}
}
