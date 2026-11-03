//go:build integration

package integration

// PAT-2150 (child of PAT-2146): the SAM version sprawl report. Reuses the
// PAT-2147 lifecycle test helpers (slcSeedDevice, slcSeedInstall, slcStore,
// slcPropose) from software_lifecycle_test.go in this same package.

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/lifecycle"
)

type vsVersion struct {
	Version          string `json:"version"`
	DeviceCount      int    `json:"device_count"`
	StaleDeviceCount int    `json:"stale_device_count"`
}

type vsProduct struct {
	ProductKey                    string      `json:"product_key"`
	Name                          string      `json:"name"`
	Platform                      string      `json:"platform"`
	DistinctVersions              int         `json:"distinct_versions"`
	OldestVersion                 string      `json:"oldest_version"`
	NewestVersion                 string      `json:"newest_version"`
	LatestReleased                *string     `json:"latest_released"`
	LatestReleasedSource          *vsSource   `json:"latest_released_source"`
	DevicesMoreThanOneMajorBehind int         `json:"devices_more_than_one_major_behind"`
	DevicesNotComparable          int         `json:"devices_not_comparable"`
	CVECountOnOldest              *int        `json:"cve_count_on_oldest_version"`
	CVENotAssessed                bool        `json:"cve_not_assessed_on_oldest_version"`
	DeviceCount                   int         `json:"device_count"`
	StaleDeviceCount              int         `json:"stale_device_count"`
	Versions                      []vsVersion `json:"versions"`
}

type vsSource struct {
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	URL       string     `json:"url"`
	Label     string     `json:"label"`
	CheckedAt *time.Time `json:"checked_at"`
}

type vsReport struct {
	Definition struct {
		ID                     string   `json:"id"`
		MajorVersionRule       string   `json:"major_version_rule"`
		LatestSourcePrecedence []string `json:"latest_source_precedence"`
		CatalogueMaxAgeDays    int      `json:"catalogue_max_age_days"`
	} `json:"definition"`
	Basis struct {
		DevicesTotal    int    `json:"devices_total"`
		DevicesAssessed int    `json:"devices_assessed"`
		DevicesStale    int    `json:"devices_stale"`
		DevicesRetired  int    `json:"devices_retired"`
		RetiredExcluded bool   `json:"retired_devices_excluded"`
		Complete        bool   `json:"complete"`
		Statement       string `json:"statement"`
		NotCounted      []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"not_counted"`
	} `json:"basis"`
	Total    int         `json:"total"`
	Products []vsProduct `json:"products"`
}

func vsGet(t *testing.T, token, path string) vsReport {
	t.Helper()
	resp := portalDo(t, http.MethodGet, path, token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
	}
	var out vsReport
	decodeJSON(t, resp, &out)
	return out
}

// vsRef renders a latest_released pointer for a failure message.
func vsRef(p *string) string {
	if p == nil {
		return "null"
	}
	return *p
}

func vsFindByKey(products []vsProduct, key string) *vsProduct {
	for i := range products {
		if products[i].ProductKey == key {
			return &products[i]
		}
	}
	return nil
}

// TestVersionSprawlReport covers the three required cases in one seed (a
// product with one version, one with many, one with no known latest
// release), plus a curated-catalogue-trusted Homebrew formula, a
// lifecycle-sourced latest via a published mapping, a retired device
// excluded, tenant isolation and the CSV export.
func TestVersionSprawlReport(t *testing.T) {
	ctx := context.Background()
	sfx := randomHex(4)
	now := time.Now().UTC()
	fresh := now.Add(-time.Hour)

	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "pat2150-a-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantA)
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "pat2150-b-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTestTenant(t, tenantB)
	emailA, emailB := "a-"+sfx+"@pat2150.example", "b-"+sfx+"@pat2150.example"
	mapPortalUser(t, emailA, tenantA, http.StatusCreated)
	mapPortalUser(t, emailB, tenantB, http.StatusCreated)
	tokA, tokB := env.idp.token(t, emailA), env.idp.token(t, emailB)

	// --- Case 1: a product with exactly one live version. ---
	oneID := "com.pat2150.one" + sfx
	oneDev1 := slcSeedDevice(t, tenantA, "one-1-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	oneDev2 := slcSeedDevice(t, tenantA, "one-2-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	oneKey := slcSeedInstall(t, tenantA, oneDev1, "macos", "macos_bundle", oneID, "", "OneVersionApp", "4.2.0")
	slcSeedInstall(t, tenantA, oneDev2, "macos", "macos_bundle", oneID, "", "OneVersionApp", "4.2.0")

	// --- Case 2: a product spread across many versions, with a real
	// major-behind spread and one unparseable (Homebrew HEAD-shaped) version
	// that must read "not comparable", never behind or current. ---
	manyID := "com.pat2150.many" + sfx
	manyCurrent := slcSeedDevice(t, tenantA, "many-current-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	manyOneBehind := slcSeedDevice(t, tenantA, "many-oneback-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	manyTwoBehind := slcSeedDevice(t, tenantA, "many-twoback-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	manyStale := slcSeedDevice(t, tenantA, "many-stale-"+sfx, "macOS", "15.0", "24A5", "", now.Add(-20*24*time.Hour))
	manyUnparseable := slcSeedDevice(t, tenantA, "many-unparse-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	manyKey := slcSeedInstall(t, tenantA, manyCurrent, "macos", "macos_bundle", manyID, "", "ManyVersionApp", "10.0.0")
	slcSeedInstall(t, tenantA, manyOneBehind, "macos", "macos_bundle", manyID, "", "ManyVersionApp", "9.5.0")
	slcSeedInstall(t, tenantA, manyTwoBehind, "macos", "macos_bundle", manyID, "", "ManyVersionApp", "8.0.0")
	slcSeedInstall(t, tenantA, manyStale, "macos", "macos_bundle", manyID, "", "ManyVersionApp", "8.0.0")
	slcSeedInstall(t, tenantA, manyUnparseable, "macos", "macos_bundle", manyID, "", "ManyVersionApp", "HEAD-deadbee")

	// --- Case 3: a product with no known latest release (no lifecycle
	// mapping, no catalogue entry). Its newest-seen version must never be
	// echoed back as latest_released. ---
	unknownID := "com.pat2150.unknownlatest" + sfx
	unknownDev := slcSeedDevice(t, tenantA, "unknown-latest-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	unknownKey := slcSeedInstall(t, tenantA, unknownDev, "macos", "macos_bundle", unknownID, "", "NoLatestApp", "99.9.9")

	// --- A Homebrew formula with a trusted latest via the curated catalogue
	// (app_catalog_entries applies uniformly across identity kinds; Patched
	// holds no separate Homebrew upstream-version feed). ---
	brewDev := slcSeedDevice(t, tenantA, "brew-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	brewName := "pat2150brew" + sfx
	brewKey := slcSeedInstall(t, tenantA, brewDev, "macos", "homebrew_formula", brewName, "homebrew/core", brewName, "1.0.0")
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO app_catalog_entries (label, name, category, platform, verified_signer, latest_version, verified_at)
		VALUES ($1, $2, 'Development', 'macOS', NULL, '1.4.0', now())`, "pat2150-cat-"+sfx, brewName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), `DELETE FROM app_catalog_entries WHERE label = $1`, "pat2150-cat-"+sfx)
	})

	// A curated Homebrew CVE mapping plus a matched finding: the CVE count
	// on the oldest (only) live version must be real evidence, not a guess.
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, 'pat2150vendor', 'pat2150product', 'test', 'homebrew_formula', 'curated')`, brewName); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ($1, 'integration test vulnerability', 'nvd', 9.1, 'CRITICAL') ON CONFLICT (cve_id) DO NOTHING`,
		"CVE-2150-"+sfx); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, cvss_v3_score, severity)
		VALUES ($1::uuid, $2, $3, '1.0.0', 9.1, 'CRITICAL')`,
		brewDev, "CVE-2150-"+sfx, brewName+" (Homebrew formula)"); err != nil {
		t.Fatal(err)
	}

	// --- A lifecycle-sourced latest via a staff-published endoflife.date
	// mapping. ---
	lcID := "com.pat2150.lifecycle" + sfx
	lcSlug := "pat2150-lc-" + sfx
	slcStore(t, lcSlug, now.Add(-time.Hour), []lifecycle.Cycle{
		{Name: "1", LatestVersion: "1.9.0"},
		{Name: "2", LatestVersion: "2.6.1"}, // newest by release_date DESC in LoadProducts
	})
	lcPub := slcPropose(t, map[string]any{"platform": "macos", "identity_kind": "macos_bundle",
		"identity_value": lcID, "eol_slug": lcSlug, "version_rule": "major"}, http.StatusCreated)
	adminJSON(t, http.MethodPost, fmt.Sprintf("/admin/lifecycle/mappings/%d/publish", lcPub.Mapping.ID), nil, http.StatusOK, nil)
	lcDev := slcSeedDevice(t, tenantA, "lc-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	lcKey := slcSeedInstall(t, tenantA, lcDev, "macos", "macos_bundle", lcID, "", "LifecycleLatestApp", "1.5.0")

	// --- PAT-2509: two products from one vendor share a Team ID. Each must be
	// shown its own catalogue reference, never the other's; a reference lower
	// than a live version, or from an entry not verified inside the window, is
	// not shown at all. ---
	sharedTeam := "PAT2509TM1"
	mkCatalogue := func(label, name, signer, latest string, verifiedAt time.Time) {
		t.Helper()
		var signerArg any
		if signer != "" {
			signerArg = signer
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO app_catalog_entries (label, name, category, platform, verified_signer, latest_version, verified_at)
			VALUES ($1, $2, 'Test', 'macOS', $3, $4, $5)`, label, name, signerArg, latest, verifiedAt); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = env.pool.Exec(context.Background(), `DELETE FROM app_catalog_entries WHERE label = $1`, label)
		})
	}
	edgeName, excelName := "Pat2509Edge"+sfx, "Pat2509Excel"+sfx
	mkCatalogue("pat2509-edge-"+sfx, edgeName, sharedTeam, "126.0.2592.68", now)
	mkCatalogue("pat2509-excel-"+sfx, excelName, sharedTeam, "16.86.24061613", now)
	edgeDev := slcSeedDevice(t, tenantA, "edge-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	excelDev := slcSeedDevice(t, tenantA, "excel-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	edgeKey := slcSeedInstall(t, tenantA, edgeDev, "macos", "macos_bundle_team", "com.pat2509.edge"+sfx, sharedTeam, edgeName, "120.0.1")
	excelKey := slcSeedInstall(t, tenantA, excelDev, "macos", "macos_bundle_team", "com.pat2509.excel"+sfx, sharedTeam, excelName, "16.70.0")

	// Same vendor, no catalogue entry of its own: the shared signer alone gives
	// it nothing.
	strangerDev := slcSeedDevice(t, tenantA, "stranger-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	strangerKey := slcSeedInstall(t, tenantA, strangerDev, "macos", "macos_bundle_team", "com.pat2509.stranger"+sfx, sharedTeam, "Pat2509Stranger"+sfx, "3.0.0")

	// A longer display name that merely contains a catalogue name is a
	// different product ("Teams classic" is not "Teams"): no reference.
	classicDev := slcSeedDevice(t, tenantA, "classic-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	classicKey := slcSeedInstall(t, tenantA, classicDev, "macos", "macos_bundle_team", "com.pat2509.excelclassic"+sfx, sharedTeam, excelName+" classic", "16.70.0")

	// An entry not verified inside the window is not a reference.
	staleName := "Pat2509Stale" + sfx
	mkCatalogue("pat2509-stale-"+sfx, staleName, "PAT2509TM2", "5.0.0", now.Add(-30*24*time.Hour))
	staleDev := slcSeedDevice(t, tenantA, "staleref-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	staleKey := slcSeedInstall(t, tenantA, staleDev, "macos", "macos_bundle_team", "com.pat2509.stale"+sfx, "PAT2509TM2", staleName, "4.0.0")

	// A fresh entry that is lower than a version the estate is running.
	behindName := "Pat2509Behind" + sfx
	mkCatalogue("pat2509-behind-"+sfx, behindName, "PAT2509TM3", "126.0.6478.127", now)
	behindDevA := slcSeedDevice(t, tenantA, "behind-a-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	behindDevB := slcSeedDevice(t, tenantA, "behind-b-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	behindKey := slcSeedInstall(t, tenantA, behindDevA, "macos", "macos_bundle_team", "com.pat2509.behind"+sfx, "PAT2509TM3", behindName, "149.0.7000.1")
	slcSeedInstall(t, tenantA, behindDevB, "macos", "macos_bundle_team", "com.pat2509.behind"+sfx, "PAT2509TM3", behindName, "154.0.8037.58")

	// --- A retired device: its install must not be counted anywhere. ---
	retiredID := "com.pat2150.retired" + sfx
	retiredLive := slcSeedDevice(t, tenantA, "retired-live-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	retiredGone := slcSeedDevice(t, tenantA, "retired-gone-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	retiredKey := slcSeedInstall(t, tenantA, retiredLive, "macos", "macos_bundle", retiredID, "", "RetiredScopeApp", "5.0.0")
	slcSeedInstall(t, tenantA, retiredGone, "macos", "macos_bundle", retiredID, "", "RetiredScopeApp", "5.0.0")
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
		VALUES ($1::uuid, $2::uuid, 'retire', 'admin@pat2150.example')`, tenantA, retiredGone); err != nil {
		t.Fatal(err)
	}

	// --- Tenant isolation: same product identity on tenant B. ---
	bDev := slcSeedDevice(t, tenantB, "b-"+sfx, "macOS", "15.0", "24A5", "", fresh)
	slcSeedInstall(t, tenantB, bDev, "macos", "macos_bundle", oneID, "", "OneVersionApp", "1.0.0")

	rep := vsGet(t, tokA, "/v1/portal/reports/software/version-sprawl?limit=500")
	if rep.Definition.ID != "sam.version-sprawl" {
		t.Fatalf("definition id = %q", rep.Definition.ID)
	}
	if rep.Definition.MajorVersionRule == "" || len(rep.Definition.LatestSourcePrecedence) == 0 {
		t.Errorf("definition missing documentation: %+v", rep.Definition)
	}
	if rep.Definition.CatalogueMaxAgeDays != 7 {
		t.Errorf("definition catalogue_max_age_days = %d, want 7", rep.Definition.CatalogueMaxAgeDays)
	}

	// Case 1: one version, no sprawl.
	if r := vsFindByKey(rep.Products, oneKey); r == nil {
		t.Fatal("one-version product row missing")
	} else {
		if r.DistinctVersions != 1 || r.OldestVersion != "4.2.0" || r.NewestVersion != "4.2.0" {
			t.Errorf("one-version row = %+v", r)
		}
		if r.DevicesMoreThanOneMajorBehind != 0 || r.DevicesNotComparable != 0 {
			t.Errorf("one-version row behind/not-comparable = %+v", r)
		}
		if r.DeviceCount != 2 {
			t.Errorf("one-version device count = %d, want 2", r.DeviceCount)
		}
	}

	// Case 2: many versions, real sprawl.
	if r := vsFindByKey(rep.Products, manyKey); r == nil {
		t.Fatal("many-version product row missing")
	} else {
		if r.DistinctVersions != 3 { // 10.0.0, 9.5.0, 8.0.0 -- HEAD-deadbee excluded
			t.Errorf("many-version distinct versions = %d, want 3", r.DistinctVersions)
		}
		if r.OldestVersion != "8.0.0" || r.NewestVersion != "10.0.0" {
			t.Errorf("many-version oldest/newest = %q/%q, want 8.0.0/10.0.0", r.OldestVersion, r.NewestVersion)
		}
		// Newest live major is 10; major 8 (two devices: manyTwoBehind,
		// manyStale) is two behind, major 9 is one behind (not counted).
		if r.DevicesMoreThanOneMajorBehind != 2 {
			t.Errorf("many-version devices behind = %d, want 2", r.DevicesMoreThanOneMajorBehind)
		}
		if r.DevicesNotComparable != 1 {
			t.Errorf("many-version devices not comparable = %d, want 1 (the HEAD-shaped version)", r.DevicesNotComparable)
		}
		if r.DeviceCount != 5 {
			t.Errorf("many-version device count = %d, want 5", r.DeviceCount)
		}
		if r.StaleDeviceCount != 1 {
			t.Errorf("many-version stale device count = %d, want 1", r.StaleDeviceCount)
		}
		var versionsSeen []string
		for _, v := range r.Versions {
			versionsSeen = append(versionsSeen, v.Version)
		}
		if len(r.Versions) != 3 {
			t.Errorf("many-version breakdown = %v, want 3 entries", versionsSeen)
		}
	}

	// Case 3: no known latest release. The newest version seen on the
	// estate (99.9.9) must never be echoed back as latest_released.
	if r := vsFindByKey(rep.Products, unknownKey); r == nil {
		t.Fatal("no-known-latest product row missing")
	} else {
		if r.LatestReleased != nil {
			t.Errorf("latest released = %q, want nil (no trusted source, must never fall back to newest seen)", *r.LatestReleased)
		}
		if r.LatestReleasedSource != nil {
			t.Errorf("latest released source = %+v, want nil", r.LatestReleasedSource)
		}
		if !r.CVENotAssessed || r.CVECountOnOldest != nil {
			t.Errorf("no-known-latest cve = assessed:%v count:%v, want not assessed (no cpe mapping)", !r.CVENotAssessed, r.CVECountOnOldest)
		}
	}

	// Homebrew formula: trusted latest via the curated catalogue, and a
	// real CVE count on its (only) live version.
	if r := vsFindByKey(rep.Products, brewKey); r == nil {
		t.Fatal("homebrew product row missing")
	} else {
		if r.LatestReleased == nil || *r.LatestReleased != "1.4.0" {
			t.Errorf("homebrew latest released = %v, want 1.4.0", r.LatestReleased)
		}
		if r.LatestReleasedSource == nil || r.LatestReleasedSource.Name != "curated_catalogue" {
			t.Errorf("homebrew latest released source = %+v, want curated_catalogue", r.LatestReleasedSource)
		} else if r.LatestReleasedSource.Label != "Patched reference list" || r.LatestReleasedSource.CheckedAt == nil {
			t.Errorf("homebrew latest released source = %+v, want label %q and a checked_at", r.LatestReleasedSource, "Patched reference list")
		}
		if r.CVENotAssessed {
			t.Error("homebrew product with a curated mapping read not assessed")
		}
		if r.CVECountOnOldest == nil || *r.CVECountOnOldest != 1 {
			t.Errorf("homebrew cve count = %v, want 1", r.CVECountOnOldest)
		}
	}

	// Lifecycle-sourced latest via a published mapping: the newest cycle's
	// latest_version (2.6.1), not the oldest cycle's (1.9.0).
	if r := vsFindByKey(rep.Products, lcKey); r == nil {
		t.Fatal("lifecycle-latest product row missing")
	} else {
		if r.LatestReleased == nil || *r.LatestReleased != "2.6.1" {
			t.Errorf("lifecycle latest released = %v, want 2.6.1", r.LatestReleased)
		}
		if r.LatestReleasedSource == nil || r.LatestReleasedSource.Name != "endoflife.date" || r.LatestReleasedSource.Slug != lcSlug {
			t.Errorf("lifecycle latest released source = %+v, want endoflife.date/%s", r.LatestReleasedSource, lcSlug)
		} else if r.LatestReleasedSource.Label != "endoflife.date" || r.LatestReleasedSource.CheckedAt == nil {
			t.Errorf("lifecycle latest released source = %+v, want label endoflife.date and a checked_at", r.LatestReleasedSource)
		}
	}

	// PAT-2509: shared signer never crosses products.
	if r := vsFindByKey(rep.Products, edgeKey); r == nil {
		t.Fatal("shared-signer Edge-like row missing")
	} else if r.LatestReleased == nil || *r.LatestReleased != "126.0.2592.68" {
		t.Errorf("Edge-like reference = %s, want its own 126.0.2592.68", vsRef(r.LatestReleased))
	}
	if r := vsFindByKey(rep.Products, excelKey); r == nil {
		t.Fatal("shared-signer Excel-like row missing")
	} else if r.LatestReleased == nil || *r.LatestReleased != "16.86.24061613" {
		t.Errorf("Excel-like reference = %s, want its own 16.86.24061613, never the other product's", vsRef(r.LatestReleased))
	}
	if r := vsFindByKey(rep.Products, strangerKey); r == nil {
		t.Fatal("shared-signer stranger row missing")
	} else if r.LatestReleased != nil || r.LatestReleasedSource != nil {
		t.Errorf("stranger under a shared signer got reference %s / %+v, want none", vsRef(r.LatestReleased), r.LatestReleasedSource)
	}
	if r := vsFindByKey(rep.Products, classicKey); r == nil {
		t.Fatal("partial-name row missing")
	} else if r.LatestReleased != nil || r.LatestReleasedSource != nil {
		t.Errorf("a name that only contains a catalogue name got reference %s / %+v, want none", vsRef(r.LatestReleased), r.LatestReleasedSource)
	}
	// PAT-2509: an entry not verified inside the window shows nothing.
	if r := vsFindByKey(rep.Products, staleKey); r == nil {
		t.Fatal("stale-reference row missing")
	} else if r.LatestReleased != nil || r.LatestReleasedSource != nil {
		t.Errorf("30-day-old catalogue entry produced reference %s / %+v, want none", vsRef(r.LatestReleased), r.LatestReleasedSource)
	}
	// PAT-2509: a reference lower than a live version is withheld.
	if r := vsFindByKey(rep.Products, behindKey); r == nil {
		t.Fatal("behind-reference row missing")
	} else if r.LatestReleased != nil || r.LatestReleasedSource != nil {
		t.Errorf("reference 126 under live 154 produced %s / %+v, want none", vsRef(r.LatestReleased), r.LatestReleasedSource)
	}

	// Retired device excluded from every figure.
	if r := vsFindByKey(rep.Products, retiredKey); r == nil {
		t.Fatal("retired-scope product row missing")
	} else if r.DeviceCount != 1 {
		t.Errorf("retired-scope device count = %d, want 1 (the retired device excluded)", r.DeviceCount)
	}
	var retiredNC int
	for _, nc := range rep.Basis.NotCounted {
		if nc.Reason == "retired_devices" {
			retiredNC = nc.Count
		}
	}
	if retiredNC != 1 || rep.Basis.DevicesRetired != 1 || !rep.Basis.RetiredExcluded {
		t.Errorf("basis retired accounting = %+v, not_counted retired=%d", rep.Basis, retiredNC)
	}

	// Tenant isolation: tenant B installed the identical product identity
	// (so the same identity fingerprint / product_key, by design -- the key
	// is not tenant-scoped), but its figures must reflect only its own
	// device and version, never tenant A's.
	repB := vsGet(t, tokB, "/v1/portal/reports/software/version-sprawl?limit=500")
	if repB.Basis.DevicesTotal != 1 {
		t.Errorf("tenant B devices total = %d, want 1", repB.Basis.DevicesTotal)
	}
	if repB.Total != 1 {
		t.Errorf("tenant B product total = %d, want 1", repB.Total)
	}
	if r := vsFindByKey(repB.Products, oneKey); r == nil {
		t.Fatal("tenant B's own product row missing")
	} else if r.DeviceCount != 1 || r.OldestVersion != "1.0.0" || r.NewestVersion != "1.0.0" {
		t.Errorf("tenant B row leaked tenant A data: %+v", r)
	}

	// Unknown query parameters are refused.
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/software/version-sprawl?stat=unsupported", tokA, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("typo parameter = %d, want 400", resp.StatusCode)
	}

	// CSV export: one row per product, unpaged.
	resp = portalDo(t, http.MethodGet, "/v1/portal/reports/software/version-sprawl?format=csv", tokA, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	records, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if body := string(body); strings.Contains(body, "curated_catalogue") {
		t.Errorf("csv prints the machine source name curated_catalogue")
	}
	wantTail := []string{"generated_at", "latest_released_checked_at"}
	if h := records[0]; len(h) != 15 || strings.Join(h[len(h)-2:], ",") != strings.Join(wantTail, ",") {
		t.Errorf("csv header = %v, want 14 original columns then %v", h, wantTail)
	}
	if len(records) != 1+len(rep.Products) {
		t.Errorf("csv rows = %d, want %d (header + %d products)", len(records), 1+len(rep.Products), len(rep.Products))
	}
	for _, rec := range records[1:] {
		for _, cell := range rec {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) && !strings.HasPrefix(cell, "-") {
				t.Errorf("unneutralised csv cell %q", cell)
			}
		}
	}
}
