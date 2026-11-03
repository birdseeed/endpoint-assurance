package cvepipeline

// PAT-2029: app_cpe_mappings.platform ('any' | 'macos' | 'windows') exists,
// but LoadMappings never selected it and matchDevice (the event-driven
// match path introduced by PAT-2024) never scoped a mapping to the device's
// own platform, so a platform-specific mapping (e.g. a Windows-only
// Microsoft Word CPE) applied to a macOS device too. This test exercises the
// real LoadMappings SQL (proving it selects platform) and matchDevice (the
// write path) end to end against a live database, mirroring the same
// scenario cmd/patched-cve-sync/platform_scope_db_test.go exercises through
// the nightly full-match path, so both matchers are proven to agree.

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const platformScopeTestSchema = "pat2029_platform_scope_test"

func platformScopeTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping platform-scope DB test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = platformScopeTestSchema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	for _, stmt := range []string{
		`DROP SCHEMA IF EXISTS ` + platformScopeTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + platformScopeTestSchema,
		`CREATE TABLE ` + platformScopeTestSchema + `.app_cpe_mappings (id BIGSERIAL PRIMARY KEY,
			platform TEXT NOT NULL DEFAULT 'any', match_name TEXT NOT NULL, cpe_vendor TEXT NOT NULL,
			cpe_product TEXT NOT NULL, source_type TEXT NOT NULL DEFAULT 'app_name',
			review_state TEXT NOT NULL DEFAULT 'curated')`,
		`CREATE TABLE ` + platformScopeTestSchema + `.devices (id UUID PRIMARY KEY, tenant_id UUID NOT NULL,
			hostname TEXT, os TEXT)`,
		`CREATE TABLE ` + platformScopeTestSchema + `.device_apps (device_id UUID NOT NULL, name TEXT NOT NULL, version TEXT)`,
		`CREATE TABLE ` + platformScopeTestSchema + `.cve_feed_entries (cve_id TEXT PRIMARY KEY,
			description TEXT NOT NULL DEFAULT '', cvss_v3_score NUMERIC(4,1), severity TEXT,
			cpe_patterns TEXT[] NOT NULL DEFAULT '{}', cpe_ranges JSONB NOT NULL DEFAULT '[]',
			published_at TIMESTAMPTZ)`,
		`CREATE TABLE ` + platformScopeTestSchema + `.device_cve_findings (device_id UUID NOT NULL, cve_id TEXT NOT NULL,
			app_name TEXT NOT NULL, app_version TEXT NOT NULL DEFAULT '', cvss_v3_score NUMERIC(4,1), severity TEXT,
			match_confidence TEXT NOT NULL DEFAULT 'version_unverified', fixed_version TEXT NOT NULL DEFAULT '',
			first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			mapping_basis TEXT, UNIQUE (device_id, cve_id, app_name))`,
		`CREATE TABLE ` + platformScopeTestSchema + `.cve_match_assessments (device_id UUID NOT NULL, tenant_id UUID NOT NULL,
			app_name TEXT NOT NULL, app_versions TEXT[] NOT NULL, finding_count INT NOT NULL,
			last_matched_at TIMESTAMPTZ NOT NULL, match_source TEXT NOT NULL, PRIMARY KEY (device_id, app_name))`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+platformScopeTestSchema+` CASCADE`)
	})
	return pool
}

func TestMatchDeviceScopesFindingsByDevicePlatform(t *testing.T) {
	pool := platformScopeTestPool(t)
	ctx := context.Background()
	s := platformScopeTestSchema

	const (
		windowsDevice = "11111111-1111-1111-1111-111111111111"
		macosDevice   = "22222222-2222-2222-2222-222222222222"
		unknownDevice = "33333333-3333-3333-3333-333333333333"
		tenantID      = "99999999-9999-9999-9999-999999999999"
	)
	for _, stmt := range []string{
		`INSERT INTO ` + s + `.app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product) VALUES
			('windows', 'Test Word', 'microsoft', 'word'),
			('macos',   'Test Word', 'microsoft', 'word-mac'),
			('any',     'Test AnyApp', 'acme', 'anyapp')`,
		`INSERT INTO ` + s + `.devices (id, tenant_id, hostname, os) VALUES
			('` + windowsDevice + `', '` + tenantID + `', 'win-host', 'Windows'),
			('` + macosDevice + `', '` + tenantID + `', 'mac-host', 'macOS'),
			('` + unknownDevice + `', '` + tenantID + `', 'unk-host', NULL)`,
		`INSERT INTO ` + s + `.device_apps (device_id, name, version) VALUES
			('` + windowsDevice + `', 'Test Word', '1.0'), ('` + windowsDevice + `', 'Test AnyApp', '1.0'),
			('` + macosDevice + `', 'Test Word', '1.0'), ('` + macosDevice + `', 'Test AnyApp', '1.0'),
			('` + unknownDevice + `', 'Test Word', '1.0'), ('` + unknownDevice + `', 'Test AnyApp', '1.0')`,
		`INSERT INTO ` + s + `.cve_feed_entries (cve_id, cvss_v3_score, severity, cpe_patterns) VALUES
			('CVE-2099-0301', 9.0, 'CRITICAL', ARRAY['microsoft:word']),
			('CVE-2099-0302', 8.0, 'HIGH',     ARRAY['microsoft:word-mac']),
			('CVE-2099-0303', 7.0, 'HIGH',     ARRAY['acme:anyapp'])`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}

	// LoadMappings' own SQL must select platform, not just default the Go
	// struct field: assert the loaded rows carry the platform actually
	// stored, keyed by cpe_product so the assertion doesn't depend on row
	// order.
	mappings, err := LoadMappings(ctx, pool)
	if err != nil {
		t.Fatalf("LoadMappings: %v", err)
	}
	gotPlatforms := map[string]string{}
	for _, m := range mappings {
		gotPlatforms[m.CPEProduct] = m.Platform
	}
	wantPlatforms := map[string]string{"word": "windows", "word-mac": "macos", "anyapp": "any"}
	if !reflect.DeepEqual(gotPlatforms, wantPlatforms) {
		t.Fatalf("LoadMappings platforms = %v, want %v", gotPlatforms, wantPlatforms)
	}

	ix := newMappingIndex(mappings)
	feed := newFeedCache()
	names := []string{"Test Word", "Test AnyApp"}

	for _, deviceID := range []string{windowsDevice, macosDevice, unknownDevice} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin tx for %s: %v", deviceID, err)
		}
		if _, err := matchDevice(ctx, tx, ix, feed, deviceID, names, SourceIngest); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("matchDevice(%s): %v", deviceID, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit for %s: %v", deviceID, err)
		}
	}

	rows, err := pool.Query(ctx, `SELECT device_id::text, cve_id FROM `+s+`.device_cve_findings ORDER BY device_id, cve_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string][]string{}
	for rows.Next() {
		var device, cve string
		if err := rows.Scan(&device, &cve); err != nil {
			t.Fatal(err)
		}
		got[device] = append(got[device], cve)
	}
	want := map[string][]string{
		windowsDevice: {"CVE-2099-0301", "CVE-2099-0303"}, // windows word + any
		macosDevice:   {"CVE-2099-0302", "CVE-2099-0303"}, // macos word + any
		unknownDevice: {"CVE-2099-0303"},                  // any only; FreeBSD is never guessed as macos/windows
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("device_cve_findings by device = %v, want %v", got, want)
	}

	// The assessment rows matchDevice writes must agree: an unrecognised
	// platform still has a real ('any') mapping to assess Test AnyApp
	// against, but Test Word is not_assessed there (no mapping applies), so
	// no assessment row exists for it on that device.
	assessRows, err := pool.Query(ctx, `SELECT device_id::text, app_name FROM `+s+`.cve_match_assessments ORDER BY device_id, app_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer assessRows.Close()
	gotAssessed := map[string][]string{}
	for assessRows.Next() {
		var device, app string
		if err := assessRows.Scan(&device, &app); err != nil {
			t.Fatal(err)
		}
		gotAssessed[device] = append(gotAssessed[device], app)
	}
	wantAssessed := map[string][]string{
		windowsDevice: {"Test AnyApp", "Test Word"},
		macosDevice:   {"Test AnyApp", "Test Word"},
		unknownDevice: {"Test AnyApp"}, // Test Word has no applicable mapping on this platform
	}
	if !reflect.DeepEqual(gotAssessed, wantAssessed) {
		t.Fatalf("cve_match_assessments by device = %v, want %v", gotAssessed, wantAssessed)
	}
}
