package report

// PAT-1805 regression: devices.pending_updates is populated only by the
// macOS collector (migrations/0004_patching_data.sql) - Windows never
// writes it, so it is always NULL for a Windows device today.
// fetchPatchingStats used to read "pending_updates IS NULL OR
// jsonb_array_length(...) = 0" as a single "up to date" case, so a NULL
// value (no collector has ever reported this device's update state) was
// counted identically to a genuine zero-updates observation from the macOS
// collector. Every Windows-only tenant therefore showed 100% up to date,
// permanently, regardless of its real patch posture.
//
// The fix adds a third bucket, DevicesUpdateStateUnknown, keyed off
// pending_updates IS NULL rather than any OS special-case, so it
// self-corrects the moment a Windows collector starts emitting the field.
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as platform_switch_aggregation_db_test.go (pat862Pool).

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1805Schema = "pat1805_test"

func pat1805Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1805Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1805Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1805Schema,
		`CREATE TABLE ` + pat1805Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1805Schema + `.devices (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id       UUID NOT NULL REFERENCES ` + pat1805Schema + `.tenants(id),
			hostname        TEXT,
			os              TEXT,
			os_version      TEXT,
			last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
			pending_updates JSONB
		)`,
		// patches backs fetchPatchingStats' median-days-since-last-patch
		// query; empty is fine, the table just needs to exist.
		`CREATE TABLE ` + pat1805Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1805Schema+` CASCADE`)
	})
	return pool
}

// seedPAT1805Tenant creates a tenant with both platforms enabled and three
// devices: one macOS device with a non-empty pending_updates array, one
// macOS device with a real empty array, and one Windows device with NULL
// pending_updates - the shape of every Windows device today, since no
// collector has ever written this column for it.
func seedPAT1805Tenant(t *testing.T, pool *pgxpool.Pool) (tenantID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1805 Test Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	seeds := []struct {
		hostname string
		os       string
		pending  string // SQL literal: NULL or a jsonb array literal
	}{
		{"mac-pending", "macOS", `'[{"name":"Chrome"}]'::jsonb`},
		{"mac-clean", "macOS", `'[]'::jsonb`},
		{"win-unknown", "Windows", `NULL`},
	}
	for _, s := range seeds {
		if _, err := pool.Exec(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version, pending_updates)
			VALUES ($1::uuid, $2, $3, '1.0', `+s.pending+`)
		`, tenantID, s.hostname, s.os); err != nil {
			t.Fatalf("insert device %s: %v", s.hostname, err)
		}
	}
	return tenantID
}

// TestFetchPatchingStats_ThreeStates is the PAT-1805 acceptance test: a
// macOS device with pending updates, a macOS device with a real empty
// array, and a Windows device with NULL pending_updates must land in three
// different, mutually exclusive buckets, and the buckets must sum to the
// total in-scope device count.
func TestFetchPatchingStats_ThreeStates(t *testing.T) {
	pool := pat1805Pool(t)
	tenantID := seedPAT1805Tenant(t, pool)

	var stats PatchingStats
	if err := fetchPatchingStats(context.Background(), pool, tenantID,
		platformSwitches{macOSEnabled: true, windowsEnabled: true}, &stats); err != nil {
		t.Fatalf("fetchPatchingStats: %v", err)
	}

	if stats.DevicesPendingUpdates != 1 {
		t.Errorf("DevicesPendingUpdates = %d, want 1 (mac-pending)", stats.DevicesPendingUpdates)
	}
	if stats.DevicesUpToDate != 1 {
		t.Errorf("DevicesUpToDate = %d, want 1 (mac-clean)", stats.DevicesUpToDate)
	}
	if stats.DevicesUpdateStateUnknown != 1 {
		t.Errorf("DevicesUpdateStateUnknown = %d, want 1 (win-unknown: NULL pending_updates must never count as up to date)", stats.DevicesUpdateStateUnknown)
	}

	total := stats.DevicesUpToDate + stats.DevicesPendingUpdates + stats.DevicesUpdateStateUnknown
	if total != 3 {
		t.Errorf("three buckets sum to %d, want 3 (every seeded device must land in exactly one bucket)", total)
	}
}

// TestFetchPatchingStats_NullNeverCountsAsUpToDate is the direct regression
// assertion for the bug as filed: before the fix, fetchPatchingStats' SQL
// treated "pending_updates IS NULL" and "jsonb_array_length(...) = 0" as the
// same up-to-date case, so a NULL value (a device whose update state has
// never been collected) incremented the same counter as a genuine
// zero-updates observation.
func TestFetchPatchingStats_NullNeverCountsAsUpToDate(t *testing.T) {
	pool := pat1805Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1805 Null-Only Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version, pending_updates)
		VALUES ($1::uuid, 'win-only', 'Windows', '11', NULL)
	`, tenantID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	var stats PatchingStats
	if err := fetchPatchingStats(ctx, pool, tenantID,
		platformSwitches{macOSEnabled: true, windowsEnabled: true}, &stats); err != nil {
		t.Fatalf("fetchPatchingStats: %v", err)
	}

	if stats.DevicesUpToDate != 0 {
		t.Errorf("DevicesUpToDate = %d, want 0: a NULL pending_updates value must never increment the up-to-date counter", stats.DevicesUpToDate)
	}
	if stats.DevicesUpdateStateUnknown != 1 {
		t.Errorf("DevicesUpdateStateUnknown = %d, want 1", stats.DevicesUpdateStateUnknown)
	}
}

// TestFetchPatchStatusReport_ThreeStates exercises the same fixture through
// the full FetchPatchStatusReport path (tenant platform switches +
// fetchPatchingStats + the per-device pending-updates list) - the actual
// consumer path patch_status_pdf.go renders from.
func TestFetchPatchStatusReport_ThreeStates(t *testing.T) {
	pool := pat1805Pool(t)
	tenantID := seedPAT1805Tenant(t, pool)

	rep, err := FetchPatchStatusReport(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchPatchStatusReport: %v", err)
	}

	if rep.Patching.DevicesUpdateStateUnknown != 1 {
		t.Errorf("Patching.DevicesUpdateStateUnknown = %d, want 1", rep.Patching.DevicesUpdateStateUnknown)
	}
	total := rep.Patching.DevicesUpToDate + rep.Patching.DevicesPendingUpdates + rep.Patching.DevicesUpdateStateUnknown
	if total != 3 {
		t.Errorf("Patching buckets sum to %d, want 3", total)
	}

	// win-unknown has no pending updates recorded at all (NULL, not an
	// empty array), so it must not appear in the pending-updates device
	// list either - that list is scoped to jsonb_array_length > 0.
	for _, d := range rep.Devices {
		if d.Hostname == "win-unknown" {
			t.Errorf("win-unknown must not appear in the pending-updates device list (its pending_updates is NULL, not a non-empty array)")
		}
	}
}
