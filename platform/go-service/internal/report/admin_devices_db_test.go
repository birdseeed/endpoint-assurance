package report

// PAT-745 regression: disabling a platform via the tenant master switch
// (macos_enabled/windows_enabled = false) must NOT hide that platform's
// devices from GET /admin/tenants/{id}/devices (FetchTenantDevices). The
// extractor keeps ingesting/updating those devices — only their compliance
// evaluation/scoring is meant to be suppressed by the switch. Before this
// fix, FetchTenantDevices reused enabledOSFilter (the same SQL-layer filter
// the aggregate report queries use to exclude disabled-platform devices from
// their counts) and so silently dropped those devices from the roster too.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as internal/report/report_db_test.go and
// internal/auth/bearer_db_test.go. The pool's search_path is pinned to an
// isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat745Schema = "pat745_test"

func pat745Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat745Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat745Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat745Schema,
		// Only the columns FetchTenantDevices' queries touch.
		`CREATE TABLE ` + pat745Schema + `.tenants (
			id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name           TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat745Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat745Schema + `.tenants(id),
			serial               TEXT,
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			primary_user_display TEXT,
			backup_status        JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown',
			os_caption           TEXT
		)`,
		`CREATE TABLE ` + pat745Schema + `.compliance_rules (
			id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL,
			title    TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'low'
		)`,
		`CREATE TABLE ` + pat745Schema + `.compliance_evaluations (
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat745Schema + `.device_hardware (
			id                       BIGSERIAL PRIMARY KEY,
			device_id                UUID NOT NULL,
			battery_max_capacity_pct INTEGER,
			battery_condition        TEXT,
			battery_cycle_count      INTEGER
		)`,
		`CREATE TABLE ` + pat745Schema + `.device_storage_volume (
			id                 BIGSERIAL PRIMARY KEY,
			device_hardware_id BIGINT NOT NULL,
			mount              TEXT NOT NULL,
			free_bytes         BIGINT NOT NULL,
			used_pct           INTEGER NOT NULL
		)`,
		`CREATE TABLE ` + pat745Schema + `.device_disk (
			id                 BIGSERIAL PRIMARY KEY,
			device_hardware_id BIGINT NOT NULL,
			smart_status       TEXT NOT NULL,
			internal           BOOLEAN NOT NULL
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat745Schema+` CASCADE`)
	})
	return pool
}

// TestFetchTenantDevices_DisabledPlatformStaysVisible is the PAT-745
// regression test: a tenant with macOS disabled must still see its macOS
// devices in FetchTenantDevices, each flagged EvaluationDisabled, while its
// Windows devices (platform still enabled) are returned with the flag
// unset.
func TestFetchTenantDevices_DisabledPlatformStaysVisible(t *testing.T) {
	pool := pat745Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-745 Test Tenant', false, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var macDeviceID, winDeviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hostname, os, os_version)
		VALUES ($1::uuid, 'MACSERIAL', 'mac-01', 'macOS', '15.0')
		RETURNING id::text
	`, tenantID).Scan(&macDeviceID); err != nil {
		t.Fatalf("insert macOS device: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hostname, os, os_version)
		VALUES ($1::uuid, 'WINSERIAL', 'win-01', 'Windows', '11')
		RETURNING id::text
	`, tenantID).Scan(&winDeviceID); err != nil {
		t.Fatalf("insert Windows device: %v", err)
	}

	// Give the macOS device some stale compliance history from before the
	// platform was disabled — FetchTenantDevices should still surface it
	// (the switch suppresses future evaluation, it doesn't erase history).
	var ruleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat745_test_rule', 'PAT-745 Test Rule', 'high')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, severity)
		VALUES ($1::uuid, $2::uuid, 'pass', 'high')
	`, macDeviceID, ruleID); err != nil {
		t.Fatalf("insert evaluation: %v", err)
	}

	result, err := FetchTenantDevices(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchTenantDevices: %v", err)
	}
	if result.Total != 2 {
		t.Fatalf("Total = %d, want 2 (macOS device must not be hidden by the disabled platform switch)", result.Total)
	}
	if len(result.Devices) != 2 {
		t.Fatalf("len(Devices) = %d, want 2", len(result.Devices))
	}

	var mac, win *TenantDeviceRow
	for i := range result.Devices {
		switch result.Devices[i].ID {
		case macDeviceID:
			mac = &result.Devices[i]
		case winDeviceID:
			win = &result.Devices[i]
		}
	}
	if mac == nil {
		t.Fatal("macOS device missing from FetchTenantDevices result — disabled platform switch hid it")
	}
	if win == nil {
		t.Fatal("Windows device missing from FetchTenantDevices result")
	}

	if !mac.EvaluationDisabled {
		t.Error("macOS device: EvaluationDisabled = false, want true (macos_enabled is false for this tenant)")
	}
	if win.EvaluationDisabled {
		t.Error("Windows device: EvaluationDisabled = true, want false (windows_enabled is true for this tenant)")
	}

	// The macOS device's pre-disablement evaluation history should still be
	// reflected in its compliance summary, not zeroed out.
	if mac.PassCount != 1 {
		t.Errorf("macOS device PassCount = %d, want 1 (stale evaluation history should still count)", mac.PassCount)
	}
}

// TestFetchTenantDevices_AllPlatformsEnabled is a control case: with both
// switches on, no device should ever be marked EvaluationDisabled.
func TestFetchTenantDevices_AllPlatformsEnabled(t *testing.T) {
	pool := pat745Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-745 Control Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, serial, hostname, os, os_version)
		VALUES ($1::uuid, 'MACSERIAL2', 'mac-02', 'macOS', '15.0')
	`, tenantID); err != nil {
		t.Fatalf("insert macOS device: %v", err)
	}

	result, err := FetchTenantDevices(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchTenantDevices: %v", err)
	}
	if len(result.Devices) != 1 {
		t.Fatalf("len(Devices) = %d, want 1", len(result.Devices))
	}
	if result.Devices[0].EvaluationDisabled {
		t.Error("EvaluationDisabled = true, want false when both platform switches are enabled")
	}
}
