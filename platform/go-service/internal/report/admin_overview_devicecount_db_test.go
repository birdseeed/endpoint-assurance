package report

// PAT-1686 regression: the tenant-list/sidebar device count
// (FetchTenantsOverview.DeviceCount, served by GET /admin/tenants/overview
// and rendered as the dashboard's tenant header "N devices" and tenant-list
// "Devices" column) and the tenant's Devices page total
// (FetchTenantDevices.Total, served by GET /admin/tenants/{id}/devices) are
// supposed to answer the exact same question — "how many devices does this
// tenant have" — for the same tenant, at the same time.
//
// Before this fix they didn't: FetchTenantsOverview computed DeviceCount from
// the eligible-devices CTE, which excludes a platform's devices when that
// platform's tenant master switch (macos_enabled/windows_enabled) is off.
// FetchTenantDevices stopped doing that under PAT-745 (be602bc) specifically
// so disabling a platform's compliance scoring didn't also cost operators
// fleet visibility on the roster. FetchTenantsOverview was never updated to
// match, so a tenant with a disabled platform showed two different device
// counts across the dashboard for the same estate.
//
// This test builds a tenant with macos_enabled = false and both macOS and
// Windows devices, then asserts FetchTenantsOverview's DeviceCount and
// ActiveLast7d equal FetchTenantDevices' Total and its own live-computed
// active-7d count — both counting every device, macOS included.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as admin_devices_db_test.go (pat745Pool) and
// platform_switch_aggregation_db_test.go (pat862Pool). The pool's
// search_path is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1686Schema = "pat1686_test"

func pat1686Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1686Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1686Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1686Schema,
		// Only the columns FetchTenantsOverview and FetchTenantDevices touch.
		`CREATE TABLE ` + pat1686Schema + `.tenants (
			id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name                      TEXT NOT NULL,
			tenant_kind               TEXT NOT NULL DEFAULT 'customer',
			macos_enabled             boolean NOT NULL DEFAULT true,
			windows_enabled           boolean NOT NULL DEFAULT true,
			is_trial                  boolean NOT NULL DEFAULT false,
			trial_expires_at          TIMESTAMPTZ,
			health_score              INTEGER,
			health_bucket             TEXT,
			health_score_computed_at  TIMESTAMPTZ,
			compliance_score_current  INTEGER,
			compliance_score_30d_ago  INTEGER,
			last_dashboard_login_at   TIMESTAMPTZ,
			dashboard_logins_last_30d INTEGER NOT NULL DEFAULT 0,
			payment_failed            boolean NOT NULL DEFAULT false,
			revoked_at                TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1686Schema + `.agent_config (
			tenant_id UUID NOT NULL UNIQUE REFERENCES ` + pat1686Schema + `.tenants(id),
			body      JSONB NOT NULL DEFAULT '{}'
		)`,
		`CREATE TABLE ` + pat1686Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1686Schema + `.tenants(id),
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
		`CREATE TABLE ` + pat1686Schema + `.compliance_rules (
			id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL,
			title    TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'low'
		)`,
		`CREATE TABLE ` + pat1686Schema + `.compliance_evaluations (
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1686Schema + `.tenant_new_apps (
			tenant_id UUID NOT NULL REFERENCES ` + pat1686Schema + `.tenants(id),
			decision  TEXT
		)`,
		`CREATE TABLE ` + pat1686Schema + `.device_hardware (
			id                       BIGSERIAL PRIMARY KEY,
			device_id                UUID NOT NULL,
			battery_max_capacity_pct INTEGER,
			battery_condition        TEXT,
			battery_cycle_count      INTEGER
		)`,
		`CREATE TABLE ` + pat1686Schema + `.device_storage_volume (
			id                 BIGSERIAL PRIMARY KEY,
			device_hardware_id BIGINT NOT NULL,
			mount              TEXT NOT NULL,
			free_bytes         BIGINT NOT NULL,
			used_pct           INTEGER NOT NULL
		)`,
		`CREATE TABLE ` + pat1686Schema + `.device_disk (
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
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1686Schema+` CASCADE`)
	})
	return pool
}

// TestTenantsOverviewDeviceCount_MatchesTenantDevicesTotal is the PAT-1686
// regression test: for a tenant with macOS disabled (compliance-wise) but
// still actively reporting macOS devices, the sidebar/tenant-list device
// count (FetchTenantsOverview) must equal the Devices page total
// (FetchTenantDevices) — both must count every device the tenant has, not
// just the platform-eligible subset.
func TestTenantsOverviewDeviceCount_MatchesTenantDevicesTotal(t *testing.T) {
	pool := pat1686Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1686 Test Tenant', false, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	// Three macOS devices (platform disabled — excluded from the old eligible
	// filter) and one Windows device (platform enabled). All four are real,
	// currently-reporting devices the operator expects to see counted.
	now := time.Now().UTC()
	for i, os := range []string{"macOS", "macOS", "macOS", "Windows"} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO devices (tenant_id, serial, hostname, os, os_version, last_seen)
			VALUES ($1::uuid, $2, $3, $4, '1.0', $5)
		`, tenantID, "SERIAL"+string(rune('A'+i)), "host-"+string(rune('a'+i)), os, now); err != nil {
			t.Fatalf("insert device %d: %v", i, err)
		}
	}

	overview, err := FetchTenantsOverview(ctx, pool)
	if err != nil {
		t.Fatalf("FetchTenantsOverview: %v", err)
	}
	var row *TenantOverview
	for i := range overview {
		if overview[i].ID == tenantID {
			row = &overview[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("tenant %s missing from FetchTenantsOverview result", tenantID)
	}

	devices, err := FetchTenantDevices(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchTenantDevices: %v", err)
	}

	if devices.Total != 4 {
		t.Fatalf("FetchTenantDevices.Total = %d, want 4 (all devices, disabled-platform macOS devices included per PAT-745)", devices.Total)
	}
	if row.DeviceCount != devices.Total {
		t.Errorf("FetchTenantsOverview.DeviceCount = %d, FetchTenantDevices.Total = %d — sidebar and Devices page disagree on this tenant's device count",
			row.DeviceCount, devices.Total)
	}
	if row.DeviceCount != 4 {
		t.Errorf("FetchTenantsOverview.DeviceCount = %d, want 4 (must not exclude the disabled-platform macOS devices)", row.DeviceCount)
	}
	if row.ActiveLast7d != 4 {
		t.Errorf("FetchTenantsOverview.ActiveLast7d = %d, want 4 (all devices were just seen, regardless of platform switch)", row.ActiveLast7d)
	}
}
