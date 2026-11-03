package report

// PAT-1588: coverage-honesty fields on GET /v1/portal/overview.
// "Absence requires authority" (root AGENTS.md) - devices_total alone can
// imply a customer's coverage is as good as that count, even when the known
// devices are stale or degraded. These tests pin fetchPortalCoverage's two
// signals: oldest_successful_ingest (MIN(last_seen) across known devices)
// and devices_degraded (COUNT DISTINCT device with an open device_agent_health
// row).
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as platform_switch_aggregation_db_test.go (pat862Pool) and
// portal_findings_pagination_db_test.go (pat1201PoolNoCVETables). The pool's
// search_path is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1588Schema = "pat1588_test"

// pat1588Pool builds a scratch schema with the tables FetchPortalOverview's
// full call chain needs (FetchExecutiveSummary's tenants/devices/
// compliance_rules/compliance_evaluations/patches, same set as pat862Pool)
// plus device_agent_health for the degraded-count query.
func pat1588Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1588Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1588Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1588Schema,
		`CREATE TABLE ` + pat1588Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1588Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1588Schema + `.tenants(id),
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat1588Schema + `.compliance_rules (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key        TEXT NOT NULL,
			benchmark       TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version TEXT NOT NULL DEFAULT 'v1',
			title           TEXT NOT NULL,
			severity        TEXT NOT NULL DEFAULT 'low',
			platform        TEXT NOT NULL DEFAULT 'macos',
			collection_tier TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled         BOOLEAN NOT NULL DEFAULT true,
			device_class    TEXT[]
		)`,
		// tenant_rules (PAT-1794): fetchControlCoverage (called via
		// FetchExecutiveSummary, part of FetchPortalOverview's call chain)
		// joins this to count T2 rules actively enabled for a tenant. No
		// rows are seeded in this suite's fixtures, but the table must
		// exist for the JOIN to plan.
		`CREATE TABLE ` + pat1588Schema + `.tenant_rules (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id        UUID NOT NULL REFERENCES ` + pat1588Schema + `.tenants(id),
			rule_id          UUID NOT NULL REFERENCES ` + pat1588Schema + `.compliance_rules(id),
			enabled          BOOLEAN NOT NULL DEFAULT true,
			suppressed_until TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + pat1588Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1588Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1588Schema + `.device_agent_health (
			device_id      UUID NOT NULL REFERENCES ` + pat1588Schema + `.devices(id),
			kind           TEXT NOT NULL,
			subject        TEXT NOT NULL,
			reason         TEXT NOT NULL DEFAULT '',
			first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
			count          BIGINT NOT NULL DEFAULT 1,
			ever_succeeded BOOLEAN NOT NULL DEFAULT false,
			collected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (device_id, kind, subject)
		)`,
		// device_retirement_decisions (PAT-2135): read by the coverage
		// query to count retired devices apart.
		`CREATE TABLE ` + pat1588Schema + `.device_retirement_decisions (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL,
			device_id   UUID NOT NULL,
			action      TEXT NOT NULL,
			reason      TEXT,
			actor_email TEXT NOT NULL,
			decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// agent_config is queried best-effort (non-fatal) by
		// FetchExecutiveSummary for the report_user_attribution toggle; same
		// omission as pat862Pool, the toggle just defaults to "off".
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1588Schema+` CASCADE`)
	})
	return pool
}

// pat1588PoolNoAgentHealth is the same schema minus device_agent_health, to
// prove the coverage query degrades to devices_degraded=0 rather than
// erroring when the table isn't migrated on this install yet - mirrors
// TestFetchPortalCVEFindingsPage_TablesNotMigrated's pattern one directory
// over (portal_findings_pagination_db_test.go).
func pat1588PoolNoAgentHealth(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	schema := pat1588Schema + "_no_health"
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`,
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + schema + `.tenants(id),
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + schema + `.compliance_rules (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key        TEXT NOT NULL,
			benchmark       TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version TEXT NOT NULL DEFAULT 'v1',
			title           TEXT NOT NULL,
			severity        TEXT NOT NULL DEFAULT 'low',
			platform        TEXT NOT NULL DEFAULT 'macos',
			collection_tier TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled         BOOLEAN NOT NULL DEFAULT true,
			device_class    TEXT[]
		)`,
		// tenant_rules (PAT-1794): see the pat1588Schema definition above
		// for why this table must exist even with no rows seeded here.
		`CREATE TABLE ` + schema + `.tenant_rules (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id        UUID NOT NULL REFERENCES ` + schema + `.tenants(id),
			rule_id          UUID NOT NULL REFERENCES ` + schema + `.compliance_rules(id),
			enabled          BOOLEAN NOT NULL DEFAULT true,
			suppressed_until TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// device_retirement_decisions (PAT-2135): read by the coverage
		// query to count retired devices apart.
		`CREATE TABLE ` + schema + `.device_retirement_decisions (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL,
			device_id   UUID NOT NULL,
			action      TEXT NOT NULL,
			reason      TEXT,
			actor_email TEXT NOT NULL,
			decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// device_agent_health deliberately absent.
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	return pool
}

func pat1588SeedTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1588 Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return tenantID
}

// TestFetchPortalCoverage_OldestIngestIsEarliestLastSeen proves
// oldest_successful_ingest is MIN(last_seen) across the tenant's known
// devices, not (say) the most recent or an average.
func TestFetchPortalCoverage_OldestIngestIsEarliestLastSeen(t *testing.T) {
	pool := pat1588Pool(t)
	ctx := context.Background()
	tenantID := pat1588SeedTenant(t, pool)

	oldest := time.Date(2026, 12, 15, 9, 0, 0, 0, time.UTC)
	newest := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)

	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, last_seen)
		VALUES ($1::uuid, 'stale-01', 'macOS', $2), ($1::uuid, 'fresh-01', 'macOS', $3)
	`, tenantID, oldest, newest); err != nil {
		t.Fatalf("insert devices: %v", err)
	}

	got, degraded, _, err := fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCoverage: %v", err)
	}
	if got == nil {
		t.Fatal("oldestIngest = nil, want the earliest last_seen")
	}
	if !got.Equal(oldest) {
		t.Errorf("oldestIngest = %v, want %v (the earlier of the two devices)", got, oldest)
	}
	if degraded != 0 {
		t.Errorf("devicesDegraded = %d, want 0 (no device_agent_health rows)", degraded)
	}
}

// TestFetchPortalCoverage_ZeroDevicesIsNilNotZeroTime proves a tenant with no
// devices gets a nil oldest_successful_ingest, never a zero-value time.Time
// that would masquerade as a real (very old) timestamp.
func TestFetchPortalCoverage_ZeroDevicesIsNilNotZeroTime(t *testing.T) {
	pool := pat1588Pool(t)
	ctx := context.Background()
	tenantID := pat1588SeedTenant(t, pool)

	got, degraded, _, err := fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCoverage: %v", err)
	}
	if got != nil {
		t.Errorf("oldestIngest = %v, want nil (tenant has zero devices)", *got)
	}
	if degraded != 0 {
		t.Errorf("devicesDegraded = %d, want 0", degraded)
	}
}

// TestFetchPortalCoverage_DevicesDegradedCountsOnlyFaultingDevices proves
// devices_degraded counts distinct devices with an open device_agent_health
// row, and leaves a device with no such row out of the count.
func TestFetchPortalCoverage_DevicesDegradedCountsOnlyFaultingDevices(t *testing.T) {
	pool := pat1588Pool(t)
	ctx := context.Background()
	tenantID := pat1588SeedTenant(t, pool)

	var healthyID, degradedID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'healthy-01', 'macOS')
		RETURNING id::text
	`, tenantID).Scan(&healthyID); err != nil {
		t.Fatalf("insert healthy device: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'degraded-01', 'macOS')
		RETURNING id::text
	`, tenantID).Scan(&degradedID); err != nil {
		t.Fatalf("insert degraded device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_agent_health (device_id, kind, subject, ever_succeeded)
		VALUES ($1::uuid, 'sync_never_succeeded', 'catalogue_sync', false)
	`, degradedID); err != nil {
		t.Fatalf("insert agent health row: %v", err)
	}
	_ = healthyID

	_, degraded, _, err := fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCoverage: %v", err)
	}
	if degraded != 1 {
		t.Errorf("devicesDegraded = %d, want 1 (only degraded-01 has a device_agent_health row)", degraded)
	}
}

// TestFetchPortalCoverage_AgentHealthTableAbsentDegradesToZero mirrors
// TestFetchPortalCVEFindingsPage_TablesNotMigrated (portal_findings_pagination_db_test.go):
// on a fresh/pre-migration schema without device_agent_health, the coverage
// query must catch Postgres 42P01 via isUndefinedTable and degrade to
// devices_degraded=0 with a nil error, not a 500.
func TestFetchPortalCoverage_AgentHealthTableAbsentDegradesToZero(t *testing.T) {
	pool := pat1588PoolNoAgentHealth(t)
	ctx := context.Background()
	tenantID := pat1588SeedTenant(t, pool)

	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, 'dev-01', 'macOS')
	`, tenantID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	_, degraded, _, err := fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCoverage: %v, want nil error (degrade, not an error)", err)
	}
	if degraded != 0 {
		t.Errorf("devicesDegraded = %d, want 0 (device_agent_health table absent)", degraded)
	}
}

// TestFetchPortalOverview_CarriesCoverageFields is the end-to-end check that
// FetchPortalOverview (not just the unexported fetchPortalCoverage helper)
// wires OldestSuccessfulIngest and DevicesDegraded onto PortalOverview.
func TestFetchPortalOverview_CarriesCoverageFields(t *testing.T) {
	pool := pat1588Pool(t)
	ctx := context.Background()
	tenantID := pat1588SeedTenant(t, pool)

	seenAt := time.Date(2026, 12, 15, 9, 0, 0, 0, time.UTC)
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, last_seen)
		VALUES ($1::uuid, 'dev-01', 'macOS', $2)
		RETURNING id::text
	`, tenantID, seenAt).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_agent_health (device_id, kind, subject, ever_succeeded)
		VALUES ($1::uuid, 'capability_missing', 'log_upload', false)
	`, deviceID); err != nil {
		t.Fatalf("insert agent health row: %v", err)
	}

	ov, err := FetchPortalOverview(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchPortalOverview: %v", err)
	}
	if ov.OldestSuccessfulIngest == nil || !ov.OldestSuccessfulIngest.Equal(seenAt) {
		t.Errorf("OldestSuccessfulIngest = %v, want %v", ov.OldestSuccessfulIngest, seenAt)
	}
	if ov.DevicesDegraded != 1 {
		t.Errorf("DevicesDegraded = %d, want 1", ov.DevicesDegraded)
	}
}

// TestFetchPortalCoverage_RetiredDeviceCountedApart (PAT-2135): a device the
// customer retired is counted in devices_retired and no longer sets
// oldest_successful_ingest; unretiring it puts it back. Remove the retired
// filter from the coverage query and the oldest-ingest assertion goes red.
func TestFetchPortalCoverage_RetiredDeviceCountedApart(t *testing.T) {
	pool := pat1588Pool(t)
	ctx := context.Background()
	tenantID := pat1588SeedTenant(t, pool)

	quiet := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	var quietID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, last_seen)
		VALUES ($1::uuid, 'gone-01', 'macOS', $2) RETURNING id::text
	`, tenantID, quiet).Scan(&quietID); err != nil {
		t.Fatalf("insert quiet device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, last_seen) VALUES ($1::uuid, 'fresh-01', 'Windows', $2)
	`, tenantID, fresh); err != nil {
		t.Fatalf("insert fresh device: %v", err)
	}
	decide := func(action string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_retirement_decisions (tenant_id, device_id, action, actor_email)
			VALUES ($1::uuid, $2::uuid, $3, 'admin@example.test')
		`, tenantID, quietID, action); err != nil {
			t.Fatalf("insert %s decision: %v", action, err)
		}
	}

	decide("retire")
	oldest, _, retired, err := fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCoverage: %v", err)
	}
	if retired != 1 {
		t.Errorf("devicesRetired = %d, want 1", retired)
	}
	if oldest == nil || !oldest.Equal(fresh) {
		t.Errorf("oldestIngest = %v, want %v (the retired device must not set it)", oldest, fresh)
	}

	decide("unretire")
	oldest, _, retired, err = fetchPortalCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("fetchPortalCoverage after unretire: %v", err)
	}
	if retired != 0 || oldest == nil || !oldest.Equal(quiet) {
		t.Errorf("after unretire: retired = %d, oldest = %v; want 0 and %v", retired, oldest, quiet)
	}
}
