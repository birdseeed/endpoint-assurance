package report

// PAT-1806 acceptance test: report.FetchOSUpdateStatus partitions a tenant's
// devices into four buckets — current, behind, behind-with-a-security-
// relevant-update-outstanding, and not-reported. The fourth bucket is the
// load-bearing one: a device that has never sent an os_update block (every
// device today, since neither endpoint agent uploads this yet) must land in
// "not reported", never silently read as "current" — the same
// absence-requires-authority discipline PAT-1805 established for
// devices.pending_updates (see pat1805_windows_update_unknown_db_test.go in
// this package).
//
// Self-contained scratch schema, same convention as pat1805Pool in this
// package: this test does NOT apply migrations/0144_device_os_update.sql —
// it defines a minimal device_os_update table matching that migration's
// shape directly, so it can run without a full migrated database. Skipped
// unless TEST_DATABASE_URL points at a reachable Postgres.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1806Schema = "pat1806_test"

func pat1806Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1806Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1806Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1806Schema,
		`CREATE TABLE ` + pat1806Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1806Schema + `.devices (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id       UUID NOT NULL REFERENCES ` + pat1806Schema + `.tenants(id),
			hostname        TEXT,
			os              TEXT,
			os_version      TEXT,
			last_seen       TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// Minimal device_os_update shape matching migrations/0144_device_os_update.sql.
		`CREATE TABLE ` + pat1806Schema + `.device_os_update (
			id                   BIGSERIAL   PRIMARY KEY,
			device_id            UUID        NOT NULL UNIQUE REFERENCES ` + pat1806Schema + `.devices(id),
			installed_os         TEXT        NOT NULL,
			latest_os            TEXT        NOT NULL,
			target_os            TEXT,
			state                TEXT        NOT NULL,
			severity             TEXT,
			security_relevant    BOOLEAN     NOT NULL DEFAULT false,
			actively_exploited   BOOLEAN     NOT NULL DEFAULT false,
			deferrals_remaining  INTEGER,
			release_age_days     INTEGER,
			deadline             TIMESTAMPTZ,
			checked_at           TIMESTAMPTZ,
			reported_at          TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1806Schema+` CASCADE`)
	})
	return pool
}

// seedPAT1806Tenant creates a tenant with both platforms enabled and four
// devices, one per bucket:
//   - "current-mac": device_os_update row, state = "up_to_date" (PAT-1862: the
//     real agent-side value, not the placeholder "current" this fixture used
//     before the platform contract was verified against updater's real
//     contracts/update-status.schema.json)
//   - "behind-mac": device_os_update row, state = "update_recommended", security_relevant = false
//   - "behind-security-win": device_os_update row, state = "update_required", security_relevant = true
//   - "never-reported-win": NO device_os_update row at all — the PAT-1806 shape
//     every device has today, since no agent uploads this block yet.
func seedPAT1806Tenant(t *testing.T, pool *pgxpool.Pool) (tenantID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1806 Test Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	type seed struct {
		hostname string
		os       string
		hasRow   bool
		state    string
		secRel   bool
	}
	seeds := []seed{
		{"current-mac", "macOS", true, "up_to_date", false},
		{"behind-mac", "macOS", true, "update_recommended", false},
		{"behind-security-win", "Windows", true, "update_required", true},
		{"never-reported-win", "Windows", false, "", false},
	}
	for _, s := range seeds {
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version)
			VALUES ($1::uuid, $2, $3, '1.0')
			RETURNING id::text
		`, tenantID, s.hostname, s.os).Scan(&deviceID); err != nil {
			t.Fatalf("insert device %s: %v", s.hostname, err)
		}
		if !s.hasRow {
			continue
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_os_update (device_id, installed_os, latest_os, state, security_relevant, actively_exploited)
			VALUES ($1::uuid, '1.0', '1.1', $2, $3, false)
		`, deviceID, s.state, s.secRel); err != nil {
			t.Fatalf("insert device_os_update for %s: %v", s.hostname, err)
		}
	}
	return tenantID
}

// TestFetchOSUpdateStatus_FourBuckets is the PAT-1806 acceptance test: each
// seeded device must land in exactly one of the four buckets, and the never-
// reported device must land in DevicesNotReported, never DevicesCurrent.
func TestFetchOSUpdateStatus_FourBuckets(t *testing.T) {
	pool := pat1806Pool(t)
	tenantID := seedPAT1806Tenant(t, pool)

	status, err := FetchOSUpdateStatus(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchOSUpdateStatus: %v", err)
	}

	if status.DevicesCurrent != 1 {
		t.Errorf("DevicesCurrent = %d, want 1 (current-mac)", status.DevicesCurrent)
	}
	if status.DevicesBehind != 2 {
		t.Errorf("DevicesBehind = %d, want 2 (behind-mac, behind-security-win)", status.DevicesBehind)
	}
	if status.DevicesBehindSecurityRelevant != 1 {
		t.Errorf("DevicesBehindSecurityRelevant = %d, want 1 (behind-security-win)", status.DevicesBehindSecurityRelevant)
	}
	if status.DevicesNotReported != 1 {
		t.Errorf("DevicesNotReported = %d, want 1 (never-reported-win: no device_os_update row must never count as current)", status.DevicesNotReported)
	}

	total := status.DevicesCurrent + status.DevicesBehind + status.DevicesNotReported
	if total != 4 {
		t.Errorf("current + behind + not_reported sums to %d, want 4 (every seeded device must land in exactly one of the three mutually exclusive buckets; behind_security_relevant is a SUBSET of behind, not a fourth exclusive bucket)", total)
	}
}

// TestFetchOSUpdateStatus_UpToDateStateCountsAsCurrent is the PAT-1862
// regression test: the platform's rollup query used to hardcode the literal
// 'current' for its FILTER clauses, but no real agent ever sends that value
// — the real contract's state enum uses "up_to_date". Before this fix, a
// device_os_update row with state = "up_to_date" matched none of the three
// FILTER clauses (dou.state = 'current', dou.state <> 'current', and the
// security-relevant variant of the latter), so it fell through and was
// silently miscounted as "behind" — the exact failure shape that made every
// real up-to-date device read as needing an update. This test seeds exactly
// that row directly (independent of seedPAT1806Tenant, so it keeps failing
// this specific regression even if that shared fixture ever changes) and
// asserts it lands in DevicesCurrent, not DevicesBehind.
func TestFetchOSUpdateStatus_UpToDateStateCountsAsCurrent(t *testing.T) {
	pool := pat1806Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1862 Up-To-Date Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, 'up-to-date-mac', 'macOS', '15.6.1')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_os_update (device_id, installed_os, latest_os, state, security_relevant, actively_exploited)
		VALUES ($1::uuid, '15.6.1', '15.6.1', 'up_to_date', false, false)
	`, deviceID); err != nil {
		t.Fatalf("insert device_os_update: %v", err)
	}

	status, err := FetchOSUpdateStatus(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchOSUpdateStatus: %v", err)
	}

	if status.DevicesCurrent != 1 {
		t.Errorf("DevicesCurrent = %d, want 1: a device_os_update row with state=\"up_to_date\" must be counted as current", status.DevicesCurrent)
	}
	if status.DevicesBehind != 0 {
		t.Errorf("DevicesBehind = %d, want 0: an up_to_date device must never be miscounted as behind (this is the exact bug a hardcoded state = 'current' FILTER caused)", status.DevicesBehind)
	}
}

// TestFetchOSUpdateStatus_NeverReportedNeverCountsAsCurrent is the direct
// regression assertion: a tenant where every device has never sent an
// os_update block must show zero current devices, not devices_total current
// devices — the exact failure shape PAT-1805 fixed for pending_updates.
func TestFetchOSUpdateStatus_NeverReportedNeverCountsAsCurrent(t *testing.T) {
	pool := pat1806Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1806 All-Unreported Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, 'win-only', 'Windows', '11')
	`, tenantID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	status, err := FetchOSUpdateStatus(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchOSUpdateStatus: %v", err)
	}

	if status.DevicesCurrent != 0 {
		t.Errorf("DevicesCurrent = %d, want 0: a device with no device_os_update row must never count as current", status.DevicesCurrent)
	}
	if status.DevicesNotReported != 1 {
		t.Errorf("DevicesNotReported = %d, want 1", status.DevicesNotReported)
	}
}

// TestFetchOSUpdateStatus_UnknownAndUnrecognisedAreNotReported is the PAT-2295
// regression test. The rollup used to count every state other than
// "up_to_date" as behind, so a device whose agent said "unknown" (it could
// not tell) or sent a state this server has never heard of read as behind
// here while the portal roster (osUpdatePatchPending) reported the same
// device as not reported. Neither is a claim about the device, so neither
// may be counted as behind, and neither may reach the security-relevant
// subset even when the agent set security_relevant.
func TestFetchOSUpdateStatus_UnknownAndUnrecognisedAreNotReported(t *testing.T) {
	pool := pat1806Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-2295 Unknown Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	type seed struct {
		hostname string
		state    string
		secRel   bool
	}
	seeds := []seed{
		{"current", "up_to_date", false},
		{"recommended", "update_recommended", false},
		{"required", "update_required", true},
		{"deadline", "deadline_passed", true},
		{"unsupported", "unsupported_hardware", false},
		{"unknown", "unknown", true},
		{"banana", "banana", true},
		{"empty", "", true},
		// Matching is exact, like the portal's: a case variant is not the
		// contract's value, so it is not a claim either.
		{"case-variant", "Up_To_Date", false},
	}
	for _, s := range seeds {
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version)
			VALUES ($1::uuid, $2, 'Windows', '11')
			RETURNING id::text
		`, tenantID, s.hostname).Scan(&deviceID); err != nil {
			t.Fatalf("insert device %s: %v", s.hostname, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO device_os_update (device_id, installed_os, latest_os, state, security_relevant, actively_exploited)
			VALUES ($1::uuid, '1.0', '1.1', $2, $3, false)
		`, deviceID, s.state, s.secRel); err != nil {
			t.Fatalf("insert device_os_update for %s: %v", s.hostname, err)
		}
	}
	// One device with no row at all, to prove the two not-reported causes
	// land in the same bucket.
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, 'no-row', 'Windows', '11')
	`, tenantID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	status, err := FetchOSUpdateStatus(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchOSUpdateStatus: %v", err)
	}
	if status.DevicesCurrent != 1 {
		t.Errorf("DevicesCurrent = %d, want 1 (only the exact up_to_date)", status.DevicesCurrent)
	}
	if status.DevicesBehind != 4 {
		t.Errorf("DevicesBehind = %d, want 4 (update_recommended, update_required, deadline_passed, unsupported_hardware)", status.DevicesBehind)
	}
	if status.DevicesBehindSecurityRelevant != 2 {
		t.Errorf("DevicesBehindSecurityRelevant = %d, want 2 (update_required and deadline_passed; unknown, unrecognised and empty never count)", status.DevicesBehindSecurityRelevant)
	}
	if status.DevicesNotReported != 5 {
		t.Errorf("DevicesNotReported = %d, want 5 (unknown, banana, empty, case-variant, no-row)", status.DevicesNotReported)
	}
	if total := status.DevicesCurrent + status.DevicesBehind + status.DevicesNotReported; total != len(seeds)+1 {
		t.Errorf("current + behind + not_reported sums to %d, want %d", total, len(seeds)+1)
	}
}

// TestFetchOSUpdateStatus_TenantNotFound asserts the same ErrTenantNotFound
// contract every other Fetch* function in this package honours.
func TestFetchOSUpdateStatus_TenantNotFound(t *testing.T) {
	pool := pat1806Pool(t)

	_, err := FetchOSUpdateStatus(context.Background(), pool, "00000000-0000-0000-0000-000000000000")
	if err != ErrTenantNotFound {
		t.Errorf("FetchOSUpdateStatus with unknown tenant: got err = %v, want ErrTenantNotFound", err)
	}
}
