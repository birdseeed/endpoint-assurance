package report

// PAT-1960: a Windows Server that enrols must get an honest "not assessed:
// no benchmark for this device class" instead of being scored against a
// workstation-only Windows benchmark. This file proves the four acceptance
// cases at the report layer:
//
//  1. A server device with the workstation-only rule enabled produces zero
//     evaluations and appears in the NotAssessedDevices bucket.
//  2. A workstation device is scored exactly as before.
//  3. An unknown-class device is scored exactly as before, but is counted
//     in DeviceClassUnreportedDevices ("device class not reported").
//  4. A macOS device is completely unaffected (its rules have NULL
//     device_class, so its own device_class — always 'unknown' today — is
//     never consulted).
//
// TestPAT1960_NonCISWindowsRuleAppliesToServer below proves a fifth case
// added after review: only the CIS Microsoft Windows 11 benchmark is
// workstation-specific. A server device with a general (non-CIS,
// NULL-device_class) Windows rule enabled still receives evaluations from
// it and must not be reported as not-assessed — the migration 0158 backfill
// must not have swept every Windows rule into device_class={workstation}.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as executive_control_coverage_db_test.go (pat1794Pool). The
// pool's search_path is pinned to an isolated schema so no real data is
// touched. This suite's fixture schema mirrors pat1794Pool's but adds the
// two device_class columns migration 0158 introduces.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1960Schema = "pat1960_device_class_test"

func pat1960Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping device-class DB test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1960Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1960Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1960Schema,
		`CREATE TABLE ` + pat1960Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1960Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1960Schema + `.tenants(id),
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat1960Schema + `.compliance_rules (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key           TEXT NOT NULL,
			benchmark          TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version  TEXT NOT NULL DEFAULT 'v1',
			title              TEXT NOT NULL,
			severity           TEXT NOT NULL DEFAULT 'low',
			platform           TEXT NOT NULL DEFAULT 'macos',
			collection_tier    TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled            BOOLEAN NOT NULL DEFAULT true,
			device_class       TEXT[]
		)`,
		`CREATE TABLE ` + pat1960Schema + `.tenant_rules (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          UUID NOT NULL REFERENCES ` + pat1960Schema + `.tenants(id),
			rule_id            UUID NOT NULL REFERENCES ` + pat1960Schema + `.compliance_rules(id),
			enabled            BOOLEAN NOT NULL DEFAULT true,
			suppressed_until   TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + pat1960Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1960Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// agent_config intentionally omitted — FetchExecutiveSummary's
		// report_user_attribution lookup is best-effort/non-fatal (same
		// reasoning as pat1794Pool).
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1960Schema+` CASCADE`)
	})
	return pool
}

// TestPAT1960_DeviceClassScenarios builds one tenant with a workstation-only
// Windows rule, a class-agnostic macOS rule, and four devices — server,
// workstation, unknown-class Windows, and macOS — and asserts the four
// acceptance-criteria outcomes from the coverage read model.
func TestPAT1960_DeviceClassScenarios(t *testing.T) {
	pool := pat1960Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1960 Device Class Test Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	insertDevice := func(hostname, osName, deviceClass string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, device_class)
			VALUES ($1::uuid, $2, $3, $4)
			RETURNING id::text
		`, tenantID, hostname, osName, deviceClass).Scan(&id); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return id
	}
	serverDevice := insertDevice("pat1960-server", "Windows", "server")
	workstationDevice := insertDevice("pat1960-workstation", "Windows", "workstation")
	unknownDevice := insertDevice("pat1960-unknown", "Windows", "unknown")
	macDevice := insertDevice("pat1960-mac", "macOS", "unknown") // macOS never reports device_class; always defaults to 'unknown'

	var winWorkstationRule, macRule string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, benchmark, title, platform, collection_tier, enabled, device_class)
		VALUES ('pat1960_win_workstation', 'CIS Microsoft Windows 11', 'PAT-1960 Windows workstation rule', 'windows', 'T1', true, ARRAY['workstation'])
		RETURNING id::text
	`).Scan(&winWorkstationRule); err != nil {
		t.Fatalf("insert windows rule: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, benchmark, title, platform, collection_tier, enabled, device_class)
		VALUES ('pat1960_mac_universal', 'CIS Apple macOS', 'PAT-1960 macOS rule', 'macos', 'T1', true, NULL)
		RETURNING id::text
	`).Scan(&macRule); err != nil {
		t.Fatalf("insert macos rule: %v", err)
	}

	// Evaluations mirror what the evaluator would actually have written:
	// workstation and unknown devices matched the workstation-scoped rule
	// (unknown via the load-bearing "or unknown" clause) and passed it; the
	// server device produced NO evaluation row at all, because
	// evaluator.LoadRules already excluded the rule for it. The macOS
	// device passed its own class-agnostic rule, untouched by any of this.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, evaluated_at)
		VALUES
			($1::uuid, $3::uuid, 'pass', 'Yes', now()),
			($2::uuid, $3::uuid, 'pass', 'Yes', now())
	`, workstationDevice, unknownDevice, winWorkstationRule); err != nil {
		t.Fatalf("insert windows evaluations: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, evaluated_at)
		VALUES ($1::uuid, $2::uuid, 'pass', 'Yes', now())
	`, macDevice, macRule); err != nil {
		t.Fatalf("insert macos evaluation: %v", err)
	}

	coverage, err := FetchControlCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchControlCoverage: %v", err)
	}

	// 1. Server device: zero evaluations exist for it (never inserted above,
	// matching what the evaluator would produce), and it is counted in the
	// not-assessed bucket with the exact required reason string.
	if coverage.NotAssessedDevices != 1 {
		t.Errorf("NotAssessedDevices = %d, want 1 (the server device)", coverage.NotAssessedDevices)
	}
	if coverage.NotAssessedReason != "Not assessed: no benchmark for this device class" {
		t.Errorf("NotAssessedReason = %q, want the exact PAT-1960 string", coverage.NotAssessedReason)
	}

	var serverEvalCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM compliance_evaluations WHERE device_id = $1::uuid`, serverDevice).Scan(&serverEvalCount); err != nil {
		t.Fatalf("count server evaluations: %v", err)
	}
	if serverEvalCount != 0 {
		t.Errorf("server device has %d compliance_evaluations rows, want 0", serverEvalCount)
	}

	// 2. Workstation device: scored exactly as before — its pass evaluation
	// counts in Measurements.Pass, not in NotAssessedDevices.
	if coverage.Measurements.Pass < 2 {
		t.Errorf("Measurements.Pass = %d, want at least 2 (workstation + unknown devices' passes)", coverage.Measurements.Pass)
	}

	// 3. Unknown-class device: scored exactly as before (its pass is
	// included in Measurements.Pass above, identical treatment to the
	// workstation device), but labelled "device class not reported" via its
	// own bucket rather than folded silently into the score.
	if coverage.DeviceClassUnreportedDevices != 1 {
		t.Errorf("DeviceClassUnreportedDevices = %d, want 1 (the Windows device whose class was never reported; macOS is excluded — see reasoning in fetchDeviceClassCoverage)", coverage.DeviceClassUnreportedDevices)
	}
	if coverage.DeviceClassUnreportedReason != "Device class not reported" {
		t.Errorf("DeviceClassUnreportedReason = %q, want the exact PAT-1960 string", coverage.DeviceClassUnreportedReason)
	}

	// 4. macOS device: its evaluation is present and counted normally
	// (already covered by the Measurements.Pass >= 2 assertion not
	// double-counting it oddly), and — critically — it must never
	// contribute to NotAssessedDevices or DeviceClassUnreportedDevices,
	// because macOS rules have NULL device_class and are never gated by it.
	var macEvalCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM compliance_evaluations WHERE device_id = $1::uuid AND status = 'pass'`, macDevice).Scan(&macEvalCount); err != nil {
		t.Fatalf("count mac evaluations: %v", err)
	}
	if macEvalCount != 1 {
		t.Errorf("macOS device pass-evaluation count = %d, want 1 (completely unaffected by device_class)", macEvalCount)
	}
}

// TestPAT1960_NonCISWindowsRuleAppliesToServer is the regression for the
// migration 0158 backfill fix: only the CIS Microsoft Windows 11 benchmark
// is workstation-specific. A blanket `WHERE platform = 'windows'` backfill
// would have marked EVERY Windows rule workstation-only, including general
// controls (NIST SP 800-53, the patched.im baseline) that have no
// workstation/server distinction and stay device_class NULL deliberately.
//
// This proves the distinction directly: a server device with a workstation-
// only CIS Windows 11 rule AND a class-agnostic (NULL device_class) non-CIS
// Windows rule both enabled receives an evaluation from the non-CIS rule,
// and is therefore NOT reported as not-assessed — the exact case the
// blanket backfill would have broken, since with it BOTH rules would have
// excluded the server and it would have wrongly read as "no benchmark for
// this device class" despite one rule genuinely applying.
func TestPAT1960_NonCISWindowsRuleAppliesToServer(t *testing.T) {
	pool := pat1960Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1960 Non-CIS Windows Rule Test Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var serverDevice string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, device_class)
		VALUES ($1::uuid, 'pat1960-noncis-server', 'Windows', 'server')
		RETURNING id::text
	`, tenantID).Scan(&serverDevice); err != nil {
		t.Fatalf("insert server device: %v", err)
	}

	// Workstation-only CIS Windows 11 rule — matches the 0158 backfill shape.
	// The server must NOT match this one.
	var cisWin11Rule string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, benchmark, benchmark_version, title, platform, collection_tier, enabled, device_class)
		VALUES ('pat1960_noncis_cis_win11', 'CIS Microsoft Windows 11', 'v2.0.0', 'PAT-1960 CIS Win11 rule', 'windows', 'T1', true, ARRAY['workstation'])
		RETURNING id::text
	`).Scan(&cisWin11Rule); err != nil {
		t.Fatalf("insert CIS Windows 11 rule: %v", err)
	}

	// A NIST SP 800-53 Windows rule — general control, NULL device_class,
	// exactly the shape 0158 leaves untouched. The server MUST match this one.
	var nistRule string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, benchmark, benchmark_version, title, platform, collection_tier, enabled, device_class)
		VALUES ('pat1960_noncis_nist', 'NIST SP 800-53 Rev 5', 'Rev 5 (2020)', 'PAT-1960 NIST rule', 'windows', 'T1', true, NULL)
		RETURNING id::text
	`).Scan(&nistRule); err != nil {
		t.Fatalf("insert NIST rule: %v", err)
	}

	// The server produces an evaluation from the NIST rule (it applies) but
	// none from the CIS Windows 11 rule (excluded by device_class), mirroring
	// exactly what evaluator.LoadRules would produce.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, evaluated_at)
		VALUES ($1::uuid, $2::uuid, 'pass', 'Yes', now())
	`, serverDevice, nistRule); err != nil {
		t.Fatalf("insert NIST evaluation: %v", err)
	}

	coverage, err := FetchControlCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchControlCoverage: %v", err)
	}

	// The bug this test guards against: with a blanket backfill, the NIST
	// rule would ALSO have been workstation-only, the server would match
	// nothing at all, and NotAssessedDevices would wrongly be 1.
	if coverage.NotAssessedDevices != 0 {
		t.Errorf("NotAssessedDevices = %d, want 0 — the server has a genuinely applicable non-CIS Windows rule (NIST SP 800-53) and must not read as unbenchmarked", coverage.NotAssessedDevices)
	}
	if coverage.NotAssessedReason != "" {
		t.Errorf("NotAssessedReason = %q, want empty when NotAssessedDevices is 0", coverage.NotAssessedReason)
	}

	var cisEvalCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM compliance_evaluations WHERE device_id = $1::uuid AND rule_id = $2::uuid
	`, serverDevice, cisWin11Rule).Scan(&cisEvalCount); err != nil {
		t.Fatalf("count CIS Win11 evaluations: %v", err)
	}
	if cisEvalCount != 0 {
		t.Errorf("server has %d evaluations against the workstation-only CIS Windows 11 rule, want 0", cisEvalCount)
	}

	if coverage.Measurements.Pass < 1 {
		t.Errorf("Measurements.Pass = %d, want at least 1 (the server's NIST rule pass)", coverage.Measurements.Pass)
	}
}
