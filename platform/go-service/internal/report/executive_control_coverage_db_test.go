package report

// PAT-1794: the executive summary's control-coverage band (ControlsTotal /
// ControlsEvaluated / ControlsOutOfScope) must be computed for real against
// compliance_rules + tenant_rules, denominated by the tenant's platform mix
// — not assumed 100% T2 coverage just because PAT-1794 seeds every T2 rule
// on tenant creation, since a tenant can still have a T2 rule
// administratively disabled or suppressed afterwards.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as platform_switch_aggregation_db_test.go (pat862Pool) and
// tenant_rules_evaluated_devices_db_test.go (pat1690Pool in the handlers
// package). The pool's search_path is pinned to an isolated schema so no
// real data is touched.

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1794Schema = "pat1794_coverage_test"

func pat1794Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping control-coverage DB test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1794Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1794Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1794Schema,
		`CREATE TABLE ` + pat1794Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1794Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1794Schema + `.tenants(id),
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat1794Schema + `.compliance_rules (
			id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key          TEXT NOT NULL,
			benchmark         TEXT NOT NULL DEFAULT 'Fixture benchmark',
			benchmark_version TEXT NOT NULL DEFAULT 'v1',
			title             TEXT NOT NULL,
			severity          TEXT NOT NULL DEFAULT 'low',
			platform          TEXT NOT NULL DEFAULT 'macos',
			collection_tier   TEXT NOT NULL DEFAULT 'T1',
			control_identifier TEXT,
			enabled           BOOLEAN NOT NULL DEFAULT true,
			device_class      TEXT[]
		)`,
		`CREATE TABLE ` + pat1794Schema + `.tenant_rules (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          UUID NOT NULL REFERENCES ` + pat1794Schema + `.tenants(id),
			rule_id            UUID NOT NULL REFERENCES ` + pat1794Schema + `.compliance_rules(id),
			enabled            BOOLEAN NOT NULL DEFAULT true,
			suppressed_until   TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		`CREATE TABLE ` + pat1794Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1794Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// agent_config intentionally omitted, same reasoning as pat862Pool:
		// FetchExecutiveSummary's report_user_attribution lookup is
		// best-effort and non-fatal on error, defaulting the toggle to "off".
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1794Schema+` CASCADE`)
	})
	return pool
}

// insertRule inserts one compliance_rules row and returns its id.
func pat1794InsertRule(t *testing.T, ctx context.Context, pool *pgxpool.Pool, key, platform, tier string, enabled bool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, platform, collection_tier, enabled)
		VALUES ($1, $1, $2, $3, $4)
		RETURNING id::text
	`, key, platform, tier, enabled).Scan(&id); err != nil {
		t.Fatalf("insert rule %s: %v", key, err)
	}
	return id
}

// TestFetchExecutiveSummary_ControlCoverage builds a macOS-only tenant (T1 +
// T2 + T3 macOS rules, plus decoy Windows-only rules that must not count)
// and asserts:
//   - ControlsTotal counts every enabled rule across all tiers for the
//     tenant's enabled platforms only.
//   - ControlsOutOfScope counts T3 rules and nothing else.
//   - ControlsEvaluated counts T1 (always) plus only the T2 rules that carry
//     an enabled, non-suppressed tenant_rules row — a T2 rule seeded but
//     later disabled, and one that is suppressed, must NOT count as
//     evaluated, proving the field is computed live rather than assumed
//     100% from PAT-1794's seeding.
func TestFetchExecutiveSummary_ControlCoverage(t *testing.T) {
	pool := pat1794Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1794 Coverage Test Tenant', true, false)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	// In-scope (macOS) rules.
	pat1794InsertRule(t, ctx, pool, "pat1794_t1", "macos", "T1", true)
	t2EnabledRule := pat1794InsertRule(t, ctx, pool, "pat1794_t2_enabled", "macos", "T2", true)
	t2DisabledRule := pat1794InsertRule(t, ctx, pool, "pat1794_t2_disabled", "macos", "T2", true)
	t2SuppressedRule := pat1794InsertRule(t, ctx, pool, "pat1794_t2_suppressed", "macos", "T2", true)
	// t2_unconfigured deliberately gets no tenant_rules row at all — never
	// evaluated, same as the pre-PAT-1794 default for an unconfigured rule.
	pat1794InsertRule(t, ctx, pool, "pat1794_t2_unconfigured", "macos", "T2", true)
	pat1794InsertRule(t, ctx, pool, "pat1794_t3", "macos", "T3", true)                         // out of scope
	pat1794InsertRule(t, ctx, pool, "pat1794_t2_rule_disabled_globally", "macos", "T2", false) // globally disabled: must not count anywhere

	// Decoy Windows-only rules: windows_enabled=false for this tenant, so
	// none of these may appear in any coverage count.
	pat1794InsertRule(t, ctx, pool, "pat1794_win_t1", "windows", "T1", true)
	pat1794InsertRule(t, ctx, pool, "pat1794_win_t2", "windows", "T2", true)
	pat1794InsertRule(t, ctx, pool, "pat1794_win_t3", "windows", "T3", true)

	// tenant_rules rows: enabled+active, disabled, suppressed, and
	// deliberately absent (t2UnconfiguredRule has no row at all — never
	// evaluated, same as the pre-PAT-1794 default).
	insertTenantRule := func(ruleID string, enabled bool, suppressedUntil any) {
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_rules (tenant_id, rule_id, enabled, suppressed_until)
			VALUES ($1::uuid, $2::uuid, $3, $4)
		`, tenantID, ruleID, enabled, suppressedUntil); err != nil {
			t.Fatalf("insert tenant_rules for %s: %v", ruleID, err)
		}
	}
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	insertTenantRule(t2EnabledRule, true, nil)
	insertTenantRule(t2DisabledRule, false, nil)
	insertTenantRule(t2SuppressedRule, true, farFuture)

	summary, err := FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	// Total: T1 (1) + T2 enabled (t2_enabled, t2_disabled, t2_suppressed,
	// t2_unconfigured = 4) + T3 (1) = 6, restricted to macOS (the 3 Windows
	// decoys and the 1 globally-disabled T2 rule excluded).
	if want := 6; summary.Coverage.ControlsTotal != want {
		t.Errorf("ControlsTotal = %d, want %d", summary.Coverage.ControlsTotal, want)
	}
	if want := 1; summary.Coverage.ControlsOutOfScope != want {
		t.Errorf("ControlsOutOfScope = %d, want %d (only the T3 rule)", summary.Coverage.ControlsOutOfScope, want)
	}
	// Evaluated: T1 (1) + only the one T2 rule with an enabled,
	// non-suppressed tenant_rules row (t2EnabledRule) = 2. The disabled,
	// suppressed and unconfigured T2 rules must not count.
	if want := 2; summary.Coverage.ControlsEvaluated != want {
		t.Errorf("ControlsEvaluated = %d, want %d (T1 always-evaluated + only the actively-enabled T2 rule)", summary.Coverage.ControlsEvaluated, want)
	}
}

// TestFetchExecutiveSummary_ControlCoverage_BothPlatformsEnabled confirms
// the denominator grows to include Windows rules once windows_enabled=true,
// so a dual-platform tenant is never short-changed the way a platform-blind
// count would be.
func TestFetchExecutiveSummary_ControlCoverage_BothPlatformsEnabled(t *testing.T) {
	pool := pat1794Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1794 Both Platforms Test Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	pat1794InsertRule(t, ctx, pool, "pat1794b_mac_t1", "macos", "T1", true)
	pat1794InsertRule(t, ctx, pool, "pat1794b_win_t1", "windows", "T1", true)
	macT2 := pat1794InsertRule(t, ctx, pool, "pat1794b_mac_t2", "macos", "T2", true)
	winT2 := pat1794InsertRule(t, ctx, pool, "pat1794b_win_t2", "windows", "T2", true)

	for _, ruleID := range []string{macT2, winT2} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant_rules (tenant_id, rule_id, enabled, suppressed_until)
			VALUES ($1::uuid, $2::uuid, true, NULL)
		`, tenantID, ruleID); err != nil {
			t.Fatalf("insert tenant_rules for %s: %v", ruleID, err)
		}
	}

	summary, err := FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	if want := 4; summary.Coverage.ControlsTotal != want {
		t.Errorf("ControlsTotal = %d, want %d (both platforms' T1+T2 rules)", summary.Coverage.ControlsTotal, want)
	}
	if want := 4; summary.Coverage.ControlsEvaluated != want {
		t.Errorf("ControlsEvaluated = %d, want %d (both T1 rules + both actively-enabled T2 rules)", summary.Coverage.ControlsEvaluated, want)
	}
	if want := 0; summary.Coverage.ControlsOutOfScope != want {
		t.Errorf("ControlsOutOfScope = %d, want %d (no T3 rules seeded)", summary.Coverage.ControlsOutOfScope, want)
	}
}

// TestFetchControlCoverage_BenchmarkMultiplicityIsolationAndScoreSemantics
// keeps the portal and PDF definition honest. It proves that device
// multiplicity cannot inflate rule totals, benchmark versions remain
// distinct, disabled-platform and other-tenant evaluations cannot leak in,
// and the existing score still keeps unreadable fails in its denominator.
func TestFetchControlCoverage_BenchmarkMultiplicityIsolationAndScoreSemantics(t *testing.T) {
	pool := pat1794Pool(t)
	ctx := context.Background()

	var tenantID, otherTenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1857 Coverage Test Tenant', true, false)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1857 Other Tenant', true, false)
		RETURNING id::text
	`).Scan(&otherTenantID); err != nil {
		t.Fatalf("insert other tenant: %v", err)
	}

	insertDevice := func(owner, hostname, osName string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os)
		VALUES ($1::uuid, $2, $3)
		RETURNING id::text
	`, owner, hostname, osName).Scan(&id); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return id
	}
	macOne := insertDevice(tenantID, "coverage-mac-one", "macOS")
	macTwo := insertDevice(tenantID, "coverage-mac-two", "macOS")
	disabledWindows := insertDevice(tenantID, "coverage-windows-disabled", "Windows")
	otherMac := insertDevice(otherTenantID, "coverage-other-tenant", "macOS")

	var ruleV91, ruleV100, windowsRule string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules
			(rule_key, benchmark, benchmark_version, title, platform, collection_tier, enabled)
		VALUES ('pat1857_t1', 'CIS Example', 'v9.1', 'PAT-1857 T1', 'macos', 'T1', true)
		RETURNING id::text
	`).Scan(&ruleV91); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules
			(rule_key, benchmark, benchmark_version, title, platform, collection_tier, enabled)
		VALUES ('pat1857_t1_new_version', 'CIS Example', 'v10.0', 'PAT-1857 T1 new version', 'macos', 'T1', true)
		RETURNING id::text
	`).Scan(&ruleV100); err != nil {
		t.Fatalf("insert second benchmark version: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules
			(rule_key, benchmark, benchmark_version, title, platform, collection_tier, enabled)
		VALUES ('pat1857_windows_t1', 'CIS Windows Example', 'v1', 'PAT-1857 Windows T1', 'windows', 'T1', true)
		RETURNING id::text
	`).Scan(&windowsRule); err != nil {
		t.Fatalf("insert Windows rule: %v", err)
	}

	// macOne's older unreadable result is superseded by a real pass. macTwo's
	// latest result remains unreadable. The extra unreadable rows prove both
	// the platform and tenant boundaries.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, evaluated_at)
		VALUES
			($1::uuid, $5::uuid, 'fail', NULL, now() - interval '2 minutes'),
			($1::uuid, $5::uuid, 'pass', 'on', now() - interval '1 minute'),
			($2::uuid, $5::uuid, 'fail', NULL, now()),
			($1::uuid, $6::uuid, 'fail', NULL, now()),
			($3::uuid, $5::uuid, 'fail', NULL, now()),
			($3::uuid, $7::uuid, 'fail', NULL, now()),
			($4::uuid, $5::uuid, 'fail', NULL, now())
	`, macOne, macTwo, disabledWindows, otherMac, ruleV91, ruleV100, windowsRule); err != nil {
		t.Fatalf("insert evaluations: %v", err)
	}

	coverage, err := FetchControlCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchControlCoverage: %v", err)
	}
	if coverage.TotalZero {
		t.Error("TotalZero = true, want false with enabled rules")
	}
	if want := []string{"macos"}; !reflect.DeepEqual(coverage.Platforms, want) {
		t.Errorf("Platforms = %#v, want %#v", coverage.Platforms, want)
	}
	if coverage.ControlsTotal != 2 || coverage.ControlsEvaluated != 2 || coverage.ControlsOutOfScope != 0 {
		t.Errorf("coverage totals = %+v, want total=2 evaluated=2 out_of_scope=0", coverage)
	}
	if coverage.UndeterminedEvaluations != 2 {
		t.Errorf("UndeterminedEvaluations = %d, want 2", coverage.UndeterminedEvaluations)
	}
	if len(coverage.Benchmarks) != 2 {
		t.Fatalf("len(Benchmarks) = %d, want 2", len(coverage.Benchmarks))
	}
	versions := []string{coverage.Benchmarks[0].BenchmarkVersion, coverage.Benchmarks[1].BenchmarkVersion}
	if want := []string{"v10.0", "v9.1"}; !reflect.DeepEqual(versions, want) {
		t.Errorf("benchmark versions = %#v, want %#v", versions, want)
	}
	for _, benchmark := range coverage.Benchmarks {
		if benchmark.Benchmark != "CIS Example" || benchmark.ControlsTotal != 1 || benchmark.ControlsEvaluated != 1 {
			t.Errorf("benchmark coverage = %+v, want one evaluated CIS Example control", benchmark)
		}
		if benchmark.UndeterminedEvaluations != 1 {
			t.Errorf("benchmark undetermined = %d, want 1 for %s", benchmark.UndeterminedEvaluations, benchmark.BenchmarkVersion)
		}
	}

	// The coverage read does not introduce a new score category. Both
	// unreadable fails still count in the established percentage denominator:
	// macOne is one pass out of two results, macTwo is zero out of one, and the
	// tenant score remains the average of those per-device percentages.
	summary, err := FetchExecutiveSummary(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}
	if want := 25.0; summary.Compliance.OverallPct != want {
		t.Errorf("OverallPct = %.2f, want %.2f; undetermined must not raise the score", summary.Compliance.OverallPct, want)
	}
	if summary.Compliance.UndeterminedEvaluations != 2 {
		t.Errorf("summary undetermined = %d, want 2 without folding them into real fails", summary.Compliance.UndeterminedEvaluations)
	}
}

// TestFetchControlCoverageFiveStateMeasurementsAndIdentifiers proves the
// portal's additive dimensions keep their distinct units and scopes: latest
// evaluation rows create the four measurement buckets, while each enabled
// definition belongs to exactly one identifier bucket.
func TestFetchControlCoverageFiveStateMeasurementsAndIdentifiers(t *testing.T) {
	pool := pat1794Pool(t)
	ctx := context.Background()

	var tenantID, otherTenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1919 Five State Tenant', true, true)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1919 Other Tenant', true, true)
		RETURNING id::text
	`).Scan(&otherTenantID); err != nil {
		t.Fatalf("insert other tenant: %v", err)
	}

	insertDevice := func(owner, hostname, osName string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os)
			VALUES ($1::uuid, $2, $3)
			RETURNING id::text
		`, owner, hostname, osName).Scan(&id); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return id
	}
	macPass := insertDevice(tenantID, "five-state-mac-pass", "macOS")
	macFail := insertDevice(tenantID, "five-state-mac-fail", "macOS")
	macNA := insertDevice(tenantID, "five-state-mac-na", "macOS")
	winError := insertDevice(tenantID, "five-state-win-error", "Windows")
	otherMac := insertDevice(otherTenantID, "five-state-other", "macOS")

	insertRule := func(key, benchmark, version, platform, identifier string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO compliance_rules
				(rule_key, benchmark, benchmark_version, title, platform, collection_tier, control_identifier, enabled)
			VALUES ($1, $2, $3, $1, $4, 'T1', NULLIF($5, ''), true)
			RETURNING id::text
		`, key, benchmark, version, platform, identifier).Scan(&id); err != nil {
			t.Fatalf("insert rule %s: %v", key, err)
		}
		return id
	}
	mapped := insertRule("pat1919_cis_mapped", "CIS Example", "v1", "macos", "1.1")
	unmapped := insertRule("pat1919_cis_unmapped", "CIS Example", "v1", "macos", "")
	nonCIS := insertRule("pat1919_nist", "NIST Example", "r5", "windows", "")

	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, evaluated_at)
		VALUES
			($1::uuid, $6::uuid, 'fail', NULL, now() - interval '2 minutes'),
			($1::uuid, $6::uuid, 'pass', 'on', now() - interval '1 minute'),
			($2::uuid, $7::uuid, 'fail', 'off', now()),
			($3::uuid, $6::uuid, 'not_applicable', NULL, now()),
			($4::uuid, $8::uuid, 'error', 'collector unavailable', now()),
			($5::uuid, $6::uuid, 'fail', 'other tenant', now())
	`, macPass, macFail, macNA, winError, otherMac, mapped, unmapped, nonCIS); err != nil {
		t.Fatalf("insert evaluations: %v", err)
	}

	coverage, err := FetchControlCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchControlCoverage: %v", err)
	}
	if want := []string{"macos", "windows"}; !reflect.DeepEqual(coverage.Platforms, want) {
		t.Errorf("Platforms = %#v, want %#v", coverage.Platforms, want)
	}
	if got, want := coverage.Measurements, (ControlCoverageMeasurements{Pass: 1, Fail: 1, Undetermined: 1, NotApplicable: 1}); got != want {
		t.Errorf("Measurements = %+v, want %+v", got, want)
	}
	if got, want := coverage.Identifiers, (ControlCoverageIdentifiers{CISMapped: 1, CISUnmapped: 1, NonCIS: 1}); got != want {
		t.Errorf("Identifiers = %+v, want %+v", got, want)
	}
	if coverage.UndeterminedEvaluations != 0 {
		t.Errorf("legacy undetermined = %d, want 0 because only the error row is undetermined", coverage.UndeterminedEvaluations)
	}
	if len(coverage.Benchmarks) != 2 {
		t.Fatalf("len(Benchmarks) = %d, want 2", len(coverage.Benchmarks))
	}
	for _, benchmark := range coverage.Benchmarks {
		switch benchmark.Benchmark {
		case "CIS Example":
			if got, want := benchmark.Measurements, (ControlCoverageMeasurements{Pass: 1, Fail: 1, NotApplicable: 1}); got != want {
				t.Errorf("CIS measurements = %+v, want %+v", got, want)
			}
			if got, want := benchmark.Identifiers, (ControlCoverageIdentifiers{CISMapped: 1, CISUnmapped: 1}); got != want {
				t.Errorf("CIS identifiers = %+v, want %+v", got, want)
			}
		case "NIST Example":
			if got, want := benchmark.Measurements, (ControlCoverageMeasurements{Undetermined: 1}); got != want {
				t.Errorf("NIST measurements = %+v, want %+v", got, want)
			}
			if got, want := benchmark.Identifiers, (ControlCoverageIdentifiers{NonCIS: 1}); got != want {
				t.Errorf("NIST identifiers = %+v, want %+v", got, want)
			}
		default:
			t.Errorf("unexpected benchmark %#v", benchmark)
		}
	}
}

// TestFetchControlCoverage_TotalZeroIsExplicit checks the deliberate empty
// state. Empty is not a zero-percent score and must remain distinguishable
// from a populated control set with zero evaluation coverage.
func TestFetchControlCoverage_TotalZeroIsExplicit(t *testing.T) {
	pool := pat1794Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, macos_enabled, windows_enabled)
		VALUES ('PAT-1857 Empty Coverage Tenant', true, false)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	coverage, err := FetchControlCoverage(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchControlCoverage: %v", err)
	}
	if !coverage.TotalZero {
		t.Error("TotalZero = false, want true when no enabled rules match the platform mix")
	}
	if coverage.ControlsTotal != 0 || len(coverage.Benchmarks) != 0 {
		t.Errorf("empty coverage = %+v, want zero total and no benchmarks", coverage)
	}
}
