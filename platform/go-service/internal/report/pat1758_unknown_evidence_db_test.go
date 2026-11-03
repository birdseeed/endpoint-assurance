package report

// PAT-1758 regression: an evaluation that failed because the collector could
// not read the signal (an absent key, or — since both agents now emit the
// literal "Unknown" sentinel on a failed read per PAT-1710/1751/1752 — a
// present-but-unreadable value) must not be counted the same way as a real
// observation of non-compliance in the executive report. Before the fix,
// fetchTopFailingControls and fetchComplianceStats counted every
// status='fail' row identically, so a device whose evidence the collector
// simply could not read was reported as "unmanaged"/"non-compliant" exactly
// like a device that was actually checked and found wanting.
//
// The evaluator half of this fix (a present "Unknown" signal routed through
// treat_unknown_as with ObservedValue left nil, same as an absent key) is
// covered by internal/evaluator/evaluator_test.go. This file covers the
// persisted-evidence half: compliance_evaluations.observed_value really does
// come back NULL for those rows, and the executive report's aggregates
// exclude them from the real-fail counts while surfacing them separately.
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as platform_switch_aggregation_db_test.go (pat862Pool). The
// pool's search_path is pinned to an isolated schema so no real data is
// touched and no full migration run is required — this schema only mirrors
// the columns FetchExecutiveSummary's section fetchers actually read.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1758Schema = "pat1758_test"

func pat1758Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1758Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1758Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1758Schema,
		`CREATE TABLE ` + pat1758Schema + `.tenants (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name            TEXT NOT NULL,
			macos_enabled   boolean NOT NULL DEFAULT true,
			windows_enabled boolean NOT NULL DEFAULT true
		)`,
		`CREATE TABLE ` + pat1758Schema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1758Schema + `.tenants(id),
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			pending_updates      JSONB,
			device_class         TEXT NOT NULL DEFAULT 'unknown'
			                     CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat1758Schema + `.compliance_rules (
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
		// tenant_rules (PAT-1794): fetchControlCoverage joins this to count
		// T2 rules actively enabled for a tenant. No rows are seeded in
		// this suite's fixtures — every rule here defaults to T1 — but the
		// table must exist for the JOIN to plan. Same shape as pat862Pool's
		// (platform_switch_aggregation_db_test.go) fixture.
		`CREATE TABLE ` + pat1758Schema + `.tenant_rules (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id        UUID NOT NULL REFERENCES ` + pat1758Schema + `.tenants(id),
			rule_id          UUID NOT NULL REFERENCES ` + pat1758Schema + `.compliance_rules(id),
			enabled          BOOLEAN NOT NULL DEFAULT true,
			suppressed_until TIMESTAMPTZ,
			UNIQUE (tenant_id, rule_id)
		)`,
		// observed_value is the column this regression is about: NULL for a
		// signal that was absent or the "Unknown" sentinel, populated for a
		// real observation. id/PRIMARY KEY and column set mirror
		// migrations/0003_compliance_rules.sql exactly (append-only table,
		// no unique constraint beyond the surrogate key — "latest per
		// device+rule" is a query-time DISTINCT ON, not a DB constraint).
		`CREATE TABLE ` + pat1758Schema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1758Schema + `.patches (
			device_id    UUID NOT NULL,
			identifier   TEXT,
			title        TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// agent_config omitted deliberately: FetchExecutiveSummary's toggle
		// lookup is best-effort and discards the error, defaulting to "off" —
		// same behavior as a tenant with no agent_config row.
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1758Schema+` CASCADE`)
	})
	return pool
}

// seedPAT1758Tenant creates one tenant, one critical rule, and three
// devices whose latest evaluation of that rule is:
//   - realFailDeviceID:  status=fail, observed_value='Off'  — a genuine,
//     evidenced non-compliance.
//   - unknownFailDeviceID: status=fail, observed_value=NULL — the collector
//     could not read the signal (absent key, or a present "Unknown" that the
//     evaluator has already routed through treat_unknown_as=fail).
//   - passDeviceID: status=pass, observed_value='On' — compliant.
func seedPAT1758Tenant(t *testing.T, pool *pgxpool.Pool) (tenantID, realFailDeviceID, unknownFailDeviceID, passDeviceID, ruleID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1758 Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	for _, dst := range []*string{&realFailDeviceID, &unknownFailDeviceID, &passDeviceID} {
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version)
			VALUES ($1::uuid, 'dev-' || substr(gen_random_uuid()::text, 1, 8), 'macOS', '15.0')
			RETURNING id::text
		`, tenantID).Scan(dst); err != nil {
			t.Fatalf("insert device: %v", err)
		}
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat1758_test_rule', 'PAT-1758 Test Rule', 'critical')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	// evaluated_at values are explicit and distinct (not all DEFAULT now())
	// so DISTINCT ON (device_id, rule_id) ... ORDER BY evaluated_at DESC has
	// a deterministic "latest" row to pick even though every row here
	// already has a unique (device_id, rule_id) pair — defensive against a
	// future edit that inserts re-evaluation history for the same pair.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
		VALUES ($1::uuid, $2::uuid, 'fail', 'Off', 'critical', now() - interval '40 seconds')
	`, realFailDeviceID, ruleID); err != nil {
		t.Fatalf("insert real-fail evaluation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
		VALUES ($1::uuid, $2::uuid, 'fail', NULL, 'critical', now() - interval '30 seconds')
	`, unknownFailDeviceID, ruleID); err != nil {
		t.Fatalf("insert unknown-evidence-fail evaluation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
		VALUES ($1::uuid, $2::uuid, 'pass', 'On', 'critical', now() - interval '20 seconds')
	`, passDeviceID, ruleID); err != nil {
		t.Fatalf("insert pass evaluation: %v", err)
	}

	return tenantID, realFailDeviceID, unknownFailDeviceID, passDeviceID, ruleID
}

// seedPAT1758NotConfiguredFailDevice adds one more device to tenantID/ruleID
// whose latest evaluation is status=fail, observed_value='NotConfigured'
// (PAT-1767: the read succeeded, the setting is genuinely absent, and the
// rule's effective treat_not_configured_as resolved to fail). Unlike the
// unknown-evidence fail seeded by seedPAT1758Tenant, this IS a real,
// evidenced result — the read did not fail, it read "absent" — and must be
// counted in DevicesAffected/FailEvaluations/CriticalFails exactly like the
// 'Off' fail, not folded into UndeterminedDevices/UndeterminedEvaluations.
func seedPAT1758NotConfiguredFailDevice(t *testing.T, pool *pgxpool.Pool, tenantID, ruleID string) (deviceID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, 'dev-' || substr(gen_random_uuid()::text, 1, 8), 'macOS', '15.0')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert not-configured-fail device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
		VALUES ($1::uuid, $2::uuid, 'fail', 'NotConfigured', 'critical', now() - interval '10 seconds')
	`, deviceID, ruleID); err != nil {
		t.Fatalf("insert not-configured-fail evaluation: %v", err)
	}
	return deviceID
}

// TestFetchExecutiveSummary_NotConfiguredFailCountedAsReal is the PAT-1767 x
// PAT-1758 boundary case: a device whose signal read succeeded and came back
// "NotConfigured" (real evidence, non-null observed_value) must be counted
// as a real fail in both fetchTopFailingControls' DevicesAffected and
// fetchComplianceStats' FailEvaluations/CriticalFails — the observed_value
// IS NOT NULL predicate this ticket introduced must not accidentally sweep
// up NotConfigured rows alongside genuinely unreadable ones.
func TestFetchExecutiveSummary_NotConfiguredFailCountedAsReal(t *testing.T) {
	pool := pat1758Pool(t)
	tenantID, _, _, _, ruleID := seedPAT1758Tenant(t, pool)
	seedPAT1758NotConfiguredFailDevice(t, pool, tenantID, ruleID)

	summary, err := FetchExecutiveSummary(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	if len(summary.TopFailing) != 1 {
		t.Fatalf("TopFailing: got %d controls, want 1", len(summary.TopFailing))
	}
	tc := summary.TopFailing[0]
	if tc.DevicesAffected != 2 {
		t.Errorf("DevicesAffected = %d, want 2 (the 'Off' real fail plus the 'NotConfigured' real fail)", tc.DevicesAffected)
	}
	if tc.UndeterminedDevices != 1 {
		t.Errorf("UndeterminedDevices = %d, want 1 (only the unknown-evidence fail; NotConfigured must not count here)", tc.UndeterminedDevices)
	}
	if tc.TotalDevices != 4 {
		t.Errorf("TotalDevices = %d, want 4 (real fail + unknown fail + pass + NotConfigured fail)", tc.TotalDevices)
	}

	c := summary.Compliance
	if c.FailEvaluations != 2 {
		t.Errorf("FailEvaluations = %d, want 2 (the 'Off' fail and the 'NotConfigured' fail; the unknown-evidence fail is excluded)", c.FailEvaluations)
	}
	if c.CriticalFails != 2 {
		t.Errorf("CriticalFails = %d, want 2 (both real fails are severity=critical)", c.CriticalFails)
	}
	if c.UndeterminedEvaluations != 1 {
		t.Errorf("UndeterminedEvaluations = %d, want 1 (unchanged by adding a NotConfigured fail)", c.UndeterminedEvaluations)
	}
}

// TestFetchExecutiveSummary_UnknownEvidenceFailExcludedFromTopFailing is the
// fetchTopFailingControls half of the regression: a device whose evidence
// for a control could not be read must not be counted in DevicesAffected
// (the number the "Enrol N unmanaged endpoints" / "Remediate X across N
// devices" recommendations are built from), and must be counted in the new
// UndeterminedDevices instead. A real fail must still be counted.
func TestFetchExecutiveSummary_UnknownEvidenceFailExcludedFromTopFailing(t *testing.T) {
	pool := pat1758Pool(t)
	tenantID, _, _, _, _ := seedPAT1758Tenant(t, pool)

	summary, err := FetchExecutiveSummary(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	if len(summary.TopFailing) != 1 {
		t.Fatalf("TopFailing: got %d controls, want 1", len(summary.TopFailing))
	}
	tc := summary.TopFailing[0]
	if tc.RuleKey != "pat1758_test_rule" {
		t.Fatalf("TopFailing[0].RuleKey = %q, want pat1758_test_rule", tc.RuleKey)
	}
	if tc.DevicesAffected != 1 {
		t.Errorf("DevicesAffected = %d, want 1 (only the real fail; the unknown-evidence fail must be excluded)", tc.DevicesAffected)
	}
	if tc.UndeterminedDevices != 1 {
		t.Errorf("UndeterminedDevices = %d, want 1 (the unknown-evidence fail)", tc.UndeterminedDevices)
	}
	if tc.TotalDevices != 3 {
		t.Errorf("TotalDevices = %d, want 3 (all three devices have a latest evaluation)", tc.TotalDevices)
	}
	wantPct := 1.0 / 3.0 * 100.0
	if diff := tc.PctAffected - wantPct; diff > 0.01 || diff < -0.01 {
		t.Errorf("PctAffected = %.4f, want ~%.4f (based on real DevicesAffected, not real+undetermined)", tc.PctAffected, wantPct)
	}
}

// TestFetchExecutiveSummary_UnknownEvidenceFailExcludedFromComplianceStats is
// the fetchComplianceStats half: FailEvaluations/CriticalFails and the
// per-device compliance percentage must not count an unknown-evidence fail
// as a real failure, and UndeterminedEvaluations must report it separately.
func TestFetchExecutiveSummary_UnknownEvidenceFailExcludedFromComplianceStats(t *testing.T) {
	pool := pat1758Pool(t)
	tenantID, _, _, _, _ := seedPAT1758Tenant(t, pool)

	summary, err := FetchExecutiveSummary(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	c := summary.Compliance
	if c.PassEvaluations != 1 {
		t.Errorf("PassEvaluations = %d, want 1", c.PassEvaluations)
	}
	if c.FailEvaluations != 1 {
		t.Errorf("FailEvaluations = %d, want 1 (only the real fail)", c.FailEvaluations)
	}
	if c.CriticalFails != 1 {
		t.Errorf("CriticalFails = %d, want 1 (only the real fail; both fails are severity=critical)", c.CriticalFails)
	}
	if c.UndeterminedEvaluations != 1 {
		t.Errorf("UndeterminedEvaluations = %d, want 1", c.UndeterminedEvaluations)
	}

	// The unknown-evidence-fail device is NOT excluded from the pct
	// denominator (only from the fail_count/crit_count-style buckets above):
	// device_pcts stays pass / (pass + fail + error), counting an
	// undetermined fail exactly like any other fail, so a device that sends
	// no readable evidence never scores as well as, or better than, one that
	// was actually checked. Each device here has exactly one evaluation, so
	// per-device pct is 100% (pass), 0% (real fail), 0% (undetermined fail);
	// the tenant-wide average across all three is 33.33%, not 50%.
	wantPct := 100.0 / 3.0
	if diff := c.OverallPct - wantPct; diff > 0.01 || diff < -0.01 {
		t.Errorf("OverallPct = %.4f, want %.4f (undetermined fail must count in the denominator, same as a real fail)", c.OverallPct, wantPct)
	}
}

// seedPAT1758AllUndeterminedRule adds a second rule to tenantID whose only
// latest-evaluation rows are undetermined fails (observed_value NULL) across
// two fresh devices — no real fail, no pass. Used to verify that such a rule
// is excluded from TopFailing entirely rather than sorting in as
// TopFailing[0] with DevicesAffected=0 (PAT-1758 follow-up: a 0-affected
// control must never drive the "Remediate X across 0 of N devices" or "Enrol
// 0 unmanaged endpoints" recommendation text).
func seedPAT1758AllUndeterminedRule(t *testing.T, pool *pgxpool.Pool, tenantID string) (ruleID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat1758_all_undetermined_rule', 'PAT-1758 All-Undetermined Rule', 'high')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert all-undetermined rule: %v", err)
	}

	for i := 0; i < 2; i++ {
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version)
			VALUES ($1::uuid, 'dev-' || substr(gen_random_uuid()::text, 1, 8), 'macOS', '15.0')
			RETURNING id::text
		`, tenantID).Scan(&deviceID); err != nil {
			t.Fatalf("insert device: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
			VALUES ($1::uuid, $2::uuid, 'fail', NULL, 'high', now() - (interval '1 second' * $3))
		`, deviceID, ruleID, i); err != nil {
			t.Fatalf("insert undetermined-only evaluation: %v", err)
		}
	}

	return ruleID
}

// TestFetchExecutiveSummary_AllUndeterminedRuleExcludedFromTopFailing is the
// PAT-1758 follow-up regression: a rule whose latest fail rows are ALL
// undetermined (devices_affected=0) must not appear in TopFailing at all —
// specifically, it must never sort to TopFailing[0] and drive
// deriveRecommendations' "Remediate X across 0 of N devices" line. The rule
// WITH a real fail (from seedPAT1758Tenant) must still appear.
func TestFetchExecutiveSummary_AllUndeterminedRuleExcludedFromTopFailing(t *testing.T) {
	pool := pat1758Pool(t)
	tenantID, _, _, _, _ := seedPAT1758Tenant(t, pool)
	allUndeterminedRuleID := seedPAT1758AllUndeterminedRule(t, pool, tenantID)

	summary, err := FetchExecutiveSummary(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	for _, tc := range summary.TopFailing {
		if tc.RuleKey == "pat1758_all_undetermined_rule" {
			t.Fatalf("all-undetermined rule (id=%s) must not appear in TopFailing (devices_affected=0), got row: %+v", allUndeterminedRuleID, tc)
		}
	}
	if len(summary.TopFailing) != 1 {
		t.Fatalf("TopFailing: got %d controls, want 1 (only the real-fail rule)", len(summary.TopFailing))
	}
	if summary.TopFailing[0].RuleKey != "pat1758_test_rule" {
		t.Fatalf("TopFailing[0].RuleKey = %q, want pat1758_test_rule", summary.TopFailing[0].RuleKey)
	}

	// deriveRecommendations must not produce a "0 of N devices" line: the
	// only rule left in TopFailing has a real fail, so recommendation #2
	// (the top-failing-control remediation) must cite a nonzero count.
	recs := deriveRecommendations(summary)
	for _, r := range recs {
		if strings.Contains(r, "across 0 of") {
			t.Errorf("recommendation cites a 0-affected control: %q", r)
		}
		if strings.Contains(r, "Enrol 0 unmanaged") {
			t.Errorf("recommendation cites 0 unmanaged endpoints: %q", r)
		}
	}
}

// seedPAT1758WorstDevicesScenario creates one tenant, two rules, and three
// devices for the fetchWorstDevices regression:
//   - deviceA: fails both rules with a real observed value (2 real fails).
//   - deviceB: fails both rules with observed_value NULL (0 real fails, 2
//     undetermined) — the collector could not read either signal.
//   - deviceC: fails ruleX for real and ruleY as undetermined (1 real fail,
//     1 undetermined).
//
// evaluated_at is explicit and distinct per row for deterministic
// DISTINCT ON tie-breaking (same reasoning as seedPAT1758Tenant).
func seedPAT1758WorstDevicesScenario(t *testing.T, pool *pgxpool.Pool) (tenantID, deviceA, deviceB, deviceC string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1758 Worst-Devices Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var ruleX, ruleY string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat1758_worst_rule_x', 'PAT-1758 Worst Devices Rule X', 'critical')
		RETURNING id::text
	`).Scan(&ruleX); err != nil {
		t.Fatalf("insert rule X: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat1758_worst_rule_y', 'PAT-1758 Worst Devices Rule Y', 'high')
		RETURNING id::text
	`).Scan(&ruleY); err != nil {
		t.Fatalf("insert rule Y: %v", err)
	}

	for _, dst := range []*string{&deviceA, &deviceB, &deviceC} {
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version)
			VALUES ($1::uuid, 'dev-' || substr(gen_random_uuid()::text, 1, 8), 'macOS', '15.0')
			RETURNING id::text
		`, tenantID).Scan(dst); err != nil {
			t.Fatalf("insert device: %v", err)
		}
	}

	// severity is denormalised onto compliance_evaluations independently of
	// compliance_rules (fetchWorstDevices reads e.severity, not a joined
	// rule severity), so it must match ruleX='critical'/ruleY='high' here
	// for deviceA's CriticalCount assertion to mean anything.
	type row struct {
		device        string
		rule          string
		severity      string
		observedValue interface{}
		offsetSeconds int
	}
	rows := []row{
		{deviceA, ruleX, "critical", "Off", 60},
		{deviceA, ruleY, "high", "Off", 59},
		{deviceB, ruleX, "critical", nil, 58},
		{deviceB, ruleY, "high", nil, 57},
		{deviceC, ruleX, "critical", "Off", 56},
		{deviceC, ruleY, "high", nil, 55},
	}
	for _, r := range rows {
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
			VALUES ($1::uuid, $2::uuid, 'fail', $3, $4, now() - (interval '1 second' * $5))
		`, r.device, r.rule, r.observedValue, r.severity, r.offsetSeconds); err != nil {
			t.Fatalf("insert evaluation (device=%s rule=%s): %v", r.device, r.rule, err)
		}
	}

	return tenantID, deviceA, deviceB, deviceC
}

// TestFetchExecutiveSummary_WorstDevicesExcludesUndeterminedOnly is the
// fetchWorstDevices half of the PAT-1758 non-author-review fix: FailingCount/
// CriticalCount there must count only real, evidenced fails (consistent with
// fetchComplianceStats/fetchTopFailingControls), and a device whose latest
// evaluations are ALL undetermined must not appear in the "Devices Needing
// Attention" list at all — it has no evidenced problem to report.
func TestFetchExecutiveSummary_WorstDevicesExcludesUndeterminedOnly(t *testing.T) {
	pool := pat1758Pool(t)
	tenantID, deviceA, deviceB, deviceC := seedPAT1758WorstDevicesScenario(t, pool)

	summary, err := FetchExecutiveSummary(context.Background(), pool, tenantID)
	if err != nil {
		t.Fatalf("FetchExecutiveSummary: %v", err)
	}

	byDevice := map[string]WorstDevice{}
	for _, w := range summary.WorstDevices {
		byDevice[w.DeviceID] = w
	}

	if _, ok := byDevice[deviceB]; ok {
		t.Fatalf("deviceB (only undetermined fails) must not appear in WorstDevices, got: %+v", byDevice[deviceB])
	}

	wa, ok := byDevice[deviceA]
	if !ok {
		t.Fatalf("deviceA (2 real fails) must appear in WorstDevices")
	}
	if wa.FailingCount != 2 {
		t.Errorf("deviceA FailingCount = %d, want 2", wa.FailingCount)
	}
	if wa.CriticalCount != 1 {
		t.Errorf("deviceA CriticalCount = %d, want 1 (only ruleX is severity=critical)", wa.CriticalCount)
	}
	if wa.UndeterminedCount != 0 {
		t.Errorf("deviceA UndeterminedCount = %d, want 0", wa.UndeterminedCount)
	}

	wc, ok := byDevice[deviceC]
	if !ok {
		t.Fatalf("deviceC (1 real fail + 1 undetermined) must appear in WorstDevices")
	}
	if wc.FailingCount != 1 {
		t.Errorf("deviceC FailingCount = %d, want 1 (the undetermined fail on ruleY must be excluded)", wc.FailingCount)
	}
	if wc.UndeterminedCount != 1 {
		t.Errorf("deviceC UndeterminedCount = %d, want 1", wc.UndeterminedCount)
	}
}
