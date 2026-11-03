package report

// PAT-1776 regression, extending PAT-1758/PAT-1762's undetermined-evidence
// rule to two more admin.go aggregates: FetchTenantsOverview's crit_high
// count and FetchTenantFindings' findings list. A 'fail' row with
// observed_value IS NULL is unreadable evidence (an absent signal, or the
// collector's literal "Unknown" sentinel), not a real observation of
// non-compliance:
//   - FetchTenantsOverview.CritHighFails must count only real, evidenced
//     critical/high fails; UndeterminedCritHighFails carries the rest
//     separately; CompliancePct's denominator is unaffected.
//   - FetchTenantFindings.Findings must exclude undetermined fails (there is
//     nothing to remediate for a control the collector could not read);
//     UndeterminedCount carries them separately instead of dropping them. A
//     real fail and an 'error' row must still appear in Findings.
//
// A "NotConfigured" fail (PAT-1767: the read succeeded, the setting is
// genuinely absent) has a non-NULL observed_value and must still count as a
// real fail throughout.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as pat1686Pool (admin_overview_devicecount_db_test.go) and
// pat1758Pool (pat1758_unknown_evidence_db_test.go). The pool's search_path
// is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1776AdminSchema = "pat1776_admin_test"

func pat1776AdminPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1776AdminSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1776AdminSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1776AdminSchema,
		// Same shape as pat1686Pool (admin_overview_devicecount_db_test.go) —
		// only the columns FetchTenantsOverview/FetchTenantFindings touch.
		`CREATE TABLE ` + pat1776AdminSchema + `.tenants (
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
		`CREATE TABLE ` + pat1776AdminSchema + `.agent_config (
			tenant_id UUID NOT NULL UNIQUE REFERENCES ` + pat1776AdminSchema + `.tenants(id),
			body      JSONB NOT NULL DEFAULT '{}'
		)`,
		`CREATE TABLE ` + pat1776AdminSchema + `.devices (
			id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID NOT NULL REFERENCES ` + pat1776AdminSchema + `.tenants(id),
			serial               TEXT,
			hostname             TEXT,
			os                   TEXT,
			os_version           TEXT,
			last_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
			primary_user_account TEXT,
			primary_user_display TEXT,
			backup_status        JSONB
		)`,
		`CREATE TABLE ` + pat1776AdminSchema + `.compliance_rules (
			id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL,
			title    TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'low'
		)`,
		`CREATE TABLE ` + pat1776AdminSchema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1776AdminSchema + `.tenant_new_apps (
			tenant_id UUID NOT NULL REFERENCES ` + pat1776AdminSchema + `.tenants(id),
			decision  TEXT
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1776AdminSchema+` CASCADE`)
	})
	return pool
}

// pat1776AdminSeed creates one tenant, one critical rule, and three devices
// whose latest evaluation of that rule is: a real 'Off' fail, an undetermined
// fail (observed_value NULL), and a pass. Mirrors seedPAT1758Tenant's shape.
func pat1776AdminSeed(t *testing.T, pool *pgxpool.Pool) (tenantID, realFailDeviceID, undeterminedDeviceID, passDeviceID, ruleID string) {
	t.Helper()
	ctx := context.Background()

	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1776 Admin Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	for _, dst := range []*string{&realFailDeviceID, &undeterminedDeviceID, &passDeviceID} {
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
		VALUES ('pat1776_admin_rule', 'PAT-1776 Admin Rule', 'critical')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
		VALUES ($1::uuid, $2::uuid, 'fail', 'Off', 'critical')
	`, realFailDeviceID, ruleID); err != nil {
		t.Fatalf("insert real-fail evaluation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
		VALUES ($1::uuid, $2::uuid, 'fail', NULL, 'critical')
	`, undeterminedDeviceID, ruleID); err != nil {
		t.Fatalf("insert undetermined evaluation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
		VALUES ($1::uuid, $2::uuid, 'pass', 'On', 'critical')
	`, passDeviceID, ruleID); err != nil {
		t.Fatalf("insert pass evaluation: %v", err)
	}

	return tenantID, realFailDeviceID, undeterminedDeviceID, passDeviceID, ruleID
}

// TestFetchTenantsOverview_UndeterminedCritHighExcludedFromCritHighFails is
// the FetchTenantsOverview half of the PAT-1776 regression: CritHighFails
// must count only the real, evidenced critical/high fail; the undetermined
// fail must be excluded and instead counted in
// UndeterminedCritHighFails; a NotConfigured fail (real, evidenced) must
// count in CritHighFails, not UndeterminedCritHighFails.
func TestFetchTenantsOverview_UndeterminedCritHighExcludedFromCritHighFails(t *testing.T) {
	pool := pat1776AdminPool(t)
	tenantID, _, _, _, ruleID := pat1776AdminSeed(t, pool)

	// A fourth device: NotConfigured fail — real, evidenced, non-NULL.
	ctx := context.Background()
	var notConfiguredDevice string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, 'dev-' || substr(gen_random_uuid()::text, 1, 8), 'macOS', '15.0')
		RETURNING id::text
	`, tenantID).Scan(&notConfiguredDevice); err != nil {
		t.Fatalf("insert not-configured device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
		VALUES ($1::uuid, $2::uuid, 'fail', 'NotConfigured', 'critical')
	`, notConfiguredDevice, ruleID); err != nil {
		t.Fatalf("insert not-configured evaluation: %v", err)
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

	if row.CritHighFails != 2 {
		t.Errorf("CritHighFails = %d, want 2 (the 'Off' fail and the 'NotConfigured' fail; the undetermined fail must be excluded)", row.CritHighFails)
	}
	if row.UndeterminedCritHighFails != 1 {
		t.Errorf("UndeterminedCritHighFails = %d, want 1", row.UndeterminedCritHighFails)
	}

	// CompliancePct's denominator (pass_ct/denom) is unaffected by this fix —
	// it already counted every 'fail' row regardless of observed_value.
	// pass=1, fail=3 (real+undetermined+not-configured) -> 25%.
	wantPct := 100.0 / 4.0
	if diff := row.CompliancePct - wantPct; diff > 0.01 || diff < -0.01 {
		t.Errorf("CompliancePct = %.4f, want %.4f (undetermined fail must stay in the denominator)", row.CompliancePct, wantPct)
	}
}

// TestFetchTenantFindings_UndeterminedFailExcludedButCounted is the
// FetchTenantFindings half of the PAT-1776 regression: the findings list
// must contain only the real fail (there is nothing to remediate for the
// undetermined one), and UndeterminedCount must carry the excluded row
// instead of silently dropping it.
func TestFetchTenantFindings_UndeterminedFailExcludedButCounted(t *testing.T) {
	pool := pat1776AdminPool(t)
	tenantID, realFailDeviceID, undeterminedDeviceID, _, _ := pat1776AdminSeed(t, pool)

	res, err := FetchTenantFindings(context.Background(), pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchTenantFindings: %v", err)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1 (only the real fail; the undetermined fail must be excluded)", len(res.Findings))
	}
	if res.Findings[0].DeviceID != realFailDeviceID {
		t.Errorf("Findings[0].DeviceID = %s, want %s (the real-fail device)", res.Findings[0].DeviceID, realFailDeviceID)
	}
	if res.Total != 1 {
		t.Errorf("Total = %d, want 1", res.Total)
	}
	if res.UndeterminedCount != 1 {
		t.Errorf("UndeterminedCount = %d, want 1 (the excluded undetermined fail on device %s, surfaced not dropped)", res.UndeterminedCount, undeterminedDeviceID)
	}
}
