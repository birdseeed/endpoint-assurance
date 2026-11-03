package handlers

// PAT-1776 regression, extending PAT-1758/PAT-1762's undetermined-evidence
// rule to AdminHealthHandler.queryOpenFindingsBySeverity (health_admin.go,
// GET /admin/health's metrics.open_findings_by_severity): a 'fail' row with
// observed_value IS NULL is unreadable evidence (an absent signal, or the
// collector's literal "Unknown" sentinel), not a real observation of
// non-compliance. It must not count toward any per-severity bucket, and must
// be surfaced separately (Undetermined) rather than silently dropped. A
// "NotConfigured" fail (PAT-1767: the read succeeded, the setting is
// genuinely absent) has a non-NULL observed_value and must still count as a
// real, per-severity fail.
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as pat1758Pool (internal/report/pat1758_unknown_evidence_db_test.go)
// and pat1762Pool (internal/report/pat1762_undetermined_portal_admin_db_test.go).
// The pool's search_path is pinned to an isolated schema so no real data is
// touched and no full migration run is required — this schema only mirrors
// the columns queryOpenFindingsBySeverity's query path actually reads.

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1776HealthSchema = "pat1776_health_test"

func pat1776HealthPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed health admin test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1776HealthSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1776HealthSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1776HealthSchema,
		`CREATE TABLE ` + pat1776HealthSchema + `.tenants (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name       TEXT NOT NULL,
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1776HealthSchema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1776HealthSchema + `.tenants(id)
		)`,
		`CREATE TABLE ` + pat1776HealthSchema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1776HealthSchema+` CASCADE`)
	})
	return pool
}

// TestQueryOpenFindingsBySeverity_UndeterminedExcludedFromSeverityCounts is
// the PAT-1776 regression: an undetermined fail (observed_value NULL) must
// not be counted in its severity's bucket, must be surfaced in Undetermined
// instead, and a real fail (including a NotConfigured one) must still count
// under its own severity.
func TestQueryOpenFindingsBySeverity_UndeterminedExcludedFromSeverityCounts(t *testing.T) {
	pool := pat1776HealthPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1776 Health Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	insertDevice := func() string {
		t.Helper()
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id) VALUES ($1::uuid)
			RETURNING id::text
		`, tenantID).Scan(&deviceID); err != nil {
			t.Fatalf("insert device: %v", err)
		}
		return deviceID
	}
	insertEval := func(deviceID, ruleID, status, severity string, observedValue *string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5)
		`, deviceID, ruleID, status, observedValue, severity); err != nil {
			t.Fatalf("insert evaluation (device %s, status %s): %v", deviceID, status, err)
		}
	}
	ruleID := "11111111-1111-1111-1111-111111111111"
	otherRuleID := "22222222-2222-2222-2222-222222222222"
	notConfiguredRuleID := "33333333-3333-3333-3333-333333333333"

	realFailDevice := insertDevice()
	insertEval(realFailDevice, ruleID, "fail", "critical", strPtr("Off"))

	undeterminedDevice := insertDevice()
	insertEval(undeterminedDevice, otherRuleID, "fail", "critical", nil)

	notConfiguredDevice := insertDevice()
	insertEval(notConfiguredDevice, notConfiguredRuleID, "fail", "high", strPtr("NotConfigured"))

	h := &AdminHealthHandler{pool: pool}
	result := h.queryOpenFindingsBySeverity(ctx, slog.Default())

	if result.Critical != 1 {
		t.Errorf("Critical = %d, want 1 (the real 'Off' fail; the undetermined fail must be excluded)", result.Critical)
	}
	if result.High != 1 {
		t.Errorf("High = %d, want 1 (the NotConfigured fail — a real, evidenced result)", result.High)
	}
	if result.Undetermined != 1 {
		t.Errorf("Undetermined = %d, want 1 (surfaced separately, not dropped)", result.Undetermined)
	}
}
