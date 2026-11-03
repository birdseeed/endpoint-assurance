package extractor

// DB-backed tests for PAT-1549's auto-apply-detection hook
// (markArtefactsApplied, upsert.go). Skipped unless TEST_DATABASE_URL points
// at a scratch database — same isolated-schema convention as
// applied_config_db_test.go's appliedConfigPool.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const remediationAppliedTestSchema = "pat1549_extractor_test"

func remediationAppliedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed remediation-applied test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = remediationAppliedTestSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + remediationAppliedTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + remediationAppliedTestSchema,
		`CREATE TABLE ` + remediationAppliedTestSchema + `.tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid()
		)`,
		`CREATE TABLE ` + remediationAppliedTestSchema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + remediationAppliedTestSchema + `.tenants(id)
		)`,
		`CREATE TABLE ` + remediationAppliedTestSchema + `.compliance_rules (
			id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL
		)`,
		// Mirrors migrations/0141_remediation_artefacts.sql.
		`CREATE TABLE ` + remediationAppliedTestSchema + `.remediation_artefacts (
			id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id            UUID        NOT NULL REFERENCES ` + remediationAppliedTestSchema + `.tenants(id),
			device_id            UUID        NOT NULL REFERENCES ` + remediationAppliedTestSchema + `.devices(id),
			rule_id              UUID        NOT NULL REFERENCES ` + remediationAppliedTestSchema + `.compliance_rules(id),
			platform             TEXT        NOT NULL DEFAULT 'macos',
			rule_pack_version    TEXT        NOT NULL DEFAULT 'v1.0.0',
			observed_prior_value TEXT,
			payload              TEXT        NOT NULL DEFAULT '',
			content_hash         TEXT        NOT NULL DEFAULT '',
			generated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
			generated_by         TEXT        NOT NULL DEFAULT '',
			status               TEXT        NOT NULL DEFAULT 'issued',
			applied_observed_at  TIMESTAMPTZ,
			supersedes_id        UUID        REFERENCES ` + remediationAppliedTestSchema + `.remediation_artefacts(id)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+remediationAppliedTestSchema+` CASCADE`)
	})
	return pool
}

func remediationSeedTenantDeviceRule(t *testing.T, pool *pgxpool.Pool) (tenantID, deviceID, ruleID string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO compliance_rules (rule_key) VALUES ('test_rule') RETURNING id::text`).Scan(&ruleID); err != nil {
		t.Fatalf("insert compliance_rules: %v", err)
	}
	return tenantID, deviceID, ruleID
}

func remediationInsertArtefact(t *testing.T, pool *pgxpool.Pool, tenantID, deviceID, ruleID string, status string, supersedes *string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO remediation_artefacts (tenant_id, device_id, rule_id, status, supersedes_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid)
		RETURNING id::text
	`, tenantID, deviceID, ruleID, status, supersedes).Scan(&id); err != nil {
		t.Fatalf("insert remediation_artefacts: %v", err)
	}
	return id
}

func remediationArtefactStatus(t *testing.T, pool *pgxpool.Pool, id string) (status string, appliedAt *time.Time) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT status, applied_observed_at FROM remediation_artefacts WHERE id = $1::uuid`, id,
	).Scan(&status, &appliedAt); err != nil {
		t.Fatalf("select status: %v", err)
	}
	return status, appliedAt
}

func TestMarkArtefactsApplied_FlipsCurrentIssuedArtefactOnPass(t *testing.T) {
	pool := remediationAppliedPool(t)
	tenantID, deviceID, ruleID := remediationSeedTenantDeviceRule(t, pool)
	artefactID := remediationInsertArtefact(t, pool, tenantID, deviceID, ruleID, "issued", nil)

	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	observedAt := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	n, err := markArtefactsApplied(ctx, tx, deviceID, []eval{{ruleID: ruleID, status: "pass"}}, observedAt)
	if err != nil {
		t.Fatalf("markArtefactsApplied: %v", err)
	}
	if n != 1 {
		t.Fatalf("marked %d artefacts, want 1", n)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	status, appliedAt := remediationArtefactStatus(t, pool, artefactID)
	if status != "applied" {
		t.Errorf("status = %q, want applied", status)
	}
	if appliedAt == nil || !appliedAt.Equal(observedAt) {
		t.Errorf("applied_observed_at = %v, want %v", appliedAt, observedAt)
	}
}

func TestMarkArtefactsApplied_IgnoresNonPassingEvaluations(t *testing.T) {
	pool := remediationAppliedPool(t)
	tenantID, deviceID, ruleID := remediationSeedTenantDeviceRule(t, pool)
	artefactID := remediationInsertArtefact(t, pool, tenantID, deviceID, ruleID, "issued", nil)

	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n, err := markArtefactsApplied(ctx, tx, deviceID, []eval{{ruleID: ruleID, status: "fail"}}, time.Now())
	if err != nil {
		t.Fatalf("markArtefactsApplied: %v", err)
	}
	if n != 0 {
		t.Fatalf("marked %d artefacts, want 0 for a failing evaluation", n)
	}
	_ = tx.Commit(ctx)

	status, _ := remediationArtefactStatus(t, pool, artefactID)
	if status != "issued" {
		t.Errorf("status = %q, want still issued", status)
	}
}

func TestMarkArtefactsApplied_NeverTouchesASupersededArtefact(t *testing.T) {
	pool := remediationAppliedPool(t)
	tenantID, deviceID, ruleID := remediationSeedTenantDeviceRule(t, pool)
	oldID := remediationInsertArtefact(t, pool, tenantID, deviceID, ruleID, "issued", nil)
	newID := remediationInsertArtefact(t, pool, tenantID, deviceID, ruleID, "issued", &oldID)

	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n, err := markArtefactsApplied(ctx, tx, deviceID, []eval{{ruleID: ruleID, status: "pass"}}, time.Now())
	if err != nil {
		t.Fatalf("markArtefactsApplied: %v", err)
	}
	if n != 1 {
		t.Fatalf("marked %d artefacts, want exactly 1 (the current tip only)", n)
	}
	_ = tx.Commit(ctx)

	oldStatus, _ := remediationArtefactStatus(t, pool, oldID)
	if oldStatus != "issued" {
		t.Errorf("superseded artefact status = %q, want unchanged 'issued' (never touched)", oldStatus)
	}
	newStatus, _ := remediationArtefactStatus(t, pool, newID)
	if newStatus != "applied" {
		t.Errorf("current artefact status = %q, want applied", newStatus)
	}
}

func TestMarkArtefactsApplied_NoMatchingArtefact_NoOp(t *testing.T) {
	pool := remediationAppliedPool(t)
	_, deviceID, ruleID := remediationSeedTenantDeviceRule(t, pool)
	// No remediation_artefacts row inserted at all.

	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n, err := markArtefactsApplied(ctx, tx, deviceID, []eval{{ruleID: ruleID, status: "pass"}}, time.Now())
	if err != nil {
		t.Fatalf("markArtefactsApplied: %v", err)
	}
	if n != 0 {
		t.Fatalf("marked %d artefacts, want 0 when none exist", n)
	}
}

func TestMarkArtefactsApplied_NoPassingEvaluations_SkipsQueryEntirely(t *testing.T) {
	pool := remediationAppliedPool(t)
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	n, err := markArtefactsApplied(ctx, tx, "00000000-0000-0000-0000-000000000000", nil, time.Now())
	if err != nil {
		t.Fatalf("markArtefactsApplied: %v", err)
	}
	if n != 0 {
		t.Fatalf("marked %d artefacts, want 0 for an empty eval list", n)
	}
}
