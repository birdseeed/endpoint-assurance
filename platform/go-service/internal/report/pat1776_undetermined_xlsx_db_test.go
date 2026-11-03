package report

// PAT-1776 regression, extending PAT-1758/PAT-1762's undetermined-evidence
// rule to the XLSX export (xlsx.go): a 'fail' row with observed_value IS
// NULL is unreadable evidence (an absent signal, or the collector's literal
// "Unknown" sentinel), not a real observation of non-compliance. The "CIS
// Controls" sheet lists one row per (rule, device) with a literal Status
// string — the sheet has no aggregate fail count, so the fix here is to
// report such a row as "undetermined" rather than "fail": an auditor
// filtering the exported spreadsheet for "fail" rows must not see a row
// whose true claim is "the collector could not read this device's state". A
// "NotConfigured" fail (PAT-1767: the read succeeded, the setting is
// genuinely absent) has a non-NULL observed_value and must still read
// "fail".
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as pat1758Pool (pat1758_unknown_evidence_db_test.go) and
// pat1762Pool (pat1762_undetermined_portal_admin_db_test.go). The pool's
// search_path is pinned to an isolated schema so no real data is touched.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1776XLSXSchema = "pat1776_xlsx_test"

func pat1776XLSXPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed XLSX test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1776XLSXSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1776XLSXSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1776XLSXSchema,
		`CREATE TABLE ` + pat1776XLSXSchema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1776XLSXSchema + `.devices (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id       UUID NOT NULL REFERENCES ` + pat1776XLSXSchema + `.tenants(id),
			hostname        TEXT,
			os              TEXT,
			os_version      TEXT,
			agent_version   TEXT,
			last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
			first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
			pending_updates JSONB,
			device_class    TEXT NOT NULL DEFAULT 'unknown'
			                CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat1776XLSXSchema + `.compliance_rules (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key     TEXT NOT NULL,
			title        TEXT NOT NULL,
			severity     TEXT NOT NULL DEFAULT 'low',
			platform     TEXT NOT NULL DEFAULT 'macos',
			enabled      BOOLEAN NOT NULL DEFAULT true,
			device_class TEXT[]
		)`,
		`CREATE TABLE ` + pat1776XLSXSchema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1776XLSXSchema + `.device_cve_findings (
			id              BIGSERIAL PRIMARY KEY,
			device_id       UUID NOT NULL,
			cve_id          TEXT NOT NULL,
			app_name        TEXT NOT NULL,
			app_version     TEXT,
			first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			match_confidence TEXT NOT NULL DEFAULT 'version_confirmed'
		)`,
		`CREATE TABLE ` + pat1776XLSXSchema + `.cve_feed_entries (
			cve_id        TEXT PRIMARY KEY,
			description   TEXT NOT NULL DEFAULT '',
			description_source TEXT NOT NULL DEFAULT '',
			severity      TEXT,
			cvss_v3_score NUMERIC
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1776XLSXSchema+` CASCADE`)
	})
	return pool
}

// TestFetchXLSXData_UndeterminedFailReportedSeparatelyInCISControls is the
// PAT-1776 regression: a device whose latest evaluation of a rule is a 'fail'
// with no observed value must appear on the "CIS Controls" sheet as
// Status="undetermined", never "fail" — a real fail ('Off') must still read
// "fail", a pass must still read "pass", and a 'NotConfigured' fail (a real,
// evidenced result) must still read "fail".
func TestFetchXLSXData_UndeterminedFailReportedSeparatelyInCISControls(t *testing.T) {
	pool := pat1776XLSXPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1776 XLSX Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var ruleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat1776_xlsx_rule', 'PAT-1776 XLSX Rule', 'high')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	insertDevice := func(hostname string) string {
		t.Helper()
		var deviceID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version)
			VALUES ($1::uuid, $2, 'macOS', '15.0')
			RETURNING id::text
		`, tenantID, hostname).Scan(&deviceID); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
		return deviceID
	}
	insertEval := func(deviceID, status string, observedValue *string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value)
			VALUES ($1::uuid, $2::uuid, $3, $4)
		`, deviceID, ruleID, status, observedValue); err != nil {
			t.Fatalf("insert evaluation (device %s, status %s): %v", deviceID, status, err)
		}
	}

	passDevice := insertDevice("a-pass")
	insertEval(passDevice, "pass", strPtr("On"))

	realFailDevice := insertDevice("b-real-fail")
	insertEval(realFailDevice, "fail", strPtr("Off"))

	undeterminedDevice := insertDevice("c-undetermined")
	insertEval(undeterminedDevice, "fail", nil)

	notConfiguredDevice := insertDevice("d-not-configured")
	insertEval(notConfiguredDevice, "fail", strPtr("NotConfigured"))

	data, err := FetchXLSXData(ctx, pool, tenantID, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("FetchXLSXData: %v", err)
	}

	byDevice := map[string]string{}
	for _, c := range data.CISControls {
		byDevice[c.Device] = c.Status
	}

	if got, want := byDevice["a-pass"], "pass"; got != want {
		t.Errorf("a-pass status = %q, want %q", got, want)
	}
	if got, want := byDevice["b-real-fail"], "fail"; got != want {
		t.Errorf("b-real-fail status = %q, want %q", got, want)
	}
	if got, want := byDevice["c-undetermined"], "undetermined"; got != want {
		t.Errorf("c-undetermined status = %q, want %q (unreadable evidence must not read as a real fail)", got, want)
	}
	if got, want := byDevice["d-not-configured"], "fail"; got != want {
		t.Errorf("d-not-configured status = %q, want %q (a real, evidenced result, not undetermined)", got, want)
	}
}
