package handlers

// PAT-1776 regression, extending PAT-1758/PAT-1762's undetermined-evidence
// rule to the Cyber Essentials scoring engine (ce.go): a 'fail' row with
// observed_value IS NULL is unreadable evidence (an absent signal, or the
// collector's literal "Unknown" sentinel), not a real observation of
// non-compliance, and must not:
//   - count toward a CE control's FailCount (ceAutoEvidenceJSON), or
//   - flip a control's status to "fail" (ceControlStatus).
//
// It must still be surfaced (ceAutoEvidenceJSON.UndeterminedCount) rather
// than silently dropped, and must still count in TotalCount so PassPct's
// denominator is unaffected. A "NotConfigured" fail (PAT-1767: the read
// succeeded, the setting is genuinely absent) has a non-NULL observed_value
// and must still be counted as a real fail throughout.
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as pat1758Pool (internal/report/pat1758_unknown_evidence_db_test.go)
// and pat1762Pool (internal/report/pat1762_undetermined_portal_admin_db_test.go).
// The pool's search_path is pinned to an isolated schema so no real data is
// touched and no full migration run is required — this schema only mirrors
// the columns TenantCEStatusHandler's query path actually reads.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1776CESchema = "pat1776_ce_test"

func pat1776CEPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed CE test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1776CESchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1776CESchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1776CESchema,
		`CREATE TABLE ` + pat1776CESchema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1776CESchema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1776CESchema + `.tenants(id),
			hostname  TEXT
		)`,
		`CREATE TABLE ` + pat1776CESchema + `.compliance_rules (
			id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key TEXT NOT NULL,
			title    TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'low'
		)`,
		`CREATE TABLE ` + pat1776CESchema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat1776CESchema + `.ce_attestations (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL REFERENCES ` + pat1776CESchema + `.tenants(id),
			control_id  TEXT NOT NULL,
			answer      TEXT NOT NULL,
			notes       TEXT NOT NULL DEFAULT '',
			attested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, control_id)
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1776CESchema+` CASCADE`)
	})
	return pool
}

// pat1776CEInsertTenant creates a tenant and returns its id.
func pat1776CEInsertTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name) VALUES ('PAT-1776 CE Test Tenant')
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return tenantID
}

// pat1776CEInsertDevice creates a device for tenantID.
func pat1776CEInsertDevice(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, hostname)
		VALUES ($1::uuid, 'dev-' || substr(gen_random_uuid()::text, 1, 8))
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return deviceID
}

// pat1776CEInsertEval inserts one latest evaluation. observedValue == nil
// stores SQL NULL (undetermined evidence when status="fail").
func pat1776CEInsertEval(t *testing.T, pool *pgxpool.Pool, deviceID, ruleID, status string, observedValue *string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, deviceID, ruleID, status, observedValue); err != nil {
		t.Fatalf("insert evaluation (device %s, status %s): %v", deviceID, status, err)
	}
}

// TestTenantCEStatusHandler_UndeterminedFailNotCountedAsRealFail is the
// PAT-1776 regression for the fully-mixed case: one device's evaluation is a
// genuine 'Off' fail, one is undetermined (observed_value NULL), and one is a
// 'NotConfigured' fail (non-NULL observed_value — a real, evidenced result).
// FailCount must count only the two real fails; UndeterminedCount must carry
// the one unreadable-evidence row separately; TotalCount must include all
// three so PassPct's denominator is unaffected; and the control's status
// must be "fail" (a real fail is present).
func TestTenantCEStatusHandler_UndeterminedFailNotCountedAsRealFail(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)

	var ruleID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('cis_macos_2_5_2_2_firewall', 'Host firewall', 'high')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	realFailDevice := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, realFailDevice, ruleID, "fail", strPtr("Off"))

	undeterminedDevice := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, undeterminedDevice, ruleID, "fail", nil)

	notConfiguredDevice := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, notConfiguredDevice, ruleID, "fail", strPtr("NotConfigured"))

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/ce-status", nil)
	req = catWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantCEStatusHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp ceStatusResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}

	ctrl := findCEControl(t, resp, "ce_fw_host")
	if ctrl.AutoEvidence == nil {
		t.Fatalf("ce_fw_host: AutoEvidence is nil")
	}
	ae := ctrl.AutoEvidence
	if ae.FailCount != 2 {
		t.Errorf("FailCount = %d, want 2 (the 'Off' fail and the 'NotConfigured' fail; the undetermined fail must be excluded)", ae.FailCount)
	}
	if ae.UndeterminedCount != 1 {
		t.Errorf("UndeterminedCount = %d, want 1", ae.UndeterminedCount)
	}
	if ae.TotalCount != 3 {
		t.Errorf("TotalCount = %d, want 3 (undetermined stays in the denominator)", ae.TotalCount)
	}
	if ctrl.Status != "fail" {
		t.Errorf("Status = %q, want \"fail\" (a real fail is present)", ctrl.Status)
	}
}

// TestTenantCEStatusHandler_AllUndeterminedControlIsUnknownNotPass is the
// PAT-1776 regression for a control whose ONLY evidence is undetermined: no
// real pass, no real fail. Before this fix's totalFail was computed from
// FailCount+ErrorCount where FailCount already excluded undetermined rows,
// so a control with zero real pass/fail signal would have fallen through to
// "pass" — a false compliance claim for a control the collector could not
// actually read. It must report "unknown" instead, and the undetermined
// evidence must still be visible in the response, not dropped.
func TestTenantCEStatusHandler_AllUndeterminedControlIsUnknownNotPass(t *testing.T) {
	pool := pat1776CEPool(t)
	tenantID := pat1776CEInsertTenant(t, pool)

	var ruleID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('cis_macos_5_1_auto_login_disabled', 'Auto-login disabled', 'high')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	d1 := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, d1, ruleID, "fail", nil)
	d2 := pat1776CEInsertDevice(t, pool, tenantID)
	pat1776CEInsertEval(t, pool, d2, ruleID, "fail", nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/ce-status", nil)
	req = catWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()
	TenantCEStatusHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp ceStatusResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}

	ctrl := findCEControl(t, resp, "ce_cfg_auto_login")
	if ctrl.Status != "unknown" {
		t.Errorf("Status = %q, want \"unknown\" (no real pass or fail signal; must not read as compliant)", ctrl.Status)
	}
	if ctrl.AutoEvidence == nil {
		t.Fatalf("ce_cfg_auto_login: AutoEvidence is nil")
	}
	if ctrl.AutoEvidence.FailCount != 0 {
		t.Errorf("FailCount = %d, want 0", ctrl.AutoEvidence.FailCount)
	}
	if ctrl.AutoEvidence.UndeterminedCount != 2 {
		t.Errorf("UndeterminedCount = %d, want 2 (surfaced, not dropped)", ctrl.AutoEvidence.UndeterminedCount)
	}
}

// findCEControl locates a control by ID across every area in resp, failing
// the test if it is not found.
func findCEControl(t *testing.T, resp ceStatusResp, controlID string) ceControlJSON {
	t.Helper()
	for _, area := range resp.Areas {
		for _, c := range area.Controls {
			if c.ID == controlID {
				return c
			}
		}
	}
	t.Fatalf("control %q not found in response: %+v", controlID, resp)
	return ceControlJSON{}
}
