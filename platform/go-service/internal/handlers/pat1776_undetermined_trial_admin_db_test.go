package handlers

// PAT-1776 regression, extending PAT-1758/PAT-1762's undetermined-evidence
// rule to TrialTenantsListHandler (trial_admin.go, GET /admin/tenants/trials'
// failing_eval_count): a 'fail' row with observed_value IS NULL is
// unreadable evidence (an absent signal, or the collector's literal
// "Unknown" sentinel), not a real observation of non-compliance. It must not
// count toward FailingEvalCount, and must be surfaced separately
// (UndeterminedEvalCount) rather than silently dropped. An 'error' row and a
// "NotConfigured" fail (PAT-1767: the read succeeded, the setting is
// genuinely absent, non-NULL observed_value) must still count as real fails.
//
// Skipped unless TEST_DATABASE_URL points at a reachable Postgres, same
// convention as pat1758Pool (internal/report/pat1758_unknown_evidence_db_test.go)
// and pat1762Pool (internal/report/pat1762_undetermined_portal_admin_db_test.go).
// The pool's search_path is pinned to an isolated schema so no real data is
// touched and no full migration run is required — this schema only mirrors
// the columns TrialTenantsListHandler's query path actually reads.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1776TrialSchema = "pat1776_trial_test"

func pat1776TrialPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed trial admin test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1776TrialSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1776TrialSchema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1776TrialSchema,
		`CREATE TABLE ` + pat1776TrialSchema + `.tenants (
			id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name                  TEXT NOT NULL,
			is_trial              boolean NOT NULL DEFAULT false,
			revoked_at            TIMESTAMPTZ,
			trial_email           TEXT,
			trial_expires_at      TIMESTAMPTZ,
			upgrade_email_sent_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1776TrialSchema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1776TrialSchema + `.tenants(id)
		)`,
		`CREATE TABLE ` + pat1776TrialSchema + `.compliance_evaluations (
			id             BIGSERIAL PRIMARY KEY,
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1776TrialSchema+` CASCADE`)
	})
	return pool
}

// TestTrialTenantsListHandler_UndeterminedFailExcludedButCounted is the
// PAT-1776 regression: FailingEvalCount must count only real, evidenced
// fails (an 'error' row and a NotConfigured fail included) and exclude the
// undetermined fail; UndeterminedEvalCount must carry the excluded row
// separately instead of dropping it.
func TestTrialTenantsListHandler_UndeterminedFailExcludedButCounted(t *testing.T) {
	pool := pat1776TrialPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, is_trial, trial_email)
		VALUES ('PAT-1776 Trial Test Tenant', true, 'trial@example.com')
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
	insertEval := func(deviceID, ruleID, status string, observedValue *string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value)
			VALUES ($1::uuid, $2::uuid, $3, $4)
		`, deviceID, ruleID, status, observedValue); err != nil {
			t.Fatalf("insert evaluation (device %s, status %s): %v", deviceID, status, err)
		}
	}

	realFailDevice := insertDevice()
	insertEval(realFailDevice, "11111111-1111-1111-1111-111111111111", "fail", strPtr("Off"))

	errorDevice := insertDevice()
	insertEval(errorDevice, "22222222-2222-2222-2222-222222222222", "error", nil)

	notConfiguredDevice := insertDevice()
	insertEval(notConfiguredDevice, "33333333-3333-3333-3333-333333333333", "fail", strPtr("NotConfigured"))

	undeterminedDevice := insertDevice()
	insertEval(undeterminedDevice, "44444444-4444-4444-4444-444444444444", "fail", nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/trials", nil)
	rr := httptest.NewRecorder()
	TrialTenantsListHandler(pool).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp trialsListResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}

	var row *trialEntry
	for i := range resp.Trials {
		if resp.Trials[i].TenantID == tenantID {
			row = &resp.Trials[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("tenant %s missing from trials response: %+v", tenantID, resp.Trials)
	}

	if row.FailingEvalCount != 3 {
		t.Errorf("FailingEvalCount = %d, want 3 (the real fail, the error, and the NotConfigured fail; the undetermined fail must be excluded)", row.FailingEvalCount)
	}
	if row.UndeterminedEvalCount != 1 {
		t.Errorf("UndeterminedEvalCount = %d, want 1 (surfaced separately, not dropped)", row.UndeterminedEvalCount)
	}
	if row.DeviceCount != 4 {
		t.Errorf("DeviceCount = %d, want 4", row.DeviceCount)
	}
}
