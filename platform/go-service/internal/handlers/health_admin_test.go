package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/notify"
)

func TestHomeMetricsExcludeRevokedTenantsDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping revoked-tenant exclusion DB tests")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	ctx := context.Background()
	logger := slog.Default()
	h := &AdminHealthHandler{pool: pool}

	// Insert a test compliance rule; cleaned up after tenants so no FK violation.
	// platform is explicit (not defaulted) since migration 0019 dropped
	// compliance_rules.platform's DEFAULT — this rule is exercised against
	// both macOS and Windows devices below via directly-inserted evaluations
	// (not the evaluator's platform-filtered load query), so 'cross-platform'
	// is the accurate value, not a stand-in for either OS.
	var ruleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, benchmark, benchmark_version, title, severity, signal_key, comparator, expected_values, platform)
		VALUES (gen_random_uuid()::text, 'pat451-test', '0.0', 'PAT-451 test rule', 'critical', 'test', 'eq', ARRAY['true'], 'cross-platform')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert compliance rule: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM compliance_rules WHERE id = $1::uuid`, ruleID) })

	insertTenant := func(name string, revoke bool) string {
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
			VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
			             '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
			RETURNING id::text
		`, name).Scan(&id); err != nil {
			t.Fatalf("insertTenant %s: %v", name, err)
		}
		if revoke {
			if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
				t.Fatalf("revoke tenant: %v", err)
			}
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, id) })
		return id
	}

	insertDevice := func(tenantID, osName string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (tenant_id, os, hw_uuid) VALUES ($1::uuid, $2, gen_random_uuid()) RETURNING id::text`,
			tenantID, osName,
		).Scan(&id); err != nil {
			t.Fatalf("insertDevice: %v", err)
		}
		return id
	}

	// observed_value is set for every "fail" row here (PAT-1776): this test
	// exercises real, evidenced fails, never the undetermined case (a fail
	// with observed_value NULL, meaning unreadable evidence — see
	// pat1758_unknown_evidence_db_test.go for that distinction). Without a
	// real observed_value, queryOpenFindingsBySeverity's PAT-1776 fix would
	// misclassify these intentional fails as undetermined and exclude them,
	// exactly the regression this comment prevents.
	insertEval := func(deviceID, status, severity string) {
		var observedValue any
		if status == "fail" {
			observedValue = "false"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, '0.0')
		`, deviceID, ruleID, status, observedValue, severity); err != nil {
			t.Fatalf("insertEval: %v", err)
		}
	}

	// Revoked tenant: 1 macOS device, 1 fail/critical eval — must not affect metrics.
	//
	// Assertions below call the real h.queryTotalEndpoints / h.queryPlatformSplit /
	// h.queryOpenFindingsBySeverity handler methods (health_admin.go) — the
	// same code path GET /admin/health uses — but pass this test's own
	// tenant IDs to scope the count, instead of the previous pattern of
	// snapshotting an unfiltered global count before inserting fixtures and
	// diffing against it afterward. go test ./... runs packages
	// concurrently by default, and other packages' DB-gated tests
	// (discovery-job, trial, etc.) insert/delete their own tenants against
	// the same TEST_DATABASE_URL while this test runs; a global baseline
	// snapshotted at the top of the test could go stale between that
	// snapshot and the later assertions purely from that unrelated
	// concurrent traffic, which is what made the test flaky under the full
	// suite despite passing reliably in isolation. Scoping removes the
	// dependency on global table state entirely while still exercising the
	// same queries and the same revoked_at-exclusion logic this test exists
	// to guard: if that logic regresses, these calls see it directly.
	revokedID := insertTenant("pat451-revoked", true)
	revokedDevID := insertDevice(revokedID, "macOS")
	insertEval(revokedDevID, "fail", "critical")

	if got := h.queryTotalEndpoints(ctx, logger, revokedID); got != 0 {
		t.Errorf("endpoints: revoked device leaked: want 0, got %d", got)
	}
	if got := h.queryPlatformSplit(ctx, logger, revokedID); got.MacOS != 0 {
		t.Errorf("platform_split.macos: revoked device leaked: want 0, got %d", got.MacOS)
	}
	if got := h.queryOpenFindingsBySeverity(ctx, logger, revokedID); got.Critical != 0 {
		t.Errorf("findings.critical: revoked eval leaked: want 0, got %d", got.Critical)
	}

	// Active tenant: 1 macOS + 1 Windows device, 1 pass + 1 fail/critical eval.
	activeID := insertTenant("pat451-active", false)
	activeMacID := insertDevice(activeID, "macOS")
	activeWinID := insertDevice(activeID, "Windows")
	insertEval(activeMacID, "pass", "critical")
	insertEval(activeWinID, "fail", "critical")

	if got := h.queryTotalEndpoints(ctx, logger, revokedID, activeID); got != 2 {
		t.Errorf("endpoints: want 2 (revoked tenant's device excluded), got %d", got)
	}
	split := h.queryPlatformSplit(ctx, logger, revokedID, activeID)
	if split.MacOS != 1 {
		t.Errorf("platform_split.macos: want 1, got %d", split.MacOS)
	}
	if split.Windows != 1 {
		t.Errorf("platform_split.windows: want 1, got %d", split.Windows)
	}
	findings := h.queryOpenFindingsBySeverity(ctx, logger, revokedID, activeID)
	if findings.Critical != 1 {
		t.Errorf("findings.critical: want 1 (only active tenant's fail), got %d", findings.Critical)
	}
}

func TestReadBackupJobs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("db-r2.json", `{"job":"db-r2","label":"DB Backup (R2)","status":"ok","last_success_at":"2026-12-14T03:00:12Z","detail":"snapshot e8b2"}`)
	write("git-mirrors.json", `{"status":"ok","last_success_at":"2026-12-14T02:00:00Z"}`) // no job/label -> filename fallback
	write("broken.json", `{not valid json`)                                               // skipped
	write("notes.txt", `ignore me`)                                                       // non-json, ignored

	h := &AdminHealthHandler{backupHealthDir: dir}
	jobs := h.readBackupJobs(slog.Default())

	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs (malformed + non-json skipped), got %d: %+v", len(jobs), jobs)
	}
	// Sorted by job id: "db-r2" < "git-mirrors".
	if jobs[0].Job != "db-r2" || jobs[1].Job != "git-mirrors" {
		t.Fatalf("unexpected order/ids: %+v", jobs)
	}
	if jobs[0].Label != "DB Backup (R2)" {
		t.Fatalf("want explicit label, got %q", jobs[0].Label)
	}
	if jobs[1].Job != "git-mirrors" || jobs[1].Label != "git-mirrors" {
		t.Fatalf("want job/label to fall back to filename, got job=%q label=%q", jobs[1].Job, jobs[1].Label)
	}
	if jobs[0].LastSuccessAt == nil {
		t.Fatalf("want parsed last_success_at, got nil")
	}
}

func TestReadBackupJobsMissingDir(t *testing.T) {
	h := &AdminHealthHandler{backupHealthDir: filepath.Join(t.TempDir(), "does-not-exist")}
	jobs := h.readBackupJobs(slog.Default())
	if jobs == nil {
		t.Fatal("want non-nil empty slice for JSON safety, got nil")
	}
	if len(jobs) != 0 {
		t.Fatalf("want 0 jobs for missing dir, got %+v", jobs)
	}
}

// TestAdminHealthHandler_NotifyChannelsConfigured (PAT-1215) exercises the
// full ServeHTTP path — not just notify.Notifier.ConfiguredChannelCount in
// isolation (see notify_test.go's TestConfiguredChannelCount for that) — to
// confirm GET /admin/health actually surfaces the count for zero, one, and
// several configured channels. Points the pool at a closed local port
// (nothing listens on 127.0.0.1:1) rather than a live database: every other
// sub-query already degrades to zero/null on failure by design (see the
// package doc comment), so the handler runs its normal degrade-gracefully
// path without needing TEST_DATABASE_URL, and this test only cares about the one
// field notify.New() controls via env vars.
func TestAdminHealthHandler_NotifyChannelsConfigured(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://patched:wrongpass@127.0.0.1:1/nonexistent?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New (lazy, should not itself connect): %v", err)
	}
	defer pool.Close()

	tests := []struct {
		name  string
		setup func(t *testing.T)
		want  int
	}{
		{"zero configured", func(t *testing.T) {}, 0},
		{"one configured (slack)", func(t *testing.T) {
			t.Setenv("NOTIFY_SLACK_WEBHOOK_URL", "https://hooks.slack.example/abc")
		}, 1},
		{"one configured (email)", func(t *testing.T) {
			t.Setenv("NOTIFY_SMTP_HOST", "smtp.example.com")
			t.Setenv("NOTIFY_SMTP_TO", "ops@patched.im")
		}, 1},
		{"both configured", func(t *testing.T) {
			t.Setenv("NOTIFY_SLACK_WEBHOOK_URL", "https://hooks.slack.example/abc")
			t.Setenv("NOTIFY_SMTP_HOST", "smtp.example.com")
			t.Setenv("NOTIFY_SMTP_TO", "ops@patched.im")
		}, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			h := NewHealthHandler(pool, "", notify.New())
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/health", nil))

			var resp adminHealthResp
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v (%s)", err, rr.Body.String())
			}
			if resp.ServiceHealth.NotifyChannelsConfigured != tc.want {
				t.Errorf("notify_channels_configured: got %d, want %d", resp.ServiceHealth.NotifyChannelsConfigured, tc.want)
			}
		})
	}
}

func TestReadBackupJobsDisabled(t *testing.T) {
	h := &AdminHealthHandler{backupHealthDir: ""}
	jobs := h.readBackupJobs(slog.Default())
	if jobs == nil || len(jobs) != 0 {
		t.Fatalf("want non-nil empty slice when disabled, got %+v", jobs)
	}
}

// TestQueryIngestionFreshnessExcludesInternalTenantsDB verifies PAT-1562's
// fix to PAT-1541: an internal/test tenant must never win "stalest tenant"
// on the Service Health rail, even when its own ingest is genuinely far
// staler than every real customer's. Skipped when TEST_DATABASE_URL is not set.
func TestQueryIngestionFreshnessExcludesInternalTenantsDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping tenant_kind ingestion-freshness DB test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	insertTenant := func(name, kind string) string {
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO tenants (name, bearer_token_hash, hmac_secret, tenant_kind)
			VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
			             '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea, $2)
			RETURNING id::text
		`, name, kind).Scan(&id); err != nil {
			t.Fatalf("insertTenant %s: %v", name, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, id) })
		return id
	}

	insertPayload := func(tenantID string, receivedAt time.Time) {
		if _, err := pool.Exec(ctx, `
			INSERT INTO raw_payloads (tenant_id, received_at, body)
			VALUES ($1::uuid, $2, '{}'::jsonb)
		`, tenantID, receivedAt); err != nil {
			t.Fatalf("insertPayload: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM raw_payloads WHERE tenant_id = $1::uuid`, tenantID) })
	}

	now := time.Now().UTC()

	// Internal tenant: ingest genuinely much staler (would win "stalest" on
	// name/timestamp alone) — must be excluded regardless.
	internalID := insertTenant("PAT-1562 internal fixture", "internal")
	insertPayload(internalID, now.Add(-500*time.Hour))

	// Real customer: fresher ingest, but still the only eligible candidate.
	customerID := insertTenant("PAT-1562 real customer", "customer")
	insertPayload(customerID, now.Add(-2*time.Hour))

	h := &AdminHealthHandler{pool: pool}
	result := h.queryIngestionFreshness(ctx, slog.Default())

	// This query ranks the SINGLE stalest tenant across the whole database,
	// not scoped to this test's own fixtures — go test ./... runs packages
	// concurrently and TEST_DATABASE_URL may be shared with other DB-gated tests'
	// leftover data (see TestHomeMetricsExcludeRevokedTenantsDB's comment on
	// the same risk). So the only assertion safe against that pollution is
	// the negative one this ticket actually cares about: the internal
	// tenant — despite being the single stalest row inserted by this test,
	// by a wide margin (500h vs 2h) — must never be selected. We do NOT
	// assert customerID specifically wins, since some other test's
	// leftover real-customer tenant could legitimately be staler still.
	if result.StalestTenant != nil && result.StalestTenant.TenantID == internalID {
		t.Errorf("StalestTenant = %s (%q) — internal tenant won the ranking despite tenant_kind='internal'",
			result.StalestTenant.TenantID, result.StalestTenant.TenantName)
	}
}
