//go:build integration

// Customer-scheduled reports integration tests (PAT-703).
//
// DB-backed proof of the three load-bearing behaviours:
//  1. GET/PUT /v1/portal/reports/schedule is tenant-scoped — tenant B never
//     sees or affects tenant A's schedule (cross-tenant isolation).
//  2. A due schedule swept by reportsched produces a source='portal'
//     report_records row via the SAME path as POST /v1/portal/reports, and
//     advances next_run_at / sets last_run_at.
//  3. Skip-if-already-ran-this-period: a slot whose last_run_at already
//     covers it advances without generating a duplicate report.
package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/reportsched"
)

type scheduleResp struct {
	Configured bool       `json:"configured"`
	Cadence    string     `json:"cadence"`
	Weekday    *int       `json:"weekday"`
	MonthDay   *int       `json:"month_day"`
	HourUTC    *int       `json:"hour_utc"`
	Enabled    bool       `json:"enabled"`
	LastRunAt  *time.Time `json:"last_run_at"`
	NextRunAt  *time.Time `json:"next_run_at"`
	UpdatedAt  *time.Time `json:"updated_at"`
}

func countPortalReports(t *testing.T, tenantID string) int {
	t.Helper()
	var n int
	err := env.pool.QueryRow(t.Context(), `
		SELECT COUNT(*) FROM report_records
		WHERE tenant_id = $1::uuid AND source = 'portal'
	`, tenantID).Scan(&n)
	if err != nil {
		t.Fatalf("count portal reports: %v", err)
	}
	return n
}

func TestPortalScheduleLifecycleAndIsolation(t *testing.T) {
	a := seedPortalTenant(t, "sched-iso-a", "alice@sched-a.example", "CVE-2099-2001")
	b := seedPortalTenant(t, "sched-iso-b", "bob@sched-b.example", "CVE-2099-2002")
	// PAT-2408: only an admin changes a schedule. seedPortalTenant maps a
	// viewer, so both callers are promoted; what a viewer may and may not do
	// is pinned in portal_report_roles_pat2406_test.go.
	mapPortalUserWithRole(t, a.email, a.tenantID, "admin")
	mapPortalUserWithRole(t, b.email, b.tenantID, "admin")

	// Unauthenticated requests are rejected outright.
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		resp := portalDo(t, method, "/v1/portal/reports/schedule", "", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s schedule without JWT = %d, want 401", method, resp.StatusCode)
		}
	}

	// Before configuration, GET reports an unconfigured singleton.
	var got scheduleResp
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/schedule", a.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET schedule (unconfigured) = %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &got)
	if got.Configured || got.Enabled {
		t.Fatalf("unconfigured schedule = %+v, want configured=false enabled=false", got)
	}

	// Tenant A sets weekly Monday 07:00 UTC.
	resp = portalDo(t, http.MethodPut, "/v1/portal/reports/schedule", a.token,
		strings.NewReader(`{"cadence":"weekly","weekday":1,"hour_utc":7,"enabled":true}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT schedule = %d, want 200", resp.StatusCode)
	}
	decodeJSON(t, resp, &got)
	if !got.Configured || got.Cadence != "weekly" || got.Weekday == nil || *got.Weekday != 1 ||
		got.HourUTC == nil || *got.HourUTC != 7 || !got.Enabled {
		t.Fatalf("PUT schedule response = %+v", got)
	}
	if got.NextRunAt == nil || !got.NextRunAt.After(time.Now().UTC()) {
		t.Fatalf("next_run_at = %v, want a future time", got.NextRunAt)
	}
	if got.NextRunAt.UTC().Weekday() != time.Monday || got.NextRunAt.UTC().Hour() != 7 {
		t.Fatalf("next_run_at = %v, want a Monday at 07:00 UTC", got.NextRunAt.UTC())
	}

	// Validation failures leave the stored schedule untouched.
	resp = portalDo(t, http.MethodPut, "/v1/portal/reports/schedule", a.token,
		strings.NewReader(`{"cadence":"weekly","hour_utc":7,"enabled":true}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT invalid schedule = %d, want 400", resp.StatusCode)
	}

	// Cross-tenant isolation: B sees no schedule, and B configuring its own
	// (monthly 31st) must not disturb A's.
	resp = portalDo(t, http.MethodGet, "/v1/portal/reports/schedule", b.token, nil)
	decodeJSON(t, resp, &got)
	if got.Configured {
		t.Fatalf("tenant B sees a schedule it never set: %+v (cross-tenant leak)", got)
	}
	resp = portalDo(t, http.MethodPut, "/v1/portal/reports/schedule", b.token,
		strings.NewReader(`{"cadence":"monthly","month_day":31,"hour_utc":23,"enabled":false}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT schedule (B) = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = portalDo(t, http.MethodGet, "/v1/portal/reports/schedule", a.token, nil)
	decodeJSON(t, resp, &got)
	if got.Cadence != "weekly" || !got.Enabled {
		t.Fatalf("tenant A schedule changed by tenant B write: %+v", got)
	}
	resp = portalDo(t, http.MethodGet, "/v1/portal/reports/schedule", b.token, nil)
	decodeJSON(t, resp, &got)
	if got.Cadence != "monthly" || got.MonthDay == nil || *got.MonthDay != 31 || got.Enabled {
		t.Fatalf("tenant B schedule = %+v, want monthly/31/disabled", got)
	}
}

func TestPortalScheduleSweeperGeneratesReport(t *testing.T) {
	ctx := context.Background()
	a := seedPortalTenant(t, "sched-run-a", "alice@sched-run.example", "CVE-2099-2003")
	b := seedPortalTenant(t, "sched-run-b", "bob@sched-run.example", "CVE-2099-2004")

	// A due, enabled schedule for A; B's is due but DISABLED — it must not run.
	past := time.Now().UTC().Add(-time.Hour)
	for _, row := range []struct {
		tenantID string
		enabled  bool
	}{{a.tenantID, true}, {b.tenantID, false}} {
		_, err := env.pool.Exec(ctx, `
			INSERT INTO portal_report_schedules
				(tenant_id, cadence, weekday, hour_utc, enabled, next_run_at)
			VALUES ($1::uuid, 'weekly', 1, 7, $2, $3)
		`, row.tenantID, row.enabled, past)
		if err != nil {
			t.Fatalf("seed schedule: %v", err)
		}
	}

	before := countPortalReports(t, a.tenantID)

	sweeper := reportsched.New(env.pool, handlers.PortalReportGenerator(env.pool))
	sweeper.Sweep(ctx)

	// Report row landed for A via the same source='portal' history.
	if got := countPortalReports(t, a.tenantID); got != before+1 {
		t.Fatalf("portal reports for A = %d, want %d", got, before+1)
	}
	if got := countPortalReports(t, b.tenantID); got != 0 {
		t.Fatalf("portal reports for B (disabled schedule) = %d, want 0", got)
	}

	// The generated report is visible through the customer surface.
	var list struct {
		Total   int `json:"total"`
		Reports []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"reports"`
	}
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports", a.token, nil)
	decodeJSON(t, resp, &list)
	if list.Total != 1 || !strings.HasPrefix(list.Reports[0].Name, "Scheduled security report") {
		t.Fatalf("portal report list = %+v, want the scheduled report", list)
	}

	// Schedule bookkeeping: last_run_at set, next_run_at advanced into the future.
	var lastRun, nextRun *time.Time
	err := env.pool.QueryRow(ctx, `
		SELECT last_run_at, next_run_at FROM portal_report_schedules WHERE tenant_id = $1::uuid
	`, a.tenantID).Scan(&lastRun, &nextRun)
	if err != nil {
		t.Fatalf("read schedule after sweep: %v", err)
	}
	if lastRun == nil {
		t.Fatal("last_run_at not set after sweep")
	}
	if nextRun == nil || !nextRun.After(time.Now().UTC()) {
		t.Fatalf("next_run_at = %v, want future", nextRun)
	}
	if nextRun.UTC().Weekday() != time.Monday || nextRun.UTC().Hour() != 7 {
		t.Fatalf("next_run_at = %v, want Monday 07:00 UTC", nextRun.UTC())
	}

	// Skip-if-already-ran: force the slot due again with last_run_at covering
	// it — the sweeper must advance without generating a second report.
	_, err = env.pool.Exec(ctx, `
		UPDATE portal_report_schedules
		SET next_run_at = $2
		WHERE tenant_id = $1::uuid
	`, a.tenantID, lastRun.Add(-time.Minute))
	if err != nil {
		t.Fatalf("rewind next_run_at: %v", err)
	}
	sweeper.Sweep(ctx)
	if got := countPortalReports(t, a.tenantID); got != before+1 {
		t.Fatalf("portal reports for A after skip-sweep = %d, want %d (no duplicate)", got, before+1)
	}
	err = env.pool.QueryRow(ctx, `
		SELECT next_run_at FROM portal_report_schedules WHERE tenant_id = $1::uuid
	`, a.tenantID).Scan(&nextRun)
	if err != nil {
		t.Fatalf("read schedule after skip-sweep: %v", err)
	}
	if nextRun == nil || !nextRun.After(time.Now().UTC()) {
		t.Fatalf("next_run_at after skip = %v, want future (pointer must advance)", nextRun)
	}
}

// TestPortalScheduleSweeperCrashBetweenCommits proves PAT-874: if the process
// crashes after s.generate() durably commits a report but before processOne's
// own commit advances last_run_at/next_run_at, a subsequent sweep must NOT
// regenerate (and thus duplicate) the report for that same slot.
//
// s.generate() commits report_records on its own connection, independent of
// the sweeper's claim transaction (see sweeper.go's package doc comment), and
// that gap is exactly what a crash can land in. This test reproduces the
// state such a crash leaves behind directly: insert the report_records row
// that s.generate() would have committed, but deliberately leave
// last_run_at/next_run_at untouched (as a crash would), then sweep again and
// assert no second report_records row appears and the schedule bookkeeping
// still advances correctly.
func TestPortalScheduleSweeperCrashBetweenCommits(t *testing.T) {
	ctx := context.Background()
	a := seedPortalTenant(t, "sched-crash-a", "alice@sched-crash.example", "CVE-2099-2005")

	slot := time.Now().UTC().Add(-time.Hour)
	_, err := env.pool.Exec(ctx, `
		INSERT INTO portal_report_schedules
			(tenant_id, cadence, weekday, hour_utc, enabled, next_run_at)
		VALUES ($1::uuid, 'weekly', 1, 7, TRUE, $2)
	`, a.tenantID, slot)
	if err != nil {
		t.Fatalf("seed schedule: %v", err)
	}

	// Simulate the crash: a report was durably generated for this slot
	// (s.generate()'s commit succeeded), carrying schedule_slot = slot exactly
	// as the real GenerateFunc call would have set it...
	_, err = env.pool.Exec(ctx, `
		INSERT INTO report_records (tenant_id, name, source, generated_at, created_at, schedule_slot)
		VALUES ($1::uuid, 'Scheduled security report (crash-sim)', 'portal', $2, $2, $3)
	`, a.tenantID, slot.Add(time.Second), slot)
	if err != nil {
		t.Fatalf("seed crash-simulated report record: %v", err)
	}
	// ...but the schedule row's last_run_at/next_run_at update never
	// committed. next_run_at is still the same due slot, last_run_at is
	// still nil (this schedule never ran before). This is precisely the
	// state a crash between the two commits leaves on disk.

	before := countPortalReports(t, a.tenantID)
	if before != 1 {
		t.Fatalf("portal reports for A before recovery sweep = %d, want 1 (the crash-simulated row)", before)
	}

	// generateCalls counts how many times the sweeper actually invokes
	// GenerateFunc. A stub (not the real handlers.PortalReportGenerator) is
	// used here so a regression is caught even if it produces a report
	// through some path other than a second report_records INSERT.
	var generateCalls int
	stubGenerate := func(ctx context.Context, tenantID, reportType, name string, slot time.Time) (string, error) {
		generateCalls++
		var id string
		err := env.pool.QueryRow(ctx, `
			INSERT INTO report_records (tenant_id, report_type, name, source, schedule_slot)
			VALUES ($1::uuid, $2, $3, 'portal', $4)
			RETURNING id::text
		`, tenantID, reportType, name, slot).Scan(&id)
		return id, err
	}

	sweeper := reportsched.New(env.pool, stubGenerate)
	sweeper.Sweep(ctx)

	if generateCalls != 0 {
		t.Fatalf("generate() called %d times on crash-recovery sweep, want 0 (must not regenerate)", generateCalls)
	}
	if got := countPortalReports(t, a.tenantID); got != before {
		t.Fatalf("portal reports for A after crash-recovery sweep = %d, want %d (no duplicate)", got, before)
	}

	// The schedule bookkeeping must still advance, exactly as the normal
	// success path would, so future ticks don't keep re-claiming this row.
	var lastRun, nextRun *time.Time
	err = env.pool.QueryRow(ctx, `
		SELECT last_run_at, next_run_at FROM portal_report_schedules WHERE tenant_id = $1::uuid
	`, a.tenantID).Scan(&lastRun, &nextRun)
	if err != nil {
		t.Fatalf("read schedule after crash-recovery sweep: %v", err)
	}
	if lastRun == nil {
		t.Fatal("last_run_at not set after crash-recovery sweep")
	}
	if nextRun == nil || !nextRun.After(time.Now().UTC()) {
		t.Fatalf("next_run_at after crash-recovery sweep = %v, want future", nextRun)
	}
}

// TestPortalScheduleSweeperIgnoresManualReportNearSlot proves the PAT-874
// guard's idempotency key (report_records.schedule_slot) is not fooled by a
// customer's own manual report landing in the same window as a due slot.
// Both POST /v1/portal/reports (manual) and the sweeper write source='portal'
// rows through the exact same generatePortalReport path, so a guard keyed on
// timing alone (e.g. "a portal report exists with created_at >= slot") would
// wrongly treat a coincidental manual report as proof the scheduled slot
// already ran, permanently skipping that cycle's generation. schedule_slot is
// set ONLY by the sweeper's GenerateFunc call, so a manual report (always
// schedule_slot IS NULL) can never satisfy the guard's equality check.
func TestPortalScheduleSweeperIgnoresManualReportNearSlot(t *testing.T) {
	ctx := context.Background()
	a := seedPortalTenant(t, "sched-manual-a", "alice@sched-manual.example", "CVE-2099-2006")

	slot := time.Now().UTC().Add(-time.Minute)
	_, err := env.pool.Exec(ctx, `
		INSERT INTO portal_report_schedules
			(tenant_id, cadence, weekday, hour_utc, enabled, next_run_at)
		VALUES ($1::uuid, 'weekly', 1, 7, TRUE, $2)
	`, a.tenantID, slot)
	if err != nil {
		t.Fatalf("seed schedule: %v", err)
	}

	// The customer generated their own report moments after the slot became
	// due, through the manual path (POST /v1/portal/reports), same
	// source='portal', but schedule_slot is NULL because it was never set by
	// the sweeper.
	resp := portalDo(t, http.MethodPost, "/v1/portal/reports", a.token, strings.NewReader(`{}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("manual report generate = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	before := countPortalReports(t, a.tenantID)
	if before != 1 {
		t.Fatalf("portal reports for A before sweep = %d, want 1 (the manual report)", before)
	}

	var generateCalls int
	stubGenerate := func(ctx context.Context, tenantID, reportType, name string, slot time.Time) (string, error) {
		generateCalls++
		var id string
		err := env.pool.QueryRow(ctx, `
			INSERT INTO report_records (tenant_id, report_type, name, source, schedule_slot)
			VALUES ($1::uuid, $2, $3, 'portal', $4)
			RETURNING id::text
		`, tenantID, reportType, name, slot).Scan(&id)
		return id, err
	}

	sweeper := reportsched.New(env.pool, stubGenerate)
	sweeper.Sweep(ctx)

	// The scheduled generation must still happen; the manual report must
	// not be mistaken for it.
	if generateCalls != 1 {
		t.Fatalf("generate() called %d times, want 1 (manual report must not suppress the scheduled run)", generateCalls)
	}
	if got := countPortalReports(t, a.tenantID); got != before+1 {
		t.Fatalf("portal reports for A after sweep = %d, want %d (scheduled report must still be produced)", got, before+1)
	}
}

// PAT-1847: two report types may intentionally share the same due slot. The
// composite schedule key and report idempotency key must let both run once.
func TestPortalScheduleSweeperSameSlotPerTypeIsolation(t *testing.T) {
	ctx := context.Background()
	a := seedPortalTenant(t, "sched-types-a", "alice@sched-types.example", "CVE-2099-2010")
	slot := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	for _, reportType := range []string{"executive-summary", "patch-status"} {
		_, err := env.pool.Exec(ctx, `
			INSERT INTO portal_report_schedules
				(tenant_id, report_type, cadence, weekday, hour_utc, enabled, next_run_at)
			VALUES ($1::uuid, $2, 'weekly', 1, 7, TRUE, $3)
		`, a.tenantID, reportType, slot)
		if err != nil {
			t.Fatalf("seed %s schedule: %v", reportType, err)
		}
	}

	calls := map[string]int{}
	stubGenerate := func(ctx context.Context, tenantID, reportType, name string, gotSlot time.Time) (string, error) {
		calls[reportType]++
		var id string
		err := env.pool.QueryRow(ctx, `
			INSERT INTO report_records (tenant_id, report_type, name, source, schedule_slot)
			VALUES ($1::uuid, $2, $3, 'portal', $4)
			RETURNING id::text
		`, tenantID, reportType, name, gotSlot).Scan(&id)
		return id, err
	}

	sweeper := reportsched.New(env.pool, stubGenerate)
	sweeper.Sweep(ctx)
	if calls["executive-summary"] != 1 || calls["patch-status"] != 1 {
		t.Fatalf("generation calls = %#v, want one per report type", calls)
	}
	var rows int
	if err := env.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM report_records
		WHERE tenant_id = $1::uuid AND schedule_slot = $2
	`, a.tenantID, slot).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("same-slot report rows = %d, want 2", rows)
	}

	// Rewinding both schedules to the already-generated slot exercises crash
	// recovery. Each type finds only its own row and neither regenerates.
	if _, err := env.pool.Exec(ctx, `
		UPDATE portal_report_schedules
		SET last_run_at = NULL, next_run_at = $2
		WHERE tenant_id = $1::uuid
	`, a.tenantID, slot); err != nil {
		t.Fatal(err)
	}
	sweeper.Sweep(ctx)
	if calls["executive-summary"] != 1 || calls["patch-status"] != 1 {
		t.Fatalf("recovery regenerated a report: calls = %#v", calls)
	}
}

// PAT-1847: an existing report for one type at a shared slot must not suppress
// a different type whose schedule has not generated yet.
func TestPortalScheduleSweeperRecoveryIsTypeScoped(t *testing.T) {
	ctx := context.Background()
	a := seedPortalTenant(t, "sched-recovery-type", "alice@sched-recovery-type.example", "CVE-2099-2011")
	slot := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for _, reportType := range []string{"executive-summary", "patch-status"} {
		_, err := env.pool.Exec(ctx, `
			INSERT INTO portal_report_schedules
				(tenant_id, report_type, cadence, weekday, hour_utc, enabled, next_run_at)
			VALUES ($1::uuid, $2, 'weekly', 1, 7, TRUE, $3)
		`, a.tenantID, reportType, slot)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO report_records (tenant_id, report_type, name, source, schedule_slot)
		VALUES ($1::uuid, 'executive-summary', 'crash evidence', 'portal', $2)
	`, a.tenantID, slot); err != nil {
		t.Fatal(err)
	}

	calls := map[string]int{}
	stubGenerate := func(ctx context.Context, tenantID, reportType, name string, gotSlot time.Time) (string, error) {
		calls[reportType]++
		var id string
		err := env.pool.QueryRow(ctx, `
			INSERT INTO report_records (tenant_id, report_type, name, source, schedule_slot)
			VALUES ($1::uuid, $2, $3, 'portal', $4)
			RETURNING id::text
		`, tenantID, reportType, name, gotSlot).Scan(&id)
		return id, err
	}
	reportsched.New(env.pool, stubGenerate).Sweep(ctx)
	if calls["executive-summary"] != 0 || calls["patch-status"] != 1 {
		t.Fatalf("type-scoped recovery calls = %#v, want only patch-status", calls)
	}
}
