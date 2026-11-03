package automations

import (
	"context"
	"os"
	"testing"
	"time"

	"patched.im/api/internal/db"
)

// TestKnownJobsRegistry_PAT993 pins the registry changes PAT-993 made to
// knownJobs. Pure/no-DB: IsKnownJob only ranges over the package-level slice.
func TestKnownJobsRegistry_PAT993(t *testing.T) {
	for _, want := range []string{
		"health_signals_recompute",
		"mirror_pipeline",
		"mirror_pipeline_windows",
		"installomator_sync",
		"api01_backup",
		"prod01_backup",
		"portal01_backup",
	} {
		if !IsKnownJob(want) {
			t.Errorf("IsKnownJob(%q) = false, want true", want)
		}
	}

	if IsKnownJob("not_a_real_job") {
		t.Error("IsKnownJob(\"not_a_real_job\") = true, want false")
	}
}

func TestAutomationLifecycleControlsRecording(t *testing.T) {
	if !IsKnownJob("installomator_sync") {
		t.Fatal("retired Installomator job is not readable")
	}
	if IsRecordableJob("installomator_sync") {
		t.Fatal("retired Installomator job is recordable")
	}
	for _, jobName := range []string{"mirror_pipeline", "mirror_pipeline_windows"} {
		if !IsRecordableJob(jobName) {
			t.Errorf("quarantined job %q rejected its still-present external reporter", jobName)
		}
	}
	if !IsRecordableJob("api01_backup") {
		t.Error("active backup job is not recordable")
	}
}

func TestSummariseJobSuppressesNonActiveOperationalState(t *testing.T) {
	started := time.Now().UTC().Add(-time.Minute)
	duration := 30.0
	runs := []RunEntry{{ID: 1, StartedAt: started, Status: "failed", DurationS: &duration}}

	for _, lifecycle := range []string{jobLifecycleQuarantined, jobLifecycleRetired} {
		got := summariseJob(JobSummary{JobName: "legacy", Lifecycle: lifecycle}, runs)
		if got.LastStatus != nil || got.LastRun != nil || got.LastDurationS != nil {
			t.Errorf("%s summary exposed operational last state: %#v", lifecycle, got)
		}
		if len(got.RecentRuns) != 1 || got.RecentRuns[0].Status != "failed" {
			t.Errorf("%s summary lost historical runs: %#v", lifecycle, got.RecentRuns)
		}
	}

	got := summariseJob(JobSummary{JobName: "live", Lifecycle: jobLifecycleActive}, runs)
	if got.LastStatus == nil || *got.LastStatus != "failed" || got.LastRun == nil || !got.LastRun.Equal(started) || got.LastDurationS == nil || *got.LastDurationS != duration {
		t.Fatalf("active summary lost operational last state: %#v", got)
	}
}

// TestRecordExternalRunAndListRuns_DB exercises the RecordExternalRun path
// api01_backup/prod01_backup now use end to end (insert -> list), against a
// live Postgres. Skipped when TEST_DATABASE_URL is unset, matching the pattern
// already used by internal/handlers' *_DB tests (e.g.
// TestHomeMetricsExcludeRevokedTenantsDB in health_admin_test.go) — go test
// ./... itself needs no DB (see go-service/docs/TESTING.md).
func TestRecordExternalRunAndListRuns_DB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping RecordExternalRun DB test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	started := time.Now().UTC().Add(-2 * time.Minute)
	finished := time.Now().UTC()

	if err := RecordExternalRun(ctx, pool, "api01_backup", "success", "restic backup ok", "", started, finished); err != nil {
		t.Fatalf("RecordExternalRun: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM scheduled_job_runs WHERE job_name = 'api01_backup' AND started_at = $1`, started)
	})

	runs, err := ListRuns(ctx, pool, "api01_backup")
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("want at least one run for api01_backup, got none")
	}
	if runs[0].Status != "success" {
		t.Errorf("want most recent run status 'success', got %q", runs[0].Status)
	}
}
