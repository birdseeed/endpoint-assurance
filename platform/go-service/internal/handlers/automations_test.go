package handlers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"patched.im/api/internal/automations"
)

func writeHeartbeat(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write heartbeat file: %v", err)
	}
}

func baseJobs() []automations.JobSummary {
	return []automations.JobSummary{
		{
			JobName:    "api01_backup",
			Lifecycle:  "active",
			LastStatus: strPtr("success"),
			LastRun:    timePtr(time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)),
			RecentRuns: []automations.RunEntry{},
		},
		{
			JobName:    "portal01_backup",
			Lifecycle:  "active",
			RecentRuns: []automations.RunEntry{},
		},
	}
}

func findJob(jobs []automations.JobSummary, name string) *automations.JobSummary {
	for i := range jobs {
		if jobs[i].JobName == name {
			return &jobs[i]
		}
	}
	return nil
}

func TestApplyPortalBackupHeartbeat_SuccessOverlaysLastRun(t *testing.T) {
	dir := t.TempDir()
	writeHeartbeat(t, dir, "portal-r2", `{"job":"portal-r2","label":"Portal R2","status":"ok","last_success_at":"2026-09-11T02:15:00Z"}`)

	jobs := baseJobs()
	before := findJob(jobs, "api01_backup")
	beforeLastRun := *before.LastRun
	beforeLastStatus := *before.LastStatus

	out := applyPortalBackupHeartbeat(jobs, dir)

	portal := findJob(out, "portal01_backup")
	if portal.LastRun == nil {
		t.Fatalf("expected portal01_backup.LastRun to be set")
	}
	want, _ := time.Parse(time.RFC3339, "2026-09-11T02:15:00Z")
	if !portal.LastRun.Equal(want) {
		t.Errorf("LastRun = %v, want %v", portal.LastRun, want)
	}
	if portal.LastStatus == nil || *portal.LastStatus != "success" {
		t.Errorf("LastStatus = %v, want success", portal.LastStatus)
	}
	if len(portal.RecentRuns) != 0 {
		t.Errorf("RecentRuns = %v, want empty", portal.RecentRuns)
	}

	api := findJob(out, "api01_backup")
	if !api.LastRun.Equal(beforeLastRun) || *api.LastStatus != beforeLastStatus {
		t.Errorf("api01_backup was mutated: LastRun=%v LastStatus=%v", api.LastRun, api.LastStatus)
	}
}

func TestApplyPortalBackupHeartbeat_MissingFile(t *testing.T) {
	dir := t.TempDir()
	jobs := baseJobs()

	out := applyPortalBackupHeartbeat(jobs, dir)

	portal := findJob(out, "portal01_backup")
	if portal.LastRun != nil {
		t.Errorf("LastRun = %v, want nil", portal.LastRun)
	}
	if portal.LastStatus != nil {
		t.Errorf("LastStatus = %v, want nil", portal.LastStatus)
	}
	if len(portal.RecentRuns) != 0 {
		t.Errorf("RecentRuns = %v, want empty", portal.RecentRuns)
	}
}

func TestApplyPortalBackupHeartbeat_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeHeartbeat(t, dir, "portal-r2", `{not valid json`)

	jobs := baseJobs()
	out := applyPortalBackupHeartbeat(jobs, dir)

	portal := findJob(out, "portal01_backup")
	if portal.LastRun != nil {
		t.Errorf("LastRun = %v, want nil", portal.LastRun)
	}
	if len(portal.RecentRuns) != 0 {
		t.Errorf("RecentRuns = %v, want empty", portal.RecentRuns)
	}
}

func TestApplyPortalBackupHeartbeat_FailStatusStillSetsLastRun(t *testing.T) {
	dir := t.TempDir()
	writeHeartbeat(t, dir, "portal-r2", `{"job":"portal-r2","label":"Portal R2","status":"fail","last_success_at":"2026-09-09T02:15:00Z","detail":"restic check failed"}`)

	jobs := baseJobs()
	out := applyPortalBackupHeartbeat(jobs, dir)

	portal := findJob(out, "portal01_backup")
	if portal.LastStatus == nil || *portal.LastStatus != "failed" {
		t.Errorf("LastStatus = %v, want failed", portal.LastStatus)
	}
	want, _ := time.Parse(time.RFC3339, "2026-09-09T02:15:00Z")
	if portal.LastRun == nil || !portal.LastRun.Equal(want) {
		t.Errorf("LastRun = %v, want %v", portal.LastRun, want)
	}
	if len(portal.RecentRuns) != 0 {
		t.Errorf("RecentRuns = %v, want empty", portal.RecentRuns)
	}
}

func TestApplyPortalBackupHeartbeat_EmptyDirNoFilesystemAccess(t *testing.T) {
	jobs := baseJobs()
	out := applyPortalBackupHeartbeat(jobs, "")

	portal := findJob(out, "portal01_backup")
	if portal.LastRun != nil {
		t.Errorf("LastRun = %v, want nil", portal.LastRun)
	}
	if len(portal.RecentRuns) != 0 {
		t.Errorf("RecentRuns = %v, want empty", portal.RecentRuns)
	}
}
