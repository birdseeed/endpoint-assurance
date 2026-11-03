package handlers

// Automation handlers (PAT-595, PAT-642) — scheduled job run history and external run recording.
//
// Routes:
//
//	GET  /admin/automations
//	GET  /admin/automations/{jobName}/runs
//	POST /admin/automations/{jobName}/record

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/automations"
)

// portalBackupHeartbeatJob is the job id portal-backup.sh's heartbeat is
// filed under (see health_admin.go's backupJobResp / the default
// BACKUP_HEARTBEAT_ALLOWED_JOBS in cmd/patched-api/main.go) — distinct
// from "portal01_backup", the name this automations tab uses. The two
// ids exist for different reasons (one is a public-heartbeat job id
// scoped to a narrow credential, the other is this tab's internal
// registry key) and are not meant to be unified.
const portalBackupHeartbeatJob = "portal-r2"

// applyPortalBackupHeartbeat overlays portal01_backup's LastRun/LastStatus
// from the backup-health heartbeat file (PAT-954) onto the automations
// job list. portal-01 (tag:portal) has zero Tailscale data-plane grants by
// design, so it can never POST /admin/automations/portal01_backup/record
// the way api-01 and prod-01 do (see tracker.go's knownJobs comment) —
// without this, LastRun stays permanently nil and the dashboard's
// staleness check reports "Last run: never" every night even though the
// backup itself runs correctly (PAT-1637).
//
// Deliberately does NOT populate RecentRuns. The heartbeat file carries
// no per-run id, and synthesizing one (e.g. always 0) would mean the
// failure-alert loop's automation_alerts_sent dedup key (job_name,
// run_id) matches on the very first synthetic entry and then silently
// suppresses every future real failure alert for this job forever.
// LastRun alone is what the staleness check reads and is sufficient to
// fix PAT-1637; failure alerting for this job is out of scope here — the
// Service Health strip's own portal-r2 row already goes red on a failed
// heartbeat.
func applyPortalBackupHeartbeat(jobs []automations.JobSummary, backupHealthDir string) []automations.JobSummary {
	if backupHealthDir == "" {
		return jobs
	}
	data, err := os.ReadFile(filepath.Join(backupHealthDir, portalBackupHeartbeatJob+".json"))
	if err != nil {
		return jobs // missing/unreadable heartbeat — job stays "never", same as today
	}
	var hb struct {
		Status        string     `json:"status"`
		LastSuccessAt *time.Time `json:"last_success_at"`
	}
	if err := json.Unmarshal(data, &hb); err != nil || hb.LastSuccessAt == nil {
		return jobs
	}
	status := "failed"
	if hb.Status == "ok" {
		status = "success"
	}
	for i := range jobs {
		if jobs[i].JobName == "portal01_backup" {
			jobs[i].LastRun = hb.LastSuccessAt
			jobs[i].LastStatus = &status
		}
	}
	return jobs
}

// AutomationsListHandler serves GET /admin/automations.
func AutomationsListHandler(pool *pgxpool.Pool, backupHealthDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobs, err := automations.ListJobs(r.Context(), pool)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}
		jobs = applyPortalBackupHeartbeat(jobs, backupHealthDir)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
	}
}

// AutomationRunsHandler serves GET /admin/automations/{jobName}/runs.
func AutomationRunsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobName := chi.URLParam(r, "jobName")
		if !automations.IsKnownJob(jobName) {
			http.Error(w, `{"error":"unknown job"}`, http.StatusNotFound)
			return
		}
		runs, err := automations.ListRuns(r.Context(), pool, jobName)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"job_name": jobName, "runs": runs})
	}
}

// AutomationRecordHandler serves POST /admin/automations/{jobName}/record.
// Accepts a completed run pushed by an active or quarantined external job (e.g.
// GitHub Actions) with explicit timestamps; inserts directly into
// scheduled_job_runs. Retired jobs remain readable but cannot add history.
func AutomationRecordHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobName := chi.URLParam(r, "jobName")
		if !automations.IsKnownJob(jobName) {
			http.Error(w, `{"error":"unknown job"}`, http.StatusNotFound)
			return
		}
		if !automations.IsRecordableJob(jobName) {
			http.Error(w, `{"error":"job is retired and read-only"}`, http.StatusConflict)
			return
		}

		var body struct {
			StartedAt  time.Time `json:"started_at"`
			FinishedAt time.Time `json:"finished_at"`
			Status     string    `json:"status"`
			Output     string    `json:"output"`
			ErrorMsg   string    `json:"error_msg"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if body.Status == "" {
			http.Error(w, `{"error":"status is required"}`, http.StatusBadRequest)
			return
		}

		if err := automations.RecordExternalRun(r.Context(), pool, jobName, body.Status, body.Output, body.ErrorMsg, body.StartedAt, body.FinishedAt); err != nil {
			http.Error(w, `{"error":"db error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"recorded": true})
	}
}
