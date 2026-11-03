// Package automations provides job-run tracking and background maintenance jobs.
package automations

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunEntry is one row from scheduled_job_runs.
type RunEntry struct {
	ID         int64      `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	DurationS  *float64   `json:"duration_s,omitempty"`
	Output     *string    `json:"output,omitempty"`
	ErrorMsg   *string    `json:"error_msg,omitempty"`
}

// JobSummary is a job descriptor with its last run state and recent history.
type JobSummary struct {
	JobName       string     `json:"job_name"`
	Lifecycle     string     `json:"lifecycle"`
	Schedule      string     `json:"schedule"`
	Description   string     `json:"description"`
	LastStatus    *string    `json:"last_status,omitempty"`
	LastRun       *time.Time `json:"last_run,omitempty"`
	LastDurationS *float64   `json:"last_duration_s,omitempty"`
	RecentRuns    []RunEntry `json:"recent_runs"`
}

const (
	jobLifecycleActive      = "active"
	jobLifecycleQuarantined = "quarantined"
	jobLifecycleRetired     = "retired"
)

// knownJobs defines every registered automation.
var knownJobs = []JobSummary{
	{
		JobName:     "health_signals_recompute",
		Lifecycle:   jobLifecycleActive,
		Schedule:    "Daily (~02:30 UTC, extractor loop)",
		Description: "Recompute per-tenant health signals: ingestion staleness, compliance score trending",
	},
	{
		JobName:     "mirror_pipeline",
		Lifecycle:   jobLifecycleQuarantined,
		Schedule:    "Manual only (quarantined; no schedule)",
		Description: "Legacy mirror workflow retained outside production scheduling; run records remain accepted during cross-repository retirement",
	},
	{
		JobName:     "mirror_pipeline_windows",
		Lifecycle:   jobLifecycleQuarantined,
		Schedule:    "Manual only (quarantined; no schedule)",
		Description: "Legacy Windows mirror workflow retained outside production scheduling; run records remain accepted during cross-repository retirement",
	},
	{
		JobName:     "installomator_sync",
		Lifecycle:   jobLifecycleRetired,
		Schedule:    "Retired (read-only history)",
		Description: "Historical Installomator manifest synchronisation; implementation removed and no trigger or record route exists",
	},
	{
		// PAT-993: instrumented directly — api-vps-artefacts/backup.sh (run by
		// patched-backup.service on api-01) POSTs to
		// /admin/automations/api01_backup/record on both its success and
		// failure paths (best-effort; a POST failure never fails the backup
		// job itself). See backup.sh's report_run/report_automation_run.
		JobName:     "api01_backup",
		Lifecycle:   jobLifecycleActive,
		Schedule:    "Nightly, ~03:00 UTC",
		Description: "Restic backup of the api-01 Postgres DB to Cloudflare R2",
	},
	{
		// PAT-993: instrumented directly — api-vps-artefacts/prod-01-backup/prod-backup.sh
		// (run by patched-prod-backup.service on prod-01) POSTs to api-01 over
		// the tailnet (tag:main -> tag:api:8443, already-open per
		// tailscale-acl.json) on both its success and failure paths, same
		// best-effort contract as api01_backup above.
		JobName:     "prod01_backup",
		Lifecycle:   jobLifecycleActive,
		Schedule:    "Nightly, ~02:00 UTC",
		Description: "Restic backup of prod-01's dashboard.db + reports/ to Cloudflare R2",
	},
	{
		// PAT-993: registered but deliberately NOT instrumented via
		// RecordExternalRun/POST-to-record from this repo/session. portal-01
		// runs on Tailscale ACL tag "tag:portal", whose data plane grants
		// zero routes by design (portal/AGENTS.md "Network posture": "the
		// data path never traverses the tailnet") — wiring portal-backup.sh
		// to POST /admin/automations/portal01_backup/record would need a new
		// ACL grant that weakens that deliberate hardening choice, so it's
		// out of scope here.
		//
		// PAT-1637: LastRun is instead sourced by AutomationsListHandler
		// (go-service/internal/handlers/automations.go) from the "portal-r2"
		// backup-health heartbeat file that portal-backup.sh already POSTs
		// reliably to /v1/backup-health — see applyPortalBackupHeartbeat
		// there. This entry still has zero rows in scheduled_job_runs
		// (RecentRuns stays empty); the maintenance-facts emitter's `timers`
		// array remains the source for per-run history, via check_statuses
		// rather than this tab.
		JobName:     "portal01_backup",
		Lifecycle:   jobLifecycleActive,
		Schedule:    "Nightly (see patched-portal-backup.timer on portal-01)",
		Description: "Restic backup of portal-01's scan.db + uploads/ + reports/ + both services' config to Cloudflare R2 — last run sourced from the portal-r2 backup-health heartbeat (PAT-1637); see portal-01's own maintenance-facts timers array for per-run history",
	},
}

// StartRun inserts a 'running' row and returns its id.
func StartRun(ctx context.Context, pool *pgxpool.Pool, jobName string) (int64, error) {
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO scheduled_job_runs (job_name, started_at, status)
		 VALUES ($1, now(), 'running') RETURNING id`,
		jobName,
	).Scan(&id)
	return id, err
}

// FinishRun stamps the row with finished_at, status, output, error_msg.
func FinishRun(ctx context.Context, pool *pgxpool.Pool, id int64, status, output, errMsg string) error {
	var outPtr, errPtr *string
	if output != "" {
		outPtr = &output
	}
	if errMsg != "" {
		errPtr = &errMsg
	}
	_, err := pool.Exec(ctx,
		`UPDATE scheduled_job_runs
		 SET finished_at = now(), status = $2, output = $3, error_msg = $4
		 WHERE id = $1`,
		id, status, outPtr, errPtr,
	)
	return err
}

// ListJobs returns all known jobs with their last run state and the 10 most recent
// runs each. Queries are bounded per known job: an unrelated retired history
// must never consume a global shared limit and hide an active job's runs.
func ListJobs(ctx context.Context, pool *pgxpool.Pool) ([]JobSummary, error) {
	out := make([]JobSummary, len(knownJobs))
	for i, meta := range knownJobs {
		runs, err := listRecentRuns(ctx, pool, meta.JobName, 10)
		if err != nil {
			return nil, err
		}
		out[i] = summariseJob(meta, runs)
	}
	return out, nil
}

func summariseJob(meta JobSummary, runs []RunEntry) JobSummary {
	js := meta
	if len(runs) == 0 {
		js.RecentRuns = []RunEntry{}
		return js
	}

	js.RecentRuns = runs
	// Retired and quarantined jobs have no expected next run. Leaving their
	// historical last status in the operational summary makes lifecycle-unaware
	// consumers report a permanent stale failure. Detailed history remains
	// available in recent_runs and the per-job runs endpoint.
	if js.Lifecycle == jobLifecycleActive {
		js.LastStatus = &runs[0].Status
		js.LastRun = &runs[0].StartedAt
		js.LastDurationS = runs[0].DurationS
	}
	return js
}

func listRecentRuns(ctx context.Context, pool *pgxpool.Pool, jobName string, limit int) ([]RunEntry, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, started_at, finished_at, status, output, error_msg
		FROM scheduled_job_runs
		WHERE job_name = $1
		ORDER BY started_at DESC
		LIMIT $2
	`, jobName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RunEntry
	for rows.Next() {
		var e RunEntry
		if err := rows.Scan(&e.ID, &e.StartedAt, &e.FinishedAt, &e.Status, &e.Output, &e.ErrorMsg); err != nil {
			return nil, err
		}
		if e.FinishedAt != nil {
			d := e.FinishedAt.Sub(e.StartedAt).Seconds()
			e.DurationS = &d
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListRuns returns the 50 most recent runs for a specific job.
func ListRuns(ctx context.Context, pool *pgxpool.Pool, jobName string) ([]RunEntry, error) {
	return listRecentRuns(ctx, pool, jobName, 50)
}

// RecordExternalRun inserts a completed run row with caller-supplied timestamps.
// Used by externally-driven jobs (e.g. GitHub Actions mirror pipeline) to push
// their run history into the automations tab.
func RecordExternalRun(ctx context.Context, pool *pgxpool.Pool, jobName, status, output, errMsg string, startedAt, finishedAt time.Time) error {
	var outPtr, errPtr *string
	if output != "" {
		outPtr = &output
	}
	if errMsg != "" {
		errPtr = &errMsg
	}
	_, err := pool.Exec(ctx,
		`INSERT INTO scheduled_job_runs (job_name, started_at, finished_at, status, output, error_msg)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		jobName, startedAt, finishedAt, status, outPtr, errPtr,
	)
	return err
}

// IsKnownJob returns true if jobName is a registered automation.
func IsKnownJob(jobName string) bool {
	for _, j := range knownJobs {
		if j.JobName == jobName {
			return true
		}
	}
	return false
}

// IsRecordableJob distinguishes jobs that can still have a live reporter from
// read-only history. Quarantined mirror reporters remain compatible until their
// external workflow record steps are removed; retired jobs are GET-only.
func IsRecordableJob(jobName string) bool {
	for _, j := range knownJobs {
		if j.JobName == jobName {
			return j.Lifecycle == jobLifecycleActive || j.Lifecycle == jobLifecycleQuarantined
		}
	}
	return false
}

// ShouldRun reports whether the job has not completed successfully within minInterval.
func ShouldRun(ctx context.Context, pool *pgxpool.Pool, jobName string, minInterval time.Duration) bool {
	var lastRun *time.Time
	_ = pool.QueryRow(ctx, `
		SELECT MAX(started_at) FROM scheduled_job_runs
		WHERE job_name = $1 AND status IN ('success', 'warning')
	`, jobName).Scan(&lastRun)
	if lastRun == nil {
		return true
	}
	return time.Since(*lastRun) >= minInterval
}
