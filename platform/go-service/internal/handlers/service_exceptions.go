package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"patched.im/api/internal/automations"
)

// Limits are inherited observation-age limits, not inferred timer schedules.
// Their provenance and unsupported coverage are in contracts/service-exceptions.md.
const (
	serviceDailyJobObservationLimit = 36 * time.Hour
	serviceBackupObservationLimit   = 26 * time.Hour
	serviceGlobalReceiptLimit       = 4 * time.Hour
	serviceTenantReceiptLimit       = 12 * time.Hour
	serviceTenantLimit              = 100
	serviceReadTimeout              = 5 * time.Second
)

// A category can have a supported observation while its wider coverage remains
// unknown. These bounded sub-source rows retain actual per-job success history.
type serviceObservation struct {
	ID            string     `json:"id"`
	Scope         string     `json:"scope"`
	Result        string     `json:"result"`
	EvidenceAt    *time.Time `json:"evidence_at"`
	LastSuccessAt *time.Time `json:"last_success_at"`
}

type serviceCheck struct {
	Observations   []serviceObservation `json:"observations,omitempty"`
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Explanation    string               `json:"explanation"`
	Source         string               `json:"source"`
	Scope          string               `json:"scope"`
	Availability   string               `json:"availability"`
	Result         string               `json:"result"`
	CheckedAt      *time.Time           `json:"checked_at"`
	LastSuccessAt  *time.Time           `json:"last_success_at"`
	NextExpectedAt *time.Time           `json:"next_expected_at"`
	Reason         string               `json:"reason"`
	NextAction     string               `json:"next_action"`
}

type serviceException struct {
	ID         string     `json:"id"`
	CheckID    string     `json:"check_id"`
	TenantID   *string    `json:"tenant_id"`
	Scope      string     `json:"scope"`
	Since      *time.Time `json:"since"`
	EvidenceAt time.Time  `json:"evidence_at"`
	Reason     string     `json:"reason"`
	DeepLink   string     `json:"deep_link"`
}

type serviceExceptionsResponse struct {
	ObservedAt time.Time          `json:"observed_at"`
	Coverage   string             `json:"coverage"`
	Checks     []serviceCheck     `json:"checks"`
	Exceptions []serviceException `json:"exceptions"`
}

// ServiceExceptionsHandler only reads local evidence. It does not probe providers,
// execute jobs, accept source paths or tenant filters, or expose private output.
// The production router supplies the existing internal admin-token guard.
type ServiceExceptionsHandler struct {
	pool            *pgxpool.Pool
	backupHealthDir string
}

func NewServiceExceptionsHandler(pool *pgxpool.Pool, backupHealthDir string) *ServiceExceptionsHandler {
	return &ServiceExceptionsHandler{pool: pool, backupHealthDir: backupHealthDir}
}

func (h *ServiceExceptionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(r.Context(), serviceReadTimeout)
	defer cancel()
	resp := serviceExceptionsResponse{ObservedAt: now, Coverage: "partial", Checks: serviceChecks(), Exceptions: []serviceException{}}
	h.readServiceJobs(ctx, &resp.Checks[1], &resp.Exceptions, now)
	h.readServiceReceipts(ctx, &resp.Checks[3], &resp.Exceptions, now)
	h.readServiceBackups(&resp.Checks[7], &resp.Exceptions, now)
	c := &resp.Checks[8]
	c.CheckedAt = &now
	c.Availability, c.Result = "degraded", "unknown"
	c.Reason = "Database connectivity could not be verified. Disk capacity, server certificates and other service availability are unavailable in this feed."
	if h.pool != nil && h.pool.Ping(ctx) == nil {
		c.Reason = "The API database answered this request. Disk capacity, server certificates and other service availability are unavailable in this feed. This is not stored success history."
	}
	sort.Slice(resp.Exceptions, func(i, j int) bool { return resp.Exceptions[i].ID < resp.Exceptions[j].ID })
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func serviceChecks() []serviceCheck {
	rows := []struct{ id, name, explanation, source, scope, reason, action string }{
		{"outgoing_email", "Outgoing email", "Checks sending, authentication, attempts and delivery evidence.", "Dashboard email checks (not connected)", "patched-prod-01 / outgoing email", "API notification configuration does not prove email authentication, provider acceptance, rejection, bounce or recipient delivery. Dashboard evidence is not connected.", "Inspect the dashboard email checks; provider acceptance alone is not delivery proof."},
		{"scheduled_jobs", "Scheduled jobs", "Checks the latest recorded outcome of active registered jobs.", "scheduled_job_runs and automation registry", "Registered active platform jobs", "Run history has not been read.", "Inspect Operations job history; verify the source timer before judging a missed schedule."},
		{"customer_access", "Customer access setup", "Checks tenant membership, access policy membership and provisioning.", "Dashboard and access provider (not connected)", "patched-prod-01 / customer access", "Exact provider policy membership and provisioning evidence are unavailable. API portal mappings alone cannot verify customer access.", "Inspect customer access setup in the console."},
		{"device_reports", "Device reports", "Checks recorded receipt freshness for active customer tenants.", "raw_payloads joined to tenants", "API ingestion / active customer tenants", "Receipt evidence has not been read. Expected device population and reporting drops are unknown.", "Inspect Operations ingestion evidence and establish the expected device population."},
		{"assurance_processing", "Assurance processing", "Checks CIS evaluation and vulnerability matching job outcomes.", "Processing job outcome evidence (not connected)", "patched-api-01 / evaluator and matcher", "Durable job outcomes and freshness limits are not connected. Customer posture findings do not prove processing health.", "Inspect evaluator and matcher operating evidence."},
		{"vulnerability_data", "Vulnerability data updates", "Checks successful feed refreshes against source-owned overdue limits.", "Feed refresh evidence (not connected)", "patched-api-01 / vulnerability feeds", "Feed outcome evidence and source-owned overdue limits are unavailable in this feed.", "Inspect the vulnerability feed refresh record and its expected cadence."},
		{"reports", "Report generation and delivery", "Checks failed generation, stuck jobs, schedules and delivery.", "Report job evidence (not connected)", "Platform reports / dashboard delivery", "Report records are frozen pending by migration 0126; they prove neither generation failures nor delivery. Stuck-job limits and dashboard send evidence are unavailable.", "Inspect report generation and dashboard delivery evidence; do not infer delivery from a report record."},
		{"backups", "Backups and restore tests", "Checks backup heartbeats; restore-test evidence is separate.", "Local backup heartbeat files", "patched-api-01, patched-prod-01 and patched-portal-01 / backups", "Backup evidence has not been read. Restore-test evidence is unavailable.", "Inspect Operations backup records and the separate restore-test record."},
		{"server_health", "Server health", "Checks API database connectivity; other host checks need separate evidence.", "API database connection check", "API process / database connection", "Server evidence has not been read.", "Inspect Operations host checks for service availability, disk capacity and certificate expiry."},
		{"version_checks", "Software version checks", "Checks deployed revision, file changes and deployment failures.", "Deployment receipts and verification records (not connected)", "Platform servers / deployed software", "Deployment receipts and file verification evidence are unavailable. Stale verification would not prove an old release.", "Inspect the recorded deployment receipt and latest file verification."},
		{"billing", "Billing connection", "Checks billing provider and subscription update processing.", "Billing provider integration (not connected)", "Platform billing", "Billing, trial-end, failed-payment and cancellation evidence is unavailable until the billing integration ships.", "Track the billing integration before interpreting subscription status."},
	}
	out := make([]serviceCheck, 0, len(rows))
	for _, r := range rows {
		out = append(out, serviceCheck{ID: r.id, Name: r.name, Explanation: r.explanation, Source: r.source, Scope: r.scope, Availability: "unavailable", Result: "unavailable", Reason: r.reason, NextAction: r.action})
	}
	return out
}

func serviceTime(t *time.Time, now time.Time) *time.Time {
	if t == nil || t.IsZero() || t.After(now) || t.Year() < 1970 {
		return nil
	}
	v := t.UTC()
	return &v
}

func addServiceException(out *[]serviceException, check, id, scope, reason, link string, at time.Time, tenant *string) {
	*out = append(*out, serviceException{ID: check + ":" + id, CheckID: check, TenantID: tenant, Scope: scope, EvidenceAt: at.UTC(), Reason: reason + " The onset time is unknown.", DeepLink: link})
}

func serviceProblem(c *serviceCheck, result string) {
	// Preserve supported failures even when other sub-sources are missing.
	if c.Result != "failed" {
		c.Result = result
	}
}

func (h *ServiceExceptionsHandler) readServiceJobs(ctx context.Context, c *serviceCheck, out *[]serviceException, now time.Time) {
	c.CheckedAt, c.Availability, c.Result = &now, "degraded", "unknown"
	c.Reason = "Active job history could not be read. Next expected runs and missed schedules are unknown."
	if h.pool == nil {
		return
	}
	// Use registry metadata, not ListJobs: private output/error columns are never
	// selected. A separate bounded query per active job avoids history starvation.
	type run struct {
		started  time.Time
		finished *time.Time
		status   string
	}
	var pending []serviceException
	observations := []serviceObservation{}
	pendingResult := "unknown"
	incomplete := false
	for _, job := range automations.RegisteredJobs() {
		if job.Lifecycle != "active" {
			continue
		}
		observations = append(observations, serviceObservation{ID: job.JobName, Scope: "Platform job / " + job.JobName, Result: "unknown"})
		observation := &observations[len(observations)-1]
		rows, err := h.pool.Query(ctx, `SELECT started_at, finished_at, status FROM scheduled_job_runs WHERE job_name=$1 ORDER BY started_at DESC, id DESC LIMIT 10`, job.JobName)
		if err != nil {
			return
		}
		runs := []run{}
		for rows.Next() {
			var v run
			if err = rows.Scan(&v.started, &v.finished, &v.status); err != nil {
				break
			}
			runs = append(runs, v)
		}
		rowErr := rows.Err()
		rows.Close()
		if err != nil || rowErr != nil {
			return
		}
		if len(runs) == 0 {
			incomplete = true
			continue
		}
		for _, v := range runs {
			at := serviceTime(v.finished, now)
			if v.status == "success" && at != nil && serviceTime(&v.started, now) != nil && !at.Before(v.started) && (observation.LastSuccessAt == nil || at.After(*observation.LastSuccessAt)) {
				observation.LastSuccessAt = at
			}
		}
		latest := runs[0]
		at := serviceTime(latest.finished, now)
		if at == nil || serviceTime(&latest.started, now) == nil || at.Before(latest.started) {
			incomplete = true
			continue
		}
		observation.EvidenceAt = at
		reason := ""
		switch latest.status {
		case "failed", "warning":
			observation.Result = "failed"
			pendingResult = "failed"
			reason = "The latest completed job reported a failure or warning."
			streak := 0
			for _, v := range runs {
				if (v.status != "failed" && v.status != "warning") || serviceTime(v.finished, now) == nil || serviceTime(&v.started, now) == nil || v.finished.Before(v.started) {
					break
				}
				streak++
			}
			if streak > 1 {
				reason += fmt.Sprintf(" The latest %d recorded runs reported failure or warning (history capped at 10).", streak)
			}
		case "success":
			// Only these current daily/nightly jobs have validated UI provenance.
			// A future registration needs its own cadence validation, not a default.
			switch job.JobName {
			case "health_signals_recompute", "api01_backup", "prod01_backup", "portal01_backup":
			default:
				incomplete = true
				continue
			}
			observation.Result = "ok"
			if now.Sub(*at) > serviceDailyJobObservationLimit {
				observation.Result = "stale"
				reason = "The latest completed daily-job observation is older than the existing coarse 36-hour UI heuristic (24 hours times 1.5); this does not establish a missed timer schedule."
			}
		default:
			incomplete = true
		}
		if reason != "" {
			if pendingResult != "failed" {
				pendingResult = "stale"
			}
			addServiceException(&pending, c.ID, job.JobName, "Platform job / "+job.JobName, reason, "/console#automations", *at, nil)
		}
	}
	c.Reason = "Latest completed active-job observations are available. Exact next runs and missed schedules are unknown because registry schedules are descriptive text. Success history is per job, not a category-wide timestamp."
	if incomplete {
		c.Reason += " Some active jobs have no usable completed observation."
	}
	c.Observations = observations
	c.Result = pendingResult
	*out = append(*out, pending...)
}

func (h *ServiceExceptionsHandler) readServiceReceipts(ctx context.Context, c *serviceCheck, out *[]serviceException, now time.Time) {
	c.CheckedAt, c.Availability, c.Result = &now, "degraded", "unknown"
	c.Reason = "Receipt evidence could not be read. Expected device population and reporting drops are unknown."
	if h.pool == nil {
		return
	}
	var global *time.Time
	if err := h.pool.QueryRow(ctx, `SELECT MAX(received_at) FROM raw_payloads`).Scan(&global); err != nil {
		return
	}
	// Oldest first, with a stable UUID tie-break. The extra row detects truncation.
	rows, err := h.pool.Query(ctx, `SELECT rp.tenant_id::text, MAX(rp.received_at) FROM raw_payloads rp JOIN tenants t ON t.id=rp.tenant_id WHERE t.revoked_at IS NULL AND t.tenant_kind='customer' GROUP BY rp.tenant_id ORDER BY MAX(rp.received_at), rp.tenant_id LIMIT $1`, serviceTenantLimit+1)
	if err != nil {
		return
	}
	defer rows.Close()
	pending := []serviceException{}
	n := 0
	invalid := false
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return
		}
		n++
		if n > serviceTenantLimit {
			continue
		}
		valid := serviceTime(&at, now)
		if valid == nil {
			invalid = true
			continue
		}
		if now.Sub(*valid) > serviceTenantReceiptLimit {
			reason := "This customer's latest recorded receipt is older than the existing 12-hour warning limit. A receipt gap is not evidence of a population drop."
			if now.Sub(*valid) > 48*time.Hour {
				reason = "This customer's latest recorded receipt is older than the existing 48-hour critical limit. A receipt gap is not evidence of a population drop."
			}
			addServiceException(&pending, c.ID, id, "Active customer / device receipts", reason, "/console#ops", *valid, &id)
		}
	}
	if rows.Err() != nil {
		return
	}
	c.Reason = "Receipt timestamps were read. Expected device population, processing failures and reporting drops are unknown; even a recent global receipt cannot prove that every device reports."
	if at := serviceTime(global, now); at != nil {
		// This timestamp proves receipt only, never processing or population health.
		c.LastSuccessAt = at
		if now.Sub(*at) > serviceGlobalReceiptLimit {
			reason := "The latest global receipt is older than the existing 4-hour warning limit."
			if now.Sub(*at) > 24*time.Hour {
				reason = "The latest global receipt is older than the existing 24-hour critical limit."
			}
			addServiceException(&pending, c.ID, "global", "API ingestion / global receipts", reason, "/console#ops", *at, nil)
		}
	} else {
		c.Reason += " No usable global receipt timestamp is available."
	}
	if n == 0 {
		c.Reason += " No active customer receipt observations are available."
	}
	if invalid {
		c.Reason += " Some receipt timestamps are invalid or in the future."
	}
	if n > serviceTenantLimit {
		c.Reason += " Only the 100 oldest customer observations are included; customer coverage is truncated."
	}
	if len(pending) > 0 {
		c.Result = "stale"
	}
	*out = append(*out, pending...)
}

// Only source-owned job filenames are read. openat with O_NOFOLLOW and a held
// directory descriptor avoids path traversal, symlink replacement and FIFOs.
// Labels, details and file paths never enter the response.
func (h *ServiceExceptionsHandler) readServiceBackups(c *serviceCheck, out *[]serviceException, now time.Time) {
	c.CheckedAt, c.Availability, c.Result = &now, "degraded", "unknown"
	c.Reason = "Backup heartbeats are unconfigured or unreadable. Restore-test evidence is unavailable."
	if h.backupHealthDir == "" {
		return
	}
	fd, err := unix.Open(h.backupHealthDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	missing := false
	for _, job := range []struct{ id, host string }{{"db-r2", "patched-api-01"}, {"prod-r2", "patched-prod-01"}, {"portal-r2", "patched-portal-01"}} {
		c.Observations = append(c.Observations, serviceObservation{ID: job.id, Scope: job.host + " / " + job.id, Result: "unknown"})
		observation := &c.Observations[len(c.Observations)-1]
		value, received, err := readServiceHeartbeat(fd, job.id)
		if err != nil || value.Job != job.id || serviceTime(&received, now) == nil || (value.LastSuccessAt != nil && (serviceTime(value.LastSuccessAt, now) == nil || value.LastSuccessAt.After(received))) {
			missing = true
			continue
		}
		at := serviceTime(value.LastSuccessAt, now)
		observation.LastSuccessAt = at
		observation.EvidenceAt = serviceTime(&received, now)
		reason := ""
		result := "unknown"
		switch value.Status {
		case "ok", "success":
			if at == nil {
				missing = true
				continue
			}
			result = "ok"
			if now.Sub(*at) > serviceBackupObservationLimit {
				result = "stale"
				reason = "The last successful backup heartbeat is older than the existing 26-hour limit."
				received = *at
			}
		case "fail", "failed":
			result = "failed"
			reason = "The backup heartbeat reports failure. Its file timestamp records the heartbeat observation, not failure onset."
		default:
			missing = true
			continue
		}
		observation.Result = result
		if reason != "" {
			addServiceException(out, c.ID, job.id, job.host+" / "+job.id, reason, "/console#ops", received, nil)
			serviceProblem(c, result)
		}
	}
	c.Reason = "Backup heartbeat observations were read for the three registered server backup jobs. Restore-test date and result are unavailable; a heartbeat is not restore evidence. Last success is per job, not a category-wide timestamp."
	if missing {
		c.Reason += " One or more expected heartbeats are missing, unreadable, malformed or have unusable timestamps."
	}
}

func readServiceHeartbeat(dir int, job string) (backupJobResp, time.Time, error) {
	var value backupJobResp
	fd, err := unix.Openat(dir, job+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return value, time.Time{}, err
	}
	f := os.NewFile(uintptr(fd), "backup-heartbeat")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return value, time.Time{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBackupHeartbeatBytes {
		return value, time.Time{}, fmt.Errorf("invalid heartbeat file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBackupHeartbeatBytes+1))
	if err != nil {
		return value, time.Time{}, err
	}
	if len(data) > maxBackupHeartbeatBytes {
		return value, time.Time{}, fmt.Errorf("heartbeat too large")
	}
	if err = json.Unmarshal(data, &value); err != nil {
		return value, time.Time{}, err
	}
	return value, info.ModTime().UTC(), nil
}
