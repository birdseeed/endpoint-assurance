package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/notify"
	"patched.im/api/internal/platformroot"
)

// AdminHealthHandler implements GET /admin/health on the internal :8081
// listener. Returns service health indicators and headline metrics in a single
// call, designed to drive a dashboard home panel.
//
// Auth posture: network-only (Tailscale, same as all /admin/* routes).
//
// Each sub-query uses its own 5-second timeout context. Any individual query
// failure is logged and causes that field to degrade to null/zero — the
// endpoint never returns a 500 for a partially-broken DB state.

type AdminHealthHandler struct {
	pool *pgxpool.Pool
	// backupHealthDir holds per-job backup heartbeat JSON files. Each backup
	// job (api-01 DB→R2 Restic, prod-01 dashboard→R2, portal-01 scan/portal→R2)
	// writes one <job>.json file on success into this directory. Empty string
	// disables the check. See OPERATIONS.md for the heartbeat contract.
	backupHealthDir string
	// notifier (PAT-1215) backs NotifyChannelsConfigured below — nil-safe,
	// see notify.Notifier.ConfiguredChannelCount.
	notifier *notify.Notifier
}

func NewHealthHandler(pool *pgxpool.Pool, backupHealthDir string, notifier *notify.Notifier) *AdminHealthHandler {
	return &AdminHealthHandler{pool: pool, backupHealthDir: backupHealthDir, notifier: notifier}
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

type ingestionFreshnessResp struct {
	MostRecentIngestAt *time.Time        `json:"most_recent_ingest_at"`
	StalestTenant      *stalestTenantRow `json:"stalest_tenant"`
}

type stalestTenantRow struct {
	TenantID     string    `json:"tenant_id"`
	TenantName   string    `json:"tenant_name"`
	LastIngestAt time.Time `json:"last_ingest_at"`
	HoursStale   float64   `json:"hours_stale"`
}

type serviceHealthResp struct {
	DBReachable        bool                   `json:"db_reachable"`
	IngestionFreshness ingestionFreshnessResp `json:"ingestion_freshness"`
	CertExpiry         []certExpiryRow        `json:"cert_expiry"`
	// PlatformRootCertExpiry / SuspiciousCerts (PAT-1738): certificates
	// excluded from CertExpiry because they classified as a known platform
	// root, or flagged because their subject names a platform vendor but the
	// thumbprint did not match — see queryCertExpiry.
	PlatformRootCertExpiry []platformRootRow       `json:"platform_root_cert_expiry"`
	SuspiciousCerts        []suspiciousCertRow     `json:"suspicious_certs"`
	BackupJobs             []backupJobResp         `json:"backup_jobs"`
	DiskUsage              []diskUsageResp         `json:"disk_usage"`
	AssessmentStorage      assessmentStorageHealth `json:"assessment_storage"`
	// NotifyChannelsConfigured (PAT-1215) is the count of notify.Notifier
	// channels (slack, email) with their env vars set — 0, 1, or 2. Dispatch
	// silently skips an unconfigured channel by design (see
	// internal/notify.Notifier.Dispatch); this field exists so an operator or
	// probe reading this surface can tell "zero channels configured, alerts
	// are dark" apart from "channels configured and presumably working". Does
	// not name which channels — that's the notifier's own config, not
	// exposed here.
	NotifyChannelsConfigured int `json:"notify_channels_configured"`
}

type assessmentStorageHealth struct {
	Compatible bool   `json:"compatible"`
	Detail     string `json:"detail,omitempty"`
}

// backupJobResp mirrors a backup heartbeat JSON file. last_success_at is null
// when a job has never reported a success; staleness/colour is computed by the
// dashboard (red when >26h old or status != "ok").
type backupJobResp struct {
	Job           string     `json:"job"`
	Label         string     `json:"label"`
	Status        string     `json:"status"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	Detail        string     `json:"detail,omitempty"`
}

type certExpiryRow struct {
	DeviceID  string    `json:"device_id"`
	SubjectCN string    `json:"subject_cn"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
}

// platformRootRow (PAT-1738) mirrors certExpiryRow for the informational
// platform-root list — same shape, kept as a distinct type so the two never
// accidentally interchange in the response.
type platformRootRow struct {
	DeviceID  string    `json:"device_id"`
	SubjectCN string    `json:"subject_cn"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
}

// suspiciousCertRow (PAT-1738) is a certificate whose subject names a
// platform vendor but whose thumbprint did not match the known platform-root
// list — a standalone investigation flag, never folded into cert_expiry.
type suspiciousCertRow struct {
	DeviceID  string `json:"device_id"`
	SubjectCN string `json:"subject_cn"`
	SHA1      string `json:"sha1"`
}

type diskUsageResp struct {
	Path    string  `json:"path"`
	TotalGB float64 `json:"total_gb"`
	UsedGB  float64 `json:"used_gb"`
	FreeGB  float64 `json:"free_gb"`
	UsedPct float64 `json:"used_pct"`
}

type findingsBySeverityResp struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	// Undetermined is the count of latest evaluations that resolved to fail
	// with no observed value (PAT-1758/PAT-1762/PAT-1776) — unreadable
	// evidence, not a real observation of non-compliance. Excluded from the
	// per-severity counts above; reported here so it is never silently
	// dropped.
	Undetermined int `json:"undetermined"`
}

type platformSplitResp struct {
	MacOS   int `json:"macos"`
	Windows int `json:"windows"`
}

type metricsResp struct {
	TotalTenants           int                    `json:"total_tenants"`
	TotalEndpoints         int                    `json:"total_endpoints"`
	CompliancePct          *float64               `json:"compliance_pct"`
	OpenFindingsBySeverity findingsBySeverityResp `json:"open_findings_by_severity"`
	PlatformSplit          platformSplitResp      `json:"platform_split"`
	ReportsGenerated       int                    `json:"reports_generated"`
}

type adminHealthResp struct {
	ServiceHealth serviceHealthResp `json:"service_health"`
	Metrics       metricsResp       `json:"metrics"`
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

func (h *AdminHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := middleware.GetReqID(r.Context())
	logger := slog.With("req_id", reqID, "handler", "admin_health")

	resp := adminHealthResp{
		ServiceHealth: serviceHealthResp{
			CertExpiry:             []certExpiryRow{},     // never nil in JSON output
			PlatformRootCertExpiry: []platformRootRow{},   // never nil in JSON output
			SuspiciousCerts:        []suspiciousCertRow{}, // never nil in JSON output
			BackupJobs:             []backupJobResp{},     // never nil in JSON output
			DiskUsage:              []diskUsageResp{},     // never nil in JSON output
		},
		Metrics: metricsResp{
			OpenFindingsBySeverity: findingsBySeverityResp{},
		},
	}

	// -- DB reachability -------------------------------------------------------
	pingCtx, pingCancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer pingCancel()
	if err := h.pool.Ping(pingCtx); err != nil {
		logger.Warn("db ping failed", "err", err)
		resp.ServiceHealth.DBReachable = false
	} else {
		resp.ServiceHealth.DBReachable = true
	}

	// -- Ingestion freshness ---------------------------------------------------
	resp.ServiceHealth.IngestionFreshness = h.queryIngestionFreshness(r.Context(), logger)

	// -- Cert expiry (expiring within 30 days, capped at 20 rows) -------------
	resp.ServiceHealth.CertExpiry, resp.ServiceHealth.PlatformRootCertExpiry, resp.ServiceHealth.SuspiciousCerts =
		h.queryCertExpiry(r.Context(), logger)

	// -- Backup jobs (heartbeat files; PAT-387) --------------------------------
	resp.ServiceHealth.BackupJobs = h.readBackupJobs(logger)

	// -- Disk usage (root filesystem) -----------------------------------------
	resp.ServiceHealth.DiskUsage = h.queryDiskUsage(logger)
	artifactsExpected, metadataErr := h.queryAssessmentArtifactsExist(r.Context())
	if metadataErr != nil {
		resp.ServiceHealth.AssessmentStorage = assessmentStorageHealth{Compatible: false, Detail: "assessment artifact metadata state is unavailable"}
		logger.Warn("assessment storage compatibility could not be established", "err", metadataErr)
	} else if err := validateAssessmentStorageRoot(reportStorageRoot(), artifactsExpected); err != nil {
		resp.ServiceHealth.AssessmentStorage = assessmentStorageHealth{Compatible: false, Detail: err.Error()}
		logger.Warn("assessment storage root is incompatible with safe purge", "err", err)
	} else {
		resp.ServiceHealth.AssessmentStorage = assessmentStorageHealth{Compatible: true}
	}

	// -- Notify channel count (PAT-1215; nil-safe) -----------------------------
	resp.ServiceHealth.NotifyChannelsConfigured = h.notifier.ConfiguredChannelCount()

	// -- Metrics ---------------------------------------------------------------
	resp.Metrics.TotalTenants = h.queryTotalTenants(r.Context(), logger)
	resp.Metrics.TotalEndpoints = h.queryTotalEndpoints(r.Context(), logger)
	resp.Metrics.CompliancePct = h.queryCompliancePct(r.Context(), logger)
	resp.Metrics.OpenFindingsBySeverity = h.queryOpenFindingsBySeverity(r.Context(), logger)
	resp.Metrics.PlatformSplit = h.queryPlatformSplit(r.Context(), logger)
	resp.Metrics.ReportsGenerated = 0 // no PDF generation tracking table yet

	logger.Info("admin health served",
		"db_reachable", resp.ServiceHealth.DBReachable,
		"total_tenants", resp.Metrics.TotalTenants,
		"total_endpoints", resp.Metrics.TotalEndpoints,
		"backup_jobs", len(resp.ServiceHealth.BackupJobs),
		"notify_channels_configured", resp.ServiceHealth.NotifyChannelsConfigured,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *AdminHealthHandler) queryAssessmentArtifactsExist(ctx context.Context) (bool, error) {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var exists bool
	err := h.pool.QueryRow(qCtx, `SELECT EXISTS (SELECT 1 FROM assessment_artifacts LIMIT 1)`).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------------
// Sub-queries — each gets its own 5 s timeout; errors degrade gracefully.
// ---------------------------------------------------------------------------

func (h *AdminHealthHandler) queryIngestionFreshness(ctx context.Context, logger *slog.Logger) ingestionFreshnessResp {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result := ingestionFreshnessResp{}

	// Most-recent ingest across all tenants.
	var mostRecent *time.Time
	err := h.pool.QueryRow(qCtx, `SELECT MAX(received_at) FROM raw_payloads`).Scan(&mostRecent)
	if err != nil {
		logger.Warn("query most_recent_ingest_at failed", "err", err)
	} else {
		result.MostRecentIngestAt = mostRecent
	}

	// Stalest tenant — the one whose latest ingest is oldest.
	row := h.pool.QueryRow(qCtx, `
		SELECT
			rp.tenant_id::text,
			t.name,
			MAX(rp.received_at) AS last_ingest_at
		FROM raw_payloads rp
		JOIN tenants t ON t.id = rp.tenant_id
		WHERE t.revoked_at IS NULL AND t.tenant_kind = 'customer'
		GROUP BY rp.tenant_id, t.name
		ORDER BY MAX(rp.received_at) ASC
		LIMIT 1
	`)
	var tenantID, tenantName string
	var lastIngestAt time.Time
	if err := row.Scan(&tenantID, &tenantName, &lastIngestAt); err != nil {
		// No rows is fine (no tenants yet); log other errors.
		if err.Error() != "no rows in result set" {
			logger.Warn("query stalest_tenant failed", "err", err)
		}
	} else {
		hoursStale := math.Round(time.Since(lastIngestAt).Hours()*10) / 10
		result.StalestTenant = &stalestTenantRow{
			TenantID:     tenantID,
			TenantName:   tenantName,
			LastIngestAt: lastIngestAt,
			HoursStale:   hoursStale,
		}
	}

	return result
}

// queryCertExpiry returns (actionable expiry rows, platform-root rows,
// suspicious rows) — see the serviceHealthResp field docs. Platform-root and
// suspicious classification (PAT-1738) is computed live via the LEFT JOIN
// below, never stored on device_certificates, and the suspicious regexes
// come from internal/platformroot so this query and the Windows-filter
// substrings PAT-1737 removed never drift apart.
func (h *AdminHealthHandler) queryCertExpiry(ctx context.Context, logger *slog.Logger) ([]certExpiryRow, []platformRootRow, []suspiciousCertRow) {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := h.pool.Query(qCtx, `
		SELECT
			dc.device_id::text,
			dc.subject_cn,
			dc.sha1,
			dc.not_after,
			EXTRACT(DAY FROM dc.not_after - now())::int AS days_left,
			(prc.thumbprint_sha1 IS NOT NULL) AS is_platform_root,
			(prc.thumbprint_sha1 IS NULL AND (
			    (d.os = 'Windows' AND dc.subject_cn ~* $1)
			    OR (d.os = 'macOS' AND dc.subject_cn ~* $2)
			)) AS is_suspicious
		FROM device_certificates dc
		JOIN devices d ON d.id = dc.device_id
		LEFT JOIN platform_root_certificates prc
		       ON prc.thumbprint_sha1 = dc.sha1
		      AND prc.platform = CASE d.os WHEN 'Windows' THEN 'windows' WHEN 'macOS' THEN 'macos' END
		WHERE dc.not_after BETWEEN now() AND now() + INTERVAL '30 days'
		ORDER BY dc.not_after ASC
		LIMIT 20
	`,
		platformroot.SuspiciousSubjectRegexOrNoMatch(platformroot.PlatformWindows),
		platformroot.SuspiciousSubjectRegexOrNoMatch(platformroot.PlatformMacOS),
	)
	if err != nil {
		logger.Warn("query cert_expiry failed", "err", err)
		return []certExpiryRow{}, []platformRootRow{}, []suspiciousCertRow{}
	}
	defer rows.Close()

	var certs []certExpiryRow
	var platformRoots []platformRootRow
	var suspicious []suspiciousCertRow
	for rows.Next() {
		var deviceID, subjectCN, sha1 string
		var notAfter time.Time
		var daysLeft int
		var isPlatformRoot, isSuspicious bool
		if err := rows.Scan(&deviceID, &subjectCN, &sha1, &notAfter, &daysLeft, &isPlatformRoot, &isSuspicious); err != nil {
			logger.Warn("scan cert_expiry row failed", "err", err)
			continue
		}
		switch {
		case isPlatformRoot:
			platformRoots = append(platformRoots, platformRootRow{
				DeviceID: deviceID, SubjectCN: subjectCN, NotAfter: notAfter, DaysLeft: daysLeft,
			})
		case isSuspicious:
			suspicious = append(suspicious, suspiciousCertRow{
				DeviceID: deviceID, SubjectCN: subjectCN, SHA1: sha1,
			})
		default:
			certs = append(certs, certExpiryRow{
				DeviceID: deviceID, SubjectCN: subjectCN, NotAfter: notAfter, DaysLeft: daysLeft,
			})
		}
	}
	if err := rows.Err(); err != nil {
		logger.Warn("iterate cert_expiry rows failed", "err", err)
	}
	if certs == nil {
		certs = []certExpiryRow{}
	}
	if platformRoots == nil {
		platformRoots = []platformRootRow{}
	}
	if suspicious == nil {
		suspicious = []suspiciousCertRow{}
	}
	return certs, platformRoots, suspicious
}

// readBackupJobs loads one backupJobResp per *.json heartbeat file in
// backupHealthDir. Unlike the other sub-queries this touches the filesystem,
// not the DB. A missing/unreadable directory or a malformed file is logged and
// skipped — the endpoint still returns (the dashboard renders "no data"), so a
// backup-reporting outage never takes down the health endpoint.
func (h *AdminHealthHandler) readBackupJobs(logger *slog.Logger) []backupJobResp {
	jobs := []backupJobResp{}
	if h.backupHealthDir == "" {
		return jobs
	}

	entries, err := os.ReadDir(h.backupHealthDir)
	if err != nil {
		logger.Warn("read backup_health dir failed", "dir", h.backupHealthDir, "err", err)
		return jobs
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		full := filepath.Join(h.backupHealthDir, e.Name())
		data, err := os.ReadFile(full)
		if err != nil {
			logger.Warn("read backup heartbeat failed", "file", full, "err", err)
			continue
		}
		var job backupJobResp
		if err := json.Unmarshal(data, &job); err != nil {
			logger.Warn("parse backup heartbeat failed", "file", full, "err", err)
			continue
		}
		if job.Job == "" {
			job.Job = strings.TrimSuffix(e.Name(), ".json")
		}
		if job.Label == "" {
			job.Label = job.Job
		}
		jobs = append(jobs, job)
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Job < jobs[j].Job })
	return jobs
}

func (h *AdminHealthHandler) queryTotalTenants(ctx context.Context, logger *slog.Logger) int {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var count int
	if err := h.pool.QueryRow(qCtx,
		`SELECT COUNT(*) FROM tenants WHERE revoked_at IS NULL`,
	).Scan(&count); err != nil {
		logger.Warn("query total_tenants failed", "err", err)
	}
	return count
}

// tenantIDs, when non-empty, scopes the count to just those tenants (AND
// t.id = ANY(...)) in addition to the usual revoked_at exclusion. The real
// /admin/health caller never passes any, so production behavior (an
// estate-wide count) is unchanged; it exists so DB-gated tests can assert
// against only the tenant rows they themselves created — see
// TestHomeMetricsExcludeRevokedTenantsDB in health_admin_test.go — instead
// of a global count that other concurrently-running test packages can
// perturb against a shared DATABASE_URL.
func (h *AdminHealthHandler) queryTotalEndpoints(ctx context.Context, logger *slog.Logger, tenantIDs ...string) int {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	query := `SELECT COUNT(*) FROM devices d JOIN tenants t ON t.id = d.tenant_id WHERE t.revoked_at IS NULL`
	args := []any{}
	if len(tenantIDs) > 0 {
		query += ` AND t.id = ANY($1::uuid[])`
		args = append(args, tenantIDs)
	}

	var count int
	if err := h.pool.QueryRow(qCtx, query, args...).Scan(&count); err != nil {
		logger.Warn("query total_endpoints failed", "err", err)
	}
	return count
}

func (h *AdminHealthHandler) queryCompliancePct(ctx context.Context, logger *slog.Logger) *float64 {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Latest evaluation per (device, rule) — use the window function pattern
	// used elsewhere in the codebase. Exclude not_applicable from both numerator
	// and denominator; count pass as pass, everything else (fail, error) as fail.
	row := h.pool.QueryRow(qCtx, `
		WITH latest_evals AS (
			SELECT DISTINCT ON (ce.device_id, ce.rule_id)
				ce.status
			FROM compliance_evaluations ce
			JOIN devices d ON d.id = ce.device_id
			JOIN tenants t ON t.id = d.tenant_id
			WHERE t.revoked_at IS NULL
			ORDER BY ce.device_id, ce.rule_id, ce.evaluated_at DESC
		)
		SELECT
			COUNT(*) FILTER (WHERE status NOT IN ('not_applicable')) AS total,
			COUNT(*) FILTER (WHERE status = 'pass')                  AS passing
		FROM latest_evals
	`)

	var total, passing int64
	if err := row.Scan(&total, &passing); err != nil {
		logger.Warn("query compliance_pct failed", "err", err)
		return nil
	}
	if total == 0 {
		return nil
	}
	pct := math.Round(float64(passing)/float64(total)*1000) / 10 // one decimal place
	return &pct
}

// tenantIDs, when non-empty, scopes the query to just those tenants — see
// queryTotalEndpoints for why.
func (h *AdminHealthHandler) queryOpenFindingsBySeverity(ctx context.Context, logger *slog.Logger, tenantIDs ...string) findingsBySeverityResp {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result := findingsBySeverityResp{}

	// Latest evaluation per (device, rule) where status = 'fail', grouped by
	// severity. PAT-1776: a 'fail' row with no observed value is unreadable
	// evidence (an absent signal, or the collector's literal "Unknown"
	// sentinel), not a real observation of non-compliance — same predicate
	// as isUndeterminedEval (internal/report/pdf.go). Excluded from the
	// per-severity counts below; summed into a flat Undetermined bucket
	// instead. A "NotConfigured" fail has a non-nil observed value and stays
	// a real, per-severity fail.
	tenantFilter := ""
	args := []any{}
	if len(tenantIDs) > 0 {
		tenantFilter = ` AND t.id = ANY($1::uuid[])`
		args = append(args, tenantIDs)
	}
	query := `
		WITH latest_evals AS (
			SELECT DISTINCT ON (ce.device_id, ce.rule_id)
				ce.severity,
				ce.status,
				ce.observed_value
			FROM compliance_evaluations ce
			JOIN devices d ON d.id = ce.device_id
			JOIN tenants t ON t.id = d.tenant_id
			WHERE t.revoked_at IS NULL` + tenantFilter + `
			ORDER BY ce.device_id, ce.rule_id, ce.evaluated_at DESC
		)
		SELECT
			severity,
			COUNT(*) FILTER (WHERE observed_value IS NOT NULL) AS cnt,
			COUNT(*) FILTER (WHERE observed_value IS NULL)     AS undetermined_cnt
		FROM latest_evals
		WHERE status = 'fail'
		GROUP BY severity
	`
	rows, err := h.pool.Query(qCtx, query, args...)
	if err != nil {
		logger.Warn("query open_findings_by_severity failed", "err", err)
		return result
	}
	defer rows.Close()

	for rows.Next() {
		var sev string
		var cnt, undeterminedCnt int
		if err := rows.Scan(&sev, &cnt, &undeterminedCnt); err != nil {
			logger.Warn("scan findings severity row failed", "err", err)
			continue
		}
		switch sev {
		case "critical":
			result.Critical = cnt
		case "high":
			result.High = cnt
		case "medium":
			result.Medium = cnt
		case "low":
			result.Low = cnt
		case "informational":
			result.Informational = cnt
		}
		result.Undetermined += undeterminedCnt
	}
	if err := rows.Err(); err != nil {
		logger.Warn("iterate findings severity rows failed", "err", err)
	}

	return result
}

func (h *AdminHealthHandler) queryDiskUsage(logger *slog.Logger) []diskUsageResp {
	total, free, avail, err := diskUsageBytes("/")
	if err != nil {
		logger.Warn("statfs / failed", "err", err)
		return []diskUsageResp{}
	}
	used := total - free
	toGB := func(b float64) float64 { return math.Round(b/1e9*10) / 10 }
	usedPct := math.Round(used/total*1000) / 10
	return []diskUsageResp{{
		Path:    "/",
		TotalGB: toGB(total),
		UsedGB:  toGB(used),
		FreeGB:  toGB(avail),
		UsedPct: usedPct,
	}}
}

// tenantIDs, when non-empty, scopes the query to just those tenants — see
// queryTotalEndpoints for why.
func (h *AdminHealthHandler) queryPlatformSplit(ctx context.Context, logger *slog.Logger, tenantIDs ...string) platformSplitResp {
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result := platformSplitResp{}

	// devices.os stores "macOS" or "Windows" (from the payload OS.Name field).
	tenantFilter := ""
	args := []any{}
	if len(tenantIDs) > 0 {
		tenantFilter = ` AND t.id = ANY($1::uuid[])`
		args = append(args, tenantIDs)
	}
	query := `
		SELECT d.os, COUNT(*) AS cnt
		FROM devices d
		JOIN tenants t ON t.id = d.tenant_id
		WHERE t.revoked_at IS NULL` + tenantFilter + `
		GROUP BY d.os
	`
	rows, err := h.pool.Query(qCtx, query, args...)
	if err != nil {
		logger.Warn("query platform_split failed", "err", err)
		return result
	}
	defer rows.Close()

	for rows.Next() {
		var osName string
		var cnt int
		if err := rows.Scan(&osName, &cnt); err != nil {
			logger.Warn("scan platform_split row failed", "err", err)
			continue
		}
		switch osName {
		case "macOS":
			result.MacOS = cnt
		case "Windows":
			result.Windows = cnt
		}
	}
	if err := rows.Err(); err != nil {
		logger.Warn("iterate platform_split rows failed", "err", err)
	}

	return result
}
