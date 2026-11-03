package report

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantOverview is one tenant row from FetchTenantsOverview.
type TenantOverview struct {
	ID             string
	Name           string
	Tier           string
	TenantKind     string
	MacOSEnabled   bool
	WindowsEnabled bool
	// DeviceCount and ActiveLast7d are the tenant's TOTAL device count and
	// count of devices seen in the last 7 days, unfiltered by the per-OS
	// master switch — the same population FetchTenantDevices' Total counts
	// (PAT-1686; see FetchTenantsOverview's doc comment). CompliancePct and
	// CritHighFails below remain scoped to eligible (master-switch-enabled)
	// devices, a deliberately different and narrower population.
	DeviceCount   int
	ActiveLast7d  int
	CompliancePct float64
	CritHighFails int
	// UndeterminedCritHighFails counts eligible devices' latest
	// critical/high-severity evaluations that resolved to fail with no
	// observed value (PAT-1758/PAT-1762/PAT-1776) — unreadable evidence, not
	// a real observation of non-compliance. Excluded from CritHighFails
	// above; CompliancePct's denominator is unaffected (still counts every
	// fail, undetermined or not) so missing evidence never raises the score.
	UndeterminedCritHighFails int
	NewAppsAwaitingDecision   int
	IsTrial                   bool
	TrialExpiresAt            *time.Time

	// Health-score fields (PAT-677 / migration 0065). NULL until first nightly run.
	HealthScore           *int
	HealthBucket          *string
	HealthScoreComputedAt *time.Time

	// PAT-676 engagement signals (migration 0063).
	ComplianceScoreCurrent *int
	ComplianceScore30dAgo  *int
	LastDashboardLoginAt   *time.Time
	DashboardLoginsLast30d int
	PaymentFailed          bool

	// Backup status aggregate (PAT-679/680 agents; PAT-948 server ingestion +
	// PAT-673 fleet overview consumer). Computed from the same eligible-device
	// set (respects each tenant's per-OS master switch) as CompliancePct above
	// — NOT the same population as DeviceCount/ActiveLast7d since PAT-1686
	// (those are unfiltered). See BackupBucket (report.go) for the bucket
	// rule — these four counts partition eligible devices that HAVE reported
	// backup_status; a device that predates PAT-679/680 (no backup_status at
	// all) contributes to none of the four.
	BackupOK       int
	BackupStale    int
	BackupNone     int
	BackupSyncOnly int
}

// TenantDeviceRow is one device from FetchTenantDevices.
type TenantDeviceRow struct {
	ID                 string
	Hostname           string
	Serial             string
	OS                 string
	OSVersion          string
	LastSeen           time.Time
	PrimaryUserAccount string
	PrimaryUserDisplay string
	PassCount          int
	FailCount          int
	NACount            int
	ErrorCount         int
	// UndeterminedCount is the number of this device's latest evaluations
	// that resolved to fail with no observed value (PAT-1758/PAT-1762) —
	// unreadable evidence, not a real observation of non-compliance.
	// Excluded from FailCount (this is customer-facing via portal.go's
	// FetchPortalDevices, which embeds TenantDeviceRow into the roster
	// GET /v1/portal/devices reads for findings_open); included in
	// CompliancePct's denominator so missing evidence never raises a score.
	UndeterminedCount int
	CompliancePct     float64

	// Hardware health digest (PAT-686). HasHardware is false when the device
	// has never reported hardware data (no device_hardware row).
	HasHardware           bool
	BatteryMaxCapacityPct *int
	BatteryCondition      *string
	BatteryCycleCount     *int
	StorageFreeBytes      *int64
	StorageUsedPct        *int
	SMARTStatus           *string

	// EvaluationDisabled is true when this device's OS has its tenant master
	// switch turned off (PAT-745). The device is still ingested/updated by the
	// extractor and stays visible in the fleet roster — only its compliance
	// evaluation/scoring is suppressed — so operators don't lose visibility of
	// endpoints that are still actively reporting.
	EvaluationDisabled bool

	// Backup status digest (PAT-679/680 agents; PAT-948 server ingestion).
	// Nil when the device predates PAT-679/680 or its backup_status failed
	// to parse — same nil-means-absent convention as DeviceBackupStatus
	// elsewhere.
	BackupStatus *DeviceBackupStatus

	// StoredDeviceClass and StoredOSCaption (PAT-2324) are devices.device_class
	// and devices.os_caption exactly as stored (NULL read as ""). They are the
	// raw inputs to the customer portal's device_class and os_caption, which
	// are derived from them in one place (derivePortalDeviceClass in
	// portal.go). Nothing else should read them as a customer-facing value.
	StoredDeviceClass string
	StoredOSCaption   string
}

// FindingsOpen is the device's open configuration findings: real failures
// plus errored evaluations. Undetermined evaluations (a fail with no observed
// value, PAT-1762) are unreadable evidence and are not counted. The customer
// portal's roster and device page both read this one definition, so the two
// cannot disagree (PAT-2294).
func (d TenantDeviceRow) FindingsOpen() int {
	return d.FailCount + d.ErrorCount
}

// BackupBucket applies the PAT-948 bucket rule (see report.BackupBucket) to
// this row's backup digest. Returns "" when the device has never reported
// backup_status at all (predates PAT-679/680, or the value failed to parse).
func (d TenantDeviceRow) BackupBucket() string {
	if d.BackupStatus == nil {
		return ""
	}
	return BackupBucket(d.BackupStatus.HasBackup, d.BackupStatus.SyncOnly, d.BackupStatus.LastBackupDaysAgo)
}

// HardwareFlag applies the PAT-684/PAT-686 attention thresholds to the row's
// hardware digest (battery <70% or bad condition, <10 GB free, non-Verified
// SMART). False when the device has no hardware data.
func (d TenantDeviceRow) HardwareFlag() bool {
	if !d.HasHardware {
		return false
	}
	return DeviceNeedsAttention(DeviceHealthRow{
		BatteryCondition:      d.BatteryCondition,
		BatteryMaxCapacityPct: d.BatteryMaxCapacityPct,
		StorageUsedPct:        d.StorageUsedPct,
		StorageFreeBytes:      d.StorageFreeBytes,
		SMARTStatus:           d.SMARTStatus,
	})
}

// hardwareIssueSummary returns a short, human-readable reason for a flagged
// device's hardware digest, e.g. "battery 62% health (412 cycles) — consider
// replacement". Deliberately checked in its own priority order (battery
// condition, battery capacity, storage, SMART, then the used_pct fallback) —
// NOT the same order as DeviceNeedsAttention (which checks SMART before
// storage) — because this only picks which single reason to narrate when a
// device happens to trip more than one signal at once; DeviceNeedsAttention's
// order only matters for its early-return short-circuit. Returns "" when the
// device isn't flagged (or has no hardware data).
func (d TenantDeviceRow) hardwareIssueSummary() string {
	if !d.HardwareFlag() {
		return ""
	}
	if d.BatteryCondition != nil {
		bc := *d.BatteryCondition
		if bc != "" && bc != "Normal" && bc != "Good" {
			return fmt.Sprintf("battery condition %q: consider replacement", bc)
		}
	}
	if d.BatteryMaxCapacityPct != nil && *d.BatteryMaxCapacityPct > 0 &&
		*d.BatteryMaxCapacityPct < batteryFlagMaxCapacityPct {
		if d.BatteryCycleCount != nil {
			return fmt.Sprintf("battery %d%% health (%d cycles): consider replacement",
				*d.BatteryMaxCapacityPct, *d.BatteryCycleCount)
		}
		return fmt.Sprintf("battery %d%% health: consider replacement", *d.BatteryMaxCapacityPct)
	}
	if d.StorageFreeBytes != nil && *d.StorageFreeBytes < storageFlagFreeBytes {
		gb := int(math.Ceil(float64(*d.StorageFreeBytes) / float64(int64(1)<<30)))
		return fmt.Sprintf("<%d GB free disk: storage pressure", gb)
	}
	if d.SMARTStatus != nil && *d.SMARTStatus != "" && *d.SMARTStatus != "Verified" {
		return "SMART warning: potential drive failure"
	}
	// DeviceNeedsAttention's used_pct>85 fallback (StorageFreeBytes unreported).
	if d.StorageUsedPct != nil && *d.StorageUsedPct > 85 {
		return fmt.Sprintf("%d%% disk used: storage pressure", *d.StorageUsedPct)
	}
	return "" // shouldn't happen: HardwareFlag() true implies one of the above matched
}

// TenantDevicesResult is the paged result from FetchTenantDevices.
type TenantDevicesResult struct {
	Total   int
	Devices []TenantDeviceRow
}

// TenantFindingRow is one failing/error evaluation from FetchTenantFindings.
type TenantFindingRow struct {
	DeviceID    string
	Hostname    string
	RuleKey     string
	Title       string
	Severity    string
	Status      string
	EvaluatedAt time.Time
}

// TenantFindingsResult is the paged result from FetchTenantFindings.
type TenantFindingsResult struct {
	Total    int
	Findings []TenantFindingRow
	// UndeterminedCount is the number of latest evaluations across the
	// tenant's eligible devices that resolved to fail with no observed value
	// (PAT-1758/PAT-1762/PAT-1776) — unreadable evidence, not a real
	// observation of non-compliance. These are excluded from Findings/Total
	// (there is nothing to remediate for a control the collector could not
	// read) and reported here instead so the evidence gap is never silently
	// dropped. A "NotConfigured" fail has a non-nil observed value and stays
	// a real finding in Findings, not counted here.
	UndeterminedCount int
}

// FetchTenantsOverview returns a summary row for every non-revoked tenant.
// Compliance aggregates (CompliancePct, CritHighFails, the four backup_*
// buckets) respect each tenant's per-OS master switches via a per-row CASE
// expression in the eligible-devices filter — that scoping is deliberate and
// correct: a disabled platform's devices are not evaluated, so they must not
// count toward compliance scoring (same reasoning as PAT-745's commit
// message: "score/report aggregations where excluding a disabled platform's
// devices from the numbers is correct").
//
// DeviceCount and ActiveLast7d are DIFFERENT: they are meant to answer "how
// many devices does this tenant actually have", the same question
// FetchTenantDevices (GET /admin/tenants/{id}/devices, the roster behind the
// dashboard's Devices page) answers, and the dashboard renders both figures
// under the same "device count" label (tenant header/breadcrumb "N devices"
// and the tenant-list "Devices" column both read this field; see
// dashboard/templates/console.html's ctx-client-fleet). Before PAT-1686 these
// two counted DIFFERENT populations for a tenant with a platform disabled:
// this query's eligible-devices filter silently excluded that platform's
// devices from DeviceCount/ActiveLast7d, while FetchTenantDevices — fixed by
// PAT-745 to stop doing exactly that for the roster itself, precisely so a
// disabled platform doesn't cost operators fleet visibility — kept counting
// them. The two screens then showed different totals for the same tenant.
// DeviceCount/ActiveLast7d are therefore sourced from tenant_totals below, an
// unfiltered per-tenant device count, so they always agree with
// FetchTenantDevices's Total.
// Tier is read from agent_config.body; defaults to "assurance" when absent
// (PAT-1599, migration 0138 — was "report_deploy").
func FetchTenantsOverview(ctx context.Context, pool *pgxpool.Pool) ([]TenantOverview, error) {
	rows, err := pool.Query(ctx, `
		WITH tenant_data AS (
			SELECT
				t.id,
				t.name,
				t.tenant_kind,
				t.macos_enabled,
				t.windows_enabled,
				t.is_trial,
				t.trial_expires_at,
				t.health_score,
				t.health_bucket,
				t.health_score_computed_at,
				t.compliance_score_current,
				t.compliance_score_30d_ago,
				t.last_dashboard_login_at,
				t.dashboard_logins_last_30d,
				t.payment_failed,
				COALESCE(ac.body->>'tier', 'assurance') AS tier
			FROM tenants t
			LEFT JOIN agent_config ac ON ac.tenant_id = t.id
			WHERE t.revoked_at IS NULL
		),
		eligible AS (
			SELECT d.id AS device_id, d.tenant_id, d.last_seen
			FROM devices d
			JOIN tenant_data td ON td.id = d.tenant_id
			WHERE CASE
				WHEN d.os = 'macOS'   THEN td.macos_enabled
				WHEN d.os = 'Windows' THEN td.windows_enabled
				ELSE true
			END
		),
		latest_evals AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.status, e.severity, e.observed_value
			FROM compliance_evaluations e
			WHERE e.device_id IN (SELECT device_id FROM eligible)
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		),
		device_comp AS (
			SELECT
				el.tenant_id,
				el.device_id,
				el.last_seen,
				-- Backup status digest per device (PAT-679/680 agents; PAT-948).
				-- has_status is false for devices that predate PAT-679/680 (no
				-- backup_status at all) — those devices are excluded from all
				-- four backup_* aggregate counts below, same as HardwareFlag's
				-- HasHardware gate.
				-- 'null'::jsonb parity with the Go read paths (DecodeDeviceBackupStatus
				-- treats a stored JSON-null as absent); the write path never stores it,
				-- this is defense-in-depth so the aggregate can't diverge from list/detail.
				(d.backup_status IS NOT NULL AND d.backup_status <> 'null'::jsonb) AS backup_has_status,
				COALESCE((d.backup_status->>'sync_only')::boolean, false)        AS backup_sync_only,
				COALESCE((d.backup_status->>'has_backup')::boolean, false)       AS backup_has_backup,
				(d.backup_status->>'last_backup_days_ago')::int                  AS backup_days_ago,
				COUNT(*) FILTER (WHERE le.status = 'pass')::float                              AS pass_ct,
				COUNT(*) FILTER (WHERE le.status IN ('pass','fail','error'))::float             AS denom,
				-- PAT-1776: a 'fail' row with no observed value is unreadable
				-- evidence, not a real observation of non-compliance — same
				-- predicate as isUndeterminedEval (internal/report/pdf.go).
				-- Excluded from crit_high; denom above is unaffected (still
				-- counts every fail row) so it stays in the pct denominator.
				COALESCE(SUM(CASE WHEN le.status = 'fail'
				                   AND le.observed_value IS NOT NULL
				                   AND le.severity IN ('critical','high') THEN 1 ELSE 0 END), 0)::int
				                                                                                AS crit_high,
				COALESCE(SUM(CASE WHEN le.status = 'fail'
				                   AND le.observed_value IS NULL
				                   AND le.severity IN ('critical','high') THEN 1 ELSE 0 END), 0)::int
				                                                                                AS undetermined_crit_high
			FROM eligible el
			JOIN devices d ON d.id = el.device_id
			LEFT JOIN latest_evals le ON le.device_id = el.device_id
			GROUP BY el.tenant_id, el.device_id, el.last_seen, d.backup_status
		),
		-- PAT-1686: total device count and 7-day-active count, UNFILTERED by
		-- the per-OS master switch — same population FetchTenantDevices
		-- returns as its Total. See the function doc comment above for why
		-- these two must not reuse the eligible-devices filter that
		-- device_comp/tenant_agg apply for compliance scoring.
		tenant_totals AS (
			SELECT
				d.tenant_id,
				COUNT(*)::int                                                       AS total_devices,
				COUNT(*) FILTER (WHERE d.last_seen > now() - interval '7 days')::int AS active_7d
			FROM devices d
			JOIN tenant_data td ON td.id = d.tenant_id
			GROUP BY d.tenant_id
		),
		tenant_agg AS (
			SELECT
				tenant_id,
				AVG(CASE WHEN denom > 0 THEN pass_ct / denom * 100.0 ELSE NULL END)   AS avg_pct,
				COALESCE(SUM(crit_high), 0)::int                                       AS total_crit_high,
				COALESCE(SUM(undetermined_crit_high), 0)::int                          AS total_undetermined_crit_high,
				-- Backup aggregate counts (PAT-948). Bucket rule MUST stay in
				-- lockstep with report.BackupBucket (report.go): sync_only
				-- checked first (never counted as backed up even though it also
				-- has backup_has_backup=false); then none (no backup at all);
				-- then stale (has_backup, >= 7 days); else ok (has_backup and
				-- either < 7 days, or no known last-backup timestamp at all).
				COALESCE(SUM(CASE WHEN backup_has_status AND backup_sync_only
				                  THEN 1 ELSE 0 END), 0)::int                          AS backup_sync_only_ct,
				COALESCE(SUM(CASE WHEN backup_has_status AND NOT backup_sync_only
				                       AND NOT backup_has_backup
				                  THEN 1 ELSE 0 END), 0)::int                          AS backup_none_ct,
				COALESCE(SUM(CASE WHEN backup_has_status AND NOT backup_sync_only
				                       AND backup_has_backup AND backup_days_ago >= 7
				                  THEN 1 ELSE 0 END), 0)::int                          AS backup_stale_ct,
				COALESCE(SUM(CASE WHEN backup_has_status AND NOT backup_sync_only
				                       AND backup_has_backup
				                       AND (backup_days_ago IS NULL OR backup_days_ago < 7)
				                  THEN 1 ELSE 0 END), 0)::int                          AS backup_ok_ct
			FROM device_comp
			GROUP BY tenant_id
		),
		new_apps_pending AS (
			SELECT tenant_id, COUNT(*)::int AS pending_count
			FROM tenant_new_apps
			WHERE decision IS NULL
			GROUP BY tenant_id
		)
		SELECT
			td.id::text, td.name, td.tier, td.tenant_kind, td.macos_enabled, td.windows_enabled,
			COALESCE(tt.total_devices,   0)::int,
			COALESCE(tt.active_7d,       0)::int,
			COALESCE(ta.avg_pct,         0.0)::float,
			COALESCE(ta.total_crit_high, 0)::int,
			COALESCE(ta.total_undetermined_crit_high, 0)::int,
			COALESCE(nap.pending_count,  0)::int,
			td.is_trial,
			td.trial_expires_at,
			td.health_score,
			td.health_bucket,
			td.health_score_computed_at,
			td.compliance_score_current,
			td.compliance_score_30d_ago,
			td.last_dashboard_login_at,
			COALESCE(td.dashboard_logins_last_30d, 0)::int,
			COALESCE(td.payment_failed, false),
			COALESCE(ta.backup_ok_ct,        0)::int,
			COALESCE(ta.backup_stale_ct,     0)::int,
			COALESCE(ta.backup_none_ct,      0)::int,
			COALESCE(ta.backup_sync_only_ct, 0)::int
		FROM tenant_data td
		LEFT JOIN tenant_agg ta ON ta.tenant_id = td.id
		LEFT JOIN tenant_totals tt ON tt.tenant_id = td.id
		LEFT JOIN new_apps_pending nap ON nap.tenant_id = td.id
		ORDER BY td.name
	`)
	if err != nil {
		return nil, fmt.Errorf("fetch tenants overview: %w", err)
	}
	defer rows.Close()

	var result []TenantOverview
	for rows.Next() {
		var t TenantOverview
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Tier, &t.TenantKind, &t.MacOSEnabled, &t.WindowsEnabled,
			&t.DeviceCount, &t.ActiveLast7d, &t.CompliancePct, &t.CritHighFails,
			&t.UndeterminedCritHighFails,
			&t.NewAppsAwaitingDecision,
			&t.IsTrial, &t.TrialExpiresAt,
			&t.HealthScore, &t.HealthBucket, &t.HealthScoreComputedAt,
			&t.ComplianceScoreCurrent, &t.ComplianceScore30dAgo,
			&t.LastDashboardLoginAt, &t.DashboardLoginsLast30d, &t.PaymentFailed,
			&t.BackupOK, &t.BackupStale, &t.BackupNone, &t.BackupSyncOnly,
		); err != nil {
			return nil, fmt.Errorf("scan tenant overview row: %w", err)
		}
		result = append(result, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant overview rows: %w", err)
	}
	return result, nil
}

// fetchPlatformSwitches returns the per-OS master-switch state for a tenant.
// Returns ErrTenantNotFound when the tenant row doesn't exist.
func fetchPlatformSwitches(ctx context.Context, pool *pgxpool.Pool, tenantID string) (platformSwitches, error) {
	var sw platformSwitches
	err := pool.QueryRow(ctx, `
		SELECT macos_enabled, windows_enabled
		FROM tenants WHERE id = $1::uuid
	`, tenantID).Scan(&sw.macOSEnabled, &sw.windowsEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return sw, ErrTenantNotFound
	}
	if err != nil {
		return sw, fmt.Errorf("fetch platform switches: %w", err)
	}
	return sw, nil
}

// FetchTenantDevices returns devices and per-device compliance summaries for a
// tenant. Unlike the report-aggregation queries, this list is NOT filtered by
// the per-OS master switch (PAT-745): devices on a disabled platform are still
// actively ingested/updated by the extractor, so hiding them here would cost
// operators visibility of endpoints that are still reporting. Instead, each
// returned row is annotated with EvaluationDisabled so callers can surface an
// indicator without losing the device from the roster.
func FetchTenantDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int) (TenantDevicesResult, error) {
	return fetchTenantDevices(ctx, pool, tenantID, limit, offset, "")
}

// fetchTenantDevices is FetchTenantDevices with an optional single-device
// scope. onlyDeviceID "" is the unscoped roster and produces exactly the
// query text FetchTenantDevices always ran. A non-empty onlyDeviceID (a UUID
// the caller has already validated) narrows both the latest-evaluation CTE and
// the device list to that one device, still inside the tenant, so the portal
// device page reads its summary figures from the same query the roster does
// (PAT-2294).
func fetchTenantDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int, onlyDeviceID string) (TenantDevicesResult, error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return TenantDevicesResult{}, err
	}

	args := []any{tenantID, limit, offset}
	latestScope, deviceScope := "", ""
	if onlyDeviceID != "" {
		latestScope = "\n\t\t\t  AND d.id = $4::uuid"
		deviceScope = "\n\t\t  AND d.id = $4::uuid"
		args = append(args, onlyDeviceID)
	}

	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.status, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1::uuid`+latestScope+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		),
		device_comp AS (
			SELECT
				device_id,
				COUNT(*) FILTER (WHERE status = 'pass')::int                                       AS pass_count,
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NOT NULL)::int         AS fail_count,
				COUNT(*) FILTER (WHERE status = 'not_applicable')::int                              AS na_count,
				COUNT(*) FILTER (WHERE status = 'error')::int                                       AS error_count,
				-- PAT-1758/PAT-1762: a 'fail' row with no observed value is
				-- unreadable evidence (absent signal, or the collector's
				-- "Unknown" sentinel), not a real observation of
				-- non-compliance. Excluded from fail_count above; reported
				-- separately so it is never silently folded into either
				-- "failing" or dropped.
				COUNT(*) FILTER (WHERE status = 'fail' AND observed_value IS NULL)::int             AS undetermined_count
			FROM latest
			GROUP BY device_id
		)
		SELECT
			d.id::text,
			COALESCE(d.hostname, ''),
			COALESCE(d.serial, ''),
			COALESCE(d.os, ''),
			COALESCE(d.os_version, ''),
			d.last_seen,
			COALESCE(d.primary_user_account, ''),
			COALESCE(d.primary_user_display, ''),
			COALESCE(dc.pass_count,  0),
			COALESCE(dc.fail_count,  0),
			COALESCE(dc.na_count,    0),
			COALESCE(dc.error_count, 0),
			COALESCE(dc.undetermined_count, 0),
			dh.id IS NOT NULL,
			dh.battery_max_capacity_pct, dh.battery_condition, dh.battery_cycle_count,
			sv.free_bytes, sv.used_pct, dsk.smart_status,
			d.backup_status::text,
			COALESCE(d.device_class, ''),
			COALESCE(d.os_caption, ''),
			COUNT(*) OVER()::int
		FROM devices d
		LEFT JOIN device_comp dc ON dc.device_id = d.id
		LEFT JOIN device_hardware dh ON dh.device_id = d.id
		LEFT JOIN LATERAL (
			SELECT v.free_bytes, v.used_pct
			FROM device_storage_volume v
			WHERE v.device_hardware_id = dh.id AND v.mount IN ('/', 'C:\')
			LIMIT 1
		) sv ON true
		LEFT JOIN LATERAL (
			SELECT k.smart_status
			FROM device_disk k
			WHERE k.device_hardware_id = dh.id AND k.internal = true
			ORDER BY (k.smart_status <> 'Verified') DESC
			LIMIT 1
		) dsk ON true
		WHERE d.tenant_id = $1::uuid`+deviceScope+`
		ORDER BY d.hostname NULLS LAST, d.id
		LIMIT $2 OFFSET $3
	`, args...)
	if err != nil {
		return TenantDevicesResult{}, fmt.Errorf("fetch tenant devices: %w", err)
	}
	defer rows.Close()

	var res TenantDevicesResult
	for rows.Next() {
		var row TenantDeviceRow
		var total int
		var backupStatusRaw []byte
		if err := rows.Scan(
			&row.ID, &row.Hostname, &row.Serial,
			&row.OS, &row.OSVersion, &row.LastSeen,
			&row.PrimaryUserAccount, &row.PrimaryUserDisplay,
			&row.PassCount, &row.FailCount, &row.NACount, &row.ErrorCount,
			&row.UndeterminedCount,
			&row.HasHardware,
			&row.BatteryMaxCapacityPct, &row.BatteryCondition, &row.BatteryCycleCount,
			&row.StorageFreeBytes, &row.StorageUsedPct, &row.SMARTStatus,
			&backupStatusRaw,
			&row.StoredDeviceClass, &row.StoredOSCaption,
			&total,
		); err != nil {
			return TenantDevicesResult{}, fmt.Errorf("scan device row: %w", err)
		}
		res.Total = total
		// PAT-1762: Undetermined stays IN the percentage denominator (missing
		// evidence must never raise the score) even though it is excluded
		// from FailCount's headline "failing" count above.
		row.CompliancePct = DeviceCompliancePct(row.PassCount, row.FailCount+row.UndeterminedCount, row.ErrorCount)
		row.EvaluationDisabled = osEvaluationDisabled(sw, row.OS)
		// backup_status JSONB — non-fatal decode, same posture as report.Fetch:
		// a malformed stored value just leaves BackupStatus nil rather than
		// failing the whole roster page. Stale is server-derived inside the
		// decoder (see DecodeDeviceBackupStatus).
		row.BackupStatus = DecodeDeviceBackupStatus(backupStatusRaw)
		res.Devices = append(res.Devices, row)
	}
	if err := rows.Err(); err != nil {
		return TenantDevicesResult{}, fmt.Errorf("iterate device rows: %w", err)
	}
	return res, nil
}

// FetchTenantFindings returns failing and error evaluations across a tenant's
// fleet, ordered critical-first. Respects the per-OS master switch. Supports
// offset-based pagination.
func FetchTenantFindings(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int) (TenantFindingsResult, error) {
	sw, err := fetchPlatformSwitches(ctx, pool, tenantID)
	if err != nil {
		return TenantFindingsResult{}, err
	}
	osFilter := enabledOSFilter(sw)

	// PAT-1776: a 'fail' row with no observed value is unreadable evidence
	// (an absent signal, or the collector's literal "Unknown" sentinel), not
	// a real observation of non-compliance — same predicate as
	// isUndeterminedEval (internal/report/pdf.go). There is nothing to
	// remediate for such a row, so it is excluded from the findings list
	// below and counted separately instead (see the undetermined_count query
	// after this one). An "error" row is never undetermined by this rule and
	// stays a real finding. A "NotConfigured" fail has a non-nil observed
	// value and stays a real finding too.
	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.device_id, e.rule_id, e.status, e.severity, e.evaluated_at, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1::uuid
			  AND `+osFilter+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		),
		findings AS (
			SELECT
				l.device_id,
				COALESCE(d.hostname, '') AS hostname,
				r.rule_key,
				r.title,
				l.severity,
				l.status,
				l.evaluated_at
			FROM latest l
			JOIN devices d ON d.id = l.device_id
			JOIN compliance_rules r ON r.id = l.rule_id
			WHERE l.status = 'error'
			   OR (l.status = 'fail' AND l.observed_value IS NOT NULL)
		)
		SELECT
			device_id::text, hostname, rule_key, title, severity, status, evaluated_at,
			COUNT(*) OVER()::int
		FROM findings
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high'     THEN 2
				WHEN 'medium'   THEN 3
				WHEN 'low'      THEN 4
				ELSE 5
			END,
			CASE status
				WHEN 'fail'  THEN 1
				WHEN 'error' THEN 2
				ELSE 3
			END,
			rule_key, device_id
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return TenantFindingsResult{}, fmt.Errorf("fetch tenant findings: %w", err)
	}
	defer rows.Close()

	var res TenantFindingsResult
	for rows.Next() {
		var f TenantFindingRow
		var total int
		if err := rows.Scan(
			&f.DeviceID, &f.Hostname, &f.RuleKey, &f.Title,
			&f.Severity, &f.Status, &f.EvaluatedAt,
			&total,
		); err != nil {
			return TenantFindingsResult{}, fmt.Errorf("scan finding row: %w", err)
		}
		res.Total = total
		res.Findings = append(res.Findings, f)
	}
	if err := rows.Err(); err != nil {
		return TenantFindingsResult{}, fmt.Errorf("iterate finding rows: %w", err)
	}

	// Separate scalar query for the undetermined count: the findings query
	// above is paginated (LIMIT/OFFSET), so COUNT(*) OVER() there only ever
	// reflects the "real findings" total, never the excluded undetermined
	// rows.
	if err := pool.QueryRow(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (e.device_id, e.rule_id)
				e.status, e.observed_value
			FROM compliance_evaluations e
			JOIN devices d ON d.id = e.device_id
			WHERE d.tenant_id = $1::uuid
			  AND `+osFilter+`
			ORDER BY e.device_id, e.rule_id, e.evaluated_at DESC
		)
		SELECT COUNT(*)::int FROM latest
		WHERE status = 'fail' AND observed_value IS NULL
	`, tenantID).Scan(&res.UndeterminedCount); err != nil {
		return TenantFindingsResult{}, fmt.Errorf("count undetermined findings: %w", err)
	}

	return res, nil
}

// DeviceCompliancePct returns the compliance percentage for a device given its
// pass, fail, and error counts. NA evaluations are excluded from the denominator
// (same formula as Report.Summary.CompliancePct).
func DeviceCompliancePct(pass, fail, errCount int) float64 {
	denom := pass + fail + errCount
	if denom == 0 {
		return 0
	}
	return float64(pass) / float64(denom) * 100.0
}
