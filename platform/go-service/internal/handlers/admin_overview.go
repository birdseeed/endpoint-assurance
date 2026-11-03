package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

const (
	defaultPageLimit = 500
	maxPageLimit     = 500
)

// ---------------------------------------------------------------------------
// GET /admin/tenants/overview
// ---------------------------------------------------------------------------

type tenantOverviewEntry struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Tier           string  `json:"tier"`
	TenantKind     string  `json:"tenant_kind"`
	MacOSEnabled   bool    `json:"macos_enabled"`
	WindowsEnabled bool    `json:"windows_enabled"`
	DeviceCount    int     `json:"device_count"`
	ActiveLast7d   int     `json:"active_last_7d"`
	CompliancePct  float64 `json:"compliance_pct"`
	CritHighFails  int     `json:"crit_high_fail_count"`
	// UndeterminedCritHighFails is the count of eligible devices' latest
	// critical/high evaluations that could not be determined (PAT-1758/
	// PAT-1762/PAT-1776) — unreadable evidence, not a real fail. Excluded
	// from CritHighFails above; reported here so it is never silently
	// dropped.
	UndeterminedCritHighFails int        `json:"undetermined_crit_high_fail_count"`
	NewAppsAwaitingDecision   int        `json:"new_apps_awaiting_decision"`
	IsTrial                   bool       `json:"is_trial"`
	TrialExpiresAt            *time.Time `json:"trial_expires_at,omitempty"`

	// Health-score fields (PAT-677 / migration 0065). Null until first nightly run.
	HealthScore           *int       `json:"health_score"`
	HealthBucket          *string    `json:"health_bucket"`
	HealthScoreComputedAt *time.Time `json:"health_score_computed_at"`

	// PAT-676 engagement signals (migration 0063).
	ComplianceScoreCurrent *int       `json:"compliance_score_current"`
	ComplianceScore30dAgo  *int       `json:"compliance_score_30d_ago"`
	LastDashboardLoginAt   *time.Time `json:"last_dashboard_login_at"`
	DashboardLoginsLast30d int        `json:"dashboard_logins_last_30d"`
	PaymentFailed          bool       `json:"payment_failed"`

	// Backup status aggregate (PAT-679/680 agents; PAT-948 server ingestion;
	// PAT-673 fleet overview consumer). Counts partition eligible devices that
	// HAVE reported backup_status — a device whose agent predates PAT-679/680
	// contributes to none of the four buckets. See report.BackupBucket for
	// the rule.
	BackupStatusCounts tenantBackupStatusCounts `json:"backup_status_counts"`
}

// tenantBackupStatusCounts is the per-tenant partition of eligible devices
// across the four PAT-948 backup buckets (report.BackupBucket).
type tenantBackupStatusCounts struct {
	OK       int `json:"ok"`
	Stale    int `json:"stale"`
	None     int `json:"none"`
	SyncOnly int `json:"sync_only"`
}

type tenantsOverviewResp struct {
	Tenants []tenantOverviewEntry `json:"tenants"`
}

// TenantsOverviewHandler returns a summary row for every non-revoked tenant:
// id, name, tier, platform switches, device count, active-7d count, overall
// compliance %, and critical+high fail count. Device count and active-7d
// count are the tenant's actual total (same population as
// GET /admin/tenants/{id}/devices' Total); compliance % and crit+high fail
// count respect each tenant's per-OS master switches (PAT-1686 — see
// report.FetchTenantsOverview's doc comment for why these are deliberately
// different populations).
//
// Route: GET /admin/tenants/overview   (internal listener :8081)
func TenantsOverviewHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenants_overview")

		tenants, err := report.FetchTenantsOverview(r.Context(), pool)
		if err != nil {
			logger.Error("fetch tenants overview failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		entries := make([]tenantOverviewEntry, len(tenants))
		for i, t := range tenants {
			entries[i] = tenantOverviewEntry{
				ID:                        t.ID,
				Name:                      t.Name,
				Tier:                      t.Tier,
				TenantKind:                t.TenantKind,
				MacOSEnabled:              t.MacOSEnabled,
				WindowsEnabled:            t.WindowsEnabled,
				DeviceCount:               t.DeviceCount,
				ActiveLast7d:              t.ActiveLast7d,
				CompliancePct:             t.CompliancePct,
				CritHighFails:             t.CritHighFails,
				UndeterminedCritHighFails: t.UndeterminedCritHighFails,
				NewAppsAwaitingDecision:   t.NewAppsAwaitingDecision,
				IsTrial:                   t.IsTrial,
				TrialExpiresAt:            t.TrialExpiresAt,
				HealthScore:               t.HealthScore,
				HealthBucket:              t.HealthBucket,
				HealthScoreComputedAt:     t.HealthScoreComputedAt,
				ComplianceScoreCurrent:    t.ComplianceScoreCurrent,
				ComplianceScore30dAgo:     t.ComplianceScore30dAgo,
				LastDashboardLoginAt:      t.LastDashboardLoginAt,
				DashboardLoginsLast30d:    t.DashboardLoginsLast30d,
				PaymentFailed:             t.PaymentFailed,
				BackupStatusCounts: tenantBackupStatusCounts{
					OK:       t.BackupOK,
					Stale:    t.BackupStale,
					None:     t.BackupNone,
					SyncOnly: t.BackupSyncOnly,
				},
			}
		}
		if entries == nil {
			entries = []tenantOverviewEntry{}
		}

		logger.Info("tenants overview served", "count", len(entries))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantsOverviewResp{Tenants: entries})
	}
}

// ---------------------------------------------------------------------------
// PUT /admin/tenants/{tenantID}/kind
// ---------------------------------------------------------------------------

type tenantKindPutReq struct {
	TenantKind string `json:"tenant_kind"`
}

type tenantKindPutResp struct {
	TenantID   string `json:"tenant_id"`
	TenantKind string `json:"tenant_kind"`
}

// TenantKindPutHandler sets a tenant's tenant_kind ("customer" or
// "internal"), used by the dashboard to de-emphasize non-customer tenants
// (PAT-1562) and to exclude them from the stalest-tenant ingest-lag signal
// (health_admin.go, PAT-1541).
//
// Route: PUT /admin/tenants/{tenantID}/kind   (internal listener :8081)
func TenantKindPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_kind_put")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<10)) // 1 KB is plenty
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req tenantKindPutReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.TenantKind != "customer" && req.TenantKind != "internal" {
			http.Error(w, `{"error":"tenant_kind must be customer or internal"}`, http.StatusBadRequest)
			return
		}

		tag, err := pool.Exec(r.Context(), `
			UPDATE tenants SET tenant_kind = $1
			WHERE id = $2::uuid AND revoked_at IS NULL
		`, req.TenantKind, tenantID)
		if err != nil {
			logger.Error("tenant kind update failed", "tenant_id", tenantID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tag.RowsAffected() == 0 {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		logger.Info("tenant kind updated", "tenant_id", tenantID, "tenant_kind", req.TenantKind)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantKindPutResp{TenantID: tenantID, TenantKind: req.TenantKind})
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/devices
// ---------------------------------------------------------------------------

type deviceComplianceSummary struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"not_applicable"`
	Error         int `json:"error"`
	// Undetermined is unreadable evidence (PAT-1758/PAT-1762): a latest
	// evaluation that resolved to fail with no observed value. Excluded from
	// Fail; kept in CompliancePct's denominator. Reported here rather than
	// silently dropped now that it no longer counts toward Fail.
	Undetermined  int     `json:"undetermined"`
	CompliancePct float64 `json:"compliance_pct"`
}

type tenantDeviceEntry struct {
	ID                 string                  `json:"id"`
	Hostname           string                  `json:"hostname"`
	Serial             string                  `json:"serial"`
	OS                 string                  `json:"os"`
	OSVersion          string                  `json:"os_version"`
	LastSeen           time.Time               `json:"last_seen"`
	PrimaryUserAccount string                  `json:"primary_user_account,omitempty"`
	PrimaryUserDisplay string                  `json:"primary_user_display,omitempty"`
	Compliance         deviceComplianceSummary `json:"compliance"`
	Hardware           *deviceHardwareSummary  `json:"hardware,omitempty"`
	Backup             *deviceBackupSummary    `json:"backup,omitempty"`

	// EvaluationDisabled is true when this device's OS master switch is off
	// for the tenant (PAT-745). The device stays in the roster — only its
	// compliance evaluation/scoring is suppressed — so the dashboard can
	// surface an indicator instead of the device silently vanishing.
	EvaluationDisabled bool `json:"evaluation_disabled"`
}

// deviceHardwareSummary is the per-device hardware-health digest for the
// fleet roster (PAT-686). Present only when the device has reported hardware
// data; flag applies the decided thresholds (battery <70%, <10 GB free,
// non-Verified SMART).
type deviceHardwareSummary struct {
	BatteryMaxCapacityPct *int    `json:"battery_max_capacity_pct,omitempty"`
	BatteryCondition      *string `json:"battery_condition,omitempty"`
	BatteryCycleCount     *int    `json:"battery_cycle_count,omitempty"`
	StorageFreeBytes      *int64  `json:"storage_free_bytes,omitempty"`
	SMARTStatus           *string `json:"smart_status,omitempty"`
	Flag                  bool    `json:"flag"`
}

// deviceBackupSummary is the per-device backup-status digest for the fleet
// roster (PAT-679/680 agents; PAT-948). Present only when the device has
// reported backup_status at least once; Bucket applies report.BackupBucket's
// rule ("ok" | "stale" | "none" | "sync_only").
type deviceBackupSummary struct {
	HasBackup         bool    `json:"has_backup"`
	BackupType        *string `json:"backup_type,omitempty"`
	LastBackupAt      *string `json:"last_backup_at,omitempty"`
	LastBackupDaysAgo *int    `json:"last_backup_days_ago,omitempty"`
	Stale             bool    `json:"stale"`
	SyncOnly          bool    `json:"sync_only"`
	Notes             *string `json:"notes,omitempty"`
	Bucket            string  `json:"bucket"`
}

type tenantDevicesResp struct {
	TenantID string              `json:"tenant_id"`
	Total    int                 `json:"total"`
	Limit    int                 `json:"limit"`
	Offset   int                 `json:"offset"`
	Devices  []tenantDeviceEntry `json:"devices"`
}

// TenantDevicesHandler returns the fleet roster for a tenant with per-device
// compliance summaries. Supports ?limit and ?offset (default limit 500, max 500).
//
// Route: GET /admin/tenants/{tenantID}/devices   (internal listener :8081)
func TenantDevicesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_devices")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		limit, offset := parsePagination(r)

		result, err := report.FetchTenantDevices(r.Context(), pool, tenantID, limit, offset)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch tenant devices failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		devices := make([]tenantDeviceEntry, len(result.Devices))
		for i, d := range result.Devices {
			devices[i] = tenantDeviceEntry{
				ID:                 d.ID,
				Hostname:           d.Hostname,
				Serial:             d.Serial,
				OS:                 d.OS,
				OSVersion:          d.OSVersion,
				LastSeen:           d.LastSeen,
				PrimaryUserAccount: d.PrimaryUserAccount,
				PrimaryUserDisplay: d.PrimaryUserDisplay,
				Compliance: deviceComplianceSummary{
					Pass:          d.PassCount,
					Fail:          d.FailCount,
					NotApplicable: d.NACount,
					Error:         d.ErrorCount,
					Undetermined:  d.UndeterminedCount,
					CompliancePct: d.CompliancePct,
				},
				EvaluationDisabled: d.EvaluationDisabled,
			}
			if d.HasHardware {
				devices[i].Hardware = &deviceHardwareSummary{
					BatteryMaxCapacityPct: d.BatteryMaxCapacityPct,
					BatteryCondition:      d.BatteryCondition,
					BatteryCycleCount:     d.BatteryCycleCount,
					StorageFreeBytes:      d.StorageFreeBytes,
					SMARTStatus:           d.SMARTStatus,
					Flag:                  d.HardwareFlag(),
				}
			}
			if bs := d.BackupStatus; bs != nil {
				devices[i].Backup = &deviceBackupSummary{
					HasBackup:         bs.HasBackup,
					BackupType:        bs.BackupType,
					LastBackupAt:      bs.LastBackupAt,
					LastBackupDaysAgo: bs.LastBackupDaysAgo,
					Stale:             bs.Stale,
					SyncOnly:          bs.SyncOnly,
					Notes:             bs.Notes,
					Bucket:            d.BackupBucket(),
				}
			}
		}
		if devices == nil {
			devices = []tenantDeviceEntry{}
		}

		logger.Info("tenant devices served", "tenant_id", tenantID, "count", len(devices))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantDevicesResp{
			TenantID: tenantID,
			Total:    result.Total,
			Limit:    limit,
			Offset:   offset,
			Devices:  devices,
		})
	}
}

// ---------------------------------------------------------------------------
// GET /admin/devices/{deviceID}
// ---------------------------------------------------------------------------

type deviceComplianceJSON struct {
	Total         int     `json:"total"`
	Pass          int     `json:"pass"`
	Fail          int     `json:"fail"`
	NotApplicable int     `json:"not_applicable"`
	Error         int     `json:"error"`
	CompliancePct float64 `json:"compliance_pct"`
}

type deviceDetailEval struct {
	RuleKey       string    `json:"rule_key"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	ObservedValue *string   `json:"observed_value"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

type deviceDetailPendingUpdate struct {
	Label       string `json:"label"`
	Title       string `json:"title"`
	Version     string `json:"version"`
	Action      string `json:"action,omitempty"`
	Recommended bool   `json:"recommended"`
}

type deviceDetailPatch struct {
	Title         string     `json:"title"`
	Identifier    string     `json:"identifier"`
	InstalledAt   *time.Time `json:"installed_at"`
	Outcome       string     `json:"outcome,omitempty"`
	FailureReason string     `json:"failure_reason,omitempty"`
}

type deviceDetailInfo struct {
	ID                    string     `json:"id"`
	Serial                string     `json:"serial"`
	HWUUID                string     `json:"hw_uuid"`
	Hostname              string     `json:"hostname"`
	ComputerName          string     `json:"computer_name"`
	HWModel               string     `json:"hw_model"`
	Arch                  string     `json:"arch"`
	OS                    string     `json:"os"`
	OSVersion             string     `json:"os_version"`
	OSBuild               string     `json:"os_build"`
	AgentVersion          string     `json:"agent_version"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
	PrimaryUserAccount    string     `json:"primary_user_account,omitempty"`
	PrimaryUserDisplay    string     `json:"primary_user_display,omitempty"`
	PrimaryUserLastSeenAt *time.Time `json:"primary_user_last_seen_at,omitempty"`
}

// deviceDetailResp is the JSON response for GET /admin/devices/{deviceID}.
// Fields are omitted (not null) when absent so the frontend can use a simple
// presence check (if resp.hardware) rather than checking for explicit nulls.
type deviceDetailResp struct {
	GeneratedAt       time.Time                       `json:"generated_at"`
	Tenant            string                          `json:"tenant"`
	Device            deviceDetailInfo                `json:"device"`
	Compliance        deviceComplianceJSON            `json:"compliance"`
	Evaluations       []deviceDetailEval              `json:"evaluations"`
	PendingUpdates    []deviceDetailPendingUpdate     `json:"pending_updates"`
	PatchHistory      []deviceDetailPatch             `json:"patch_history"`
	AppCount          int                             `json:"app_count"`
	Hardware          *report.DeviceHardware          `json:"hardware,omitempty"`
	HardwareHealth    *report.DeviceHardwareHealth    `json:"hardware_health,omitempty"`
	SecurityInventory *report.DeviceSecurityInventory `json:"security_inventory,omitempty"`
	Backup            *deviceDetailBackup             `json:"backup,omitempty"`
	RawSignals        []report.DeviceRawSignal        `json:"raw_signals,omitempty"`
	// AgentHealthDegraded (PAT-2099): this device's currently open
	// degraded-capability entries (PAT-1064's agent_health.degraded
	// channel), unscoped by tenant — this endpoint already is. Empty
	// (never null) when the device has no open faults.
	AgentHealthDegraded []report.DeviceAgentHealthEntry `json:"agent_health_degraded"`
}

// deviceDetailBackup wraps report.DeviceBackupStatus with the derived bucket
// (PAT-948) so the dashboard doesn't have to re-implement report.BackupBucket
// client-side.
type deviceDetailBackup struct {
	report.DeviceBackupStatus
	Bucket string `json:"bucket"`
}

// DeviceDetailHandler returns the full compliance posture and identity
// metadata for one device as JSON (same data as the PDF compliance report).
//
// Route: GET /admin/devices/{deviceID}   (internal listener :8081)
func DeviceDetailHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_detail")

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		rep, err := report.Fetch(r.Context(), pool, deviceID)
		if err != nil {
			if errors.Is(err, report.ErrDeviceNotFound) {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch device detail failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		evals := make([]deviceDetailEval, len(rep.Evaluations))
		for i, e := range rep.Evaluations {
			evals[i] = deviceDetailEval{
				RuleKey:       e.RuleKey,
				Title:         e.Title,
				Severity:      e.Severity,
				Status:        e.Status,
				ObservedValue: e.ObservedValue,
				EvaluatedAt:   e.EvaluatedAt,
			}
		}

		pending := make([]deviceDetailPendingUpdate, len(rep.PendingUpdates))
		for i, p := range rep.PendingUpdates {
			pending[i] = deviceDetailPendingUpdate{
				Label:       p.Label,
				Title:       p.Title,
				Version:     p.Version,
				Action:      p.Action,
				Recommended: p.Recommended,
			}
		}

		// The JSON device-detail response is the one consumer that wants the
		// combined, outcome-aware view — OS-patch rows (rep.PatchHistory) and
		// provenance-sourced third-party update attempts
		// (rep.ProvenancePatchHistory) merged newest-first. Deliberately NOT
		// done inside report.Fetch itself: rep.PatchHistory alone also feeds
		// the PDF renderer's OS-update-only section, and a failed third-party
		// install merged in there would render as a successful, dated OS
		// update in a customer-facing document (see
		// Report.ProvenancePatchHistory's doc comment).
		combinedPatches := report.MergePatchHistory(rep.PatchHistory, rep.ProvenancePatchHistory)
		patches := make([]deviceDetailPatch, len(combinedPatches))
		for i, p := range combinedPatches {
			patches[i] = deviceDetailPatch{
				Title:         p.Title,
				Identifier:    p.Identifier,
				InstalledAt:   p.InstalledAt,
				Outcome:       p.Outcome,
				FailureReason: p.FailureReason,
			}
		}

		// Fetch primary_user fields (not in report.Fetch to keep PDF path clean).
		var primaryUserAccount, primaryUserDisplay string
		var primaryUserLastSeenAt *time.Time
		_ = pool.QueryRow(r.Context(), `
			SELECT
				COALESCE(primary_user_account, ''),
				COALESCE(primary_user_display, ''),
				primary_user_last_seen_at
			FROM devices WHERE id = $1
		`, deviceID).Scan(&primaryUserAccount, &primaryUserDisplay, &primaryUserLastSeenAt)

		agentHealth, err := report.FetchDeviceAgentHealth(r.Context(), pool, deviceID)
		if err != nil {
			logger.Error("fetch device agent health failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		s := rep.Summary()
		resp := deviceDetailResp{
			GeneratedAt: rep.GeneratedAt,
			Tenant:      rep.Tenant,
			Device: deviceDetailInfo{
				ID:                    rep.Device.ID,
				Serial:                rep.Device.Serial,
				HWUUID:                rep.Device.HWUUID,
				Hostname:              rep.Device.Hostname,
				ComputerName:          rep.Device.ComputerName,
				HWModel:               rep.Device.HWModel,
				Arch:                  rep.Device.Arch,
				OS:                    rep.Device.OS,
				OSVersion:             rep.Device.OSVersion,
				OSBuild:               rep.Device.OSBuild,
				AgentVersion:          rep.Device.AgentVersion,
				FirstSeen:             rep.Device.FirstSeen,
				LastSeen:              rep.Device.LastSeen,
				PrimaryUserAccount:    primaryUserAccount,
				PrimaryUserDisplay:    primaryUserDisplay,
				PrimaryUserLastSeenAt: primaryUserLastSeenAt,
			},
			Compliance: deviceComplianceJSON{
				Total:         s.Total,
				Pass:          s.Pass,
				Fail:          s.Fail,
				NotApplicable: s.NotApplicable,
				Error:         s.Error,
				CompliancePct: s.CompliancePct,
			},
			Evaluations:         evals,
			PendingUpdates:      pending,
			PatchHistory:        patches,
			AppCount:            len(rep.Apps),
			Hardware:            rep.Hardware,
			HardwareHealth:      rep.HardwareHealth,
			SecurityInventory:   rep.SecurityInventory,
			RawSignals:          rep.RawSignals,
			AgentHealthDegraded: agentHealth,
		}
		if rep.BackupStatus != nil {
			resp.Backup = &deviceDetailBackup{
				DeviceBackupStatus: *rep.BackupStatus,
				Bucket: report.BackupBucket(
					rep.BackupStatus.HasBackup,
					rep.BackupStatus.SyncOnly,
					rep.BackupStatus.LastBackupDaysAgo,
				),
			}
		}

		logger.Info("device detail served", "device_id", deviceID, "evaluations", len(evals))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/tenants/{tenantID}/findings
// ---------------------------------------------------------------------------

type findingEntry struct {
	DeviceID    string    `json:"device_id"`
	Hostname    string    `json:"hostname"`
	RuleKey     string    `json:"rule_key"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type tenantFindingsResp struct {
	TenantID string         `json:"tenant_id"`
	Total    int            `json:"total"`
	Limit    int            `json:"limit"`
	Offset   int            `json:"offset"`
	Findings []findingEntry `json:"findings"`
	// UndeterminedCount is the number of latest evaluations excluded from
	// Findings because they could not be determined (PAT-1758/PAT-1762/
	// PAT-1776) — unreadable evidence, not a real finding to remediate.
	// Reported here so the evidence gap is never silently dropped.
	UndeterminedCount int `json:"undetermined_count"`
}

// TenantFindingsHandler returns all failing and error evaluations across a
// tenant's fleet, ordered critical-first. Respects the per-OS platform switch.
// Supports ?limit and ?offset (default limit 500, max 500).
//
// Route: GET /admin/tenants/{tenantID}/findings   (internal listener :8081)
func TenantFindingsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "tenant_findings")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		limit, offset := parsePagination(r)

		result, err := report.FetchTenantFindings(r.Context(), pool, tenantID, limit, offset)
		if err != nil {
			if errors.Is(err, report.ErrTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("fetch tenant findings failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		findings := make([]findingEntry, len(result.Findings))
		for i, f := range result.Findings {
			findings[i] = findingEntry{
				DeviceID:    f.DeviceID,
				Hostname:    f.Hostname,
				RuleKey:     f.RuleKey,
				Title:       f.Title,
				Severity:    f.Severity,
				Status:      f.Status,
				EvaluatedAt: f.EvaluatedAt,
			}
		}
		if findings == nil {
			findings = []findingEntry{}
		}

		logger.Info("tenant findings served", "tenant_id", tenantID, "count", len(findings))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tenantFindingsResp{
			TenantID:          tenantID,
			Total:             result.Total,
			Limit:             limit,
			Offset:            offset,
			Findings:          findings,
			UndeterminedCount: result.UndeterminedCount,
		})
	}
}

// ── Device apps ─────────────────────────────────────────────────────────────

type deviceAppEntry struct {
	Name                  string     `json:"name"`
	Version               string     `json:"version"`
	Identifier            string     `json:"identifier"`
	Publisher             string     `json:"publisher"`
	Signer                string     `json:"signer"`
	TeamID                string     `json:"team_id"`
	Architecture          string     `json:"architecture"`
	Notarized             *bool      `json:"notarized"`
	SizeBytes             *int64     `json:"size_bytes"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
	LastUsedAt            *time.Time `json:"last_used_at"`
	LaunchCount           *int       `json:"launch_count"`
	UsageEvidence         *string    `json:"usage_evidence"`
	UsageEvidenceAt       *time.Time `json:"usage_evidence_at"`
	UsageEvidenceComplete *bool      `json:"usage_evidence_complete"`
}

type deviceAppsResp struct {
	DeviceID string           `json:"device_id"`
	Total    int              `json:"total"`
	Apps     []deviceAppEntry `json:"apps"`
}

// DeviceAppsHandler returns all apps installed on a device, ordered by name.
// Route: GET /admin/devices/{deviceID}/apps  (internal listener :8081)
func DeviceAppsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "device_apps")

		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(deviceID) {
			http.Error(w, "deviceID must be a UUID", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(r.Context(), `
            SELECT name, COALESCE(version,''), COALESCE(identifier,''),
                   COALESCE(publisher,''), COALESCE(signer,''), COALESCE(team_id,''),
                   COALESCE(architecture,''), notarized, size_bytes, first_seen, last_seen,
                   last_used_at, launch_count, usage_evidence, usage_evidence_at, usage_evidence_complete
            FROM device_apps
            WHERE device_id = $1
            ORDER BY name
        `, deviceID)
		if err != nil {
			logger.Error("query device apps failed", "err", err, "device_id", deviceID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var apps []deviceAppEntry
		for rows.Next() {
			var a deviceAppEntry
			if err := rows.Scan(&a.Name, &a.Version, &a.Identifier, &a.Publisher,
				&a.Signer, &a.TeamID, &a.Architecture, &a.Notarized,
				&a.SizeBytes, &a.FirstSeen, &a.LastSeen, &a.LastUsedAt, &a.LaunchCount, &a.UsageEvidence, &a.UsageEvidenceAt, &a.UsageEvidenceComplete); err != nil {
				logger.Error("scan device app row failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			apps = append(apps, a)
		}
		if err := rows.Err(); err != nil {
			logger.Error("device apps rows error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if apps == nil {
			apps = []deviceAppEntry{}
		}

		logger.Info("device apps served", "device_id", deviceID, "count", len(apps))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deviceAppsResp{DeviceID: deviceID, Total: len(apps), Apps: apps})
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// parsePagination extracts limit and offset from ?limit and ?offset query params.
// limit is clamped to [1, maxPageLimit]; offset must be >= 0.
// Invalid or missing params use the defaults (500 and 0 respectively).
func parsePagination(r *http.Request) (limit, offset int) {
	limit = defaultPageLimit
	offset = 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// ---------------------------------------------------------------------------
// DELETE /admin/tenants/{tenantID}/devices/{deviceID}
// ---------------------------------------------------------------------------

// DeleteDeviceHandler removes a device row and all associated data
// (compliance_signals, device_apps, compliance_evaluations) from the tenant's
// estate. Scoped by tenantID to prevent cross-tenant deletes.
//
// Route: DELETE /admin/tenants/{tenantID}/devices/{deviceID}   (internal :8081)
func DeleteDeviceHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		deviceID := strings.TrimSpace(chi.URLParam(r, "deviceID"))
		if !looksLikeUUID(tenantID) || !looksLikeUUID(deviceID) {
			http.Error(w, "invalid UUID", http.StatusBadRequest)
			return
		}

		// Verify the device belongs to this tenant before deleting.
		var owner string
		err := pool.QueryRow(r.Context(),
			`SELECT tenant_id::text FROM devices WHERE id = $1`, deviceID,
		).Scan(&owner)
		if err != nil {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		if owner != tenantID {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}

		// Delete in dependency order. Failures here are non-fatal for the
		// main devices row — log but continue so the device is always removed.
		_, _ = pool.Exec(r.Context(),
			`DELETE FROM compliance_evaluations WHERE device_id = $1`, deviceID)
		_, _ = pool.Exec(r.Context(),
			`DELETE FROM compliance_signals WHERE device_id = $1`, deviceID)
		_, _ = pool.Exec(r.Context(),
			`DELETE FROM device_apps WHERE device_id = $1`, deviceID)
		_, err = pool.Exec(r.Context(),
			`DELETE FROM devices WHERE id = $1`, deviceID)
		if err != nil {
			slog.Error("delete device failed", "device_id", deviceID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		slog.Info("device deleted", "tenant_id", tenantID, "device_id", deviceID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}
