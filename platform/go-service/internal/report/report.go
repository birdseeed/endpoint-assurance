// Package report renders a device's latest CIS L1 compliance posture as a
// printable PDF. Two entry points:
//
//	Fetch  — read device metadata + the latest evaluation per rule into a
//	         Report struct. Pure data, no presentation.
//	Render — turn a Report into a PDF byte slice using go-pdf/fpdf.
//
// They're split so callers (handler, future scheduled-export job, CLI) can
// reuse the data layer without dragging the PDF library along, and so tests
// can build a Report by hand and exercise the renderer without DB access.
package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrDeviceNotFound is returned when Fetch is called with a device ID that
// doesn't exist. Handler maps this to 404.
var ErrDeviceNotFound = errors.New("device not found")

// ComplianceFormatVersion is the version string stamped on compliance PDFs.
// Bump this when a structural field is added or removed from Report so
// digests don't silently span incompatible report shapes.
const ComplianceFormatVersion = "v2"

// Report is the rendered-ready view of one device's compliance posture.
type Report struct {
	GeneratedAt        time.Time
	Tenant             string
	Device             Device
	Evaluations        []EvalRow
	BenchmarkTotals    map[string]int // key = "benchmark||version"; total enabled rules per benchmark
	CVEFindings        []DeviceCVEFinding
	CatalogUpdates     []CatalogUpdate
	PendingUpdates     []PendingUpdate
	PatchHistory       []PatchHistoryItem
	Apps               []App
	ElevatedExtensions []BrowserExtensionRow

	// ProvenancePatchHistory is third-party app-update attempts sourced from
	// provenance_records (PAT-1007) — kept deliberately SEPARATE from
	// PatchHistory rather than merged in here. PatchHistory feeds
	// pdf.go's renderPatchHistory section, captioned "macOS Update History
	// ... From softwareupdate --history" in a customer-facing compliance
	// PDF; a provenance row (which can be a FAILED third-party install, e.g.
	// outcome "verification_failed") merged into that slice would render as
	// an ordinary dated OS-update row in that PDF — a failed install
	// reported to the customer as a successful one. Only a consumer that
	// explicitly wants the combined, outcome-aware view (today: the JSON
	// device-detail handler) should call MergePatchHistory itself.
	ProvenancePatchHistory []PatchHistoryItem

	// Extended fields — not used by the PDF renderer; surfaced on the API
	// device-detail endpoint.
	Hardware          *DeviceHardware
	HardwareHealth    *DeviceHardwareHealth
	SecurityInventory *DeviceSecurityInventory
	BackupStatus      *DeviceBackupStatus
	RawSignals        []DeviceRawSignal

	// NotAssessed (PAT-1960) is true when this device's platform has at
	// least one enabled compliance rule, but none of them apply to this
	// device's Device.DeviceClass — e.g. a 'server' device under the
	// workstation-only Windows 11 pack. Evaluations is then always empty by
	// design (evaluator.LoadRules already excluded every such rule), and
	// this must render as "not assessed", never as a device that failed
	// every control. NotAssessedReason carries the customer-facing string.
	NotAssessed       bool
	NotAssessedReason string
}

// DeviceHardware holds the hardware specification from devices.hardware JSONB.
type DeviceHardware struct {
	CPUModel    string  `json:"cpu_model"`
	CPUCores    int     `json:"cpu_cores"`
	RAMgb       float64 `json:"ram_gb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskFreeGB  float64 `json:"disk_free_gb"`
}

// DeviceBattery holds battery health data from device_hardware.
type DeviceBattery struct {
	Present        bool    `json:"present"`
	CycleCount     *int    `json:"cycle_count,omitempty"`
	Condition      *string `json:"condition,omitempty"`
	MaxCapacityPct *int    `json:"max_capacity_pct,omitempty"`
}

// DeviceStorageVolume is one mount point from device_storage_volume.
type DeviceStorageVolume struct {
	Mount      string `json:"mount"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	UsedPct    int    `json:"used_pct"`
}

// DeviceDisk is one disk entry from device_disk.
type DeviceDisk struct {
	DeviceNode  string  `json:"device_node"`
	SMARTStatus *string `json:"smart_status,omitempty"`
	Internal    bool    `json:"internal"`
	SolidState  bool    `json:"solid_state"`
}

// DeviceHardwareHealth aggregates battery, storage, and disk data for a device.
type DeviceHardwareHealth struct {
	Battery *DeviceBattery        `json:"battery,omitempty"`
	Volumes []DeviceStorageVolume `json:"volumes,omitempty"`
	Disks   []DeviceDisk          `json:"disks,omitempty"`
}

// DeviceSecurityTool is one entry in the security_tools array of security_inventory.
type DeviceSecurityTool struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DeviceSystemExtension is one entry in the system_extensions array (macOS).
type DeviceSystemExtension struct {
	Enabled  bool   `json:"enabled"`
	Active   bool   `json:"active"`
	TeamID   string `json:"team_id"`
	BundleID string `json:"bundle_id"`
	Version  string `json:"version"`
	Name     string `json:"name"`
	State    string `json:"state"`
}

// DeviceBackgroundItem is one entry in the background_items array (macOS).
type DeviceBackgroundItem struct {
	Name        string `json:"name"`
	Identifier  string `json:"identifier"`
	TeamID      string `json:"team_id"`
	URL         string `json:"url"`
	Type        int    `json:"type"`
	Disposition int    `json:"disposition"`
}

// DeviceICloud holds iCloud sign-in state (macOS).
type DeviceICloud struct {
	SignedIn string `json:"signed_in"`
}

// DeviceSecurityInventory is the decoded form of devices.security_inventory JSONB.
// The stored value is an object {security_tools:[], system_extensions:[], ...}
// not a top-level array — see extractor/upsert.go and migration 0002.
type DeviceSecurityInventory struct {
	SecurityTools    []DeviceSecurityTool    `json:"security_tools"`
	SystemExtensions []DeviceSystemExtension `json:"system_extensions"`
	BackgroundItems  []DeviceBackgroundItem  `json:"background_items"`
	ICloud           DeviceICloud            `json:"icloud"`
}

// DeviceBackupStatus is the decoded form of devices.backup_status JSONB
// (PAT-679 macOS Time Machine / PAT-680 Windows File History detection;
// PAT-948 server ingestion). Nil on Report when the reporting agent predates
// PAT-679/680, or the stored value failed to parse.
type DeviceBackupStatus struct {
	HasBackup         bool    `json:"has_backup"`
	BackupType        *string `json:"backup_type,omitempty"`
	LastBackupAt      *string `json:"last_backup_at,omitempty"`
	LastBackupDaysAgo *int    `json:"last_backup_days_ago,omitempty"`
	Stale             bool    `json:"stale"`
	SyncOnly          bool    `json:"sync_only"`
	Notes             *string `json:"notes,omitempty"`
}

// DecodeDeviceBackupStatus decodes a stored devices.backup_status JSONB value.
// Returns nil for absent / JSON-null / malformed input (log-and-continue is
// the caller's posture — a bad stored value must never fail a whole page).
//
// The served Stale field is DERIVED here from the same >= 7-day rule as
// BackupBucket, overriding the agent-reported flag: the macOS/Windows
// collectors compute stale with a strict > 7 days, so at exactly
// last_backup_days_ago == 7 the raw flag would contradict the bucket
// ("stale": false next to "bucket": "stale" in the same payload). One
// threshold — the server's — wins everywhere; the agent's original flag
// remains in the raw JSONB if forensics ever need it.
func DecodeDeviceBackupStatus(raw []byte) *DeviceBackupStatus {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var bs DeviceBackupStatus
	if err := json.Unmarshal(raw, &bs); err != nil {
		return nil
	}
	bs.Stale = BackupBucket(bs.HasBackup, bs.SyncOnly, bs.LastBackupDaysAgo) == "stale"
	return &bs
}

// BackupBucket classifies a device's backup status into one of four buckets
// for fleet-level aggregation and display (PAT-948):
//
//   - "sync_only" — a sync mechanism (OneDrive, iCloud Drive), never counted
//     as backed up, checked first so it can never fall through to another
//     bucket even though sync_only devices also report has_backup=false.
//   - "none"      — no backup mechanism detected at all.
//   - "stale"     — has_backup is true but the last backup is >= 7 days old.
//   - "ok"        — has_backup is true and either under the 7-day threshold,
//     or the mechanism doesn't expose a last-backup timestamp at all (e.g.
//     most third-party tools only report presence) — treated as ok rather
//     than unknown/stale since the agent itself doesn't flag it stale.
//
// This is the single source of truth for the bucket rule. FetchTenantsOverview
// (admin.go) computes the same four counts in SQL for per-tenant aggregates —
// that CASE logic MUST be kept in lockstep with this function.
func BackupBucket(hasBackup, syncOnly bool, lastBackupDaysAgo *int) string {
	if syncOnly {
		return "sync_only"
	}
	if !hasBackup {
		return "none"
	}
	if lastBackupDaysAgo != nil && *lastBackupDaysAgo >= 7 {
		return "stale"
	}
	return "ok"
}

// DeviceRawSignal is one row from compliance_signals (latest value per key).
type DeviceRawSignal struct {
	Key        string    `json:"key"`
	Value      string    `json:"value"`
	ObservedAt time.Time `json:"observed_at"`
}

// DeviceCVEFinding is one CVE affecting an installed app on this device,
// sourced from device_cve_findings + cve_feed_entries (populated by patched-cve-sync).
type DeviceCVEFinding struct {
	CVEID             string
	Description       string
	DescriptionSource string
	CVSSScore         *float64
	Severity          string
	AppName           string
	AppVersion        string
	MatchConfidence   string
	// FixedVersion is the version that resolves this CVE, "" when unknown.
	// device_cve_findings.fixed_version is TEXT NOT NULL DEFAULT '' — never
	// SQL NULL, so this is a plain string, not *string.
	FixedVersion string
}

// CatalogUpdate is one available app update sourced from app_catalog_entries,
// with the CVE IDs from device_cve_findings that would be closed by updating.
type CatalogUpdate struct {
	AppName        string
	Identifier     string
	CurrentVersion string
	TargetVersion  string
	Source         string
	LinkedCVEIDs   []string
}

// BrowserExtensionRow is one row from device_browser_extensions with elevated
// risk_level. Used by the "Browser extensions worth a look" report subsection.
type BrowserExtensionRow struct {
	Browser         string
	Profile         string
	UserAccount     string
	ExtensionID     string
	Name            string
	Version         string
	Enabled         bool
	Permissions     []string
	HostPermissions []string
	LastSeen        time.Time
}

// PendingUpdate is one currently-outstanding macOS update from the device's
// most recent `softwareupdate -l` run (stored as JSONB on devices.pending_updates).
type PendingUpdate struct {
	Label       string `json:"label"`
	Title       string `json:"title"`
	Version     string `json:"version"`
	Action      string `json:"action,omitempty"` // "shut down", "restart", or empty
	Recommended bool   `json:"recommended"`
}

// PatchHistoryItem is one row in the combined patch-outcome history shown on
// the device-detail console. Two sources feed the same slice (PAT-1007):
//
//   - The patches table — an OS update parsed from `softwareupdate
//     --history`. installed_at may be NULL when locale-formatted dates
//     couldn't be parsed. Outcome/FailureReason are always empty here:
//     softwareupdate's history is success-only by construction (a failed OS
//     update never appears in it at all), so there is no outcome to carry.
//   - provenance_records — a third-party app-update attempt posted by the
//     updater agent, which does carry a real outcome. InstalledAt for these
//     rows is the agent's own recorded event time (macOS 'recorded_at' /
//     Windows 'action_at'), falling back to the provenance row's received_at
//     only when that's absent or unparseable — see
//     fetchProvenancePatchHistory's doc comment for why receipt time alone
//     isn't safe to sort/display by (a queued, later-delivered event can
//     have a receipt time that doesn't reflect when it actually happened).
//     There's no separate "install completed" timestamp in this data beyond
//     that; InstalledAt reuses the same field the frontend already reads as
//     a timestamp fallback.
type PatchHistoryItem struct {
	Title         string
	Identifier    string // "<name>|<version>" or "<name>"
	InstalledAt   *time.Time
	Outcome       string // provenance rows only; empty for OS-patch rows
	FailureReason string // provenance rows only; empty when outcome wasn't a failure
}

// App is one row from device_apps. We render a compact subset in the
// software-inventory section of the report; the full row is still in the DB
// for ad-hoc queries.
type App struct {
	Name           string
	Version        string
	BundleID       string
	IdentifierKind string
	Signer         string
	TeamID         string
	Architecture   string
	Notarized      *bool
	LastSeen       time.Time
}

// Device is the metadata band that runs across the top of the report.
type Device struct {
	ID           string
	Serial       string
	HWUUID       string
	Hostname     string
	ComputerName string
	HWModel      string
	Arch         string
	OS           string
	OSVersion    string
	OSBuild      string
	AgentVersion string
	FirstSeen    time.Time
	LastSeen     time.Time

	// DeviceClass (PAT-1960): "workstation" | "server" | "domain_controller"
	// | "unknown". "unknown" means no agent has reported a real class for
	// this device yet (PAT-1959 is what starts reporting it) — scored
	// exactly as before this change, but labelled "device class not
	// reported" rather than implied "workstation".
	DeviceClass string
}

// EvalRow is one rule's latest evaluation joined with the rule's metadata —
// everything the renderer needs for one row of the failing / passing tables.
type EvalRow struct {
	RuleKey                 string
	Title                   string
	Description             string
	Benchmark               string
	BenchmarkVersion        string
	Severity                string
	Status                  string
	ObservedValue           *string
	EvaluatedAt             time.Time
	NISTMappings            []string
	ISOMappings             []string
	CyberEssentialsMappings []string
}

// Summary derives the topline counts from a Report's evaluations.
type Summary struct {
	Total         int
	Pass          int
	Fail          int
	NotApplicable int
	Error         int
	// Undetermined counts evaluations that resolved to fail with no observed
	// value (PAT-1758/PAT-1762): an absent signal, or the collector's literal
	// "Unknown" sentinel routed through treat_unknown_as. This is unreadable
	// evidence, not a real observation of non-compliance, so it is excluded
	// from Fail here — same predicate and reasoning as
	// ComplianceStats.UndeterminedEvaluations in executive.go. A "NotConfigured"
	// fail has a non-nil observed value and stays counted in Fail.
	Undetermined int
	// Percentage of (Pass) over (Pass+Fail+Undetermined+Error) — not_applicable
	// is excluded from the denominator so an Intel mac doesn't look "more
	// compliant" by virtue of having fewer rules apply to it. Undetermined
	// stays IN the denominator (unlike Fail's headline count) so a device
	// that sends no readable evidence for a control never scores as well as,
	// or better than, one that was actually checked — "absence requires
	// authority" (root AGENTS.md).
	CompliancePct float64
}

// Summary computes counts. Cheap; called from the renderer on every page.
func (r *Report) Summary() Summary {
	s := Summary{Total: len(r.Evaluations)}
	for _, e := range r.Evaluations {
		switch e.Status {
		case "pass":
			s.Pass++
		case "fail":
			if e.ObservedValue == nil {
				s.Undetermined++
			} else {
				s.Fail++
			}
		case "not_applicable":
			s.NotApplicable++
		case "error":
			s.Error++
		}
	}
	denom := s.Pass + s.Fail + s.Undetermined + s.Error
	if denom > 0 {
		s.CompliancePct = (float64(s.Pass) / float64(denom)) * 100.0
	}
	return s
}

// Fetch loads the latest evaluation per rule for the device, plus device
// metadata, tenant name, pending macOS updates, patch history, and the
// installed-software inventory. Returns ErrDeviceNotFound if the device row
// doesn't exist.
func Fetch(ctx context.Context, pool *pgxpool.Pool, deviceID string) (Report, error) {
	var rep Report
	rep.GeneratedAt = time.Now().UTC()

	var tenantID string
	var pendingRaw, hardwareRaw, secInvRaw, backupStatusRaw []byte
	err := pool.QueryRow(ctx, `
		SELECT
			d.id::text, d.tenant_id::text,
			COALESCE(d.serial, ''), COALESCE(d.hw_uuid::text, ''),
			COALESCE(d.hostname, ''), COALESCE(d.computer_name, ''),
			COALESCE(d.hw_model, ''), COALESCE(d.arch, ''),
			COALESCE(d.os, ''), COALESCE(d.os_version, ''), COALESCE(d.os_build, ''),
			COALESCE(d.agent_version, ''),
			d.first_seen, d.last_seen,
			d.pending_updates::text,
			d.hardware::text,
			d.security_inventory::text,
			d.backup_status::text,
			d.device_class
		FROM devices d
		WHERE d.id = $1
	`, deviceID).Scan(
		&rep.Device.ID, &tenantID,
		&rep.Device.Serial, &rep.Device.HWUUID,
		&rep.Device.Hostname, &rep.Device.ComputerName,
		&rep.Device.HWModel, &rep.Device.Arch,
		&rep.Device.OS, &rep.Device.OSVersion, &rep.Device.OSBuild,
		&rep.Device.AgentVersion,
		&rep.Device.FirstSeen, &rep.Device.LastSeen,
		&pendingRaw,
		&hardwareRaw,
		&secInvRaw,
		&backupStatusRaw,
		&rep.Device.DeviceClass,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rep, ErrDeviceNotFound
		}
		return rep, fmt.Errorf("fetch device: %w", err)
	}

	// pending_updates is JSONB; decode the raw bytes into our typed slice.
	// Empty/NULL column is fine — silently leaves rep.PendingUpdates nil.
	if len(pendingRaw) > 0 && string(pendingRaw) != "null" {
		if err := json.Unmarshal(pendingRaw, &rep.PendingUpdates); err != nil {
			// Don't fail the report for malformed JSONB — log and continue.
			rep.PendingUpdates = nil
		}
	}

	// hardware JSONB — non-fatal; absent on Windows schema_version=3 or pre-migration devices.
	if len(hardwareRaw) > 0 && string(hardwareRaw) != "null" {
		var hw DeviceHardware
		if err := json.Unmarshal(hardwareRaw, &hw); err == nil {
			rep.Hardware = &hw
		}
	}

	// security_inventory JSONB — stored as an object {security_tools:[], ...}.
	// Non-fatal; only macOS schema_version<3 devices have this populated.
	if len(secInvRaw) > 0 && string(secInvRaw) != "null" {
		var si DeviceSecurityInventory
		if err := json.Unmarshal(secInvRaw, &si); err == nil {
			rep.SecurityInventory = &si
		}
	}

	// backup_status JSONB (PAT-679/680 agents; PAT-948 server ingestion).
	// Non-fatal — absent on devices reported by agents that predate PAT-679/680,
	// or if the stored value somehow fails to decode; don't fail the report for
	// malformed JSONB — same treatment as pending_updates above. Stale is
	// server-derived inside the decoder (see DecodeDeviceBackupStatus).
	rep.BackupStatus = DecodeDeviceBackupStatus(backupStatusRaw)

	if err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&rep.Tenant); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Tenant row vanished but device row referenced it. Fall back to UUID.
			rep.Tenant = tenantID
		} else {
			return rep, fmt.Errorf("fetch tenant: %w", err)
		}
	}

	// Latest evaluation per (device, rule). DISTINCT ON keeps the top-of-
	// ordered row for each rule_id; the index on (device_id, evaluated_at DESC)
	// keeps this cheap.
	rows, err := pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (rule_id)
				rule_id, status, observed_value, evaluated_at, severity
			FROM compliance_evaluations
			WHERE device_id = $1
			ORDER BY rule_id, evaluated_at DESC
		)
		SELECT
			r.rule_key, r.title, COALESCE(r.description, ''),
			r.benchmark, r.benchmark_version, l.severity,
			l.status, l.observed_value, l.evaluated_at,
			COALESCE(r.nist_mappings, '{}'),
			COALESCE(r.iso_mappings, '{}'),
			COALESCE(r.cyber_essentials_mappings, '{}')
		FROM latest l
		JOIN compliance_rules r ON r.id = l.rule_id
		ORDER BY
			CASE l.status
				WHEN 'fail'           THEN 1
				WHEN 'error'          THEN 2
				WHEN 'not_applicable' THEN 3
				WHEN 'pass'           THEN 4
				ELSE 5
			END,
			CASE l.severity
				WHEN 'critical' THEN 1
				WHEN 'high'     THEN 2
				WHEN 'medium'   THEN 3
				WHEN 'low'      THEN 4
				ELSE 5
			END,
			r.rule_key
	`, deviceID)
	if err != nil {
		return rep, fmt.Errorf("fetch evaluations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ev EvalRow
		if err := rows.Scan(
			&ev.RuleKey, &ev.Title, &ev.Description,
			&ev.Benchmark, &ev.BenchmarkVersion, &ev.Severity,
			&ev.Status, &ev.ObservedValue, &ev.EvaluatedAt,
			&ev.NISTMappings, &ev.ISOMappings, &ev.CyberEssentialsMappings,
		); err != nil {
			return rep, fmt.Errorf("scan evaluation row: %w", err)
		}
		rep.Evaluations = append(rep.Evaluations, ev)
	}
	if err := rows.Err(); err != nil {
		return rep, fmt.Errorf("iterate evaluation rows: %w", err)
	}

	// macOS patch history. Most-recent-first; the renderer caps the rendered
	// count if it would explode the page.
	patchRows, err := pool.Query(ctx, `
		SELECT title, identifier, installed_at
		FROM patches
		WHERE device_id = $1
		ORDER BY COALESCE(installed_at, observed_at) DESC, identifier
	`, deviceID)
	if err != nil {
		return rep, fmt.Errorf("fetch patches: %w", err)
	}
	for patchRows.Next() {
		var p PatchHistoryItem
		if err := patchRows.Scan(&p.Title, &p.Identifier, &p.InstalledAt); err != nil {
			patchRows.Close()
			return rep, fmt.Errorf("scan patch row: %w", err)
		}
		rep.PatchHistory = append(rep.PatchHistory, p)
	}
	patchRows.Close()
	if err := patchRows.Err(); err != nil {
		return rep, fmt.Errorf("iterate patch rows: %w", err)
	}

	// Third-party app-update outcomes from provenance_records (PAT-1007).
	// macOS-only today — see fetchProvenancePatchHistory's doc comment for
	// why Windows provenance can't be attributed to a device here.
	//
	// Deliberately kept on its own field, NOT merged into rep.PatchHistory —
	// see ProvenancePatchHistory's doc comment on the Report struct for why:
	// PatchHistory feeds the PDF's OS-update-only section, and a failed
	// third-party install merged in there would render as a successful,
	// dated OS update in a customer-facing document. Callers that want the
	// combined, outcome-aware view (the JSON device-detail handler) call
	// MergePatchHistory themselves.
	provHistory, err := fetchProvenancePatchHistory(ctx, pool, tenantID, rep.Device.HWUUID)
	if err != nil {
		return rep, err
	}
	rep.ProvenancePatchHistory = provHistory

	// Software inventory. Grouping bundle_id with the *most recent* version
	// per device — UNIQUE(device_id, identifier, version) means a given app
	// can have multiple rows (one per version seen); the report shows the
	// version the device has most recently been observed running.
	appRows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (identifier)
			COALESCE(name, ''),
			COALESCE(version, ''),
			identifier,
			COALESCE(identifier_kind, ''),
			COALESCE(signer, ''),
			COALESCE(team_id, ''),
			COALESCE(architecture, ''),
			notarized,
			last_seen
		FROM device_apps
		WHERE device_id = $1
		ORDER BY identifier, last_seen DESC
	`, deviceID)
	if err != nil {
		return rep, fmt.Errorf("fetch apps: %w", err)
	}
	for appRows.Next() {
		var a App
		if err := appRows.Scan(
			&a.Name, &a.Version, &a.BundleID, &a.IdentifierKind,
			&a.Signer, &a.TeamID, &a.Architecture,
			&a.Notarized, &a.LastSeen,
		); err != nil {
			appRows.Close()
			return rep, fmt.Errorf("scan app row: %w", err)
		}
		rep.Apps = append(rep.Apps, a)
	}
	appRows.Close()
	if err := appRows.Err(); err != nil {
		return rep, fmt.Errorf("iterate app rows: %w", err)
	}

	// Browser extensions with elevated risk. One row per unique
	// (browser, user_account, profile, extension_id) combination.
	// Silently skips if the table does not yet exist (migration pending).
	extRows, extErr := pool.Query(ctx, `
		SELECT browser, profile, user_account, extension_id, name,
		       COALESCE(version, ''), enabled,
		       permissions, host_permissions, last_seen
		FROM device_browser_extensions
		WHERE device_id = $1::uuid
		  AND risk_level = 'elevated'
		ORDER BY browser, name
	`, deviceID)
	if extErr == nil {
		for extRows.Next() {
			var ext BrowserExtensionRow
			var permsRaw, hostPermsRaw []byte
			if err := extRows.Scan(
				&ext.Browser, &ext.Profile, &ext.UserAccount, &ext.ExtensionID, &ext.Name,
				&ext.Version, &ext.Enabled, &permsRaw, &hostPermsRaw, &ext.LastSeen,
			); err != nil {
				extRows.Close()
				return rep, fmt.Errorf("scan browser extension row: %w", err)
			}
			_ = json.Unmarshal(permsRaw, &ext.Permissions)
			_ = json.Unmarshal(hostPermsRaw, &ext.HostPermissions)
			rep.ElevatedExtensions = append(rep.ElevatedExtensions, ext)
		}
		extRows.Close()
	}
	// Non-fatal: if the table doesn't exist yet the section is simply absent.

	// CVE findings for installed apps on this device.
	cveRows, cveErr := pool.Query(ctx, `
		SELECT
			f.cve_id,
			e.description,
			e.description_source,
			e.cvss_v3_score,
			e.severity,
			f.app_name,
			f.app_version,
			f.match_confidence,
			f.fixed_version
		FROM device_cve_findings f
		JOIN cve_feed_entries e ON e.cve_id = f.cve_id
		WHERE f.device_id = $1::uuid
		ORDER BY e.cvss_v3_score DESC NULLS LAST, f.cve_id
	`, deviceID)
	if cveErr == nil {
		for cveRows.Next() {
			var cf DeviceCVEFinding
			if err := cveRows.Scan(
				&cf.CVEID, &cf.Description, &cf.DescriptionSource, &cf.CVSSScore, &cf.Severity,
				&cf.AppName, &cf.AppVersion, &cf.MatchConfidence, &cf.FixedVersion,
			); err != nil {
				cveRows.Close()
				return rep, fmt.Errorf("scan cve finding: %w", err)
			}
			rep.CVEFindings = append(rep.CVEFindings, cf)
		}
		cveRows.Close()
	}
	// Non-fatal: cve_feed_entries may not exist if patched-cve-sync hasn't run yet.

	// Available app updates from the catalog (app_catalog_entries).
	platform := "macOS"
	if strings.EqualFold(rep.Device.OS, "windows") {
		platform = "Windows"
	}
	catRows, catErr := pool.Query(ctx, `
		SELECT
			da.name,
			da.identifier,
			da.version AS current_version,
			ace.latest_version AS target_version,
			ace.source,
			COALESCE(
				array_agg(dcf.cve_id ORDER BY dcf.cve_id)
				FILTER (WHERE dcf.cve_id IS NOT NULL),
				'{}'
			) AS linked_cve_ids
		FROM device_apps da
		JOIN app_catalog_entries ace ON (
			ace.platform = $2
			AND (
				(ace.verified_signer IS NOT NULL AND da.team_id = ace.verified_signer)
				OR (ace.verified_signer IS NULL  AND lower(da.name) = lower(ace.name))
			)
		)
		LEFT JOIN device_cve_findings dcf ON (
			dcf.device_id = $1::uuid
			AND dcf.app_name = da.name
			AND dcf.app_version = da.version
		)
		WHERE da.device_id = $1::uuid
		  AND da.version IS NOT NULL
		  AND da.version != ace.latest_version
		GROUP BY da.name, da.identifier, da.version, ace.latest_version, ace.source
		ORDER BY da.name
	`, deviceID, platform)
	if catErr == nil {
		for catRows.Next() {
			var cu CatalogUpdate
			if err := catRows.Scan(
				&cu.AppName, &cu.Identifier, &cu.CurrentVersion,
				&cu.TargetVersion, &cu.Source, &cu.LinkedCVEIDs,
			); err != nil {
				catRows.Close()
				return rep, fmt.Errorf("scan catalog update: %w", err)
			}
			rep.CatalogUpdates = append(rep.CatalogUpdates, cu)
		}
		catRows.Close()
	}
	// Non-fatal: app_catalog_entries may not exist before migration 0030 is applied.

	// Benchmark totals: count of enabled compliance_rules per (benchmark, benchmark_version)
	// for this device's platform AND device class (PAT-1960). Used for "X of
	// N" display in the PDF.
	dbPlatform := "macos"
	if strings.EqualFold(rep.Device.OS, "windows") {
		dbPlatform = "windows"
	}
	// Unfiltered platform total, so NotAssessed can be told apart from "this
	// platform simply has no enabled rules at all" — the latter is not this
	// device's fault and must not be reported as "not assessed".
	// A failed count is not the same fact as a count of zero, and conflating
	// them silently restores the bug this ticket exists to fix: with the total
	// forced to 0 the NotAssessed label below is suppressed, and a server is
	// rendered with an all-zero benchmark table exactly as before. Absence
	// requires authority, so an unknown total fails toward saying the device
	// was not assessed rather than toward a confident-looking empty result.
	var totalPlatformRules int
	totalPlatformRulesKnown := true
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM compliance_rules WHERE platform = $1 AND enabled = true
	`, dbPlatform).Scan(&totalPlatformRules); err != nil {
		totalPlatformRules = 0
		totalPlatformRulesKnown = false
	}
	bmRows, bmErr := pool.Query(ctx, `
		SELECT benchmark, benchmark_version, COUNT(*)
		FROM compliance_rules
		WHERE platform = $1 AND enabled = true
		  AND `+deviceClassMatchParam("device_class", 2)+`
		GROUP BY benchmark, benchmark_version
	`, dbPlatform, rep.Device.DeviceClass)
	if bmErr == nil {
		rep.BenchmarkTotals = map[string]int{}
		applicableRules := 0
		for bmRows.Next() {
			var bm, ver string
			var cnt int
			if err := bmRows.Scan(&bm, &ver, &cnt); err != nil {
				bmRows.Close()
				break
			}
			rep.BenchmarkTotals[bm+"||"+ver] = cnt
			applicableRules += cnt
		}
		bmRows.Close()
		if applicableRules == 0 && (totalPlatformRules > 0 || !totalPlatformRulesKnown) {
			rep.NotAssessed = true
			rep.NotAssessedReason = notAssessedReason
		}
	}

	// Hardware health — battery, all storage volumes, all disks.
	// Non-fatal: silently absent when device_hardware tables don't exist or
	// no row has been collected for this device yet.
	if hh := fetchHardwareHealth(ctx, pool, deviceID); hh != nil {
		rep.HardwareHealth = hh
	}

	// Raw compliance signals — latest value per key for this device.
	// Non-fatal; silently absent when no signals recorded yet.
	sigRows, sigErr := pool.Query(ctx, `
		SELECT DISTINCT ON (key) key, value, observed_at
		FROM compliance_signals
		WHERE device_id = $1
		ORDER BY key, observed_at DESC
	`, deviceID)
	if sigErr == nil {
		for sigRows.Next() {
			var s DeviceRawSignal
			if err := sigRows.Scan(&s.Key, &s.Value, &s.ObservedAt); err != nil {
				sigRows.Close()
				break
			}
			rep.RawSignals = append(rep.RawSignals, s)
		}
		sigRows.Close()
	}

	return rep, nil
}

// MergePatchHistory combines OS-patch rows (from the patches table) and
// provenance-sourced rows (from provenance_records) into one newest-first
// slice. Both inputs arrive already sorted newest-first from their own
// queries; this does a stable sort by InstalledAt descending to interleave
// them correctly, matching the frontend's implicit newest-first ordering
// assumption for patch_history. Entries with no parseable timestamp
// (locale-unparsed OS-patch dates — see PatchHistoryItem's doc comment) sort
// last rather than participating in timestamp comparison.
//
// Exported deliberately: Report.PatchHistory and Report.ProvenancePatchHistory
// are kept separate on purpose (see ProvenancePatchHistory's doc comment) — a
// consumer that wants the combined, outcome-aware view (today: the JSON
// device-detail handler, internal/handlers/admin_overview.go) calls this
// itself rather than Fetch doing an implicit merge that every caller of Fetch
// (including the PDF renderer) would otherwise silently inherit.
func MergePatchHistory(osHistory, provHistory []PatchHistoryItem) []PatchHistoryItem {
	merged := make([]PatchHistoryItem, 0, len(osHistory)+len(provHistory))
	merged = append(merged, osHistory...)
	merged = append(merged, provHistory...)
	sort.SliceStable(merged, func(i, j int) bool {
		a, b := merged[i].InstalledAt, merged[j].InstalledAt
		if a == nil {
			return false
		}
		if b == nil {
			return true
		}
		return a.After(*b)
	})
	return merged
}

// fetchProvenancePatchHistory reads third-party app-update attempts for one
// device from provenance_records — the updater agent's POST /v1/provenance
// audit trail, populated with real success/failure outcomes (unlike the
// patches table, which only ever contains successful OS installs). The
// COALESCE pairs mirror the established pattern in
// internal/rings/advance.go's queryFailureRate: macOS emits outcome/label/
// available_version nested under a top-level "app" object, Windows emits
// label/state flat at the top level.
//
// Windows provenance carries no per-device identifier at all (see
// queryFailureRate's doc comment in advance.go — a documented, deliberate
// gap from the PAT-999 work, not introduced here), so the hw_uuid join below
// can only ever match macOS rows. A device with an empty HWUUID (e.g. a
// pre-migration device row) skips the query entirely rather than issuing one
// that can never match.
//
// LIMIT 200, newest first: a device stuck retrying a broken update hundreds
// of times must not blow up the device-detail response size.
//
// label/available_version/outcome/failure_reason are all LEFT(...,500)-capped
// in the SELECT. LIMIT 200 bounds row COUNT, not row SIZE: all four fields
// are client-supplied text straight out of provenance_records.body — JSON
// POSTed by the updater agent under a shared tenant secret, accepted up to
// POST /v1/provenance's body-size cap (see internal/handlers/inventory.go's
// maxBodyBytes and provenance.go for the matching limit) — so an adversarial
// or simply buggy agent could otherwise post a single field containing
// megabytes of text and have 200 rows of it land in one device-detail
// response. outcome/state is exactly as client-controlled as the other
// three — it's read from the same untrusted JSONB body, not a DB-enforced
// enum — so it gets the identical cap, not just label/version/failure_reason.
// 500 chars is generously above any real app name, version string, outcome
// value, or failure reason; this is a defensive cap against a
// hostile/malformed payload, not an expected truncation of legitimate data.
//
// "event_at" — ordering/InstalledAt use the AGENT's own event timestamp, not
// pr.received_at (server ingestion time), because they can legitimately
// diverge: the updater agent queues events locally and posts them in a batch
// on retry/backoff (e.g. an offline device), so a stale queued FAILURE can
// land in provenance_records with a LATER received_at than a genuinely more
// recent SUCCESS that was posted immediately. Sorting by received_at would
// then surface the old failure as "current" for a device that's actually
// fine. Both emitters carry their own event time under different top-level
// keys (same cross-shape COALESCE pattern as label/version/outcome above):
// macOS emits 'recorded_at' (endpoint/patched-update.sh,
// '%Y-%m-%dT%H:%M:%SZ' — plain UTC, no fractional seconds), Windows emits
// 'action_at' (ProvenancePoster.cs BuildPayload, DateTimeOffset "O" —
// higher precision, explicit offset). Both forms cast cleanly to timestamptz
// (verified directly against Postgres, not assumed).
//
// The pg_input_is_valid(...) guard exists because these are, like every
// other field read here, untrusted client text — an attacker (or a
// future/buggy agent build) could post a non-timestamp string in
// recorded_at/action_at, and an unconditional ::timestamptz cast on that
// would raise a hard Postgres error and 500 the ENTIRE device-detail
// response, not just drop the one field. pg_input_is_valid (Postgres 16+,
// this stack's target — see AGENTS.md) validates a value against a type's
// real input function WITHOUT throwing, so it catches what a shape-only
// regex can't: a string that's structurally ISO-8601 (right digit
// positions) but out of range, e.g. "2026-99-99T99:99:99" — that would pass
// a `~ '^\d{4}-\d{2}-\d{2}...'` regex and then still blow up the cast. The
// CASE only attempts the cast once pg_input_is_valid has confirmed it will
// succeed; anything invalid (or the field simply being absent, the
// pre-existing/expected case — pg_input_is_valid(NULL, ...) returns NULL,
// which WHEN treats as not-true) falls back to pr.received_at, a
// DB-generated timestamptz that can never fail to cast.
//
// pg_input_is_valid alone is not sufficient: timestamptz's real input
// function accepts the special values "infinity"/"-infinity" as genuinely
// valid, so pg_input_is_valid('infinity', 'timestamptz') is true — but pgx
// cannot scan an infinite timestamptz into a Go time.Time (Scan errors),
// which would fail the whole query, not just this field, and would do so
// on EVERY future request for that device once such a row exists (a
// persisted row, not a one-off bad request). The explicit NOT IN guard
// rejects both special values before the validity check even runs, so
// they fall back to pr.received_at like any other invalid input.
func fetchProvenancePatchHistory(ctx context.Context, pool *pgxpool.Pool, tenantID, hwUUID string) ([]PatchHistoryItem, error) {
	if hwUUID == "" {
		return nil, nil
	}

	rows, err := pool.Query(ctx, `
		SELECT
			LEFT(COALESCE(pr.body->'app'->>'label', pr.body->>'label'), 500) AS label,
			LEFT(COALESCE(pr.body->'app'->>'available_version', pr.body->>'available_version'), 500) AS version,
			LEFT(COALESCE(pr.body->>'outcome', pr.body->>'state'), 500) AS outcome,
			LEFT(pr.body->>'failure_reason', 500) AS failure_reason,
			CASE
				WHEN lower(trim(COALESCE(pr.body->>'recorded_at', pr.body->>'action_at', ''))) NOT IN ('infinity', '-infinity')
					AND pg_input_is_valid(COALESCE(pr.body->>'recorded_at', pr.body->>'action_at'), 'timestamptz')
					THEN COALESCE(pr.body->>'recorded_at', pr.body->>'action_at')::timestamptz
				ELSE pr.received_at
			END AS event_at
		FROM provenance_records pr
		WHERE pr.tenant_id = $1::uuid
		  AND lower(pr.body->'device'->>'hw_uuid') = lower($2)
		  AND COALESCE(pr.body->>'record_type', 'third_party_update') = 'third_party_update'
		  AND COALESCE(pr.body->'app'->>'label', pr.body->>'label') IS NOT NULL
		ORDER BY event_at DESC
		LIMIT 200
	`, tenantID, hwUUID)
	if err != nil {
		return nil, fmt.Errorf("fetch provenance patch history: %w", err)
	}
	defer rows.Close()

	var items []PatchHistoryItem
	for rows.Next() {
		var label string
		var version, outcome, failureReason *string
		var eventAt time.Time
		if err := rows.Scan(&label, &version, &outcome, &failureReason, &eventAt); err != nil {
			return nil, fmt.Errorf("scan provenance patch row: %w", err)
		}

		identifier := label
		if version != nil && *version != "" {
			identifier = label + "|" + *version
		}

		item := PatchHistoryItem{
			Title:       label,
			Identifier:  identifier,
			InstalledAt: &eventAt,
		}
		if outcome != nil {
			item.Outcome = *outcome
		}
		if failureReason != nil {
			item.FailureReason = *failureReason
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate provenance patch rows: %w", err)
	}
	return items, nil
}

// fetchHardwareHealth queries the device_hardware, device_storage_volume, and
// device_disk tables for a single device. Returns nil if the tables don't exist
// or no hardware row has been collected yet (non-fatal).
func fetchHardwareHealth(ctx context.Context, pool *pgxpool.Pool, deviceID string) *DeviceHardwareHealth {
	var hh DeviceHardwareHealth

	// Battery — one row per device (if any).
	var hwID int64
	var batt DeviceBattery
	err := pool.QueryRow(ctx, `
		SELECT id, battery_present,
		       battery_cycle_count, battery_condition, battery_max_capacity_pct
		FROM device_hardware
		WHERE device_id = $1
	`, deviceID).Scan(
		&hwID, &batt.Present,
		&batt.CycleCount, &batt.Condition, &batt.MaxCapacityPct,
	)
	if err != nil {
		// No hardware row or table doesn't exist — nothing to surface.
		return nil
	}
	hh.Battery = &batt

	// Storage volumes — all mounts for this device.
	svRows, svErr := pool.Query(ctx, `
		SELECT mount, total_bytes, free_bytes, used_pct
		FROM device_storage_volume
		WHERE device_hardware_id = $1
		ORDER BY mount
	`, hwID)
	if svErr == nil {
		for svRows.Next() {
			var v DeviceStorageVolume
			if err := svRows.Scan(&v.Mount, &v.TotalBytes, &v.FreeBytes, &v.UsedPct); err != nil {
				svRows.Close()
				break
			}
			hh.Volumes = append(hh.Volumes, v)
		}
		svRows.Close()
	}

	// Disks — all entries for this device.
	dskRows, dskErr := pool.Query(ctx, `
		SELECT device_node, smart_status, internal, solid_state
		FROM device_disk
		WHERE device_hardware_id = $1
		ORDER BY device_node
	`, hwID)
	if dskErr == nil {
		for dskRows.Next() {
			var d DeviceDisk
			if err := dskRows.Scan(&d.DeviceNode, &d.SMARTStatus, &d.Internal, &d.SolidState); err != nil {
				dskRows.Close()
				break
			}
			hh.Disks = append(hh.Disks, d)
		}
		dskRows.Close()
	}

	return &hh
}
