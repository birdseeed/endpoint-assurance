package handlers

// PAT-136 — Tenant data export bundler (GDPR data portability / access).
//
// Backend for the customer data-export obligation under UK GDPR / IoM DPA 2018.
// Produces a single machine-readable JSON bundle of everything Patched holds for
// a tenant across the named categories: hosts, apps, compliance scores,
// vulnerabilities, reports, audit log, and per-host user attribution.
//
// Route: GET /admin/tenants/{tenantID}/export[?user=<account>]
//
// With ?user set, the bundle is scoped to a single named user's data — the
// devices they are the primary user of and the data attributed to those devices
// — to fulfil a Data Subject Request (access / portability) for that individual.
// Tenant-wide records (reports, enforcement audit) are excluded from a
// user-scoped export as they are not the individual's personal data.
//
// Read-only: this handler never mutates. Delivery to the customer (signed link,
// 7-day expiry) and the self-service dashboard button are separate surfaces.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type exportTenant struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type exportApp struct {
	Name         string    `json:"name"`
	Version      *string   `json:"version"`
	Identifier   string    `json:"identifier"`
	Path         *string   `json:"path"`
	Signer       *string   `json:"signer"`
	TeamID       *string   `json:"team_id"`
	Architecture *string   `json:"architecture"`
	Notarized    *bool     `json:"notarized"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

type exportPatch struct {
	Identifier  string     `json:"identifier"`
	Title       *string    `json:"title"`
	InstalledAt *time.Time `json:"installed_at"`
	ObservedAt  time.Time  `json:"observed_at"`
}

type exportSignal struct {
	Key        string    `json:"key"`
	Value      string    `json:"value"`
	Severity   *string   `json:"severity"`
	ObservedAt time.Time `json:"observed_at"`
}

type exportEvaluation struct {
	RuleKey       string    `json:"rule_key"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	ObservedValue *string   `json:"observed_value"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

type exportVulnerability struct {
	CVEID           string    `json:"cve_id"`
	AppName         string    `json:"app_name"`
	AppVersion      string    `json:"app_version"`
	Severity        *string   `json:"severity"`
	MatchConfidence string    `json:"match_confidence"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

type exportDevice struct {
	ID                    string     `json:"id"`
	Serial                *string    `json:"serial"`
	HWUUID                *string    `json:"hw_uuid"`
	Hostname              *string    `json:"hostname"`
	ComputerName          *string    `json:"computer_name"`
	OS                    string     `json:"os"`
	OSVersion             *string    `json:"os_version"`
	OSBuild               *string    `json:"os_build"`
	HWModel               *string    `json:"hw_model"`
	Arch                  *string    `json:"arch"`
	FirstSeen             time.Time  `json:"first_seen"`
	LastSeen              time.Time  `json:"last_seen"`
	PrimaryUserAccount    *string    `json:"primary_user_account"`
	PrimaryUserDisplay    *string    `json:"primary_user_display"`
	PrimaryUserLastSeenAt *time.Time `json:"primary_user_last_seen_at"`
	PrimaryUserSource     *string    `json:"primary_user_source"`

	Apps                  []exportApp           `json:"apps"`
	Patches               []exportPatch         `json:"patches"`
	ComplianceSignals     []exportSignal        `json:"compliance_signals"`
	ComplianceEvaluations []exportEvaluation    `json:"compliance_evaluations"`
	Vulnerabilities       []exportVulnerability `json:"vulnerabilities"`
}

type exportReport struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	GeneratedAt    time.Time `json:"generated_at"`
	DeliveryStatus string    `json:"delivery_status"`
}

type exportAuditEntry struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"device_id"`
	EventType  string    `json:"event_type"`
	Subject    string    `json:"subject"`
	OccurredAt time.Time `json:"occurred_at"`
}

type exportBundle struct {
	ExportedAt time.Time    `json:"exported_at"`
	TenantID   string       `json:"tenant_id"`
	Scope      string       `json:"scope"`                 // "tenant" | "user"
	UserFilter string       `json:"user_filter,omitempty"` // set when Scope == "user"
	Tenant     exportTenant `json:"tenant"`

	Devices  []exportDevice     `json:"devices"`
	Reports  []exportReport     `json:"reports"`
	AuditLog []exportAuditEntry `json:"audit_log"`
}

// TenantExportHandler assembles and returns the full data-export bundle for a
// tenant. See the file header for the GDPR context and route.
func TenantExportHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "tenant_export", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		userFilter := strings.TrimSpace(r.URL.Query().Get("user"))
		// A present-but-blank ?user= must not silently fall back to a whole-tenant
		// export: that would hand every individual's data to what was meant to be a
		// single-person DSR export. Treat it as a client error.
		if r.URL.Query().Has("user") && userFilter == "" {
			http.Error(w, "user must be non-empty when provided", http.StatusBadRequest)
			return
		}

		bundle, err := buildExportBundle(r.Context(), pool, tenantID, userFilter)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			logger.Error("build export bundle failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("tenant export served", "scope", bundle.Scope, "devices", len(bundle.Devices))
		w.Header().Set("Content-Type", "application/json")
		// Content-Disposition hints the caller (and any proxy) that this is a
		// downloadable artefact, not a page to render.
		w.Header().Set("Content-Disposition", "attachment; filename=\"patched-export-"+tenantID+".json\"")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(bundle)
	}
}

// buildExportBundle runs the read queries and assembles the bundle. Returns
// pgx.ErrNoRows if the tenant does not exist.
func buildExportBundle(ctx context.Context, pool *pgxpool.Pool, tenantID, userFilter string) (*exportBundle, error) {
	var t exportTenant
	t.ID = tenantID
	if err := pool.QueryRow(ctx,
		`SELECT name, created_at, revoked_at FROM tenants WHERE id = $1::uuid`,
		tenantID,
	).Scan(&t.Name, &t.CreatedAt, &t.RevokedAt); err != nil {
		return nil, err
	}

	scope := "tenant"
	if userFilter != "" {
		scope = "user"
	}

	devices, deviceIDs, err := fetchExportDevices(ctx, pool, tenantID, userFilter)
	if err != nil {
		return nil, err
	}

	if len(deviceIDs) > 0 {
		if err := attachDeviceChildren(ctx, pool, devices, deviceIDs); err != nil {
			return nil, err
		}
	}

	bundle := &exportBundle{
		ExportedAt: time.Now().UTC(),
		TenantID:   tenantID,
		Scope:      scope,
		Tenant:     t,
		Devices:    devices,
		Reports:    []exportReport{},
		AuditLog:   []exportAuditEntry{},
	}
	if scope == "user" {
		bundle.UserFilter = userFilter
	}

	// Tenant-wide records are only part of a whole-tenant export. A user-scoped
	// DSR export must not leak other individuals' data via shared records.
	if scope == "tenant" {
		if bundle.Reports, err = fetchExportReports(ctx, pool, tenantID); err != nil {
			return nil, err
		}
		if bundle.AuditLog, err = fetchExportAuditLog(ctx, pool, tenantID); err != nil {
			return nil, err
		}
	}

	return bundle, nil
}

func fetchExportDevices(ctx context.Context, pool *pgxpool.Pool, tenantID, userFilter string) ([]exportDevice, []string, error) {
	const base = `
		SELECT id::text, serial, hw_uuid::text, hostname, computer_name, os, os_version,
		       os_build, hw_model, arch, first_seen, last_seen,
		       primary_user_account, primary_user_display, primary_user_last_seen_at, primary_user_source
		FROM devices
		WHERE tenant_id = $1::uuid`

	var rows pgx.Rows
	var err error
	if userFilter != "" {
		rows, err = pool.Query(ctx, base+`
		  AND (lower(primary_user_account) = lower($2) OR lower(primary_user_display) = lower($2))
		ORDER BY first_seen`, tenantID, userFilter)
	} else {
		rows, err = pool.Query(ctx, base+`
		ORDER BY first_seen`, tenantID)
	}
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var devices []exportDevice
	var ids []string
	for rows.Next() {
		var d exportDevice
		if err := rows.Scan(
			&d.ID, &d.Serial, &d.HWUUID, &d.Hostname, &d.ComputerName, &d.OS, &d.OSVersion,
			&d.OSBuild, &d.HWModel, &d.Arch, &d.FirstSeen, &d.LastSeen,
			&d.PrimaryUserAccount, &d.PrimaryUserDisplay, &d.PrimaryUserLastSeenAt, &d.PrimaryUserSource,
		); err != nil {
			return nil, nil, err
		}
		d.Apps = []exportApp{}
		d.Patches = []exportPatch{}
		d.ComplianceSignals = []exportSignal{}
		d.ComplianceEvaluations = []exportEvaluation{}
		d.Vulnerabilities = []exportVulnerability{}
		devices = append(devices, d)
		ids = append(ids, d.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if devices == nil {
		devices = []exportDevice{}
	}
	return devices, ids, nil
}

// attachDeviceChildren batch-fetches every child collection for the given
// device set and attaches it to the matching device by ID.
func attachDeviceChildren(ctx context.Context, pool *pgxpool.Pool, devices []exportDevice, deviceIDs []string) error {
	byID := make(map[string]*exportDevice, len(devices))
	for i := range devices {
		byID[devices[i].ID] = &devices[i]
	}

	// Apps
	if err := queryChildren(ctx, pool, `
		SELECT device_id::text, name, version, identifier, path, signer, team_id, architecture, notarized, first_seen, last_seen
		FROM device_apps WHERE device_id = ANY($1::uuid[]) ORDER BY device_id, name, version`,
		deviceIDs, func(rows pgx.Rows) error {
			var did string
			var a exportApp
			if err := rows.Scan(&did, &a.Name, &a.Version, &a.Identifier, &a.Path, &a.Signer, &a.TeamID, &a.Architecture, &a.Notarized, &a.FirstSeen, &a.LastSeen); err != nil {
				return err
			}
			if d := byID[did]; d != nil {
				d.Apps = append(d.Apps, a)
			}
			return nil
		}); err != nil {
		return err
	}

	// Patches
	if err := queryChildren(ctx, pool, `
		SELECT device_id::text, identifier, title, installed_at, observed_at
		FROM patches WHERE device_id = ANY($1::uuid[]) ORDER BY device_id, identifier`,
		deviceIDs, func(rows pgx.Rows) error {
			var did string
			var p exportPatch
			if err := rows.Scan(&did, &p.Identifier, &p.Title, &p.InstalledAt, &p.ObservedAt); err != nil {
				return err
			}
			if d := byID[did]; d != nil {
				d.Patches = append(d.Patches, p)
			}
			return nil
		}); err != nil {
		return err
	}

	// Compliance signals
	if err := queryChildren(ctx, pool, `
		SELECT device_id::text, key, value, severity, observed_at
		FROM compliance_signals WHERE device_id = ANY($1::uuid[]) ORDER BY device_id, key`,
		deviceIDs, func(rows pgx.Rows) error {
			var did string
			var s exportSignal
			if err := rows.Scan(&did, &s.Key, &s.Value, &s.Severity, &s.ObservedAt); err != nil {
				return err
			}
			if d := byID[did]; d != nil {
				d.ComplianceSignals = append(d.ComplianceSignals, s)
			}
			return nil
		}); err != nil {
		return err
	}

	// Compliance evaluations (joined to the rule for a portable rule key/title)
	if err := queryChildren(ctx, pool, `
		SELECT e.device_id::text, r.rule_key, r.title, r.severity, e.status, e.observed_value, e.evaluated_at
		FROM compliance_evaluations e
		JOIN compliance_rules r ON r.id = e.rule_id
		WHERE e.device_id = ANY($1::uuid[]) ORDER BY e.device_id, r.rule_key`,
		deviceIDs, func(rows pgx.Rows) error {
			var did string
			var e exportEvaluation
			if err := rows.Scan(&did, &e.RuleKey, &e.Title, &e.Severity, &e.Status, &e.ObservedValue, &e.EvaluatedAt); err != nil {
				return err
			}
			if d := byID[did]; d != nil {
				d.ComplianceEvaluations = append(d.ComplianceEvaluations, e)
			}
			return nil
		}); err != nil {
		return err
	}

	// Vulnerabilities
	if err := queryChildren(ctx, pool, `
		SELECT device_id::text, cve_id, app_name, app_version, severity, match_confidence, first_seen_at, last_seen_at
		FROM device_cve_findings WHERE device_id = ANY($1::uuid[]) ORDER BY device_id, cve_id, app_name`,
		deviceIDs, func(rows pgx.Rows) error {
			var did string
			var v exportVulnerability
			if err := rows.Scan(&did, &v.CVEID, &v.AppName, &v.AppVersion, &v.Severity, &v.MatchConfidence, &v.FirstSeenAt, &v.LastSeenAt); err != nil {
				return err
			}
			if d := byID[did]; d != nil {
				d.Vulnerabilities = append(d.Vulnerabilities, v)
			}
			return nil
		}); err != nil {
		return err
	}

	return nil
}

// queryChildren runs a device-scoped child query and calls scan for each row.
func queryChildren(ctx context.Context, pool *pgxpool.Pool, sql string, deviceIDs []string, scan func(pgx.Rows) error) error {
	rows, err := pool.Query(ctx, sql, deviceIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func fetchExportReports(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]exportReport, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text, name, generated_at, delivery_status
		FROM report_records WHERE tenant_id = $1::uuid ORDER BY generated_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	reports := []exportReport{}
	for rows.Next() {
		var rep exportReport
		if err := rows.Scan(&rep.ID, &rep.Name, &rep.GeneratedAt, &rep.DeliveryStatus); err != nil {
			return nil, err
		}
		reports = append(reports, rep)
	}
	return reports, rows.Err()
}

func fetchExportAuditLog(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]exportAuditEntry, error) {
	rows, err := pool.Query(ctx, `
		SELECT id::text, device_id, event_type, subject, occurred_at
		FROM enforcement_audit WHERE tenant_id = $1::uuid ORDER BY occurred_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []exportAuditEntry{}
	for rows.Next() {
		var e exportAuditEntry
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.EventType, &e.Subject, &e.OccurredAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
