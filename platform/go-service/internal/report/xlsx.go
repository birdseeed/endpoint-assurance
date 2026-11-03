package report

// XLSX report generation — PAT-370.
//
// RenderXLSX builds a workbook with up to six sheets depending on ContentType:
//   - Summary    — always included
//   - CVE Findings — included for "full" and "cve_only"
//   - CIS Controls  — included for "full" and "cis_only"
//   - Devices      — included for "full"
//   - Patch Activity — included for "full"
//   - Agent Health  — included for "full"
//
// Each sheet is formatted as an Excel Table (ListObject) so filter/sort/pivot
// work out of the box in Excel and Numbers.
//
// The data is fetched from Postgres via FetchXLSXData; the render step is pure
// and has no DB access so tests can build XLSXData by hand.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xuri/excelize/v2"

	"patched.im/api/internal/exploitation"
)

// ContentType controls which sheets the workbook includes.
type ContentType string

const (
	ContentTypeFull    ContentType = "full"
	ContentTypeCVEOnly ContentType = "cve_only"
	ContentTypeCISOnly ContentType = "cis_only"
)

// XLSXData is the self-contained data bag for one report workbook.
type XLSXData struct {
	GeneratedAt time.Time
	TenantName  string
	PeriodStart time.Time
	PeriodEnd   time.Time

	// Summary stats
	DeviceCount   int
	CVECount      int
	CompliancePct float64

	// Patching posture (PAT-1805). DevicesUpdateStateUnknown counts devices
	// no collector has ever reported an update state for (every Windows
	// device today, since pending_updates is populated only by the macOS
	// collector) — kept separate from DevicesUpToDate so a platform gap in
	// collection is never exported as a clean patch posture.
	DevicesUpToDate           int
	DevicesPendingUpdates     int
	DevicesUpdateStateUnknown int

	// NotAssessedDevices (PAT-1960) counts devices whose reported
	// device_class matches zero enabled rules for their platform — e.g. a
	// server under the workstation-only Windows 11 pack. Never counted as a
	// pass and never folded into an "undetermined"/error bucket: these
	// devices produced zero evaluations because no rule applied, not
	// because evidence was unreadable. NotAssessedReason is set whenever
	// NotAssessedDevices > 0.
	NotAssessedDevices int
	NotAssessedReason  string

	Devices       []XLSXDevice
	CVEFindings   []XLSXCVEFinding
	CISControls   []XLSXCISControl
	PatchActivity []XLSXPatchActivity
	AgentHealth   []XLSXAgentHealth
}

type XLSXDevice struct {
	Hostname     string
	Platform     string
	OSVersion    string
	AgentVersion string
	LastCheckIn  time.Time
	EnrolledAt   time.Time
}

type XLSXCVEFinding struct {
	CVEID             string
	Description       string
	DescriptionSource string
	Severity          string
	CVSSScore         string
	Device            string
	OS                string
	Component         string
	Version           string
	FirstSeen         time.Time
	LastSeen          time.Time
	PatchAvail        string // "Yes" | "No" | "Unknown"
	Confidence        string // "version_confirmed" | "version_unverified"
	Exploitation      exploitation.Assessment
}

type XLSXCISControl struct {
	ControlID   string
	Description string
	Severity    string
	Device      string
	Platform    string
	// Status: "pass" | "fail" | "error" | "not_applicable" | "not_evaluated" |
	// "undetermined". "undetermined" (PAT-1758/PAT-1762/PAT-1776) is a 'fail'
	// row with no observed value — unreadable evidence (an absent signal, or
	// the collector's literal "Unknown" sentinel), not a real observation of
	// non-compliance — and is reported as its own status rather than folded
	// into "fail" so an exported spreadsheet never reads as a real finding.
	// A "NotConfigured" fail has a non-nil observed value and stays "fail".
	Status   string
	Evidence string
}

type XLSXPatchActivity struct {
	Device    string
	AppName   string
	OldVer    string
	NewVer    string
	UpdatedAt time.Time
	Status    string
}

type XLSXAgentHealth struct {
	Device       string
	Platform     string
	AgentVersion string
	LastCheckIn  time.Time
	Status       string // "healthy" | "stale" | "missing"
}

// FetchXLSXData loads the data for an XLSX workbook for the given tenant.
// periodStart/End bound the patch activity sheet; pass zero values to omit the
// time filter (fetches all history).
func FetchXLSXData(ctx context.Context, pool *pgxpool.Pool, tenantID string,
	periodStart, periodEnd time.Time) (*XLSXData, error) {

	data := &XLSXData{
		GeneratedAt: time.Now().UTC(),
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}

	// Tenant name
	if err := pool.QueryRow(ctx,
		`SELECT name FROM tenants WHERE id = $1::uuid`, tenantID,
	).Scan(&data.TenantName); err != nil {
		return nil, fmt.Errorf("fetch tenant: %w", err)
	}

	// ─── Devices ──────────────────────────────────────────────────────────────
	// PAT-732: devices has no created_at column (first_seen/last_seen are the
	// NOT NULL enrolment/check-in timestamps) — the prior query referenced a
	// non-existent column and 500'd on every export.
	// PAT-861: same class of bug — devices has no os_platform column either.
	// The real column is `os` (migrations/0001_initial.sql:45). `os_platform`
	// only exists on the unrelated os_cve_advisories table (migration 0050).
	// All three queries below (Devices, CVE findings, CIS controls) must
	// select `os`/`d.os`, never `os_platform`/`d.os_platform`.
	rows, err := pool.Query(ctx, `
		SELECT
			COALESCE(hostname, id::text),
			COALESCE(os, ''),
			COALESCE(os_version,  ''),
			COALESCE(agent_version, ''),
			last_seen,
			first_seen
		FROM devices
		WHERE tenant_id = $1::uuid
		ORDER BY hostname`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("fetch devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d XLSXDevice
		if err := rows.Scan(&d.Hostname, &d.Platform, &d.OSVersion,
			&d.AgentVersion, &d.LastCheckIn, &d.EnrolledAt); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		data.Devices = append(data.Devices, d)
	}
	rows.Close()
	data.DeviceCount = len(data.Devices)

	// ─── CVE findings ─────────────────────────────────────────────────────────
	cveRows, err := pool.Query(ctx, `
		SELECT
			f.cve_id,
			COALESCE(c.description, ''),
			COALESCE(c.description_source, ''),
			COALESCE(c.severity, ''),
			COALESCE(c.cvss_v3_score::text, ''),
			COALESCE(d.hostname, d.id::text),
			COALESCE(d.os, ''),
			f.app_name,
			COALESCE(f.app_version, ''),
			f.first_seen_at,
			f.last_seen_at,
			f.match_confidence
		FROM device_cve_findings f
		JOIN devices           d ON d.id = f.device_id
		LEFT JOIN cve_feed_entries c ON c.cve_id = f.cve_id
		WHERE d.tenant_id = $1::uuid
		ORDER BY c.cvss_v3_score DESC NULLS LAST, f.cve_id, d.hostname`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("fetch cve findings: %w", err)
	}
	defer cveRows.Close()
	cveSet := map[string]struct{}{}
	for cveRows.Next() {
		var v XLSXCVEFinding
		if err := cveRows.Scan(&v.CVEID, &v.Description, &v.DescriptionSource, &v.Severity, &v.CVSSScore,
			&v.Device, &v.OS, &v.Component, &v.Version,
			&v.FirstSeen, &v.LastSeen, &v.Confidence); err != nil {
			return nil, fmt.Errorf("scan cve finding: %w", err)
		}
		v.PatchAvail = "Unknown"
		data.CVEFindings = append(data.CVEFindings, v)
		cveSet[v.CVEID] = struct{}{}
	}
	cveRows.Close()
	data.CVECount = len(cveSet)
	cveIDs := make([]string, 0, len(cveSet))
	for cveID := range cveSet {
		cveIDs = append(cveIDs, cveID)
	}
	assessments, err := exploitation.FetchAssessments(ctx, pool, cveIDs, data.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("fetch exploitation evidence: %w", err)
	}
	for i := range data.CVEFindings {
		data.CVEFindings[i].Exploitation = assessments[data.CVEFindings[i].CVEID]
	}

	// ─── CIS controls ─────────────────────────────────────────────────────────
	cisRows, err := pool.Query(ctx, `
		SELECT
			r.rule_key,
			r.title,
			r.severity,
			COALESCE(d.hostname, d.id::text),
			COALESCE(d.os, ''),
			CASE
				WHEN e.status = 'fail' AND e.observed_value IS NULL THEN 'undetermined'
				ELSE COALESCE(e.status, 'not_evaluated')
			END,
			''
		FROM compliance_rules r
		CROSS JOIN devices d
		LEFT JOIN compliance_evaluations e
			ON  e.rule_id    = r.id
			AND e.device_id  = d.id
		WHERE d.tenant_id = $1::uuid
		  AND r.enabled     = TRUE
		ORDER BY r.rule_key, d.hostname`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("fetch cis controls: %w", err)
	}
	defer cisRows.Close()
	for cisRows.Next() {
		var c XLSXCISControl
		if err := cisRows.Scan(&c.ControlID, &c.Description, &c.Severity,
			&c.Device, &c.Platform, &c.Status, &c.Evidence); err != nil {
			return nil, fmt.Errorf("scan cis control: %w", err)
		}
		data.CISControls = append(data.CISControls, c)
	}
	cisRows.Close()

	// ─── Compliance % ─────────────────────────────────────────────────────────
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(
			ROUND(
				100.0 * SUM(CASE WHEN e.status = 'pass' THEN 1 ELSE 0 END)
				/ NULLIF(COUNT(*), 0),
				1
			), 0)
		FROM compliance_evaluations e
		JOIN devices d ON d.id = e.device_id
		JOIN compliance_rules r ON r.id = e.rule_id
		WHERE d.tenant_id = $1::uuid
		  AND r.enabled = TRUE`, tenantID,
	).Scan(&data.CompliancePct); err != nil {
		data.CompliancePct = 0
	}

	// ─── Patching posture (PAT-1805) ──────────────────────────────────────────
	// Three-state device count: pending_updates IS NULL means no collector
	// has ever reported an update state for that device (every Windows
	// device today - pending_updates is populated only by the macOS
	// collector) and must not be counted as up to date. Mirrors
	// fetchPatchingStats' semantics in executive.go, but queried directly
	// here rather than via that function, since this sheet has no use for
	// its separate patches-table median-days calculation, and this file does
	// not apply platform-switch filtering anywhere else either.
	if err := pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE d.pending_updates IS NOT NULL AND jsonb_array_length(d.pending_updates) = 0)::int,
			COUNT(*) FILTER (WHERE jsonb_array_length(d.pending_updates) > 0)::int,
			COUNT(*) FILTER (WHERE d.pending_updates IS NULL)::int
		FROM devices d
		WHERE d.tenant_id = $1::uuid`, tenantID,
	).Scan(&data.DevicesUpToDate, &data.DevicesPendingUpdates, &data.DevicesUpdateStateUnknown); err != nil {
		return nil, fmt.Errorf("patching stats: %w", err)
	}

	// ─── Not assessed (PAT-1960) ───────────────────────────────────────────────
	// Devices whose reported device_class matches zero enabled rules for
	// their platform. Same predicate as executive.go's
	// fetchDeviceClassCoverage, queried directly here since this file
	// doesn't apply platform-switch filtering anywhere else either.
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (
			WHERE d.device_class <> 'unknown'
			  AND NOT EXISTS (
			      SELECT 1 FROM compliance_rules cr
			      WHERE cr.enabled = true
			        AND ((cr.platform = 'macos' AND d.os = 'macOS')
			          OR (cr.platform = 'windows' AND d.os = 'Windows'))
			        AND `+deviceClassMatch("d", "cr.device_class")+`
			  )
		)::int
		FROM devices d
		WHERE d.tenant_id = $1::uuid`, tenantID,
	).Scan(&data.NotAssessedDevices); err != nil {
		return nil, fmt.Errorf("not-assessed devices: %w", err)
	}
	if data.NotAssessedDevices > 0 {
		data.NotAssessedReason = notAssessedReason
	}

	// ─── Patch activity ───────────────────────────────────────────────────────
	// Pull from pending_updates JSONB on the devices table as a best-effort
	// source — a dedicated patch_log table is future work.
	// We surface pending updates (i.e. updates that haven't been applied yet)
	// as "Pending" status rows.
	patchRows, err := pool.Query(ctx, `
		SELECT
			COALESCE(d.hostname, d.id::text),
			pu->>'name',
			COALESCE(pu->>'current_version', ''),
			COALESCE(pu->>'available_version', ''),
			d.last_seen,
			'Pending'
		FROM devices d,
			 LATERAL jsonb_array_elements(COALESCE(d.pending_updates, '[]'::jsonb)) AS pu
		WHERE d.tenant_id = $1::uuid
		ORDER BY d.hostname, pu->>'name'`, tenantID)
	if err == nil {
		defer patchRows.Close()
		for patchRows.Next() {
			var p XLSXPatchActivity
			if err := patchRows.Scan(&p.Device, &p.AppName, &p.OldVer,
				&p.NewVer, &p.UpdatedAt, &p.Status); err == nil {
				data.PatchActivity = append(data.PatchActivity, p)
			}
		}
		patchRows.Close()
	}

	// ─── Agent health ─────────────────────────────────────────────────────────
	staleThreshold := time.Now().UTC().Add(-14 * 24 * time.Hour)
	for _, d := range data.Devices {
		status := "healthy"
		if d.LastCheckIn.IsZero() {
			status = "missing"
		} else if d.LastCheckIn.Before(staleThreshold) {
			status = "stale"
		}
		data.AgentHealth = append(data.AgentHealth, XLSXAgentHealth{
			Device:       d.Hostname,
			Platform:     d.Platform,
			AgentVersion: d.AgentVersion,
			LastCheckIn:  d.LastCheckIn,
			Status:       status,
		})
	}

	return data, nil
}

// RenderXLSX generates an XLSX workbook byte slice from XLSXData.
// contentType controls which sheets are written.
func RenderXLSX(data *XLSXData, contentType ContentType) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	// Delete the auto-created Sheet1.
	f.DeleteSheet("Sheet1")

	if err := writeXLSXSummary(f, data); err != nil {
		return nil, fmt.Errorf("summary sheet: %w", err)
	}

	if contentType == ContentTypeFull || contentType == ContentTypeCVEOnly {
		if err := writeXLSXCVEFindings(f, data); err != nil {
			return nil, fmt.Errorf("cve sheet: %w", err)
		}
	}
	if contentType == ContentTypeFull || contentType == ContentTypeCISOnly {
		if err := writeXLSXCISControls(f, data); err != nil {
			return nil, fmt.Errorf("cis sheet: %w", err)
		}
	}
	if contentType == ContentTypeFull {
		if err := writeXLSXDevices(f, data); err != nil {
			return nil, fmt.Errorf("devices sheet: %w", err)
		}
		if err := writeXLSXPatchActivity(f, data); err != nil {
			return nil, fmt.Errorf("patch sheet: %w", err)
		}
		if err := writeXLSXAgentHealth(f, data); err != nil {
			return nil, fmt.Errorf("agent health sheet: %w", err)
		}
	}

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("write buffer: %w", err)
	}
	return buf.Bytes(), nil
}

// ─── sheet writers ─────────────────────────────────────────────────────────────

func writeXLSXSummary(f *excelize.File, data *XLSXData) error {
	sheet := "Summary"
	f.NewSheet(sheet)

	bold, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 11}})
	header, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"1E3A5F"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	_ = bold
	_ = header

	rows := [][]interface{}{
		{"Field", "Value"},
		{"Tenant", data.TenantName},
		{"Generated At", data.GeneratedAt.Format(time.RFC3339)},
		{"Period Start", fmtDate(data.PeriodStart)},
		{"Period End", fmtDate(data.PeriodEnd)},
		{"Device Count", data.DeviceCount},
		{"CVE Count (unique)", data.CVECount},
		{"Compliance Score (%)", fmt.Sprintf("%.1f", data.CompliancePct)},
		{"Devices Up To Date", data.DevicesUpToDate},
		{"Devices With Pending Updates", data.DevicesPendingUpdates},
		// PAT-1805: honest bucket for devices no collector has reported an
		// update state for, rather than folding them into "Up To Date".
		{"Devices, Update State Not Reported", data.DevicesUpdateStateUnknown},
		// PAT-1960: devices whose device_class matches no enabled rule for
		// their platform — never a pass, never folded into "undetermined".
		{"Devices Not Assessed (No Benchmark For Device Class)", data.NotAssessedDevices},
	}
	if data.NotAssessedReason != "" {
		rows = append(rows, []interface{}{"Not Assessed Reason", data.NotAssessedReason})
	}

	for i, row := range rows {
		cell, _ := excelize.CoordinatesToCellName(1, i+1)
		f.SetSheetRow(sheet, cell, &row)
	}

	f.SetColWidth(sheet, "A", "A", 28)
	f.SetColWidth(sheet, "B", "B", 40)

	// Apply header style to row 1
	for col := 1; col <= 2; col++ {
		c, _ := excelize.CoordinatesToCellName(col, 1)
		f.SetCellStyle(sheet, c, c, header)
	}

	return nil
}

func writeXLSXCVEFindings(f *excelize.File, data *XLSXData) error {
	sheet := "CVE Findings"
	f.NewSheet(sheet)

	headers := []interface{}{
		"CVE ID", "Description", "Description Source", "Severity", "CVSS Score", "Device", "OS",
		"Component", "Installed Version", "First Seen", "Last Seen",
		"Patch Available", "Match Confidence", "Exploitation Status", "Exploitation Source",
		"Exploitation Source URL", "Exploitation Source Fetched", "Exploitation Match Basis",
		"Exploitation Unavailable Reason",
	}
	f.SetSheetRow(sheet, "A1", &headers)

	for i, v := range data.CVEFindings {
		sources, fetched, bases, unavailable := exploitationProvenanceColumns(v.Exploitation)
		row := []interface{}{
			v.CVEID, v.Description, v.DescriptionSource, v.Severity, v.CVSSScore, v.Device, v.OS,
			v.Component, v.Version,
			fmtTime(v.FirstSeen), fmtTime(v.LastSeen),
			v.PatchAvail, v.Confidence, exploitationStatusLabel(v.Exploitation), sources,
			exploitationSourceURLs(v.Exploitation),
			fetched, bases, unavailable,
		}
		cell, _ := excelize.CoordinatesToCellName(1, i+2)
		f.SetSheetRow(sheet, cell, &row)
	}

	setTableStyle(f, sheet, 19, len(data.CVEFindings)+1, "TableCVE")
	setColumnWidths(f, sheet, []int{15, 44, 18, 10, 10, 22, 12, 24, 18, 16, 16, 14, 20, 20, 18, 64, 24, 42, 26})
	return nil
}

func writeXLSXCISControls(f *excelize.File, data *XLSXData) error {
	sheet := "CIS Controls"
	f.NewSheet(sheet)

	headers := []interface{}{
		"Control ID", "Description", "Severity", "Device", "Platform", "Status", "Evidence",
	}
	f.SetSheetRow(sheet, "A1", &headers)

	for i, c := range data.CISControls {
		row := []interface{}{
			c.ControlID, c.Description, c.Severity,
			c.Device, c.Platform, c.Status, c.Evidence,
		}
		cell, _ := excelize.CoordinatesToCellName(1, i+2)
		f.SetSheetRow(sheet, cell, &row)
	}

	setTableStyle(f, sheet, 7, len(data.CISControls)+1, "TableCIS")
	setColumnWidths(f, sheet, []int{18, 48, 10, 22, 10, 14, 40})
	return nil
}

func writeXLSXDevices(f *excelize.File, data *XLSXData) error {
	sheet := "Devices"
	f.NewSheet(sheet)

	headers := []interface{}{
		"Device Name", "OS Platform", "OS Version", "Agent Version",
		"Last Check-in", "Enrolled Date",
	}
	f.SetSheetRow(sheet, "A1", &headers)

	for i, d := range data.Devices {
		row := []interface{}{
			d.Hostname, d.Platform, d.OSVersion, d.AgentVersion,
			fmtTime(d.LastCheckIn), fmtDate(d.EnrolledAt),
		}
		cell, _ := excelize.CoordinatesToCellName(1, i+2)
		f.SetSheetRow(sheet, cell, &row)
	}

	setTableStyle(f, sheet, 6, len(data.Devices)+1, "TableDevices")
	setColumnWidths(f, sheet, []int{28, 12, 18, 16, 20, 16})
	return nil
}

func writeXLSXPatchActivity(f *excelize.File, data *XLSXData) error {
	sheet := "Patch Activity"
	f.NewSheet(sheet)

	headers := []interface{}{
		"Device", "Application", "Current Version", "Available Version", "As Of", "Status",
	}
	f.SetSheetRow(sheet, "A1", &headers)

	for i, p := range data.PatchActivity {
		row := []interface{}{
			p.Device, p.AppName, p.OldVer, p.NewVer,
			fmtTime(p.UpdatedAt), p.Status,
		}
		cell, _ := excelize.CoordinatesToCellName(1, i+2)
		f.SetSheetRow(sheet, cell, &row)
	}

	setTableStyle(f, sheet, 6, len(data.PatchActivity)+1, "TablePatch")
	setColumnWidths(f, sheet, []int{28, 32, 18, 18, 20, 12})
	return nil
}

func writeXLSXAgentHealth(f *excelize.File, data *XLSXData) error {
	sheet := "Agent Health"
	f.NewSheet(sheet)

	headers := []interface{}{
		"Device", "Platform", "Agent Version", "Last Check-in", "Status",
	}
	f.SetSheetRow(sheet, "A1", &headers)

	for i, a := range data.AgentHealth {
		row := []interface{}{
			a.Device, a.Platform, a.AgentVersion,
			fmtTime(a.LastCheckIn), a.Status,
		}
		cell, _ := excelize.CoordinatesToCellName(1, i+2)
		f.SetSheetRow(sheet, cell, &row)
	}

	setTableStyle(f, sheet, 5, len(data.AgentHealth)+1, "TableAgentHealth")
	setColumnWidths(f, sheet, []int{28, 12, 16, 20, 12})
	return nil
}

// ─── helpers ───────────────────────────────────────────────────────────────────

// setTableStyle wraps a range in an Excel Table for filter/sort/pivot support.
// colCount is the number of columns; rowCount is total rows including header.
func setTableStyle(f *excelize.File, sheet string, colCount, rowCount int, name string) {
	if rowCount < 2 {
		// No data rows — skip table creation to avoid an empty-range error.
		return
	}
	endCol, _ := excelize.ColumnNumberToName(colCount)
	tableRange := fmt.Sprintf("A1:%s%d", endCol, rowCount)
	_ = f.AddTable(sheet, &excelize.Table{
		Range:          tableRange,
		Name:           name,
		StyleName:      "TableStyleMedium2",
		ShowRowStripes: func() *bool { b := true; return &b }(),
	})
}

func setColumnWidths(f *excelize.File, sheet string, widths []int) {
	for i, w := range widths {
		col, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth(sheet, col, col, float64(w))
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}
