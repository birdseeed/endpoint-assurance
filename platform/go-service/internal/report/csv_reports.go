package report

import (
	"fmt"
	"strings"
	"time"
)

// CSV renderers for the customer report catalogue (PAT-2405). Each takes the
// same fetched data model as the PDF renderer of the same report, so one
// generation yields two files describing one moment. They return the file
// bytes; the portal stores them beside the PDF.

// executiveCSVHeader is the executive summary's fixed header. It has no
// generated_at column because the layout is metric,value; the time is a row.
var executiveCSVHeader = []string{"metric", "value"}

// PortalExecutiveCSV is the Executive Estate Summary as metric,value rows:
// the figures the PDF's summary band, severity pills and patch bar show,
// then its findings, devices-not-reporting, roster and hardware sections,
// in the PDF's order, with the section folded into the metric label. It
// carries no primary-user or other personal data, as the PDF does not.
func PortalExecutiveCSV(s ExecutiveSummary, ov PortalOverview, findings []PortalCVEFinding, devices PortalDevicesResult) ([]byte, error) {
	generated := ov.GeneratedAt
	if generated.IsZero() {
		generated = s.GeneratedAt
	}
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	generated = generated.UTC()

	var rows [][]string
	add := func(metric, value string) { rows = append(rows, []string{metric, value}) }

	add("Report: generated at", csvTime(generated))
	add("Report: tenant", fallback(prTenantName(s, ov)))
	add("Estate: total devices", csvInt(ov.DevicesTotal))
	add("Estate: macOS devices", csvInt(s.Estate.MacOSDevices))
	add("Estate: Windows devices", csvInt(s.Estate.WindowsDevices))
	add("Estate: other devices", csvInt(s.Estate.OtherDevices))
	add("Estate: devices reporting in the last 24 hours", csvInt(ov.DevicesReporting24h))
	add("Estate: retired devices", csvInt(ov.DevicesRetired))
	add("CIS Level 1: score out of 100", csvFloat(ov.CISScoreCurrent))
	add("Open findings: critical", csvInt(ov.FindingsOpen.Critical))
	add("Open findings: high", csvInt(ov.FindingsOpen.High))
	add("Open findings: medium", csvInt(ov.FindingsOpen.Medium))
	add("Open findings: low", csvInt(ov.FindingsOpen.Low))
	add("Patch posture: up to date", csvInt(ov.PatchStatus.UpToDate))
	add("Patch posture: updates pending", csvInt(ov.PatchStatus.Pending))
	add("Patch posture: failed", csvInt(ov.PatchStatus.Failed))
	add("Patch posture: not reported", csvInt(ov.PatchStatus.Unknown))
	add("Patch posture: median days since last patch", csvCount(s.Patching.MedianDaysSinceLastPatch))

	// Open vulnerability findings: value is the number of devices affected.
	for _, f := range findings {
		label := "Vulnerability finding: " + f.CVEID + " " + strings.TrimSpace(f.App+" "+f.Version)
		if f.Severity != "" {
			label += " (" + f.Severity + ")"
		}
		add(label, csvInt(f.DevicesAffected))
	}

	// Devices not reporting, as the PDF's coverage-gap section computes it.
	for _, d := range devices.Devices {
		if d.Retirement != nil {
			continue
		}
		switch {
		case d.LastSeen.IsZero():
			add("Not reporting: "+fallback(d.Hostname), "never reported")
		case generated.Sub(d.LastSeen) > prStaleAfter:
			add("Not reporting: "+fallback(d.Hostname),
				csvInt(int(generated.Sub(d.LastSeen).Hours()/24))+" days since last seen")
		}
	}

	// Device roster: value is score, encryption, patch status, last seen.
	for _, d := range devices.Devices {
		name := fallback(d.Hostname)
		if d.Retirement != nil {
			name += " (retired)"
		}
		enc := "not assessed"
		if d.EncryptionOK != nil {
			enc = "not encrypted"
			if *d.EncryptionOK {
				enc = "encrypted"
			}
		}
		patch := "up to date"
		switch {
		case d.PatchPending == nil:
			patch = "not reported"
		case *d.PatchPending:
			patch = "updates pending"
		}
		last := "never"
		if !d.LastSeen.IsZero() {
			last = csvTime(d.LastSeen)
		}
		add("Roster: "+name+" ("+strings.TrimSpace(d.OS+" "+d.OSVersion)+")",
			fmt.Sprintf("score %.0f%%; %s; patches %s; last seen %s", d.CompliancePct, enc, patch, last))
	}

	// Hardware health.
	withTelemetry, flagged := 0, 0
	for _, d := range devices.Devices {
		if !d.HasHardware {
			continue
		}
		withTelemetry++
		if d.HardwareFlag() {
			flagged++
		}
	}
	add("Hardware health: reporting telemetry", csvInt(withTelemetry))
	add("Hardware health: flagged", csvInt(flagged))
	for _, d := range devices.Devices {
		if reason := d.hardwareIssueSummary(); reason != "" {
			add("Hardware flagged: "+fallback(d.Hostname), reason)
		}
	}
	return writeCSVTable(executiveCSVHeader, rows)
}

var cisCSVColumns = []string{
	"metric", "value",
	"rule_key", "title", "severity", "devices_affected", "total_devices", "pct_affected", "undetermined_devices",
	"hostname", "os", "os_version", "compliance_pct", "failing_count", "critical_count", "undetermined_count",
}

// CISComplianceCSV: sections summary (metric,value), control (top failing
// controls) and device (devices needing attention).
func CISComplianceCSV(d CISComplianceReport) ([]byte, error) {
	var rows []csvRow
	for _, m := range []struct{ metric, value string }{
		{"compliance_pct", csvFloat(d.Compliance.OverallPct)},
		{"pass_evaluations", csvInt(d.Compliance.PassEvaluations)},
		{"fail_evaluations", csvInt(d.Compliance.FailEvaluations)},
		{"critical_fails", csvInt(d.Compliance.CriticalFails)},
		{"high_fails", csvInt(d.Compliance.HighFails)},
		{"medium_fails", csvInt(d.Compliance.MediumFails)},
		{"low_fails", csvInt(d.Compliance.LowFails)},
		{"undetermined_evaluations", csvInt(d.Compliance.UndeterminedEvaluations)},
	} {
		rows = append(rows, csvRow{"section": "summary", "metric": m.metric, "value": m.value})
	}
	for _, c := range d.TopFailing {
		rows = append(rows, csvRow{"section": "control", "rule_key": c.RuleKey, "title": c.Title,
			"severity": c.Severity, "devices_affected": csvInt(c.DevicesAffected),
			"total_devices": csvInt(c.TotalDevices), "pct_affected": csvFloat(c.PctAffected),
			"undetermined_devices": csvInt(c.UndeterminedDevices)})
	}
	for _, w := range d.WorstDevices {
		// PrimaryUser is deliberately not written: the customer PDF does not
		// show it either (PII guardrail, PAT-112).
		rows = append(rows, csvRow{"section": "device", "hostname": w.Hostname, "os": w.OS,
			"os_version": w.OSVersion, "compliance_pct": csvFloat(w.CompliancePct),
			"failing_count": csvInt(w.FailingCount), "critical_count": csvInt(w.CriticalCount),
			"undetermined_count": csvInt(w.UndeterminedCount)})
	}
	return writeReportCSV(d.GeneratedAt, true, cisCSVColumns, rows)
}

var cveCSVColumns = []string{
	"cve_id", "severity", "cvss", "published_at", "exploitation", "description",
	"hostname", "app_name", "app_version", "match_confidence", "fixed_version",
}

// FreeCVECSV is one row per (CVE, device, app) hit. A CVE with no hits is a
// row with the CVE columns only.
func FreeCVECSV(r FreeCVEReport) ([]byte, error) {
	var rows []csvRow
	for _, c := range r.CVEs {
		base := csvRow{"cve_id": c.CVEID, "severity": c.Severity, "cvss": csvFloatPtr(c.CVSSScore),
			"published_at": csvTimePtr(c.PublishedAt), "exploitation": c.Exploitation.Status,
			"description": c.Description}
		if len(c.Hits) == 0 {
			rows = append(rows, base)
			continue
		}
		for _, h := range c.Hits {
			row := csvRow{}
			for k, v := range base {
				row[k] = v
			}
			row["hostname"], row["app_name"], row["app_version"] = h.Hostname, h.AppName, h.AppVersion
			row["match_confidence"], row["fixed_version"] = h.MatchConfidence, h.FixedVersion
			rows = append(rows, row)
		}
	}
	return writeReportCSV(r.GeneratedAt, false, cveCSVColumns, rows)
}

func PatchStatusCSV(d PatchStatusReport) ([]byte, error) {
	var rows []csvRow
	for _, p := range d.Devices {
		rows = append(rows, csvRow{"hostname": p.Hostname, "os": p.OS, "os_version": p.OSVersion,
			"pending_count": csvInt(p.PendingCount)})
	}
	return writeReportCSV(d.GeneratedAt, false, []string{"hostname", "os", "os_version", "pending_count"}, rows)
}

var staleCSVColumns = []string{"hostname", "os", "os_version", "last_seen", "days_since", "threshold_days", "retired_at", "retired_by", "reported_after_retirement"}

// StaleEndpointsCSV: sections stale and retired.
func StaleEndpointsCSV(d StaleEndpointsReport) ([]byte, error) {
	var rows []csvRow
	for _, s := range d.Devices {
		rows = append(rows, csvRow{"section": "stale", "hostname": s.Hostname, "os": s.OS, "os_version": s.OSVersion,
			"last_seen": csvTime(s.LastSeen), "days_since": csvFloat(s.DaysSince), "threshold_days": csvInt(d.ThresholdDays)})
	}
	for _, r := range d.Retired {
		rows = append(rows, csvRow{"section": "retired", "hostname": r.Hostname, "os": r.OS,
			"last_seen": csvTime(r.LastSeen), "retired_at": csvTime(r.RetiredAt), "retired_by": r.RetiredBy,
			"reported_after_retirement": csvBool(r.ReportedAfterRetirement)})
	}
	return writeReportCSV(d.GeneratedAt, true, staleCSVColumns, rows)
}

// CertExpiryCSV: sections actionable, platform_root and suspicious.
func CertExpiryCSV(d CertExpiryReport) ([]byte, error) {
	var rows []csvRow
	add := func(section string, certs []ExpiryCert) {
		for _, c := range certs {
			rows = append(rows, csvRow{"section": section, "subject_cn": c.SubjectCN, "issuer_cn": c.IssuerCN,
				"sha1": c.SHA1, "hostname": c.Hostname, "not_after": csvTime(c.NotAfter), "days_until": csvInt(c.DaysUntil)})
		}
	}
	add("actionable", d.Certs)
	add("platform_root", d.PlatformRootCerts)
	add("suspicious", d.SuspiciousCerts)
	return writeReportCSV(d.GeneratedAt, true,
		[]string{"subject_cn", "issuer_cn", "sha1", "hostname", "not_after", "days_until"}, rows)
}

func EDRCoverageCSV(d EDRCoverageReport) ([]byte, error) {
	var rows []csvRow
	for _, e := range d.Devices {
		rows = append(rows, csvRow{"hostname": e.Hostname, "os": e.OS, "state": string(e.State),
			"tools": strings.Join(e.Tools, ";")})
	}
	return writeReportCSV(d.GeneratedAt, false, []string{"hostname", "os", "state", "tools"}, rows)
}

// EncryptionPostureCSV: sections device and finding.
func EncryptionPostureCSV(d EncryptionPostureReport) ([]byte, error) {
	var rows []csvRow
	for _, e := range d.Devices {
		// A row with no state, or any value other than the two definite ones,
		// prints unknown: the column never has a blank that reads as fine.
		state := e.State
		if state != EncryptionStateEncrypted && state != EncryptionStateNotEncrypted {
			state = EncryptionStateUnknown
		}
		rows = append(rows, csvRow{"section": "device", "hostname": e.Hostname, "os": e.OS,
			"state": state, "filevault": csvStrPtr(e.FileVault), "bitlocker": csvStrPtr(e.BitLocker)})
	}
	for _, f := range d.Findings {
		rows = append(rows, csvRow{"section": "finding", "finding_type": f.FindingType, "details": f.Details})
	}
	return writeReportCSV(d.GeneratedAt, true,
		[]string{"hostname", "os", "state", "filevault", "bitlocker", "finding_type", "details"}, rows)
}

// LocalAdminCSV carries admin_names exactly as the PDF of the same record
// does, to the same audience.
func LocalAdminCSV(d LocalAdminReport) ([]byte, error) {
	var rows []csvRow
	for _, l := range d.Devices {
		rows = append(rows, csvRow{"hostname": l.Hostname, "os": l.OS, "admin_count": csvCount(l.AdminCount),
			"risk": l.Risk, "admin_names": strings.Join(l.AdminNames, "; ")})
	}
	return writeReportCSV(d.GeneratedAt, false, []string{"hostname", "os", "admin_count", "risk", "admin_names"}, rows)
}

func NewSoftwareCSV(d NewSoftwareReport) ([]byte, error) {
	var rows []csvRow
	for _, p := range d.Data.Products {
		rows = append(rows, csvRow{"type": p.Type, "name": p.Name, "platform": p.Platform, "identifier": p.Identifier,
			"team_id": p.TeamID, "identity_basis": p.IdentityBasis, "approval_state": p.ApprovalState,
			"first_seen_at": csvTime(p.FirstSeenAt), "device_count": csvInt(p.DeviceCount),
			"first_device": p.FirstDevice.Hostname})
	}
	return writeReportCSV(d.GeneratedAt, false, []string{"type", "name", "platform", "identifier", "team_id",
		"identity_basis", "approval_state", "first_seen_at", "device_count", "first_device"}, rows)
}

var driftCSVColumns = []string{
	"type", "name", "platform", "identifier", "approval_state", "device_count", "stale_device_count",
	"observed_since", "marked_by", "marked_at", "devices",
	"hostname", "unapproved_product_count", "unapproved_products", "last_seen", "stale",
	"week_start", "recorded", "unapproved_total", "unreviewed_total",
}

// SoftwareDriftCSV: sections product, unapproved_present, top_device, trend.
func SoftwareDriftCSV(d SoftwareDriftReport) ([]byte, error) {
	var rows []csvRow
	for _, p := range d.Data.Products {
		rows = append(rows, csvRow{"section": "product", "type": p.Type, "name": p.Name, "platform": p.Platform,
			"identifier": govIdentifier(p.Product), "approval_state": p.ApprovalState,
			"device_count": csvInt(p.DeviceCount), "stale_device_count": csvInt(p.StaleDeviceCount),
			"observed_since": csvTime(p.ObservedSince)})
	}
	for _, u := range d.Data.UnapprovedPresent {
		hosts := make([]string, 0, len(u.Devices))
		for _, dev := range u.Devices {
			hosts = append(hosts, dev.Hostname)
		}
		by := "not recorded"
		if u.MarkedBy != nil {
			by = *u.MarkedBy
		}
		rows = append(rows, csvRow{"section": "unapproved_present", "type": u.Type, "name": u.Name,
			"platform": u.Platform, "identifier": govIdentifier(u.Product), "approval_state": "unapproved",
			"device_count": csvInt(u.DeviceCount), "stale_device_count": csvInt(u.StaleDeviceCount),
			"observed_since": csvTime(u.Since), "marked_by": by, "marked_at": csvTime(u.MarkedAt),
			"devices": strings.Join(hosts, "; ")})
	}
	for _, t := range d.Data.TopDevices {
		rows = append(rows, csvRow{"section": "top_device", "hostname": t.Hostname, "platform": t.Platform,
			"unapproved_product_count": csvInt(t.UnapprovedProductCount),
			"unapproved_products":      strings.Join(t.UnapprovedProductSample, "; "),
			"last_seen":                csvTime(t.LastSeen), "stale": csvBool(t.Stale)})
	}
	for _, p := range d.Data.Trend {
		rows = append(rows, csvRow{"section": "trend", "week_start": p.WeekStart, "recorded": csvBool(p.Recorded),
			"unapproved_total": csvIntPtr(p.UnapprovedProducts), "unreviewed_total": csvIntPtr(p.UnreviewedProducts)})
	}
	return writeReportCSV(d.GeneratedAt, true, driftCSVColumns, rows)
}

func ApprovedSoftwareCSV(d ApprovedSoftwareReport) ([]byte, error) {
	var rows []csvRow
	for _, p := range d.Data.Products {
		by := "operator"
		if p.ApprovedBy != nil {
			by = *p.ApprovedBy
		}
		ident := p.Identifier
		platform := p.Platform
		if p.Browser != "" || p.ExtensionID != "" {
			ident = p.ExtensionID
			if platform == "" {
				platform = p.Browser
			}
		}
		rows = append(rows, csvRow{"type": p.Type, "name": p.Name, "platform": platform, "identifier": ident,
			"team_id": p.TeamID, "publisher": p.Publisher, "approved_by": by, "approved_at": csvTime(p.ApprovedAt),
			"approved_via": p.ApprovedVia, "observed_installation_count": csvInt(p.ObservedInstallationCount)})
	}
	return writeReportCSV(d.GeneratedAt, false, []string{"type", "name", "platform", "identifier", "team_id",
		"publisher", "approved_by", "approved_at", "approved_via", "observed_installation_count"}, rows)
}

var toolingSeverityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// ToolingEvidenceCSV is one row per tooling item, with the item's
// assessments reduced to a count and the highest severity among them.
func ToolingEvidenceCSV(r ToolingEvidenceReport) ([]byte, error) {
	var rows []csvRow
	for _, it := range r.Items {
		highest, rank := "", 0
		for _, a := range it.Assessments {
			if a.HighestSeverity == nil {
				continue
			}
			if n := toolingSeverityRank[strings.ToLower(*a.HighestSeverity)]; n > rank {
				highest, rank = *a.HighestSeverity, n
			}
		}
		rows = append(rows, csvRow{"hostname": it.Hostname, "platform": it.Platform, "item_type": it.EntryKind,
			"identity": it.Identity, "name": it.Name, "version": csvStrPtr(it.Version), "publisher": csvStrPtr(it.Publisher),
			"source": it.Source, "collection_status": it.CollectionStatus, "lower_bound": csvBool(it.LowerBound),
			"policy_state": it.PolicyState, "observed_at": csvTime(it.ObservedAt), "last_used_at": csvTimePtr(it.LastUsedAt),
			"assessment_count": csvInt(len(it.Assessments)), "highest_severity": highest})
	}
	return writeReportCSV(r.GeneratedAt, false, []string{"hostname", "platform", "item_type", "identity", "name",
		"version", "publisher", "source", "collection_status", "lower_bound", "policy_state", "observed_at",
		"last_used_at", "assessment_count", "highest_severity"}, rows)
}

// InsuranceEvidenceCSV is one row per question on the evidence pack.
func InsuranceEvidenceCSV(d InsuranceEvidence) ([]byte, error) {
	var rows []csvRow
	for _, q := range d.Questions {
		row := csvRow{"id": q.ID, "group": q.Group, "title": q.Title, "question": q.Question, "status": q.Status,
			"reason": csvStrPtr(q.Reason), "unit": q.Answer.Unit, "percentage": csvFloatPtr(q.Answer.Percentage),
			"unknown_devices": csvIntPtr(q.UnknownDevices), "as_of": csvTimePtr(q.AsOf),
			"oldest_evidence_at": csvTimePtr(q.OldestEvidenceAt), "headline": q.Headline,
			"answer_text": q.AnswerText, "basis": q.Basis, "value": csvIntPtr(q.Answer.Value)}
		if q.Source != nil {
			row["source_label"], row["source_path"] = q.Source.Label, q.Source.Path
		}
		rows = append(rows, row)
	}
	return writeReportCSV(d.GeneratedAt, false, []string{"id", "group", "title", "question", "status", "reason",
		"value", "unit", "percentage", "unknown_devices", "as_of", "oldest_evidence_at", "headline", "answer_text",
		"basis", "source_label", "source_path"}, rows)
}
