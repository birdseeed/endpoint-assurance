package report

import (
	"os"
	"strings"
	"testing"
	"time"
)

func fixturePortalOverview() PortalOverview {
	return PortalOverview{
		TenantName:          "Acme SME Co",
		GeneratedAt:         time.Date(2026, 7, 3, 9, 30, 0, 0, time.UTC),
		DevicesTotal:        12,
		DevicesReporting24h: 10,
		CISScoreCurrent:     78.4,
		FindingsOpen:        PortalSeverityCounts{Critical: 2, High: 9, Medium: 14, Low: 6},
		PatchStatus:         PortalPatchStatus{UpToDate: 8, Pending: 4, Failed: 0, Unknown: 2},
	}
}

func fixturePortalFindings() []PortalCVEFinding {
	cvss := func(v float64) *float64 { return &v }
	base := time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)
	return []PortalCVEFinding{
		{CVEID: "CVE-2026-30334", Severity: "critical", CVSS: cvss(9.8),
			App: "Google Chrome", Version: "137.0.7151.55", DevicesAffected: 6, FirstSeen: base},
		{CVEID: "CVE-2026-24085", Severity: "high", CVSS: cvss(8.1),
			App: "Zoom Workplace", Version: "6.4.1", DevicesAffected: 4, FirstSeen: base.AddDate(0, 0, 6)},
		{CVEID: "CVE-2026-1897", Severity: "medium", CVSS: cvss(5.4),
			App: "Slack", Version: "4.43.51", DevicesAffected: 3, FirstSeen: base.AddDate(0, 0, 11)},
		{CVEID: "CVE-2026-0450", Severity: "low", CVSS: cvss(3.1),
			App: "Visual Studio Code", Version: "1.101.0", DevicesAffected: 2, FirstSeen: base.AddDate(0, 0, 14)},
		{CVEID: "CVE-2026-9999", Severity: "",
			App:     "A Very Long Application Name That Will Certainly Need Truncating In The Table",
			Version: "0.0.1-beta.7+build.2026", DevicesAffected: 1, FirstSeen: base.AddDate(0, 0, 20)},
	}
}

func fixturePortalDevices(now time.Time) PortalDevicesResult {
	bp := func(v bool) *bool { return &v }
	mk := func(host, os, ver string, pct float64, enc *bool, pending *bool, lastSeen time.Time) PortalDeviceRow {
		return PortalDeviceRow{
			TenantDeviceRow: TenantDeviceRow{
				Hostname: host, OS: os, OSVersion: ver,
				CompliancePct: pct, LastSeen: lastSeen,
			},
			EncryptionOK: enc,
			PatchPending: pending,
		}
	}
	rows := []PortalDeviceRow{
		mk("finance-mbp-03", "macOS", "15.5", 94.1, bp(true), bp(false), now.Add(-2*time.Hour)),
		mk("dev-mbp-12", "macOS", "15.4.1", 88.2, bp(true), bp(true), now.Add(-26*time.Hour)),
		mk("ops-windows-01", "Windows", "11 24H2", 85.0, bp(true), nil, now.Add(-3*time.Hour)),
		mk("marketing-mac-04", "macOS", "15.4.1", 41.2, bp(false), bp(true), now.Add(-1*time.Hour)),
		mk("andys-macbook", "macOS", "15.4.1", 70.6, nil, bp(true), now.Add(-49*time.Hour)),
		mk("reception-imac", "macOS", "14.7.5", 62.0, bp(true), bp(false), now.AddDate(0, 0, -12)),
		mk("warehouse-laptop", "Windows", "10 22H2", 55.5, bp(false), nil, now.AddDate(0, 0, -21)),
		mk("spare-macbook-air", "macOS", "15.2", 0, nil, bp(false), time.Time{}),
	}
	return PortalDevicesResult{Total: len(rows), Devices: rows}
}

// TestRenderPortalReportPDF_Brand renders the full customer report with
// representative data and asserts it is a valid, multi-page PDF. Set
// PORTAL_PDF_SAMPLE=/path/to/out.pdf to also write the rendered sample.
func TestRenderPortalReportPDF_Brand(t *testing.T) {
	s := fixtureExecutiveSummary()
	ov := fixturePortalOverview()
	findings := fixturePortalFindings()
	devices := fixturePortalDevices(ov.GeneratedAt)

	pdf, err := RenderPortalReportPDF(s, ov, findings, devices, false)
	if err != nil {
		t.Fatalf("RenderPortalReportPDF: %v", err)
	}
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Fatalf("output is not a PDF (first 8 bytes: %q)", pdf[:8])
	}
	if len(pdf) < 20000 {
		t.Fatalf("PDF suspiciously small: %d bytes", len(pdf))
	}
	// Page objects appear uncompressed in fpdf output; "/Type /Pages" is the
	// tree root, everything else is a real page.
	body := string(pdf)
	pages := strings.Count(body, "/Type /Page") - strings.Count(body, "/Type /Pages")
	if pages < 3 {
		t.Errorf("expected a multi-page report (cover + summary + tables), got %d pages", pages)
	}

	if out := os.Getenv("PORTAL_PDF_SAMPLE"); out != "" {
		if err := os.WriteFile(out, pdf, 0o644); err != nil {
			t.Fatalf("write sample: %v", err)
		}
		t.Logf("sample written to %s (%d bytes, %d pages)", out, len(pdf), pages)
	}
}

// TestRenderPortalReportPDF_EmptyEstate: a tenant with no devices, findings
// or telemetry must still get a valid document, not a panic or an error.
func TestRenderPortalReportPDF_EmptyEstate(t *testing.T) {
	pdf, err := RenderPortalReportPDF(ExecutiveSummary{},
		PortalOverview{TenantName: "Empty Co"}, nil, PortalDevicesResult{}, false)
	if err != nil {
		t.Fatalf("RenderPortalReportPDF (empty): %v", err)
	}
	if !strings.HasPrefix(string(pdf[:8]), "%PDF-") {
		t.Fatalf("output is not a PDF (first 8 bytes: %q)", pdf[:8])
	}
}

// TestRenderPortalReportPDF_HardwareHealthGating locks the PAT-686 Tier 2+
// gate at the renderer boundary: includeHardwareHealth=false must render
// (and must not panic or error) exactly like a report with no hardware
// section at all, while =true with hardware data present renders more
// content. fpdf compresses page content streams by default, so this can't
// grep for the section's literal text (see hardwareIssueSummary's own unit
// test in admin_test.go for the narration logic) — the byte-length increase
// plus a clean render on both edges (no hardware data, all-flagged, all-ok)
// is the practical signal available here.
func TestRenderPortalReportPDF_HardwareHealthGating(t *testing.T) {
	pct := func(v int) *int { return &v }
	i64 := func(v int64) *int64 { return &v }
	str := func(v string) *string { return &v }

	devices := PortalDevicesResult{
		Total: 3,
		Devices: []PortalDeviceRow{
			{TenantDeviceRow: TenantDeviceRow{
				Hostname: "MACLT-18", HasHardware: true,
				BatteryMaxCapacityPct: pct(62), BatteryCycleCount: pct(412),
				SMARTStatus: str("Verified"), StorageFreeBytes: i64(200 << 30),
			}},
			{TenantDeviceRow: TenantDeviceRow{
				Hostname: "WINLT-11", HasHardware: true,
				BatteryMaxCapacityPct: pct(95), SMARTStatus: str("Failing"),
				StorageFreeBytes: i64(200 << 30),
			}},
			{TenantDeviceRow: TenantDeviceRow{
				Hostname: "MACLT-30", HasHardware: true,
				BatteryMaxCapacityPct: pct(95), SMARTStatus: str("Verified"),
				StorageFreeBytes: i64(200 << 30),
			}},
		},
	}

	s := fixtureExecutiveSummary()
	ov := fixturePortalOverview()

	pdfTier1, err := RenderPortalReportPDF(s, ov, nil, devices, false)
	if err != nil {
		t.Fatalf("render (tier 1): %v", err)
	}
	if !strings.HasPrefix(string(pdfTier1[:8]), "%PDF-") {
		t.Fatalf("tier 1 output is not a PDF")
	}

	pdfTier2, err := RenderPortalReportPDF(s, ov, nil, devices, true)
	if err != nil {
		t.Fatalf("render (tier 2+): %v", err)
	}
	if !strings.HasPrefix(string(pdfTier2[:8]), "%PDF-") {
		t.Fatalf("tier 2+ output is not a PDF")
	}

	if len(pdfTier2) <= len(pdfTier1) {
		t.Errorf("expected the tier 2+ report (with Hardware health) to be larger than tier 1: %d vs %d bytes",
			len(pdfTier2), len(pdfTier1))
	}

	// Zero-hardware and all-flagged edges must not panic or error either.
	if _, err := RenderPortalReportPDF(s, ov, nil, PortalDevicesResult{}, true); err != nil {
		t.Fatalf("render (tier 2+, no devices): %v", err)
	}
}

// TestPortalPlainEnglishSummary_BrandLanguage locks the customer-facing
// language rules: UK plain English, "estate" never "fleet", no em dashes.
func TestPortalPlainEnglishSummary_BrandLanguage(t *testing.T) {
	cases := []PortalOverview{
		fixturePortalOverview(),
		{DevicesTotal: 3, DevicesReporting24h: 3, CISScoreCurrent: 100},
		{DevicesTotal: 5, FindingsOpen: PortalSeverityCounts{Medium: 2},
			PatchStatus: PortalPatchStatus{UpToDate: 4, Pending: 1}},
	}
	for _, ov := range cases {
		for _, para := range portalPlainEnglishSummary(ExecutiveSummary{}, ov) {
			lower := strings.ToLower(para)
			if strings.Contains(lower, "fleet") {
				t.Errorf("summary uses 'fleet', must be 'estate': %q", para)
			}
			if strings.Contains(para, "—") {
				t.Errorf("summary contains an em dash: %q", para)
			}
		}
	}
}
