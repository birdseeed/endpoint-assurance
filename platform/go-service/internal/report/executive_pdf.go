package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// RenderExecutiveSummaryPDF turns an ExecutiveSummary into a printable PDF.
// Same brand language as the per-workstation report — image header, tagline,
// horizontal rules, conservative tables — but the body is KPI bands and
// top-N tables rather than per-control drill-down. Target reader: CEO / CFO
// / auditor reviewer wanting the gestalt in 60 seconds.
func RenderExecutiveSummaryPDF(s ExecutiveSummary) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Endpoint Estate Executive Summary", true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)

	if err := registerHeader(pdf); err != nil {
		return nil, err
	}

	pdf.SetFooterFunc(func() {
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()),
			"", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")

	pdf.AddPage()

	renderExecHeader(pdf, s)
	renderExecEstate(pdf, s)
	renderExecCompliance(pdf, s)
	renderExecCoverage(pdf, s)
	renderExecTopFailing(pdf, s)
	renderExecWorstDevices(pdf, s)
	renderExecPatching(pdf, s)
	renderExecRecommendations(pdf, s)
	renderExecCloser(pdf, s)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write executive summary pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// --- Sections --------------------------------------------------------------

func renderExecHeader(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	// Brand image (same 80mm width as the per-workstation report).
	imageWidth := 80.0
	x := (210.0 - imageWidth) / 2
	pdf.ImageOptions("header.png", x, topMargin, imageWidth, 0, false,
		fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	pdf.SetY(topMargin + imageWidth*0.6 + 3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Security  |  Compliance  |  Patch Management",
		"", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.6)

	pdf.Ln(4)
	pdf.SetFont(reportFont, "B", 18)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 10, "Endpoint Estate Executive Summary", "", 1, "C", false, 0, "")

	pdf.Ln(1)
	pdf.SetFont(reportFont, "", 10)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for", "", 1, "C", false, 0, "")

	pdf.SetFont(reportFont, "B", 13)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, fallback(s.Tenant), "", 1, "C", false, 0, "")

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 5,
		"Report Date: "+s.GeneratedAt.Format("02 Jan 2006"),
		"", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "Classification: Confidential", "", 1, "C", false, 0, "")
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im Ltd  |  patched.im", "", 1, "C", false, 0, "")

	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(4)
}

func renderExecEstate(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	sectionHeader(pdf, "Estate")

	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", s.Estate.TotalDevices), label: "Devices"},
		{value: fmt.Sprintf("%d", s.Estate.MacOSDevices), label: "macOS"},
		{value: fmt.Sprintf("%d", s.Estate.WindowsDevices), label: "Windows"},
		{value: fmt.Sprintf("%d", s.Estate.ActiveLast7d), label: "Active (last 7d)"},
	})
	pdf.Ln(3)
}

func renderExecCompliance(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	sectionHeader(pdf, "Compliance Posture")

	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%.1f%%", s.Compliance.OverallPct), label: "Overall compliance"},
		{value: fmt.Sprintf("%d", s.Compliance.PassEvaluations), label: "Passing evaluations"},
		{value: fmt.Sprintf("%d", s.Compliance.FailEvaluations), label: "Failing evaluations"},
		{value: fmt.Sprintf("%d", s.Compliance.CriticalFails+s.Compliance.HighFails), label: "Critical + High fails"},
		{value: fmt.Sprintf("%d", s.Compliance.UndeterminedEvaluations), label: "Could not be determined"},
	})
	pdf.Ln(1)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4,
		"Compliance is the per-device average across the estate. A single broken device in a 100-strong estate reads as ~1% impact, not as estate-wide ruin. Evaluations are the most recent per (device, rule) pair. \"Could not be determined\" evaluations are excluded from the failing count above. The collector could not read the control, which is not the same claim as a device being checked and found non-compliant.",
		"", "L", false)
	pdf.Ln(2)
}

// renderExecCoverage renders the PAT-1794 "how much of the benchmark are we
// actually running" line — plain language plus the raw counts, not raw
// numbers alone with no context. Out-of-scope (T3) controls are named
// explicitly rather than folded into "evaluated" or silently dropped, so an
// omitted control never reads as a pass.
func renderExecCoverage(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	if s.Coverage.ControlsTotal == 0 {
		return
	}
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	line := fmt.Sprintf(
		"Controls evaluated: %d of %d defined for this estate's platforms (%d are Tier 3 manual-review controls, out of scope for automated evaluation and not counted as evaluated).",
		s.Coverage.ControlsEvaluated, s.Coverage.ControlsTotal, s.Coverage.ControlsOutOfScope)
	pdf.MultiCell(0, 4.5, line, "", "L", false)

	// PAT-1960: device_class rule matching means some devices produce zero
	// evaluations by design (their class matches no enabled rule for their
	// platform) rather than being scored. Surface the count and the reason
	// rather than let it read as a silent gap in the numbers above.
	if s.Coverage.NotAssessedDevices > 0 {
		pdf.Ln(1)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4.5, fmt.Sprintf(
			"%d device%s not assessed: no benchmark for this device class.",
			s.Coverage.NotAssessedDevices, plural(s.Coverage.NotAssessedDevices)),
			"", "L", false)
	}
	if s.Coverage.DeviceClassUnreportedDevices > 0 {
		pdf.Ln(1)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4.5, fmt.Sprintf(
			"%d device%s scored under the pre-device-class rule set: device class not reported.",
			s.Coverage.DeviceClassUnreportedDevices, plural(s.Coverage.DeviceClassUnreportedDevices)),
			"", "L", false)
	}
	pdf.Ln(2)
}

func renderExecTopFailing(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	if len(s.TopFailing) == 0 {
		sectionHeader(pdf, "Top Failing Controls")
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No failing controls across the evaluated estate.",
			"", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	sectionHeader(pdf, fmt.Sprintf("Top Failing Controls (top %d)", len(s.TopFailing)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4, "Ranked by number of devices in the estate failing each control.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{20, 100, 25, 29}
	tableHeader(pdf, []string{"Severity", "Control", "Devices", "% of estate"}, widths)
	rows := make([][]string, 0, len(s.TopFailing))
	undetermined := 0
	for _, tc := range s.TopFailing {
		rows = append(rows, []string{
			titleCase(tc.Severity),
			tc.Title,
			fmt.Sprintf("%d / %d", tc.DevicesAffected, tc.TotalDevices),
			fmt.Sprintf("%.0f%%", tc.PctAffected),
		})
		undetermined += tc.UndeterminedDevices
	}
	tableBody(pdf, rows, widths, true)

	// PAT-1758: devices whose evidence for one of these controls could not
	// be read (collector "Unknown", or no reading at all) are excluded from
	// the Devices/% of estate columns above rather than counted as failing.
	// Surface that honestly rather than silently dropping it.
	if undetermined > 0 {
		pdf.Ln(1)
		pdf.SetFont(reportFont, "I", 8)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4,
			fmt.Sprintf("Could not be determined on %d device%s among the controls above (unreadable evidence), excluded from the counts shown.",
				undetermined, plural(undetermined)),
			"", "L", false)
	}
	pdf.Ln(3)
}

func renderExecWorstDevices(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	if len(s.WorstDevices) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Devices Needing Attention (top %d)", len(s.WorstDevices)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4, "Ranked by critical-severity failures first, then by total failing controls.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{55, 50, 22, 22, 25}
	tableHeader(pdf, []string{"Hostname", "OS", "Score", "Failing", "Critical"}, widths)
	rows := make([][]string, 0, len(s.WorstDevices))
	undetermined := 0
	for _, w := range s.WorstDevices {
		osStr := w.OS
		if w.OSVersion != "" {
			osStr = w.OS + " " + w.OSVersion
		}

		// Primary-user attribution (PAT-116).
		// PII guardrail: only render when the tenant has explicitly opted in via
		// report_user_attribution (default "off"). Controlled by PAT-112 DPA.
		hostnameCell := truncate(w.Hostname, 32)
		if s.UserAttributionToggle != "off" && w.PrimaryUser != "" {
			var displayUser string
			switch s.UserAttributionToggle {
			case "local_part":
				displayUser = strings.SplitN(w.PrimaryUser, "@", 2)[0]
			case "full_upn":
				displayUser = w.PrimaryUser
			}
			if displayUser != "" {
				hostnameCell = truncate(w.Hostname, 24) + " (" + truncate(displayUser, 18) + ")"
			}
		}

		rows = append(rows, []string{
			hostnameCell,
			truncate(osStr, 28),
			fmt.Sprintf("%.0f%%", w.CompliancePct),
			fmt.Sprintf("%d", w.FailingCount),
			fmt.Sprintf("%d", w.CriticalCount),
		})
		undetermined += w.UndeterminedCount
	}
	tableBody(pdf, rows, widths, true)

	// PAT-1758: Failing/Critical above count only real, evidenced fails.
	// Surface undetermined evidence among these same devices honestly
	// rather than silently dropping it (a device whose ONLY fails are
	// undetermined never reaches this list at all — see fetchWorstDevices).
	if undetermined > 0 {
		pdf.Ln(1)
		pdf.SetFont(reportFont, "I", 8)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4,
			fmt.Sprintf("Could not be determined on %d additional evaluation%s among the devices above (unreadable evidence), excluded from Failing/Critical.",
				undetermined, plural(undetermined)),
			"", "L", false)
	}
	pdf.Ln(3)
}

func renderExecPatching(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	sectionHeader(pdf, "Patching Posture")

	median := "—"
	if s.Patching.MedianDaysSinceLastPatch >= 0 {
		median = fmt.Sprintf("%d days", s.Patching.MedianDaysSinceLastPatch)
	}
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", s.Patching.DevicesUpToDate), label: "Up to date"},
		{value: fmt.Sprintf("%d", s.Patching.DevicesPendingUpdates), label: "Pending updates"},
		// PAT-1805: devices no collector has reported an update state for
		// (every Windows device today) get their own honest KPI rather than
		// being folded into "Up to date".
		{value: fmt.Sprintf("%d", s.Patching.DevicesUpdateStateUnknown), label: "Update state not reported"},
		{value: median, label: "Median since last patch"},
		{value: kpiPlaceholder(s.Estate.TotalDevices, "—"), label: "Devices"},
	})
	pdf.Ln(3)
}

func renderExecRecommendations(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	if len(s.Recommendations) == 0 {
		return
	}
	sectionHeader(pdf, "Recommendations")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	for i, rec := range s.Recommendations {
		pdf.SetFont(reportFont, "B", 9)
		pdf.CellFormat(8, 5, fmt.Sprintf("%d.", i+1), "", 0, "L", false, 0, "")
		pdf.SetFont(reportFont, "", 9)
		// MultiCell wraps at the right margin; using fixed indent so the
		// number+text reads as a hanging-indent list.
		pdf.MultiCell(0, 4.5, rec, "", "L", false)
		pdf.Ln(0.5)
	}
}

func renderExecCloser(pdf *fpdf.Fpdf, s ExecutiveSummary) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This executive summary was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent across the tenant's enrolled devices, evaluated against the CIS Apple macOS Level 1 benchmark and the patched.im baseline ruleset. Per-device drill-down is available in the per-workstation compliance reports.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+s.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}

// --- KPI band primitive ----------------------------------------------------

// kpi is one cell in a KPI band — a large value above a small label, on a
// light bordered background. Four KPIs per band fit neatly across the page.
type kpi struct {
	value string
	label string
}

func kpiBand(pdf *fpdf.Fpdf, kpis []kpi) {
	if len(kpis) == 0 {
		return
	}
	cellWidth := contentWidth / float64(len(kpis))
	startX := pdf.GetX()
	startY := pdf.GetY()
	cellHeight := 17.0

	// Cell backgrounds + border first
	for i := range kpis {
		x := startX + float64(i)*cellWidth
		pdf.SetDrawColor(colourRule[0], colourRule[1], colourRule[2])
		pdf.SetLineWidth(0.2)
		setFillColour(pdf, colourTableHdr)
		pdf.Rect(x, startY, cellWidth, cellHeight, "FD")
	}

	// Big numbers
	pdf.SetY(startY + 2.5)
	pdf.SetFont(reportFont, "B", 16)
	setTextColour(pdf, colourBodyText)
	for i, k := range kpis {
		pdf.SetX(startX + float64(i)*cellWidth)
		pdf.CellFormat(cellWidth, 7, k.value, "", 0, "C", false, 0, "")
	}
	pdf.Ln(-1)

	// Labels
	pdf.SetY(startY + 10.5)
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourMuted)
	for i, k := range kpis {
		pdf.SetX(startX + float64(i)*cellWidth)
		pdf.CellFormat(cellWidth, 4, k.label, "", 0, "C", false, 0, "")
	}
	pdf.SetY(startY + cellHeight + 2)
}

func kpiPlaceholder(count int, fallback string) string {
	if count <= 0 {
		return fallback
	}
	return fmt.Sprintf("%d", count)
}
