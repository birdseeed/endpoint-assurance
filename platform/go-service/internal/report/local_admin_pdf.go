package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// RenderLocalAdminPDF renders a Local Admin / Privileged Access PDF report
// for staff/admin use. Header carries the internal header.png mark,
// unchanged.
func RenderLocalAdminPDF(d LocalAdminReport) ([]byte, error) {
	return renderLocalAdminPDF(d, AudienceStaff)
}

// RenderLocalAdminPDFCustomer renders the same Local Admin / Privileged
// Access report for a customer's own portal download (PAT-2264). The only
// difference from RenderLocalAdminPDF is the header: no "Staff report"
// wording and the current in-app brand mark instead of the retired pixel-P
// baked into header.png. Every other section, colour, font and layout is
// shared.
func RenderLocalAdminPDFCustomer(d LocalAdminReport) ([]byte, error) {
	return renderLocalAdminPDF(d, AudienceCustomer)
}

func renderLocalAdminPDF(d LocalAdminReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Local Admin / Privileged Access Report", true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)

	// PAT-2264: customer downloads never draw header.png, so skip
	// registering it at all -- fpdf embeds every registered image
	// regardless of use, and the retired pixel-P asset has no business
	// riding along inertly in a document that leaves the building.
	if audience != AudienceCustomer {
		if err := registerHeader(pdf); err != nil {
			return nil, err
		}
	}

	pdf.SetFooterFunc(func() {
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")
	pdf.AddPage()

	renderLocalAdminHeader(pdf, d, audience)
	renderLocalAdminKPIBand(pdf, d)
	renderLocalAdminTable(pdf, d)
	renderLocalAdminCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write local admin pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderLocalAdminHeader(pdf *fpdf.Fpdf, d LocalAdminReport, audience ReportAudience) {
	imageWidth := 80.0
	if audience == AudienceCustomer {
		pdf.SetY(drawCustomerHeaderMark(pdf, imageWidth))
	} else {
		x := (210.0 - imageWidth) / 2
		pdf.ImageOptions("header.png", x, topMargin, imageWidth, 0, false,
			fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
		pdf.SetY(topMargin + imageWidth*0.6 + 3)
	}

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Security  |  Compliance  |  Patch Management",
		"", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.6)

	pdf.Ln(4)
	pdf.SetFont(reportFont, "B", 18)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 10, "Local Admin / Privileged Access Report", "", 1, "C", false, 0, "")

	pdf.Ln(1)
	pdf.SetFont(reportFont, "", 10)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for", "", 1, "C", false, 0, "")

	pdf.SetFont(reportFont, "B", 13)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, fallback(d.Tenant), "", 1, "C", false, 0, "")

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 5, "Report Date: "+d.GeneratedAt.Format("02 Jan 2006"), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "Classification: Confidential", "", 1, "C", false, 0, "")
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im Ltd  |  patched.im", "", 1, "C", false, 0, "")

	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(4)
}

func renderLocalAdminKPIBand(pdf *fpdf.Fpdf, d LocalAdminReport) {
	sectionHeader(pdf, "Privileged Access Overview")
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", d.TotalDevices), label: "Total devices"},
		{value: fmt.Sprintf("%d", d.CompliantCount), label: "Compliant (≤2 admins)"},
		{value: fmt.Sprintf("%d", d.AtRiskCount), label: "At risk (3–4 admins)"},
		{value: fmt.Sprintf("%d", d.CriticalCount), label: "Critical (5+ admins)"},
	})
	if line := builtinExcludedSummary(d); line != "" {
		pdf.Ln(1)
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 4.5, line, "", "L", false)
	}
	pdf.Ln(3)
}

func renderLocalAdminTable(pdf *fpdf.Fpdf, d LocalAdminReport) {
	sectionHeader(pdf, fmt.Sprintf("Device Admin Inventory (%d)", d.TotalDevices))
	if len(d.Devices) == 0 {
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No devices found.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	widths := []float64{36, 20, 20, 22, 26, 50}
	tableHeader(pdf, []string{"Hostname", "OS", "Admin Count", "Risk", "Built-in Admin", "Admin Accounts"}, widths)
	rows := make([][]string, 0, len(d.Devices))
	for _, dev := range d.Devices {
		countStr := fmt.Sprintf("%d", dev.AdminCount)
		if dev.AdminCount < 0 {
			countStr = "—"
		}
		names := "—"
		if len(dev.AdminNames) > 0 {
			// PAT-1974: evidence only — a roster with no AdminNames yet
			// (older agent, or a collection that has never completed) must
			// never render as "no admins", so absence stays the em dash
			// rather than an empty string that could be misread as "none".
			names = strings.Join(dev.AdminNames, ", ")
		}
		if dev.ReportedAdminCount >= 0 && dev.AdminCount != dev.ReportedAdminCount {
			// PAT-1992: show both numbers so an excluded disabled built-in
			// Administrator is visible rather than silently subtracted.
			countStr = fmt.Sprintf("%d (of %d)", dev.AdminCount, dev.ReportedAdminCount)
		}
		rows = append(rows, []string{
			truncate(dev.Hostname, 26),
			truncate(dev.OS, 14),
			countStr,
			riskLabel(dev.Risk),
			builtinAdminLabel(dev.BuiltinAdmin),
			truncate(names, 50),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderLocalAdminCloser(pdf *fpdf.Fpdf, d LocalAdminReport) {
	sectionHeader(pdf, "Recommendations")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)

	recs := localAdminRecommendations(d)
	for _, rec := range recs {
		pdf.CellFormat(5, 5, "•", "", 0, "L", false, 0, "")
		pdf.MultiCell(0, 5, rec, "", "L", false)
	}
	pdf.Ln(4)

	hrule(pdf, 0.4)
	pdf.Ln(3)
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This Local Admin / Privileged Access Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent. Admin counts are sourced from the CIS macOS 5.8 / Windows equivalent control evaluation.",
		"", "L", false)
	pdf.Ln(1)
	pdf.MultiCell(0, 4.5, builtinAdminMethodNote, "", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}

func localAdminRecommendations(d LocalAdminReport) []string {
	var recs []string
	if d.CriticalCount > 0 {
		recs = append(recs,
			fmt.Sprintf("%d device(s) have 5 or more local admin accounts. Review immediately and remove unauthorised accounts.", d.CriticalCount))
	}
	if d.AtRiskCount > 0 {
		recs = append(recs,
			fmt.Sprintf("%d device(s) have 3–4 local admin accounts. Audit whether all accounts require administrator privileges.", d.AtRiskCount))
	}
	if d.BuiltinEnabledCount > 0 {
		recs = append(recs,
			fmt.Sprintf("%d Windows device(s) have the built-in Administrator account enabled. Disable it unless there is a documented reason to keep it.", d.BuiltinEnabledCount))
	}
	if d.UnknownCount > 0 {
		recs = append(recs,
			fmt.Sprintf("%d device(s) have no admin count data. Ensure the patched.im agent is running and reporting on these endpoints.", d.UnknownCount))
	}
	if d.CompliantCount == d.TotalDevices && d.TotalDevices > 0 {
		recs = append(recs, "All devices are within the compliant threshold (≤2 local admin accounts). Continue regular review on this cadence.")
	}
	if len(recs) == 0 {
		recs = append(recs, "No devices found. Ensure agents are enrolled and reporting.")
	}
	return recs
}

// builtinAdminMethodNote states how the built-in Administrator is treated
// (PAT-1992), so a macOS verdict never reads as though a built-in check ran.
const builtinAdminMethodNote = "Built-in Administrator: on Windows, a built-in Administrator account the agent reads as disabled is not counted towards the admin count, and one read as enabled is flagged and the device is rated at least At Risk, whatever its admin count. If its state could not be established it is still counted. This check is Windows-only. On macOS the agent leaves root out of the admin roster, so macOS results are based on the roster and count as reported."

// builtinExcludedSummary is the KPI-band line for BuiltinDisabledExcludedCount
// (PAT-1992), so an exclusion is never silent. Empty when there is none.
func builtinExcludedSummary(d LocalAdminReport) string {
	if d.BuiltinDisabledExcludedCount == 0 {
		return ""
	}
	return fmt.Sprintf("%d Windows device(s) have a disabled built-in Administrator account, which is not counted in their admin count.", d.BuiltinDisabledExcludedCount)
}

// builtinAdminLabel renders a BuiltinAdmin* verdict for the device table.
func builtinAdminLabel(v string) string {
	switch v {
	case BuiltinAdminDisabled:
		return "Disabled"
	case BuiltinAdminEnabled:
		return "Enabled"
	case BuiltinAdminUnknown:
		return "Not established"
	case BuiltinAdminNone:
		return "Not reported"
	default:
		return "N/A (not Windows)"
	}
}

func riskLabel(risk string) string {
	switch risk {
	case "compliant":
		return "Compliant"
	case "at-risk":
		return "At Risk"
	case "critical":
		return "Critical"
	default:
		return "Unknown"
	}
}
