package report

import (
	"bytes"
	"fmt"

	"github.com/go-pdf/fpdf"
)

// RenderCISCompliancePDF renders a CIS Compliance Report PDF for staff/admin
// use. Header carries the internal header.png mark, unchanged.
func RenderCISCompliancePDF(d CISComplianceReport) ([]byte, error) {
	return renderCISCompliancePDF(d, AudienceStaff)
}

// RenderCISCompliancePDFCustomer renders the same CIS Compliance Report for
// a customer's own portal download (PAT-2264). The only difference from
// RenderCISCompliancePDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderCISCompliancePDFCustomer(d CISComplianceReport) ([]byte, error) {
	return renderCISCompliancePDF(d, AudienceCustomer)
}

func renderCISCompliancePDF(d CISComplianceReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: CIS Compliance Report", true)
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

	renderCISHeader(pdf, d, audience)
	renderCISKPIBand(pdf, d)
	renderCISTopFailing(pdf, d)
	renderCISWorstDevices(pdf, d)
	renderCISCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write cis compliance pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderCISHeader(pdf *fpdf.Fpdf, d CISComplianceReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "CIS Compliance Report", "", 1, "C", false, 0, "")

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

func renderCISKPIBand(pdf *fpdf.Fpdf, d CISComplianceReport) {
	sectionHeader(pdf, "Compliance Posture")
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%.1f%%", d.Compliance.OverallPct), label: "Compliance %"},
		{value: fmt.Sprintf("%d", d.Compliance.PassEvaluations), label: "Pass evaluations"},
		{value: fmt.Sprintf("%d", d.Compliance.FailEvaluations), label: "Fail evaluations"},
		{value: fmt.Sprintf("%d", d.Compliance.CriticalFails+d.Compliance.HighFails), label: "Critical + High fails"},
	})
	pdf.Ln(3)
}

func renderCISTopFailing(pdf *fpdf.Fpdf, d CISComplianceReport) {
	if len(d.TopFailing) == 0 {
		sectionHeader(pdf, "Top Failing Controls")
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No failing controls across the evaluated fleet.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	sectionHeader(pdf, fmt.Sprintf("Top Failing Controls (%d)", len(d.TopFailing)))
	widths := []float64{20, 95, 30, 29}
	tableHeader(pdf, []string{"Severity", "Control", "Devices Affected", "% of Fleet"}, widths)
	rows := make([][]string, 0, len(d.TopFailing))
	for _, tc := range d.TopFailing {
		rows = append(rows, []string{
			titleCase(tc.Severity),
			truncate(tc.Title, 60),
			fmt.Sprintf("%d / %d", tc.DevicesAffected, tc.TotalDevices),
			fmt.Sprintf("%.0f%%", tc.PctAffected),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderCISWorstDevices(pdf *fpdf.Fpdf, d CISComplianceReport) {
	if len(d.WorstDevices) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Devices Needing Attention (%d)", len(d.WorstDevices)))
	widths := []float64{55, 45, 25, 25, 24}
	tableHeader(pdf, []string{"Hostname", "OS", "Compliance Score", "Failing", "Critical"}, widths)
	rows := make([][]string, 0, len(d.WorstDevices))
	undetermined := 0
	for _, w := range d.WorstDevices {
		osStr := w.OS
		if w.OSVersion != "" {
			osStr = w.OS + " " + w.OSVersion
		}
		rows = append(rows, []string{
			truncate(w.Hostname, 32),
			truncate(osStr, 28),
			fmt.Sprintf("%.0f%%", w.CompliancePct),
			fmt.Sprintf("%d", w.FailingCount),
			fmt.Sprintf("%d", w.CriticalCount),
		})
		undetermined += w.UndeterminedCount
	}
	tableBody(pdf, rows, widths, true)

	// PAT-1758: Failing/Critical above count only real, evidenced fails; a
	// device whose ONLY fails are undetermined never reaches this list at
	// all (see fetchWorstDevices). Surface remaining undetermined evidence
	// among the devices shown rather than dropping it silently.
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

func renderCISCloser(pdf *fpdf.Fpdf, d CISComplianceReport) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This CIS Compliance Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent across the tenant's enrolled devices, evaluated against the CIS benchmark ruleset.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}
