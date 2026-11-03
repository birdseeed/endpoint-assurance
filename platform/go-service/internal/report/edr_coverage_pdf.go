package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// RenderEDRCoveragePDF renders an EDR Coverage Report PDF for staff/admin
// use. Header carries the internal header.png mark, unchanged.
func RenderEDRCoveragePDF(d EDRCoverageReport) ([]byte, error) {
	return renderEDRCoveragePDF(d, AudienceStaff)
}

// RenderEDRCoveragePDFCustomer renders the same EDR Coverage Report for a
// customer's own portal download (PAT-2264). The only difference from
// RenderEDRCoveragePDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderEDRCoveragePDFCustomer(d EDRCoverageReport) ([]byte, error) {
	return renderEDRCoveragePDF(d, AudienceCustomer)
}

func renderEDRCoveragePDF(d EDRCoverageReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: EDR Coverage Report", true)
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

	renderEDRHeader(pdf, d, audience)
	renderEDRKPIBand(pdf, d)
	renderEDRTable(pdf, d)
	renderEDRStates(pdf)
	renderEDRCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write edr coverage pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderEDRHeader(pdf *fpdf.Fpdf, d EDRCoverageReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "EDR Coverage Report", "", 1, "C", false, 0, "")

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

func renderEDRKPIBand(pdf *fpdf.Fpdf, d EDRCoverageReport) {
	sectionHeader(pdf, "EDR Coverage Overview")
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", d.TotalDevices), label: "Total devices"},
		{value: fmt.Sprintf("%d", d.Covered), label: "Covered"},
		{value: fmt.Sprintf("%d", d.Unrecognised), label: "Unrecognised"},
		{value: fmt.Sprintf("%d", d.Unknown), label: "Unknown"},
		{value: fmt.Sprintf("%.1f%%", d.CoveragePct), label: "Coverage %"},
	})
	pdf.Ln(3)
}

func edrStateLabel(s EDRState) string {
	switch s {
	case EDRStateCovered:
		return "Covered"
	case EDRStateUnrecognised:
		return "Unrecognised"
	default:
		return "Unknown"
	}
}

func renderEDRTable(pdf *fpdf.Fpdf, d EDRCoverageReport) {
	sectionHeader(pdf, fmt.Sprintf("Device EDR Status (%d)", len(d.Devices)))
	if len(d.Devices) == 0 {
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No devices found.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	widths := []float64{50, 30, 28, 66}
	tableHeader(pdf, []string{"Hostname", "OS", "Status", "Reported tools"}, widths)
	rows := make([][]string, 0, len(d.Devices))
	for _, dev := range d.Devices {
		toolsStr := "None reported"
		if len(dev.Tools) > 0 {
			toolsStr = strings.Join(dev.Tools, ", ")
		}
		rows = append(rows, []string{
			truncate(dev.Hostname, 36),
			truncate(dev.OS, 22),
			edrStateLabel(dev.State),
			truncate(toolsStr, 48),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

// renderEDRStates explains the three states in plain English so the
// customer never has to infer what "unrecognised" or "unknown" means
// on their own. PAT-2226: this is the direct replacement for the old
// hardcoded three-vendor footer.
func renderEDRStates(pdf *fpdf.Fpdf) {
	sectionHeader(pdf, "What these statuses mean")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)

	entries := []struct{ label, text string }{
		{"Covered", "the reported security software matches your protected list."},
		{"Unrecognised", "security software was reported but is not on your protected list; add it on the Software page if it is your EDR."},
		{"Unknown", "this device has not reported its security tools."},
	}
	for _, e := range entries {
		pdf.SetFont(reportFont, "B", 9)
		pdf.CellFormat(28, 4.5, e.label+":", "", 0, "L", false, 0, "")
		pdf.SetFont(reportFont, "", 9)
		pdf.MultiCell(contentWidth-28, 4.5, e.text, "", "L", false)
	}
	pdf.Ln(2)
}

func renderEDRCloser(pdf *fpdf.Fpdf, d EDRCoverageReport) {
	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This EDR Coverage Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent. "+
			"Recognition uses your own protected-software list plus Patched's shared baseline, not a fixed vendor list. "+
			"An unrecognised or unknown status is not itself a finding that a device lacks EDR; it means Patched cannot yet confirm coverage from the evidence reported.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}
