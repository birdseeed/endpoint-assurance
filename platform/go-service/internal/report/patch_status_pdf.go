package report

import (
	"bytes"
	"fmt"

	"github.com/go-pdf/fpdf"
)

// RenderPatchStatusPDF renders a Patch Status Report PDF for staff/admin
// use. Header carries the internal header.png mark, unchanged.
func RenderPatchStatusPDF(d PatchStatusReport) ([]byte, error) {
	return renderPatchStatusPDF(d, AudienceStaff)
}

// RenderPatchStatusPDFCustomer renders the same Patch Status Report for a
// customer's own portal download (PAT-2264). The only difference from
// RenderPatchStatusPDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderPatchStatusPDFCustomer(d PatchStatusReport) ([]byte, error) {
	return renderPatchStatusPDF(d, AudienceCustomer)
}

func renderPatchStatusPDF(d PatchStatusReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Patch Status Report", true)
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

	renderPatchStatusHeader(pdf, d, audience)
	renderPatchStatusKPIBand(pdf, d)
	renderPatchStatusDevices(pdf, d)
	renderPatchStatusCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write patch status pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderPatchStatusHeader(pdf *fpdf.Fpdf, d PatchStatusReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "Patch Status Report", "", 1, "C", false, 0, "")

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

func renderPatchStatusKPIBand(pdf *fpdf.Fpdf, d PatchStatusReport) {
	sectionHeader(pdf, "Patching Overview")
	median := "—"
	if d.Patching.MedianDaysSinceLastPatch >= 0 {
		median = fmt.Sprintf("%d days", d.Patching.MedianDaysSinceLastPatch)
	}
	total := d.Patching.DevicesUpToDate + d.Patching.DevicesPendingUpdates + d.Patching.DevicesUpdateStateUnknown
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", d.Patching.DevicesUpToDate), label: "Up to date"},
		{value: fmt.Sprintf("%d", d.Patching.DevicesPendingUpdates), label: "Pending updates"},
		// PAT-1805: devices no collector has reported an update state for
		// (every Windows device today) get their own honest KPI rather than
		// being folded into "Up to date".
		{value: fmt.Sprintf("%d", d.Patching.DevicesUpdateStateUnknown), label: "Update state not reported"},
		{value: median, label: "Median days since patch"},
		{value: fmt.Sprintf("%d", total), label: "Total devices"},
	})
	pdf.Ln(3)
}

func renderPatchStatusDevices(pdf *fpdf.Fpdf, d PatchStatusReport) {
	if len(d.Devices) == 0 {
		sectionHeader(pdf, "Devices with Pending Updates")
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No devices with pending updates.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	sectionHeader(pdf, fmt.Sprintf("Devices with Pending Updates (%d)", len(d.Devices)))
	widths := []float64{55, 35, 40, 44}
	tableHeader(pdf, []string{"Hostname", "OS", "OS Version", "Pending Updates"}, widths)
	rows := make([][]string, 0, len(d.Devices))
	for _, dev := range d.Devices {
		rows = append(rows, []string{
			truncate(dev.Hostname, 36),
			truncate(dev.OS, 22),
			truncate(dev.OSVersion, 26),
			fmt.Sprintf("%d", dev.PendingCount),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderPatchStatusCloser(pdf *fpdf.Fpdf, d PatchStatusReport) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This Patch Status Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}
