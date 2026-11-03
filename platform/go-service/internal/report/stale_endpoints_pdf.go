package report

import (
	"bytes"
	"fmt"

	"github.com/go-pdf/fpdf"
)

// RenderStaleEndpointsPDF renders a Stale Endpoints Report PDF for
// staff/admin use. Header carries the internal header.png mark, unchanged.
func RenderStaleEndpointsPDF(d StaleEndpointsReport) ([]byte, error) {
	return renderStaleEndpointsPDF(d, AudienceStaff)
}

// RenderStaleEndpointsPDFCustomer renders the same Stale Endpoints Report
// for a customer's own portal download (PAT-2264). The only difference from
// RenderStaleEndpointsPDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderStaleEndpointsPDFCustomer(d StaleEndpointsReport) ([]byte, error) {
	return renderStaleEndpointsPDF(d, AudienceCustomer)
}

func renderStaleEndpointsPDF(d StaleEndpointsReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Stale Endpoints Report", true)
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

	renderStaleHeader(pdf, d, audience)
	renderStaleDevices(pdf, d)
	renderRetiredDevices(pdf, d)
	renderStaleCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write stale endpoints pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderStaleHeader(pdf *fpdf.Fpdf, d StaleEndpointsReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "Stale Endpoints Report", "", 1, "C", false, 0, "")

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

func renderStaleDevices(pdf *fpdf.Fpdf, d StaleEndpointsReport) {
	summary := fmt.Sprintf("%d stale endpoint%s (not seen in %d+ days)",
		len(d.Devices), plural(len(d.Devices)), d.ThresholdDays)
	sectionHeader(pdf, summary)

	if len(d.Devices) == 0 {
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No stale endpoints found.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	widths := []float64{50, 30, 35, 35, 24}
	tableHeader(pdf, []string{"Hostname", "OS", "OS Version", "Last Seen", "Days Since"}, widths)
	rows := make([][]string, 0, len(d.Devices))
	for _, dev := range d.Devices {
		rows = append(rows, []string{
			truncate(dev.Hostname, 32),
			truncate(dev.OS, 20),
			truncate(dev.OSVersion, 24),
			dev.LastSeen.UTC().Format("02 Jan 2006"),
			fmt.Sprintf("%.0f", dev.DaysSince),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

// renderRetiredDevices lists the devices the customer has retired (PAT-2135)
// apart from the stale ones: retired, not missing. Nothing is rendered when
// there are none, so a tenant that never retires a device sees the report
// unchanged.
func renderRetiredDevices(pdf *fpdf.Fpdf, d StaleEndpointsReport) {
	if len(d.Retired) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("%d retired device%s (not counted as stale)", len(d.Retired), plural(len(d.Retired))))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4.5,
		"Your organisation has recorded these devices as retired. They are shown here rather than as stale or missing. "+
			"A device marked as reported since retirement has sent a report after it was retired and stays retired until you change it.",
		"", "L", false)
	pdf.Ln(1)
	widths := []float64{44, 24, 50, 24, 32}
	tableHeader(pdf, []string{"Hostname", "Retired", "Retired By", "Last Seen", "Reported Since"}, widths)
	rows := make([][]string, 0, len(d.Retired))
	for _, dev := range d.Retired {
		since := "No"
		if dev.ReportedAfterRetirement {
			since = "Yes"
		}
		rows = append(rows, []string{
			truncate(dev.Hostname, 28),
			dev.RetiredAt.UTC().Format("02 Jan 2006"),
			truncate(dev.RetiredBy, 32),
			dev.LastSeen.UTC().Format("02 Jan 2006"),
			since,
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderStaleCloser(pdf *fpdf.Fpdf, d StaleEndpointsReport) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This Stale Endpoints Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}
