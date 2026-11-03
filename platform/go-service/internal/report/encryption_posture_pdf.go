package report

import (
	"bytes"
	"fmt"

	"github.com/go-pdf/fpdf"
)

// RenderEncryptionPosturePDF renders an Encryption Posture Report PDF for
// staff/admin use. Header carries the internal header.png mark, unchanged.
func RenderEncryptionPosturePDF(d EncryptionPostureReport) ([]byte, error) {
	return renderEncryptionPosturePDF(d, AudienceStaff)
}

// RenderEncryptionPosturePDFCustomer renders the same Encryption Posture
// Report for a customer's own portal download (PAT-2264). The only
// difference from RenderEncryptionPosturePDF is the header: no "Staff
// report" wording and the current in-app brand mark instead of the retired
// pixel-P baked into header.png. Every other section, colour, font and
// layout is shared.
func RenderEncryptionPosturePDFCustomer(d EncryptionPostureReport) ([]byte, error) {
	return renderEncryptionPosturePDF(d, AudienceCustomer)
}

func renderEncryptionPosturePDF(d EncryptionPostureReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Encryption Posture Report", true)
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

	renderEncryptionHeader(pdf, d, audience)
	renderEncryptionKPIBand(pdf, d)
	renderEncryptionDevices(pdf, d)
	renderEncryptionFindings(pdf, d)
	renderEncryptionCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write encryption posture pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderEncryptionHeader(pdf *fpdf.Fpdf, d EncryptionPostureReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "Encryption Posture Report", "", 1, "C", false, 0, "")

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

func renderEncryptionKPIBand(pdf *fpdf.Fpdf, d EncryptionPostureReport) {
	sectionHeader(pdf, "Encryption Overview")
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", d.EncryptedCount), label: "Encrypted"},
		{value: fmt.Sprintf("%d", d.UnencryptedCount), label: "Unencrypted"},
		{value: fmt.Sprintf("%d", d.UnknownCount), label: "Unknown"},
		{value: fmt.Sprintf("%d", len(d.Devices)), label: "Total devices"},
	})
	pdf.Ln(3)
}

func renderEncryptionDevices(pdf *fpdf.Fpdf, d EncryptionPostureReport) {
	sectionHeader(pdf, fmt.Sprintf("Encryption Posture (%d devices)", len(d.Devices)))
	if len(d.Devices) == 0 {
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No device data found.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	widths := []float64{55, 35, 42, 42}
	tableHeader(pdf, []string{"Hostname", "OS", "FileVault", "BitLocker"}, widths)
	rows := make([][]string, 0, len(d.Devices))
	for _, dev := range d.Devices {
		fv := "—"
		if dev.FileVault != nil {
			fv = *dev.FileVault
		}
		bl := "—"
		if dev.BitLocker != nil {
			bl = *dev.BitLocker
		}
		rows = append(rows, []string{
			truncate(dev.Hostname, 36),
			truncate(dev.OS, 24),
			truncate(fv, 28),
			truncate(bl, 28),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderEncryptionFindings(pdf *fpdf.Fpdf, d EncryptionPostureReport) {
	if len(d.Findings) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Compliance Findings (%d)", len(d.Findings)))
	widths := []float64{80, 94}
	tableHeader(pdf, []string{"Finding Type", "Details"}, widths)
	rows := make([][]string, 0, len(d.Findings))
	for _, f := range d.Findings {
		rows = append(rows, []string{
			truncate(f.FindingType, 52),
			truncate(f.Details, 64),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderEncryptionCloser(pdf *fpdf.Fpdf, d EncryptionPostureReport) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This Encryption Posture Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}
