package report

import (
	"bytes"
	"fmt"
	"time"

	"github.com/go-pdf/fpdf"
)

// RenderCertExpiryPDF renders a Certificate Expiry Report PDF for
// staff/admin use. Header carries the internal header.png mark, unchanged.
func RenderCertExpiryPDF(d CertExpiryReport) ([]byte, error) {
	return renderCertExpiryPDF(d, AudienceStaff)
}

// RenderCertExpiryPDFCustomer renders the same Certificate Expiry Report
// for a customer's own portal download (PAT-2264). The only difference from
// RenderCertExpiryPDF is the header: no "Staff report" wording and the
// current in-app brand mark instead of the retired pixel-P baked into
// header.png. Every other section, colour, font and layout is shared.
func RenderCertExpiryPDFCustomer(d CertExpiryReport) ([]byte, error) {
	return renderCertExpiryPDF(d, AudienceCustomer)
}

func renderCertExpiryPDF(d CertExpiryReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Certificate Expiry Report", true)
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

	renderCertHeader(pdf, d, audience)
	renderCertKPIBand(pdf, d)
	renderCertTable(pdf, d)
	renderPlatformRootSection(pdf, d)
	renderSuspiciousSection(pdf, d)
	renderCertCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write cert expiry pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func renderCertHeader(pdf *fpdf.Fpdf, d CertExpiryReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "Certificate Expiry Report", "", 1, "C", false, 0, "")

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

func renderCertKPIBand(pdf *fpdf.Fpdf, d CertExpiryReport) {
	sectionHeader(pdf, "Certificate Overview")
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d", d.ExpiredCount), label: "Expired"},
		{value: fmt.Sprintf("%d", d.CriticalCount), label: "Critical (≤7d)"},
		{value: fmt.Sprintf("%d", d.WarningCount), label: "Warning (≤30d)"},
		{value: fmt.Sprintf("%d", len(d.Certs)), label: "Total certs (≤90d)"},
	})
	pdf.Ln(3)
}

func renderCertTable(pdf *fpdf.Fpdf, d CertExpiryReport) {
	sectionHeader(pdf, fmt.Sprintf("Certificates Expiring Within 90 Days (%d)", len(d.Certs)))
	if len(d.Certs) == 0 {
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No certificates expiring within 90 days.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	now := time.Now().UTC()
	widths := []float64{45, 40, 35, 30, 24}
	tableHeader(pdf, []string{"Subject CN", "Issuer CN", "Hostname", "Expires", "Days Until"}, widths)
	rows := make([][]string, 0, len(d.Certs))
	for _, c := range d.Certs {
		daysUntil := int(time.Until(c.NotAfter).Hours() / 24)
		daysStr := fmt.Sprintf("%d", daysUntil)
		if c.NotAfter.Before(now) {
			daysStr = "Expired"
		}
		rows = append(rows, []string{
			truncate(c.SubjectCN, 30),
			truncate(c.IssuerCN, 28),
			truncate(c.Hostname, 24),
			c.NotAfter.UTC().Format("02 Jan 2006"),
			daysStr,
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

// renderPlatformRootSection (PAT-1738) lists certificates whose thumbprint
// matched a known Microsoft/Apple platform root. These are informational
// only — deliberately excluded from the actionable table above and from the
// KPI band's counts — but still listed, since a platform root can expire
// and matter operationally even though it is not a tenant-actionable
// finding.
func renderPlatformRootSection(pdf *fpdf.Fpdf, d CertExpiryReport) {
	if len(d.PlatformRootCerts) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Platform Root Certificates (%d, informational)", len(d.PlatformRootCerts)))
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5, "Matched a known Microsoft or Apple platform-root thumbprint. Not counted above.", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{55, 45, 35, 39}
	tableHeader(pdf, []string{"Subject CN", "Hostname", "Expires", "SHA-1"}, widths)
	rows := make([][]string, 0, len(d.PlatformRootCerts))
	for _, c := range d.PlatformRootCerts {
		rows = append(rows, []string{
			truncate(c.SubjectCN, 36),
			truncate(c.Hostname, 28),
			c.NotAfter.UTC().Format("02 Jan 2006"),
			truncate(c.SHA1, 24),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

// renderSuspiciousSection (PAT-1738) lists certificates whose subject text
// names a platform ("Microsoft"/"Windows" on a Windows device, "Apple" on a
// macOS device) but whose thumbprint did NOT match the known platform-root
// list. This is a standalone flag for investigation, not an expiry finding —
// it is never folded into the table above.
func renderSuspiciousSection(pdf *fpdf.Fpdf, d CertExpiryReport) {
	if len(d.SuspiciousCerts) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Suspicious Certificates (%d)", len(d.SuspiciousCerts)))
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5, "Subject names a platform vendor but the thumbprint does not match a known platform root. Investigate.", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{50, 45, 35, 24, 20}
	tableHeader(pdf, []string{"Subject CN", "Issuer CN", "Hostname", "SHA-1", "Expires"}, widths)
	rows := make([][]string, 0, len(d.SuspiciousCerts))
	for _, c := range d.SuspiciousCerts {
		rows = append(rows, []string{
			truncate(c.SubjectCN, 32),
			truncate(c.IssuerCN, 28),
			truncate(c.Hostname, 24),
			truncate(c.SHA1, 16),
			c.NotAfter.UTC().Format("02 Jan 2006"),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(3)
}

func renderCertCloser(pdf *fpdf.Fpdf, d CertExpiryReport) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This Certificate Expiry Report was generated by Patched.im Ltd from telemetry collected by the patched.im endpoint agent.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+d.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}
