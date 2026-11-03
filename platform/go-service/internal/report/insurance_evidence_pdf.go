package report

// PDF rendering for the cyber insurance evidence pack (PAT-2258). The staff
// and customer variants differ only in the header (PAT-2264); every answer,
// figure and caveat comes from InsuranceEvidence unchanged, so the PDF, the
// JSON endpoint, the CSV and the portal page can never disagree.

import (
	"bytes"
	"fmt"
	"time"

	"github.com/go-pdf/fpdf"
)

// RenderInsuranceEvidencePDF renders the pack for staff/admin use (the
// internal header.png mark).
func RenderInsuranceEvidencePDF(d InsuranceEvidence) ([]byte, error) {
	return renderInsuranceEvidencePDF(d, AudienceStaff)
}

// RenderInsuranceEvidencePDFCustomer renders the pack for a customer's own
// portal download: the customer header, never the staff mark.
func RenderInsuranceEvidencePDFCustomer(d InsuranceEvidence) ([]byte, error) {
	return renderInsuranceEvidencePDF(d, AudienceCustomer)
}

// InsuranceStatusLabel is the customer wording of an answer status.
func InsuranceStatusLabel(status string) string {
	switch status {
	case InsuranceEvidenced:
		return "Evidenced"
	case InsurancePartial:
		return "Partly evidenced"
	case InsuranceNotEvidenced:
		return "Not evidenced by Patched"
	}
	return "Unknown"
}

// insurancePortalHost prefixes a source path so a printed pack names where
// the evidence can be seen.
const insurancePortalHost = "app.patched.im"

func renderInsuranceEvidencePDF(d InsuranceEvidence, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("Patched: Cyber Insurance Evidence Pack", true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)
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

	renderInsuranceHeader(pdf, d, audience)
	renderInsuranceSummary(pdf, d)
	renderInsuranceAnswers(pdf, d)
	renderInsuranceNotEvidenced(pdf, d)
	renderInsuranceCloser(pdf, d)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write insurance evidence pdf: %w", err)
	}
	return buf.Bytes(), nil
}

func insFmtTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("02 Jan 2006 15:04") + " UTC"
}

func renderInsuranceHeader(pdf *fpdf.Fpdf, d InsuranceEvidence, audience ReportAudience) {
	imageWidth := 80.0
	if audience == AudienceCustomer {
		pdf.SetY(drawCustomerHeaderMark(pdf, imageWidth))
	} else {
		x := (210.0 - imageWidth) / 2
		pdf.ImageOptions("header.png", x, topMargin, imageWidth, 0, false, fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
		pdf.SetY(topMargin + imageWidth*0.6 + 3)
	}
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Assurance  |  Audit Evidence", "", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.6)

	pdf.Ln(4)
	pdf.SetFont(reportFont, "B", 18)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 10, "Cyber Insurance Evidence Pack", "", 1, "C", false, 0, "")
	pdf.Ln(1)
	pdf.SetFont(reportFont, "", 10)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for", "", 1, "C", false, 0, "")
	pdf.SetFont(reportFont, "B", 13)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, fallback(d.Tenant), "", 1, "C", false, 0, "")
	pdf.SetFont(reportFont, "", 9)
	gen := d.GeneratedAt
	pdf.CellFormat(0, 5, "Evidence as of "+insFmtTime(&gen), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "Classification: Confidential", "", 1, "C", false, 0, "")
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im Ltd  |  patched.im", "", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5, d.Statement, "", "L", false)
	pdf.Ln(3)
}

func renderInsuranceSummary(pdf *fpdf.Fpdf, d InsuranceEvidence) {
	byStatus := map[string]int{}
	evidencedGroup := 0
	for _, q := range d.Questions {
		byStatus[q.Status]++
		if q.Group == InsuranceGroupEvidenced {
			evidencedGroup++
		}
	}
	total := len(d.Questions)
	sectionHeader(pdf, "Summary")
	kpiBand(pdf, []kpi{
		{value: fmt.Sprintf("%d of %d", byStatus[InsuranceEvidenced], total), label: "Evidenced"},
		{value: fmt.Sprintf("%d of %d", byStatus[InsurancePartial], total), label: "Partly evidenced"},
		{value: fmt.Sprintf("%d of %d", byStatus[InsuranceUnknown], total), label: "Unknown"},
		{value: fmt.Sprintf("%d of %d", byStatus[InsuranceNotEvidenced], total), label: "Not evidenced by Patched"},
	})
	pdf.Ln(2)
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4.5, fmt.Sprintf("%d of %d questions are answered from Patched's endpoint evidence, across %d in-scope %s. "+
		"The status says how much of the estate the evidence covers, not whether the answer is a good one.",
		evidencedGroup, total, d.DevicesInScope, insPlural(d.DevicesInScope, "device", "devices")), "", "L", false)
	pdf.Ln(2)

	widths := []float64{60, 42, 72}
	tableHeader(pdf, []string{"Question", "Evidence", "Answer"}, widths)
	rows := make([][]string, 0, len(d.Questions))
	for _, q := range d.Questions {
		rows = append(rows, []string{truncate(q.Title, 42), InsuranceStatusLabel(q.Status), truncate(q.Headline, 48)})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(4)
}

func renderInsuranceAnswers(pdf *fpdf.Fpdf, d InsuranceEvidence) {
	prEnsureSpace(pdf, 60)
	sectionHeader(pdf, "Answers from Patched evidence")
	for _, q := range d.Questions {
		if q.Group != InsuranceGroupEvidenced {
			continue
		}
		prEnsureSpace(pdf, 40)
		pdf.Ln(1)
		pdf.SetFont(reportFont, "B", 10)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 5, q.Title, "", "L", false)
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4.5, q.Question, "", "L", false)
		pdf.Ln(0.5)

		pdf.SetFont(reportFont, "B", 8)
		setTextColour(pdf, colourBodyText)
		meta := "Evidence: " + InsuranceStatusLabel(q.Status)
		if q.UnknownDevices != nil {
			meta += fmt.Sprintf("   |   Unknown devices: %d", *q.UnknownDevices)
		}
		meta += "   |   As of " + insFmtTime(q.AsOf)
		pdf.MultiCell(0, 4.5, meta, "", "L", false)
		if q.OldestEvidenceAt != nil {
			pdf.SetFont(reportFont, "", 8)
			setTextColour(pdf, colourMuted)
			pdf.MultiCell(0, 4.5, "Oldest device evidence used: "+insFmtTime(q.OldestEvidenceAt), "", "L", false)
		}
		pdf.Ln(0.5)
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 4.5, q.AnswerText, "", "L", false)
		pdf.Ln(0.5)
		pdf.SetFont(reportFont, "", 8)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4.2, "How this is worked out: "+q.Basis, "", "L", false)
		if q.Source != nil {
			pdf.MultiCell(0, 4.2, "Source: "+q.Source.Label+", "+insurancePortalHost+q.Source.Path, "", "L", false)
		}
		pdf.Ln(2)
	}
}

func renderInsuranceNotEvidenced(pdf *fpdf.Fpdf, d InsuranceEvidence) {
	prEnsureSpace(pdf, 30)
	pdf.Ln(2)
	sectionHeader(pdf, "Not evidenced by Patched")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4.5, "Renewal forms usually ask these too. Patched collects evidence from your endpoints only, so it "+
		"holds nothing that answers them. They are listed so none is missed; answer each from the record named.", "", "L", false)
	pdf.Ln(1)
	for _, q := range d.Questions {
		if q.Group != InsuranceGroupNotEvidenced {
			continue
		}
		prEnsureSpace(pdf, 18)
		pdf.Ln(1)
		pdf.SetFont(reportFont, "B", 10)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 5, q.Title, "", "L", false)
		pdf.SetFont(reportFont, "I", 9)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4.5, q.Question, "", "L", false)
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 4.5, q.AnswerText, "", "L", false)
		pdf.Ln(1)
	}
}

func renderInsuranceCloser(pdf *fpdf.Fpdf, d InsuranceEvidence) {
	pdf.Ln(3)
	hrule(pdf, 0.4)
	pdf.Ln(3)
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4.2, fmt.Sprintf("A device counts as reporting when it has sent evidence within the last %d days. "+
		"Devices your organisation retired are not counted. Each answer names the view in the Patched portal it is drawn "+
		"from, where the device-level evidence behind it can be checked.", d.ReportingWindowDays), "", "L", false)
	pdf.Ln(1)
	pdf.SetFont(reportFont, "I", 8)
	gen := d.GeneratedAt
	pdf.CellFormat(0, 4.5, "Generated: "+insFmtTime(&gen)+"  |  patched.im", "", 1, "L", false, 0, "")
}
