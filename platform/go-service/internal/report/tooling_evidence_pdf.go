package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// RenderToolingEvidencePDF renders the same rows returned by
// BuildToolingEvidence for staff/admin use. It does not perform a database
// query or reinterpret collection state. Header carries the internal
// header.png mark, unchanged.
func RenderToolingEvidencePDF(r ToolingEvidenceReport) ([]byte, error) {
	return renderToolingEvidencePDF(r, AudienceStaff)
}

// RenderToolingEvidencePDFCustomer renders the same AI Tooling Evidence
// report for a customer's own portal download (PAT-2264). The only
// difference from RenderToolingEvidencePDF is the header: no "Staff report"
// wording and the current in-app brand mark instead of the retired pixel-P
// baked into header.png. Every other section, colour, font and layout is
// shared.
func RenderToolingEvidencePDFCustomer(r ToolingEvidenceReport) ([]byte, error) {
	return renderToolingEvidencePDF(r, AudienceCustomer)
}

func renderToolingEvidencePDF(r ToolingEvidenceReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im - AI Tooling Evidence", true)
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
	if audience == AudienceCustomer {
		pdf.SetY(drawCustomerHeaderMark(pdf, 60))
	} else {
		pdf.ImageOptions("header.png", 75, topMargin, 60, 0, false, fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
		pdf.SetY(topMargin + 40)
	}
	pdf.SetFont(reportFont, "B", 18)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 9, "AI Tooling Evidence", "", 1, "L", false, 0, "")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for "+r.TenantName, "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, "Generated "+r.GeneratedAt.Format("2 January 2006 15:04 UTC"), "", 1, "L", false, 0, "")
	pdf.Ln(3)

	pdf.SetFillColor(colourTableHdr[0], colourTableHdr[1], colourTableHdr[2])
	pdf.SetFont(reportFont, "B", 10)
	pdf.CellFormat(43.5, 8, "Estate devices", "1", 0, "C", true, 0, "")
	pdf.CellFormat(43.5, 8, "With AI tooling", "1", 0, "C", true, 0, "")
	pdf.CellFormat(43.5, 8, "Lower-bound devices", "1", 0, "C", true, 0, "")
	pdf.CellFormat(43.5, 8, "Unknown coverage", "1", 1, "C", true, 0, "")
	pdf.SetFont(reportFont, "", 11)
	pdf.CellFormat(43.5, 8, fmt.Sprint(r.Coverage.DevicesTotal), "1", 0, "C", false, 0, "")
	pdf.CellFormat(43.5, 8, fmt.Sprint(r.Coverage.DevicesWithTooling), "1", 0, "C", false, 0, "")
	pdf.CellFormat(43.5, 8, fmt.Sprint(r.Coverage.LowerBoundDevices), "1", 0, "C", false, 0, "")
	pdf.CellFormat(43.5, 8, fmt.Sprint(r.Coverage.UnknownDevices), "1", 1, "C", false, 0, "")
	pdf.Ln(5)

	pdf.SetFont(reportFont, "B", 8)
	pdf.SetFillColor(colourTableHdr[0], colourTableHdr[1], colourTableHdr[2])
	for _, h := range []struct {
		text  string
		width float64
	}{{"Device", 30}, {"Type", 25}, {"Identity", 42}, {"Version", 20}, {"Last used", 27}, {"Policy", 15}, {"Assessment", 15}} {
		pdf.CellFormat(h.width, 7, h.text, "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetFont(reportFont, "", 7)
	for i, item := range r.Items {
		if pdf.GetY() > 272 {
			pdf.AddPage()
		}
		assessment := "not assessed"
		if len(item.Assessments) > 0 {
			states := make([]string, 0, len(item.Assessments))
			for _, a := range item.Assessments {
				states = append(states, a.State)
			}
			assessment = strings.Join(states, ", ")
		}
		version := ""
		if item.Version != nil {
			version = *item.Version
		}
		lastUsed := toolingEvidenceLastUsedLabel(item)
		if i%2 == 1 {
			pdf.SetFillColor(colourRowAlt[0], colourRowAlt[1], colourRowAlt[2])
		}
		fill := i%2 == 1
		for _, c := range []struct {
			text  string
			width float64
		}{
			{item.Hostname, 30}, {item.EntryKind, 25}, {item.Identity, 42}, {version, 20}, {lastUsed, 27}, {item.PolicyState, 15}, {assessment, 15},
		} {
			pdf.CellFormat(c.width, 6, truncatePDFCell(c.text, 34), "1", 0, "L", fill, 0, "")
		}
		pdf.Ln(-1)
	}
	pdf.Ln(5)
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4, "Coverage note: partial collection is a lower bound. Failed or not reported collection remains unknown. An entry without a current, fresh assessment is not presented as clean.", "", "L", false)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write AI tooling evidence PDF: %w", err)
	}
	return buf.Bytes(), nil
}

// toolingEvidenceLastUsedLabel translates evidence coverage into customer
// language. A nil timestamp is deliberately not presented as non-use unless
// fully metered collection has established that no launch was recorded.
func toolingEvidenceLastUsedLabel(item ToolingEvidenceItem) string {
	// Launch metering exists only for desktop application rows. Older tooling
	// blocks do not have a metering contract, so an empty state means N/A, not
	// unknown evidence.
	if item.EntryKind != "application" {
		return "Not applicable"
	}
	if item.LastUsedAt != nil {
		return item.LastUsedAt.UTC().Format("2 Jan 2006")
	}
	switch item.MeteringState {
	case "metered":
		return "No launch recorded"
	case "stale":
		return "Stale"
	case "unmetered":
		return "Unavailable"
	case "unknown", "partial":
		return "Unknown"
	case "not_applicable":
		return "Not applicable"
	default:
		return "Unknown"
	}
}

func truncatePDFCell(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "..."
}
