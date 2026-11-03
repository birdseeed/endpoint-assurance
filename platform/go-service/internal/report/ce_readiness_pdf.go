package report

// The CE evidence pack is a presentation of the existing tenant read model.
// It neither fetches evidence nor derives control states or readiness scores.
import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/sfnt"
)

// RenderCEReadinessPDFCustomer renders the complete in-memory read model with
// the same customer branding and embedded fonts as the insurance evidence pack.
// All endpoint/feed strings are plain text, never HTML or PDF links. Text
// wraps even unbroken strings and automatically continues across pages; no
// device, control, item or field is truncated to fit a table or page budget.
func RenderCEReadinessPDFCustomer(d PortalCEReadiness) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("Patched: Cyber Essentials readiness evidence pack", true)
	pdf.SetAuthor("Patched LTD", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")
	pdf.AddPage()
	pdf.SetY(drawCustomerHeaderMark(pdf, 80))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Assurance  |  Audit Evidence", "", 1, "C", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.6)
	pdf.Ln(4)
	pdf.SetFont(reportFont, "B", 17)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 8, "Cyber Essentials readiness evidence pack", "", "C", false)
	pdf.Ln(2)
	cePDFField(pdf, "Generated", cePDFTime(&d.GeneratedAt))
	cePDFField(pdf, "Classification", "Confidential: authenticated customer estate")
	pdf.Ln(2)
	cePDFParagraph(pdf, "This is dated endpoint evidence for the existing Cyber Essentials v3.3 readiness view. It provides no estate pass/fail verdict or certification promise. No outstanding items evidenced does not establish that nothing is outstanding. Unknown, stale, silent and not_evidenced states remain explicit.")
	cePDFParagraph(pdf, "Update due dates use advisory publication plus 14 days, a conservative proxy. The platform stores no fix-release date; this basis can overstate how overdue an item is. The pack does not establish when a fix became available or close the 14-day update obligation. Remediation belongs to your endpoint-management platform. Only a Cyber Essentials assessor certifies.")
	cePDFParagraph(pdf, "Scope is the existing read model: confirmed critical/high CVE items and the controls listed for each device. OS update evidence is shown as held, including unknown or unavailable states. Missing evidence is not a positive result. This pack adds no collection, control mapping or scoring.")
	cePDFParagraph(pdf, "Characters unavailable in the embedded font are shown as Unicode codepoint escapes: for example U+1F600 in square brackets. Literal opening square brackets are encoded as U+005B in the same form, making the text reversible. Windows line endings appear as one line break; lone carriage returns are escaped.")
	cePDFHeading(pdf, "Thresholds")
	cePDFField(pdf, "Update due after", fmt.Sprintf("%d days", d.Thresholds.UpdateDueAfterDays))
	cePDFField(pdf, "Active within", fmt.Sprintf("%d hours", d.Thresholds.ActiveWithinHours))
	cePDFField(pdf, "Silent after", fmt.Sprintf("%d days", d.Thresholds.SilentAfterDays))
	cePDFHeading(pdf, "Estate counts (no verdict)")
	for _, c := range []struct {
		label string
		value int
	}{
		{"Devices in scope", d.Estate.DevicesTotal},
		{"Not passing", d.Estate.NotPassing},
		{"With outstanding items", d.Estate.WithOutstandingItems},
		{"With controls not passing", d.Estate.WithControlsNotPassing},
		{"Unknown", d.Estate.Unknown},
		{"No outstanding items evidenced", d.Estate.NoOutstandingItemsEvidence},
		{"Retired devices excluded", d.Estate.RetiredExcluded},
	} {
		cePDFField(pdf, c.label, fmt.Sprint(c.value))
	}
	cePDFField(pdf, "Count source", d.Estate.Source)
	cePDFField(pdf, "Counts generated", cePDFTime(&d.Estate.Freshness.GeneratedAt))
	cePDFField(pdf, "Newest underlying observation", cePDFTime(d.Estate.Freshness.ObservedAt))
	cePDFEvidence(pdf, "Global CVE matching", d.CVEMatching)
	if len(d.Devices) == 0 {
		cePDFParagraph(pdf, "No devices in scope in this read model. This is not evidence of a healthy or complete estate.")
	}
	for i, dev := range d.Devices {
		pdf.AddPage()
		cePDFHeading(pdf, fmt.Sprintf("Device %d of %d", i+1, len(d.Devices)))
		cePDFField(pdf, "Hostname", dev.Hostname)
		cePDFField(pdf, "Device ID", dev.DeviceID)
		cePDFField(pdf, "Platform", dev.Platform)
		cePDFField(pdf, "Device state", dev.State)
		if len(dev.StateReasons) == 0 {
			cePDFField(pdf, "State reasons", "none recorded")
		}
		for _, reason := range dev.StateReasons {
			cePDFField(pdf, "State reason", reason)
		}
		cePDFHeading(pdf, "Reporting")
		cePDFField(pdf, "Bucket", dev.Reporting.Bucket)
		cePDFField(pdf, "Source", dev.Reporting.Source)
		cePDFField(pdf, "Observed", cePDFTime(dev.Reporting.ObservedAt))
		cePDFEvidence(pdf, "CVE matching evidence", dev.CVEEvidence)
		cePDFEvidence(pdf, "OS update evidence", dev.OSUpdateEvidence)
		if len(dev.Controls) == 0 {
			cePDFHeading(pdf, "Controls (0)")
			cePDFParagraph(pdf, "No controls are mapped in this read model for this device. No control outcome is implied.")
		}
		for j, c := range dev.Controls {
			headings := []string{fmt.Sprintf("Control %d of %d", j+1, len(dev.Controls))}
			if j == 0 {
				headings = append([]string{fmt.Sprintf("Controls (%d)", len(dev.Controls))}, headings...)
			}
			cePDFBlock(pdf, headings, []cePDFBlockField{
				{"Control", c.Control}, {"Category", c.Category}, {"State", c.State},
				{"Reason", cePDFString(c.Reason)}, {"Source", c.Source},
				{"Rule key", cePDFString(c.RuleKey)}, {"Observed", cePDFTime(c.ObservedAt)},
			})
		}
		if len(dev.Items) == 0 {
			cePDFHeading(pdf, "Outstanding critical/high items (0)")
			cePDFParagraph(pdf, "No outstanding items recorded for this device. Interpret this alongside its reporting state, reasons and evidence availability above.")
		}
		for j, it := range dev.Items {
			headings := []string{fmt.Sprintf("Item %d of %d", j+1, len(dev.Items))}
			if j == 0 {
				headings = append([]string{fmt.Sprintf("Outstanding critical/high items (%d)", len(dev.Items))}, headings...)
			}
			cePDFBlock(pdf, headings, []cePDFBlockField{
				{"CVE", it.CVEID}, {"Kind", it.Kind}, {"Severity", it.Severity}, {"Product", it.Product},
				{"Installed version", it.InstalledVersion}, {"Fixed version", cePDFString(it.FixedVersion)},
				{"Source", it.Source}, {"Observed", cePDFTime(it.ObservedAt)},
				{"Advisory published", cePDFTime(&it.PublishedAt)}, {"Due basis", it.DueBasis},
				{"Due", cePDFTime(&it.DueAt)}, {"Age", fmt.Sprintf("%d days", it.AgeDays)},
				{"Overdue", fmt.Sprintf("%d days", it.DaysOverdue)},
				{"", "Due/overdue use advisory publication plus 14 days, a conservative proxy, not the fix-release date."},
				{"KEV state", it.KEV.State}, {"KEV source", it.KEV.Source},
				{"KEV fetched", cePDFTime(it.KEV.FetchedAt)}, {"KEV reason", cePDFString(it.KEV.Reason)},
			})
		}
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write CE readiness PDF: %w", err)
	}
	return buf.Bytes(), nil
}

func cePDFTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
func cePDFString(s *string) string {
	if s == nil || *s == "" {
		return "not recorded"
	}
	return *s
}
func cePDFField(pdf *fpdf.Fpdf, label, value string) {
	if value == "" {
		value = "not recorded"
	}
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	cePDFText(pdf, label+": "+value)
}
func cePDFParagraph(pdf *fpdf.Fpdf, text string) {
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	cePDFText(pdf, text)
	pdf.Ln(2)
}
func cePDFHeading(pdf *fpdf.Fpdf, title string) {
	// Use this document's actual bottom margin, as block measurement does.
	// The portal report's larger branded footer has different geometry.
	_, pageHeight := pdf.GetPageSize()
	_, margin := pdf.GetAutoPageBreak()
	if pdf.GetY()+18 > pageHeight-margin {
		pdf.AddPage()
	}
	pdf.Ln(3)
	sectionHeader(pdf, title)
}
func cePDFEvidence(pdf *fpdf.Fpdf, title string, e CEEvidence) {
	cePDFHeading(pdf, title)
	cePDFField(pdf, "State", e.State)
	cePDFField(pdf, "Reason", cePDFString(e.Reason))
	cePDFField(pdf, "Source", e.Source)
	cePDFField(pdf, "Observed", cePDFTime(e.ObservedAt))
}

// cePDFBlock keeps a control or item with its heading when its measured
// wrapped content fits on a fresh page. Oversized blocks flow across pages.
// Wrapping happens once, using the actual font metrics; the same lines are
// measured and rendered, avoiding estimates or drifting field lists.
type cePDFBlockField struct{ label, value string }

func cePDFBlock(pdf *fpdf.Fpdf, headings []string, fields []cePDFBlockField) {
	type wrappedField struct {
		lines     []string
		paragraph bool
	}
	pdf.SetFont(reportFont, "", 9)
	pageWidth, pageHeight := pdf.GetPageSize()
	left, top, right, _ := pdf.GetMargins()
	wrapped := make([]wrappedField, 0, len(fields))
	height := float64(len(headings)) * 10 // 3 mm heading spacing + 7 mm title
	for _, field := range fields {
		text := field.value
		if field.label != "" {
			if text == "" {
				text = "not recorded"
			}
			text = field.label + ": " + text
		}
		lines := cePDFWrap(pdf, text, pageWidth-left-right-2*pdf.GetCellMargin())
		if pdf.Error() != nil {
			return
		}
		if len(lines) == 0 {
			lines = []string{""}
		}
		paragraph := field.label == ""
		wrapped = append(wrapped, wrappedField{lines, paragraph})
		height += float64(len(lines)) * 4.8
		if paragraph {
			height += 2
		}
	}
	_, margin := pdf.GetAutoPageBreak()
	if height <= pageHeight-margin-top && pdf.GetY()+height > pageHeight-margin {
		pdf.AddPage()
	}
	for _, heading := range headings {
		cePDFHeading(pdf, heading)
	}
	for _, field := range wrapped {
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourBodyText)
		if field.paragraph {
			setTextColour(pdf, colourMuted)
		}
		for _, line := range field.lines {
			pdf.CellFormat(0, 4.8, line, "", 1, "L", false, 0, "")
		}
		if field.paragraph {
			pdf.Ln(2)
		}
	}
}

// Wrap at actual glyph widths without treating non-space characters as
// discardable word separators. fpdf's SplitText directly indexes its 16-bit
// width table for arbitrary runes, unlike MultiCell's checked path.
func cePDFWrap(pdf *fpdf.Fpdf, text string, width float64) []string {
	if pdf.Error() != nil {
		return nil
	}
	var lines []string
	text = cePDFPrintable(pdf, text)
	if pdf.Error() != nil {
		return nil
	}
	for _, paragraph := range strings.Split(text, "\n") {
		runes := []rune(paragraph)
		start, end, space := 0, 0, -1
		used := 0.0
		for end < len(runes) {
			r := runes[end]
			glyph := pdf.GetStringWidth(string(r))
			if used+glyph > width && end > start {
				if space >= start {
					lines = append(lines, string(runes[start:space]))
					start = space + 1
				} else {
					lines = append(lines, string(runes[start:end]))
					start = end
				}
				end, space, used = start, -1, 0
				continue
			}
			used += glyph
			if r == ' ' {
				space = end
			}
			end++
		}
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

func cePDFText(pdf *fpdf.Fpdf, text string) {
	width, _ := pdf.GetPageSize()
	left, _, right, _ := pdf.GetMargins()
	for _, line := range cePDFWrap(pdf, text, width-left-right-2*pdf.GetCellMargin()) {
		pdf.CellFormat(0, 4.8, line, "", 1, "L", false, 0, "")
	}
}

// The same embedded Inter regular font renders every evidence value. Read its
// actual glyph map once; sfnt parses the existing font without adding assets or
// a handwritten font parser. Each call owns its scratch buffer.
var cePDFFont = sync.OnceValues(func() (*sfnt.Font, error) { return sfnt.Parse(reportSansRegular) })

func cePDFPrintable(pdf *fpdf.Fpdf, text string) string {
	font, err := cePDFFont()
	if err != nil {
		pdf.SetErrorf("read CE evidence font: %v", err)
		return ""
	}
	var buf sfnt.Buffer
	var out strings.Builder
	// Treat Windows CRLF as one line break; retain a lone CR explicitly.
	for _, r := range strings.ReplaceAll(text, "\r\n", "\n") {
		if r == '\n' {
			out.WriteRune(r)
			continue
		}
		supported := r <= 0xffff && unicode.IsPrint(r) && r != '['
		if supported {
			glyph, err := font.GlyphIndex(&buf, r)
			if err != nil {
				pdf.SetErrorf("read CE evidence glyph: %v", err)
				return ""
			}
			supported = glyph != 0
		}
		if supported {
			out.WriteRune(r)
		} else {
			fmt.Fprintf(&out, "[U+%04X]", r)
		}
	}
	return out.String()
}
