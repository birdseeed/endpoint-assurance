package report

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-pdf/fpdf"
)

// assetsFS embeds the brand assets shipped with the report renderer.
//
//go:embed assets/header.png
var assetsFS embed.FS

// Shared UTF-8 report font (PAT-2265). fpdf's core "Helvetica" is not UTF-8
// aware: any en/em dash, bullet or ≤/≥ in report copy came out as mojibake
// ("â€..." sequences) because fpdf silently mapped the rune through
// Latin-1/cp1252 rather than embedding a real glyph. Inter (SIL OFL 1.1;
// see assets/fonts/OFL-Inter.txt) was already vendored for the
// customer-facing portal renderer (portal_pdf.go, prInterRegular/prInterBold)
// — this reuses exactly those two files plus a matching italic from the same
// upstream release, rather than vendoring a second font. Source: the
// official upstream release, github.com/rsms/inter releases/download/v4.1/
// Inter-4.1.zip, extras/ttf/Inter-{Regular,Bold,Italic}.ttf. sha256 of
// Inter-Regular.ttf and Inter-Bold.ttf match the files already vendored
// under assets/fonts/ byte-for-byte, confirming they came from that same
// v4.1 release; Inter-Italic.ttf was extracted from the same zip so all
// three styles are provably the same build. No published checksum manifest
// ships alongside the zip on GitHub, so provenance is the official release
// URL plus this byte-for-byte match against a file already carried in this
// repo.
//
//go:embed assets/fonts/Inter-Regular.ttf
var reportSansRegular []byte

//go:embed assets/fonts/Inter-Bold.ttf
var reportSansBold []byte

//go:embed assets/fonts/Inter-Italic.ttf
var reportSansItalic []byte

// reportFont is the UTF-8 font family every renderer in this package
// registers in place of the core "Helvetica"/"Arial" font.
const reportFont = "PSans"

// registerReportFont registers the shared UTF-8 report font (regular, bold,
// italic) on pdf. fpdf keeps registered fonts per *Fpdf instance, not
// process-wide, so every renderer that creates its own fpdf.New(...) must
// call this once, before its first SetFont(reportFont, ...) call.
//
// Page-number footers are a deliberate exception (PAT-2264/PAT-2265): they
// keep pdf.SetFont(reportFont, ...) because fpdf's {nb}/AliasNbPages total-
// page-count substitution rewrites the raw content stream by literal byte
// search, which does not survive being encoded through a subsetted UTF-8
// font. Page numbers are ASCII digits, so they carry no mojibake risk either
// way — see the identical note already in portal_pdf.go.
func registerReportFont(pdf *fpdf.Fpdf) {
	pdf.AddUTF8FontFromBytes(reportFont, "", reportSansRegular)
	pdf.AddUTF8FontFromBytes(reportFont, "B", reportSansBold)
	pdf.AddUTF8FontFromBytes(reportFont, "I", reportSansItalic)
}

// Page geometry. A4 portrait, 18mm side margins gives 174mm content width —
// matches the visual density of the CVE Vulnerability Assessment template
// (the deliberate "corporate document" look, not a dashboard).
const (
	contentWidth = 174.0
	leftMargin   = 18.0
	rightMargin  = 18.0
	topMargin    = 14.0
	bottomMargin = 14.0
)

// Palette is intentionally minimal. The brand image carries the colour;
// the body text stays nearly monochrome so the document reads as an
// auditor-friendly report, not a dashboard.
var (
	colourBodyText = [3]int{40, 40, 40}    // near-black, slightly softened
	colourMuted    = [3]int{110, 110, 110} // labels, metadata
	colourRule     = [3]int{40, 40, 40}    // horizontal rules
	colourRowAlt   = [3]int{246, 246, 248} // zebra striping for long tables
	colourTableHdr = [3]int{231, 231, 235} // soft grey table header band
	colourAccent   = [3]int{245, 83, 10}   // signal orange #f5530a
	colourSlate    = [3]int{15, 17, 21}    // near-black #0f1115 — CTA panel
)

// ReportAudience selects who a rendered report PDF is for. It controls only
// the header's brand mark and wording (PAT-2264); it changes no colours,
// fonts or layout of anything else. The zero value, AudienceStaff,
// reproduces the exact header every existing caller already gets, so no
// current call site changes behaviour unless it explicitly asks for
// AudienceCustomer.
type ReportAudience int

const (
	// AudienceStaff renders the internal header: the embedded header.png,
	// unchanged — icon, "Patched" wordmark and "Staff report" caption, all
	// baked into one raster. Used by every /admin/reports/* route.
	AudienceStaff ReportAudience = iota
	// AudienceCustomer renders the customer-safe header: the current in-app
	// brand mark plus "Patched" as live text, and never the word "Staff".
	// Used by the authenticated customer portal's own report downloads.
	AudienceCustomer
)

// RenderPDF turns a Report into a printable PDF byte slice in the
// patched.im corporate-document style: image header, tagline, ━━━ rule,
// "Prepared for" block, conservative tables, closing disclaimer.
func RenderPDF(r Report) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Endpoint Compliance Assessment", true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)

	// Register the embedded brand header once at startup; subsequent
	// ImageOptions calls draw from the registered image.
	if err := registerHeader(pdf); err != nil {
		return nil, err
	}

	pdf.SetFooterFunc(func() {
		// Per-page footer: page X / Y only. The full closer (rule +
		// disclaimer + generated line) draws once at the end of the
		// content, not on every page — matches the CVE doc template.
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()),
			"", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")

	pdf.AddPage()

	renderHeader(pdf, r)
	renderEstateSummary(pdf, r)
	renderComplianceSummary(pdf, r)
	renderDevicePosture(pdf, r)
	renderFailingControls(pdf, r)
	renderUndeterminedControls(pdf, r)
	renderPassingControls(pdf, r)
	renderPendingUpdates(pdf, r)
	renderPatchHistory(pdf, r)
	renderSoftwareInventory(pdf, r)
	renderBrowserExtensions(pdf, r)
	renderComplianceCVEFindings(pdf, r)
	renderComplianceCatalogUpdates(pdf, r)
	renderRecommendations(pdf, r)
	renderCloser(pdf, r)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// --- Header + closer -------------------------------------------------------

func registerHeader(pdf *fpdf.Fpdf) error {
	f, err := assetsFS.Open("assets/header.png")
	if err != nil {
		return fmt.Errorf("open header asset: %w", err)
	}
	defer f.Close()
	// Read into memory; fpdf's RegisterImageOptionsReader wants an io.Reader.
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, f); err != nil {
		return fmt.Errorf("read header asset: %w", err)
	}
	pdf.RegisterImageOptionsReader("header.png",
		fpdf.ImageOptions{ImageType: "PNG", ReadDpi: false},
		buf)
	return nil
}

// drawCustomerHeaderMark draws the customer-facing report header's brand
// block in place of header.png: the current in-app brand mark (prMarkPNG,
// the same embedded asset the executive-summary customer renderer already
// uses — see portal_pdf.go) plus "Patched" as live text, never the "Staff
// report" caption baked into header.png (PAT-2264). imageWidth is the same
// value the caller already used for header.png, so the block occupies
// materially the same footprint. Returns the y coordinate the caller should
// resume drawing from.
func drawCustomerHeaderMark(pdf *fpdf.Fpdf, imageWidth float64) float64 {
	return drawCustomerHeaderMarkOn(pdf, imageWidth, 210.0)
}

// drawCustomerHeaderMarkOn is drawCustomerHeaderMark centred on a page
// pageWidth mm wide, for a renderer that is not A4 portrait (PAT-2405's
// landscape table export).
func drawCustomerHeaderMarkOn(pdf *fpdf.Fpdf, imageWidth, pageWidth float64) float64 {
	pdf.RegisterImageOptionsReader("pat2264-customer-mark",
		fpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(prMarkPNG))
	markSize := imageWidth * 0.3
	markX := (pageWidth - markSize) / 2
	pdf.ImageOptions("pat2264-customer-mark", markX, topMargin, markSize, markSize, false,
		fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	y := topMargin + markSize + 3
	pdf.SetXY((pageWidth-imageWidth)/2, y)
	pdf.SetFont(reportFont, "B", 20)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(imageWidth, 9, "Patched", "", 1, "C", false, 0, "")
	return y + 9 + 2
}

func renderHeader(pdf *fpdf.Fpdf, r Report) {
	// Image is 500x300 (5:3). At 80mm wide it renders 48mm tall — same
	// visual weight as the 3.5-inch width used in the CVE doc template,
	// centred on the page.
	imageWidth := 80.0
	x := (210.0 - imageWidth) / 2 // page width 210mm A4 / centre
	pdf.ImageOptions("header.png", x, topMargin, imageWidth, 0, false,
		fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	pdf.SetY(topMargin + imageWidth*0.6 + 3)

	// Tagline
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Endpoint Security  |  Compliance  |  Patch Management",
		"", 1, "C", false, 0, "")
	pdf.Ln(2)

	// Heavy horizontal rule across the content width
	hrule(pdf, 0.6)

	// Title — centred, bold, dark
	pdf.Ln(4)
	pdf.SetFont(reportFont, "B", 18)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 10, "Endpoint Compliance Assessment", "", 1, "C", false, 0, "")

	// Prepared-for block — five centred lines, conservative spacing.
	pdf.Ln(1)
	pdf.SetFont(reportFont, "", 10)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared for", "", 1, "C", false, 0, "")

	pdf.SetFont(reportFont, "B", 13)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, fallback(r.Tenant), "", 1, "C", false, 0, "")

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 5,
		"Report Date: "+r.GeneratedAt.Format("02 Jan 2006"),
		"", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, "Classification: Confidential", "", 1, "C", false, 0, "")
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im Ltd  |  patched.im", "", 1, "C", false, 0, "")

	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(4)
}

func renderCloser(pdf *fpdf.Fpdf, r Report) {
	pdf.Ln(4)
	hrule(pdf, 0.4)
	pdf.Ln(3)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"This report was generated by Patched.im Ltd from device telemetry collected by the patched.im endpoint agent, evaluated against the CIS Apple macOS Level 1 benchmark and the patched.im baseline ruleset. It does not constitute a penetration test or a formal audit certification. Findings reflect the most recent successful collection from each device.",
		"", "L", false)

	pdf.Ln(2)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated: "+r.GeneratedAt.Format("02 Jan 2006 15:04 MST")+"  |  patched.im",
		"", 1, "L", false, 0, "")
}

// --- Estate / compliance / device summary ----------------------------------

func renderEstateSummary(pdf *fpdf.Fpdf, r Report) {
	sectionHeader(pdf, "Estate Summary")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	deviceOS := strings.TrimSpace(r.Device.OS + " " + r.Device.OSVersion)
	pdf.MultiCell(0, 5,
		fmt.Sprintf("patched.im assessed 1 endpoint (%s) belonging to %s against the CIS Apple macOS Level 1 benchmark and the patched.im baseline ruleset. Each control was evaluated from the device's most recent telemetry collection.",
			deviceOS, fallback(r.Tenant)),
		"", "L", false)
	pdf.Ln(2)
}

func renderComplianceSummary(pdf *fpdf.Fpdf, r Report) {
	sectionHeader(pdf, "Compliance Summary")

	// PAT-1960: this device's class matches no enabled rule for its
	// platform (e.g. a server under the workstation-only Windows 11 pack).
	// Evaluations is empty by design — render that honestly rather than a
	// table of zeros that would read as the device failing every control.
	if r.NotAssessed {
		pdf.SetFont(reportFont, "B", 10)
		setTextColour(pdf, colourBodyText)
		pdf.CellFormat(0, 5, r.NotAssessedReason+".", "", 1, "L", false, 0, "")
		pdf.Ln(1)
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourMuted)
		pdf.MultiCell(0, 4,
			fmt.Sprintf("This device's class did not match any enabled rule in the %s benchmark. No control was evaluated, and this device is excluded from the estate's pass/fail counts rather than scored.",
				strings.TrimSpace(r.Device.OS)),
			"", "L", false)
		pdf.Ln(2)
		return
	}

	s := r.Summary()

	// Five-column counts table. PAT-1762: Undetermined (unreadable evidence)
	// is broken out of Fail — see Report.Summary — so it gets its own column
	// rather than being silently folded into either Fail or Not Applicable.
	widths := []float64{34.8, 34.8, 34.8, 34.8, 34.8}
	tableHeader(pdf, []string{"Pass", "Fail", "Undetermined", "Not Applicable", "Errors"}, widths)
	tableBody(pdf, [][]string{{
		fmt.Sprintf("%d", s.Pass),
		fmt.Sprintf("%d", s.Fail),
		fmt.Sprintf("%d", s.Undetermined),
		fmt.Sprintf("%d", s.NotApplicable),
		fmt.Sprintf("%d", s.Error),
	}}, widths, false)

	// Compliance percentage as a short emphasised line beneath the table.
	// Denominator includes Undetermined (PAT-1762: missing evidence must
	// never raise the score) even though Undetermined is excluded from the
	// "passing" numerator's counterpart, Fail, above.
	pdf.Ln(2)
	pdf.SetFont(reportFont, "B", 10)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 5,
		fmt.Sprintf("Overall compliance: %.1f%% (%d of %d evaluated controls passing)",
			s.CompliancePct, s.Pass, s.Pass+s.Fail+s.Undetermined+s.Error),
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	if s.Undetermined > 0 {
		pdf.MultiCell(0, 4,
			fmt.Sprintf("%d control%s could not be determined. The collector could not read the device's current state, which is not the same claim as the device being checked and found non-compliant. See \"Could Not Be Determined\" below.",
				s.Undetermined, plural(s.Undetermined)),
			"", "L", false)
		pdf.Ln(1)
	}
	pdf.CellFormat(0, 4, "Benchmarks evaluated: "+summariseBenchmarks(r.Evaluations),
		"", 1, "L", false, 0, "")

	// Coverage note: implemented vs benchmark_total per benchmark.
	if len(r.BenchmarkTotals) > 0 {
		pdf.Ln(1)
		for _, line := range benchmarkCoverageLines(r) {
			pdf.CellFormat(0, 4, line, "", 1, "L", false, 0, "")
		}
	}
	pdf.Ln(2)
}

func renderDevicePosture(pdf *fpdf.Fpdf, r Report) {
	sectionHeader(pdf, "Device")
	widths := []float64{50, 124}
	rows := [][]string{
		{"Hostname", fallback(r.Device.Hostname)},
		{"Computer name", fallback(r.Device.ComputerName)},
		{"Serial", fallback(r.Device.Serial)},
		{"Hardware UUID", fallback(r.Device.HWUUID)},
		{"Model", fallback(r.Device.HWModel)},
		{"Architecture", fallback(r.Device.Arch)},
		{"Operating system", strings.TrimSpace(r.Device.OS + " " + r.Device.OSVersion + " (" + r.Device.OSBuild + ")")},
		{"Agent version", fallback(r.Device.AgentVersion)},
		{"First seen", r.Device.FirstSeen.Format("02 Jan 2006 15:04 MST")},
		{"Last seen", r.Device.LastSeen.Format("02 Jan 2006 15:04 MST")},
	}
	tableHeader(pdf, []string{"Attribute", "Value"}, widths)
	tableBody(pdf, rows, widths, true)
	pdf.Ln(2)
}

// --- Compliance findings ---------------------------------------------------

// isUndeterminedEval reports whether ev is unreadable evidence (PAT-1758/
// PAT-1762): status=fail with no observed value — an absent signal, or the
// collector's literal "Unknown" sentinel routed through treat_unknown_as.
// A "NotConfigured" fail has a non-nil observed value and is a real,
// evidenced result, so it is NOT undetermined by this predicate.
func isUndeterminedEval(ev EvalRow) bool {
	return ev.Status == "fail" && ev.ObservedValue == nil
}

// Undetermined reports whether the evaluation failed only because its value
// could not be read (isUndeterminedEval). The portal device page sends it as
// "undetermined" on each Compliance tab entry (PAT-2496) so a rule that was
// not observed failing is not shown as a failure that was.
func (ev EvalRow) Undetermined() bool { return isUndeterminedEval(ev) }

// realFailingEvals drops undetermined fails from a fail/error slice, leaving
// only genuinely evidenced results. "error" rows are never undetermined by
// this predicate and pass through unchanged.
func realFailingEvals(in []EvalRow) []EvalRow {
	out := make([]EvalRow, 0, len(in))
	for _, ev := range in {
		if !isUndeterminedEval(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// undeterminedEvals returns only the undetermined fails from in.
func undeterminedEvals(in []EvalRow) []EvalRow {
	out := make([]EvalRow, 0)
	for _, ev := range in {
		if isUndeterminedEval(ev) {
			out = append(out, ev)
		}
	}
	return out
}

func renderFailingControls(pdf *fpdf.Fpdf, r Report) {
	// PAT-1762: undetermined fails (unreadable evidence) are excluded here
	// and reported in their own "Could Not Be Determined" section instead —
	// a buyer must not read "the control failed" when the true claim is
	// "the collector could not read this device's state".
	failing := realFailingEvals(filterEvals(r.Evaluations, "fail", "error"))
	if len(failing) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Failing Controls (%d)", len(failing)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4, "Controls where the device's reported state did not satisfy the benchmark.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{20, 78, 32, 44}
	tableHeader(pdf, []string{"Severity", "Control", "Observed", "Reference"}, widths)

	rows := make([][]string, 0, len(failing))
	for _, ev := range failing {
		obs := "—"
		if ev.ObservedValue != nil {
			obs = *ev.ObservedValue
		}
		rows = append(rows, []string{
			strings.ToUpper(ev.Severity),
			ev.Title,
			obs,
			ev.Benchmark + " " + ev.BenchmarkVersion,
		})
	}
	tableBody(pdf, rows, widths, true)

	// Framework-mapping rollout block — render below the table so the table
	// stays narrow and scannable. One bullet line per failing rule.
	pdf.Ln(2)
	pdf.SetFont(reportFont, "B", 9)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 5, "Framework mappings (failing controls)", "", 1, "L", false, 0, "")
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourBodyText)
	for _, ev := range failing {
		mappings := joinMappings(ev)
		if mappings == "" {
			mappings = "no framework mappings recorded"
		}
		pdf.MultiCell(0, 4,
			fmt.Sprintf("•  %s:  %s", ev.Title, mappings),
			"", "L", false)
	}
	pdf.Ln(2)
}

// renderUndeterminedControls surfaces evaluations the collector could not
// read (PAT-1758/PAT-1762) in plain words, separately from Failing Controls.
// Missing evidence is not the same claim as a real observation of
// non-compliance, and reporting it here rather than dropping it silently is
// the point of this section — see Report.Summary's Undetermined field.
func renderUndeterminedControls(pdf *fpdf.Fpdf, r Report) {
	undetermined := undeterminedEvals(filterEvals(r.Evaluations, "fail"))
	if len(undetermined) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Could Not Be Determined (%d)", len(undetermined)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4, "The collector could not read the device's current state for these controls (absent or unreadable evidence). This is excluded from Failing Controls above and is not a real observation of non-compliance.",
		"", "L", false)
	pdf.Ln(1)
	renderEvalTable(pdf, undetermined)
	pdf.Ln(2)
}

func renderPassingControls(pdf *fpdf.Fpdf, r Report) {
	passing := filterEvals(r.Evaluations, "pass")
	notApp := filterEvals(r.Evaluations, "not_applicable")
	if len(passing) == 0 && len(notApp) == 0 {
		return
	}

	if len(passing) > 0 {
		sectionHeader(pdf, fmt.Sprintf("Passing Controls (%d)", len(passing)))
		renderEvalTable(pdf, passing)
		pdf.Ln(2)
	}
	if len(notApp) > 0 {
		sectionHeader(pdf, fmt.Sprintf("Not Applicable (%d)", len(notApp)))
		renderEvalTable(pdf, notApp)
		pdf.Ln(2)
	}
}

func renderEvalTable(pdf *fpdf.Fpdf, evs []EvalRow) {
	widths := []float64{20, 110, 44}
	tableHeader(pdf, []string{"Severity", "Control", "Observed"}, widths)
	rows := make([][]string, 0, len(evs))
	for _, ev := range evs {
		obs := "—"
		if ev.ObservedValue != nil {
			obs = *ev.ObservedValue
		}
		rows = append(rows, []string{
			strings.ToUpper(ev.Severity),
			ev.Title,
			obs,
		})
	}
	tableBody(pdf, rows, widths, true)
}

// --- Patching --------------------------------------------------------------

func renderPendingUpdates(pdf *fpdf.Fpdf, r Report) {
	if len(r.PendingUpdates) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Pending macOS Updates (%d)", len(r.PendingUpdates)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4, "Outstanding macOS updates reported by softwareupdate at last collection.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{78, 28, 28, 40}
	tableHeader(pdf, []string{"Update", "Version", "Recommended", "Required action"}, widths)
	rows := make([][]string, 0, len(r.PendingUpdates))
	for _, u := range r.PendingUpdates {
		rec := "No"
		if u.Recommended {
			rec = "Yes"
		}
		action := u.Action
		if action == "" {
			action = "—"
		}
		rows = append(rows, []string{u.Title, u.Version, rec, action})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(2)
}

func renderPatchHistory(pdf *fpdf.Fpdf, r Report) {
	if len(r.PatchHistory) == 0 {
		return
	}

	total := len(r.PatchHistory)
	heading := fmt.Sprintf("macOS Update History (%d)", total)
	if total > patchHistoryLimit {
		heading = fmt.Sprintf("macOS Update History (most recent %d of %d)", patchHistoryLimit, total)
	}
	sectionHeader(pdf, heading)
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4, "From softwareupdate --history. Most recent first.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{106, 28, 40}
	tableHeader(pdf, []string{"Update", "Version", "Installed"}, widths)

	limit := total
	if limit > patchHistoryLimit {
		limit = patchHistoryLimit
	}
	rows := make([][]string, 0, limit)
	for i := 0; i < limit; i++ {
		p := r.PatchHistory[i]
		installed := "unknown"
		if p.InstalledAt != nil {
			installed = p.InstalledAt.UTC().Format("02 Jan 2006")
		}
		rows = append(rows, []string{p.Title, afterPipe(p.Identifier), installed})
	}
	tableBody(pdf, rows, widths, true)

	if total > patchHistoryLimit {
		pdf.Ln(1)
		pdf.SetFont(reportFont, "I", 8)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 4, fmt.Sprintf("+ %d earlier updates not shown", total-patchHistoryLimit),
			"", 1, "L", false, 0, "")
	}
	pdf.Ln(2)
}

const patchHistoryLimit = 20

func renderSoftwareInventory(pdf *fpdf.Fpdf, r Report) {
	if len(r.Apps) == 0 {
		return
	}
	pdf.AddPage()
	sectionHeader(pdf, fmt.Sprintf("Software Inventory (%d)", len(r.Apps)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4, "All .app bundles observed at last collection. Third-party software listed first.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{60, 24, 18, 14, 58}
	tableHeader(pdf, []string{"Name", "Version", "Arch", "Notarised", "Signer"}, widths)

	sorted := sortAppsForReport(r.Apps)
	rows := make([][]string, 0, len(sorted))
	for _, a := range sorted {
		nz := "—"
		if a.Notarized != nil {
			if *a.Notarized {
				nz = "yes"
			} else {
				nz = "no"
			}
		}
		rows = append(rows, []string{
			truncate(a.Name, 42),
			truncate(a.Version, 18),
			truncate(a.Architecture, 12),
			nz,
			truncate(a.Signer, 42),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(2)
}

// --- Browser extensions ----------------------------------------------------

// renderBrowserExtensions renders an advisory subsection listing elevated-risk
// extensions (broad host access or sensitive API permissions). Platform-neutral
// wording — the data model covers both macOS and Windows.
func renderBrowserExtensions(pdf *fpdf.Fpdf, r Report) {
	if len(r.ElevatedExtensions) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Browser extensions worth a look (%d)", len(r.ElevatedExtensions)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4,
		"Extensions with broad host access or sensitive API permissions, from the most recent collection.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{58, 18, 16, 14, 68}
	tableHeader(pdf, []string{"Name", "Browser", "Version", "Enabled", "Concerning permissions / host access"}, widths)

	rows := make([][]string, 0, len(r.ElevatedExtensions))
	for _, ext := range r.ElevatedExtensions {
		enabled := "yes"
		if !ext.Enabled {
			enabled = "no"
		}
		rows = append(rows, []string{
			truncate(ext.Name, 40),
			ext.Browser,
			truncate(ext.Version, 14),
			enabled,
			truncate(joinExtPerms(ext.Permissions, ext.HostPermissions), 50),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(2)
}

// joinExtPerms concatenates the concerning permissions and host-permission
// patterns into a compact comma-separated string for the report cell.
func joinExtPerms(perms, hostPerms []string) string {
	all := make([]string, 0, len(perms)+len(hostPerms))
	all = append(all, perms...)
	all = append(all, hostPerms...)
	if len(all) == 0 {
		return "—"
	}
	return strings.Join(all, ", ")
}

// --- CVE findings + catalog updates ----------------------------------------

// renderComplianceCVEFindings renders the CVE vulnerability findings for installed apps.
// Matches the same data shown by GET /v1/posture findings (P2).
func renderComplianceCVEFindings(pdf *fpdf.Fpdf, r Report) {
	if len(r.CVEFindings) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Vulnerability Findings (%d CVEs affecting installed apps)", len(r.CVEFindings)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4,
		"CVEs matched against installed software versions. Description provenance is shown per finding.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{30, 20, 18, 52, 54}
	tableHeader(pdf, []string{"CVE ID", "CVSS", "Severity", "App / Version", "Description"}, widths)

	rows := make([][]string, 0, len(r.CVEFindings))
	for _, f := range r.CVEFindings {
		score := "—"
		if f.CVSSScore != nil {
			score = fmt.Sprintf("%.1f", *f.CVSSScore)
		}
		rows = append(rows, []string{
			f.CVEID,
			score,
			f.Severity,
			truncate(f.AppName+" "+f.AppVersion, 36),
			truncate(cveDescriptionWithSource(f.Description, f.DescriptionSource), 38),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(2)
}

// renderComplianceCatalogUpdates renders the available app updates from the updater catalog.
// Matches the same data shown by GET /v1/posture updates (P3).
func renderComplianceCatalogUpdates(pdf *fpdf.Fpdf, r Report) {
	if len(r.CatalogUpdates) == 0 {
		return
	}
	sectionHeader(pdf, fmt.Sprintf("Available App Updates (%d)", len(r.CatalogUpdates)))
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4,
		"Apps with installed version differing from the Patched-verified latest version. Update to close linked CVEs.",
		"", 1, "L", false, 0, "")
	pdf.Ln(1)

	widths := []float64{58, 30, 30, 56}
	tableHeader(pdf, []string{"App", "Current", "Target", "Closes CVEs"}, widths)

	rows := make([][]string, 0, len(r.CatalogUpdates))
	for _, u := range r.CatalogUpdates {
		cves := "—"
		if len(u.LinkedCVEIDs) > 0 {
			cves = strings.Join(u.LinkedCVEIDs, ", ")
		}
		rows = append(rows, []string{
			truncate(u.AppName, 40),
			truncate(u.CurrentVersion, 20),
			truncate(u.TargetVersion, 20),
			truncate(cves, 38),
		})
	}
	tableBody(pdf, rows, widths, true)
	pdf.Ln(2)
}

// benchmarkCoverageLines returns one line per benchmark showing "X of N controls checked".
func benchmarkCoverageLines(r Report) []string {
	// Group evaluations by benchmark||version.
	counts := map[string]int{}
	for _, ev := range r.Evaluations {
		key := ev.Benchmark + "||" + ev.BenchmarkVersion
		counts[key]++
	}
	lines := []string{}
	for key, total := range r.BenchmarkTotals {
		implemented := counts[key]
		// Human-readable: strip the "||" separator.
		parts := strings.SplitN(key, "||", 2)
		label := key
		if len(parts) == 2 {
			label = parts[0] + " " + parts[1]
		}
		lines = append(lines, fmt.Sprintf("Coverage: %d of %d controls checked (%s)", implemented, total, label))
	}
	return lines
}

// --- Recommendations -------------------------------------------------------

func renderRecommendations(pdf *fpdf.Fpdf, r Report) {
	// Static recommendation set in the v1 patched.im baseline. Future
	// versions can derive these from the failing-control set automatically.
	recs := []struct {
		title, body string
	}{
		{"1.  Remediate failing controls in priority order",
			"Address Critical and High severity failures first, then Medium. Each failing control in this report includes its CIS reference and cross-framework mappings (NIST SP 800-53, ISO 27001:2022, Cyber Essentials). The same evidence underpins multiple audit programmes."},
		{"2.  Enrol unmanaged endpoints in Intune (or equivalent MDM)",
			"MDM is the centralised lever for nearly every other control in this benchmark: FileVault enforcement, firewall policy, password policy, automatic updates. Unmanaged endpoints will continue to fail multiple controls regardless of remediation effort applied locally."},
		{"3.  Enable automatic macOS security updates",
			"Auto-installed security updates close the gap between vulnerability disclosure and remediation without operator intervention. Drift here is the single largest contributor to known-vulnerable mac fleets in SME estates."},
		{"4.  Establish a regular scan cadence",
			"Monthly patched.im collections to track remediation progress and surface newly-disclosed CVEs. Trend lines on compliance percentage are part of the audit-ready posture."},
		{"5.  Layer Conditional Access on top of compliance",
			"Block non-compliant endpoints from sensitive resources via Intune Conditional Access policies. Compliance enforcement that has business-impact teeth converts faster than soft compliance reporting."},
	}

	sectionHeader(pdf, "Recommendations")
	for _, rec := range recs {
		pdf.SetFont(reportFont, "B", 10)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 5, rec.title, "", "L", false)
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 4.5, rec.body, "", "L", false)
		pdf.Ln(1)
	}
}

// --- Table + section primitives --------------------------------------------

// sectionHeader draws a heading band: bold black title, no underline. Matches
// the visual rhythm of the CVE Vulnerability Assessment template — section
// titles aren't decorated, they just sit in bold above their content.
func sectionHeader(pdf *fpdf.Fpdf, title string) {
	pdf.SetFont(reportFont, "B", 12)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, title, "", 1, "L", false, 0, "")
}

// tableHeader draws a single-row header band with cell labels.
func tableHeader(pdf *fpdf.Fpdf, labels []string, widths []float64) {
	pdf.SetFont(reportFont, "B", 8)
	setTextColour(pdf, colourBodyText)
	setFillColour(pdf, colourTableHdr)
	for i, label := range labels {
		pdf.CellFormat(widths[i], 6, " "+label, "", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
}

// tableBody renders rows. When zebra=true alternates row fill for readability.
// All rows are 4mm tall; long content can overflow the visual cell — callers
// are expected to truncate where they want a hard upper bound.
func tableBody(pdf *fpdf.Fpdf, rows [][]string, widths []float64, zebra bool) {
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourBodyText)
	for i, row := range rows {
		if zebra && i%2 == 1 {
			setFillColour(pdf, colourRowAlt)
		} else {
			setFillColour(pdf, [3]int{255, 255, 255})
		}
		for j, cell := range row {
			pdf.CellFormat(widths[j], 4.8, " "+cell, "", 0, "L", true, 0, "")
		}
		pdf.Ln(-1)
	}
}

// hrule draws a horizontal rule the width of the content area, at the
// current Y position. Caller controls vertical spacing before/after.
func hrule(pdf *fpdf.Fpdf, thicknessMM float64) {
	hruleBetween(pdf, thicknessMM, leftMargin, leftMargin+contentWidth)
}

// hruleBetween is hrule from x1 to x2, for a renderer whose content area is
// not the A4 portrait one (PAT-2405's landscape table export).
func hruleBetween(pdf *fpdf.Fpdf, thicknessMM, x1, x2 float64) {
	r, g, b := colourRule[0], colourRule[1], colourRule[2]
	pdf.SetDrawColor(r, g, b)
	pdf.SetLineWidth(thicknessMM)
	y := pdf.GetY()
	pdf.Line(x1, y, x2, y)
	pdf.Ln(thicknessMM + 0.5)
}

// --- Helpers ---------------------------------------------------------------

func setTextColour(pdf *fpdf.Fpdf, c [3]int) {
	pdf.SetTextColor(c[0], c[1], c[2])
}

func setFillColour(pdf *fpdf.Fpdf, c [3]int) {
	pdf.SetFillColor(c[0], c[1], c[2])
}

func filterEvals(in []EvalRow, statuses ...string) []EvalRow {
	out := make([]EvalRow, 0)
	for _, ev := range in {
		for _, s := range statuses {
			if ev.Status == s {
				out = append(out, ev)
				break
			}
		}
	}
	return out
}

func summariseBenchmarks(evals []EvalRow) string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, ev := range evals {
		key := ev.Benchmark + " " + ev.BenchmarkVersion
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return strings.Join(out, ", ")
}

func joinMappings(ev EvalRow) string {
	parts := make([]string, 0, 3)
	if len(ev.NISTMappings) > 0 {
		parts = append(parts, "NIST: "+strings.Join(ev.NISTMappings, ", "))
	}
	if len(ev.ISOMappings) > 0 {
		parts = append(parts, "ISO 27001: "+strings.Join(ev.ISOMappings, ", "))
	}
	if len(ev.CyberEssentialsMappings) > 0 {
		parts = append(parts, "Cyber Essentials: "+strings.Join(ev.CyberEssentialsMappings, ", "))
	}
	return strings.Join(parts, " | ")
}

func fallback(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// afterPipe returns the substring after "|" in "name|version" identifiers,
// or empty if the identifier doesn't carry a version suffix.
func afterPipe(s string) string {
	if i := strings.IndexByte(s, '|'); i >= 0 && i+1 < len(s) {
		return s[i+1:]
	}
	return ""
}

// truncate clips a string to max runes, appending "…" when truncated.
func truncate(s string, max int) string {
	if max <= 1 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}

// sortAppsForReport puts third-party apps (Developer ID Application: …) first
// so auditors see commercial software up top, with Apple-bundled apps at the
// bottom. Within each group, sort by name.
func sortAppsForReport(in []App) []App {
	out := make([]App, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ag := signerGroup(a.Signer)
		bg := signerGroup(b.Signer)
		if ag != bg {
			return ag < bg
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out
}

// signerGroup gives third-party apps a smaller number so they sort earlier.
// 0 = third-party Developer ID, 1 = Apple-bundled (Software Signing, Apple), 2 = unsigned / unknown.
func signerGroup(signer string) int {
	switch {
	case strings.HasPrefix(signer, "Developer ID Application"):
		return 0
	case signer == "Software Signing", strings.HasPrefix(signer, "Apple"):
		return 1
	default:
		return 2
	}
}
