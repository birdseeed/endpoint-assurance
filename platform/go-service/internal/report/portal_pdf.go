// Customer-facing estate security report (PAT-331). This renderer is
// deliberately DISTINCT from the internal/staff layout in report.go and
// executive_pdf.go (PAT-330 decision 5): it carries the current Patched
// brand system (Pivot/Quiet: snow, paper, slate, one signal orange; Archivo
// display, Inter text), leads with plain English, and never carries
// per-user attribution. This document leaves the building.
//
// Rendering only: all data arrives through the existing Fetch* functions
// (portal.go, executive.go, admin.go), which are unchanged.
package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// Brand assets, vendored from the canonical branding kit
// (branding/kit/logo) and the OFL-licensed font upstreams
// (see assets/fonts/OFL-*.txt).
var (
	//go:embed assets/fonts/Inter-Regular.ttf
	prInterRegular []byte
	//go:embed assets/fonts/Inter-Bold.ttf
	prInterBold []byte
	//go:embed assets/fonts/Archivo-SemiBold.ttf
	prArchivoSemiBold []byte
	// Ring mark (app icon variant, slate tile) — the product mark per the
	// brand system's two-marks rule; the pixel-P is marketing-only.
	//go:embed assets/patched-app-icon.png
	prMarkPNG []byte
)

// Palette. Core tokens are lifted from website/styles.css (the brand source
// of truth); rule/hair/uv-wash are the rgba() tokens pre-blended onto snow.
// Severity and status colours match the customer portal palette
// (portal/static/css/portal.css) so the PDF reads like the portal it came from.
var (
	prPaper    = [3]int{245, 245, 243} // --paper #f5f5f3
	prSlate    = [3]int{15, 17, 21}    // --slate #0f1115
	prGraphite = [3]int{42, 45, 51}    // --graphite #2a2d33
	prMute     = [3]int{125, 128, 137} // --mute #7d8089
	prRuleC    = [3]int{226, 226, 227} // --rule rgba(15,17,21,.12) on snow
	prHair     = [3]int{238, 238, 239} // --hair rgba(15,17,21,.07) on snow
	prUV       = [3]int{245, 83, 10}   // --uv #f5530a (signal orange)
	prUVDeep   = [3]int{201, 63, 4}    // --uv-deep #c93f04
	prUVWash   = [3]int{254, 241, 235} // --uv-wash rgba(245,83,10,.08) on snow

	prSevCritical = [3]int{185, 28, 28} // --sev-critical #b91c1c
	prSevHigh     = [3]int{194, 65, 12} // --sev-high #c2410c
	prSevMedium   = [3]int{133, 77, 14} // --sev-medium #854d0e
	prSevLow      = [3]int{71, 85, 105} // --sev-low #475569
	prOK          = [3]int{21, 128, 61} // --ok #15803d
	prOKWash      = [3]int{240, 253, 244}
	prWarn        = [3]int{194, 65, 12} // --warn #c2410c
	prWarnWash    = [3]int{255, 247, 237}
	prBad         = [3]int{185, 28, 28} // --bad #b91c1c
	prBadWash     = [3]int{254, 242, 242}
	prMediumWash  = [3]int{254, 252, 232}
	prLowWash     = [3]int{241, 245, 249}
)

// Geometry. Shares the A4 margins defined in pdf.go (18mm sides, content
// width 174mm) but reserves a deeper bottom band for the branded footer.
const (
	prPageW       = 210.0
	prPageH       = 297.0
	prFooterBand  = 26.0       // auto-page-break trigger from bottom
	prMaxFindings = 40         // table cap; remainder summarised
	prMaxDevices  = 60         // roster cap; remainder summarised
	prFontBody    = "PInter"   // Inter Regular / Bold
	prFontDisplay = "PArchivo" // Archivo SemiBold (headings)
)

// RenderPortalReportPDF renders the customer-facing estate security report
// generated from POST /v1/portal/reports. Cover page, plain-English
// executive summary with a visual CIS score, open vulnerability findings,
// device roster, and a closing explainer. UK English throughout; "estate",
// never "fleet".
//
// includeHardwareHealth gates the Hardware health section at the renderer
// boundary. It was a managed-tier entitlement gate (PAT-686, subscription_tier
// "managed"; was Tier 2+ patch/full_endpoint before PAT-1599 migration 0138
// collapsed the tier vocabulary) provisional pending a product decision.
// PAT-2130 (ruled 24 September 2026): one plan, no report gating — the
// caller (portal.go) now always passes true, so every tenant gets the
// section. The parameter stays so this renderer keeps deciding layout only,
// never entitlement.
func RenderPortalReportPDF(s ExecutiveSummary, ov PortalOverview,
	findings []PortalCVEFinding, devices PortalDevicesResult,
	includeHardwareHealth bool) ([]byte, error) {

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, prFooterBand)
	pdf.SetTitle("Patched | Estate security report", true)
	pdf.SetAuthor("Patched (patched.im)", true)
	pdf.SetCreator("patched-api report renderer", true)

	pdf.AddUTF8FontFromBytes(prFontBody, "", prInterRegular)
	pdf.AddUTF8FontFromBytes(prFontBody, "B", prInterBold)
	pdf.AddUTF8FontFromBytes(prFontDisplay, "", prArchivoSemiBold)

	pdf.RegisterImageOptionsReader("pr-mark",
		fpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(prMarkPNG))

	generated := ov.GeneratedAt
	if generated.IsZero() {
		generated = s.GeneratedAt
	}
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	generated = generated.UTC()

	// Footer on every page: wordmark, provenance line, page numbers.
	// Page numbers use core Helvetica because fpdf's {nb} alias is not
	// substituted inside subsetted UTF-8 font streams.
	pdf.SetFooterFunc(func() {
		y := prPageH - 16.0
		pdf.SetDrawColor(prHair[0], prHair[1], prHair[2])
		pdf.SetLineWidth(0.25)
		pdf.Line(leftMargin, y-1.5, prPageW-rightMargin, y-1.5)

		pdf.SetFont(prFontDisplay, "", 8)
		setTextColour(pdf, prSlate)
		pdf.SetXY(leftMargin, y)
		pdf.CellFormat(20, 4, "Patched", "", 0, "L", false, 0, "")

		pdf.SetFont("Helvetica", "", 7)
		setTextColour(pdf, prMute)
		pdf.SetXY(leftMargin, y)
		pdf.CellFormat(contentWidth, 4,
			"Prepared by Patched  |  patched.im  |  Generated "+
				generated.Format("2 Jan 2006 15:04 MST"),
			"", 0, "C", false, 0, "")
		pdf.SetXY(leftMargin, y)
		pdf.CellFormat(contentWidth, 4,
			fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
	})
	pdf.AliasNbPages("")

	prRenderCover(pdf, s, ov, generated)

	pdf.AddPage()
	prRenderSummary(pdf, s, ov)
	prRenderScore(pdf, ov)
	prRenderSeverity(pdf, ov)
	prRenderPatchPosture(pdf, s, ov)

	prRenderFindings(pdf, findings)
	prRenderCoverageGap(pdf, devices, generated)
	prRenderRoster(pdf, devices)
	if includeHardwareHealth {
		prRenderHardwareHealth(pdf, devices)
	}
	prRenderExplainer(pdf)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write portal report pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// --- Cover -------------------------------------------------------------------

func prRenderCover(pdf *fpdf.Fpdf, s ExecutiveSummary, ov PortalOverview, generated time.Time) {
	pdf.AddPage()

	// Signal-orange band across the top edge: the one loud brand element.
	pdf.SetFillColor(prUV[0], prUV[1], prUV[2])
	pdf.Rect(0, 0, prPageW, 3.0, "F")

	// Brand mark + wordmark, centred in the upper third.
	markW := 20.0
	markH := markW // ring-mark app icon is square (512x512)
	pdf.ImageOptions("pr-mark", (prPageW-markW)/2, 58, markW, 0, false,
		fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	// Wordmark set live in Archivo — the pixel wordmark raster is retired.
	pdf.SetFont(prFontDisplay, "", 26)
	setTextColour(pdf, prSlate)
	pdf.SetXY(0, 58+markH+7)
	pdf.CellFormat(prPageW, 12, "Patched", "", 0, "C", false, 0, "")

	// Accent rule between the marks and the title.
	pdf.SetFillColor(prUV[0], prUV[1], prUV[2])
	pdf.Rect((prPageW-22)/2, 128, 22, 1.4, "F")

	pdf.SetY(138)
	pdf.SetFont(prFontDisplay, "", 27)
	setTextColour(pdf, prSlate)
	pdf.CellFormat(0, 12, "Estate security report", "", 1, "C", false, 0, "")

	pdf.Ln(2)
	pdf.SetFont(prFontBody, "B", 13)
	setTextColour(pdf, prGraphite)
	pdf.CellFormat(0, 7, fallback(prTenantName(s, ov)), "", 1, "C", false, 0, "")

	pdf.Ln(6)
	pdf.SetFont(prFontBody, "", 10)
	setTextColour(pdf, prMute)
	pdf.CellFormat(0, 5.5, "Generated "+generated.Format("2 January 2006"),
		"", 1, "C", false, 0, "")
	from := generated.AddDate(0, 0, -portalTrendDays)
	pdf.CellFormat(0, 5.5,
		"Reporting period "+from.Format("2 January 2006")+" to "+generated.Format("2 January 2006"),
		"", 1, "C", false, 0, "")

	pdf.SetY(252)
	pdf.SetFont(prFontBody, "", 8.5)
	setTextColour(pdf, prMute)
	pdf.MultiCell(0, 4.5,
		"Prepared for "+fallback(prTenantName(s, ov))+" by Patched. "+
			"This report summarises the security posture of your device estate "+
			"as measured by the Patched platform. Confidential.",
		"", "C", false)
}

func prTenantName(s ExecutiveSummary, ov PortalOverview) string {
	if ov.TenantName != "" {
		return ov.TenantName
	}
	return s.Tenant
}

// --- Executive summary ---------------------------------------------------------

func prRenderSummary(pdf *fpdf.Fpdf, s ExecutiveSummary, ov PortalOverview) {
	prSectionHeader(pdf, "Executive summary")

	pdf.SetFont(prFontBody, "", 10)
	setTextColour(pdf, prGraphite)
	for _, para := range portalPlainEnglishSummary(s, ov) {
		pdf.MultiCell(0, 5.2, para, "", "L", false)
		pdf.Ln(1.5)
	}
	pdf.Ln(1)

	// Estate-at-a-glance stat band.
	stats := []struct{ value, label string }{
		{fmt.Sprintf("%d", ov.DevicesTotal), "Devices in estate"},
		{fmt.Sprintf("%d", ov.DevicesReporting24h), "Reporting (24 hours)"},
		{fmt.Sprintf("%.0f%%", ov.CISScoreCurrent), "CIS Level 1 score"},
		{fmt.Sprintf("%d", ov.FindingsOpen.Critical+ov.FindingsOpen.High+
			ov.FindingsOpen.Medium+ov.FindingsOpen.Low), "Open findings"},
	}
	const gap = 4.0
	boxW := (contentWidth - gap*3) / 4
	boxH := 20.0
	x := leftMargin
	y := pdf.GetY()
	for _, st := range stats {
		pdf.SetFillColor(prPaper[0], prPaper[1], prPaper[2])
		pdf.SetDrawColor(prRuleC[0], prRuleC[1], prRuleC[2])
		pdf.SetLineWidth(0.25)
		pdf.RoundedRect(x, y, boxW, boxH, 1.5, "1234", "FD")

		pdf.SetXY(x, y+3.5)
		pdf.SetFont(prFontDisplay, "", 16)
		setTextColour(pdf, prSlate)
		pdf.CellFormat(boxW, 8, st.value, "", 0, "C", false, 0, "")

		pdf.SetXY(x, y+12.5)
		pdf.SetFont(prFontBody, "", 6.8)
		setTextColour(pdf, prMute)
		pdf.CellFormat(boxW, 4, strings.ToUpper(st.label), "", 0, "C", false, 0, "")

		x += boxW + gap
	}
	pdf.SetY(y + boxH + 7)
}

// prRenderScore draws the CIS Level 1 score element: large number plus a
// banded progress bar with the 80% "good practice" marker.
func prRenderScore(pdf *fpdf.Fpdf, ov PortalOverview) {
	prSubHeader(pdf, "CIS Level 1 benchmark")

	score := ov.CISScoreCurrent
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	col, _ := prScoreBand(score)

	y := pdf.GetY()
	pdf.SetFont(prFontDisplay, "", 30)
	setTextColour(pdf, col)
	pdf.SetXY(leftMargin, y)
	pdf.CellFormat(34, 13, fmt.Sprintf("%.0f", score), "", 0, "L", false, 0, "")
	pdf.SetFont(prFontBody, "", 8)
	setTextColour(pdf, prMute)
	pdf.SetXY(leftMargin, y+13.5)
	pdf.CellFormat(34, 4, "OUT OF 100", "", 0, "L", false, 0, "")

	// Bar: hair track, banded fill, slate marker at the 80 target.
	barX, barW, barH := leftMargin+40, contentWidth-40, 6.0
	barY := y + 5.0
	pdf.SetFillColor(prHair[0], prHair[1], prHair[2])
	pdf.SetDrawColor(prRuleC[0], prRuleC[1], prRuleC[2])
	pdf.SetLineWidth(0.25)
	pdf.RoundedRect(barX, barY, barW, barH, barH/2, "1234", "FD")
	if score > 0 {
		fillW := barW * score / 100
		if fillW < barH {
			fillW = barH // keep the rounded cap legible at tiny scores
		}
		pdf.SetFillColor(col[0], col[1], col[2])
		pdf.RoundedRect(barX, barY, fillW, barH, barH/2, "1234", "F")
	}
	tickX := barX + barW*0.8
	pdf.SetDrawColor(prSlate[0], prSlate[1], prSlate[2])
	pdf.SetLineWidth(0.35)
	pdf.Line(tickX, barY-1.2, tickX, barY+barH+1.2)
	pdf.SetFont(prFontBody, "", 6.8)
	setTextColour(pdf, prMute)
	pdf.SetXY(tickX-15, barY+barH+2.0)
	pdf.CellFormat(30, 3.5, "80 TARGET", "", 0, "C", false, 0, "")

	pdf.SetY(y + 20)
}

// prRenderSeverity draws the open-findings-by-severity pill row.
func prRenderSeverity(pdf *fpdf.Fpdf, ov PortalOverview) {
	prSubHeader(pdf, "Open findings by severity")

	pills := []struct {
		count     int
		label     string
		col, wash [3]int
	}{
		{ov.FindingsOpen.Critical, "Critical", prSevCritical, prBadWash},
		{ov.FindingsOpen.High, "High", prSevHigh, prWarnWash},
		{ov.FindingsOpen.Medium, "Medium", prSevMedium, prMediumWash},
		{ov.FindingsOpen.Low, "Low", prSevLow, prLowWash},
	}
	const gap = 4.0
	pillW := (contentWidth - gap*3) / 4
	pillH := 11.0
	x := leftMargin
	y := pdf.GetY()
	for _, p := range pills {
		pdf.SetFillColor(p.wash[0], p.wash[1], p.wash[2])
		pdf.SetDrawColor(prRuleC[0], prRuleC[1], prRuleC[2])
		pdf.SetLineWidth(0.25)
		pdf.RoundedRect(x, y, pillW, pillH, pillH/2, "1234", "FD")

		pdf.SetFillColor(p.col[0], p.col[1], p.col[2])
		pdf.Circle(x+7.0, y+pillH/2, 1.5, "F")

		pdf.SetXY(x+10.5, y)
		pdf.SetFont(prFontBody, "B", 10)
		setTextColour(pdf, p.col)
		pdf.CellFormat(12, pillH, fmt.Sprintf("%d", p.count), "", 0, "L", false, 0, "")
		pdf.SetFont(prFontBody, "", 8.5)
		pdf.CellFormat(pillW-22.5, pillH, p.label, "", 0, "L", false, 0, "")

		x += pillW + gap
	}
	pdf.SetY(y + pillH + 7)
}

// prRenderPatchPosture draws the patch stacked bar + legend.
func prRenderPatchPosture(pdf *fpdf.Fpdf, s ExecutiveSummary, ov PortalOverview) {
	prSubHeader(pdf, "Patch posture")

	total := ov.PatchStatus.UpToDate + ov.PatchStatus.Pending + ov.PatchStatus.Failed + ov.PatchStatus.Unknown
	y := pdf.GetY()
	barH := 6.0
	if total > 0 {
		x := leftMargin
		segs := []struct {
			n   int
			col [3]int
		}{
			{ov.PatchStatus.UpToDate, prOK},
			{ov.PatchStatus.Pending, prWarn},
			{ov.PatchStatus.Failed, prBad},
			// PAT-1805: devices with no reported update state (e.g. every
			// Windows device today) get their own neutral segment rather
			// than being folded into the "up to date" (green) portion.
			{ov.PatchStatus.Unknown, prMute},
		}
		for _, seg := range segs {
			if seg.n == 0 {
				continue
			}
			w := contentWidth * float64(seg.n) / float64(total)
			pdf.SetFillColor(seg.col[0], seg.col[1], seg.col[2])
			pdf.Rect(x, y, w, barH, "F")
			x += w
		}
	} else {
		pdf.SetFillColor(prHair[0], prHair[1], prHair[2])
		pdf.Rect(leftMargin, y, contentWidth, barH, "F")
	}

	pdf.SetY(y + barH + 2.5)
	pdf.SetFont(prFontBody, "", 8.5)
	setTextColour(pdf, prGraphite)
	legend := fmt.Sprintf("%d up to date   |   %d with updates pending   |   %d failed   |   %d not reported",
		ov.PatchStatus.UpToDate, ov.PatchStatus.Pending, ov.PatchStatus.Failed, ov.PatchStatus.Unknown)
	if s.Patching.MedianDaysSinceLastPatch >= 0 {
		legend += fmt.Sprintf("   |   median %d days since last patch",
			s.Patching.MedianDaysSinceLastPatch)
	}
	pdf.CellFormat(0, 5, legend, "", 1, "L", false, 0, "")
	pdf.Ln(4)
}

// --- Findings table ------------------------------------------------------------

func prRenderFindings(pdf *fpdf.Fpdf, findings []PortalCVEFinding) {
	prEnsureSpace(pdf, 40)
	prSectionHeader(pdf, "Open vulnerability findings")

	if len(findings) == 0 {
		pdf.SetFont(prFontBody, "", 10)
		setTextColour(pdf, prGraphite)
		pdf.MultiCell(0, 5.2,
			"No open vulnerability findings were recorded against applications "+
				"in your estate during this reporting period.",
			"", "L", false)
		pdf.Ln(4)
		return
	}

	cols := []prCol{
		{w: 32, label: "CVE"},
		{w: 20, label: "Severity"},
		{w: 56, label: "Application"},
		{w: 26, label: "Devices affected", align: "C"},
		{w: 40, label: "First seen"},
	}
	prTableHeader(pdf, cols)

	shown := findings
	if len(shown) > prMaxFindings {
		shown = shown[:prMaxFindings]
	}
	for i, f := range shown {
		prTableRowStart(pdf, cols, i)
		app := f.App
		if f.Version != "" {
			app += " " + f.Version
		}
		sevLabel, sevCol := prSeverityStyle(f.Severity)

		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, prSlate)
		prCell(pdf, cols[0], f.CVEID)
		pdf.SetFont(prFontBody, "B", 8)
		setTextColour(pdf, sevCol)
		prCell(pdf, cols[1], sevLabel)
		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, prGraphite)
		prCell(pdf, cols[2], app)
		prCell(pdf, cols[3], fmt.Sprintf("%d", f.DevicesAffected))
		prCell(pdf, cols[4], f.FirstSeen.UTC().Format("2 Jan 2006"))
		pdf.Ln(-1)
	}
	if rest := len(findings) - len(shown); rest > 0 {
		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, prMute)
		pdf.CellFormat(0, 6,
			fmt.Sprintf("Plus %d further finding%s, available in the portal.", rest, plural(rest)),
			"", 1, "L", false, 0, "")
	}
	prRenderExploitationEvidence(pdf, shown)
	pdf.Ln(4)
}

func prRenderExploitationEvidence(pdf *fpdf.Fpdf, findings []PortalCVEFinding) {
	prEnsureSpace(pdf, 28)
	prSubHeader(pdf, "Exploitation evidence")
	pdf.SetFont(prFontBody, "", 8)
	setTextColour(pdf, prMute)
	pdf.MultiCell(0, 4.4,
		"Known exploited is set only by fresh CISA KEV or SOFA evidence. Severity and CVSS do not set this status. Unknown means authoritative evidence was unavailable, failed or stale.",
		"", "L", false)
	pdf.Ln(2)

	cols := []prCol{
		{w: 31, label: "CVE"},
		{w: 30, label: "Status"},
		{w: 25, label: "Source"},
		{w: 36, label: "Fetched"},
		{w: 52, label: "Match basis / availability"},
	}
	prTableHeader(pdf, cols)
	seen := map[string]bool{}
	row := 0
	for _, finding := range findings {
		if seen[finding.CVEID] {
			continue
		}
		seen[finding.CVEID] = true
		prTableRowStart(pdf, cols, row)
		row++
		sources, fetched, _, _ := exploitationProvenanceColumns(finding.Exploitation)
		basis := exploitationDisplayBasis(finding.Exploitation)
		if exploitationStatusLabel(finding.Exploitation) == "Unknown" {
			sources = "Unavailable"
		}
		pdf.SetFont(prFontBody, "", 7.3)
		setTextColour(pdf, prGraphite)
		prCell(pdf, cols[0], finding.CVEID)
		prCell(pdf, cols[1], exploitationStatusLabel(finding.Exploitation))
		prCell(pdf, cols[2], truncate(sources, 17))
		prCell(pdf, cols[3], truncate(fetched, 22))
		prCell(pdf, cols[4], truncate(basis, 36))
		pdf.Ln(-1)
	}
}

// --- Devices not reporting ---------------------------------------------------------

// prStaleAfter is the reporting-coverage window: a device whose last report
// is older than this is treated as an estate-coverage gap.
const prStaleAfter = 7 * 24 * time.Hour

// prRenderCoverageGap lists devices that have not reported within the last
// seven days. Presented in plain English as a coverage gap: an unmeasured
// device is invisible to every other number in this report.
//
// PAT-2135: a device the customer has retired is not a coverage gap. It is
// left out of the list and counted in one sentence of its own.
func prRenderCoverageGap(pdf *fpdf.Fpdf, devices PortalDevicesResult, generated time.Time) {
	var stale []PortalDeviceRow
	retired := 0
	for _, d := range devices.Devices {
		if d.Retirement != nil {
			retired++
			continue
		}
		if d.LastSeen.IsZero() || generated.Sub(d.LastSeen) > prStaleAfter {
			stale = append(stale, d)
		}
	}
	retiredNote := ""
	if retired > 0 {
		retiredNote = fmt.Sprintf(" %d retired device%s, retired by your organisation, %s not counted here.",
			retired, plural(retired), isAre(retired))
	}

	prEnsureSpace(pdf, 40)
	prSectionHeader(pdf, "Devices not reporting")

	pdf.SetFont(prFontBody, "", 10)
	setTextColour(pdf, prGraphite)
	if len(stale) == 0 {
		everyDevice := "Every device in your estate has reported within the last 7 days, " +
			"so the figures in this report cover your whole estate."
		if retired > 0 {
			everyDevice = "Every device in your estate that has not been retired has reported within the last 7 days." + retiredNote
		}
		pdf.MultiCell(0, 5.2, everyDevice, "", "L", false)
		pdf.Ln(4)
		return
	}
	pdf.MultiCell(0, 5.2, fmt.Sprintf(
		"%d of %d device%s ha%s not reported in the last 7 days. A device that is not "+
			"reporting is not being measured, so the scores and findings in this report "+
			"do not cover it. The usual causes are a device that is switched off, away "+
			"from the network, or has had the Patched agent removed.%s",
		len(stale), devices.Total, plural(len(stale)), hasHave(len(stale)), retiredNote),
		"", "L", false)
	pdf.Ln(2)

	cols := []prCol{
		{w: 62, label: "Device"},
		{w: 42, label: "Platform"},
		{w: 40, label: "Last seen"},
		{w: 30, label: "Days since", align: "C"},
	}
	prTableHeader(pdf, cols)
	for i, d := range stale {
		prTableRowStart(pdf, cols, i)
		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, prSlate)
		prCell(pdf, cols[0], fallback(d.Hostname))
		setTextColour(pdf, prGraphite)
		prCell(pdf, cols[1], fallback(strings.TrimSpace(d.OS+" "+d.OSVersion)))
		if d.LastSeen.IsZero() {
			setTextColour(pdf, prBad)
			prCell(pdf, cols[2], "Never reported")
			prCell(pdf, cols[3], "n/a")
		} else {
			days := int(generated.Sub(d.LastSeen).Hours() / 24)
			setTextColour(pdf, prWarn)
			prCell(pdf, cols[2], d.LastSeen.UTC().Format("2 Jan 2006"))
			prCell(pdf, cols[3], fmt.Sprintf("%d", days))
		}
		pdf.Ln(-1)
	}
	pdf.Ln(4)
}

// --- Device roster ---------------------------------------------------------------

func prRenderRoster(pdf *fpdf.Fpdf, devices PortalDevicesResult) {
	prEnsureSpace(pdf, 40)
	prSectionHeader(pdf, "Device roster")

	if len(devices.Devices) == 0 {
		pdf.SetFont(prFontBody, "", 10)
		setTextColour(pdf, prGraphite)
		pdf.MultiCell(0, 5.2, "No devices are enrolled in your estate yet.", "", "L", false)
		pdf.Ln(4)
		return
	}

	cols := []prCol{
		{w: 46, label: "Device"},
		{w: 36, label: "Operating system"},
		{w: 18, label: "Score", align: "C"},
		{w: 27, label: "Encryption"},
		{w: 27, label: "Patch status"},
		{w: 20, label: "Last seen"},
	}
	prTableHeader(pdf, cols)

	shown := devices.Devices
	if len(shown) > prMaxDevices {
		shown = shown[:prMaxDevices]
	}
	for i, d := range shown {
		prTableRowStart(pdf, cols, i)

		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, prSlate)
		name := fallback(d.Hostname)
		if d.Retirement != nil {
			name += " (retired)"
		}
		prCell(pdf, cols[0], name)
		setTextColour(pdf, prGraphite)
		os := strings.TrimSpace(d.OS + " " + d.OSVersion)
		prCell(pdf, cols[1], fallback(os))

		scoreCol, _ := prScoreBand(d.CompliancePct)
		pdf.SetFont(prFontBody, "B", 8)
		setTextColour(pdf, scoreCol)
		prCell(pdf, cols[2], fmt.Sprintf("%.0f%%", d.CompliancePct))

		encLabel, encCol := "Not assessed", prMute
		if d.EncryptionOK != nil {
			if *d.EncryptionOK {
				encLabel, encCol = "Encrypted", prOK
			} else {
				encLabel, encCol = "Not encrypted", prBad
			}
		}
		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, encCol)
		prCell(pdf, cols[3], encLabel)

		patchLabel, patchCol := "Up to date", prOK
		switch {
		case d.PatchPending == nil:
			// PAT-1805: no collector has reported an update state for this
			// device (every Windows device today) — honest "not reported",
			// never rendered as "Up to date".
			patchLabel, patchCol = "Not reported", prMute
		case *d.PatchPending:
			patchLabel, patchCol = "Updates pending", prWarn
		}
		setTextColour(pdf, patchCol)
		prCell(pdf, cols[4], patchLabel)

		setTextColour(pdf, prMute)
		last := "never"
		if !d.LastSeen.IsZero() {
			last = d.LastSeen.UTC().Format("2 Jan")
		}
		prCell(pdf, cols[5], last)
		pdf.Ln(-1)
	}
	if rest := devices.Total - len(shown); rest > 0 {
		pdf.SetFont(prFontBody, "", 8)
		setTextColour(pdf, prMute)
		pdf.CellFormat(0, 6,
			fmt.Sprintf("Plus %d further device%s, available in the portal.", rest, plural(rest)),
			"", 1, "L", false, 0, "")
	}
	pdf.Ln(4)
}

// --- Hardware health (PAT-686, Tier 2+ only) --------------------------------

// prRenderHardwareHealth summarises the estate's hardware-health digest
// (battery, SMART, free disk — thresholds enforced server-side, see
// TenantDeviceRow.HardwareFlag) as a short narrative rather than a table,
// matching the plain-English register of the rest of this report. Devices
// that have never reported hardware telemetry are excluded from both the
// total and the flagged count (same convention as the dashboard's per-device
// badge: no data means no signal, not a clean bill of health).
func prRenderHardwareHealth(pdf *fpdf.Fpdf, devices PortalDevicesResult) {
	var total int
	var flagged []PortalDeviceRow
	for _, d := range devices.Devices {
		if !d.HasHardware {
			continue
		}
		total++
		if d.HardwareFlag() {
			flagged = append(flagged, d)
		}
	}

	prEnsureSpace(pdf, 40)
	prSectionHeader(pdf, fmt.Sprintf("Hardware health: %d device%s", total, plural(total)))

	pdf.SetFont(prFontBody, "", 10)
	setTextColour(pdf, prGraphite)

	if total == 0 {
		pdf.MultiCell(0, 5.2,
			"No hardware telemetry (battery health, disk health, storage capacity) has been reported for this estate yet.",
			"", "L", false)
		pdf.Ln(4)
		return
	}

	if len(flagged) > 0 {
		prEnsureSpace(pdf, 8+6*float64(len(flagged)))
		setTextColour(pdf, prWarn)
		pdf.SetFont(prFontBody, "B", 10)
		pdf.CellFormat(0, 6, fmt.Sprintf("%d device%s flagged:", len(flagged), plural(len(flagged))),
			"", 1, "L", false, 0, "")
		pdf.SetFont(prFontBody, "", 9)
		for _, d := range flagged {
			reason := d.hardwareIssueSummary()
			if reason == "" {
				continue // degrade quietly rather than print a blank bullet
			}
			setTextColour(pdf, prGraphite)
			pdf.MultiCell(0, 5, "-  "+fallback(d.Hostname)+": "+reason, "", "L", false)
		}
		pdf.Ln(2)
	}

	normal := total - len(flagged)
	setTextColour(pdf, prOK)
	pdf.SetFont(prFontBody, "B", 10)
	pdf.CellFormat(0, 6, fmt.Sprintf("%d device%s within normal parameters", normal, plural(normal)),
		"", 1, "L", false, 0, "")
	pdf.Ln(4)
}

// --- Explainer -------------------------------------------------------------------

func prRenderExplainer(pdf *fpdf.Fpdf) {
	prEnsureSpace(pdf, 70)
	prSectionHeader(pdf, "What these numbers mean")

	items := []struct{ term, text string }{
		{"CIS Level 1 score",
			"The percentage of security controls from the CIS Level 1 benchmark that your " +
				"devices currently pass. CIS Level 1 is a widely adopted, independently maintained " +
				"baseline of essential security settings. A score of 80 or above is generally " +
				"considered good practice for a small or medium-sized estate."},
		{"Severity levels",
			"Findings are graded critical, high, medium or low. Critical and high findings " +
				"describe weaknesses that are practical for an attacker to exploit and should be " +
				"remediated promptly. Medium and low findings belong on the routine maintenance list."},
		{"Patch posture",
			"A device is up to date when its operating system has no updates waiting to install. " +
				"Pending updates are normal for short periods; devices that stay pending for weeks " +
				"are the ones to chase."},
		{"How this data is collected",
			"The Patched agent on each enrolled device reports its configuration to the Patched " +
				"platform, where it is evaluated against the benchmark. Figures reflect the most " +
				"recent report from each device at the time this document was generated. " +
				"This report contains no personal data about the people using the devices."},
	}
	for _, it := range items {
		prEnsureSpace(pdf, 22)
		pdf.SetFont(prFontBody, "B", 9.5)
		setTextColour(pdf, prSlate)
		pdf.CellFormat(0, 5.5, it.term, "", 1, "L", false, 0, "")
		pdf.SetFont(prFontBody, "", 9)
		setTextColour(pdf, prGraphite)
		pdf.MultiCell(0, 4.8, it.text, "", "L", false)
		pdf.Ln(2.5)
	}

	pdf.Ln(1)
	pdf.SetFillColor(prUVWash[0], prUVWash[1], prUVWash[2])
	pdf.SetDrawColor(prUVDeep[0], prUVDeep[1], prUVDeep[2])
	y := pdf.GetY()
	pdf.SetLineWidth(0.3)
	pdf.RoundedRect(leftMargin, y, contentWidth, 16, 1.5, "1234", "F")
	pdf.SetFillColor(prUV[0], prUV[1], prUV[2])
	pdf.Rect(leftMargin, y, 1.4, 16, "F")
	pdf.SetXY(leftMargin+5, y+3)
	pdf.SetFont(prFontBody, "", 9)
	setTextColour(pdf, prGraphite)
	pdf.MultiCell(contentWidth-10, 5,
		"Questions about anything in this report? Contact your Patched representative "+
			"or visit patched.im. We are happy to walk through any finding and its remediation.",
		"", "L", false)
	pdf.SetY(y + 16 + 4)
}

// --- Plain-English summary (pure, tested) -----------------------------------------

// portalPlainEnglishSummary derives the executive-summary paragraphs from the
// aggregates. Deterministic and rule-based; kept pure for tests. UK English,
// customer-facing: "estate", never "fleet"; no em dashes.
func portalPlainEnglishSummary(s ExecutiveSummary, ov PortalOverview) []string {
	var out []string

	out = append(out, fmt.Sprintf(
		"Patched is monitoring %d device%s in your estate; %d reported in within the last 24 hours. "+
			"Your estate scores %.0f%% against the CIS Level 1 security baseline.",
		ov.DevicesTotal, plural(ov.DevicesTotal), ov.DevicesReporting24h, ov.CISScoreCurrent))

	// PAT-2135: retired devices are the customer's decision, so the report
	// names them as retired rather than letting a quiet one read as missing.
	if ov.DevicesRetired > 0 {
		out = append(out, fmt.Sprintf(
			"%d of these device%s ha%s been retired by your organisation and %s not treated as missing.",
			ov.DevicesRetired, plural(ov.DevicesRetired), hasHave(ov.DevicesRetired), isAre(ov.DevicesRetired)))
	}

	urgent := ov.FindingsOpen.Critical + ov.FindingsOpen.High
	routine := ov.FindingsOpen.Medium + ov.FindingsOpen.Low
	switch {
	case urgent == 0 && routine == 0:
		out = append(out, "There are no open security findings across your estate. "+
			"Nothing needs your attention right now.")
	case urgent == 0:
		out = append(out, fmt.Sprintf(
			"There are no critical or high-severity findings open. %d lower-severity item%s remain%s on the routine remediation list.",
			routine, plural(routine), singularVerb(routine)))
	default:
		out = append(out, fmt.Sprintf(
			"%d finding%s need%s prompt attention (%d critical, %d high). "+
				"The findings table in this report lists them in priority order.",
			urgent, plural(urgent), singularVerb(urgent),
			ov.FindingsOpen.Critical, ov.FindingsOpen.High))
	}

	// PAT-1805: Unknown (no collector has reported an update state - every
	// Windows device today) must never be silently absorbed into "up to
	// date" or dropped from the summary - both branches below name it
	// explicitly whenever it is nonzero.
	switch {
	case ov.PatchStatus.Pending > 0 && ov.PatchStatus.Unknown > 0:
		out = append(out, fmt.Sprintf(
			"%d device%s ha%s operating-system updates waiting to be installed; %d %s fully up to date; "+
				"update status could not be determined for %d device%s.",
			ov.PatchStatus.Pending, plural(ov.PatchStatus.Pending), hasHave(ov.PatchStatus.Pending),
			ov.PatchStatus.UpToDate, isAre(ov.PatchStatus.UpToDate),
			ov.PatchStatus.Unknown, plural(ov.PatchStatus.Unknown)))
	case ov.PatchStatus.Pending > 0:
		out = append(out, fmt.Sprintf(
			"%d device%s ha%s operating-system updates waiting to be installed; %d %s fully up to date.",
			ov.PatchStatus.Pending, plural(ov.PatchStatus.Pending), hasHave(ov.PatchStatus.Pending),
			ov.PatchStatus.UpToDate, isAre(ov.PatchStatus.UpToDate)))
	case ov.PatchStatus.Unknown > 0:
		out = append(out, fmt.Sprintf(
			"Update status could not be determined for %d device%s; %d %s confirmed up to date.",
			ov.PatchStatus.Unknown, plural(ov.PatchStatus.Unknown),
			ov.PatchStatus.UpToDate, isAre(ov.PatchStatus.UpToDate)))
	case ov.DevicesTotal > 0:
		out = append(out, "Every reporting device is up to date on operating-system patches.")
	}

	return out
}

// --- Layout helpers ----------------------------------------------------------------

// prSectionHeader: orange tick, Archivo title, hair rule.
func prSectionHeader(pdf *fpdf.Fpdf, title string) {
	prEnsureSpace(pdf, 24)
	y := pdf.GetY()
	pdf.SetFillColor(prUV[0], prUV[1], prUV[2])
	pdf.Rect(leftMargin, y+1.2, 1.4, 5.4, "F")
	pdf.SetXY(leftMargin+4.5, y)
	pdf.SetFont(prFontDisplay, "", 14)
	setTextColour(pdf, prSlate)
	pdf.CellFormat(0, 8, title, "", 1, "L", false, 0, "")
	pdf.SetDrawColor(prRuleC[0], prRuleC[1], prRuleC[2])
	pdf.SetLineWidth(0.25)
	pdf.Line(leftMargin, pdf.GetY()+1, prPageW-rightMargin, pdf.GetY()+1)
	pdf.Ln(4.5)
}

// prSubHeader: small uppercase Inter Bold label.
func prSubHeader(pdf *fpdf.Fpdf, title string) {
	prEnsureSpace(pdf, 24)
	pdf.SetFont(prFontBody, "B", 8)
	setTextColour(pdf, prMute)
	pdf.CellFormat(0, 5, strings.ToUpper(title), "", 1, "L", false, 0, "")
	pdf.Ln(1)
}

type prCol struct {
	w     float64
	label string
	align string // "" = left
}

func prTableHeader(pdf *fpdf.Fpdf, cols []prCol) {
	pdf.SetFillColor(prPaper[0], prPaper[1], prPaper[2])
	pdf.SetFont(prFontBody, "B", 7)
	setTextColour(pdf, prGraphite)
	for _, c := range cols {
		align := c.align
		if align == "" {
			align = "L"
		}
		pdf.CellFormat(c.w, 7, strings.ToUpper(c.label), "", 0, align, true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetDrawColor(prRuleC[0], prRuleC[1], prRuleC[2])
	pdf.SetLineWidth(0.25)
	pdf.Line(leftMargin, pdf.GetY(), prPageW-rightMargin, pdf.GetY())
}

// prTableRowStart handles the page break (re-drawing the header) and the
// zebra stripe before a row's cells are drawn.
func prTableRowStart(pdf *fpdf.Fpdf, cols []prCol, i int) {
	if pdf.GetY() > prPageH-prFooterBand-10 {
		pdf.AddPage()
		prTableHeader(pdf, cols)
	}
	if i%2 == 1 {
		total := 0.0
		for _, c := range cols {
			total += c.w
		}
		pdf.SetFillColor(prPaper[0], prPaper[1], prPaper[2])
		pdf.Rect(leftMargin, pdf.GetY(), total, 6.5, "F")
	}
}

func prCell(pdf *fpdf.Fpdf, c prCol, text string) {
	align := c.align
	if align == "" {
		align = "L"
	}
	pdf.CellFormat(c.w, 6.5, prTruncate(pdf, text, c.w-2), "", 0, align, false, 0, "")
}

// prTruncate shortens a string to fit a cell width, appending an ellipsis.
func prTruncate(pdf *fpdf.Fpdf, s string, w float64) string {
	if pdf.GetStringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 1 && pdf.GetStringWidth(string(r)+"…") > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// prEnsureSpace starts a new page if fewer than need mm remain above the footer.
func prEnsureSpace(pdf *fpdf.Fpdf, need float64) {
	if pdf.GetY()+need > prPageH-prFooterBand {
		pdf.AddPage()
	}
}

// prScoreBand maps a 0-100 score to the portal status palette.
func prScoreBand(score float64) ([3]int, [3]int) {
	switch {
	case score >= 80:
		return prOK, prOKWash
	case score >= 60:
		return prWarn, prWarnWash
	default:
		return prBad, prBadWash
	}
}

// prSeverityStyle maps a lowercased severity string to its label + colour.
func prSeverityStyle(sev string) (string, [3]int) {
	switch strings.ToLower(sev) {
	case "critical":
		return "Critical", prSevCritical
	case "high":
		return "High", prSevHigh
	case "medium", "moderate":
		return "Medium", prSevMedium
	case "low":
		return "Low", prSevLow
	default:
		return "Unrated", prMute
	}
}

// --- tiny grammar helpers (plain-English summary) ---------------------------

func singularVerb(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

func hasHave(n int) string {
	if n == 1 {
		return "s"
	}
	return "ve"
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
