package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// RenderFreeCVEPDF turns a FreeCVEReport into a printable PDF using the
// patched.im corporate-document style (shared with RenderPDF / RenderExecutiveSummaryPDF).
// The output is deterministic: identical input → identical byte sequence.
//
// Structure (PAT-1205 — Part 2 restructured from a flat per-hit table into a
// ranked remediation plan):
//   - Part 1 — Executive Summary: stat boxes, plain-English narrative, CTA
//   - Part 2 — Technical Findings: methodology, confidence key, Remediation
//     Plan (one ranked action per affected app), Possibly Affected (findings
//     NVD can't confirm a version range for), then Appendix A — Full
//     Findings (the old flat per-hit table, forced onto its own page)
//   - Part 3 — What happens next
func RenderFreeCVEPDF(r FreeCVEReport) ([]byte, error) {
	return renderFreeCVEPDF(r, AudienceStaff)
}

// RenderFreeCVEPDFCustomer renders the same CVE / Vulnerability Exposure
// report for a customer's own portal download (PAT-2264). The only
// difference from RenderFreeCVEPDF is the header: no "Staff report" wording
// and the current in-app brand mark instead of the retired pixel-P baked
// into header.png. Every other section, colour, font and layout is shared.
func RenderFreeCVEPDFCustomer(r FreeCVEReport) ([]byte, error) {
	return renderFreeCVEPDF(r, AudienceCustomer)
}

func renderFreeCVEPDF(r FreeCVEReport, audience ReportAudience) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	// fpdf writes font/font-file/image objects by ranging over internal Go
	// maps (f.fonts, f.fontFiles, f.images); without catalog sort that
	// iteration order — and therefore the resulting object numbering and
	// byte layout — varies run to run even for byte-identical content. Found
	// while adding TestRenderFreeCVEPDF_Determinism (PAT-1205): the "same
	// input → byte-for-byte output" guarantee in docs/FREE_CVE_REPORT.md did
	// not actually hold before this. SetCatalogSort(true) makes fpdf sort
	// those keys before emitting them, which is what makes the guarantee
	// true rather than aspirational.
	pdf.SetCatalogSort(true)
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	pdf.SetTitle("patched.im: Free CVE Vulnerability Assessment", true)
	pdf.SetAuthor("patched.im", true)
	pdf.SetCreator("patched-api report renderer", true)
	registerReportFont(pdf)
	// Pin the PDF's /CreationDate and /ModDate to the input's GeneratedAt.
	// fpdf defaults both to time.Now() when unset, which would also break
	// the determinism guarantee ("no wall-clock timestamps beyond the
	// GeneratedAt field passed in").
	pdf.SetCreationDate(r.GeneratedAt)
	pdf.SetModificationDate(r.GeneratedAt)

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
		pdf.CellFormat(0, 6, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()),
			"", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("")

	// Fold the flat findings list into the ranked remediation plan once, up
	// front — Part 1's headline sentence and Part 2's plan/appendix all read
	// from the same actions/unverified slices, so the numbers can't drift.
	actions, unverified := BuildCVEActions(r)

	pdf.AddPage()

	// ── Part 1: Executive Summary ────────────────────────────────────────────
	renderCVEHeader(pdf, r, audience)
	renderCVEStatBoxes(pdf, r)
	renderCVENarrative(pdf, r, actions)
	renderCVECallToAction(pdf)

	// ── Part 2: Technical Findings ───────────────────────────────────────────
	pdf.AddPage()
	renderCVETechnicalHeader(pdf, r)
	renderCVEMethodology(pdf)
	renderCVEConfidenceKey(pdf)
	renderCVEExploitationEvidence(pdf, r)
	renderCVERemediationPlan(pdf, r, actions)
	renderCVEUnverified(pdf, unverified)
	renderCVEFootnote(pdf)
	renderCVECloser(pdf, r)

	pdf.AddPage()
	renderCVEAppendix(pdf, r)

	// ── Part 3: What happens next ────────────────────────────────────────────
	pdf.AddPage()
	renderCVEWhatHappensNext(pdf)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("write pdf: %w", err)
	}
	return buf.Bytes(), nil
}

// renderCVEExploitationEvidence makes every active-exploitation result
// auditable. Unknown is rendered explicitly when the authoritative catalogue
// is missing, failed or stale; severity never substitutes for source evidence.
func renderCVEExploitationEvidence(pdf *fpdf.Fpdf, r FreeCVEReport) {
	sectionHeader(pdf, "Exploitation evidence")
	pdf.SetFont(reportFont, "", 8.5)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4.5,
		"Active exploitation is assessed only from fresh CISA KEV or SOFA evidence. Severity and CVSS do not set this status. Unknown means authoritative evidence was unavailable, failed or stale.",
		"", "L", false)
	pdf.Ln(2)
	if len(r.CVEs) == 0 {
		pdf.CellFormat(0, 5, "No CVEs to assess.", "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	widths := []float64{28, 29, 24, 35, 58}
	tableHeader(pdf, []string{"CVE ID", "Status", "Source", "Fetched", "Match basis / availability"}, widths)
	for i, cve := range r.CVEs {
		if i%2 == 1 {
			setFillColour(pdf, colourRowAlt)
		} else {
			setFillColour(pdf, [3]int{255, 255, 255})
		}
		sources, fetched, _, _ := exploitationProvenanceColumns(cve.Exploitation)
		basis := exploitationDisplayBasis(cve.Exploitation)
		if exploitationStatusLabel(cve.Exploitation) == "Unknown" {
			sources = "Unavailable"
		}
		pdf.SetFont(reportFont, "", 7.5)
		setTextColour(pdf, colourBodyText)
		pdf.CellFormat(widths[0], 4.8, " "+cve.CVEID, "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[1], 4.8, " "+exploitationStatusLabel(cve.Exploitation), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[2], 4.8, " "+truncate(sources, 17), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[3], 4.8, " "+truncate(fetched, 22), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[4], 4.8, " "+truncate(basis, 40), "", 0, "L", true, 0, "")
		pdf.Ln(-1)
	}
	pdf.Ln(4)
}

// --- Part 1 renderers -------------------------------------------------------

func renderCVEHeader(pdf *fpdf.Fpdf, r FreeCVEReport, audience ReportAudience) {
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
	pdf.CellFormat(0, 10, "Free CVE Vulnerability Assessment", "", 1, "C", false, 0, "")

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
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, "Prepared by Patched.im  |  patched.im", "", 1, "C", false, 0, "")

	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(6)
}

// renderCVEStatBoxes draws four coloured severity count boxes side by side.
func renderCVEStatBoxes(pdf *fpdf.Fpdf, r FreeCVEReport) {
	// Colours chosen to be legible when printed: dark fills with white text.
	type band struct {
		label string
		count int
		fill  [3]int
	}
	bands := []band{
		{"CRITICAL", r.CriticalCount, [3]int{185, 28, 28}},
		{"HIGH", r.HighCount, [3]int{194, 65, 12}},
		{"MEDIUM", r.MediumCount, [3]int{161, 98, 7}},
		{"LOW", r.LowCount, [3]int{21, 128, 61}},
	}

	boxW := contentWidth / 4 // 43.5mm per box

	// Row 1 — large count number.
	for _, b := range bands {
		setFillColour(pdf, b.fill)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont(reportFont, "B", 22)
		pdf.CellFormat(boxW, 14, fmt.Sprintf("%d", b.count), "", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Row 2 — severity label.
	for _, b := range bands {
		setFillColour(pdf, b.fill)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont(reportFont, "B", 8)
		pdf.CellFormat(boxW, 7, b.label, "", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.Ln(6)
}

// remediationCoveragePct returns the percentage of total (confirmed +
// unverified) findings that the confirmed remediation plan resolves:
// r.ConfirmedHits / (r.ConfirmedHits + r.UnverifiedHits) * 100. Every
// confirmed hit belongs to exactly one CVEAction (grouped by app), so this
// is equivalently "percentage of hits covered by the actions in the
// Remediation Plan section". Returns 0 when there are no hits of either
// kind. Shared by the Part 1 headline sentence and the Part 2 plan heading
// so the two numbers can never drift apart.
func remediationCoveragePct(r FreeCVEReport) int {
	total := r.ConfirmedHits + r.UnverifiedHits
	if total == 0 {
		return 0
	}
	return int(float64(r.ConfirmedHits) / float64(total) * 100)
}

// renderCVENarrative writes a plain-English paragraph summarising the findings.
func renderCVENarrative(pdf *fpdf.Fpdf, r FreeCVEReport, actions []CVEAction) {
	// Count unique affected devices.
	deviceSet := map[string]struct{}{}
	for _, cve := range r.CVEs {
		for _, h := range cve.Hits {
			if h.Hostname != "" {
				deviceSet[h.Hostname] = struct{}{}
			}
		}
	}
	deviceCount := len(deviceSet)

	var para string
	if r.TotalCVEs == 0 {
		para = "No CVE findings were identified in this estate based on the submitted application inventory. " +
			"This may reflect a clean posture, limited application data in the upload, or gaps in the current CVE-to-application mapping. " +
			"Patched.im recommends running a full agent-based scan for a comprehensive picture."
	} else {
		sevPhrase := buildSevPhrase(r)
		devicePhrase := fmt.Sprintf("%d device%s", deviceCount, plural(deviceCount))

		confirmedPhrase := ""
		if r.ConfirmedHits > 0 {
			confirmedPhrase = fmt.Sprintf(
				" %d of these %s version-confirmed matches, meaning the installed software falls within "+
					"a known vulnerable release range according to NVD data.",
				r.ConfirmedHits, plural2(r.ConfirmedHits, "is a", "are"),
			)
		}

		para = fmt.Sprintf(
			"Scanning the submitted inventory across %s, we identified %d CVE%s affecting this estate. "+
				"%s%s",
			devicePhrase,
			r.TotalCVEs, plural(r.TotalCVEs),
			sevPhrase,
			confirmedPhrase,
		)

		if len(actions) > 0 {
			para += fmt.Sprintf(
				" A ranked remediation plan of %d action%s, one per affected application, clears %d%% of all findings; see the Remediation Plan in the Technical Findings section.",
				len(actions), plural(len(actions)), remediationCoveragePct(r),
			)
		}
	}

	sectionHeader(pdf, "Executive Summary")
	pdf.SetFont(reportFont, "", 9.5)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 5, para, "", "L", false)
	pdf.Ln(4)

	if r.TotalCVEs > 0 {
		// Second paragraph — product pitch.
		pitch := "Patched.im continuously monitors your estate for new vulnerabilities, prioritises remediation " +
			"by risk, and gives your IT team a clear action plan, so issues like these get resolved, not overlooked. " +
			"The technical breakdown on the following pages shows every finding in detail."
		pdf.SetFont(reportFont, "", 9.5)
		setTextColour(pdf, colourBodyText)
		pdf.MultiCell(0, 5, pitch, "", "L", false)
		pdf.Ln(4)
	}
}

// renderCVECallToAction draws a highlighted box inviting the prospect to book a call.
func renderCVECallToAction(pdf *fpdf.Fpdf) {
	// Light-blue tinted box with a darker border.
	setFillColour(pdf, [3]int{235, 245, 255})
	pdf.SetDrawColor(30, 100, 200)
	pdf.SetLineWidth(0.5)
	pdf.SetTextColor(20, 60, 140)

	// Row 1 — headline.
	pdf.SetFont(reportFont, "B", 11)
	pdf.CellFormat(contentWidth, 8, "Want to close these gaps?", "LRT", 1, "C", true, 0, "")

	// Row 2 — subtext.
	pdf.SetFont(reportFont, "", 9)
	pdf.CellFormat(contentWidth, 7,
		"Book a free 30-minute call with the Patched.im team  →  patched.im/#book",
		"LRB", 1, "C", true, 0, "")

	// Reset draw state.
	pdf.SetDrawColor(colourRule[0], colourRule[1], colourRule[2])
	pdf.SetLineWidth(0.3)
	pdf.Ln(4)
}

// --- Part 2 renderers -------------------------------------------------------

// renderCVETechnicalHeader draws a lightweight heading for the technical section.
func renderCVETechnicalHeader(pdf *fpdf.Fpdf, r FreeCVEReport) {
	pdf.SetFont(reportFont, "B", 14)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 9, "Technical Findings", "", 1, "L", false, 0, "")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, fallback(r.Tenant)+", "+r.GeneratedAt.Format("02 Jan 2006"), "", 1, "L", false, 0, "")
	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(4)
}

func renderCVEMethodology(pdf *fpdf.Fpdf) {
	sectionHeader(pdf, "Methodology")
	pdf.SetFont(reportFont, "", 9)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"CVE records and application matching are refreshed from the NIST National Vulnerability Database (NVD) API 2.0. OS vendor-confirmed findings may also use Microsoft Security Response Center (MSRC) or Apple advisory data. Every non-empty description is labelled with its own source; an empty description has no source. Application-to-CVE matching uses curated CPE product mappings evaluated against endpoint inventory. Findings carry the confidence levels described below; the snapshot date is shown in the report footer.",
		"", "L", false)
	pdf.Ln(3)
}

// cveDescriptionWithSource makes the provenance of a CVE description visible
// wherever the PDF renders it. The database constraint keeps a blank source
// paired with an empty description; tolerate legacy rows defensively rather
// than inventing an attribution for them.
func cveDescriptionWithSource(description, source string) string {
	description = strings.TrimSpace(description)
	if description == "" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "nvd":
		return "NVD: " + description
	case "msrc":
		return "MSRC: " + description
	case "apple":
		return "Apple: " + description
	default:
		return description
	}
}

func renderCVEConfidenceKey(pdf *fpdf.Fpdf) {
	sectionHeader(pdf, "Confidence Levels")
	widths := []float64{38, 136}
	tableHeader(pdf, []string{"Confidence", "Meaning"}, widths)

	setFillColour(pdf, [3]int{255, 255, 255})
	pdf.SetFont(reportFont, "B", 8)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(widths[0], 5.5, " Confirmed", "", 0, "L", true, 0, "")
	pdf.SetFont(reportFont, "", 8)
	pdf.CellFormat(widths[1], 5.5,
		" Installed version falls within a known NVD vulnerable version range. High confidence.",
		"", 0, "L", true, 0, "")
	pdf.Ln(-1)

	setFillColour(pdf, colourRowAlt)
	pdf.SetFont(reportFont, "I", 8)
	pdf.CellFormat(widths[0], 5.5, " Possibly affected", "", 0, "L", true, 0, "")
	pdf.SetFont(reportFont, "", 8)
	pdf.CellFormat(widths[1], 5.5,
		" Product matches a CVE but NVD provides no usable version-range data. Manual verification recommended.",
		"", 0, "L", true, 0, "")
	pdf.Ln(-1)
	pdf.Ln(3)
}

// worstSeverityLabel returns the highest severity band present in cves
// ("CRITICAL" beats "HIGH" beats "MEDIUM" beats "LOW"), or "—" when cves is
// empty or carries no recognised severity.
func worstSeverityLabel(cves []CVERecord) string {
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	best := ""
	bestRank := len(order)
	for _, c := range cves {
		sev := strings.ToUpper(c.Severity)
		if rank, ok := order[sev]; ok && rank < bestRank {
			bestRank = rank
			best = sev
		}
	}
	if best == "" {
		return "—"
	}
	return best
}

// cveConfidenceLabel summarises a confirmed CVERecord's hit confidences for
// the compact per-action table: "Confirmed" if any hit is an NVD
// version_confirmed match (the stronger signal), otherwise
// "Vendor-confirmed" when every hit is version_vendor_confirmed (PAT-409:
// Apple security releases / MSRC). Only meaningful for records already
// filtered to confirmed hits (see BuildCVEActions); an empty Hits slice
// falls back to "Confirmed".
func cveConfidenceLabel(rec CVERecord) string {
	sawVendorConfirmed := false
	for _, h := range rec.Hits {
		if h.MatchConfidence == "version_vendor_confirmed" {
			sawVendorConfirmed = true
			continue
		}
		return "Confirmed"
	}
	if sawVendorConfirmed {
		return "Vendor-confirmed"
	}
	return "Confirmed"
}

// renderCVERemediationPlan renders the ranked "Remediation Plan" section:
// a headline stating how many actions clear what percentage of findings, a
// short numbered summary table, then one detailed block per action.
func renderCVERemediationPlan(pdf *fpdf.Fpdf, r FreeCVEReport, actions []CVEAction) {
	total := r.ConfirmedHits + r.UnverifiedHits
	sectionHeader(pdf, fmt.Sprintf("Remediation Plan: %d action%s clear %d of %d findings (%d%%)",
		len(actions), plural(len(actions)), r.ConfirmedHits, total, remediationCoveragePct(r)))

	if len(actions) == 0 {
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No confirmed findings to remediate.", "", 1, "L", false, 0, "")
		pdf.Ln(3)
		return
	}

	// Summary table columns sum to contentWidth (174mm).
	widths := []float64{72, 22, 18, 32, 30}
	tableHeader(pdf, []string{"Action", "Devices", "CVEs", "Worst severity", "Top CVSS"}, widths)
	for i, a := range actions {
		if i%2 == 1 {
			setFillColour(pdf, colourRowAlt)
		} else {
			setFillColour(pdf, [3]int{255, 255, 255})
		}
		cvss := "—"
		if a.TopCVSS != nil {
			cvss = fmt.Sprintf("%.1f", *a.TopCVSS)
		}
		pdf.SetFont(reportFont, "B", 8)
		setTextColour(pdf, colourBodyText)
		pdf.CellFormat(widths[0], 4.8, " "+truncate(fmt.Sprintf("%d. %s → %s", i+1, a.AppName, actionTargetLabel(a)), 58),
			"", 0, "L", true, 0, "")
		pdf.SetFont(reportFont, "", 8)
		pdf.CellFormat(widths[1], 4.8, " "+fmt.Sprintf("%d", len(a.Devices)), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[2], 4.8, " "+fmt.Sprintf("%d", len(a.CVEs)), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[3], 4.8, " "+worstSeverityLabel(a.CVEs), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[4], 4.8, " "+cvss, "", 0, "L", true, 0, "")
		pdf.Ln(-1)
	}
	pdf.Ln(3)

	for i, a := range actions {
		renderCVEActionBlock(pdf, i+1, a)
	}
}

// actionTargetLabel returns the action's TargetVersion, or "latest vendor
// release" when it is unknown (no confirmed hit under this action carried a
// FixedVersion).
func actionTargetLabel(a CVEAction) string {
	if a.TargetVersion == "" {
		return "latest vendor release"
	}
	return a.TargetVersion
}

// renderCVEActionBlock renders one numbered remediation action: heading,
// stat line, wrapped device list, then a compact per-CVE table.
func renderCVEActionBlock(pdf *fpdf.Fpdf, index int, a CVEAction) {
	pdf.SetFont(reportFont, "B", 11)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 7, fmt.Sprintf("%d. Update %s → %s", index, a.AppName, actionTargetLabel(a)),
		"", 1, "L", false, 0, "")

	cvss := "—"
	if a.TopCVSS != nil {
		cvss = fmt.Sprintf("%.1f", *a.TopCVSS)
	}
	pdf.SetFont(reportFont, "", 8.5)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 5, fmt.Sprintf(
		"%d device%s  |  %d CVE%s (%d critical, %d high, %d medium, %d low)  |  top CVSS %s",
		len(a.Devices), plural(len(a.Devices)),
		len(a.CVEs), plural(len(a.CVEs)),
		a.CriticalCount, a.HighCount, a.MediumCount, a.LowCount,
		cvss,
	), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	devParts := make([]string, len(a.Devices))
	for i, d := range a.Devices {
		devParts[i] = fmt.Sprintf("%s (%s)", d.Hostname, fallback(d.InstalledVersion))
	}
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5, strings.Join(devParts, ", "), "", "L", false)
	pdf.Ln(1)

	// Per-CVE table columns sum to contentWidth (174mm).
	// CVE ID(24) + CVSS(11) + Severity(18) + Description(91) + Confidence(30)
	widths := []float64{24, 11, 18, 91, 30}
	tableHeader(pdf, []string{"CVE ID", "CVSS", "Severity", "Description", "Confidence"}, widths)
	for i, cve := range a.CVEs {
		if i%2 == 1 {
			setFillColour(pdf, colourRowAlt)
		} else {
			setFillColour(pdf, [3]int{255, 255, 255})
		}
		cvssStr := "—"
		if cve.CVSSScore != nil {
			cvssStr = fmt.Sprintf("%.1f", *cve.CVSSScore)
		}
		pdf.SetFont(reportFont, "", 8)
		setTextColour(pdf, colourBodyText)
		pdf.CellFormat(widths[0], 4.8, " "+cve.CVEID, "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[1], 4.8, " "+cvssStr, "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[2], 4.8, " "+strings.ToUpper(cve.Severity), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[3], 4.8, " "+truncate(cveDescriptionWithSource(cve.Description, cve.DescriptionSource), 60), "", 0, "L", true, 0, "")
		pdf.SetFont(reportFont, "B", 8)
		pdf.CellFormat(widths[4], 4.8, " "+cveConfidenceLabel(cve), "", 0, "L", true, 0, "")
		pdf.Ln(-1)
	}
	pdf.Ln(3)
}

// renderCVEUnverified renders the shorter "Possibly Affected" section: one
// summary row per app group, no per-CVE table — this section exists so
// unconfirmed findings don't get lost, not to duplicate the Remediation
// Plan's depth.
func renderCVEUnverified(pdf *fpdf.Fpdf, unverified []CVEUnverifiedGroup) {
	sectionHeader(pdf, "Possibly Affected: Verify Manually")

	if len(unverified) == 0 {
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No unverified findings recorded for this tenant.", "", 1, "L", false, 0, "")
		pdf.Ln(3)
		return
	}

	pdf.SetFont(reportFont, "", 8.5)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"NVD provides no usable version-range data for these products, so the installed version could not be "+
			"confirmed as vulnerable or excluded. Review manually; patched.im recommends updating to the latest "+
			"vendor-released version regardless.",
		"", "L", false)
	pdf.Ln(2)

	// Columns sum to contentWidth (174mm).
	widths := []float64{62, 24, 18, 70}
	tableHeader(pdf, []string{"App", "Devices", "CVEs", "Worst severity"}, widths)
	for i, g := range unverified {
		if i%2 == 1 {
			setFillColour(pdf, colourRowAlt)
		} else {
			setFillColour(pdf, [3]int{255, 255, 255})
		}
		pdf.SetFont(reportFont, "", 8)
		setTextColour(pdf, colourBodyText)
		pdf.CellFormat(widths[0], 4.8, " "+truncate(g.AppName, 42), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[1], 4.8, " "+fmt.Sprintf("%d", len(g.Devices)), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[2], 4.8, " "+fmt.Sprintf("%d", len(g.CVEs)), "", 0, "L", true, 0, "")
		pdf.CellFormat(widths[3], 4.8, " "+worstSeverityLabel(g.CVEs), "", 0, "L", true, 0, "")
		pdf.Ln(-1)
	}
	pdf.Ln(3)
}

// renderCVEAppendix renders the complete, unranked per-hit findings table —
// the report's original (pre-PAT-1205) Part 2 content, now demoted to an
// appendix behind the Remediation Plan and Possibly Affected sections so it
// reads as reference material, not the main content. Body logic is
// unchanged from the old renderCVEFindings; only the heading and its
// forced-own-page placement (see RenderFreeCVEPDF) are new.
func renderCVEAppendix(pdf *fpdf.Fpdf, r FreeCVEReport) {
	sectionHeader(pdf, "Appendix A: Full Findings")
	pdf.SetFont(reportFont, "", 8.5)
	setTextColour(pdf, colourMuted)
	pdf.MultiCell(0, 4.5,
		"Complete per-device, per-application findings underlying the Remediation Plan and Possibly Affected "+
			"sections above, provided for reference and audit.",
		"", "L", false)
	pdf.Ln(3)

	if len(r.CVEs) == 0 {
		sectionHeader(pdf, "Findings")
		pdf.SetFont(reportFont, "", 9)
		setTextColour(pdf, colourMuted)
		pdf.CellFormat(0, 5, "No CVE findings recorded for this tenant.", "", 1, "L", false, 0, "")
		return
	}

	// Group CVEs by severity band; preserve within-band ordering from r.CVEs.
	byBand := map[string][]CVERecord{}
	for _, cve := range r.CVEs {
		sev := strings.ToUpper(cve.Severity)
		byBand[sev] = append(byBand[sev], cve)
	}

	// Column widths sum to contentWidth (174mm).
	// CVE ID(28) + CVSS(11) + Description(48) + Device(28) + App(30) + Ver(15) + Confidence(14)
	widths := []float64{28, 11, 48, 28, 30, 15, 14}
	cols := []string{"CVE ID", "CVSS", "Description", "Device", "Application", "Version", "Confidence"}

	sevOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, sev := range sevOrder {
		cvs, ok := byBand[sev]
		if !ok || len(cvs) == 0 {
			continue
		}

		sectionHeader(pdf, fmt.Sprintf("Findings: %s (%d CVE%s)", sev, len(cvs), plural(len(cvs))))
		tableHeader(pdf, cols, widths)

		rowIdx := 0
		for _, cve := range cvs {
			cvssStr := "—"
			if cve.CVSSScore != nil {
				cvssStr = fmt.Sprintf("%.1f", *cve.CVSSScore)
			}
			for _, hit := range cve.Hits {
				if rowIdx%2 == 1 {
					setFillColour(pdf, colourRowAlt)
				} else {
					setFillColour(pdf, [3]int{255, 255, 255})
				}
				rowIdx++

				pdf.SetFont(reportFont, "", 8)
				setTextColour(pdf, colourBodyText)
				pdf.CellFormat(widths[0], 4.8, " "+cve.CVEID, "", 0, "L", true, 0, "")
				pdf.CellFormat(widths[1], 4.8, " "+cvssStr, "", 0, "L", true, 0, "")
				pdf.CellFormat(widths[2], 4.8, " "+truncate(cveDescriptionWithSource(cve.Description, cve.DescriptionSource), 35), "", 0, "L", true, 0, "")
				pdf.CellFormat(widths[3], 4.8, " "+truncate(hit.Hostname, 18), "", 0, "L", true, 0, "")
				pdf.CellFormat(widths[4], 4.8, " "+truncate(hit.AppName, 20), "", 0, "L", true, 0, "")
				pdf.CellFormat(widths[5], 4.8, " "+truncate(hit.AppVersion, 10), "", 0, "L", true, 0, "")

				switch hit.MatchConfidence {
				case "version_unverified":
					pdf.SetFont(reportFont, "I", 8)
					pdf.CellFormat(widths[6], 4.8, " Possible", "", 0, "L", true, 0, "")
				case "version_vendor_confirmed":
					// Vendor-grade OS finding (Apple security releases / MSRC) —
					// distinguished from NVD CPE confirmations (PAT-409).
					pdf.SetFont(reportFont, "B", 8)
					pdf.CellFormat(widths[6], 4.8, " Vendor-confirmed", "", 0, "L", true, 0, "")
				default:
					pdf.SetFont(reportFont, "B", 8)
					pdf.CellFormat(widths[6], 4.8, " Confirmed", "", 0, "L", true, 0, "")
				}
				pdf.Ln(-1)
			}
		}
		pdf.Ln(2)
	}
}

func renderCVEFootnote(pdf *fpdf.Fpdf) {
	pdf.Ln(2)
	hrule(pdf, 0.4)
	pdf.Ln(3)
	pdf.SetFont(reportFont, "I", 8.5)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 4.5,
		"\"Possibly affected\" findings indicate that the installed product matches a CVE in the NVD database, but no authoritative version-range data is available to confirm or exclude the specific installed version. These findings should be reviewed manually. Patched.im recommends updating to the latest vendor-released version.",
		"", "L", false)
}

func renderCVECloser(pdf *fpdf.Fpdf, r FreeCVEReport) {
	pdf.Ln(4)
	pdf.SetFont(reportFont, "I", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(0, 4.5,
		"Generated by patched.im  |  format "+r.FormatVersion+"  |  "+r.GeneratedAt.Format("02 Jan 2006 15:04")+" UTC",
		"", 1, "L", false, 0, "")
}

// --- Part 3: What happens next -----------------------------------------------

// cveRung holds the display data for one tier rung on the closing page.
type cveRung struct {
	No     string
	Name   string
	Flow   string
	Status string
	Desc   string
}

// cveClosingRungs returns the three tier rungs with statuses sourced from TierStatuses.
// Tests flip TierStatuses fields to assert badge changes; the renderer calls this at render time.
func cveClosingRungs() []cveRung {
	return []cveRung{
		{
			No:     "01",
			Name:   "Report",
			Flow:   "Scan + Prove",
			Status: TierStatuses.Report,
			Desc: "Continuous vulnerability scanning and CIS compliance reporting, with a live dashboard " +
				"and reports on demand. The same assessment you are reading, kept current, plus visibility " +
				"of unused licences and shadow IT. No MDM required, agent installs in minutes.",
		},
		{
			No:     "02",
			Name:   "Patch & Deploy",
			Flow:   "Scan + Patch + Prove",
			Status: TierStatuses.PatchAndDeploy,
			Desc: "Everything in Report, plus active patching and app deployment from verified sources. " +
				"The findings in this report get closed automatically, not just listed. Still no MDM required.",
		},
		{
			No:     "03",
			Name:   "Full Endpoint Management",
			Flow:   "Configuration + policy enforcement",
			Status: TierStatuses.FullEndpointManagement,
			Desc: "The complete managed service: device configuration, policy enforcement and lifecycle " +
				"management across Mac and Windows via Microsoft Intune. For when advisory findings need " +
				"to become enforced controls.",
		},
	}
}

// renderCVEWhatHappensNext renders the closing "What happens next" page.
func renderCVEWhatHappensNext(pdf *fpdf.Fpdf) {
	// Kicker
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, [3]int{245, 83, 10}) // signal orange, same as colourAccent
	pdf.CellFormat(0, 5, "05 · What happens next", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Title
	pdf.SetFont(reportFont, "B", 16)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(0, 9, "From a one-off scan to an estate that stays clear", "", 1, "L", false, 0, "")
	pdf.Ln(3)

	// Intro paragraph
	pdf.SetFont(reportFont, "", 9.5)
	setTextColour(pdf, colourBodyText)
	pdf.MultiCell(0, 5,
		"This assessment is a point in time. The picture will keep moving as software updates land "+
			"and new CVEs are published, so the real question is how you keep your estate clear, not just "+
			"how it looks today. You can work through these findings yourself, or hand the ongoing job to us.",
		"", "L", false)
	pdf.Ln(5)

	// Three rungs
	for _, rung := range cveClosingRungs() {
		renderCVERung(pdf, rung)
		pdf.Ln(5)
	}
	pdf.Ln(3)

	// CTA block
	renderCVECTABlock(pdf)
}

// renderCVERung draws one tier rung: left accent bar, number/name/badge header, flow caption, description.
func renderCVERung(pdf *fpdf.Fpdf, r cveRung) {
	const (
		accentBarW = 3.0  // space reserved for the left accent bar
		innerPadX  = 6.0  // horizontal padding inside the rung
		noW        = 10.0 // width of the "01" number cell
		badgeW     = 28.0 // width of the status badge cell
		rowH       = 6.5  // header row height
	)

	textX := leftMargin + accentBarW + innerPadX
	textW := contentWidth - accentBarW - innerPadX*2
	nameW := textW - noW - badgeW
	isAvailable := r.Status == TierStatusAvailable

	y0 := pdf.GetY()

	// Header row: number | name | badge
	pdf.SetX(textX)

	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(noW, rowH, r.No, "", 0, "L", false, 0, "")

	pdf.SetFont(reportFont, "B", 11)
	setTextColour(pdf, colourBodyText)
	pdf.CellFormat(nameW, rowH, r.Name, "", 0, "L", false, 0, "")

	// Status badge
	if isAvailable {
		setFillColour(pdf, [3]int{234, 243, 222}) // #eaf3de
		pdf.SetTextColor(59, 109, 17)             // #3b6d11
	} else {
		setFillColour(pdf, [3]int{241, 239, 232}) // #f1efe8
		pdf.SetTextColor(95, 94, 90)              // #5f5e5a
	}
	pdf.SetFont(reportFont, "B", 7)
	pdf.CellFormat(badgeW, rowH, r.Status, "", 1, "C", true, 0, "")
	setFillColour(pdf, [3]int{255, 255, 255}) // reset

	// Flow caption
	pdf.SetX(textX + noW)
	pdf.SetFont(reportFont, "", 8)
	setTextColour(pdf, colourMuted)
	pdf.CellFormat(textW-noW, 5, r.Flow, "", 1, "L", false, 0, "")

	// Description — SetLeftMargin so MultiCell line-breaks indent to textX+noW
	pdf.SetLeftMargin(textX + noW)
	pdf.SetX(textX + noW)
	pdf.SetFont(reportFont, "", 9)
	pdf.SetTextColor(92, 96, 106) // #5c606a
	pdf.MultiCell(textW-noW, 4.5, r.Desc, "", "L", false)
	pdf.SetLeftMargin(leftMargin)
	pdf.SetX(leftMargin)

	y1 := pdf.GetY()

	// Left accent bar
	accentColour := colourRule
	if isAvailable {
		accentColour = colourAccent
	}
	pdf.SetDrawColor(accentColour[0], accentColour[1], accentColour[2])
	pdf.SetLineWidth(2.5)
	pdf.Line(leftMargin+1.25, y0, leftMargin+1.25, y1)
	pdf.SetDrawColor(colourRule[0], colourRule[1], colourRule[2])
	pdf.SetLineWidth(0.3)
}

// renderCVECTABlock draws the dark slate "Want a hand reading your results?" panel.
func renderCVECTABlock(pdf *fpdf.Fpdf) {
	const (
		pad  = 6.0  // internal padding
		bgH  = 70.0 // generous estimated panel height
		btnW = 52.0 // button width
	)

	x := leftMargin
	y0 := pdf.GetY()

	// Background fill
	setFillColour(pdf, colourSlate)
	pdf.Rect(x, y0, contentWidth, bgH, "F")

	// Title
	pdf.SetXY(x+pad, y0+pad)
	pdf.SetFont(reportFont, "B", 12)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(contentWidth-pad*2, 9, "Want a hand reading your results?", "", 1, "L", false, 0, "")
	pdf.Ln(3)

	// Body text
	pdf.SetLeftMargin(x + pad)
	pdf.SetX(x + pad)
	pdf.SetFont(reportFont, "", 9)
	pdf.SetTextColor(184, 188, 196) // #b8bcc4
	pdf.MultiCell(contentWidth-pad*2, 5,
		"Book a 15-minute walkthrough and we will go through what matters, what does not, and the fastest "+
			"way to close the gaps. No pitch, no pressure, just the scan.",
		"", "L", false)
	pdf.SetLeftMargin(leftMargin)
	pdf.SetX(leftMargin)
	pdf.Ln(6)

	// Button — orange filled cell showing the friendly URL
	pdf.SetX(x + pad)
	setFillColour(pdf, colourAccent)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont(reportFont, "B", 10)
	pdf.CellFormat(btnW, 9, "  patched.im/#book", "", 1, "L", true, 0, "")
	pdf.Ln(5)

	// Small text: reply-to + CAN-SPAM address
	pdf.SetLeftMargin(x + pad)
	pdf.SetX(x + pad)
	pdf.SetFont(reportFont, "", 7.5)
	pdf.SetTextColor(128, 133, 143) // #80858f
	pdf.MultiCell(contentWidth-pad*2, 5,
		"Reply to scans@patched.im  |  Patched.im, 30 Thorny Road, Douglas, Isle of Man, IM2 5EE",
		"", "L", false)
	pdf.SetLeftMargin(leftMargin)
	pdf.SetX(leftMargin)

	// Advance Y to end of background rect
	if pdf.GetY() < y0+bgH {
		pdf.SetY(y0 + bgH)
	}
	setFillColour(pdf, [3]int{255, 255, 255}) // reset
}

// --- Narrative helpers -------------------------------------------------------

// buildSevPhrase returns a sentence fragment describing the severity breakdown.
func buildSevPhrase(r FreeCVEReport) string {
	type band struct {
		label string
		count int
	}
	var present []band
	for _, b := range []band{
		{"critical", r.CriticalCount},
		{"high", r.HighCount},
		{"medium", r.MediumCount},
		{"low", r.LowCount},
	} {
		if b.count > 0 {
			present = append(present, b)
		}
	}
	if len(present) == 0 {
		return ""
	}

	parts := make([]string, len(present))
	for i, b := range present {
		parts[i] = fmt.Sprintf("%d %s", b.count, b.label)
	}

	switch len(parts) {
	case 1:
		return fmt.Sprintf("All %s are %s severity. ", parts[0], present[0].label)
	default:
		last := parts[len(parts)-1]
		rest := strings.Join(parts[:len(parts)-1], ", ")
		return fmt.Sprintf("These include %s and %s severity CVE%s. ", rest, last, plural(r.TotalCVEs))
	}
}

// plural2 returns s1 when n == 1, s2 otherwise.
func plural2(n int, s1, s2 string) string {
	if n == 1 {
		return s1
	}
	return s2
}
