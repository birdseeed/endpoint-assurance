package report

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-pdf/fpdf"
)

func TestRenderCEReadinessPDFCustomer_ExplicitUnknownAndUTC(t *testing.T) {
	generated := time.Date(2026, 10, 2, 12, 34, 56, 0, time.FixedZone("UTC+2", 2*3600))
	observed := generated.Add(-2 * time.Hour)
	published := generated.AddDate(0, 0, -33)
	due := published.AddDate(0, 0, 14)
	s := func(v string) *string { return &v }
	model := PortalCEReadiness{
		GeneratedAt: generated, Thresholds: CEThresholds{14, 24, 14},
		CVEMatching: CEEvidence{State: "evidenced", Source: "cve_match_runs.full_match", ObservedAt: &observed},
		Estate:      CEEstate{DevicesTotal: 2, NotPassing: 1, WithOutstandingItems: 1, WithControlsNotPassing: 1, Unknown: 1, RetiredExcluded: 3, Source: "devices + existing CE read model", Freshness: CEFreshness{GeneratedAt: generated, ObservedAt: &observed}},
		Devices: []CEDevice{
			{DeviceID: "synthetic-unknown-device", Hostname: "No observation available", Platform: "Windows", State: CEDeviceUnknown, StateReasons: []string{CEReasonDeviceNoReportTime}, Reporting: CEReporting{Bucket: "unknown", Source: "devices.last_seen"}, CVEEvidence: CEEvidence{State: "unknown", Reason: s("cve_match_pending"), Source: "cve_match_runs"}, OSUpdateEvidence: CEEvidence{State: "unknown", Reason: s("version_evidence_pending"), Source: "devices.os_update_status"}, Controls: []CEControl{{Control: "firewall_domain", Category: CECategoryFirewall, State: CEControlNotEvidenced, Reason: s(CEReasonNoEvaluation), Source: "compliance_evaluations"}}},
			{DeviceID: "synthetic-active-device", Hostname: "Finance Mac (synthetic)", Platform: "macOS", State: CEDeviceNotPassing, StateReasons: []string{CEReasonOutstandingItems, CEReasonControlNotPassing}, Reporting: CEReporting{Bucket: "active", Source: "devices.last_seen", ObservedAt: &observed}, CVEEvidence: CEEvidence{State: "evidenced", Source: "device_cve_findings", ObservedAt: &observed}, OSUpdateEvidence: CEEvidence{State: "unavailable", Reason: s("source_not_migrated"), Source: "devices.os_update_status"}, Controls: []CEControl{{Control: "gatekeeper", Category: CECategorySecure, State: CEControlNotPassing, Reason: s(CEReasonEvaluationFailed), Source: "compliance_evaluations", RuleKey: s("cis_macos_2_5_2_1_gatekeeper"), ObservedAt: &observed}}, Items: []CEItem{{Kind: "application", CVEID: "CVE-2099-123456", Severity: "critical", Product: "Synthetic Browser (not a real finding)", InstalledVersion: "1.0", FixedVersion: s("2.0"), Source: "device_cve_findings + cve_feed_entries", ObservedAt: &observed, PublishedAt: published, DueBasis: CEDueBasis, DueAt: due, AgeDays: 33, DaysOverdue: 19, KEV: CEKEV{State: "unknown", Source: "cisa_kev", Reason: s("not_fetched")}}}},
		},
	}
	pdf, err := RenderCEReadinessPDFCustomer(model)
	if err != nil {
		t.Fatal(err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, value := range []string{
		"Generated: 2026-10-02 10:34:56 UTC", "Counts generated: 2026-10-02 10:34:56 UTC", "Newest underlying observation: 2026-10-02 08:34:56 UTC",
		"Update due after: 14 days", "Active within: 24 hours", "Silent after: 14 days", "Devices in scope: 2", "Not passing: 1", "With outstanding items: 1", "With controls not passing: 1", "Unknown: 1", "No outstanding items evidenced: 0", "Retired devices excluded: 3",
		"Device state: unknown", "device_no_report_time", "Bucket: unknown", "Observed: not recorded", "Fixed version: 2.0", "Rule key: not recorded", "Reason: not recorded", "KEV fetched: not recorded", "KEV reason: not_fetched", "State: not_evidenced", "no_evaluation", "Source: cve_match_runs.full_match", "source_not_migrated", "Source: devices.os_update_status", "cis_macos_2_5_2_1_gatekeeper", "2026-08-30 10:34:56 UTC", "2026-09-13 10:34:56 UTC", "Age: 33 days", "Overdue: 19 days", CEDueBasis,
	} {
		if !strings.Contains(compact, strings.Join(strings.Fields(value), "")) {
			t.Errorf("missing %q", value)
		}
	}
	if bytes.Contains(pdf, []byte("/Width 1000")) || !bytes.Contains(pdf, []byte("/Width 512")) {
		t.Error("customer mark missing or staff mark included")
	}
	if out := os.Getenv("CE_READINESS_PDF_SYNTHETIC"); out != "" {
		if err := os.WriteFile(out, pdf, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRenderCEReadinessPDFCustomer_EmptyModel(t *testing.T) {
	pdf, err := RenderCEReadinessPDFCustomer(PortalCEReadiness{})
	if err != nil {
		t.Fatal(err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"Generated: not recorded", "Count source: not recorded", "Observed: not recorded", "No devices in scope"} {
		if !strings.Contains(text, value) {
			t.Errorf("missing %q", value)
		}
	}
}

// Ordinary item/control blocks keep their identifying header and final
// evidence together. A product larger than a whole page still flows without
// dropping any part. This exercises the public renderer, not its measurements.
func TestRenderCEReadinessPDFCustomer_PaginationKeepsEvidenceTogether(t *testing.T) {
	model := PortalCEReadiness{Devices: []CEDevice{{DeviceID: "pagination-device"}}}
	dev := &model.Devices[0]
	for i := 0; i < 12; i++ {
		rule := fmt.Sprintf("END-CONTROL-%02d", i)
		dev.Controls = append(dev.Controls, CEControl{Control: fmt.Sprintf("START-CONTROL-%02d", i), RuleKey: &rule})
	}
	for i := 0; i < 5; i++ {
		reason := fmt.Sprintf("END-ITEM-%02d", i)
		dev.Items = append(dev.Items, CEItem{CVEID: fmt.Sprintf("CVE-2099-%04d", i), Product: strings.Repeat("Ordinary wrapped product name ", 12), KEV: CEKEV{Reason: &reason}})
	}
	var huge strings.Builder
	for i := 0; i < 700; i++ {
		fmt.Fprintf(&huge, "LONGPART%04d-complete ", i)
	}
	final := "END-OVERSIZED-ITEM"
	dev.Items = append(dev.Items, CEItem{CVEID: "CVE-2099-OVERSIZED", Product: huge.String(), KEV: CEKEV{Reason: &final}})
	data, err := RenderCEReadinessPDFCustomer(model)
	if err != nil {
		t.Fatal(err)
	}
	streams, err := reportPDFContentStreams(data)
	if err != nil {
		t.Fatal(err)
	}
	var pages []string
	for _, stream := range streams {
		// Reuse the font-aware text decoder on one content stream at a time.
		wrapper := append([]byte("1 0 obj\n<<>>\nstream\n"), stream...)
		wrapper = append(wrapper, []byte("\nendstream\nendobj")...)
		text, err := extractReportPDFText(wrapper)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(text) != "" {
			pages = append(pages, strings.Join(strings.Fields(text), ""))
		}
	}
	expectedPages := strings.Count(string(data), "/Type /Page") - strings.Count(string(data), "/Type /Pages")
	if len(pages) != expectedPages {
		t.Fatalf("decoded %d page streams, PDF has %d", len(pages), expectedPages)
	}
	pageOf := func(marker string) int {
		t.Helper()
		for page, text := range pages {
			if strings.Contains(text, marker) {
				return page
			}
		}
		t.Errorf("missing %s", marker)
		return -1
	}
	for i := 0; i < 12; i++ {
		first, last := pageOf(fmt.Sprintf("START-CONTROL-%02d", i)), pageOf(fmt.Sprintf("END-CONTROL-%02d", i))
		if first != last {
			t.Errorf("control %d split between pages %d and %d", i, first+1, last+1)
		}
	}
	for i := 0; i < 5; i++ {
		first, last := pageOf(fmt.Sprintf("CVE-2099-%04d", i)), pageOf(fmt.Sprintf("END-ITEM-%02d", i))
		if first != last {
			t.Errorf("ordinary item %d split between pages %d and %d", i, first+1, last+1)
		}
	}
	first, last := pageOf("CVE-2099-OVERSIZED"), pageOf(final)
	if last <= first {
		t.Errorf("oversized item must span pages: %d to %d", first+1, last+1)
	}
	for i := 0; i < 700; i++ {
		pageOf(fmt.Sprintf("LONGPART%04d-complete", i))
	}
}

func TestRenderCEReadinessPDFCustomer_UnsupportedGlyphsAreReversible(t *testing.T) {
	product := "Browser \U0001F600 literal [U+1F600] " + strings.Repeat("中éΩ", 60) + "\tend"
	model := PortalCEReadiness{Devices: []CEDevice{{Hostname: "Example \U0001F4BB", Items: []CEItem{{Product: product}}}}}
	pdf, err := RenderCEReadinessPDFCustomer(model)
	if err != nil {
		t.Fatal(err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, value := range []string{"Hostname: Example [U+1F4BB]", "Browser [U+1F600] literal [U+005B]U+1F600]", "[U+0009]end"} {
		if !strings.Contains(compact, strings.Join(strings.Fields(value), "")) {
			t.Errorf("missing reversible text %q", value)
		}
	}
	for _, part := range []string{"[U+4E2D]", "é", "Ω"} {
		if got := strings.Count(compact, part); got != 60 {
			t.Errorf("wrapped Unicode %q appeared %d times, want 60", part, got)
		}
	}
}

func TestCEReadinessPDF_BlockUsesCEBottomMargin(t *testing.T) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(leftMargin, topMargin, rightMargin)
	pdf.SetAutoPageBreak(true, bottomMargin)
	registerReportFont(pdf)
	pdf.AddPage()
	// This full block ends at 278.6 mm, above the CE footer boundary at
	// 283 mm. The portal report's 26 mm footer wrongly moves its second
	// heading to another page even though the measured block fits here.
	pdf.SetY(249)
	cePDFBlock(pdf, []string{"Boundary section", "Boundary item"}, []cePDFBlockField{
		{"CVE", "CVE-2099-BOUNDARY"}, {"KEV reason", "boundary final evidence"},
	})
	if pdf.Error() != nil {
		t.Fatal(pdf.Error())
	}
	if pdf.PageNo() != 1 {
		t.Fatalf("fitting block split across %d pages", pdf.PageNo())
	}
	if pdf.GetY() > 283 {
		t.Fatalf("block overlaps footer at y=%f", pdf.GetY())
	}
	// The same block really must move together when it would overlap.
	pdf.SetY(260)
	cePDFBlock(pdf, []string{"Next section", "Next item"}, []cePDFBlockField{
		{"CVE", "CVE-2099-NEXT"}, {"KEV reason", "next final evidence"},
	})
	if pdf.PageNo() != 2 {
		t.Fatalf("overflowing block got %d pages, want 2", pdf.PageNo())
	}
}

func TestRenderCEReadinessPDFCustomer_CRLFAndLoneCR(t *testing.T) {
	model := PortalCEReadiness{Devices: []CEDevice{{Hostname: "first\r\nsecond\rlast"}}}
	pdf, err := RenderCEReadinessPDFCustomer(model)
	if err != nil {
		t.Fatal(err)
	}
	text, err := extractReportPDFText(pdf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Hostname: first\nsecond[U+000D]last") {
		t.Fatalf("CRLF should be one line break, lone CR explicit: %q", text)
	}
}
