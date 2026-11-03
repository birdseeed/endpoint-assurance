package report

import (
	"strings"
	"testing"
	"time"
)

// pat2265Fixture is injected into one printed free-text field per report
// type (almost always Tenant/TenantName, rendered in every renderer's
// "Prepared for" line): an en dash, an em dash, a bullet, and the two
// comparison operators the local-admin copy uses natively (≤/≥), plus an
// accented Latin letter. None of these survive fpdf's core Helvetica path
// intact -- each multi-byte UTF-8 character gets its raw bytes written into
// a single-byte-encoded content stream, which is read back by any real PDF
// viewer one byte at a time against WinAnsiEncoding and comes out as
// "â€¦"-shaped mojibake (verified by hand against this exact fixture while
// building this test, before the font swap: see the PAT-2265 report).
const pat2265Fixture = "– — • ≤ ≥ é"

// pat2265MojibakeMarker is the byte sequence a Latin-1/cp1252-decoding PDF
// viewer shows for the UTF-8 lead byte 0xE2 (which starts the 3-byte UTF-8
// encoding of U+2013/U+2014/U+2022/U+2264/U+2265, all present in
// pat2265Fixture): cp1252 0xE2 is "â", 0x80 is "€". Any real occurrence of
// this pair in extracted text means a multi-byte character was written into
// a single-byte-font content stream and misread back.
const pat2265MojibakeMarker = "â€"

// pat2265Case is one of the report package's 18 registered report types
// (see registry.go) plus the render function under test.
type pat2265Case struct {
	reportType string
	render     func() ([]byte, error)
}

func pat2265Cases() []pat2265Case {
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

	return []pat2265Case{
		{
			reportType: "device-compliance",
			render: func() ([]byte, error) {
				r := fixtureReport()
				r.Tenant = pat2265Fixture
				return RenderPDF(r)
			},
		},
		{
			reportType: "executive-summary",
			render: func() ([]byte, error) {
				s := fixtureExecutiveSummary()
				s.Tenant = pat2265Fixture
				return RenderExecutiveSummaryPDF(s)
			},
		},
		{
			reportType: "cis-compliance",
			render: func() ([]byte, error) {
				return RenderCISCompliancePDF(CISComplianceReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "cve-report",
			render: func() ([]byte, error) {
				r := fixtureFreeCVEReport()
				r.Tenant = pat2265Fixture
				return RenderFreeCVEPDF(r)
			},
		},
		{
			reportType: "patch-status",
			render: func() ([]byte, error) {
				return RenderPatchStatusPDF(PatchStatusReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "stale-endpoints",
			render: func() ([]byte, error) {
				return RenderStaleEndpointsPDF(StaleEndpointsReport{
					GeneratedAt:   now,
					Tenant:        pat2265Fixture,
					ThresholdDays: 30,
				})
			},
		},
		{
			reportType: "cert-expiry",
			render: func() ([]byte, error) {
				return RenderCertExpiryPDF(CertExpiryReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "software-inventory",
			render: func() ([]byte, error) {
				return RenderSoftwareInventoryPDF(SoftwareInventoryReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "app-policy-drift",
			render: func() ([]byte, error) {
				return RenderAppPolicyDriftPDF(AppPolicyDriftReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "browser-extensions",
			render: func() ([]byte, error) {
				return RenderBrowserExtensionsPDF(BrowserExtensionsReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "edr-coverage",
			render: func() ([]byte, error) {
				return RenderEDRCoveragePDF(EDRCoverageReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "device-health",
			render: func() ([]byte, error) {
				return RenderDeviceHealthPDF(DeviceHealthReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "encryption-posture",
			render: func() ([]byte, error) {
				return RenderEncryptionPosturePDF(EncryptionPostureReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "local-admin",
			render: func() ([]byte, error) {
				return RenderLocalAdminPDF(LocalAdminReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "new-software",
			render: func() ([]byte, error) {
				return RenderNewSoftwarePDF(NewSoftwareReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "software-drift",
			render: func() ([]byte, error) {
				return RenderSoftwareDriftPDF(SoftwareDriftReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "approved-software",
			render: func() ([]byte, error) {
				return RenderApprovedSoftwarePDF(ApprovedSoftwareReport{
					GeneratedAt: now,
					Tenant:      pat2265Fixture,
				})
			},
		},
		{
			reportType: "insurance-evidence",
			render: func() ([]byte, error) {
				d := buildInsuranceEvidence(insFixture())
				d.Tenant = pat2265Fixture
				return RenderInsuranceEvidencePDF(d)
			},
		},
		{
			reportType: "ai-tooling-evidence",
			render: func() ([]byte, error) {
				return RenderToolingEvidencePDF(ToolingEvidenceReport{
					GeneratedAt: now,
					TenantName:  pat2265Fixture,
				})
			},
		},
	}
}

// TestUTF8FontRoundTrip is PAT-2265's acceptance test: every one of the 18
// registered report types (registry.go's reportRegistry — 17 renderer files
// plus report.go/pdf.go's device-compliance renderer) must render an
// en dash, em dash, bullet, ≤, ≥ and an accented letter through to the PDF's
// extractable text unchanged, with no "â€"-shaped mojibake, once its
// SetFont calls carry a real UTF-8 font instead of fpdf's core Helvetica.
//
// This test fails on pre-PAT-2265 code: reverting registerReportFont's
// insertion and any one of the 16 files' SetFont("Helvetica", ...) swaps
// back to SetFont("Helvetica", ...) reproduces the exact mojibake the
// ticket describes ("Compliant (â€°¤2 admins)") -- confirmed by hand while
// building this test, before wiring up the fix, on local-admin and cve-report.
func TestUTF8FontRoundTrip(t *testing.T) {
	for _, tc := range pat2265Cases() {
		t.Run(tc.reportType, func(t *testing.T) {
			pdfBytes, err := tc.render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			text, err := extractReportPDFText(pdfBytes)
			if err != nil {
				t.Fatalf("extractReportPDFText: %v", err)
			}
			if !strings.Contains(text, pat2265Fixture) {
				t.Errorf("rendered PDF text does not contain the fixture string %q verbatim\nextracted text: %q",
					pat2265Fixture, text)
			}
			if strings.Contains(text, pat2265MojibakeMarker) {
				t.Errorf("rendered PDF text contains the mojibake marker %q (core-font UTF-8 byte corruption)\nextracted text: %q",
					pat2265MojibakeMarker, text)
			}
		})
	}
}

// TestUTF8FontRoundTrip_AllRegisteredReportTypes cross-checks pat2265Cases
// against registry.go's reportRegistry: if a report type is ever added to
// the registry without a matching case here, this fails loudly instead of
// the coverage silently going stale.
func TestUTF8FontRoundTrip_AllRegisteredReportTypes(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range pat2265Cases() {
		covered[tc.reportType] = true
	}
	for _, def := range ReportCatalogue() {
		if !covered[def.Type] {
			t.Errorf("report type %q is registered in registry.go but has no TestUTF8FontRoundTrip case", def.Type)
		}
	}
}
