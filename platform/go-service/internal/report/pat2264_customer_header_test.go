package report

// PAT-2264: 12 of 13 customer-facing report types went to the staff PDF
// renderers (internal/handlers/portal.go's portalReportRenderers), so a
// customer downloading e.g. the CIS Compliance Report from their own portal
// got the internal header: header.png, which bakes the retired pixel-P
// icon and a "Staff report" caption into one 1000x600 raster (see
// go-service/internal/report/assets/header.png). executive-summary already
// had its own customer renderer (portal_pdf.go) and was unaffected.
//
// The "Staff report" wording is pixels, not text, so it can never appear in
// a PDF-text extraction (extractPDFText, cve_report_test.go) — that check
// is kept below because it documents the literal acceptance criterion and
// will catch any future regression that draws "Staff" as real text, but it
// is not the signal that actually distinguishes fixed from unfixed code.
// The real signal is which brand mark image is embedded: header.png is
// 1000x600; the current in-app mark (prMarkPNG, portal_pdf.go, the same
// asset the executive-summary customer renderer already uses) is 512x512.
// fpdf embeds every image an Fpdf instance ever registers regardless of
// whether a page actually draws it, so "does the PDF embed a 1000x600
// image" is a reliable proxy for "did this renderer ever touch header.png"
// even though the image is never visible on the rendered page either way.
//
// Before the PAT-2264 fix, every one of these twelve report types rendered
// through the plain (staff) Render*PDF entry point, which always embeds
// header.png (1000x600) and never the customer mark (512x512) — the
// opposite of what this test requires, and the *Customer functions it calls
// did not exist at all, so this test could not have compiled, let alone
// passed, against the pre-fix code.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/softwaregov"
)

const (
	pat2264StaffMarkFingerprint    = "/Width 1000" // header.png, 1000x600
	pat2264CustomerMarkFingerprint = "/Width 512"  // prMarkPNG, 512x512
)

func TestCustomerReportHeaders_NeverStaffMark(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	tenant := "Acme Ltd"

	cases := []struct {
		name   string
		render func() ([]byte, error)
	}{
		{"cis-compliance", func() ([]byte, error) {
			return RenderCISCompliancePDFCustomer(CISComplianceReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"cve-report", func() ([]byte, error) {
			return RenderFreeCVEPDFCustomer(FreeCVEReport{FormatVersion: FreeCVEFormatVersion, Tenant: tenant, GeneratedAt: now})
		}},
		{"patch-status", func() ([]byte, error) {
			return RenderPatchStatusPDFCustomer(PatchStatusReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"stale-endpoints", func() ([]byte, error) {
			return RenderStaleEndpointsPDFCustomer(StaleEndpointsReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"cert-expiry", func() ([]byte, error) {
			return RenderCertExpiryPDFCustomer(CertExpiryReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"edr-coverage", func() ([]byte, error) {
			return RenderEDRCoveragePDFCustomer(EDRCoverageReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"encryption-posture", func() ([]byte, error) {
			return RenderEncryptionPosturePDFCustomer(EncryptionPostureReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"local-admin", func() ([]byte, error) {
			return RenderLocalAdminPDFCustomer(LocalAdminReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"new-software", func() ([]byte, error) {
			return RenderNewSoftwarePDFCustomer(NewSoftwareReport{
				Tenant: tenant, GeneratedAt: now,
				Data: softwaregov.NewSoftware{SinceBasis: softwaregov.SinceNoReview, Until: now},
			})
		}},
		{"software-drift", func() ([]byte, error) {
			return RenderSoftwareDriftPDFCustomer(SoftwareDriftReport{
				Tenant: tenant, GeneratedAt: now, Data: softwaregov.Drift{GeneratedAt: now},
			})
		}},
		{"approved-software", func() ([]byte, error) {
			return RenderApprovedSoftwarePDFCustomer(ApprovedSoftwareReport{
				Tenant: tenant, GeneratedAt: now, Data: softwaregov.ApprovedList{GeneratedAt: now},
			})
		}},
		{"ai-tooling-evidence", func() ([]byte, error) {
			return RenderToolingEvidencePDFCustomer(ToolingEvidenceReport{TenantName: tenant, GeneratedAt: now})
		}},
		{"insurance-evidence", func() ([]byte, error) {
			return RenderInsuranceEvidencePDFCustomer(InsuranceEvidence{Tenant: tenant, GeneratedAt: now})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdf, err := tc.render()
			if err != nil {
				t.Fatalf("render error: %v", err)
			}

			if text := extractPDFText(t, pdf); strings.Contains(text, "Staff") {
				t.Errorf("customer PDF text contains \"Staff\": %q", text)
			}
			if bytes.Contains(pdf, []byte(pat2264StaffMarkFingerprint)) {
				t.Errorf("customer PDF embeds header.png (the staff mark, 1000x600) — got the internal header instead of the customer one")
			}
			if !bytes.Contains(pdf, []byte(pat2264CustomerMarkFingerprint)) {
				t.Errorf("customer PDF does not embed the current in-app brand mark (512x512)")
			}
		})
	}
}

// TestStaffReportHeaders_Unchanged asserts the staff/admin PDF entry points
// (internal/handlers/reports.go, portal_software_governance.go,
// portal_tooling.go) keep drawing exactly the header they always did:
// header.png only, never the new customer mark. Every one of these calls
// the same plain Render*PDF function it called before PAT-2264, unchanged.
func TestStaffReportHeaders_Unchanged(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	tenant := "Acme Ltd"

	cases := []struct {
		name   string
		render func() ([]byte, error)
	}{
		{"cis-compliance", func() ([]byte, error) {
			return RenderCISCompliancePDF(CISComplianceReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"cve-report", func() ([]byte, error) {
			return RenderFreeCVEPDF(FreeCVEReport{FormatVersion: FreeCVEFormatVersion, Tenant: tenant, GeneratedAt: now})
		}},
		{"patch-status", func() ([]byte, error) {
			return RenderPatchStatusPDF(PatchStatusReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"stale-endpoints", func() ([]byte, error) {
			return RenderStaleEndpointsPDF(StaleEndpointsReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"cert-expiry", func() ([]byte, error) {
			return RenderCertExpiryPDF(CertExpiryReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"edr-coverage", func() ([]byte, error) {
			return RenderEDRCoveragePDF(EDRCoverageReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"encryption-posture", func() ([]byte, error) {
			return RenderEncryptionPosturePDF(EncryptionPostureReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"local-admin", func() ([]byte, error) {
			return RenderLocalAdminPDF(LocalAdminReport{Tenant: tenant, GeneratedAt: now})
		}},
		{"new-software", func() ([]byte, error) {
			return RenderNewSoftwarePDF(NewSoftwareReport{
				Tenant: tenant, GeneratedAt: now,
				Data: softwaregov.NewSoftware{SinceBasis: softwaregov.SinceNoReview, Until: now},
			})
		}},
		{"software-drift", func() ([]byte, error) {
			return RenderSoftwareDriftPDF(SoftwareDriftReport{
				Tenant: tenant, GeneratedAt: now, Data: softwaregov.Drift{GeneratedAt: now},
			})
		}},
		{"approved-software", func() ([]byte, error) {
			return RenderApprovedSoftwarePDF(ApprovedSoftwareReport{
				Tenant: tenant, GeneratedAt: now, Data: softwaregov.ApprovedList{GeneratedAt: now},
			})
		}},
		{"ai-tooling-evidence", func() ([]byte, error) {
			return RenderToolingEvidencePDF(ToolingEvidenceReport{TenantName: tenant, GeneratedAt: now})
		}},
		{"insurance-evidence", func() ([]byte, error) {
			return RenderInsuranceEvidencePDF(InsuranceEvidence{Tenant: tenant, GeneratedAt: now})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdf, err := tc.render()
			if err != nil {
				t.Fatalf("render error: %v", err)
			}
			if !bytes.Contains(pdf, []byte(pat2264StaffMarkFingerprint)) {
				t.Errorf("staff PDF no longer embeds header.png (1000x600) — staff header must stay unchanged")
			}
			if bytes.Contains(pdf, []byte(pat2264CustomerMarkFingerprint)) {
				t.Errorf("staff PDF unexpectedly embeds the customer brand mark (512x512)")
			}
		})
	}
}
