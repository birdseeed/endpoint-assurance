package handlers

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

// ---------------------------------------------------------------------------
// groupAppFindings — pure grouping logic for /v1/portal/devices/{id}
// ---------------------------------------------------------------------------

func TestGroupAppFindings(t *testing.T) {
	in := []report.DeviceCVEFinding{
		{CVEID: "CVE-2024-0002", Severity: "HIGH", AppName: "Slack", AppVersion: "4.35.0"},
		{CVEID: "CVE-2024-0001", Severity: "CRITICAL", AppName: "Slack", AppVersion: "4.35.0"},
		{CVEID: "CVE-2023-9999", Severity: "low", AppName: "Zoom", AppVersion: "5.1"},
	}
	got := groupAppFindings(in)
	want := []portalAppFinding{
		{App: "Slack", Version: "4.35.0", CVEIDs: []string{"CVE-2024-0001", "CVE-2024-0002"}, MaxSeverity: "critical"},
		{App: "Zoom", Version: "5.1", CVEIDs: []string{"CVE-2023-9999"}, MaxSeverity: "low"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("groupAppFindings() = %+v, want %+v", got, want)
	}
}

func TestGroupAppFindingsEmpty(t *testing.T) {
	if got := groupAppFindings(nil); len(got) != 0 {
		t.Errorf("expected empty result, got %+v", got)
	}
}

func TestPortalControlCountsFromCoverage(t *testing.T) {
	got := portalControlCountsFromCoverage(report.ControlCoverage{
		ControlsTotal:           12,
		ControlsEvaluated:       8,
		ControlsOutOfScope:      2,
		UndeterminedEvaluations: 3,
		Measurements: report.ControlCoverageMeasurements{
			Pass: 4, Fail: 2, Undetermined: 3, NotApplicable: 1,
		},
		Identifiers: report.ControlCoverageIdentifiers{
			CISMapped: 5, CISUnmapped: 6, NonCIS: 1,
		},
	})
	want := portalControlCounts{
		Total:                   12,
		Evaluated:               8,
		OutOfScope:              2,
		UndeterminedEvaluations: 3,
	}
	if got != want {
		t.Errorf("portalControlCountsFromCoverage() = %+v, want %+v", got, want)
	}
}

func TestPortalControlCoverageAdditiveCounts(t *testing.T) {
	measurements := portalControlMeasurementsFromCoverage(report.ControlCoverageMeasurements{
		Pass: 4, Fail: 2, Undetermined: 3, NotApplicable: 1,
	})
	if want := (portalControlMeasurements{Pass: 4, Fail: 2, Undetermined: 3, NotApplicable: 1}); measurements != want {
		t.Errorf("portalControlMeasurementsFromCoverage() = %+v, want %+v", measurements, want)
	}
	identifiers := portalControlIdentifiersFromCoverage(report.ControlCoverageIdentifiers{
		CISMapped: 5, CISUnmapped: 6, NonCIS: 1,
	})
	if want := (portalControlIdentifiers{CISMapped: 5, CISUnmapped: 6, NonCIS: 1}); identifiers != want {
		t.Errorf("portalControlIdentifiersFromCoverage() = %+v, want %+v", identifiers, want)
	}
}

func TestGroupAppFindingsUnknownSeverity(t *testing.T) {
	got := groupAppFindings([]report.DeviceCVEFinding{
		{CVEID: "CVE-1", Severity: "", AppName: "App", AppVersion: "1"},
	})
	if len(got) != 1 || got[0].MaxSeverity != "" {
		t.Errorf("got %+v, want single row with empty max_severity", got)
	}
}

// TestGroupAppFindingsConfidenceAndFixedVersion covers groupAppFindings' fold
// logic for match_confidence (confirmedFlavorRank priority, hasUnverified
// wins over any confirmed flavor) and fixed_version (max via
// cvematch.CompareVersions, not lexicographic string comparison) — none of
// the tests above ever set these fields, so they never exercised the fold.
func TestGroupAppFindingsConfidenceAndFixedVersion(t *testing.T) {
	t.Run("mixed confirmed flavors resolve by priority, vendor-confirmed first", func(t *testing.T) {
		got := groupAppFindings([]report.DeviceCVEFinding{
			{CVEID: "CVE-1", AppName: "App", AppVersion: "1", MatchConfidence: "version_confirmed"},
			{CVEID: "CVE-2", AppName: "App", AppVersion: "1", MatchConfidence: "version_vendor_confirmed"},
		})
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if got[0].MatchConfidence != "version_vendor_confirmed" {
			t.Errorf("MatchConfidence = %q, want version_vendor_confirmed", got[0].MatchConfidence)
		}
	})

	t.Run("mixed confirmed flavors resolve by priority, vendor-confirmed last", func(t *testing.T) {
		got := groupAppFindings([]report.DeviceCVEFinding{
			{CVEID: "CVE-1", AppName: "App", AppVersion: "1", MatchConfidence: "version_vendor_confirmed"},
			{CVEID: "CVE-2", AppName: "App", AppVersion: "1", MatchConfidence: "version_confirmed"},
		})
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if got[0].MatchConfidence != "version_vendor_confirmed" {
			t.Errorf("MatchConfidence = %q, want version_vendor_confirmed (order-independent)", got[0].MatchConfidence)
		}
	})

	t.Run("any unverified hit wins over any number of confirmed hits", func(t *testing.T) {
		got := groupAppFindings([]report.DeviceCVEFinding{
			{CVEID: "CVE-1", AppName: "App", AppVersion: "1", MatchConfidence: "version_confirmed"},
			{CVEID: "CVE-2", AppName: "App", AppVersion: "1", MatchConfidence: "version_vendor_confirmed"},
			{CVEID: "CVE-3", AppName: "App", AppVersion: "1", MatchConfidence: "version_unverified"},
		})
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if got[0].MatchConfidence != "version_unverified" {
			t.Errorf("MatchConfidence = %q, want version_unverified", got[0].MatchConfidence)
		}
	})

	t.Run("fixed_version folds via real version comparison, not string comparison", func(t *testing.T) {
		got := groupAppFindings([]report.DeviceCVEFinding{
			{CVEID: "CVE-1", AppName: "App", AppVersion: "1", FixedVersion: "9.0"},
			{CVEID: "CVE-2", AppName: "App", AppVersion: "1", FixedVersion: "10.0"},
		})
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if got[0].FixedVersion != "10.0" {
			t.Errorf("FixedVersion = %q, want 10.0 (true semantic max, not lexicographic \"9.0\" > \"10.0\")", got[0].FixedVersion)
		}
	})

	t.Run("empty fixed_version hits don't clobber a real one", func(t *testing.T) {
		got := groupAppFindings([]report.DeviceCVEFinding{
			{CVEID: "CVE-1", AppName: "App", AppVersion: "1", FixedVersion: "2.0"},
			{CVEID: "CVE-2", AppName: "App", AppVersion: "1", FixedVersion: ""},
		})
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if got[0].FixedVersion != "2.0" {
			t.Errorf("FixedVersion = %q, want 2.0", got[0].FixedVersion)
		}
	})

	t.Run("all-empty bucket stays empty, never fabricated", func(t *testing.T) {
		got := groupAppFindings([]report.DeviceCVEFinding{
			{CVEID: "CVE-1", AppName: "App", AppVersion: "1", FixedVersion: ""},
			{CVEID: "CVE-2", AppName: "App", AppVersion: "1", FixedVersion: ""},
		})
		if len(got) != 1 {
			t.Fatalf("len(got) = %d, want 1", len(got))
		}
		if got[0].FixedVersion != "" {
			t.Errorf("FixedVersion = %q, want empty", got[0].FixedVersion)
		}
	})
}

// ---------------------------------------------------------------------------
// Handlers without identity fail closed — the guard against portal routes
// ever being mounted outside portalauth.Middleware.
// ---------------------------------------------------------------------------

func TestPortalHandlersWithoutIdentityFailClosed(t *testing.T) {
	handlersUnderTest := map[string]http.HandlerFunc{
		"overview":         PortalOverviewHandler(nil),
		"control_coverage": PortalControlCoverageHandler(nil),
		"devices":          PortalDevicesHandler(nil),
		"device_detail":    PortalDeviceDetailHandler(nil),
		"findings":         PortalFindingsHandler(nil),
		"unapproved_apps":  PortalUnapprovedAppsHandler(nil),
		"reports_list":     PortalReportsListHandler(nil),
		"local_admins":     PortalLocalAdminsHandler(nil),    // PAT-2215
		"driver_findings":  PortalDriverFindingsHandler(nil), // PAT-2263
		"report_generate":  PortalReportGenerateHandler(nil),
		"report_download":  PortalReportDownloadHandler(nil),
		"report_catalogue": PortalReportCatalogueHandler(nil),
		"enrolment":        PortalEnrolmentGenerateHandler(nil, nil), // PAT-453
		// PAT-2135
		"device_retirement_put":        PortalDeviceRetirementPutHandler(nil),
		"device_retirement_history":    PortalDeviceRetirementHistoryHandler(nil),
		"device_list_get":              PortalDeviceListGetHandler(nil),
		"device_list_put":              PortalDeviceListPutHandler(nil),
		"device_list_delete":           PortalDeviceListDeleteHandler(nil),
		"unsupported_software":         PortalUnsupportedSoftwareHandler(nil),        // PAT-2147
		"unsupported_software_devices": PortalUnsupportedSoftwareDevicesHandler(nil), // PAT-2147
		"remote_access":                PortalRemoteAccessHandler(nil),               // PAT-2148
		"remote_access_devices":        PortalRemoteAccessDevicesHandler(nil),        // PAT-2148
		"version_sprawl":               PortalVersionSprawlHandler(nil),              // PAT-2150
		"software_publishers":          PortalSoftwarePublishersHandler(nil),         // PAT-2152
		"software_publishers_devices":  PortalSoftwarePublishersDevicesHandler(nil),  // PAT-2152
		"duplicate_tools":              PortalDuplicateToolsHandler(nil),             // PAT-2151
		"jamf_coverage":                PortalJamfCoverageHandler(nil),               // PAT-2145
		"jamf_setup_get":               PortalJamfSetupGetHandler(nil),               // PAT-2145
		"jamf_setup_put":               PortalJamfSetupPutHandler(nil),               // PAT-2145
		"jamf_token_post":              PortalJamfTokenPostHandler(nil),              // PAT-2145
		"jamf_token_delete":            PortalJamfTokenDeleteHandler(nil),            // PAT-2145
		"jamf_devices_delete":          PortalJamfDevicesDeleteHandler(nil),          // PAT-2145
	}
	for name, h := range handlersUnderTest {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/portal/x", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 (fail closed without identity)", rr.Code)
			}
		})
	}
}

func TestPortalReportGenerateRejectsUnknownAndNonCustomerTypesBeforeDB(t *testing.T) {
	const wantBody = "unknown or unavailable report_type\n"
	for _, reportType := range []string{"not-a-report", "software-inventory", "device-compliance"} {
		t.Run(reportType, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/portal/reports",
				strings.NewReader(`{"report_type":"`+reportType+`"}`))
			req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
				Email: "a@b.c", TenantID: "1e8b6c1e-0000-0000-0000-000000000001",
			}))
			rr := httptest.NewRecorder()
			PortalReportGenerateHandler(nil).ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			if got := rr.Body.String(); got != wantBody {
				t.Fatalf("body = %q, want generic rejection %q", got, wantBody)
			}
		})
	}
}

func TestPortalReportRenderersMatchCustomerCatalogue(t *testing.T) {
	want := make(map[string]bool)
	for _, def := range report.PortalReportCatalogue() {
		want[def.Type] = true
		if _, found := portalReportRenderers[def.Type]; !found {
			t.Errorf("customer-facing report %q has no renderer", def.Type)
		}
	}
	for reportType := range portalReportRenderers {
		if !want[reportType] {
			t.Errorf("renderer %q is not a customer-facing catalogue type", reportType)
		}
	}
}

func TestPortalReportGenerateRejectsConflictingTypeAliases(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/portal/reports",
		strings.NewReader(`{"report_type":"executive-summary","type":"patch-status"}`))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
		Email: "a@b.c", TenantID: "1e8b6c1e-0000-0000-0000-000000000001",
	}))
	rr := httptest.NewRecorder()
	PortalReportGenerateHandler(nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// TestPortalDeviceDetailRejectsNonUUID — malformed device IDs 404 before any
// DB access (pool is nil; a query would panic).
func TestPortalDeviceDetailRejectsNonUUID(t *testing.T) {
	h := PortalDeviceDetailHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/devices/not-a-uuid", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "a@b.c", TenantID: "1e8b6c1e-0000-0000-0000-000000000001"}))
	req = withChiParam(req, "deviceID", "not-a-uuid")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestPortalReportDownloadRejectsNonUUID — same guard on the report ID.
func TestPortalReportDownloadRejectsNonUUID(t *testing.T) {
	h := PortalReportDownloadHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/reports/../../etc/passwd", nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(),
		portalauth.Identity{Email: "a@b.c", TenantID: "1e8b6c1e-0000-0000-0000-000000000001"}))
	req = withChiParam(req, "id", "../../etc/passwd")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}
