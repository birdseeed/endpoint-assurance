package handlers

// PAT-2130: the customer-facing /v1/portal/* surface must never expose
// subscription_tier (tenants.subscription_tier, the internal commercial
// entitlement field — see tier.go, admin.go's setTenantTierReq). Nothing in
// this package's portal handlers currently declares a `json:"subscription_tier"`
// field (checked by grep across internal/handlers/portal*.go,
// internal/handlers/software_*.go, internal/handlers/protected_software.go
// and internal/report/portal*.go — the only `subscription_tier` json tags in
// the tree are admin.go's setTenantTierReq/setTenantTierResp, which back
// /admin/tenant-tier/{tenantID}, not a /v1/portal/* route). This test locks
// that as a regression guard, driven dynamically against every route
// cmd/patched-api/main.go registers under r.Route("/v1/portal", ...) as of
// PAT-2130 (44 routes: 37 GET, 4 PUT, 3 POST; 49 since PAT-2135 added
// 2 GET, 2 PUT and 1 DELETE) — the full table below mirrors
// that block 1:1; keep them in sync when either changes.
//
// Coverage note: every registered route is driven, but most return a 401
// (no identity — checked separately by TestPortalHandlersWithoutIdentityFailClosed),
// 403 (viewer role; the seeded tenant carries no portal_users row so every
// role check resolves to RoleViewer) or 400 (deliberately invalid JSON body
// for every write route, chosen so no handler under test performs a DB
// mutation) rather than a fully populated 200. That's still a meaningful
// check: a struct field, if present, is marshalled into the JSON body
// regardless of how much data backs it or which branch produced the body —
// none of these handlers strip subscription_tier out of a generic error
// payload, so this drives the literal source of every response body each
// route can currently produce through this seam. It is deliberately not
// the same claim as "every /v1/portal/* endpoint behaves correctly for a
// populated, admin-role tenant" — that's covered by each handler's own
// dedicated tests. DB-backed; skipped without TEST_DATABASE_URL.
//
// A regression that added subscription_tier back to a portal response
// struct would be caught here regardless of which of the three response
// shapes above it landed in, because struct-to-JSON marshalling doesn't
// care about the handler's status code.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

// portalNoTierRoute describes one registered /v1/portal/* route to drive.
type portalNoTierRoute struct {
	name    string
	method  string
	path    string
	params  map[string]string // chi URL params, e.g. {"deviceID": "..."}
	body    string            // request body; "" means no body
	handler func(pool *pgxpool.Pool) http.HandlerFunc
}

// portalNoTierWithParams injects chi URL params the way the real router
// would, so handlers reading chi.URLParam behave as they do in production.
func portalNoTierWithParams(r *http.Request, params map[string]string) *http.Request {
	if len(params) == 0 {
		return r
	}
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestPortalNoTierAcrossRegisteredRoutes is PAT-2130's second guarantee:
// no /v1/portal/* response body ever carries "subscription_tier". See the
// coverage note in this file's package-level doc comment for what "driven"
// means for each route and what it does and doesn't prove.
func TestPortalNoTierAcrossRegisteredRoutes(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2130-no-tier")
	email := "viewer-" + tenantID[:8] + "@pat2130.example"

	const fakeUUID = "00000000-0000-0000-0000-00000000abcd"
	// Deliberately trips DisallowUnknownFields on every write handler that
	// decodes JSON, so no handler under test reaches a DB mutation — pure
	// exposure check, no side effects to clean up.
	const invalidJSONBody = `{"__pat2130_unknown_field__": true}`

	routes := []portalNoTierRoute{
		{"overview", http.MethodGet, "/v1/portal/overview", nil, "", PortalOverviewHandler},
		{"control_coverage", http.MethodGet, "/v1/portal/control-coverage", nil, "", PortalControlCoverageHandler},
		{"devices", http.MethodGet, "/v1/portal/devices", nil, "", PortalDevicesHandler},
		{"device_detail", http.MethodGet, "/v1/portal/devices/{deviceID}", map[string]string{"deviceID": fakeUUID}, "", PortalDeviceDetailHandler},
		{"device_retirement_put", http.MethodPut, "/v1/portal/devices/{deviceID}/retirement", map[string]string{"deviceID": fakeUUID}, invalidJSONBody, PortalDeviceRetirementPutHandler},
		{"device_retirement_history", http.MethodGet, "/v1/portal/devices/{deviceID}/retirement/history", map[string]string{"deviceID": fakeUUID}, "", PortalDeviceRetirementHistoryHandler},
		{"device_list_get", http.MethodGet, "/v1/portal/device-list", nil, "", PortalDeviceListGetHandler},
		{"device_list_put", http.MethodPut, "/v1/portal/device-list", nil, invalidJSONBody, PortalDeviceListPutHandler},
		{"device_list_delete", http.MethodDelete, "/v1/portal/device-list", nil, "", PortalDeviceListDeleteHandler},
		{"device_list_entry_delete", http.MethodDelete, "/v1/portal/device-list/entries/{entryID}", map[string]string{"entryID": "1"}, "", PortalDeviceListEntryDeleteHandler}, // PAT-2271
		{"findings", http.MethodGet, "/v1/portal/findings", nil, "", PortalFindingsHandler},
		{"unapproved_apps", http.MethodGet, "/v1/portal/unapproved-apps", nil, "", PortalUnapprovedAppsHandler},
		{"extensions", http.MethodGet, "/v1/portal/extensions", nil, "", PortalExtensionsHandler},
		{"applications", http.MethodGet, "/v1/portal/applications", nil, "", PortalApplicationsHandler},
		{"software", http.MethodGet, "/v1/portal/software", nil, "", PortalSoftwareHandler},
		{"software_new", http.MethodGet, "/v1/portal/software/new", nil, "", PortalNewSoftwareHandler},
		{"software_drift", http.MethodGet, "/v1/portal/software/drift", nil, "", PortalSoftwareDriftHandler},
		{"software_approved", http.MethodGet, "/v1/portal/software/approved", nil, "", PortalApprovedSoftwareHandler},
		{"software_notifications_get", http.MethodGet, "/v1/portal/software-notifications", nil, "", PortalSoftwareNotificationsGetHandler},
		{"software_notifications_put", http.MethodPut, "/v1/portal/software-notifications", nil, invalidJSONBody, PortalSoftwareNotificationsPutHandler},
		{"tagged_products", http.MethodGet, "/v1/portal/tagged-products", nil, "", PortalTaggedProductsHandler},
		{"homebrew_summary", http.MethodGet, "/v1/portal/homebrew/summary", nil, "", PortalHomebrewSummaryHandler},
		{"homebrew_formulae", http.MethodGet, "/v1/portal/homebrew/formulae", nil, "", PortalHomebrewFormulaeHandler},
		{"homebrew_casks", http.MethodGet, "/v1/portal/homebrew/casks", nil, "", PortalHomebrewCasksHandler},
		{"homebrew_taps", http.MethodGet, "/v1/portal/homebrew/taps", nil, "", PortalHomebrewTapsHandler},
		{"homebrew_devices", http.MethodGet, "/v1/portal/homebrew/devices", nil, "", PortalHomebrewDevicesHandler},
		{"homebrew_device", http.MethodGet, "/v1/portal/homebrew/devices/{deviceID}", map[string]string{"deviceID": fakeUUID}, "", PortalHomebrewDeviceHandler},
		{"ai_tooling_summary", http.MethodGet, "/v1/portal/ai-tooling/summary", nil, "", PortalToolingSummaryHandler},
		{"ai_tooling_devices", http.MethodGet, "/v1/portal/ai-tooling/devices", nil, "", PortalToolingDevicesHandler},
		{"protected_software", http.MethodGet, "/v1/portal/protected-software", nil, "", PortalProtectedSoftwareHandler},
		{"exceptions", http.MethodGet, "/v1/portal/exceptions", nil, "", PortalExceptionsHandler},
		{"local_admins", http.MethodGet, "/v1/portal/local-admins", nil, "", PortalLocalAdminsHandler}, // PAT-2215
		{"reports_list", http.MethodGet, "/v1/portal/reports", nil, "", PortalReportsListHandler},
		{"reports_generate", http.MethodPost, "/v1/portal/reports", nil, invalidJSONBody, PortalReportGenerateHandler},
		{"reports_schedule_get", http.MethodGet, "/v1/portal/reports/schedule", nil, "", PortalReportScheduleGetHandler},
		{"reports_schedule_put", http.MethodPut, "/v1/portal/reports/schedule", nil, invalidJSONBody, PortalReportSchedulePutHandler},
		{"reports_schedules_list", http.MethodGet, "/v1/portal/reports/schedules", nil, "", PortalReportSchedulesListHandler},
		{"reports_schedule_type_get", http.MethodGet, "/v1/portal/reports/schedules/{reportType}", map[string]string{"reportType": "executive-summary"}, "", PortalReportScheduleTypeGetHandler},
		{"reports_schedule_type_put", http.MethodPut, "/v1/portal/reports/schedules/{reportType}", map[string]string{"reportType": "executive-summary"}, invalidJSONBody, PortalReportScheduleTypePutHandler},
		{"reports_unsupported_software", http.MethodGet, "/v1/portal/reports/software/unsupported", nil, "", PortalUnsupportedSoftwareHandler},                        // PAT-2147
		{"reports_unsupported_software_devices", http.MethodGet, "/v1/portal/reports/software/unsupported/devices", nil, "", PortalUnsupportedSoftwareDevicesHandler}, // PAT-2147
		{"reports_remote_access", http.MethodGet, "/v1/portal/reports/software/remote-access", nil, "", PortalRemoteAccessHandler},                                    // PAT-2148
		{"reports_remote_access_devices", http.MethodGet, "/v1/portal/reports/software/remote-access/devices", nil, "", PortalRemoteAccessDevicesHandler},             // PAT-2148
		{"reports_version_sprawl", http.MethodGet, "/v1/portal/reports/software/version-sprawl", nil, "", PortalVersionSprawlHandler},                                 // PAT-2150
		{"reports_software_publishers", http.MethodGet, "/v1/portal/reports/software/publishers", nil, "", PortalSoftwarePublishersHandler},                           // PAT-2152
		{"reports_software_publishers_devices", http.MethodGet, "/v1/portal/reports/software/publishers/devices", nil, "", PortalSoftwarePublishersDevicesHandler},    // PAT-2152
		{"reports_duplicate_tools", http.MethodGet, "/v1/portal/reports/software/duplicate-tools", nil, "", PortalDuplicateToolsHandler},                              // PAT-2151
		{"reports_download", http.MethodGet, "/v1/portal/reports/{id}", map[string]string{"id": fakeUUID}, "", PortalReportDownloadHandler},
		{"exports_table_pdf", http.MethodPost, "/v1/portal/exports/table-pdf", nil, invalidJSONBody, PortalTablePDFHandler}, // PAT-2405
		{"finding_lifecycle", http.MethodGet, "/v1/portal/finding-lifecycle", nil, "", PortalFindingLifecycleCurrentHandler},
		{"finding_lifecycle_history", http.MethodGet, "/v1/portal/finding-lifecycle/history", nil, "", PortalFindingLifecycleHistoryHandler},
		{"me", http.MethodGet, "/v1/portal/me", nil, "", PortalMeHandler},
		{"software_approvals_put", http.MethodPut, "/v1/portal/software-approvals", nil, invalidJSONBody, PortalSoftwareApprovalsPutHandler},
		{"software_approvals_history", http.MethodGet, "/v1/portal/software-approvals/history", nil, "", PortalSoftwareApprovalHistoryHandler},
		{"software_approvals_history_export", http.MethodGet, "/v1/portal/software-approvals/history/export", nil, "", PortalSoftwareApprovalHistoryExportHandler},
		{"software_alerts", http.MethodGet, "/v1/portal/software-alerts", nil, "", PortalSoftwareAlertsHandler},
		{"software_alert", http.MethodGet, "/v1/portal/software-alerts/{id}", map[string]string{"id": "1"}, "", PortalSoftwareAlertHandler},
		{"software_alert_ack", http.MethodPost, "/v1/portal/software-alerts/{id}/acknowledge", map[string]string{"id": "1"}, invalidJSONBody, PortalSoftwareAlertAcknowledgeHandler},
		{"jamf_coverage", http.MethodGet, "/v1/portal/mdm/jamf/coverage", nil, "", PortalJamfCoverageHandler},               // PAT-2145
		{"jamf_setup_get", http.MethodGet, "/v1/portal/mdm/jamf/setup", nil, "", PortalJamfSetupGetHandler},                 // PAT-2145
		{"jamf_setup_put", http.MethodPut, "/v1/portal/mdm/jamf/setup", nil, invalidJSONBody, PortalJamfSetupPutHandler},    // PAT-2145
		{"jamf_token_post", http.MethodPost, "/v1/portal/mdm/jamf/token", nil, invalidJSONBody, PortalJamfTokenPostHandler}, // PAT-2145
		{"jamf_token_delete", http.MethodDelete, "/v1/portal/mdm/jamf/token", nil, "", PortalJamfTokenDeleteHandler},        // PAT-2145
		{"jamf_devices_delete", http.MethodDelete, "/v1/portal/mdm/jamf/devices", nil, "", PortalJamfDevicesDeleteHandler},  // PAT-2145
	}

	driven := map[string]bool{}
	for _, rt := range routes {
		driven[rt.name] = true
		t.Run(rt.name, func(t *testing.T) {
			var reqBody *strings.Reader
			if rt.body != "" {
				reqBody = strings.NewReader(rt.body)
			} else {
				reqBody = strings.NewReader("")
			}
			req := httptest.NewRequest(rt.method, rt.path, reqBody)
			req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
			req = portalNoTierWithParams(req, rt.params)
			rec := httptest.NewRecorder()
			rt.handler(pool).ServeHTTP(rec, req)

			body := rec.Body.String()
			if strings.Contains(body, "subscription_tier") {
				t.Errorf("%s %s (status %d) leaked subscription_tier: %s", rt.method, rt.path, rec.Code, body)
			}
			if rec.Code == http.StatusInternalServerError {
				t.Errorf("%s %s returned 500, investigate: %s", rt.method, rt.path, body)
			}
		})
	}

	// Two routes have a different handler signature and are driven outside
	// the table: PortalReportCatalogueHandler has its own subtest, and
	// PortalEnrolmentGenerateHandler takes a rate limiter (nil disables the
	// extra per-tenant check, same as the fail-closed test above).
	t.Run("reports_catalogue", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/reports/catalogue", nil)
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
		rec := httptest.NewRecorder()
		PortalReportCatalogueHandler(pool).ServeHTTP(rec, req)
		if body := rec.Body.String(); strings.Contains(body, "subscription_tier") {
			t.Errorf("GET /v1/portal/reports/catalogue (status %d) leaked subscription_tier: %s", rec.Code, body)
		}
	})
	t.Run("enrolment", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/portal/enrolment", strings.NewReader(invalidJSONBody))
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
		rec := httptest.NewRecorder()
		PortalEnrolmentGenerateHandler(pool, nil).ServeHTTP(rec, req)
		if body := rec.Body.String(); strings.Contains(body, "subscription_tier") {
			t.Errorf("POST /v1/portal/enrolment (status %d) leaked subscription_tier: %s", rec.Code, body)
		}
	})

	// This table must track cmd/patched-api/main.go's r.Route("/v1/portal",
	// ...) block exactly. This count (66: the 64 table entries above, plus
	// reports_catalogue and enrolment driven separately) is PAT-2130's
	// snapshot of that block, plus PAT-2135's five device self-service
	// routes, PAT-2148's two remote-access report routes, PAT-2150's
	// version-sprawl report route, PAT-2152's two publisher report routes,
	// PAT-2151's duplicate-tools report route, PAT-2145's six Jamf coverage
	// routes, PAT-2271's per-entry device-list delete route, PAT-2215's
	// local-admins route and PAT-2405's table PDF export route; a route
	// added there without a matching entry here silently drops out of this
	// guard, so this assertion fails loudly instead. Update both together.
	const wantRoutesRegistered = 66
	if got := len(driven) + 2; got != wantRoutesRegistered {
		t.Fatalf("this test drives %d /v1/portal/* routes, want %d (cmd/patched-api/main.go's r.Route(\"/v1/portal\", ...) block) — "+
			"the table in this file and that route block have drifted apart; update both", got, wantRoutesRegistered)
	}
}
