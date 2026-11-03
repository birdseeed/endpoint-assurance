package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/portalauth"
)

// ---------------------------------------------------------------------------
// Fail closed without identity — the guard against the schedule routes ever
// being mounted outside portalauth.Middleware (PAT-703).
// ---------------------------------------------------------------------------

func TestPortalScheduleHandlersWithoutIdentityFailClosed(t *testing.T) {
	handlersUnderTest := map[string]http.HandlerFunc{
		"schedule_get": PortalReportScheduleGetHandler(nil),
		"schedule_put": PortalReportSchedulePutHandler(nil),
	}
	for name, h := range handlersUnderTest {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/portal/reports/schedule", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 (fail closed without identity)", rr.Code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PUT validation — every rejection fires BEFORE any DB access (pool is nil;
// a query would panic), proving the handler fails closed on bad input.
// ---------------------------------------------------------------------------

func schedulePut(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v1/portal/reports/schedule",
		strings.NewReader(body))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
		Email:    "customer@example.com",
		TenantID: "5f9c1a2b-0000-0000-0000-000000000001",
	}))
	rr := httptest.NewRecorder()
	PortalReportSchedulePutHandler(nil).ServeHTTP(rr, req)
	return rr
}

func TestPortalSchedulePutValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"not JSON", `not json`},
		{"unknown field rejected", `{"cadence":"daily","hour_utc":7,"enabled":true,"tenant_id":"attacker"}`},
		{"client-supplied next_run_at rejected", `{"cadence":"daily","hour_utc":7,"enabled":true,"next_run_at":"2020-01-01T00:00:00Z"}`},
		{"missing cadence", `{"hour_utc":7,"enabled":true}`},
		{"bad cadence", `{"cadence":"hourly","hour_utc":7,"enabled":true}`},
		{"admin-only cadence rejected", `{"cadence":"quarterly","hour_utc":7,"enabled":true}`},
		{"missing hour", `{"cadence":"daily","enabled":true}`},
		{"hour too high", `{"cadence":"daily","hour_utc":24,"enabled":true}`},
		{"hour negative", `{"cadence":"daily","hour_utc":-1,"enabled":true}`},
		{"missing enabled", `{"cadence":"daily","hour_utc":7}`},
		{"daily with weekday", `{"cadence":"daily","weekday":1,"hour_utc":7,"enabled":true}`},
		{"daily with month_day", `{"cadence":"daily","month_day":1,"hour_utc":7,"enabled":true}`},
		{"weekly missing weekday", `{"cadence":"weekly","hour_utc":7,"enabled":true}`},
		{"weekly weekday out of range", `{"cadence":"weekly","weekday":7,"hour_utc":7,"enabled":true}`},
		{"weekly negative weekday", `{"cadence":"weekly","weekday":-1,"hour_utc":7,"enabled":true}`},
		{"weekly with month_day", `{"cadence":"weekly","weekday":1,"month_day":3,"hour_utc":7,"enabled":true}`},
		{"monthly missing month_day", `{"cadence":"monthly","hour_utc":7,"enabled":true}`},
		{"monthly month_day zero", `{"cadence":"monthly","month_day":0,"hour_utc":7,"enabled":true}`},
		{"monthly month_day 32", `{"cadence":"monthly","month_day":32,"hour_utc":7,"enabled":true}`},
		{"monthly with weekday", `{"cadence":"monthly","weekday":1,"month_day":3,"hour_utc":7,"enabled":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := schedulePut(t, tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestPortalSchedulePutReqValidateAccepts(t *testing.T) {
	i := func(n int) *int { return &n }
	b := func(v bool) *bool { return &v }
	cases := []struct {
		name string
		req  portalSchedulePutReq
	}{
		{"daily", portalSchedulePutReq{Cadence: "daily", HourUTC: i(7), Enabled: b(true)}},
		{"weekly monday", portalSchedulePutReq{Cadence: "weekly", Weekday: i(1), HourUTC: i(7), Enabled: b(true)}},
		{"weekly sunday", portalSchedulePutReq{Cadence: "weekly", Weekday: i(0), HourUTC: i(0), Enabled: b(false)}},
		{"monthly 31st", portalSchedulePutReq{Cadence: "monthly", MonthDay: i(31), HourUTC: i(23), Enabled: b(true)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reason := tc.req.validate(); reason != "" {
				t.Errorf("validate() = %q, want accept", reason)
			}
		})
	}
}
