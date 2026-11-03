package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
)

// The integration parity guard invokes this to enumerate the actual production
// constructor. No HTTP request or database access is made by this test.
func TestPAT2539ProductionRouteManifest(t *testing.T) {
	output := os.Getenv("PAT2539_ROUTE_MANIFEST")
	if output == "" {
		t.Skip("manifest requested only by integration parity guard")
	}
	limiter := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	router := newPublicRouter(nil, nil, limiter, 5*time.Minute, portalauth.New("https://fixture.invalid", "fixture", "https://fixture.invalid"), limiter, limiter, "", "", nil, nil, "", nil, "", nil)
	var routes []string
	if err := chi.Walk(router.(chi.Routes), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(routes)
	data, err := json.Marshal(routes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPAT2539JamfUnknownOSIsVisible(t *testing.T) {
	f := pat2393Fixture(t)
	_, bareID := pat2538SeedDevices(t, f)
	// A known Windows row remains genuinely excluded. The NULL OS row does not.
	f.exec(t, `INSERT INTO devices(tenant_id,hostname,os) VALUES($1::uuid,'known-windows','Windows')`, f.tenant)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/mdm/jamf/coverage", nil)
	req.Header.Set(portalauth.Header, f.admin)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("coverage = %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Counts struct {
			NonMac        int  `json:"non_mac_devices_excluded"`
			OSNotReported *int `json:"os_not_reported"`
		} `json:"counts"`
		OSNotReported struct {
			Total int `json:"total"`
			Rows  []struct {
				DeviceID string `json:"device_id"`
			} `json:"rows"`
		} `json:"os_not_reported"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Counts.NonMac != 1 {
		t.Errorf("non-Mac excluded=%d, want only the known Windows device (1)", out.Counts.NonMac)
	}
	if out.Counts.OSNotReported == nil || *out.Counts.OSNotReported != 1 {
		t.Errorf("OS not yet reported count=%v, want 1", out.Counts.OSNotReported)
	}
	if out.OSNotReported.Total != 1 || len(out.OSNotReported.Rows) != 1 || out.OSNotReported.Rows[0].DeviceID != bareID {
		t.Errorf("OS not yet reported bucket=%+v, want NULL OS device %s", out.OSNotReported, bareID)
	}
}
