//go:build integration

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPortalReportCatalogueAndTypedGeneration(t *testing.T) {
	a := seedPortalTenant(t, "report-types-a", "alice@report-types.example", "CVE-2099-2020")

	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/catalogue", a.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET catalogue = %d", resp.StatusCode)
	}
	var catalogue struct {
		Reports []struct {
			Type string `json:"type"`
		} `json:"reports"`
	}
	decodeJSON(t, resp, &catalogue)
	// PAT-2406: seedPortalTenant maps a viewer, who is offered every
	// customer-facing type except the admin-only Local Admin report.
	if len(catalogue.Reports) != 13 {
		t.Fatalf("viewer portal catalogue length = %d, want 13", len(catalogue.Reports))
	}
	for _, entry := range catalogue.Reports {
		if entry.Type == "local-admin" {
			t.Fatalf("viewer portal catalogue offers local-admin")
		}
	}

	for _, body := range []string{
		`{"report_type":"not-real"}`,
		`{"report_type":"software-inventory"}`,
		`{"report_type":"device-compliance"}`,
	} {
		resp = portalDo(t, http.MethodPost, "/v1/portal/reports", a.token, strings.NewReader(body))
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST rejected type body %s = %d, want 400", body, resp.StatusCode)
		}
	}

	resp = portalDo(t, http.MethodPost, "/v1/portal/reports", a.token,
		strings.NewReader(`{"type":"patch-status","name":"Patch evidence"}`))
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST patch-status = %d: %s", resp.StatusCode, raw)
	}
	var created struct {
		ID          string `json:"id"`
		ReportType  string `json:"report_type"`
		ReportLabel string `json:"report_label"`
	}
	decodeJSON(t, resp, &created)
	if created.ID == "" || created.ReportType != "patch-status" || created.ReportLabel != "Patch & Update Status" {
		t.Fatalf("created report = %+v", created)
	}

	var storedType string
	if err := env.pool.QueryRow(t.Context(), `
		SELECT report_type FROM report_records
		WHERE id = $1::uuid AND tenant_id = $2::uuid AND source = 'portal'
	`, created.ID, a.tenantID).Scan(&storedType); err != nil {
		t.Fatal(err)
	}
	if storedType != "patch-status" {
		t.Fatalf("stored report_type = %q", storedType)
	}

	// PAT-2258: the insurance evidence pack is generated through the same
	// catalogue path, and its JSON read model is served on the portal API.
	resp = portalDo(t, http.MethodPost, "/v1/portal/reports", a.token,
		strings.NewReader(`{"report_type":"insurance-evidence"}`))
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST insurance-evidence = %d: %s", resp.StatusCode, raw)
	}
	resp.Body.Close()
	resp = portalDo(t, http.MethodGet, "/v1/portal/insurance-evidence", a.token, nil)
	var pack struct {
		Questions []struct {
			ID string `json:"id"`
		} `json:"questions"`
	}
	decodeJSON(t, resp, &pack)
	if len(pack.Questions) != 12 {
		t.Fatalf("insurance evidence questions = %d, want 12", len(pack.Questions))
	}
	if _, err := env.pool.Exec(t.Context(), `DELETE FROM report_records WHERE tenant_id = $1::uuid AND report_type = 'insurance-evidence'`, a.tenantID); err != nil {
		t.Fatal(err)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/reports", a.token, nil)
	var history struct {
		Reports []struct {
			ID          string `json:"id"`
			ReportType  string `json:"report_type"`
			ReportLabel string `json:"report_label"`
		} `json:"reports"`
	}
	decodeJSON(t, resp, &history)
	if len(history.Reports) != 1 || history.Reports[0].ReportType != "patch-status" || history.Reports[0].ReportLabel == "" {
		t.Fatalf("typed history = %+v", history.Reports)
	}
}

func TestPortalTypedScheduleIsolation(t *testing.T) {
	a := seedPortalTenant(t, "typed-schedule-a", "alice@typed-schedule-a.example", "CVE-2099-2021")
	b := seedPortalTenant(t, "typed-schedule-b", "bob@typed-schedule-b.example", "CVE-2099-2022")
	// PAT-2408: only an admin changes a schedule (seedPortalTenant maps a viewer).
	mapPortalUserWithRole(t, a.email, a.tenantID, "admin")
	mapPortalUserWithRole(t, b.email, b.tenantID, "admin")
	body := `{"cadence":"weekly","weekday":2,"hour_utc":8,"enabled":true}`

	for _, reportType := range []string{"executive-summary", "patch-status"} {
		resp := portalDo(t, http.MethodPut, "/v1/portal/reports/schedules/"+reportType,
			a.token, strings.NewReader(body))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s schedule = %d", reportType, resp.StatusCode)
		}
		resp.Body.Close()
	}

	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/schedules", a.token, nil)
	var own struct {
		Schedules []struct {
			ReportType string `json:"report_type"`
		} `json:"schedules"`
	}
	decodeJSON(t, resp, &own)
	if len(own.Schedules) != 2 || own.Schedules[0].ReportType == own.Schedules[1].ReportType {
		t.Fatalf("tenant A schedules = %+v, want two independent types", own.Schedules)
	}

	resp = portalDo(t, http.MethodGet, "/v1/portal/reports/schedules", b.token, nil)
	var other struct {
		Schedules []any `json:"schedules"`
	}
	decodeJSON(t, resp, &other)
	if len(other.Schedules) != 0 {
		t.Fatalf("tenant B saw tenant A schedules: %+v", other.Schedules)
	}

	resp = portalDo(t, http.MethodPut, "/v1/portal/reports/schedules/software-inventory",
		a.token, strings.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT non-customer schedule = %d, want 400", resp.StatusCode)
	}
}
