package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

func TestReportCatalogueHandlerReturnsAllEntries(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/reports/catalogue", nil)
	rr := httptest.NewRecorder()
	ReportCatalogueHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Reports []report.ReportDefinition `json:"reports"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Reports) != 19 {
		t.Fatalf("reports = %d, want 19", len(body.Reports))
	}
}

func catalogueRole(role string, err error) portalRoleLookup {
	return func(context.Context, portalauth.Identity) (string, error) { return role, err }
}

func portalCatalogueGet(t *testing.T, h http.Handler, id *portalauth.Identity) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/reports/catalogue", nil)
	if id != nil {
		req = req.WithContext(portalauth.WithIdentity(req.Context(), *id))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func portalCatalogueEntries(t *testing.T, rr *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %q", rr.Code, rr.Body.String())
	}
	var body struct {
		Reports []map[string]any `json:"reports"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Reports
}

var catalogueCaller = portalauth.Identity{
	Email: "portal@example.test", TenantID: "1e8b6c1e-0000-0000-0000-000000000001",
}

func TestPortalReportCatalogueRequiresIdentityAndHidesAdminMetadata(t *testing.T) {
	// A nil pool: an unauthenticated request must be refused before any
	// role read, which would panic.
	if rr := portalCatalogueGet(t, PortalReportCatalogueHandler(nil), nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rr.Code)
	}

	reports := portalCatalogueEntries(t, portalCatalogueGet(t,
		portalReportCatalogueHandler(catalogueRole(portalauth.RoleAdmin, nil)), &catalogueCaller))
	if len(reports) != 14 {
		t.Fatalf("admin portal reports = %d entries, want 14", len(reports))
	}
	for _, entry := range reports {
		if _, leaked := entry["admin_pdf_path"]; leaked {
			t.Fatalf("portal catalogue leaked admin_pdf_path: %#v", entry)
		}
		if _, leaked := entry["customer_facing"]; leaked {
			t.Fatalf("portal catalogue leaked internal flag: %#v", entry)
		}
	}
}

// PAT-2406: the Local Admin report is offered to an admin only. An admin sees
// it flagged admin_only; nobody else is sent the entry at all, and no other
// entry carries the field (it is additive for existing clients).
func TestPortalReportCatalogueOffersAdminOnlyReportsToAdminsOnly(t *testing.T) {
	admin := portalCatalogueEntries(t, portalCatalogueGet(t,
		portalReportCatalogueHandler(catalogueRole(portalauth.RoleAdmin, nil)), &catalogueCaller))
	flagged := []string{}
	for _, entry := range admin {
		v, present := entry["admin_only"]
		if !present {
			continue
		}
		if v != true {
			t.Errorf("%v admin_only = %v, want the field absent or true", entry["type"], v)
		}
		flagged = append(flagged, entry["type"].(string))
	}
	if len(flagged) != 1 || flagged[0] != "local-admin" {
		t.Fatalf("admin_only entries = %v, want [local-admin]", flagged)
	}

	// The service identity has no email and is never more than a viewer.
	service := portalauth.Identity{TenantID: catalogueCaller.TenantID, Service: "svc"}
	for name, rr := range map[string]*httptest.ResponseRecorder{
		"viewer": portalCatalogueGet(t, portalReportCatalogueHandler(catalogueRole(portalauth.RoleViewer, nil)), &catalogueCaller),
		// PAT-1883 made "owner" a real role (below), so the stand-ins for a
		// role this binary does not know are now other strings.
		"unknown role":     portalCatalogueGet(t, portalReportCatalogueHandler(catalogueRole("superuser", nil)), &catalogueCaller),
		"empty role":       portalCatalogueGet(t, portalReportCatalogueHandler(catalogueRole("", nil)), &catalogueCaller),
		"case variant":     portalCatalogueGet(t, portalReportCatalogueHandler(catalogueRole("Owner", nil)), &catalogueCaller),
		"service role":     portalCatalogueGet(t, portalReportCatalogueHandler(catalogueRole(portalauth.RoleServiceReadOnly, nil)), &catalogueCaller),
		"service identity": portalCatalogueGet(t, PortalReportCatalogueHandler(nil), &service),
	} {
		entries := portalCatalogueEntries(t, rr)
		if len(entries) != 13 {
			t.Errorf("%s catalogue = %d entries, want 13", name, len(entries))
		}
		for _, entry := range entries {
			if _, present := entry["admin_only"]; present || entry["type"] == "local-admin" {
				t.Errorf("%s catalogue offers an admin-only report: %#v", name, entry)
			}
		}
	}
}

// PAT-1883: an owner can do everything an admin can, so the admin-only report
// is offered to an owner exactly as it is to an admin.
func TestPortalReportCatalogueOffersAdminOnlyReportsToOwners(t *testing.T) {
	admin := portalCatalogueEntries(t, portalCatalogueGet(t,
		portalReportCatalogueHandler(catalogueRole(portalauth.RoleAdmin, nil)), &catalogueCaller))
	owner := portalCatalogueEntries(t, portalCatalogueGet(t,
		portalReportCatalogueHandler(catalogueRole(portalauth.RoleOwner, nil)), &catalogueCaller))
	if len(owner) != 14 || len(owner) != len(admin) {
		t.Fatalf("owner catalogue = %d entries, admin = %d, want 14 for both", len(owner), len(admin))
	}
	offered := false
	for _, entry := range owner {
		if entry["type"] == "local-admin" && entry["admin_only"] == true {
			offered = true
		}
	}
	if !offered {
		t.Fatal("owner catalogue does not offer the admin-only local-admin report")
	}
}

// A failed role lookup must never fall through to the full catalogue.
func TestPortalReportCatalogueRoleLookupFailureIs500(t *testing.T) {
	rr := portalCatalogueGet(t, portalReportCatalogueHandler(catalogueRole("", io.ErrUnexpectedEOF)), &catalogueCaller)
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "local-admin") {
		t.Fatalf("role lookup failure = %d %q, want 500 and no catalogue", rr.Code, rr.Body.String())
	}
}
