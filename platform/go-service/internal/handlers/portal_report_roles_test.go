package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/portalauth"
)

// PAT-2406: an identity with no email (the read-only service identity, or
// anything else that can never match a portal_users row) is a viewer without
// any database read, so the Local Admin report is refused before the pool is
// touched. The pool is nil: reaching generation would panic into a failure.
func TestPortalReportGenerateRefusesLocalAdminForAnEmailLessIdentityBeforeDB(t *testing.T) {
	for _, body := range []string{`{"report_type":"local-admin"}`, `{"type":"local-admin"}`} {
		req := httptest.NewRequest(http.MethodPost, "/v1/portal/reports", strings.NewReader(body))
		req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{
			TenantID: "5f9c1a2b-0000-0000-0000-000000000001", Service: "svc",
		}))
		rr := httptest.NewRecorder()
		PortalReportGenerateHandler(nil).ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s = %d, want 403; body %q", body, rr.Code, rr.Body.String())
		}
		var out struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&out); err != nil || out.Error != "admin_role_required" {
			t.Fatalf("%s body error = %q (decode err %v), want admin_role_required", body, out.Error, err)
		}
		if !strings.Contains(out.Message, "viewer") {
			t.Errorf("%s message = %q, want it to name the caller's role", body, out.Message)
		}
	}
}
