package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// newExtChiRequest builds a test request with tenantID (and optionally entryID)
// injected as chi URL params, mirroring newChiRequest in admin_app_control_test.go.
func newExtChiRequest(method, path, tenantID, entryID, body string) *http.Request {
	r := newChiRequest(method, path, tenantID, body)
	if entryID != "" {
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			rctx.URLParams.Add("entryID", entryID)
		}
	}
	return r
}

// --- GET — UUID guard ---

func TestExtensionPoliciesGet_InvalidUUID(t *testing.T) {
	handler := TenantExtensionPoliciesGetHandler(nil) // pool never reached for invalid UUIDs
	req := newExtChiRequest(http.MethodGet, "/admin/tenants/bad/extension-policies", "bad", "", "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

// --- POST — UUID, JSON, validation guards ---

func TestExtensionPolicyAdd_InvalidUUID(t *testing.T) {
	handler := TenantExtensionPolicyAddHandler(nil)
	req := newExtChiRequest(http.MethodPost, "/admin/tenants/bad/extension-policies", "bad", "",
		`{"extension_id":"abc"}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

func TestExtensionPolicyAdd_BadJSON(t *testing.T) {
	handler := TenantExtensionPolicyAddHandler(nil)
	req := newExtChiRequest(http.MethodPost, "/admin/tenants/"+acTestTenantID+"/extension-policies",
		acTestTenantID, "", `not json`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", rr.Code)
	}
}

func TestExtensionPolicyAdd_MissingExtensionID(t *testing.T) {
	handler := TenantExtensionPolicyAddHandler(nil)
	req := newExtChiRequest(http.MethodPost, "/admin/tenants/"+acTestTenantID+"/extension-policies",
		acTestTenantID, "", `{"extension_id":"   "}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing extension_id, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestExtensionPolicyAdd_InvalidBrowser(t *testing.T) {
	handler := TenantExtensionPolicyAddHandler(nil)
	req := newExtChiRequest(http.MethodPost, "/admin/tenants/"+acTestTenantID+"/extension-policies",
		acTestTenantID, "", `{"extension_id":"abc","browser":"opera"}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid browser, got %d: %s", rr.Code, rr.Body.String())
	}
}

// PAT-2071: Safari extensions (PAT-2064, device_browser_extensions
// browser='safari') need a Safari-specific policy vocabulary, so 'safari' is
// now a valid browser value for extension policies — the validation guard
// must accept it (not reject it as it did before this ticket).
func TestExtensionPolicyAdd_SafariIsValidBrowser(t *testing.T) {
	if !extensionValidBrowsers["safari"] {
		t.Fatal("safari must be a valid extension policy browser value (PAT-2071)")
	}
}

func TestExtensionPolicyAdd_InvalidPolicy(t *testing.T) {
	handler := TenantExtensionPolicyAddHandler(nil)
	req := newExtChiRequest(http.MethodPost, "/admin/tenants/"+acTestTenantID+"/extension-policies",
		acTestTenantID, "", `{"extension_id":"abc","policy":"banned"}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid policy, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- PUT — UUID, entryID, JSON, validation guards ---

func TestExtensionPolicyUpdate_InvalidUUID(t *testing.T) {
	handler := TenantExtensionPolicyUpdateHandler(nil)
	req := newExtChiRequest(http.MethodPut, "/admin/tenants/bad/extension-policies/1", "bad", "1",
		`{"policy":"approved"}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

func TestExtensionPolicyUpdate_BadEntryID(t *testing.T) {
	handler := TenantExtensionPolicyUpdateHandler(nil)
	req := newExtChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/extension-policies/notint",
		acTestTenantID, "notint", `{"policy":"approved"}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-integer entryID, got %d", rr.Code)
	}
}

func TestExtensionPolicyUpdate_BadJSON(t *testing.T) {
	handler := TenantExtensionPolicyUpdateHandler(nil)
	req := newExtChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/extension-policies/1",
		acTestTenantID, "1", `{bad}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", rr.Code)
	}
}

func TestExtensionPolicyUpdate_InvalidPolicy(t *testing.T) {
	handler := TenantExtensionPolicyUpdateHandler(nil)
	req := newExtChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/extension-policies/1",
		acTestTenantID, "1", `{"policy":"nope"}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid policy, got %d", rr.Code)
	}
}

// --- DELETE — UUID, entryID guards ---

func TestExtensionPolicyDelete_InvalidUUID(t *testing.T) {
	handler := TenantExtensionPolicyDeleteHandler(nil)
	req := newExtChiRequest(http.MethodDelete, "/admin/tenants/bad/extension-policies/1", "bad", "1", "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

func TestExtensionPolicyDelete_BadEntryID(t *testing.T) {
	handler := TenantExtensionPolicyDeleteHandler(nil)
	req := newExtChiRequest(http.MethodDelete, "/admin/tenants/"+acTestTenantID+"/extension-policies/x",
		acTestTenantID, "x", "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-integer entryID, got %d", rr.Code)
	}
}

// --- scan — UUID guard ---

func TestExtensionPolicyScan_InvalidUUID(t *testing.T) {
	handler := TenantExtensionPolicyScanHandler(nil)
	req := newExtChiRequest(http.MethodGet, "/admin/tenants/bad/extension-policies/scan", "bad", "", "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

// --- normalizeOptionalString unit tests ---

func TestNormalizeOptionalString(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		name string
		in   *string
		want *string
	}{
		{"nil", nil, nil},
		{"empty", s(""), nil},
		{"whitespace", s("   "), nil},
		{"trimmed", s("  Acme  "), s("Acme")},
		{"plain", s("Acme"), s("Acme")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeOptionalString(tc.in)
			switch {
			case got == nil && tc.want == nil:
				// ok
			case got == nil || tc.want == nil:
				t.Fatalf("got %v, want %v", got, tc.want)
			case *got != *tc.want:
				t.Fatalf("got %q, want %q", *got, *tc.want)
			}
		})
	}
}
