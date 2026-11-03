package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newChiRequest builds a test request with the given tenantID injected as a chi URL param.
func newChiRequest(method, path, tenantID, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	return acWithTenantID(r, tenantID)
}

// --- GET handler — UUID guard ---

func TestAppControlGet_InvalidUUID(t *testing.T) {
	handler := AppControlGetHandler(nil) // pool never reached for invalid UUIDs
	req := newChiRequest(http.MethodGet, "/admin/tenants/notauuid/app-control", "notauuid", "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

// --- PUT /admins — UUID, JSON, validation guards ---

func TestAppControlAdminsPut_InvalidUUID(t *testing.T) {
	handler := AppControlAdminsPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/bad/app-control/admins", "bad", `{"approved_admins":["alice"]}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

func TestAppControlAdminsPut_BadJSON(t *testing.T) {
	handler := AppControlAdminsPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/app-control/admins", acTestTenantID, `not json`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", rr.Code)
	}
}

func TestAppControlAdminsPut_EmptyEntry(t *testing.T) {
	handler := AppControlAdminsPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/app-control/admins", acTestTenantID,
		`{"approved_admins":["alice",""]}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty entry, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAppControlAdminsPut_WhitespaceEntry(t *testing.T) {
	handler := AppControlAdminsPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/app-control/admins", acTestTenantID,
		`{"approved_admins":["   "]}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for whitespace-only entry, got %d", rr.Code)
	}
}

// --- PUT /allowlist — UUID, JSON, validation guards ---

func TestAppControlAllowlistPut_InvalidUUID(t *testing.T) {
	handler := AppControlAllowlistPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/bad/app-control/allowlist", "bad", `{"app_allowlist":["com.apple.Safari"]}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid UUID, got %d", rr.Code)
	}
}

func TestAppControlAllowlistPut_BadJSON(t *testing.T) {
	handler := AppControlAllowlistPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/app-control/allowlist", acTestTenantID, `{bad}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", rr.Code)
	}
}

func TestAppControlAllowlistPut_EmptyEntry(t *testing.T) {
	handler := AppControlAllowlistPutHandler(nil)
	req := newChiRequest(http.MethodPut, "/admin/tenants/"+acTestTenantID+"/app-control/allowlist", acTestTenantID,
		`{"app_allowlist":["com.apple.Safari",""]}`)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty entry, got %d", rr.Code)
	}
}

// --- validateStringSlice unit tests ---

func TestValidateStringSlice(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{"nil slice", nil, false},
		{"empty slice", []string{}, false},
		{"valid single", []string{"alice"}, false},
		{"valid multiple", []string{"alice", `DOMAIN\bob`, "com.apple.Safari"}, false},
		{"empty string element", []string{"alice", ""}, true},
		{"whitespace-only element", []string{"   "}, true},
		{"tab-only element", []string{"\t"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStringSlice("field", tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateStringSlice(%v) error=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}
