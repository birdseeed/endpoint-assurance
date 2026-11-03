package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TenantExportHandler must reject a non-UUID tenantID before touching the pool,
// so a nil pool is safe here (mirrors admin_lifecycle_test.go).
func TestTenantExportHandlerUUIDValidation(t *testing.T) {
	cases := []struct {
		id   string
		want int
	}{
		{"not-a-uuid", http.StatusBadRequest},
		{"gggggggg-0000-0000-0000-000000000000", http.StatusBadRequest},
		{"", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			h := TenantExportHandler(nil)
			req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tc.id+"/export", nil)
			req = withChiParam(req, "tenantID", tc.id)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Errorf("got %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

// A present-but-blank ?user= must be rejected before any DB access, so a whole-
// tenant export is never returned in place of a single-person DSR export. The
// guard runs before the pool is touched, so a nil pool is safe.
func TestTenantExportHandlerBlankUserRejected(t *testing.T) {
	const validUUID = "11111111-1111-1111-1111-111111111111"
	for _, raw := range []string{"?user=", "?user=%20"} {
		t.Run(raw, func(t *testing.T) {
			h := TenantExportHandler(nil)
			req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+validUUID+"/export"+raw, nil)
			req = withChiParam(req, "tenantID", validUUID)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("blank user %q: got %d, want %d", raw, rr.Code, http.StatusBadRequest)
			}
		})
	}
}
