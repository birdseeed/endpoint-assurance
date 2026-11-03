package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/extractor"
)

const (
	certTestTenantID = "550e8400-e29b-41d4-a716-446655440000"
	certTestDeviceID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

func certTestExistsAlways(_ context.Context, _ string) (bool, error) { return true, nil }
func certTestExistsNever(_ context.Context, _ string) (bool, error)  { return false, nil }

func certTestSampleRow(deviceID string) extractor.CertRow {
	return extractor.CertRow{
		DeviceID:                    deviceID,
		SubjectCN:                   "Test Leaf",
		IssuerCN:                    "Test CA",
		SHA1:                        "aabbccddeeff00112233445566778899aabbccdd",
		NotAfter:                    time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
		DaysUntilExpiryAtCollection: 588,
		CollectedAt:                 time.Date(2026, 12, 6, 9, 0, 0, 0, time.UTC),
		EKU:                         []string{"1.3.6.1.5.5.7.3.3"},
		BasicConstraintsCA:          false,
		IsSelfSigned:                false,
	}
}

// certTestWithTenantID injects a chi tenant_id URL param into the request
// context so the handler can retrieve it without a full chi router.
func certTestWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenant_id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestCertsEndpointEmptyTenant checks that a known tenant with no certs returns
// an empty JSON array (not null) with HTTP 200.
func TestCertsEndpointEmptyTenant(t *testing.T) {
	handler := newTenantCertsHandler(
		certTestExistsAlways,
		func(_ context.Context, _ string, _ extractor.ListCertsFilter) ([]extractor.CertRow, error) {
			return nil, nil
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant/"+certTestTenantID+"/certs", nil)
	req = certTestWithTenantID(req, certTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got []certResp
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got == nil {
		t.Error("want [] (non-null empty array), got null")
	}
	if len(got) != 0 {
		t.Errorf("want empty array, got %d certs", len(got))
	}
}

// TestCertsEndpointDeviceFilter verifies that ?device_id= is forwarded to the
// cert lister and that only the matching device's certs are returned.
func TestCertsEndpointDeviceFilter(t *testing.T) {
	otherDeviceID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	allCerts := []extractor.CertRow{
		certTestSampleRow(certTestDeviceID),
		certTestSampleRow(otherDeviceID),
	}

	var capturedFilter extractor.ListCertsFilter
	listFn := func(_ context.Context, _ string, f extractor.ListCertsFilter) ([]extractor.CertRow, error) {
		capturedFilter = f
		var out []extractor.CertRow
		for _, c := range allCerts {
			if f.DeviceID == "" || c.DeviceID == f.DeviceID {
				out = append(out, c)
			}
		}
		return out, nil
	}
	handler := newTenantCertsHandler(certTestExistsAlways, listFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant/"+certTestTenantID+"/certs?device_id="+certTestDeviceID, nil)
	req = certTestWithTenantID(req, certTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if capturedFilter.DeviceID != certTestDeviceID {
		t.Errorf("want filter.DeviceID=%q, got %q", certTestDeviceID, capturedFilter.DeviceID)
	}
	var got []certResp
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 cert for device filter, got %d", len(got))
	}
	if got[0].DeviceID != certTestDeviceID {
		t.Errorf("want device_id=%q, got %q", certTestDeviceID, got[0].DeviceID)
	}
}

// TestCertsEndpointExpiringFilter verifies that ?expiring_within_days= is
// forwarded to the cert lister, including already-expired certs.
func TestCertsEndpointExpiringFilter(t *testing.T) {
	expiringSoon := certTestSampleRow(certTestDeviceID)
	expiringSoon.NotAfter = time.Now().Add(10 * 24 * time.Hour) // 10 days from now

	var capturedFilter extractor.ListCertsFilter
	listFn := func(_ context.Context, _ string, f extractor.ListCertsFilter) ([]extractor.CertRow, error) {
		capturedFilter = f
		if f.ExpiringWithinDays > 0 {
			return []extractor.CertRow{expiringSoon}, nil
		}
		return nil, nil
	}
	handler := newTenantCertsHandler(certTestExistsAlways, listFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant/"+certTestTenantID+"/certs?expiring_within_days=30", nil)
	req = certTestWithTenantID(req, certTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if capturedFilter.ExpiringWithinDays != 30 {
		t.Errorf("want ExpiringWithinDays=30, got %d", capturedFilter.ExpiringWithinDays)
	}
	var got []certResp
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 expiring cert, got %d", len(got))
	}
}

// TestCertsEndpointFieldShape asserts that every element in the response has
// exactly the ten expected snake_case JSON keys — no Go-field-name leakage.
func TestCertsEndpointFieldShape(t *testing.T) {
	cert := certTestSampleRow(certTestDeviceID)
	listFn := func(_ context.Context, _ string, _ extractor.ListCertsFilter) ([]extractor.CertRow, error) {
		return []extractor.CertRow{cert}, nil
	}
	handler := newTenantCertsHandler(certTestExistsAlways, listFn)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant/"+certTestTenantID+"/certs", nil)
	req = certTestWithTenantID(req, certTestTenantID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var raw []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("want 1 element, got %d", len(raw))
	}

	wantKeys := []string{
		"device_id", "subject_cn", "issuer_cn", "sha1",
		"not_after", "days_until_expiry_at_collection",
		"ext_key_usage", "basic_constraints_ca", "is_self_signed", "collected_at",
	}
	gotKeys := make([]string, 0, len(raw[0]))
	for k := range raw[0] {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(wantKeys)
	sort.Strings(gotKeys)

	if len(wantKeys) != len(gotKeys) {
		t.Fatalf("want %d keys %v, got %d keys %v", len(wantKeys), wantKeys, len(gotKeys), gotKeys)
	}
	for i := range wantKeys {
		if wantKeys[i] != gotKeys[i] {
			t.Errorf("key[%d]: want %q, got %q", i, wantKeys[i], gotKeys[i])
		}
	}
}

// TestCertsEndpointUnknownTenant asserts that a valid UUID that is not in the
// tenant table returns HTTP 404 and does not invoke the cert lister.
func TestCertsEndpointUnknownTenant(t *testing.T) {
	listFn := func(_ context.Context, _ string, _ extractor.ListCertsFilter) ([]extractor.CertRow, error) {
		t.Error("listFn must not be called for an unknown tenant")
		return nil, nil
	}
	handler := newTenantCertsHandler(certTestExistsNever, listFn)

	unknownUUID := "11111111-2222-3333-4444-555555555555"
	req := httptest.NewRequest(http.MethodGet, "/admin/tenant/"+unknownUUID+"/certs", nil)
	req = certTestWithTenantID(req, unknownUUID)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
