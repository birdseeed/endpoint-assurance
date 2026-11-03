package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"patched.im/api/internal/auth"
)

// PAT-2246: GET /v1/catalogue is retired. Every request, authenticated or
// not, conditional or not, gets the same bodyless-of-data 410.
func TestCatalogueGet_RetiredAnswers410WithoutAuth(t *testing.T) {
	handler := CatalogueHandler()
	for name, mutate := range map[string]func(*http.Request){
		"no credentials":  func(*http.Request) {},
		"bogus bearer":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") },
		"if-none-match *": func(r *http.Request) { r.Header.Set("If-None-Match", "*") },
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/catalogue", nil)
			mutate(req)
			rr := httptest.NewRecorder()
			handler(rr, req)
			assertCatalogueRetired(t, rr)
		})
	}
}

func assertCatalogueRetired(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410: %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != catalogueRetiredBody {
		t.Fatalf("body = %q, want %q", rr.Body.String(), catalogueRetiredBody)
	}
	if rr.Header().Get("ETag") != "" {
		t.Fatalf("retired route must not emit an ETag, got %q", rr.Header().Get("ETag"))
	}
}

// TestCatalogueGet_DB_ValidDeviceAuthStill410 drives the retired route with a
// correctly v3-signed device credential against a real database. It must
// still answer 410, and must not have consumed the nonce: the route does no
// authentication and touches no table.
func TestCatalogueGet_DB_ValidDeviceAuthStill410(t *testing.T) {
	pool := adConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		tenantBearer = "pat2246-catalogue-tenant-token"
		tenantSecret = "pat2246-catalogue-tenant-hmac"
		deviceBearer = "pat2246-catalogue-device-token"
		deviceSecret = "pat2246-catalogue-device-hmac"
	)
	tenantID := parSeedTenant(t, ctx, pool, "pat2246-catalogue-retired", tenantBearer, tenantSecret)
	deviceID := adSeedDevice(t, ctx, pool, tenantID, "2246bbbb-0000-4000-8000-000000002246", "catalogue-poller")
	adSeedDeviceCredential(t, ctx, pool, tenantID, deviceID, deviceBearer, deviceSecret)

	req := aadV3Request(t, http.MethodGet, "/v1/catalogue", auth.EndpointID("catalogue"), deviceBearer, deviceSecret)
	rr := httptest.NewRecorder()
	CatalogueHandler()(rr, req)
	assertCatalogueRetired(t, rr)

	var nonces int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM seen_nonces WHERE tenant_id = $1::uuid`, tenantID).Scan(&nonces); err != nil {
		t.Fatalf("count nonces: %v", err)
	}
	if nonces != 0 {
		t.Fatalf("retired route consumed %d nonce(s); it must not authenticate or write", nonces)
	}
}
