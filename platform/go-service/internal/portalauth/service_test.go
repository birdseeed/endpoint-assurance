package portalauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"patched.im/api/internal/ratelimit"
)

// PAT-2257: the read-only service identity. Placeholder values only.
const (
	testServiceCN     = "walker-test.access"
	testServiceTenant = "00000000-0000-4000-8000-00000000000a"
)

func serviceIdP(t *testing.T) *testIdP {
	t.Helper()
	idp := newTestIdP(t)
	idp.verifier.WithService(&ServiceIdentity{CommonName: testServiceCN, TenantID: testServiceTenant})
	return idp
}

func liveTenant(_ context.Context, tenantID string) error {
	if tenantID != testServiceTenant {
		return ErrServiceTenantInactive
	}
	return nil
}

type auditEntry struct {
	name, tenant, method string
	status               int
}

type auditRecorder struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (a *auditRecorder) fn() AuditFunc {
	return func(name, tenantID, method, _ string, status int) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.entries = append(a.entries, auditEntry{name, tenantID, method, status})
	}
}

// identityEcho writes the context identity back, and counts calls so a
// refused request can be proved never to have reached a handler.
func identityEcho(calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		id, ok := FromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"tenant_id": id.TenantID, "email": id.Email, "service": id.Service,
		})
	})
}

func serviceDo(t *testing.T, h http.Handler, method, url, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set(Header, token)
	}
	req.Header.Set("X-Tenant-ID", "tenant-B")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// --- config -------------------------------------------------------------

func TestServiceIdentityFromEnv(t *testing.T) {
	cases := []struct {
		name, cn, tenant string
		wantNil, wantErr bool
	}{
		{"both unset is off", "", "", true, false},
		{"only common name is an error", testServiceCN, "", true, true},
		{"only tenant is an error", "", testServiceTenant, true, true},
		{"non-uuid tenant is an error", testServiceCN, "tenant-zero", true, true},
		{"both set", testServiceCN, testServiceTenant, false, false},
		{"uppercase uuid is normalised", testServiceCN, "00000000-0000-4000-8000-00000000000A", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PORTAL_SERVICE_TOKEN_COMMON_NAME", tc.cn)
			t.Setenv("PORTAL_SERVICE_TOKEN_TENANT_ID", tc.tenant)
			s, err := ServiceIdentityFromEnv()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if (s == nil) != tc.wantNil {
				t.Fatalf("identity = %+v, wantNil %v", s, tc.wantNil)
			}
			if s != nil && s.TenantID != testServiceTenant {
				t.Errorf("tenant = %q", s.TenantID)
			}
		})
	}
}

// --- verification -------------------------------------------------------

func TestVerifyPrincipalServiceToken(t *testing.T) {
	idp := newTestIdP(t)
	p, err := idp.verifier.VerifyPrincipal(idp.sign(t, tokenOpts{commonName: testServiceCN}))
	if err != nil {
		t.Fatalf("VerifyPrincipal: %v", err)
	}
	if p.CommonName != testServiceCN || p.Email != "" {
		t.Errorf("principal = %+v", p)
	}
	// Verify (email-only callers) still refuses it.
	if _, err := idp.verifier.Verify(idp.sign(t, tokenOpts{commonName: testServiceCN})); !errors.Is(err, ErrNoEmailClaim) {
		t.Errorf("Verify err = %v, want ErrNoEmailClaim", err)
	}
}

func TestVerifyPrincipalEmailWinsOverCommonName(t *testing.T) {
	idp := newTestIdP(t)
	p, err := idp.verifier.VerifyPrincipal(idp.sign(t, tokenOpts{email: "a@b.c", commonName: testServiceCN}))
	if err != nil || p.Email != "a@b.c" || p.CommonName != "" {
		t.Fatalf("principal = %+v err = %v", p, err)
	}
}

func TestServiceTokenForgedOrInvalidIsRefused(t *testing.T) {
	idp := serviceIdP(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": idp.issuer, "aud": idp.audience, "exp": time.Now().Add(time.Hour).Unix(),
		"common_name": testServiceCN,
	})
	none.Header["kid"] = idp.kid
	unsigned, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil, WithServiceTenantCheck(liveTenant))
	calls := 0
	handler := h(identityEcho(&calls))
	for name, tok := range map[string]string{
		"forged signature": idp.sign(t, tokenOpts{commonName: testServiceCN, key: otherKey}),
		"unknown kid":      idp.sign(t, tokenOpts{commonName: testServiceCN, kid: "nope"}),
		"wrong audience":   idp.sign(t, tokenOpts{commonName: testServiceCN, aud: "other-app"}),
		"wrong issuer":     idp.sign(t, tokenOpts{commonName: testServiceCN, iss: "https://evil.cloudflareaccess.com"}),
		"expired":          idp.sign(t, tokenOpts{commonName: testServiceCN, exp: time.Now().Add(-time.Minute)}),
		"alg none":         unsigned,
	} {
		t.Run(name, func(t *testing.T) {
			if rr := serviceDo(t, handler, http.MethodGet, "/v1/portal/overview", tok); rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rr.Code)
			}
		})
	}
	if calls != 0 {
		t.Errorf("handler reached %d times", calls)
	}
}

// --- middleware ---------------------------------------------------------

func TestServiceIdentityReadsTenantZeroOnly(t *testing.T) {
	idp := serviceIdP(t)
	audit := &auditRecorder{}
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(map[string]string{"a@b.c": "tenant-B"}), nil, audit.fn(),
		WithServiceTenantCheck(liveTenant))(identityEcho(&calls))

	for _, url := range []string{
		"/v1/portal/overview",
		"/v1/portal/devices?tenant_id=tenant-B&tenant=tenant-B",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rr := serviceDo(t, h, method, url, idp.sign(t, tokenOpts{commonName: testServiceCN}))
			if rr.Code != http.StatusOK {
				t.Fatalf("%s %s = %d, want 200 (%s)", method, url, rr.Code, rr.Body.String())
			}
			if method == http.MethodHead {
				continue
			}
			var got map[string]string
			_ = json.Unmarshal(rr.Body.Bytes(), &got)
			if got["tenant_id"] != testServiceTenant || got["service"] != testServiceCN || got["email"] != "" {
				t.Errorf("%s identity = %v", url, got)
			}
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, e := range audit.entries {
		if e.name != ServiceAuditPrefix+testServiceCN || e.tenant != testServiceTenant {
			t.Errorf("audit entry = %+v, want service:<cn> on tenant zero", e)
		}
	}
}

func TestServiceIdentityNonAllowlistedCommonNameRefused(t *testing.T) {
	idp := serviceIdP(t)
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil, WithServiceTenantCheck(liveTenant))(identityEcho(&calls))
	for _, cn := range []string{"other.access", testServiceCN + "x", "WALKER-TEST.ACCESS"} {
		if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", idp.sign(t, tokenOpts{commonName: cn})); rr.Code != http.StatusUnauthorized {
			t.Errorf("cn %q: status = %d, want 401", cn, rr.Code)
		}
	}
	if calls != 0 {
		t.Errorf("handler reached %d times", calls)
	}
}

func TestServiceIdentityOffByDefault(t *testing.T) {
	idp := newTestIdP(t) // no WithService
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil, WithServiceTenantCheck(liveTenant))(identityEcho(&calls))
	if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", idp.sign(t, tokenOpts{commonName: testServiceCN})); rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestServiceIdentityWithoutTenantCheckFailsClosed(t *testing.T) {
	idp := serviceIdP(t)
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil)(identityEcho(&calls))
	if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", idp.sign(t, tokenOpts{commonName: testServiceCN})); rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if calls != 0 {
		t.Errorf("handler reached")
	}
}

func TestServiceIdentityRevokedTenantRefused(t *testing.T) {
	idp := newTestIdP(t)
	idp.verifier.WithService(&ServiceIdentity{CommonName: testServiceCN, TenantID: "00000000-0000-4000-8000-0000000000ff"})
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil, WithServiceTenantCheck(liveTenant))(identityEcho(&calls))
	if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", idp.sign(t, tokenOpts{commonName: testServiceCN})); rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	if calls != 0 {
		t.Errorf("handler reached")
	}
}

func TestServiceIdentityEveryWriteMethodRefused(t *testing.T) {
	idp := serviceIdP(t)
	audit := &auditRecorder{}
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(nil), nil, audit.fn(), WithServiceTenantCheck(liveTenant))(identityEcho(&calls))
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodOptions, http.MethodConnect, http.MethodTrace, "PROPFIND"}
	for _, m := range methods {
		rr := serviceDo(t, h, m, "/v1/portal/software-approvals", idp.sign(t, tokenOpts{commonName: testServiceCN}))
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", m, rr.Code)
		}
	}
	if calls != 0 {
		t.Errorf("a write reached the handler %d times", calls)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.entries) != len(methods) {
		t.Fatalf("audit entries = %d, want %d", len(audit.entries), len(methods))
	}
	for _, e := range audit.entries {
		if e.name != "service:"+testServiceCN || e.status != http.StatusForbidden {
			t.Errorf("audit entry = %+v", e)
		}
	}
}

func TestPersonUnaffectedByServiceConfig(t *testing.T) {
	idp := serviceIdP(t)
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(map[string]string{"a@b.c": "tenant-B"}), nil, nil,
		WithServiceTenantCheck(liveTenant))(identityEcho(&calls))
	// A person's write passes the middleware (handlers own role checks).
	rr := serviceDo(t, h, http.MethodPut, "/v1/portal/software-approvals", idp.sign(t, tokenOpts{email: "a@b.c"}))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["tenant_id"] != "tenant-B" || got["service"] != "" {
		t.Errorf("identity = %v", got)
	}
}

func TestServiceIdentityRateLimitedSeparately(t *testing.T) {
	idp := serviceIdP(t)
	rl := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 1})
	calls := 0
	h := Middleware(idp.verifier, fakeLookup(map[string]string{"a@b.c": "tenant-B"}), rl, nil,
		WithServiceTenantCheck(liveTenant))(identityEcho(&calls))
	tok := idp.sign(t, tokenOpts{commonName: testServiceCN})
	if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", tok); rr.Code != 200 {
		t.Fatalf("first = %d", rr.Code)
	}
	if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", tok); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second = %d, want 429", rr.Code)
	}
	if rr := serviceDo(t, h, http.MethodGet, "/v1/portal/overview", idp.sign(t, tokenOpts{email: "a@b.c"})); rr.Code != 200 {
		t.Fatalf("person = %d, want 200", rr.Code)
	}
}

func TestDBRoleEmptyEmailIsViewerWithoutQuery(t *testing.T) {
	// nil querier: must return before touching it.
	role, err := DBRole(context.Background(), nil, "", testServiceTenant, true)
	if err != nil || role != RoleViewer {
		t.Fatalf("role = %q err = %v", role, err)
	}
}

func TestIdentityAuditName(t *testing.T) {
	if got := (Identity{Email: "a@b.c"}).AuditName(); got != "a@b.c" {
		t.Errorf("person = %q", got)
	}
	if got := (Identity{Service: testServiceCN}).AuditName(); got != "service:"+testServiceCN {
		t.Errorf("service = %q", got)
	}
}
