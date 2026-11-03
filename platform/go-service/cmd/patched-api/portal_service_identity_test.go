package main

// PAT-2257: every write route on the real /v1/portal router refuses the
// read-only service identity. The routes are enumerated from the router
// itself (chi.Walk), so a write handler added later is covered without
// anyone remembering to add it here.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"patched.im/api/internal/portalauth"
)

const (
	svcTestCN     = "walker-test.access" // placeholder, not a real client id
	svcTestTenant = "00000000-0000-4000-8000-00000000000a"
	svcTestIssuer = "https://svctest.cloudflareaccess.com"
	svcTestAud    = "svc-test-aud"
	svcTestKid    = "svc-test-kid"
)

func serviceTestVerifier(t *testing.T) (*portalauth.Verifier, func() string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": svcTestKid, "kty": "RSA", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	v := portalauth.New(svcTestIssuer, svcTestAud, srv.URL).
		WithService(&portalauth.ServiceIdentity{CommonName: svcTestCN, TenantID: svcTestTenant})
	sign := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": svcTestIssuer, "aud": svcTestAud, "common_name": svcTestCN, "sub": "",
			"type": "app", "iat": time.Now().Add(-time.Minute).Unix(),
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		tok.Header["kid"] = svcTestKid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return v, sign
}

func portalWriteRoutes(t *testing.T, r http.Handler) [][2]string {
	t.Helper()
	routes, ok := r.(chi.Routes)
	if !ok {
		t.Fatal("public router is not a chi router")
	}
	var out [][2]string
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/v1/portal/") {
			return nil
		}
		if method == http.MethodGet || method == http.MethodHead {
			return nil
		}
		out = append(out, [2]string{method, route})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPortalEveryWriteRouteRefusesServiceIdentity(t *testing.T) {
	v, sign := serviceTestVerifier(t)
	// nil pool: a refused write never reaches a handler or the DB. If one
	// did, the nil pool would panic into a 500, not a 403, and fail here.
	r := newPublicRouter(nil, nil, nil, 0, v, nil, nil, "", "", nil, nil, "", nil, "", nil)

	writes := portalWriteRoutes(t, r)
	want := map[[2]string]bool{
		{"PUT", "/v1/portal/software-approvals"}:                false,
		{"PUT", "/v1/portal/devices/{deviceID}/retirement"}:     false,
		{"PUT", "/v1/portal/device-list"}:                       false,
		{"DELETE", "/v1/portal/device-list"}:                    false,
		{"DELETE", "/v1/portal/device-list/entries/{entryID}"}:  false,
		{"PUT", "/v1/portal/software-notifications"}:            false,
		{"POST", "/v1/portal/reports"}:                          false,
		{"PUT", "/v1/portal/reports/schedule"}:                  false,
		{"POST", "/v1/portal/enrolment"}:                        false,
		{"POST", "/v1/portal/enrolment-keys"}:                   false,
		{"POST", "/v1/portal/enrolment-keys/{keyID}/revoke"}:    false,
		{"POST", "/v1/portal/feedback"}:                         false,
		{"POST", "/v1/portal/software-alerts/{id}/acknowledge"}: false,
		{"PUT", "/v1/portal/mdm/jamf/setup"}:                    false,
		{"POST", "/v1/portal/mdm/jamf/token"}:                   false,
		{"DELETE", "/v1/portal/mdm/jamf/token"}:                 false,
		{"DELETE", "/v1/portal/mdm/jamf/devices"}:               false,
		{"PUT", "/v1/portal/agent-releases"}:                    false,
		{"PUT", "/v1/portal/reports/schedules/{reportType}"}:    false,
		{"POST", "/v1/portal/exports/table-pdf"}:                false, // PAT-2405
		// PAT-1883: the sign-up group has its own middleware, which must
		// refuse the service identity's writes the same way.
		{"POST", "/v1/portal/signup/organisation"}:                      false,
		{"POST", "/v1/portal/signup/invitations/{invitationID}/accept"}: false,
		{"POST", "/v1/portal/access/invitations"}:                       false,
		{"POST", "/v1/portal/access/invitations/{invitationID}/revoke"}: false,
		{"PUT", "/v1/portal/access/members/{memberEmail}/role"}:         false,
		{"POST", "/v1/portal/access/members/{memberEmail}/disable"}:     false,
		{"POST", "/v1/portal/access/members/{memberEmail}/enable"}:      false,
	}
	for _, w := range writes {
		if _, ok := want[w]; ok {
			want[w] = true
		}
	}
	for route, seen := range want {
		if !seen {
			t.Errorf("expected write route %v not found by the walk (enumeration broken?)", route)
		}
	}
	t.Logf("enumerated %d portal write routes", len(writes))

	for _, w := range writes {
		method, route := w[0], w[1]
		path := strings.NewReplacer("{deviceID}", "00000000-0000-4000-8000-000000000001",
			"{entryID}", "1", "{keyID}", "00000000-0000-4000-8000-000000000002",
			"{id}", "1", "{reportType}", "executive-summary").Replace(route)
		req := httptest.NewRequest(method, path, strings.NewReader(`{"state":"approved","items":[]}`))
		req.Header.Set(portalauth.Header, sign())
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		// The body pins WHICH refusal fired: the central read-only guard,
		// not the (nil-pool) tenant check further down the middleware.
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "read-only") {
			t.Errorf("%s %s = %d %q, want 403 from the read-only guard", method, route, rr.Code, rr.Body.String())
		}
	}
}
