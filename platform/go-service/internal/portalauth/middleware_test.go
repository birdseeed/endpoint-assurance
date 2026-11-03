package portalauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"patched.im/api/internal/ratelimit"
)

// fakeLookup maps emails to tenants in memory — the unit-level stand-in for
// the portal_users table (the DB-backed path is covered by the integration
// cross-tenant matrix).
func fakeLookup(m map[string]string) LookupFunc {
	return func(_ context.Context, email string) (string, error) {
		if tid, ok := m[email]; ok {
			return tid, nil
		}
		return "", ErrNoPortalUser
	}
}

// echoTenantHandler writes back the context tenant — lets tests assert which
// tenant a given identity resolved to.
func echoTenantHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := FromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"tenant_id": id.TenantID, "email": id.Email})
	})
}

func TestMiddlewareNilVerifierFailsClosed503(t *testing.T) {
	h := Middleware(nil, fakeLookup(nil), nil, nil)(echoTenantHandler())
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestMiddlewareMissingHeader401(t *testing.T) {
	idp := newTestIdP(t)
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil)(echoTenantHandler())
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddlewareInvalidToken401(t *testing.T) {
	idp := newTestIdP(t)
	h := Middleware(idp.verifier, fakeLookup(nil), nil, nil)(echoTenantHandler())
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	req.Header.Set(Header, "garbage.token.value")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddlewareUnmappedEmail403(t *testing.T) {
	idp := newTestIdP(t)
	var mu sync.Mutex
	var audited []int
	audit := func(_, _, _, _ string, status int) {
		mu.Lock()
		audited = append(audited, status)
		mu.Unlock()
	}
	h := Middleware(idp.verifier, fakeLookup(map[string]string{}), nil, audit)(echoTenantHandler())
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	req.Header.Set(Header, idp.sign(t, tokenOpts{email: "stranger@nowhere.example"}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(audited) != 1 || audited[0] != http.StatusForbidden {
		t.Errorf("audit log = %v, want one 403 entry", audited)
	}
}

func TestMiddlewareMapsEmailToTenant(t *testing.T) {
	idp := newTestIdP(t)
	lookup := fakeLookup(map[string]string{"alice@tenant-a.example": "tenant-A"})
	h := Middleware(idp.verifier, lookup, nil, nil)(echoTenantHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	req.Header.Set(Header, idp.sign(t, tokenOpts{email: "Alice@Tenant-A.example"})) // mixed case
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	var got map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["tenant_id"] != "tenant-A" {
		t.Errorf("tenant_id = %q, want tenant-A", got["tenant_id"])
	}
	if got["email"] != "alice@tenant-a.example" {
		t.Errorf("email = %q, want lowercased", got["email"])
	}
}

// TestMiddlewareIsolationMatrix is the unit-level half of the cross-tenant
// isolation proof: for every (identity, mapping) combination the resolved
// tenant is exactly the portal_users mapping — never influenced by anything
// the client sends. The DB-backed half (real queries scoped by the resolved
// tenant) lives in integration/portal_test.go.
func TestMiddlewareIsolationMatrix(t *testing.T) {
	idp := newTestIdP(t)
	mapping := map[string]string{
		"alice@tenant-a.example": "tenant-A",
		"bob@tenant-b.example":   "tenant-B",
	}
	h := Middleware(idp.verifier, fakeLookup(mapping), nil, nil)(echoTenantHandler())

	cases := []struct {
		name       string
		email      string
		url        string // client-controlled: path/query must never matter
		wantStatus int
		wantTenant string
	}{
		{"alice resolves to A", "alice@tenant-a.example", "/v1/portal/overview", 200, "tenant-A"},
		{"bob resolves to B", "bob@tenant-b.example", "/v1/portal/overview", 200, "tenant-B"},
		{"alice cannot claim B via query", "alice@tenant-a.example", "/v1/portal/overview?tenant_id=tenant-B", 200, "tenant-A"},
		{"bob cannot claim A via query", "bob@tenant-b.example", "/v1/portal/devices?tenant=tenant-A&tenant_id=tenant-A", 200, "tenant-B"},
		{"unmapped identity rejected", "mallory@evil.example", "/v1/portal/overview", 403, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Header.Set(Header, idp.sign(t, tokenOpts{email: tc.email}))
			// Belt and braces: a spoofed tenant header must be ignored too.
			req.Header.Set("X-Tenant-ID", "tenant-B")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			if tc.wantTenant != "" {
				var got map[string]string
				_ = json.Unmarshal(rr.Body.Bytes(), &got)
				if got["tenant_id"] != tc.wantTenant {
					t.Errorf("tenant_id = %q, want %q", got["tenant_id"], tc.wantTenant)
				}
			}
		})
	}
}

func TestMiddlewareRateLimitPerIdentity(t *testing.T) {
	idp := newTestIdP(t)
	mapping := map[string]string{
		"alice@tenant-a.example": "tenant-A",
		"bob@tenant-b.example":   "tenant-B",
	}
	// Tiny bucket: 2 immediate tokens, negligible refill.
	rl := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 2})
	h := Middleware(idp.verifier, fakeLookup(mapping), rl, nil)(echoTenantHandler())

	do := func(email string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
		req.Header.Set(Header, idp.sign(t, tokenOpts{email: email}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if c := do("alice@tenant-a.example"); c != 200 {
		t.Fatalf("req 1 = %d", c)
	}
	if c := do("alice@tenant-a.example"); c != 200 {
		t.Fatalf("req 2 = %d", c)
	}
	if c := do("alice@tenant-a.example"); c != http.StatusTooManyRequests {
		t.Fatalf("req 3 = %d, want 429", c)
	}
	// Limits are per identity — bob is unaffected by alice's exhaustion.
	if c := do("bob@tenant-b.example"); c != 200 {
		t.Fatalf("bob req = %d, want 200", c)
	}
}

func TestMiddlewareAuditsSuccess(t *testing.T) {
	idp := newTestIdP(t)
	type entry struct {
		email, tenant, method string
		status                int
	}
	var mu sync.Mutex
	var log []entry
	audit := func(email, tenantID, method, _ string, status int) {
		mu.Lock()
		log = append(log, entry{email, tenantID, method, status})
		mu.Unlock()
	}
	h := Middleware(idp.verifier, fakeLookup(map[string]string{"a@b.c": "T1"}), nil, audit)(echoTenantHandler())

	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	req.Header.Set(Header, idp.sign(t, tokenOpts{email: "a@b.c"}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	mu.Lock()
	defer mu.Unlock()
	if len(log) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(log))
	}
	got := log[0]
	if got.email != "a@b.c" || got.tenant != "T1" || got.method != "GET" || got.status != 200 {
		t.Errorf("audit entry = %+v", got)
	}
}
