package portalauth

// PAT-1883: the owner role and the pre-membership (sign-up) middleware.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"patched.im/api/internal/ratelimit"
)

func TestRolePredicates(t *testing.T) {
	cases := []struct {
		role                                   string
		valid, canWrite, isOwner, ownerAssigns bool
	}{
		{RoleOwner, true, true, true, false},
		{RoleAdmin, true, true, false, true},
		{RoleViewer, true, false, false, true},
		// The service identity's role is never a portal_users role.
		{RoleServiceReadOnly, false, false, false, false},
		// Anything this binary does not know is the least privileged thing.
		{"", false, false, false, false},
		{"Owner", false, false, false, false},
		{"OWNER", false, false, false, false},
		{"owner ", false, false, false, false},
		{"superuser", false, false, false, false},
		{"admin,owner", false, false, false, false},
	}
	for _, c := range cases {
		if got := ValidRole(c.role); got != c.valid {
			t.Errorf("ValidRole(%q) = %v, want %v", c.role, got, c.valid)
		}
		if got := CanWrite(c.role); got != c.canWrite {
			t.Errorf("CanWrite(%q) = %v, want %v", c.role, got, c.canWrite)
		}
		if got := IsOwner(c.role); got != c.isOwner {
			t.Errorf("IsOwner(%q) = %v, want %v", c.role, got, c.isOwner)
		}
		if got := OwnerAssignable(c.role); got != c.ownerAssigns {
			t.Errorf("OwnerAssignable(%q) = %v, want %v", c.role, got, c.ownerAssigns)
		}
	}
	// An owner can do everything an admin can: nothing may be open to admin
	// and closed to owner.
	if CanWrite(RoleAdmin) && !CanWrite(RoleOwner) {
		t.Fatal("admin can write and owner cannot")
	}
	// Ownership is never something an owner hands out.
	if OwnerAssignable(RoleOwner) {
		t.Fatal("owner is assignable by an owner")
	}
}

// applicantEcho reports what the sign-up middleware put in the context, and
// counts calls so a refused request can be proved never to reach a handler.
func applicantEcho(calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		a, hasApplicant := ApplicantFromContext(r.Context())
		_, hasIdentity := FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"email": a.Email, "applicant": hasApplicant, "identity": hasIdentity,
		})
	})
}

func signupDo(t *testing.T, h http.Handler, method, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/v1/portal/signup/state", nil)
	if token != "" {
		req.Header.Set(Header, token)
	}
	// Headers that try to name an identity or a tenant are not credentials.
	req.Header.Set("Cf-Access-Authenticated-User-Email", "owner@victim.example")
	req.Header.Set("X-Tenant-ID", "tenant-B")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSignupMiddlewareFailsClosed(t *testing.T) {
	idp := newTestIdP(t)
	calls := 0
	if rr := signupDo(t, SignupMiddleware(nil, nil, nil)(applicantEcho(&calls)), http.MethodGet, ""); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("nil verifier = %d, want 503", rr.Code)
	}
	h := SignupMiddleware(idp.verifier, nil, nil)(applicantEcho(&calls))
	for name, token := range map[string]string{
		"no token":       "",
		"garbage":        "garbage.token.value",
		"wrong audience": idp.sign(t, tokenOpts{email: "a@b.example", aud: "another-aud"}),
		"wrong issuer":   idp.sign(t, tokenOpts{email: "a@b.example", iss: "https://evil.example"}),
		"no email":       idp.sign(t, tokenOpts{}),
	} {
		if rr := signupDo(t, h, http.MethodGet, token); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, rr.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("a refused request reached the handler %d times", calls)
	}
}

// A verified person with no tenant is served, as an Applicant and never as an
// Identity: a tenant handler mounted behind this middleware by mistake finds
// no Identity and refuses.
func TestSignupMiddlewareSetsAnApplicantAndNoIdentity(t *testing.T) {
	idp := newTestIdP(t)
	rec := &auditRecorder{}
	calls := 0
	h := SignupMiddleware(idp.verifier, nil, rec.fn())(applicantEcho(&calls))

	rr := signupDo(t, h, http.MethodPost, idp.sign(t, tokenOpts{email: "  New.Person@Example.COM "}))
	if rr.Code != http.StatusOK || calls != 1 {
		t.Fatalf("status = %d, calls = %d: %s", rr.Code, calls, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["email"] != "new.person@example.com" || got["applicant"] != true || got["identity"] != false {
		t.Fatalf("context = %v, want the verified lower-cased email as an applicant and no identity", got)
	}
	if len(rec.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(rec.entries))
	}
	if e := rec.entries[0]; e.name != "new.person@example.com" || e.tenant != "" || e.method != http.MethodPost || e.status != http.StatusOK {
		t.Fatalf("audit entry = %+v, want the email, no tenant, POST, 200", e)
	}
}

func TestApplicantFromContextNeedsAnEmail(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := ApplicantFromContext(req.Context()); ok {
		t.Error("an empty context yields an applicant")
	}
	if _, ok := ApplicantFromContext(WithApplicant(req.Context(), Applicant{})); ok {
		t.Error("an applicant with no email is accepted")
	}
	// An Identity is not an Applicant, and the reverse.
	if _, ok := ApplicantFromContext(WithIdentity(req.Context(), Identity{Email: "a@b.example", TenantID: "T"})); ok {
		t.Error("an identity was read as an applicant")
	}
	if _, ok := FromContext(WithApplicant(req.Context(), Applicant{Email: "a@b.example"})); ok {
		t.Error("an applicant was read as an identity")
	}
}

// The read-only service identity has no email and is fixed to one tenant: it
// is refused on every sign-up method, and an unallowlisted service token is
// simply unauthenticated.
func TestSignupMiddlewareRefusesTheServiceIdentity(t *testing.T) {
	idp := serviceIdP(t)
	rec := &auditRecorder{}
	calls := 0
	h := SignupMiddleware(idp.verifier, nil, rec.fn())(applicantEcho(&calls))
	token := idp.sign(t, tokenOpts{commonName: testServiceCN})

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rr := signupDo(t, h, method, token)
		if rr.Code != http.StatusForbidden {
			t.Errorf("service %s = %d, want 403", method, rr.Code)
		}
		wantReadOnly := !ServiceMethodAllowed(method)
		if got := strings.Contains(rr.Body.String(), "read-only"); got != wantReadOnly && method != http.MethodHead {
			t.Errorf("service %s body %q: read-only wording = %v, want %v", method, rr.Body.String(), got, wantReadOnly)
		}
	}
	if calls != 0 {
		t.Fatalf("the service identity reached the handler %d times", calls)
	}
	for _, e := range rec.entries {
		if e.name != ServiceAuditPrefix+testServiceCN || e.tenant != "" || e.status != http.StatusForbidden {
			t.Fatalf("audit entry = %+v, want the service name, no tenant, 403", e)
		}
	}
	if len(rec.entries) != 6 {
		t.Fatalf("audit entries = %d, want one per refusal", len(rec.entries))
	}

	if rr := signupDo(t, h, http.MethodGet, idp.sign(t, tokenOpts{commonName: "someone-else.access"})); rr.Code != http.StatusUnauthorized {
		t.Errorf("unallowlisted service token = %d, want 401", rr.Code)
	}
	// With no service identity configured, a service token is 401 as it
	// always was.
	plain := newTestIdP(t)
	h = SignupMiddleware(plain.verifier, nil, nil)(applicantEcho(&calls))
	if rr := signupDo(t, h, http.MethodGet, plain.sign(t, tokenOpts{commonName: testServiceCN})); rr.Code != http.StatusUnauthorized {
		t.Errorf("service token with the feature off = %d, want 401", rr.Code)
	}
}

func TestSignupMiddlewareRateLimitsPerEmail(t *testing.T) {
	idp := newTestIdP(t)
	rl := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 2})
	calls := 0
	h := SignupMiddleware(idp.verifier, rl, nil)(applicantEcho(&calls))
	alice, bob := idp.sign(t, tokenOpts{email: "alice@a.example"}), idp.sign(t, tokenOpts{email: "bob@b.example"})

	for i := 1; i <= 2; i++ {
		if rr := signupDo(t, h, http.MethodGet, alice); rr.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, rr.Code)
		}
	}
	rr := signupDo(t, h, http.MethodGet, alice)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("request 3 = %d with Retry-After %q, want 429 and a Retry-After", rr.Code, rr.Header().Get("Retry-After"))
	}
	if rr := signupDo(t, h, http.MethodGet, bob); rr.Code != http.StatusOK {
		t.Fatalf("another person = %d, want 200", rr.Code)
	}
	if calls != 3 {
		t.Fatalf("handler calls = %d, want 3 (the limited request must not reach it)", calls)
	}
	// The same limiter instance serves the tenant middleware, so one person
	// has one budget across both groups.
	tenant := Middleware(idp.verifier, fakeLookup(map[string]string{"alice@a.example": "T"}), rl, nil)(echoTenantHandler())
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/overview", nil)
	req.Header.Set(Header, alice)
	out := httptest.NewRecorder()
	tenant.ServeHTTP(out, req)
	if out.Code != http.StatusTooManyRequests {
		t.Fatalf("tenant route after the sign-up budget is spent = %d, want 429", out.Code)
	}
}
