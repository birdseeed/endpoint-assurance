package handlers

// PAT-1883 unit tests: everything about sign-up and access management that
// can be decided without a database. The behaviour through the production
// router and a real PostgreSQL is in cmd/patched-api.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

type signupHandlerCase struct {
	name      string
	method    string
	handler   func(*PortalSignup) http.HandlerFunc
	preMember bool
}

// Every handler the feature exports. A handler added to PortalSignup and not
// listed here is caught by TestPortalSignupEveryExportedHandlerIsListed.
var signupHandlerCases = []signupHandlerCase{
	{"StateHandler", http.MethodGet, (*PortalSignup).StateHandler, true},
	{"CreateOrganisationHandler", http.MethodPost, (*PortalSignup).CreateOrganisationHandler, true},
	{"AcceptInvitationHandler", http.MethodPost, (*PortalSignup).AcceptInvitationHandler, true},
	{"AccessListHandler", http.MethodGet, (*PortalSignup).AccessListHandler, false},
	{"InvitationCreateHandler", http.MethodPost, (*PortalSignup).InvitationCreateHandler, false},
	{"InvitationRevokeHandler", http.MethodPost, (*PortalSignup).InvitationRevokeHandler, false},
	{"MemberRoleHandler", http.MethodPut, (*PortalSignup).MemberRoleHandler, false},
	{"MemberDisableHandler", http.MethodPost, (*PortalSignup).MemberDisableHandler, false},
	{"MemberEnableHandler", http.MethodPost, (*PortalSignup).MemberEnableHandler, false},
}

// Every exported method of PortalSignup is an HTTP handler constructor and is
// listed above, so the flag-off and wrong-caller tests below cover it. A
// handler added later and not listed fails here, before it can ship ungated.
func TestPortalSignupEveryExportedHandlerIsListed(t *testing.T) {
	listed := map[string]bool{}
	for _, c := range signupHandlerCases {
		listed[c.name] = true
	}
	rt := reflect.TypeOf(&PortalSignup{})
	handlerFunc := reflect.TypeOf(http.HandlerFunc(nil))
	for i := 0; i < rt.NumMethod(); i++ {
		m := rt.Method(i)
		if m.Type.NumIn() != 1 || m.Type.NumOut() != 1 || m.Type.Out(0) != handlerFunc {
			t.Errorf("PortalSignup.%s is exported and is not a handler constructor: every exported method must return a gated http.HandlerFunc", m.Name)
			continue
		}
		if !listed[m.Name] {
			t.Errorf("PortalSignup.%s is not in signupHandlerCases, so nothing proves it is gated by the flag", m.Name)
		}
		delete(listed, m.Name)
	}
	for name := range listed {
		t.Errorf("signupHandlerCases lists %s, which PortalSignup does not have", name)
	}
	if rt.NumMethod() != len(signupHandlerCases) {
		t.Errorf("PortalSignup has %d exported methods, %d are listed", rt.NumMethod(), len(signupHandlerCases))
	}
}

// contextWithChi attaches a chi route context, so chi.URLParam works on a
// handler called directly.
func contextWithChi(r *http.Request, rc *chi.Context) context.Context {
	return context.WithValue(r.Context(), chi.RouteCtxKey, rc)
}

func signupTestRequest(method string) *http.Request {
	req := httptest.NewRequest(method, "/x", strings.NewReader(`{"name":"Some Organisation","email":"a@b.example","role":"viewer"}`))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("invitationID", "00000000-0000-4000-8000-000000000001")
	rc.URLParams.Add("memberEmail", "member@b.example")
	return req.WithContext(contextWithChi(req, rc))
}

// With the flag off, every handler answers 404 before it touches anything:
// the pool here is nil, so a handler that got past the gate would panic.
func TestPortalSignupFlagOffEveryHandlerIs404(t *testing.T) {
	notFound := httptest.NewRecorder()
	http.NotFound(notFound, httptest.NewRequest(http.MethodGet, "/x", nil))

	for label, s := range map[string]*PortalSignup{
		"zero config":        NewPortalSignup(nil, PortalSignupConfig{}),
		"limits but no flag": NewPortalSignup(nil, PortalSignupConfig{InvitationTTL: time.Hour, OrgCreationsPerHour: 100, InvitationsPerTenantPerHour: 100}),
		"nil receiver":       nil,
	} {
		for _, c := range signupHandlerCases {
			for who, ctx := range map[string]func(*http.Request) *http.Request{
				"no identity": func(r *http.Request) *http.Request { return r },
				"an applicant": func(r *http.Request) *http.Request {
					return r.WithContext(portalauth.WithApplicant(r.Context(), portalauth.Applicant{Email: "a@b.example"}))
				},
				"a member": func(r *http.Request) *http.Request {
					return r.WithContext(portalauth.WithIdentity(r.Context(), portalauth.Identity{Email: "a@b.example", TenantID: "00000000-0000-4000-8000-00000000000a"}))
				},
			} {
				rr := httptest.NewRecorder()
				c.handler(s).ServeHTTP(rr, ctx(signupTestRequest(c.method)))
				if rr.Code != http.StatusNotFound || rr.Body.String() != notFound.Body.String() {
					t.Errorf("%s, %s, %s: %d %q, want the plain 404 of an unmounted route", label, c.name, who, rr.Code, rr.Body.String())
				}
			}
		}
		if s != nil && (s.inviteRL != nil || s.orgCeiling != nil) {
			t.Errorf("%s: limiters were created for a disabled feature", label)
		}
	}
}

// The two groups cannot serve each other's caller. A sign-up handler needs an
// Applicant and ignores an Identity; an access handler needs an Identity and
// ignores an Applicant. Either way the answer is 401 before any database
// work (the pool is nil).
func TestPortalSignupHandlersFailClosedOnTheWrongCaller(t *testing.T) {
	s := NewPortalSignup(nil, PortalSignupConfig{Enabled: true})
	member := portalauth.Identity{Email: "member@b.example", TenantID: "00000000-0000-4000-8000-00000000000a"}
	for _, c := range signupHandlerCases {
		req := signupTestRequest(c.method)
		wrong := req.WithContext(portalauth.WithApplicant(req.Context(), portalauth.Applicant{Email: "a@b.example"}))
		if c.preMember {
			wrong = req.WithContext(portalauth.WithIdentity(req.Context(), member))
		}
		for who, r := range map[string]*http.Request{"nobody": req, "the other group's caller": wrong} {
			rr := httptest.NewRecorder()
			c.handler(s).ServeHTTP(rr, r)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s reached by %s = %d %q, want 401", c.name, who, rr.Code, rr.Body.String())
			}
		}
	}
}

// A tenant-scoped handler mounted in the sign-up group by mistake would be
// handed an Applicant and no Identity. Every such handler reads identity(),
// which refuses.
func TestTenantHandlersRefuseAnApplicant(t *testing.T) {
	var pool *pgxpool.Pool
	for name, h := range map[string]http.HandlerFunc{
		"PortalMeHandler":                   PortalMeHandler(pool),
		"PortalOverviewHandler":             PortalOverviewHandler(pool),
		"PortalDevicesHandler":              PortalDevicesHandler(pool),
		"PortalSoftwareApprovalsPutHandler": PortalSoftwareApprovalsPutHandler(pool),
		"PortalEnrolmentKeysListHandler":    PortalEnrolmentKeysListHandler(pool),
		"PortalLocalAdminsHandler":          PortalLocalAdminsHandler(pool),
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req = req.WithContext(portalauth.WithApplicant(req.Context(), portalauth.Applicant{Email: "stranger@b.example"}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s served an applicant with no tenant: %d %q", name, rr.Code, rr.Body.String())
		}
	}
}

func TestPortalSignupConfigDefaults(t *testing.T) {
	got := PortalSignupConfig{}.withDefaults()
	want := PortalSignupConfig{InvitationTTL: 168 * time.Hour, InvitationsPerTenantPerHour: 20, OrgCreationsPerHour: 20}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
	// A zero or negative limit is never "no limit".
	neg := PortalSignupConfig{Enabled: true, InvitationTTL: -time.Hour, InvitationsPerTenantPerHour: -1, OrgCreationsPerHour: 0}.withDefaults()
	want.Enabled = true
	if neg != want {
		t.Fatalf("negative limits = %+v, want the defaults %+v", neg, want)
	}
	set := PortalSignupConfig{Enabled: true, InvitationTTL: time.Hour, InvitationsPerTenantPerHour: 3, OrgCreationsPerHour: 4}
	if set.withDefaults() != set {
		t.Fatalf("explicit limits were changed: %+v", set.withDefaults())
	}
	if s := NewPortalSignup(nil, set); s.inviteRL == nil || s.orgCeiling == nil {
		t.Fatal("an enabled feature has a missing limiter")
	}
}

// The two pre-membership writes refuse a body they do not define before any
// database work: the pool here is nil, so a handler that got as far as a
// query would panic rather than answer 400. A tenant id, an identity, a role
// and case or Unicode-fold variants of a real key are all just unknown keys.
// (The owner-only writes check the role first, which needs a database; they
// are covered through the production router in cmd/patched-api.)
func TestPortalSignupRefusesUndefinedBodyKeysBeforeTheDatabase(t *testing.T) {
	s := NewPortalSignup(nil, PortalSignupConfig{Enabled: true})
	call := func(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
		rc := chi.NewRouteContext()
		rc.URLParams.Add("invitationID", "00000000-0000-4000-8000-000000000001")
		req = req.WithContext(portalauth.WithApplicant(contextWithChi(req, rc), portalauth.Applicant{Email: "a@b.example"}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	longS, kelvin := string(rune(0x017f)), string(rune(0x212a))
	for _, body := range []string{
		`{"name":"Valid Name","tenant_id":"00000000-0000-4000-8000-00000000000a"}`,
		`{"name":"Valid Name","email":"owner@victim.example"}`,
		`{"name":"Valid Name","role":"owner"}`,
		`{"name":"Valid Name","contact_email":"x@victim.example"}`,
		`{"name":"Valid Name","created_via":"operator"}`,
		`{"NAME":"Valid Name"}`, `{"Name":"Valid Name"}`,
		`{"name":"Valid Name","name":"Other Name"}`,
		`{"name":"Valid Name"} {"name":"Other Name"}`,
		`{"name":"Valid Name","` + longS + `tatus":"x"}`, `{"name":"Valid Name","` + kelvin + `ind":"x"}`,
		`["Valid Name"]`, `"Valid Name"`, `null`, ``, `{"name":`,
	} {
		rr := call(s.CreateOrganisationHandler(), body)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"invalid_request"`) && !strings.Contains(rr.Body.String(), `"invalid_name"`) {
			t.Errorf("create organisation with body %s = %d %s, want 400", body, rr.Code, rr.Body.String())
		}
	}
	// A route that takes no input accepts an empty body, {} and (as the shared
	// requireEmptyOrEmptyObject helper always has) a bare JSON null, none of
	// which carries a key. Everything else is refused.
	for _, body := range []string{
		`{"email":"invitee@b.example"}`, `{"tenant_id":"00000000-0000-4000-8000-00000000000a"}`, `{"role":"owner"}`,
		`{"x":1}`, `[]`, `"accept"`, `{} {}`, `{`, `{"":""}`,
	} {
		rr := call(s.AcceptInvitationHandler(), body)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"invalid_request"`) {
			t.Errorf("accept invitation with body %s = %d %s, want 400 invalid_request", body, rr.Code, rr.Body.String())
		}
	}
}

// With self-service sign-up off the operator route refuses the owner role
// before it touches the database (the pool here is nil: reaching it would
// panic), and says what the role needs.
func TestPortalUserCreateRefusesOwnerWhileSignupIsOff(t *testing.T) {
	post := func(ownerRoleEnabled bool, role string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		body := `{"email":"someone@example.invalid","tenant_id":"00000000-0000-4000-8000-000000000001","role":"` + role + `"}`
		PortalUserCreateHandler(nil, ownerRoleEnabled)(rr, httptest.NewRequest(http.MethodPost, "/admin/portal-users", strings.NewReader(body)))
		return rr
	}
	rr := post(false, "owner")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "self-service sign-up") {
		t.Fatalf("owner with sign-up off = %d %q, want 400 naming self-service sign-up", rr.Code, rr.Body.String())
	}
	// An undefined role is 400 in either state, and with sign-up off the
	// message does not offer owner.
	if rr := post(false, "superuser"); rr.Code != http.StatusBadRequest || strings.Contains(rr.Body.String(), "owner, admin") {
		t.Errorf("superuser with sign-up off = %d %q", rr.Code, rr.Body.String())
	}
	if rr := post(true, "superuser"); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "owner, admin or viewer") {
		t.Errorf("superuser with sign-up on = %d %q", rr.Code, rr.Body.String())
	}
}

func TestValidOrganisationName(t *testing.T) {
	ok := map[string]string{
		"Ab":                          "Ab",
		"  Acme Estates Ltd  ":        "Acme Estates Ltd",
		"\tTabbed and trimmed\n":      "Tabbed and trimmed",
		"Åre & Søn":                   "Åre & Søn",
		"日本":                          "日本",
		strings.Repeat("x", 80):       strings.Repeat("x", 80),
		strings.Repeat("é", 80):       strings.Repeat("é", 80),
		" " + strings.Repeat("x", 80): strings.Repeat("x", 80),
	}
	for in, want := range ok {
		if got, valid := validOrganisationName(in); !valid || got != want {
			t.Errorf("validOrganisationName(%q) = %q, %v; want %q, true", in, got, valid, want)
		}
	}
	for _, in := range []string{
		"", " ", "A", " A ", strings.Repeat("x", 81), strings.Repeat("é", 81),
		"Line one\nLine two", "Tab\tinside", "Bell\u0007", "Null\u0000byte", "C1\u0085control",
		"Bad\xffutf8",
	} {
		if got, valid := validOrganisationName(in); valid {
			t.Errorf("validOrganisationName(%q) accepted as %q", in, got)
		}
	}

	// Characters a reader cannot see. Each is refused wherever it sits in an
	// otherwise ordinary name, because the name is shown to invitees.
	unseen := map[rune]string{
		0x200B: "zero width space", 0x200C: "zero width non-joiner", 0x200D: "zero width joiner",
		0x200E: "left-to-right mark", 0x200F: "right-to-left mark",
		0x202A: "left-to-right embedding", 0x202E: "right-to-left override",
		0x2066: "left-to-right isolate", 0x2067: "right-to-left isolate", 0x2068: "first strong isolate", 0x2069: "pop directional isolate",
		0xFEFF: "byte order mark", 0x00AD: "soft hyphen", 0x2060: "word joiner",
		0x2028: "line separator", 0x2029: "paragraph separator",
		0xE000: "private use", 0xF8FF: "private use", 0x100000: "private use (plane 16)",
		// Letters by category, blank on screen: Other_Default_Ignorable_Code_Point.
		0x115F: "hangul choseong filler", 0x1160: "hangul jungseong filler", 0x3164: "hangul filler", 0xFFA0: "halfwidth hangul filler",
		0x034F: "combining grapheme joiner", 0x17B4: "khmer vowel inherent aq",
	}
	for cp, what := range unseen {
		if got, valid := validOrganisationName("Acme" + string(cp) + "Ltd"); valid {
			t.Errorf("U+%04X %s inside a name: accepted as %+q", cp, what, got)
		}
		for _, in := range []string{string(cp) + "Acme Ltd", "Acme Ltd" + string(cp)} {
			got, valid := validOrganisationName(in)
			if unicode.IsSpace(cp) {
				// The two separators are white space: at either end they are
				// trimmed away like a space or a newline, and never stored.
				if !valid || got != "Acme Ltd" {
					t.Errorf("U+%04X %s at an end: validOrganisationName(%+q) = %+q, %v; want it trimmed to \"Acme Ltd\"", cp, what, in, got, valid)
				}
			} else if valid {
				t.Errorf("U+%04X %s at an end: validOrganisationName(%+q) accepted as %+q", cp, what, in, got)
			}
		}
	}
	// A surrogate cannot be written in valid UTF-8; its encoded form is refused.
	if got, valid := validOrganisationName("Acme\xed\xa0\x80Ltd"); valid {
		t.Errorf("an encoded surrogate was accepted as %+q", got)
	}

	// At least two letters or digits, so a name cannot be blank-looking.
	for _, in := range []string{
		"--", "& .", "A-", "- 7 -", "!!!!", "\u2014\u2014\u2014",
		string(rune(0x3164)) + string(rune(0x3164)), // two "letters" nobody can see
		string(rune(0x2800)) + string(rune(0x2800)), // braille blank: not a letter
		"\u0301\u0301\u0301",                        // combining marks with nothing under them
	} {
		if got, valid := validOrganisationName(in); valid {
			t.Errorf("validOrganisationName(%+q) accepted as %+q: fewer than two letters or digits", in, got)
		}
	}
	for _, in := range []string{
		"A1", "42", "é1", "A & B", "3M", "日本", "Åre & Søn", "Ünïcödé Ltd", "Компания", "شركة", "한국 회사",
		"Acme \u2764\ufe0f IT", // an emoji with its variation selector is left alone
		"O'Brien & Sons (IoM) Ltd.",
	} {
		if got, valid := validOrganisationName(in); !valid || got != in {
			t.Errorf("validOrganisationName(%+q) = %+q, %v; want it accepted unchanged", in, got, valid)
		}
	}
}

func TestNormaliseInviteEmail(t *testing.T) {
	ok := map[string]string{
		"a@b.example":                  "a@b.example",
		"  First.Last@Example.COM  ":   "first.last@example.com",
		"first+tag@sub.example.co.uk":  "first+tag@sub.example.co.uk",
		"o'brien@example.ie":           "o'brien@example.ie",
		"under_score-dash@x-y.example": "under_score-dash@x-y.example",
	}
	for in, want := range ok {
		if got, valid := normaliseInviteEmail(in); !valid || got != want {
			t.Errorf("normaliseInviteEmail(%q) = %q, %v; want %q, true", in, got, valid, want)
		}
	}
	for _, in := range []string{
		"", " ", "plain", "@example.com", "a@", "a@b", "a@.example", "a@example.", "a@@example.com", "a@b@example.com",
		"Someone <a@b.example>", "a@b.example, c@d.example", "a@b.example;c@d.example", "a b@c.example",
		"a@b.example (comment)", `"quoted"@b.example`, "a@[127.0.0.1]", "a\u0000@b.example", "a\n@b.example",
		strings.Repeat("a", 250) + "@b.example",
	} {
		if got, valid := normaliseInviteEmail(in); valid {
			t.Errorf("normaliseInviteEmail(%q) accepted as %q", in, got)
		}
	}
}

// Who a member counts as disabled by. Anything that is not exactly an owner's
// disable is the operator's: a row disabled before the column existed, and a
// value this build does not know.
func TestEffectiveDisabledBy(t *testing.T) {
	at := time.Now()
	str := func(s string) *string { return &s }
	show := func(p *string) string {
		if p == nil {
			return "nil"
		}
		return *p
	}
	for _, c := range []struct {
		what       string
		disabledAt *time.Time
		stored     *string
		want       string
	}{
		{"enabled", nil, nil, "nil"},
		{"enabled, whatever the marker says", nil, str("owner"), "nil"},
		{"disabled by an owner", &at, str("owner"), "owner"},
		{"disabled by the operator", &at, str("operator"), "operator"},
		{"disabled before the column existed", &at, nil, "operator"},
		{"disabled with a marker this build does not know", &at, str("someone"), "operator"},
		{"disabled with an empty marker", &at, str(""), "operator"},
	} {
		if got := show(effectiveDisabledBy(c.disabledAt, c.stored)); got != c.want {
			t.Errorf("%s: effectiveDisabledBy = %s, want %s", c.what, got, c.want)
		}
	}
}

func TestInvitationStatus(t *testing.T) {
	for _, c := range []struct {
		stored  string
		expired bool
		want    string
	}{
		{"pending", false, "pending"}, {"pending", true, "expired"},
		// Only a pending invitation can read as expired.
		{"accepted", true, "accepted"}, {"revoked", true, "revoked"},
		{"accepted", false, "accepted"}, {"revoked", false, "revoked"},
	} {
		if got := invitationStatus(c.stored, c.expired); got != c.want {
			t.Errorf("invitationStatus(%q, %v) = %q, want %q", c.stored, c.expired, got, c.want)
		}
	}
}

// memberEmailParam decodes the path segment exactly once. Which of the two
// forms it receives depends on how chi routed the request, so each case is a
// whole request path sent through a chi router, as net/http would parse it.
// (The same thing through the production router and a database:
// TestPAT1883MemberAddressIsDecodedOnce in cmd/patched-api.)
func TestMemberEmailParam(t *testing.T) {
	seen := func(segment string) (string, bool) {
		t.Helper()
		got, routed := "", false
		r := chi.NewRouter()
		r.Route("/v1/portal", func(pr chi.Router) {
			pr.Post("/access/members/{memberEmail}/disable", func(_ http.ResponseWriter, req *http.Request) {
				got, routed = memberEmailParam(req), true
			})
		})
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/portal/access/members/"+segment+"/disable", nil))
		return got, routed
	}
	for segment, want := range map[string]string{
		"member@b.example":      "member@b.example",
		"Member@B.Example":      "member@b.example",
		"member%40b.example":    "member@b.example",    // not canonical: routed raw, decoded here
		"first%2Btag@b.example": "first+tag@b.example", // likewise
		"first+tag@b.example":   "first+tag@b.example",
		// A literal "%" is sent as "%25". Alone that is canonical, so the
		// router has already decoded it and it must not be decoded again.
		"x%2541y@d.example":      "x%41y@d.example",
		"x%2541y%40d.example":    "x%41y@d.example", // the same address, routed raw
		"x%252541y@d.example":    "x%2541y@d.example",
		"100%25@d.example":       "100%@d.example",
		"x%41y@d.example":        "xay@d.example", // "%41" is "A": the client asked for xAy
		"%20member@b.example":    "member@b.example",
		"a%00b@c.example":        "",
		"a%0Ab@c.example":        "",
		strings.Repeat("a", 321): "",
	} {
		got, routed := seen(segment)
		if !routed {
			t.Errorf("%q did not reach the handler", segment)
			continue
		}
		if got != want {
			t.Errorf("member address from path segment %q = %q, want %q", segment, got, want)
		}
	}
	// The parameter is what it is told it is: with no raw path it is taken as
	// already decoded, and with one it is decoded. An undecodable raw segment
	// is no address.
	direct := func(param, rawPath string) string {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.URL.RawPath = rawPath
		rc := chi.NewRouteContext()
		rc.URLParams.Add("memberEmail", param)
		return memberEmailParam(req.WithContext(contextWithChi(req, rc)))
	}
	if got := direct("x%41y@d.example", ""); got != "x%41y@d.example" {
		t.Errorf("an already decoded parameter was decoded again: %q", got)
	}
	if got := direct("x%41y@d.example", "/raw"); got != "xay@d.example" {
		t.Errorf("a raw parameter was not decoded: %q", got)
	}
	for _, bad := range []string{"%", "%zz", "a%4"} {
		if got := direct(bad, "/raw"); got != "" {
			t.Errorf("undecodable raw parameter %q = %q, want none", bad, got)
		}
	}
	if got := direct("", ""); got != "" {
		t.Errorf("empty parameter = %q", got)
	}
}
