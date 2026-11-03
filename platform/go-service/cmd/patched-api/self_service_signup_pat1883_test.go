package main

// PAT-1883 acceptance: self-service organisation sign-up, invitations and
// access management, through the production routers. See the fixture file.
//
// What each test pins:
//
//	flag off            every new route is 404, and writes nothing
//	organisation        verified email only, one owner, provisioned like an
//	                    operator tenant, single use and race-safe
//	body identity       a body that names a tenant or an identity, or carries
//	                    any key the route does not define, is refused 400;
//	                    a query or header that tries is ignored
//	invitations         create, accept, expire, revoke, reuse; wrong email
//	owner-only writes   admin and viewer refused; guards on self and owners
//	cross-tenant        another tenant's ids and addresses answer as missing
//	service identity    refused on every new route
//	abuse controls      per-email and global sign-up limits, invitation
//	                    limit and cap, all 429 or 409 without side effects
//	audit               one ledger row per change, in the same transaction
//	tenant purge        invitations go, ledger rows stay without addresses

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
	"patched.im/api/internal/softwaregov"
)

// ---------------------------------------------------------------------------
// Flag and routing (no database)
// ---------------------------------------------------------------------------

func TestPAT1883SignupIsDisabledByDefault(t *testing.T) {
	for _, k := range []string{"SELF_SERVICE_SIGNUP_ENABLED", "PORTAL_INVITATION_TTL_HOURS", "PORTAL_INVITATIONS_PER_HOUR",
		"SIGNUP_ORG_CREATIONS_PER_HOUR"} {
		t.Setenv(k, "")
	}
	got := loadConfig().SelfServiceSignup
	if got.Enabled {
		t.Fatal("SELF_SERVICE_SIGNUP_ENABLED must default to false")
	}
	if got.InvitationTTL != 168*time.Hour || got.InvitationsPerTenantPerHour != 20 || got.OrgCreationsPerHour != 20 {
		t.Fatalf("defaults = %+v, want 168h, 20, 20", got)
	}

	// Anything that is not an explicit yes leaves it off.
	for _, v := range []string{"0", "false", "no", "off", "maybe", " "} {
		t.Setenv("SELF_SERVICE_SIGNUP_ENABLED", v)
		if loadConfig().SelfServiceSignup.Enabled {
			t.Errorf("SELF_SERVICE_SIGNUP_ENABLED=%q enabled the feature", v)
		}
	}
	t.Setenv("SELF_SERVICE_SIGNUP_ENABLED", "true")
	t.Setenv("PORTAL_INVITATION_TTL_HOURS", "24")
	t.Setenv("PORTAL_INVITATIONS_PER_HOUR", "7")
	t.Setenv("SIGNUP_ORG_CREATIONS_PER_HOUR", "9")
	got = loadConfig().SelfServiceSignup
	want := handlers.PortalSignupConfig{Enabled: true, InvitationTTL: 24 * time.Hour,
		InvitationsPerTenantPerHour: 7, OrgCreationsPerHour: 9}
	if got != want {
		t.Fatalf("configured = %+v, want %+v", got, want)
	}
}

// The new routes are exactly the documented ones, and the sign-up group holds
// nothing else: no tenant route can be reached through it.
func TestPAT1883NewRoutesAreExactlyTheDocumentedOnes(t *testing.T) {
	r := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
	sorted := func(in [][2]string) []string {
		var out []string
		for _, x := range in {
			out = append(out, x[0]+" "+x[1])
		}
		sort.Strings(out)
		return out
	}
	if got, want := sorted(pat1883Routes(t, r, "/v1/portal/signup")), sorted(pat1883SignupRoutes); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sign-up group routes:\n got %v\nwant %v", got, want)
	}
	if got, want := sorted(pat1883Routes(t, r, "/v1/portal/access")), sorted(pat1883AccessRoutes); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("access routes:\n got %v\nwant %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Flag off
// ---------------------------------------------------------------------------

func TestPAT1883FlagOffEveryNewRouteIs404(t *testing.T) {
	f := newSignupFx(t)
	on, off := f.router(pat1883Enabled()), f.router()

	org := f.newOrg(t, on)
	admin, viewer := f.join(t, on, org, "admin"), f.join(t, on, org, "viewer")
	outsider := pat1883Email("outsider")
	pending := f.invite(t, on, org, pat1883Email("pending"), "viewer")

	snapshot := func() string {
		return fmt.Sprintf("tenants=%d users=%d invitations=%d audit=%d viewerRole=%s pending=%s",
			f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE 'PAT1883 flag off %'`),
			f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid`, org.Tenant),
			f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, org.Tenant),
			f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid`, org.Tenant),
			f.text(t, `SELECT role || coalesce(disabled_at::text,'') FROM portal_users WHERE email=$1`, viewer),
			f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, pending))
	}
	before := snapshot()

	body := map[string]any{"name": "PAT1883 flag off " + pat1883Rand(), "email": pat1883Email("x"), "role": "viewer"}
	real := strings.NewReplacer("{invitationID}", pending, "{memberEmail}", viewer)
	for _, route := range pat1883AllNewRoutes() {
		isSignup := strings.HasPrefix(route[1], "/v1/portal/signup")
		for who, email := range map[string]string{"owner": org.Owner, "admin": admin, "viewer": viewer, "non-member": outsider} {
			want := http.StatusNotFound
			if !isSignup && who == "non-member" {
				// Never a member of anything: the tenant middleware refuses
				// before any handler, flag or no flag.
				want = http.StatusForbidden
			}
			for _, path := range []string{pat1883Fill(route[1]), real.Replace(route[1])} {
				r := f.do(t, off, route[0], path, f.token(t, email), body)
				if r.Code != want {
					t.Errorf("flag off: %s %s as %s = %d, want %d: %s", route[0], path, who, r.Code, want, r.Raw)
				}
			}
		}
	}
	if after := snapshot(); after != before {
		t.Fatalf("flag-off requests changed state:\nbefore %s\nafter  %s", before, after)
	}

	// The same requests do work with the flag on: the 404s above were the
	// flag, not a missing route or a bad request.
	f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, org.Owner), nil).want(t, "flag on control", http.StatusOK, "")
	f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, outsider), nil).want(t, "flag on control", http.StatusOK, "")
}

// What "off" looks like from outside, as the contract states it. A disabled
// route answers 404 to a verified caller who uses its method, with the same
// body as a path that was never mounted. It is not otherwise identical to an
// unmounted route: a wrong method is 405 (a path nobody mounted is 404 for
// every method), and everything the route group decides before a handler
// runs still comes first.
func TestPAT1883WhatADisabledRouteAnswers(t *testing.T) {
	f := newSignupFx(t)
	on, off := f.router(pat1883Enabled()), f.router()
	org := f.newOrg(t, on)
	owner, stranger := f.token(t, org.Owner), f.token(t, pat1883Email("stranger"))

	raw := func(router http.Handler, method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set(portalauth.Header, token)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}
	// The right method: 404, and the same answer as an unmounted path in the
	// same group gives the same caller.
	for _, c := range []struct{ method, disabled, unmounted, token string }{
		{"GET", "/v1/portal/signup/state", "/v1/portal/signup/never-mounted", stranger},
		{"POST", "/v1/portal/signup/organisation", "/v1/portal/signup/never-mounted", stranger},
		{"GET", "/v1/portal/access", "/v1/portal/never-mounted", owner},
		{"POST", "/v1/portal/access/invitations", "/v1/portal/access/never-mounted", owner},
	} {
		got, ref := raw(off, c.method, c.disabled, c.token), raw(off, c.method, c.unmounted, c.token)
		if got.Code != http.StatusNotFound || ref.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d and unmounted %s = %d, want 404 for both", c.method, c.disabled, got.Code, c.unmounted, ref.Code)
		}
		if got.Body.String() != ref.Body.String() || got.Header().Get("Content-Type") != ref.Header().Get("Content-Type") {
			t.Errorf("%s %s answers %q (%s); an unmounted path answers %q (%s)", c.method, c.disabled,
				got.Body.String(), got.Header().Get("Content-Type"), ref.Body.String(), ref.Header().Get("Content-Type"))
		}
	}
	// A wrong method: 405 with the flag off exactly as with it on, where an
	// unmounted path is 404. So the path's existence can be told from this.
	for _, c := range []struct{ method, path, token string }{
		{"DELETE", "/v1/portal/signup/state", stranger},
		{"GET", "/v1/portal/signup/organisation", stranger},
		{"GET", "/v1/portal/signup/invitations/" + pat1883ZeroUUID + "/accept", stranger},
		{"DELETE", "/v1/portal/access", owner},
		{"GET", "/v1/portal/access/invitations", owner},
		{"GET", "/v1/portal/access/members/" + org.Owner + "/role", owner},
		{"GET", "/v1/portal/access/members/" + org.Owner + "/disable", owner},
	} {
		for label, router := range map[string]http.Handler{"flag off": off, "flag on": on} {
			if rr := raw(router, c.method, c.path, c.token); rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: %s %s = %d, want 405", label, c.method, c.path, rr.Code)
			}
		}
	}
	if rr := raw(off, "DELETE", "/v1/portal/signup/never-mounted", stranger); rr.Code != http.StatusNotFound {
		t.Errorf("a wrong method on an unmounted path = %d, want 404", rr.Code)
	}

	// What the group decides before any handler still comes first, flag off.
	svc := f.serviceToken(t)
	for _, route := range pat1883AllNewRoutes() {
		path := pat1883Fill(route[1])
		if rr := raw(off, route[0], path, ""); rr.Code != http.StatusUnauthorized {
			t.Errorf("flag off, no token: %s %s = %d, want 401", route[0], route[1], rr.Code)
		}
		// The read-only service identity: refused on every sign-up route and
		// on every write. Its one permitted read reaches the flag and is 404.
		want := http.StatusForbidden
		if route[0] == http.MethodGet && route[1] == "/v1/portal/access" {
			want = http.StatusNotFound
		}
		if rr := raw(off, route[0], path, svc); rr.Code != want {
			t.Errorf("flag off, service identity: %s %s = %d, want %d", route[0], route[1], rr.Code, want)
		}
	}
	// A person who belongs to no tenant is refused by the tenant group, 403,
	// before the flag is looked at. (On the sign-up group they get the 404.)
	if rr := raw(off, "GET", "/v1/portal/access", stranger); rr.Code != http.StatusForbidden {
		t.Errorf("flag off, non-member on the tenant group = %d, want 403", rr.Code)
	}
	// The per-email request limit of the group, 429.
	tight := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 1})
	verifier := portalauth.New(svcTestIssuer, svcTestAud, f.jwksURL)
	limited := newPublicRouter(f.pool, nil, tight, 5*time.Minute, verifier, tight, tight, "", "", nil, nil, "", nil, "", nil)
	if rr := raw(limited, "GET", "/v1/portal/signup/state", stranger); rr.Code != http.StatusNotFound {
		t.Fatalf("flag off, first request within the limit = %d, want 404", rr.Code)
	}
	if rr := raw(limited, "GET", "/v1/portal/signup/state", stranger); rr.Code != http.StatusTooManyRequests {
		t.Errorf("flag off, second request over the per-email limit = %d, want 429", rr.Code)
	}
}

// A route that takes no input accepts an empty body, {} and a bare JSON null,
// through the production router, and nothing else (the refusals are in
// TestPAT1883IdentityInTheRequestIsRefused).
func TestPAT1883NoInputRoutesAcceptEmptyObjectAndNull(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)
	for label, body := range map[string]any{"no body": nil, "an empty object": `{}`, "null": `null`, "white space": " \n "} {
		member := f.join(t, on, org, "viewer")
		base := "/v1/portal/access/members/" + member
		f.do(t, on, http.MethodPost, base+"/disable", owner, body).want(t, "disable with "+label, http.StatusOK, "")
		f.do(t, on, http.MethodPost, base+"/enable", owner, body).want(t, "enable with "+label, http.StatusOK, "")
		invitee := pat1883Email("null")
		f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+f.invite(t, on, org, invitee, "viewer")+"/revoke", owner, body).
			want(t, "revoke with "+label, http.StatusOK, "")
		f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+f.invite(t, on, org, invitee, "viewer")+"/accept", f.token(t, invitee), body).
			want(t, "accept with "+label, http.StatusOK, "")
	}
}

// ---------------------------------------------------------------------------
// Organisation creation
// ---------------------------------------------------------------------------

func TestPAT1883OrganisationCreation(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	owner := pat1883Email("owner")
	tok := f.token(t, owner)
	name := "Acme Estates " + pat1883Rand()

	st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", tok, nil).want(t, "state before", http.StatusOK, "")
	if st.str("email") != owner || st.JSON["member"] != false || st.JSON["can_create_organisation"] != true {
		t.Fatalf("state before = %s", st.Raw)
	}
	if inv, ok := st.JSON["pending_invitations"].([]any); !ok || len(inv) != 0 {
		t.Fatalf("pending_invitations before = %v, want an empty list", st.JSON["pending_invitations"])
	}
	// Verified, but a member of nothing: no tenant route is reachable.
	f.do(t, on, http.MethodGet, "/v1/portal/me", tok, nil).want(t, "me before", http.StatusForbidden, "")
	f.do(t, on, http.MethodGet, "/v1/portal/access", tok, nil).want(t, "access before", http.StatusForbidden, "")

	r := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tok, map[string]any{"name": "  " + name + "  "}).
		want(t, "create", http.StatusCreated, "")
	tenant := r.str("tenant_id")
	if r.str("organisation_name") != name || r.str("role") != "owner" || len(tenant) != 36 {
		t.Fatalf("create response = %s", r.Raw)
	}
	// The tenant-level ingest credential is generated and never handed out.
	if len(r.JSON) != 3 || strings.Contains(strings.ToLower(r.Raw), "bearer") || strings.Contains(strings.ToLower(r.Raw), "hmac") {
		t.Fatalf("create response carries more than tenant_id, organisation_name and role: %s", r.Raw)
	}

	got := f.text(t, `SELECT name || '|' || created_via || '|' || tenant_kind || '|' || is_trial::text || '|' ||
		(trial_email IS NULL)::text || '|' || (trial_expires_at IS NULL)::text || '|' || (revoked_at IS NULL)::text
		FROM tenants WHERE id=$1::uuid`, tenant)
	if want := name + "|self_service|customer|false|true|true|true"; got != want {
		t.Fatalf("tenant row = %s, want %s", got, want)
	}
	if got := f.text(t, `SELECT tenant_id::text || '|' || role || '|' || (disabled_at IS NULL)::text FROM portal_users WHERE email=$1`, owner); got != tenant+"|owner|true" {
		t.Fatalf("owner row = %s", got)
	}

	// The tenant has a contact from the start: the owner's verified email, so
	// alert and report mail has a recipient without anyone at Patched setting
	// one. Nothing else about the contact is invented.
	if got := f.text(t, `SELECT coalesce(contact_email, 'NULL') || '|' || coalesce(contact_name, 'NULL') || '|' || coalesce(contact_role, 'NULL') FROM tenants WHERE id=$1::uuid`, tenant); got != owner+"|NULL|NULL" {
		t.Fatalf("tenant contact = %s, want the owner's verified email and no name or role", got)
	}
	// The reader the unapproved software alert mail uses finds it.
	recipient, err := softwaregov.TenantRecipient(context.Background(), f.pool, tenant)
	if err != nil || !recipient.Configured || recipient.Email == nil || *recipient.Email != owner {
		t.Fatalf("alert mail recipient = %+v (err %v), want the owner configured", recipient, err)
	}

	// Provisioned exactly like an operator-created tenant.
	operator := f.operatorTenant(t, "parity")
	for _, table := range []string{"tenant_credentials", "tenant_rules", "tenant_app_policies"} {
		self := f.count(t, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1::uuid`, tenant)
		op := f.count(t, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1::uuid`, operator)
		if self != op || (table == "tenant_credentials" && self != 1) {
			t.Errorf("%s: self-service tenant has %d rows, operator tenant has %d", table, self, op)
		}
	}
	if got := f.text(t, `SELECT created_via FROM tenants WHERE id=$1::uuid`, operator); got != "operator" {
		t.Errorf("operator tenant created_via = %q, want operator", got)
	}
	// An operator-created tenant's contact is still whatever the operator
	// gave, which here was nothing.
	if got := f.text(t, `SELECT coalesce(contact_email, 'NULL') FROM tenants WHERE id=$1::uuid`, operator); got != "NULL" {
		t.Errorf("operator tenant contact_email = %q, want none", got)
	}

	if a := f.audit(t, tenant); len(a) != 1 || a[0] != "organisation_created|"+owner+"|"+owner+"||owner|false" {
		t.Fatalf("ledger after create = %v", a)
	}

	st = f.do(t, on, http.MethodGet, "/v1/portal/signup/state", tok, nil).want(t, "state after", http.StatusOK, "")
	if st.JSON["member"] != true || st.JSON["can_create_organisation"] != false {
		t.Fatalf("state after = %s", st.Raw)
	}
	me := f.do(t, on, http.MethodGet, "/v1/portal/me", tok, nil).want(t, "me after", http.StatusOK, "")
	if me.str("role") != "owner" || me.str("tenant_id") != tenant || me.str("email") != owner {
		t.Fatalf("me after = %s", me.Raw)
	}

	// Single use: the same person cannot create a second organisation.
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tok, map[string]any{"name": name + " two"}).
		want(t, "second create", http.StatusConflict, "already_member")
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, name+"%"); n != 1 {
		t.Fatalf("tenants named for this owner = %d, want 1", n)
	}

	// Sign-up requests are audit-logged with no tenant.
	if n := f.count(t, `SELECT count(*) FROM portal_access_log WHERE email=$1 AND tenant_id IS NULL
		AND route IN ('/v1/portal/signup/state', '/v1/portal/signup/organisation')`, owner); n != 4 {
		t.Errorf("portal_access_log sign-up rows with a NULL tenant = %d, want 4", n)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_access_log WHERE email=$1 AND tenant_id IS NOT NULL AND route LIKE '/v1/portal/signup/%'`, owner); n != 0 {
		t.Errorf("%d sign-up access-log rows carry a tenant", n)
	}
}

// N simultaneous creations by one verified person produce one tenant and one
// owner. The portal_users primary key on email is the arbiter.
func TestPAT1883OrganisationCreationIsRaceSafe(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	owner := pat1883Email("racer")
	tok := f.token(t, owner)
	prefix := "PAT1883 race " + pat1883Rand()

	const n = 16
	f.warmPool(t, n) // so the requests really overlap
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tok, map[string]any{"name": prefix + " " + strconv.Itoa(i)})
			codes[i], bodies[i] = r.Code, r.Raw
		}(i)
	}
	close(start)
	wg.Wait()

	created, conflicts := 0, 0
	for i, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		default:
			t.Errorf("request %d = %d: %s", i, c, bodies[i])
		}
	}
	if created != 1 || conflicts != n-1 {
		t.Fatalf("created %d, conflicts %d of %d; want exactly 1 created", created, conflicts, n)
	}
	if got := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, prefix+"%"); got != 1 {
		t.Fatalf("tenants created = %d, want 1 (a losing request left its tenant behind)", got)
	}
	if got := f.count(t, `SELECT count(*) FROM portal_users WHERE email=$1 AND role='owner'`, owner); got != 1 {
		t.Fatalf("owner rows = %d, want 1", got)
	}
	if got := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE actor_email=$1 AND action='organisation_created'`, owner); got != 1 {
		t.Fatalf("organisation_created ledger rows = %d, want 1", got)
	}
	// No orphan credentials or policies from a rolled-back loser.
	if got := f.count(t, `SELECT count(*) FROM tenant_credentials c WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id=c.tenant_id)`); got != 0 {
		t.Fatalf("%d orphan tenant_credentials rows", got)
	}
}

// Nothing a caller sends names the caller or the tenant: identity is the
// verified JWT email only. A request body that carries any key the route
// does not define (a tenant id, an email, a role, a case variant of a real
// key) is refused 400 and changes nothing, as on every other portal write. A
// query parameter or header that tries is not a body key and is ignored.
func TestPAT1883IdentityInTheRequestIsRefused(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	victim := f.newOrg(t, on)
	victimViewer := f.join(t, on, victim, "viewer")
	victimState := func() string {
		return f.text(t, `SELECT string_agg(email || ':' || role || ':' || coalesce(disabled_at::text, ''), ',' ORDER BY email) FROM portal_users WHERE tenant_id=$1::uuid`, victim.Tenant) +
			" invitations=" + strconv.Itoa(f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, victim.Tenant))
	}
	victimBefore := victimState()
	hostile := []string{"X-Tenant-ID", victim.Tenant, "X-Patched-Tenant", victim.Tenant,
		"Cf-Access-Authenticated-User-Email", victim.Owner, "X-Forwarded-Email", victim.Owner}
	refused := func(what string, r pat1883Resp) {
		t.Helper()
		if r.Code != http.StatusBadRequest || r.str("error") != "invalid_request" {
			t.Errorf("%s: %d %s, want 400 invalid_request", what, r.Code, r.Raw)
		}
	}

	// 1. Organisation creation: every extra key is refused and nothing is created.
	mallory := pat1883Email("mallory")
	mtok := f.token(t, mallory)
	name := "PAT1883 Mallory " + pat1883Rand()
	for key, value := range map[string]any{
		"tenant_id": victim.Tenant, "tenantId": victim.Tenant, "email": victim.Owner, "owner_email": victim.Owner,
		"contact_email": victim.Owner, "role": "owner", "created_via": "operator", "is_trial": true, "tier": 3,
		"Name": name, "NAME": name, "name ": name, "": name,
	} {
		body := map[string]any{"name": name, key: value}
		if key == "Name" || key == "NAME" {
			body = map[string]any{key: value} // a case variant standing in for the real key
		}
		refused("create with key "+strconv.Quote(key), f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", mtok, body))
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE name = $1`, name); n != 0 {
		t.Fatalf("%d tenants created by refused requests", n)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE email = $1`, mallory); n != 0 {
		t.Fatal("a refused request gave the caller a membership")
	}
	if st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", mtok, nil); st.JSON["can_create_organisation"] != true {
		t.Fatalf("after refused requests the caller can no longer sign up: %s", st.Raw)
	}

	// A query parameter or header naming the victim is not a credential and
	// not a body key: the request succeeds as the caller's own.
	r := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation?tenant_id="+victim.Tenant+"&email="+victim.Owner,
		mtok, map[string]any{"name": name}, hostile...).want(t, "create with hostile query and headers", http.StatusCreated, "")
	own := r.str("tenant_id")
	if own == victim.Tenant || own == "" {
		t.Fatalf("created into the victim tenant: %s", r.Raw)
	}
	if got := f.text(t, `SELECT tenant_id::text || '|' || role FROM portal_users WHERE email=$1`, mallory); got != own+"|owner" {
		t.Fatalf("mallory row = %s, want own tenant and owner", got)
	}
	st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state?email="+victim.Owner, mtok, nil, hostile...).
		want(t, "state with hostile query and headers", http.StatusOK, "")
	if st.str("email") != mallory {
		t.Fatalf("state answered for %q, want the caller", st.str("email"))
	}

	// 2. Invitation.
	invitee := pat1883Email("invitee")
	for key, value := range map[string]any{"tenant_id": victim.Tenant, "invited_by": victim.Owner, "status": "accepted", "expires_at": "2099-01-01T00:00:00Z", "Role": "admin"} {
		refused("invite with key "+strconv.Quote(key), f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", mtok,
			map[string]any{"email": invitee, "role": "viewer", key: value}))
	}
	if n := f.count(t, `SELECT count(*) FROM portal_invitations WHERE email = $1`, invitee); n != 0 {
		t.Fatalf("%d invitations created by refused requests", n)
	}
	r = f.do(t, on, http.MethodPost, "/v1/portal/access/invitations?tenant_id="+victim.Tenant, mtok,
		map[string]any{"email": invitee, "role": "viewer"}, hostile...).want(t, "invite with hostile query and headers", http.StatusCreated, "")
	inv := r.str("id")
	if got := f.text(t, `SELECT tenant_id::text || '|' || invited_by_email || '|' || status FROM portal_invitations WHERE id=$1::uuid`, inv); got != own+"|"+mallory+"|pending" {
		t.Fatalf("invitation row = %s", got)
	}

	// 3. Acceptance takes no body. Anything in one is refused and the
	// invitation is untouched; then the invitee joins as themselves.
	itok := f.token(t, invitee)
	for _, body := range []any{
		map[string]any{"email": victim.Owner}, map[string]any{"tenant_id": victim.Tenant}, map[string]any{"role": "owner"},
		`{"email": "` + invitee + `"}`, `[]`, `"accept"`, `{} {}`,
	} {
		refused(fmt.Sprintf("accept with body %v", body), f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+inv+"/accept", itok, body))
	}
	if got := f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, inv); got != "pending" {
		t.Fatalf("invitation after refused acceptances = %s, want pending", got)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE email = $1`, invitee); n != 0 {
		t.Fatal("a refused acceptance created a membership")
	}
	r = f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+inv+"/accept?tenant_id="+victim.Tenant, itok, `{}`, hostile...).
		want(t, "accept with an empty object, hostile query and headers", http.StatusOK, "")
	if r.str("tenant_id") != own || r.str("role") != "viewer" {
		t.Fatalf("accept response = %s", r.Raw)
	}

	// 4. Member writes: the role change takes {"role"} only; disable, enable
	// and revoke take no body.
	base := "/v1/portal/access/members/" + invitee
	for key, value := range map[string]any{"tenant_id": victim.Tenant, "email": victimViewer, "member": victimViewer, "ROLE": "admin"} {
		refused("role change with key "+strconv.Quote(key), f.do(t, on, http.MethodPut, base+"/role", mtok, map[string]any{"role": "admin", key: value}))
	}
	other := f.invite(t, on, pat1883Org{Tenant: own, Owner: mallory}, pat1883Email("other"), "viewer")
	for _, path := range []string{base + "/disable", base + "/enable", "/v1/portal/access/invitations/" + other + "/revoke"} {
		refused(path+" with a body", f.do(t, on, http.MethodPost, path, mtok, map[string]any{"tenant_id": victim.Tenant, "email": victimViewer}))
	}
	if got := f.text(t, `SELECT role || '|' || (disabled_at IS NULL)::text FROM portal_users WHERE email=$1`, invitee); got != "viewer|true" {
		t.Fatalf("own member after refused writes = %s, want viewer and enabled", got)
	}
	if got := f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, other); got != "pending" {
		t.Fatalf("invitation after a refused revoke = %s, want pending", got)
	}
	f.do(t, on, http.MethodPut, base+"/role?tenant_id="+victim.Tenant, mtok, map[string]any{"role": "admin"}, hostile...).
		want(t, "role change with hostile query and headers", http.StatusOK, "")
	if got := f.text(t, `SELECT role FROM portal_users WHERE email=$1`, invitee); got != "admin" {
		t.Fatalf("own member role = %s, want admin", got)
	}

	// The victim tenant never moved.
	if after := victimState(); after != victimBefore {
		t.Fatalf("the victim tenant changed:\nbefore %s\nafter  %s", victimBefore, after)
	}
	// A refused request writes no ledger row either.
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid`, own); n != 5 {
		t.Fatalf("ledger rows for the caller's tenant = %d, want 5 (created, invited, accepted, invited, role changed)", n)
	}
}

func TestPAT1883OrganisationNameValidation(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	tok := f.token(t, pat1883Email("namer"))
	marker := "PAT1883 badname " + pat1883Rand()

	for label, body := range map[string]any{
		"missing":          map[string]any{},
		"empty":            map[string]any{"name": ""},
		"spaces only":      map[string]any{"name": "     "},
		"one character":    map[string]any{"name": " A "},
		"81 characters":    map[string]any{"name": marker + strings.Repeat("x", 81-len(marker))},
		"control char":     map[string]any{"name": marker + "\u0007"},
		"newline":          map[string]any{"name": marker + "\nsecond line"},
		"not a string":     map[string]any{"name": 12345},
		"null":             map[string]any{"name": nil},
		"array body":       `["` + marker + `"]`,
		"malformed JSON":   `{"name": "` + marker,
		"trailing content": `{"name": "` + marker + `"} {"name": "x"}`,
		"duplicate name":   `{"name": "` + marker + ` one", "name": "` + marker + ` two"}`,
		"empty body":       nil,
		"unknown key":      map[string]any{"name": marker + " ok", "nickname": "x"},
		"case-variant key": `{"NAME": "` + marker + ` ok"}`,
	} {
		r := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tok, body)
		if r.Code != http.StatusBadRequest || (r.str("error") != "invalid_name" && r.str("error") != "invalid_request") {
			t.Errorf("%s: %d %s, want 400 invalid_name or invalid_request", label, r.Code, r.Raw)
		}
	}
	big := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tok, `{"name":"`+marker+`","pad":"`+strings.Repeat("p", 8<<10)+`"}`)
	if big.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d, want 413", big.Code)
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, marker+"%"); n != 0 {
		t.Fatalf("%d tenants created from refused names", n)
	}

	// A name must not be blank-looking or reordered on screen: it is shown to
	// people the owner invites. Characters a reader cannot see are refused,
	// and at least two characters must be letters or digits.
	selfService := func() int {
		return f.count(t, `SELECT count(*) FROM tenants WHERE created_via = 'self_service'`)
	}
	before := selfService()
	for label, name := range map[string]string{
		"zero-width space":       marker + string(rune(0x200B)),
		"left-to-right mark":     marker + string(rune(0x200E)) + "x",
		"right-to-left override": marker + string(rune(0x202E)) + "dtL emcA",
		"isolate":                string(rune(0x2066)) + marker + string(rune(0x2069)),
		"byte order mark":        string(rune(0xFEFF)) + marker,
		"hangul fillers only":    string(rune(0x3164)) + string(rune(0x3164)) + string(rune(0x3164)),
		"hangul filler inside":   marker + string(rune(0x1160)),
		"punctuation only":       "-- & --",
		"one letter":             "A --",
	} {
		r := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("unseen")), map[string]any{"name": name})
		if r.Code != http.StatusBadRequest || r.str("error") != "invalid_name" {
			t.Errorf("%s (%+q): %d %s, want 400 invalid_name", label, name, r.Code, r.Raw)
		}
	}
	if after := selfService(); after != before {
		t.Fatalf("%d tenants created from names a reader cannot see", after-before)
	}

	// The limits are inclusive: 2 and 80 characters are accepted, and
	// characters are counted, not bytes.
	two := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("two")), map[string]any{"name": "é1"})
	two.want(t, "two characters", http.StatusCreated, "")
	eighty := marker + strings.Repeat("é", 80-len(marker))
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("eighty")), map[string]any{"name": eighty}).
		want(t, "eighty characters", http.StatusCreated, "")
	// A name another organisation already uses is accepted: names are not
	// unique, so creation never says whether a name is taken.
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("same")), map[string]any{"name": eighty}).
		want(t, "same name as another organisation", http.StatusCreated, "")
}

func TestPAT1883OrganisationRefusedForExistingIdentities(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	existing := f.operatorTenant(t, "existing")
	marker := "PAT1883 refused " + pat1883Rand()

	active := f.member(t, existing, "viewer")
	disabled := f.member(t, existing, "admin")
	f.admin(t, http.MethodDelete, "/admin/portal-users/"+disabled, nil).want(t, "disable", http.StatusOK, "")

	claimed := pat1883Rand() + ".claimed.pat1883.invalid"
	f.admin(t, http.MethodPost, "/admin/tenant-email-domains", map[string]any{"domain": claimed, "tenant_id": existing}).
		want(t, "claim domain", http.StatusCreated, "")
	byDomain := "someone-" + pat1883Rand() + "@" + claimed

	for who, email := range map[string]string{"explicit member": active, "disabled member": disabled, "member by domain": byDomain} {
		tok := f.token(t, email)
		st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", tok, nil).want(t, who+" state", http.StatusOK, "")
		if st.JSON["can_create_organisation"] != false {
			t.Errorf("%s: can_create_organisation = %v, want false", who, st.JSON["can_create_organisation"])
		}
		if wantMember := who != "disabled member"; st.JSON["member"] != wantMember {
			t.Errorf("%s: member = %v, want %v", who, st.JSON["member"], wantMember)
		}
		f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tok, map[string]any{"name": marker + " " + who}).
			want(t, who+" create", http.StatusConflict, "already_member")
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, marker+"%"); n != 0 {
		t.Fatalf("%d tenants created for people who already belong somewhere", n)
	}
	if got := f.text(t, `SELECT tenant_id::text || role FROM portal_users WHERE email=$1`, active); got != existing+"viewer" {
		t.Fatalf("existing member's row changed: %s", got)
	}

	// A domain claim that has been disabled no longer makes anyone a member.
	f.admin(t, http.MethodDelete, "/admin/tenant-email-domains/"+claimed, nil).want(t, "disable domain", http.StatusOK, "")
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, byDomain), map[string]any{"name": marker + " free now"}).
		want(t, "create after the claim is disabled", http.StatusCreated, "")
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

func TestPAT1883InvitationLifecycle(t *testing.T) {
	f := newSignupFx(t)
	ttl := 6 * time.Hour
	cfg := pat1883Enabled()
	cfg.InvitationTTL = ttl
	on := f.router(cfg)
	org := f.newOrg(t, on)
	invitee := pat1883Email("invitee")

	r := f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", f.token(t, org.Owner),
		map[string]any{"email": "  " + strings.ToUpper(invitee) + " ", "role": "admin"}).want(t, "create", http.StatusCreated, "")
	id := r.str("id")
	if r.str("email") != invitee || r.str("role") != "admin" || r.str("status") != "pending" || r.str("invited_by") != org.Owner {
		t.Fatalf("invitation = %s", r.Raw)
	}
	expires, err := time.Parse(time.RFC3339, r.str("expires_at"))
	if err != nil || time.Until(expires) < ttl-time.Minute || time.Until(expires) > ttl+time.Minute {
		t.Fatalf("expires_at = %q, want about %s from now", r.str("expires_at"), ttl)
	}
	if !pat1883Contains(f.audit(t, org.Tenant), "invitation_created|"+org.Owner+"|"+invitee+"||admin|true") {
		t.Fatalf("no invitation_created ledger row: %v", f.audit(t, org.Tenant))
	}

	// The owner sees it; the invitee sees it, with the organisation's name.
	list := f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, org.Owner), nil).want(t, "list", http.StatusOK, "")
	if !strings.Contains(list.Raw, id) || !strings.Contains(list.Raw, invitee) || !strings.Contains(list.Raw, org.Owner) {
		t.Fatalf("access list lacks the invitation or the owner: %s", list.Raw)
	}
	st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, invitee), nil).want(t, "invitee state", http.StatusOK, "")
	pending, _ := st.JSON["pending_invitations"].([]any)
	if len(pending) != 1 {
		t.Fatalf("invitee pending_invitations = %s", st.Raw)
	}
	p := pending[0].(map[string]any)
	if p["id"] != id || p["organisation_name"] != org.Name || p["role"] != "admin" || p["expires_at"] == "" {
		t.Fatalf("pending invitation = %v", p)
	}
	// The organisation's name is whatever its owner typed. The invitee is also
	// told who invited them, which the owner did not choose: their verified
	// address. Exactly these five keys and nothing else about the tenant.
	if p["invited_by"] != org.Owner || len(p) != 5 {
		t.Fatalf("pending invitation = %v, want invited_by %q and five keys", p, org.Owner)
	}
	// An invitation is not membership.
	f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, invitee), nil).want(t, "invitee before accepting", http.StatusForbidden, "")

	// A second invitation for the same address while one is pending.
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", f.token(t, org.Owner), map[string]any{"email": invitee, "role": "viewer"}).
		want(t, "duplicate pending", http.StatusConflict, "invitation_pending")

	acc := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, invitee), nil).want(t, "accept", http.StatusOK, "")
	if acc.str("tenant_id") != org.Tenant || acc.str("role") != "admin" || acc.str("organisation_name") != org.Name {
		t.Fatalf("accept = %s", acc.Raw)
	}
	if got := f.text(t, `SELECT tenant_id::text || '|' || role FROM portal_users WHERE email=$1`, invitee); got != org.Tenant+"|admin" {
		t.Fatalf("invitee row = %s", got)
	}
	if got := f.text(t, `SELECT status || '|' || (accepted_at IS NOT NULL)::text FROM portal_invitations WHERE id=$1::uuid`, id); got != "accepted|true" {
		t.Fatalf("invitation after accept = %s", got)
	}
	if !pat1883Contains(f.audit(t, org.Tenant), "invitation_accepted|"+invitee+"|"+invitee+"||admin|true") {
		t.Fatalf("no invitation_accepted ledger row: %v", f.audit(t, org.Tenant))
	}
	me := f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, invitee), nil).want(t, "me after accepting", http.StatusOK, "")
	if me.str("role") != "admin" || me.str("tenant_id") != org.Tenant {
		t.Fatalf("me = %s", me.Raw)
	}

	// Single use.
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, invitee), nil).
		want(t, "reuse of an accepted invitation", http.StatusGone, "invitation_accepted")
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE invitation_id=$1::uuid AND action='invitation_accepted'`, id); n != 1 {
		t.Fatalf("invitation_accepted rows = %d, want 1", n)
	}
	// Already a member here: no further invitation.
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", f.token(t, org.Owner), map[string]any{"email": invitee, "role": "viewer"}).
		want(t, "invite an existing member", http.StatusConflict, "already_member")
}

// An invitation is single use under real concurrency, not only in sequence:
// many simultaneous accepts by its invitee give one membership. The others
// are told it has been used.
func TestPAT1883InvitationAcceptanceIsRaceSafe(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	invitee := pat1883Email("racer")
	id := f.invite(t, on, org, invitee, "admin")
	tok := f.token(t, invitee)

	const n = 16
	f.warmPool(t, n) // so the requests really overlap
	codes, errs, bodies := make([]int, n), make([]string, n), make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", tok, nil)
			codes[i], errs[i], bodies[i] = r.Code, r.str("error"), r.Raw
		}(i)
	}
	close(start)
	wg.Wait()

	accepted, used := 0, 0
	for i, c := range codes {
		switch {
		case c == http.StatusOK:
			accepted++
		case c == http.StatusGone && errs[i] == "invitation_accepted":
			used++
		default:
			t.Errorf("request %d = %d: %s", i, c, bodies[i])
		}
	}
	if accepted != 1 || used != n-1 {
		t.Fatalf("%d accepted and %d told it was used, of %d; want exactly 1 and %d", accepted, used, n, n-1)
	}
	if got := f.text(t, `SELECT count(*)::text || '|' || min(tenant_id::text) || '|' || min(role) FROM portal_users WHERE email = $1`, invitee); got != "1|"+org.Tenant+"|admin" {
		t.Fatalf("memberships for the invitee = %s, want one, in the inviting tenant, as admin", got)
	}
	if got := f.text(t, `SELECT status || '|' || (accepted_at IS NOT NULL)::text FROM portal_invitations WHERE id = $1::uuid`, id); got != "accepted|true" {
		t.Fatalf("invitation = %s, want accepted", got)
	}
	if got := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE invitation_id = $1::uuid AND action = 'invitation_accepted'`, id); got != 1 {
		t.Fatalf("invitation_accepted ledger rows = %d, want 1", got)
	}
	if got := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id = $1::uuid AND subject_email = $2`, org.Tenant, invitee); got != 2 {
		t.Fatalf("ledger rows about the invitee = %d, want 2 (invited, accepted)", got)
	}
}

// The invitee accepts at the same moment the owner revokes. Exactly one of
// them happens, the other is told so, and the membership, the invitation and
// the ledger all say the same thing. Repeated, because which side wins is a
// matter of timing and both orders have to hold.
func TestPAT1883AcceptRacingRevokeHasOneOutcome(t *testing.T) {
	f := newSignupFx(t)
	cfg := pat1883Enabled()
	cfg.InvitationsPerTenantPerHour = 1000 // this test creates more than the default hourly allowance
	on := f.router(cfg)
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)

	const rounds = 24
	f.warmPool(t, 4) // both requests of a round find an open connection
	acceptWon, revokeWon := 0, 0
	for round := 0; round < rounds; round++ {
		invitee := pat1883Email("race")
		id := f.invite(t, on, org, invitee, "viewer")
		tok := f.token(t, invitee)

		var acc, rev pat1883Resp
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			acc = f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", tok, nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			rev = f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+id+"/revoke", owner, nil)
		}()
		close(start)
		wg.Wait()

		rows := f.text(t, `
			SELECT (SELECT status FROM portal_invitations WHERE id = $1::uuid)
			    || ' members=' || (SELECT count(*) FROM portal_users WHERE email = $2)::text
			    || ' accepted=' || (SELECT count(*) FROM portal_access_audit WHERE invitation_id = $1::uuid AND action = 'invitation_accepted')::text
			    || ' revoked=' || (SELECT count(*) FROM portal_access_audit WHERE invitation_id = $1::uuid AND action = 'invitation_revoked')::text`, id, invitee)
		switch {
		case acc.Code == http.StatusOK:
			// The acceptance happened: the revocation must have been refused.
			acceptWon++
			if rev.Code != http.StatusConflict || rev.str("error") != "invitation_accepted" {
				t.Fatalf("round %d: accept = 200 and revoke = %d %s; want 409 invitation_accepted", round, rev.Code, rev.Raw)
			}
			if rows != "accepted members=1 accepted=1 revoked=0" {
				t.Fatalf("round %d: accept won but the rows say: %s", round, rows)
			}
			f.do(t, on, http.MethodGet, "/v1/portal/me", tok, nil).want(t, "the member after winning", http.StatusOK, "")
		case rev.Code == http.StatusOK && rev.JSON["changed"] == true:
			// The revocation happened: the acceptance must have been refused.
			revokeWon++
			if acc.Code != http.StatusGone || acc.str("error") != "invitation_revoked" {
				t.Fatalf("round %d: revoke = 200 and accept = %d %s; want 410 invitation_revoked", round, acc.Code, acc.Raw)
			}
			if rows != "revoked members=0 accepted=0 revoked=1" {
				t.Fatalf("round %d: revoke won but the rows say: %s", round, rows)
			}
			f.do(t, on, http.MethodGet, "/v1/portal/me", tok, nil).want(t, "the invitee after losing", http.StatusForbidden, "")
		default:
			t.Fatalf("round %d: neither happened cleanly: accept = %d %s; revoke = %d %s; rows: %s", round, acc.Code, acc.Raw, rev.Code, rev.Raw, rows)
		}
	}
	t.Logf("%d rounds: the acceptance won %d, the revocation won %d", rounds, acceptWon, revokeWon)
}

func TestPAT1883InvitationRevokeAndExpiry(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)

	// Revoked.
	revokee := pat1883Email("revokee")
	rid := f.invite(t, on, org, revokee, "viewer")
	rv := f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+rid+"/revoke", owner, nil).want(t, "revoke", http.StatusOK, "")
	if rv.str("status") != "revoked" || rv.JSON["changed"] != true || rv.str("revoked_at") == "" {
		t.Fatalf("revoke = %s", rv.Raw)
	}
	if !pat1883Contains(f.audit(t, org.Tenant), "invitation_revoked|"+org.Owner+"|"+revokee+"|viewer||true") {
		t.Fatalf("no invitation_revoked ledger row: %v", f.audit(t, org.Tenant))
	}
	again := f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+rid+"/revoke", owner, nil).want(t, "revoke again", http.StatusOK, "")
	if again.JSON["changed"] != false {
		t.Fatalf("second revoke = %s, want changed false", again.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE invitation_id=$1::uuid AND action='invitation_revoked'`, rid); n != 1 {
		t.Fatalf("invitation_revoked rows = %d, want 1 (a no-op revoke must not write)", n)
	}
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+rid+"/accept", f.token(t, revokee), nil).
		want(t, "accept a revoked invitation", http.StatusGone, "invitation_revoked")
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE email=$1`, revokee); n != 0 {
		t.Fatal("a revoked invitation created a member")
	}
	if st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, revokee), nil); strings.Contains(st.Raw, rid) {
		t.Fatalf("revoked invitation still offered to the invitee: %s", st.Raw)
	}

	// Expired: nothing sweeps it, the row still says pending, and it is
	// refused and no longer offered because expires_at is read every time.
	expiree := pat1883Email("expiree")
	eid := f.invite(t, on, org, expiree, "admin")
	f.exec(t, `UPDATE portal_invitations SET created_at = now() - interval '9 days', expires_at = now() - interval '1 minute' WHERE id=$1::uuid`, eid)
	if got := f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, eid); got != "pending" {
		t.Fatalf("expired invitation's stored status = %s, want pending (expiry is not a stored state)", got)
	}
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+eid+"/accept", f.token(t, expiree), nil).
		want(t, "accept an expired invitation", http.StatusGone, "invitation_expired")
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE email=$1`, expiree); n != 0 {
		t.Fatal("an expired invitation created a member")
	}
	if st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, expiree), nil); strings.Contains(st.Raw, eid) {
		t.Fatalf("expired invitation still offered to the invitee: %s", st.Raw)
	}
	list := f.do(t, on, http.MethodGet, "/v1/portal/access", owner, nil).want(t, "list", http.StatusOK, "")
	statuses := map[string]string{}
	for _, raw := range list.JSON["invitations"].([]any) {
		inv := raw.(map[string]any)
		statuses[inv["id"].(string)] = inv["status"].(string)
	}
	if statuses[rid] != "revoked" || statuses[eid] != "expired" {
		t.Fatalf("listed statuses = %v, want %s revoked and %s expired", statuses, rid, eid)
	}

	// Inviting the same address again retires the expired invitation and
	// issues a new one; the old id stays dead.
	neu := f.invite(t, on, org, expiree, "viewer")
	if neu == eid {
		t.Fatal("re-invitation reused the expired invitation's id")
	}
	if got := f.text(t, `SELECT status || '|' || coalesce(revoked_by_email,'') FROM portal_invitations WHERE id=$1::uuid`, eid); got != "revoked|"+org.Owner {
		t.Fatalf("superseded invitation = %s, want revoked by the owner", got)
	}
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+eid+"/accept", f.token(t, expiree), nil).
		want(t, "accept the superseded invitation", http.StatusGone, "invitation_revoked")
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+neu+"/accept", f.token(t, expiree), nil).
		want(t, "accept the new invitation", http.StatusOK, "")

	// An accepted invitation cannot be revoked; the member is disabled instead.
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+neu+"/revoke", owner, nil).
		want(t, "revoke an accepted invitation", http.StatusConflict, "invitation_accepted")
}

// Only the person the invitation was addressed to can accept it, and nobody
// else can tell that it exists.
// An invitation is only as good as the authority of the owner who sent it.
// Once that person is no longer an enabled owner of the tenant (the operator
// disabled them, demoted them or moved them elsewhere) their pending
// invitations cannot be accepted and are not offered to the invitee. The
// stored status stays pending: the invitation is still listed to the tenant,
// still blocks a second invitation to the same address until it is revoked or
// expires, and is usable again if the inviter is restored.
func TestPAT1883AnInvitationNeedsItsInviterToStillBeAnOwner(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	accept := func(id, invitee string) pat1883Resp {
		t.Helper()
		return f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, invitee), nil)
	}
	offered := func(invitee string) int {
		t.Helper()
		st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, invitee), nil).want(t, "state", http.StatusOK, "")
		list, ok := st.JSON["pending_invitations"].([]any)
		if !ok {
			t.Fatalf("state has no pending_invitations list: %s", st.Raw)
		}
		return len(list)
	}

	// What a really revoked invitation answers, to compare with.
	ref := f.newOrg(t, on)
	refInvitee := pat1883Email("ref")
	refID := f.invite(t, on, ref, refInvitee, "viewer")
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+refID+"/revoke", f.token(t, ref.Owner), nil).want(t, "revoke", http.StatusOK, "")
	revoked := accept(refID, refInvitee).want(t, "accept a revoked invitation", http.StatusGone, "invitation_revoked")

	refused := func(what, id, invitee, tenant string) {
		t.Helper()
		r := accept(id, invitee)
		if r.Code != http.StatusGone || r.str("error") != "invitation_revoked" {
			t.Fatalf("%s: accept = %d %s, want 410 invitation_revoked", what, r.Code, r.Raw)
		}
		if r.Raw != revoked.Raw {
			t.Errorf("%s: the answer differs from a revoked invitation's:\n got %s\nwant %s", what, r.Raw, revoked.Raw)
		}
		if n := f.count(t, `SELECT count(*) FROM portal_users WHERE email = $1`, invitee); n != 0 {
			t.Fatalf("%s: the refused accept created a membership", what)
		}
		if got := f.text(t, `SELECT status FROM portal_invitations WHERE id = $1::uuid`, id); got != "pending" {
			t.Fatalf("%s: stored status = %s, want pending (not rewritten)", what, got)
		}
		if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id = $1::uuid AND invitation_id = $2::uuid AND action <> 'invitation_created'`, tenant, id); n != 0 {
			t.Fatalf("%s: the refused accept wrote %d ledger rows", what, n)
		}
		if n := offered(invitee); n != 0 {
			t.Fatalf("%s: state still offers %d invitations", what, n)
		}
		f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, invitee), nil).want(t, what+": invitee", http.StatusForbidden, "")
	}

	// 1. The operator disables the owner.
	a := f.newOrg(t, on)
	inviteeA := pat1883Email("a")
	idA := f.invite(t, on, a, inviteeA, "admin")
	if n := offered(inviteeA); n != 1 {
		t.Fatalf("control: state offers %d invitations before the owner is disabled, want 1", n)
	}
	f.admin(t, http.MethodDelete, "/admin/portal-users/"+a.Owner, nil).want(t, "operator disables the owner", http.StatusOK, "")
	refused("inviter disabled by the operator", idA, inviteeA, a.Tenant)
	// The operator restores the owner: the same invitation works again.
	f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": a.Owner, "tenant_id": a.Tenant}).want(t, "operator restores the owner", http.StatusCreated, "")
	if n := offered(inviteeA); n != 1 {
		t.Fatalf("state offers %d invitations after the owner was restored, want 1", n)
	}
	accept(idA, inviteeA).want(t, "accept after the owner was restored", http.StatusOK, "")

	// 2. The operator demotes the owner.
	b := f.newOrg(t, on)
	inviteeB := pat1883Email("b")
	idB := f.invite(t, on, b, inviteeB, "viewer")
	f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": b.Owner, "tenant_id": b.Tenant, "role": "admin"}).
		want(t, "operator demotes the owner", http.StatusCreated, "")
	refused("inviter demoted to admin", idB, inviteeB, b.Tenant)
	// The tenant still sees it as pending (the demoted owner is an admin and may read the list).
	list := f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, b.Owner), nil).want(t, "access list", http.StatusOK, "")
	seen := false
	for _, raw := range list.JSON["invitations"].([]any) {
		if inv := raw.(map[string]any); inv["id"] == idB {
			seen = inv["status"] == "pending" && inv["invited_by"] == b.Owner
		}
	}
	if !seen {
		t.Fatalf("the tenant's list does not show the invitation as pending from its inviter: %s", list.Raw)
	}
	// A second owner, made by the operator, cannot invite that address while
	// the stale invitation is pending, can revoke it, and then can.
	second := f.member(t, b.Tenant, "owner")
	secondOrg := pat1883Org{Tenant: b.Tenant, Owner: second, Name: b.Name}
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", f.token(t, second), map[string]any{"email": inviteeB, "role": "viewer"}).
		want(t, "re-invite while the stale invitation is pending", http.StatusConflict, "invitation_pending")
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+idB+"/revoke", f.token(t, second), nil).want(t, "second owner revokes the stale invitation", http.StatusOK, "")
	idB2 := f.invite(t, on, secondOrg, inviteeB, "viewer")
	if n := offered(inviteeB); n != 1 {
		t.Fatalf("state offers %d invitations from the second owner, want 1", n)
	}
	// The second owner's invitations work, including for someone else.
	accept(idB2, inviteeB).want(t, "accept the second owner's invitation", http.StatusOK, "")
	other := pat1883Email("b-other")
	accept(f.invite(t, on, secondOrg, other, "admin"), other).want(t, "accept another of the second owner's invitations", http.StatusOK, "")

	// 3. The operator moves the owner to another tenant, still as an owner.
	c := f.newOrg(t, on)
	inviteeC := pat1883Email("c")
	idC := f.invite(t, on, c, inviteeC, "viewer")
	f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": c.Owner, "tenant_id": f.operatorTenant(t, "moved"), "role": "owner"}).
		want(t, "operator moves the owner to another tenant", http.StatusCreated, "")
	refused("inviter is an owner of a different tenant now", idC, inviteeC, c.Tenant)
}

func TestPAT1883InvitationAcceptByADifferentEmail(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	invitee, thief := pat1883Email("invitee"), pat1883Email("thief")
	id := f.invite(t, on, org, invitee, "admin")

	missing := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+pat1883ZeroUUID+"/accept", f.token(t, thief), nil).
		want(t, "missing invitation", http.StatusNotFound, "not_found")
	for label, tok := range map[string]string{
		"a stranger":               f.token(t, thief),
		"the inviting owner":       f.token(t, org.Owner),
		"another org's owner":      f.token(t, f.newOrg(t, on).Owner),
		"a near-miss address":      f.token(t, "x"+invitee),
		"a sub-address":            f.token(t, strings.Replace(invitee, "@", "+tag@", 1)),
		"same local, other domain": f.token(t, strings.Split(invitee, "@")[0]+"@other.pat1883.invalid"),
	} {
		r := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", tok, nil)
		if r.Code != missing.Code || r.Raw != missing.Raw {
			t.Errorf("%s: %d %s, want exactly the missing-invitation answer %d %s", label, r.Code, r.Raw, missing.Code, missing.Raw)
		}
		// Claiming the invitee's address in a body does not help: a body is
		// refused whatever it says, the same for a real id and a missing one.
		claim := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", tok, map[string]any{"email": invitee})
		claimMissing := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+pat1883ZeroUUID+"/accept", tok, map[string]any{"email": invitee})
		if claim.Code != http.StatusBadRequest || claim.Code != claimMissing.Code || claim.Raw != claimMissing.Raw {
			t.Errorf("%s with a body naming the invitee: %d %s; for a missing id %d %s; want identical 400s", label, claim.Code, claim.Raw, claimMissing.Code, claimMissing.Raw)
		}
	}
	for _, bad := range []string{"not-a-uuid", "1", strings.ToUpper(id) + "x"} {
		r := f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+bad+"/accept", f.token(t, invitee), nil)
		if r.Code != http.StatusNotFound {
			t.Errorf("malformed id %q = %d, want 404", bad, r.Code)
		}
	}
	if got := f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, id); got != "pending" {
		t.Fatalf("invitation after refused attempts = %s, want pending", got)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid`, org.Tenant); n != 1 {
		t.Fatalf("tenant has %d members after refused attempts, want only the owner", n)
	}
	// The stranger's view of their own invitations says nothing about it.
	if st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, thief), nil); strings.Contains(st.Raw, id) || strings.Contains(st.Raw, org.Name) {
		t.Fatalf("a stranger's state mentions someone else's invitation: %s", st.Raw)
	}
	// And the rightful invitee still can.
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, invitee), nil).want(t, "rightful accept", http.StatusOK, "")
}

// Creating an invitation checks this tenant only, so it never reveals whether
// an address is known to another tenant. A clash surfaces to the invitee, at
// acceptance.
func TestPAT1883InvitationCreationIsNotAMembershipOracle(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org, other := f.newOrg(t, on), f.newOrg(t, on)
	owner := f.token(t, org.Owner)

	otherMember := f.join(t, on, other, "admin")
	otherDisabled := f.join(t, on, other, "viewer")
	f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+otherDisabled+"/disable", f.token(t, other.Owner), nil).want(t, "disable", http.StatusOK, "")
	otherPending := pat1883Email("pending-elsewhere")
	f.invite(t, on, other, otherPending, "viewer")
	claimed := pat1883Rand() + ".claimed.pat1883.invalid"
	f.admin(t, http.MethodPost, "/admin/tenant-email-domains", map[string]any{"domain": claimed, "tenant_id": other.Tenant}).want(t, "claim", http.StatusCreated, "")

	keys := func(m map[string]any) string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	fresh := f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", owner, map[string]any{"email": pat1883Email("fresh"), "role": "viewer"}).
		want(t, "fresh address", http.StatusCreated, "")
	for label, email := range map[string]string{
		"an active member of another tenant":    otherMember,
		"another tenant's owner":                other.Owner,
		"a disabled member of another tenant":   otherDisabled,
		"an address invited by another tenant":  otherPending,
		"an address on another tenant's domain": "x-" + pat1883Rand() + "@" + claimed,
	} {
		r := f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", owner, map[string]any{"email": email, "role": "viewer"})
		if r.Code != fresh.Code || keys(r.JSON) != keys(fresh.JSON) || r.str("status") != "pending" {
			t.Errorf("%s: %d %s; want the same answer as a fresh address (%d, keys %s)", label, r.Code, r.Raw, fresh.Code, keys(fresh.JSON))
		}
	}

	// The clash is the invitee's to see.
	var id string
	if err := f.pool.QueryRow(context.Background(), `SELECT id::text FROM portal_invitations WHERE tenant_id=$1::uuid AND email=$2`, org.Tenant, otherMember).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, otherMember), nil).
		want(t, "accept while a member elsewhere", http.StatusConflict, "already_member")
	if got := f.text(t, `SELECT tenant_id::text FROM portal_users WHERE email=$1`, otherMember); got != other.Tenant {
		t.Fatalf("member moved tenant: %s", got)
	}
	if got := f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, id); got != "pending" {
		t.Fatalf("refused acceptance consumed the invitation: %s", got)
	}

	// Validation.
	for label, body := range map[string]any{
		"owner role":      map[string]any{"email": pat1883Email("o"), "role": "owner"},
		"unknown role":    map[string]any{"email": pat1883Email("o"), "role": "superuser"},
		"service role":    map[string]any{"email": pat1883Email("o"), "role": "service_readonly"},
		"missing role":    map[string]any{"email": pat1883Email("o")},
		"upper-case role": map[string]any{"email": pat1883Email("o"), "role": "Admin"},
		"missing email":   map[string]any{"role": "viewer"},
		"no at sign":      map[string]any{"email": "not-an-address", "role": "viewer"},
		"display name":    map[string]any{"email": "Someone <a@b.pat1883.invalid>", "role": "viewer"},
		"two addresses":   map[string]any{"email": "a@b.pat1883.invalid, c@d.pat1883.invalid", "role": "viewer"},
		"control char":    map[string]any{"email": "a\u0000b@c.pat1883.invalid", "role": "viewer"},
		"too long":        map[string]any{"email": strings.Repeat("a", 320) + "@c.pat1883.invalid", "role": "viewer"},
		"malformed":       `{"email": `,
		"unknown key":     map[string]any{"email": pat1883Email("o"), "role": "viewer", "note": "hello"},
		"tenant id":       map[string]any{"email": pat1883Email("o"), "role": "viewer", "tenant_id": other.Tenant},
	} {
		r := f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", owner, body)
		if r.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", label, r.Code, r.Raw)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid AND role NOT IN ('admin','viewer')`, org.Tenant); n != 0 {
		t.Fatal("an invitation with a role other than admin or viewer exists")
	}
}

// ---------------------------------------------------------------------------
// Owner, admin and viewer permissions
// ---------------------------------------------------------------------------

func TestPAT1883OnlyAnOwnerManagesAccess(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	admin, viewer := f.join(t, on, org, "admin"), f.join(t, on, org, "viewer")
	target := f.join(t, on, org, "viewer")
	pending := f.invite(t, on, org, pat1883Email("pending"), "viewer")
	claimed := pat1883Rand() + ".claimed.pat1883.invalid"
	f.admin(t, http.MethodPost, "/admin/tenant-email-domains", map[string]any{"domain": claimed, "tenant_id": org.Tenant}).want(t, "claim", http.StatusCreated, "")
	byDomain := "d-" + pat1883Rand() + "@" + claimed

	state := func() string {
		return f.text(t, `SELECT role || '|' || (disabled_at IS NULL)::text FROM portal_users WHERE email=$1`, target) + " " +
			f.text(t, `SELECT status FROM portal_invitations WHERE id=$1::uuid`, pending) + " " +
			strconv.Itoa(f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, org.Tenant)) + " " +
			strconv.Itoa(len(f.audit(t, org.Tenant)))
	}
	before := state()

	writes := []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/portal/access/invitations", map[string]any{"email": pat1883Email("new"), "role": "admin"}},
		{"POST", "/v1/portal/access/invitations/" + pending + "/revoke", nil},
		{"PUT", "/v1/portal/access/members/" + target + "/role", map[string]any{"role": "admin"}},
		{"POST", "/v1/portal/access/members/" + target + "/disable", nil},
		{"POST", "/v1/portal/access/members/" + target + "/enable", nil},
		// An admin must not be able to promote themselves either.
		{"PUT", "/v1/portal/access/members/" + admin + "/role", map[string]any{"role": "admin"}},
		{"PUT", "/v1/portal/access/members/" + viewer + "/role", map[string]any{"role": "admin"}},
	}
	for who, email := range map[string]string{"admin": admin, "viewer": viewer, "member by domain": byDomain} {
		for _, w := range writes {
			f.do(t, on, w.method, w.path, f.token(t, email), w.body).want(t, who+" "+w.method+" "+w.path, http.StatusForbidden, "owner_role_required")
		}
	}
	if after := state(); after != before {
		t.Fatalf("refused access writes changed state:\nbefore %s\nafter  %s", before, after)
	}

	// Reading who has access: owner and admin, not a viewer.
	f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, org.Owner), nil).want(t, "owner reads", http.StatusOK, "")
	ad := f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, admin), nil).want(t, "admin reads", http.StatusOK, "")
	if ad.str("role") != "admin" || !strings.Contains(ad.Raw, target) {
		t.Fatalf("admin's access list = %s", ad.Raw)
	}
	for who, email := range map[string]string{"viewer": viewer, "member by domain": byDomain} {
		r := f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, email), nil).want(t, who+" reads", http.StatusForbidden, "admin_role_required")
		if strings.Contains(r.Raw, target) || strings.Contains(r.Raw, org.Owner) {
			t.Fatalf("%s's refusal lists members: %s", who, r.Raw)
		}
	}

	// The owner can do every one of them (control: the 403s were the role).
	for _, w := range writes[:5] {
		if r := f.do(t, on, w.method, w.path, f.token(t, org.Owner), w.body); r.Code != http.StatusOK && r.Code != http.StatusCreated {
			t.Errorf("owner %s %s = %d: %s", w.method, w.path, r.Code, r.Raw)
		}
	}
}

func TestPAT1883MemberRoleDisableAndEnable(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)
	member := f.join(t, on, org, "viewer")
	mtok := f.token(t, member)
	rolePath := "/v1/portal/access/members/" + member + "/role"

	r := f.do(t, on, http.MethodPut, rolePath, owner, map[string]any{"role": "admin"}).want(t, "promote", http.StatusOK, "")
	if r.str("email") != member || r.str("role") != "admin" || r.JSON["changed"] != true {
		t.Fatalf("promote = %s", r.Raw)
	}
	if me := f.do(t, on, http.MethodGet, "/v1/portal/me", mtok, nil); me.str("role") != "admin" {
		t.Fatalf("member's role after promotion = %s", me.Raw)
	}
	if !pat1883Contains(f.audit(t, org.Tenant), "role_changed|"+org.Owner+"|"+member+"|viewer|admin|false") {
		t.Fatalf("no role_changed ledger row: %v", f.audit(t, org.Tenant))
	}
	rows := len(f.audit(t, org.Tenant))
	same := f.do(t, on, http.MethodPut, rolePath, owner, map[string]any{"role": "admin"}).want(t, "same role", http.StatusOK, "")
	if same.JSON["changed"] != false || len(f.audit(t, org.Tenant)) != rows {
		t.Fatalf("setting the same role = %s with %d ledger rows, want changed false and %d", same.Raw, len(f.audit(t, org.Tenant)), rows)
	}
	for _, bad := range []any{map[string]any{"role": "owner"}, map[string]any{"role": "superuser"}, map[string]any{"role": ""}, map[string]any{}, `{"role":`} {
		f.do(t, on, http.MethodPut, rolePath, owner, bad).want(t, fmt.Sprintf("role %v", bad), http.StatusBadRequest, "")
	}
	if got := f.text(t, `SELECT role FROM portal_users WHERE email=$1`, member); got != "admin" {
		t.Fatalf("role after refused changes = %s", got)
	}

	// The address in the path is matched case-insensitively and may be
	// percent-encoded.
	enc := strings.ToUpper(strings.Replace(member, "@", "%40", 1))
	f.do(t, on, http.MethodPut, "/v1/portal/access/members/"+enc+"/role", owner, map[string]any{"role": "viewer"}).want(t, "encoded address", http.StatusOK, "")
	if got := f.text(t, `SELECT role FROM portal_users WHERE email=$1`, member); got != "viewer" {
		t.Fatalf("role after encoded-address change = %s", got)
	}

	// Disable: the member loses access at once and it is recorded.
	d := f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+member+"/disable", owner, nil).want(t, "disable", http.StatusOK, "")
	if d.JSON["changed"] != true || d.str("disabled_at") == "" {
		t.Fatalf("disable = %s", d.Raw)
	}
	f.do(t, on, http.MethodGet, "/v1/portal/me", mtok, nil).want(t, "disabled member", http.StatusForbidden, "")
	if !pat1883Contains(f.audit(t, org.Tenant), "member_disabled|"+org.Owner+"|"+member+"|viewer|viewer|false") {
		t.Fatalf("no member_disabled ledger row: %v", f.audit(t, org.Tenant))
	}
	rows = len(f.audit(t, org.Tenant))
	if again := f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+member+"/disable", owner, nil); again.JSON["changed"] != false || len(f.audit(t, org.Tenant)) != rows {
		t.Fatalf("second disable = %s, want changed false and no ledger row", again.Raw)
	}
	// A disabled person cannot start again somewhere else under the same address.
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", mtok, map[string]any{"name": "PAT1883 escape " + pat1883Rand()}).
		want(t, "disabled member creates an organisation", http.StatusConflict, "already_member")

	e := f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+member+"/enable", owner, nil).want(t, "enable", http.StatusOK, "")
	if e.JSON["changed"] != true || e.JSON["disabled_at"] != nil {
		t.Fatalf("enable = %s", e.Raw)
	}
	f.do(t, on, http.MethodGet, "/v1/portal/me", mtok, nil).want(t, "enabled member", http.StatusOK, "")
	if !pat1883Contains(f.audit(t, org.Tenant), "member_enabled|"+org.Owner+"|"+member+"|viewer|viewer|false") {
		t.Fatalf("no member_enabled ledger row: %v", f.audit(t, org.Tenant))
	}

	missing := "/v1/portal/access/members/" + pat1883Email("nobody")
	f.do(t, on, http.MethodPut, missing+"/role", owner, map[string]any{"role": "admin"}).want(t, "unknown member role", http.StatusNotFound, "not_found")
	f.do(t, on, http.MethodPost, missing+"/disable", owner, nil).want(t, "unknown member disable", http.StatusNotFound, "not_found")
	f.do(t, on, http.MethodPost, missing+"/enable", owner, nil).want(t, "unknown member enable", http.StatusNotFound, "not_found")
}

// An owner cannot change, disable or demote themselves or another owner, so
// these routes can never leave a tenant without an active owner.
// The {memberEmail} path segment is percent-decoded exactly once. chi hands
// the handler a decoded parameter when the request path was in its canonical
// encoding and a still-encoded one otherwise; decoding the first kind again
// turned "%2541" into "A" and made a request for one member act on another.
// Through the production router, with paths as a client sends them.
func TestPAT1883MemberAddressIsDecodedOnce(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)
	// Two members of one tenant. The first has a literal "%41" in its
	// address; the second is what the first becomes if "%41" is decoded.
	tail := "-" + pat1883Rand() + "@" + pat1883Rand() + ".pat1883.invalid"
	literal, lookalike := "p%41q"+tail, "paq"+tail
	for _, email := range []string{literal, lookalike} {
		id := f.invite(t, on, org, email, "viewer")
		f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, email), nil).want(t, "accept as "+email, http.StatusOK, "")
	}
	state := func() string {
		t.Helper()
		return f.text(t, `SELECT string_agg(role || ':' || (disabled_at IS NULL)::text, ' ' ORDER BY email) FROM portal_users WHERE email IN ($1, $2)`, literal, lookalike)
	}
	// ORDER BY email: "p%41q..." sorts before "paq...", in any collation that
	// compares the third character at all ("%" before "a").
	if got := state(); got != "viewer:true viewer:true" {
		t.Fatalf("fixture: %s", got)
	}
	touched := func(email string) int {
		t.Helper()
		return f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id = $1::uuid AND subject_email = $2 AND action IN ('role_changed','member_disabled','member_enabled')`, org.Tenant, email)
	}
	base := "/v1/portal/access/members/"
	// The literal "%" must be sent as "%25". This path is in its canonical
	// encoding, so the router matches on the decoded path.
	canonical := strings.Replace(literal, "%", "%25", 1)
	// The same address with "@" encoded as well: not canonical, so the router
	// matches on the raw path and the handler does the decoding.
	encodedAt := strings.Replace(canonical, "@", "%40", 1)

	f.do(t, on, http.MethodPost, base+canonical+"/disable", owner, nil).want(t, "disable the member with a literal %41", http.StatusOK, "")
	if got := state(); got != "viewer:false viewer:true" {
		t.Fatalf("after disabling %q: %s; want that member disabled and the other untouched", literal, got)
	}
	f.do(t, on, http.MethodPost, base+encodedAt+"/enable", owner, nil).want(t, "enable it, with %40 for @", http.StatusOK, "")
	f.do(t, on, http.MethodPut, base+canonical+"/role", owner, map[string]any{"role": "admin"}).want(t, "promote it", http.StatusOK, "")
	if got := state(); got != "admin:true viewer:true" {
		t.Fatalf("after enabling and promoting %q: %s; want admin:true and the other untouched", literal, got)
	}
	if n := touched(lookalike); n != 0 {
		t.Fatalf("%d access changes were recorded against %q, which no request named", n, lookalike)
	}
	if n := touched(literal); n != 3 {
		t.Fatalf("%d access changes recorded against %q, want 3 (disabled, enabled, role)", n, literal)
	}

	// "%40" for "@" still works on an ordinary address, as does the plain form.
	f.do(t, on, http.MethodPost, base+strings.Replace(lookalike, "@", "%40", 1)+"/disable", owner, nil).want(t, "disable by %40", http.StatusOK, "")
	f.do(t, on, http.MethodPost, base+lookalike+"/enable", owner, nil).want(t, "enable by the plain address", http.StatusOK, "")
	if got := state(); got != "admin:true viewer:true" {
		t.Fatalf("after disabling and enabling %q: %s", lookalike, got)
	}

	// An address nobody has, however it is written, is 404 and changes nothing.
	for _, missing := range []string{"p%2525" + tail, "p%252541q" + tail, strings.Replace("nobody"+tail, "@", "%40", 1)} {
		f.do(t, on, http.MethodPost, base+missing+"/disable", owner, nil).want(t, "disable "+missing, http.StatusNotFound, "not_found")
	}
	if got := state(); got != "admin:true viewer:true" {
		t.Fatalf("after requests for addresses nobody has: %s", got)
	}
}

// Who disabled a member decides who may enable them again. An operator's
// disable is not an owner's to undo: before portal_users.disabled_by both
// wrote the same disabled_at and the owner's enable cleared either.
func TestPAT1883AnOwnerCannotUndoAnOperatorDisable(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)
	path := func(member, verb string) string { return "/v1/portal/access/members/" + member + "/" + verb }
	operatorDisable := func(member string) {
		t.Helper()
		f.admin(t, http.MethodDelete, "/admin/portal-users/"+member, nil).want(t, "operator disable", http.StatusOK, "")
	}
	operatorPost := func(member string) {
		t.Helper()
		f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": member, "tenant_id": org.Tenant}).
			want(t, "operator re-post", http.StatusCreated, "")
	}
	// stored is "disabled|by" as the row holds it: by is NULL, operator or owner.
	stored := func(member string) string {
		t.Helper()
		return f.text(t, `SELECT (disabled_at IS NOT NULL)::text || '|' || coalesce(disabled_by, 'NULL') FROM portal_users WHERE email = $1`, member)
	}
	// listed is what GET /v1/portal/access says about the member.
	listed := func(member string) map[string]any {
		t.Helper()
		list := f.do(t, on, http.MethodGet, "/v1/portal/access", owner, nil).want(t, "access list", http.StatusOK, "")
		members, _ := list.JSON["members"].([]any)
		for _, m := range members {
			if row := m.(map[string]any); row["email"] == member {
				if _, has := row["disabled_by"]; !has {
					t.Fatalf("member row has no disabled_by key: %v", row)
				}
				return row
			}
		}
		t.Fatalf("member %s is not in the access list: %s", member, list.Raw)
		return nil
	}
	refusedEnable := func(what, member string) {
		t.Helper()
		rows := len(f.audit(t, org.Tenant))
		r := f.do(t, on, http.MethodPost, path(member, "enable"), owner, nil)
		if r.Code != http.StatusConflict || r.str("error") != "disabled_by_operator" {
			t.Fatalf("%s: owner's enable = %d %s, want 409 disabled_by_operator", what, r.Code, r.Raw)
		}
		if got := len(f.audit(t, org.Tenant)); got != rows {
			t.Fatalf("%s: a refused enable wrote %d ledger rows", what, got-rows)
		}
		f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, member), nil).want(t, what+": member after a refused enable", http.StatusForbidden, "")
	}

	// 1. The operator disables; the owner cannot enable.
	byOperator := f.join(t, on, org, "viewer")
	operatorDisable(byOperator)
	refusedEnable("disabled by the operator", byOperator)
	if got := stored(byOperator); got != "true|operator" {
		t.Fatalf("operator-disabled row = %s, want true|operator", got)
	}
	if row := listed(byOperator); row["status"] != "disabled" || row["disabled_by"] != "operator" {
		t.Fatalf("access list for an operator-disabled member = %v", row)
	}
	// The owner "disabling" them changes nothing and does not take the disable over.
	rows := len(f.audit(t, org.Tenant))
	d := f.do(t, on, http.MethodPost, path(byOperator, "disable"), owner, nil).want(t, "owner disables an operator-disabled member", http.StatusOK, "")
	if d.JSON["changed"] != false || d.JSON["disabled_by"] != "operator" || stored(byOperator) != "true|operator" || len(f.audit(t, org.Tenant)) != rows {
		t.Fatalf("owner's disable of an operator-disabled member = %s, row %s; want changed false and operator kept", d.Raw, stored(byOperator))
	}
	refusedEnable("after the owner's no-op disable", byOperator)
	// Only the operator restores them, and that clears who disabled them.
	operatorPost(byOperator)
	if got := stored(byOperator); got != "false|NULL" {
		t.Fatalf("row after the operator re-enabled = %s, want false|NULL", got)
	}
	f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, byOperator), nil).want(t, "member the operator restored", http.StatusOK, "")
	if row := listed(byOperator); row["status"] != "active" || row["disabled_by"] != nil || row["disabled_at"] != nil {
		t.Fatalf("access list for an active member = %v, want disabled_by null", row)
	}

	// 2. The owner disables; the owner can enable.
	byOwner := f.join(t, on, org, "admin")
	d = f.do(t, on, http.MethodPost, path(byOwner, "disable"), owner, nil).want(t, "owner disable", http.StatusOK, "")
	if d.JSON["changed"] != true || d.JSON["disabled_by"] != "owner" || d.str("disabled_at") == "" || stored(byOwner) != "true|owner" {
		t.Fatalf("owner's disable = %s, row %s", d.Raw, stored(byOwner))
	}
	if row := listed(byOwner); row["status"] != "disabled" || row["disabled_by"] != "owner" {
		t.Fatalf("access list for an owner-disabled member = %v", row)
	}
	e := f.do(t, on, http.MethodPost, path(byOwner, "enable"), owner, nil).want(t, "owner enables their own disable", http.StatusOK, "")
	if _, has := e.JSON["disabled_by"]; e.JSON["changed"] != true || e.JSON["disabled_at"] != nil || e.JSON["disabled_by"] != nil || !has || stored(byOwner) != "false|NULL" {
		t.Fatalf("owner's enable = %s, row %s", e.Raw, stored(byOwner))
	}
	// Enabling someone who is not disabled changes nothing.
	if again := f.do(t, on, http.MethodPost, path(byOwner, "enable"), owner, nil).want(t, "enable an active member", http.StatusOK, ""); again.JSON["changed"] != false || again.JSON["disabled_by"] != nil {
		t.Fatalf("enable of an active member = %s", again.Raw)
	}

	// 3. The owner disables first, then the operator does: it is the
	// operator's disable now, and the first disabled_at is kept.
	f.do(t, on, http.MethodPost, path(byOwner, "disable"), owner, nil).want(t, "owner disable", http.StatusOK, "")
	first := f.text(t, `SELECT disabled_at::text FROM portal_users WHERE email = $1`, byOwner)
	operatorDisable(byOwner)
	if got := stored(byOwner); got != "true|operator" {
		t.Fatalf("row after the operator disabled an owner-disabled member = %s, want true|operator", got)
	}
	if got := f.text(t, `SELECT disabled_at::text FROM portal_users WHERE email = $1`, byOwner); got != first {
		t.Fatalf("disabled_at moved from %s to %s", first, got)
	}
	refusedEnable("owner disabled first, operator second", byOwner)

	// 4. The operator can undo an owner's disable (a re-post re-enables).
	third := f.join(t, on, org, "viewer")
	f.do(t, on, http.MethodPost, path(third, "disable"), owner, nil).want(t, "owner disable", http.StatusOK, "")
	operatorPost(third)
	if got := stored(third); got != "false|NULL" {
		t.Fatalf("row after the operator re-enabled an owner-disabled member = %s, want false|NULL", got)
	}

	// 5. A row disabled before the column existed says nothing about who did
	// it. It counts as the operator's.
	legacy := f.join(t, on, org, "viewer")
	f.exec(t, `UPDATE portal_users SET disabled_at = now(), disabled_by = NULL WHERE email = $1`, legacy)
	if row := listed(legacy); row["status"] != "disabled" || row["disabled_by"] != "operator" {
		t.Fatalf("access list for a legacy disabled member = %v, want disabled_by operator", row)
	}
	refusedEnable("legacy disabled row", legacy)
	if d := f.do(t, on, http.MethodPost, path(legacy, "disable"), owner, nil).want(t, "owner disables a legacy disabled row", http.StatusOK, ""); d.JSON["changed"] != false || d.JSON["disabled_by"] != "operator" || stored(legacy) != "true|NULL" {
		t.Fatalf("owner's disable of a legacy disabled row = %s, row %s", d.Raw, stored(legacy))
	}

	// 6. The table holds the rule: a marker only on a disabled row, and only
	// the two values.
	for what, sql := range map[string]string{
		"a marker on an enabled row": `UPDATE portal_users SET disabled_at = NULL, disabled_by = 'owner' WHERE email = $1`,
		"an undefined marker":        `UPDATE portal_users SET disabled_at = now(), disabled_by = 'portal' WHERE email = $1`,
		"an empty marker":            `UPDATE portal_users SET disabled_at = now(), disabled_by = '' WHERE email = $1`,
	} {
		if _, err := f.pool.Exec(context.Background(), sql, third); err == nil || !strings.Contains(err.Error(), "portal_users_disabled_by_check") {
			t.Errorf("%s was not refused by portal_users_disabled_by_check: %v", what, err)
		}
	}
}

func TestPAT1883OwnerGuards(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)
	// A second owner can only come from an operator.
	second := pat1883Email("second-owner")
	f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": second, "tenant_id": org.Tenant, "role": "owner"}).
		want(t, "operator designates a second owner", http.StatusCreated, "")
	before := len(f.audit(t, org.Tenant))

	for label, target := range map[string]string{"themselves": org.Owner, "another owner": second} {
		code := "cannot_change_owner"
		if target == org.Owner {
			code = "cannot_change_own_access"
		}
		base := "/v1/portal/access/members/" + target
		f.do(t, on, http.MethodPut, base+"/role", owner, map[string]any{"role": "viewer"}).want(t, "demote "+label, http.StatusConflict, code)
		f.do(t, on, http.MethodPut, base+"/role", owner, map[string]any{"role": "admin"}).want(t, "demote "+label+" to admin", http.StatusConflict, code)
		f.do(t, on, http.MethodPost, base+"/disable", owner, nil).want(t, "disable "+label, http.StatusConflict, code)
		f.do(t, on, http.MethodPost, base+"/enable", owner, nil).want(t, "enable "+label, http.StatusConflict, code)
	}
	// Still refused when the other owner has been disabled by an operator:
	// an owner's access is not another owner's to restore.
	f.admin(t, http.MethodDelete, "/admin/portal-users/"+second, nil).want(t, "operator disables the second owner", http.StatusOK, "")
	f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+second+"/enable", owner, nil).want(t, "enable a disabled owner", http.StatusConflict, "cannot_change_owner")

	if got := f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid AND role='owner'`, org.Tenant); got != 2 {
		t.Fatalf("owner rows = %d, want 2", got)
	}
	if got := f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid AND role='owner' AND disabled_at IS NULL`, org.Tenant); got != 1 {
		t.Fatalf("active owners = %d, want 1 (the caller)", got)
	}
	if after := len(f.audit(t, org.Tenant)); after != before {
		t.Fatalf("refused owner changes wrote %d ledger rows", after-before)
	}
	// The sole remaining owner is still an owner.
	if me := f.do(t, on, http.MethodGet, "/v1/portal/me", owner, nil); me.str("role") != "owner" {
		t.Fatalf("owner's role after refused self-changes = %s", me.Raw)
	}
	// Ownership is never handed out: not by invitation, not by role change.
	member := f.join(t, on, org, "admin")
	f.do(t, on, http.MethodPut, "/v1/portal/access/members/"+member+"/role", owner, map[string]any{"role": "owner"}).
		want(t, "promote to owner", http.StatusBadRequest, "invalid_role")
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", owner, map[string]any{"email": pat1883Email("o"), "role": "owner"}).
		want(t, "invite as owner", http.StatusBadRequest, "invalid_role")
}

// ---------------------------------------------------------------------------
// Cross-tenant
// ---------------------------------------------------------------------------

// Another tenant's invitation id or member address answers exactly as one
// that does not exist, and nothing of theirs changes.
func TestPAT1883CrossTenantIdsAnswerAsMissing(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	a, b := f.newOrg(t, on), f.newOrg(t, on)
	attacker := f.token(t, a.Owner)
	bViewer := f.join(t, on, b, "viewer")
	bAdmin := f.join(t, on, b, "admin")
	bInvitee := pat1883Email("b-invitee")
	bInvitation := f.invite(t, on, b, bInvitee, "admin")

	snapshot := func() string {
		var s string
		if err := f.pool.QueryRow(context.Background(), `
			SELECT (SELECT string_agg(email || ':' || role || ':' || coalesce(disabled_at::text, ''), ',' ORDER BY email) FROM portal_users WHERE tenant_id=$1::uuid)
			    || ' ' || (SELECT string_agg(id::text || ':' || status, ',' ORDER BY id) FROM portal_invitations WHERE tenant_id=$1::uuid)
			    || ' ' || (SELECT count(*)::text FROM portal_access_audit WHERE tenant_id=$1::uuid)`, b.Tenant).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot()

	type call struct {
		method, tmpl string
		body         any
	}
	same := func(label string, c call, victim, missing string) {
		t.Helper()
		got := f.do(t, on, c.method, strings.Replace(c.tmpl, "{x}", victim, 1), attacker, c.body)
		want := f.do(t, on, c.method, strings.Replace(c.tmpl, "{x}", missing, 1), attacker, c.body)
		if got.Code != http.StatusNotFound || got.Code != want.Code || got.Raw != want.Raw {
			t.Errorf("%s: another tenant's = %d %s; a missing one = %d %s; want identical 404s", label, got.Code, got.Raw, want.Code, want.Raw)
		}
		for _, leak := range []string{b.Tenant, b.Name, b.Owner, bInvitee, "viewer", "admin"} {
			if strings.Contains(got.Raw, leak) {
				t.Errorf("%s: the refusal mentions %q: %s", label, leak, got.Raw)
			}
		}
	}
	same("revoke invitation", call{"POST", "/v1/portal/access/invitations/{x}/revoke", nil}, bInvitation, pat1883ZeroUUID)
	missingEmail := pat1883Email("nobody")
	for _, victim := range []string{bViewer, bAdmin, b.Owner} {
		same("change role of "+victim, call{"PUT", "/v1/portal/access/members/{x}/role", map[string]any{"role": "admin"}}, victim, missingEmail)
		same("change role of "+victim, call{"PUT", "/v1/portal/access/members/{x}/role", map[string]any{"role": "viewer"}}, victim, missingEmail)
		same("disable "+victim, call{"POST", "/v1/portal/access/members/{x}/disable", nil}, victim, missingEmail)
		same("enable "+victim, call{"POST", "/v1/portal/access/members/{x}/enable", nil}, victim, missingEmail)
	}
	if after := snapshot(); after != before {
		t.Fatalf("cross-tenant attempts changed tenant B:\nbefore %s\nafter  %s", before, after)
	}

	// Each tenant's list is its own.
	list := f.do(t, on, http.MethodGet, "/v1/portal/access", attacker, nil).want(t, "A's list", http.StatusOK, "")
	for _, leak := range []string{b.Owner, bViewer, bAdmin, bInvitee, bInvitation} {
		if strings.Contains(list.Raw, leak) {
			t.Errorf("tenant A's access list contains tenant B's %q", leak)
		}
	}
	// The invitee of B's invitation cannot be made a member of A by A's owner
	// accepting on their behalf: acceptance is the invitee's alone.
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+bInvitation+"/accept", attacker, nil).
		want(t, "A's owner accepts B's invitation", http.StatusNotFound, "not_found")
}

// A verified person who belongs to no tenant reaches the sign-up group and
// nothing else under /v1/portal.
func TestPAT1883NonMemberReachesOnlyTheSignupGroup(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	tok := f.token(t, pat1883Email("non-member"))
	param := regexp.MustCompile(`\{[^}]+\}`)
	checked := 0
	for _, route := range pat1883Routes(t, on, "/v1/portal/") {
		if strings.HasPrefix(route[1], "/v1/portal/signup/") {
			continue
		}
		checked++
		path := param.ReplaceAllString(route[1], pat1883ZeroUUID)
		r := f.do(t, on, route[0], path, tok, map[string]any{"name": "x", "email": "x@y.pat1883.invalid", "role": "admin"})
		if r.Code != http.StatusForbidden || strings.TrimSpace(r.Raw) != "forbidden" {
			t.Errorf("non-member %s %s = %d %q, want 403 forbidden from the tenant middleware", route[0], route[1], r.Code, r.Raw)
		}
	}
	if checked < 80 {
		t.Fatalf("only %d tenant routes walked: enumeration broken?", checked)
	}
	// Control: the same person is served by the sign-up group.
	f.do(t, on, http.MethodGet, "/v1/portal/signup/state", tok, nil).want(t, "sign-up state", http.StatusOK, "")
}

// ---------------------------------------------------------------------------
// Service identity
// ---------------------------------------------------------------------------

func TestPAT1883ServiceIdentityIsRefusedOnEveryNewRoute(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	svc := f.serviceToken(t)
	marker := "PAT1883 service " + pat1883Rand()
	tenants := f.count(t, `SELECT count(*) FROM tenants`)
	body := map[string]any{"name": marker, "email": pat1883Email("x"), "role": "admin"}

	for _, route := range pat1883AllNewRoutes() {
		r := f.do(t, on, route[0], pat1883Fill(route[1]), svc, body)
		switch {
		case route[0] != http.MethodGet:
			if r.Code != http.StatusForbidden || !strings.Contains(r.Raw, "read-only") {
				t.Errorf("service %s %s = %d %q, want 403 read-only", route[0], route[1], r.Code, r.Raw)
			}
		case strings.HasPrefix(route[1], "/v1/portal/signup"):
			if r.Code != http.StatusForbidden || !strings.Contains(r.Raw, "verified email") {
				t.Errorf("service %s %s = %d %q, want 403 (sign-up needs a person)", route[0], route[1], r.Code, r.Raw)
			}
		default: // GET /v1/portal/access: a viewer for reads
			if r.Code != http.StatusForbidden || r.str("error") != "admin_role_required" {
				t.Errorf("service %s %s = %d %q, want 403 admin_role_required", route[0], route[1], r.Code, r.Raw)
			}
		}
	}
	if n := f.count(t, `SELECT count(*) FROM tenants`); n != tenants {
		t.Fatalf("the service identity created a tenant")
	}
	if n := f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, f.serviceTenant); n != 0 {
		t.Fatalf("the service identity created an invitation")
	}
	// A service token that is not the allowlisted one is not authenticated.
	other := f.sign(t, map[string]any{"common_name": "someone-else.access", "type": "app", "sub": ""})
	for _, route := range pat1883SignupRoutes {
		if r := f.do(t, on, route[0], pat1883Fill(route[1]), other, body); r.Code != http.StatusUnauthorized {
			t.Errorf("unallowlisted service token %s %s = %d, want 401", route[0], route[1], r.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Abuse and rate controls
// ---------------------------------------------------------------------------

func pat1883RetryAfter(t *testing.T, r pat1883Resp, what string) {
	t.Helper()
	if r.Code != http.StatusTooManyRequests {
		t.Fatalf("%s: status = %d, want 429: %s", what, r.Code, r.Raw)
	}
	if n, err := strconv.Atoi(r.Header.Get("Retry-After")); err != nil || n < 1 {
		t.Fatalf("%s: Retry-After = %q, want a positive number of seconds", what, r.Header.Get("Retry-After"))
	}
}

func TestPAT1883SignupRateLimits(t *testing.T) {
	f := newSignupFx(t)
	const ceiling = 7
	cfg := pat1883Enabled()
	cfg.OrgCreationsPerHour = ceiling
	on := f.router(cfg)
	marker := "PAT1883 limit " + pat1883Rand()
	create := func(ip string) (pat1883Resp, string) {
		email := pat1883Email("limited")
		return f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, email),
			map[string]any{"name": marker + " " + pat1883Rand()}, "CF-Connecting-IP", ip), email
	}
	// Every sign-up reaches the platform from the portal server, so they all
	// carry one client address. There is no per-address limit: the ceiling is
	// reached by that many creations from the same address, not sooner. Seven
	// is more than the per-address cap of five this code once had, so a cap
	// like it coming back fails here.
	const portalServer, elsewhere = "198.51.100.10", "2001:db8:1:2:3:4:5:6" // TEST-NET-2 and the IPv6 documentation prefix

	r, first := create(portalServer)
	r.want(t, "first", http.StatusCreated, "")

	// A request that was never going to create anything costs the shared
	// budget nothing: an existing member, or anyone sending a bad name,
	// cannot spend the ceiling every new customer shares.
	for i := 0; i < 10; i++ {
		f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, first), map[string]any{"name": marker + " again"}, "CF-Connecting-IP", portalServer).
			want(t, "existing member", http.StatusConflict, "already_member")
		f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("bad")), map[string]any{"name": "x"}, "CF-Connecting-IP", portalServer).
			want(t, "invalid name", http.StatusBadRequest, "invalid_name")
	}

	for i := 2; i <= ceiling; i++ {
		r, _ = create(portalServer)
		r.want(t, fmt.Sprintf("creation %d of %d from the same address", i, ceiling), http.StatusCreated, "")
	}

	// The global ceiling, and it does not matter where the request says it
	// came from: no header moves a caller to a different budget.
	r, refused := create(portalServer)
	pat1883RetryAfter(t, r, "one past the global ceiling")
	if r.str("error") != "rate_limited" {
		t.Fatalf("ceiling refusal = %s", r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE email=$1`, refused); n != 0 {
		t.Fatal("a rate-limited creation left a membership behind")
	}
	r, _ = create(elsewhere)
	pat1883RetryAfter(t, r, "another address, same ceiling")
	other := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("spoof")),
		map[string]any{"name": marker + " spoof"}, "X-Forwarded-For", "192.0.2.77", "X-Real-IP", "192.0.2.78", "True-Client-IP", "192.0.2.79")
	pat1883RetryAfter(t, other, "forwarded-address headers, same ceiling")
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, marker+"%"); n != ceiling {
		t.Fatalf("tenants created under the ceiling of %d = %d", ceiling, n)
	}
	// Reading state and being refused are not blocked by the ceiling: it
	// limits creation only.
	f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, refused), nil).want(t, "state at the ceiling", http.StatusOK, "")
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, first), map[string]any{"name": marker + " again"}).
		want(t, "existing member at the ceiling", http.StatusConflict, "already_member")

	// The sign-up group sits behind the same per-email limiter as the rest of
	// the portal surface.
	verifier := portalauth.New(svcTestIssuer, svcTestAud, f.jwksURL)
	tight := ratelimit.New(ratelimit.Config{RPM: 1, Burst: 2})
	loose := ratelimit.New(ratelimit.Config{RPM: 60000, Burst: 10000})
	limited := newPublicRouter(f.pool, nil, loose, 5*time.Minute, verifier, tight, loose, "", "", nil, nil, "", nil, "", nil, withPortalSignup(pat1883Enabled()))
	one, two := f.token(t, pat1883Email("one")), f.token(t, pat1883Email("two"))
	f.do(t, limited, http.MethodGet, "/v1/portal/signup/state", one, nil).want(t, "1st", http.StatusOK, "")
	f.do(t, limited, http.MethodGet, "/v1/portal/signup/state", one, nil).want(t, "2nd", http.StatusOK, "")
	pat1883RetryAfter(t, f.do(t, limited, http.MethodGet, "/v1/portal/signup/state", one, nil), "per-email limit")
	pat1883RetryAfter(t, f.do(t, limited, http.MethodPost, "/v1/portal/signup/organisation", one, map[string]any{"name": marker + " limited"}), "per-email limit on create")
	f.do(t, limited, http.MethodGet, "/v1/portal/signup/state", two, nil).want(t, "another person", http.StatusOK, "")
}

// The ceiling counts organisations that were created. People signing up at
// the same moment under a ceiling of K get exactly K organisations: never
// more, and never fewer because a slot went missing.
func TestPAT1883SignupCeilingUnderConcurrency(t *testing.T) {
	f := newSignupFx(t)
	const ceiling, n = 5, 24
	cfg := pat1883Enabled()
	cfg.OrgCreationsPerHour = ceiling
	on := f.router(cfg)
	marker := "PAT1883 crowd " + pat1883Rand()

	emails, tokens := make([]string, n), make([]string, n)
	for i := range emails {
		emails[i] = pat1883Email("crowd")
		tokens[i] = f.token(t, emails[i])
	}
	f.warmPool(t, n) // so the requests really overlap
	codes, bodies := make([]int, n), make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", tokens[i], map[string]any{"name": marker + " " + strconv.Itoa(i)})
			codes[i], bodies[i] = r.Code, r.Raw
		}(i)
	}
	close(start)
	wg.Wait()

	created, limited := 0, 0
	for i, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Errorf("request %d = %d: %s", i, c, bodies[i])
		}
	}
	if created != ceiling || limited != n-ceiling {
		t.Fatalf("%d created and %d refused of %d under a ceiling of %d; want exactly %d and %d", created, limited, n, ceiling, ceiling, n-ceiling)
	}
	if got := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, marker+"%"); got != ceiling {
		t.Fatalf("tenants created = %d, want %d", got, ceiling)
	}
	if got := f.count(t, `SELECT count(*) FROM portal_users WHERE email = ANY($1) AND role = 'owner'`, emails); got != ceiling {
		t.Fatalf("owners created = %d, want %d", got, ceiling)
	}
	// Full now, for someone new too.
	pat1883RetryAfter(t, f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("late")),
		map[string]any{"name": marker + " late"}), "after the crowd")
}

// A request that creates nothing leaves the ceiling as it found it, through
// the production router: an address the table could not hold is refused
// before a slot is taken, however often it is sent.
func TestPAT1883SignupCeilingIsNotSpentByRequestsThatCreateNothing(t *testing.T) {
	f := newSignupFx(t)
	cfg := pat1883Enabled()
	cfg.OrgCreationsPerHour = 1
	on := f.router(cfg)
	marker := "PAT1883 unspent " + pat1883Rand()

	long := f.token(t, strings.Repeat("a", 300)+"-"+pat1883Email("long"))
	for i := 0; i < 3; i++ {
		f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", long, map[string]any{"name": marker + " long"}).
			want(t, "over-long address", http.StatusBadRequest, "unsupported_email")
	}
	if st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", long, nil).want(t, "state", http.StatusOK, ""); st.JSON["can_create_organisation"] != false {
		t.Fatalf("state offers creation to an address that cannot be stored: %s", st.Raw)
	}
	f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("first")), map[string]any{"name": marker + " first"}).
		want(t, "the first real creation", http.StatusCreated, "")
	pat1883RetryAfter(t, f.do(t, on, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, pat1883Email("second")),
		map[string]any{"name": marker + " second"}), "one past a ceiling of one")
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE name LIKE $1`, marker+"%"); n != 1 {
		t.Fatalf("tenants created = %d, want 1", n)
	}
}

func TestPAT1883InvitationRateLimitAndCap(t *testing.T) {
	f := newSignupFx(t)
	cfg := pat1883Enabled()
	cfg.InvitationsPerTenantPerHour = 2
	on := f.router(cfg)
	org, other := f.newOrg(t, on), f.newOrg(t, on)
	admin := f.join(t, on, org, "admin") // one invitation spent on the admin
	invite := func(o pat1883Org, as string) pat1883Resp {
		return f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", f.token(t, as), map[string]any{"email": pat1883Email("i"), "role": "viewer"})
	}
	// People who may not invite cannot spend the tenant's budget.
	for i := 0; i < 10; i++ {
		invite(org, admin).want(t, "admin", http.StatusForbidden, "owner_role_required")
	}
	invite(org, org.Owner).want(t, "second invitation", http.StatusCreated, "")
	r := invite(org, org.Owner)
	pat1883RetryAfter(t, r, "third invitation")
	if r.str("error") != "rate_limited" {
		t.Fatalf("invitation limit refusal = %s", r.Raw)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, org.Tenant); n != 2 {
		t.Fatalf("invitations stored = %d, want 2", n)
	}
	// The budget is per tenant.
	invite(other, other.Owner).want(t, "another tenant", http.StatusCreated, "")

	// The cap on pending invitations, with the hourly limit out of the way.
	wide := pat1883Enabled()
	wide.InvitationsPerTenantPerHour = 1000
	on = f.router(wide)
	capped := f.newOrg(t, on)
	owner := f.token(t, capped.Owner)
	var ids []string
	for i := 0; i < 50; i++ {
		ids = append(ids, f.invite(t, on, capped, pat1883Email("cap"), "viewer"))
	}
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", owner, map[string]any{"email": pat1883Email("cap"), "role": "viewer"}).
		want(t, "51st pending invitation", http.StatusConflict, "invitation_limit_reached")
	if n := f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid AND status='pending'`, capped.Tenant); n != 50 {
		t.Fatalf("pending invitations = %d, want 50", n)
	}
	// Revoking one, or one expiring, makes room.
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+ids[0]+"/revoke", owner, nil).want(t, "revoke one", http.StatusOK, "")
	f.invite(t, on, capped, pat1883Email("cap"), "viewer")
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations", owner, map[string]any{"email": pat1883Email("cap"), "role": "viewer"}).
		want(t, "full again", http.StatusConflict, "invitation_limit_reached")
	f.exec(t, `UPDATE portal_invitations SET created_at = now() - interval '9 days', expires_at = now() - interval '1 minute' WHERE id=$1::uuid`, ids[1])
	f.invite(t, on, capped, pat1883Email("cap"), "viewer")
}

// ---------------------------------------------------------------------------
// Audit ledger
// ---------------------------------------------------------------------------

// Every state change writes exactly one ledger row, and a refused or no-op
// request writes none.
func TestPAT1883EveryAccessChangeIsAudited(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	org := f.newOrg(t, on)
	owner := f.token(t, org.Owner)
	o := org.Owner

	joiner := pat1883Email("joiner")
	jid := f.invite(t, on, org, joiner, "viewer")
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+jid+"/accept", f.token(t, joiner), nil).want(t, "accept", http.StatusOK, "")
	dropped := pat1883Email("dropped")
	did := f.invite(t, on, org, dropped, "admin")
	f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+did+"/revoke", owner, nil).want(t, "revoke", http.StatusOK, "")
	f.do(t, on, http.MethodPut, "/v1/portal/access/members/"+joiner+"/role", owner, map[string]any{"role": "admin"}).want(t, "role", http.StatusOK, "")
	f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+joiner+"/disable", owner, nil).want(t, "disable", http.StatusOK, "")
	f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+joiner+"/enable", owner, nil).want(t, "enable", http.StatusOK, "")

	want := []string{
		"organisation_created|" + o + "|" + o + "||owner|false",
		"invitation_created|" + o + "|" + joiner + "||viewer|true",
		"invitation_accepted|" + joiner + "|" + joiner + "||viewer|true",
		"invitation_created|" + o + "|" + dropped + "||admin|true",
		"invitation_revoked|" + o + "|" + dropped + "|admin||true",
		"role_changed|" + o + "|" + joiner + "|viewer|admin|false",
		"member_disabled|" + o + "|" + joiner + "|admin|admin|false",
		"member_enabled|" + o + "|" + joiner + "|admin|admin|false",
	}
	got := f.audit(t, org.Tenant)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ledger:\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid AND invitation_id IN ($2::uuid, $3::uuid)`, org.Tenant, jid, did); n != 4 {
		t.Fatalf("ledger rows carrying the invitation ids = %d, want 4", n)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid AND occurred_at > now() - interval '5 minutes' AND tenant_purge_anonymized_at IS NULL`, org.Tenant); n != len(want) {
		t.Fatalf("recent unmarked ledger rows = %d, want %d", n, len(want))
	}

	// Refusals and no-ops write nothing.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/portal/access/invitations", map[string]any{"email": joiner, "role": "viewer"}}, // already a member
		{"POST", "/v1/portal/access/invitations", map[string]any{"email": "nope", "role": "viewer"}}, // invalid
		{"POST", "/v1/portal/access/invitations/" + did + "/revoke", nil},                            // already revoked
		{"PUT", "/v1/portal/access/members/" + joiner + "/role", map[string]any{"role": "admin"}},    // same role
		{"POST", "/v1/portal/access/members/" + joiner + "/enable", nil},                             // already enabled
		{"PUT", "/v1/portal/access/members/" + o + "/role", map[string]any{"role": "viewer"}},        // self
		{"POST", "/v1/portal/signup/invitations/" + jid + "/accept", nil},                            // not the invitee
	} {
		f.do(t, on, c.method, c.path, owner, c.body)
	}
	if after := f.audit(t, org.Tenant); len(after) != len(want) {
		t.Fatalf("refused or no-op requests wrote ledger rows: %v", after[len(want):])
	}

	// The ledger is append-only for the application role.
	for _, sql := range []string{
		`UPDATE portal_access_audit SET actor_email='forged@pat1883.invalid' WHERE tenant_id=$1::uuid`,
		`UPDATE portal_access_audit SET actor_email=NULL, subject_email=NULL, tenant_purge_anonymized_at=transaction_timestamp() WHERE tenant_id=$1::uuid`,
		`DELETE FROM portal_access_audit WHERE tenant_id=$1::uuid`,
	} {
		if _, err := f.pool.Exec(context.Background(), sql, org.Tenant); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want an append-only refusal", sql, err)
		}
	}
	if _, err := f.pool.Exec(context.Background(), `TRUNCATE portal_access_audit`); err == nil {
		t.Error("TRUNCATE portal_access_audit succeeded")
	}
}

// ---------------------------------------------------------------------------
// Tenant purge
// ---------------------------------------------------------------------------

// A tenant with rows in both new tables purges through the real operator
// route. Its invitations are deleted with it; its ledger rows are kept with
// the addresses removed; another tenant's rows are untouched.
func TestPAT1883TenantPurgeLeavesNoPersonalData(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	build := func() (pat1883Org, []string) {
		org := f.newOrg(t, on)
		owner := f.token(t, org.Owner)
		admin := f.join(t, on, org, "admin")
		viewer := f.join(t, on, org, "viewer")
		pending, revoked := pat1883Email("pending"), pat1883Email("revoked")
		f.invite(t, on, org, pending, "viewer")
		rid := f.invite(t, on, org, revoked, "admin")
		f.do(t, on, http.MethodPost, "/v1/portal/access/invitations/"+rid+"/revoke", owner, nil).want(t, "revoke", http.StatusOK, "")
		f.do(t, on, http.MethodPut, "/v1/portal/access/members/"+viewer+"/role", owner, map[string]any{"role": "admin"}).want(t, "role", http.StatusOK, "")
		f.do(t, on, http.MethodPost, "/v1/portal/access/members/"+admin+"/disable", owner, nil).want(t, "disable", http.StatusOK, "")
		return org, []string{org.Owner, admin, viewer, pending, revoked}
	}
	a, aEmails := build()
	b, _ := build()

	dump := func(table, tenant, minus string) string {
		var s string
		if err := f.pool.QueryRow(context.Background(),
			`SELECT coalesce(string_agg((to_jsonb(x)`+minus+`)::text, '|' ORDER BY id), '') FROM `+table+` x WHERE tenant_id=$1::uuid`, tenant).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	const redacted = ` - 'actor_email' - 'subject_email' - 'tenant_purge_anonymized_at'`
	aRows := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid`, a.Tenant)
	aShape := dump("portal_access_audit", a.Tenant, redacted)
	bAudit, bInvitations := dump("portal_access_audit", b.Tenant, ""), dump("portal_invitations", b.Tenant, "")
	bUsers := f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid`, b.Tenant)
	if aRows < 9 || f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, a.Tenant) != 4 {
		t.Fatalf("fixture: %d ledger rows and %d invitations for tenant A", aRows, f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, a.Tenant))
	}
	for _, e := range aEmails {
		if !strings.Contains(dump("portal_access_audit", a.Tenant, ""), e) {
			t.Fatalf("fixture: ledger does not mention %s before the purge", e)
		}
	}
	if got := f.text(t, `SELECT coalesce(contact_email, 'NULL') FROM tenants WHERE id=$1::uuid`, a.Tenant); got != a.Owner {
		t.Fatalf("fixture: tenant A's contact_email = %s, want its owner %s", got, a.Owner)
	}

	// Purge needs the tenant revoked first.
	f.admin(t, http.MethodDelete, "/admin/tenants/"+a.Tenant+"/purge", nil).want(t, "purge before revoke", http.StatusConflict, "")
	f.admin(t, http.MethodDelete, "/admin/tenants/"+a.Tenant, nil).want(t, "revoke tenant", http.StatusOK, "")
	// A revoked tenant's people are locked out, and its pending invitation
	// can no longer be accepted.
	f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, a.Owner), nil).want(t, "owner of a revoked tenant", http.StatusForbidden, "")
	var pendingID string
	if err := f.pool.QueryRow(context.Background(), `SELECT id::text FROM portal_invitations WHERE tenant_id=$1::uuid AND status='pending'`, a.Tenant).Scan(&pendingID); err != nil {
		t.Fatal(err)
	}
	f.do(t, on, http.MethodPost, "/v1/portal/signup/invitations/"+pendingID+"/accept", f.token(t, aEmails[3]), nil).
		want(t, "accept into a revoked tenant", http.StatusNotFound, "not_found")

	p := f.admin(t, http.MethodDelete, "/admin/tenants/"+a.Tenant+"/purge", nil).want(t, "purge", http.StatusOK, "")
	if p.JSON["purged"] != true {
		t.Fatalf("purge = %s", p.Raw)
	}

	if n := f.count(t, `SELECT count(*) FROM tenants WHERE id=$1::uuid`, a.Tenant); n != 0 {
		t.Fatal("tenant A still exists")
	}
	// The contact address lived on the tenant row and went with it.
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE contact_email = $1`, a.Owner); n != 0 {
		t.Fatalf("the purged owner's address is still a tenant contact (%d rows)", n)
	}
	if got := f.text(t, `SELECT coalesce(contact_email, 'NULL') FROM tenants WHERE id=$1::uuid`, b.Tenant); got != b.Owner {
		t.Fatalf("tenant B's contact_email = %s after purging A, want %s", got, b.Owner)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_invitations WHERE tenant_id=$1::uuid`, a.Tenant); n != 0 {
		t.Fatalf("%d of tenant A's invitations survived the purge", n)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid`, a.Tenant); n != 0 {
		t.Fatalf("%d of tenant A's memberships survived the purge", n)
	}
	// The ledger rows are kept, marked, with both addresses gone.
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid`, a.Tenant); n != aRows {
		t.Fatalf("ledger rows after purge = %d, want %d kept", n, aRows)
	}
	if n := f.count(t, `SELECT count(*) FROM portal_access_audit WHERE tenant_id=$1::uuid
		AND tenant_purge_anonymized_at IS NOT NULL AND actor_email IS NULL AND subject_email IS NULL`, a.Tenant); n != aRows {
		t.Fatalf("redacted and marked ledger rows = %d, want all %d", n, aRows)
	}
	after := dump("portal_access_audit", a.Tenant, "")
	for _, e := range aEmails {
		if strings.Contains(after, e) || strings.Contains(after, strings.Split(e, "@")[1]) {
			t.Errorf("purged tenant's ledger still contains %s", e)
		}
	}
	if got := dump("portal_access_audit", a.Tenant, redacted); got != aShape {
		t.Errorf("purge changed non-identifying ledger fields:\nbefore %s\nafter  %s", aShape, got)
	}
	// Nothing of A's addresses is left in either new table, in any tenant.
	for _, e := range aEmails {
		if n := f.count(t, `SELECT (SELECT count(*) FROM portal_invitations WHERE email=$1 OR invited_by_email=$1 OR revoked_by_email=$1)
			+ (SELECT count(*) FROM portal_access_audit WHERE actor_email=$1 OR subject_email=$1)`, e); n != 0 {
			t.Errorf("%s is still present in the new tables after the purge (%d rows)", e, n)
		}
	}

	// Tenant B is exactly as it was.
	if dump("portal_access_audit", b.Tenant, "") != bAudit || dump("portal_invitations", b.Tenant, "") != bInvitations ||
		f.count(t, `SELECT count(*) FROM portal_users WHERE tenant_id=$1::uuid`, b.Tenant) != bUsers {
		t.Fatal("purging tenant A changed tenant B's invitations, ledger or members")
	}
	f.do(t, on, http.MethodGet, "/v1/portal/access", f.token(t, b.Owner), nil).want(t, "tenant B still works", http.StatusOK, "")

	// Redacted rows stay append-only: no un-marking, no rewrite, no delete.
	for _, sql := range []string{
		`UPDATE portal_access_audit SET tenant_purge_anonymized_at=NULL WHERE tenant_id=$1::uuid`,
		`UPDATE portal_access_audit SET actor_email='forged@pat1883.invalid' WHERE tenant_id=$1::uuid`,
		`DELETE FROM portal_access_audit WHERE tenant_id=$1::uuid`,
	} {
		for _, tenant := range []string{a.Tenant, b.Tenant} {
			if _, err := f.pool.Exec(context.Background(), sql, tenant); err == nil {
				t.Errorf("%s succeeded after the purge", sql)
			}
		}
	}
	// The purged owner's address is free again: they are a stranger now.
	st := f.do(t, on, http.MethodGet, "/v1/portal/signup/state", f.token(t, a.Owner), nil).want(t, "purged owner's state", http.StatusOK, "")
	if st.JSON["member"] != false || st.JSON["can_create_organisation"] != true {
		t.Fatalf("purged owner's state = %s", st.Raw)
	}
}

// ---------------------------------------------------------------------------
// Roles across the whole portal write surface (decision C)
// ---------------------------------------------------------------------------

func TestPAT1883OperatorCanDesignateAnOwner(t *testing.T) {
	f := newSignupFx(t)
	on := f.router() // owner recognition does not depend on the flag
	tenant := f.operatorTenant(t, "designated")
	owner := f.member(t, tenant, "owner")
	me := f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, owner), nil).want(t, "me", http.StatusOK, "")
	if me.str("role") != "owner" || me.str("tenant_id") != tenant {
		t.Fatalf("me = %s", me.Raw)
	}
	// Like admin, owner is kept by a re-post on the same tenant that names no
	// role, and never carries over to another tenant.
	repost := func(tenantID string) string {
		t.Helper()
		return f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": owner, "tenant_id": tenantID}).
			want(t, "re-post", http.StatusCreated, "").str("role")
	}
	if got := repost(tenant); got != "owner" {
		t.Fatalf("re-post on the same tenant without a role = %q, want owner kept", got)
	}
	if got := repost(f.operatorTenant(t, "elsewhere")); got != "viewer" {
		t.Fatalf("move to another tenant without a role = %q, want viewer (owner must not carry over)", got)
	}
	f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": owner, "tenant_id": tenant, "role": "owner"}).
		want(t, "owner again on the first tenant", http.StatusCreated, "")
	for _, bad := range []string{"superuser", "Owner", "service_readonly", ""} {
		r := f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": pat1883Email("bad"), "tenant_id": tenant, "role": bad})
		if r.Code != http.StatusBadRequest {
			t.Errorf("role %q = %d, want 400", bad, r.Code)
		}
	}
	// A domain-matched identity stays a viewer, whatever else exists.
	claimed := pat1883Rand() + ".claimed.pat1883.invalid"
	f.admin(t, http.MethodPost, "/admin/tenant-email-domains", map[string]any{"domain": claimed, "tenant_id": tenant}).want(t, "claim", http.StatusCreated, "")
	if me := f.do(t, on, http.MethodGet, "/v1/portal/me", f.token(t, "x-"+pat1883Rand()+"@"+claimed), nil); me.str("role") != "viewer" {
		t.Fatalf("domain-matched role = %s, want viewer", me.Raw)
	}
}

// With SELF_SERVICE_SIGNUP_ENABLED off, which is the default, the operator
// route does not make an owner. The customer portal does not yet treat an
// owner as admin-level, so turning an existing admin into an owner would take
// their write screens away. Admin and viewer grants are unaffected, and an
// owner row that already exists keeps working and keeps its role.
func TestPAT1883OperatorOwnerRoleNeedsTheFlag(t *testing.T) {
	f := newSignupFx(t)
	// No option: the internal router as production builds it with the flag unset.
	off := newInternalRouter(f.pool, nil, 0, "", pat1883AdminToken, "", nil, "", nil)
	tenant := f.operatorTenant(t, "owner-flag")
	post := func(router http.Handler, email string, role any) pat1883Resp {
		t.Helper()
		body := map[string]any{"email": email, "tenant_id": tenant}
		if role != nil {
			body["role"] = role
		}
		return f.adminVia(t, router, http.MethodPost, "/admin/portal-users", body)
	}
	stored := func(email string) string {
		t.Helper()
		return f.text(t, `SELECT coalesce((SELECT role || '|' || (disabled_at IS NULL)::text FROM portal_users WHERE email = $1), 'no row')`, email)
	}
	refused := func(what string, r pat1883Resp) {
		t.Helper()
		if r.Code != http.StatusBadRequest {
			t.Fatalf("%s with the flag off = %d %s, want 400", what, r.Code, r.Raw)
		}
		if !strings.Contains(r.Raw, "self-service sign-up") {
			t.Errorf("%s: the refusal does not say what the role needs: %q", what, r.Raw)
		}
	}

	// A new address.
	fresh := pat1883Email("fresh")
	refused("owner for a new address", post(off, fresh, "owner"))
	if got := stored(fresh); got != "no row" {
		t.Fatalf("a refused owner grant left a row: %s", got)
	}

	// An existing admin is not promoted, and is not otherwise changed.
	admin := pat1883Email("admin")
	post(off, admin, "admin").want(t, "admin grant with the flag off", http.StatusCreated, "")
	refused("owner for an existing admin", post(off, admin, "owner"))
	if got := stored(admin); got != "admin|true" {
		t.Fatalf("existing admin after a refused owner grant = %s, want admin|true", got)
	}
	// Nor is a disabled member re-enabled by a refused request.
	f.adminVia(t, off, http.MethodDelete, "/admin/portal-users/"+admin, nil).want(t, "disable", http.StatusOK, "")
	refused("owner for a disabled admin", post(off, admin, "owner"))
	if got := stored(admin); got != "admin|false" {
		t.Fatalf("disabled admin after a refused owner grant = %s, want admin|false", got)
	}
	post(off, pat1883Email("viewer"), "viewer").want(t, "viewer grant with the flag off", http.StatusCreated, "")

	// An owner row that already exists keeps working with the flag off: the
	// role is honoured, and a re-post that names no role keeps it.
	owner := pat1883Email("owner")
	f.exec(t, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'owner')`, owner, tenant)
	if me := f.do(t, f.router(), http.MethodGet, "/v1/portal/me", f.token(t, owner), nil).want(t, "me", http.StatusOK, ""); me.str("role") != "owner" {
		t.Fatalf("existing owner with the flag off reads as %s", me.Raw)
	}
	if r := post(off, owner, nil).want(t, "re-post of an existing owner with no role", http.StatusCreated, ""); r.str("role") != "owner" {
		t.Fatalf("re-post with no role = %s, want owner kept", r.Raw)
	}

	// With the flag on the same grant is accepted.
	if r := post(f.internal(), fresh, "owner").want(t, "owner grant with the flag on", http.StatusCreated, ""); r.str("role") != "owner" {
		t.Fatalf("owner grant with the flag on = %s", r.Raw)
	}
	// An undefined role is refused either way.
	for _, router := range []http.Handler{off, f.internal()} {
		if r := post(router, pat1883Email("bad"), "superuser"); r.Code != http.StatusBadRequest {
			t.Errorf("role superuser = %d, want 400", r.Code)
		}
	}
}

// Walks every write route registered under /v1/portal on the production
// router. A viewer is refused on role grounds; an admin and an owner are not.
// The five access-management writes are owner only, so there an admin is
// refused too. A write route added later lands in the default class and
// fails here unless it refuses a viewer.
func TestPAT1883EveryPortalWriteRouteEnforcesRoles(t *testing.T) {
	f := newSignupFx(t)
	on := f.router(pat1883Enabled())
	tenant := f.operatorTenant(t, "role-walk")
	owner, admin, viewer := f.member(t, tenant, "owner"), f.member(t, tenant, "admin"), f.member(t, tenant, "viewer")
	var device string
	// A hostname is set because the Local Admin report cannot render a
	// device without one (it scans the column into a string).
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO devices (tenant_id, serial, hostname, os) VALUES ($1::uuid, $2, 'pat1883-host', 'macOS') RETURNING id::text`, tenant, "PAT1883-"+pat1883Rand()).Scan(&device); err != nil {
		t.Fatal(err)
	}

	// Routes that are not decided by role at all.
	everyRole := map[string]bool{
		"POST /v1/portal/feedback": true, // every role may send feedback (404 here: FEEDBACK_ENABLED is off)
	}
	preMembership := map[string]bool{ // members are refused as members, not by role
		"POST /v1/portal/signup/organisation":                      true,
		"POST /v1/portal/signup/invitations/{invitationID}/accept": true,
	}
	ownerOnly := map[string]bool{
		"POST /v1/portal/access/invitations":                       true,
		"POST /v1/portal/access/invitations/{invitationID}/revoke": true,
		"PUT /v1/portal/access/members/{memberEmail}/role":         true,
		"POST /v1/portal/access/members/{memberEmail}/disable":     true,
		"POST /v1/portal/access/members/{memberEmail}/enable":      true,
	}
	// Bodies that pass each handler's own validation, so the answer is the
	// role decision and not a 400 that came first.
	schedule := map[string]any{"cadence": "weekly", "weekday": 1, "hour_utc": 3, "enabled": false}
	bodies := map[string]any{
		"PUT /v1/portal/agent-releases":                map[string]any{"action": "device_channels", "device_ids": []string{device}, "channel": "beta"},
		"PUT /v1/portal/device-list":                   map[string]any{"filename": "pat1883.csv", "entries": []map[string]string{{"hostname": "pat1883-host"}}},
		"PUT /v1/portal/devices/{deviceID}/retirement": map[string]any{"retired": true, "reason": "pat1883"},
		"POST /v1/portal/enrolment-keys":               map[string]any{"label": "pat1883", "max_devices": 2, "expires_in_days": 1},
		// The two routes a viewer may use for everything except the local
		// administrators roster: ask for exactly that.
		"POST /v1/portal/exports/table-pdf":                             map[string]any{"export": "local-admins", "columns": []string{"Hostname"}, "rows": [][]string{{"pat1883"}}},
		"POST /v1/portal/reports":                                       map[string]any{"report_type": "local-admin"},
		"PUT /v1/portal/reports/schedule":                               schedule,
		"PUT /v1/portal/reports/schedules/{reportType}":                 schedule,
		"PUT /v1/portal/mdm/jamf/setup":                                 map[string]any{"check_in_enabled": true},
		"POST /v1/portal/software-alerts/{id}/acknowledge":              map[string]any{"note": "pat1883"},
		"PUT /v1/portal/software-approvals":                             map[string]any{"items": []map[string]string{{"type": "application", "platform": "macos", "identifier": "invalid.pat1883.app", "team_id": "PAT1883TEAM"}}, "state": "approved", "reason": "pat1883"},
		"POST /v1/portal/software-declarations":                         map[string]any{"name": "PAT1883 App", "publisher": "PAT1883", "platform": "macos", "justification": "pat1883"},
		"POST /v1/portal/software-declarations/{declarationID}/resolve": map[string]any{"alias_id": pat1883ZeroUUID, "justification": "pat1883"},
		"PUT /v1/portal/software-notifications":                         map[string]any{"unapproved_alerts_enabled": false, "new_software_enabled": true},
		"PUT /v1/portal/access/members/{memberEmail}/role":              map[string]any{"role": "viewer"},
		"POST /v1/portal/access/invitations":                            map[string]any{"email": pat1883Email("walk"), "role": "viewer"},
	}
	fill := strings.NewReplacer("{deviceID}", device, "{entryID}", "1", "{keyID}", pat1883ZeroUUID, "{id}", "1",
		"{reportType}", "executive-summary", "{declarationID}", pat1883ZeroUUID,
		"{invitationID}", pat1883ZeroUUID, "{memberEmail}", "nobody@nowhere.pat1883.invalid")

	roleRefusal := func(r pat1883Resp) string {
		if r.Code != http.StatusForbidden {
			return ""
		}
		if e := r.str("error"); e == "admin_role_required" || e == "owner_role_required" {
			return e
		}
		return ""
	}
	walked, classes := 0, map[string]int{}
	for _, route := range pat1883Routes(t, on, "/v1/portal/") {
		method, pattern := route[0], route[1]
		if method == http.MethodGet || method == http.MethodHead {
			continue
		}
		walked++
		key := method + " " + pattern
		path := fill.Replace(pattern)
		if strings.Contains(path, "{") {
			t.Errorf("%s: unfilled route parameter; add it to the test's replacer", key)
			continue
		}
		call := func(email string) pat1883Resp { return f.do(t, on, method, path, f.token(t, email), bodies[key]) }
		v, a, o := call(viewer), call(admin), call(owner)
		for who, r := range map[string]pat1883Resp{"viewer": v, "admin": a, "owner": o} {
			if r.Code >= 500 {
				t.Errorf("%s as %s = %d: %s", key, who, r.Code, r.Raw)
			}
		}
		switch {
		case everyRole[key], preMembership[key]:
			classes["not role-gated"]++
			for who, r := range map[string]pat1883Resp{"viewer": v, "admin": a, "owner": o} {
				if ref := roleRefusal(r); ref != "" {
					t.Errorf("%s as %s refused with %s; this route is not decided by role", key, who, ref)
				}
			}
		case ownerOnly[key]:
			classes["owner only"]++
			if roleRefusal(v) != "owner_role_required" {
				t.Errorf("%s as viewer = %d %s, want 403 owner_role_required", key, v.Code, v.Raw)
			}
			if roleRefusal(a) != "owner_role_required" {
				t.Errorf("%s as admin = %d %s, want 403 owner_role_required", key, a.Code, a.Raw)
			}
			if ref := roleRefusal(o); ref != "" {
				t.Errorf("%s as owner refused with %s", key, ref)
			}
		default:
			classes["admin level"]++
			if roleRefusal(v) != "admin_role_required" {
				t.Errorf("%s as viewer = %d %s, want 403 admin_role_required", key, v.Code, v.Raw)
			}
			if ref := roleRefusal(a); ref != "" {
				t.Errorf("%s as admin refused with %s", key, ref)
			}
			if ref := roleRefusal(o); ref != "" {
				t.Errorf("%s as owner refused with %s: an owner can do everything an admin can", key, ref)
			}
			// An owner and an admin are treated alike on every admin-level
			// write: same status for the same request.
			if o.Code != a.Code && !pat1883StatefulOnce[key] {
				t.Errorf("%s: owner = %d, admin = %d; want the same answer", key, o.Code, a.Code)
			}
		}
	}
	if classes["owner only"] != len(ownerOnly) || classes["not role-gated"] != len(everyRole)+len(preMembership) || classes["admin level"] < 20 {
		t.Fatalf("walked %d write routes in classes %v: enumeration broken?", walked, classes)
	}
	t.Logf("walked %d portal write routes: %v", walked, classes)
}

// pat1883StatefulOnce lists admin-level writes whose second identical call
// legitimately answers differently from the first (the first created or
// removed the thing), so owner and admin statuses are not compared.
var pat1883StatefulOnce = map[string]bool{
	"POST /v1/portal/software-declarations": true,
	"DELETE /v1/portal/device-list":         true,
	"DELETE /v1/portal/mdm/jamf/token":      true,
	"POST /v1/portal/mdm/jamf/token":        true,
	"PUT /v1/portal/device-list":            true,
	"PUT /v1/portal/software-approvals":     true,
	"PUT /v1/portal/agent-releases":         true,
}

// The read-only checks that were admin only are open to an owner as well.
func TestPAT1883OwnerReadsWhatAnAdminReads(t *testing.T) {
	f := newSignupFx(t)
	on := f.router()
	tenant := f.operatorTenant(t, "owner-reads")
	owner, admin, viewer := f.member(t, tenant, "owner"), f.member(t, tenant, "admin"), f.member(t, tenant, "viewer")
	for _, path := range []string{"/v1/portal/local-admins", "/v1/portal/reports/catalogue"} {
		o := f.do(t, on, http.MethodGet, path, f.token(t, owner), nil)
		a := f.do(t, on, http.MethodGet, path, f.token(t, admin), nil)
		v := f.do(t, on, http.MethodGet, path, f.token(t, viewer), nil)
		if o.Code != http.StatusOK || a.Code != http.StatusOK {
			t.Errorf("%s: owner = %d, admin = %d, want 200 for both", path, o.Code, a.Code)
		}
		if strings.Contains(a.Raw, `"local-admin"`) != strings.Contains(o.Raw, `"local-admin"`) {
			t.Errorf("%s: owner and admin see different admin-only content", path)
		}
		if path == "/v1/portal/local-admins" && v.Code != http.StatusForbidden {
			t.Errorf("%s as viewer = %d, want 403", path, v.Code)
		}
		if path == "/v1/portal/reports/catalogue" && (strings.Contains(v.Raw, `"local-admin"`) || !strings.Contains(o.Raw, `"local-admin"`)) {
			t.Errorf("%s: viewer sees local-admin, or owner does not", path)
		}
	}
}

// The unauthenticated and unconfigured answers on the new routes are the
// portal surface's usual ones, whatever the flag says.
func TestPAT1883NewRoutesFailClosedWithoutAVerifiedCaller(t *testing.T) {
	for label, cfg := range map[string][]publicRouterOption{"flag off": nil, "flag on": {withPortalSignup(pat1883Enabled())}} {
		v, _ := serviceTestVerifier(t)
		configured := newPublicRouter(nil, nil, nil, 0, v, nil, nil, "", "", nil, nil, "", nil, "", nil, cfg...)
		unconfigured := newPublicRouter(nil, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil, cfg...)
		for _, route := range pat1883AllNewRoutes() {
			path := pat1883Fill(route[1])
			for _, token := range []string{"", "not-a-jwt", "aaaa.bbbb.cccc"} {
				req := httptest.NewRequest(route[0], path, strings.NewReader(`{"name":"x"}`))
				if token != "" {
					req.Header.Set(portalauth.Header, token)
				}
				// A forged identity header is not a credential.
				req.Header.Set("Cf-Access-Authenticated-User-Email", "owner@pat1883.invalid")
				rr := httptest.NewRecorder()
				configured.ServeHTTP(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Errorf("%s: %s %s with token %q = %d, want 401", label, route[0], route[1], token, rr.Code)
				}
			}
			rr := httptest.NewRecorder()
			unconfigured.ServeHTTP(rr, httptest.NewRequest(route[0], path, nil))
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("%s: %s %s with no verifier = %d, want 503", label, route[0], route[1], rr.Code)
			}
		}
	}
}
