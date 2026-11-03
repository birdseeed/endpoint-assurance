package handlers

// PAT-1883, database-backed checks that belong beside the handlers because
// they reach what the routes are designed never to reach:
//
//   - the last-owner guard. No route can remove a tenant's last active owner
//     (an owner cannot act on themselves or another owner), so the guard is
//     exercised directly here, against rows put in that state by hand. A
//     guard that is never seen to fire is not known to work.
//   - an owner submitting portal feedback, which records the reporter's role
//     in a column that accepted only viewer and admin before migration 0229.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

func pat1883Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not: the PAT-1883 database checks would silently not run")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid TEST_DATABASE_URL")
	}
	host := strings.ToLower(cfg.ConnConfig.Host)
	if !strings.Contains(strings.ToLower(cfg.ConnConfig.Database), "test") ||
		!(host == "localhost" || host == "127.0.0.1" || strings.HasPrefix(host, "/")) {
		t.Fatal("requires a local test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot connect to the test database")
	}
	t.Cleanup(pool.Close)
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0230_portal_invitations_and_access_audit')`).Scan(&ready); err != nil || !ready {
		t.Fatal("PAT-1883 requires the forward migrations through 0230")
	}
	return pool
}

// pat1883Tenant creates a tenant with provisionTenant, the function both the
// operator route and sign-up use, and removes it when the test ends.
func pat1883Tenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created, err := provisionTenant(ctx, tx, tenantProvision{Name: "PAT1883 handlers " + t.Name()})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, created.TenantID); err != nil {
			t.Errorf("remove synthetic tenant: %v", err)
		}
	})
	return created.TenantID
}

// pat1883User maps a fresh address (label keeps two users of one role apart)
// to tenant with role, and returns the address. The domain is this file's
// own: the cmd/patched-api acceptance tests sweep every tenant with a member
// under *.pat1883.invalid, and must not sweep these when both packages run
// against one database at the same time.
func pat1883User(t *testing.T, pool *pgxpool.Pool, tenant, label, role string) string {
	t.Helper()
	email := label + "-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "@pat1883-handlers.invalid"
	if _, err := pool.Exec(context.Background(), `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, $3)`, email, tenant, role); err != nil {
		t.Fatal(err)
	}
	return email
}

func TestPAT1883ProvisionTenantSeedsWhatATenantNeeds(t *testing.T) {
	pool := pat1883Pool(t)
	tenant := pat1883Tenant(t, pool)
	var credentials, rules, baseline, policies int
	var createdVia string
	var isTrial, noContact bool
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM tenant_credentials WHERE tenant_id = t.id),
		       (SELECT count(*) FROM tenant_rules WHERE tenant_id = t.id),
		       (SELECT count(*) FROM compliance_rules WHERE collection_tier = 'T2' AND enabled),
		       (SELECT count(*) FROM tenant_app_policies WHERE tenant_id = t.id),
		       t.created_via, t.is_trial,
		       t.contact_email IS NULL AND t.contact_name IS NULL AND t.contact_role IS NULL
		FROM tenants t WHERE t.id = $1::uuid`, tenant).Scan(&credentials, &rules, &baseline, &policies, &createdVia, &isTrial, &noContact); err != nil {
		t.Fatal(err)
	}
	// provisionTenant stores the contact it is given and invents none: the
	// sign-up handler passes the owner's verified email, this call passed nothing.
	if !noContact {
		t.Fatal("provisionTenant set a contact nobody gave it")
	}
	if credentials != 1 || rules != baseline || baseline == 0 || policies == 0 {
		t.Fatalf("provisioned tenant: %d credentials, %d of %d baseline rules, %d agent policies", credentials, rules, baseline, policies)
	}
	// provisionTenant itself never marks a tenant self-service or trial: the
	// default is the operator's, and only the sign-up handler sets the marker.
	if createdVia != "operator" || isTrial {
		t.Fatalf("created_via = %q, is_trial = %v; want operator and false", createdVia, isTrial)
	}
}

func TestPAT1883EnsureActiveOwnerRemains(t *testing.T) {
	pool := pat1883Pool(t)
	ctx := context.Background()
	tenant, other := pat1883Tenant(t, pool), pat1883Tenant(t, pool)
	owner := pat1883User(t, pool, tenant, "owner", "owner")
	pat1883User(t, pool, tenant, "admin", "admin")
	// Another tenant's owner must never count for this one.
	pat1883User(t, pool, other, "other-owner", "owner")

	check := func(mutation string) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if mutation != "" {
			if _, err := tx.Exec(ctx, mutation, owner); err != nil {
				t.Fatal(err)
			}
		}
		return ensureActiveOwnerRemains(ctx, tx, tenant)
	}
	if err := check(""); err != nil {
		t.Fatalf("a tenant with an active owner was refused: %v", err)
	}
	for label, mutation := range map[string]string{
		"demoted to admin":  `UPDATE portal_users SET role = 'admin' WHERE email = $1`,
		"demoted to viewer": `UPDATE portal_users SET role = 'viewer' WHERE email = $1`,
		"disabled":          `UPDATE portal_users SET disabled_at = now() WHERE email = $1`,
		"removed":           `DELETE FROM portal_users WHERE email = $1`,
	} {
		if err := check(mutation); !errors.Is(err, errNoActiveOwner) {
			t.Errorf("last owner %s: err = %v, want errNoActiveOwner", label, err)
		}
	}
	// A tenant that never had an owner (every operator-created tenant before
	// one is designated) is reported the same way, which is why the guard
	// runs only after an owner-made change.
	if err := func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		return ensureActiveOwnerRemains(ctx, tx, pat1883Tenant(t, pool))
	}(); !errors.Is(err, errNoActiveOwner) {
		t.Errorf("tenant with no owner: err = %v, want errNoActiveOwner", err)
	}
	// With a second active owner, losing the first is fine.
	pat1883User(t, pool, tenant, "owner-two", "owner")
	if err := check(`UPDATE portal_users SET disabled_at = now() WHERE email = $1`); err != nil {
		t.Errorf("one of two owners disabled: err = %v, want nil", err)
	}
}

// requirePortalOwner is the one gate on every owner-only write.
func TestPAT1883RequirePortalOwner(t *testing.T) {
	pool := pat1883Pool(t)
	ctx := context.Background()
	tenant, other := pat1883Tenant(t, pool), pat1883Tenant(t, pool)
	owner := pat1883User(t, pool, tenant, "owner", "owner")
	admin := pat1883User(t, pool, tenant, "admin", "admin")
	viewer := pat1883User(t, pool, tenant, "viewer", "viewer")
	disabled := pat1883User(t, pool, tenant, "owner-disabled", "owner")
	if _, err := pool.Exec(ctx, `UPDATE portal_users SET disabled_at = now() WHERE email = $1`, disabled); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		label, email, tenant string
		service              string
		want                 bool
	}{
		{"the owner", owner, tenant, "", true},
		{"the owner, address in another case", strings.ToUpper(owner), tenant, "", true},
		{"an admin", admin, tenant, "", false},
		{"a viewer", viewer, tenant, "", false},
		{"a disabled owner", disabled, tenant, "", false},
		{"the owner, against another tenant", owner, other, "", false},
		{"an unknown address", "nobody@pat1883-handlers.invalid", tenant, "", false},
		{"no address", "", tenant, "", false},
		{"the service identity", "", tenant, "svc", false},
	} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		got := requirePortalOwner(ctx, tx, rr, portalauth.Identity{Email: c.email, TenantID: c.tenant, Service: c.service}, "do this", slog.Default())
		_ = tx.Rollback(ctx)
		if got != c.want {
			t.Errorf("%s: allowed = %v, want %v (%d %s)", c.label, got, c.want, rr.Code, rr.Body.String())
		}
		if !c.want && (rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "owner_role_required")) {
			t.Errorf("%s: refusal = %d %s, want 403 owner_role_required", c.label, rr.Code, rr.Body.String())
		}
	}
}

// The portal_users primary key on email is the arbiter of membership. The
// handlers check first and serialise one person's own requests on an advisory
// lock, but another writer (the operator route, say) takes no such lock. This
// gives the address a membership after every check has passed, at the last
// moment before the insert, and proves the request is still refused and
// leaves nothing behind.
func TestPAT1883PrimaryKeyArbitratesMembership(t *testing.T) {
	pool := pat1883Pool(t)
	ctx := context.Background()
	elsewhere, inviting := pat1883Tenant(t, pool), pat1883Tenant(t, pool)
	s := NewPortalSignup(pool, PortalSignupConfig{Enabled: true})
	t.Cleanup(func() { signupBeforeMembershipInsert = nil })

	intruded := 0
	signupBeforeMembershipInsert = func(_ context.Context, email string) {
		intruded++
		// A separate connection, committed at once: not this request's transaction.
		if _, err := pool.Exec(ctx, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'viewer')`, email, elsewhere); err != nil {
			t.Errorf("intruding insert: %v", err)
		}
	}
	call := func(h http.HandlerFunc, email, body string, params map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
		rc := chi.NewRouteContext()
		for k, v := range params {
			rc.URLParams.Add(k, v)
		}
		req = req.WithContext(portalauth.WithApplicant(contextWithChi(req, rc), portalauth.Applicant{Email: email}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	settled := func(email string) string {
		var s string
		if err := pool.QueryRow(ctx, `
			SELECT (SELECT tenant_id::text || ':' || role FROM portal_users WHERE email = $1)
			    || ' audit=' || (SELECT count(*) FROM portal_access_audit WHERE actor_email = $1 OR subject_email = $1)::text`, email).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Organisation creation.
	// A name and addresses no earlier run can have used, and nothing left
	// behind whatever happens: a run that wrongly succeeds must not make the
	// next run fail for a different reason.
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	creator := "creator-" + run + "@pat1883-handlers.invalid"
	name := "PAT1883 arbiter " + run
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE name = $1`, name); err != nil {
			t.Errorf("remove synthetic tenant: %v", err)
		}
	})
	rr := call(s.CreateOrganisationHandler(), creator, `{"name":"`+name+`"}`, nil)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "already_member") {
		t.Fatalf("creation after the address gained a membership = %d %s, want 409 already_member", rr.Code, rr.Body.String())
	}
	if intruded != 1 {
		t.Fatalf("the seam ran %d times, want 1: the request did not reach the insert", intruded)
	}
	var tenants, orphans int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM tenants WHERE name = $1),
		       (SELECT count(*) FROM tenant_credentials c WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = c.tenant_id))`, name).Scan(&tenants, &orphans); err != nil {
		t.Fatal(err)
	}
	if tenants != 0 || orphans != 0 {
		t.Fatalf("the refused creation left %d tenants and %d orphan credentials", tenants, orphans)
	}
	if got := settled(creator); got != elsewhere+":viewer audit=0" {
		t.Fatalf("after the refused creation: %s; want the intruding membership only and no ledger row", got)
	}

	// Invitation acceptance.
	// The invitation is sent by an enabled owner of the inviting tenant:
	// acceptance refuses one whose sender is not, before it reaches the insert.
	invitee := "invitee-" + run + "@pat1883-handlers.invalid"
	inviter := pat1883User(t, pool, inviting, "inviter", portalauth.RoleOwner)
	var invitation string
	if err := pool.QueryRow(ctx, `
		INSERT INTO portal_invitations (tenant_id, email, role, invited_by_email, expires_at)
		VALUES ($1::uuid, $2, 'admin', $3, now() + interval '1 day') RETURNING id::text`, inviting, invitee, inviter).Scan(&invitation); err != nil {
		t.Fatal(err)
	}
	rr = call(s.AcceptInvitationHandler(), invitee, ``, map[string]string{"invitationID": invitation})
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "already_member") {
		t.Fatalf("acceptance after the address gained a membership = %d %s, want 409 already_member", rr.Code, rr.Body.String())
	}
	if intruded != 2 {
		t.Fatalf("the seam ran %d times, want 2", intruded)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM portal_invitations WHERE id = $1::uuid`, invitation).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("the refused acceptance left the invitation %s, want pending", status)
	}
	if got := settled(invitee); got != elsewhere+":viewer audit=0" {
		t.Fatalf("after the refused acceptance: %s; want the intruding membership only and no ledger row", got)
	}
}

// An owner can send feedback: the reporter's role is recorded as it is.
// A revocation that arrives while an acceptance is in progress waits for it.
// The seam runs when every acceptance check has passed and the membership is
// about to be inserted. The owner's revocation is started at that moment and
// given time to do whatever it can. With the invitation row locked it can do
// nothing until the acceptance commits, and is then refused because the
// invitation has been used. Without the lock it would revoke a row the
// acceptance is about to mark accepted, and one of the two would fail half
// way. (Both orders under real timing: TestPAT1883AcceptRacingRevokeHasOneOutcome
// in cmd/patched-api.)
func TestPAT1883RevokeDuringAcceptanceWaitsForIt(t *testing.T) {
	pool := pat1883Pool(t)
	ctx := context.Background()
	tenant := pat1883Tenant(t, pool)
	owner := pat1883User(t, pool, tenant, "owner", portalauth.RoleOwner)
	s := NewPortalSignup(pool, PortalSignupConfig{Enabled: true})
	t.Cleanup(func() { signupBeforeMembershipInsert = nil })

	invitee := "invitee-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "@pat1883-handlers.invalid"
	var invitation string
	if err := pool.QueryRow(ctx, `
		INSERT INTO portal_invitations (tenant_id, email, role, invited_by_email, expires_at)
		VALUES ($1::uuid, $2, 'viewer', $3, now() + interval '1 day') RETURNING id::text`, tenant, invitee, owner).Scan(&invitation); err != nil {
		t.Fatal(err)
	}

	revoked := make(chan *httptest.ResponseRecorder, 1)
	finishedEarly := false
	signupBeforeMembershipInsert = func(context.Context, string) {
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			rc := chi.NewRouteContext()
			rc.URLParams.Add("invitationID", invitation)
			req = req.WithContext(portalauth.WithIdentity(contextWithChi(req, rc), portalauth.Identity{Email: owner, TenantID: tenant}))
			rr := httptest.NewRecorder()
			s.InvitationRevokeHandler().ServeHTTP(rr, req)
			revoked <- rr
		}()
		// Far longer than a revocation takes when nothing holds it back.
		select {
		case rr := <-revoked:
			finishedEarly = true
			revoked <- rr
		case <-time.After(400 * time.Millisecond):
		}
	}

	acc := signupCall(ctx, s.AcceptInvitationHandler(), invitee, "", map[string]string{"invitationID": invitation})
	var rev *httptest.ResponseRecorder
	select {
	case rev = <-revoked:
	case <-time.After(15 * time.Second):
		t.Fatal("the revocation never finished")
	}
	if finishedEarly {
		t.Errorf("the revocation finished while the acceptance was still in progress: %d %s", rev.Code, rev.Body.String())
	}
	if acc.Code != http.StatusOK {
		t.Errorf("acceptance = %d %s, want 200", acc.Code, acc.Body.String())
	}
	if rev.Code != http.StatusConflict || !strings.Contains(rev.Body.String(), "invitation_accepted") {
		t.Errorf("revocation = %d %s, want 409 invitation_accepted", rev.Code, rev.Body.String())
	}
	var rows string
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT status FROM portal_invitations WHERE id = $1::uuid)
		    || ' members=' || (SELECT count(*) FROM portal_users WHERE email = $2 AND tenant_id = $3::uuid)::text
		    || ' accepted=' || (SELECT count(*) FROM portal_access_audit WHERE invitation_id = $1::uuid AND action = 'invitation_accepted')::text
		    || ' revoked=' || (SELECT count(*) FROM portal_access_audit WHERE invitation_id = $1::uuid AND action = 'invitation_revoked')::text`,
		invitation, invitee, tenant).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != "accepted members=1 accepted=1 revoked=0" {
		t.Errorf("after the race the rows say: %s", rows)
	}
}

func TestPAT1883OwnerCanSubmitFeedback(t *testing.T) {
	pool := pat1883Pool(t)
	tenant := pat1883Tenant(t, pool)
	owner := pat1883User(t, pool, tenant, "owner", "owner")

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for k, v := range map[string]string{
		"type": "feature", "title": "PAT-1883 owner feedback", "description": "An owner should be able to send this.", "route": "/settings/access",
	} {
		if err := form.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/portal/feedback", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: owner, TenantID: tenant}))
	rr := httptest.NewRecorder()
	PortalFeedbackHandler(pool, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("owner feedback = %d %s, want 201", rr.Code, rr.Body.String())
	}
	var role string
	if err := pool.QueryRow(context.Background(), `SELECT reporter_role FROM feedback WHERE tenant_id = $1::uuid AND reporter_email = $2`, tenant, owner).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "owner" {
		t.Fatalf("recorded reporter_role = %q, want owner", role)
	}
	// The column still refuses a role that does not exist.
	if _, err := pool.Exec(context.Background(), `UPDATE feedback SET reporter_role = 'superuser' WHERE tenant_id = $1::uuid`, tenant); err == nil {
		t.Fatal("feedback.reporter_role accepted an unknown role")
	}
}
