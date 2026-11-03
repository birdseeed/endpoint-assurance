package handlers

// PAT-1883: the ceiling on organisations created per hour counts tenants that
// were created, not requests that tried. These tests force the outcomes a
// caller could otherwise repeat to hold sign-up shut for everyone: a refusal
// after every check has passed, a request that dies half way, a panic.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

// signupCall calls a sign-up handler directly as the verified applicant email.
func signupCall(ctx context.Context, h http.HandlerFunc, email, body string, params map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)).WithContext(ctx)
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	req = req.WithContext(portalauth.WithApplicant(contextWithChi(req, rc), portalauth.Applicant{Email: email}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

type ceilingFx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	run    string
	marker string
	n      int
}

func newCeilingFx(t *testing.T) *ceilingFx {
	t.Helper()
	pool := pat1883Pool(t)
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	f := &ceilingFx{t: t, pool: pool, run: run, marker: "PAT1883 ceiling " + run}
	t.Cleanup(func() {
		signupBeforeMembershipInsert = nil
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE name LIKE $1`, f.marker+"%"); err != nil {
			t.Errorf("remove synthetic tenants: %v", err)
		}
	})
	return f
}

func (f *ceilingFx) email(label string) string {
	f.n++
	return label + "-" + f.run + "-" + strconv.Itoa(f.n) + "@pat1883-handlers.invalid"
}

func (f *ceilingFx) body() string {
	f.n++
	return `{"name":"` + f.marker + ` ` + strconv.Itoa(f.n) + `"}`
}

func (f *ceilingFx) tenants() int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenants WHERE name LIKE $1`, f.marker+"%").Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// With a ceiling of one, a request that reserved the only slot and then
// created nothing must give it back: the next new person still gets in.
func TestPAT1883CeilingIsReleasedUnlessATenantIsCreated(t *testing.T) {
	bg := context.Background()
	for _, c := range []struct {
		name string
		// arrange installs the seam and returns the context to call with and
		// the status the doomed request must get (0: it panics).
		arrange func(f *ceilingFx, elsewhere string) (context.Context, int)
	}{
		{"the primary key refuses after every check passed (409)", func(f *ceilingFx, elsewhere string) (context.Context, int) {
			signupBeforeMembershipInsert = func(_ context.Context, email string) {
				if _, err := f.pool.Exec(bg, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, 'viewer')`, email, elsewhere); err != nil {
					f.t.Errorf("intruding insert: %v", err)
				}
			}
			return bg, http.StatusConflict
		}},
		{"the caller goes away half way (500)", func(f *ceilingFx, _ string) (context.Context, int) {
			ctx, cancel := context.WithCancel(bg)
			f.t.Cleanup(cancel)
			signupBeforeMembershipInsert = func(context.Context, string) { cancel() }
			return ctx, http.StatusInternalServerError
		}},
		{"the handler panics", func(f *ceilingFx, _ string) (context.Context, int) {
			signupBeforeMembershipInsert = func(context.Context, string) { panic("PAT-1883 forced panic") }
			return bg, 0
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCeilingFx(t)
			elsewhere := pat1883Tenant(t, f.pool)
			s := NewPortalSignup(f.pool, PortalSignupConfig{Enabled: true, OrgCreationsPerHour: 1})

			reached := 0
			ctx, want := c.arrange(f, elsewhere)
			inner := signupBeforeMembershipInsert
			signupBeforeMembershipInsert = func(ctx context.Context, email string) { reached++; inner(ctx, email) }

			doomed := f.email("doomed")
			func() {
				defer func() {
					if r := recover(); (r != nil) != (want == 0) {
						t.Fatalf("panic = %v, want a panic: %v", r, want == 0)
					}
				}()
				if rr := signupCall(ctx, s.CreateOrganisationHandler(), doomed, f.body(), nil); rr.Code != want {
					t.Fatalf("the doomed creation = %d %s, want %d", rr.Code, rr.Body.String(), want)
				}
			}()
			if reached != 1 {
				t.Fatalf("the seam ran %d times, want 1: the request never held a slot", reached)
			}
			signupBeforeMembershipInsert = nil

			// Nothing was created, so the only slot is free again.
			fresh := f.email("fresh")
			if rr := signupCall(bg, s.CreateOrganisationHandler(), fresh, f.body(), nil); rr.Code != http.StatusCreated {
				t.Fatalf("a new person after a creation that created nothing = %d %s, want 201: the failed request kept the slot", rr.Code, rr.Body.String())
			}
			// And a tenant that was created does keep it.
			rr := signupCall(bg, s.CreateOrganisationHandler(), f.email("late"), f.body(), nil)
			if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" {
				t.Fatalf("one past the ceiling = %d %s (Retry-After %q), want 429 with Retry-After", rr.Code, rr.Body.String(), rr.Header().Get("Retry-After"))
			}
			// The rollback of an abandoned request is the server's to finish.
			deadline := time.Now().Add(5 * time.Second)
			for f.tenants() != 1 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if n := f.tenants(); n != 1 {
				t.Fatalf("%d tenants exist, want exactly the one that was created", n)
			}
		})
	}
}

// A caller over the ceiling is refused before any provisioning work, and an
// address the table could not store is refused before a slot is taken.
func TestPAT1883CeilingRefusesBeforeTheWork(t *testing.T) {
	bg := context.Background()
	f := newCeilingFx(t)
	s := NewPortalSignup(f.pool, PortalSignupConfig{Enabled: true, OrgCreationsPerHour: 1})
	reached := 0
	signupBeforeMembershipInsert = func(context.Context, string) { reached++ }

	// An address longer than any real one. Nothing is reserved for it.
	long := strings.Repeat("a", 300) + "-" + f.run + "@pat1883-handlers.invalid"
	for i := 0; i < 3; i++ {
		rr := signupCall(bg, s.CreateOrganisationHandler(), long, f.body(), nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"unsupported_email"`) {
			t.Fatalf("over-long address = %d %s, want 400 unsupported_email", rr.Code, rr.Body.String())
		}
	}
	if reached != 0 || f.tenants() != 0 {
		t.Fatalf("an unusable address reached provisioning %d times and left %d tenants", reached, f.tenants())
	}

	if rr := signupCall(bg, s.CreateOrganisationHandler(), f.email("first"), f.body(), nil); rr.Code != http.StatusCreated {
		t.Fatalf("first creation = %d %s, want 201: the refused address spent the ceiling", rr.Code, rr.Body.String())
	}
	if reached != 1 {
		t.Fatalf("the seam ran %d times, want 1", reached)
	}
	for i := 0; i < 3; i++ {
		rr := signupCall(bg, s.CreateOrganisationHandler(), f.email("over"), f.body(), nil)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("over the ceiling = %d %s, want 429", rr.Code, rr.Body.String())
		}
	}
	if reached != 1 || f.tenants() != 1 {
		t.Fatalf("over-ceiling callers reached provisioning (seam ran %d times, %d tenants); want 1 and 1", reached, f.tenants())
	}
}

// The table stores an address only in the form lower() gives it. The check
// that runs before a slot is reserved asks the database, so it agrees with
// the table whatever the database's collation.
func TestPAT1883SignupEmailStorable(t *testing.T) {
	pool := pat1883Pool(t)
	ctx := context.Background()
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	const domain = "@pat1883-handlers.invalid"
	longest := strings.Repeat("a", inviteEmailMaxBytes-len(run)-len(domain)) + run + domain
	for email, want := range map[string]bool{
		"someone-" + run + domain:             true,
		"first.last+tag-" + run + domain:      true,
		longest:                               true,
		"a" + longest:                         false,
		"Someone-" + run + domain:             false,
		"someone-" + run + "@PAT1883.invalid": false,
		"":                                    false,
		"ctl\u0007-" + run + domain:           false,
		"bad\xffutf8-" + run + domain:         false,
	} {
		got, err := signupEmailStorable(ctx, pool, email)
		if err != nil {
			t.Fatalf("signupEmailStorable(%q): %v", email, err)
		}
		if got != want {
			t.Errorf("signupEmailStorable(%q) = %v, want %v", email, got, want)
		}
		// It must agree with the table itself.
		if want {
			tenant := pat1883Tenant(t, pool)
			if _, err := pool.Exec(ctx, `INSERT INTO portal_users (email, tenant_id) VALUES ($1, $2::uuid)`, email, tenant); err != nil {
				t.Errorf("the table refused %q, which the check accepted: %v", email, err)
			}
		}
	}
}

// After a COMMIT that returned an error the handler asks whether the tenant
// exists, so the ceiling counts it if it does.
func TestPAT1883TenantExists(t *testing.T) {
	pool := pat1883Pool(t)
	s := NewPortalSignup(pool, PortalSignupConfig{Enabled: true})
	if !s.tenantExists(pat1883Tenant(t, pool)) {
		t.Error("an existing tenant was reported missing")
	}
	if s.tenantExists("00000000-0000-4000-8000-0000000000ff") {
		t.Error("a tenant that does not exist was reported present")
	}
	// Unable to find out is counted, never waved through.
	if !s.tenantExists("not-a-uuid") {
		t.Error("a failed lookup was treated as no tenant")
	}
}
