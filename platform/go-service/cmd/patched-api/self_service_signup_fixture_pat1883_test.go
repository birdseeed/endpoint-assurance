package main

// PAT-1883 acceptance fixture: self-service organisation sign-up and access
// management through the PRODUCTION routers (newPublicRouter and
// newInternalRouter), a real PostgreSQL and a local stand-in for the
// Cloudflare Access key set. No handler stub and no test-only route table.
//
// Run after the integration migration step, against a disposable
// TEST_DATABASE_URL only. Synthetic data: every address is under .invalid.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
)

const (
	pat1883Kid        = "pat1883-test"
	pat1883ServiceCN  = "pat1883-service.access" // placeholder, not a real client id
	pat1883AdminToken = "synthetic-pat1883-admin-token"
	pat1883ZeroUUID   = "00000000-0000-4000-8000-000000000000"
)

type signupFx struct {
	pool          *pgxpool.Pool
	key           *rsa.PrivateKey
	jwksURL       string
	serviceTenant string
	internalOnce  http.Handler
}

func pat1883Rand() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// newSignupFx connects to the disposable test database. A missing database is
// a skip, unless PATCHED_DB_TESTS_REQUIRED says one was promised, in which
// case it is a failure: these are the only tests of the feature's behaviour,
// and a silent skip would read as a pass.
func newSignupFx(t *testing.T) *signupFx {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED: the PAT-1883 sign-up acceptance tests need TEST_DATABASE_URL and migrations 0229 and 0230")
		}
		t.Skip("requires a migrated disposable TEST_DATABASE_URL")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Never connect to a non-test database or a remote host: these tests
	// create and purge tenants.
	host := cfg.ConnConfig.Host
	if !strings.Contains(strings.ToLower(cfg.ConnConfig.Database), "test") ||
		!(host == "localhost" || host == "127.0.0.1" || strings.HasPrefix(host, "/")) {
		t.Fatal("requires a local test database")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var migrated bool
	if err := pool.QueryRow(context.Background(), `
		SELECT to_regclass('public.portal_invitations') IS NOT NULL
		   AND to_regclass('public.portal_access_audit') IS NOT NULL
	`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("migration 0230 is not applied to TEST_DATABASE_URL: portal_invitations / portal_access_audit are missing")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": pat1883Kid, "kty": "RSA", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)

	reportRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", reportRoot)

	f := &signupFx{pool: pool, key: key, jwksURL: jwks.URL}
	// Registered after pool.Close, so it runs before it. Every tenant these
	// tests make is removed again: a later test in this database must not
	// meet a leftover synthetic device or membership (a device left on the
	// beta channel changes the agent release gate, for one). DELETE FROM
	// tenants is what the operator purge runs, so every test also ends by
	// exercising the cascade and the ledger redaction trigger.
	t.Cleanup(func() { pat1883Sweep(t, pool) })
	pat1883Sweep(t, pool) // and anything an interrupted earlier run left
	f.serviceTenant = f.operatorTenant(t, "service")
	return f
}

// pat1883Sweep removes every synthetic tenant these tests created (operator
// tenants by name, self-service ones by their members' reserved addresses)
// and their access-log rows.
func pat1883Sweep(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		DELETE FROM tenants t
		WHERE t.name LIKE 'PAT1883 operator %'
		   OR EXISTS (SELECT 1 FROM portal_users pu WHERE pu.tenant_id = t.id AND pu.email LIKE '%.pat1883.invalid')
	`); err != nil {
		t.Errorf("sweep of synthetic PAT-1883 tenants failed: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM portal_access_log WHERE email LIKE '%.pat1883.invalid'`); err != nil {
		t.Errorf("sweep of synthetic PAT-1883 access-log rows failed: %v", err)
	}
}

// enabled is the feature switched on with production defaults for limits.
func pat1883Enabled() handlers.PortalSignupConfig {
	return handlers.PortalSignupConfig{Enabled: true}
}

// router builds the production public router. With no config the feature is
// at its default, which is off.
func (f *signupFx) router(cfgs ...handlers.PortalSignupConfig) http.Handler {
	verifier := portalauth.New(svcTestIssuer, svcTestAud, f.jwksURL).
		WithService(&portalauth.ServiceIdentity{CommonName: pat1883ServiceCN, TenantID: f.serviceTenant})
	limiter := ratelimit.New(ratelimit.Config{RPM: 60000, Burst: 10000})
	var opts []publicRouterOption
	for _, c := range cfgs {
		opts = append(opts, withPortalSignup(c))
	}
	return newPublicRouter(f.pool, nil, limiter, 5*time.Minute, verifier, limiter, limiter, "", "", nil, nil, "", nil, "", nil, opts...)
}

// internal is the production internal (operator) router as it is built when
// self-service sign-up is enabled, the only state in which an operator can
// designate an owner: several tests make an owner through it. The router with
// the flag off is built in TestPAT1883OperatorOwnerRoleNeedsTheFlag.
func (f *signupFx) internal() http.Handler {
	if f.internalOnce == nil {
		f.internalOnce = newInternalRouter(f.pool, nil, 0, "", pat1883AdminToken, "", nil, "", nil, withOperatorOwnerRole(true))
	}
	return f.internalOnce
}

func (f *signupFx) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"], claims["aud"] = svcTestIssuer, svcTestAud
	claims["iat"] = time.Now().Add(-time.Minute).Unix()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = pat1883Kid
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// token is a person's Access JWT for email.
func (f *signupFx) token(t *testing.T, email string) string {
	t.Helper()
	return f.sign(t, jwt.MapClaims{"email": email, "sub": email})
}

// serviceToken is the allowlisted read-only service identity's JWT.
func (f *signupFx) serviceToken(t *testing.T) string {
	t.Helper()
	return f.sign(t, jwt.MapClaims{"common_name": pat1883ServiceCN, "type": "app", "sub": ""})
}

// email returns a fresh address on its own fresh domain, so no test is ever
// affected by another's email-domain claim.
func pat1883Email(prefix string) string {
	return prefix + "-" + pat1883Rand() + "@" + pat1883Rand() + ".pat1883.invalid"
}

type pat1883Resp struct {
	Code   int
	Header http.Header
	Raw    string
	JSON   map[string]any
}

// do sends one request through router. body nil sends no body; a string is
// sent verbatim; anything else is JSON-encoded.
func (f *signupFx) do(t *testing.T, router http.Handler, method, path, token string, body any, header ...string) pat1883Resp {
	t.Helper()
	var rdr *bytes.Reader
	switch b := body.(type) {
	case nil:
		rdr = bytes.NewReader(nil)
	case string:
		rdr = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set(portalauth.Header, token)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	out := pat1883Resp{Code: rr.Code, Header: rr.Header(), Raw: rr.Body.String()}
	_ = json.Unmarshal(rr.Body.Bytes(), &out.JSON)
	return out
}

// want fails the test unless the response has the given status and, when
// code is not empty, the given {"error": code}.
func (r pat1883Resp) want(t *testing.T, what string, status int, code string) pat1883Resp {
	t.Helper()
	if r.Code != status {
		t.Fatalf("%s: status = %d, want %d: %s", what, r.Code, status, r.Raw)
	}
	if code != "" {
		if got, _ := r.JSON["error"].(string); got != code {
			t.Fatalf("%s: error = %q, want %q: %s", what, got, code, r.Raw)
		}
	}
	return r
}

func (r pat1883Resp) str(key string) string {
	s, _ := r.JSON[key].(string)
	return s
}

func (f *signupFx) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *signupFx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *signupFx) text(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// warmPool leaves n connections open and idle in the pool (or as many as the
// pool allows). A request that has to open its own connection spends longer
// doing that than a short transaction takes, so without this the first of
// several simultaneous requests has committed before the others have begun,
// nothing overlaps, and a concurrency test passes whatever the locking is.
func (f *signupFx) warmPool(t *testing.T, n int) {
	t.Helper()
	if max := int(f.pool.Config().MaxConns); n > max {
		n = max
	}
	held := make([]*pgxpool.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := f.pool.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	for _, c := range held {
		c.Release()
	}
}

// admin sends one request to the production internal router with the admin
// token.
func (f *signupFx) admin(t *testing.T, method, path string, body any) pat1883Resp {
	t.Helper()
	return f.adminVia(t, f.internal(), method, path, body)
}

// adminVia sends one request with the admin token to the given internal
// router.
func (f *signupFx) adminVia(t *testing.T, router http.Handler, method, path string, body any) pat1883Resp {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+pat1883AdminToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	out := pat1883Resp{Code: rr.Code, Header: rr.Header(), Raw: rr.Body.String()}
	_ = json.Unmarshal(rr.Body.Bytes(), &out.JSON)
	return out
}

// operatorTenant creates a tenant the way an operator does, through the
// production POST /admin/tenants.
func (f *signupFx) operatorTenant(t *testing.T, label string) string {
	t.Helper()
	r := f.admin(t, http.MethodPost, "/admin/tenants", map[string]any{"name": "PAT1883 operator " + label + " " + pat1883Rand()})
	if r.Code != http.StatusCreated || r.str("tenant_id") == "" {
		t.Fatalf("operator tenant create = %d: %s", r.Code, r.Raw)
	}
	return r.str("tenant_id")
}

// member maps email to tenant with role through the production operator
// route, and returns the address.
func (f *signupFx) member(t *testing.T, tenant, role string) string {
	t.Helper()
	email := pat1883Email(role)
	r := f.admin(t, http.MethodPost, "/admin/portal-users", map[string]any{"email": email, "tenant_id": tenant, "role": role})
	if r.Code != http.StatusCreated || r.str("role") != role {
		t.Fatalf("map %s as %s = %d: %s", email, role, r.Code, r.Raw)
	}
	return email
}

// org is a self-service organisation with its owner.
type pat1883Org struct {
	Tenant string
	Owner  string // email
	Name   string
}

// newOrg creates an organisation through the real sign-up route.
func (f *signupFx) newOrg(t *testing.T, router http.Handler) pat1883Org {
	t.Helper()
	owner := pat1883Email("owner")
	name := "PAT1883 Org " + pat1883Rand()
	r := f.do(t, router, http.MethodPost, "/v1/portal/signup/organisation", f.token(t, owner), map[string]any{"name": name})
	r.want(t, "create organisation", http.StatusCreated, "")
	return pat1883Org{Tenant: r.str("tenant_id"), Owner: owner, Name: name}
}

// invite creates an invitation as the organisation's owner and returns its id.
func (f *signupFx) invite(t *testing.T, router http.Handler, o pat1883Org, email, role string) string {
	t.Helper()
	r := f.do(t, router, http.MethodPost, "/v1/portal/access/invitations", f.token(t, o.Owner), map[string]any{"email": email, "role": role})
	r.want(t, "create invitation", http.StatusCreated, "")
	if r.str("id") == "" {
		t.Fatalf("invitation has no id: %s", r.Raw)
	}
	return r.str("id")
}

// join invites email and accepts as that person: a real member made through
// the real routes. Returns the address.
func (f *signupFx) join(t *testing.T, router http.Handler, o pat1883Org, role string) string {
	t.Helper()
	email := pat1883Email(role)
	id := f.invite(t, router, o, email, role)
	f.do(t, router, http.MethodPost, "/v1/portal/signup/invitations/"+id+"/accept", f.token(t, email), nil).
		want(t, "accept invitation", http.StatusOK, "")
	return email
}

// audit returns the tenant's ledger as "action|actor|subject|old|new|hasInvitation"
// lines in id order.
func (f *signupFx) audit(t *testing.T, tenant string) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `
		SELECT action || '|' || coalesce(actor_email, 'NULL') || '|' || coalesce(subject_email, 'NULL') || '|' ||
		       coalesce(old_role, '') || '|' || coalesce(new_role, '') || '|' || (invitation_id IS NOT NULL)::text
		FROM portal_access_audit WHERE tenant_id = $1::uuid ORDER BY id`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func pat1883Contains(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// pat1883Routes lists every (method, route pattern) on router whose pattern
// starts with prefix.
func pat1883Routes(t *testing.T, router http.Handler, prefix string) [][2]string {
	t.Helper()
	var out [][2]string
	err := chi.Walk(router.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, prefix) {
			out = append(out, [2]string{method, route})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pat1883NewRoutes is every route this ticket adds, by group.
var pat1883SignupRoutes = [][2]string{
	{"GET", "/v1/portal/signup/state"},
	{"POST", "/v1/portal/signup/organisation"},
	{"POST", "/v1/portal/signup/invitations/{invitationID}/accept"},
}

var pat1883AccessRoutes = [][2]string{
	{"GET", "/v1/portal/access"},
	{"POST", "/v1/portal/access/invitations"},
	{"POST", "/v1/portal/access/invitations/{invitationID}/revoke"},
	{"PUT", "/v1/portal/access/members/{memberEmail}/role"},
	{"POST", "/v1/portal/access/members/{memberEmail}/disable"},
	{"POST", "/v1/portal/access/members/{memberEmail}/enable"},
}

func pat1883AllNewRoutes() [][2]string {
	return append(append([][2]string{}, pat1883SignupRoutes...), pat1883AccessRoutes...)
}

// pat1883Fill replaces route parameters with values that match nothing.
func pat1883Fill(route string) string {
	return strings.NewReplacer(
		"{invitationID}", pat1883ZeroUUID,
		"{memberEmail}", "nobody@nowhere.pat1883.invalid",
	).Replace(route)
}
