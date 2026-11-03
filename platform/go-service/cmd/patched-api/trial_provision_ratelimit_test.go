package main

// PAT-2529: POST /v1/trial/provision is unauthenticated on the public listener
// and inserts a tenant plus its supporting rows. These tests drive the real
// public router and prove that the request over the limit is refused with 429
// before the body is parsed and before any database work.
//
// "No database work" is measured, not assumed. Most tests hand the router a
// pool whose every connection attempt is counted and refused, so a request
// that reaches a query shows up as a dial and a refused request must leave the
// count unchanged. That also means the permitted requests here answer 500
// (the dead database), which is the proof they reached the handler's lookup.
// The database-backed test at the bottom checks the same thing against real
// rows.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/handlers"
)

// pat2529Router builds the shipping public router with the trial provision
// limits sized perIP and global per hour.
func pat2529Router(pool *pgxpool.Pool, perIP, global int) http.Handler {
	limits := handlers.NewTrialProvisionLimits(handlers.TrialProvisionLimitsConfig{PerIPPerHour: perIP, GlobalPerHour: global})
	return newPublicRouter(pool, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", limits)
}

// pat2529DeadPool returns a pool that never reaches a database: every
// connection attempt is counted and refused. Nothing is dialled.
func pat2529DeadPool(t *testing.T) (*pgxpool.Pool, *atomic.Int64) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://pat2529@127.0.0.1:1/pat2529?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MinConns = 0
	var dials atomic.Int64
	cfg.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("pat2529: database access is blocked in this test")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, &dials
}

var pat2529Seq atomic.Int64

// pat2529ValidBody is a well-formed provision request with a fresh address.
func pat2529ValidBody() string {
	return fmt.Sprintf(`{"email":"burst-%d@example-pat2529.test","name":"Burst Test"}`, pat2529Seq.Add(1))
}

// pat2529Post sends one provision request as the client at cfIP (the
// Cloudflare-supplied address) with any extra headers.
func pat2529Post(h http.Handler, cfIP, body string, extra map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/trial/provision", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cfIP != "" {
		req.Header.Set("CF-Connecting-IP", cfIP)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// pat2529WantPermitted fails unless the request got past the limiter and
// reached the database layer (the dead pool answers it with 500).
func pat2529WantPermitted(t *testing.T, label string, rr *httptest.ResponseRecorder, dials *atomic.Int64, before int64) {
	t.Helper()
	if rr.Code == http.StatusTooManyRequests {
		t.Fatalf("%s: refused with 429, want it permitted: %s", label, rr.Body.String())
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("%s: status %d, want 500 from the dead database: %s", label, rr.Code, rr.Body.String())
	}
	if dials.Load() <= before {
		t.Fatalf("%s: permitted request made no database attempt; the dial counter would not catch refused-request database work", label)
	}
}

// pat2529WantRefused fails unless the request was refused 429 in the shape the
// other limiters use, with a Retry-After, and without any database attempt.
func pat2529WantRefused(t *testing.T, label string, rr *httptest.ResponseRecorder, dials *atomic.Int64, before int64) {
	t.Helper()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("%s: status %d, want 429: %s", label, rr.Code, rr.Body.String())
	}
	if n, err := strconv.Atoi(rr.Header().Get("Retry-After")); err != nil || n < 1 {
		t.Fatalf("%s: Retry-After = %q, want a positive number of seconds", label, rr.Header().Get("Retry-After"))
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s: Content-Type = %q, want JSON", label, ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["error"] != "rate_limited" {
		t.Fatalf("%s: body %q, want the rate_limited JSON error", label, rr.Body.String())
	}
	if got := dials.Load(); got != before {
		t.Fatalf("%s: refused request attempted database work (%d -> %d dials)", label, before, got)
	}
}

func TestPAT2529TrialProvisionPerIPLimit(t *testing.T) {
	pool, dials := pat2529DeadPool(t)
	h := pat2529Router(pool, 3, 1000)

	for i := 1; i <= 3; i++ {
		before := dials.Load()
		pat2529WantPermitted(t, fmt.Sprintf("client A request %d", i),
			pat2529Post(h, "203.0.113.10", pat2529ValidBody(), nil), dials, before)
	}
	for i := 4; i <= 6; i++ {
		before := dials.Load()
		pat2529WantRefused(t, fmt.Sprintf("client A request %d", i),
			pat2529Post(h, "203.0.113.10", pat2529ValidBody(), nil), dials, before)
	}

	// The limit is per client: another address is unaffected.
	before := dials.Load()
	pat2529WantPermitted(t, "client B first request",
		pat2529Post(h, "203.0.113.11", pat2529ValidBody(), nil), dials, before)
}

// Every request is counted, valid or not, and the check runs before the body
// is read: a client cannot probe or hammer the handler's validation for free.
func TestPAT2529TrialProvisionCountsInvalidRequestsBeforeParsing(t *testing.T) {
	pool, dials := pat2529DeadPool(t)
	h := pat2529Router(pool, 3, 1000)

	for i := 1; i <= 3; i++ {
		rr := pat2529Post(h, "203.0.113.20", "not-json", nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("malformed request %d: status %d, want 400 while under the limit: %s", i, rr.Code, rr.Body.String())
		}
	}
	before := dials.Load()
	// Malformed again: over the limit it must be 429, not the parser's 400.
	pat2529WantRefused(t, "malformed request over the limit",
		pat2529Post(h, "203.0.113.20", "not-json", nil), dials, before)
	pat2529WantRefused(t, "valid request after invalid ones used the allowance",
		pat2529Post(h, "203.0.113.20", pat2529ValidBody(), nil), dials, before)
	// An oversized body is refused before it is read, not after.
	pat2529WantRefused(t, "oversized body over the limit",
		pat2529Post(h, "203.0.113.20", strings.Repeat("x", 64*1024), nil), dials, before)
}

func TestPAT2529TrialProvisionGlobalLimit(t *testing.T) {
	pool, dials := pat2529DeadPool(t)
	h := pat2529Router(pool, 1000, 4)

	// Four different clients spend the global allowance.
	for i := 1; i <= 4; i++ {
		before := dials.Load()
		pat2529WantPermitted(t, fmt.Sprintf("distinct client %d", i),
			pat2529Post(h, fmt.Sprintf("198.51.100.%d", i), pat2529ValidBody(), nil), dials, before)
	}
	// A fifth, never seen before, is refused by the global bucket alone.
	for i := 5; i <= 7; i++ {
		before := dials.Load()
		pat2529WantRefused(t, fmt.Sprintf("distinct client %d", i),
			pat2529Post(h, fmt.Sprintf("198.51.100.%d", i), pat2529ValidBody(), nil), dials, before)
	}
}

// A client already refused by its own bucket must not spend the global
// allowance, or one abusive address could lock every other customer out.
func TestPAT2529TrialProvisionRefusedClientDoesNotSpendGlobal(t *testing.T) {
	pool, dials := pat2529DeadPool(t)
	h := pat2529Router(pool, 2, 5)

	permitted := 0
	for i := 0; i < 12; i++ {
		rr := pat2529Post(h, "203.0.113.30", pat2529ValidBody(), nil)
		if rr.Code != http.StatusTooManyRequests {
			permitted++
		}
	}
	if permitted != 2 {
		t.Fatalf("abusive client got %d requests through, want exactly its per-client allowance of 2", permitted)
	}
	// 2 of the 5 global tokens went to that client; three others still fit.
	for i := 1; i <= 3; i++ {
		before := dials.Load()
		pat2529WantPermitted(t, fmt.Sprintf("other client %d", i),
			pat2529Post(h, fmt.Sprintf("198.51.100.%d", 40+i), pat2529ValidBody(), nil), dials, before)
	}
	before := dials.Load()
	pat2529WantRefused(t, "other client 4 after the global allowance is spent",
		pat2529Post(h, "198.51.100.44", pat2529ValidBody(), nil), dials, before)
}

// Only CF-Connecting-IP keys the per-client bucket. The public router mounts
// chi's RealIP, which rewrites RemoteAddr from True-Client-IP, X-Real-IP and
// X-Forwarded-For, none of which Cloudflare overwrites; a client that could
// choose its bucket by sending one of them would have no limit at all.
func TestPAT2529TrialProvisionClientCannotChooseItsBucket(t *testing.T) {
	pool, dials := pat2529DeadPool(t)
	h := pat2529Router(pool, 2, 1000)

	for i := 1; i <= 2; i++ {
		before := dials.Load()
		pat2529WantPermitted(t, fmt.Sprintf("request %d", i),
			pat2529Post(h, "203.0.113.50", pat2529ValidBody(), map[string]string{
				"X-Forwarded-For": fmt.Sprintf("192.0.2.%d", i),
				"X-Real-IP":       fmt.Sprintf("192.0.2.%d", 10+i),
				"True-Client-IP":  fmt.Sprintf("192.0.2.%d", 20+i),
			}), dials, before)
	}
	before := dials.Load()
	pat2529WantRefused(t, "request 3 with yet another set of forwarded addresses",
		pat2529Post(h, "203.0.113.50", pat2529ValidBody(), map[string]string{
			"X-Forwarded-For": "192.0.2.99",
			"X-Real-IP":       "192.0.2.98",
			"True-Client-IP":  "192.0.2.97",
		}), dials, before)

	// The converse: different Cloudflare client addresses do not share a
	// bucket just because they claim the same forwarded address.
	for i := 1; i <= 2; i++ {
		before := dials.Load()
		pat2529WantPermitted(t, fmt.Sprintf("distinct client %d with a shared forwarded address", i),
			pat2529Post(h, fmt.Sprintf("203.0.113.%d", 60+i), pat2529ValidBody(), map[string]string{
				"X-Forwarded-For": "192.0.2.1",
				"X-Real-IP":       "192.0.2.1",
				"True-Client-IP":  "192.0.2.1",
			}), dials, before)
	}
}

// A permitted request is handled exactly as before: the handler's own
// validation answers are untouched by the limiter.
func TestPAT2529TrialProvisionPermittedRequestUnchanged(t *testing.T) {
	pool, _ := pat2529DeadPool(t)
	h := pat2529Router(pool, 100, 100)

	for _, tc := range []struct {
		name, body, want string
	}{
		{"invalid json", `not-json`, "invalid JSON"},
		{"no at-sign", `{"email":"notanemail","name":"Bob"}`, "email is required"},
		{"empty name", `{"email":"bob@example.com","name":""}`, "name is required"},
	} {
		rr := pat2529Post(h, "203.0.113.70", tc.body, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), tc.want) {
			t.Errorf("%s: got %d %q, want 400 containing %q", tc.name, rr.Code, rr.Body.String(), tc.want)
		}
		if rr.Header().Get("Retry-After") != "" {
			t.Errorf("%s: a permitted request must not carry Retry-After", tc.name)
		}
	}
}

// The limits come from the environment, default to 5 per client and 30 in
// total per hour, and a value that is not a positive integer falls back to the
// default rather than disabling the limit.
func TestPAT2529TrialProvisionConfig(t *testing.T) {
	for _, tc := range []struct {
		name, perIP, global string
		wantPerIP, wantGlob int
	}{
		{"unset", "", "", 5, 30},
		{"overridden", "7", "40", 7, 40},
		{"not a number", "many", "lots", 5, 30},
		{"zero is not unlimited", "0", "0", 5, 30},
		{"negative is not unlimited", "-3", "-1", 5, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRIAL_PROVISION_PER_IP_PER_HOUR", tc.perIP)
			t.Setenv("TRIAL_PROVISION_GLOBAL_PER_HOUR", tc.global)
			cfg := loadConfig()
			if cfg.TrialProvisionPerIPPerHour != tc.wantPerIP || cfg.TrialProvisionGlobalPerHour != tc.wantGlob {
				t.Fatalf("per-IP %d and global %d, want %d and %d",
					cfg.TrialProvisionPerIPPerHour, cfg.TrialProvisionGlobalPerHour, tc.wantPerIP, tc.wantGlob)
			}
		})
	}
}

// An unconfigured limiter must never mean an unlimited route.
func TestPAT2529TrialProvisionWithoutLimiterFailsClosed(t *testing.T) {
	pool, dials := pat2529DeadPool(t)
	h := newPublicRouter(pool, nil, nil, 0, nil, nil, nil, "", "", nil, nil, "", nil, "", nil)
	rr := pat2529Post(h, "203.0.113.80", pat2529ValidBody(), nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 when the limiter is not wired: %s", rr.Code, rr.Body.String())
	}
	if dials.Load() != 0 {
		t.Fatalf("unconfigured route attempted database work")
	}
}

// Against a real database: the permitted request still creates its tenant
// (201), a repeat is still the idempotent 409, and the refused request leaves
// no tenant behind.
func TestPAT2529TrialProvisionDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not")
		}
		t.Skip("TEST_DATABASE_URL not set; skipping the PAT-2529 database check")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(cfg.ConnConfig.Database), "test") ||
		!(cfg.ConnConfig.Host == "localhost" || cfg.ConnConfig.Host == "127.0.0.1" || strings.HasPrefix(cfg.ConnConfig.Host, "/")) {
		t.Fatal("requires a local database whose name contains \"test\"")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	const suffix = "@example-pat2529-db.test"
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE trial_email LIKE '%' || $1`, suffix); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	count := func(email string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM tenants WHERE trial_email = $1`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	h := pat2529Router(pool, 2, 1000)
	const ip = "203.0.113.90"
	first := "first" + suffix
	body := func(email string) string { return `{"email":"` + email + `","name":"Limit Test","company":"ACME Inc"}` }

	rr := pat2529Post(h, ip, body(first), nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("first request: status %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		TenantID      string `json:"tenant_id"`
		EnrollmentURL string `json:"enrollment_url"`
		ExpiresAt     string `json:"expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil || created.TenantID == "" || created.EnrollmentURL == "" || created.ExpiresAt == "" {
		t.Fatalf("first request body %q, want tenant_id, enrollment_url and expires_at", rr.Body.String())
	}
	if count(first) != 1 {
		t.Fatalf("permitted request left %d tenants for its email, want 1", count(first))
	}

	rr = pat2529Post(h, ip, body(first), nil)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), created.TenantID) {
		t.Fatalf("repeat request: status %d body %q, want the idempotent 409 naming tenant %s", rr.Code, rr.Body.String(), created.TenantID)
	}

	refused := "refused" + suffix
	rr = pat2529Post(h, ip, body(refused), nil)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status %d, want 429: %s", rr.Code, rr.Body.String())
	}
	if n := count(refused); n != 0 {
		t.Fatalf("refused request left %d tenants for its email, want 0", n)
	}
	var tokens int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, created.TenantID).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 2 {
		t.Fatalf("tenant has %d enrolment tokens, want 2 (the 201 and the 409 each minted one, the refused request none)", tokens)
	}
}
