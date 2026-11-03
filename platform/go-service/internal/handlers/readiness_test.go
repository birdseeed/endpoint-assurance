package handlers

// Tests for GET /ready (PAT-1215) — see readiness.go's file doc comment for
// why this is a separate endpoint from /health.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

// TestReadinessHandler_NilPool covers the defensive fail-closed branch: a
// misconfigured/nil pool must never panic and must report failure, not 2xx.
func TestReadinessHandler_NilPool(t *testing.T) {
	h := ReadinessHandler(nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil pool: got %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	assertReadinessBodySafe(t, rr.Body.String(), "error")
}

// TestReadinessHandler_UnreachableDB points a real pgxpool.Pool at a closed
// local port (nothing listens on 127.0.0.1:1) so the DB round trip genuinely
// fails — connection refused — without needing a live database. Exercises
// the same code path a hung/down production database would hit.
func TestReadinessHandler_UnreachableDB(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://patched:wrongpass@127.0.0.1:1/nonexistent?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New (lazy, should not itself connect): %v", err)
	}
	defer pool.Close()

	h := ReadinessHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rr.Code >= 200 && rr.Code < 300 {
		t.Fatalf("unreachable db: got %d, want a non-2xx status code", rr.Code)
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreachable db: got %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}

	body := rr.Body.String()
	assertReadinessBodySafe(t, body, "error")

	// The body must never leak the DSN, host, port, or password used above.
	for _, secret := range []string{"wrongpass", "127.0.0.1:1", "nonexistent", "patched:wrongpass"} {
		if strings.Contains(body, secret) {
			t.Fatalf("readiness failure body leaked connection detail %q: %s", secret, body)
		}
	}
}

// TestReadinessHandler_HealthyDB requires TEST_DATABASE_URL (same convention as
// the rest of this package's DB-backed tests, e.g. admin_lifecycle_test.go)
// and is skipped otherwise. Confirms the success path: 2xx + a body naming
// what was checked, no "reason".
func TestReadinessHandler_HealthyDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping readiness healthy-DB test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	h := ReadinessHandler(pool)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("healthy db: got %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp readinessResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rr.Body.String())
	}
	if resp.Status != "ok" {
		t.Errorf("status: got %q, want %q", resp.Status, "ok")
	}
	if resp.Checked != "database" {
		t.Errorf("checked: got %q, want %q", resp.Checked, "database")
	}
	if resp.Reason != "" {
		t.Errorf("reason: got %q, want empty on success", resp.Reason)
	}
}

// assertReadinessBodySafe decodes the JSON body, checks the status/checked
// fields, and asserts the body never contains anything that looks like
// connection detail an unauthenticated caller shouldn't learn.
func assertReadinessBodySafe(t *testing.T, body, wantStatus string) {
	t.Helper()

	var resp readinessResp
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if resp.Status != wantStatus {
		t.Errorf("status: got %q, want %q", resp.Status, wantStatus)
	}
	if resp.Checked != "database" {
		t.Errorf("checked: got %q, want %q", resp.Checked, "database")
	}

	for _, forbidden := range []string{"postgres://", "://", "password", "DATABASE_URL", "@"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("body contains disallowed substring %q: %s", forbidden, body)
		}
	}
}
