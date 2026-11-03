package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

// hsWithTenantID sets a tenantID chi URL param on the request.
func hsWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// -- HealthSignalHandler unit tests (no DB) -----------------------------------

func TestHealthSignalHandlerBadUUID(t *testing.T) {
	// pool can be nil — handler validates UUID before any DB call.
	h := HealthSignalHandler((*pgxpool.Pool)(nil))
	req := httptest.NewRequest(http.MethodPut, "/admin/tenant/not-a-uuid/signal", nil)
	req = hsWithTenantID(req, "not-a-uuid")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad UUID, got %d: %s", w.Code, w.Body.String())
	}
}

// -- HealthSignalHandler DB round-trip tests ----------------------------------

func TestHealthSignalHandlerDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping health signal DB tests")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	// Insert a test tenant.
	var tenantID string
	err = pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('hs-test-tenant', '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		                          '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

	h := HealthSignalHandler(pool)

	// First signal — counter goes from 0 → 1.
	req := httptest.NewRequest(http.MethodPut, "/admin/tenant/"+tenantID+"/signal", nil)
	req = hsWithTenantID(req, tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var loginCount int
	if err := pool.QueryRow(ctx,
		`SELECT dashboard_logins_last_30d FROM tenants WHERE id = $1::uuid`, tenantID,
	).Scan(&loginCount); err != nil {
		t.Fatalf("query counter: %v", err)
	}
	if loginCount != 1 {
		t.Errorf("want dashboard_logins_last_30d=1, got %d", loginCount)
	}

	// Second signal — counter goes 1 → 2.
	req2 := httptest.NewRequest(http.MethodPut, "/admin/tenant/"+tenantID+"/signal", nil)
	req2 = hsWithTenantID(req2, tenantID)
	w2 := httptest.NewRecorder()
	h(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("want 200 on second call, got %d", w2.Code)
	}
	if err := pool.QueryRow(ctx,
		`SELECT dashboard_logins_last_30d FROM tenants WHERE id = $1::uuid`, tenantID,
	).Scan(&loginCount); err != nil {
		t.Fatalf("query counter: %v", err)
	}
	if loginCount != 2 {
		t.Errorf("want dashboard_logins_last_30d=2, got %d", loginCount)
	}
}

func TestHealthSignalHandlerNotFoundDB(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping health signal not-found DB test")
	}

	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	nonExistent := "00000000-0000-0000-0000-000000000099"
	h := HealthSignalHandler(pool)
	req := httptest.NewRequest(http.MethodPut, "/admin/tenant/"+nonExistent+"/signal", nil)
	req = hsWithTenantID(req, nonExistent)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown tenant, got %d: %s", w.Code, w.Body.String())
	}
}
