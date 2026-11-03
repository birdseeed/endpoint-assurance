package handlers

// Shared DB-backed test helpers used across this package's test files
// (admin_candidates_test.go, app_policies_tier_test.go, notify_alerts_test.go,
// tenant_apps_test.go). Originally lived in catalogue_test.go; moved here when
// PAT-1561 retired that file along with the tenant_catalogue table and its
// admin handlers — these helpers are generic and outlived that feature.

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
)

// catWithTenantID injects a chi tenantID URL param.
func catWithTenantID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// catConnectOrSkip opens a pool using TEST_DATABASE_URL or skips the test.
func catConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping DB-backed test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// catSeedTenant inserts a throwaway tenant and registers cleanup.
func catSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		            '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`, name).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}
