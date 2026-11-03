// Package driverblocktest gives DB-gated tests their own copy of the global
// driver list tables (PAT-2263), so packages that run at the same time
// against one scratch database never see each other's lists. Tenant-scoped
// device tables stay shared; tests isolate those by creating their own
// tenants. Imported by tests only.
package driverblocktest

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool connects to TEST_DATABASE_URL (skipping the test without it, or
// failing when PATCHED_DB_TESTS_REQUIRED promises a database) with a
// search_path that puts a fresh schema named schema ahead of public, holding
// copies of driver_blocklist_source_state and driver_blocklist_entries made
// from the migrated tables (LIKE ... INCLUDING ALL: columns, defaults, CHECKs
// and indexes, so the copy cannot drift from migration 0216). The schema is
// dropped when the test ends.
func Pool(t *testing.T, schema string) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not")
		}
		t.Skip("TEST_DATABASE_URL not set; skipping PAT-2263 driver list DB test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx := context.Background()
	for _, statement := range []string{
		`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`,
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.driver_blocklist_source_state (LIKE public.driver_blocklist_source_state INCLUDING ALL)`,
		`CREATE TABLE ` + schema + `.driver_blocklist_entries (LIKE public.driver_blocklist_entries INCLUDING ALL)`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			pool.Close()
			t.Fatalf("isolate driver list tables: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		pool.Close()
	})
	return pool
}
