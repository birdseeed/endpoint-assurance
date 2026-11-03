package evidencecatalogue

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// This test creates a private schema inside the explicitly supplied test DB.
// Production/shared databases must never be supplied as TEST_DATABASE_URL.
func TestWindowsDeliveryLedgerDatabase(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "pat1921_delivery_test"
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	forward, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0155_windows_installation_evidence_deliveries.sql"))
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0155_windows_installation_evidence_deliveries_rollback.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(forward)); err != nil {
		t.Fatal(err)
	}
	var canRead, canAppend, canUpdate, canDelete, canTruncate bool
	// has_table_privilege() reports the *effective* privilege, which a
	// superuser always has regardless of any REVOKE — exactly CI's
	// bootstrap `patched` role (postgres:16's POSTGRES_USER gets superuser
	// power), so it can't tell an intact REVOKE from a missing one there.
	// Query the literal ACL entries instead: unlike has_table_privilege,
	// information_schema.role_table_grants is not superuser-bypassed, so
	// this reflects what migration 0155 actually granted/revoked for
	// `patched` whether or not the connecting role happens to be super.
	if err := pool.QueryRow(ctx, `SELECT
		COALESCE(bool_or(privilege_type = 'SELECT'), false),
		COALESCE(bool_or(privilege_type = 'INSERT'), false),
		COALESCE(bool_or(privilege_type = 'UPDATE'), false),
		COALESCE(bool_or(privilege_type = 'DELETE'), false),
		COALESCE(bool_or(privilege_type = 'TRUNCATE'), false)
		FROM information_schema.role_table_grants
		WHERE table_schema = current_schema() AND table_name = 'windows_installation_evidence_deliveries' AND grantee = 'patched'`).Scan(&canRead, &canAppend, &canUpdate, &canDelete, &canTruncate); err != nil || !canRead || !canAppend || canUpdate || canDelete || canTruncate {
		t.Fatalf("application ledger grants read=%v append=%v update=%v delete=%v truncate=%v: %v", canRead, canAppend, canUpdate, canDelete, canTruncate, err)
	}
	if _, err := pool.Exec(ctx, string(rollback)); err != nil {
		t.Fatalf("empty migration rollback: %v", err)
	}
	if _, err := pool.Exec(ctx, string(forward)); err != nil {
		t.Fatal(err)
	}
	d, _ := EmbeddedWindowsDelivery()
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- admitWindowsDelivery(ctx, pool, d, deliveryTestNow()) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent first publication: %v", err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM windows_installation_evidence_deliveries`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("publication count=%d err=%v", count, err)
	}
	publisher := NewWindowsDeliveryPublisher(pool)
	if _, err := publisher.Delivery(ctx, deliveryTestNow()); err != nil {
		t.Fatalf("first cached admission: %v", err)
	}
	// Hold the publication lock on another connection. The cached path must
	// still finish: it only checks the durable head with a lock-free SELECT.
	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lockTx.Rollback(ctx) }()
	if _, err := lockTx.Exec(ctx, `SELECT pg_advisory_xact_lock(1921, 1)`); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	_, cacheErr := publisher.Delivery(bounded, deliveryTestNow())
	cancel()
	_ = lockTx.Rollback(ctx)
	if cacheErr != nil {
		t.Fatalf("cached request waited on publication lock: %v", cacheErr)
	}
	changed := *d
	changed.ExpiresAt = "2026-12-18T00:00:00Z"
	if admitWindowsDelivery(ctx, pool, &changed, deliveryTestNow()) == nil {
		t.Fatal("same version changed metadata accepted")
	}
	changed = *d
	changed.DeliveryVersion = 3
	if admitWindowsDelivery(ctx, pool, &changed, deliveryTestNow()) == nil {
		t.Fatal("skipped version accepted")
	}
	changed.DeliveryVersion = 2
	if err := admitWindowsDelivery(ctx, pool, &changed, deliveryTestNow()); err != nil {
		t.Fatalf("rollback/renewal at higher version: %v", err)
	}
	if stale, err := publisher.Delivery(ctx, deliveryTestNow()); err == nil || stale != nil {
		t.Fatal("cached v1 handler served evidence after concurrent v2 publication")
	}
	if admitWindowsDelivery(ctx, pool, d, deliveryTestNow()) == nil {
		t.Fatal("old binary publication accepted")
	}
	mutations := []string{
		`UPDATE windows_installation_evidence_deliveries SET publication = publication`,
		`DELETE FROM windows_installation_evidence_deliveries`,
		`TRUNCATE windows_installation_evidence_deliveries`,
	}
	// Production's `patched` role is a non-superuser owner with UPDATE,
	// DELETE and TRUNCATE explicitly revoked by migration 0155 (verified on
	// api-01: \dp shows patched=arxt, no w/d/D). Postgres denies those at
	// the ACL layer before the BEFORE-trigger ever runs, so the connecting
	// role gets "permission denied", not the trigger's "immutable" message.
	// CI's bootstrap `patched` role (postgres:16's POSTGRES_USER) is a
	// superuser and bypasses ACL entirely, so it reaches the trigger and
	// gets "immutable" instead. Assert refusal, accepting either message,
	// since which layer produced it depends on which role is connected.
	for _, stmt := range mutations {
		_, err := pool.Exec(ctx, stmt)
		if err == nil {
			t.Fatalf("history mutation was not rejected: %s", stmt)
		}
		if !strings.Contains(err.Error(), "immutable") && !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Fatalf("history mutation rejected for an unexpected reason: %s: %v", stmt, err)
		}
	}
	// The trigger is the only guard left once ACL allows the write through
	// (a superuser, or a future mis-grant on the owner) — table ownership
	// means the connecting role can always re-grant to itself, so force
	// that path and confirm the trigger alone still refuses every mutation,
	// regardless of whether this run's role is CI's superuser or a
	// production-shaped non-superuser owner.
	if _, err := pool.Exec(ctx, `GRANT UPDATE, DELETE, TRUNCATE ON windows_installation_evidence_deliveries TO CURRENT_USER`); err != nil {
		t.Fatalf("grant for trigger-only check: %v", err)
	}
	for _, stmt := range mutations {
		if _, err := pool.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("trigger did not refuse mutation once ACL allowed it: %s: %v", stmt, err)
		}
	}
	if _, err := pool.Exec(ctx, `REVOKE UPDATE, DELETE, TRUNCATE ON windows_installation_evidence_deliveries FROM CURRENT_USER`); err != nil {
		t.Fatalf("revoke after trigger-only check: %v", err)
	}
	changed.DeliveryVersion = 4
	raw, _ := json.Marshal(changed)
	if _, err := pool.Exec(ctx, `INSERT INTO windows_installation_evidence_deliveries (delivery_version, publication) VALUES (4, $1)`, raw); err == nil {
		t.Fatal("DB trigger accepted skipped version")
	}
	// Failed multi-statement rollback leaves its connection in an aborted
	// transaction. Own and explicitly roll back that connection before reuse.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, string(rollback))
	_, _ = conn.Exec(ctx, "ROLLBACK")
	conn.Release()
	if err == nil || !strings.Contains(err.Error(), "Retain Windows") {
		t.Fatalf("populated ledger rollback did not preserve evidence: %v", err)
	}
}
