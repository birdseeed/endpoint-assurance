package handlers

// PAT-2145: the ingest transaction re-checks the token under a lock, so an
// event that authenticated just before a rotate or revoke committed is not
// written. Skipped without TEST_DATABASE_URL.

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"testing"
	"time"

	"patched.im/api/internal/jamfcoverage"
)

func TestJamfIngestRechecksTokenInsideTransaction(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2145-recheck")
	oldHash := sha256.Sum256([]byte("pjwh_old"))
	if _, err := pool.Exec(ctx, `
		INSERT INTO jamf_webhook_connectors (tenant_id, webhook_id, token_hash, token_issued_at)
		VALUES ($1::uuid, $2, $3, now())`, tenantID, "rc"+tenantID[:8]+"0123456789abcdefghijkl", oldHash[:]); err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	ev := jamfcoverage.Event{Type: jamfcoverage.EventComputerAdded, Serial: "C02RECHECK1", SerialNormalized: "C02RECHECK1", Time: time.Now()}
	count := func() int {
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM jamf_devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&n)
		return n
	}

	// The handler authenticated "pjwh_old"; a rotation then commits.
	newHash := sha256.Sum256([]byte("pjwh_new"))
	if _, err := pool.Exec(ctx, `UPDATE jamf_webhook_connectors SET token_hash = $2 WHERE tenant_id = $1::uuid`, tenantID, newHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := jamfIngestEvent(ctx, pool, tenantID, "pjwh_old", ev, "", slog.Default()); !errors.Is(err, errJamfTokenChanged) {
		t.Fatalf("stale token after rotation: err = %v, want errJamfTokenChanged", err)
	}
	// Revoked.
	if _, err := pool.Exec(ctx, `UPDATE jamf_webhook_connectors SET token_hash = NULL WHERE tenant_id = $1::uuid`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := jamfIngestEvent(ctx, pool, tenantID, "pjwh_new", ev, "", slog.Default()); !errors.Is(err, errJamfTokenChanged) {
		t.Fatalf("after revoke: err = %v, want errJamfTokenChanged", err)
	}
	if n := count(); n != 0 {
		t.Fatalf("stale-token events wrote %d rows", n)
	}

	// A revoke that starts while an event holds the connector row waits for
	// it: the event commits first, then the revoke.
	if _, err := pool.Exec(ctx, `UPDATE jamf_webhook_connectors SET token_hash = $2 WHERE tenant_id = $1::uuid`, tenantID, newHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := jamfIngestEvent(ctx, pool, tenantID, "pjwh_new", ev, "", slog.Default()); err != nil {
		t.Fatalf("current token: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("current token wrote %d rows, want 1", n)
	}
	// Tenant revoked: nothing is written even with the current token.
	if _, err := pool.Exec(ctx, `UPDATE tenants SET revoked_at = now() WHERE id = $1::uuid`, tenantID); err != nil {
		t.Fatal(err)
	}
	ev.Serial, ev.SerialNormalized = "C02RECHECK2", "C02RECHECK2"
	if _, err := jamfIngestEvent(ctx, pool, tenantID, "pjwh_new", ev, "", slog.Default()); !errors.Is(err, errJamfTokenChanged) {
		t.Fatalf("revoked tenant: err = %v, want errJamfTokenChanged", err)
	}
}
