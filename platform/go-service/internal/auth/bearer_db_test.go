package auth_test

// PAT-687: end-to-end bearer-auth test against a real Postgres. Skipped unless
// TEST_DATABASE_URL points at a scratch database (CI has no DB, so `go test
// ./...` stays green there). Verifies that a credential written with the
// envelope ENABLED (marked ciphertext in the column) is decrypted back to the
// original hmac_secret by LookupTenantByBearer, and that a legacy PLAINTEXT
// credential in the same table still authenticates unchanged.
//
// The pool's search_path is pinned to an isolated schema (pat687_test) so the
// unqualified table names in bearer.go resolve there and no real data is
// touched; the schema is dropped on cleanup.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/envelope"
)

const testSchema = "pat687_test"

func dbPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed bearer test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	// Every connection in the pool resolves unqualified names in the test schema.
	cfg.ConnConfig.RuntimeParams["search_path"] = testSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`,
		`CREATE SCHEMA ` + testSchema,
		`CREATE TABLE ` + testSchema + `.tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			revoked_at TIMESTAMPTZ
		)`,
		// Minimal mirror of migrations/0001_initial.sql's devices table (just
		// enough for the FK below); PAT-1417's DB tests need a real device row
		// to reference, matching production exactly (see tenant_credentials
		// below).
		`CREATE TABLE ` + testSchema + `.devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + testSchema + `.tenants(id) ON DELETE CASCADE
		)`,
		// device_id mirrors production's tenant_credentials_device_id_fkey
		// (confirmed on patched-api-01, PAT-1417 review): UUID, nullable
		// (NULL = tenant-level credential), REFERENCES devices(id) ON DELETE
		// CASCADE. The cascade means deleting a device silently deletes its
		// credentials too — deliberate in production (a removed device's
		// tokens should stop working), but worth remembering here since it's
		// what would silently swallow this table's rows in a test that
		// deletes a device row directly instead of via schema teardown.
		`CREATE TABLE ` + testSchema + `.tenant_credentials (
			id BIGSERIAL PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES ` + testSchema + `.tenants(id),
			device_id UUID REFERENCES ` + testSchema + `.devices(id) ON DELETE CASCADE,
			bearer_token_hash BYTEA NOT NULL,
			hmac_secret BYTEA NOT NULL,
			revoked_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup exec %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE`)
	})
	return pool
}

func insertCredential(t *testing.T, pool *pgxpool.Pool, storedSecret []byte) (tenantID, bearerToken string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (revoked_at) VALUES (NULL) RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("rand token: %v", err)
	}
	bearerToken = base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(bearerToken))
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
		 VALUES ($1::uuid, $2, $3)`,
		tenantID, hash[:], storedSecret,
	); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	return tenantID, bearerToken
}

func TestLookupTenantByBearer_EnvelopeRoundTrip(t *testing.T) {
	pool := dbPool(t)
	withKEK(t) // envelope enabled

	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	stored, err := envelope.Default().EncryptBytes(secret)
	if err != nil {
		t.Fatalf("EncryptBytes: %v", err)
	}
	_, token := insertCredential(t, pool, stored)

	_, gotSecret, err := auth.LookupTenantByBearer(context.Background(), pool, "Bearer "+token)
	if err != nil {
		t.Fatalf("LookupTenantByBearer: %v", err)
	}
	if string(gotSecret) != string(secret) {
		t.Fatalf("decrypted secret mismatch: got %x want %x", gotSecret, secret)
	}
}

func TestLookupTenantByBearer_PlaintextCredentialStillAuths(t *testing.T) {
	pool := dbPool(t)
	withKEK(t) // KEK enabled, but the stored row is legacy plaintext

	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	_, token := insertCredential(t, pool, secret) // stored verbatim, no marker

	_, gotSecret, err := auth.LookupTenantByBearer(context.Background(), pool, "Bearer "+token)
	if err != nil {
		t.Fatalf("LookupTenantByBearer: %v", err)
	}
	if string(gotSecret) != string(secret) {
		t.Fatalf("plaintext credential mismatch: got %x want %x", gotSecret, secret)
	}
}
