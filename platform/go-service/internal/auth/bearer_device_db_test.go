package auth_test

// PAT-1417: end-to-end tests for LookupDeviceByBearer's server-side-only
// distinction between "no such token" and "token exists but is tenant-level"
// (auth.ErrDeviceCredentialRequired). Skipped unless TEST_DATABASE_URL points
// at a scratch database (CI has no DB, so `go test ./...` stays green there),
// same convention as bearer_db_test.go.
//
// The critical invariant under test is NOT just "does the new error fire" —
// it's that it fires in exactly one case (a live, non-revoked, unexpired
// credential with device_id NULL) and nowhere else: a genuinely unknown token
// and a revoked/expired device-scoped credential must still come back as the
// same ErrUnknownToken as before this change, or a caller could mistake a
// dead credential for one that "just needs a device scope".

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
)

// insertCredentialFull inserts a tenant_credentials row with full control over
// device_id, revoked_at, and expires_at. When deviceScoped is true it first
// inserts a real row into the test schema's devices table and points
// device_id at it — production's tenant_credentials_device_id_fkey (confirmed
// on patched-api-01, PAT-1417 review) is device_id UUID REFERENCES
// devices(id) ON DELETE CASCADE, so a bare unreferenced UUID is not an insert
// production's schema could accept; the test setup must mirror that or it
// proves nothing about the real constraint. deviceScoped == false stores a
// tenant-level row (device_id NULL).
func insertCredentialFull(t *testing.T, pool *pgxpool.Pool, storedSecret []byte, deviceScoped bool, revokedAt, expiresAt *time.Time) (tenantID, deviceID, bearerToken string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (revoked_at) VALUES (NULL) RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	if deviceScoped {
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`,
			tenantID,
		).Scan(&deviceID); err != nil {
			t.Fatalf("insert device: %v", err)
		}
	}

	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("rand token: %v", err)
	}
	bearerToken = base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(bearerToken))

	var devArg any
	if deviceID != "" {
		devArg = deviceID
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret, revoked_at, expires_at)
		 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`,
		tenantID, devArg, hash[:], storedSecret, revokedAt, expiresAt,
	); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	return tenantID, deviceID, bearerToken
}

func randSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	return secret
}

// TestLookupDeviceByBearer_TenantLevelCredentialReturnsErrDeviceCredentialRequired
// is the core PAT-1417 case: a live, non-revoked, unexpired credential row
// whose device_id is NULL must be reported, server-side, as
// ErrDeviceCredentialRequired rather than the generic ErrUnknownToken.
func TestLookupDeviceByBearer_TenantLevelCredentialReturnsErrDeviceCredentialRequired(t *testing.T) {
	pool := dbPool(t)
	secret := randSecret(t)
	_, _, token := insertCredentialFull(t, pool, secret, false, nil, nil)

	_, _, _, err := auth.LookupDeviceByBearer(context.Background(), pool, "Bearer "+token)
	if err == nil {
		t.Fatal("LookupDeviceByBearer: want error for tenant-level credential, got nil")
	}
	if !errors.Is(err, auth.ErrDeviceCredentialRequired) {
		t.Errorf("want errors.Is(err, ErrDeviceCredentialRequired), got %v", err)
	}
	if errors.Is(err, auth.ErrUnknownToken) {
		t.Errorf("tenant-level credential must NOT also satisfy errors.Is(err, ErrUnknownToken), got %v", err)
	}
}

// TestLookupDeviceByBearer_UnknownTokenStillErrUnknownToken confirms a token
// that matches no row at all is unaffected by the PAT-1417 change: it still
// returns ErrUnknownToken, not the new sentinel.
func TestLookupDeviceByBearer_UnknownTokenStillErrUnknownToken(t *testing.T) {
	pool := dbPool(t)

	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("rand token: %v", err)
	}
	neverInserted := "Bearer " + base64.RawURLEncoding.EncodeToString(raw)

	_, _, _, err := auth.LookupDeviceByBearer(context.Background(), pool, neverInserted)
	if err == nil {
		t.Fatal("LookupDeviceByBearer: want error for unknown token, got nil")
	}
	if !errors.Is(err, auth.ErrUnknownToken) {
		t.Errorf("want errors.Is(err, ErrUnknownToken), got %v", err)
	}
	if errors.Is(err, auth.ErrDeviceCredentialRequired) {
		t.Errorf("unknown token must NOT satisfy errors.Is(err, ErrDeviceCredentialRequired), got %v", err)
	}
}

// TestLookupDeviceByBearer_RevokedDeviceCredentialStillErrUnknownToken pins
// down that a revoked device-scoped credential is NOT reported as "just needs
// a device scope" — it must still be the uniform ErrUnknownToken, exactly as
// before PAT-1417. A revoked credential does not "need" anything; it is dead.
func TestLookupDeviceByBearer_RevokedDeviceCredentialStillErrUnknownToken(t *testing.T) {
	pool := dbPool(t)
	secret := randSecret(t)
	revokedAt := time.Now().Add(-time.Hour)
	_, _, token := insertCredentialFull(t, pool, secret, true, &revokedAt, nil)

	_, _, _, err := auth.LookupDeviceByBearer(context.Background(), pool, "Bearer "+token)
	if err == nil {
		t.Fatal("LookupDeviceByBearer: want error for revoked credential, got nil")
	}
	if !errors.Is(err, auth.ErrUnknownToken) {
		t.Errorf("want errors.Is(err, ErrUnknownToken), got %v", err)
	}
	if errors.Is(err, auth.ErrDeviceCredentialRequired) {
		t.Errorf("revoked device credential must NOT satisfy errors.Is(err, ErrDeviceCredentialRequired), got %v", err)
	}
}

// TestLookupDeviceByBearer_ExpiredDeviceCredentialStillErrUnknownToken is the
// expired-credential counterpart to the revoked test above.
func TestLookupDeviceByBearer_ExpiredDeviceCredentialStillErrUnknownToken(t *testing.T) {
	pool := dbPool(t)
	secret := randSecret(t)
	expiresAt := time.Now().Add(-time.Hour)
	_, _, token := insertCredentialFull(t, pool, secret, true, nil, &expiresAt)

	_, _, _, err := auth.LookupDeviceByBearer(context.Background(), pool, "Bearer "+token)
	if err == nil {
		t.Fatal("LookupDeviceByBearer: want error for expired credential, got nil")
	}
	if !errors.Is(err, auth.ErrUnknownToken) {
		t.Errorf("want errors.Is(err, ErrUnknownToken), got %v", err)
	}
	if errors.Is(err, auth.ErrDeviceCredentialRequired) {
		t.Errorf("expired device credential must NOT satisfy errors.Is(err, ErrDeviceCredentialRequired), got %v", err)
	}
}

// TestLookupDeviceByBearer_ValidDeviceCredentialSucceeds confirms the
// happy path is unchanged by the query rewrite: a live device-scoped
// credential still resolves to the same tenantID/deviceID/secret as before.
func TestLookupDeviceByBearer_ValidDeviceCredentialSucceeds(t *testing.T) {
	pool := dbPool(t)
	secret := randSecret(t)
	wantTenantID, wantDeviceID, token := insertCredentialFull(t, pool, secret, true, nil, nil)

	gotTenantID, gotDeviceID, gotSecret, err := auth.LookupDeviceByBearer(context.Background(), pool, "Bearer "+token)
	if err != nil {
		t.Fatalf("LookupDeviceByBearer: %v", err)
	}
	if gotTenantID != wantTenantID {
		t.Errorf("tenantID: got %q want %q", gotTenantID, wantTenantID)
	}
	if gotDeviceID != wantDeviceID {
		t.Errorf("deviceID: got %q want %q", gotDeviceID, wantDeviceID)
	}
	if string(gotSecret) != string(secret) {
		t.Errorf("secret mismatch: got %x want %x", gotSecret, secret)
	}
}
