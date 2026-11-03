package auth_test

// PAT-687: tests for the envelope decrypt-with-plaintext-fallback that
// LookupTenantByBearer / LookupDeviceByBearer apply to hmac_secret on the
// bearer-auth hot path. These exercise the exact call the auth path makes —
// envelope.Default().DecryptBytes — through the process-wide Init/Default
// wiring, without needing a database. A DB-backed end-to-end auth test lives in
// bearer_db_test.go (skipped unless TEST_DATABASE_URL is set).

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"patched.im/api/internal/envelope"
)

// withKEK sets a fresh 32-byte KEK into the process-wide Default() envelope for
// the duration of the test, restoring the previous (disabled) state after.
func withKEK(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	t.Setenv(envelope.EnvVar, base64.StdEncoding.EncodeToString(key))
	if _, err := envelope.Init(); err != nil {
		t.Fatalf("envelope.Init: %v", err)
	}
	if !envelope.Default().Enabled() {
		t.Fatal("expected envelope enabled after Init with KEK set")
	}
	t.Cleanup(func() {
		// Restore a disabled default so other tests are unaffected.
		t.Setenv(envelope.EnvVar, "")
		_, _ = envelope.Init()
	})
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	return s
}

// TestBearerDecrypt_RoundTrip models the write side (EncryptBytes at the INSERT
// sites) then the read side (DecryptBytes in bearer.go): the auth path recovers
// the exact original 32-byte secret.
func TestBearerDecrypt_RoundTrip(t *testing.T) {
	withKEK(t)
	secret := randomSecret(t)

	stored, err := envelope.Default().EncryptBytes(secret)
	if err != nil {
		t.Fatalf("EncryptBytes: %v", err)
	}
	if bytes.Equal(stored, secret) {
		t.Fatal("stored value equals plaintext — not encrypted")
	}
	if !bytes.HasPrefix(stored, []byte(envelope.Marker)) {
		t.Fatalf("stored value missing marker: %q", stored)
	}

	got, err := envelope.Default().DecryptBytes(stored)
	if err != nil {
		t.Fatalf("DecryptBytes: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, secret)
	}
}

// TestBearerDecrypt_PlaintextFallback is the load-bearing safety property: a
// legacy PLAINTEXT (unmarked) 32-byte secret decrypts to itself verbatim, with
// no error, so existing credentials keep authenticating after the KEK-aware
// binary is deployed but before the backfill runs.
func TestBearerDecrypt_PlaintextFallback(t *testing.T) {
	withKEK(t) // KEK configured, yet unmarked input must still pass through.

	for i := 0; i < 256; i++ {
		secret := randomSecret(t)
		if bytes.HasPrefix(secret, []byte(envelope.Marker)) {
			continue // astronomically unlikely; a real marked value is not "plaintext"
		}
		got, err := envelope.Default().DecryptBytes(secret)
		if err != nil {
			t.Fatalf("plaintext fallback errored: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("plaintext fallback mutated secret: got %x want %x", got, secret)
		}
	}
}

// TestBearerDecrypt_KEKUnsetPassthrough verifies that with no KEK configured the
// whole path is plaintext passthrough and still round-trips (the state before a
// KEK is provisioned).
func TestBearerDecrypt_KEKUnsetPassthrough(t *testing.T) {
	t.Setenv(envelope.EnvVar, "")
	if _, err := envelope.Init(); err != nil {
		t.Fatalf("envelope.Init: %v", err)
	}
	if envelope.Default().Enabled() {
		t.Fatal("expected disabled envelope with KEK unset")
	}

	secret := randomSecret(t)
	stored, err := envelope.Default().EncryptBytes(secret)
	if err != nil {
		t.Fatalf("EncryptBytes: %v", err)
	}
	if !bytes.Equal(stored, secret) {
		t.Fatal("disabled envelope should store plaintext unchanged")
	}
	got, err := envelope.Default().DecryptBytes(stored)
	if err != nil {
		t.Fatalf("DecryptBytes: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("passthrough round-trip mismatch: got %x want %x", got, secret)
	}
}
