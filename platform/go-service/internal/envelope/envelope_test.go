package envelope

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func newTestEnvelope(t *testing.T) *Envelope {
	t.Helper()
	key := make([]byte, kekSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	e, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	for _, pt := range []string{
		"",
		"hello",
		"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n",
		strings.Repeat("a1b2c3d4", 64),
	} {
		enc, err := e.EncryptString(pt)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if pt != "" && enc == pt {
			t.Fatal("ciphertext equals plaintext")
		}
		if pt != "" && !strings.HasPrefix(enc, Marker) {
			t.Fatalf("missing marker: %q", enc)
		}
		got, err := e.DecryptString(enc)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != pt {
			t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestNonDeterministic(t *testing.T) {
	e := newTestEnvelope(t)
	a, _ := e.EncryptString("same")
	b, _ := e.EncryptString("same")
	if a == b {
		t.Fatal("two encryptions of the same plaintext are identical (nonce reuse?)")
	}
}

func TestDisabledIsPassthrough(t *testing.T) {
	var e Envelope // disabled zero value
	if e.Enabled() {
		t.Fatal("zero-value Envelope should be disabled")
	}
	enc, err := e.EncryptString("plaintext-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc != "plaintext-secret" {
		t.Fatalf("disabled encrypt should passthrough, got %q", enc)
	}
}

func TestPlaintextFallbackOnDecrypt(t *testing.T) {
	e := newTestEnvelope(t)
	// A legacy plaintext (unmarked) value must be returned verbatim.
	got, err := e.DecryptString("legacy-plaintext-secret")
	if err != nil {
		t.Fatalf("decrypt legacy: %v", err)
	}
	if got != "legacy-plaintext-secret" {
		t.Fatalf("legacy passthrough failed: %q", got)
	}
}

func TestMarkedButNoKEKIsError(t *testing.T) {
	e := newTestEnvelope(t)
	enc, _ := e.EncryptString("secret")

	var disabled Envelope
	if _, err := disabled.DecryptString(enc); err == nil {
		t.Fatal("decrypting a marked value without a KEK should error, not leak")
	}
}

func TestTamperDetection(t *testing.T) {
	e := newTestEnvelope(t)
	enc, _ := e.EncryptString("secret")
	blob, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, Marker))
	blob[len(blob)-1] ^= 0xFF // flip a ciphertext bit
	tampered := Marker + base64.StdEncoding.EncodeToString(blob)
	if _, err := e.DecryptString(tampered); err == nil {
		t.Fatal("GCM should reject a tampered ciphertext")
	}
}

func TestWrongKEKFails(t *testing.T) {
	a := newTestEnvelope(t)
	b := newTestEnvelope(t)
	enc, _ := a.EncryptString("secret")
	if _, err := b.DecryptString(enc); err == nil {
		t.Fatal("decrypting with the wrong KEK should fail")
	}
}
