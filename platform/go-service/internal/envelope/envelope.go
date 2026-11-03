// Package envelope provides AES-256-GCM envelope encryption for secret columns
// stored at rest in Postgres (tenant CA private keys, HMAC secrets, webhook
// secrets — PAT-687).
//
// Envelope scheme: a fresh 256-bit data-encryption key (DEK) is generated for
// every value and used to AES-GCM-encrypt the plaintext. The DEK is then itself
// AES-GCM-encrypted ("wrapped") with a long-lived key-encryption key (KEK) read
// from the PATCHED_KEK environment variable. Only the wrapped DEK and the
// ciphertext are persisted; the plaintext DEK never touches disk. To rotate the
// KEK you re-wrap DEKs, not re-encrypt data.
//
// Stored form is a marked, base64 string:
//
//	penc1:<base64( kekNonce || wrappedDEK || dataNonce || dataCiphertext )>
//
// The "penc1:" marker lets the read path distinguish an encrypted value from a
// legacy plaintext one: DecryptString returns unmarked input verbatim, giving a
// decrypt-with-plaintext-fallback read path so existing rows keep working. The
// marker contains ':' which is not a base64 character, so it can never collide
// with a legacy base64/hex secret, and PEM material starts with "-----BEGIN".
//
// When PATCHED_KEK is unset the Envelope is disabled: EncryptString returns the
// plaintext unchanged. This is deliberate — nothing breaks before a KEK is
// provisioned. A KEK that is set but malformed is a hard error (fail closed).
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
)

// Marker prefixes every envelope-encrypted value.
const Marker = "penc1:"

// EnvVar is the environment variable holding the base64-encoded 32-byte KEK.
const EnvVar = "PATCHED_KEK"

const (
	kekSize = 32 // AES-256 key-encryption key
	dekSize = 32 // AES-256 data-encryption key
)

// Envelope encrypts/decrypts secret values. A nil kek means the Envelope is
// disabled (plaintext passthrough on write). The zero value is a valid,
// disabled Envelope.
type Envelope struct {
	kek cipher.AEAD
}

// FromEnv builds an Envelope from PATCHED_KEK (base64-encoded 32-byte key).
// An empty/unset variable yields a disabled Envelope (plaintext writes). A set
// but malformed key returns an error so callers can fail closed at startup
// rather than silently writing plaintext when encryption was intended.
func FromEnv() (*Envelope, error) {
	raw := strings.TrimSpace(os.Getenv(EnvVar))
	if raw == "" {
		return &Envelope{}, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid base64: %w", EnvVar, err)
	}
	if len(key) != kekSize {
		return nil, fmt.Errorf("%s: expected %d-byte key, got %d bytes", EnvVar, kekSize, len(key))
	}
	return New(key)
}

// New builds an Envelope from a raw 32-byte KEK. Intended for tests and callers
// that source the KEK themselves.
func New(key []byte) (*Envelope, error) {
	if len(key) != kekSize {
		return nil, fmt.Errorf("envelope: KEK must be %d bytes, got %d", kekSize, len(key))
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &Envelope{kek: aead}, nil
}

// Enabled reports whether a KEK is configured (i.e. writes will be encrypted).
func (e *Envelope) Enabled() bool { return e != nil && e.kek != nil }

// EncryptString encrypts plaintext and returns the marked, base64 stored form.
// When no KEK is configured it returns plaintext unchanged (plaintext-write
// fallback) so callers work identically before a KEK is provisioned.
func (e *Envelope) EncryptString(plaintext string) (string, error) {
	if !e.Enabled() {
		return plaintext, nil
	}

	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", fmt.Errorf("envelope: generate DEK: %w", err)
	}
	dataAEAD, err := newGCM(dek)
	if err != nil {
		return "", err
	}

	kekNonce := make([]byte, e.kek.NonceSize())
	if _, err := io.ReadFull(rand.Reader, kekNonce); err != nil {
		return "", fmt.Errorf("envelope: kek nonce: %w", err)
	}
	wrapped := e.kek.Seal(nil, kekNonce, dek, nil)

	dataNonce := make([]byte, dataAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return "", fmt.Errorf("envelope: data nonce: %w", err)
	}
	ciphertext := dataAEAD.Seal(nil, dataNonce, []byte(plaintext), nil)

	blob := make([]byte, 0, len(kekNonce)+len(wrapped)+len(dataNonce)+len(ciphertext))
	blob = append(blob, kekNonce...)
	blob = append(blob, wrapped...)
	blob = append(blob, dataNonce...)
	blob = append(blob, ciphertext...)

	return Marker + base64.StdEncoding.EncodeToString(blob), nil
}

// DecryptString reverses EncryptString. A value that does not carry the Marker
// is assumed to be legacy plaintext and returned verbatim (decrypt-with-
// plaintext-fallback). A marked value requires a configured KEK; if none is set
// this returns an error rather than leaking ciphertext.
func (e *Envelope) DecryptString(stored string) (string, error) {
	if !strings.HasPrefix(stored, Marker) {
		return stored, nil // legacy plaintext
	}
	if !e.Enabled() {
		return "", errors.New("envelope: value is encrypted but " + EnvVar + " is not configured")
	}

	blob, err := base64.StdEncoding.DecodeString(stored[len(Marker):])
	if err != nil {
		return "", fmt.Errorf("envelope: base64 decode: %w", err)
	}

	kekNonceLen := e.kek.NonceSize()
	wrappedLen := dekSize + e.kek.Overhead()
	// dataNonce is a standard GCM nonce (12 bytes); validated below via newGCM.
	if len(blob) < kekNonceLen+wrappedLen {
		return "", errors.New("envelope: ciphertext too short")
	}

	kekNonce := blob[:kekNonceLen]
	wrapped := blob[kekNonceLen : kekNonceLen+wrappedLen]
	rest := blob[kekNonceLen+wrappedLen:]

	dek, err := e.kek.Open(nil, kekNonce, wrapped, nil)
	if err != nil {
		return "", fmt.Errorf("envelope: unwrap DEK: %w", err)
	}
	dataAEAD, err := newGCM(dek)
	if err != nil {
		return "", err
	}

	dataNonceLen := dataAEAD.NonceSize()
	if len(rest) < dataNonceLen {
		return "", errors.New("envelope: ciphertext too short (data nonce)")
	}
	dataNonce := rest[:dataNonceLen]
	ciphertext := rest[dataNonceLen:]

	plaintext, err := dataAEAD.Open(nil, dataNonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("envelope: decrypt: %w", err)
	}
	return string(plaintext), nil
}

// EncryptBytes is the []byte counterpart of EncryptString, for BYTEA columns
// (e.g. hmac_secret) whose plaintext is raw bytes rather than text. The stored
// form is the ASCII bytes of the marked base64 string. Disabled Envelope
// returns the input unchanged.
func (e *Envelope) EncryptBytes(plaintext []byte) ([]byte, error) {
	s, err := e.EncryptString(string(plaintext))
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// DecryptBytes reverses EncryptBytes with the same plaintext fallback: a value
// not carrying the Marker is returned verbatim (legacy raw bytes).
func (e *Envelope) DecryptBytes(stored []byte) ([]byte, error) {
	if !bytesHasPrefix(stored, Marker) {
		return stored, nil
	}
	s, err := e.DecryptString(string(stored))
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func bytesHasPrefix(b []byte, prefix string) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: gcm: %w", err)
	}
	return aead, nil
}

// ─── Process-wide default ─────────────────────────────────────────────────────
//
// Handlers reach the configured Envelope via Default() rather than threading it
// through every constructor. Init() is called once at startup; if it is never
// called (e.g. in tests) Default() returns a disabled Envelope.

var defaultEnv atomic.Pointer[Envelope]

// Init loads the process-wide Envelope from the environment and stores it for
// Default(). Call once at startup. Returns an error for a malformed KEK so the
// caller can fail closed.
func Init() (*Envelope, error) {
	e, err := FromEnv()
	if err != nil {
		return nil, err
	}
	defaultEnv.Store(e)
	return e, nil
}

// Default returns the Envelope stored by Init, or a disabled Envelope if Init
// has not run. Never nil.
func Default() *Envelope {
	if e := defaultEnv.Load(); e != nil {
		return e
	}
	return &Envelope{}
}
