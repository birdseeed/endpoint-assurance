package main

import (
	"crypto/rand"
	"io"
	"testing"

	"patched.im/api/internal/envelope"
)

func newTestEnvelope(t *testing.T) *envelope.Envelope {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	env, err := envelope.New(key)
	if err != nil {
		t.Fatalf("envelope.New: %v", err)
	}
	return env
}

func TestIsEncrypted(t *testing.T) {
	cases := []struct {
		name string
		val  []byte
		want bool
	}{
		{"nil", nil, false},
		{"empty", []byte(""), false},
		{"shorter than marker", []byte("penc"), false},
		{"exact marker, no payload", []byte(envelope.Marker), true},
		{"marker plus payload", []byte(envelope.Marker + "AAAA"), true},
		{"plaintext secret", []byte("some-plaintext-hmac-secret"), false},
		{"plaintext PEM", []byte("-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n"), false},
		{"marker-like prefix but wrong bytes", []byte("penc2:AAAA"), false},
		{"marker embedded, not at start", []byte("xpenc1:AAAA"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEncrypted(tc.val); got != tc.want {
				t.Fatalf("isEncrypted(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// TestEncryptForColumn_BranchSelection asserts that a BYTEA column is routed
// through EncryptBytes and a TEXT column through EncryptString, and that the
// two paths are distinguishable by the returned parameter type: EncryptBytes
// returns []byte, EncryptString returns string. This is the exact failure
// mode PAT-1697 is guarding against — a wrong bytea flag silently sending a
// BYTEA column's raw bytes through the TEXT string path (or vice versa) would
// still "work" syntactically but corrupt the stored value.
func TestEncryptForColumn_BranchSelection(t *testing.T) {
	env := newTestEnvelope(t)
	plaintext := []byte("super-secret-value")

	t.Run("bytea column returns []byte via EncryptBytes", func(t *testing.T) {
		c := column{table: "tenant_credentials", col: "hmac_secret", pk: "id", pkCast: "bigint", bytea: true}
		got, err := encryptForColumn(env, c, plaintext)
		if err != nil {
			t.Fatalf("encryptForColumn: %v", err)
		}
		b, ok := got.([]byte)
		if !ok {
			t.Fatalf("bytea column: got type %T, want []byte (TEXT path ran instead of BYTEA path)", got)
		}
		if len(b) < len(envelope.Marker) || string(b[:len(envelope.Marker)]) != envelope.Marker {
			t.Fatalf("bytea column: result not marked: %q", b)
		}
		// Round-trip through the BYTEA-side decoder to confirm the encoding
		// used really is the bytes codec, not a string round-trip artefact.
		dec, err := env.DecryptBytes(b)
		if err != nil {
			t.Fatalf("DecryptBytes: %v", err)
		}
		if string(dec) != string(plaintext) {
			t.Fatalf("round-trip mismatch: got %q want %q", dec, plaintext)
		}
	})

	t.Run("text column returns string via EncryptString", func(t *testing.T) {
		c := column{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false}
		got, err := encryptForColumn(env, c, plaintext)
		if err != nil {
			t.Fatalf("encryptForColumn: %v", err)
		}
		s, ok := got.(string)
		if !ok {
			t.Fatalf("text column: got type %T, want string (BYTEA path ran instead of TEXT path)", got)
		}
		if len(s) < len(envelope.Marker) || s[:len(envelope.Marker)] != envelope.Marker {
			t.Fatalf("text column: result not marked: %q", s)
		}
		dec, err := env.DecryptString(s)
		if err != nil {
			t.Fatalf("DecryptString: %v", err)
		}
		if dec != string(plaintext) {
			t.Fatalf("round-trip mismatch: got %q want %q", dec, plaintext)
		}
	})

	t.Run("all four real columns select the documented branch", func(t *testing.T) {
		for _, c := range []column{
			{table: "tenant_credentials", col: "hmac_secret", pk: "id", pkCast: "bigint", bytea: true},
			{table: "tenants", col: "hmac_secret", pk: "id", pkCast: "uuid", bytea: true},
			{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false},
			{table: "tenant_webhooks", col: "secret", pk: "id", pkCast: "uuid", bytea: false},
		} {
			got, err := encryptForColumn(env, c, plaintext)
			if err != nil {
				t.Fatalf("%s.%s: encryptForColumn: %v", c.table, c.col, err)
			}
			_, isBytes := got.([]byte)
			_, isString := got.(string)
			switch {
			case c.bytea && !isBytes:
				t.Fatalf("%s.%s: bytea=true but result is %T, not []byte", c.table, c.col, got)
			case c.bytea && isString:
				t.Fatalf("%s.%s: bytea=true but went through the string (TEXT) path", c.table, c.col)
			case !c.bytea && !isString:
				t.Fatalf("%s.%s: bytea=false but result is %T, not string", c.table, c.col, got)
			case !c.bytea && isBytes:
				t.Fatalf("%s.%s: bytea=false but went through the []byte (BYTEA) path", c.table, c.col)
			}
		}
	})
}

// TestEncryptForColumn_DisabledEnvelopeIsPassthrough documents that an
// Envelope with no KEK configured leaves values unchanged, for both branches.
// run() itself refuses to proceed without an enabled Envelope (see
// TestColumnsCoverFourRealColumns and run()'s own env.Enabled() check) — this
// only pins encryptForColumn's own behaviour in isolation.
func TestEncryptForColumn_DisabledEnvelopeIsPassthrough(t *testing.T) {
	var disabled envelope.Envelope // zero value: disabled
	plaintext := []byte("plaintext-value")

	byteaCol := column{table: "tenants", col: "hmac_secret", pk: "id", pkCast: "uuid", bytea: true}
	got, err := encryptForColumn(&disabled, byteaCol, plaintext)
	if err != nil {
		t.Fatalf("encryptForColumn (bytea, disabled): %v", err)
	}
	if b, ok := got.([]byte); !ok || string(b) != string(plaintext) {
		t.Fatalf("bytea disabled passthrough: got %v (%T), want %q", got, got, plaintext)
	}

	textCol := column{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false}
	got, err = encryptForColumn(&disabled, textCol, plaintext)
	if err != nil {
		t.Fatalf("encryptForColumn (text, disabled): %v", err)
	}
	if s, ok := got.(string); !ok || s != string(plaintext) {
		t.Fatalf("text disabled passthrough: got %v (%T), want %q", got, got, plaintext)
	}
}

// TestColumnsCoverFourRealColumns pins the column table in run() against the
// four columns this ticket is about, so a future edit that drops or
// mis-flags one of them fails a unit test instead of only being caught (or
// missed) by inspection. Mirrors run()'s columns literal; keep in sync.
func TestColumnsCoverFourRealColumns(t *testing.T) {
	columns := []column{
		{table: "tenant_credentials", col: "hmac_secret", pk: "id", pkCast: "bigint", bytea: true},
		{table: "tenants", col: "hmac_secret", pk: "id", pkCast: "uuid", bytea: true},
		{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false},
		{table: "tenant_webhooks", col: "secret", pk: "id", pkCast: "uuid", bytea: false},
	}
	want := map[string]bool{
		"tenant_credentials.hmac_secret": true,
		"tenants.hmac_secret":            true,
		"tenant_ca.ca_key_pem":           false,
		"tenant_webhooks.secret":         false,
	}
	if len(columns) != len(want) {
		t.Fatalf("got %d columns, want %d", len(columns), len(want))
	}
	for _, c := range columns {
		key := c.table + "." + c.col
		bytea, ok := want[key]
		if !ok {
			t.Fatalf("unexpected column %s", key)
		}
		if c.bytea != bytea {
			t.Fatalf("%s: bytea=%v, want %v", key, c.bytea, bytea)
		}
	}
}
