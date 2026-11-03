package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHashDownloadToken(t *testing.T) {
	const tok = "3f1a2b4c-5d6e-7f80-9a1b-2c3d4e5f6071"

	got := hashDownloadToken(tok)
	if len(got) != sha256.Size {
		t.Fatalf("hash length = %d, want %d", len(got), sha256.Size)
	}

	// Deterministic.
	if hex.EncodeToString(hashDownloadToken(tok)) != hex.EncodeToString(got) {
		t.Fatal("hashDownloadToken is not deterministic")
	}

	// Canonicalisation: surrounding whitespace and case must not change the hash,
	// so a link generated in either form redeems the same row.
	for _, variant := range []string{"  " + tok + "  ", "3F1A2B4C-5D6E-7F80-9A1B-2C3D4E5F6071"} {
		if hex.EncodeToString(hashDownloadToken(variant)) != hex.EncodeToString(got) {
			t.Fatalf("hash mismatch for canonical variant %q", variant)
		}
	}

	// Different tokens hash differently.
	other := hashDownloadToken("00000000-0000-0000-0000-000000000000")
	if hex.EncodeToString(other) == hex.EncodeToString(got) {
		t.Fatal("distinct tokens produced identical hashes")
	}
}
