package platformroot

import (
	"os"
	"testing"
	"time"
)

func TestParseAppleCSV(t *testing.T) {
	data, err := os.ReadFile("testdata/apple_roots.csv")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fetchedAt := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	certs, err := ParseAppleCSV(data, "https://example.test/apple.csv", fetchedAt)
	if err != nil {
		t.Fatalf("ParseAppleCSV: %v", err)
	}

	// Fixture has one "Included" row with a valid PEM, one "Not Included"
	// row (must be excluded), and one "Included" row with a broken PEM
	// (must be skipped, not fatal to the whole parse).
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1; certs=%+v", len(certs), certs)
	}

	c := certs[0]
	if c.Platform != PlatformMacOS {
		t.Errorf("platform = %q, want %q", c.Platform, PlatformMacOS)
	}
	if c.Source != SourceAppleCCADBTLSServer {
		t.Errorf("source = %q, want %q", c.Source, SourceAppleCCADBTLSServer)
	}
	if c.SubjectCN != "Test Apple Root CA A" {
		t.Errorf("subject_cn = %q, want %q", c.SubjectCN, "Test Apple Root CA A")
	}
	// SHA-1 computed from the PEM, cross-checked against `openssl x509
	// -noout -fingerprint -sha1` on the same fixture certificate.
	want := "e8d402446a82c8363d9008e9b25b132de5e6f9c1"
	if c.ThumbprintSHA1 != want {
		t.Errorf("thumbprint_sha1 = %q, want %q", c.ThumbprintSHA1, want)
	}
	if !c.FetchedAt.Equal(fetchedAt) {
		t.Errorf("fetchedAt = %v, want %v", c.FetchedAt, fetchedAt)
	}
}

func TestParseAppleCSV_MissingColumn(t *testing.T) {
	_, err := ParseAppleCSV([]byte("A,B,C\n1,2,3\n"), "u", time.Now())
	if err == nil {
		t.Fatal("expected error for missing required columns, got nil")
	}
}
