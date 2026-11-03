package platformroot

import (
	"os"
	"testing"
	"time"
)

func TestParseMicrosoftCSV(t *testing.T) {
	data, err := os.ReadFile("testdata/microsoft_roots.csv")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fetchedAt := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	certs, err := ParseMicrosoftCSV(data, "https://example.test/msft.csv", fetchedAt)
	if err != nil {
		t.Fatalf("ParseMicrosoftCSV: %v", err)
	}

	// Fixture has 2 "Included" rows and 1 "Disabled" row — Disabled must be
	// excluded (a disabled root should never classify a device certificate
	// as a legitimate platform root).
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2 (Disabled row must be excluded); certs=%+v", len(certs), certs)
	}

	for _, c := range certs {
		if c.Platform != PlatformWindows {
			t.Errorf("cert %q: platform = %q, want %q", c.SubjectCN, c.Platform, PlatformWindows)
		}
		if c.Source != SourceMicrosoftCCADB {
			t.Errorf("cert %q: source = %q, want %q", c.SubjectCN, c.Source, SourceMicrosoftCCADB)
		}
		if c.SourceURL != "https://example.test/msft.csv" {
			t.Errorf("cert %q: sourceURL = %q", c.SubjectCN, c.SourceURL)
		}
		if !c.FetchedAt.Equal(fetchedAt) {
			t.Errorf("cert %q: fetchedAt = %v, want %v", c.SubjectCN, c.FetchedAt, fetchedAt)
		}
	}

	// SHA-1 must be lowercased — the mixed-case fixture row exercises this.
	found := map[string]string{}
	for _, c := range certs {
		found[c.ThumbprintSHA1] = c.SubjectCN
	}
	wantLower := "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00"
	if _, ok := found[wantLower]; !ok {
		t.Errorf("expected lowercased thumbprint %q present, got %v", wantLower, found)
	}
	wantMixed := "00112233445566778899aabbccddeeff0011223"
	if _, ok := found[wantMixed]; !ok {
		t.Errorf("expected thumbprint %q present, got %v", wantMixed, found)
	}
	if name := found[wantLower]; name != "Contoso Root CA" {
		t.Errorf("subject_cn for %q = %q, want Contoso Root CA", wantLower, name)
	}
}

func TestParseMicrosoftCSV_MissingColumn(t *testing.T) {
	_, err := ParseMicrosoftCSV([]byte("A,B,C\n1,2,3\n"), "u", time.Now())
	if err == nil {
		t.Fatal("expected error for missing required columns, got nil")
	}
}
