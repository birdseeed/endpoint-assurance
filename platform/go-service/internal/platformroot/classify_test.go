package platformroot

import "testing"

func TestSuspiciousSubjectRegex(t *testing.T) {
	if got := SuspiciousSubjectRegex(PlatformWindows); got != "Microsoft|Windows" {
		t.Errorf("windows regex = %q, want %q", got, "Microsoft|Windows")
	}
	if got := SuspiciousSubjectRegex(PlatformMacOS); got != "Apple" {
		t.Errorf("macos regex = %q, want %q", got, "Apple")
	}
	if got := SuspiciousSubjectRegex("linux"); got != "" {
		t.Errorf("unknown platform regex = %q, want empty", got)
	}
}

func TestSuspiciousSubjectRegexOrNoMatch(t *testing.T) {
	if got := SuspiciousSubjectRegexOrNoMatch(PlatformWindows); got != "Microsoft|Windows" {
		t.Errorf("windows regex = %q, want %q", got, "Microsoft|Windows")
	}
	if got := SuspiciousSubjectRegexOrNoMatch(PlatformMacOS); got != "Apple" {
		t.Errorf("macos regex = %q, want %q", got, "Apple")
	}
	// The whole point: an unknown platform must never produce "", which as a
	// Postgres ~* pattern matches every string.
	if got := SuspiciousSubjectRegexOrNoMatch("linux"); got == "" {
		t.Errorf("unknown platform regex = %q, must never be empty", got)
	}
}

func TestMatchesSuspiciousSubject(t *testing.T) {
	cases := []struct {
		platform string
		subject  string
		want     bool
	}{
		{PlatformWindows, "CN=Microsoft Root Certificate Authority", true},
		{PlatformWindows, "CN=WINDOWS Update Root", true},
		{PlatformWindows, "CN=DigiCert Global Root", false},
		{PlatformMacOS, "CN=Apple Root CA", true},
		{PlatformMacOS, "CN=DigiCert Global Root", false},
		{"linux", "CN=Microsoft Root Certificate Authority", false},
	}
	for _, c := range cases {
		if got := MatchesSuspiciousSubject(c.platform, c.subject); got != c.want {
			t.Errorf("MatchesSuspiciousSubject(%q, %q) = %v, want %v", c.platform, c.subject, got, c.want)
		}
	}
}
