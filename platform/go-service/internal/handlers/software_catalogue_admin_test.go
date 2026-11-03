package handlers

import "testing"

// The evidence bar, case by case. No database: catalogueVerdict is the single
// statement of the bar that both the candidate list and the review route use.
func TestCatalogueVerdict(t *testing.T) {
	const team, publisher = "ABCDE12345", "synthetic publisher"
	for _, tc := range []struct {
		name, platform, companion string
		e                         catalogueEvidence
		want                      string // "" = promotable
	}{
		{"mac signed", "macos", team, catalogueEvidence{States: map[string]int{"signed": 1}}, ""},
		{"mac signed beside missing evidence", "macos", team, catalogueEvidence{States: map[string]int{"signed": 1, "not_reported": 4, "error": 2}}, ""},
		{"mac nothing signed", "macos", team, catalogueEvidence{States: map[string]int{"not_reported": 3, "error": 1}}, catalogueBlockedNoSigned},
		{"mac adhoc elsewhere", "macos", team, catalogueEvidence{States: map[string]int{"signed": 9, "adhoc": 1}}, catalogueBlockedBadSignature},
		{"mac unsigned elsewhere", "macos", team, catalogueEvidence{States: map[string]int{"signed": 9, "unsigned": 1}}, catalogueBlockedBadSignature},
		{"mac untrusted elsewhere", "macos", team, catalogueEvidence{States: map[string]int{"signed": 9, "untrusted": 1}}, catalogueBlockedBadSignature},
		{"mac invalid elsewhere", "macos", team, catalogueEvidence{States: map[string]int{"signed": 9, "invalid": 1}}, catalogueBlockedBadSignature},
		{"mac short team", "macos", "SHORT1", catalogueEvidence{States: map[string]int{"signed": 1}}, catalogueBlockedTeamID},
		{"mac lower-case team", "macos", "abcde12345", catalogueEvidence{States: map[string]int{"signed": 1}}, catalogueBlockedTeamID},
		{"mac team with newline", "macos", team + "\n", catalogueEvidence{States: map[string]int{"signed": 1}}, catalogueBlockedTeamID},
		{"mac windows verdict is not mac evidence", "macos", team, catalogueEvidence{States: map[string]int{"valid": 1}, TrustedValid: 1}, catalogueBlockedNoSigned},
		{"win valid microsoft", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 1}, RootKinds: []string{"microsoft"}, TrustedValid: 1}, ""},
		{"win valid public beside unknown", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 1, "unknown": 3, "not_reported": 2}, RootKinds: []string{"public"}, TrustedValid: 1}, ""},
		{"win enterprise and public", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 2}, RootKinds: []string{"enterprise", "public"}, TrustedValid: 1}, ""},
		{"win enterprise only", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 2}, RootKinds: []string{"enterprise"}}, catalogueBlockedEnterpriseRoot},
		{"win valid with no root reported", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 2}}, catalogueBlockedNoAuthenticode},
		{"win registry publisher only", "windows", publisher, catalogueEvidence{States: map[string]int{"not_reported": 5}}, catalogueBlockedNoAuthenticode},
		{"win unknown only", "windows", publisher, catalogueEvidence{States: map[string]int{"unknown": 5}}, catalogueBlockedNoAuthenticode},
		{"win invalid elsewhere", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 9, "invalid": 1}, RootKinds: []string{"microsoft"}, TrustedValid: 9}, catalogueBlockedBadSignature},
		{"win unsigned elsewhere", "windows", publisher, catalogueEvidence{States: map[string]int{"valid": 9, "unsigned": 1}, RootKinds: []string{"microsoft"}, TrustedValid: 9}, catalogueBlockedBadSignature},
		{"win blank publisher", "windows", "  ", catalogueEvidence{States: map[string]int{"valid": 1}, RootKinds: []string{"microsoft"}, TrustedValid: 1}, catalogueBlockedNoPublisher},
		{"win mac verdict is not windows evidence", "windows", publisher, catalogueEvidence{States: map[string]int{"signed": 1}}, catalogueBlockedNoAuthenticode},
		{"unknown platform", "linux", publisher, catalogueEvidence{States: map[string]int{"signed": 1, "valid": 1}, TrustedValid: 1}, catalogueBlockedNoSigned},
	} {
		ok, blocked := catalogueVerdict(tc.platform, tc.companion, tc.e)
		if ok != (tc.want == "") || blocked != tc.want {
			t.Errorf("%s: promotable=%v blocked=%q, want blocked=%q", tc.name, ok, blocked, tc.want)
		}
		if blocked != "" && catalogueBlockedMessages[blocked] == "" {
			t.Errorf("%s: refusal %q has no message", tc.name, blocked)
		}
	}
}
