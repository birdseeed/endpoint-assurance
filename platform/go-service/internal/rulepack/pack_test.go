package rulepack

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPack_TreatNotConfiguredAsRoundTrip (PAT-1767): a rule pack YAML file
// that sets treat_not_configured_as parses into RuleSpec.TreatNotConfiguredAs
// unchanged, and a rule that omits it round-trips as the empty string (which
// Validate treats as "use treat_unknown_as", not an error — see
// TestValidate_TreatNotConfiguredAsOptional).
func TestLoadPack_TreatNotConfiguredAsRoundTrip(t *testing.T) {
	yaml := `
benchmark: "NIST SP 800-53 Rev 5"
benchmark_version: "Rev 5 (2020)"
platform: windows
rules:
  - rule_key: nist_win_sc13_tls10_client_disabled
    title: "TLS 1.0 disabled for Schannel client"
    severity: high
    signal_key: tls10_client_disabled
    comparator: eq
    expected_values: ["Yes"]
    treat_unknown_as: fail
    treat_not_configured_as: pass
    control_identifier: "SC-13"
  - rule_key: cis_win_1_1_password_history
    title: "Password history"
    severity: medium
    signal_key: pw_history
    comparator: gte
    expected_values: ["24"]
    treat_unknown_as: fail
`
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	p, err := LoadPack(path)
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(p.Rules))
	}
	if got := p.Rules[0].TreatNotConfiguredAs; got != "pass" {
		t.Errorf("rule[0].TreatNotConfiguredAs = %q, want %q", got, "pass")
	}
	if got := p.Rules[0].ControlIdentifier; got == nil || *got != "SC-13" {
		t.Errorf("rule[0].ControlIdentifier = %v, want %q", got, "SC-13")
	}
	if got := p.Rules[1].ControlIdentifier; got != nil {
		t.Errorf("rule[1].ControlIdentifier (omitted) = %q, want nil", *got)
	}
	if got := p.Rules[1].TreatNotConfiguredAs; got != "" {
		t.Errorf("rule[1].TreatNotConfiguredAs (omitted) = %q, want empty", got)
	}

	if errs := Validate(p); len(errs) != 0 {
		t.Errorf("expected pack to validate cleanly, got: %v", errs)
	}
}
