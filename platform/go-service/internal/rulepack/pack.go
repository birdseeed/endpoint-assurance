// Package rulepack provides YAML-driven bulk import of CIS compliance rules
// into the compliance_rules table. It is the backing library for the
// patched-rules CLI (cmd/patched-rules).
//
// Usage flow:
//
//	pack, err := rulepack.LoadPack("cis-windows-l1.yaml")
//	if errs := rulepack.Validate(pack); len(errs) > 0 { … }
//	result, err := rulepack.Import(ctx, pool, pack, false)
package rulepack

import (
	"bytes"
	"fmt"
	"os"

	"go.yaml.in/yaml/v2"
)

// Pack is the top-level structure of a rule-pack YAML file.
// All rules in the file share Benchmark, BenchmarkVersion, and Platform.
type Pack struct {
	Benchmark        string     `yaml:"benchmark"`
	BenchmarkVersion string     `yaml:"benchmark_version"`
	Platform         string     `yaml:"platform"`
	Rules            []RuleSpec `yaml:"rules"`
}

// RuleSpec maps one YAML rule entry to a compliance_rules row.
// Fields mirror the table columns; see go-service/docs/RULE_PACKS.md for
// the full field reference.
type RuleSpec struct {
	RuleKey     string `yaml:"rule_key"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	// ControlIdentifier is the authoritative identifier for this exact pack's
	// benchmark version. Nil means omitted: preserve an existing value on
	// update and store NULL on insert. A present value must be non-blank.
	ControlIdentifier *string  `yaml:"control_identifier"`
	Severity          string   `yaml:"severity"`
	SignalKey         string   `yaml:"signal_key"`
	Comparator        string   `yaml:"comparator"`
	ExpectedValues    []string `yaml:"expected_values"`
	ApplicableArch    []string `yaml:"applicable_arch"`
	TreatUnknownAs    string   `yaml:"treat_unknown_as"`
	// TreatNotConfiguredAs is optional (PAT-1767); omitted/empty means the
	// evaluator falls back to TreatUnknownAs for this rule.
	TreatNotConfiguredAs    string   `yaml:"treat_not_configured_as"`
	NistMappings            []string `yaml:"nist_mappings"`
	IsoMappings             []string `yaml:"iso_mappings"`
	CyberEssentialsMappings []string `yaml:"cyber_essentials_mappings"`
	// Enabled defaults to true when omitted; use false to import a disabled rule.
	Enabled             *bool  `yaml:"enabled"`
	CollectionTier      string `yaml:"collection_tier"`
	PiiObserved         string `yaml:"pii_observed"`
	RequiresUserConsent bool   `yaml:"requires_user_consent"`
}

// LoadPack reads a YAML rule-pack from path and returns the parsed Pack.
// Unknown YAML keys are rejected — a common authoring error caught early.
func LoadPack(path string) (*Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.SetStrict(true)
	var p Pack
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &p, nil
}
