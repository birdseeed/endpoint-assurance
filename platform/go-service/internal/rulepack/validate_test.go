package rulepack

import (
	"strings"
	"testing"
)

// validPack returns a minimal well-formed Pack; tests override the fields they care about.
func validPack() *Pack {
	enabled := true
	return &Pack{
		Benchmark:        "CIS Windows Server 2022",
		BenchmarkVersion: "1.0.0",
		Platform:         "windows",
		Rules: []RuleSpec{
			{
				RuleKey:        "cis_win_1_1_password_history",
				Title:          "Ensure password history is 24 or more passwords",
				Severity:       "medium",
				SignalKey:      "pw_history",
				Comparator:     "gte",
				ExpectedValues: []string{"24"},
				CollectionTier: "T1",
				TreatUnknownAs: "fail",
				Enabled:        &enabled,
			},
		},
	}
}

func TestValidate_Valid(t *testing.T) {
	if errs := Validate(validPack()); len(errs) != 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidate_MinimalRequired(t *testing.T) {
	// Only the truly required fields; omit optional ones.
	p := &Pack{
		Benchmark:        "Test Benchmark",
		BenchmarkVersion: "1.0",
		Platform:         "macos",
		Rules: []RuleSpec{
			{
				RuleKey:        "test_rule",
				Title:          "Test Rule",
				Severity:       "low",
				SignalKey:      "some_signal",
				Comparator:     "eq",
				ExpectedValues: []string{"Yes"},
			},
		},
	}
	if errs := Validate(p); len(errs) != 0 {
		t.Errorf("minimal valid pack: unexpected errors: %v", errs)
	}
}

func TestValidate_PackLevelErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Pack)
		wantErr string
	}{
		{
			"missing benchmark",
			func(p *Pack) { p.Benchmark = "" },
			"benchmark is required",
		},
		{
			"missing benchmark_version",
			func(p *Pack) { p.BenchmarkVersion = "" },
			"benchmark_version is required",
		},
		{
			"missing platform",
			func(p *Pack) { p.Platform = "" },
			"platform is required",
		},
		{
			"invalid platform",
			func(p *Pack) { p.Platform = "linux" },
			`platform "linux" is not valid`,
		},
		{
			"empty rules list",
			func(p *Pack) { p.Rules = nil },
			"rules list is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPack()
			tc.mutate(p)
			errs := Validate(p)
			if !anyContains(errs, tc.wantErr) {
				t.Errorf("want error containing %q, got: %v", tc.wantErr, errs)
			}
		})
	}
}

func TestValidate_RuleLevelErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RuleSpec)
		wantErr string
	}{
		{
			"missing rule_key",
			func(r *RuleSpec) { r.RuleKey = "" },
			"rule_key is required",
		},
		{
			"missing title",
			func(r *RuleSpec) { r.Title = "" },
			"title is required",
		},
		{
			"blank control_identifier",
			func(r *RuleSpec) {
				blank := "   "
				r.ControlIdentifier = &blank
			},
			"control_identifier must be non-blank when set",
		},
		{
			"missing signal_key",
			func(r *RuleSpec) { r.SignalKey = "" },
			"signal_key is required",
		},
		{
			"missing severity",
			func(r *RuleSpec) { r.Severity = "" },
			"severity is required",
		},
		{
			"invalid severity",
			func(r *RuleSpec) { r.Severity = "extreme" },
			`severity "extreme" is not valid`,
		},
		{
			"missing comparator",
			func(r *RuleSpec) { r.Comparator = "" },
			"comparator is required",
		},
		{
			"invalid comparator",
			func(r *RuleSpec) { r.Comparator = "regex" },
			`comparator "regex" is not valid`,
		},
		{
			"empty expected_values",
			func(r *RuleSpec) { r.ExpectedValues = nil },
			"expected_values must be a non-empty list",
		},
		{
			"invalid collection_tier",
			func(r *RuleSpec) { r.CollectionTier = "T4" },
			`collection_tier "T4" is not valid`,
		},
		{
			"invalid treat_unknown_as",
			func(r *RuleSpec) { r.TreatUnknownAs = "unknown" },
			`treat_unknown_as "unknown" is not valid`,
		},
		{
			"invalid treat_not_configured_as",
			func(r *RuleSpec) { r.TreatNotConfiguredAs = "unknown" },
			`treat_not_configured_as "unknown" is not valid`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPack()
			tc.mutate(&p.Rules[0])
			errs := Validate(p)
			if !anyContains(errs, tc.wantErr) {
				t.Errorf("want error containing %q, got: %v", tc.wantErr, errs)
			}
		})
	}
}

func TestValidate_DuplicateRuleKeys(t *testing.T) {
	p := validPack()
	dupe := p.Rules[0]
	p.Rules = append(p.Rules, dupe)
	errs := Validate(p)
	if !anyContains(errs, "duplicate rule_key") {
		t.Errorf("expected duplicate_rule_key error, got: %v", errs)
	}
}

func TestValidate_MultipleErrorsReported(t *testing.T) {
	p := &Pack{
		// benchmark and platform missing; one rule with multiple errors
		BenchmarkVersion: "1.0",
		Rules: []RuleSpec{
			{
				RuleKey:  "bad_rule",
				Severity: "mega",
			},
		},
	}
	errs := Validate(p)
	if len(errs) < 4 {
		t.Errorf("expected at least 4 errors, got %d: %v", len(errs), errs)
	}
}

func TestValidate_AllComparatorsAccepted(t *testing.T) {
	for _, c := range []string{"eq", "neq", "in", "contains", "gte", "lte"} {
		p := validPack()
		p.Rules[0].Comparator = c
		if errs := Validate(p); len(errs) != 0 {
			t.Errorf("comparator %q should be valid, got: %v", c, errs)
		}
	}
}

func TestValidate_AllSeveritiesAccepted(t *testing.T) {
	for _, s := range []string{"low", "medium", "high", "critical"} {
		p := validPack()
		p.Rules[0].Severity = s
		if errs := Validate(p); len(errs) != 0 {
			t.Errorf("severity %q should be valid, got: %v", s, errs)
		}
	}
}

func TestValidate_AllTiersAccepted(t *testing.T) {
	for _, tier := range []string{"T1", "T2", "T3"} {
		p := validPack()
		p.Rules[0].CollectionTier = tier
		if errs := Validate(p); len(errs) != 0 {
			t.Errorf("collection_tier %q should be valid, got: %v", tier, errs)
		}
	}
}

func TestValidate_AllTreatUnknownAccepted(t *testing.T) {
	for _, v := range []string{"pass", "fail", "not_applicable"} {
		p := validPack()
		p.Rules[0].TreatUnknownAs = v
		if errs := Validate(p); len(errs) != 0 {
			t.Errorf("treat_unknown_as %q should be valid, got: %v", v, errs)
		}
	}
}

// TestValidate_TreatNotConfiguredAsOptional documents that omitting
// treat_not_configured_as (PAT-1767) is valid — it means "use
// treat_unknown_as" and is not required like the other fields.
func TestValidate_TreatNotConfiguredAsOptional(t *testing.T) {
	p := validPack()
	p.Rules[0].TreatNotConfiguredAs = ""
	if errs := Validate(p); len(errs) != 0 {
		t.Errorf("empty treat_not_configured_as should be valid (falls back to treat_unknown_as), got: %v", errs)
	}
}

func TestValidate_AllTreatNotConfiguredAccepted(t *testing.T) {
	for _, v := range []string{"pass", "fail", "not_applicable"} {
		p := validPack()
		p.Rules[0].TreatNotConfiguredAs = v
		if errs := Validate(p); len(errs) != 0 {
			t.Errorf("treat_not_configured_as %q should be valid, got: %v", v, errs)
		}
	}
}

func TestValidate_BothPlatformsAccepted(t *testing.T) {
	for _, platform := range []string{"macos", "windows"} {
		p := validPack()
		p.Platform = platform
		if errs := Validate(p); len(errs) != 0 {
			t.Errorf("platform %q should be valid, got: %v", platform, errs)
		}
	}
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
