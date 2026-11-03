package rulepack

import (
	"fmt"
	"strings"
)

var validComparators = map[string]bool{
	"eq": true, "neq": true, "in": true,
	"contains": true, "gte": true, "lte": true,
}

var validSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

var validTiers = map[string]bool{
	"T1": true, "T2": true, "T3": true,
}

// validTreatUnknown is the shared value domain for both treat_unknown_as and
// treat_not_configured_as (PAT-1767) — same CHECK constraint domain in the DB.
var validTreatUnknown = map[string]bool{
	"pass": true, "fail": true, "not_applicable": true,
}

var validPlatforms = map[string]bool{
	"macos": true, "windows": true,
}

// Validate checks a parsed Pack for required fields, enum correctness, and
// intra-pack duplicate rule_keys. Returns one string per error; empty slice
// means the pack is valid.
func Validate(p *Pack) []string {
	var errs []string

	if p.Benchmark == "" {
		errs = append(errs, "pack: benchmark is required")
	}
	if p.BenchmarkVersion == "" {
		errs = append(errs, "pack: benchmark_version is required")
	}
	if p.Platform == "" {
		errs = append(errs, "pack: platform is required")
	} else if !validPlatforms[p.Platform] {
		errs = append(errs, fmt.Sprintf("pack: platform %q is not valid (must be macos or windows)", p.Platform))
	}
	if len(p.Rules) == 0 {
		errs = append(errs, "pack: rules list is empty or missing")
	}

	seen := map[string]int{}
	for i, r := range p.Rules {
		pfx := rulePrefix(i, r.RuleKey)

		if r.RuleKey == "" {
			errs = append(errs, fmt.Sprintf("%s: rule_key is required", pfx))
		} else {
			if j, dup := seen[r.RuleKey]; dup {
				errs = append(errs, fmt.Sprintf("rule[%d] and rule[%d]: duplicate rule_key %q", j, i, r.RuleKey))
			}
			seen[r.RuleKey] = i
		}

		if r.Title == "" {
			errs = append(errs, fmt.Sprintf("%s: title is required", pfx))
		}
		if r.ControlIdentifier != nil && strings.TrimSpace(*r.ControlIdentifier) == "" {
			errs = append(errs, fmt.Sprintf("%s: control_identifier must be non-blank when set", pfx))
		}
		if r.SignalKey == "" {
			errs = append(errs, fmt.Sprintf("%s: signal_key is required", pfx))
		}
		if r.Severity == "" {
			errs = append(errs, fmt.Sprintf("%s: severity is required", pfx))
		} else if !validSeverities[r.Severity] {
			errs = append(errs, fmt.Sprintf("%s: severity %q is not valid (low|medium|high|critical)", pfx, r.Severity))
		}
		if r.Comparator == "" {
			errs = append(errs, fmt.Sprintf("%s: comparator is required", pfx))
		} else if !validComparators[r.Comparator] {
			errs = append(errs, fmt.Sprintf("%s: comparator %q is not valid (eq|neq|in|contains|gte|lte)", pfx, r.Comparator))
		}
		if len(r.ExpectedValues) == 0 {
			errs = append(errs, fmt.Sprintf("%s: expected_values must be a non-empty list", pfx))
		}
		if r.CollectionTier != "" && !validTiers[r.CollectionTier] {
			errs = append(errs, fmt.Sprintf("%s: collection_tier %q is not valid (T1|T2|T3)", pfx, r.CollectionTier))
		}
		if r.TreatUnknownAs != "" && !validTreatUnknown[r.TreatUnknownAs] {
			errs = append(errs, fmt.Sprintf("%s: treat_unknown_as %q is not valid (pass|fail|not_applicable)", pfx, r.TreatUnknownAs))
		}
		if r.TreatNotConfiguredAs != "" && !validTreatUnknown[r.TreatNotConfiguredAs] {
			errs = append(errs, fmt.Sprintf("%s: treat_not_configured_as %q is not valid (pass|fail|not_applicable)", pfx, r.TreatNotConfiguredAs))
		}
	}

	return errs
}

func rulePrefix(i int, key string) string {
	if key == "" {
		return fmt.Sprintf("rule[%d]", i)
	}
	return fmt.Sprintf("rule[%d] (%s)", i, key)
}
