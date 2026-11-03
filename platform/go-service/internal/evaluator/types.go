// Package evaluator applies the CIS L1 (and patched.im baseline) rule pack to
// the compliance signals extracted from a single device snapshot. It reads
// rules from the compliance_rules table and emits one Evaluation per rule
// applicable to the device's architecture. The extractor inserts the
// evaluations into compliance_evaluations as part of the same per-row
// transaction that writes the device, apps, and signals — so a device is
// never in a state where its data is half-written.
//
// Rules are data, not Go code: comparator + signal_key + expected_values are
// enough to evaluate every control in the v1 macOS L1 pack. New benchmark
// versions, per-tenant exemptions, or additional frameworks are SQL changes,
// not redeploys. This file defines the data types the engine reads and writes;
// evaluator.go contains the comparison logic.
package evaluator

// Status values written to compliance_evaluations.status. Mirrors the SQL
// CHECK constraint in migration 0003.
const (
	StatusPass          = "pass"
	StatusFail          = "fail"
	StatusNotApplicable = "not_applicable"
	StatusError         = "error"
)

// Comparator values supported by Evaluate. Mirrors the SQL CHECK constraint.
const (
	ComparatorEq       = "eq"       // observed equals any of expected_values
	ComparatorNeq      = "neq"      // observed does not equal any of expected_values
	ComparatorIn       = "in"       // synonym for eq; clearer when expected_values is a set
	ComparatorContains = "contains" // observed contains expected_values[0] as substring
	ComparatorGTE      = "gte"      // numeric: observed >= expected_values[0]
	ComparatorLTE      = "lte"      // numeric: observed <= expected_values[0]
)

// TreatUnknownAs values control what status the engine emits for a rule whose
// signal is absent from the device snapshot, or whose signal is the literal
// "read failed" marker (null on the wire, which never enters the signals map,
// or the string "Unknown", which does). Same value domain backs
// TreatNotConfiguredAs (below).
const (
	UnknownAsPass          = "pass"
	UnknownAsFail          = "fail"
	UnknownAsNotApplicable = "not_applicable"
)

// SignalNotConfigured is the exact wire value (PAT-1767) meaning "the read
// succeeded and the setting is genuinely absent" — distinct from null/
// "Unknown", which mean "the read itself failed". Case-sensitive, no spaces;
// this is the only string the evaluator treats specially before it ever
// reaches a comparator.
const SignalNotConfigured = "NotConfigured"

// Rule mirrors one row of compliance_rules. Only the columns the engine reads
// are mapped; framework-mapping arrays are stored back to the DB on each
// evaluation as denorm but never used in comparison logic.
type Rule struct {
	ID               string
	RuleKey          string
	Benchmark        string
	BenchmarkVersion string
	Title            string
	Severity         string
	SignalKey        string
	Comparator       string
	ExpectedValues   []string
	ApplicableArch   []string // nil → applies to every arch
	TreatUnknownAs   string
	// TreatNotConfiguredAs is the status to emit when the signal equals
	// SignalNotConfigured. Empty string means "no explicit override" — the
	// evaluator falls back to TreatUnknownAs (PAT-1767); see
	// effectiveTreatNotConfiguredAs, the one place that applies the fallback.
	TreatNotConfiguredAs string
	Platform             string // "macos" or "windows"; used to filter rules per device
}

// Evaluation is what the engine emits per rule. The extractor copies these
// straight into compliance_evaluations.
type Evaluation struct {
	RuleID           string
	Status           string
	ObservedValue    *string // nil when the signal was absent
	Severity         string
	BenchmarkVersion string
}
