package evaluator

import (
	"context"
	"os"
	"testing"

	"patched.im/api/internal/db"
)

// Helper: a rule with sensible defaults; tests override the fields they care about.
func mkRule(opts ...func(*Rule)) Rule {
	r := Rule{
		ID:               "rule-1",
		RuleKey:          "test_rule",
		Benchmark:        "test",
		BenchmarkVersion: "v1",
		Title:            "Test rule",
		Severity:         "medium",
		SignalKey:        "k",
		Comparator:       ComparatorEq,
		ExpectedValues:   []string{"On"},
		TreatUnknownAs:   UnknownAsFail,
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func TestEvaluate_Eq(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"On"}
	})}

	got := Evaluate(rules, map[string]string{"k": "On"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("eq match: got %s want pass", got[0].Status)
	}

	got = Evaluate(rules, map[string]string{"k": "Off"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("eq miss: got %s want fail", got[0].Status)
	}
}

func TestEvaluate_In(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorIn
		r.ExpectedValues = []string{"enabled", "assessments"}
	})}

	for _, v := range []string{"enabled", "assessments"} {
		got := Evaluate(rules, map[string]string{"k": v}, "arm64")
		if got[0].Status != StatusPass {
			t.Errorf("in %q: got %s want pass", v, got[0].Status)
		}
	}

	got := Evaluate(rules, map[string]string{"k": "disabled"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("in mismatch: got %s want fail", got[0].Status)
	}
}

func TestEvaluate_Neq(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorNeq
		r.ExpectedValues = []string{"Yes"}
	})}

	got := Evaluate(rules, map[string]string{"k": "No"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("neq pass case: got %s", got[0].Status)
	}

	got = Evaluate(rules, map[string]string{"k": "Yes"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("neq fail case: got %s", got[0].Status)
	}
}

func TestEvaluate_Contains(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorContains
		r.ExpectedValues = []string{"mdm=Yes"}
	})}

	cases := []struct {
		in   string
		want string
	}{
		{"dep=Yes mdm=Yes", StatusPass},
		{"dep=No mdm=Yes", StatusPass},
		{"dep=No mdm=No", StatusFail},
		{"", StatusFail},
	}
	for _, tc := range cases {
		got := Evaluate(rules, map[string]string{"k": tc.in}, "arm64")
		if got[0].Status != tc.want {
			t.Errorf("contains(%q): got %s want %s", tc.in, got[0].Status, tc.want)
		}
	}
}

func TestEvaluate_GTE(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorGTE
		r.ExpectedValues = []string{"0"}
	})}

	got := Evaluate(rules, map[string]string{"k": "5"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("gte 5>=0: got %s want pass", got[0].Status)
	}

	got = Evaluate(rules, map[string]string{"k": "-1"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("gte -1>=0: got %s want fail", got[0].Status)
	}

	got = Evaluate(rules, map[string]string{"k": "not-a-number"}, "arm64")
	if got[0].Status != StatusError {
		t.Errorf("gte non-numeric observed: got %s want error", got[0].Status)
	}
}

func TestEvaluate_LTE(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorLTE
		r.ExpectedValues = []string{"2"}
	})}

	cases := []struct {
		in   string
		want string
	}{
		{"0", StatusPass},
		{"2", StatusPass},
		{"3", StatusFail},
		{"junk", StatusError},
	}
	for _, tc := range cases {
		got := Evaluate(rules, map[string]string{"k": tc.in}, "arm64")
		if got[0].Status != tc.want {
			t.Errorf("lte(%q <= 2): got %s want %s", tc.in, got[0].Status, tc.want)
		}
	}
}

func TestEvaluate_ApplicableArch(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.ApplicableArch = []string{"arm64"}
	})}

	got := Evaluate(rules, map[string]string{"k": "On"}, "x86_64")
	if got[0].Status != StatusNotApplicable {
		t.Errorf("intel device, arm-only rule: got %s want not_applicable", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("not_applicable should leave observed nil, got %v", *got[0].ObservedValue)
	}

	got = Evaluate(rules, map[string]string{"k": "On"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("arm64 device, arm-only rule, signal matches: got %s want pass", got[0].Status)
	}
}

func TestEvaluate_MissingSignal(t *testing.T) {
	// treat_unknown_as=fail (the default for almost every CIS L1 control)
	rules := []Rule{mkRule(func(r *Rule) {
		r.TreatUnknownAs = UnknownAsFail
	})}
	got := Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("missing signal, fail-safe: got %s", got[0].Status)
	}

	// treat_unknown_as=pass — for signals that mean "Apple default in effect"
	rules = []Rule{mkRule(func(r *Rule) {
		r.TreatUnknownAs = UnknownAsPass
	})}
	got = Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("missing signal, treat-as-pass: got %s", got[0].Status)
	}

	// treat_unknown_as=not_applicable
	rules = []Rule{mkRule(func(r *Rule) {
		r.TreatUnknownAs = UnknownAsNotApplicable
	})}
	got = Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusNotApplicable {
		t.Errorf("missing signal, treat-as-na: got %s", got[0].Status)
	}
}

// TestEvaluate_PresentUnknownSentinel is the PAT-1758 regression: a
// collector-emitted literal "Unknown" value for a signal that IS present in
// the map must be treated exactly like an absent key, not compared against
// expected_values as a real observation.
func TestEvaluate_PresentUnknownSentinel(t *testing.T) {
	// treat_unknown_as=fail: present "Unknown" -> fail, ObservedValue nil
	// (not a plain comparator fail against the literal string "Unknown").
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorContains
		r.ExpectedValues = []string{"mdm=Yes"}
		r.TreatUnknownAs = UnknownAsFail
	})}
	got := Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("present Unknown, treat-as-fail: got %s want fail", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("present Unknown should leave ObservedValue nil (same as absent), got %v", *got[0].ObservedValue)
	}

	// treat_unknown_as=not_applicable
	rules = []Rule{mkRule(func(r *Rule) {
		r.TreatUnknownAs = UnknownAsNotApplicable
	})}
	got = Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusNotApplicable {
		t.Errorf("present Unknown, treat-as-na: got %s want not_applicable", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Error("present Unknown, treat-as-na should leave ObservedValue nil")
	}

	// treat_unknown_as=pass
	rules = []Rule{mkRule(func(r *Rule) {
		r.TreatUnknownAs = UnknownAsPass
	})}
	got = Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("present Unknown, treat-as-pass: got %s want pass", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Error("present Unknown, treat-as-pass should leave ObservedValue nil")
	}

	// Case and whitespace variants of the sentinel are all recognised.
	rules = []Rule{mkRule(func(r *Rule) {
		r.TreatUnknownAs = UnknownAsFail
	})}
	for _, v := range []string{"unknown", "UNKNOWN", " Unknown ", "  unknown\t"} {
		got = Evaluate(rules, map[string]string{"k": v}, "arm64")
		if got[0].Status != StatusFail {
			t.Errorf("sentinel variant %q: got %s want fail", v, got[0].Status)
		}
		if got[0].ObservedValue != nil {
			t.Errorf("sentinel variant %q should leave ObservedValue nil, got %v", v, *got[0].ObservedValue)
		}
	}

	// A real, non-matching value is a genuine fail with its observed value
	// recorded — the sentinel handling must not swallow real failures.
	rules = []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"On"}
		r.TreatUnknownAs = UnknownAsFail
	})}
	got = Evaluate(rules, map[string]string{"k": "Off"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("real non-matching value: got %s want fail", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "Off" {
		t.Errorf("real non-matching value should record its observed value, got %v", got[0].ObservedValue)
	}

	// A real, matching value still passes and records its observed value.
	got = Evaluate(rules, map[string]string{"k": "On"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("real matching value: got %s want pass", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "On" {
		t.Errorf("real matching value should record its observed value, got %v", got[0].ObservedValue)
	}

	// A value that merely contains "unknown" as a substring (not the whole,
	// trimmed value) is a real observation, not the sentinel.
	rules = []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"On"}
		r.TreatUnknownAs = UnknownAsFail
	})}
	got = Evaluate(rules, map[string]string{"k": "unknown-state"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("substring-only match: got %s want fail", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "unknown-state" {
		t.Errorf("substring-only match should record its literal observed value, got %v", got[0].ObservedValue)
	}
}

func TestEvaluate_ObservedValueRecorded(t *testing.T) {
	rules := []Rule{mkRule()}
	got := Evaluate(rules, map[string]string{"k": "On"}, "arm64")
	if got[0].ObservedValue == nil {
		t.Fatal("observed value should be recorded when signal present")
	}
	if *got[0].ObservedValue != "On" {
		t.Errorf("observed value: got %q want %q", *got[0].ObservedValue, "On")
	}
}

func TestEvaluate_SeverityAndVersionPassthrough(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Severity = "critical"
		r.BenchmarkVersion = "v3.0.0"
	})}
	got := Evaluate(rules, map[string]string{"k": "On"}, "arm64")
	if got[0].Severity != "critical" {
		t.Errorf("severity passthrough: got %q", got[0].Severity)
	}
	if got[0].BenchmarkVersion != "v3.0.0" {
		t.Errorf("benchmark_version passthrough: got %q", got[0].BenchmarkVersion)
	}
}

// TestEvaluate_NotConfigured_ExplicitTreat covers PAT-1767: a signal equal to
// the literal "NotConfigured" resolves via treat_not_configured_as when the
// rule sets one explicitly, for every status the engine supports, and the
// observed value is recorded (non-nil) rather than left null — PAT-1758
// keys "undetermined" off status='fail' AND observed_value IS NULL, so a
// NotConfigured evaluation must never look like that.
func TestEvaluate_NotConfigured_ExplicitTreat(t *testing.T) {
	cases := []struct {
		treat string
		want  string
	}{
		{UnknownAsPass, StatusPass},
		{UnknownAsFail, StatusFail},
		{UnknownAsNotApplicable, StatusNotApplicable},
	}
	for _, tc := range cases {
		rules := []Rule{mkRule(func(r *Rule) {
			r.TreatUnknownAs = UnknownAsFail // deliberately different, to prove NotConfigured ignores it here
			r.TreatNotConfiguredAs = tc.treat
		})}
		got := Evaluate(rules, map[string]string{"k": "NotConfigured"}, "arm64")
		if got[0].Status != tc.want {
			t.Errorf("treat_not_configured_as=%s: got %s want %s", tc.treat, got[0].Status, tc.want)
		}
		if got[0].ObservedValue == nil {
			t.Fatalf("treat_not_configured_as=%s: observed value must not be nil", tc.treat)
		}
		if *got[0].ObservedValue != "NotConfigured" {
			t.Errorf("treat_not_configured_as=%s: observed value = %q, want %q", tc.treat, *got[0].ObservedValue, "NotConfigured")
		}
	}
}

// TestEvaluate_NotConfigured_FallsBackToTreatUnknownAs covers the default
// (NULL / unset treat_not_configured_as) case: a rule that never set the new
// field resolves "NotConfigured" exactly the way it resolved an absent
// signal before this field existed, so introducing the column changes no
// existing rule's outcome.
func TestEvaluate_NotConfigured_FallsBackToTreatUnknownAs(t *testing.T) {
	cases := []struct {
		treatUnknown string
		want         string
	}{
		{UnknownAsPass, StatusPass},
		{UnknownAsFail, StatusFail},
		{UnknownAsNotApplicable, StatusNotApplicable},
	}
	for _, tc := range cases {
		rules := []Rule{mkRule(func(r *Rule) {
			r.TreatUnknownAs = tc.treatUnknown
			r.TreatNotConfiguredAs = "" // unset — must fall back
		})}
		got := Evaluate(rules, map[string]string{"k": "NotConfigured"}, "arm64")
		if got[0].Status != tc.want {
			t.Errorf("treat_unknown_as=%s (fallback): got %s want %s", tc.treatUnknown, got[0].Status, tc.want)
		}
		if got[0].ObservedValue == nil || *got[0].ObservedValue != "NotConfigured" {
			t.Errorf("treat_unknown_as=%s (fallback): observed value not recorded as NotConfigured", tc.treatUnknown)
		}
	}
}

// TestEvaluate_NotConfigured_NeverReachesComparator: expected_values never
// contains "NotConfigured", and the comparator (eq against "On") would fail
// it if it were ever compared — proving NotConfigured resolves via
// treat_not_configured_as/treat_unknown_as and never through compare().
func TestEvaluate_NotConfigured_NeverReachesComparator(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"On"}
		r.TreatUnknownAs = UnknownAsFail
		r.TreatNotConfiguredAs = UnknownAsPass
	})}
	got := Evaluate(rules, map[string]string{"k": "NotConfigured"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("NotConfigured must resolve via treat_not_configured_as (pass), not the eq comparator (would fail): got %s", got[0].Status)
	}
}

// TestEvaluate_UnknownAndNull_UnchangedByNotConfigured documents that adding
// NotConfigured handling (PAT-1767) left null/absent and the "Unknown"
// sentinel (PAT-1758) untouched relative to each other, and that
// "NotConfigured" stays a distinct third state from both. A missing key and a
// present literal "Unknown" both resolve via treat_unknown_as with
// ObservedValue left nil (PAT-1758 — a present-but-unreadable signal is
// evidence of a failed read, not a real observation to compare); only the
// exact string "NotConfigured" is a real, successful read of "genuinely
// absent" and resolves via treat_not_configured_as with ObservedValue
// recorded (PAT-1767).
func TestEvaluate_UnknownAndNull_UnchangedByNotConfigured(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsPass
		r.TreatNotConfiguredAs = UnknownAsFail // deliberately different, to prove these are independent knobs
	})}

	// Absent signal (models null: renderJSONValue drops it before the map is
	// built, so it's simply not a key here) goes through treat_unknown_as.
	got := Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("absent signal (null): got %s want pass (via treat_unknown_as)", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("absent signal (null): observed value should stay nil, got %v", *got[0].ObservedValue)
	}

	// A present literal "Unknown" (PAT-1758) is treated identically to an
	// absent signal: treat_unknown_as, ObservedValue nil. It must NOT fall
	// through to the eq comparator against "Yes".
	got = Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("present \"Unknown\" value: got %s want pass (via treat_unknown_as, same as absent)", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("present \"Unknown\" value: observed value should stay nil, got %v", *got[0].ObservedValue)
	}

	// "NotConfigured" is a distinct real state (PAT-1767): it resolves via
	// treat_not_configured_as (fail here), not treat_unknown_as (pass), and
	// its observed value IS recorded.
	got = Evaluate(rules, map[string]string{"k": "NotConfigured"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("\"NotConfigured\": got %s want fail (via treat_not_configured_as, distinct from treat_unknown_as)", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "NotConfigured" {
		t.Errorf("\"NotConfigured\": observed value should be recorded as the literal string")
	}
}

// TestEvaluate_Migration0131Shape mirrors the seven Windows NIST rules
// migrations/0131 flipped to treat_unknown_as='fail',
// treat_not_configured_as='pass' (the six Schannel TLS rules plus
// nist_win_si16_mandatory_aslr): a genuine read failure ("Unknown", PAT-1758)
// must be undetermined evidence (fail, ObservedValue nil — the report layer
// keys "could not be determined" on exactly this shape), while a real,
// successful read of "the setting is absent" ("NotConfigured", PAT-1767)
// must pass on the OS-default reading, with the observed value recorded.
func TestEvaluate_Migration0131Shape(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsFail
		r.TreatNotConfiguredAs = UnknownAsPass
	})}

	// Read failed (collector sends the literal "Unknown"): undetermined, not
	// a scored non-compliance.
	got := Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("Unknown on a migration-0131 rule: got %s want fail (undetermined evidence)", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("Unknown on a migration-0131 rule: ObservedValue should be nil, got %v", *got[0].ObservedValue)
	}

	// Read succeeded, setting genuinely absent: OS default applies, real pass.
	got = Evaluate(rules, map[string]string{"k": "NotConfigured"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("NotConfigured on a migration-0131 rule: got %s want pass (OS default)", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "NotConfigured" {
		t.Errorf("NotConfigured on a migration-0131 rule: observed value should be recorded as the literal string")
	}

	// Absent key (older agent that doesn't send the signal at all) behaves
	// the same as a present "Unknown" — both are read failures.
	got = Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("absent key on a migration-0131 rule: got %s want fail (undetermined evidence)", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("absent key on a migration-0131 rule: ObservedValue should be nil, got %v", *got[0].ObservedValue)
	}
}

// TestEvaluate_LAPSEnrolledShape mirrors migrations/0132's
// nist_win_ac2_laps_enrolled fix: this rule has no NotConfigured case (the
// Windows agent sends the real value "No" for genuinely-absent LAPS), so
// after 0132 both an absent key and the "Unknown" sentinel must resolve to
// fail via treat_unknown_as, not the pre-0132 'pass'. A real "No" observation
// must still be a comparator fail with its value recorded.
func TestEvaluate_LAPSEnrolledShape(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsFail // post-0132 value
	})}

	got := Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("LAPS Unknown: got %s want fail (post-0132, no more pass-on-unknown)", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("LAPS Unknown: ObservedValue should be nil, got %v", *got[0].ObservedValue)
	}

	got = Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("LAPS absent key: got %s want fail", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("LAPS absent key: ObservedValue should be nil, got %v", *got[0].ObservedValue)
	}

	// A real "No" (LAPS genuinely not enrolled) is a comparator fail with
	// its observed value recorded — distinct from undetermined evidence.
	got = Evaluate(rules, map[string]string{"k": "No"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("LAPS real \"No\": got %s want fail", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "No" {
		t.Errorf("LAPS real \"No\": ObservedValue should be recorded as \"No\", got %v", got[0].ObservedValue)
	}
}

// TestEvaluate_TimeMachineEncryptedShape mirrors migrations/0132's
// cis_macos_2_3_4_2_time_machine_encrypted fix: "NotConfigured" (no backup
// destination — nothing to encrypt) is a real pass via
// treat_not_configured_as, while "Unknown"/absent (a failed read) is
// undetermined evidence via treat_unknown_as, no longer a pass.
func TestEvaluate_TimeMachineEncryptedShape(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsFail       // post-0132 value
		r.TreatNotConfiguredAs = UnknownAsPass // post-0132 value
	})}

	// No Time Machine destination configured: real pass, value recorded.
	got := Evaluate(rules, map[string]string{"k": "NotConfigured"}, "arm64")
	if got[0].Status != StatusPass {
		t.Errorf("Time Machine NotConfigured: got %s want pass (no destination = nothing to encrypt)", got[0].Status)
	}
	if got[0].ObservedValue == nil || *got[0].ObservedValue != "NotConfigured" {
		t.Errorf("Time Machine NotConfigured: ObservedValue should be recorded as \"NotConfigured\", got %v", got[0].ObservedValue)
	}

	// Failed read: undetermined evidence, no longer a pass.
	got = Evaluate(rules, map[string]string{"k": "Unknown"}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("Time Machine Unknown: got %s want fail (post-0132, failed read no longer passes)", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("Time Machine Unknown: ObservedValue should be nil, got %v", *got[0].ObservedValue)
	}

	got = Evaluate(rules, map[string]string{}, "arm64")
	if got[0].Status != StatusFail {
		t.Errorf("Time Machine absent key: got %s want fail", got[0].Status)
	}
	if got[0].ObservedValue != nil {
		t.Errorf("Time Machine absent key: ObservedValue should be nil, got %v", *got[0].ObservedValue)
	}
}

func TestEvaluate_BadComparator(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.Comparator = "regex-i-wish" // not in supported set
	})}
	got := Evaluate(rules, map[string]string{"k": "On"}, "arm64")
	if got[0].Status != StatusError {
		t.Errorf("bad comparator: got %s want error", got[0].Status)
	}
}

func TestEvaluate_RealCISShape(t *testing.T) {
	// Smoke test: simulate Andy's actual Mac state from the verified extraction
	// run and assert a handful of representative rules behave as expected.
	signals := map[string]string{
		"filevault":                  "On",
		"sip":                        "enabled",
		"firewall":                   "disabled", // intentionally non-compliant on Andy's box
		"gatekeeper":                 "enabled",
		"sealed_system_volume":       "enabled",
		"auto_security_updates":      "On",
		"mdm_enrolment":              "dep=No mdm=No", // intentionally non-compliant
		"local_admin_count":          "1",
		"password_policy_is_default": "Yes", // intentionally non-compliant
		"auto_login_user":            "None",
		"icloud_signed_in":           "Yes",
		"pending_updates_count":      "1", // intentionally non-compliant
		"secure_boot":                "Valid",
	}

	rules := []Rule{
		mkRule(func(r *Rule) { r.RuleKey = "filevault"; r.SignalKey = "filevault"; r.ExpectedValues = []string{"On"} }),
		mkRule(func(r *Rule) {
			r.RuleKey = "firewall"
			r.SignalKey = "firewall"
			r.ExpectedValues = []string{"enabled"}
		}),
		mkRule(func(r *Rule) {
			r.RuleKey = "mdm"
			r.SignalKey = "mdm_enrolment"
			r.Comparator = ComparatorContains
			r.ExpectedValues = []string{"mdm=Yes"}
		}),
		mkRule(func(r *Rule) {
			r.RuleKey = "pwpolicy"
			r.SignalKey = "password_policy_is_default"
			r.ExpectedValues = []string{"No"}
		}),
		mkRule(func(r *Rule) {
			r.RuleKey = "pending"
			r.SignalKey = "pending_updates_count"
			r.Comparator = ComparatorEq
			r.ExpectedValues = []string{"0"}
		}),
		mkRule(func(r *Rule) {
			r.RuleKey = "secureboot"
			r.SignalKey = "secure_boot"
			r.Comparator = ComparatorIn
			r.ExpectedValues = []string{"Full Security", "Valid"}
			r.ApplicableArch = []string{"arm64"}
		}),
	}

	got := Evaluate(rules, signals, "arm64")

	// Positional asserts — mkRule defaults all rule IDs to "rule-1" so we
	// can't key by ID; the order matches the slice order in `rules` above.
	if got[0].Status != StatusPass { // filevault
		t.Errorf("filevault: %s", got[0].Status)
	}
	if got[1].Status != StatusFail { // firewall disabled
		t.Errorf("firewall: %s", got[1].Status)
	}
	if got[2].Status != StatusFail { // mdm=No
		t.Errorf("mdm: %s", got[2].Status)
	}
	if got[3].Status != StatusFail { // password_policy_is_default=Yes
		t.Errorf("pwpolicy: %s", got[3].Status)
	}
	if got[4].Status != StatusFail { // pending=1
		t.Errorf("pending: %s", got[4].Status)
	}
	if got[5].Status != StatusPass { // secure_boot=Valid on arm64
		t.Errorf("secureboot: %s", got[5].Status)
	}
}

func TestEvaluate_MacOSMDMNeutralSignalAndBoundedLegacyFallback(t *testing.T) {
	rule := mkRule(func(r *Rule) {
		r.RuleKey = macOSMDMRuleKey
		r.Platform = "macos"
		r.SignalKey = neutralMDMSignalKey
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsFail
	})

	tests := []struct {
		name             string
		signals          map[string]string
		wantStatus       string
		wantObserved     string
		wantObservedNull bool
	}{
		{"neutral Yes passes", map[string]string{"mdm_enrolled": "Yes"}, StatusPass, "Yes", false},
		{"neutral No fails", map[string]string{"mdm_enrolled": "No"}, StatusFail, "No", false},
		{"neutral Unknown fails closed", map[string]string{"mdm_enrolled": "Unknown"}, StatusFail, "", true},
		{"missing signal fails closed", map[string]string{}, StatusFail, "", true},
		{"legacy enrolled passes during bridge", map[string]string{"mdm_enrolment": "dep=No mdm=Yes (User Approved)"}, StatusPass, "Yes", false},
		{"legacy unenrolled fails during bridge", map[string]string{"mdm_enrolment": "dep=No mdm=No"}, StatusFail, "No", false},
		{"legacy malformed Yes-like value fails closed", map[string]string{"mdm_enrolment": "dep=No mdm=YesPlease"}, StatusFail, "", true},
		{"legacy duplicate MDM tokens fail closed", map[string]string{"mdm_enrolment": "dep=No mdm=Yes mdm=Yes"}, StatusFail, "", true},
		{"neutral Unknown cannot fall back to stale legacy Yes", map[string]string{"mdm_enrolled": "Unknown", "mdm_enrolment": "dep=Yes mdm=Yes"}, StatusFail, "", true},
		{"neutral No cannot fall back to stale legacy Yes", map[string]string{"mdm_enrolled": "No", "mdm_enrolment": "dep=Yes mdm=Yes"}, StatusFail, "No", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate([]Rule{rule}, tt.signals, "arm64")[0]
			if got.Status != tt.wantStatus {
				t.Fatalf("status: got %s want %s", got.Status, tt.wantStatus)
			}
			if tt.wantObservedNull {
				if got.ObservedValue != nil {
					t.Fatalf("ObservedValue: got %q want nil", *got.ObservedValue)
				}
				return
			}
			if got.ObservedValue == nil || *got.ObservedValue != tt.wantObserved {
				t.Fatalf("ObservedValue: got %v want %q", got.ObservedValue, tt.wantObserved)
			}
		})
	}
}

func TestEvaluate_WindowsMDMSemanticsIgnoreMacOSLegacyFallback(t *testing.T) {
	rule := mkRule(func(r *Rule) {
		r.RuleKey = "patched_win_mdm_enrolled"
		r.Platform = "windows"
		r.SignalKey = neutralMDMSignalKey
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsFail
	})

	got := Evaluate([]Rule{rule}, map[string]string{"mdm_enrolment": "dep=Yes mdm=Yes"}, "x86_64")[0]
	if got.Status != StatusFail || got.ObservedValue != nil {
		t.Fatalf("legacy macOS signal influenced Windows rule: status=%s observed=%v", got.Status, got.ObservedValue)
	}

	got = Evaluate([]Rule{rule}, map[string]string{"mdm_enrolled": "Yes"}, "x86_64")[0]
	if got.Status != StatusPass || got.ObservedValue == nil || *got.ObservedValue != "Yes" {
		t.Fatalf("Windows neutral Yes changed: status=%s observed=%v", got.Status, got.ObservedValue)
	}
}

func TestEvaluate_MacOSLegacyFallbackRequiresExactRuleAndSignal(t *testing.T) {
	base := mkRule(func(r *Rule) {
		r.Platform = "macos"
		r.Comparator = ComparatorEq
		r.ExpectedValues = []string{"Yes"}
		r.TreatUnknownAs = UnknownAsFail
	})

	for _, tt := range []struct {
		name string
		rule Rule
	}{
		{
			name: "different macOS rule",
			rule: func() Rule {
				r := base
				r.RuleKey = "another_macos_rule"
				r.SignalKey = neutralMDMSignalKey
				return r
			}(),
		},
		{
			name: "different signal on MDM rule",
			rule: func() Rule {
				r := base
				r.RuleKey = macOSMDMRuleKey
				r.SignalKey = "another_signal"
				return r
			}(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate([]Rule{tt.rule}, map[string]string{legacyMDMSignalKey: "dep=Yes mdm=Yes"}, "arm64")[0]
			if got.Status != StatusFail || got.ObservedValue != nil {
				t.Fatalf("legacy fallback escaped its guard: status=%s observed=%v", got.Status, got.ObservedValue)
			}
		})
	}
}

// TestEvaluate_PasswordAfterScreensaverDelay mirrors the shape of
// cis_macos_2_10_2_password_after_screensaver_delay (PAT-1746,
// migrations/0129): screensaver_delay_seconds, lte 5, treat_unknown_as=fail.
// A 3600-second password grace (the value that incorrectly passed the
// retired cis_macos_2_10_1_screensaver_timeout's 1200-second idle-timeout
// check) must fail here, since it is being evaluated as a password delay,
// not an idle interval.
func TestEvaluate_PasswordAfterScreensaverDelay(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.RuleKey = "cis_macos_2_10_2_password_after_screensaver_delay"
		r.SignalKey = "screensaver_delay_seconds"
		r.Comparator = ComparatorLTE
		r.ExpectedValues = []string{"5"}
		r.TreatUnknownAs = UnknownAsFail
	})}

	cases := []struct {
		signal map[string]string
		want   string
		name   string
	}{
		{map[string]string{"screensaver_delay_seconds": "3600"}, StatusFail, "1-hour password delay fails"},
		{map[string]string{"screensaver_delay_seconds": "5"}, StatusPass, "5-second password delay passes"},
		{map[string]string{"screensaver_delay_seconds": "0"}, StatusPass, "immediate password passes"},
		{map[string]string{}, StatusFail, "missing signal fails (fail-safe)"},
	}
	for _, tc := range cases {
		got := Evaluate(rules, tc.signal, "arm64")
		if got[0].Status != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got[0].Status, tc.want)
		}
	}
}

// TestEvaluate_ScreensaverInactivity mirrors the shape of
// cis_macos_2_10_1_screensaver_inactivity (PAT-1753, migrations/0130):
// screensaver_idle_seconds, lte 1200, treat_unknown_as=fail. idleTime 0
// ("never") is sent by the collector as the sentinel 99999, which must fail
// the same as any other over-limit value.
func TestEvaluate_ScreensaverInactivity(t *testing.T) {
	rules := []Rule{mkRule(func(r *Rule) {
		r.RuleKey = "cis_macos_2_10_1_screensaver_inactivity"
		r.SignalKey = "screensaver_idle_seconds"
		r.Comparator = ComparatorLTE
		r.ExpectedValues = []string{"1200"}
		r.TreatUnknownAs = UnknownAsFail
	})}

	cases := []struct {
		signal map[string]string
		want   string
		name   string
	}{
		{map[string]string{"screensaver_idle_seconds": "600"}, StatusPass, "10-minute idle timeout passes"},
		{map[string]string{"screensaver_idle_seconds": "1200"}, StatusPass, "20-minute idle timeout passes"},
		{map[string]string{"screensaver_idle_seconds": "1201"}, StatusFail, "just over 20 minutes fails"},
		{map[string]string{"screensaver_idle_seconds": "99999"}, StatusFail, "never (sentinel 99999) fails"},
		{map[string]string{}, StatusFail, "missing signal fails (fail-safe)"},
	}
	for _, tc := range cases {
		got := Evaluate(rules, tc.signal, "arm64")
		if got[0].Status != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got[0].Status, tc.want)
		}
	}
}

// TestSeedT2Baseline_LoadRulesForTenantReturnsFullT2Set is the PAT-1794 DB
// regression: SeedT2Baseline on a freshly-created tenant with no tenant_rules
// rows must leave LoadRulesForTenant(tenantID, "macos") returning exactly
// the full enabled T2/macos rule set — not a subset, not empty (the
// pre-PAT-1794 default for every tenant with no manual opt-in).
//
// DB-backed: requires TEST_DATABASE_URL against a database with the full
// migration chain applied (same convention as the handlers package's
// TEST_DATABASE_URL-gated DB tests, e.g. admin_agentidentity_db_test.go).
func TestSeedT2Baseline_LoadRulesForTenantReturnsFullT2Set(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping SeedT2Baseline DB test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat1794-seed-t2-baseline-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

	// Before seeding: a brand-new tenant has no tenant_rules rows, so no T2
	// rule evaluates for it — this is the pre-PAT-1794 (opt-in) baseline.
	before, err := LoadRulesForTenant(ctx, pool, tenantID, "macos", "unknown")
	if err != nil {
		t.Fatalf("LoadRulesForTenant before seed: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("expected 0 T2 rules before seeding, got %d", len(before))
	}

	if err := SeedT2Baseline(ctx, pool, tenantID); err != nil {
		t.Fatalf("SeedT2Baseline: %v", err)
	}

	var wantCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM compliance_rules
		WHERE collection_tier = 'T2' AND enabled = true AND platform = 'macos'
	`).Scan(&wantCount); err != nil {
		t.Fatalf("count expected T2 macos rules: %v", err)
	}

	after, err := LoadRulesForTenant(ctx, pool, tenantID, "macos", "unknown")
	if err != nil {
		t.Fatalf("LoadRulesForTenant after seed: %v", err)
	}
	if len(after) != wantCount {
		t.Errorf("LoadRulesForTenant after SeedT2Baseline: got %d rules, want %d (the full enabled T2/macos set)", len(after), wantCount)
	}

	// Idempotent: calling again must not duplicate or change the set.
	if err := SeedT2Baseline(ctx, pool, tenantID); err != nil {
		t.Fatalf("second SeedT2Baseline call: %v", err)
	}
	again, err := LoadRulesForTenant(ctx, pool, tenantID, "macos", "unknown")
	if err != nil {
		t.Fatalf("LoadRulesForTenant after second seed: %v", err)
	}
	if len(again) != wantCount {
		t.Errorf("LoadRulesForTenant after duplicate SeedT2Baseline call: got %d rules, want %d (unchanged)", len(again), wantCount)
	}
}

// containsRuleKey reports whether rules contains a Rule with the given key.
// Used instead of exact-count assertions in the device-class tests below,
// since LoadRules/LoadRulesForTenant also return the real seeded Windows 11
// pack (all device_class={workstation} after migration 0158's backfill) —
// asserting presence/absence of specific test rules is robust to that,
// exact counts would not be.
func containsRuleKey(rules []Rule, key string) bool {
	for _, r := range rules {
		if r.RuleKey == key {
			return true
		}
	}
	return false
}

// TestLoadRules_DeviceClassMatching is the PAT-1960 DB regression for the
// crux rule-matching predicate:
//
//	cr.device_class IS NULL OR d.device_class = ANY(cr.device_class) OR d.device_class = 'unknown'
//
// A workstation-scoped rule must not apply to a server device class; a
// server-scoped rule must not apply to a workstation; a class-agnostic
// (NULL device_class) rule must apply to both; and — the load-bearing third
// clause — an 'unknown' device class (every device until PAT-1959 ships)
// must see every rule, exactly as if device_class did not exist at all.
//
// DB-backed: requires TEST_DATABASE_URL against a database with the full
// migration chain applied (same convention as
// TestSeedT2Baseline_LoadRulesForTenantReturnsFullT2Set above).
func TestLoadRules_DeviceClassMatching(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping device-class DB test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('pat1960-device-class-matching-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000001'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000001'::bytea)
		RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

	insertRule := func(key, tier string, deviceClass any) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO compliance_rules
				(rule_key, benchmark, benchmark_version, title, severity, signal_key, comparator, expected_values,
				 treat_unknown_as, enabled, platform, collection_tier, device_class)
			VALUES ($1, 'PAT-1960 Test Benchmark', 'v1', $1, 'low', 'k', 'eq', '{Yes}',
			        'fail', true, 'windows', $2, $3)
			RETURNING id::text
		`, key, tier, deviceClass).Scan(&id); err != nil {
			t.Fatalf("insert rule %s: %v", key, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM compliance_rules WHERE id = $1::uuid`, id) })
		return id
	}

	workstationOnly := insertRule("pat1960_t1_workstation", "T1", []string{"workstation"})
	serverOnly := insertRule("pat1960_t1_server", "T1", []string{"server"})
	universal := insertRule("pat1960_t1_universal", "T1", nil)
	t2Workstation := insertRule("pat1960_t2_workstation", "T2", []string{"workstation"})

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_rules (tenant_id, rule_id, enabled)
		VALUES ($1::uuid, $2::uuid, true)
	`, tenantID, t2Workstation); err != nil {
		t.Fatalf("insert tenant_rules: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_rules WHERE tenant_id = $1::uuid`, tenantID)
	})
	_ = workstationOnly
	_ = serverOnly
	_ = universal

	// T1 (LoadRules): workstation sees workstation+universal, not server.
	wsRules, err := LoadRules(ctx, pool, "windows", "workstation")
	if err != nil {
		t.Fatalf("LoadRules(workstation): %v", err)
	}
	if !containsRuleKey(wsRules, "pat1960_t1_workstation") {
		t.Error("LoadRules(workstation) missing the workstation-scoped rule")
	}
	if !containsRuleKey(wsRules, "pat1960_t1_universal") {
		t.Error("LoadRules(workstation) missing the class-agnostic (NULL device_class) rule")
	}
	if containsRuleKey(wsRules, "pat1960_t1_server") {
		t.Error("LoadRules(workstation) must not include the server-scoped rule")
	}

	// T1: server sees server+universal, not workstation — the acceptance-
	// criteria case: a server device under a workstation-only pack.
	srvRules, err := LoadRules(ctx, pool, "windows", "server")
	if err != nil {
		t.Fatalf("LoadRules(server): %v", err)
	}
	if !containsRuleKey(srvRules, "pat1960_t1_server") {
		t.Error("LoadRules(server) missing the server-scoped rule")
	}
	if !containsRuleKey(srvRules, "pat1960_t1_universal") {
		t.Error("LoadRules(server) missing the class-agnostic rule")
	}
	if containsRuleKey(srvRules, "pat1960_t1_workstation") {
		t.Error("LoadRules(server) must not include the workstation-scoped rule — this is the PAT-1960 bug being fixed")
	}

	// T1: 'unknown' — the load-bearing third clause — sees everything,
	// exactly as if device_class did not exist.
	unkRules, err := LoadRules(ctx, pool, "windows", "unknown")
	if err != nil {
		t.Fatalf("LoadRules(unknown): %v", err)
	}
	for _, key := range []string{"pat1960_t1_workstation", "pat1960_t1_server", "pat1960_t1_universal"} {
		if !containsRuleKey(unkRules, key) {
			t.Errorf("LoadRules(unknown) missing %s — 'unknown' must keep pre-PAT-1960 behaviour (every rule)", key)
		}
	}

	// T2 (LoadRulesForTenant): same predicate, tenant-scoped.
	t2ws, err := LoadRulesForTenant(ctx, pool, tenantID, "windows", "workstation")
	if err != nil {
		t.Fatalf("LoadRulesForTenant(workstation): %v", err)
	}
	if !containsRuleKey(t2ws, "pat1960_t2_workstation") {
		t.Error("LoadRulesForTenant(workstation) missing the enabled T2 workstation-scoped rule")
	}

	t2srv, err := LoadRulesForTenant(ctx, pool, tenantID, "windows", "server")
	if err != nil {
		t.Fatalf("LoadRulesForTenant(server): %v", err)
	}
	if containsRuleKey(t2srv, "pat1960_t2_workstation") {
		t.Error("LoadRulesForTenant(server) must not include the workstation-scoped T2 rule")
	}

	t2unk, err := LoadRulesForTenant(ctx, pool, tenantID, "windows", "unknown")
	if err != nil {
		t.Fatalf("LoadRulesForTenant(unknown): %v", err)
	}
	if !containsRuleKey(t2unk, "pat1960_t2_workstation") {
		t.Error("LoadRulesForTenant(unknown) missing the T2 workstation-scoped rule — 'unknown' must see every rule")
	}
}
