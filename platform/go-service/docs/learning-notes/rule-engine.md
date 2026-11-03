# Rule engine — CIS L1 evaluator

**Subsystem:** compliance rule evaluation
**Code:** `internal/evaluator/`
**Related:** `go-service/docs/CIS_SCORING_ARCHITECTURE.md` (deep-dive architecture page)

---

## Core idea: rules are data

Every compliance control is a row in `compliance_rules`, not Go code. `Evaluate()` is a generic function that applies a comparator against a signal value. Adding a new CIS rule is a SQL migration, not a Go change.

```go
func Evaluate(rules []Rule, signals map[string]string) []EvaluationResult
```

That's the entire public API of the evaluator. No platform-specific logic, no hardcoded rule IDs.

---

## Rule struct

```go
type Rule struct {
    ID               uuid.UUID
    RuleKey          string    // e.g. "cis_macos_2_5_1_1_filevault"
    SignalKey         string    // looked up in signals map
    Comparator        string    // "eq" | "in" | "neq" | "contains" | "gte" | "lte"
    ExpectedValues    []string
    ApplicableArch    []string  // nil = all; ["arm64"] = Apple Silicon only
    TreatUnknownAs    string    // "fail" | "pass" | "not_applicable"
    CollectionTier    string    // "T1" | "T2" | "T3"
    Severity          string    // "critical" | "high" | "medium" | "low"
}
```

---

## Comparators

| Comparator | Pass when | Notes |
|---|---|---|
| `eq` | `observed` == any `expected_values` element | Multi-value allow-list |
| `in` | same as `eq` | Alias; use when intent is "must be one of" |
| `neq` | `observed` not in `expected_values` | Deny-list |
| `contains` | `observed` contains `expected_values[0]` as substring | For compound signal strings |
| `gte` | `float64(observed)` >= `float64(expected_values[0])` | Non-numeric → `error` result |
| `lte` | `float64(observed)` <= `float64(expected_values[0])` | Non-numeric → `error` result |

---

## Evaluation results

```go
type EvaluationResult struct {
    RuleID        uuid.UUID
    Status        string   // "pass" | "fail" | "not_applicable" | "error"
    ObservedValue string
}
```

`not_applicable` is returned when:
- `applicable_arch` is set and the device's arch doesn't match (checked from the signal `device_arch`).

`error` is returned when:
- `gte`/`lte` comparator but the signal value is not numeric.
- Unknown comparator.

---

## Treat-unknown-as

When `signals[rule.SignalKey]` is absent, the rule falls back to `rule.TreatUnknownAs`. For the vast majority of CIS L1 controls, this is `"fail"` — a device that doesn't report the signal for a control we check is considered non-compliant by default.

See `TestEvaluate_MissingSignal` in `internal/evaluator/evaluator_test.go:167`.

---

## Collection tiers

| Tier | Gate | Count |
|---|---|---|
| T1 | Per-OS master switch only (`tenants.macos_enabled`/`windows_enabled`) | 17 macOS + 13 Windows |
| T2 | Master switch + per-tenant `tenant_rules(enabled = true)` | 35 macOS + 39 Windows |
| T3 | Not yet implemented | 0 |

T1 rules always evaluate for every device in an enabled-platform tenant. T2 rules evaluate only if the tenant has opted them in. `LoadRulesForTenant` handles the join:

```sql
SELECT r.* FROM compliance_rules r
LEFT JOIN tenant_rules tr ON tr.rule_id = r.id AND tr.tenant_id = $1
WHERE r.collection_tier = 'T2'
  AND tr.enabled = true
```

The extractor combines `LoadRules()` (T1) and `LoadRulesForTenant()` (T2) before calling `Evaluate()`.

---

## Per-tenant overrides

`tenant_rules` also supports:
- `override_severity` — escalate/downgrade a rule's severity for this tenant.
- `suppression_reason` + `suppressed_until` — suppress a finding for a time-boxed exemption.

These affect report rendering, not evaluation — `Evaluate()` always runs; suppression is a display-layer concern.

---

## Testing

The evaluator is pure Go with no external dependencies — it takes a slice of rules and a map, returns a slice of results. This makes it easy to test:

```go
result := evaluator.Evaluate([]Rule{{
    SignalKey: "filevault",
    Comparator: "eq",
    ExpectedValues: []string{"On"},
    TreatUnknownAs: "fail",
}}, map[string]string{"filevault": "Off"})
// result[0].Status == "fail"
```

Full test coverage in `internal/evaluator/evaluator_test.go`. See also `go-service/docs/TESTING.md`.

---

## Key files

| File | Role |
|---|---|
| `internal/evaluator/types.go` | `Rule` struct and comparator constants |
| `internal/evaluator/evaluator.go` | `Evaluate()` implementation |
| `internal/evaluator/rules.go` | `LoadRules()`, `LoadRulesForTenant()` (DB queries) |
| `internal/evaluator/evaluator_test.go` | Table-driven tests |
| `migrations/0003_compliance_rules.sql` | T1 rule seeding |
| `go-service/docs/CIS_SCORING_ARCHITECTURE.md` | Full architecture deep-dive |
