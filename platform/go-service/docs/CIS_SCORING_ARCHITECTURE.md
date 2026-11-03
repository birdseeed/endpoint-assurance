# CIS L1 compliance scoring — architecture

**Status:** live. Rule inventory is data-driven and must be obtained from the
live database after applying ordered migrations; see
[`contracts/portal-api.md`](../../contracts/portal-api.md#rule-count-source-of-truth).
**Canonical rule catalogue:** `go-service/docs/CIS_RULES.md`
**ADR:** `go-service/docs/adr/0001-cis-collection-scope.md`

---

## Design principle: rules are data

Every compliance control is a row in the `compliance_rules` table, not Go code. The engine is generic: it applies a comparator against a signal value and emits a pass/fail/not-applicable outcome. Adding a new CIS rule, bumping a benchmark version, or granting a per-tenant severity override is a SQL migration — not a Go change, not a redeploy.

This means:

- New CIS L1 releases can be shipped as migrations without touching the Go binary.
- Backfill scenarios ("what would today's rules say about last quarter's snapshot?") run by re-evaluating the archived `raw_payloads` against the current rule pack.
- Per-tenant rule activation (`tenant_rules`) and the T1/T2 tier model are data-driven, not hardcoded.

See the rationale in `migrations/0003_compliance_rules.sql:13-22` and `adr/0001-cis-collection-scope.md`.

---

## Data flow

```
Endpoint (macOS/Windows)
  └── patched-collect / Windows collector
        └── compliance signals in payload JSON
              └── POST /v1/inventory
                    └── raw_payloads (JSONB, immutable)
                          └── patched-extractor (async)
                                ├── buildSignalsMap()           ← flat map[string]string
                                ├── LoadRules(T1)               ← always-evaluate rules
                                ├── LoadRulesForTenant(T2)      ← per-tenant enabled rules
                                └── Evaluate(rules, signals)
                                      └── compliance_evaluations (append-only)
```

The extractor is a separate systemd binary (`patched-extractor`) that polls `raw_payloads` for unprocessed rows. It runs `Evaluate` in the same DB transaction as the device/apps upsert, so a device is never in a partial state where signals exist but evaluations don't.

---

## Rule structure

Each `compliance_rules` row maps to the `evaluator.Rule` struct (`internal/evaluator/types.go`):

| Field | Type | Role |
|---|---|---|
| `rule_key` | text | Slug encoding the benchmark reference, e.g. `cis_macos_2_5_1_1_filevault` |
| `benchmark` | text | `"CIS Apple macOS"` / `"CIS Microsoft Windows 11"` / `"patched.im baseline"` |
| `benchmark_version` | text | `"v3.0.0"` (macOS) / `"v3.0.0"` (Windows) / `"v1"` (baseline) |
| `signal_key` | text | Key looked up in `buildSignalsMap()`, sourced from `compliance_signals` |
| `comparator` | text | `eq` / `in` / `neq` / `contains` / `gte` / `lte` |
| `expected_values` | text[] | The passing set; semantics depend on comparator |
| `applicable_arch` | text[] | NULL = all; `['arm64']` = Apple Silicon only; `['amd64']` = Intel only |
| `treat_unknown_as` | text | `fail` / `pass` / `not_applicable` — used when signal is absent or unreadable (PAT-1758) |
| `collection_tier` | text | `T1` (always) / `T2` (per-tenant) / `T3` (out of scope) |
| `severity` | text | `critical` / `high` / `medium` / `low` |
| `pii_observed` | text | What personal data the signal reveals; must be non-NULL before a T2 rule can be published |

---

## Collection tiers

### T1 — always evaluate

T1 rules run for every managed device on every inventory POST, regardless of per-tenant `tenant_rules` settings. The only gate is the per-OS **master switch** (`tenants.macos_enabled` / `windows_enabled`): if the platform is disabled for a tenant, no evaluation runs — not even T1.

The current T1 inventory is a live database query, not a value maintained in
this architecture snapshot.

These controls represent baseline security hygiene that no managed endpoint should be exempt from: full-disk encryption, OS integrity protections, screen lock, key security features enabled.

### T2 — per-tenant activation

T2 rules require an `enabled = true` row in `tenant_rules(tenant_id, rule_id)`. The absence of a row means the rule does not evaluate for that tenant. `LoadRulesForTenant(ctx, pool, tenantID)` handles the per-tenant T2 slice; the extractor combines it with the T1 set before calling `Evaluate`.

T2 rules require controls that either:
- Need additional context about the tenant's environment (e.g. password policy detail)
- Have `pii_observed` values requiring documented consent before activation
- Are desirable for most tenants but may have legitimate exemptions (e.g. `nfsd_disabled` may conflict with legacy file-server setups)

The current T2 inventory is a live database query, not a value maintained in
this architecture snapshot.

### T3 — out of scope

Reserved for CIS L2 and user-elective controls not yet included in the product.
Whether any T3 rows are currently enabled is a live database query.

---

## Comparators

Defined in `internal/evaluator/types.go`, enforced by SQL CHECK constraint.

| Comparator | Pass condition | Notes |
|---|---|---|
| `eq` | `observed == expected_values[0]` or any element | Multi-value: pass if observed matches any element |
| `in` | Synonym for `eq` | Use for allow-lists where name makes intent clearer |
| `neq` | `observed` not in `expected_values` | Deny-list |
| `contains` | `observed` contains `expected_values[0]` as substring | Used for compound signal strings (e.g. MDM enrolment flags) |
| `gte` | `float64(observed) >= float64(expected_values[0])` | Numeric; `error` status if observed is non-numeric |
| `lte` | `float64(observed) <= float64(expected_values[0])` | Numeric |

### Treat-unknown-as policy

When a device has no signal for a rule's `signal_key` (key absent from `compliance_signals`), or the key is present but its value is the collector's literal "Unknown" sentinel (PAT-1758 — both agents emit this on a signal they attempted to read but could not), the engine falls back to `treat_unknown_as`. For almost all CIS L1 controls this is `fail` — absence or unreadability of the signal from a control we check is a problem. See `TestEvaluate_MissingSignal` and `TestEvaluate_PresentUnknownSentinel` in `internal/evaluator/evaluator_test.go`.

---

## Evaluation outcomes

| Status | Meaning |
|---|---|
| `pass` | Observed value satisfies the rule |
| `fail` | Observed value does not satisfy the rule |
| `not_applicable` | Architecture gate excluded this rule from the device |
| `error` | Rule configuration error (unsupported comparator, non-numeric value against `gte`/`lte`) |

Outcomes are stored in `compliance_evaluations(device_id, rule_id, status, observed_value, evaluated_at)` — append-only; old rows are not updated. The most recent evaluation per `(device_id, rule_id)` is the current posture. Historical rows are retained for trend and backfill analysis.

---

## Per-tenant policy model

### Master switches

`tenants.macos_enabled` and `tenants.windows_enabled` are ON/OFF toggles for each platform. When OFF, the extractor skips all rule evaluation (including T1) for that platform. Admin API: `GET`/`PUT /admin/tenant-platforms/{tenantID}`. Every flip is logged in `tenant_platform_changes` (append-only).

### Per-rule toggles (`tenant_rules`)

```
tenant_rules(tenant_id, rule_id, enabled, override_severity, suppression_reason, suppressed_until)
```

| Column | Purpose |
|---|---|
| `enabled` | T2: controls whether the rule evaluates. T1: no effect on evaluation gate. |
| `override_severity` | Tenant-specific severity override (e.g. escalate a medium to critical). Overrides `compliance_rules.severity` in evaluations and PDF reports. |
| `suppression_reason` | Operator note for exemptions (e.g. "accepted risk — compensating control in risk register"). |
| `suppressed_until` | Non-NULL future timestamp = rule is suppressed for this tenant. NULL or past = active. |

Every mutation is recorded in `tenant_rule_changes` (append-only audit log). The admin API (`PUT /admin/tenants/{id}/rules/{ruleId}`) writes through to both tables in one transaction.

### PII gate for T2 rule activation

Before a T2 rule can be activated for any tenant:
- `compliance_rules.pii_observed` must be non-NULL (documents what personal data the signal could reveal, or explicitly "none")
- `compliance_rules.requires_user_consent` must be set accurately

This is enforced by code review (CLAUDE.md checklist), not a DB constraint. The intent is to ensure that every T2 rule has been reviewed for data-protection implications before customer exposure.

---

## Signal sourcing

Signals flow from the endpoint agent through the inventory payload to `compliance_signals` via the extractor.

### macOS

The macOS collector (`patched-collect.sh`) emits compliance signals in the `compliance` object of the inventory payload (schema_v3). Each signal key maps directly to a `compliance_rules.signal_key`. The collector is structured as a thin orchestrator + 11 `lib/` modules — each module owns one signal group (e.g. `lib/filevault.sh` → `filevault` signal, `lib/sip.sh` → `sip` signal).

Signals are strings in the payload JSON. The extractor normalises booleans to `"Yes"`/`"No"` and unknown values to the collector-documented sentinel strings. The `buildSignalsMap` function in `internal/extractor/upsert.go:263` builds the flat `map[string]string` that `Evaluate` operates on.

### Windows

The Windows collector (`ComplianceCollector.cs`) emits the same flat `compliance` map structure. Windows signals use the same snake_case conventions. Some Windows signals require normalisation for "0 = never" cases (e.g. `max_password_age_days` = 0 means "never expires" and is clamped to `99999` to fail the `lte` rule). Normalisation is documented per-signal in the batch migration comments and is owned by the collector (`ComplianceCollector.cs`), not the extractor.

---

## Versioning and benchmark drift

### Current benchmark versions

- macOS: CIS Apple macOS Sonoma 14 / Sequoia 15 L1 (referenced as v3.0.0 in `benchmark_version`)
- Windows: CIS Microsoft Windows 11 Enterprise Benchmark (referenced as v3.0.0)

### When a new CIS benchmark is released

1. Review the new benchmark for added, removed, or renumbered controls.
2. For **added** controls: write a new `compliance_rules` INSERT migration. Set `collection_tier = 'T1'` if the control is always-on; `'T2'` if per-tenant.
3. For **removed or renamed** controls: do not delete existing rows (historical evaluations reference them by UUID). Add a comment in the migration noting the deprecation; optionally set `enabled = false`.
4. For **renumbered** controls: update `rule_key` and `benchmark_version` in a migration; the UUID is stable.
5. The agent collector may need a new signal — create a paired collector ticket in the `updater` workstream (following the T2 batch pattern in `WINDOWS_T2_GAPMAP.md`).

### macOS major version changes

macOS 26 introduced parser changes for several signals:
- `systemextensionsctl list` now uses `*`/`-` markers instead of "enabled"/"active"
- `bputil --display-all-policies` → parse "Pairing Integrity" (not "Secure Boot")
- `com.apple.screensaver` plist: missing `askForPassword` = default-secure (emit as `"DefaultAssumed"`)

These are handled in the collector's `lib/` modules and are documented in `CLAUDE.md §macOS agent-script footguns`.

---

## Code pointers

| What | Where |
|---|---|
| Rule struct and comparator definitions | `internal/evaluator/types.go` |
| `Evaluate()` function | `internal/evaluator/evaluator.go` |
| `LoadRules` / `LoadRulesForTenant` | `internal/evaluator/rules.go` |
| `buildSignalsMap` | `internal/extractor/upsert.go:263` |
| Rule seeding (T1) | `migrations/0003_compliance_rules.sql` |
| Rule seeding (macOS T2 batches 1–3) | `migrations/0006_*.sql`, `0007_*.sql`, `0008_*.sql` |
| Rule seeding (Windows T1) | `migrations/0019_windows_cis_l1_rules.sql` |
| Rule seeding (Windows T2 batches 1–5) | `migrations/0024_*.sql` – `0028_*.sql` |
| Evaluator tests | `internal/evaluator/evaluator_test.go` |
| Framework mappings (NIST, ISO, CE) | `go-service/docs/CIS_RULES.md §Framework mappings` |
