# Rule packs

The `patched-rules import` CLI ingests a whole CIS benchmark rule pack from a YAML file into `compliance_rules`. It is the primary authoring tool for:

- **The CIS Windows L1 rule pack** — a self-contained YAML file to author and import
- **Annual macOS benchmark refreshes** — bumping `benchmark_version` and editing rule parameters

For the manual one-rule-at-a-time approach, see CIS_RULES.md. For existing rules already in the DB, see the 52-rule catalogue in that doc.

---

## Running the tool

```bash
# Validate a pack and preview what would change (no writes)
DATABASE_URL="postgres://..." patched-rules import --dry-run cis-windows-l1.yaml

# Import for real
DATABASE_URL="postgres://..." patched-rules import cis-windows-l1.yaml
```

`DATABASE_URL` is required for both modes: `--dry-run` queries existing rows to compute the insert/update plan.

**Import is idempotent.** Re-importing the same pack updates every row to match the YAML — no duplicates are created. The natural key is `(benchmark, benchmark_version, rule_key)`, enforced by a DB UNIQUE constraint.

---

## YAML file format

```yaml
benchmark: "CIS Microsoft Windows Server 2022"   # required — free text, matches compliance_rules.benchmark
benchmark_version: "1.0.0"                        # required — matches compliance_rules.benchmark_version
platform: windows                                 # required — macos | windows

rules:
  - rule_key: cis_win_1_1_1_password_history      # required — slug, unique within this benchmark+version
    title: "Ensure 'Enforce password history' is set to '24 or more password(s)'"  # required
    severity: medium                              # required — low | medium | high | critical
    signal_key: pw_history                        # required — key in the compliance_signals map
    comparator: gte                               # required — eq | neq | in | contains | gte | lte
    expected_values: ["24"]                       # required — list; semantics depend on comparator
    description: "..."                            # optional
    control_identifier: "1.1.1"                   # optional — exact identifier for this benchmark version
    collection_tier: T1                           # optional — T1 (default) | T2 | T3
    treat_unknown_as: fail                        # optional — fail (default) | pass | not_applicable
    treat_not_configured_as: null                 # optional — pass | fail | not_applicable; omit/null = use treat_unknown_as
    applicable_arch: []                           # optional — omit or [] for all; ["arm64"] to restrict
    nist_mappings: ["IA-5"]                       # optional
    iso_mappings: ["A.9.4.3"]                     # optional
    cyber_essentials_mappings: []                 # optional
    pii_observed: "none"                          # optional — required non-null before T2 rule can be tenant-activated
    requires_user_consent: false                  # optional — default false
    enabled: true                                 # optional — default true
```

### Pack-level fields

| Field | Required | Description |
|---|---|---|
| `benchmark` | yes | Human-readable benchmark name. Free text; stored verbatim in `compliance_rules.benchmark`. |
| `benchmark_version` | yes | Version string. Stored in `compliance_rules.benchmark_version`. |
| `platform` | yes | `macos` or `windows`. Applied to every rule in the file. |

### Per-rule fields

| Field | Required | Default | Notes |
|---|---|---|---|
| `rule_key` | yes | — | Unique within `(benchmark, benchmark_version)`. Use a stable slug, e.g. `cis_win_1_1_1_password_history`. |
| `title` | yes | — | Display title in reports. |
| `severity` | yes | — | `low` / `medium` / `high` / `critical` |
| `signal_key` | yes | — | The key in `compliance_signals` (and the signals map) that this rule evaluates. |
| `comparator` | yes | — | `eq` / `neq` / `in` / `contains` / `gte` / `lte` — see [Comparators](#comparators) |
| `expected_values` | yes | — | Non-empty list. Semantics depend on comparator. |
| `description` | no | null | Explanation for auditors and customers. |
| `control_identifier` | no | null on insert; preserve on update | Authoritative identifier for this exact benchmark version. Omit it to create an unmapped new rule or preserve an existing rule's identifier. A present value must be non-blank. Never derive it from `rule_key`. |
| `collection_tier` | no | `T1` | `T1` = always-evaluate; `T2` = per-tenant; `T3` = out of scope. |
| `treat_unknown_as` | no | `fail` | What status to emit when the signal is absent, or is `null` / the literal string `"Unknown"` (the read failed) — `fail` / `pass` / `not_applicable`. |
| `treat_not_configured_as` | no | null (use `treat_unknown_as`) | What status to emit when the signal is the exact string `"NotConfigured"` (PAT-1767 — the read succeeded and the setting is genuinely absent). Omitted/null means this rule uses `treat_unknown_as` for both states, which is also what every rule seeded before this field existed continues to do. |
| `applicable_arch` | no | null (all) | Omit or use `[]` to apply to all architectures. `["arm64"]` restricts to Apple Silicon. |
| `nist_mappings` | no | null | NIST SP 800-53 r5 control IDs. |
| `iso_mappings` | no | null | ISO 27001:2022 Annex A controls. |
| `cyber_essentials_mappings` | no | null | UK Cyber Essentials categories. |
| `pii_observed` | no | null | Documents PII exposure. **Required non-null before any T2 rule can be tenant-activated.** Use `"none"` to explicitly confirm no PII concern. |
| `requires_user_consent` | no | `false` | Set true if the signal reads user-specific data (e.g. a user `~/Library` plist). |
| `enabled` | no | `true` | Set false to import a rule in disabled state. |

### Comparators

Same semantics as the macOS pack — see CIS_RULES.md § Comparators.

| Comparator | Pass condition |
|---|---|
| `eq` | Observed value equals any element of `expected_values` |
| `in` | Synonym for `eq`; clearer for multi-value allow-lists |
| `neq` | Observed value does not equal any element of `expected_values` |
| `contains` | Observed value contains `expected_values[0]` as a substring |
| `gte` | Numeric: `float64(observed) >= float64(expected_values[0])` |
| `lte` | Numeric: `float64(observed) <= float64(expected_values[0])` |

---

## Validation

The tool validates before any write:

- Required pack fields present (`benchmark`, `benchmark_version`, `platform`)
- `platform` must be `macos` or `windows`
- At least one rule in the pack
- Each rule: required fields present, enum values legal, `expected_values` non-empty
- `control_identifier`, when present, must contain a non-blank authoritative value
- No duplicate `rule_key` values within the pack
- Unknown YAML keys are rejected (caught by strict YAML parsing at load time)

Per-rule errors are reported individually; all errors are reported before exit so you can fix them in one pass.

---

## Upsert behaviour

The import uses `INSERT ... ON CONFLICT (benchmark, benchmark_version, rule_key) DO UPDATE SET ...`. Authored columns except `id` and `created_at` are overwritten on conflict. `control_identifier` is presence-aware: an explicit non-blank value replaces the stored value, while omission preserves it. This means:

- **First import**: inserts all rules.
- **Re-import of unchanged pack**: updates every row (same values — idempotent in practice).
- **Amended pack (some rules changed)**: updates every row; changed values take effect immediately.
- **New rules added to the pack**: inserted; existing rules updated.

The importer does not provide an implicit identifier-clear operation. Clearing authoritative mapping evidence requires a deliberate SQL migration with its own review and rollback, rather than an omitted or blank YAML field.

Rules **removed** from the YAML are **not deleted** from the DB — deleting a live rule requires a deliberate SQL statement. This is intentional: the import tool is additive.

---

## T2 rules and PII gate

Before a T2 rule can be activated for any tenant, its row must have `pii_observed` non-null. The import tool does not enforce this gate — it will import T2 rules with null `pii_observed`. The gate is a process constraint enforced at tenant-activation time and documented in CIS_RULES.md § PII gate for T2 rules.

As a matter of practice: fill `pii_observed` (even if `"none"`) for every rule you import. It documents that you thought about it.

---

## Example — minimal Windows pack

```yaml
benchmark: "CIS Microsoft Windows Server 2022"
benchmark_version: "1.0.0"
platform: windows

rules:
  - rule_key: cis_win_1_1_1_password_history
    title: "Ensure 'Enforce password history' is set to '24 or more password(s)'"
    severity: medium
    signal_key: pw_history
    comparator: gte
    expected_values: ["24"]
    collection_tier: T1
    pii_observed: "none"

  - rule_key: cis_win_1_1_2_max_password_age
    title: "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
    severity: medium
    signal_key: pw_max_age_days
    comparator: lte
    expected_values: ["365"]
    collection_tier: T1
    pii_observed: "none"
```

```bash
# Dry-run first
DATABASE_URL="$PATCHED_DB_URL" patched-rules import --dry-run cis-windows-l1.yaml

# Import for real
DATABASE_URL="$PATCHED_DB_URL" patched-rules import cis-windows-l1.yaml
```
