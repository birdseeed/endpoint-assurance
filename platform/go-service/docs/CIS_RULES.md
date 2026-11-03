# CIS rule catalogue

The rule engine (`internal/evaluator`) applies the CIS Apple macOS L1 benchmark controls and the patched.im baseline ruleset to the compliance signals extracted from each device snapshot. Rules are data (rows in `compliance_rules`), not Go code — new rules, version bumps, and per-tenant exemptions are SQL changes, not redeploys.

> **Scope of this catalogue.** The detailed table below describes the macOS
> pack and its migrations. It is not a runtime inventory assertion: enabled
> rule counts change through migrations and tenant policy. Obtain a current
> count by applying ordered migrations then grouping live
> `compliance_rules` rows, as documented in
> [`contracts/portal-api.md`](../../contracts/portal-api.md#rule-count-source-of-truth).
> The Windows signal contracts remain in `PAYLOAD_SCHEMA.md` and
> `WINDOWS_T2_GAPMAP.md` rather than being re-tabulated here.

---

## Overview

**How a rule fires:**

1. The extractor checks the per-tenant, per-OS **master switch** (`tenants.macos_enabled` / `windows_enabled`). If the platform is disabled for the tenant, evaluation is skipped entirely — no `compliance_evaluations` rows are written. This overrides T1 always-on rules.
2. If the platform is enabled, the extractor calls `evaluator.LoadRules` to pull enabled T1 rows and `evaluator.LoadRulesForTenant` to pull enabled T2 rows for the tenant, both filtered by the device's platform.
3. It builds a flat `map[string]string` of signals from the payload (`buildSignalsMap` in `upsert.go:263`).
4. `evaluator.Evaluate(rules, signals, arch)` runs each rule against the signals map and returns one `Evaluation` per rule.
5. Evaluations are inserted into `compliance_evaluations` in the same transaction as the device/apps/signals data — a device is never in a state where signals exist but evaluations don't.

**Per-platform admin UI:** The admin UI (`dashboard.patched.im/admin`) shows macOS and Windows compliance as separate sections. Each section has a **master switch** (ON/OFF) backed by `GET`/`PUT /admin/tenant-platforms/{tenantID}`. The Windows section shows a clean empty state until the CIS Windows L1 rule pack is imported. When the master switch is OFF, the rule rows below are visually disabled (greyed / non-interactive) so the operator can still see what would be evaluated.

**Architecture decision:** rules are data so that new CIS releases, per-tenant exemptions, and backfill scenarios (`"what would today's rules say about last quarter's snapshot?"`) are SQL-only. See `migrations/0003_compliance_rules.sql:13-22` for the rationale.

---

## Rule structure

Each row in `compliance_rules` maps to the `evaluator.Rule` struct (`internal/evaluator/types.go`).

| Column | Go field | Type | Notes |
|---|---|---|---|
| `id` | `Rule.ID` | UUID | Primary key; referenced from `compliance_evaluations.rule_id` |
| `rule_key` | `Rule.RuleKey` | text | Slug, unique within `(benchmark, benchmark_version)`. E.g. `"cis_macos_2_5_1_1_filevault"` |
| `benchmark` | `Rule.Benchmark` | text | `"CIS Apple macOS"` or `"patched.im baseline"` |
| `benchmark_version` | `Rule.BenchmarkVersion` | text | `"v3.0.0"` for CIS; `"v1"` for patched.im rules |
| `control_identifier` | — | text, nullable | Authoritative identifier for this exact benchmark version. NULL is an explicit unmapped/non-CIS state; never infer it from `rule_key`. |
| `title` | `Rule.Title` | text | Display title in reports |
| `description` | — | text | Explanation for auditors and customers |
| `severity` | `Rule.Severity` | text | `"low"` / `"medium"` / `"high"` / `"critical"` |
| `signal_key` | `Rule.SignalKey` | text | The key in the `compliance_signals` / signals map to evaluate |
| `comparator` | `Rule.Comparator` | text | See [Comparators](#comparators) |
| `expected_values` | `Rule.ExpectedValues` | text[] | Semantics depend on comparator |
| `applicable_arch` | `Rule.ApplicableArch` | text[] | NULL = all architectures. e.g. `['arm64']` |
| `treat_unknown_as` | `Rule.TreatUnknownAs` | text | What status to emit when the signal is absent, or is `null` / the literal string `"Unknown"` — see [Treat-unknown-as policy](#treat-unknown-as-policy) |
| `treat_not_configured_as` | `Rule.TreatNotConfiguredAs` | text, nullable | What status to emit when the signal is the exact string `"NotConfigured"` (PAT-1767). NULL means "use `treat_unknown_as`" — see [Treat-not-configured-as policy](#treat-not-configured-as-policy-pat-1767) |
| `nist_mappings` | — | text[] | NIST SP 800-53 r5 control IDs |
| `iso_mappings` | — | text[] | ISO 27001:2022 Annex A controls |
| `cyber_essentials_mappings` | — | text[] | UK Cyber Essentials category |
| `enabled` | — | boolean | False = rule skipped by the engine. Current pack: all enabled. |
| `collection_tier` | — | text | `'T1'` = always-evaluate; `'T2'` = evaluate per `tenant_rules`; `'T3'` = out of scope. See below. |
| `pii_observed` | — | text | What personal data this signal could reveal. NULL = no PII concern. Required non-NULL before a T2 rule can be activated for any tenant. |
| `requires_user_consent` | — | boolean | True if the signal reads user-specific data. Blocks T2 activation without a documented consent story. |

### Comparators

Defined in `internal/evaluator/types.go` and enforced by SQL CHECK constraint.

| Comparator | Semantics |
|---|---|
| `eq` | Pass if `observed` equals any element of `expected_values` |
| `in` | Synonym for `eq`; use for multi-value allow-lists |
| `neq` | Pass if `observed` does not equal any element of `expected_values` |
| `contains` | Pass if `observed` contains `expected_values[0]` as a substring |
| `gte` | Numeric: pass if `float64(observed) >= float64(expected_values[0])` |
| `lte` | Numeric: pass if `float64(observed) <= float64(expected_values[0])` |

A non-numeric `observed` value against `gte`/`lte` emits `status = 'error'`.

### Evaluation statuses

| Status | Meaning |
|---|---|
| `pass` | Observed value satisfied the rule |
| `fail` | Observed value did not satisfy the rule |
| `not_applicable` | Rule skipped because of architecture mismatch (`applicable_arch` gate) |
| `error` | Rule configuration error (unsupported comparator or non-numeric value for numeric comparator) |

---

## Treat-unknown-as policy

The engine falls back to `treat_unknown_as` in two cases (PAT-1758):

- the key is absent from `compliance_signals` for a rule's `signal_key`, or
- the key is present but its value is the collector's literal "Unknown"
  sentinel (matched case-insensitively after trimming whitespace — both
  agents emit this on a signal they attempted to read but could not, per
  PAT-1710/1751/1752).

Both cases are treated identically: the comparator never runs against
"Unknown" as if it were a real observation, and `ObservedValue` is left nil
either way. `compliance_evaluations.observed_value` is NULL for both, which
is how downstream reporting (`internal/report/executive.go`) tells
undetermined evidence apart from a real, evidenced fail.

| Value | Default for | Rationale |
|---|---|---|
| `fail` | Almost all CIS L1 controls | Conservative for compliance — absence or unreadability of a signal from a control we check is a problem |
| `pass` | None currently | Reserved for controls where absence = Apple default = safe |
| `not_applicable` | None currently | Reserved for platform-specific controls on platforms we don't detect |

See `TestEvaluate_MissingSignal` in `internal/evaluator/evaluator_test.go:167` for the test that documents this policy.

---

## Treat-not-configured-as policy (PAT-1767)

When a signal's value is exactly the string `"NotConfigured"` — the read succeeded and the setting is genuinely absent, as opposed to `null`/`"Unknown"` (the read failed) — the engine resolves it via `treat_not_configured_as` instead of `treat_unknown_as`. A rule with `treat_not_configured_as = NULL` (every rule seeded before migration 0131, and any new rule that doesn't set it explicitly) falls back to that rule's `treat_unknown_as`, so adding this column never silently changes an existing rule's outcome. `effectiveTreatNotConfiguredAs` in `internal/evaluator/evaluator.go` is the one place that fallback is applied.

`"NotConfigured"` never reaches the comparator — it is resolved before `compare()` is called, the same way an absent signal is.

The six Windows NIST Schannel TLS rules (`nist_win_sc13_tls10_client_disabled`, `nist_win_sc13_tls10_server_disabled`, `nist_win_sc13_tls11_client_disabled`, `nist_win_sc13_tls11_server_disabled`, `nist_win_sc13_tls12_client_enabled`, `nist_win_sc13_tls12_server_enabled`) and `nist_win_si16_mandatory_aslr` are the only rules with `treat_not_configured_as` set as of migration 0131: `pass` for absent (OS default), `fail` for a genuine read failure (`treat_unknown_as`, changed from its original `pass`). See `migrations/0131_treat_not_configured_as.sql` for the full rationale — the Windows agent does not yet send `"NotConfigured"` for these signals, so they read as not-pass on un-upgraded agents until the agent update ships.

---

## Catalogue — migration-managed rule pack

Seeded by `migrations/0003_compliance_rules.sql`, `0006_t2_batch1.sql`,
`0007_t2_batch2.sql`, `0008_t2_batch3.sql`,
`0129_macos_2_10_2_password_after_screensaver_delay.sql`, and
`0130_macos_2_10_1_screensaver_inactivity.sql`. `migrations/0131_treat_not_configured_as.sql`
changes policy fields only. `cis_macos_2_10_1_screensaver_timeout` remains
retired rather than deleted so its historical `compliance_evaluations` keep
their original meaning. Query the live rule library for enabled counts; do
not infer them from this migration narrative.

### CIS Apple macOS v3.0.0 — Level 1

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Arch | Treat unknown |
|---|---|---|---|---|---|---|---|
| `cis_macos_2_5_1_1_filevault` | Enable FileVault | critical | `filevault` | eq | `["On"]` | all | fail |
| `cis_macos_2_5_3_sip` | Enable System Integrity Protection (SIP) | high | `sip` | eq | `["enabled"]` | all | fail |
| `cis_macos_2_5_2_1_gatekeeper` | Enable Gatekeeper | high | `gatekeeper` | in | `["enabled","assessments"]` | all | fail |
| `cis_macos_2_5_2_2_firewall` | Enable the Application Layer Firewall | high | `firewall` | eq | `["enabled"]` | all | fail |
| `cis_macos_2_5_5_sealed_system_volume` | Sealed System Volume integrity intact | high | `sealed_system_volume` | in | `["enabled","true"]` | all | fail |
| `cis_macos_1_4_auto_security_updates` | Auto-install macOS security updates | high | `auto_security_updates` | eq | `["On"]` | all | fail |
| `cis_macos_3_x_audit_logging` | Enable audit logging | medium | `audit_logging` | eq | `["enabled"]` | all | fail |
| `cis_macos_2_4_1_remote_apple_events` | Disable Remote Apple Events | medium | `remote_apple_events` | eq | `["Off"]` | all | fail |
| `cis_macos_2_4_4_remote_login` | Disable Remote Login (SSH) | high | `remote_login` | eq | `["Off"]` | all | fail |
| `cis_macos_2_4_10_screen_sharing` | Disable Screen Sharing | medium | `screen_sharing` | eq | `["Off"]` | all | fail |
| `cis_macos_2_10_screensaver_password` | Require password to wake from screen saver / sleep | medium | `screensaver_password` | in | `["Yes","DefaultAssumed"]` | all | fail |
| `cis_macos_2_10_2_password_after_screensaver_delay` | Ensure Require Password After Screen Saver Begins or Display Is Turned Off Is Enabled for 5 Seconds or Immediately | medium | `screensaver_delay_seconds` | lte | `["5"]` | all | fail |
| `cis_macos_2_10_1_screensaver_inactivity` | Ensure an Inactivity Interval of 20 Minutes or Less for the Screen Saver Is Enabled | medium | `screensaver_idle_seconds` | lte | `["1200"]` | all | fail |
| `cis_macos_5_1_auto_login_disabled` | Disable automatic login at boot | high | `auto_login_user` | eq | `["None"]` | all | fail |
| `cis_macos_1_1_pending_security_updates` | No outstanding macOS security updates | medium | `pending_updates_count` | eq | `["0"]` | all | fail |

### patched.im baseline

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Arch | Treat unknown |
|---|---|---|---|---|---|---|---|
| `patched_mdm_enrolment` | Device is MDM-enrolled | medium | `mdm_enrolled` | eq | `["Yes"]` | all | fail |
| `cis_macos_5_8_local_admin_count` | Limit local administrator accounts | medium | `local_admin_count` | lte | `["2"]` | all | fail |
| `cis_macos_5_x_password_policy_non_default` | Password policy must not be the Apple-default 4-character fallback | medium | `password_policy_is_default` | eq | `["No"]` | all | fail |
| `cis_macos_5_x_secure_boot_arm64` | Apple Silicon: Secure Boot integrity intact | high | `secure_boot` | in | `["Full Security","Valid"]` | arm64 only | fail |

The patched.im baseline coexists with CIS L1 in the same `compliance_rules` table and is evaluated by the same engine. It captures assurance checks that do not map exactly to a CIS control. MDM enrolment has a related CIS v2.1.0 control, but Patched does not establish its stricter User Approved MDM condition, so it deliberately has no CIS identifier.

PAT-1752 gives macOS and Windows the same neutral `mdm_enrolled` value. For one macOS updater compatibility release, the evaluator converts the deprecated `mdm_enrolment` value only when the neutral key is absent. A present `Unknown` never falls back, the bridge is scoped to this macOS rule, and `legacyMacOSMDMEnrolmentFallbackEnabled` is the explicit removal seam.

### CIS Apple macOS v2.1.0 — T2 batch 1

Added by `migrations/0006_t2_batch1.sql`. All require collector **v0.4.0** (schema_version 3). Devices on older collectors emit null for these signals → `treat_unknown_as = 'fail'` applies. Activated per-tenant via `tenant_rules`; no tenant has these enabled by default.

#### §5.2 — Password policy (parsed from `password_policy_raw` — no new shell cost)

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_5_2_1a_lockout_threshold` | Limit failed login attempts (≤ 5) | medium | `pwpolicy_lockout_threshold` | lte | `["5"]` | fail |
| `cis_macos_5_2_1b_lockout_reset_minutes` | Lockout observation window (≥ 15 min) | medium | `pwpolicy_lockout_reset_minutes` | gte | `["15"]` | fail |
| `cis_macos_5_2_2_min_length` | Minimum password length (≥ 15 chars) | medium | `pwpolicy_min_length` | gte | `["15"]` | fail |
| `cis_macos_5_2_7_max_age_days` | Maximum password lifetime (≤ 365 days) | medium | `pwpolicy_max_age_days` | lte | `["365"]` | fail |
| `cis_macos_5_2_8_history_depth` | Prohibit password reuse (≥ 15 generations) | medium | `pwpolicy_history_depth` | gte | `["15"]` | fail |

#### §1 — Software update enforcement (com.apple.SoftwareUpdate prefs)

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_1_2_update_check_auto` | Enforce automatic check for updates | medium | `update_check_auto` | eq | `["On"]` | fail |
| `cis_macos_1_3_update_download_auto` | Enforce automatic download of updates | medium | `update_download_auto` | eq | `["On"]` | fail |
| `cis_macos_1_5_app_updates_auto` | Enforce automatic App Store update install | medium | `app_updates_auto_install` | eq | `["On"]` | fail |
| `cis_macos_1_6a_xprotect_data_auto` | Enforce XProtect/Gatekeeper data auto-update | medium | `xprotect_data_auto_update` | eq | `["On"]` | fail |
| `cis_macos_1_6b_critical_updates_auto` | Enforce critical security update auto-install | medium | `critical_updates_auto_install` | eq | `["On"]` | fail |

### CIS Apple macOS v2.1.0 — T2 batch 2

Added by `migrations/0007_t2_batch2.sql`. All require collector **v0.5.0**. Devices on older collectors emit null for these signals → `treat_unknown_as = 'fail'` applies. Activated per-tenant via `tenant_rules`; no tenant has these enabled by default.

#### §2.3 — Sharing cluster (launchctl / cupsctl / mdmclient)

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_2_3_3_2_smbd_disabled` | Disable SMB File Sharing | medium | `smbd_disabled` | eq | `["Yes"]` | fail |
| `cis_macos_2_3_3_3_printer_sharing_disabled` | Disable Printer Sharing | medium | `printer_sharing_disabled` | eq | `["Yes"]` | fail |
| `cis_macos_2_3_3_5_remote_management_disabled` | Disable Remote Management (ARD) | medium | `remote_management_disabled` | eq | `["Yes"]` | fail |
| `cis_macos_2_3_3_7_internet_sharing_disabled` | Disable Internet Sharing | medium | `internet_sharing_disabled` | eq | `["Yes"]` | fail |

#### §4 — Network services (launchctl)

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_4_2_httpd_disabled` | Disable Built-in Web Server (Apache httpd) | medium | `httpd_disabled` | eq | `["Yes"]` | fail |
| `cis_macos_4_3_nfsd_disabled` | Disable Network File System Service (NFS) | medium | `nfsd_disabled` | eq | `["Yes"]` | fail |

#### §5 — Access control

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_5_1_3_amfi_enabled` | Enable Apple Mobile File Integrity (AMFI) | medium | `amfi_enabled` | eq | `["Yes"]` | fail |
| `cis_macos_5_6_root_disabled` | Disable Root Login | medium | `root_disabled` | eq | `["Yes"]` | fail |

### CIS Apple macOS v2.1.0 — T2 batch 3

Added by `migrations/0008_t2_batch3.sql`. All require collector **v0.6.0**. Devices on older collectors emit null for these signals → `treat_unknown_as = 'fail'` applies. Activated per-tenant via `tenant_rules`; no tenant has these enabled by default.

#### §2.10 — Screensaver timeout (reuses existing signal) — RETIRED, see below

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_2_10_1_screensaver_timeout` | Ensure Screen Saver Activates Within 20 Minutes | medium | `screensaver_delay_seconds` | lte | `["1200"]` | fail |

**Retired by `migrations/0129` (PAT-1746), `enabled = false`.** `screensaver_delay_seconds` is not the idle-to-activation interval this rule's title claims — it is the delay after the screen saver starts (or the display sleeps) before a password is required to unlock, read via `sysadminctl -screenLock status` on macOS 13+ and the legacy `askForPasswordDelay` plist key before that. The rule checked the wrong control: a device with a 20-minute idle timeout and only a 10-minute password grace period incorrectly passed it. The row is kept (not deleted or rewritten) so historical `compliance_evaluations` referencing it keep their original meaning. The correctly-scoped replacement for the password-delay control is `cis_macos_2_10_2_password_after_screensaver_delay` (T1, above), added by the same migration. The correctly-scoped replacement for this rule's original idle-to-activation intent is `cis_macos_2_10_1_screensaver_inactivity` (T1, above), added by `migrations/0130` (PAT-1753) once the updater agent started emitting the `screensaver_idle_seconds` signal (PAT-1720) that actually measures it.

#### §2.9 — Power management (pmset)

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_2_9_2_power_nap_disabled` | Disable Power Nap | low | `power_nap_disabled` | eq | `["Yes"]` | fail |
| `cis_macos_2_9_3_wake_on_network_disabled` | Disable Wake for Network Access | low | `wake_on_network_disabled` | eq | `["Yes"]` | fail |

#### §3.5 — Audit record permissions (one-pass over audit_control + /var/audit)

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_3_5_audit_control_no_acl` | Ensure /etc/security/audit_control Has No ACL | medium | `audit_control_no_acl` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_control_owner` | Ensure /etc/security/audit_control Is Owned by Root | medium | `audit_control_owner` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_control_group` | Ensure /etc/security/audit_control Is Group-Owned by Wheel | medium | `audit_control_group` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_control_mode` | Ensure /etc/security/audit_control Has Mode 440 or More Restrictive | medium | `audit_control_mode` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_folder_no_acl` | Ensure Audit Log Folder Has No ACL | medium | `audit_folder_no_acl` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_folder_owner` | Ensure Audit Log Folder Is Owned by Root | medium | `audit_folder_owner` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_folder_group` | Ensure Audit Log Folder Is Group-Owned by Wheel | medium | `audit_folder_group` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_folder_mode` | Ensure Audit Log Folder Has Mode 700 or More Restrictive | medium | `audit_folder_mode` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_logs_no_acl` | Ensure Audit Log Files Have No ACL | medium | `audit_logs_no_acl` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_logs_owner` | Ensure Audit Log Files Are Owned by Root | medium | `audit_logs_owner` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_logs_group` | Ensure Audit Log Files Are Group-Owned by Wheel | medium | `audit_logs_group` | eq | `["Yes"]` | fail |
| `cis_macos_3_5_audit_logs_mode` | Ensure Audit Log Files Have Mode 440 or More Restrictive | medium | `audit_logs_mode` | eq | `["Yes"]` | fail |

#### §5.4/5.5 — sudo configuration

| rule_key | Title | Severity | Signal key | Comparator | Expected values | Treat unknown |
|---|---|---|---|---|---|---|
| `cis_macos_5_4_sudo_timeout` | Ensure sudo Timeout Is Set to Zero | medium | `sudo_timeout_minutes` | lte | `["0"]` | fail |
| `cis_macos_5_5_sudo_timestamp_type` | Ensure sudo Uses Per-TTY Timestamps | medium | `sudo_timestamp_type` | eq | `["tty"]` | fail |

---

## Collection tiers and per-tenant policy

Added in `migrations/0005_tenant_rules.sql` (ADR-0001 action item 3). See `go-service/docs/adr/0001-cis-collection-scope.md` for the full rationale.

### Tiers

| Tier | `collection_tier` value | Who evaluates? | Inventory method |
|---|---|---|---|
| T1 — always-evaluate | `'T1'` | Every tenant, every device | Query live enabled rows after migrations |
| T2 — per-tenant | `'T2'` | Tenants with an `enabled = true` row in `tenant_rules` | Query live enabled rows after migrations |
| T3 — out of scope | `'T3'` | Nobody | Query live enabled rows after migrations |

**T1 rules** are evaluated for every device by `evaluator.LoadRules` (filtered to `collection_tier = 'T1'`). A `tenant_rules` row for a T1 rule adds an `override_severity` or suppresses the rule for that tenant — it does not control whether the rule evaluates.

**T2 rules** are evaluated only if an `enabled = true` `tenant_rules` row exists for the `(tenant_id, rule_id)` pair. A missing row means the rule does not evaluate for that tenant. The evaluator function `LoadRulesForTenant(ctx, pool, tenantID)` handles the per-tenant T2 slice; the extractor calls it per row and combines the result with the T1 set before calling `Evaluate`.

### tenant_rules

```
tenant_rules(tenant_id, rule_id, enabled, override_severity, suppression_reason, suppressed_until)
```

| Column | Purpose |
|---|---|
| `enabled` | T2: controls evaluation. T1: no effect on whether the rule runs. |
| `override_severity` | Tenant-specific severity; overrides `compliance_rules.severity` in evaluations and PDF reports. |
| `suppression_reason` | Operator note explaining the suppression (e.g. "accepted risk — compensating control in risk register"). |
| `suppressed_until` | Non-NULL future timestamp = rule is suppressed; NULL or past = active. |

Every mutation to `tenant_rules` must be recorded in the `tenant_rule_changes` audit table (append-only, never updated or deleted).

### PII gate for T2 rules

Before a T2 rule can be activated for any tenant, its `compliance_rules` row must have:
- `pii_observed` non-NULL (documenting what personal data the signal could reveal, or explicitly "none")
- `requires_user_consent` set accurately

This gate is a process constraint enforced by the code-review checklist, not a DB constraint (it's possible to insert a T2 rule with NULL `pii_observed` — don't).

---

## Adding a new rule

1. Write the SQL INSERT into `compliance_rules` following the existing pattern in `0003_compliance_rules.sql`. Choose a `rule_key` slug that encodes the benchmark reference (e.g. `cis_macos_X_Y_shortname`) or the patched.im baseline convention (`patched_<topic>`).
2. Set `collection_tier`: `'T1'` for always-evaluate controls, `'T2'` for per-tenant. Most new CIS L1 controls added in the T2 expansion batch are `'T2'`.
3. Fill `pii_observed` and `requires_user_consent`. For T2 rules, `pii_observed` must be non-NULL before the rule can be published to tenants. Even `'none'` is acceptable — it just means the reviewer confirmed no PII concern.
4. Create a new migration file (`0006_*.sql`, etc.) or append to an existing patch migration.
5. Write a test case in `internal/evaluator/evaluator_test.go` using `mkRule` + `Evaluate` to verify pass/fail/not-applicable behaviour. Mirror the pattern in `TestEvaluate_RealCISShape`.
6. Apply the migration: `psql -h example-api-host -U patched -d patched -f migrations/0006_your_rule.sql`.
7. The extractor picks up the new rule on the next batch — no restart required (rules are loaded once per batch, not cached longer).

**No Go code change is needed for a new rule.** The engine is generic: comparator + signal_key + expected_values is sufficient for every control in the v1 macOS pack.

---

## Framework mappings

Each CIS L1 rule carries non-normative framework mappings (`nist_mappings`, `iso_mappings`, `cyber_essentials_mappings`). These are stored in `compliance_rules` and denormalised into report output. Mappings are intentionally conservative — only included where the control is a direct corollary, not an approximate fit.

| Framework | Standard | Example |
|---|---|---|
| NIST | SP 800-53 r5 | `SC-28`, `SI-7`, `AU-2` |
| ISO | 27001:2022 Annex A | `A.8.24`, `A.12.5.1`, `A.9.4.2` |
| Cyber Essentials | UK NCSC | `secure-configuration`, `malware-protection`, `firewalls` |
