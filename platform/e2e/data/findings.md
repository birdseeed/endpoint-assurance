# T2 Compliance Signal/Rule Coverage Audit — findings.md
## PAT-739, task T2

---

> **SUPERSEDED (2026-07-14).** This is a point-in-time PAT-739 audit. Its central
> finding below, that neither agent emits `compliance_findings[]` and therefore the
> disk-encryption / removable-storage CIS rules (migration 0033, `treat_unknown_as='pass'`)
> silently evaluate PASS, is **no longer true**. Both agents now emit `compliance_findings[]`:
> the macOS collector via `macos/lib/compliance_findings.sh` (PAT-743), sourced and spliced
> into the payload by `patched-collect.sh`; the Windows service via
> `StatusWriter.DetectComplianceFindings()`, wired into `InventoryPoster.BuildPayload()`
> so the finding is set on the posted `InventoryPayload` (both in `Patched-LTD/updater`).
> The specific coverage gaps in sections (b) and (d) below (both agents send an
> empty/absent findings array) are closed. Sections (a) and (c) remain a useful
> historical snapshot of rule counts and signal coverage. Read the sections below as a
> record of the state at audit time, not the current system.

---

## (a) Rule counts by platform and tier

| Platform | Tier | Count | Source migrations |
|----------|------|-------|-------------------|
| macos    | T1   | 17    | 0003 (backfilled T1 by 0005) |
| macos    | T2   | 73    | 0006 (10), 0007 (8), 0008 (17), 0040 (38) |
| windows  | T1   | 13    | 0019 |
| windows  | T2   | 58    | 0024 (9), 0025 (10), 0026 (8), 0027 (6), 0028 (6), 0041 (19) |
| macos (findings) | T1 | 2 | 0033 |
| windows (findings) | T1 | 2 | 0033 |
| **TOTAL** | | **165** | |

**macOS total: 90. Windows total: 71. Findings: 4. Grand total: 165.**

This exactly matches the expected ballpark (90 macos + 71 windows + 4 findings = 165). No rules were found to have been disabled or deleted by any subsequent migration — all UPDATE/DELETE statements in the scanned migrations were schema changes (adding columns, backfilling platform), not deactivations.

---

## (b) Rules whose signal_key no collector emits (broken coverage)

All four findings-based rules (migration 0033) are RULE_WITHOUT_SIGNAL on both platforms:

| rule_key | platform | signal_key |
|----------|----------|------------|
| patched_macos_disk_encryption_off | macos | disk_encryption_off |
| patched_win_disk_encryption_off | windows | disk_encryption_off |
| patched_macos_removable_storage_unencrypted | macos | removable_storage_unencrypted |
| patched_win_removable_storage_unencrypted | windows | removable_storage_unencrypted |

**macOS:** `patched-collect.sh` never emits a `compliance_findings` key or a `disk_encryption_off` / `removable_storage_unencrypted` key in its JSON output. Grep of the full heredoc (lines 649-792) and all lib/*.sh files returns no match.

**Windows:** `StatusWriter.DetectComplianceFindings()` (StatusWriter.cs:102-126) detects `disk_encryption_off` and `removable_storage_unencrypted` via WMI, but writes them exclusively to the tray status file (`update-status.json`) via `StatusWriter.WriteAtomic()`. `InventoryPayload.cs` has no `compliance_findings` field. `InventoryPoster.BuildPayload()` never calls `DetectComplianceFindings()` and does not populate any findings list in the POST body.

**Net effect (as at audit time; see SUPERSEDED banner):** The server-side `buildSignalsMap` (upsert.go:462-488) loops over `p.ComplianceFindings[]` to populate signal entries, but since both agents send an empty/absent array, these signals are never written to `compliance_signals`. Both findings rules use `treat_unknown_as = 'pass'`, so they silently evaluate as PASS for every device, meaning real violations are never surfaced through the compliance framework. **This is fixed:** both agents now emit `compliance_findings[]` (macOS PAT-743; Windows `DetectComplianceFindings` wired into `BuildPayload`), so `buildSignalsMap` receives real findings and the rules no longer default-PASS.

**Recommendation:** The macOS collector needs a `compliance_findings[]` array added to its JSON output (with a FileVault check emitting `disk_encryption_off` when off). For Windows, `InventoryPoster.BuildPayload()` needs to call `StatusWriter.DetectComplianceFindings()` (or an equivalent method) and include the result as a `compliance_findings` field in `InventoryPayload`. The InventoryPayload.cs record needs a new `compliance_findings` property matching the server contract (`json:"compliance_findings,omitempty"`).

---

## (c) Collector signals with no rule (inventory-only, expected for some)

**macOS only** — 4 signals emitted by `patched-collect.sh` compliance{} block with no corresponding rule:

| signal_key | source | notes |
|------------|--------|-------|
| xprotect_version | lib/updates.sh | Inventory/informational; version string, not a pass/fail control |
| mrt_version | lib/updates.sh | Inventory/informational; same reasoning |
| password_policy_present | lib/auth.sh | Intermediate; `password_policy_is_default` (ruled) is derived from this |
| password_policy_raw | lib/auth.sh | Raw XML blob used server-side for parsing pwpolicy_* signals; not directly rule-able |

**Windows:** Zero. Every signal emitted by `ComplianceCollector.Collect()` has a corresponding rule.

These are expected — xprotect_version and mrt_version are version trackers, password_policy_raw is the raw source for T2 password rules.

---

## (d) compliance_findings[] wire format — definitive answer

### Server-side expectation (upsert.go:457-488)

`buildSignalsMap` at `go-service/internal/extractor/upsert.go:462` merges two sources:
1. `p.Compliance` (the flat compliance dict) — emitted by both agents
2. `p.ComplianceFindings[]` (the findings array) — mapped as: if `f.Volumes` is non-empty, `out[f.ID] = string(f.Volumes)`; otherwise `out[f.ID] = "Fail"`

The payload struct at `payload.go:44` declares:

```go
ComplianceFindings []complianceFinding `json:"compliance_findings,omitempty"`
```

This is the wire field both agents must populate for findings rules to fire.

### macOS agent (updater/macos/patched-collect.sh)

The macOS collector does **NOT** emit `compliance_findings` in its JSON output. The compliance{} heredoc (lines 683-778) has no `compliance_findings` key and no `disk_encryption_off` or `removable_storage_unencrypted` key. No lib/*.sh file sets variables for these signals. The macOS agent has zero compliance_findings support.

### Windows agent (updater/windows/src/Service/)

The Windows agent detects findings in `StatusWriter.DetectComplianceFindings()` (StatusWriter.cs:102-126):
- `disk_encryption_off`: emitted when WMI Win32_EncryptableVolume for C: has ProtectionStatus != 1
- `removable_storage_unencrypted`: emitted when USB/removable volumes lack BitLocker To Go protection

These findings are stored in the `UpdateStatus.ComplianceFindings` field and written to `%ProgramData%\Patched\update-status.json` for the tray to read.

`InventoryPayload.cs` (the POST /v1/inventory schema) has **no** `compliance_findings` field. `InventoryPoster.BuildPayload()` (InventoryPoster.cs:100-138) does **not** call `DetectComplianceFindings()`. The inventory POST body never contains `compliance_findings`.

### Verdict

| Agent | Detects findings? | Includes in POST /v1/inventory? | Tray file only? |
|-------|------------------|--------------------------------|-----------------|
| macOS | No | No | No |
| Windows | Yes (StatusWriter.cs:102-126) | No (InventoryPayload.cs has no field; InventoryPoster never calls DetectComplianceFindings) | Yes |

### How findings become signals — the mechanics

`buildSignalsMap` (upsert.go:471-483):
```go
for _, f := range p.ComplianceFindings {
    if f.ID == "" { continue }
    if len(f.Volumes) > 0 && string(f.Volumes) != "null" {
        out[f.ID] = string(f.Volumes)
    } else {
        out[f.ID] = "Fail"
    }
}
```

When the finding is absent, nothing is written → signal absent → `treat_unknown_as = 'pass'` (per migration 0033) → rule evaluates PASS. When present, the signal value is `"Fail"` (or the volumes JSON). The rule comparator `eq ['Pass']` then evaluates FAIL (violation detected). This logic is correct, but neither agent feeds it real data via the POST body.

---

## (e) Value-vocabulary mismatches

Checked 20+ rules spanning T1 (0003, 0019), T2 batches (0006-0008, 0024-0028), and the newest packs (0040, 0041). No vocabulary mismatches found in the rules checked.

**Sample verified (rule → collector emission):**

| rule_key | expected_values | collector emits | verdict |
|----------|----------------|-----------------|---------|
| cis_macos_2_5_1_1_filevault | ["On"] | "On"/"Off"/"Unknown" (fdesetup status awk) | OK |
| cis_macos_2_5_2_1_gatekeeper | ["enabled","assessments"] | "enabled"/"assessments" (spctl --status) | OK |
| cis_macos_2_10_screensaver_password | ["Yes","DefaultAssumed"] | "Yes"/"No"/"DefaultAssumed" (macOS 26 com.apple.screensaver missing key → DefaultAssumed) | OK |
| cis_macos_5_x_secure_boot_arm64 | ["Full Security","Valid"] | string from bputil (macOS 26: parses "Pairing Integrity" field) | OK |
| cis_macos_5_7_screensaver_unlock_group | ["authenticate-session-owner"] | authorizationdb group string verbatim | OK |
| cis_macos_3_4_audit_retention_expire | ["Yes"] | "Yes"/"No" (filesystem.sh parses audit.control expire-after) | OK |
| cis_macos_1_7_update_deferral_days | lte 30 | integer (managed_prefs.sh) | OK |
| cis_macos_2_2_2_firewall_stealth_mode | ["Yes"] | "Yes"/"No" (security.sh socketfilterfw) | OK |
| cis_macos_2_3_2_time_server_enforced | ["Yes"] | "Yes"/"No" (managed_prefs.sh) | OK |
| cis_macos_2_3_4_2_time_machine_encrypted | ["Yes"] | "Yes"/"No"/"Unknown" (filesystem.sh) | OK |
| cis_win_18_10_11_bitlocker_os_drive | ["On"] | "On"/"Off"/"Unknown" (ProtectionStatus == 1 → "On") | OK |
| cis_win_18_9_45_defender_realtime | ["enabled"] | "enabled"/"disabled" (DisableRealtimeMonitoring) | OK — but inverted convention vs all other T1 rules |
| cis_win_18_10_56_2_rdp_disabled | ["disabled"] | "enabled"/"disabled" (fDenyTSConnections == 0 → "enabled") | OK |
| cis_win_17_1_1_audit_credential_validation | ["Success and Failure"] | verbatim auditpol string | OK |
| cis_win_17_2_2_audit_security_group_management | contains ["Success"] | "Success and Failure" contains "Success" | OK |
| cis_win_17_5_1_audit_account_lockout | contains ["Failure"] | "Success and Failure" contains "Failure" | OK |
| cis_win_account_lockout_threshold | lte 5 | integer (secedit; 0 clamped to 5 by collector) | OK — 0=disabled clamped by design |
| nist_win_ia7_fips_mode | ["Yes"] | "Yes"/"No"/"Unknown" (Enabled == 1 → "Yes") | OK |
| nist_win_sc28_bitlocker_cipher | ["Yes"] | "Yes"/"No" (enc in {2,4,7} → "Yes") | OK |
| nist_win_sc39_vbs | ["Yes"] | "Yes"/"No"/"Unknown" (VirtualizationBasedSecurityStatus == 2 → "Yes") | OK |
| nist_win_au11_security_log_max_size | gte 196608 | integer KB (registry or sys bytes/1024) | OK |
| nist_win_si3_defender_definition_age | lte 1 | integer days (AntivirusSignatureAge WMI) | OK |
| nist_win_si3_asr_ransomware | ["Yes"] | "Yes"/"No"/"Unknown" (ASR rule GUID value "1") | OK |
| cis_win_19_1_3_4_screensaver_timeout | lte 900 | integer seconds; omitted when policy key absent → treat_unknown_as='fail' applies | OK |
| nist_win_tls10_client_disabled | ["Yes"] | "Yes"/"No"/"Unknown" (registry key; absent → "Unknown") | OK — treat_unknown_as='pass' |
| nist_win_laps_enrolled | ["Yes"] | "Yes"/"No"/"Unknown" | OK — treat_unknown_as='pass' |

**One near-miss noted (not a mismatch, but fragile):**

`cis_win_18_9_45_defender_realtime` rule expects `eq ["enabled"]`. Every other T1 Windows rule uses `["Yes"]`/`["No"]`/`["On"]`/`["Off"]`. The `"enabled"`/`"disabled"` vocabulary is isolated to this one rule and is internally consistent (collector and rule agree), but it diverges from the Yes/No convention used everywhere else. Future rule authors adding a Defender rule who follow the convention will get a mismatch unless they check the existing Defender signal vocabulary.

**No mismatches found across all 20+ rules sampled.**

---

## Summary table

| Category | Count |
|----------|-------|
| Total rules in DB | 165 |
| macOS rules (T1+T2) | 90 |
| Windows rules (T1+T2) | 71 |
| Findings rules | 4 |
| Rules with full collector coverage (OK) | 161 |
| RULE_WITHOUT_SIGNAL (broken coverage) | 4 |
| SIGNAL_WITHOUT_RULE (inventory-only, macOS) | 4 |
| Value-vocabulary mismatches found | 0 |
