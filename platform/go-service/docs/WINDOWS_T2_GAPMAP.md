# Windows CIS L1 T2 expansion — gap-map

**Ticket:** PAT-405 (parity epic PAT-404, ADR-0007)
**Status:** living document — updated as batches land

## Why this exists

macOS has 52 CIS rules (17 T1 + 35 T2). Windows has 13 T1-only rules (migration `0019`). This maps the macOS T2 surface onto Windows equivalents so Windows reaches comparable depth.

## The gating constraint (read this first)

**A Windows rule can only pass/fail meaningfully if the collector emits the signal it evaluates.** As of `patched-agent-win v0.3.0`, the collector (`updater/windows/src/Service/ComplianceCollector.cs`) emits **exactly the 13 signals that already have T1 rules** — there is no spare signal to write a T2 rule against. So every T2 batch here is **collector-gated**: it needs a matching signal added to `ComplianceCollector.cs` before its rules return anything but the `treat_unknown_as='fail'` default.

We follow the **macOS pattern**: the rule pack (this repo) *declares the signal contract* with `treat_unknown_as='fail'`; the collector (updater repo) implements it in a paired version bump. Each macOS T2 batch did exactly this ("Collector must be on vX.Y.Z for non-null values"). The `signal_key` strings defined in each migration here are therefore the **authoritative contract** the collector must emit — snake_case, flat key in the `compliance` map, matching the existing 13.

Each batch ships as a pair: a migration here **+** a collector ticket in the `updater` workstream. Per ADR-0007 action item 4, the counterpart ticket opens in the same change.

## Payload conventions (from ComplianceCollector.cs / InventoryPayload.cs)

- `compliance` is a **flat** `Dictionary<string,object>`; keys are snake_case; values are strings (or ints for timeout-style fields). Server normalises all to strings.
- Boolean-style controls emit `"Yes"`/`"No"`/`"Unknown"`; state controls emit `"enabled"`/`"disabled"`; numerics emit the raw number.
- **Normalisation rule for "0 = disabled = fail" cases:** where a value of 0 means "never" (e.g. max password age 0 = never expires; lockout threshold 0 = never lock), the **collector clamps** it to a sentinel that fails the comparator (e.g. `99999` for an `lte` rule), so the rule pack can use a single clean comparator. This mirrors how macOS pre-normalises collector values. The clamp is specified per-signal in the batch migration comments.

## macOS T2 → Windows parity map

| macOS T2 group (rules) | Windows L1 analog | Windows source | Batch |
|---|---|---|---|
| §5.2 Password policy (5) | §1.1 Password Policy + §1.2 Account Lockout | `secedit /export` / `net accounts` | **1 (this PR)** |
| §3.5 Audit record perms (12) | §17 Advanced Audit Policy Configuration | `auditpol /get /category:*` | 2 |
| §5.4/5.5 sudo + §5 access (4) | §2.3.x Security Options (UAC behaviour, LSA, interactive logon) | registry (`HKLM\...\System`, `...\Lsa`) | 3 |
| §2.3 Sharing + §4 net services (6) | §18/services — SMBv1, ICS, unwanted features/services | service state / registry | 4 |
| §1 Software update detail (5) + §2.9 power (2) | §18.9 Windows Update granular + Defender extras (ASR, cloud, PUA) | registry (`...\WindowsUpdate`, `...\Windows Defender`) | 5 |

Target: ~13 T1 + ~40 T2 ≈ **53 Windows rules**, parity with macOS's 52. Counts are approximate — some controls are genuinely platform-specific each way (see below); parity means *equivalent coverage of the platform's CIS surface*, not identical rule IDs.

## Controls with no clean cross-platform equivalent (recorded, not forced)

- **macOS-only, no Windows analog:** AMFI (§5.1.3), Gatekeeper/XProtect data updates (§1.6) — Defender/SmartScreen are the rough Windows counterparts and are covered separately, not 1:1.
- **Windows-only, no macOS analog:** SMBv1 removal, reversible-encryption storage, Administrator-account-lockout — these are net-new Windows controls with no macOS line; they count toward Windows depth without a macOS twin.

This asymmetry is expected and fine under ADR-0007 — equivalent coverage, not mirrored rule IDs.

## Batch status

| Batch | Rules | Migration | Collector ticket | State |
|---|---|---|---|---|
| 1 — Account & Password Policy | 9 | `0024_windows_t2_account_policy.sql` | PAT-406 (`secedit`) | ✅ done — verified on win-staging |
| 2 — Advanced Audit Policy | 10 | `0025_windows_t2_audit_policy.sql` | PAT-423 (`auditpol`) | ✅ done — verified on win-staging |
| 3 — Security Options / UAC | 8 | `0026_windows_t2_security_options.sql` | PAT-425 (registry) | ✅ done — verified on win-staging |
| 4 — Services & features | 6 | `0027_windows_t2_services_features.sql` | PAT-427 (registry) | ✅ done — verified on win-staging |
| 5 — Defender policy detail | 6 | `0028_windows_t2_defender_policy.sql` | PAT-428 (registry) | rules authored; collector in progress |

Windows rule count after batch 5: 13 T1 + 39 T2 = **52** — **parity with macOS (52)**.
