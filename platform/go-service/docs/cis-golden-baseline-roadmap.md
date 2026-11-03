# CIS golden baseline — Intune config profiles (roadmap)

> **Roadmap capture, revised 2026-08-15.** PAT-1306 makes the content pack and the attended delivery runbook current work. The Graph renderer and control-plane surfaces remain deliberately deferred until real delivery volume justifies them.

_Migrated from Notion: https://www.notion.so/367054a7591881329a09f73910153ddf_

---

## Why this exists

Today Patched.im *measures* CIS Level 1 compliance — the agent collects signals, the evaluator scores them, reports go out. This is the other half: *establishing* compliance. A base set of Intune configuration profiles that bring a new client's Windows and macOS fleet up to CIS L1, deployed as a repeatable baseline for every client.

It closes a loop. Deploy the baseline → the next scan verifies it took effect → every later scan is drift detection against a known-good state. The deploy side and the scoring side become one system. It also turns the "compliance from zero" onboarding fee into a concrete deliverable.

## "Golden image" — the framing

For Intune-managed estates this is not a captured OS disk image. It is a **golden configuration baseline**: a versioned, reusable set of Intune configuration profiles, compliance policies, and settings-catalog definitions, held as code and replicated into each client's Intune tenant. Autopilot (Windows) and Automated Device Enrolment (macOS, via Apple Business Manager) enrol the device; the baseline then configures it. Modern endpoint management is configuration-as-policy, not image deployment — and config-as-code is the more powerful model because the baseline is versionable, diffable, and deployable through the Graph API.

## The source material — this already exists

Patched does not invent the baseline. CIS publishes Intune-specific benchmarks:

- **CIS Microsoft Intune for Windows 11 Benchmark** — v4.0.0 (April 2025). Written specifically for MDM/Intune-joined devices; ships as settings-catalog JSON you import into Intune.
- **CIS Microsoft Intune for Apple macOS Benchmark** — equivalent benchmark for macOS (Sonoma / Sequoia) via Intune.
- **macOS Security Compliance Project (mSCP)** — open-source; `generate_guidance.py -p -s baselines/cis_lvl1.yaml` generates `.mobileconfig` profiles, compliance scripts, and documentation for a chosen baseline. Supports the CIS Benchmarks; Intune-deployable.
- **CIS Build Kits** (CIS SecureSuite) — ready-made Intune settings-catalog content for the benchmarks.

Patched's value is not authoring the rules — it is curating, versioning, and *operationalising* a known-good baseline, deploying it per client, and tying it back to the scoring loop. The same CIS L1 Patched already scores against.

## Deployment model — config-as-code, per tenant

1. **Master baseline** lives in a git repo: Windows settings-catalog JSON + macOS `.mobileconfig` profiles + compliance policies, versioned.
2. **Per-client deploy** via Microsoft Graph or a tool such as **IntuneCD** (Python — exports config from a master/dev tenant and imports it into a production tenant, exactly the cross-tenant replication this needs) or **IntuneBackupAndRestore** (PowerShell, cross-tenant).
3. **Versioning** tracks both CIS benchmark revisions and OS versions (Windows 11 24H2, macOS Sequoia, etc.). A client's deployed baseline version is recorded.
4. **Enrolment first.** The baseline only lands on enrolled devices — Windows Autopilot; macOS ADE via Apple Business Manager. Unmanaged estates get an onboarding step — set up the tenant, enrol devices — before the baseline applies.

## macOS baseline — profile groups

Generated from mSCP `cis_lvl1.yaml`. Indicative grouping (exact keys come from the mSCP output — verify against the generated profiles):

- **Encryption** — FileVault enforced, recovery key escrow to Intune.
- **App security** — Gatekeeper enforced, app restrictions.
- **Firewall** — application firewall on, stealth mode.
- **Software update** — automatic check / download / install, deferral window.
- **Authentication & lock** — password policy (length, complexity, lockout), screen-saver lock with grace period.
- **System services** — disable remote login, screen sharing, remote management where not needed.
- **Audit & logging** — audit subsystem enabled, retention.
- **Restrictions** — content caching, AirDrop, iCloud document/desktop sync per policy.

Some CIS macOS controls cannot be enforced by a profile alone and need a deployed script — that split mirrors the existing agent's collect-side scripting and should be designed in.

## Windows baseline — profile groups

From the CIS Microsoft Intune for Windows 11 v4.0.0 settings-catalog JSON, optionally cross-referenced with the Microsoft Security Baseline. Indicative grouping:

- **BitLocker** — drive encryption enforced, recovery key escrow to Entra / Intune.
- **Microsoft Defender Antivirus** — real-time and cloud-delivered protection, PUA blocking, scan schedule.
- **Attack Surface Reduction (ASR) rules** — the CIS-recommended ASR rule set in Block mode.
- **Account & lockout policy** — password length / complexity, lockout threshold and duration.
- **Device lock** — screen-lock timeout, password on wake.
- **Windows Update** — update rings, deferral and deadline policy.
- **Firewall** — domain / private / public profiles configured.
- **Audit policy** — advanced audit configuration for the CIS-required categories.
- **Attack surface / hardening** — SmartScreen, scripting and macro restrictions, legacy-protocol disablement.

## Core vs tunable — the part that breaks things

A hardening baseline deployed wholesale to an in-use fleet *will* break something — ASR rules block line-of-business apps, firewall rules block tooling, update deadlines surprise users, password policy collides with existing accounts. The design must split:

- **Core** — universally safe CIS L1 controls, deployed unchanged for every client, non-negotiable.
- **Tunable** — controls that commonly need per-client adjustment (ASR rules, firewall exceptions, update windows, password policy). Deployed from the baseline but with a per-client exception process.
- **Staged rollout** — pilot ring → broad ring, never big-bang, per client.

This mirrors the product's existing T1 (always-on) / T2 (per-tenant) rule tiers — the same idea, on the deploy side.

## Per-tenant control management — the dashboard layer

The deploy side, the scoring side, and the management side are one system. Two dashboard requirements:

**Surface Windows CIS controls, toggled per tenant — like macOS.** The Compliance Admin (`/admin`) already manages macOS tenant rules via the `tenant_rules` model. Once Windows rules exist in `compliance_rules` — carrying the `platform` column from the schema-v3 work — the admin UI becomes platform-aware: rules grouped and filtered by platform, Windows rules toggled per tenant exactly as macOS rules are. Hard dependency on `compliance_rules.platform` (already in the schema-v3 migration).

**Per-OS master switch.** A per-tenant, per-platform "in scope" flag — already shipped (migration `0010`). A Windows-only client → flip macOS off → every macOS control disabled for that tenant and hidden from its dashboard and reports, in one action. The evaluator skips a disabled platform's rules; the dashboard and report generator hide them.

**The unifying idea — platform scope per tenant.** The same concept runs through both halves: a Windows-only client does not receive the macOS golden baseline *and* has macOS controls switched off in scoring.

## Risks and constraints

- **Breakage / liability.** Configuring a client's devices (vs only observing them) is a materially bigger responsibility — breakage is now partly Patched's. Staged rollout is mandatory; the contract and insurance posture must account for it. Lands alongside Patched.im Ltd. incorporation.
- **Profile conflicts** — multiple profiles, or a Microsoft baseline, touching the same setting.
- **macOS profile limits** — some CIS controls need a script, not just a profile; user-approval and FileVault key-escrow handling need care.
- **Benchmark churn** — CIS revises the benchmarks (Windows v4.0.0 was a large change); the baseline-as-code repo must track revisions.
- **Not blocked by incorporation.** Config profiles deployed via Intune need no Apple Developer ID or code signing — so this is buildable now, unlike the signed-installer work.

## Sequencing

Current ordering:

- Author the **versioned CIS L1 content pack** first under PAT-614, including the mapping from every deployable control to the Patched advisory rule that verifies it. Exact settings and values still require the licensed/current benchmark sources named below.
- Exercise the **attended delivery runbook** in [`FULL_ENDPOINT_MANAGEMENT_DELIVERY.md`](FULL_ENDPOINT_MANAGEMENT_DELIVERY.md). Customer-one delivery uses the Intune admin centre, controlled rings, and reconciled Intune plus Patched evidence.
- Keep PAT-613, PAT-615, PAT-616, and PAT-170 blocked until live engagements demonstrate repeated operations worth automating. They are scale tools, not prerequisites for customer one.
- The dashboard platform controls and per-OS master switch already exist on the measurement side. They do not authorise enforcement or replace the delivery evidence gate.
- Ownership: macOS baseline → Andy; Windows baseline → Andy; the seam is the shared CIS L1 definition.

## Open questions

- Separate professional-services offering vs bundled into onboarding + monthly.
- How per-client exceptions are recorded and surfaced — and whether they feed the score as accepted-risk.
- Whether Patched holds one master baseline tenant, or each client's baseline is generated fresh.
- Pricing of the onboarding deployment.

## Verification note

Profile groupings and control areas above are accurate to the CIS L1 structure, but exact settings-catalog identifiers and values must be taken from the live CIS Microsoft Intune benchmarks (Windows 11 v4.0.0; the macOS Intune benchmark) and the mSCP-generated output when the baseline is actually built. Do not treat the indicative lists as the final setting list.
