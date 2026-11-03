# ADR-0004: Non-Intune endpoint delivery rail

**Status:** Proposed, incorporation gate lifted (see 2026-09-13 note below); still Proposed only because action item 1 (Andy's formal acceptance) remains open.
**Deciders:** Andy (v2 decision, per ADR-0002) — pending
**Spike:** PAT-67 — investigation commissioned 

**Update:** Reframed as Andy's v2 call — Andy owns all workstreams including Windows.

**Update (2026-09-13, PAT-1700):** Incorporation is complete: Patched.im Ltd, Isle of Man company number 139269C. Every "Blocked until incorporation completes" / "pre-incorporation" gate in this ADR (the signing-dependency rows for Option M-A and Option W-A, and action item 6) is lifted: Apple Developer Programme enrolment and Authenticode/EV certificate acquisition can now proceed. This does not change the decision recorded below, and it does not itself accept the ADR; action item 1 (Andy's acceptance of the bootstrap-rail recommendation) is still outstanding, which is why Status stays Proposed rather than Accepted.

---

## Context

ADR-0002 decided the v1 endpoint client on both platforms is an **Intune-deployed script**: `patched-collect.sh` on macOS and a PowerShell collector on Windows. It deferred the native-agent question to a joint macOS + Windows v2 decision and named **"a confirmed non-Intune customer"** as one trigger that would strengthen the case to reopen it.

This ADR investigates whether that trigger condition is already met — specifically, whether a meaningful share of the target IoM SME market operates without Intune, or without any MDM at all — and what the minimum viable non-Intune delivery rail looks like on each platform. It does **not** take the decision. It assembles evidence and makes a recommendation for the joint v2 call.

### The three components — do not conflate them

ADR-0002's framing holds: the "endpoint client" bundles three separable things.

| Component | What it is | Status |
|-----------|------------|--------|
| **Collector** | CIS L1 compliance-signal gatherer | Decided: script (ADR-0002). Not in question here. |
| **Updater** | Third-party app patching (`updater` repo) | Separate product surface. Bundling analysed in §5 below. |
| **Delivery + lifecycle rail** | How the client is installed, scheduled, configured, updated, and removed | **The gap this ADR addresses.** |

The collector script is already MDM-agnostic at runtime: it runs locally, reads the CIS surface, and POSTs to the ingest endpoint with bearer + HMAC auth. It calls no Graph or Intune API. What a non-Intune customer loses is not the collection; it is the **rail** — install mechanism, scheduled-task / LaunchDaemon provisioning, config delivery, and the Intune-redeploy update path. That rail gap is the subject of this ADR.

---

## 1. Market evidence: how common is non-Intune in the IoM SME target?

### 1.1 What the research repo says

The IoM market materials (`research/daf/`) describe the target as regulated IoM SMEs in fiduciary/financial services, e-gaming, legal, and healthcare. The DAF Research Brief characterises this market as one where **"businesses hold data-rich regulated estates but IT governance has historically been informal"** — implicitly an estate where formal MDM is the exception. The explainer notes that for a credible DAF posture, a business must move from *"we think the fleet is mostly fine"* to a position of actual evidence, which implies the current state in many targets is unmanaged or lightly managed.

ADR-0001 records that the first end-to-end demo was run on **Andy's own daily-driver Mac, never MDM-managed**, scoring 70.6% compliance — a deliberate choice because that machine represents the median IoM SME endpoint, not a managed outlier.

Build-notes describe the target sales motion as "compliance is the compelling event, not patching" and "buyers respond to 'tell me what's wrong with my fleet'" — language that assumes the prospective customer does not already know the state of their fleet. A fleet under active Intune management would already have partial visibility; the pitch lands strongest against estates with no visibility, which means no MDM.

### 1.2 UK SME MDM adoption data

Published hard data on MDM adoption among UK SMEs under 250 employees is sparse. The best proxies available:

- UK businesses with **50+ employees** show approximately **78% MDM adoption** as of 2025 (Expert Insights / IDG). This implies roughly 22% of mid-SMEs have no MDM — and the rate is materially higher for micro- and small businesses (under 50 employees).
- Cyber Essentials certifications: approximately **190,000 total certifications** have been issued since the scheme launched in 2014 across all UK business sizes. Against a UK business population of ~5.5 million, this implies that even the most basic device-control posture (which Cyber Essentials recommends but does not mandate MDM for) is absent in the vast majority of organisations.
- NCSC "10 Steps" guidance lists MDM as a recommended control but reports show it is one of the least-consistently-implemented steps in businesses under 100 employees.
- **No IoM-specific data exists.** Crown Dependencies follow UK regulatory frameworks but no IoM-specific MDM adoption statistics have been published.

### 1.3 Assumption this ADR rests on

**No hard IoM-specific MDM-adoption figure exists. ADR-0004 proceeds on the following assumption, which Andy should validate:**

> *The majority of IoM regulated SMEs in the target verticals (financial services, legal, e-gaming, healthcare, under ~100 employees) do not have Intune properly stood up. A material fraction — estimated at over half — have no MDM at all. This estimate is based on the UK SME proxy data above, the character of the IoM market as described in the research materials, and first-hand observation (Andy's network). It is not confirmed by a published survey of IoM fleets.*

The practical consequence: if this assumption holds, "deploy via Intune" is a barrier to entry for the median IoM prospect, not a convenience. ADR-0002's v2 trigger condition — "a confirmed non-Intune customer" — is likely to be met by the first or second design-partner conversation, not at some later stage of growth.

### 1.4 The DAF framework as a forcing function

The Isle of Man Data Asset Foundations framework (Royal Assent granted ~20 May 2026, Foundations (Amendment) Act 2026) requires DAF registrants to maintain audit trails, enforceable access rules, and a remediation-period regime. The compliance requirement lands directly on the endpoint estate. This framework is aimed at exactly the IoM SME verticals Patched.im targets.

The consequence for delivery: DAF-motivated prospects will include organisations that have never needed MDM, whose regulatory-driven interest in endpoint compliance is new, and who will not be willing to adopt Intune as a prerequisite for enrolling a compliance product. **A non-Intune rail is a sales-prerequisite, not a nice-to-have, for this segment.**

---

## 2. Rail-gap enumeration: what Intune provides that a non-Intune customer loses

### 2.1 macOS rail (current: `patched-collect.sh` via Intune)

| Lifecycle stage | What Intune currently provides | What a non-Intune customer loses |
|-----------------|-------------------------------|----------------------------------|
| **Initial install** | Intune pushes `patched-collect.sh` to `/usr/local/patched/` as a Shell Script policy, running as root | Delivery mechanism. The customer must run an installer or execute a bootstrap manually. |
| **LaunchDaemon provisioning** | The Intune shell-script deployment creates and loads `com.patched.collect.plist` as part of the script's own install logic | Nothing, if the bootstrap script creates the plist itself. The script already writes its own plist in the current design. |
| **Configuration delivery** | Intune script parameters pass tenant token and ingest endpoint | The bootstrap must receive these (URL parameter, environment variable, or interactive prompt). |
| **Update path** | Intune redeploys the script with updated content. No in-script self-update exists. | **Full update capability.** No mechanism currently exists to update the collector without Intune. |
| **Uninstall / cleanup** | Intune runs a removal script policy | The bootstrap's companion uninstaller must do this instead. |

### 2.2 Windows rail (current: PowerShell collector via Intune)

| Lifecycle stage | What Intune currently provides | What a non-Intune customer loses |
|-----------------|-------------------------------|----------------------------------|
| **Initial install** | Intune pushes the PowerShell script to a protected path as a Device Management script policy, running as SYSTEM | Delivery mechanism. Customer must run a bootstrap manually or receive a package. |
| **Scheduled Task provisioning** | The Intune script creates and registers `patched-runner` as a Scheduled Task via `Register-ScheduledTask` | Nothing, if the bootstrap script registers the task itself. The Windows collector already self-registers its Scheduled Task. |
| **Configuration delivery** | Intune script parameters pass tenant token and ingest endpoint | The bootstrap must receive these. |
| **Update path** | Intune redeploys the script with new content. No in-script self-update exists. | **Full update capability.** No mechanism currently exists to update the collector without Intune. |
| **Uninstall / cleanup** | Intune runs an uninstall script via Device Management policy | The bootstrap's companion uninstaller must do this instead. |

**Key finding:** The most significant gap is the **update path**. Everything else — scheduling, configuration, uninstall — can be handled by a bootstrap script that the customer runs once. The update path requires an always-on mechanism that the collector itself triggers. This is the one new component that does not exist in the v1 Intune model and must be built regardless of which non-Intune rail option is chosen.

---

## 3. Minimum self-contained rail options

### 3.1 macOS options

#### Option M-A: Notarized signed `.pkg` installing a LaunchDaemon

A `.pkg` package (macOS flat package) is the native macOS install format. The customer double-clicks it (or runs `installer -pkg patched.pkg -target /`) and Gatekeeper presents a standard install flow. The package installs the collector script, writes and loads the LaunchDaemon plist, and leaves a version file for the self-update check.

| Dimension | Assessment |
|-----------|------------|
| Effort | 2–3 days: `pkgbuild` + `productbuild` build pipeline; notarization CLI via `xcrun notarytool`; Gatekeeper testing |
| Signing dependency | **Blocked until incorporation.** Requires a **Developer ID Installer** certificate, issued by Apple only to enrolled Apple Developer Programme members (individual or organisation). Incorporation gates the DUNS number and Apple enrolment. An unsigned `.pkg` is quarantined by Gatekeeper on macOS 15+ and will not install without explicit security override from the user — not acceptable for a product. |
| Recurring cost | Apple Developer Programme: £99/year (included in the incorporation roadmap as a known cost). No per-install cost. |
| Security / Gatekeeper | Notarized `.pkg` clears Gatekeeper automatically. No user security warning. |
| Self-update mechanism | The installer drops a version pint at a fixed path. The LaunchDaemon's daily run checks `GET https://api.patched.im/v1/version?platform=macos`; if the response version exceeds the pinned version, the collector downloads and runs the updated `.pkg` with `installer -pkg … -target /` as root. This is a pull-based update symmetric to the existing ingest POST. |
| Robustness | Strong. Native install format; survives reboots, OS upgrades, user profile changes. |
| Customer install friction | Low. Double-click install with tenant-token passed as command-line argument to `installer`, or embedded in a preflight script. |
| Risk | Medium pre-incorporation (blocked); Low post-incorporation. |

**Status: Preferred post-incorporation path. Blocked until incorporation completes.**

#### Option M-B: Shell bootstrap (`curl | sudo bash`) writing plist directly

A single zsh/bash bootstrap script, delivered by URL or as a file download, is run by the customer's IT contact with `sudo`. It installs `patched-collect.sh` to `/usr/local/patched/`, writes and loads the LaunchDaemon plist, and writes a version pin.

| Dimension | Assessment |
|-----------|------------|
| Effort | 1 day: bootstrap script; uninstaller; self-update function embedded in collector |
| Signing dependency | **None. Shell scripts are not subject to macOS Gatekeeper notarization.** Gatekeeper applies to binary executables and installer packages, not to `.sh`/`.zsh` files. Running a script with `sudo` is explicit user intent — macOS does not quarantine it. |
| Recurring cost | None beyond the existing ingest infrastructure. The bootstrap download URL adds one static-file route or a CDN path. |
| Security / Gatekeeper | The bootstrap runs as root via explicit `sudo` — Gatekeeper is bypassed by user intent. This is the same model as Homebrew, Tailscale CLI, and virtually every developer tool. The collector script itself is unchanged. |
| Self-update mechanism | The collector's daily run checks `GET https://api.patched.im/v1/version?platform=macos`. If the remote version exceeds the local pin, the collector fetches and atomically replaces itself via `curl -L … > /usr/local/patched/patched-collect.sh.tmp && mv`. Root privilege is already present (LaunchDaemon runs as root). |
| Robustness | Adequate. LaunchDaemon runs at boot; survives reboots. Potential failure modes: manual deletion of the plist (recoverable via re-run of bootstrap); macOS update moving the plist (mitigated by the 2026 macOS parser-change handling already in the collector). |
| Customer install friction | Medium. Requires the customer to open Terminal and paste a `sudo` command. Not click-through. For a regulated IoM SME, this friction is acceptable for a one-time install — it is the same friction as any developer tool or server agent. |
| Risk | Low. No new technology; mirrors the existing Intune-delivered model at the script level. |

**Status: Available now (pre-incorporation). Recommended as the immediate unblocking path.**

#### Option M-C: Signed `.pkg` without notarization (interim, not recommended)

A Developer ID-signed but not notarized `.pkg` requires the customer to right-click and choose "Open" to bypass Gatekeeper, or to set `spctl --master-disable` globally. This is unacceptable for a product: it trains customers to bypass a security control that exists to protect them, and for a compliance product that is a brand and trust liability.

**Rejected.**

### 3.2 Windows options

#### Option W-A: Signed MSI installing a Windows Service

An MSI package (Windows Installer) installs a Windows Service that wraps the PowerShell collector, provides clean install/uninstall via `msiexec`, and self-manages its scheduled execution. This is the ADR-0002 Option A territory.

| Dimension | Assessment |
|-----------|------------|
| Effort | High: Windows Service wrapper (Go or C#), WiX/MSBuild installer toolchain, CI signing pipeline, testing on Windows 10/11 and Server 2019/2022 |
| Signing dependency | **Blocked until incorporation.** Requires an **Authenticode / EV code-signing certificate** from a Microsoft-trusted CA (DigiCert, Sectigo, etc.). EV certificates require a legal entity and physical verification — incorporation is a prerequisite. Lead time from a CA: 5–15 business days post-incorporation. SmartScreen reputation cold-start: months of installs before the binary stops triggering "Windows protected your PC." |
| Recurring cost | EV cert: ~£250–400/year. SmartScreen reputation: no cash cost but multi-month time cost. |
| Security reputation | High risk during the cold-start period. For a compliance product, triggering SmartScreen on the installer is a first-impression failure — a security-conscious buyer will not proceed. |
| Self-update | Built into the Service or via a companion update task. Can check a versioned endpoint, download a new MSI, and run `msiexec /i new.msi /quiet`. |
| Robustness | High. Windows Service lifecycle is well-understood; survives reboots and Windows Update. |
| Customer install friction | Low post-incorporation. Double-click install, standard Windows flow. |
| Risk | High pre-incorporation (blocked + SmartScreen); Medium-Low post-incorporation + reputation-warm. |

**Status: Preferred post-incorporation, post-SmartScreen-warm path. Blocked until incorporation completes. Not available for the near-term non-Intune use case. Aligns with ADR-0002 v2 native-agent direction.**

#### Option W-B: PowerShell bootstrap registering a Scheduled Task + pull self-update

A PowerShell bootstrap script (`.ps1`), delivered as a file download or via a short one-liner, is run by the customer's IT contact with administrator rights. It installs the collector to `C:\Program Files\Patched\`, registers a Scheduled Task (`patched-collect`) to run daily as SYSTEM, writes a version pin, and registers an uninstaller entry. The collector's daily run includes a self-update check.

| Dimension | Assessment |
|-----------|------------|
| Effort | 1–2 days: bootstrap script; uninstaller script; self-update logic in collector; version-check endpoint on the API |
| Signing dependency | **None for PowerShell scripts.** A `.ps1` file does not require Authenticode signing to execute, provided the machine's ExecutionPolicy allows it (e.g. `RemoteSigned` or `Bypass`). Machines managed by no MDM / Group Policy typically have a permissive or default ExecutionPolicy. The bootstrap can set `Set-ExecutionPolicy Bypass -Scope Process` for its own process. Note: some hardened enterprise environments restrict ExecutionPolicy to `AllSigned` — those machines would require a signed script, but that is the same population that is likely to have Intune. |
| Recurring cost | None beyond the existing ingest infrastructure. |
| Security / Defender | PowerShell scripts are inspected by AMSI (Antimalware Scan Interface) at execution time. A well-written bootstrap that performs only `Invoke-WebRequest` / `Register-ScheduledTask` / file copies should pass AMSI without detections. Obfuscation must be avoided; the bootstrap should be clean and human-readable. Testing against Windows Defender and a representative EDR (e.g. Defender for Endpoint in audit mode) is a prerequisite before shipping to a customer. |
| Self-update mechanism | The collector's daily run checks `GET https://api.patched.im/v1/version?platform=windows`. If the remote version exceeds the pinned version, the collector downloads the new `.ps1` and replaces itself, then re-runs. The Scheduled Task runs SYSTEM-level, which has write access to `C:\Program Files\Patched\`. Atomic replacement: download to temp, verify hash, rename. |
| Robustness | Adequate. Scheduled Task survives reboots. Potential failure modes: Task Scheduler database corruption (rare; recoverable by re-running bootstrap); ExecutionPolicy change (the task itself records the execution policy override). |
| Customer install friction | Medium. IT contact must open an elevated PowerShell window and paste a command. Same friction as Option M-B on macOS. |
| Risk | Low. Mirrors the existing Intune-deployed model at the script level. AMSI/EDR validation required before customer deployment. |

**Status: Available now (pre-incorporation). Recommended as the immediate unblocking path.**

#### Option W-C: MSIX / AppX package (unsigned, developer mode)

MSIX packages can be sideloaded on Windows 10/11 with developer mode enabled. Without signing, the customer must toggle a system setting to allow sideloading. For a compliance product, requiring the customer to put their device in developer mode is a trust and positioning problem. **Rejected.**

---

## 4. Updater bundling analysis

### 4.1 The bundling case

The `updater` repo holds the hardened Installomator fork (macOS, PAT-39 epic) targeting the same IoM SME endpoint population. On Windows, `winget` is the natural engine. The bundling question: if a non-Intune delivery rail exists anyway, does the updater ride the same rail cheaply, covering a second genuine gap for unmanaged SMEs?

**The case for bundling:**

- An unmanaged IoM SME almost certainly has no third-party app patching at all. Chrome, Slack, Zoom, Firefox, 1Password, Notion — the six-app starter set in the allowlist — are almost certainly out of date on unmanaged endpoints. Patching those is a clear and demonstrable value.
- The client process is already resident, scheduled, and reporting. Adding an update-check step to the daily scheduled run is marginal engineering: a second loop after the compliance-collection step, using the same root/SYSTEM privilege already held.
- The collector and the updater share the same delivery rail (the bootstrap installs both; the scheduled task runs both). One enrollment, one onboarding conversation, two product surfaces.
- The compliance and patching stories reinforce each other: "we tell you what's wrong AND we fix the third-party app vulnerabilities automatically."

**The case against bundling (the security-exposure delta):**

An install-capable component is categorically different from a read-only collector in the EDR / Gatekeeper / Defender / SmartScreen risk model:

- **macOS Gatekeeper:** Gatekeeper checks the Team ID of every binary an installer attempts to install. The hardened Installomator fork verifies Team IDs from the manifest (`expectedTeamID`, confirmed against Apple as of PAT-42) before running each installation. This is the correct architecture — but Gatekeeper will still prompt or block on any unsigned installer package it does not recognise. The updater cannot deliver apps to a customer endpoint without being notarized (post-incorporation) or requiring Gatekeeper override. Pre-incorporation, the updater can only run on endpoints that have been explicitly told to trust the download source — not acceptable for a customer-facing product.

- **macOS LaunchDaemon scope creep:** Changing the LaunchDaemon from a read-only reporter to an installer of other software materially widens the blast radius of a compromise. If the API endpoint or the update manifest were poisoned, the LaunchDaemon would execute the payload with root privilege. The updater's security review (`docs/installomator-security-review.md`) addresses T4 and T5 at the manifest level; the daily verification agent (PAT-52) monitors vendor sources. That architecture is sound, but it is genuinely more attack surface than a collector alone. This must be disclosed to customers and assessed by GitHub-Non-Author-Review.

- **Windows AMSI / Defender / EDR:** A process that downloads executables and runs them as SYSTEM triggers substantially more EDR telemetry than a process that reads registry keys and POSTs JSON. In a zero-trust enterprise environment, this activity would require explicit allowlisting. Unmanaged SMEs (the target for a non-Intune rail) are unlikely to have a restrictive EDR, but the first deployment of the updater must be tested against Windows Defender in real conditions before customer use.

- **SmartScreen (Windows, post-incorporation):** A signed MSI (W-A path) that installs software from a vendor CDN will be inspected by SmartScreen both at install time and at update-download time. The cold-start period applies to each new binary the MSI installs, not only to the MSI itself.

### 4.2 Bundling recommendation

**Bundle the updater on the non-Intune rail, but gate customer-facing delivery on incorporation.**

The marginal cost is low; the customer value is high; and the security-exposure delta is addressed architecturally (manifest-level Team ID verification, daily verification agent, GitHub-Non-Author-Review). However:

- Pre-incorporation, the updater cannot notarize its delivered packages on macOS → Gatekeeper will block or warn → do not ship the updater to macOS customers until notarization is available.
- Pre-incorporation, Windows delivery is viable (PowerShell bootstrap, AMSI-clean) but requires explicit EDR testing before customer use.
- Post-incorporation, the full updater runs on both platforms via the signed-package rail.

The updater is a second product surface, not a free add-on. Its risk posture must be disclosed to customers at onboarding ("this component downloads and installs software; here is how we verify what it installs"). That disclosure is also a trust differentiator — few competitors are this explicit.

---

## 5. Recommendation

This section is the proposed recommendation for Andy's v2 decision. It is not yet accepted.

### 5.1 Immediate (pre-incorporation): unblock non-Intune customers with a bootstrap rail

**Build Option M-B (macOS) and Option W-B (Windows) — the PowerShell / shell bootstrap rails — now.** These unblock non-Intune customers without the native-agent cost and without waiting for incorporation. The work is:

- A shared API endpoint: `GET https://api.patched.im/v1/version?platform={macos|windows}` returning `{"version": "X.Y.Z", "checksum": "..."}`.
- A self-update function embedded in each collector script (already a sensible addition for Intune customers too — Intune redeploy remains supported and now has a fallback).
- macOS bootstrap: ~200-line zsh script; installs collector, writes and loads plist, writes version pin.
- Windows bootstrap: ~150-line PowerShell script; installs collector, registers Scheduled Task, writes version pin.
- Uninstaller variants for each platform.
- One-page customer install guide per platform.
- AMSI/EDR and Gatekeeper testing before any customer deployment.

**Estimated effort: 3–4 days total, both platforms.**

This approach is not a long-term architecture; it is a door-opener. The bootstrap rail's self-update mechanism means the collector can be improved iteratively without customer re-engagement. The transition to the signed-package rail (post-incorporation) is non-breaking: the bootstrap's install paths are identical to what the signed package will use.

### 5.2 Post-incorporation: graduate to signed-package rails

Once Patched.im Ltd. is incorporated and the Apple Developer Programme enrolment and Authenticode/EV certificate are in place:

- **macOS:** Build Option M-A — a notarized `.pkg` installer. The bootstrap and the `.pkg` install to the same paths; existing bootstrap installs self-update to the `.pkg` rail transparently.
- **Windows:** Build Option W-A — a signed MSI. Begin SmartScreen warm-up immediately on first install. The MSI wraps the PowerShell collector initially; migrating to a Go/native binary is a later v2 decision.

This graduation is the joint macOS + Windows v2 call ADR-0002 specifies. The recommendation here is to run the bootstrap rail during the incorporation period and treat it as the v1.5 state.

### 5.3 Updater bundling: deliver on the bootstrap rail post-incorporation on macOS, now on Windows

- **Windows:** Bundle the updater (winget engine) with the W-B bootstrap rail after AMSI/EDR testing. Gate on GitHub-Non-Author-Review.
- **macOS:** Bundle the updater (hardened Installomator fork) with the M-A signed-package rail post-incorporation (notarization required for the delivered packages). Pre-incorporation: do not ship the macOS updater to customer endpoints.

---

## 6. Options considered — summary table

| Option | Platform | Incorporation gate? | Effort | Signing | Self-update | Status |
|--------|----------|--------------------|---------|---------|-----------|----|
| M-A: Notarized `.pkg` | macOS | **Yes** | 2–3 days post-incorp | Developer ID Installer | `.pkg` pull-reinstall | Preferred post-incorp |
| M-B: Shell bootstrap + LaunchDaemon | macOS | No | 1 day | None | Script self-replace | **Recommended now** |
| M-C: Unsigned `.pkg` | macOS | No | 1 day | None | N/A | Rejected (Gatekeeper) |
| W-A: Signed MSI + Windows Service | Windows | **Yes** | High | Authenticode/EV | MSI pull-reinstall | Deferred (ADR-0002 v2 direction) |
| W-B: PowerShell bootstrap + Scheduled Task | Windows | No | 1–2 days | None | `.ps1` self-replace | **Recommended now** |
| W-C: MSIX sideload (developer mode) | Windows | No | 1 day | None | N/A | Rejected (dev-mode) |

---

## 7. Trade-off analysis

The central tension is **immediate market access vs long-term product grade**.

The bootstrap rails (M-B, W-B) are not as polished as signed installers. Customers must open a terminal and paste a command. This friction is real but is consistent with the existing IT-contact-led motion (the IoM SME target has a named IT person or IT adviser, not an end-user self-enrolment expectation). The bootstrap is defensible as a v1.5 artifact; it should not be the permanent answer.

The signed-package rails (M-A, W-A) are the right long-term destination. They require incorporation. Incorporation is in motion but not complete. Building toward M-A and W-A now — the pipeline, the notarization workflow, the MSI toolchain — alongside the bootstrap work is not wasted effort; it is parallel-path. The bootstrap buys time while incorporation completes.

The self-update mechanism is the most important single component regardless of rail choice. Without it, every collector update requires manual customer re-engagement. With it, the collector becomes a managed, self-healing artifact that the team can improve iteratively. This component has value for Intune customers too (it provides a fallback if Intune redeployment fails or is slow) and should be built regardless of the non-Intune decision.

The updater bundling amplifies both the value and the risk. It turns a single-signal compliance product into a two-signal managed-endpoint product (compliance + patching). For the unmanaged IoM SME, that is a materially stronger pitch. The security exposure is real but is addressed architecturally; the key safeguards are the manifest-level Team ID verification (PAT-42, done), the daily verification agent (PAT-52, in progress), and the pre-ship review (GitHub-Non-Author-Review).

---

## 8. Consequences

**If the bootstrap recommendation (§5.1) is accepted:**

*What becomes possible:*
- Non-Intune and no-MDM IoM prospects can be onboarded immediately, pre-incorporation.
- DAF-motivated prospects (the largest near-term pipeline) are not filtered by "do you have Intune?" during the sales conversation.
- The collector gains a self-update capability that benefits all customers, including Intune-managed ones.
- The path to the signed-package rails (post-incorporation) is laid, not blocked.

*What becomes harder:*
- An additional install path must be maintained, tested, and documented. Two rails (Intune + bootstrap) means two onboarding runbooks and two support paths.
- The bootstrap's one-time install friction must be managed in customer conversations ("open a terminal once, then it manages itself").
- AMSI/EDR and Gatekeeper testing of the bootstrap adds a prerequisite before any customer deployment.

**What stays unchanged:**
- ADR-0002 is not superseded or modified. The v1 Intune-deployed model continues as the primary rail for Intune-managed customers.
- The native-agent v2 decision (ADR-0002 §Consequences) remains Andy's call gated on pilot data and incorporation.
- The updater bundling decision is separate from the bootstrap rail decision; the two can be taken independently.

---

## Action Items (for decision-makers, not yet committed)

1. [ ] **Andy: accept or modify this ADR** — v2 call per ADR-0002. Confirm whether the bootstrap rails are the right pre-incorporation path, and set a target date tied to the first non-Intune prospect conversation.
2. [ ] **If accepted:** Build `GET /v1/version` endpoint on the API VPS — the shared version-check backend for both platform self-updates.
3. [ ] **If accepted:** Build Option M-B (macOS bootstrap). Pre-ship Gatekeeper + collector-functionality testing required.
4. [ ] **If accepted:** Build Option W-B (Windows bootstrap). Pre-ship AMSI/Defender testing required.
5. [ ] **If accepted:** Run GitHub-Non-Author-Review before any customer deployment of the bootstrap.
6. [ ] **On incorporation:** Begin Developer ID Installer and Authenticode/EV certificate acquisition. Start building Option M-A and Option W-A in parallel.
7. [ ] **Updater bundling:** Take as a separate decision once PAT-52 (daily verification agent) is complete and GitHub-Non-Author-Review has assessed the security exposure delta.

---

## Cross-references

- [[ADR-0002]] (`0002-windows-client-approach.md`) — deferred the native-agent and non-Intune questions to this v2 decision. ADR-0004 feeds that decision; ADR-0002 is not superseded.
- [[ADR-0001]] (`0001-cis-collection-scope.md`) — three-tier collection model; the bootstrap rail must preserve the full T1+T2 collection capability.
- `macos-agent/patched-collect.sh` — the macOS collector this rail delivers.
- `updater/` — the third-party app updater whose bundling is analysed in §4.
- `updater/docs/installomator-security-review.md` — the threat model for the updater; the bundling analysis in §4 of this ADR rests on it.
- `updater/contracts/label.schema.json` — the manifest the updater checks; PAT-42 confirmed Team IDs for the six-app starter set.
- PAT-67 (Linear) — spike tracking this investigation.
- PAT-52 (Linear) — daily verification agent; prerequisite for the updater bundling decision.
- PAT-66 (Linear) — pre-ship code + security review; must run before any bootstrap rail reaches a customer.
- `research/daf/` — IoM market materials; the DAF framework analysis informing §1 of this ADR.
