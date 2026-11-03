# ADR-0002: Windows endpoint client approach — script collector vs native agent

**Status:** Superseded by [ADR-0006](0006-windows-native-agent.md); further context in [[ADR-0007]]
**Deciders:** Andy (sole maintainer, pre-incorporation)

**Superseded:** The Windows endpoint became a **native C# .NET 8 Windows Service** (`windows-agent/`), not a PowerShell script — because the compliance collector converged with the Patched Updater (winget/choco patching + tray), which needs a persistent background process. See [ADR-0006](0006-windows-native-agent.md). The reasoning below remains valid for a compliance-*only* collector and still describes the macOS model.

**Update:** Andy owns all workstreams including Windows. Decision history below is preserved as a record.

**Update — context from [[ADR-0007]]:** macOS/Windows parity is now a **standing principle across the whole feature surface** (collection depth, CIS coverage, deploy/patch, client tier). The CIS-depth gap (Windows is T1-only vs macOS T1+T2) is drift to be closed, not an accepted state.

---

## Context

Windows support is part of Andy's remit. Before any Windows engineering starts, one question gates the rest: **what is the Windows endpoint client?** A native agent (a Windows Service installed from a signed MSI), or a PowerShell collection script deployed via Intune that mirrors the macOS `patched-collect.sh` model?

This was originally tracked as the "[Windows] Decide Windows wedge" task. It was decided once (no agent — script), then reopened the same day when the parity / MDM-agnostic case was raised. This ADR formalises the reaffirmed decision so it is not relitigated a third time.

**Forces in play:**

- **macOS v1 is itself a script.** `patched-collect.sh` is an unsigned zsh script deployed via Intune. The native Swift/Go macOS agent is explicitly deferred (the "[macOS] Plan v1 agent" task — revisit after 3–6 months of operational data). "Parity" with macOS *today* therefore means a script, not an agent. A native Windows agent now would put the Windows client a tier *ahead* of macOS, not at parity with it.
- **An endpoint collector is required either way.** Intune's GA May 2026 Windows App Inventory already collects installed-app data multiple times per day. But CIS Windows L1 needs the control-signal surface — security policy, audit configuration, service/feature state, registry-backed settings — that Intune app inventory does not expose. Something must run on the endpoint to collect it. The question is *agent vs script for that collector*, not *whether to collect*.
- **MDM-agnosticism is mostly orthogonal to agent-vs-script.** The collection script is not Intune-coupled at runtime: it runs locally, reads the CIS surface, and POSTs to the ingest endpoint with bearer + HMAC auth. It calls no Graph or Intune API. Any MDM that can push a script — or a manual / GPO install — can deploy it. A native agent does not make the client *more* portable at runtime; an MSI still needs a deployment mechanism exactly as a script does.
- **Intune-first strategy.** The primary motion assumes Intune for both Windows and Mac. MDM-agnosticism is optionality against a future that is not the current plan; it has a real cost and is not free to carry.
- **Pre-incorporation, pre-revenue, pre-customer.** Patched.im Ltd. incorporation is in motion. There is no paying customer and the first design-partner pilot is not yet onboarded.
- **A native agent re-incurs the Windows native-binary tax.** Windows Service, MSI/WiX packaging, a CI signing pipeline, an Authenticode/EV certificate (real cost and multi-day CA lead time), the SmartScreen reputation cold-start, and Defender/EDR allowlisting. The SmartScreen cold-start runs for months and is a particularly bad first impression for a *compliance* product in front of security-conscious buyers.

---

## Decision

**The v1 Windows endpoint client is a PowerShell collection script deployed via Intune, mirroring the macOS `patched-collect.sh` model.** No native Windows agent for v1.

The native-agent question is **deferred to a joint macOS + Windows v2 decision**, taken after the design-partner pilot, when there is operational data to justify it. macOS and Windows move to native agents together or not at all — that is what real parity means here.

This is **Option B** below.

---

## Options Considered

### Option A: Native Windows agent now (Windows Service + signed MSI)

| Dimension | Assessment |
|-----------|------------|
| Complexity | High (Service, MSI/WiX, signing pipeline, config model) |
| Cost | High (EV cert spend + lead time; months of SmartScreen cold-start) |
| Parity | Inverted — Windows client ahead of the macOS script |
| Time to revenue | Months |

**Pros:**
- A native agent is a more credible enterprise artifact
- Robustness, self-update, clean install/uninstall, config management built in
- Gets the signing / reputation grind done early, so it is "warm" later

**Cons:**
- Re-incurs every task the review cut: Windows Service, MSI/WiX, CI signing, Authenticode/EV cert, SmartScreen, GPO/ADMX
- SmartScreen / EDR cold-start is a multi-month problem and a poor look for a compliance product
- Inverts parity — macOS is still a script
- Front-loads the most painful Windows-specific work before there is a customer to justify it

### Option B: PowerShell collection script deployed via Intune (mirror macOS v1)

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low–Medium (script + scheduled task; reuses the macOS shape) |
| Cost | Low (no signing, no cert, no installer pipeline) |
| Parity | True tier-parity with macOS v1 |
| Time to revenue | Weeks |

**Pros:**
- Genuine parity with the macOS v1 client (both platforms ship a script collector)
- No EV cert spend or lead time; no SmartScreen cold-start incurred now
- Portable: not Intune-coupled at runtime — deployable by any MDM, GPO, or manually
- The Windows workstream collapses from 11 tasks to 4 (collection script, Intune deployment runbook, self-pilot, CIS Windows L1 evaluator)
- Reuses the tenant-policy model from migration `0005` and the shared payload schema

**Cons:**
- Script robustness has limits — reboot/sleep handling, scheduled-task survival across Windows Update
- No self-update; updating the script means redeploying via Intune
- Config rides Intune script parameters rather than a managed GPO/ADMX surface
- Less of an "enterprise-grade" artifact than a signed installed agent

### Option C: Graph pull primary + PowerShell gap-filler script

Pull Windows app inventory and device data server-side from Intune via the Microsoft Graph API as the primary mechanism, with a thin PowerShell script deployed via Intune as a gap-filler for the CIS control signals Graph does not expose well (ASR rules, Defender signature freshness, BitLocker escrow state, registry uninstall keys).

**Rejected.** This was the model the "API VPS architecture" page documented before this ADR. It is rejected for two reasons. First, it couples the Windows data path to the Microsoft Graph and Intune Advanced Endpoint Analytics API surface — endpoints whose GA state the architecture page itself flagged as needing verification — so an unannounced Microsoft change can silently break ingestion. Second, a gap-filler script has to exist anyway for the CIS L1 control surface; once a script is on the endpoint, letting it also collect app inventory keeps the Windows client self-contained for marginal extra collector code and removes the external dependency entirely. The pull-primary split adds an integration surface without removing the script.

---

## Trade-off Analysis

The pivotal axis is **enterprise-grade robustness now vs cost and parity discipline.**

The parity instinct is correct, but parity is about *tier*, not feature count: macOS and Windows should sit at the same client tier. Today that tier is "script." Building a native Windows agent now satisfies a feeling of parity while actually breaking it.

The MDM-agnostic instinct is also reasonable, but a native agent is not what delivers it. The script collector is already MDM-agnostic at runtime — it is a generic local artifact that POSTs to the ingest endpoint. If validating the agnostic story matters, the cheap test is to deploy the v1 script via a non-Intune path and confirm ingest flows; that proves portability for near-zero cost.

What a native agent genuinely buys — robustness, self-update, clean install, config management — is real but is a v2 concern, and is exactly what the macOS side already chose to defer. Taking on the Windows native-binary tax (signing, EV cert, SmartScreen cold-start) before there is a paying customer, or even a confirmed non-Intune one, is a large front-loaded cost for optionality.

Against Option C specifically: the gap-filler script must exist regardless, so the only real question is whether app inventory arrives via Graph or via that same script. Routing it through Graph adds a second integration path and couples ingestion to an external API surface Microsoft changes without notice. Folding app inventory into the script keeps the Windows client self-contained and resilient to Graph-side churn, for little extra collector code.

**Decision: Option B.**

---

## Consequences

**What becomes easier:**

- The Windows workstream is 4 focused tasks, not 11 — shippable in weeks
- No EV certificate spend or CA lead time; no SmartScreen reputation cold-start incurred now
- The Windows collector reuses the macOS collection shape, the shared payload schema, and the migration `0005` tenant-policy model
- The client stays portable — a future non-Intune customer does not require a rebuild

**What becomes harder:**

- Script robustness must be engineered deliberately — scheduled-task survival across reboots, sleep/wake, and Windows Update cycles
- No self-update path; script changes ship as Intune redeployments
- Configuration is delivered through Intune script parameters rather than a managed GPO/ADMX surface
- The client is a less "enterprise-grade" artifact than a signed installed agent — a perception cost with some buyers

**What we will need to revisit:**

- **Native agent as a joint v2 decision.** Take it for macOS *and* Windows together, after the design-partner pilot, when operational data justifies the investment. A confirmed non-Intune customer would also strengthen the case.
- **MDM-agnostic de-risk test.** Prove the v1 script deploys cleanly via a non-Intune path — cheap validation of the portability story without building an agent.
- **Defender / EDR behaviour.** A recon-style script can still draw EDR attention; verify during Windows self-pilot. (This absorbed the deleted SmartScreen/EDR task.)

---

## Action Items

Most of these were executed tasks-vs-roadmap session; this section records them.

1. [x] **Scrap the native-agent tasks.** The wedge decision task and 6 native-agent tasks (Windows Service, MSI/WiX installer, CI signing pipeline, Authenticode cert, SmartScreen/EDR, GPO/ADMX) flagged `[SUPERSEDED — delete]` and removed from the Tasks Tracker.
2. [x] **Rescope the surviving Windows tasks** for the script model: the Intune-deployed collection script, the Intune deployment runbook, self-pilot on Windows VMs, and the CIS Windows L1 evaluator.
3. [x] **Commit this ADR** to `go-service/docs/adr/0002-windows-client-approach.md`.
4. [ ] **Link this ADR** from the Notion "API VPS architecture" page with a one-paragraph summary.
5. [ ] **Record the v2 revisit trigger** — the native-agent decision is taken jointly with macOS after the design-partner pilot.

**Cross-references:**

- [[ADR-0001]] (`0001-cis-collection-scope.md`) — the three-tier CIS collection model and the migration `0005` tenant-policy model both apply to Windows CIS L1; extend that design, do not duplicate it.
- `macos-agent/patched-collect.sh` — the collection model the Windows script mirrors.
- Notion "Working state" page — Build track and Recently completed updated to reflect this decision.

**Definition of Done (per the in-repo docs + Notion close-out rule):**

- This ADR committed to `go-service/docs/adr/0002-windows-client-approach.md`
- Notion "API VPS architecture" page gains a link to this ADR + a one-paragraph summary
- Notion "Working state" page reflects the decision (done — Build track + Recently completed)
