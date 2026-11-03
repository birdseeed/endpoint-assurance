# ADR-0007: macOS / Windows parity as a standing principle

**Vocabulary note (2026-09-13, PAT-1700):** buyer-facing tiers were retired on 2026-09-11 (PAT-1566); the internal enum is now `assurance` and `managed`. Below, "Tier 3 policy-sets" means Full Endpoint Management, which maps to `managed`; "client tier" and the CIS three-tier model are a different, unrelated vocabulary (architecture maturity and CIS control depth respectively) and are not affected by this retirement. The decision text is unchanged.

**Status:** Accepted
**Deciders:** Andy
**Supersedes:** [[ADR-0002]] (Windows client approach — the *deferral* clause specifically; see below)
**Related:** [[ADR-0001]] (CIS collection scope), [[ADR-0004]] (non-Intune delivery rail), [[ADR-0009]] (agent home + per-tenant deployment)

---

## Context

Patched is endpoint-first on **macOS + Windows**. Historically the two platforms moved at different speeds and parity was treated decision-by-decision:

- [[ADR-0002]] framed parity as *tier*-parity — "both ship a script collector" — and **deferred the native Windows agent to a joint macOS + Windows v2 decision** taken after the design-partner pilot. Its closing philosophy was already parity-shaped: *"macOS and Windows move to native agents together or not at all — that is what real parity means here."*
- In practice that left real gaps where one platform advanced without the other. The two live ones:
  - **CIS control depth.** macOS has 52 rules (17 T1 + 35 T2 — migrations `0003`, `0006`–`0008`); Windows has 13 T1-only rules (migration `0019`). No Windows T2 set exists. (Note: ADR-0002 did *not* defer the Windows CIS evaluator — it kept it as a surviving task — so this gap is drift, not a decision.)
  - **Deploy / patch agent.** The macOS updater is shipped (in `updater`); the Windows winget-based deploy/patch agent (PAT-276) is backlog and "not armed."
- Areas already at or near parity: collector (`patched-collect.sh` ↔ clean-room `.ps1`, PAT-105), contract-conformant ingestion incl. HMAC + sender (PAT-336), tray / self-service app (PAT-306), Tier 3 policy-sets (PAT-357).

The recurring cost of relitigating parity per decision, plus the drift it permits, motivates promoting parity from a per-decision instinct to a **standing principle**.

## Decision

**macOS and Windows are held at feature parity across everything: collection depth, CIS control coverage, deploy/patch, client tier, and customer-facing surfaces. Neither platform ships a capability without a tracked plan to bring the other to match.**

Concretely:

1. **Parity is a release gate, not an aspiration.** A capability that lands on one platform carries a tracked parity ticket for the other. "Done on macOS" is not done until the Windows counterpart is tracked (and vice versa).
2. **The native-agent question stays a *joint* decision** — this part of ADR-0002 is reaffirmed, not overturned. Both platforms move to native agents together or not at all, on operational data after the pilot. What changes is that *every other* capability is now held to parity in the meantime, rather than parity being invoked only to defer the agent.
3. **CIS control coverage reaches parity.** Windows gets a T2 expansion mapped onto the same three-tier model as macOS ([[ADR-0001]]), gated by what the Windows collector can signal. Target: Windows control depth comparable to macOS, not a fixed count — some CIS controls are genuinely platform-specific on each side.
4. **Deploy/patch reaches parity.** The Windows winget deploy/patch agent (PAT-276) is brought to parity with the shipped macOS updater.

### What this supersedes in ADR-0002

ADR-0002's **Option B decision (v1 client = script collector) stands** — that is not reopened. What this ADR supersedes is the *narrow framing of parity as tier-only-and-otherwise-deferred*. Parity is now the active, standing constraint across the whole feature surface, and the CIS-depth / deploy-agent drift is explicitly something we close rather than carry.

## Consequences

**What becomes easier:**

- Parity is no longer relitigated per decision — the default is "match the other platform" and the burden of proof is on *not* doing so.
- Drift becomes visible: any one-platform capability without a tracked counterpart is now a defect, not an accepted state.

**What becomes harder:**

- Every platform-specific capability roughly doubles in tracked scope. This is the intended cost — parity is the product promise to mixed-estate SME buyers.
- Some controls/features are inherently platform-specific (e.g. BitLocker vs FileVault, Gatekeeper vs SmartScreen). Parity means *equivalent coverage of the platform's CIS surface*, not identical rule IDs. Judgement is required per control; "no equivalent exists" is a valid, recorded outcome.

**What we will need to revisit:**

- **Native agent**, still as the joint v2 trigger from ADR-0002 — unchanged.
- **The parity ledger.** Tracked as a Linear parity epic with child tickets per gap (Windows CIS T2, Windows deploy/patch agent), plus reconciliation of the now-stale PAT-15.

## Action Items

1. [x] Commit this ADR; mark [[ADR-0002]] superseded-in-part with a pointer here.
2. [ ] Linear: parity epic + child gap tickets (Windows CIS T2 depth; Windows deploy/patch agent parity).
3. [ ] Reconcile PAT-15 — its "zero Windows rules" premise is stale post-PAT-337/migration `0019`; rescope to "Windows CIS T2 expansion" under the epic or close.
4. [ ] When adding any platform-specific capability, open the counterpart parity ticket in the same change.

**Cross-references:**

- [[ADR-0001]] — three-tier CIS collection model; the Windows T2 expansion extends it, does not duplicate it.
- [[ADR-0002]] — superseded in part (parity framing); the script-collector decision itself stands.
- `migrations/0019_windows_cis_l1_rules.sql` — the current 13-rule Windows T1 baseline the T2 work builds on.
