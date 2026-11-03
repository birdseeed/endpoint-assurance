# ADR-0010: Microsoft Graph scope — dead for inventory, alive for Tier 3 orchestration

**Vocabulary note (2026-09-13, PAT-1700):** buyer-facing tiers were retired on 2026-09-11 (PAT-1566); the internal enum is now `assurance` and `managed`. "Tier 3" below means Full Endpoint Management, which maps to `managed`. The decision text is unchanged.

**Status:** Accepted (2026-08-14)
**Date:** 2026-08-14
**Deciders:** Andy (sole maintainer, pre-incorporation)
**Supersedes:** [0003-tier3-graph-access.md](0003-tier3-graph-access.md) and [0012-tier3-graph-access-full.md](0012-tier3-graph-access-full.md) (renumbered from `0003-tier3-graph-access-full.md` 2026-09-13, PAT-1700); the "drop Microsoft Graph entirely" note, as it applies to Tier 3 orchestration
**Related:** PAT-168, PAT-301 (Tier 3 orchestration ruling), PAT-911 (`internal/tier3/` deletion), PAT-612 (Graph/GDAP onboarding), PAT-572 (public-scan Graph path removed), [0008-dashboard-as-primary-product-surface.md](0008-dashboard-as-primary-product-surface.md)

---

## Context

Two rulings, both made, are both live in the record and read as contradictory:

- **/12 (PAT-168 / PAT-301):** Tier 3 (Full Endpoint Management) is a per-tenant orchestration layer that drives the customer's own Intune via Microsoft Graph, applying Patched's pre-created CIS policy set. Patched is the control plane; Intune remains the MDM — Patched does not build one. This is the decision ADR-0003 was designed against.
- **** drop Microsoft Graph entirely, no more Graph API integration.

Nothing in the record reconciled these, and the estate carries the confusion forward:

- `internal/tier3/` (`graph/`, `mapping/`, `policy/`, `reconcile/`, `renderer/`) was built against the 06-11 ruling — complete and tested — never wired to a route or `cmd/` binary, and deleted under PAT-911 on 2026-07-14 to remove the landmine of a fully-built, unreviewed Graph contract that could be wired in later with no review trigger.
- ADR-0003 is marked Superseded, carrying a "Graph dropped as a platform dependency" framing that does not distinguish inventory from orchestration.
- `tenants.intune_tenant_id` survives, described in ADR-0003 as "harmless, unused."
- `internal/handlers/admin.go` still emits a live runtime warning that Graph/GDAP onboarding (PAT-612) gates Tier 3 enforcement — which, without this ADR, reads as pointing at the dropped work.

An assessor or engineer reading this record before a pentest, or before picking up Tier 3 work again, finds a superseded design and a live runtime warning pointing at it, with nothing saying which ruling governs.

## Decision

**Both rulings are correct, about different things, and neither was ever wrong.**

1. **Dead: Microsoft Graph as an inventory and scanning source.** The macOS/Windows agent plus `POST /v1/inventory` (schema v2/v3, extractor, evaluator) is what replaced whatever Graph-based inventory path the platform once might have used for device/app data and CVE scoring. The ruling is about this path, and it stays dropped: compliance signals, device inventory, and the dashboard's live fleet view ([ADR-0008](0008-dashboard-as-primary-product-surface.md)) run off the continuous agent pipeline, never off Graph. The public CVE scan's own separate Graph-only path was independently removed under PAT-572 and is unaffected by this ADR either way.

2. **Alive: Microsoft Graph as the Tier 3 orchestration mechanism.** Tier 3 (Full Endpoint Management) applies Patched's CIS policy set into the customer's own Intune tenant. Patched does not build an MDM; Intune is the MDM; Microsoft Graph is the only API surface Intune exposes for writing configuration into it. There is no alternative mechanism that keeps "the customer's own Intune" true. PAT-168 / PAT-301 stands, unreversed.

The two rulings answer different questions — "where does data about the estate come from" versus "how does Patched write configuration into a tenant it does not own" — and both answers hold simultaneously. This ADR is the single record of that distinction. It supersedes ADR-0003 (both the summary and the full options-analysis document) and the dropped-Graph note as either was being read to mean Tier 3 orchestration is also dead. The inventory conclusion those documents also carry is not overturned here — it is restated, correctly scoped, rather than left to imply more than it should.

## What this means for the artefacts already in the estate

- **`internal/tier3/` stays deleted.** PAT-911 was the right call given an unreviewed, unwired Graph contract sitting in the tree with no review trigger; that risk argument is orthogonal to whether Tier 3 orchestration itself is alive. Rebuilding it is future work, gated by PAT-612 (Graph/GDAP onboarding) and a non-author security review before any customer — this ADR does not authorise starting that work, only clears up what is and is not settled.
- **`tenants.intune_tenant_id` — keep.** Graph-as-orchestration is alive, and a per-tenant Intune tenant identifier is the natural key for it; removing the column would only mean re-adding it. It is not "harmless, unused" — it is the field the Tier 3 orchestration path will read once built, and as of this ADR it is not yet populated by any live path.
- **The `admin.go` Tier 3 warning — kept, reworded.** `SetTenantTierHandler`'s warning that `full_endpoint` requires Graph/GDAP onboarding (PAT-612) before enforcement surfaces go live is substantively correct: it names live, planned Tier 3 orchestration work, not the dropped inventory integration. It is reworded to say so explicitly and to cite this ADR by number, so it no longer reads as pointing at deleted work.
- **PAT-612 — re-scoped, not closed.** It remains the correct ticket for Graph/GDAP onboarding as the Tier 3 orchestration prerequisite; its description should say so explicitly rather than reading as a stale pointer into the dropped integration. (Re-scoping wording proposed separately, not applied by this change.)

## Consequences

**What becomes possible:**

- The record says one thing. An assessor, or a future engineer, reading ADR-0003 lands on this ADR instead of a dead end.
- Tier 3 work, if and when it resumes, has an unambiguous starting document instead of two contradictory rulings.

**What becomes harder / stays hard:**

- This ADR does not re-authorise building `internal/tier3/`, does not add any Graph client code, and does not change PAT-612's blocked status. It is a record correction, not new scope.
- The inventory/orchestration distinction has to be actively maintained. The next person touching Graph-adjacent code needs to know which side of the line they are on — any future PR that adds Graph calls for anything other than Tier 3 Intune orchestration should be treated as a red flag against this ADR.

## Cross-references

- [0003-tier3-graph-access.md](0003-tier3-graph-access.md) — superseded by this ADR; historical record of the Tier 3 Graph access design.
- [0012-tier3-graph-access-full.md](0012-tier3-graph-access-full.md) — superseded by this ADR; full options analysis, still valid as reference material if Tier 3 orchestration resumes.
- [0008-dashboard-as-primary-product-surface.md](0008-dashboard-as-primary-product-surface.md) — the inventory-side move off Graph and onto the agent pipeline that this ADR's "dead" half restates.
- PAT-168, PAT-301 — the original Tier 3 orchestration ruling this ADR reaffirms.
- PAT-911 — `internal/tier3/` deletion; unaffected by this ADR.
- PAT-612 — Graph/GDAP onboarding; re-scoped by this ADR to be explicit about what it gates.
