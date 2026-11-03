# ADR-0003: Tier 3 Microsoft Graph access model

**Vocabulary note (2026-09-13, PAT-1700):** buyer-facing tiers were retired on 2026-09-11 (PAT-1566); the internal enum is now `assurance` and `managed`. "Tier 3" below means Full Endpoint Management, which maps to `managed`. The decision text is unchanged.

**Status:** Superseded by [ADR-0010](0010-microsoft-graph-scope-reconciliation.md) (2026-08-14). Retained as the historical record of the spike decision.
**Accepted:** spike PAT-350, authoring layer PAT-351
**Deciders:** Andy (sole maintainer, pre-incorporation)
**Security review gate:** GitHub-Non-Author-Review (non-author review before first Tier 3 customer) — moot for this implementation; Tier 3, if rebuilt, will not be built on this deleted code.

**Full ADR:** `go-service/docs/adr/0012-tier3-graph-access-full.md` (moved from `spikes/tier3-graph-access/ADR-graph-access.md` when the spike was deleted; renumbered from `0003-tier3-graph-access-full.md` on 2026-09-13, PAT-1700, to stop two files claiming ADR-0003) — contains the complete options analysis, GDAP rules verification, credential custody model, per-tenant consent flow, and open items. This file is the formal summary for the ADR catalogue.

**2026-07-14 update:** Andy's call — the *implementation* is a dropped direction, deleted. The full `internal/tier3/` implementation this ADR describes (`graph/`, `mapping/`, `policy/`, `reconcile/`, `renderer/`) was complete and tested but never wired into any route or `cmd/` binary. It was deleted in PAT-911 to remove the landmine of a fully-built, unreviewed Graph contract being wired in later with no review trigger. This ADR stays as the record of why the Graph access model was designed the way it was, in case Tier 3 config-enforcement is revisited on different grounds.

**2026-08-14 update — see [ADR-0010](0010-microsoft-graph-scope-reconciliation.md):** this ADR's "Graph dropped" framing, read on its own, was mistaken for a ruling that *all* Tier 3 use of Microsoft Graph was dead. It was not. ADR-0010 is the authoritative reconciliation: Microsoft Graph is dead as an inventory/scanning source (the agent + `/v1/inventory` pipeline replaced it — unaffected by this document) but alive as the Tier 3 orchestration mechanism, because Intune remains the customer's MDM and Graph is the only API surface for writing into it. Read ADR-0010 before treating anything below as settled either way.

---

## Decision

**One multi-tenant Entra app, app-only client credentials, customer-tenant authority.**

- Single app registration in Patched's Entra ID tenant (never re-registered per customer).
- Two application permissions: `DeviceManagementConfiguration.ReadWrite.All` + `DeviceManagementScripts.ReadWrite.All` (July 2025 split — requesting only the first silently 403s on script endpoints).
- Token acquired against `login.microsoftonline.com/{CUSTOMER_TENANT_ID}/...` using Patched's stable credentials. Customer's Entra validates Patched's app because the app was consented there.
- Credential: `PATCHED_GRAPH_CLIENT_SECRET` env var on `example-api-host` (→ HSM/cert before Tier 3 scales past 2–3 customers, per the GitHub-Non-Author-Review open item).

**Near-term (pre-CSP):** customer admin grants consent via admin consent URL (one manual step per onboarding). Same token-acquisition mechanics.
**Target state:** GDAP relationship (Intune Administrator + Cloud Application Administrator roles) → Patched partner grants consent on customer's behalf.

## Graph resource / API-version map

| Resource | Graph path | API version | Permission |
|---|---|---|---|
| Settings Catalog policies | `deviceManagement/configurationPolicies` | **beta only** | Configuration |
| Legacy device configs (incl. `.mobileconfig`) | `deviceManagement/deviceConfigurations` | v1.0 | Configuration |
| Compliance policies | `deviceManagement/deviceCompliancePolicies` | v1.0 | Configuration |
| Remediation scripts | `deviceManagement/deviceHealthScripts` | v1.0 | Scripts |
| Platform scripts | `deviceManagement/deviceManagementScripts` | v1.0 | Scripts |

`configurationPolicies` is beta-only (no v1.0 equivalent); this is accepted risk — all commercial MDM tooling uses these same endpoints.

## What this enabled (removed, PAT-911)

- `internal/tier3/graph.Client` — token caching + APIVersion-aware routing (PAT-351). Deleted 2026-07-14.
- `internal/tier3/renderer` — idempotent declarative→Graph with script-write gate (PAT-351). Deleted 2026-07-14.
- `tenants.intune_tenant_id` remains in the schema — the customer tenant ID would have been the only per-tenant parameter the renderer needed. Per ADR-0010, this column is kept deliberately: Tier 3 orchestration is alive, `intune_tenant_id` is its natural per-tenant key, and it is simply not yet populated by any live path.

## Key constraints (historical — implementation no longer exists)

- Scripts scope (`DeviceManagementScripts.ReadWrite.All`) is powerful: permits arbitrary shell script creation on managed devices. Would have been gated behind `ScriptWritesEnabled=false` in the renderer until GitHub-Non-Author-Review cleared it.
- `configurationPolicies` beta API: breaking changes possible without notice. Would have been an accepted risk; moot now.
- App-only consent cannot be automated under GDAP — always a manual URL-click per customer onboarding, had this been built.
