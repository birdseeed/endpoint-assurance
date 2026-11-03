# ADR-0009: Agent home and per-tenant deployment model

**Vocabulary note (2026-09-13, PAT-1700):** buyer-facing tiers were retired on 2026-09-11 (PAT-1566); the internal enum is now `assurance` and `managed`. Below, "tier" in the signed per-tenant config refers to this subscription-tier field; this ADR's own text doesn't name which specific tier, so this note does not assert a mapping beyond the field's new value set. The decision text is unchanged.

**Status:** Accepted (consolidates already-made decisions; one open sub-question, §7)
**Deciders:** Andy
**Related:** [[ADR-0002]] (client approach), [[ADR-0004]] (non-Intune delivery rail)

---

## Context

Recurring question: *where should each customer's agent live — a new repo storing customer-specific agents, downloadable from the customer dashboard?*

This ADR records the answer, consolidating decisions already taken across PAT-384, PAT-279/281/282, and PAT-267 so the model is explicit rather than tribal.

The key framing: an "agent" has two parts that must not be conflated.

| Part | What it is | Customer-specific? |
|---|---|---|
| **Code / artifact** | The collector + updater binaries/scripts that run on the endpoint | **No** — identical for every customer |
| **Per-tenant data** | Credentials (tenant id, bearer token, HMAC secret) + signed config (tier, policy, proxy rules) | **Yes** — but it is *data*, delivered to a generic agent, not compiled in |

## Decision

**1. One repo for agent code: `updater`.** Per PAT-384 (Done): "code that executes on a customer endpoint → `updater`; everything server-side stays in `patched.im`," symmetric macOS/Windows layout. There is **no per-customer agent repo** and no per-customer source.

**2. One generic, signed artifact per platform — not per customer.** Distribution: interim unsigned GitHub Release tarball (PAT-267, Done) → notarized `.pkg` / signed MSI post-incorporation (PAT-9, ADR-0004). The same artifact ships to every tenant.

**3. Per-tenant behaviour is delivered as signed data at runtime, not baked into a build.** `GET /v1/agent-config` returns Ed25519-signed per-tenant config; the endpoint fetches, verifies, caches and polls every 15 min (PAT-279/281/282, Done). Tier/policy/proxy differences are config, not code.

**4. "Customer-specific" at install time = a per-tenant enrolment token, not a bespoke binary.** The customer-facing dashboard's "download" is: the generic installer **+** a per-tenant enrolment bootstrap the dashboard generates on demand, carrying a short-lived enrolment token (cf. the enrolment endpoint, PAT-23). The token is generated per customer; it is not stored in a repo. Credentials then live on-device per the storage model to be finalised in PAT-19.

## Why not a per-customer agent repo / per-customer builds

- **Signing cost multiplies.** Each bespoke artifact needs Apple notarization / Authenticode signing — N customers = N signed artifacts to produce and re-produce on every change.
- **Security-review gate multiplies.** GitHub-Non-Author-Review requires a full review before any agent reaches a customer; N artifacts = N reviews.
- **Supply-chain surface multiplies.** Every distinct customer binary is a distinct thing to compromise, sign, and track.
- **Updates become O(N).** A one-line collector fix would mean rebuilding/re-signing every customer's artifact. A generic artifact + dynamic config makes a fix O(1).

Generic-artifact + per-tenant-data is strictly cheaper and is already half-built (the agent-config channel and the GitHub-Release path both exist).

## Not in scope (do not conflate)

- **PAT-234** "self-hosted Patched app repo" is for the third-party *applications the updater deploys to endpoints*, not the agent itself. Different concept.

## Consequences

- The dashboard download surface (PAT-108: bootstrap loader via GitHub or a dashboard signed-artifact endpoint) serves one generic artifact + generates per-tenant enrolment commands. Tenant provisioning automation (PAT-110) mints the credentials/config rows that back the enrolment token.
- Adding a customer is a *data* operation (provision credentials + config rows), never a *code* operation.
- The agent-config channel is the single lever for per-tenant behaviour; new tenant-varying behaviour should be added there, not via build flags.

## 7. Open sub-question (the one remaining decision)

**Does the per-tenant enrolment token travel embedded in the downloaded bootstrap, or is it entered at install time?**

- *Embedded:* dashboard generates a per-tenant bootstrap with the token baked in → lowest customer friction, but the download artifact is now sensitive (token leakage if shared).
- *Entered at install:* one generic bootstrap for everyone; the IT contact pastes a tenant token/enrolment code at install → safer, slightly more friction.

This is the substance of PAT-19 ("credential storage and pre-configured agent deployment model") and should be resolved there. Everything else above is settled.
