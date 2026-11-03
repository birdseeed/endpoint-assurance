# ADR-0001: macOS agent CIS collection scope and per-tenant rule activation

**Status:** Accepted
**Accepted:** all six action items delivered → (see cowork-handover.md "Recently completed").
**Deciders:** Andy (sole maintainer, pre-incorporation)

---

## Context

The macOS endpoint agent currently collects ~30+ fields via `patched-collect.sh` (725 lines of zsh, deployed via Intune as root). The CIS L1 evaluator runs against 17 controls (16 from CIS macOS Sonoma 14 v3.0.0 + 1 patched.im baseline). Each control is data in `compliance_rules` (per the "rules are data, not Go code" convention in `CLAUDE.md`).

The question: should the agent collect signals for the **entire CIS L1 control surface** — roughly 80–100 more controls beyond what we evaluate today — and let per-tenant policy decide which rules actually run in the evaluator? Or stay narrow and add collection incrementally as each rule is enabled?

This decision must be settled before significant collector expansion, because either path materially affects:

- The payload shape (likely a `schema_v3` bump)
- The collector's structure (the existing 725-line zsh script is at the upper end of maintainability — doubling it needs a refactor first)
- The DB model (per-tenant rule activation has no schema today)
- The dashboard surface (no tenant-level rule customisation UI exists)
- Time-to-first-revenue (a non-trivial amount of work)

**Constraints / forces in play:**

- **Solo maintainer.** Andy is the only engineer. Whatever path is taken must stay maintainable by one person.
- **Pre-revenue, pre-incorporation.** Patched.im Ltd. incorporation in motion; gates DUNS / Apple Developer ID / signed-pkg work. v1 agent is intentionally unsigned-zsh-via-Intune.
- **IoM SME market positioning.** Compliance is the compelling event, not patching. Buyers respond to "tell me what's wrong with my fleet"; "we check 17 things" is a weaker pitch than "we monitor 100 signals and surface what matters for your insurer / auditor".
- **`rules are data, not Go code` convention.** Already established. The decision here is whether collection should follow the same data-driven shape, or stay coupled to whatever rules are enabled in code.
- **macOS version drift.** `patched-collect.sh` already handles macOS 26 parser changes (per CLAUDE.md known traps). Each new collected signal multiplies the surface for silent breakage.
- **Privacy / PII boundary.** Some L1 controls reach into user-specific configuration. BYOD-style endpoints in IoM SMEs mean what's collected becomes a story we have to tell.
- **Schema migration cost on live data.** Doing this before customer #1 is cheap. After #1, every collection change becomes a migration event.

---

## Decision

**Adopt a three-tier collection model.** Refactor the collector to support it, design the per-tenant policy model, and roll out the expanded collection in phased batches.

- **Tier 1 — Collect always, evaluate always.** The 17 controls currently implemented. Core baseline; default-on for every tenant.
- **Tier 2 — Collect always, evaluate per-tenant policy.** The rest of the CIS macOS Sonoma L1 surface (~80–100 more controls). Signals flow into `raw_payloads` and the extracted tables; the evaluator runs only the rules enabled for that tenant.
- **Tier 3 — Out of scope (for now).** CIS L2, user-elective recommendations, anything that varies meaningfully per-host rather than per-fleet. Re-evaluate quarterly or when a tenant specifically requests.

This is **Option B** below.

---

## Options Considered

### Option A: Status quo — narrow collection (just the 17 controls)

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low (already done) |
| Cost | Low (no schema work, no collector expansion) |
| Scalability | Fine (small payloads) |
| Team familiarity | Highest |
| Time to revenue | Already shippable |

**Pros:**
- Smallest surface area for collector failures
- Already in production; no migration risk
- Maintainable indefinitely by a solo engineer

**Cons:**
- No backfill data when new rules are added — a tenant enabling rule X on day 100 sees compliance status from day 100, not day 1
- Compelling-event narrative is weaker — "we check 17 things" reads as a checklist, not a platform
- Every new rule requires an agent re-deploy if its signal isn't already collected
- Brittle for tenant customisation; different SMEs (insurer-aligned, regulator-aligned, vendor-aligned) want different baselines
- Inverts the "rules are data, not Go code" principle for the collector — collection stays coupled to evaluator state

### Option B: Three-tier — full L1 collection, per-tenant evaluation

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium (collector expansion + new policy model) |
| Cost | Medium (schema_v3, more storage, new dashboard surfaces) |
| Scalability | OK with monthly partitions (pg_partman wiring becomes more pressing) |
| Team familiarity | Medium (full L1 surface needs inventorying) |
| Time to revenue | Delay measured in weeks, not months |

**Pros:**
- Backfill data — historical compliance evidence available immediately when a rule is activated
- Single agent version per OS; all policy centralised in DB
- Stronger architect-positioning story ("we collect the full CIS L1 surface; tenants choose what to evaluate")
- "Compliance from zero" first-scan demo is more revealing — supports IoM SME sales motion
- Per-tenant customisation without redeploy; aligns with insurer-driven adoption
- Extends the "rules are data" convention to collection — symmetric architecture

**Cons:**
- Schema_v3 migration commitment; v2-extractor maintenance during transition
- 725-line collector grows; needs a structural refactor (per-CIS-section modules) before doubling
- PII boundary widens — every new signal needs a "what does observing this reveal about the user" entry in the catalogue
- New DB tables (`tenant_rules`, audit), new dashboard surface for managing policy
- Storage growth — `raw_payloads` partitions grow faster (R2 backup wiring becomes more urgent — already on backlog)
- Time-to-first-revenue extends; weeks-not-months of foundational work

### Option C: Collect everything (L1 + L2 + extras)

| Dimension | Assessment |
|-----------|------------|
| Complexity | High (L2 touches deeper system internals, audit log config, etc.) |
| Cost | High (large payloads, more extractor work, big collector) |
| Scalability | Strained — large payloads × fleet × daily |
| Team familiarity | Low (L2 is meaningfully different surface) |
| Time to revenue | Months |

**Pros:**
- Most comprehensive collection story
- Future-proof against any rule activation
- Maximum optionality

**Cons:**
- L2 controls vary by org policy in ways that don't make sense at fleet level
- PII / privacy story gets materially harder
- Collector reliability suffers — many more macOS version quirks
- ROI on L2 unclear until a customer specifically demands it
- Single-engineer maintainability becomes the constraint

### Option D: Per-tenant agent builds

Each tenant gets a custom collector script with only their enabled signals.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Very High |
| Cost | High (build pipeline + signing per tenant) |
| Scalability | Fails by design once tenants > 5 |
| Team familiarity | Anti-pattern |
| Time to revenue | Months — and worsens with tenant count |

**Rejected.** Fragments the codebase, breaks the eventual signed-pkg story (each tenant build needs its own signing run post-incorporation), provides no backfill data, and inverts the "rules are data" convention. Discussed for completeness only.

---

## Trade-off Analysis

The pivotal axis is **time-to-revenue vs differentiation/optionality.**

Option A wins on time-to-revenue at the cost of architectural optionality and pitch strength. Option B sacrifices some weeks of foundational work for materially better positioning, a future-proof policy model, and backfill data that becomes valuable the moment a tenant activates a new rule. Option C buys maximum optionality at a cost that doesn't pay back before product-market fit.

For Patched.im specifically, three memory-backed factors tip the balance:

1. **Compliance-as-compelling-event** (per `project_iom_mac_market_reality.md`). Buyers don't respond to checklists; they respond to "what's wrong with my fleet right now." A platform that collects 100 signals and prioritises what matters for *their* insurer/auditor outperforms one that checks 17 boxes.

2. **Architect positioning** (per `project_endpoint_architect_positioning.md`). The architectural story is part of the sale. "Full CIS L1 surface, per-tenant policy" is a defensible technical pitch — to Jamf, to insurers, to auditors. "We have 17 hand-picked rules" is not.

3. **Insurer-driven adoption variance.** Different insurers care about different controls. A per-tenant policy model (which Option B requires anyway) is the right shape for a multi-vertical SME play. Building it later means schema migrations on live customer data.

The cost — schema_v3 + collector refactor + new policy model + delayed revenue by weeks — is the right investment to make pre-customer rather than post-.

**Decision: Option B.**

---

## Consequences

**What becomes easier:**

- Activating a new rule for a tenant is a DB update; no agent re-deploy, with immediate backfill of historical signals
- Pitching the architecture to technical buyers, channel partners (Jamf contacts per `reference_jamf_relationships.md`), and insurers
- Selling the same product to insurer-aligned tenants with different baselines
- Audit / replay scenarios — historical signals are present even if not evaluated at the time
- Symmetric architecture: collection is data-driven the same way rules are

**What becomes harder:**

- Collector reliability work — more macOS version quirks to track across Sonoma 14, Sequoia 15, macOS 26 (already in CLAUDE.md known traps)
- Schema migration discipline — `schema_v3` commits us to v2-extractor maintenance during transition, and to a deliberate forward-compat plan for `schema_v4`+
- Privacy posture — every newly-collected signal needs a "what about the user does this reveal" column in the rule catalogue, plus a published privacy story
- Storage growth — `raw_payloads` partitions grow faster; R2 backup wiring (currently backlog item 7) becomes more urgent
- Test surface — extractor + evaluator coverage grows with the collected fields; CI run time will increase

**What we'll need to revisit:**

- **`pg_partman` automation.** Manual monthly partitioning is annoying at 30+ fields per device per 15 min; it becomes painful at 100+ fields. Wiring `pg_partman` properly is on the backlog and gets more pressing.
- **Wire compression.** Larger payloads make on-wire compression (`Content-Encoding: gzip`) more worthwhile. Likely add when `schema_v3` lands.
- **Collection cadence.** A 15-minute batch upload of 200 fields × N devices is heavier than the current scheme. Consider event-driven collection for slow-changing signals (FileVault state doesn't need 15-min cadence; pending updates might).
- **CIS L2.** Defer until a tenant specifically asks. Revisit quarterly. Some L2 items (e.g. screensaver lockout enforcement) may be candidates for opt-in collection earlier than full L2.
- **PII filtering.** Once T2 expands collection meaningfully, may need to add server-side filtering / redaction of specific fields per tenant agreement.
- **Versioning windows.** When `schema_v4` arrives, decide policy on how long we maintain `v3` extraction (suggestion: 90 days from the first `v4` agent in production, with a deprecation notice in the agent rollout doc).

---

## Action Items

**All six items below are complete. This section is preserved as a historical record.**

Roadmap, sequenced to keep changes small and reversible. Items 1–3 are ordering-sensitive; items 4–6 can run in parallel once the foundation is in.

1. [ ] **Inventory the gap.** Enumerate the full CIS macOS Sonoma 14 L1 (and Sequoia 15 L1 if benchmark is out) control surface vs the 17 implemented today. Output: `go-service/docs/CIS_L1_GAP.md` — delta table with recommended collection methods per missing control + a "PII observation" column. Estimate ~half day.

2. [ ] **Refactor `patched-collect.sh`** into composable modules before doubling its size. Each CIS section gets its own collector function or sourced script fragment. Backward-compat output — same JSON shape, internally restructured. Estimate ~half day to one day.

3. [ ] **Design tenant policy model.** Migration `0005_tenant_rules.sql`: `tenant_rules(tenant_id, rule_id, enabled, override_severity, suppression_reason, suppressed_until)`, `tenant_rule_changes` audit table. Include per-rule `pii_observed` and `requires_user_consent` columns on `compliance_rules`. Estimate ~half day.

4. [ ] **Schema_v3 design + extractor extension.** Collector emits new sections; extractor parses them into typed tables. Update `PAYLOAD_SCHEMA.md` and `payload.schema.json`. Keep v2 extraction working during transition. Estimate ~two days.

5. [ ] **Phase the collector expansion.** Add CIS L1 controls in batches of 10–15. Each batch: collector function + extractor handling + rule INSERTs + evaluator test. Estimate ~one batch per session, ~6–10 sessions total.

6. [ ] **Dashboard surface for tenant policy.** Manage enabled/disabled rules per tenant, surface PII implications, show audit log. Estimate ~one day.

7. [ ] **Update product positioning** once T2 collection is live for ~2 months and we have backfill stories to tell. Site copy, CVE leave-behind, sales narrative.

**Linkage to existing backlog:**

- Backlog item 15 (rule-pack import tool) — accelerates step 5. Build before starting the rule batches.
- Backlog item 14 (learning notes) — capture per-rule rationale alongside the catalogue. Lands after step 1.
- Backlog item 12 (Windows agent + CIS Windows L1) — parallel architectural concern; the tenant policy model from step 3 applies cleanly to both. Don't duplicate the design — extend it.
- Backlog item 7 (Backup / DR — Restic to R2) — promote in urgency once `schema_v3` lands.
- Backlog item 9 (Observability) — extractor performance becomes more interesting to monitor; promote after step 5 batch 2.

**Cross-references:**

- `go-service/docs/PAYLOAD_SCHEMA.md` — schema versioning model (will gain `schema_v3` section)
- `go-service/docs/CIS_RULES.md` — rule catalogue (will gain `pii_observed` column + T2/T1 distinction)
- `macos-agent/README.md` — collector architecture (will be updated to reflect the modularised structure)
- `CLAUDE.md` — known traps (add a "schema_v3 transition" entry when the migration is in progress)

**Definition of Done for this ADR (per `feedback_doc_before_close_out.md`):**

- This ADR file committed to `go-service/docs/adr/0001-cis-collection-scope.md`
- Notion arch page "API VPS architecture" updated with a link to the ADR + a one-paragraph summary
- `cowork-handover.md` updated to reflect the new build-track ordering (CIS gap inventory becomes the next concrete step, ahead of the rule-pack import tool — though the import tool may slot in between step 1 and step 5)
