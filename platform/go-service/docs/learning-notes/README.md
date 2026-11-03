# Learning notes index

Per-rule and per-subsystem rationale notes. Each note answers: WHY does this control matter or HOW does this subsystem work, and any non-obvious implementation details. These complement the reference docs (API.md, SCHEMA.md, CIS_RULES.md) which answer the WHAT.

## Subsystem notes (PAT-36)

Eight short notes on the core server-side subsystems — written to ease solo maintenance when returning to a subsystem after months away.

| File | What it covers |
|---|---|
| [ingestion-path.md](ingestion-path.md) | `POST /v1/inventory` — the full flow from endpoint HTTP request to raw_payloads INSERT; async extract decoupling |
| [auth-model.md](auth-model.md) | Bearer + HMAC + timestamp + nonce: how the four-layer auth works, why each layer exists, credential lifecycle |
| [extractor.md](extractor.md) | `patched-extractor` poll loop, per-row extraction steps, dead-letter handling, buildSignalsMap |
| [rule-engine.md](rule-engine.md) | CIS L1 evaluator: rules-as-data, comparators, T1/T2 tiers, treat-unknown-as policy |
| [tenant-data-model.md](tenant-data-model.md) | Tenant hierarchy, multi-credential rotation, per-tenant rule policy (tenant_rules), PII gate |
| [backup-and-retention.md](backup-and-retention.md) | 3-2-1 strategy, R2 leg + retired pat-backup-01 leg (historical), RPO/RTO, data retention per table |
| [observability.md](observability.md) | Prometheus metrics wired today, health endpoint, gaps (Grafana, Alertmanager, SIEM) |
| [migrations-and-schema.md](migrations-and-schema.md) | Migration pattern, current state (0001–0035), key tables, raw_payloads partitioning, how to add a migration |

## CIS rule notes (PAT-22)

Per-rule rationale notes for the CIS L1 controls — answer WHY a control matters, what failure looks like in practice.

| File | Contents |
|---|---|
| macos-t1-rules.md | macOS CIS L1 T1 rules (17 always-on controls + `patched_mdm_enrolment`): FileVault, SIP, Gatekeeper, ALF, SSV, auto-updates, audit logging, sharing controls, screensaver, auto-login, admin count, password policy, pending updates, Secure Boot |

## Coverage

**Done:** subsystem recap notes (8, PAT-36); macOS T1 CIS rules (18 rules, PAT-22).

**To do:** macOS T2 batch 1–3 (35 rules), Windows T1 (13 rules), Windows T2 (39 rules).
