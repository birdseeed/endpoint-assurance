# patched.im

Endpoint inventory + CIS L1 compliance scoring for SME estates running Intune (Windows + macOS).
Two-VPS Hetzner footprint: marketing/admin surface on `patched.im`, ingestion + customer dashboard on `api.patched.im` / `app.patched.im`, joined by a Tailscale tailnet.

This repo is the **server-side** platform: ingestion service, extractor, CIS rule engine, infra config, and design/decision notes. **Endpoint agents live in `Patched-LTD/updater`** — the macOS collector (`macos/`) and updater, and the Windows agent (`windows/`). This repo *serves* them (ingestion, the signed agent-config endpoint, the `contracts/` wire format); it holds no agent code.

## Where to start

If you are opening this cold:

- **[go-service/docs/architecture.md](go-service/docs/architecture.md)** — canonical architecture page for the API VPS. The "Current state" block is the live production snapshot; update it on every deploy.
- **`Patched-LTD/docs`**: public customer help content for [`docs.patched.im`](https://docs.patched.im), deployed from its own Cloudflare Workers Static Assets project. This repository does not publish that hostname.
- **Linear: Architecture docs backlog** — open architecture documentation issues in Linear team PAT (Docs project).

### Reference docs

The latest verified API release explicitly separates OS-not-reported Jamf
coverage from known non-macOS devices. Workflow 37458778734 installed PR #753;
artifact, receipt, installed and running hashes agree, with healthy services.
The current-state snapshot records the synthetic report and route-parity proof.

The latest verified API release also bounds self-service access member pages,
retains disabled members and exposes explicit completeness for members and
invitations. Workflow 37456659577 installed PR #752 with signup still disabled;
all three artifact/receipt/installed hashes and live health checks agree.
The enabled portal journey remains separate preparation under PAT-1884.

Production insurance encryption evidence is verified in the current-state
snapshot: known off and unknown remain separate in the page, CSV and PDF.

The latest verified API release includes the self-service signup backend with
its flag off. The production snapshot above records the installed binaries and
the remaining activation and customer-journey evidence gates.

| Doc | What it covers |
|---|---|
| [docs/architecture-overview.md](docs/architecture-overview.md) | **Audit-ready architectural overview** — system context diagram, all components, trust/auth model, data model, network/infra, backup/DR, deployment, secrets, tenancy model (snapshot) |
| [docs/threat-model.md](docs/threat-model.md) | **STRIDE threat model** — trust boundaries, STRIDE analysis per component, key handling, tamper resistance, data minimisation, BYOD scoping, log hygiene, compliance mappings (snapshot) |
| [go-service/docs/SETUP.md](go-service/docs/SETUP.md) | Clone-to-running-locally for the Go service |
| [go-service/docs/API.md](go-service/docs/API.md) | All 6 HTTP routes: auth requirements, request/response shapes, error codes |
| [go-service/docs/PAYLOAD_SCHEMA.md](go-service/docs/PAYLOAD_SCHEMA.md) | Canonical JSON shape for `POST /v1/inventory` payloads |
| [go-service/docs/payload.schema.json](go-service/docs/payload.schema.json) | JSON Schema 2020-12 for programmatic validation |
| [go-service/docs/SCHEMA.md](go-service/docs/SCHEMA.md) | Postgres schema: all tables, columns, indexes, retention |
| [go-service/docs/CIS_RULES.md](go-service/docs/CIS_RULES.md) | CIS L1 rule catalogue — macOS (90 controls) and Windows (52 controls) |
| [go-service/docs/TESTING.md](go-service/docs/TESTING.md) | Test coverage, philosophy, how to run, what's deliberately excluded |
| api-vps-artefacts/OPERATIONS.md | Ops runbooks: service down, extractor lag, key rotation, deploy |
| api-vps-artefacts/BACKUP_DR.md | **Backup, DR, and recovery objectives** — 3-2-1 strategy, RPO/RTO targets, per-scenario DR steps, drill procedure, backup security (snapshot) |
| updater → macos/README.md | macOS collector (what it collects, Intune deployment, debugging) — now in the `updater` repo |
| [docs/prod-01-architecture.md](docs/prod-01-architecture.md) | **Main box (example-prod-host) architecture** — services (marketing site + ops dashboard), network posture, TLS, recovery runbook (snapshot) |
| [docs/artefact-pipeline-architecture.md](docs/artefact-pipeline-architecture.md) | **Artefact pipeline** — current verifier, planned staging catalog + Ed25519 signed records, tenant deployment gate, artefact caching (snapshot) |
| [docs/secrets-management.md](docs/secrets-management.md) | **Secrets management** — secrets inventory, current storage model (env files + password manager), rotation procedures, gaps and roadmap (snapshot) |
| [go-service/docs/CIS_SCORING_ARCHITECTURE.md](go-service/docs/CIS_SCORING_ARCHITECTURE.md) | **CIS L1 compliance scoring architecture** — rule engine design, T1/T2 tier model, per-tenant policy, signal sourcing, benchmark versioning |
| [go-service/docs/AUDIT_STORE.md](go-service/docs/AUDIT_STORE.md) | **Audit store** — current coverage, event taxonomy, proposed schema, retention policy, SIEM shipping roadmap (snapshot) |
| [go-service/docs/NETWORK_TOPOLOGY.md](go-service/docs/NETWORK_TOPOLOGY.md) | **Network topology** — Cloudflare DNS posture, Hetzner FW rules, Tailscale overlay, TLS map, traffic flows, Postgres network posture, egress matrix (snapshot) |
| [go-service/docs/OBSERVABILITY.md](go-service/docs/OBSERVABILITY.md) | **Observability and logging** — Prometheus metrics (live), named gaps, planned alert rules, Grafana dashboards, structured logging roadmap (snapshot) |
| [go-service/docs/learning-notes/](go-service/docs/learning-notes/) | **Learning notes** — per-subsystem rationale notes (ingestion, auth, extractor, rule engine, tenant model, backup, observability, migrations) + per-rule CIS L1 notes |

## Layout

```
go-service/             — Go binaries
                          ├── cmd/patched-api/        ingestion service (POST /v1/inventory, admin endpoints)
                          ├── cmd/patched-extractor/  raw_payloads → devices / device_apps / compliance_signals worker
                          ├── internal/auth/          bearer + HMAC verification
                          ├── internal/db/            Postgres connection pool
                          ├── internal/evaluator/     CIS L1 rule engine
                          ├── internal/extractor/     schema_v2 payload extraction
                          ├── internal/handlers/      HTTP handlers
                          ├── internal/report/        compliance PDF report renderer
                          └── migrations/             SQL migrations applied with psql
contracts/              — wire-format authoring (agent-config schema); agents consume it
api-vps-artefacts/      — Caddyfile, pg_hba, systemd units, Tailscale ACL, provisioning checklist
.github/workflows/      — CI: go test/vet/build, Tailscale ACL validation
```

Endpoint agents (macOS collector + updater, Windows agent) are **not** in this repo — they live in `Patched-LTD/updater`. The macOS collector was imported there with history under PAT-384. The `infra/`, `docs/`, `runbooks/` directories from the planned monorepo shape (backlog item 13) are not yet populated — they land as the corresponding work does.

## Conventions

- Pre-commit runs `gitleaks protect --staged --redact` (see `.git/hooks/pre-commit`). Install with `brew install gitleaks` if it isn't already present.
- Per-machine deployment artefacts (Tailscale-IP-baked configs, bearer tokens, HMAC secrets) live in `/etc/patched/` or `/etc/patched-api/` on the deployed boxes; they are never committed. `.gitignore` covers the in-tree rendered forms (`*.ready`, `*-secret`, `*-creds`).
