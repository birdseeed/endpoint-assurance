# Security posture & audit-evidence pack — Patched.im

**Purpose.** A single, maintained document that a prospect's security reviewer, an insurer, or an
auditor can be shown to understand Patched's security architecture and controls without reading the
whole codebase. Patched sells to compliance-led SMEs (legal / financial / IoM-regulated) whose
vendor take-on includes a security review — and, as a security product, we expect to be scrutinised
harder than most.

**Status:** Living document. Accurate to production as of the [`architecture.md`](./architecture.md)
"Current state" block. **Update on any material infra/security change** — git history is the
control-evidence trail.
**Linear:** PAT-411 (this pack). Pre-incorporation; planned transfer to `Patched.im Ltd.`
**Scope of stage:** pre-revenue, pre-first-customer. Several controls are deliberately deferred to
the first paying customer to keep iteration fast; those are listed honestly in [§10 Open items](#10-open-items--honest-gaps).

> **This document does not re-derive the architecture — it consolidates and cites it.** Each section
> points to the authoritative source doc. Where this doc and a source doc disagree, the source doc
> (and ultimately the deployed reality) wins; raise the drift as a fix.

---

## 1. System overview & data flow

Patched ingests endpoint inventory + CIS L1 compliance signals from customer fleets (macOS +
Windows, managed via Intune) and produces compliance/CVE reports. Server-side only; the endpoint
agents live in the separate `Patched-LTD/updater` repo.

Two Hetzner VPS, both behind Cloudflare proxy + a Tailscale admin overlay:

| Box | Role | Public surface | Data store |
|---|---|---|---|
| `example-api-host` (HEL1, CPX22 x86) | Go ingestion API + extractor | `api.patched.im` (CF-proxied) | Postgres 16 (system of record) |
| `example-prod-host` (NBG1, CAX21 Arm64) | FastAPI ops dashboard + report delivery | `dashboard.patched.im` (CF-proxied + CF Access) | SQLite `dashboard.db` + `reports/` |

**Primary data flow (ingestion):**

```
Managed endpoint (anywhere) → Cloudflare edge (WAF + DDoS + TLS)
  → Caddy :443 on api-01 (CF Origin Cert) → Go :8080 (bearer + HMAC + replay + rate-limit)
  → Postgres (raw_payloads = immutable source of truth) → extractor → typed/compliance tables
```

**Admin/control flow:** dashboard on prod-01 → Tailscale → api-01 internal admin API (`:8443` →
Go `:8081`), Tailscale-only, no public DNS record. Cross-box DB access is **not** permitted
(see §4); boxes exchange data only over HTTP admin endpoints.

Full diagrams and traffic flows: [`NETWORK_TOPOLOGY.md`](./NETWORK_TOPOLOGY.md) and [`../../docs/architecture-overview.md`](../../docs/architecture-overview.md), which holds the security posture and threat model since PAT-1057.

---

## 2. Network security — three filtering layers

Outside-in, the same model on both boxes (source: dashboard `HARDENING-SUMMARY-2026-11-14.md`,
dashboard `CLAUDE.md`, [`NETWORK_TOPOLOGY.md`](./NETWORK_TOPOLOGY.md)):

1. **Cloudflare edge** — both public hostnames are orange-cloud proxied; the origin IP is hidden
   from DNS. CF provides WAF (default ruleset), volumetric DDoS scrubbing, and TLS termination at
   the edge. `dashboard.patched.im` additionally sits behind **Cloudflare Access** (email-OTP / SSO,
   team-only) — unauthenticated requests never reach the origin.
2. **Hetzner Cloud Firewall** (`example-api-host-edge`, `example-prod-host-edge`) — primary edge filter:
   TCP 80/443 from **Cloudflare published ranges only** (v4 + v6), UDP 41641 from anywhere
   (Tailscale WireGuard), ICMP. **No public SSH** (TCP 22 blocked at edge on both boxes). Rules are
   regenerated daily by `hetzner-firewall-apply` timers that live-fetch the CF range list — config
   as code in the dashboard repo `deploy/`.
3. **Host firewall (UFW)** — defence-in-depth, parity with the edge: CF + Tailscale CGNAT
   (`100.64.0.0/10`) on 80/443, Tailscale CGNAT on 22, no `Anywhere` rules. On prod-01, **nginx**
   adds a fourth proxy layer (TLS via Origin Cert; `real_ip_header CF-Connecting-IP` for log
   accuracy — deliberately *not* an IP allowlist, see dashboard `CLAUDE.md` for the why).

**Admin access is Tailscale-only.** SSH is reachable solely over the tailnet (WireGuard arrives as
UDP 41641, decapsulates on `tailscale0`, bypassing the public INPUT chain). The home-IP SSH rule was
deliberately removed; emergency access is the Hetzner Cloud Console (network-independent
browser TTY). No port 22 is exposed to the public internet on either box.

**Postgres is never public.** Listens on `127.0.0.1` and the Tailscale IP only; `pg_hba.conf`
restricts to localhost + the tailnet CIDR; UFW drops 5432 on the public interface. **No peer
Postgres access between boxes** — enforced in the Tailscale ACL.

---

## 3. Authentication & access control

| Surface | Mechanism | Source |
|---|---|---|
| **Endpoint ingestion** (`POST /v1/inventory`, `/v1/provenance`) | **Two-layer:** (1) `Authorization: Bearer <token>` → SHA-256-hashed lookup in `tenant_credentials` (plaintext never stored; multiple concurrent credentials for zero-downtime rotation); (2) `X-Patched-Signature` → current v3 HMAC-SHA256 binds method, endpoint, timestamp, nonce, and raw body with constant-time comparison. Transitional targetless-v2 and body-only fallbacks remain accepted pending measured retirement. Both checks run **before** any JSON parse or DB write. | api-01 `CLAUDE.md`, `internal/auth/`, [`architecture.md`](./architecture.md) |
| **Replay protection** | `X-Patched-Timestamp` freshness (±300 s) + `X-Patched-Nonce` rejection against `seen_nonces` (migration 0016). Live (PAT-338). | [`architecture.md`](./architecture.md) "Current state" |
| **Per-device posture** (`GET /v1/posture`) | Device-specific bearer (`device_credentials`, migration 0029) + HMAC + rate limit; per-device revocation via `device_revocations` (PAT-549). | [`architecture.md`](./architecture.md) |
| **Rate limiting** | Per-tenant 60 rpm, burst 10, enforced in the Go service; CF edge handles volumetric. | [`NETWORK_TOPOLOGY.md`](./NETWORK_TOPOLOGY.md) |
| **api-01 admin API** (`:8081` / `:8443`) | **No application-layer auth by design** — protected by three network layers: binds `127.0.0.1`, Caddy site bound to the Tailscale interface only, and a Tailscale ACL (`tag:main → tag:api:8443`). Tailscale membership is the gate. | api-01 `CLAUDE.md`, `tailscale-acl.json` |
| **Staff dashboard** | Cloudflare Access (email-OTP/SSO, team allowlist) at the edge **+** app-level Bearer middleware on `/api/*` and `/admin/*` (defence-in-depth, PAT-456). `/download` paths use the CF Access cookie (browser anchor clicks can't carry headers). | dashboard `CLAUDE.md`, dashboard `architecture.md` |
| **Tailscale ACL** | Least-privilege, default-deny. Admins reach all nodes; `tag:main → tag:api:8443` and `tag:api → tag:main:8443` only; **no peer Postgres**; Tailscale-SSH restricted to admins. Versioned (`tailscale-acl.json`) and CI-validated on every PR (`validate-tailscale-acl.yml`). | `api-vps-artefacts/tailscale-acl.json` |

Token recovery is impossible by design — only the SHA-256 hash is stored, so a leaked token is
rotated (issue a new credential, revoke the old), never recovered.

---

## 4. Data handling & classification

- **Raw payload is the immutable source of truth.** `raw_payloads.body` (JSONB, partitioned
  monthly) is the canonical archive; `devices`, `device_apps`, `compliance_signals`, etc. are
  *derived* and fully re-derivable by resetting extraction flags. Append-only ingestion path.
- **HMAC compatibility telemetry is aggregate and identity-free.** PAT-1872 stores only a closed
  accepted signing-form value, a sanitised reported agent version, count, and first/last seen
  times. The table has no tenant/device identifier or bearer token, HMAC secret, signature,
  request timestamp/nonce, body, source address, or user-agent field. Novel agent versions are
  capped at 64 and overflow to `Unknown`; this is the denial-of-service/storage-cardinality
  boundary against authenticated version churn. Admin visibility is authenticated and capped at
  260 rows. `HMAC_COMPATIBILITY_TELEMETRY_ENABLED=false` disables writes without changing auth.
- **Data categories processed:** device hardware identity (serial, hw UUID, hostname), OS posture
  (FileVault/BitLocker, SIP, Gatekeeper, etc.), installed-app inventory, CIS L1 compliance signals,
  pending updates, and agent provenance. This is **endpoint security state on customer hosts** — see
  the DPA gap in §10.
- **PII / primary-user attribution is opt-in, off by default** (PAT-116, in review). User-account
  attribution (who's on a host) is treated as PII: **new tenants get it OFF**; an admin enables it
  per-tenant after internal sign-off; even when on, email bodies redact to local-part and the full
  identifier appears only in the PDF. This is a deliberate privacy-by-default control, not an
  oversight. DPA coverage of device-user-association data is tracked in PAT-112.
- **Tenancy isolation.** Single-tenant-per-credential ingestion; all data keyed by `tenant_id`.
  The ops dashboard is Patched-team-internal (not multi-tenant customer-facing); a future
  customer-facing portal with server-side tenant scoping is roadmap, not built.
- **Retention.** `raw_payloads` partitioned monthly for cheap pruning; `reports/*.docx` pruned at
  90 days (PAT-87, Done); audit-table retention is specified per category in
  [`AUDIT_STORE.md`](./AUDIT_STORE.md) (90 d auth, 3 y admin, etc.) for when the unified store is built.

Source: api-01 `CLAUDE.md`, [`PAYLOAD_SCHEMA.md`](./PAYLOAD_SCHEMA.md), [`SCHEMA.md`](./SCHEMA.md), [`AUDIT_STORE.md`](./AUDIT_STORE.md).

---

## 5. Encryption

| Leg | Control |
|---|---|
| Browser ↔ Cloudflare | TLS 1.2/1.3 at the CF edge; HTTP/3 supported |
| Cloudflare ↔ origin (Caddy/nginx) | CF Origin Cert (`*.patched.im`, ~2041 validity); origin accepts CF ranges only |
| Endpoint ↔ api.patched.im | HTTPS (CF-proxied) + application HMAC over the body |
| Inter-box (admin, dashboard→api, backup pulls) | Tailscale WireGuard (ChaCha20-Poly1305); `tls internal` on the Caddy admin site as belt-and-braces |
| Postgres / SQLite at rest | Disk-level on the VPS; not separately app-encrypted (single-tenant box, network-isolated) |
| Backups at rest | restic client-side AES-256 (target R2 holds ciphertext only) — see §7 |

Source: [`NETWORK_TOPOLOGY.md`](./NETWORK_TOPOLOGY.md) §TLS map, [`architecture.md`](./architecture.md) §Security posture.

---

## 6. Secrets management & SDLC

- **Secrets live outside the repo**, in mode-600 root/service-owned env files on the box
  (`/etc/patched-api/env`, `/etc/patched-dashboard/dashboard.env`, etc.) and escrowed in a password
  manager + offline copy. Bearer tokens stored only as SHA-256 hashes. Agent-config responses are
  Ed25519-signed (`agent_config`, key `ecd47f2c5b3d5705`) — cert-over-secret where possible.
- **gitleaks** runs as a pre-commit hook (`gitleaks protect --staged --redact`) and in CI; `.gitignore`
  covers secret-shaped artefacts. No secret values appear in any doc — only their locations.
- **CI gates** (GitHub Actions): `go test/vet/build`, shellcheck, `zsh -n`, HuJSON Tailscale-ACL
  validation. Migrations are reviewed SQL.
- **Endpoint-trust / non-author review gate** (PAT-66, **Done **): no agent ships to a
  customer endpoint without a full code + security review by someone other than its author (macOS
  reviewed by Rob, Windows by Andy). Wired as a zero-touch CI gate in both `patched.im` and
  `updater` repos. Branch protection / required review is otherwise deferred to first customer
  (PAT-65) — this gate is the interim supply-chain safeguard.
- **Supply chain:** one generic agent artefact + signed per-tenant config; vendor-download sources
  for the Updater engine are in scope of GitHub-Non-Author-Review.

Source: api-01 `CLAUDE.md`, dashboard `CLAUDE.md`, PAT-66.

---

## 7. Backup & DR posture

- **Layered 3-2-1 (target):** Tier 0 live DBs → Tier 1 Hetzner Cloud snapshots (fast rollback,
  same account) → Tier 2 restic → Cloudflare R2 (client-side AES-256, immutable via bucket lock,
  off-provider/off-account).
- **Current reality (honest):** the independent offsite leg (R2) is **decided but not yet built**
  (PAT-84, blocked on R2 creds); the interim on-prem `pat-backup-01` box **has been
  retired** (PAT-401 canceled). Hetzner snapshots provide fast rollback today.
- **Alerting:** Alertmanager → Slack is **live** (PAT-20, Done) with **BackupFailed**
  / **BackupMissed** rules; backup-health heartbeats surface on the dashboard Service Health strip.
- **Restore testing:** procedure documented; **no full restore has been formally tested yet** —
  the quarterly restore-test checklist exists to change that.

Full detail, RTO/RPO, and per-failure-mode runbooks: `../../api-vps-artefacts/DR_PLAN.md`
and `../../api-vps-artefacts/BACKUP_DR.md`.

---

## 8. Observability, logging & audit

- **Metrics:** Prometheus on api-01 scraping `:8081/metrics` (HTTP rate/latency, extractor
  throughput/dead-letter). Grafana + Alertmanager + Slack are **live** (PAT-20, Done) with 7
  alert rules. Source: [`OBSERVABILITY.md`](./OBSERVABILITY.md), PAT-20.
- **Logs:** journald, 90-day retention (`MaxRetentionSec=7776000`, `SystemMaxUse=500M`). Request
  bodies (PII) are **not** logged. Auth-failure *reasons* are logged; auth events are not yet in the DB.
- **Audit trail (partial today):** several append-only tables already capture specific mutations —
  `tenant_rule_changes`, `tenant_platform_changes`, `tenant_allowlist_changes`, `provenance_records`,
  `device_revocations`, enrollment-token audit log, and `compliance_evaluations` (full eval history).
  `raw_payloads` is an immutable ingestion archive. **Gap:** no *unified* `audit_events` store, no
  admin-action log for all CRUD, no auth-event rows, no SIEM shipping — a documented pre-customer
  deliverable. Source: [`AUDIT_STORE.md`](./AUDIT_STORE.md).

---

## 9. Framework mapping (high level)

Mapped to the frameworks Patched's clientele and website cite. This is a **self-assessed,
indicative** mapping for reviewer orientation, not a certified attestation — none of these
certifications are held today.

| Control area | Cyber Essentials | ISO 27001 Annex A (2022) | IoM FSA / Applied UK-GDPR Art. 32 | Patched status |
|---|---|---|---|---|
| Firewalls / boundary | CE: Firewalls | A.8.20–8.22 (network security/segregation) | Art.32 "appropriate technical measures" | ✅ 3 filtering layers (§2) |
| Secure config | CE: Secure configuration | A.8.9 | — | ✅ no public SSH, no default-allow, CIS-aligned host posture |
| Access control | CE: User access control | A.5.15–5.18, A.8.2–8.5 | FSA outsourcing/access; Art.32 | ✅ bearer+HMAC+replay; Tailscale-only admin; CF Access (§3) |
| Malware/supply chain | CE: Malware protection | A.8.25–8.31 (secure dev) | — | ✅ CI gates, GitHub-Non-Author-Review (§6) |
| Patch/vuln mgmt | CE: Security update mgmt | A.8.8 | — | ✅ this *is* the product surface; internal CVE scanning |
| Encryption | — | A.8.24 (cryptography) | Art.32(1)(a) | ✅ TLS in transit, WireGuard, restic AES-256 (§5) |
| Backup & recovery | — | A.8.13, A.5.29–5.30 (continuity) | Art.32(1)(c) restore availability | ⚠️ partial — R2 offsite pending PAT-84, untested restore (§7) |
| Logging & monitoring | — | A.8.15–8.16 | Art.32 | ⚠️ partial — metrics+alerting live; unified audit store pending (§8) |
| Data protection / DPA | — | A.5.34 (privacy/PII), A.5.19 (supplier) | UK GDPR / IoM DPA 2018 | ⚠️ PII opt-in built; **no DPA/MSA yet** (PAT-112) |
| Independent testing | — | A.8.29 (security testing) | — | ⚠️ **no pen test yet** (PAT-140) |
| CIS Controls (product) | — | — | — | ✅ CIS L1 evaluator. Current enabled inventory is derived from the live rule library after ordered migrations, not a hardcoded document count — see [`CIS_RULES.md`](./CIS_RULES.md) and [`contracts/portal-api.md`](../../contracts/portal-api.md#rule-count-source-of-truth). |

> **TODO: confirm (Andy)** — verify exactly which frameworks the public website currently cites
> (the ticket lists Cyber Essentials, ISO 27001 Annex A, IoM FSA, Applied-GDPR Art.32; the website
> may phrase these differently). Align wording so this table matches outward claims. Also confirm
> CIS L1 should be listed as a *recognised framework* per PAT-411 (it's both our product and a
> control set) — kept in the table for clarity.

---

## 10. Open items — honest gaps

Auditors and reviewers reward candour over hidden gaps. Stated plainly:

| Gap | Status / risk | Tracking |
|---|---|---|
| **Independent pen test not done** | No external adversarial testing yet; planned before customer #1 (grey-box, UK/EU firm). | PAT-140 |
| **No DPA / MSA in place** | Cannot formally onboard a paying customer until signed agreements exist; PII processing (PAT-116) needs DPA cover. | PAT-112 |
| **Offsite backup (R2) not built** | Independent immutable offsite leg pending R2 creds; interim cover only. | PAT-84 |
| **No tested restore** | Restore procedure documented but never executed end-to-end. | PAT-139 |
| **No unified audit store / SIEM** | Partial per-entity audit tables only; no admin-action or auth-event log, no log shipping. | [`AUDIT_STORE.md`](./AUDIT_STORE.md) |
| **Branch protection / required review deferred** | Deferred to first customer; GitHub-Non-Author-Review is the interim safeguard. | PAT-65, PAT-66 (Done) |
| **No formal certification held** | Cyber Essentials / ISO 27001 not yet pursued; framework mapping above is self-assessed. | PAT-130 (CE+) |
| **Single-founder bus factor** | No second on-call; DR plan is the mitigation. | PAT-139 |
| **No customer-facing portal yet** | Per-tenant portal (CF Access + SSO + server-side scoping) is roadmap, not built. | architecture roadmap |

> **TODO: confirm (Andy)** — PAT-411 also asks for a reusable **vendor-questionnaire response pack**
> (SIG-Lite / CAIQ-style pre-filled answers) and a curated **client-facing extract**. Those are not
> in this commit — this doc is the internal authoritative source they'd be drawn from. Want them as
> follow-on deliverables (separate ticket/PR), or appended here?

---

## Related docs

- [`architecture.md`](./architecture.md) — canonical api-01 architecture + "Current state" snapshot
- [`NETWORK_TOPOLOGY.md`](./NETWORK_TOPOLOGY.md) — network/host facts, TLS map, ACL, traffic flows
- [`AUDIT_STORE.md`](./AUDIT_STORE.md) — audit-event taxonomy, schema, retention, build trigger
- [`OBSERVABILITY.md`](./OBSERVABILITY.md) — metrics, logging, alerting
- [`CIS_RULES.md`](./CIS_RULES.md) — CIS L1 control catalogue + framework mappings
- `../../api-vps-artefacts/DR_PLAN.md` — disaster-recovery plan, RTO/RPO, restore runbooks
- dashboard repo `HARDENING-SUMMARY-2026-11-14.md` + `CLAUDE.md` — prod-01 network posture
- Linear: PAT-411 (this pack), PAT-66, PAT-116, PAT-140, PAT-112
