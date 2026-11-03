# Patched Platform — Threat Model and Security Architecture

**Framework:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
**Audience:** internal security review; customer/prospect security due-diligence; Cyber Essentials assessor
**Scope:** server-side platform (`Patched-LTD/patched.im`) and endpoint agents (`Patched-LTD/updater`)
**Related:** `docs/architecture-overview.md` (system context and component map)

---

## 1. Assets and trust boundaries

### Assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Per-tenant bearer tokens and HMAC keys | Critical — compromise allows impersonating endpoints | Critical — rotation is the only revocation path | High |
| Ed25519 signing private key | Critical — compromise allows forging agent-config and catalogue | Critical | High |
| Postgres device/compliance data | High — employee device inventory is personal data | High — tampering would corrupt audit evidence | Medium |
| `raw_payloads` (verbatim inventory) | High — GDPR-relevant, includes device identifiers | High — authoritative source of truth | Medium |
| Signed agent-config | N/A | Critical — forgery changes what the agent does | High |
| Signed verifier catalogue (`latest.signed.json`) | Low | Critical — hash forgery enables malicious installs | High |
| Admin API (`:8081`) | Critical — exposes all tenant data | Critical — admin writes affect all tenants | High |
| Tailscale tailnet membership | Critical — membership = admin access | Critical | High |

### Trust boundaries (TB)

| ID | Boundary | Direction | Mechanism |
|---|---|---|---|
| TB-1 | Public internet → Cloudflare edge | Ingress | Cloudflare WAF, orange-cloud proxy, CF origin cert |
| TB-2 | Cloudflare → Caddy / `example-api-host` | Ingress | CF-range-only Hetzner firewall, CF Origin Cert mutual TLS |
| TB-3 | Caddy → Go `:8080` (public endpoints) | Ingress | 5 MB body cap, passed TLS context |
| TB-4 | Endpoint agent → `/v1/inventory` | Data flow | Bearer token + HMAC-SHA256 + timestamp + nonce |
| TB-5 | Go service → Postgres | Data flow | Localhost + Tailscale CIDR, `pg_hba.conf` restriction |
| TB-6 | Operator → Tailscale → Caddy `:8443` → Go `:8081` | Admin | Tailscale ACL membership + MagicDNS (no public record) |
| TB-7 | CI pipeline → Ed25519 signing key | Signing | Key loaded from GitHub Actions secret; no HSM today |
| TB-8 | Endpoint → `/v1/agent-config` (signed response) | Config | Ed25519 signature verified by agent before acting |
| TB-9 | Agent → label catalogue (`latest.signed.json`) | Update | Ed25519 signature verified before any install |

---

## 2. STRIDE analysis

### 2.1 Endpoint agents (macOS `patched-collect.sh` / `patched-update.sh`; Windows service)

| Threat | STRIDE | Control in place | Residual risk | Status |
|---|---|---|---|---|
| Attacker replays a previously captured valid POST | **S** | `X-Patched-Nonce` checked against `seen_nonces`; `X-Patched-Timestamp` freshness ±300 s | Replay within 300-second window from a stolen packet capture | Low — window is short; requires MITM of TLS |
| Attacker spoofs a valid tenant by stealing bearer token from endpoint | **S** | Token lives in Intune Configuration Profile (macOS Keychain / Windows DPAPI) | Requires compromise of a managed endpoint with full disk access | Medium — v2 per-device JWTs reduce blast radius; deferred (PAT-513) |
| Compromised endpoint tampers with its own payload (inflating compliance scores) | **T** | Server evaluates raw signals against rule pack — client does not self-score | A compromised agent can emit false signal values | Low — requires root/SYSTEM and deliberate manipulation; signals are simple boolean/string values with server-side rules |
| Agent replaced with a malicious binary via MDM misconfiguration | **T** | Intune Platform Scripts are cryptographically signed by the MDM tenant; macOS LaunchDaemon path is root-owned | A compromised MDM tenant can push malicious scripts | Medium — acceptably low for current MDM-dependent deployment model; PKG signing (gated on Apple Developer ID) will add a second verification layer |
| Agent receives a forged agent-config | **T** | Response is Ed25519-signed; agent verifies signature against pinned public key before acting | N/A if private key not compromised | Low — see §4 (key handling) |
| Attacker installs a malicious app via a forged label catalogue entry | **T** | Catalogue is Ed25519-signed; each label enforces Team ID + Authenticode publisher; SHA-256 pinned for top-30 labels; runtime HTTPS-only enforcement in `Installomator.sh` | Requires signing key compromise or a label with no SHA-256 pin | Medium — SHA-256 pinning expansion to all labels is the roadmap (PAT-500) |
| Endpoint disclosure: agent payload contains employee identifiable data | **I** | Payload is TLS-encrypted in transit; bearer + HMAC required to ingest; data minimisation scope documented in `go-service/docs/PAYLOAD_SCHEMA.md` | Data at rest in Postgres is unencrypted (disk-level encryption depends on Hetzner host) | Medium — see §6 (data minimisation) |
| Agent does not verify verifier catalogue signature | **T** | Agent reads `latest.signed.json`; Ed25519 verification runs before any install; bad signature aborts with `PATCHED_VERIFICATION_FAILED` | — | Addressed |
| Agent log events suppressed by root attacker | **R** | `PATCHED_VERIFICATION_FAILED` and `PATCHED_POSTURE_WARNING` logged locally; structured SIEM shipping designed (PAT-499) | Local-only logs can be tampered by root | Medium — SIEM shipping wires this; not yet deployed |

### 2.2 Public ingestion endpoint (`POST /v1/inventory`, `/v1/provenance`, `/v1/posture`)

| Threat | STRIDE | Control in place | Residual risk | Status |
|---|---|---|---|---|
| Unauthenticated POST floods the endpoint | **D** | Cloudflare WAF + DDoS scrubbing at edge; 5 MB body cap before auth; per-tenant rate limit (60 rpm, burst 10) | Volumetric attacks exceeding CF capacity | Low — CF is the line; per-tenant bucket prevents legitimate-token flood |
| Bearer token brute-forced | **S** | Token is a high-entropy random value; no enumeration surface (wrong token → 401, no hint) | Offline brute-force against captured tokens | Negligible — token entropy is ~128 bits |
| HMAC forged without the key | **T** | HMAC-SHA256 is cryptographically unforgeable without the key | — | Addressed |
| Timestamp/nonce bypass allows replay | **S** | `X-Patched-Timestamp` ±300 s checked server-side; `X-Patched-Nonce` stored in `seen_nonces` | `seen_nonces` table grows unbounded without pruning | Low — pruning by age is the mitigation; `seen_nonces` currently trimmed at query time |
| Body-size attack (large payload exhausts memory) | **D** | Caddy `request_body { max_size 5MB }` rejects before Go parses | — | Addressed |
| Response reveals tenant existence (side-channel) | **I** | All auth failures return 401 with no distinguishing body | — | Addressed |
| Compromised Cloudflare account allows origin IP exposure | **I** | Origin IP (`203.0.113.20`) is blocked at Hetzner FW for all non-CF CIDRs | CF account compromise exposes CF-to-origin link | Low — hardened at Hetzner layer |

### 2.3 Admin surface (`:8081`, Tailscale-only)

| Threat | STRIDE | Control in place | Residual risk | Status |
|---|---|---|---|---|
| Attacker reaches `:8081` from the public internet | **S** | Caddy binds the admin site block to the Tailscale interface only; Hetzner FW blocks 8081 from public; no public DNS record | — | Addressed |
| Compromised Tailscale account gains admin access | **E** | Tailscale membership = admin access; no application-layer auth on `:8081` | A stolen Tailscale credential gives full admin API access | High — partially mitigated by Tailscale's SSO; mitigated in practice by single-developer tailnet |
| Admin API misuse — e.g., deleting a tenant | **T/R** | All `tenant_rule_changes` and `tenant_platform_changes` logged in append-only tables | No independent audit log for all admin API calls | Medium — full audit store is a deferred backlog item (PAT-29) |
| Postgres accessible from Tailscale network | **I** | `pg_hba.conf` restricts to `127.0.0.1` and Tailscale CIDR `100.64.0.0/10`; no public port | A tailnet member can reach Postgres directly | Low — tailnet membership is tightly controlled; Postgres has its own credential layer |

### 2.4 Signing and CI infrastructure

| Threat | STRIDE | Control in place | Residual risk | Status |
|---|---|---|---|---|
| Ed25519 private key exposed in git | **I** | Key is a GitHub Actions secret; pre-commit `gitleaks` hook; CI `secrets-scan` workflow | — | Addressed |
| Ed25519 key compromised via GitHub Actions secret | **T** | Signing is isolated to the release job; no HSM today | Key compromise allows forging agent-config and catalogue; rotation requires all agents to receive the new public key | High — HSM-backed key (YubiHSM 2 / KMS) is the roadmap (PAT-497) |
| Malicious label merged to `engine/labels/` | **T** | CI `validate-labels` gate (schema, Team ID format, HTTPS URL); GitHub-Non-Author-Review required on all PRs; CODEOWNERS (`engine/`) requires security-reviewer approval | Reviewer collusion or GitHub-Non-Author-Review bot compromise | Low — two independent gates |
| Verifier `verify.py` dependency compromised | **T** | Dependabot + pip-audit (PAT-509); pinned requirements | Supply chain attack on `requests`/`jsonschema` | Low — Dependabot alerts within 24 h of CVE publication |
| Build artefact tampered between build and release | **T** | SHA-256 published in GitHub release notes; release gated on `verify` job pass (PAT-507) | — | Addressed |
| Gitleaks false-negative on a real secret | **I** | Gitleaks uses pattern + entropy scan; pre-commit + CI | Novel secret patterns not yet in ruleset | Low — standard major secret types covered |
| Upstream Installomator security fix not adopted | **T** | Monitoring process documented (PAT-512); PAT-512 webhook/triage runbook in place | Delayed cherry-pick window | Low — weekly monitoring process |

### 2.5 Data plane — Postgres and backups

| Threat | STRIDE | Control in place | Residual risk | Status |
|---|---|---|---|---|
| Backup stolen from Cloudflare R2 | **I** | R2 bucket is private; credentials in `/etc/patched-api/` (not committed); `restic` repository is additionally encrypted with a repo password | R2 credentials exposure | Low — two-layer encryption (R2 IAM + restic encryption) |
| Backup modified to plant malicious data | **T** | `restic check` runs after each backup; SHA-256 tree integrity | — | Addressed |
| Postgres connection sniffed on Tailscale link | **I** | Tailscale is WireGuard-encrypted end-to-end; Postgres connection additionally uses TLS if configured | — | Low — WireGuard covers this |
| `raw_payloads` exfiltrated via compromised API service | **I** | Go service process is the only DB consumer; runs as a non-root systemd user; `raw_payloads` is immutable once written | A Go service exploit with SQL injection would reach all tenants | Medium — mitigated by parameterised queries throughout; formal pen-test deferred to pre-customer |

---

## 3. Key handling

### 3.1 Per-tenant bearer tokens and HMAC keys

- Generated at tenant provisioning (`POST /admin/tenants`).
- Stored at rest in Postgres `tenant_credentials` table (bearer token hashed for lookup; HMAC secret envelope-encrypted at rest; see §3.4).
- Deployed to endpoints via Intune Configuration Profile push (macOS Keychain / Windows DPAPI). Never transmitted in any other channel.
- Multiple concurrently-valid credentials per tenant allow zero-downtime rotation. `PUT /admin/tenants/{id}/credential` rotates in Ops runbook (`api-vps-artefacts/OPERATIONS.md §Key rotation`).
- Revocation is immediate: `PATCH /admin/tenants/{id}` with `revoked=true` blocks agents on the next request.

### 3.2 Ed25519 signing key (`key_id ecd47f2c5b3d5705`)

- Loaded by `patched-api` at startup from `/etc/patched-api/` env file (never committed; `.gitignore` covers rendered forms).
- Signs `GET /v1/agent-config` responses and the daily verifier catalogue (`latest.signed.json`).
- **Today:** stored as a plain secret in the GitHub Actions environment and as an env file on `example-api-host`. This is an acknowledged temporary state.
- **Roadmap:** YubiHSM 2 (offline) or cloud KMS (AWS KMS / Azure Key Vault), with signing requests proxied — the private key never leaves the HSM. Key rotation runbook documented in PAT-497.
- The public key is pinned in the agent build. Key rotation requires a coordinated agent update.

### 3.3 Restic and R2 credentials

- Stored in `/etc/patched-api/` env files (not committed). R2 IAM scoped to the `patched-backups` bucket only.
- `restic` repository has its own passphrase, providing a second encryption layer over R2's native encryption.

### 3.4 HMAC secret storage (envelope-encrypted at rest)

- Per-tenant HMAC secrets are stored in Postgres `tenant_credentials.hmac_secret` (BYTEA), envelope-encrypted at the application layer. Plaintext HMAC secrets never touch disk, so a Postgres-only compromise (dump, stolen volume, read replica) yields ciphertext, not usable secrets. Recovering a secret additionally requires the `PATCHED_KEK` key-encryption key, which lives only in the `patched-api` process environment on `example-api-host` (`/etc/patched-api/env`), never in the database.
- Scheme (`internal/envelope/envelope.go`, PAT-687): AES-256-GCM envelope encryption. A fresh 256-bit data-encryption key (DEK) is generated per value and AES-GCM-encrypts the plaintext; the DEK is itself wrapped with a long-lived 256-bit key-encryption key (KEK) read from the `PATCHED_KEK` environment variable (base64 32-byte key). Only the wrapped DEK and ciphertext are persisted. KEK rotation re-wraps DEKs rather than re-encrypting data.
- Read path: `auth.LookupTenantByBearer` (`internal/auth/bearer.go`) decrypts the stored secret on every bearer lookup via `envelope.Default().DecryptBytes`. Stored values carry a `penc1:` marker; unmarked values are treated as legacy plaintext and returned verbatim (decrypt-with-plaintext fallback), so rows written before the KEK was provisioned keep authenticating. A genuine decrypt failure is surfaced as an error rather than authenticating against a corrupt secret.
- Fail-closed startup: an unset `PATCHED_KEK` disables encryption (plaintext passthrough on write, for pre-provisioning); a set-but-malformed KEK is a hard startup error, so the service never silently writes plaintext when encryption was intended.
- Backfill: `cmd/patched-kek-backfill` is a one-shot, idempotent tool that envelope-encrypts any historical plaintext (unmarked) rows in the covered columns (`tenant_credentials.hmac_secret`, `tenants.hmac_secret`, `tenant_ca.ca_key_pem`, `tenant_webhooks.secret`). Values already carrying the marker are skipped, so re-running is a no-op.
- Residual note: the same value's DEK is wrapped by a single KEK held in the process environment. Moving the KEK into a dedicated secrets manager or HSM (see §7) would remove the on-box KEK-at-rest exposure; this is a further hardening step, not a gap in encryption coverage.

---

## 4. Tamper resistance

### Agent update pipeline

1. New version tagged in `Patched-LTD/updater`.
2. CI `verify` job: runs `validate-labels.py`, `shellcheck`, `zsh -n`, `.NET build`, CodeQL.
3. CI `release-gate` job: computes `sha256sum` of every build artefact; publishes as GitHub Release notes.
4. Endpoint update delivery: via Intune Platform Scripts (macOS) or WiX MSI re-deployment (Windows).
5. **Gap:** agent binary itself is not currently code-signed with a Patched-issued certificate (PKG signing gated on Apple Developer ID + incorporation). Endpoints rely on Intune signing the deployment action, not the artefact. This is explicitly noted in ADR-0009.

### Label-manifest integrity

- Every label is validated against `contracts/label.schema.json` at PR time (CI `validate-labels` gate).
- `expected_team_id` is enforced for every macOS label (10-character Apple Team ID); `expected_publisher` for Windows labels.
- At install time: Team ID / Authenticode publisher checked before execution; Gatekeeper notarisation checked via `spctl`; runtime `https://` URL scheme enforced before `curl`.
- SHA-256 pin in signed catalogue checked for top-30 labels; expansion in progress (PAT-500).

### Config integrity

- `GET /v1/agent-config` signs response with Ed25519. Agent verifies against the pinned public key; bad signature = abort.
- Signed catalogue (`latest.signed.json`) verified by agent before any install is triggered.

---

## 5. Data minimisation and BYOD scoping

### What the agent collects

The inventory payload is defined in `go-service/docs/PAYLOAD_SCHEMA.md`. Collection is bounded to:

- **Device identity:** hardware serial, hardware UUID, hostname, OS version, OS platform. No user account names, no home directory contents, no browser history, no file content.
- **System configuration signals:** FileVault / BitLocker state, SIP, Gatekeeper, pending OS updates, Defender status — signals needed to evaluate the CIS L1 control surface only.
- **App inventory:** installed app name, bundle ID, version, code-signing identity (Team ID / publisher). No installed-app data content (no licence keys, no stored credentials inside apps).
- **Software metering:** `last_used_at` and `launch_count` per app (macOS only via Spotlight metadata). Optional and configurable.

### What is explicitly NOT collected

- User credentials or session tokens.
- Documents, photos, or any file content from the user's home directory.
- Browser history, bookmarks, cookies.
- Email or calendar data.
- Communications (messages, calls).
- Personal app data (banking apps, personal storage, health apps).

### BYOD scoping

The Patched agent is deployed via Intune and therefore inherently scoped to Intune-enrolled devices. Personal (BYOD) devices not enrolled in the corporate Intune tenant do not receive the agent and are not inventoried.

For BYOD-enrolled devices (where the employer manages a work profile / container):

- macOS PPPC profile restricts the agent to System-level data only (no user-profile-level access unless explicitly granted by the PPPC profile).
- The agent runs as root (LaunchDaemon) and cannot be scoped below system-level by the OS. Customers deploying to BYOD should review what the PPPC profile allows (documented in `updater/macos/README.md`).
- Windows: the Windows service runs as LocalSystem; scoped to registry keys and WMI classes that report system-level compliance state, not user-profile data.

### Retention

- `raw_payloads`: immutable; partitioned monthly. Pruning policy (soft-delete by partition drop) is not yet automated — see `docs/architecture-overview.md` section Open items (moved there under PAT-1057).
- `device_apps`, `compliance_signals`, `compliance_evaluations`: overwritten / appended on each inventory cycle; no separate expiry.
- Retention and deletion-on-request SLA: not yet formally documented (pre-customer). Must be addressed before first paid customer under any EU GDPR or IoM DPA contract.

---

## 6. Log hygiene

### What is logged today

- Structured Go `log/slog` output: per-request method, path, status code, duration (JSON lines). No request body, no bearer token, no tenant data in logs.
- `patched-extractor` logs per-row result and batch size.
- Prometheus time-series at `GET :8081/metrics` (route + status dimensions; no per-tenant cardinality).
- macOS agent: `PATCHED_VERIFICATION_FAILED`, `PATCHED_POSTURE_WARNING`, `PATCHED_UPLOAD_ERROR` events to `/var/log/patched/` (system log, root-owned).
- Windows agent: Windows Application Event Log under source `PatchedAgent`.

### Gaps

- No structured audit log of admin API calls (admin writes to `:8081` leave no independent trail beyond the DB `_changes` tables). Full audit store is deferred (PAT-29).
- Agent verification events are local-only. A root attacker can suppress or alter them. Structured SIEM shipping is designed (PAT-499) but not yet deployed.
- No alerting on repeated auth failures or unusual inventory POST rates. Planned via Grafana + Alertmanager (PAT-20).

### What is explicitly excluded from logs

- Bearer tokens and HMAC keys: never logged, even on auth failure. The 401 response body is a static string.
- Request body content: the ingestion handler rejects oversized bodies before logging; normalised structs (not raw JSON) reach the extractor.
- Personal data fields from the inventory payload: log lines reference `tenant_id` and `device_id` (opaque UUIDs), not hostnames, serial numbers, or employee names.

---

## 7. Open items and roadmap

| Item | Risk addressed | Status |
|---|---|---|
| HSM-backed Ed25519 key (PAT-497) | Key compromise enables config/catalogue forgery | Designed; deferred (no HSM yet) |
| Full audit store for admin API (PAT-29) | Repudiation of admin actions | Deferred (pre-customer) |
| SIEM log shipping for agent verification events (PAT-499) | Tampering with local agent logs | Designed; not yet wired |
| SHA-256 pinning for all labels (PAT-500) | Vendor CDN compromise delivers wrong binary | In progress (top-30 done) |
| Per-device JWT v2 auth (PAT-513) | Stolen tenant credential affects all devices | Designed; deferred |
| Apple Developer ID PKG signing (PAT-507, PAT-9) | Agent binary integrity on unmanaged path | Gated on incorporation → Developer ID enrolment |
| Grafana + Alertmanager (PAT-20) | No alerting on auth failure / backup failure | VPS access needed |
| Retention / deletion-on-request policy | GDPR / IoM DPA compliance | Pre-customer requirement |
| Formal penetration test | Unknown vulnerabilities in Go service | Planned pre-revenue |
| KEK into secrets manager / HSM (PAT-687 follow-on) | On-box `PATCHED_KEK` at rest on `example-api-host` | Hardening; deferred. Application-layer envelope encryption of HMAC secrets is shipped (§3.4); this would remove the remaining on-box KEK exposure |

---

## 8. Compliance mappings

| Control | Cyber Essentials | GDPR Art. 25 (Privacy by Design) | SOC 2 Type I (indicative) |
|---|---|---|---|
| TLS 1.2/1.3 only at edge | CE+ boundary firewalls | Encryption in transit | CC6.7 |
| Bearer + HMAC auth on all ingestion | CE+ access control | Authorisation mechanism | CC6.1 |
| Nonce replay protection | — | — | CC7.2 |
| Per-tenant data isolation | — | Data minimisation | CC6.3 |
| Tailscale-only admin access, no public SSH | CE+ boundary firewalls | — | CC6.6 |
| Gitleaks + CodeQL in CI | CE+ patch management | — | CC8.1 |
| Restic nightly backups + local DR | CE+ (backup) | Availability | A1.2 |
| Data minimisation (no user content collected) | — | Art. 5(1)(c) | CC2.1 |
| GDPR-scoped collection (Intune-enrolled only) | — | Art. 25 | CC2.1 |
