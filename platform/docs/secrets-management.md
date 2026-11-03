# Secrets management

**Status:** Current state — env files + password manager. No secrets vault in production yet. Azure Key Vault / HSM are roadmap items.

---

## Secrets inventory

All secrets that must be protected in the current production deployment:

| Secret | Where stored | Owner | Rotation procedure |
|---|---|---|---|
| Postgres `DATABASE_URL` | `/etc/patched-api/env` (root 600) | api-01 | Manual; requires binary restart |
| `patched-api` internal listen addrs | `/etc/patched-api/env` (root 600) | api-01 | Config, not a secret — in same file |
| Extractor env (`DATABASE_URL`, `EXTRACTOR_*`) | `/etc/patched-extractor/env` (root 600) | api-01 | Manual; requires extractor restart |
| Per-tenant bearer tokens (plaintext, endpoint-deployed) | `/etc/patched/` per-tenant dirs (root 600) | Managed endpoints via Intune | `POST /admin/tenants/{id}/rotate-credentials` (24h grace) |
| Per-tenant HMAC secrets (base64, endpoint-deployed) | `/etc/patched/` per-tenant dirs (root 600) | Managed endpoints via Intune | Same as bearer tokens |
| Restic repo password (R2 leg) | `/etc/patched-api/backup.env` (root 600) | api-01 | Manual; would require re-init of R2 repo if changed |
| R2 API key + secret | `/etc/patched-api/backup.env` (root 600) | api-01 | Cloudflare dashboard → new token → update backup.env |
| CF Origin Cert private key (`*.patched.im`) | `/etc/ssl/api.patched.im.key` (root 600) | api-01 + prod-01 | Cloudflare dashboard → new cert → replace file → reload Caddy (valid until ~2041) |
| Ed25519 signing key (agent-config) | `/etc/patched-api/env` (root 600) | api-01 | No automated rotation — manual env update + binary restart (PAT-499 roadmap: move to HSM) |
| Restic password (pat-backup-01 local leg) | was `/etc/patched-backup/restic.env` (root 600) on pat-backup-01 | pat-backup-01 (box retired, PAT-401 — credential no longer in use) | n/a — retired |
| GitHub PATs (read-only, for git mirrors) | was `/etc/patched-backup/github.env` (root 600) on pat-backup-01 | pat-backup-01 (box retired, PAT-401 — credential no longer in use) | n/a — retired |
| Dashboard env (`example-prod-host`) | `/etc/patched-dashboard/dashboard.env` (root or www-data 640) | prod-01 | Manual; requires dashboard restart |
| `GRAPH_MAIL_CLIENT_SECRET` | `/etc/patched-dashboard/dashboard.env` (root or www-data 640) | prod-01 | Entra ID → App registrations → Patched.im Mailer → new client secret; update EnvironmentFile and restart dashboard |
| Hetzner API token (for FW refresh timer) | `/etc/hetzner-fw-refresh/env` or inline in timer | prod-01 | Hetzner Console → API Tokens |
| Tailscale auth keys (one-time, per device) | Used once at provision; not stored post-join | — | `tailscale up --auth-key` → rotate unused keys in Tailscale Admin |

---

## Where secrets are NOT stored

- **Not in git.** `.gitignore` covers `*.ready`, `*-secret`, `*-creds` patterns. `gitleaks` pre-commit hook scans staged files before every commit. CI runs `gitleaks detect` on every PR.
- **Not in env vars passed via `docker run -e`** — no container runtime in use; systemd EnvironmentFile is the drop-in.
- **Not in plaintext in the codebase.** Secrets are loaded from EnvironmentFile at service startup; the Go binaries do not hardcode credentials.

---

## Current storage model

### EnvironmentFile pattern (systemd)

All service secrets live in EnvironmentFile-referenced files:

```
/etc/patched-api/env            ← Go service secrets
/etc/patched-extractor/env      ← Extractor secrets
/etc/patched-api/backup.env     ← Restic + R2 credentials
/etc/patched-dashboard/dashboard.env ← Dashboard secrets
```

Each file: `owner=root (or service user)`, `mode=600`. Systemd `EnvironmentFile=` loads them at unit start. The files are never committed and not in any backup leg that goes off-box unencrypted.

### Per-tenant credentials

Per-tenant bearer tokens and HMAC secrets are stored on managed endpoints:

```
/etc/patched/tenant-id          ← UUID, root 600
/etc/patched/bearer-token       ← plaintext token, root 600
/etc/patched/hmac-secret        ← base64 secret, root 600
```

Deployed via Intune Configuration Profile (Windows + macOS). Rotated via `POST /admin/tenants/{id}/rotate-credentials`; a 24-hour grace window ensures zero-downtime rotation when the new credential is deployed before `grace_until`.

The server stores `sha256(bearer_token)` and the raw HMAC secret bytes — neither is reversible to recover the plaintext token from the server side.

### Andy's password manager

All production secrets have a copy in Andy's password manager (1Password or equivalent). This is:
- The recovery path if an env file is lost/corrupted and the service needs to be rebuilt.
- The canonical source for initial provisioning of a new box.
- The only place the Restic password exists outside the box itself — losing it = unrecoverable R2 backup repository.

**Gap:** no second human has access to these secrets. Bus-factor = 1. Acceptable at pre-revenue scale; must change before a paying customer goes live.

---

## Rotation procedures

### Bearer token + HMAC secret (per-tenant)

```bash
# From any Tailscale-connected machine
curl -s -X POST https://example-api-host.example-tailnet.ts.net:8443/admin/tenants/<tenant-uuid>/rotate-credentials | jq .
# Returns: bearer_token (plaintext, ONCE ONLY), hmac_secret_b64, grace_until
# Deploy new credentials to endpoints BEFORE grace_until (default 24h)
```

Old credential continues to work until `grace_until`. Deploy the new credential to endpoints via Intune push before the grace window expires.

### Ed25519 signing key (agent-config responses)

No automated rotation today. Manual procedure:

1. Generate a new Ed25519 key pair (OpenSSL or `age-keygen`).
2. Update `/etc/patched-api/env` with the new private key and `key_id`.
3. `systemctl restart patched-api`.
4. Deploy the new public key to endpoint agents (agents verify `key_id` on every config fetch; old `key_id` will fail after the server rotates).
5. Burn the old key from env + password manager.

**Roadmap (PAT-499):** move the Ed25519 private key to an HSM (Nitrokey or CloudHSM) so the key material never lives in a file on disk.

### CF Origin Cert

Valid until ~2041. If replacement is needed:
1. `one.dash.cloudflare.com` → SSL/TLS → Origin Server → Create Certificate → `*.patched.im` → 15 years.
2. Replace `/etc/ssl/api.patched.im.pem` and `/etc/ssl/api.patched.im.key`.
3. `systemctl reload caddy` on both api-01 and prod-01.

### Microsoft Graph Mailer client secret

1. In Microsoft Entra ID, open **App registrations** → **Patched.im Mailer** → **Certificates & secrets** and create a new client secret. Record its expiry in the password manager.
2. Update only `GRAPH_MAIL_CLIENT_SECRET` in `/etc/patched-dashboard/dashboard.env`; do not put the value in git, shell history, or a ticket.
3. Restart `patched-dashboard`, then confirm its `email_delivery` health reports `ok` after acquiring a Graph token.
4. Retirement of the previous secret is a separate owner-authorised security operation and is not part of this code or documentation change.

### Restic repo password

The Restic password encrypts the repository. Changing it requires:
1. `restic key add` (adds the new key without rekeying existing snapshots).
2. `restic key remove <old-key>`.
3. Update `backup.env` and the password manager.

**Caution:** if the password is lost entirely (env file deleted AND password manager entry gone), the R2 repository is unrecoverable.

---

## Gaps and roadmap

| Gap | Risk | Roadmap |
|---|---|---|
| HMAC secrets stored in plaintext in env files | A filesystem-level compromise on api-01 reads all tenant HMAC keys; an attacker can then forge HMAC-valid requests | PAT-499: move HMAC keys to secrets vault / HSM |
| Ed25519 signing key in env file | Same filesystem exposure; compromise allows forging agent-config responses | PAT-499: HSM for signing key |
| Bus-factor 1 on password manager | If Andy is unavailable, no one can recover secrets or provision a new box | Pre-customer: second custodian for break-glass secrets |
| No secrets vault (AKV / HashiCorp Vault) | All secrets are file-based; no centralised audit log of secret access, no programmatic rotation, no just-in-time access | Pre-revenue-scale: evaluate AKV or Vault; start with at-risk secrets (signing key, HMAC secrets) |
| No audit log of secret access | A secret read from an env file leaves no trace | Addressed by moving to a vault with access logging |
| Per-tenant HMAC plaintext on endpoints | Stolen endpoint = stolen per-tenant credential | V2 auth: per-device JWTs (PAT planned) |

---

## Secrets handling conventions

1. **Never commit secrets.** `gitleaks` pre-commit hook and CI gate both enforce this.
2. **Use `root:root 600` for service secrets.** Service users read them via systemd EnvironmentFile drop-in; the Go binary never reads the file directly.
3. **One secret per logical function.** The R2 token is scoped to `patched-backups` only. GitHub PATs are fine-grained and read-only. Don't reuse credentials across systems.
4. **Show plaintext only once.** Bearer tokens and HMAC secrets are shown on creation and credential rotation, then never again (only the hash is stored on the server). Store in the password manager immediately.
5. **Rotate before compromise.** Rotation doesn't require a compromise to trigger it — rotate on: team changes, a suspected breach, a new device added to a service, or annually as a hygiene step.

---

## Related docs

- `api-vps-artefacts/OPERATIONS.md §Key rotation` — step-by-step rotation runbooks
- `api-vps-artefacts/BACKUP_DR.md` — backup secret custody table
- `go-service/docs/architecture.md` — auth model (bearer + HMAC)
- `go-service/docs/learning-notes/auth-model.md` — credential lifecycle deep-dive
