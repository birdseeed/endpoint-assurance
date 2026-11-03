# Main box architecture — example-prod-host

**Status:** Live
**Box:** Hetzner CAX21 (Arm64), Nuremberg NBG1
**Public IPv4:** 203.0.113.10
**Tailnet IPv4:** 100.64.10.2

See `go-service/docs/architecture.md` for the API box (`example-api-host`). This doc covers `example-prod-host` only.

---

## Purpose

`example-prod-host` is the public-facing marketing box and internal operations surface. It does not hold any device, compliance, or inventory data — that lives exclusively on `example-api-host`.

| Surface | URL | Audience |
|---|---|---|
| Marketing site | `https://patched.im` | Public |
| Internal ops dashboard | `https://dashboard.patched.im` | Patched team only (CF Access) |

---

## Specification

| Item | Value |
|---|---|
| Hostname | `example-prod-host` |
| Provider | Hetzner Cloud |
| Spec | CAX21 — 4 vCPU Arm64, 8 GB RAM, 80 GB NVMe |
| Datacenter | Nuremberg (NBG1) |
| Public IPv4 | `203.0.113.10` |
| Tailnet IPv4 | `100.64.10.2` (MagicDNS: `example-prod-host.example-tailnet.ts.net`) |
| OS | Ubuntu 24.04 LTS |
| SSH | Tailscale-only — `ssh root@100.64.10.2`; TCP 22 closed at Hetzner FW |

---

## Services

### Marketing site (patched.im)

- Served by **Caddy** on `0.0.0.0:443`, orange-cloud proxied via Cloudflare.
- Caddy uses a Cloudflare Origin Cert (`*.patched.im`, 15-year wildcard) — NOT ACME.
- CF handles public TLS; Caddy terminates TLS from CF origin.
- Public visitors never reach the origin IP directly — Hetzner FW allows only Cloudflare CIDR ranges on ports 80 and 443.

### Internal ops dashboard (dashboard.patched.im)

- Go binary `patched-dashboard` running as `www-data`, managed by systemd.
- **SQLite**-backed — single DB file (reverted from an earlier Postgres-backed dashboard, PAT-489).
- Gated by **Cloudflare Access** (zero-trust, Google SSO): only authenticated team members reach the origin.
- Caddy proxies `dashboard.patched.im` to the local dashboard listener.

| Path | Purpose |
|---|---|
| `${DASHBOARD_DB_PATH}` (`/var/lib/patched-dashboard/dashboard.db`) | SQLite DB (live data) |
| `/etc/patched-dashboard/dashboard.env` | Runtime env (mode 600, `www-data:www-data`) |
| `journalctl -u patched-dashboard` | Service logs |

### Hetzner FW refresh (`hetzner-firewall-apply-api.timer`)

A systemd timer on `example-prod-host` queries Cloudflare's published IP range list daily and updates the `example-api-host-edge` Hetzner Cloud Firewall to allow only current CF ranges on ports 80 and 443. This keeps the api-01 origin protected even as Cloudflare rotates CIDRs.

### Tailscale

- Member of the `patched` tailnet; MagicDNS suffix `.example-tailnet.ts.net`.
- Admin access to all other tailnet members is via this box (or direct Tailscale SSH).
- No public SSH — all shell access is through `ssh root@100.64.10.2` over the Tailscale WireGuard mesh.

---

## Network posture

- **Public ports:** 80 and 443 only (TCP and UDP). TCP 22 is closed at the Hetzner Cloud Firewall.
- **Origin protection:** Hetzner FW restricts 80/443 to Cloudflare CIDR ranges, refreshed daily by the timer above. The origin IP `203.0.113.10` is not directly reachable from the public internet.
- **dashboard.patched.im** has an additional layer: Cloudflare Access requires team-member authentication before the request reaches Caddy/origin.
- Postgres does **not** run on this box — the dashboard uses SQLite.

---

## Firewall posture

| Direction | What | Rule |
|---|---|---|
| Inbound (public) | 80/443 TCP | CF CIDR ranges only (daily refresh via `hetzner-firewall-apply-api.timer`) |
| Inbound (public) | 22 TCP | Closed |
| Inbound (Tailscale) | UDP 41641 | Open (WireGuard) |
| Inbound (Tailscale) | Any TCP | Accept on `tailscale0` interface |
| Outbound | All | Open (UFW default-allow egress) |

---

## TLS

Caddy handles TLS termination for both sites on this box. CF Origin Cert (`*.patched.im`, 15-year validity) installed at:

```
/etc/ssl/patched.im.pem   (cert chain)
/etc/ssl/patched.im.key   (private key, mode 600)
```

Cert check: `openssl x509 -enddate -noout -in /etc/ssl/patched.im.pem` — expires ~2041.

---

## How to get on the box

```bash
ssh root@example-prod-host           # via Tailscale MagicDNS
# or
ssh root@100.64.10.2             # via Tailscale IP
```

Emergency (if Tailscale is broken): `console.hetzner.cloud` → Servers → `example-prod-host` → Console tab.

---

## Service management

```bash
# Dashboard
systemctl status patched-dashboard
systemctl restart patched-dashboard
journalctl -u patched-dashboard -n 100 --no-pager

# Caddy
systemctl status caddy
systemctl reload caddy           # reload config without downtime
journalctl -u caddy -n 50 --no-pager

# Hetzner FW refresh timer
systemctl status hetzner-firewall-apply-api.timer
systemctl list-timers hetzner-firewall-apply-api.timer
```

---

## Recovery runbook

### Dashboard corruption or data loss

`dashboard.db` and `reports/` are backed up nightly to Cloudflare R2 (`patched-backups/prod-01`) by
the `patched-prod-backup.timer` (PAT-84, deployed). See `api-vps-artefacts/BACKUP_DR.md`
for the full DR runbook.

Quick restore from R2:

```bash
ssh root@example-prod-host

# 1. Defensive copy
source /etc/patched-dashboard/backup.env
cp "$DASHBOARD_DB_PATH" /root/dashboard.db.before-restore-$(date +%s)

# 2. Stop the service
systemctl stop patched-dashboard

# 3. Restore from R2
restic snapshots                         # confirm latest snapshot exists
restic restore latest --include 'dashboard-*.db' --target /tmp/restore/

# 4. Replace live file
cp /tmp/restore/tmp/dashboard-*.db "$DASHBOARD_DB_PATH"
chown www-data:www-data "$DASHBOARD_DB_PATH"
sqlite3 "$DASHBOARD_DB_PATH" 'PRAGMA integrity_check'

# 5. Start service
systemctl start patched-dashboard
rm -rf /tmp/restore/
```

### Full box rebuild

1. Provision a new Hetzner CAX21 in NBG1.
2. Install Tailscale; join the `patched` tailnet. Assign the same MagicDNS name or update references.
3. Install Caddy; deploy the Caddyfile and CF Origin Cert from the artefacts repo.
4. Restore `dashboard.db` + `reports/` from R2 (see the quick-restore above).
5. Deploy the backup system: trigger the `deploy-prod01-backup` GitHub Actions workflow.
6. Enable and start `hetzner-firewall-apply-api.timer`.
7. Verify Cloudflare Access is still pointing to the correct origin IP (update DNS record if IP changed).
8. Update Hetzner Cloud Firewall: add the new IP if different.

**Target RTO (full rebuild):** < 4 hours (primarily provisioning + Tailscale auth + Caddy config).

---

## Related docs

- `go-service/docs/architecture.md` — API box (`example-api-host`)
- `api-vps-artefacts/BACKUP_DR.md` — backup strategy, RPO/RTO, DR procedures
- `api-vps-artefacts/NETWORK_TOPOLOGY.md` — full network map across both boxes
- `api-vps-artefacts/OPERATIONS.md` — operational runbooks (api-01 focused; backup details)
