# Patched.im Dashboard

Internal operations dashboard for Patched.im Ltd. Single console (`/console`) covering CVE vulnerability assessment, per-tenant device/estate visibility, compliance and CIS control management, software catalogue, and billing/account admin.

## Access

`https://dashboard.patched.im` — protected by Cloudflare Zero Trust (authorised team only)

### Network posture

Three layers of filtering, outside-in. See `HARDENING-SUMMARY-2026-11-14.md` for the full point-of-truth.

- **Production traffic**: browser → Cloudflare edge → origin (`203.0.113.10:443`). Cloudflare Access enforces email-OTP auth at the edge. Origin TLS terminates with a Cloudflare Origin Certificate at `/etc/ssl/dashboard.patched.im.{pem,key}`.
- **Hetzner Cloud Firewall** `example-prod-host-edge` (primary edge filter, `deploy/hetzner-firewall-apply.sh`): TCP 80/443 from Cloudflare ranges only, UDP 41641 from anywhere (Tailscale direct-connect), ICMP. No public SSH. CF ranges are live-fetched daily via `hetzner-firewall-apply.timer` so they don't go stale.
- **UFW (host)**: defence-in-depth. CF + Tailscale CGNAT on 80/443, Tailscale CGNAT only on 22.
- **Nginx**: TLS termination + reverse proxy. **No IP allowlist at this layer** — `real_ip_header CF-Connecting-IP` rewrites `$remote_addr` to the browser IP before `allow`/`deny` evaluate, which breaks the pattern. The two layers above handle network filtering correctly. `set_real_ip_from` is kept purely for logging accuracy.
- **Admin access**: SSH and direct HTTP debugging go over Tailscale (`ssh root@example-prod-host`). Root is the only login; the old `patched` account was retired (PAT-2312). No home-IP rule by design — emergency path is Hetzner Cloud Console (`console.hetzner.cloud` → Server → Console — browser TTY, network-independent).

## Features

- **CVE Scanner** — upload an Intune devices export (+ optional detected-apps export), match against a local NVD SQLite dataset, generate a branded report. No Microsoft Graph credentials needed (Graph pipeline removed under PAT-572).
- **Customers console** — per-tenant workspace: devices, CVE findings, CIS controls, compliance status, software catalogue, software metering, application control, browser extensions, shadow IT, enforcement evidence, reports, webhooks, patch & deploy (ring rollouts), account/billing.
- **Support impersonation** — read-only (optionally write-enabled) session viewing a tenant's data as that tenant.

See `docs/API_REFERENCE.md` for the full route/screen inventory — this list is a summary, not exhaustive.

## Stack

- **Backend**: FastAPI + Uvicorn (Python 3.12)
- **Frontend**: Vanilla JS + one Jinja2 template (`templates/console.html`, hash-routed single-page app) — no build step required
- **Database**: SQLite (`dashboard.db` — gitignored)
- **Hosting**: Hetzner CAX21 VPS (Ubuntu 24.04)
- **Proxy**: Nginx with Cloudflare Origin Certificate
- **Auth**: Cloudflare Zero Trust Access (email OTP) + app-level session-cookie-or-Bearer + RBAC — see `docs/API_REFERENCE.md`

## Project Structure

```
main.py                          — FastAPI app, API routes, scheduler, DB
scanner.py                       — CVE scan engine (upload → local NVD SQLite match → report)
templates/console.html           — Single-page UI (Jinja2, hash-routed). No dashboard.html —
                                    that page was retired in the console rebuild.
static/                          — Logo and assets
static/vendor/brand/             — Vendored Patched brand kit (PAT-953), pinned to
                                    v2.0.0, byte-identical to the portal repo's copy.
tests/                           — pytest suite (route-level + regression coverage)
deploy/
  nginx-dashboard.conf           — Nginx 443 block + Origin Cert + CF real-IP
  patched-dashboard.service      — systemd unit
  hetzner-firewall-apply.sh      — Hetzner FW rules apply (live-fetches CF ranges)
  hetzner-firewall-apply.{service,timer}  — daily auto-refresh of FW rules
reports/                         — Generated reports (gitignored)
dashboard.db                     — SQLite (gitignored)
docs/
  SETUP.md                       — Local dev: clone-to-running-on-laptop
  SCHEMA.md                      — DB schema reference (partial — flagged stale, see file)
  API_REFERENCE.md               — Route/screen inventory + auth model + gotchas (current /console structure)
  TESTING.md                     — pytest suite + manual smoke-test checklist
  OPERATIONS.md                  — Runbooks: service down, zombie scans, CF Access lockout, cert renewal, disk filling, key rotation, tier switching
  architecture.md                — Canonical architecture doc; "Current state" block is the live production snapshot
  onboarding-audit-2026-11-15.{json,html}  — Dev onboarding doc audit
HARDENING-SUMMARY-2026-11-14.md  — Network posture point-of-truth
```

## Environment Variables

Set in the systemd service file (`deploy/patched-dashboard.service`):

| Variable | Description |
|---|---|
| `NVD_API_KEY` | Patched.im NVD API key for CVE lookups |

## Deployment

**Ongoing deploys** are `workflow_dispatch`, not automatic-on-merge: `gh workflow run deploy.yml -R Patched-LTD/dashboard`. The runner pushes `main` to the box's bare mirror (`/opt/git/dashboard.git`) over Tailscale; a post-receive hook on the box does `git reset --hard` + `pip install` + `systemctl restart`. See `AGENTS.md`'s "Deployment model" section for the full, current picture (including the manual scp fallback) — `deploy/SETUP_GITHUB_ACTIONS.md` covers the one-time infra wiring (Tailscale OAuth, deploy SSH key) rather than the day-to-day deploy flow.

### Service management
```bash
systemctl status patched-dashboard
systemctl restart patched-dashboard
journalctl -u patched-dashboard -n 50 --no-pager
```

## Required: Add to .env or systemd before deploying

The systemd service file in `deploy/` contains the NVD API key. Do not commit changes to this file with real credentials.

---

*Internal use only — Patched.im Ltd*

<!-- Trigger CD pipeline test -->
<!-- Trigger CD pipeline test 2 -->
<!-- Trigger CD pipeline test 3 -->
<!-- Trigger CD pipeline test 4 -->
