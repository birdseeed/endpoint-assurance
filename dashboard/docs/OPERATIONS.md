# Operations — `dashboard.patched.im`

Runbooks for things that break, and the rituals around the service. Read this when you're SSH'd in trying to fix something at 11pm.

## Where things live

| Thing | Path / location |
|---|---|
| App code | `/opt/patched-dashboard/` (owned `root:root`, no group or other write; the service user cannot change it, PAT-2307) |
| App process | systemd unit `patched-dashboard.service`, binds `127.0.0.1:8000` |
| nginx config | `/etc/nginx/sites-available/dashboard.patched.im` (symlinked from `sites-enabled/`) |
| Origin TLS cert | `/etc/ssl/dashboard.patched.im.{pem,key}` (Cloudflare Origin Cert, 15-year validity) |
| App logs | `journalctl -u patched-dashboard` |
| nginx access logs | `/var/log/nginx/access.log` |
| nginx error logs | `/var/log/nginx/error.log` |
| UFW logs | `journalctl --since '1 hour ago' \| grep '\[UFW BLOCK\]'` |
| App state directory | `/var/lib/patched-dashboard/` (`www-data:www-data` 0750, the unit's `StateDirectory=`). The only place the app writes (PAT-2307) |
| Database | `/var/lib/patched-dashboard/dashboard.db` (SQLite in WAL mode, www-data-owned; `DASHBOARD_DB_PATH`, PAT-994) |
| Generated reports | `/var/lib/patched-dashboard/reports/*.docx`. Reports from before PAT-2307 stay in `/opt/patched-dashboard/reports/`, root-owned, until someone removes them |
| NVD match cache | `/var/lib/patched-dashboard/nvd.db` (rebuilt from the NVD feed on the next scan if missing) |
| Env vars | Set in the systemd unit (`Environment=` or `EnvironmentFile=`) — `NVD_API_KEY`, `DASHBOARD_API_KEY` |
| Hetzner FW state | `console.hetzner.cloud` → Firewalls → `example-prod-host-edge` (also `hcloud firewall describe example-prod-host-edge`) |
| Self-maintaining FW refresh | systemd timer `hetzner-firewall-apply.timer`, daily 04:17 UTC |

## How to get on the box

```bash
ssh root@example-prod-host            # via Tailscale — the only path
```

Root is the only login. There is no `patched` account on `example-prod-host`: Andy retired it on 2026-09-30 and the deploy removes it along with its sudoers grant (PAT-2312; see `deploy/RUNBOOK.md`). Do not create one again. The deploy removes an account called `patched` with uid 1001 and fails on one with any other uid.

If Tailscale is broken or you're locked out: `console.hetzner.cloud` → Servers → `example-prod-host` → Console tab. Browser TTY, network-independent.

---

## Service down

**Symptom:** dashboard.patched.im returns a 5xx, or `systemctl status patched-dashboard` shows `failed`.

**Diagnose:**

```bash
systemctl status patched-dashboard --no-pager
journalctl -u patched-dashboard -n 100 --no-pager | tail -50
```

Common causes:

- **Syntax/import error after a deploy.** Look for a `Traceback` near the most recent `Started patched-dashboard.service`. Revert via scp from the Mac (or via git, since the repo is the source of truth — check out the last known good commit and scp).
- **Port 8000 collision.** `lsof -i:8000` (or `ss -tlnp \| grep :8000`). Kill the squatter or restart the service.
- **Database locked.** SQLite write contention — restart usually fixes. If recurring, the scheduler thread and the request thread are stepping on each other; pool to a single connection or add `PRAGMA busy_timeout`.

**Fix:**

```bash
systemctl restart patched-dashboard
systemctl status patched-dashboard --no-pager | head -10
```

---

## Stuck / zombie scans

**Symptom:** `Recent Scans` table shows a scan in `running` status that's been there for >30 minutes. Polling `/api/scan/{id}/status` returns 404 (the in-memory `JOBS` dict was cleared on restart).

**Diagnose:**

```bash
sudo -u www-data sqlite3 /var/lib/patched-dashboard/dashboard.db \
  "SELECT id, company, started_at, status FROM scans WHERE status='running' ORDER BY started_at DESC;"
```

**Why it happens:** the scan runs in a background thread on the FastAPI process. If the process is restarted (deploy, OOM, crash) mid-scan, the thread dies but the `scans` row stays in `running`. There's no janitor.

**Fix:** mark stale `running` scans as errored:

```bash
sudo -u www-data sqlite3 /var/lib/patched-dashboard/dashboard.db <<'SQL'
UPDATE scans
SET status = 'error',
    error = 'Marked stale by operator — process likely restarted mid-scan',
    completed_at = datetime('now')
WHERE status = 'running'
  AND started_at < datetime('now', '-30 minutes');
SQL
```

The dashboard UI will then show them as `error` (red badge). Andy can re-run the scan from the Scanner page.

**Long-term:** add a startup hook in `main.py` that marks all `running` scans as `error` with reason "process restarted" at boot. ~5 lines, no test coverage, prevents the zombie state entirely.

---

## CF Access locking everyone out

**Symptom:** Authorised users get a `cloudflareaccess.com` error page that won't let them through, or an unexpected redirect loop.

**Diagnose:**

1. **`console.hetzner.cloud` → Firewalls → example-prod-host-edge** — confirm rules are sane (TCP 80/443 from CF ranges).
2. **`one.dash.cloudflare.com` → Zero Trust → Access → Applications → dashboard.patched.im** — confirm the policy still lists your email and the application Domain matches `dashboard.patched.im/*`.
3. **From your Mac with Tailscale on:** `curl -I http://example-prod-host/` — bypasses CF entirely. If the origin returns sensibly (302 or whatever it normally does), the issue is at CF. If it doesn't, the issue is at the origin.

**Emergency backdoor:** Tailscale SSH always works. `ssh root@example-prod-host` is independent of CF.

**Common fixes:**

- Policy was edited and your email got dropped — add it back.
- Identity provider broke — Cloudflare's "Test access" tool in the Zero Trust admin will tell you.
- Service token rotated and the dashboard's `DASHBOARD_API_KEY` got out of sync — see "Rotate DASHBOARD_API_KEY" below.

---

## Origin TLS cert expiry

The Cloudflare Origin Cert at `/etc/ssl/dashboard.patched.im.{pem,key}` has a **15-year validity** by default, so this isn't an annual chore. But check expiry occasionally:

```bash
openssl x509 -enddate -noout -in /etc/ssl/dashboard.patched.im.pem
```

If it's getting close:

1. `one.dash.cloudflare.com` → SSL/TLS → Origin Server → Create Certificate.
2. Hostname: `dashboard.patched.im`. Validity: 15 years.
3. Save the cert and private key.
4. Replace `/etc/ssl/dashboard.patched.im.pem` (cert) and `/etc/ssl/dashboard.patched.im.key` (key) on the box. `chmod 600` on the key. `chown root:root` on both. Keep the key a regular file, not a symlink: every deploy holds it to root:root 0600 and fails on a symlink (PAT-2312).
5. `nginx -t && systemctl reload nginx`.
6. From your Mac: `openssl s_client -connect dashboard.patched.im:443 -servername dashboard.patched.im < /dev/null 2>/dev/null | openssl x509 -noout -subject -dates` — confirm the new cert is being served.

---

## Disk filling up

**Symptom:** `df -h /` shows >85% used, or the service starts erroring on writes.

**Most likely culprit:** `/var/lib/patched-dashboard/reports/` accumulating `.docx` files (one per scan). `patched-dashboard-prune-reports.timer` removes ones older than 90 days daily; check it is running.

**Diagnose:**

```bash
du -sh /var/lib/patched-dashboard/reports /opt/patched-dashboard/reports
ls -laht /var/lib/patched-dashboard/reports | head -20
systemctl list-timers patched-dashboard-prune-reports.timer
df -h /
```

**Fix (prune reports older than 90 days):**

```bash
sudo -u www-data find /var/lib/patched-dashboard/reports -maxdepth 1 -name '*.docx' -mtime +90 -delete
```

If you do this, the corresponding `scans.report_path` rows still reference files that no longer exist. `download_report` handles this gracefully — returns 404 instead of crashing. To clean up the DB rows too:

```bash
sudo -u www-data sqlite3 /var/lib/patched-dashboard/dashboard.db <<'SQL'
UPDATE scans SET report_path = NULL
WHERE report_path IS NOT NULL
  AND report_path LIKE '/var/lib/patched-dashboard/reports/%';
-- (Then a separate loop to NULL only those whose files no longer exist —
-- but the simpler path is to just leave them and let download_report 404.)
SQL
```

`deploy/prune-reports.sh` (PAT-87), run by `patched-dashboard-prune-reports.timer`, is the standing version of this.

---

## Database corruption / restore

**Symptom:** SQLite errors like `database disk image is malformed` or `database is locked` persisting across restarts.

**First — back up what you have, even if corrupt:**

```bash
cp /var/lib/patched-dashboard/dashboard.db /root/dashboard.db.before-restore-$(date +%s)
```

**Diagnose:**

```bash
sudo -u www-data sqlite3 /var/lib/patched-dashboard/dashboard.db "PRAGMA integrity_check;"
```

If output is `ok`, the file is fine — the error is elsewhere (file permissions, disk full, locked by another process).

If output reports errors:

```bash
# Attempt SQLite's built-in recovery
sqlite3 /var/lib/patched-dashboard/dashboard.db ".recover" | \
  sudo -u www-data sqlite3 /var/lib/patched-dashboard/dashboard.db.recovered
mv /var/lib/patched-dashboard/dashboard.db /var/lib/patched-dashboard/dashboard.db.corrupt
mv /var/lib/patched-dashboard/dashboard.db.recovered /var/lib/patched-dashboard/dashboard.db
chown www-data:www-data /var/lib/patched-dashboard/dashboard.db
systemctl restart patched-dashboard
```

**Restore from backup:** there's currently no automated backup. Andy's deploy notes say "Production data lives in `dashboard.db` and `reports/` — both gitignored. Treat them as irreplaceable. Backup discipline is independent of this dashboard codebase." Confirm what backup mechanism you have in place before you need it. (Hetzner snapshot? Restic to R2? Manual `scp` to Mac? Pick one and document here.)

---

## Rotate `DASHBOARD_API_KEY`

The key is used for two callers:

- The browser (injected via the page template at render time)
- The Jarvis Job Scout bot (reads from `/etc/jarvis/job-scout.env`) — *if Jarvis is still running*

**Rotation steps:**

```bash
# Generate new key
NEW_KEY="$(openssl rand -hex 32)"
echo "$NEW_KEY"  # Stash this somewhere safe — you'll need it for any external caller

# Update the dashboard's systemd Environment
systemctl edit patched-dashboard       # or sudo nano /etc/systemd/system/patched-dashboard.service.d/override.conf
# Set: Environment="DASHBOARD_API_KEY=<NEW_KEY>"
systemctl daemon-reload
systemctl restart patched-dashboard

# If Jarvis is still running, update its env too
sudo nano /etc/jarvis/job-scout.env    # update the DASHBOARD_API_KEY= line
systemctl restart jarvis*              # whatever the unit name is
```

**Verify:**

```bash
# In a private browser window, log in via CF Access, confirm pages load.
# /api/* is Access-gated at the edge, so verify the Bearer path from the box itself,
# below Cloudflare, against the local port the app binds (127.0.0.1:8000):
curl -H "Authorization: Bearer $NEW_KEY" -I http://127.0.0.1:8000/api/metrics
# Expect HTTP/1.1 200.
```

Old key continues to work until you restart — both processes have the env var in memory at startup. Plan the rotation so a brief overlap is OK.

---

## Switching a customer's tier (upgrade / downgrade)

A customer's tier is not a single column — it is an emergent combination of fields across two data stores. There is no atomic "set tier" operation yet (PAT-397 tracks automating this). Until it ships, use this sequence.

### What "tier" actually means

| Commercial tier | `billing_tier` (dashboard SQLite) | `agent_config_tier` (dashboard → Go API) | T2 CIS rules | App Control |
|---|---|---|---|---|
| Tier 1 — Report | `report` | `report_deploy` | Off | Off |
| Tier 2 — Patch & Deploy | `patch` | `patch` | On | Off |
| Tier 3 — Full Endpoint | `full` | `patch` | On | On |

App Control is an add-on that can be purchased at any tier, but is only meaningful at Tier 2+.

### Step-by-step

**1. Update the commercial billing tier**

Open the customer's Account tab in the Customers console (`Customers` → tenant → `Account`), find the Billing section, and set `billing_tier` to the new value (`report`, `patch`, or `full`). Save. This affects the Billing screen cost calculation and the badge shown next to the tenant name.

Alternatively, via API (run on the box — `/api/*` and `/admin/*` are Access-gated at the
edge, so target the local port the app binds, `127.0.0.1:8000`, not the public hostname):
```bash
curl -s -X POST http://127.0.0.1:8000/admin/tenants/<TENANT_ID>/account \
  -H "Authorization: Bearer $DASHBOARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"billing_tier": "patch"}'
```

**2. Update the agent operating mode** (Tier 1 → Tier 2 or Tier 2 → Tier 1 only)

The agent operating mode (`agent_config_tier`) controls what the endpoint agent actually does: `report_deploy` = collect + report + deploy agent updates; `patch` = additionally run managed app patching. Changing this issues a new signed `agent_config` to the Go API.

**There is no dedicated UI control for this any more** — the old standalone "Agent Config tab in Compliance Admin (`/admin`)" doesn't exist; that whole page was retired in the console rebuild. This is currently an API-only operation:

```bash
# Run on the box — /api/* is Access-gated at the edge, so target 127.0.0.1:8000.
curl -s -X PATCH http://127.0.0.1:8000/api/tenant/<TENANT_ID>/agent-config \
  -H "Authorization: Bearer $DASHBOARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_config_tier": "patch"}'
```

`agent_config_tier` accepts `report_deploy` or `patch` only (rejects anything else with 400) — there is no `full` value at this layer; Tier 3 is `patch` here too, distinguished by App Control being enabled separately (step 4). The handler validates the full body (proxy settings, update channel, pinned version — see `main.py`'s `api_agent_config_patch` if you need to set those in the same call), pushes to the Go API on success, and bumps `config_version`; agents pick up the new config on their next check-in.

Verify the new config is issued:
```bash
# Should show updated tier and incremented config_version
# (run on the box — /api/* is Access-gated at the edge; target 127.0.0.1:8000)
curl -s http://127.0.0.1:8000/api/tenant/<TENANT_ID>/agent-config \
  -H "Authorization: Bearer $DASHBOARD_API_KEY" | python3 -m json.tool
```

**3. Enable / disable T2 CIS rules** (Tier 2 upgrades)

When upgrading to Tier 2, enable the T2 rule batch for the tenant. This now lives in the **CIS Controls** tab of the tenant's workspace (`Customers` → tenant → `CIS Controls` → manage controls) — not a standalone Compliance Admin page. T2 rules render alongside always-on T1 rules, tagged and toggleable per platform.

There is no bulk "enable all T2 rules" endpoint — each rule is toggled via `PUT /admin/tenant-rules/<TENANT_ID>/<RULE_ID>`. If you need to bulk-enable via script:
```bash
# Get the rule list for the tenant (run on the box — /admin/* is Access-gated at the
# edge, so target the local port the app binds, 127.0.0.1:8000)
RULES=$(curl -s "http://127.0.0.1:8000/admin/tenant-rules/<TENANT_ID>?platform=macos" \
  -H "Authorization: Bearer $DASHBOARD_API_KEY")
# Enable each T2 rule (tier=2 in the response) that isn't already enabled
# — use the CIS Controls tab instead; bulk scripting this is error-prone
```

**4. App Control add-on** (optional, any tier)

Toggle `app_control_enabled` in the Account tab Billing section. This unlocks the Application Control tab in the customer's dashboard view and adds the per-endpoint App Control cost to billing.

```bash
# Run on the box — /admin/* is Access-gated at the edge, so target 127.0.0.1:8000.
curl -s -X POST http://127.0.0.1:8000/admin/tenants/<TENANT_ID>/account \
  -H "Authorization: Bearer $DASHBOARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"app_control_enabled": true}'
```

### Verification checklist

After a tier change, confirm:

- [ ] Billing screen shows correct tier and recalculated cost
- [ ] `GET /api/tenant/<TENANT_ID>/agent-config` shows the new `agent_config_tier` and an updated `agent_config_version`
- [ ] CIS Controls tab shows T2 rules as enabled (for Tier 2+ tenants)
- [ ] Agent on an endpoint picks up the new config on next check-in (check `agent_config_version` in device row)

### Downgrade notes

Downgrading (e.g. Tier 2 → Tier 1):
- Set `billing_tier` back to `report`
- `PATCH` `agent_config_tier` back to `report_deploy` — this stops the agent running managed updates
- Optionally disable T2 rules in the CIS Controls tab (they will still evaluate but add noise to reports)
- Leave app_control as-is unless explicitly removing the add-on

The tier change does **not** automatically undo any configuration set while the customer was on a higher tier (allowlists, app policies, etc.). Those require manual cleanup.

---

## What's NOT here (yet)

- **Backup strategy** — see DB corruption section, this is genuinely TBD. Pick a mechanism.
- **Alerting** — there's no on-call paging. If the dashboard goes down silently, you find out when you next try to use it.
- **Capacity planning** — single-tenant internal tool, the box is over-provisioned by an order of magnitude. Not a concern at current scale.
