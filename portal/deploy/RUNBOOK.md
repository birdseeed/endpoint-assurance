# Runbook: stand up app.patched.im (customer portal)

End-to-end, from nothing to a live portal. Total ~1h30 of hands-on time.
Every step is idempotent; if something fails, fix it and re-run the step.

**Deployment rule:** GitHub Actions (`deploy-portal-01.yml`) is the canonical
path for both first deployment and upgrades. Do not use the historical,
known-dirty `/opt/src/portal` checkout as an upgrade source, run `git pull` in
it, or invoke its installers. CI stages a clean checkout and deploys portal
and scan together from one commit.

**Hard dependency:** the portal shows real data only once the PAT-693 portal
read API (`/v1/portal/*` on api.patched.im) is merged and deployed. Until
then every page renders the "portal not yet enabled" screen (upstream 503),
which is the designed behaviour - you can still complete this runbook and
smoke-test auth first.

## 1. Provision the VPS (~10 min)

Hetzner Cloud -> new server:

- Type **CPX11** (2 vCPU / 2 GB - plenty; the portal is a stateless proxy)
- Image **Ubuntu 24.04**
- Name `example-portal-host`
- SSH key: your usual key (only used until Tailscale is up)
- Recommended: attach a Hetzner Cloud Firewall allowing TCP 80/443 from
  anywhere (ufw narrows to Cloudflare ranges below), UDP 41641, ICMP - and
  **no public SSH**, same pattern as `example-prod-host-edge`.

## 2. Join the tailnet (~5 min)

The Tailscale ACL already defines `tag:portal` (PAT-410, patched.im PR #216):
zero data-plane grants, admin SSH in only. **Confirm the ACL is applied in
the Tailscale admin console first** (that apply is your manual step).

```bash
ssh root@<public-ip>
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --advertise-tags=tag:portal --ssh
```

Approve/authenticate in the browser when prompted. From now on use
`ssh root@example-portal-host` over the tailnet.

## 3. Install the portal (~10 min)

From a GitHub-authorized workstation:

```bash
gh workflow run deploy-portal-01.yml --repo Patched-LTD/portal
gh run watch --repo Patched-LTD/portal
```

Before the first dispatch, complete the CI/Tailscale bootstrap in
`docs/DEPLOY.md`. The workflow's installer sets up the system user, venv,
systemd unit, nginx, and the PAT-410 ufw posture (443/80 from Cloudflare only,
SSH via tailnet only, outbound restricted, tailnet data-plane ports denied).
It runs both `install.sh` and `install-scan.sh` from a CI-pushed checkout and
records the deployed commit SHA, readable at `GET /healthz`.

Note: once ufw's outbound lockdown is active, git-over-SSH to GitHub (port
22) is blocked - use the HTTPS remote as above.

## 4. Cloudflare DNS (~5 min)

Cloudflare dashboard -> patched.im zone -> DNS:

- `A` record, name `app`, value = the VPS **public** IP, **Proxied** (orange
  cloud). Proxied is load-bearing: ufw only admits Cloudflare ranges, so a
  grey-cloud record would make the site unreachable (by design).

## 5. Cloudflare Origin Certificate (~10 min)

The installer left a self-signed placeholder; replace it so you can run
Full (strict):

1. Cloudflare -> patched.im zone -> SSL/TLS -> **Origin Server** ->
   Create Certificate (RSA, hostname `app.patched.im`, 15 years).
2. Paste the certificate into `/etc/ssl/app.patched.im.pem` and the private
   key into `/etc/ssl/app.patched.im.key` on the box; `chmod 600` the key.
3. `nginx -t && systemctl reload nginx`
4. Cloudflare -> SSL/TLS -> Overview: mode **Full (strict)** (zone-wide;
   dashboard.patched.im already uses an Origin Certificate so this is safe).

## 6. Cloudflare Access application (~15 min)

Zero Trust dashboard (one.dash.cloudflare.com) -> Access -> Applications ->
**Add an application** -> Self-hosted:

- Application name: `Patched portal`, domain `app.patched.im` (whole site,
  no path).
- Session duration: 24h is fine for v1.
- **Policies - per tenant.** One Allow policy per tenant, named after the
  tenant. v1 is one login per tenant (PAT-128 does multi-admin later):
  - SSO tenants: an Entra ID / Google Workspace login method scoped to the
    tenant's IdP (set the IdP up first under Settings -> Authentication),
    include rule = the named user's email.
  - Fallback: include rule Emails = the named contact address; Cloudflare's
    **One-time PIN** login method covers the email-PIN path (enable it under
    Settings -> Authentication if it is not already on).
- Save, then open the application's **Overview** tab and copy the
  **Application Audience (AUD) Tag** - a 64-char hex string. That is
  `PORTAL_ACCESS_AUD`.

Your team domain is under Zero Trust -> Settings -> Custom Pages, shown as
`<team>.cloudflareaccess.com`. That is `PORTAL_ACCESS_TEAM_DOMAIN` (no
scheme).

## 7. Configure and restart (~5 min)

On the box, edit `/etc/patched-portal/env`:

```
PORTAL_ACCESS_TEAM_DOMAIN=<team>.cloudflareaccess.com
PORTAL_ACCESS_AUD=<the AUD tag from step 6>
PLATFORM_BASE_URL=https://api.patched.im
```

```bash
systemctl restart patched-portal
journalctl -u patched-portal -n 20 --no-pager   # should show uvicorn up on 127.0.0.1:8000
```

## 8. Map the customer to a tenant (~5 min)

The platform derives the tenant from the verified email via the
`portal_users` table (PAT-693). Add a row over the internal admin listener
(from an admin box on the tailnet, with the platform's `ADMIN_API_TOKEN`):

```bash
curl -s -X POST http://example-api-host.example-tailnet.ts.net:8081/admin/portal-users \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "customer@tenant.example", "tenant_id": "<tenant-id>"}'
```

(Exact route per the PAT-693 implementation; run this from `patched-main-01`
or wherever you keep `ADMIN_API_TOKEN`. The portal box itself deliberately
has no admin token and cannot reach `:8081`.)

## 9. Smoke test (~10 min)

1. **Auth wall:** open https://app.patched.im in a private window -> you get
   the Cloudflare Access login, not the portal.
2. **Sign in** as the mapped user -> Overview page renders (or "portal not
   yet enabled" if PAT-693 is not deployed yet - that still proves the JWT
   path end to end).
3. **Direct-origin bypass refused:**
   `curl -sk --resolve app.patched.im:443:<public-ip> https://app.patched.im/ -o /dev/null -w '%{http_code}'`
   from a non-Cloudflare address must time out / be refused by ufw.
4. **No-JWT fail-closed:** from the box itself,
   `curl -s http://127.0.0.1:8000/ | grep -i "session has expired"` -> the
   app returns 401 without a valid JWT even when reached directly.
5. **Tailnet posture:** from the box,
   `curl -m 3 http://example-api-host.example-tailnet.ts.net:8081/` and `:8443`
   must both fail (ACL + ufw), per PAT-410.
6. Click through Devices / Findings / Reports; generate and download a
   report once PAT-693 data is live.

## Troubleshooting

- **"Portal unavailable / not fully configured"** (503 on every page): env
  vars missing - check `/etc/patched-portal/env`, restart the service.
- **"Session expired" loop after CF login:** `PORTAL_ACCESS_AUD` does not
  match the Access application's AUD tag, or the team domain is wrong.
  `journalctl -u patched-portal` logs the verify failure reason.
- **"Portal not yet enabled":** upstream returned 503 - the PAT-693 API is
  not deployed, or the tenant has no `portal_users` row (depending on how
  the platform signals it; 403 shows the session page instead).
- **522 from Cloudflare:** ufw is admitting the wrong ranges - re-run
  `bash deploy/install.sh` (it refreshes the Cloudflare IP list).
