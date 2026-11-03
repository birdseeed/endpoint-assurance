# Runbook — portal auth AUD-drift health check (PAT-837)

## What this catches

On 2026-07-12, `app.patched.im` login was broken for every user for ~9 days
with no alert — discovered only because Andy happened to hit it. Root cause:
the Cloudflare Access app's AUD tag rotated (during the PAT-127 SSO reconfig)
and `PORTAL_ACCESS_AUD` on `example-portal-host` and `example-api-host` was left
stale, so every session token was rejected as invalid-audience (a
"session expired" reauth loop for real users, and every backend JWT
verification silently rejecting).

The dashboard now runs an hourly check (`_run_portal_auth_healthcheck_tick`
in `main.py`, wired into `scheduler_loop()`) that fetches the *live* AUD from
Cloudflare's Access API and compares it against the value the dashboard is
configured with. A mismatch posts to Slack within the hour.

## Getting an alert

**Slack message (header):** `🚨 Portal auth broken: Cloudflare Access AUD drift on app.patched.im`

Posted to the same Slack channel/webhook as the automation-failure alerts
(`SLACK_WEBHOOK_URL`). This means Cloudflare's live AUD for the
`app.patched.im` Access application no longer matches what
`example-portal-host` and `example-api-host` are configured with. **Every real
customer login is currently being rejected.**

**Why Slack, not email (PAT-1010):** this alert originally emailed
`OPS_ALERT_EMAIL`, which was never set on prod-01. Simply setting it would
not have fixed delivery either: prod-01 runs with `EMAIL_DRY_RUN=1`, under
which `_send_email()` logs the message and returns success without sending
anything — so an email alert would have silently satisfied the "can I
deliver" check and reported `portal_auth` as `ok` while alerting no one. The
candidate address (`hello@patched.im`) is also unconfirmed to reach a
monitored inbox (PAT-113: Cloudflare Email Routing is disabled on the zone
and the MX points at Microsoft 365). Slack is already configured and
delivering on prod-01, so it doesn't share either failure mode.

### Fix

1. Get the current live AUD from the Cloudflare dashboard: Zero Trust →
   Access → Applications → the `app.patched.im` application → copy the
   **Application Audience (AUD) Tag**.
2. Update `PORTAL_ACCESS_AUD` in `/etc/patched-portal/env` on
   `example-portal-host` and in `/etc/patched-api/env` on `example-api-host` to
   the new value.
3. Restart both services: `systemctl restart patched-portal` on
   `example-portal-host`, and the equivalent for the Go API on
   `example-api-host`.
4. Also update `PORTAL_ACCESS_AUD` in the dashboard's own
   `/etc/patched-dashboard/dashboard.env` on `example-prod-host` (used only for this
   comparison — the dashboard has no auth-decision role) and restart
   `patched-dashboard`.
5. Confirm: log in to `app.patched.im` as a real user. The next hourly tick
   posts a `✅ Portal auth recovered` Slack message once Cloudflare's live
   AUD and the configured value agree again.

Re-alerts at most once per 24h while still broken (not once per hour) —
absence of a fresh Slack message doesn't mean it self-resolved, check
current state directly if in doubt.

## One-time setup (required before this check does anything useful)

All five of these env vars need to be set on `example-prod-host`
(`/etc/patched-dashboard/dashboard.env`) for the check to be fully functional — it
never sends a false-positive alert regardless — but they are **not**
equivalent: the first four gate whether the AUD comparison runs at all,
`SLACK_WEBHOOK_URL` alone gates whether it can tell anyone what it finds. See
the breakdown below the table.

| Var | Where to get it |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare dashboard → My Profile → API Tokens → Create Token, scoped to **Account → Access: Apps and Policies → Read** for the Patched.im account. No other scopes needed. |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare dashboard → any zone's Overview page → right sidebar → Account ID. |
| `CLOUDFLARE_ACCESS_APP_ID` | Zero Trust → Access → Applications → `app.patched.im` → the app's ID is in its URL/settings page. |
| `PORTAL_ACCESS_AUD` | Same AUD tag `example-portal-host`/`example-api-host` are already configured with (see `reference_portal_cf_access_aud`) — copy-paste from either box's env file. |
| `SLACK_WEBHOOK_URL` | The Slack incoming-webhook URL for the ops channel — already provisioned on `example-prod-host` for the PAT-643 automation alerts; portal-auth alerts share it rather than adding a second webhook/channel. |

If any of the first four (`CLOUDFLARE_*`/`PORTAL_ACCESS_AUD`) is missing, the
tick logs a line and returns — the check itself never runs, and
`portal_auth` in `/admin/check-status` reports `unconfigured`, naming the
missing variable(s).

**`SLACK_WEBHOOK_URL` is different: the AUD check still runs even without it.**
If `SLACK_WEBHOOK_URL` is unset, the AUD comparison still happens every hour,
but any alert it would send has nowhere to go (PAT-988). Rather than no-op
silently, `portal_auth` in `/admin/check-status` is forced to `degraded` —
even when the AUD comparison itself currently passes, because a channel that
can't deliver is a real problem regardless of whether anything has drifted
yet. If drift is *also* detected, the recorded detail names both problems
(the AUD mismatch and the missing `SLACK_WEBHOOK_URL`) rather than one hiding
the other.

## Second consumer of the same Cloudflare credential (PAT-1990)

The three `CLOUDFLARE_*` vars above are also read by the Customer Access
"Send welcome" action, which refuses to email a design partner their portal
sign-in instructions unless their exact address is present in an Include rule
of the `app.patched.im` Access **Allow** policy. It needs no extra Cloudflare
scope — **Access: Apps and Policies → Read** already covers the policies
endpoint — so there is nothing to provision beyond what this check needs.
Consequence worth knowing: if these vars go missing, both this monitor and the
welcome email stop, and the welcome email says so rather than sending.

One additional var belongs to that feature alone:

| Var | Where to get it |
|---|---|
| `PORTAL_WELCOME_CLOUDFLARE_SENDER` | **Andy only, one manual step.** The address Cloudflare's One-time PIN email actually arrives from. It is not exposed by any API — do a real test sign-in at `app.patched.im` and read the `From:` off the PIN message you receive. |

Until it is set, the welcome email would tell the customer to expect a code
from the literal text `{cloudflare_sender}`, so the send route refuses with a
503 naming this variable and the Customer Access tab shows the same reason
before the operator commits. Nothing is sent and no state is recorded. Set it
in `/etc/patched-dashboard/dashboard.env` and restart (same read-at-startup
rule as below).

**Fixing it requires a restart, not just an env-file edit.** `SLACK_WEBHOOK_URL`
is read into a module-level constant when `patched-dashboard` starts — the
running process never re-reads `/etc/patched-dashboard/dashboard.env`. Editing the file
alone changes nothing until the service restarts:

```
# on example-prod-host, after setting SLACK_WEBHOOK_URL in /etc/patched-dashboard/dashboard.env
systemctl restart patched-dashboard
```

Confirm it actually took by checking `/admin/check-status` for `portal_auth`
returning to `ok` (or `degraded` for a genuine, different reason) — don't
just trust that the file was edited. This applies to every var in the table
above, but it bites hardest here: setting the file and walking away without
restarting looks identical to a fix and isn't one.

If a recovery notification was already owed when the channel died (an
outage alerted, then the channel went away before the recovery Slack post
could send), restarting alone is what lets the next tick actually deliver
it — the obligation is tracked in `kv.portal_auth_recovery_pending` and is
not lost while the channel was down.

Note: `SLACK_WEBHOOK_URL` is already set and delivering on `example-prod-host`
today (it backs the PAT-643 automation alerts), so in practice this check
should come up `ok`/`degraded`-only-on-genuine-drift immediately after the
deploy that ships this change — no separate provisioning step should be
needed for the alert channel itself, only for the four `CLOUDFLARE_*`/
`PORTAL_ACCESS_AUD` vars if those aren't already set.

## Deliberately out of scope (PAT-837 follow-up)

The ticket's option (3), a traffic-ratio backstop (alert if the portal
serves zero authenticated 200s, or the 401:200 ratio spikes, over N hours)
was recommended as a cheap complement to this AUD-specific check — it'd
catch any auth breakage, not just this exact failure mode. It needs a
Cloudflare zone-level Analytics read scope (a second CF credential
decision) and was deferred to keep this packet scoped to the one CF
Access-scoped token above. Worth a small follow-up ticket if wanted.
