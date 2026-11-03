# Runbook: stand up scan.patched.im (public CVE scan service)

End-to-end bring-up of the standalone public scan service (PAT-457/PAT-121). It
runs on **example-portal-host**, alongside the customer portal but as a separate
system user, systemd unit and nginx vhost. Every step is idempotent; if
something fails, fix it and re-run the step.

This service is **public by design** — there is no Cloudflare Access in front.
Security is Turnstile + per-email/per-IP rate limits + OTP email verification +
file-size caps, all enforced in the app. **Do not** put a CF Access application
over `scan.patched.im`.

## Public scan availability (PAT-2564)

Both new-work funnels default off. `/public/scan`, its OTP verification routes,
`/public/intune-upload` and `/public/intune-instructions` return an explanatory
503 page with `Cache-Control: no-store`, before reading request bodies or doing
work. Existing scan done/status/report/delete links, retention and NVD refresh
continue operating. The waitlist is independent and remains available.

`PUBLIC_SCAN_ENABLED=true` explicitly restores the legacy funnels; missing,
blank, false or malformed values keep them disabled. Configuration is read at
startup, so restart `patched-scan.service` after an authorised setting change.
The installer preserves an existing env file; existing installs without this
setting become disabled on deploying this version. No database or files are
removed by disabling the funnels.

## The backup rail is version-controlled (PAT-994)

`deploy/portal-backup.sh`, `deploy/patched-portal-backup.service` and
`deploy/patched-portal-backup.timer` are byte-for-byte captures of what runs on
`example-portal-host` as of 2026-09-03, verified by `sha256sum` on both sides:

| file | sha256 |
| --- | --- |
| `patched-portal-backup.service` | `923192a65c11...f1b786b1` |
| `patched-portal-backup.timer` | `8bd4f0b559e1...53ccb6da` |
| `portal-backup.sh` | `203f5563d641...b81e6237` |

They were added because the rail existed only on the box: no review, no history,
no rollback. Nothing was deployed to add them, because the repo copies already
matched the live files exactly.

**Not deployed automatically.** Change here, get it reviewed, copy to the box,
`systemctl daemon-reload`, then confirm a real run:

```
systemctl start patched-portal-backup.service
journalctl -u patched-portal-backup.service -n 30 --no-pager
```

Re-verify the hashes after any deploy. A repo that has drifted from the box is
not a record of anything.

**Secrets stay out.** Restic credentials come from the systemd `EnvironmentFile`,
which is not in the repo. The script says so at the top and never sources it.

**Residual weakness fixed (PAT-994 step 2).** `scan.db` now lives in
`/var/lib/patched-scan/db`, a sub-directory containing nothing else —
`scan/shared.py`'s `DB_PATH` moved out from directly under `STATE_DIR`
(`SCAN_DB_DIR` is the explicit override, same pattern as `SCAN_STATE_DIR`).
`patched-portal-backup.service`'s `ReadWritePaths` narrowed from the whole of
`/var/lib/patched-scan` (uploads, reports, `nvd.db` — 137 MB — as well as
`scan.db`, 57 KB) to just `/var/lib/patched-scan/db`. `patched-scan.service`
needed no change: it grants the whole state tree via `StateDirectory=patched-scan`
already, and `db/` is just a child of that tree, not a new location outside it
(unlike prod-01's dashboard.db, which moved out of the app's own working
directory entirely).

`CacheDirectory=patched-portal-backup` is already set, so `ProtectHome=true`
becomes achievable here once this deploys — not done in this pass, filed as
a follow-up.

**Migration log — 2026-09-04, example-portal-host.** Stopped `patched-scan`
before deploying (unlike prod-01's dashboard.db, this move is not gated by
an unset env var — `scan/shared.py`'s new `DB_PATH` default takes effect the
moment the code deploys, so the service had to be down while the file moved
or it would create a fresh empty `scan.db` at the new location). `sha256`
-verified a manual pre-migration copy of `scan.db` (matched) before touching
anything.

First `gh workflow run deploy-portal-01.yml` failed at the SSH staging step
— `ssh: connect to host example-portal-host port 22: Connection timed out`,
a transient CI-runner-to-Tailscale blip, not caused by this change. Retried
immediately; second run succeeded (`deploy-portal-01.sh` restarts both
services as its last step, which is why the service needed to already be
stopped going in). Deploy's restart briefly started `patched-scan` with the
new code before the file move — its own `DB_DIR.mkdir()` created an empty
`db/scan.db` in that window. Caught within seconds (stopped the service
again immediately, checked row counts on both files before touching
anything further): the fresh file had 0 rows in `public_scans` and
`public_uploads`, confirming nothing real had been written to it in the
gap. Discarded it (kept a copy at
`/root/pat994-migration-backup/scan.db.fresh-empty-discarded`, not deleted
outright), moved the real `scan.db` (7 rows) into `db/`, restarted. Verified
`scan.patched.im/public/scan` serves 200, the live file still reads 7 rows,
and no `scan.db` was recreated at the old flat path.

Copied `portal-backup.sh`/`patched-portal-backup.service` to the box by
hand, `daemon-reload`d. No `backup.env` change needed — the script's own
fallback default (`${STATE_DIR}/db`) already matches the new location. Ran
a real backup: succeeded, `restic check` reported "no errors were found",
`ReadWritePaths` on the live unit reads
`-/srv/backup/health /var/lib/patched-scan/db`, and that directory contains
nothing but `scan.db`. `systemd-analyze security patched-portal-backup.service`: 4.6.

## Deployment rule

GitHub Actions is the canonical deployment path for `example-portal-host`:
`.github/workflows/deploy-portal-01.yml` stages a clean checkout and deploys
both portal and scan from the same commit. The historical
`/opt/src/portal` checkout is known to be dirty and is **not** an upgrade
source. Do not run `git pull` or either installer from it. The scan installer
now rejects an incomplete source tree before its `rsync --delete` can modify
`/opt/patched-scan`.

## 0. Prerequisites

- `example-portal-host` already stood up per `deploy/RUNBOOK.md` (Tailscale,
  ufw posture, nginx). The scan installer reuses that ufw posture and does not
  touch it. If this is a fresh box, run `deploy/install.sh` first.
- The Patched.im Mailer app (Graph app-only Mail.Send, PAT-109) credentials to
  hand, or a SendGrid key for the fallback path.
- A Cloudflare Turnstile widget (site key + secret) for `scan.patched.im`.

## 1. Install the service (~10 min)

Dispatch the GitHub Actions workflow from the commit to ship:

```bash
gh workflow run deploy-portal-01.yml --repo Patched-LTD/portal
gh run watch --repo Patched-LTD/portal
```

For a first deployment, complete the CI/Tailscale bootstrap in `docs/DEPLOY.md`
first. The workflow stages a clean checkout and invokes this installer itself;
there is no supported on-box `git pull` upgrade path.

The installer creates the `scan` system user, rsyncs `scan/` to
`/opt/patched-scan`, builds the venv, writes `/etc/patched-scan/env` from the
template (only if absent), installs a self-signed TLS placeholder, and enables
`patched-scan.service` (uvicorn on `127.0.0.1:8001`) plus the nginx vhost.

## 2. Configure and restart (~5 min)

Edit `/etc/patched-scan/env`:

```
GRAPH_MAIL_TENANT_ID=<tenant guid>
GRAPH_MAIL_CLIENT_ID=<app id>
GRAPH_MAIL_CLIENT_SECRET=<secret>
MAIL_SENDER=noreply@patched.im
TURNSTILE_SECRET=<turnstile secret>
TURNSTILE_SECRET_KEY=<same value as above>
TURNSTILE_SITE_KEY=<turnstile site key>
PUBLIC_BASE_URL=https://scan.patched.im
PUBLIC_RETENTION_DAYS=30
EMAIL_DRY_RUN=
```

```bash
systemctl restart patched-scan
journalctl -u patched-scan -n 20 --no-pager   # uvicorn up on 127.0.0.1:8001
```

The startup log warns if the NVD dataset is missing (next step).

## 3. Seed the NVD dataset (~5 min, needs outbound internet once)

The app **refuses scans (503) until `nvd.db` exists** — it never downloads the
feed mid-request. Build it with the operator script (writes to the state dir):

```bash
sudo -u scan NVD_DB_PATH=/var/lib/patched-scan/nvd.db \
  /opt/patched-scan/venv/bin/python /opt/patched-scan/bin/refresh-nvd.py
```

If the box has no outbound internet, build `nvd.db` on a machine that does
(same command with `NVD_DB_PATH=./nvd.db`) and copy it to
`/var/lib/patched-scan/nvd.db` (`chown scan:scan`).

Ongoing refresh is automatic: `deploy/install-scan.sh` installs and enables
`patched-scan-nvd-refresh.timer`, which runs the same refresh script daily at
02:00 (`patched-scan-nvd-refresh.service`, a oneshot unit). This manual seed
step is still required once, on first provisioning — the timer only keeps an
already-seeded dataset current, it does not bootstrap an empty box. Upgrading
an already-provisioned box onto the timer uses the same CI workflow dispatch
as any other change here; it stages a complete checkout and runs
`install-scan.sh` idempotently.

Confirm: `curl -s http://127.0.0.1:8001/healthz` →
`{"status":"ok","nvd":true,"nvd_stale":false,...}`. Check the timer itself with
`systemctl list-timers patched-scan-nvd-refresh.timer` and
`journalctl -u patched-scan-nvd-refresh -n 20 --no-pager`.

## 4. Cloudflare DNS (~5 min)

Cloudflare → patched.im zone → DNS:

- `A` record, name `scan`, value = the `example-portal-host` **public** IP,
  **Proxied** (orange cloud). Proxied is load-bearing: ufw only admits
  Cloudflare ranges, so a grey-cloud record would be unreachable by design.

## 5. Cloudflare Origin Certificate (~10 min)

The installer left a self-signed placeholder; replace it so the zone can stay on
Full (strict):

1. Cloudflare → patched.im → SSL/TLS → Origin Server → Create Certificate
   (RSA, hostname `scan.patched.im`, 15 years).
2. Paste the certificate into `/etc/ssl/scan.patched.im.pem` and the key into
   `/etc/ssl/scan.patched.im.key`; `chmod 600` the key.
3. `nginx -t && systemctl reload nginx`.

(The zone is already Full (strict) for app./dashboard., so no zone-wide change.)

## 6. Turnstile widget (~5 min)

Cloudflare → Turnstile → Add widget for `scan.patched.im`. Put the **site key**
in `TURNSTILE_SITE_KEY` and the **secret** in both `TURNSTILE_SECRET` and
`TURNSTILE_SECRET_KEY`, then `systemctl restart patched-scan`.

## 7. Smoke test (~10 min)

1. **Health:** `curl -s http://127.0.0.1:8001/healthz` →
   `{"status":"ok","nvd":true}`.
2. **Public form:** open `https://scan.patched.im/public/scan` → the CVE
   assessment form renders (Turnstile widget visible).
3. **Full flow:** submit the form with a real inbox and a small Intune devices
   CSV → you receive the 6-digit OTP email, enter it, and a `.docx` report
   arrives by email with working download / delete-now links.
4. **Old links still work:** the paths are unchanged from the dashboard funnel
   (`/public/scan`, `/public/scan/r/{token}`, `/public/scan/d/{token}`, …); only
   the hostname changed to `scan.patched.im`.

## The Mac app waitlist (PAT-2560)

The patched.im homepage form posts to `https://scan.patched.im/public/waitlist`
until the cutover below; once its freeze is deployed, nginx answers that path
with a 503 and the submit steps of the smoke test here no longer apply.
The list is the `waitlist_signups` table in `/var/lib/patched-scan/db/scan.db`,
which the backup rail above already covers. Everything an operator does with it
goes through one script:

```bash
W="sudo -u scan /opt/patched-scan/venv/bin/python /opt/patched-scan/bin/waitlist.py"
$W count                                      # how many people are on the list
$W count --since 2026-10-20T09:00:00+00:00    # ... and how many since the first public post (UTC)
$W list                                       # tab separated, oldest first
$W export > waitlist.csv                      # CSV, formula-safe
$W remove someone@example.com                 # take one person off; also clears their rate-limit records
```

**Smoke test after a deploy** (uses a real inbox; cleans up after itself):

1. `curl -s http://127.0.0.1:8001/healthz` shows `"waitlist_unnotified":0`.
2. Submit the form on `https://patched.im/` with a test address. The page that
   comes back says "You are on the list." and nothing about an enquiry.
3. An email arrives at `hello@patched.im` titled `Waitlist sign up N: <name>`.
4. Submit the same address again: same page, no second email, `$W count` unchanged.
5. `$W remove <the test address>` and confirm `$W count` drops by one. The count
   must read zero before the first public post.

**If sign up emails stop arriving,** check `waitlist_unnotified` on `/healthz`.
Above zero means sign ups are being stored and the mailer is failing: nobody is
lost, `$W list` has them, and `journalctl -u patched-scan | grep waitlist` names
each one. -1 means the table could not be read.

**Do not** add `waitlist_signups` to the retention sweep, and do not delete rows
by hand with `sqlite3`: `remove` also clears the rate-limit ledger for that address.

## Waitlist cutover to Cloudflare (PAT-2593)

The waitlist moves off this box. The freeze boundary is nginx, not the app:
`deploy/nginx-scan.conf` answers `/public/waitlist` and `/public/pricing-enquiry`
(exact paths, every method) with a 503 page, `Cache-Control: no-store` and
`Retry-After: 300`, and never passes them to uvicorn. Nothing else changes: the
app, `/etc/patched-scan/env`, `scan.db`, the timers, ufw and every other route,
`/healthz` included, are as they were. From the moment the freeze is live until
the website merge, a visitor who submits the homepage form sees that page and
is asked to send the form again, so keep the gap short.

**Order. Do not reorder.** `$W` is the alias from the waitlist section above.
The export holds personal details: it lives only in the protected folder named
in step 2, never in the repo, and is deleted once the reconcile is recorded.

1. **Freeze.** Merge this config to `main` and dispatch the usual workflow. It
   deploys from `main` only, and `install-scan.sh` step 8 copies the config to
   `/etc/nginx/sites-available/scan.patched.im`, runs `nginx -t` and reloads:

   ```bash
   gh workflow run deploy-portal-01.yml --repo Patched-LTD/portal
   gh run watch --repo Patched-LTD/portal
   ```

   The deploy script's rollback restores the two app directories, not the nginx
   config, and its smoke test is `/healthz` only. So validate the candidate on
   the box before dispatching (`nginx -t` against a copy, without installing
   it), and prove the freeze afterwards rather than reading it off a green run:

   ```bash
   for p in waitlist pricing-enquiry; do
     curl -s -o /dev/null -w "$p GET %{http_code}\n" https://scan.patched.im/public/$p
     curl -s -o /dev/null -w "$p POST %{http_code}\n" -d email=freeze-check@example.com https://scan.patched.im/public/$p
   done                                              # four lines, all 503
   curl -sI https://scan.patched.im/public/waitlist  # no-store, Retry-After: 300
   curl -s http://127.0.0.1:8001/healthz             # on the box: still ok
   $W count                                          # unchanged by the POSTs above
   ```

2. **Final backup, after the freeze.** With the write path closed the list can
   no longer change, so this copy is the complete source:

   ```bash
   systemctl start patched-portal-backup.service
   journalctl -u patched-portal-backup.service -n 30 --no-pager
   (
     umask 077
     install -d -m 0700 /var/backups/patched-waitlist/PAT-2593-final
     $W export > /var/backups/patched-waitlist/PAT-2593-final/waitlist-final.csv
     chmod 0600 /var/backups/patched-waitlist/PAT-2593-final/waitlist-final.csv
   ) && $W count
   ```

   The export is a private file: it is written only under the absolute,
   0700 folder `/var/backups/patched-waitlist/PAT-2593-final`, with `umask 077`
   so the file is created owner-only, never in the repository or the current
   directory. Do not print, `cat` or paste its rows anywhere; print counts only
   (`$W count`, `wc -l`).

3. **Reconcile the delta.** Compare
   `/var/backups/patched-waitlist/PAT-2593-final/waitlist-final.csv` with what the
   Cloudflare destination holds, by lower-cased email address. Only Mac signup
   rows whose consent and provenance are verified are eligible to import. The
   legacy pricing-enquiry ledger cannot reconstruct a full answer set and does
   not imply consent to join the waitlist; keep it held securely and do not
   import it while unverified. Import every
   address the source has and the destination lacks (sign ups made after the
   earlier import), then confirm the two counts are equal and no source address
   is missing. Addresses removed here with `$W remove` must not reappear there.
4. **Website merge.** Only after step 3 is clean, merge the website change that
   points the homepage form at Cloudflare. Merging to `main` deploys it.
5. **Confirm.** Submit the live form with a test address, see it arrive in the
   destination, and remove it there.

**Rollback.** Reopening means reverting this config on `main` and dispatching
the same workflow. Do it only after source and destination reconcile, in the
direction that matters: every address the Cloudflare destination has taken
since the freeze is first brought into `waitlist_signups`, and the website form
points back at `scan.patched.im`. Reopening first gives two lists that are both
accepting sign ups and neither complete. A rollback before step 4 has nothing
to bring back, because the destination has had no public traffic yet; confirm
that from its count rather than assuming it.

## Troubleshooting

- **Every scan returns "temporarily unavailable" (503):** `nvd.db` is missing —
  run the refresh script (step 3). `curl .../healthz` shows `"nvd":false`.
- **OTP / report emails never arrive:** check the Graph mail creds in
  `/etc/patched-scan/env`; `journalctl -u patched-scan` logs `[email:graph]`
  failures. With `EMAIL_DRY_RUN` set, mail is only logged, never sent.
- **Turnstile always fails:** `TURNSTILE_SECRET` empty means verification is
  skipped (dev); a wrong secret makes it fail closed. Match the widget.
- **522 from Cloudflare:** ufw/nginx — confirm the portal ufw posture is in
  place and nginx has the `scan.patched.im` vhost (`nginx -t`).
- **Permission denied writing state:** the unit's `StateDirectory=patched-scan`
  creates `/var/lib/patched-scan` owned by `scan`. If you seeded `nvd.db` as
  root, `chown scan:scan /var/lib/patched-scan/nvd.db`.
