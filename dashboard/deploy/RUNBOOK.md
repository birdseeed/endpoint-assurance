# Deploy hook RUNBOOK — PAT-909

Installing `deploy/post-receive` as the live hook on `example-prod-host`. This
is a box-side change (SSH + root), so it is Andy's manual step, not
something an agent should run — see `AGENTS.md`'s "No direct path to
production from personal machines" rule. This doc is the exact spec for
that step.

## Why

The live hook at `/opt/git/dashboard.git/hooks/post-receive` today is a raw
`fetch` + `reset --hard` + `pip install` + `systemctl restart`, un-versioned,
with no smoke test and no rollback — a bad push takes the service down with
no automatic recovery. `deploy/post-receive` (this repo, version-controlled)
delegates to `scripts/deploy.sh`, which already has a smoke suite and
auto-rollback; installing it wires that into every push instead of leaving
it dormant.

## Box-side config now deploys itself (PAT-986)

Before PAT-986, `scripts/deploy.sh` only ever moved code: `deploy/patched-dashboard.service`
and any `deploy/*.rules` had to be installed by hand over SSH, and files the repo had deleted
(e.g. a superseded sudoers rule) had to be removed by hand too. That's exactly what happened
for PAT-931 — the polkit rule and the hardened unit were installed manually, out of band, and
a deploy of the code alone would have shipped hardening that assumed authorisation config that
was never actually deployed.

As of PAT-986, every hook-mode and standalone deploy runs `sync_box_config()` (in
`scripts/deploy.sh`, called immediately before `restart_service`, both on the forward path and
from `rollback()`):

- Installs `deploy/patched-dashboard.service` to `/etc/systemd/system/`, running
  `systemctl daemon-reload` only when the file's content actually changed.
- Installs any `deploy/*.rules` to `/etc/polkit-1/rules.d/` (mode 0644, root:root). polkitd
  auto-reloads `rules.d` on its own — no reload step.
- Removes anything listed in `deploy/removed-artifacts.txt` that still exists on the box (the
  declarative manifest for artefacts a later commit has superseded — `/etc/sudoers.d/patched-ops-fw`
  is the entry PAT-986 added for PAT-931's migration). PAT-2312 added the stale sudoers grants
  and crontab for the non-existent `jarvis` and `openclaw` accounts and the `jarvis-claude` shim,
  then `/etc/sudoers.d/patched`, the retired `patched` account's passwordless grant (below).
  `90-cloud-init-users` is the provider's and is never listed. Entries are whole files deleted
  with `rm -f`; nothing in the deploy edits sudoers content.
- Removes the retired `patched` login account (PAT-2312, `remove_retired_account` in
  `scripts/deploy.sh`). Andy retired it on 2026-09-30: nobody used it by hand, nothing ran as it,
  and admin access to the box is root over Tailscale only. Before changing anything the step
  checks that the account's uid is 1001, its passwd home is `/home/patched` (a directory it
  owns, since `userdel -r` deletes whatever that entry names), no process runs as it, it owns
  nothing on the root filesystem outside its home, `/tmp` and `/var/tmp`, and every `*.json`
  under `~/.cloudflared` has a byte-identical regular file of the same name in `/etc/cloudflared`,
  so the home never takes the only copy of a tunnel credential with it. Any guard that fails
  fails the deploy with an ERROR naming it, and nothing changes. Otherwise it deletes the
  account's files in `/tmp` and `/var/tmp`, runs `userdel -r patched` (the home goes, and
  `~/.cloudflared/cert.pem` with it), removes the `patched` group if userdel left it, and proves
  the result: no passwd entry, no group, no group membership, no home, nothing owned by uid 1001.
  After that every deploy logs it as already absent, but a surviving group, home or membership
  fails the deploy until someone removes it by hand. Like the manifest it is one-directional; a
  rollback never recreates the account.

  **Order.** The manifest is read from the new checkout, so the grant goes on the first deploy
  that carries it. The account goes one deploy later, because the hook runs the previous
  `deploy.sh`. A second `deploy.yml` dispatch with no new commit is enough: it runs `deploy.sh`
  standalone on the box. Check it afterwards:

  ```bash
  ssh root@example-prod-host '
    getent passwd patched; getent group patched; getent group sudo; ls /etc/sudoers.d
    find / -xdev -uid 1001 | head
    grep "Retired account patched" /var/log/patched-deploy.log | tail -3'
  ```

  Nothing for `passwd` or `group patched`, `sudo:x:27:` without `patched`, no `patched` in
  `/etc/sudoers.d`, no files, and a `Retired account patched removed: ...` line. Do not create
  an account called `patched` on this box again: the deploy removes one with uid 1001 and fails
  on one with any other uid.
- Holds two files it does not install to root:root whenever they exist (PAT-2312):
  `/usr/local/bin/hcloud` at 0755, because root runs it from the firewall-apply units, and the
  Origin Certificate key `/etc/ssl/dashboard.patched.im.key` at 0600, because only the nginx
  master (root) reads it and it had been readable by `www-data`. Ownership and mode only, so
  upgrading hcloud or replacing the key is a root job. A symlink at either path fails the
  deploy rather than being followed; replace it with a regular file.
- Fails the deploy (triggering the normal auto-rollback path) if the live systemd unit still
  differs from the repo's after installation — a drift guard, not just a best-effort copy.

It's idempotent — a box that's already correct (example-prod-host, as of the manual PAT-931
install) sees every step logged as unchanged/skipped/already-absent and installs nothing.
Because rollback re-runs the same sync against whatever commit it resets the checkout back to,
a rollback reverts the systemd unit and polkit rules together with the code — see the
`sync_box_config()` header comment in `scripts/deploy.sh` for the one documented exception
(manifest-driven removals don't reverse on rollback, by design).

**Practical effect on this RUNBOOK:** the manual "copy the unit file / polkit rule into place"
steps that were done by hand for PAT-931 are no longer part of installing new `deploy/`
artefacts going forward — commit the file under `deploy/` and it ships on the next push through
the hook, same as code. This RUNBOOK's own subject (installing `deploy/post-receive` as the
live hook) is still a manual, box-side, Andy-only step — that bootstrap problem doesn't change:
something has to install the *first* copy of the hook and `scripts/deploy.sh` before either can
deploy itself.

## The backup rail is version-controlled (PAT-994)

`deploy/prod-backup.sh`, `deploy/patched-prod-backup.service` and
`deploy/patched-prod-backup.timer` are byte-for-byte captures of what is
running on `example-prod-host` as of 2026-09-03. They were added because the
backup rail existed **only** on the box: no review, no history, and no rollback
beyond whatever copy the person making a change happened to take. That is the
same shape as the un-versioned deploy hook this RUNBOOK exists to fix.

Nothing was deployed to add them. The repo copies matched the live files
exactly, verified by `sha256sum` on both sides:

| file | sha256 |
| --- | --- |
| `patched-prod-backup.service` | `76fdd65b10cf...44fd1851` |
| `patched-prod-backup.timer` | `e28d2bc02019...1835feed` |
| `prod-backup.sh` | `c197d01942f0...538dd0b6` |

**These are not deployed automatically.** The post-receive hook deploys the
application checkout, not `/etc/systemd/system` or `/opt/patched-dashboard/bin`.
To change the backup rail, edit here, get it reviewed, then copy to the box and
`systemctl daemon-reload`, and confirm a real backup run afterwards:

```
systemctl start patched-prod-backup.service
journalctl -u patched-prod-backup.service -n 30 --no-pager
```

Re-verify the hashes above match after any deploy. If the box and the repo
diverge, the repo is not a record of anything.

**They had diverged by 2026-09-30 (PAT-2311).** The live unit had moved on
(its comments cite PAT-1791): `ExecStart` runs
`/usr/local/libexec/patched-prod-backup/prod-backup.sh` (root:root 0750,
outside the code tree), not `/opt/patched-dashboard/bin/prod-backup.sh`.
`deploy/patched-prod-backup.service` now matches the live file byte for byte
(sha256 `0350d62c1705...bf2048de`); the timer still matches. The live script
does **not** match `deploy/prod-backup.sh` (live sha256
`4e95d2b8cc31...1429893e`), and a `restore-test.sh` sits beside it that this
repo does not have. The live script backs up `/opt/patched-dashboard/reports`,
not `/var/lib/patched-dashboard/reports`, where reports have been written
since PAT-2307. `sync_box_config()` does not install any of the three.

**Secrets stay out.** Restic credentials come from
`EnvironmentFile=/etc/patched-dashboard/backup.env`, which is not in the repo
and must never be. Both scripts say so at the top and neither sources it.

**Residual weakness fixed (PAT-994 step 2).** `dashboard.db` (+ `-wal`/`-shm`)
now lives in `/var/lib/patched-dashboard`, a dedicated state directory
containing nothing else. `DASHBOARD_DB_PATH=/var/lib/patched-dashboard/dashboard.db`
is set in both `/etc/patched-dashboard/dashboard.env` (the app reads it —
`shared.py` already supported this override) and `/etc/patched-dashboard/backup.env`
(`prod-backup.sh`'s `DB_SRC` reads the same var, falling back to the new
canonical path if unset). `patched-prod-backup.service`'s `ReadWritePaths`
narrowed from `/opt/patched-dashboard` to `-/srv/backup/health /var/lib/patched-dashboard`
— the backup process can no longer touch its own script or the application
code. `patched-dashboard.service` was granted `/var/lib/patched-dashboard` as
an *additional* write path (its `/opt/patched-dashboard` grant is unchanged —
`nvd.db` still lives there; narrowing that further is a separate, larger
PAT-887-scoped hardening pass, not this ticket). **Superseded by PAT-2307:** the
`/opt/patched-dashboard` grant is gone, `nvd.db` and `reports/` moved to the
state directory too, and the unit uses `StateDirectory=patched-dashboard`
instead of a `ReadWritePaths=` entry. See the next section.

**Migration procedure** (manual, box-side, same class of step as installing
the hook above): stop `patched-dashboard`, `mkdir -p /var/lib/patched-dashboard`
owned `www-data:www-data`, `mv` `dashboard.db`/`-wal`/`-shm` into it, add
`DASHBOARD_DB_PATH` to both env files, deploy the three updated `deploy/`
files (the service unit auto-deploys via `sync_box_config()`; the backup
script/unit/timer do not — copy by hand per the section above), reload
systemd, start `patched-dashboard`, confirm it serves 200s and reads the
relocated DB, then run a real `patched-prod-backup.service` and confirm a
clean `restic check`. See the Install log entry below for when this ran and
what it found.

## The code tree is root's, and every deploy checks it (PAT-2307)

**Why.** Root runs `scripts/deploy.sh` (the hook execs it), the venv's pip and
python, the smoke suite, and the `hetzner-firewall-apply` and
`patched-maintenance-facts` timer scripts out of `/opt/patched-dashboard`, and
installs systemd units, polkit rules and the nginx site config from its
`deploy/`. The tree was owned by `www-data`, the user the dashboard and
nginx's workers run as, so anything that could act as `www-data` could plant
code or config that root ran or installed on the next deploy. The bare mirror
`/opt/git/dashboard.git`, where the root-run hook lives, was owned by uid 999,
which has no passwd entry any more; the next system user created on the box
would have inherited it.

**The model now.**

- `/opt/patched-dashboard` and `/opt/git/dashboard.git`: `root:root`, no group
  or other write. `DEPLOYED_SHA` stays in the tree, written by root 0644, read
  by the app.
- `/var/lib/patched-dashboard` (`www-data:www-data` 0750): everything the app
  writes. `dashboard.db` (+ `-wal`/`-shm`, PAT-994, unchanged by this ticket),
  `nvd.db` (the NVD match cache) and `reports/`. The unit's
  `StateDirectory=patched-dashboard` has systemd create it before the service
  starts, and `Environment=DASHBOARD_STATE_DIR=...` points the app at it.
- The unit no longer grants write access to `/opt/patched-dashboard`, so with
  `ProtectSystem=strict` the tree is read-only in the service's namespace as
  well as by ownership.
- `patched-dashboard-prune-reports.service` prunes
  `/var/lib/patched-dashboard/reports` and is now installed by
  `sync_box_config()`. Its `.timer` is too since PAT-2311: installed when it
  differs, `enable --now` after a change, and checked enabled and active on
  every deploy. The live timer was byte-identical to the repo's copy when
  that landed, so the first sync changes nothing on the box.

**The guard.** `deploy/code-tree-guard.sh check` fails if anything under
either tree, any directory above them, or any symlink target inside them is
owned by a non-root user or writable by group or other. It also fails if
either repository's `config` has a key outside a short allowlist (what a
clone or `init --bare` writes: `core.*` basics, `remote.*.url/fetch`,
`branch.*.remote/merge`) or a file with a git hook's name other than the
mirror's `post-receive`. Root runs git in both, `git reset --hard` alone runs
the `reference-transaction` hook and `core.fsmonitor`, and until PAT-2307 the
service user could write both files, so ownership alone cannot vouch for
their contents on the transition. A read-only dry run against the live box
on 2026-09-30 found no config or hook outside the allowlist. It runs:

1. from `deploy.yml`, with the runner's own copy piped over SSH, before the
   push that fires the hook;
2. from `scripts/deploy.sh`, before it runs anything from the tree (covers a
   manual push to the mirror), and after every `git reset --hard`, forward or
   rollback, straight after `lock`;
3. from `deploy.yml` again, runner's copy, before the nginx config is
   installed.

A failed check is never healed silently. It prints one `::error::` line per
path and the deploy stops before anything runs from the tree.

**The deploy script and hook are hashed too (PAT-2311).** The guard proves
no non-root user could have changed what root runs; it cannot see an edit
made as root. So before the push `deploy.yml` also pipes the runner's copy of
`deploy/verify-box-deploy-script.sh` to the box. It reads the commit the
checkout has from `/opt/patched-dashboard/.git/HEAD` and its ref file (plain
reads, no git as root in the checkout), hashes the box's `scripts/deploy.sh`
and `/opt/git/dashboard.git/hooks/post-receive`, and fails unless `deploy.sh`
matches the same file at that commit in GitHub's history and the hook matches
`deploy/post-receive` or the pinned hash of the copy installed on 2026-07-17
(`f0291df`'s version; the repo copy has only gained comments since). The same
check, read-only, from any clone with full history:

```bash
bash deploy/verify-box-deploy-script.sh verify ssh root@example-prod-host
```

On a mismatch, nothing was pushed. Diff the box's file against GitHub's copy
at the commit it names, find out who changed it and why, and restore it by
hand before deploying again. Do not edit the check to get past it.

**First deploy of PAT-2307 (one time).** The `deploy.sh` that runs on this
deploy is the previous commit's (the hook execs the checkout's copy before the
reset, PAT-1441), and that version chowns the tree back to `www-data`. The
workflow handles both ends:

```bash
gh workflow run deploy.yml -R Patched-LTD/dashboard -f adopt_code_tree=true
```

1. **Before the push** (`adopt`, as root, runner's copy of the guard):
   - makes sure `/var/lib/patched-dashboard` exists (it does, from PAT-994);
   - as `www-data`, copies `/opt/patched-dashboard/nvd.db` and any top-level
     `/opt/patched-dashboard/reports/*.docx` into it, keeping mtimes. Each copy
     goes to a temp file, is compared byte for byte with `cmp`, and is linked
     into place only if nothing is there yet. Symlinks are skipped, and
     `nvd.db` is skipped if a rollback journal sits beside it. Originals are
     never moved or deleted;
   - `chown -hR root:root` and `chmod -R go-w` on both trees (symlinks are not
     followed), `DEPLOYED_SHA` to 0644;
   - `check`. If anything fails, the job stops before the push.
2. **The push.** The previous `deploy.sh` resets to the new commit, chowns
   the tree to `www-data`, installs requirements, installs the new
   `patched-dashboard.service` (sync_box_config, which it already has),
   restarts, runs the smoke suite and writes `DEPLOYED_SHA`. The new code
   starts with `DASHBOARD_STATE_DIR` set and writes only to the state
   directory.
3. **After the push** (`adopt-finish <sha>`): only if `DEPLOYED_SHA` names
   the commit just pushed, lock and check again. If the deploy rolled back,
   the tree is left as the old code expects and the step fails.
4. **nginx**: installed only after that check passes.

Then dispatch once more **without** the flag. The push is a no-op, so the
workflow runs the new `deploy.sh` directly: it checks, locks, and installs the
updated `patched-dashboard-prune-reports.service`. Until that second run, the
hand-installed prune unit can still read the new reports directory but not
delete from it; with 90-day retention nothing is due, and if it were, the unit
would fail visibly rather than silently skip.

**Readback after both runs** (read-only):

```bash
ssh root@example-prod-host '
  stat -c "%U:%G %a %n" /opt/patched-dashboard /opt/patched-dashboard/scripts \
    /opt/patched-dashboard/scripts/deploy.sh /opt/patched-dashboard/deploy \
    /opt/patched-dashboard/deploy/nginx-dashboard.conf /opt/patched-dashboard/DEPLOYED_SHA \
    /opt/git/dashboard.git/hooks /opt/git/dashboard.git/hooks/post-receive \
    /var/lib/patched-dashboard /var/lib/patched-dashboard/*
  find /opt/patched-dashboard /opt/git/dashboard.git ! -type l \( ! -user root -o -perm /022 \) | head
  sudo -u www-data test -w /opt/patched-dashboard/scripts/deploy.sh && echo WRITABLE || echo not-writable
  systemctl show patched-dashboard -p StateDirectory -p ReadWritePaths
  cmp /opt/patched-dashboard/deploy/patched-dashboard-prune-reports.service \
      /etc/systemd/system/patched-dashboard-prune-reports.service && echo prune-unit-current'
```

Expect `root:root` and no group or other write on everything under `/opt`,
an empty `find`, `not-writable`, and `www-data:www-data` on the state
directory and its contents.

**Rollback.** Rolling back to a commit from before PAT-2307 works without a
hand step: the old code runs on the root-owned tree, reads `dashboard.db`
from `DASHBOARD_DB_PATH` as before, and reads the untouched legacy `nvd.db`.
Only its report and NVD-cache writes, which it made inside the tree, fail. The
old `deploy.sh` would then chown the tree back to `www-data` on the next
deploy after that, and the guard would fail that deploy loudly until someone
adopts again. To undo the ownership change by hand (Andy-gated box write):
`chown -R www-data:www-data /opt/patched-dashboard` restores the previous
state exactly; nothing was deleted.

**Later cleanup, not done by this change.** The originals left in the tree:
`/opt/patched-dashboard/nvd.db`, `/opt/patched-dashboard/reports/` (and its
empty `public/`), `/opt/patched-dashboard/public_scans/` (59 empty
directories, frozen since PAT-866), the 0-byte stray
`/opt/patched-dashboard/dashboard.db`, `dashboard.db.bak-1780502779` and
`shared.py.bak-<timestamp>`. Remove them in a separate change once the
new paths have run cleanly for a while. PAT-2311 lists `nvd.db` and
`dashboard.db` in `deploy/removed-artifacts.txt`, so the deploy removes
them. `reports/` stays: the manifest removes files, not directories, and
the live backup script still backs up that path, not the state directory's
`reports/` (see the backup-rail note above). Old `scans.report_path` rows keep
their absolute `/opt/...` paths; `download_report` serves them while the
files exist and 404s after.

## Verifying what's actually deployed (PAT-992)

**A merge to `main` does not deploy anything.** `.github/workflows/deploy.yml`
is `workflow_dispatch` only — someone (or a script) has to run
`gh workflow run deploy.yml -R Patched-LTD/dashboard`, or push directly to
the box's bare mirror, or nothing changes on `example-prod-host`. "It's
merged" is never evidence that it shipped; check the box.

Before this ticket, the box-side signal for "what's actually running" was a
file (`/opt/patched-dashboard/DEPLOYED_SHA`) that nothing wrote — hand-created
once and asserting a stale SHA ever since, worse than no file at all because
it looked authoritative. Two things now make that check possible:

- **`DEPLOYED_SHA` is written by `scripts/deploy.sh` itself,** atomically
  (temp file + `mv`, and the temp file's content is read back and verified
  before the `mv` — a write that silently fails partway must never promote
  a truncated file over a good one), only as the very last step of a path
  that has positively confirmed the running state: a forward deploy whose
  smoke suite passed (or whose restart succeeded with no smoke runner
  present), or a completed rollback — where it records the commit the box
  rolled BACK to, never the one that failed. It is deliberately **not**
  written on the no-op path (nothing restarted, nothing smoke-tested, so
  nothing confirmed — the checkout could be sitting on a commit a *prior*
  smoke failure left behind under `.no-auto-rollback`, and a no-op write
  would promote that unconfirmed commit to "confirmed"), the
  `.no-auto-rollback` skip path itself, or a rollback that fails
  critically — an unwritten file leaves the previous, still-accurate value
  in place rather than asserting something unconfirmed. Format is flat and
  greppable:
  ```
  ssh root@example-prod-host 'cat /opt/patched-dashboard/DEPLOYED_SHA'
  # DEPLOYED_SHA=<full 40-char commit sha>
  # DEPLOYED_AT=<UTC ISO-8601 timestamp>
  ```
- **The dashboard's `deploy_drift` scheduler check** (`main.py`,
  `_run_deploy_drift_check_tick`) compares that recorded SHA against the
  box's own checkout `git rev-parse HEAD` and requires a clean tracked working
  tree every scheduler tick. It reports the result via
  `GET /admin/check-status` alongside every other estate health
  check. It only ever compares against the box's OWN last-confirmed deploy —
  it does not and cannot reach `origin/main` on GitHub (deploy keys are
  disabled org-wide, PAT-617), so it never claims to know whether the box is
  behind the latest merge, only whether it's running what its own tooling
  last confirmed. Tracked scp/manual hotfixes report `degraded` even when
  HEAD and `DEPLOYED_SHA` still agree; untracked runtime files are ignored.
  The git status read is bounded and an error or timeout degrades the check
  rather than assuming a clean tree. `unconfigured` means either no deploy has run under this
  tooling yet (a bootstrap gap, expected to self-resolve on the next
  deploy), or a mismatch was found but the recorded timestamp predates this
  process's own start within a bounded grace window (10 minutes,
  `_DEPLOY_INFLIGHT_GRACE` in `main.py`) — since the write always lands
  *after* the restart, a just-restarted process legitimately hasn't caught
  up to the record yet, and that is reported as "still might be finishing",
  not a false alarm. `degraded` means a real mismatch past that grace
  window, or the record/checkout couldn't be read at all. It never reports
  `ok` without a positive SHA match.

So verifying a deploy landed requires all four signals, not one file you have
to trust blindly:
```
ssh root@example-prod-host '
  git -C /opt/patched-dashboard rev-parse HEAD
  git -C /opt/patched-dashboard status --porcelain=v1 --untracked-files=no
  cat /opt/patched-dashboard/DEPLOYED_SHA
  curl -s -H "Authorization: Bearer $DASHBOARD_API_KEY" \
    https://dashboard.patched.im/admin/check-status | grep -A3 deploy_drift
'
```
HEAD and `DEPLOYED_SHA` should agree, tracked status should print nothing,
and `deploy_drift` should read `ok`.

## Order matters — read this before installing

`deploy/post-receive` invokes `$REPO_DIR/scripts/deploy.sh --from-hook ...`
using **whatever copy of `scripts/deploy.sh` is already checked out at
`/opt/patched-dashboard` at the moment the hook runs** — the hook does not
reset the checkout itself before invoking it; `deploy.sh` does that
internally. That means the box needs a checkout that already contains this
PR's `scripts/deploy.sh` (the one with `--from-hook`/`--rollback-to`
support) **before** you swap the hook. Otherwise the new hook calls an old
`deploy.sh` that doesn't understand those flags and the deploy fails
immediately on the first push after install.

So the sequence is:

1. Merge this PR to `main`.
2. Deploy normally with the **existing (old, raw) hook still in place**:
   `gh workflow run deploy.yml -R Patched-LTD/dashboard`. This lands the new
   `scripts/deploy.sh` (and `deploy/post-receive` itself, and the fixed
   `scripts/smoke/dashboard_core.py`) on `/opt/patched-dashboard` via the
   old hook's plain `reset --hard` + `pip install` + restart — no smoke
   test yet, same as every deploy today.
3. Only now install the new hook (steps below).
4. Verify (steps below) with a trivial follow-up push, watching the new
   hook path actually run.

## Smoke prerequisites — check before the first verified deploy

The smoke suite has environment preconditions of its own. If these aren't
met, every deploy will fail smoke and roll back even though the code is
fine:

- `DASHBOARD_API_KEY` must be present in
  `/etc/patched-dashboard/dashboard.env`. `scripts/deploy.sh` greps it out
  of that file for the Bearer-auth smoke checks; the hook's SSH push
  environment doesn't carry it.
- `EMAIL_DRY_RUN` must be **absent** from the same env file, and a mail
  provider (`GRAPH_MAIL_*`) configured. The `email_delivery` smoke module
  hard-fails unless `/api/smoke/health` reports `email_delivery: live`
  (PAT-1346). This is the inverse of the pre-2026-09-03 rule: outbound mail
  is now live, and the gate exists so it cannot be suppressed unnoticed.

(PAT-866: the `public_scan` module and its `TURNSTILE_SECRET`-must-be-unset
precondition are gone — that module smoke-tested the public CVE-scan
funnel, which was removed from this repo and now lives at scan.patched.im,
portal repo, with its own deploy and its own Turnstile config.)

Check both before installing the hook (don't paste values into chat;
eyeball on the box):

```
ssh root@example-prod-host 'grep -cE "^DASHBOARD_API_KEY=." /etc/patched-dashboard/dashboard.env; \
  grep -cE "^EMAIL_DRY_RUN=" /etc/patched-dashboard/dashboard.env'
```

Expect: `1` (key present) and `0` (dry-run absent, so delivery is live).

## Install

**1. Check what's there now** (ownership/mode — the new hook must match,
not introduce a privilege change):

```
ssh root@example-prod-host 'stat -c "%U:%G %a" /opt/git/dashboard.git/hooks/post-receive'
```

Expect `root:root 755` (or similar — root, since the hook runs as whoever
the SSH connection authenticates as, and both `deploy.yml` and manual pushes
connect as `root@example-prod-host`). Use whatever this command actually
returns for the `chown` below, not the assumed value, if it differs.

**2. Backup the live hook before touching it:**

```
ssh root@example-prod-host 'cp -a /opt/git/dashboard.git/hooks/post-receive \
    /opt/git/dashboard.git/hooks/post-receive.pre-pat909.bak'
```

**3. Copy in the new hook** (from a checkout that already has this PR
merged — the Mac working copy, or the box's own `/opt/patched-dashboard`
now that step 2 above of the "Order matters" sequence has landed it there):

```
scp deploy/post-receive root@example-prod-host:/opt/git/dashboard.git/hooks/post-receive
```

**4. Set permissions to match what step 1 reported** (adjust `root:root` if
step 1 showed something else):

```
ssh root@example-prod-host '
  chmod 755 /opt/git/dashboard.git/hooks/post-receive
  chown root:root /opt/git/dashboard.git/hooks/post-receive
'
```

**5. Confirm `scripts/deploy.sh` is executable in the checkout** (it should
already be, from the git checkout's own permissions, but this is what the
hook depends on existing and being runnable):

```
ssh root@example-prod-host 'ls -l /opt/patched-dashboard/scripts/deploy.sh'
```

## Verify

**Verified-deploy test — push a trivial commit through the normal path:**

1. Make a no-op-ish change (a comment, a doc line) on `main` and merge it,
   or push directly if it's doc-only.
2. `gh workflow run deploy.yml -R Patched-LTD/dashboard`
3. Watch the hook actually run the new path:
   ```
   ssh root@example-prod-host 'tail -n 60 /var/log/patched-deploy.log'
   ```
   Expect to see `Deploy invoked by post-receive hook`, `Running smoke
   suite...`, and `Smoke suite PASSED` / `Deploy SUCCESSFUL` — not just a
   silent `reset --hard` with no smoke lines, which would mean the old hook
   is still installed.
4. Confirm the commit landed: `ssh root@example-prod-host 'git -C /opt/patched-dashboard rev-parse HEAD'`
   should match the pushed commit, and `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/`
   (run on the box) should print `200`.

**Optional — deliberate-failure staging test** (proves the rollback path
for real, not just in the dry run in `scripts/test-post-receive-rollback.sh`).
Do this on a low-traffic window since it does a real restart + rollback
cycle on the live service:

1. On a branch, temporarily break something the smoke suite checks — e.g.
   change `scripts/smoke/dashboard_core.py`'s expected status code, or add
   `import sys; sys.exit(1)` at the top of `scripts/smoke/run_all.py` — and
   merge/push it through the normal deploy path.
2. Watch `/var/log/patched-deploy.log`: expect `ERROR: smoke suite FAILED`,
   `Rolling back to <previous sha>`, and `Rolled back. Service is on
   <previous sha>`.
3. Confirm `git -C /opt/patched-dashboard rev-parse HEAD` on the box is back
   at the pre-deploy commit, and the service is still serving 200s.
4. Revert the deliberately-broken commit from `main` immediately after
   confirming rollback — don't leave a known-broken commit at `main` HEAD.

If the deliberate-failure test doesn't roll back cleanly, that's a
stop-ship signal: fix `scripts/deploy.sh` before relying on this hook, and
consider re-installing `post-receive.pre-pat909.bak` in the meantime.

## Rollback of the hook itself

If the new hook misbehaves and you need the old (raw, no-smoke) behavior
back immediately:

```
ssh root@example-prod-host 'cp -a /opt/git/dashboard.git/hooks/post-receive.pre-pat909.bak \
    /opt/git/dashboard.git/hooks/post-receive'
```

## Install log

- **2026-07-17, example-prod-host:** installed. Live hook backed up to
  `post-receive.pre-pat909-20260717T175549Z.bak`. Smoke prerequisites
  checked first: `DASHBOARD_API_KEY` present, `EMAIL_DRY_RUN` was unset —
  added `EMAIL_DRY_RUN=1` to `/etc/patched-dashboard/dashboard.env` (backed
  up to `dashboard.env.pre-pat909-20260717T175522Z.bak`) and restarted the
  service to load it. `TURNSTILE_SECRET` is live in production (real
  Turnstile bot-protection is on) — left as-is, a deliberate call, not an
  oversight: disabling it to satisfy `scripts/smoke/public_scan.py`'s
  precondition would be a real security regression just to make a deploy
  hook happy. **Known consequence:** every deploy's smoke suite will fail on
  the `public_scan` module and roll back until this is resolved (either
  scripts/smoke/public_scan.py grows a genuine Turnstile-aware bypass for
  smoke runs, or Turnstile verification moves out of the request path the
  smoke test exercises). Filed as a follow-up rather than blocking this
  install — the hook, smoke suite, and rollback mechanics are still real
  and correct; this specific module needs its own fix before deploys can
  pass cleanly end-to-end. Tracked as PAT-936.

- **2026-07-17, verification deploy:** the real `deploy.yml` → hook →
  smoke path ran for the first time in production and rolled back as
  expected — but for a different, broader reason than PAT-936:
  `scripts/smoke/email.py` (predates PAT-909, added in PAT-228) shadowed
  Python's own stdlib `email` package for every module in
  `scripts/smoke/` (`run_all.py` runs each module as a direct file, which
  puts the script's own directory first on `sys.path`), breaking
  `dashboard_core`, `email` itself, and `public_scan` with
  `ModuleNotFoundError: No module named 'email.errors'`. Only `scheduler`
  passed. Rollback worked correctly — box healthy, reverted to the
  pre-deploy commit. Fixed as PAT-937 (renamed to `email_dry_run.py`, and
  again to `email_delivery.py` under PAT-1346);
  PAT-936 (Turnstile) remains open and will still fail `public_scan`
  specifically once PAT-937 lands.

- **2026-07-26, example-prod-host (manual, pre-PAT-986):** Andy installed
  `deploy/patched-dashboard.service` and `deploy/49-patched-ops-fw.rules`
  by hand and removed `/etc/sudoers.d/patched-ops-fw`, to land PAT-931's
  hardening — proving live that `scripts/deploy.sh` had no path for any of
  this (see PAT-986). This is exactly the state `sync_box_config()`
  (PAT-986, see the section above) expects to find: the first real
  hook-mode deploy after this lands should log everything as
  unchanged/skipped/already-absent and change nothing on disk. Confirm
  that's what happens on the next deploy rather than assuming it — logged
  here so it's checked, not just believed.

- **2026-09-04, example-prod-host (PAT-994 step 2, migration):** ran the
  relocation live. First `deploy.yml` run failed the smoke gate —
  `patched-dashboard.service` exited `226/NAMESPACE`, "Failed to set up
  mount namespacing: /var/lib/patched-dashboard: No such file or
  directory". Root cause: `ReadWritePaths=`, unlike `StateDirectory=`,
  does not create its target directory; the unit referenced a path that
  didn't exist yet. Auto-rollback fired correctly and the box was healthy
  on the pre-deploy commit within 18 seconds, per `/var/log/patched-deploy.log`.
  Created `/var/lib/patched-dashboard` (`www-data:www-data`, `0750`) and
  redeployed — smoke suite passed clean the second time. Then, box-side:
  stopped the service, `sha256`-verified a manual pre-migration copy of
  `dashboard.db` (matched), moved it into the new directory (no `-wal`/
  `-shm` sidecars existed at the time — clean shutdown had already
  checkpointed them), added `DASHBOARD_DB_PATH` to both `dashboard.env`
  and `backup.env` (each backed up first), restarted, and confirmed via
  `/api/metrics` (200) and a direct `sqlite3` read of the new file's `kv`
  table that the app was live-reading and -writing the relocated DB, with
  no shadow file recreated at the old path. Copied the updated
  `prod-backup.sh`/`patched-prod-backup.service` to the box by hand (not
  auto-deployed, per this doc), `daemon-reload`d, ran a real backup:
  succeeded, `restic check` reported "no errors were found",
  `ReadWritePaths` on the live unit reads
  `-/srv/backup/health /var/lib/patched-dashboard`, and
  `/var/lib/patched-dashboard` contains nothing but `dashboard.db`.
  `systemd-analyze security patched-prod-backup.service`: 6.5 → 4.6.
