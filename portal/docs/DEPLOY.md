# Deploying to example-portal-host (PAT-1151)

GitHub Actions is the canonical deployment path. The historical
`/opt/src/portal` checkout is known to be dirty from manual recovery work;
never use it as an upgrade source, run `git pull` there, or invoke either
installer from it. CI stages a clean checkout, and the installers operate only
on that staged source. The canonical live snapshot and deploy interlock are in
the [current state](architecture.md#current-state); this document describes
the deploy path and retains the historical bootstrap record.

## The deploy path, once bootstrapped

Two workflow files, mirroring `api-build.yml` / `deploy-api-01.yml` in the
`patched.im` repo (PAT-1979):

- `.github/workflows/portal-build.yml` (every push to main that touches app
  code): ruff + pytest (the same gate `ci.yml` runs) and `shellcheck` over the
  deploy scripts. Runs in CI on every push and NEVER touches the box.
- `.github/workflows/deploy-portal-01.yml` (manual `workflow_dispatch` only -
  the Andy-gate; this repo is private on a Team plan, where GitHub's
  required-reviewer `environment` protection is unavailable, so the manual
  trigger is the enforceable gate):
  1. `build-test` calls `portal-build.yml` via `workflow_call`, so the same
     lint/test steps gate a real deploy without a second copy of them.
  2. `deploy` (only when `inputs.deploy` is true and the ref is
     `refs/heads/main` - the run-name says up front whether a given dispatch
     is going to ship or not):
     - Connects to the tailnet as `tag:ci` (ephemeral).
     - `rsync`s the checkout to `example-portal-host:/opt/patched-deploy-staging/portal/`
       over Tailscale SSH. Push-to-box only (PAT-617) - the box never fetches
       from GitHub.
     - Runs `deploy/deploy-portal-01.sh <sha>` on the box.
  3. `no-deploy-notice` runs instead of `deploy` when `deploy=false` was
     requested or the dispatch targeted a non-main ref, and posts a warning
     annotation + step summary so a green "nothing shipped" run cannot be
     mistaken for a completed deploy in the Actions run list.

Before PAT-1979, `build-test` lived inside `deploy-portal-01.yml` itself and
ran on every push to main while `deploy` stayed gated on `workflow_dispatch`.
A push therefore built, tested, skipped the deploy and still reported the
whole run green under the name `deploy-portal-01` - the same shape PAT-1970
fixed in `deploy-api-01.yml`. Splitting the push-triggered checks into their
own honestly-named workflow closes that gap here too.

`deploy/deploy-portal-01.sh` (on the box) deploys **both** services this repo
ships from the one staged checkout, since they share the box and must never
drift apart:

1. `bash deploy/install.sh` (from the staged checkout) - installs/upgrades
   the portal (`main.py`, `:8000`, `app.patched.im`). This is the same
   idempotent installer described in `deploy/RUNBOOK.md`; nothing about how it
   installs changed, only where it reads the source from.
2. `bash deploy/install-scan.sh` - same, for scan (`scan/`, `:8001`,
   `scan.patched.im`), per `deploy/RUNBOOK-scan.md`.
3. Smoke test: `GET /healthz` on `127.0.0.1:8000` and `127.0.0.1:8001`, both
   must return 200.
4. **Last step, only after both smoke tests pass:** write
   `/opt/patched-portal/DEPLOYED_SHA` and `/opt/patched-scan/DEPLOYED_SHA`,
   atomically (temp file + rename), each `root:<service-user>` mode 640 -
   same convention as `/etc/patched-{portal,scan}/env`. Format matches the
   dashboard's PAT-992 `scripts/deploy.sh`:

   ```
   DEPLOYED_SHA=<full 40-char commit sha>
   DEPLOYED_AT=<UTC ISO 8601, e.g. 2026-08-05T12:00:00Z>
   ```

The portal exposes its own `DEPLOYED_SHA` on `GET /healthz` (`deployed_sha` /
`deployed_at` fields, `null` before the first deploy under this tooling has
run). This rides on the existing `/healthz` endpoint rather than a new route:
`main.py`'s invariant, locked in `AGENTS.md`, is that `/healthz` and
`/static/*` are its **only** unauthenticated paths - a `/version` route would
break that. `scan/app.py`'s own `/healthz` already reports its own diagnostic
fields (NVD dataset presence, Turnstile config) the same way; adding
`deployed_sha`/`deployed_at` there too is a natural follow-up but out of scope
here (see Follow-ups).

Before either installer runs, `deploy/deploy-portal-01.sh` takes a hardlink
snapshot of each existing live app directory. If either installer or either
health smoke check fails, it restores both app directories from those
snapshots, restarts both services, and checks both health endpoints again.
`DEPLOYED_SHA` is not updated on this failure path. The script exits
unsuccessfully whether rollback health checks pass or fail; failed rollback
verification requires manual intervention on `example-portal-host`. A first
deployment has no existing directory to snapshot, so that service has no
previous app directory to restore. This describes the implemented rollback
path; it is not evidence of a failure-injection exercise.

The workflow only ships from `main`; dispatches against a tag or another branch
are test-only and do not deploy. To roll back code, restore the earlier source
state on `main` (normally with a revert commit), then manually dispatch the
workflow. Its lock files travel with that source state and pin the dependencies
installed by the rollback.

## One-time bootstrap (historical record; verified 2026-08-05)

The following records what was checked on 2026-08-05. It is a historical
bootstrap checklist, not a statement about current box or repository state.

### 1. Authorise the CI deploy key on example-portal-host

`/root/.ssh/authorized_keys` on `example-portal-host` currently has only Andy's
personal key (`andy@patched.im`). `example-api-host` and `example-prod-host` both
additionally trust the shared CI deploy key:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwNogZ+sDIP6P8ZE6npyNw2eaCbF0u3BVbIJo1p9xqq github-actions-deploy
```

Add the same line to `example-portal-host`'s `authorized_keys` (this is the
public half of the existing org secret `DEPLOY_SSH_KEY` - no new key material
needed, just trust it on this box too):

```bash
ssh root@example-portal-host \
  'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwNogZ+sDIP6P8ZE6npyNw2eaCbF0u3BVbIJo1p9xqq github-actions-deploy" \
   >> /root/.ssh/authorized_keys'
```

### 2. Extend the tailnet ACL: tag:ci -> tag:portal:22

`api-vps-artefacts/tailscale-acl.json` in the **`patched.im`** repo is the
GitOps source of truth (`tailscale-acl-sync.yml` applies it to the live
tailnet on every push to that repo's `main` that touches the file - no manual
console step once merged). Today `tag:portal` admits only admin SSH
(`group:admins`); `tag:ci` has no reachability to it at all, by design (PAT-410:
"Do NOT add `src: [tag:portal]` accept rules" - that's outbound *from*
portal, which stays banned; this is inbound *to* portal, a different
direction).

Add, mirroring the existing `tag:ci -> tag:api:22` grant exactly:

- In the `acls` array, extend the existing CI deploy-SSH rule's `dst` to
  include `"tag:portal:22"`:

  ```json
  {
    "action": "accept",
    "src": ["tag:ci"],
    "dst": ["tag:main:22", "tag:api:22", "tag:portal:22"]
  }
  ```

- In the `ssh` array, add a new block (do not fold this into the existing
  `tag:ci -> [tag:main, tag:api]` block - `tag:portal` only ever authorises
  `root`, no `patched`/`jarvis-worker` users, matching the admin-SSH block
  immediately above it for the same tag):

  ```json
  {
    "action": "accept",
    "src": ["tag:ci"],
    "dst": ["tag:portal"],
    "users": ["root"]
  }
  ```

This is a change to a **different repo** (`patched.im`), outside this ticket's
worktree - needs its own PR there through the normal review pipeline before
`deploy-portal-01.yml`'s `deploy` job can reach the box at all. Suggest it as
a fast-follow ticket to PAT-1151.

### 3. Confirm the org secrets reach this repo

`gh secret list --repo Patched-LTD/portal` returned nothing as of 2026-08-05.
`TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET` and `DEPLOY_SSH_KEY` are org-level
secrets (visible to `patched.im` and `dashboard`'s workflows already);
GitHub org secrets can be scoped to a subset of repos, and this repo's
membership in that scope could not be confirmed without org-admin API access.
Before the first `workflow_dispatch`, confirm (Settings -> Secrets and
variables -> Actions, at the **organization** level, for a repo admin) that
`Patched-LTD/portal` is included in each secret's repository access list; add
it if not. No new secret values are needed - same three secrets, same values,
as `deploy-api-01.yml` and `deploy.yml` already use.

### 4. Nothing else needed

`/opt/patched-deploy-staging/portal` does not exist yet; the workflow's rsync
step creates it on first run (`rsync` creates missing destination directories
as needed). `/etc/patched-portal/env` and `/etc/patched-scan/env` are already
present and populated on the box (confirmed 2026-08-05, including a real
`PORTAL_ACCESS_AUD`) - this ticket's deploy path does not touch either file,
matching `install.sh`/`install-scan.sh`'s existing "never overwrite the env
file" contract.

## First activation

Once steps 1-3 above are done:

```bash
gh workflow run deploy-portal-01.yml --repo Patched-LTD/portal
gh run watch --repo Patched-LTD/portal
```

Then verify on the box:

```bash
ssh root@example-portal-host 'cat /opt/patched-portal/DEPLOYED_SHA /opt/patched-scan/DEPLOYED_SHA'
curl -s https://app.patched.im/healthz   # {"status":"ok","deployed_sha":"<sha>",...}
```

## Follow-ups (out of scope for this ticket)

- `scan/app.py`'s `/healthz` does not yet surface `deployed_sha`/`deployed_at`
  the way the portal's now does. Same file, same box, same deploy - worth
  adding for parity, but the brief for this ticket only asked for the portal
  side.
- Paired rollback snapshots were added after the original PAT-1151 bootstrap:
  `deploy/deploy-portal-01.sh` snapshots both existing app directories before
  installation and restores them if installation or smoke checks fail. A
  first deployment has no prior directory to restore, and rollback health
  verification can itself fail; see the bounded behavior above.
- The macOS AppleDouble litter (`._*` files) and the stray
  `main.py.bak-pat933-*` in `/opt/patched-portal` are leftovers from the
  pre-CI hand-copy this ticket replaces. Expect the first real run of this
  pipeline to delete them as a side effect: `install.sh`'s `rsync -a --delete`
  removes anything under `/opt/patched-portal` that has no counterpart in the
  pushed source tree, and a plain Linux-to-Linux checkout has neither AppleDouble
  sidecars nor that `.bak` file. Worth confirming after the first deploy rather
  than assuming - not itself a reason to delay bootstrapping this path.
