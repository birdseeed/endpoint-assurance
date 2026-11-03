# Runbook: api-01 deploy pipeline

Automated build-and-ship pipeline for the go-service (`patched-api` +
`patched-extractor`) running on `api-01`. Before this (PAT-1072), merged
fixes to `go-service/` had no automated path to the box — they sat unshipped
until someone ran a manual deploy. This closes that gap, mirroring the
existing `deploy-prod01-backup.yml` pattern (Tailscale, same org secrets).

api-01 has no Go toolchain, so the split is: **CI builds, the box only
receives and swaps pre-built binaries.**

## What runs

Two workflows, split under PAT-1970 so the Actions run list cannot imply a
deploy that did not happen:

- `.github/workflows/api-build.yml` (**`api-build`**) — runs on every push to
  `main` touching `go-service/**`, `deploy/api-01/**` or either workflow file.
  It builds, tests and uploads the artifact. It has no access to a box and
  ships nothing, so a green `api-build` means built, never deployed.
- `.github/workflows/deploy-api-01.yml` (**`deploy-api-01`**) — manual
  `workflow_dispatch` only, with a `concurrency` group so only one deploy runs
  at a time. It calls `api-build.yml` via `workflow_call` for the build (same
  run, so the artifact hand-off is unchanged), then runs the `deploy` job.

Before the split both jobs lived in `deploy-api-01.yml` and it ran on push
too, so a merge produced a green run named `deploy-api-01` that had
deliberately skipped its deploy job. On 2026-09-21 one of those was nearly
recorded as a completed production deploy of a security fix.

**`build-test`** (the `api-build` workflow, run on push and by the deploy
workflow alike):

1. Checks out the repo, sets up Go (version from `go-service/go.mod`).
2. Builds `patched-api` and `patched-extractor` as static Linux/amd64
   binaries (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`).
3. Runs `cd go-service && CGO_ENABLED=0 go test -short ./...`.
4. `shellcheck deploy/api-01/deploy.sh`.
5. Uploads the two binaries as an artifact.

**`deploy`** (`needs: build-test`; carries an `environment: production` block
for provenance, but that does **not** gate anything here — see "Why the gate
is a manual trigger, not an environment" below):

1. Downloads the built binaries.
2. Connects to the tailnet (`tailscale/github-action@v3`, `tag:ci`,
   ephemeral — the runner is removed from the tailnet when the job ends).
3. Rsyncs the two binaries, `go-service/migrations/`, and
   `deploy/api-01/deploy.sh` to `/opt/patched-deploy-staging/` on api-01.
4. Runs `deploy/api-01/deploy.sh` on the box over SSH — binaries, migrations,
   `patched-api`/`patched-extractor` restart and smoke test (below).
5. **Preflights and activates the CVE pipeline units** — rsyncs
   `patched-cve-sync.service`/`.timer` and the two install/verify scripts to
   `/opt/patched-cve-systemd-staging/`, runs
   `install-cve-sync-systemd-units.sh` (which itself runs
   `verify-systemd-hardening-floor.sh` against all three units plus the
   already-running `patched-maintenance-facts.service` before touching
   anything), then verifies the result: `/opt/patched-api/CVE_PIPELINE_ACTIVATED`
   exists and names this run's `$GITHUB_SHA`, `patched-cve-sync.timer` is
   enabled and active, and the service's last `Result=` is `success`. Any of
   those failing fails this step — it runs **after** step 4's binary
   swap/smoke test, not in parallel, so a broken API deploy never reaches
   CVE activation.

   The dry-run preflight (`--mode=os-sync --dry-run`) always runs on every
   deploy, and the unit files are always re-installed and re-verified
   (`cmp -s` against the staged source) whether or not they changed. Only the
   proof-of-activation step — starting `patched-cve-sync.service` for real,
   which is a full NVD resync (~378k records, 20-75 minutes) — is
   conditional (PAT-1995):

   - **Skipped** (fast path) only when *all* of: the unit files installed
     this run are byte-identical to the ones the activation receipt last
     recorded (SHA-256 comparison), the receipt exists and both its unit
     hashes parse unambiguously, and `patched-cve-sync.service`'s `Result=`
     was already `success` *before* this deploy touched anything. The
     receipt is still rewritten (new `DEPLOYED_SHA`, same unit hashes) with
     `ACTIVATION_RUN=skipped-units-unchanged`, and the timer is still
     enabled and started. A one-line log entry states the skip and why.
   - **Full run** (blocking, as before) on first activation, any unit file
     change, a missing/unreadable/malformed receipt, or a prior `Result`
     that was not `success`. Any doubt runs the full activation — the
     conditions above are the only way to skip it. The receipt records
     `ACTIVATION_RUN=full`.
   - `PATCHED_CVE_FORCE_FULL_ACTIVATION=1` (env var to the install script)
     forces the full run regardless of the above, for a deploy where you
     want the resync to happen even though nothing changed.

   The receipt/timer/`Result` checks the workflow runs afterward pass on
   both paths: `DEPLOYED_SHA` and the timer's enabled/active state are set
   every run, and `Result=success` on the skip path is simply the value
   already proven by the run this path chose not to repeat.
6. Deploys Prometheus alerting rules (`deploy-prometheus-rules.sh` —
   `promtool check rules`, backup, atomic install, reload verified via
   `systemctl reload prometheus`, PAT-1423).
7. Deploys the maintenance-facts emitter (PAT-1436).

Steps 5-7 run strictly after step 4 and each verifies its own result before
the next step starts; a failure at any step stops the run there rather than
silently continuing past it.

`deploy/api-01/deploy.sh` (root, on api-01):

1. Applies any pending migrations `>= 0056`, in version order, that are not
   already in `schema_migrations` — sourcing `/etc/patched-api/env` for
   `DATABASE_URL` (never printed) and running each with
   `psql -v ON_ERROR_STOP=1`. Migrations `<= 0055` are grandfathered
   (duplicate version numbers; some, e.g. `0053`, never recorded a
   `schema_migrations` row) and are deliberately never re-considered — any
   live DB is long past them. See `go-service/migrations/README.md`.
2. Backs up the current binaries to `*.bak-<UTC timestamp>`.
3. Swaps in the new binaries (`chown patched:patched`, `chmod 0755`, atomic
   `mv -f` into place).
4. Restarts `patched-api.service` and `patched-extractor.service`.
5. Smoke-tests: both units `systemctl is-active`, `GET 127.0.0.1:8080/health`
   returns 200 (see below), and `SELECT to_regclass('device_agent_health')`
   is non-null (proves migration `0090_agent_health.sql` is applied).
6. **On any smoke-test failure:** restores the `.bak-<timestamp>` binaries,
   restarts both services, and exits non-zero. Migrations are **not**
   rolled back — they are additive/forward-only
   (see `go-service/migrations/README.md`), so a migration applied during a
   binary rollback is safe to leave in place.
7. On success, removes the staging directory.

### Health endpoint used for the smoke test

`GET /health` on the public router, `go-service/cmd/patched-api/main.go:325`
(handler `healthHandler`, `main.go:668`) — served on `127.0.0.1:8080`,
requires no auth or DB access, returns
`{"status":"ok","version":"<version>"}` with HTTP 200. `patched-extractor`
has no HTTP surface (it is a DB-polling worker,
`go-service/cmd/patched-extractor/main.go`), so its health is checked via
`systemctl is-active` plus the fact it survives the 5s post-restart wait
before the smoke test runs.

## How to trigger

`api-build` runs automatically on any push to `main` touching `go-service/**`,
`deploy/api-01/**`, or either workflow file — so every merge is validated.
`deploy-api-01` does **not** run on push at all; it runs **only** on a manual
`workflow_dispatch`:

- Actions tab → *deploy-api-01* → **Run workflow**, or
- `gh workflow run deploy-api-01.yml --repo Patched-LTD/patched.im`

That deliberate manual trigger IS the Andy-gate (see note below).

A dispatch still does not guarantee a deploy: `-f deploy=false`, and any
`--ref` other than `main`, both run the build and stop. Those runs are green
on purpose, and they title themselves `deploy-api-01: BUILD ONLY, nothing
shipped (<ref>)` in the run list and raise a warning on the run page saying
so. A run that actually shipped reads `deploy-api-01: SHIPPING to
example-api-host (main)`. Read the title, and confirm the box from
`/opt/patched-api/DEPLOYED_BINARIES` regardless. The first
such run doubles as the api-01 catch-up: it ships HEAD and applies migration
`0090`, unblocking PAT-995 / 997 / 1003 / 1026 / 1064.

## Why the gate is a manual trigger, not an environment

This repo is **private on a GitHub Team plan**, where `environment`
required-reviewer protection is unavailable (Enterprise / public-repo only —
the same limitation that makes the branch rulesets non-enforcing here). An
`environment: production` block is kept on the deploy job for provenance and so
the gate upgrades automatically if the org ever moves to a plan that enforces
it, but today it does not gate on its own. The enforceable gate is
`if: github.event_name == 'workflow_dispatch'` — the box is only ever touched
by a deliberate manual run.

## Infra prerequisites (done in PAT-1072)

1. **SSH key.** `DEPLOY_SSH_KEY` public key is in `/root/.ssh/authorized_keys`
   on api-01 (copied from prod-01, which already had it).
2. **Tailscale ACL.** `tag:ci` is granted SSH + reachability to api-01
   (`tag:api`) in `api-vps-artefacts/tailscale-acl.json` — both the
   network-reachability `acls` rule (`tag:ci` → `tag:api:22`) and the `ssh`
   block's root grant. Applied to the live tailnet by `tailscale-acl-sync.yml`.

Until 1 and 2 are done, `build-test` passes but `deploy` fails at the
Tailscale/SSH step. Without 3, the deploy job is not Andy-gated.

## Rollback (manual, if ever needed outside the automated path)

This is the procedure the PAT-1892 drill exercised on 2026-09-22. Each deploy
backs up the release it replaces as one **set** in
`/root/patched-deploy-backups/`, keeping the newest `MAX_BACKUPS=5` sets:

| File | Restores to |
| --- | --- |
| `patched-api.bak-<TS>` | `/opt/patched-api/bin/patched-api` |
| `patched-extractor.bak-<TS>` | `/opt/patched-extractor/bin/patched-extractor` (not under `/opt/patched-api`) |
| `patched-cve-sync.bak-<TS>` | `/opt/patched-api/bin/patched-cve-sync` |
| `DEPLOYED_BINARIES.bak-<TS>` | `/opt/patched-api/DEPLOYED_BINARIES` |
| `ROLLBACK_SHA256-<TS>` | digest of the four files above, used to verify them |

Do not use `.bak*` files found anywhere else. Older hand-made copies under
`/opt/patched-api/bin/` predate this pipeline (PAT-2027).

1. Choose the set: `grep -H DEPLOYED_SHA /root/patched-deploy-backups/DEPLOYED_BINARIES.bak-*`
   names the commit each set was, and its `MIGRATION_HEAD` line names the schema it
   expects.
2. Verify it: `cd /root/patched-deploy-backups && sha256sum -c ROLLBACK_SHA256-<TS>`.
   Stop if any line is not `OK`.
3. Confirm schema compatibility: the set's `MIGRATION_HEAD` must equal
   `SELECT max(version) FROM schema_migrations`. A newer live schema is fine only
   if every migration since is additive (they are forward-only by design); never run
   a `_rollback.sql` as part of a binary rollback.
4. Copy the live set aside first (`cp -a` the three binaries and the receipt into a
   new `0700` directory under `/root/patched-deploy-backups/`).
5. Swap each file atomically, preserving owner and mode: `cp` the backup to
   `<live path>.new`, `chown`/`chmod` to match the live file, then `mv -f` over it.
   Restore the receipt the same way so it keeps describing what is running.
6. `systemctl restart patched-api patched-extractor` (cve-sync is a timer-driven
   oneshot and picks the binary up on its next run).
7. Verify: `sha256sum` of the three live binaries equals the restored receipt, both
   units `is-active`, `curl -s 127.0.0.1:8080/health` returns 200, and
   `SELECT to_regclass('device_agent_health')` is non-null.

Deploy forward again through the normal pipeline (`gh workflow run
deploy-api-01.yml --ref main -f deploy=true`), not by hand.

Migrations: forward only. Use the matching `NNNN_..._rollback.sql` under
`go-service/migrations/` only if a migration itself genuinely needs reversing;
the deploy script never does this automatically.
