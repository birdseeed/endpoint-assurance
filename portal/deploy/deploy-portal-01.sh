#!/usr/bin/env bash
# deploy-portal-01.sh - runs ON patched-portal-01 (root). Invoked over SSH by
# .github/workflows/deploy-portal-01.yml, after that workflow's rsync step has
# already staged a fresh checkout at $DEPLOY_STAGING_DIR (default
# /opt/patched-deploy-staging/portal). PAT-1151: this box previously had no
# deploy path at all - /opt/patched-portal was hand-copied out of a working
# tree, never rsynced by tooling.
#
# This repo ships TWO independent services that both live on this box (see
# AGENTS.md "Two services in this repo"): portal (main.py, :8000,
# app.patched.im) and scan (scan/, :8001, scan.patched.im). They are deployed
# together, from the same commit, in one run, so they never drift apart.
#
# Deliberately reuses the existing idempotent installers rather than
# reimplementing their swap-in-place logic: deploy/install.sh and
# deploy/install-scan.sh already do "rsync -a --delete the checkout into the
# live app dir, then restart the unit", are safe to re-run, and are the
# documented upgrade path in deploy/RUNBOOK.md / deploy/RUNBOOK-scan.md. This
# script just points them at the freshly staged source instead of a manual
# `git pull` checkout - the live app dirs (/opt/patched-portal,
# /opt/patched-scan) and everything else about how they install are
# unchanged.
#
# Push-to-box only (PAT-617): this script never fetches from GitHub. Its one
# input from CI is the staged files (already on disk) plus the commit SHA
# passed as $1 - it has no other way to learn what was deployed, and
# deliberately does not run `git` on the box to find out.
#
# ROLLBACK (PAT-1176): install.sh / install-scan.sh rsync --delete straight
# into the live app dirs with no backup of their own, so a smoke-test failure
# used to leave the box on broken freshly-installed code with no way back.
# Before either installer runs, this script takes a cheap hardlink snapshot of
# each live app dir (`cp -al DIR DIR.rollback.$$` - near-instant and
# space-cheap even with the venv present, since unchanged files just gain a
# link and only files the installer actually rewrites fork a second inode).
# If either installer or the smoke test then fails, both app dirs are
# restored from their snapshots, the services are restarted, health is
# reverified, and DEPLOYED_SHA is left untouched - so a failed deploy always
# ends on the last known-good code actually running, matching
# deploy-api-01.yml / dashboard deploy.sh. First deploy (no existing app dir
# yet) has nothing to snapshot and nothing to roll back to; that case is
# detected and skipped cleanly rather than treated as an error.
#
# LAST step: write DEPLOYED_SHA next to each app, atomically, matching the
# prod-01 / api-01 convention (PAT-992) - and only after both installers and
# both smoke tests have succeeded, so DEPLOYED_SHA never asserts a commit
# that is not actually serving traffic. Rollback snapshots are removed only
# after that succeeds too.
set -euo pipefail

STAGING_DIR="${DEPLOY_STAGING_DIR:-/opt/patched-deploy-staging/portal}"
SHA="${1:?usage: deploy-portal-01.sh <git-sha>}"

PORTAL_DIR=/opt/patched-portal
SCAN_DIR=/opt/patched-scan
PORTAL_SNAPSHOT="${PORTAL_DIR}.rollback.$$"
SCAN_SNAPSHOT="${SCAN_DIR}.rollback.$$"

log() {
  printf '\n== %s ==\n' "$*"
}

# ---------------------------------------------------------------------------
# wait_healthz NAME URL - poll /healthz with a bounded wait rather than a
# single shot. install-scan.sh restarts patched-scan immediately before this
# runs and uvicorn needs a moment to bind its port, so a one-shot curl races
# the service coming up (PAT-1151: the first deploy aborted here with scan
# returning 000 ~40ms after restart; portal only passed by luck, having been
# up ~30s while scan installed). Same bounded-retry shape as the dashboard's
# deploy smoke test. Reused as-is (PAT-1176) to reverify health after a
# rollback restore.
wait_healthz() {
  local name="$1" url="$2" i status=000
  for i in $(seq 1 30); do
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" || echo 000)"
    if [[ "$status" == "200" ]]; then
      echo "$name /healthz 200 (after ${i}s)"
      return 0
    fi
    sleep 1
  done
  echo "$name /healthz did not return 200 within 30s (last: $status)" >&2
  return 1
}

# ---------------------------------------------------------------------------
# snapshot_dir DIR SNAPSHOT NAME - hardlink snapshot of a live app dir before
# the installer rsync --delete's into it. Skips cleanly (no snapshot, no
# rollback possible) when DIR doesn't exist yet - first deploy on this box.
# Also clears any stale snapshot left behind by a prior run that crashed
# before its own cleanup ran (different $$, hence the glob rather than an
# exact match) so leftovers never pile up or get restored by mistake.
snapshot_dir() {
  local dir="$1" snapshot="$2" name="$3"
  rm -rf "${dir}".rollback.*
  if [[ ! -d "$dir" ]]; then
    echo "$name: no existing app dir at $dir - first deploy, nothing to snapshot"
    return 0
  fi
  cp -al "$dir" "$snapshot"
  echo "$name: snapshotted $dir -> $snapshot"
}

# restore_dir DIR SNAPSHOT NAME - swap the broken freshly-installed dir back
# out for the last known-good snapshot. No-op (nothing to restore) if this
# was a first deploy and there is no snapshot to restore from.
restore_dir() {
  local dir="$1" snapshot="$2" name="$3"
  if [[ ! -d "$snapshot" ]]; then
    echo "$name: no snapshot at $snapshot (first deploy) - cannot roll back, box left as installed by the failed run" >&2
    return 0
  fi
  rm -rf "$dir"
  mv "$snapshot" "$dir"
  echo "$name: restored $dir from snapshot"
}

# cleanup_snapshot SNAPSHOT NAME - drop a snapshot once it's no longer needed
# (deploy succeeded). restore_dir already consumes a snapshot via mv on the
# rollback path, so this only ever has real work to do on the success path.
cleanup_snapshot() {
  local snapshot="$1" name="$2"
  if [[ -d "$snapshot" ]]; then
    rm -rf "$snapshot"
    echo "$name: removed snapshot $snapshot"
  fi
}

# write_deployed_sha TARGET GROUP - atomic write (temp file + rename), owned
# root:GROUP mode 640 so the service user (portal/scan, same convention as
# /etc/patched-{portal,scan}/env) can read it but nothing else on the box can.
write_deployed_sha() {
  local target="$1" group="$2" tmp deployed_at
  deployed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  tmp="$(mktemp "${target}.tmp.XXXXXX")"
  {
    printf 'DEPLOYED_SHA=%s\n' "$SHA"
    printf 'DEPLOYED_AT=%s\n' "$deployed_at"
  } > "$tmp"
  chown "root:${group}" "$tmp"
  chmod 640 "$tmp"
  mv -f "$tmp" "$target"
}

# rollback_and_exit - the single failure path for both installer errors and a
# failed smoke test. Restores both app dirs (independently; either may be a
# no-op first deploy), restarts both services, reverifies health, logs
# clearly, and exits non-zero without ever touching DEPLOYED_SHA - so it keeps
# pointing at whatever last actually passed a smoke test.
rollback_and_exit() {
  log "Deploy failed - rolling back to last known-good code"
  restore_dir "$PORTAL_DIR" "$PORTAL_SNAPSHOT" portal
  restore_dir "$SCAN_DIR" "$SCAN_SNAPSHOT" scan

  if ! systemctl restart patched-portal patched-scan; then
    echo "WARNING: systemctl restart failed during rollback - continuing to health verification" >&2
  fi

  local rollback_ok=0
  wait_healthz portal http://127.0.0.1:8000/healthz || rollback_ok=1
  wait_healthz scan   http://127.0.0.1:8001/healthz || rollback_ok=1
  if [[ "$rollback_ok" -eq 0 ]]; then
    echo "Rollback verified: both services healthy again on the previous code"
  else
    echo "ROLLBACK VERIFICATION FAILED - one or both services are not healthy after restore. Manual intervention needed on patched-portal-01." >&2
  fi

  echo "DEPLOYED_SHA left unchanged; deploy of $SHA did NOT go live." >&2
  exit 1
}

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

if [[ ! -f "$STAGING_DIR/deploy/install.sh" || ! -f "$STAGING_DIR/deploy/install-scan.sh" ]]; then
  echo "no staged checkout at $STAGING_DIR (expected deploy/install.sh + deploy/install-scan.sh)" >&2
  exit 1
fi

log "Snapshotting current app dirs for rollback"
snapshot_dir "$PORTAL_DIR" "$PORTAL_SNAPSHOT" portal
snapshot_dir "$SCAN_DIR" "$SCAN_SNAPSHOT" scan

log "Installing/upgrading portal (main.py, :8000, app.patched.im)"
bash "$STAGING_DIR/deploy/install.sh" || rollback_and_exit

log "Installing/upgrading scan (scan/, :8001, scan.patched.im)"
bash "$STAGING_DIR/deploy/install-scan.sh" || rollback_and_exit

log "Smoke test"
wait_healthz portal http://127.0.0.1:8000/healthz || rollback_and_exit
wait_healthz scan   http://127.0.0.1:8001/healthz || rollback_and_exit
echo "portal and scan /healthz both returned 200"

log "Recording deployed SHA (last step)"
write_deployed_sha /opt/patched-portal/DEPLOYED_SHA portal
write_deployed_sha /opt/patched-scan/DEPLOYED_SHA scan

log "Removing rollback snapshots (deploy succeeded)"
cleanup_snapshot "$PORTAL_SNAPSHOT" portal
cleanup_snapshot "$SCAN_SNAPSHOT" scan

echo "Deployed $SHA"
