#!/bin/bash
# Restic backup: snapshot the scan service's SQLite DB + uploads/ + reports/,
# plus the portal and scan env files and TLS origin certs, and push to
# Cloudflare R2. Run as root on patched-portal-01. Restic env vars injected by
# systemd EnvironmentFile; do NOT source anything here — the file contains
# secrets.
#
# This one leg covers BOTH services that live on patched-portal-01 (portal
# repo AGENTS.md "Two services in this repo"):
#   - portal (app.patched.im)  — stateless, no DB; only its env file + TLS
#     cert need protecting.
#   - scan (scan.patched.im)   — the public CVE-scan / Intune-upload funnel;
#     holds real state (public_scans + public_uploads rows, uploaded files,
#     generated reports) under /var/lib/patched-scan.
#
# Uses sqlite3 .backup to take a consistent snapshot before upload so the live
# scan.db file is never read mid-write (same approach as prod-01's
# prod-backup.sh). nvd.db is deliberately excluded: it is a downloaded
# reference dataset (scan/bin/refresh-nvd.py), not user data, and is
# regenerated on a fresh box rather than restored.
set -euo pipefail

STAMP=$(date +%Y%m%d_%H%M%S)
STATE_DIR=/var/lib/patched-scan
# PAT-994: scan.db moved into its own sub-directory (nothing else in it) so
# the backup unit's ReadWritePaths can be narrowed to exactly that, matching
# SCAN_DB_DIR in scan/shared.py.
DB_SRC="${SCAN_DB_DIR:-${STATE_DIR}/db}/scan.db"
DB_SNAP="/tmp/scan-${STAMP}.db"
UPLOADS_DIR="${STATE_DIR}/uploads"
REPORTS_DIR="${STATE_DIR}/reports"

# Health heartbeat for the dashboard Service Health strip (PAT-387) — written
# locally first, always, then (PAT-954) shipped over HTTPS to api-01's public
# POST /v1/backup-health. Unlike prod-01, patched-portal-01 has ZERO outbound
# tailnet grants by design (tag:portal, PAT-410 — tailscale-acl.json says
# explicitly "Do NOT add src: tag:portal accept rules"), so this cannot use
# prod-01's scp-over-Tailscale channel. It goes out over portal-01's existing,
# already-allowed outbound 443 instead — the same path the portal/scan apps
# already use for PLATFORM_BASE_URL (portal repo deploy/env.template) — so no
# tailnet or ufw change is needed here. See BACKUP_DR.md "Dashboard backup
# health monitoring" for the full story.
HEALTH_DIR="${PATCHED_BACKUP_HEALTH_DIR:-/srv/backup/health}"
HEALTH_FILE="${HEALTH_DIR}/portal-r2.json"
run_ok=fail

# Reuses PLATFORM_BASE_URL rather than inventing a second base-URL variable —
# same name, same meaning ("base URL of the patched.im platform API"), as the
# portal/scan services already use (portal repo upstream.py / env.template).
# Defaults to the production platform URL exactly like upstream.py's own
# default, so backup.env doesn't strictly need to set it.
PLATFORM_BASE_URL="${PLATFORM_BASE_URL:-https://api.patched.im}"

write_health() {
  mkdir -p "$HEALTH_DIR" || return 0
  local now
  now=$(date -u +%FT%TZ)
  if [ "$run_ok" = ok ]; then
    printf '{"job":"portal-r2","label":"Portal+scan → R2 (portal-01)","status":"ok","last_success_at":"%s","detail":"snapshot %s"}\n' \
      "$now" "$STAMP" > "$HEALTH_FILE" || true
  else
    local last=null
    if [ -f "$HEALTH_FILE" ]; then
      last=$(grep -o '"last_success_at":"[^"]*"' "$HEALTH_FILE" | head -1 | cut -d'"' -f4 || true)
      if [ -n "$last" ]; then last="\"$last\""; else last=null; fi
    fi
    printf '{"job":"portal-r2","label":"Portal+scan → R2 (portal-01)","status":"fail","last_success_at":%s,"detail":"run %s failed"}\n' \
      "$last" "$STAMP" > "$HEALTH_FILE" || true
  fi
  # The local file above is the primary record and is already written,
  # unconditionally, regardless of what happens below. ship_heartbeat is
  # purely best-effort on top of it and must never be able to change this
  # script's exit status (see ship_heartbeat's own guards).
  ship_heartbeat
}

# ship_heartbeat POSTs the heartbeat file write_health just wrote, byte for
# byte, to api-01's POST /v1/backup-health (PAT-954) — so the local file and
# what api-01 stores can never diverge. Auth is BACKUP_HEARTBEAT_TOKEN, a
# dedicated credential (NOT ADMIN_API_TOKEN, NOT a tenant bearer token — see
# go-service/internal/handlers/backup_health_ingest.go) that must be
# provisioned separately in backup.env (restic.env.template).
#
# Until Andy provisions BACKUP_HEARTBEAT_TOKEN on this box, this is a
# silent-but-logged no-op: the backup itself, and the local heartbeat file
# above, are completely unaffected either way — only dashboard visibility is
# missing in the meantime. Every exit path returns 0 and nothing here runs
# under anything that could abort the script (called from the EXIT trap,
# after the primary work is already done).
ship_heartbeat() {
  if [ -z "${BACKUP_HEARTBEAT_TOKEN:-}" ] || [ -z "${PLATFORM_BASE_URL:-}" ]; then
    echo "patched-portal-backup: heartbeat POST skipped (BACKUP_HEARTBEAT_TOKEN/PLATFORM_BASE_URL not configured) — local file only"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "patched-portal-backup: heartbeat POST skipped (curl not installed) — local file only"
    return 0
  fi
  if [ ! -s "$HEALTH_FILE" ]; then
    echo "patched-portal-backup: heartbeat POST skipped (local heartbeat file missing/empty) — nothing to send"
    return 0
  fi

  local http_code
  if http_code=$(curl --silent --show-error --fail --max-time 15 --retry 2 \
      --output /dev/null --write-out '%{http_code}' \
      --request POST \
      --header "Authorization: Bearer ${BACKUP_HEARTBEAT_TOKEN}" \
      --header "Content-Type: application/json" \
      --data-binary @"$HEALTH_FILE" \
      "${PLATFORM_BASE_URL%/}/v1/backup-health"); then
    echo "patched-portal-backup: heartbeat POSTed to api-01 (HTTP ${http_code})"
  else
    echo "patched-portal-backup: heartbeat POST failed (HTTP ${http_code:-unknown}) — local file at $HEALTH_FILE remains authoritative"
  fi
  return 0
}

cleanup() {
  rm -f "$DB_SNAP"
  write_health
}
trap cleanup EXIT

echo "patched-portal-backup: starting backup ${STAMP}"

echo "patched-portal-backup: snapshotting scan.db"
sqlite3 "$DB_SRC" ".backup ${DB_SNAP}"

echo "patched-portal-backup: backing up scan state (db snapshot + uploads/ + reports/)"
# uploads/ and reports/ may be empty on a fresh install — restic handles an
# empty dir gracefully.
restic backup \
  "$DB_SNAP" \
  "$UPLOADS_DIR" \
  "$REPORTS_DIR" \
  --tag "data" \
  --tag "$(date +%Y-%m)"

# Config snapshot — files not in git that would be painful to lose after a
# box rebuild: both services' env files and both TLS origin certs.
echo "patched-portal-backup: backing up config files"
restic backup \
  /etc/patched-portal/env \
  /etc/patched-scan/env \
  /etc/ssl/app.patched.im.pem \
  /etc/ssl/app.patched.im.key \
  /etc/ssl/scan.patched.im.pem \
  /etc/ssl/scan.patched.im.key \
  --tag "config" \
  --tag "$(date +%Y-%m)"

echo "patched-portal-backup: applying retention policy"
restic forget \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 3 \
  --prune

echo "patched-portal-backup: spot-check integrity"
restic check --read-data-subset=1/10

run_ok=ok
echo "patched-portal-backup: done"
