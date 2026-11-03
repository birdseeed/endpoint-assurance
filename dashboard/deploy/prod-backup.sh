#!/bin/bash
# Restic backup: snapshot dashboard.db + reports/ and push to Cloudflare R2.
# Run as root on patched-prod-01. Restic env vars injected by systemd EnvironmentFile;
# do NOT source anything here — the file contains secrets.
#
# Uses sqlite3 .backup to take a consistent snapshot before upload so the live
# .db file is never read mid-write.
set -euo pipefail

STAMP=$(date +%Y%m%d_%H%M%S)
STARTED_AT=$(date -u +%FT%TZ)
# PAT-994: dashboard.db lives in its own state dir now, not the app code dir
# — matches DASHBOARD_DB_PATH, the same env var main.py/shared.py already
# read (dashboard.env sets it; unset means shared.py's old BASE/dashboard.db
# default, so a box that hasn't migrated yet keeps working unchanged).
DB_SRC="${DASHBOARD_DB_PATH:-/var/lib/patched-dashboard/dashboard.db}"
DB_SNAP=/tmp/dashboard-${STAMP}.db
REPORTS_DIR=/opt/patched-dashboard/reports

# Health heartbeat for the dashboard Service Health strip (PAT-387).
# Arms a fail marker via EXIT trap; only overwrites with ok after a clean run.
HEALTH_DIR="${PATCHED_BACKUP_HEALTH_DIR:-/srv/backup/health}"
HEALTH_FILE="${HEALTH_DIR}/prod-r2.json"
run_ok=fail

# PAT-993: capture what actually failed so the automations-record POST below
# (report_automation_run) can carry a useful error_msg — same approach as
# api-01's backup.sh.
LAST_ERR=""
on_error() {
  LAST_ERR="command '${BASH_COMMAND}' failed (exit $?) at line ${LINENO}"
}
trap on_error ERR

# PAT-993 — automations-tab instrumentation (knownJobs entry: prod01_backup).
# prod-01 is tag:main on the tailnet, which already has an open data-plane
# grant to tag:api:8443 (tailscale-acl.json "Main -> API: admin/control
# plane"), the same grant the dashboard's own proxy to api-01 uses — so this
# needs no new ACL rule. --insecure matches that existing proxy's own
# documented posture (tailscale-acl.json: "HTTPS, verify=False — WireGuard
# handles transport"): the tailnet tunnel is the real trust boundary here,
# not the TLS chain. ADMIN_API_TOKEN is api-01's own admin token, provisioned
# into this box's backup.env (systemd EnvironmentFile) — see
# backup.env.template — not sourced/grepped from any file directly.
AUTOMATIONS_RECORD_URL="https://patched-api-01.example-tailnet.ts.net:8443/admin/automations/prod01_backup/record"

# json_escape wraps $1 as a double-quoted JSON string, escaping backslashes,
# quotes, and the control chars our own log/error text can plausibly contain.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '"%s"' "$s"
}

# report_run POSTs one completed-run record. Best-effort only: a curl
# failure here must never fail the backup job itself — every path returns 0.
report_run() {
  local status="$1" output="$2" error_msg="$3"
  local finished_at payload http_code

  if [ -z "${ADMIN_API_TOKEN:-}" ]; then
    echo "patched-prod-backup: automations record POST skipped (ADMIN_API_TOKEN not set in backup.env) — backup result unaffected"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "patched-prod-backup: automations record POST skipped (curl not installed) — backup result unaffected"
    return 0
  fi

  finished_at=$(date -u +%FT%TZ)
  payload=$(printf '{"started_at":"%s","finished_at":"%s","status":"%s","output":%s,"error_msg":%s}' \
    "$STARTED_AT" "$finished_at" "$status" "$(json_escape "$output")" "$(json_escape "$error_msg")")

  if http_code=$(curl --silent --show-error --fail --insecure --max-time 10 --retry 1 \
      --output /dev/null --write-out '%{http_code}' \
      --request POST \
      --header "Authorization: Bearer ${ADMIN_API_TOKEN}" \
      --header "Content-Type: application/json" \
      --data "$payload" \
      "$AUTOMATIONS_RECORD_URL"); then
    echo "patched-prod-backup: automations record POSTed (HTTP ${http_code})"
  else
    echo "patched-prod-backup: automations record POST failed (HTTP ${http_code:-unknown}) — backup result unaffected"
  fi
  return 0
}

# report_automation_run translates the same run_ok/LAST_ERR state
# write_health already computed into the automations-record contract
# (started_at/finished_at/status/output/error_msg — see
# go-service/internal/handlers/automations.go AutomationRecordHandler).
report_automation_run() {
  local status output error_msg
  if [ "$run_ok" = ok ]; then
    status="success"
    output="snapshot ${STAMP}"
    error_msg=""
  else
    status="failed"
    output=""
    if [ -n "$LAST_ERR" ]; then
      error_msg="$LAST_ERR"
    else
      error_msg="backup failed (see journalctl -u patched-prod-backup)"
    fi
  fi
  report_run "$status" "$output" "$error_msg"
}

write_health() {
  mkdir -p "$HEALTH_DIR" || return 0
  local now
  now=$(date -u +%FT%TZ)
  if [ "$run_ok" = ok ]; then
    printf '{"job":"prod-r2","label":"Dashboard → R2 (prod-01)","status":"ok","last_success_at":"%s","detail":"snapshot %s"}\n' \
      "$now" "$STAMP" > "$HEALTH_FILE" || true
  else
    local last=null
    if [ -f "$HEALTH_FILE" ]; then
      last=$(grep -o '"last_success_at":"[^"]*"' "$HEALTH_FILE" | head -1 | cut -d'"' -f4 || true)
      if [ -n "$last" ]; then last="\"$last\""; else last=null; fi
    fi
    printf '{"job":"prod-r2","label":"Dashboard → R2 (prod-01)","status":"fail","last_success_at":%s,"detail":"run %s failed"}\n' \
      "$last" "$STAMP" > "$HEALTH_FILE" || true
  fi

  # Ship heartbeat to api-01 so its /admin/health endpoint picks it up.
  # Requires an SSH key from prod-01 authorised in api-01's authorized_keys.
  # Set API01_TAILSCALE_IP in backup.env to enable; leave blank to skip.
  # sshd-backup on api-01 listens on port 2222 (OpenSSH, not Tailscale SSH).
  # Key: /root/.ssh/id_prod_backup; forced command restricts to scp into /srv/backup/health/.
  # -O forces legacy scp protocol to match the forced-command "scp -t" on the server.
  if [ -n "${API01_TAILSCALE_IP:-}" ]; then
    scp -q -O -i /root/.ssh/id_prod_backup -P 2222 -o BatchMode=yes -o ConnectTimeout=10 \
      "$HEALTH_FILE" "root@${API01_TAILSCALE_IP}:${HEALTH_DIR}/prod-r2.json" 2>/dev/null || true
  fi

  # PAT-993: extend this same trap machinery to also record the run in
  # api-01's automations tab, rather than adding a second, separate
  # reporting path.
  report_automation_run
}

cleanup() {
  rm -f "$DB_SNAP"
  write_health
}
trap cleanup EXIT

echo "patched-prod-backup: starting backup ${STAMP}"

# Consistent SQLite snapshot — never reads the live .db while the app may be writing.
echo "patched-prod-backup: snapshotting dashboard.db"
sqlite3 "$DB_SRC" ".backup ${DB_SNAP}"

echo "patched-prod-backup: backing up database snapshot"
restic backup \
  "$DB_SNAP" \
  --tag "dashboard-db" \
  --tag "$(date +%Y-%m)"

echo "patched-prod-backup: backing up reports/"
# reports/ may be empty on a fresh install — restic handles an empty dir gracefully.
restic backup \
  "$REPORTS_DIR" \
  --tag "dashboard-reports" \
  --tag "$(date +%Y-%m)"

# Config snapshot — files not in git that would be painful to lose after a box rebuild.
echo "patched-prod-backup: backing up config files"
restic backup \
  /etc/patched-dashboard/dashboard.env \
  /etc/patched-dashboard/backup.env \
  /etc/ssl/patched.im.pem \
  /etc/ssl/patched.im.key \
  /etc/caddy/Caddyfile \
  --tag "config" \
  --tag "$(date +%Y-%m)"

echo "patched-prod-backup: applying retention policy"
restic forget \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 3 \
  --prune

echo "patched-prod-backup: spot-check integrity"
restic check --read-data-subset=1/10

run_ok=ok
echo "patched-prod-backup: done"
