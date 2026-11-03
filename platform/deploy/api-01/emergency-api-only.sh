#!/usr/bin/env bash
# Break-glass API-only deployment. Normal releases must use deploy.sh.
set -Eeuo pipefail

if [[ "$EUID" -eq 0 ]]; then
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  unset BASH_ENV ENV CDPATH
  if printenv PATCHED_EMERGENCY_TEST_MODE >/dev/null 2>&1; then
    echo "PATCHED_EMERGENCY_TEST_MODE is forbidden for root invocation" >&2
    exit 1
  fi
  for override_name in PATCHED_EMERGENCY_STAGING_DIR PATCHED_EMERGENCY_API_BIN \
    PATCHED_EMERGENCY_EXTRACTOR_BIN PATCHED_EMERGENCY_CVE_SYNC_BIN \
    PATCHED_EMERGENCY_RECEIPT PATCHED_EMERGENCY_API_ENV_FILE \
    PATCHED_EMERGENCY_SYSTEMCTL; do
    if printenv "$override_name" >/dev/null 2>&1; then
      echo "$override_name is forbidden for root emergency invocation" >&2
      exit 1
    fi
  done
  STAGING_DIR="/opt/patched-emergency-api"
  API_BIN="/opt/patched-api/bin/patched-api"
  EXTRACTOR_BIN="/opt/patched-extractor/bin/patched-extractor"
  CVE_SYNC_BIN="/opt/patched-api/bin/patched-cve-sync"
  RECEIPT="/opt/patched-api/DEPLOYED_BINARIES"
  API_ENV_FILE="/etc/patched-api/env"
  SYSTEMCTL=systemctl
  SMOKE_DELAY=5
  BACKUP_DIR=/root/patched-emergency-api-backups
else
  [[ "${PATCHED_EMERGENCY_TEST_MODE:-}" == "1" ]] || { echo "emergency deploy must run as root" >&2; exit 1; }
  STAGING_DIR="${PATCHED_EMERGENCY_STAGING_DIR:?}"
  API_BIN="${PATCHED_EMERGENCY_API_BIN:?}"
  EXTRACTOR_BIN="${PATCHED_EMERGENCY_EXTRACTOR_BIN:?}"
  CVE_SYNC_BIN="${PATCHED_EMERGENCY_CVE_SYNC_BIN:?}"
  RECEIPT="${PATCHED_EMERGENCY_RECEIPT:?}"
  API_ENV_FILE="${PATCHED_EMERGENCY_API_ENV_FILE:?}"
  SYSTEMCTL="${PATCHED_EMERGENCY_SYSTEMCTL:-systemctl}"
  SMOKE_DELAY=0
  BACKUP_DIR="${PATCHED_EMERGENCY_RECEIPT}.rollback-sources"
fi

EXPECTED_GITHUB_SHA_ARG="${1:-}"
REASON="${2:-}"
MIGRATION_ACK="${3:-}"
[[ "$EXPECTED_GITHUB_SHA_ARG" =~ ^[0-9a-f]{40}$ ]] || { echo "expected GITHUB_SHA argument must be 40 lowercase hex characters" >&2; exit 1; }
if [[ -z "$REASON" || "$REASON" == *$'\n'* || "$REASON" == *$'\r'* || ! "$REASON" =~ ^[[:print:]]+$ ]]; then
  echo "one single-line emergency reason argument is required" >&2
  exit 1
fi

NEW_API_BIN="$STAGING_DIR/patched-api"
MANIFEST_FILE="$STAGING_DIR/BINARY_MANIFEST"
API_BIN_DIR="$(dirname "$API_BIN")"
API_PARENT="$(dirname "$API_BIN_DIR")"
RECEIPT_DIR="$(dirname "$RECEIPT")"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$BACKUP_DIR/patched-api.emergency-bak-${TS}"
RECEIPT_BACKUP="$BACKUP_DIR/DEPLOYED_BINARIES.emergency-bak-${TS}"
BACKUP_DIGEST_FILE="$BACKUP_DIR/ROLLBACK_SHA256-${TS}"
RECEIPT_EXISTED=0
DEPLOY_PHASE=preinstall
EMERGENCY_DIRS=("$API_PARENT" "$API_BIN_DIR" "$RECEIPT_DIR")
PRE_DIR_OWNERS=()
PRE_DIR_MODES=()

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

property_value() {
  local properties="$1" property="$2" remaining line
  remaining="$properties"
  while [[ -n "$remaining" ]]; do
    if [[ "$remaining" == *$'\n'* ]]; then
      line="${remaining%%$'\n'*}"
      remaining="${remaining#*$'\n'}"
    else
      line="$remaining"
      remaining=""
    fi
    if [[ "$line" == "$property="* ]]; then
      printf '%s' "${line#*=}"
      return 0
    fi
  done
  return 1
}

read_database_url() {
  local env_file="$1" line value="" matches=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == DATABASE_URL=* ]] || continue
    matches=$((matches + 1))
    value="${line#DATABASE_URL=}"
  done < "$env_file"
  if [[ "$matches" -ne 1 || -z "$value" ||
        ( "$value" != postgres://* && "$value" != postgresql://* ) ||
        "$value" == *[[:space:]]* ||
        "$value" == *\'* || "$value" == *\"* || "$value" == *'$'* || "$value" == *'`'* ]]; then
    echo "$env_file must contain exactly one absolute postgres:// or postgresql:// DATABASE_URL without whitespace, quoting or shell expansion markers" >&2
    return 1
  fi
  printf '%s' "$value"
}

assert_api_write_contract() {
  local properties user working_directory protect_system write_line write_path
  properties="$("$SYSTEMCTL" show patched-api.service --property=User --property=WorkingDirectory \
    --property=ProtectSystem --property=ReadWritePaths --property=ReadWriteDirectories)" || return 1
  user="$(property_value "$properties" User)" || return 1
  working_directory="$(property_value "$properties" WorkingDirectory)" || return 1
  protect_system="$(property_value "$properties" ProtectSystem)" || return 1
  [[ "$user" == "patched" && "$working_directory" == "/opt/patched-api" && "$protect_system" == "strict" ]] || {
    echo "patched-api.service write contract drifted" >&2; return 1;
  }
  local remaining="$properties"
  while [[ -n "$remaining" ]]; do
    if [[ "$remaining" == *$'\n'* ]]; then
      write_line="${remaining%%$'\n'*}"
      remaining="${remaining#*$'\n'}"
    else
      write_line="$remaining"
      remaining=""
    fi
    [[ "$write_line" == ReadWritePaths=* || "$write_line" == ReadWriteDirectories=* ]] || continue
    for write_path in ${write_line#*=}; do
      [[ "$write_path" != "/opt" && "$write_path" != /opt/* ]] || {
        echo "patched-api.service permits writes under /opt: $write_path" >&2; return 1;
      }
    done
  done
}

for file in "$NEW_API_BIN" "$MANIFEST_FILE" "$API_BIN"; do
  [[ -f "$file" ]] || { echo "missing required file: $file" >&2; exit 1; }
done
[[ "$(stat -c '%U:%G %a' "$STAGING_DIR")" == "root:root 755" ]] || {
  echo "emergency staging must be root:root 0755" >&2
  exit 1
}
[[ "$(stat -c '%U:%G %a' "$NEW_API_BIN")" == "root:root 755" ]] || { echo "staged API must be root:root 0755" >&2; exit 1; }
[[ "$(stat -c '%U:%G %a' "$MANIFEST_FILE")" == "root:root 644" ]] || { echo "staged manifest must be root:root 0644" >&2; exit 1; }

BUILD_SHA="$(sed -n 's/^GITHUB_SHA=//p' "$MANIFEST_FILE")"
MIGRATION_HEAD="$(sed -n 's/^MIGRATION_HEAD=//p' "$MANIFEST_FILE")"
EXPECTED_API_SHA256="$(sed -n 's/^\([0-9a-f]\{64\}\)  patched-api$/\1/p' "$MANIFEST_FILE")"
[[ "$BUILD_SHA" == "$EXPECTED_GITHUB_SHA_ARG" ]] || { echo "manifest GITHUB_SHA does not match explicit expected SHA" >&2; exit 1; }
[[ "$MIGRATION_HEAD" =~ ^[0-9]{4}_[a-z0-9_]+$ ]] || { echo "manifest migration head is invalid" >&2; exit 1; }
[[ "$MIGRATION_ACK" == "migrations-applied=$MIGRATION_HEAD" ]] || { echo "explicit migrations-applied=$MIGRATION_HEAD acknowledgement is required" >&2; exit 1; }
[[ "$EXPECTED_API_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid manifest patched-api hash" >&2; exit 1; }
[[ "$(sha256_file "$NEW_API_BIN")" == "$EXPECTED_API_SHA256" ]] || { echo "staged API hash mismatch" >&2; exit 1; }
assert_api_write_contract || exit 1
DATABASE_URL="$(read_database_url "$API_ENV_FILE")" || exit 1
MIGRATION_PRESENT="$(psql -d "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '$MIGRATION_HEAD')" | tr -d '[:space:]')"
[[ "$MIGRATION_PRESENT" == "t" ]] || { echo "artifact migration head $MIGRATION_HEAD is not applied" >&2; exit 1; }

install -d -o root -g root -m 0700 "$BACKUP_DIR"
cp -a "$API_BIN" "$BACKUP"
if [[ -f "$RECEIPT" ]]; then
  cp -a "$RECEIPT" "$RECEIPT_BACKUP"
  RECEIPT_EXISTED=1
fi
chown root:root "$BACKUP"
chmod 0600 "$BACKUP"
BACKUP_SHA256="$(sha256_file "$BACKUP")"
{
  printf '%s  %s\n' "$BACKUP_SHA256" "$BACKUP"
  if [[ "$RECEIPT_EXISTED" -eq 1 ]]; then
    RECEIPT_BACKUP_SHA256="$(sha256_file "$RECEIPT_BACKUP")"
    printf '%s  %s\n' "$RECEIPT_BACKUP_SHA256" "$RECEIPT_BACKUP"
  fi
} > "$BACKUP_DIGEST_FILE"
chown root:root "$BACKUP_DIGEST_FILE"
chmod 0600 "$BACKUP_DIGEST_FILE"
if [[ "$RECEIPT_EXISTED" -eq 1 ]]; then
  chown root:root "$RECEIPT_BACKUP"
  chmod 0600 "$RECEIPT_BACKUP"
fi
# INVARIANT: this capture must run before ANY chown/chmod of EMERGENCY_DIRS —
# the only one in the normal path is below, at "chown root:root "$API_PARENT"
# ..." — so rollback() restores the true pre-deploy ownership/mode. Do not
# move this loop later, and do not add an earlier chown/chmod of these paths.
for dir in "${EMERGENCY_DIRS[@]}"; do
  dir_state="$(stat -c '%U:%G %a' "$dir")"
  PRE_DIR_OWNERS+=("${dir_state% *}")
  PRE_DIR_MODES+=("${dir_state##* }")
done

rollback() {
  local exit_code="${1:-1}" restore_tmp="${API_BIN}.emergency-rollback-new" rollback_failed=0
  trap - EXIT HUP INT TERM ERR
  set +e
  echo "EMERGENCY API DEPLOY FAILED; restoring $BACKUP" >&2
  rm -f "${API_BIN}.new" "${RECEIPT}.new" "$restore_tmp"
  if [[ "$(stat -c '%U:%G %a' "$BACKUP_DIR")" != "root:root 700" ||
        "$(stat -c '%U:%G %a' "$BACKUP")" != "root:root 600" ||
        "$(stat -c '%U:%G %a' "$BACKUP_DIGEST_FILE")" != "root:root 600" ||
        "$(sha256_file "$BACKUP")" != "$BACKUP_SHA256" ]] ||
     ! grep -qxF "$BACKUP_SHA256  $BACKUP" "$BACKUP_DIGEST_FILE"; then
    echo "EMERGENCY ROLLBACK ERROR: rollback source or digest record is untrusted" >&2
    rollback_failed=1
  elif ! cp -a "$BACKUP" "$restore_tmp" || ! mv -f "$restore_tmp" "$API_BIN"; then
    rollback_failed=1
  fi
  if [[ "$rollback_failed" -eq 0 ]]; then
    chown root:root "$API_BIN" || rollback_failed=1
    chmod 0755 "$API_BIN" || rollback_failed=1
  fi
  if [[ "$rollback_failed" -ne 0 ]]; then
    rm -f "$RECEIPT"
  elif [[ "$RECEIPT_EXISTED" -eq 1 ]]; then
    if [[ "$(sha256_file "$RECEIPT_BACKUP")" != "$RECEIPT_BACKUP_SHA256" ]] ||
       ! grep -qxF "$RECEIPT_BACKUP_SHA256  $RECEIPT_BACKUP" "$BACKUP_DIGEST_FILE" ||
       ! cp -a "$RECEIPT_BACKUP" "${RECEIPT}.new" || ! mv -f "${RECEIPT}.new" "$RECEIPT"; then
      rm -f "$RECEIPT"; rollback_failed=1
    else
      chown root:root "$RECEIPT" || rollback_failed=1
      chmod 0644 "$RECEIPT" || rollback_failed=1
    fi
  else
    rm -f "$RECEIPT"
  fi
  for ((i = 0; i < ${#EMERGENCY_DIRS[@]}; i++)); do
    chown "${PRE_DIR_OWNERS[$i]}" "${EMERGENCY_DIRS[$i]}" || rollback_failed=1
    chmod "${PRE_DIR_MODES[$i]}" "${EMERGENCY_DIRS[$i]}" || rollback_failed=1
  done
  "$SYSTEMCTL" restart patched-api.service || rollback_failed=1
  if [[ "$rollback_failed" -ne 0 ]]; then
    echo "EMERGENCY ROLLBACK FAILED: receipt removed; manual recovery required" >&2
    exit_code=1
  fi
  exit "$exit_code"
}

emergency_exit() {
  local exit_code="$?"
  trap - EXIT
  if [[ "$DEPLOY_PHASE" == "installing" && "$exit_code" -ne 0 ]]; then
    rollback "$exit_code"
  fi
  exit "$exit_code"
}
handle_signal() {
  local exit_code="$1"
  trap - HUP INT TERM
  if [[ "$DEPLOY_PHASE" == "installing" ]]; then
    rollback "$exit_code"
  fi
  exit "$exit_code"
}
trap emergency_exit EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM
DEPLOY_PHASE=installing

chown root:root "$API_PARENT" "$API_BIN_DIR" "$RECEIPT_DIR"
chmod 0755 "$API_PARENT" "$API_BIN_DIR" "$RECEIPT_DIR"
cp "$NEW_API_BIN" "${API_BIN}.new"
chown root:root "${API_BIN}.new"
chmod 0755 "${API_BIN}.new"
mv -f "${API_BIN}.new" "$API_BIN"
[[ "$(stat -c '%U:%G %a' "$API_PARENT")" == "root:root 755" ]]
[[ "$(stat -c '%U:%G %a' "$API_BIN_DIR")" == "root:root 755" ]]
[[ "$(stat -c '%U:%G %a' "$RECEIPT_DIR")" == "root:root 755" ]]
[[ "$(stat -c '%U:%G %a' "$API_BIN")" == "root:root 755" ]]
[[ "$(sha256_file "$API_BIN")" == "$EXPECTED_API_SHA256" ]]

"$SYSTEMCTL" restart patched-api.service
sleep "$SMOKE_DELAY"
"$SYSTEMCTL" is-active --quiet patched-api.service
HEALTH_STATUS="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8080/health || echo 000)"
if [[ "$HEALTH_STATUS" != "200" ]]; then
  echo "emergency API health check returned $HEALTH_STATUS" >&2
  false
fi

CURRENT_EXTRACTOR_SHA256=MISSING
CURRENT_CVE_SYNC_SHA256=MISSING
[[ ! -f "$EXTRACTOR_BIN" ]] || CURRENT_EXTRACTOR_SHA256="$(sha256_file "$EXTRACTOR_BIN")"
[[ ! -f "$CVE_SYNC_BIN" ]] || CURRENT_CVE_SYNC_SHA256="$(sha256_file "$CVE_SYNC_BIN")"
PREVIOUS_RECEIPT_POINTER=none
[[ "$RECEIPT_EXISTED" -eq 0 ]] || PREVIOUS_RECEIPT_POINTER="$RECEIPT_BACKUP"
{
  printf 'REDUCED_SCOPE=true\n'
  printf 'DEPLOYED_SHA=%s\n' "$EXPECTED_GITHUB_SHA_ARG"
  printf 'MIGRATION_HEAD=%s\n' "$MIGRATION_HEAD"
  printf 'DEPLOYED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'patched-api=%s\n' "$EXPECTED_API_SHA256"
  printf 'patched-extractor=%s\n' "$CURRENT_EXTRACTOR_SHA256"
  printf 'patched-cve-sync=%s\n' "$CURRENT_CVE_SYNC_SHA256"
  printf 'api_only_reason=%s\n' "$REASON"
  printf 'not_deployed=patched-extractor,patched-cve-sync,migrations\n'
  printf 'previous_receipt=%s\n' "$PREVIOUS_RECEIPT_POINTER"
} > "${RECEIPT}.new"
chown root:root "${RECEIPT}.new"
chmod 0644 "${RECEIPT}.new"
mv -f "${RECEIPT}.new" "$RECEIPT"
DEPLOY_PHASE=committed

cat "$RECEIPT" || echo "WARNING: could not print emergency receipt" >&2
prune_emergency_backups() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name "patched-api.emergency-bak-*" -print \
    | sort -r | tail -n +6 | xargs -r rm -f
}
prune_emergency_receipts() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name "DEPLOYED_BINARIES.emergency-bak-*" -print \
    | sort -r | tail -n +6 | xargs -r rm -f
}
prune_emergency_digests() {
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'ROLLBACK_SHA256-*' -print \
    | sort -r | tail -n +6 | xargs -r rm -f
}
prune_emergency_backups || echo "WARNING: could not prune emergency API backups" >&2
prune_emergency_receipts || echo "WARNING: could not prune emergency receipt history" >&2
prune_emergency_digests || echo "WARNING: could not prune emergency digest history" >&2
