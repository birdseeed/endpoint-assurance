#!/usr/bin/env bash
# deploy.sh — runs ON api-01 (root). Invoked by .github/workflows/deploy-api-01.yml
# after CI builds patched-api + patched-extractor + patched-cve-sync and rsyncs
# them, alongside go-service/migrations/, BINARY_MANIFEST and this script, into the
# staging directory this script itself lives in (/opt/patched-deploy-staging/
# by default).
#
# Steps: check the live schema for drift (read-only; warn-only or enforcing, see
# SCHEMA_DRIFT_ENFORCE_DEFAULT), apply pending DB migrations in version order, back up the current
# binaries, swap in the new ones, restart the two long-running units, smoke-test
# the result, and auto-rollback all three binaries (never the migrations — see
# below) if installation or smoke testing fails. patched-cve-sync.service is a
# timer-driven oneshot: this script replaces and hash-verifies its binary but
# never starts or restarts that unit.
#
# Migrations are forward-only: on smoke-test failure this script restores
# the previous binaries and restarts services, but does NOT run any
# migration rollback SQL. Migrations here are additive per
# go-service/migrations/README.md, so leaving an applied migration in place
# on binary rollback is safe.
#
# NEVER prints DATABASE_URL (strictly parsed from /etc/patched-api/env).
set -Eeuo pipefail

if [[ "$EUID" -eq 0 ]]; then
  # Workflow/manual production entrypoints clear the environment before Bash
  # starts. Re-establish the same contract here before any external command.
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  unset BASH_ENV ENV CDPATH
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Production is root-only and uses fixed paths. Test path/command overrides are
# accepted only for an explicitly marked non-root test process, so a root
# invocation cannot redirect deployment through supported override variables.
UNSAFE_OVERRIDE_NAMES=(
  PATCHED_DEPLOY_STAGING_DIR PATCHED_API_BIN PATCHED_EXTRACTOR_BIN
  PATCHED_CVE_SYNC_BIN PATCHED_DEPLOY_RECEIPT PATCHED_API_ENV_FILE
  PATCHED_DEPLOY_SMOKE_DELAY_SECONDS PATCHED_SYSTEMCTL_BIN
  PATCHED_DEPLOY_KEEP_STAGING PATCHED_BUSCTL_BIN PATCHED_SCHEMA_DRIFT_ENFORCE
  PATCHED_SCHEMA_DRIFT_TIMEOUT_SECONDS
)
# PAT-2062: the schema drift check (SCHEMA_DRIFT.md) runs read-only before the
# CVE timer is touched and before any migration. 0 is warn-only: drift, a
# refusal, or check artefacts that fail manifest verification are printed loudly
# and the deploy continues. 1 enforces: any of those stops the deploy with
# nothing changed. Shipped warn-only; flip to 1 once a deploy reports OK on the box.
SCHEMA_DRIFT_ENFORCE_DEFAULT=1
if [[ "$EUID" -eq 0 ]]; then
  if printenv PATCHED_DEPLOY_TEST_MODE >/dev/null 2>&1; then
    echo "PATCHED_DEPLOY_TEST_MODE is forbidden for root production invocation" >&2
    exit 1
  fi
  for override_name in "${UNSAFE_OVERRIDE_NAMES[@]}"; do
    if printenv "$override_name" >/dev/null 2>&1; then
      echo "$override_name is forbidden for root production invocation" >&2
      exit 1
    fi
  done
  STAGING_DIR="$SCRIPT_DIR"
  API_BIN="/opt/patched-api/bin/patched-api"
  EXTRACTOR_BIN="/opt/patched-extractor/bin/patched-extractor"
  CVE_SYNC_BIN="/opt/patched-api/bin/patched-cve-sync"
  DEPLOY_RECEIPT="/opt/patched-api/DEPLOYED_BINARIES"
  API_ENV_FILE="/etc/patched-api/env"
  SMOKE_DELAY_SECONDS=5
  SYSTEMCTL="systemctl"
  BUSCTL="busctl"
  BACKUP_DIR="/root/patched-deploy-backups"
  SCHEMA_DRIFT_ENFORCE="$SCHEMA_DRIFT_ENFORCE_DEFAULT"
  SCHEMA_DRIFT_TIMEOUT_SECONDS=600
else
  if [[ "${PATCHED_DEPLOY_TEST_MODE:-}" != "1" ]]; then
    echo "deploy.sh must run as root" >&2
    exit 1
  fi
  STAGING_DIR="${PATCHED_DEPLOY_STAGING_DIR:?test staging path required}"
  API_BIN="${PATCHED_API_BIN:?test API path required}"
  EXTRACTOR_BIN="${PATCHED_EXTRACTOR_BIN:?test extractor path required}"
  CVE_SYNC_BIN="${PATCHED_CVE_SYNC_BIN:?test CVE sync path required}"
  DEPLOY_RECEIPT="${PATCHED_DEPLOY_RECEIPT:?test receipt path required}"
  API_ENV_FILE="${PATCHED_API_ENV_FILE:?test env path required}"
  SMOKE_DELAY_SECONDS="${PATCHED_DEPLOY_SMOKE_DELAY_SECONDS:-0}"
  SYSTEMCTL="${PATCHED_SYSTEMCTL_BIN:-systemctl}"
  BUSCTL="${PATCHED_BUSCTL_BIN:-busctl}"
  BACKUP_DIR="${DEPLOY_RECEIPT}.rollback-sources"
  SCHEMA_DRIFT_ENFORCE="${PATCHED_SCHEMA_DRIFT_ENFORCE:-$SCHEMA_DRIFT_ENFORCE_DEFAULT}"
  SCHEMA_DRIFT_TIMEOUT_SECONDS="${PATCHED_SCHEMA_DRIFT_TIMEOUT_SECONDS:-600}"
fi
if [[ ! "$SCHEMA_DRIFT_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "SCHEMA_DRIFT_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 1
fi
if [[ "$SCHEMA_DRIFT_ENFORCE" != "0" && "$SCHEMA_DRIFT_ENFORCE" != "1" ]]; then
  echo "SCHEMA_DRIFT_ENFORCE must be 0 (warn) or 1 (enforce)" >&2
  exit 1
fi

MIGRATIONS_DIR="$STAGING_DIR/migrations"
NEW_API_BIN="$STAGING_DIR/patched-api"
NEW_EXTRACTOR_BIN="$STAGING_DIR/patched-extractor"
NEW_CVE_SYNC_BIN="$STAGING_DIR/patched-cve-sync"
MANIFEST_FILE="$STAGING_DIR/BINARY_MANIFEST"
HARDENING_GUARD="$STAGING_DIR/verify-systemd-hardening-floor.sh"
# Staged flat beside this script; each is bound by sha256 to a
# "schema-drift:<name>" line in BINARY_MANIFEST, built from the deployed commit.
SCHEMA_DRIFT_ARTEFACTS=(
  SCHEMA_FINGERPRINT_JOURNAL schema_drift.py schema_fingerprint.sql
  schema-drift-check.sh schema-drift-allowlist.txt
)

TS="$(date -u +%Y%m%dT%H%M%SZ)"
API_BACKUP="$BACKUP_DIR/patched-api.bak-${TS}"
EXTRACTOR_BACKUP="$BACKUP_DIR/patched-extractor.bak-${TS}"
CVE_SYNC_BACKUP="$BACKUP_DIR/patched-cve-sync.bak-${TS}"
RECEIPT_BACKUP="$BACKUP_DIR/DEPLOYED_BINARIES.bak-${TS}"
BACKUP_DIGEST_FILE="$BACKUP_DIR/ROLLBACK_SHA256-${TS}"
RECEIPT_HAD_EXISTING=0
TIMER_STOPPED=0
TOOLING_TIMER_STOPPED=0
TOOLING_TIMER_MANAGED=0
TIMER_RESTORE_BLOCKED=0
MAX_BACKUPS=5
DEPLOY_PHASE=preinstall
TIMER_TRANSITION=0
PENDING_SIGNAL=0
# ROLLBACK_ATTEMPTED is set the moment rollback() is entered, from any trap, so
# a second entry can never double-restore. ROLLBACK_COMPLETED is set only when
# rollback finished with every binary restored, so "attempted but not completed"
# stays distinguishable from "completed" and from "never ran at all".
ROLLBACK_ATTEMPTED=0
ROLLBACK_COMPLETED=0
RECOVERY_EVIDENCE="$STAGING_DIR/RECOVERY_REQUIRED"
BINARY_RECOVERY_EVIDENCE="$STAGING_DIR/BINARY_ROLLBACK_REQUIRED"

record_migration_recovery() {
  local reason="$1" evidence_tmp="${RECOVERY_EVIDENCE}.new" current_cve_hash="MISSING"
  [[ "${pending_count:-0}" -gt 0 ]] || return 0
  [[ -f "$CVE_SYNC_BIN" ]] && current_cve_hash="$(sha256_file "$CVE_SYNC_BIN")"
  {
    printf 'RECOVERY_REQUIRED=true\n'
    printf 'DEPLOYED_SHA=%s\n' "${BUILD_SHA:-UNKNOWN}"
    printf 'MIGRATION_HEAD=%s\n' "${MIGRATION_HEAD:-UNKNOWN}"
    printf 'MIGRATIONS_APPLIED_THIS_RUN=%s\n' "$pending_count"
    printf 'CVE_TIMER=disabled\n'
    printf 'TOOLING_CVE_TIMER=disabled\n'
    printf 'CURRENT_CVE_SYNC_SHA256=%s\n' "$current_cve_hash"
    printf 'REASON=%s\n' "$reason"
    printf 'RECOVERY=rerun the verified full deploy before enabling patched-cve-sync.timer\n'
  } > "$evidence_tmp" || return 1
  if [[ "$EUID" -eq 0 ]]; then
    chown root:root "$evidence_tmp" || return 1
  fi
  chmod 0600 "$evidence_tmp" || return 1
  mv -f "$evidence_tmp" "$RECOVERY_EVIDENCE"
}

# Sibling of record_migration_recovery for a strictly more urgent condition: the
# new binaries are installed and were NOT restored to the pre-deploy versions.
# Deliberately a separate file with its own vocabulary. An uncommitted forward
# migration leaves a consistent box with one unit held disabled; unrolled-back
# binaries leave production running unverified bytes under a receipt that still
# describes the previous release, and an operator must be able to tell those
# apart at a glance. Unlike the migration evidence this is never conditional on
# pending_count, because a deploy that dies mid-swap with no migrations at all
# is in exactly the same state.
record_binary_rollback_required() {
  local reason="$1" evidence_tmp="${BINARY_RECOVERY_EVIDENCE}.new"
  {
    printf 'BINARY_ROLLBACK_REQUIRED=true\n'
    printf 'BINARIES_ROLLED_BACK=false\n'
    printf 'DEPLOY_PHASE=%s\n' "$DEPLOY_PHASE"
    printf 'ATTEMPTED_SHA=%s\n' "${BUILD_SHA:-UNKNOWN}"
    printf 'REASON=%s\n' "$reason"
    printf 'INSTALLED_BINARIES=%s %s %s\n' "$API_BIN" "$EXTRACTOR_BIN" "$CVE_SYNC_BIN"
    printf 'ROLLBACK_SOURCES=%s\n' "$BACKUP_DIR"
    printf 'ROLLBACK_DIGESTS=%s\n' "$BACKUP_DIGEST_FILE"
    printf 'RECOVERY=the deploy receipt does not describe the installed bytes; restore the listed rollback sources or re-run the full verified deploy before trusting this host\n'
  } > "$evidence_tmp" || return 1
  if [[ "$EUID" -eq 0 ]]; then
    chown root:root "$evidence_tmp" || return 1
  fi
  chmod 0600 "$evidence_tmp" || return 1
  mv -f "$evidence_tmp" "$BINARY_RECOVERY_EVIDENCE"
}

restore_timer_on_exit() {
  local exit_code="$?"
trap - EXIT HUP INT TERM
  # Three different exits reach here and must not be conflated.
  #
  #   (i)   a clean exit, or one that never touched the installed binaries:
  #         DEPLOY_PHASE is "committed" or still "preinstall", so the block
  #         below is skipped entirely and only the timer is tidied up;
  #   (ii)  a forward migration applied but not committed: handled by the timer
  #         block, which leaves patched-cve-sync.timer disabled and writes
  #         RECOVERY_EVIDENCE;
  #   (iii) the binaries were swapped in and the ERR trap never got to undo it.
  #
  # (iii) is this block. A fatal Bash-level failure — a parse error, or a trap
  # string that does not itself parse (PAT-1938's exit 2, "unexpected EOF while
  # looking for matching ')'") — kills the interpreter rather than failing a
  # command, so ERR never fires and rollback() is never reached. EXIT still
  # fires, and before this block it restored the timer and recorded migration
  # evidence while silently leaving the new, possibly unverified binaries
  # installed: an exit that looked tidy from its own evidence.
  #
  # Every value rollback() reads — API_BACKUP*, EXTRACTOR_BACKUP*,
  # CVE_SYNC_BACKUP*, RECEIPT_BACKUP*, BACKUP_DIGEST_FILE, SECURE_DIRS,
  # PRE_DIR_OWNERS, PRE_DIR_MODES, pending_count, RECEIPT_HAD_EXISTING — is
  # assigned by unconditional top-level code strictly before DEPLOY_PHASE
  # becomes "installing", and nothing after that point unsets any of them, so
  # this branch can never call rollback() with a half-initialised backup set.
  # rollback() is likewise defined long before that assignment. It disarms ERR
  # and runs under `set +e` itself, it handles the CVE timer (a superset of the
  # block below), and it ends in `exit`, so it never returns here; EXIT is
  # already disarmed above, so that exit cannot re-enter this handler.
  if [[ "$DEPLOY_PHASE" == "installing" ]]; then
    if [[ "$ROLLBACK_ATTEMPTED" -eq 0 ]]; then
      # Written before rollback runs, not after: if rollback itself dies, the
      # box must still say so rather than look like a clean exit.
      record_binary_rollback_required "deploy died mid-install; the ERR trap never ran" || exit_code=1
      echo "RECOVERY REQUIRED: deploy died mid-install without running the ERR trap; rolling back binaries from the EXIT trap" >&2
      rollback "$exit_code" exit-trap
    elif [[ "$ROLLBACK_COMPLETED" -eq 0 ]]; then
      record_binary_rollback_required "rollback was entered but did not restore every pre-deploy binary" || exit_code=1
      echo "RECOVERY REQUIRED: binaries were NOT rolled back; see $BINARY_RECOVERY_EVIDENCE" >&2
    fi
  fi
  if [[ "$TIMER_STOPPED" -eq 1 ]]; then
    if [[ "${pending_count:-0}" -gt 0 && "$DEPLOY_PHASE" != "committed" ]]; then
      TIMER_RESTORE_BLOCKED=1
      record_migration_recovery "deploy exited after forward migration before commit" || exit_code=1
      echo "RECOVERY REQUIRED: forward migration applied; patched-cve-sync.timer remains disabled" >&2
    elif ! "$SYSTEMCTL" start patched-cve-sync.timer; then
      echo "EXIT CLEANUP FAILED: patched-cve-sync.timer could not be restored" >&2
      exit_code=1
    else
      TIMER_STOPPED=0
    fi
  fi
  if [[ "$TOOLING_TIMER_MANAGED" -eq 1 && "$TOOLING_TIMER_STOPPED" -eq 1 ]]; then
    if [[ "${pending_count:-0}" -gt 0 && "$DEPLOY_PHASE" != "committed" ]]; then
      TIMER_RESTORE_BLOCKED=1
      echo "RECOVERY REQUIRED: forward migration applied; patched-tooling-cve-refresh.timer remains disabled" >&2
    elif ! "$SYSTEMCTL" start patched-tooling-cve-refresh.timer; then
      echo "EXIT CLEANUP FAILED: patched-tooling-cve-refresh.timer could not be restored" >&2
      exit_code=1
    else
      TOOLING_TIMER_STOPPED=0
    fi
  fi
  exit "$exit_code"
}

trap restore_timer_on_exit EXIT
handle_signal() {
  local exit_code="$1"
  trap - HUP INT TERM
  if [[ "$DEPLOY_PHASE" == "installing" ]]; then
    rollback "$exit_code" signal
  fi
  exit "$exit_code"
}
dispatch_signal() {
  local exit_code="$1"
  if [[ "$TIMER_TRANSITION" -eq 1 ]]; then
    PENDING_SIGNAL="$exit_code"
    return 0
  fi
  handle_signal "$exit_code"
}
trap 'dispatch_signal 129' HUP
trap 'dispatch_signal 130' INT
trap 'dispatch_signal 143' TERM

restore_timer_after_deploy() {
  local start_status=0 queued_signal
  TIMER_TRANSITION=1
  "$SYSTEMCTL" start patched-cve-sync.timer || start_status=$?
  if [[ "$TOOLING_TIMER_MANAGED" -eq 1 ]]; then
    "$SYSTEMCTL" start patched-tooling-cve-refresh.timer || start_status=$?
  fi
  if [[ "$start_status" -eq 0 ]]; then
    TIMER_STOPPED=0
    TOOLING_TIMER_STOPPED=0
  fi
  TIMER_TRANSITION=0
  queued_signal="$PENDING_SIGNAL"
  PENDING_SIGNAL=0
  if [[ "$queued_signal" -ne 0 ]]; then
    handle_signal "$queued_signal"
  fi
  return "$start_status"
}

quiesce_timer_for_deploy() {
  local stop_status=0 queued_signal
  TIMER_TRANSITION=1
  # Conservatively mark restoration required before invoking systemctl. A
  # signal can otherwise land after systemd stopped the timer but before Bash
  # records TIMER_STOPPED=1, leaving EXIT cleanup with a false safe state.
  TIMER_STOPPED=1
  "$SYSTEMCTL" stop patched-cve-sync.timer || stop_status=$?
  if [[ "$TOOLING_TIMER_MANAGED" -eq 1 ]]; then
    TOOLING_TIMER_STOPPED=1
    "$SYSTEMCTL" stop patched-tooling-cve-refresh.timer || stop_status=$?
  fi
  TIMER_TRANSITION=0
  queued_signal="$PENDING_SIGNAL"
  PENDING_SIGNAL=0
  if [[ "$queued_signal" -ne 0 ]]; then
    handle_signal "$queued_signal"
  fi
  return "$stop_status"
}

log() {
  printf '\n== %s ==\n' "$*"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

validate_staging_dir() {
  local target="$1" staging_state
  if [[ -z "$target" || "$target" != /* || "$target" == "/" ||
        "$target" == "/opt" || "$target" == "/opt/patched-api" ||
        "$target" == "/opt/patched-extractor" || -L "$target" ]]; then
    echo "unsafe staging directory refused: $target" >&2
    return 1
  fi
  if [[ "$EUID" -eq 0 && "$target" != "/opt/patched-deploy-staging" ]]; then
    echo "root production staging must be exactly /opt/patched-deploy-staging" >&2
    return 1
  fi
  if [[ "$EUID" -eq 0 ]]; then
    staging_state="$(stat -c '%U:%G %a' "$target")" || return 1
    if [[ "$staging_state" != "root:root 755" ]]; then
      echo "root production staging must be root:root 0755, got $staging_state" >&2
      return 1
    fi
  fi
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

# Exact line-for-line match against $text as already split by the caller.
# "$wanted" is a bare migration version (no spaces), and the one caller
# pre-normalizes $text with `tr -d ' '` before calling — that's a caller
# contract, not something this function does itself, so it stays correct
# only because migration version strings never contain spaces.
text_has_exact_line() {
  local text="$1" wanted="$2" remaining line
  remaining="$text"
  while [[ -n "$remaining" ]]; do
    if [[ "$remaining" == *$'\n'* ]]; then
      line="${remaining%%$'\n'*}"
      remaining="${remaining#*$'\n'}"
    else
      line="$remaining"
      remaining=""
    fi
    [[ "$line" == "$wanted" ]] && return 0
  done
  return 1
}

cve_sync_state_is_safe() {
  local state active_state sub_state
  state="$("$SYSTEMCTL" show patched-cve-sync.service --property=ActiveState --property=SubState)" || return 1
  active_state="$(property_value "$state" ActiveState)" || return 1
  sub_state="$(property_value "$state" SubState)" || return 1
  case "$active_state/$sub_state" in
    inactive/dead|active/exited|failed/failed) return 0 ;;
    *)
      echo "patched-cve-sync.service is not safely idle: ActiveState=$active_state SubState=$sub_state" >&2
      return 1
      ;;
  esac
}

tooling_sync_state_is_safe() {
  local state active_state sub_state
  state="$("$SYSTEMCTL" show patched-tooling-cve-refresh.service --property=ActiveState --property=SubState)" || return 1
  active_state="$(property_value "$state" ActiveState)" || return 1
  sub_state="$(property_value "$state" SubState)" || return 1
  case "$active_state/$sub_state" in
    inactive/dead|active/exited|failed/failed) return 0 ;;
    *) echo "patched-tooling-cve-refresh.service is not safely idle: ActiveState=$active_state SubState=$sub_state" >&2; return 1 ;;
  esac
}

assert_service_write_contract() {
  local unit="$1" expected_working_directory="$2"
  local properties user working_directory protect_system write_line write_path
  properties="$("$SYSTEMCTL" show "$unit" --property=User --property=WorkingDirectory \
    --property=ProtectSystem --property=ReadWritePaths --property=ReadWriteDirectories)" || return 1
  user="$(property_value "$properties" User)" || return 1
  working_directory="$(property_value "$properties" WorkingDirectory)" || return 1
  protect_system="$(property_value "$properties" ProtectSystem)" || return 1
  if [[ "$user" != "patched" || "$working_directory" != "$expected_working_directory" || "$protect_system" != "strict" ]]; then
    echo "$unit write contract drifted: User=$user WorkingDirectory=$working_directory ProtectSystem=$protect_system" >&2
    return 1
  fi
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
      if [[ "$write_path" == "/opt" || "$write_path" == /opt/* ]]; then
        echo "$unit permits writes under /opt: $write_path" >&2
        return 1
      fi
    done
  done
}

# Prints why an artefact is unusable and returns 1, or returns 0 when every
# check file and the journal are present, regular, and match BINARY_MANIFEST.
verify_schema_drift_artefacts() {
  local name path expected
  for name in "${SCHEMA_DRIFT_ARTEFACTS[@]}"; do
    path="$STAGING_DIR/$name"
    expected="$(sed -n "s/^\([0-9a-f]\{64\}\)  schema-drift:${name//./\\.}$/\1/p" "$MANIFEST_FILE")"
    if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
      echo "BINARY_MANIFEST lacks exactly one schema-drift entry for $name"
      return 1
    fi
    if [[ -L "$path" || ! -f "$path" ]]; then
      echo "staged schema drift artefact is missing or not a regular file: $name"
      return 1
    fi
    if [[ "$(sha256_file "$path")" != "$expected" ]]; then
      echo "staged schema drift artefact does not match BINARY_MANIFEST: $name"
      return 1
    fi
  done
}

# The deploy log is published in GitHub Actions. The check never prints the
# URL, but psql error text is passed through, so strip the URL and its
# password here as well, in-shell, without handing either to another process.
redact_database_url() {
  local text="$1" authority userinfo password=""
  authority="${DATABASE_URL#*://}"
  authority="${authority%%/*}"
  if [[ "$authority" == *@* ]]; then
    userinfo="${authority%@*}"
    [[ "$userinfo" == *:* ]] && password="${userinfo#*:}"
  fi
  text="${text//"$DATABASE_URL"/[DATABASE_URL redacted]}"
  [[ -n "$password" ]] && text="${text//"$password"/[redacted]}"
  printf '%s' "$text"
}

# ---------------------------------------------------------------------------
log "Checking staged artefacts"
validate_staging_dir "$STAGING_DIR" || exit 1
for f in "$NEW_API_BIN" "$NEW_EXTRACTOR_BIN" "$NEW_CVE_SYNC_BIN" "$MANIFEST_FILE" "$HARDENING_GUARD"; do
  if [[ ! -f "$f" ]]; then
    echo "missing staged artefact: $f" >&2
    exit 1
  fi
done
if [[ -L "$HARDENING_GUARD" || ! -x "$HARDENING_GUARD" ]]; then
  echo "staged hardening guard must be a regular executable: $HARDENING_GUARD" >&2
  exit 1
fi
if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "missing staged migrations dir: $MIGRATIONS_DIR" >&2
  exit 1
fi
if [[ ! -f "$API_BIN" ]]; then
  echo "no existing binary at $API_BIN to back up — refusing to deploy blind" >&2
  exit 1
fi
if [[ ! -f "$EXTRACTOR_BIN" ]]; then
  echo "no existing binary at $EXTRACTOR_BIN to back up — refusing to deploy blind" >&2
  exit 1
fi
if [[ ! -f "$CVE_SYNC_BIN" ]]; then
  echo "no existing binary at $CVE_SYNC_BIN to back up — refusing to deploy blind" >&2
  exit 1
fi

if [[ "$(wc -l < "$MANIFEST_FILE" | tr -d ' ')" -lt 6 ]]; then
  echo "BINARY_MANIFEST must contain headers, three binaries and migration hashes" >&2
  exit 1
fi
BUILD_SHA="$(sed -n 's/^GITHUB_SHA=//p' "$MANIFEST_FILE")"
MIGRATION_HEAD="$(sed -n 's/^MIGRATION_HEAD=//p' "$MANIFEST_FILE")"
EXPECTED_API_SHA256="$(sed -n 's/^\([0-9a-f]\{64\}\)  patched-api$/\1/p' "$MANIFEST_FILE")"
EXPECTED_EXTRACTOR_SHA256="$(sed -n 's/^\([0-9a-f]\{64\}\)  patched-extractor$/\1/p' "$MANIFEST_FILE")"
EXPECTED_CVE_SYNC_SHA256="$(sed -n 's/^\([0-9a-f]\{64\}\)  patched-cve-sync$/\1/p' "$MANIFEST_FILE")"
if [[ ! "$BUILD_SHA" =~ ^[0-9a-f]{40}$ ]] || [[ ! "$MIGRATION_HEAD" =~ ^[0-9]{4}_[a-z0-9_]+$ ]] ||
   [[ ! "$EXPECTED_API_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
   [[ ! "$EXPECTED_EXTRACTOR_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
   [[ ! "$EXPECTED_CVE_SYNC_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "BINARY_MANIFEST is malformed or incomplete" >&2
  exit 1
fi
if [[ ! -f "$MIGRATIONS_DIR/${MIGRATION_HEAD}.sql" ]]; then
  echo "manifest migration head is not present in staged migrations: $MIGRATION_HEAD" >&2
  exit 1
fi
[[ "$(sha256_file "$NEW_API_BIN")" == "$EXPECTED_API_SHA256" ]] || { echo "staged patched-api does not match BINARY_MANIFEST" >&2; exit 1; }
[[ "$(sha256_file "$NEW_EXTRACTOR_BIN")" == "$EXPECTED_EXTRACTOR_SHA256" ]] || { echo "staged patched-extractor does not match BINARY_MANIFEST" >&2; exit 1; }
[[ "$(sha256_file "$NEW_CVE_SYNC_BIN")" == "$EXPECTED_CVE_SYNC_SHA256" ]] || { echo "staged patched-cve-sync does not match BINARY_MANIFEST" >&2; exit 1; }

# Every conventioned forward migration that this deploy may execute must have
# exactly one content hash in the CI-produced manifest. Verify the full staged
# set now and verify each file again immediately before psql below.
MIGRATION_FLOOR=56
manifest_migration_count=0
manifest_line_number=0
while IFS= read -r manifest_line || [[ -n "$manifest_line" ]]; do
  manifest_line_number=$((manifest_line_number + 1))
  [[ "$manifest_line_number" -gt 5 ]] || continue
  # Verified by verify_schema_drift_artefacts, whose failure mode is the
  # drift check's (warn or enforce), not an unconditional abort.
  [[ "$manifest_line" =~ ^[0-9a-f]{64}\ \ schema-drift:(SCHEMA_FINGERPRINT_JOURNAL|schema_drift\.py|schema_fingerprint\.sql|schema-drift-check\.sh|schema-drift-allowlist\.txt)$ ]] && continue
  [[ "$manifest_line" =~ ^([0-9a-f]{64})\ \ migration:([0-9]{4}_[a-z0-9_]+\.sql)$ ]] || {
    echo "BINARY_MANIFEST contains an invalid migration hash entry: $manifest_line" >&2
    exit 1
  }
  manifest_hash="${BASH_REMATCH[1]}"
  manifest_name="${BASH_REMATCH[2]}"
  manifest_path="$MIGRATIONS_DIR/$manifest_name"
  [[ -f "$manifest_path" ]] || { echo "manifest migration is absent from staging: $manifest_name" >&2; exit 1; }
  [[ "$(sha256_file "$manifest_path")" == "$manifest_hash" ]] || {
    echo "staged migration does not match BINARY_MANIFEST: $manifest_name" >&2
    exit 1
  }
  manifest_migration_count=$((manifest_migration_count + 1))
done < "$MANIFEST_FILE"
[[ "$manifest_migration_count" -gt 0 ]] || { echo "BINARY_MANIFEST has no migration hashes" >&2; exit 1; }

for staged_migration in "$MIGRATIONS_DIR"/*.sql; do
  [[ -f "$staged_migration" ]] || continue
  staged_name="$(basename "$staged_migration")"
  [[ "$staged_name" == *_rollback.sql ]] && continue
  if [[ ! "$staged_name" =~ ^[0-9]{4}_[a-z0-9_]+\.sql$ ]]; then
    echo "unexpected staged SQL filename refused: $staged_name" >&2
    exit 1
  fi
  staged_version="${staged_name%.sql}"
  staged_num="$((10#${staged_version%%_*}))"
  [[ "$staged_num" -lt "$MIGRATION_FLOOR" ]] && continue
  staged_hash="$(sha256_file "$staged_migration")"
  [[ "$(grep -c "^${staged_hash}  migration:${staged_version}\.sql$" "$MANIFEST_FILE")" -eq 1 ]] || {
    echo "staged migration lacks one exact manifest binding: $staged_version" >&2
    exit 1
  }
done

# Parent reownership is safe only while both effective unit sandboxes retain
# the audited read-only /opt contract. Fail before timer or filesystem mutation.
assert_service_write_contract patched-api.service /opt/patched-api || exit 1
assert_service_write_contract patched-extractor.service /opt/patched-extractor || exit 1
assert_service_write_contract patched-cve-sync.service /opt/patched-api || exit 1

# ---------------------------------------------------------------------------
# PAT-2062: schema drift check, READ-ONLY, before the CVE timer is touched and
# before any migration, so an enforced stop leaves the box exactly as it was.
# The expected schema is rebuilt from the versions the box itself records.
# Exit 1 is drift and 2 a refusal; anything non-zero counts, as does an
# artefact that fails manifest verification. Output is indented with "| " so
# text read from the database cannot start a GitHub Actions workflow command.
if [[ "$SCHEMA_DRIFT_ENFORCE" == "1" ]]; then
  log "Schema drift check (read-only, enforcing)"
else
  log "Schema drift check (read-only, warn-only)"
fi
DATABASE_URL="$(read_database_url "$API_ENV_FILE")" || exit 1
schema_drift_status=0
if ! schema_drift_output="$(verify_schema_drift_artefacts)"; then
  schema_drift_status=unverified
else
  # A wall-clock bound on top of psql's own timeouts. timeout signals the
  # whole process group, so psql under the check dies with it.
  schema_drift_output="$(DATABASE_URL="$DATABASE_URL" PGCONNECT_TIMEOUT=30 \
    PGOPTIONS="-c statement_timeout=120s" \
    timeout --kill-after=10 "$SCHEMA_DRIFT_TIMEOUT_SECONDS" \
    bash "$STAGING_DIR/schema-drift-check.sh" \
      --journal "$STAGING_DIR/SCHEMA_FINGERPRINT_JOURNAL" \
      --allowlist "$STAGING_DIR/schema-drift-allowlist.txt" 2>&1)" || schema_drift_status=$?
fi
if [[ -n "$schema_drift_output" ]]; then
  redact_database_url "$schema_drift_output" | sed 's/^/  | /'
  echo
fi
case "$schema_drift_status" in
  0) schema_drift_problem="" ;;
  1) schema_drift_problem="the live schema differs from what the migrations produce at its recorded head" ;;
  124|137) schema_drift_problem="the check refused: it did not finish within ${SCHEMA_DRIFT_TIMEOUT_SECONDS} seconds and was killed, so the live schema was not compared" ;;
  unverified) schema_drift_problem="the check did not run because its staged artefacts failed verification against BINARY_MANIFEST" ;;
  *) schema_drift_problem="the check refused or failed (exit $schema_drift_status), so the live schema was not compared" ;;
esac
if [[ -z "$schema_drift_problem" ]]; then
  echo "schema drift check: OK"
elif [[ "$SCHEMA_DRIFT_ENFORCE" == "1" ]]; then
  echo "::error::SCHEMA DRIFT CHECK FAILED: $schema_drift_problem. Enforcing, so the deploy stops here before any migration; nothing has been changed."
  exit 1
else
  echo "::warning::SCHEMA DRIFT CHECK FAILED (warn-only, deploy continues): $schema_drift_problem. See the output above."
fi

# The synchroniser is timer-owned. Refuse a window too near its next trigger,
# then stop only the timer before migrations. This bounds the Persistent=true
# catch-up risk while keeping a running oneshot entirely untouched.
if ! "$SYSTEMCTL" is-enabled --quiet patched-cve-sync.timer; then
  echo "patched-cve-sync.timer is not enabled — refusing to deploy" >&2
  exit 1
fi
if ! "$SYSTEMCTL" is-active --quiet patched-cve-sync.timer; then
  echo "patched-cve-sync.timer is not active — refusing to deploy" >&2
  exit 1
fi
if [[ "$EUID" -eq 0 ]] && "$SYSTEMCTL" is-enabled --quiet patched-tooling-cve-refresh.timer; then
  TOOLING_TIMER_MANAGED=1
  if ! "$SYSTEMCTL" is-active --quiet patched-tooling-cve-refresh.timer; then
    echo "patched-tooling-cve-refresh.timer is enabled but inactive — refusing to deploy" >&2
    exit 1
  fi
fi
NEXT_TRIGGER_RAW="$("$BUSCTL" get-property org.freedesktop.systemd1 \
  /org/freedesktop/systemd1/unit/patched_2dcve_2dsync_2etimer \
  org.freedesktop.systemd1.Timer NextElapseUSecRealtime)" || exit 1
if [[ ! "$NEXT_TRIGGER_RAW" =~ ^t\ ([0-9]+)$ ]]; then
  echo "patched-cve-sync.timer returned invalid machine next-elapse value: $NEXT_TRIGGER_RAW" >&2
  exit 1
fi
NEXT_TRIGGER_USEC="${BASH_REMATCH[1]}"
if [[ "$NEXT_TRIGGER_USEC" == "18446744073709551615" ]]; then
  echo "patched-cve-sync.timer has no finite next elapse (USEC_INFINITY) — refusing to deploy" >&2
  exit 1
fi
NEXT_TRIGGER_EPOCH="$((NEXT_TRIGGER_USEC / 1000000))"
NOW_EPOCH="$(date +%s)"
if (( NEXT_TRIGGER_EPOCH <= NOW_EPOCH + 900 )); then
  echo "patched-cve-sync.timer is due within 15 minutes — retry after the scheduled sync" >&2
  exit 1
fi

quiesce_timer_for_deploy
if ! cve_sync_state_is_safe; then
  echo "patched-cve-sync.service started while quiescing its timer" >&2
  exit 1
fi
if [[ "$TOOLING_TIMER_MANAGED" -eq 1 ]] && ! tooling_sync_state_is_safe; then
  echo "patched-tooling-cve-refresh.service started while quiescing its timer" >&2
  exit 1
fi
TOOLING_INVOCATION_BEFORE=""
if [[ "$TOOLING_TIMER_MANAGED" -eq 1 ]]; then
  TOOLING_INVOCATION_BEFORE="$("$SYSTEMCTL" show patched-tooling-cve-refresh.service --property=InvocationID --value | tr -d '[:space:]')"
fi
CVE_INVOCATION_BEFORE="$("$SYSTEMCTL" show patched-cve-sync.service --property=InvocationID --value | tr -d '[:space:]')"
if [[ -z "$CVE_INVOCATION_BEFORE" ]]; then
  # PAT-1748: a timer-owned oneshot that has not run since boot has no
  # InvocationID. Accept that only for a loaded unit that is exactly
  # inactive/dead (the never-run shape). active/exited and failed/failed are
  # safe idle states in general, but with an empty InvocationID they are not a
  # coherent systemd state and stay refused. The post-smoke check then requires
  # the ID to still be empty, so a run started during the deploy is caught.
  CVE_LOAD_STATE="$("$SYSTEMCTL" show patched-cve-sync.service --property=LoadState --value | tr -d '[:space:]')" || {
    echo "patched-cve-sync.service InvocationID is empty and LoadState could not be read" >&2
    exit 1
  }
  CVE_EMPTY_ID_STATE="$("$SYSTEMCTL" show patched-cve-sync.service --property=ActiveState --property=SubState)" || {
    echo "patched-cve-sync.service InvocationID is empty and ActiveState/SubState could not be read" >&2
    exit 1
  }
  CVE_EMPTY_ID_ACTIVE="$(property_value "$CVE_EMPTY_ID_STATE" ActiveState)" || CVE_EMPTY_ID_ACTIVE=""
  CVE_EMPTY_ID_SUB="$(property_value "$CVE_EMPTY_ID_STATE" SubState)" || CVE_EMPTY_ID_SUB=""
  if [[ "$CVE_LOAD_STATE" != "loaded" || "$CVE_EMPTY_ID_ACTIVE" != "inactive" || "$CVE_EMPTY_ID_SUB" != "dead" ]]; then
    echo "patched-cve-sync.service InvocationID is empty and cannot prove the oneshot stayed untouched; an empty InvocationID is accepted only for LoadState=loaded ActiveState=inactive SubState=dead; got LoadState=$CVE_LOAD_STATE ActiveState=$CVE_EMPTY_ID_ACTIVE SubState=$CVE_EMPTY_ID_SUB" >&2
    exit 1
  fi
  log "patched-cve-sync.service has not run since boot (empty InvocationID, loaded, inactive/dead); requiring it to stay empty"
fi
EXEC_START="$("$SYSTEMCTL" show patched-cve-sync.service --property=ExecStart --value)"
EXEC_START_PATH=""
EXEC_START_COUNT=0
exec_start_remaining="$EXEC_START"
while [[ "$exec_start_remaining" == *"{ path="* ]]; do
  EXEC_START_COUNT=$((EXEC_START_COUNT + 1))
  exec_start_remaining="${exec_start_remaining#*\{ path=}"
done
if [[ "$EXEC_START" =~ ^\{[[:space:]]path=([^[:space:];\}]+)[[:space:]]\; ]]; then
  EXEC_START_PATH="${BASH_REMATCH[1]}"
fi
if [[ "$EXEC_START_COUNT" -ne 1 || "$EXEC_START_PATH" != "$CVE_SYNC_BIN" ]]; then
  echo "patched-cve-sync.service must expose exactly one ExecStart resolving to '$CVE_SYNC_BIN'; count=$EXEC_START_COUNT path='$EXEC_START_PATH'" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
log "Applying pending migrations"

applied="$(psql -d "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc "SELECT version FROM schema_migrations" | tr -d ' ')"

# Migrations <= 0055 are grandfathered and are NEVER considered here: per
# migrations/README.md they have duplicate version numbers (0025/0033/0036/…)
# and some (e.g. 0053) never recorded a schema_migrations row at all, so a
# healthy live DB legitimately lacks their bookkeeping. Matching a filename
# basename against schema_migrations for those would treat an already-migrated
# DB as pending and abort the deploy re-creating existing objects. Any live DB
# is long past 0055; the conventioned 0056+ migrations record a full
# 'NNNN_name' row, so the schema_migrations membership check is reliable there.
#
# Application order below relies on the glob expanding in lexical order.
# That is safe here specifically because every conventioned filename is
# validated (both here and in the earlier manifest-verification loop) to
# start with a fixed-width 4-digit zero-padded version — lexical order over
# equal-width numeric strings is numeric order, so "0056_..." always sorts
# before "0057_...". This would silently break if the version prefix were
# ever allowed to vary in width.
pending_count=0
for file in "$MIGRATIONS_DIR"/*.sql; do
  [[ -f "$file" ]] || continue
  migration_name="$(basename "$file")"
  [[ "$migration_name" == *_rollback.sql ]] && continue
  [[ "$migration_name" =~ ^[0-9]{4}_[a-z0-9_]+\.sql$ ]] || {
    echo "unexpected staged SQL filename refused: $migration_name" >&2
    exit 1
  }
  version="${migration_name%.sql}"
  # Numeric prefix, base-10 (10# so leading zeros aren't read as octal).
  num="$((10#${version%%_*}))"
  [[ "$num" -lt "$MIGRATION_FLOOR" ]] && continue
  if text_has_exact_line "$applied" "$version"; then
    continue
  fi
  expected_migration_hash="$(sed -n "s/^\([0-9a-f]\{64\}\)  migration:${version}\.sql$/\1/p" "$MANIFEST_FILE")"
  if [[ ! "$expected_migration_hash" =~ ^[0-9a-f]{64}$ ]] ||
     [[ "$(sha256_file "$file")" != "$expected_migration_hash" ]]; then
    echo "migration content changed after manifest verification: $version" >&2
    exit 1
  fi
  echo "applying migration: $version"
  psql -d "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file"
  pending_count=$((pending_count + 1))
  record_migration_recovery "forward migration applied; deploy not yet committed"
done

if [[ "$pending_count" -eq 0 ]]; then
  echo "no pending migrations"
else
  echo "applied $pending_count migration(s)"
fi

verify_manifest_migration_head() {
  local present
  present="$(psql -d "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc \
    "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '$MIGRATION_HEAD')" | tr -d '[:space:]')"
  if [[ "$present" != "t" ]]; then
    echo "manifest migration head $MIGRATION_HEAD is not recorded in schema_migrations" >&2
    return 1
  fi
}
verify_manifest_migration_head

# ---------------------------------------------------------------------------
log "Backing up current binaries"
install -d -o root -g root -m 0700 "$BACKUP_DIR"
cp -a "$API_BIN" "$API_BACKUP"
cp -a "$EXTRACTOR_BIN" "$EXTRACTOR_BACKUP"
cp -a "$CVE_SYNC_BIN" "$CVE_SYNC_BACKUP"
if [[ -f "$DEPLOY_RECEIPT" ]]; then
  cp -a "$DEPLOY_RECEIPT" "$RECEIPT_BACKUP"
  RECEIPT_HAD_EXISTING=1
fi
chown root:root "$API_BACKUP" "$EXTRACTOR_BACKUP" "$CVE_SYNC_BACKUP"
chmod 0600 "$API_BACKUP" "$EXTRACTOR_BACKUP" "$CVE_SYNC_BACKUP"
API_BACKUP_SHA256="$(sha256_file "$API_BACKUP")"
EXTRACTOR_BACKUP_SHA256="$(sha256_file "$EXTRACTOR_BACKUP")"
CVE_SYNC_BACKUP_SHA256="$(sha256_file "$CVE_SYNC_BACKUP")"
{
  printf '%s  %s\n' "$API_BACKUP_SHA256" "$API_BACKUP"
  printf '%s  %s\n' "$EXTRACTOR_BACKUP_SHA256" "$EXTRACTOR_BACKUP"
  printf '%s  %s\n' "$CVE_SYNC_BACKUP_SHA256" "$CVE_SYNC_BACKUP"
  if [[ "$RECEIPT_HAD_EXISTING" -eq 1 ]]; then
    RECEIPT_BACKUP_SHA256="$(sha256_file "$RECEIPT_BACKUP")"
    printf '%s  %s\n' "$RECEIPT_BACKUP_SHA256" "$RECEIPT_BACKUP"
  fi
} > "$BACKUP_DIGEST_FILE"
chown root:root "$BACKUP_DIGEST_FILE"
chmod 0600 "$BACKUP_DIGEST_FILE"
if [[ "$RECEIPT_HAD_EXISTING" -eq 1 ]]; then
  chown root:root "$RECEIPT_BACKUP"
  chmod 0600 "$RECEIPT_BACKUP"
fi
echo "backed up to $API_BACKUP, $EXTRACTOR_BACKUP and $CVE_SYNC_BACKUP"

SECURE_DIRS=(
  "$(dirname "$(dirname "$API_BIN")")" "$(dirname "$(dirname "$EXTRACTOR_BIN")")"
  "$(dirname "$API_BIN")" "$(dirname "$EXTRACTOR_BIN")" "$(dirname "$CVE_SYNC_BIN")"
  "$(dirname "$DEPLOY_RECEIPT")"
)
# INVARIANT: this capture must run before ANY chown/chmod of SECURE_DIRS —
# the only one in the normal path is "Swapping in new binaries" below — so
# rollback() restores the true pre-deploy ownership/mode rather than the
# root:root 755 this script itself asserts during install. Do not move this
# loop later, and do not add an earlier chown/chmod of these paths.
PRE_DIR_OWNERS=()
PRE_DIR_MODES=()
for dir in "${SECURE_DIRS[@]}"; do
  dir_state="$(stat -c '%U:%G %a' "$dir")"
  PRE_DIR_OWNERS+=("${dir_state% *}")
  PRE_DIR_MODES+=("${dir_state##* }")
done

# ---------------------------------------------------------------------------
# Defined here — after the backups exist, before any swap/restart — so it is
# wired into the very FIRST restart (a non-zero `systemctl restart` under set -e
# would otherwise abort the script before the smoke-test rollback is reached,
# leaving the new binary in place with a possibly-stopped service).
#
# Binary rollback is safe only while applied migrations stay backward-compatible
# with the previous binary — i.e. new (0056+) migrations follow expand/contract
# per migrations/README.md. A destructive migration shipped in the same release
# would need manual recovery; the warning below flags that case loudly rather
# than silently restoring an old binary against an incompatible schema.
rollback() {
  local exit_code="${1:-1}"
  local failed_line="${2:-unknown}"
  # First statement, before anything that could itself fail: the EXIT trap uses
  # this to tell "rollback never ran" from "rollback ran", and a rollback that
  # dies part-way must read as the second, not the first.
  ROLLBACK_ATTEMPTED=1
  trap - ERR
  set +e
  local rollback_failed=0
  echo "DEPLOY FAILED at line $failed_line — rolling back binaries to pre-deploy versions" >&2
  if [[ "${pending_count:-0}" -gt 0 ]]; then
    # A Persistent timer must never run the pre-deploy synchroniser against a
    # schema advanced by this failed release. Stop it even if smoke testing had
    # already restored it, and leave it disabled until this release succeeds.
    TIMER_RESTORE_BLOCKED=1
    if "$SYSTEMCTL" stop patched-cve-sync.timer; then
      TIMER_STOPPED=1
    else
      echo "ROLLBACK ERROR: could not keep patched-cve-sync.timer disabled after migration" >&2
      rollback_failed=1
    fi
    if [[ "$TOOLING_TIMER_MANAGED" -eq 0 ]]; then
      :
    elif "$SYSTEMCTL" stop patched-tooling-cve-refresh.timer; then
      TOOLING_TIMER_STOPPED=1
    else
      echo "ROLLBACK ERROR: could not keep patched-tooling-cve-refresh.timer disabled after migration" >&2
      rollback_failed=1
    fi
  fi
  rm -f "${API_BIN}.new" "${EXTRACTOR_BIN}.new" "${CVE_SYNC_BIN}.new" "${DEPLOY_RECEIPT}.new"
  if [[ "$(stat -c '%U:%G %a' "$BACKUP_DIR")" != "root:root 700" ||
        "$(stat -c '%U:%G %a' "$BACKUP_DIGEST_FILE")" != "root:root 600" ]]; then
    echo "ROLLBACK ERROR: rollback directory or digest record is not root-controlled" >&2
    rollback_failed=1
  fi
  atomic_restore() {
    local backup="$1"
    local destination="$2"
    local expected_digest="$3"
    local restore_tmp="${destination}.rollback-new"
    rm -f "$restore_tmp"
    if [[ "$(stat -c '%U:%G %a' "$backup")" != "root:root 600" ||
          "$(sha256_file "$backup")" != "$expected_digest" ]] ||
       ! grep -qxF "$expected_digest  $backup" "$BACKUP_DIGEST_FILE"; then
      echo "ROLLBACK ERROR: untrusted or corrupted rollback source $backup" >&2
      rollback_failed=1
      return 1
    fi
    if ! cp -a "$backup" "$restore_tmp" || ! mv -f "$restore_tmp" "$destination"; then
      echo "ROLLBACK ERROR: could not atomically restore $destination" >&2
      rm -f "$restore_tmp"
      rollback_failed=1
    fi
  }
  atomic_restore "$API_BACKUP" "$API_BIN" "$API_BACKUP_SHA256"
  atomic_restore "$EXTRACTOR_BACKUP" "$EXTRACTOR_BIN" "$EXTRACTOR_BACKUP_SHA256"
  atomic_restore "$CVE_SYNC_BACKUP" "$CVE_SYNC_BIN" "$CVE_SYNC_BACKUP_SHA256"
  chown root:root "$API_BIN" "$EXTRACTOR_BIN" "$CVE_SYNC_BIN" || rollback_failed=1
  chmod 0755 "$API_BIN" "$EXTRACTOR_BIN" "$CVE_SYNC_BIN" || rollback_failed=1
  for ((i = 0; i < ${#SECURE_DIRS[@]}; i++)); do
    chown "${PRE_DIR_OWNERS[$i]}" "${SECURE_DIRS[$i]}" || rollback_failed=1
    chmod "${PRE_DIR_MODES[$i]}" "${SECURE_DIRS[$i]}" || rollback_failed=1
  done
  if [[ "$rollback_failed" -ne 0 ]]; then
    # Never retain a success receipt when installed bytes could not be restored.
    rm -f "$DEPLOY_RECEIPT" || true
  elif [[ "$RECEIPT_HAD_EXISTING" -eq 1 ]]; then
    atomic_restore "$RECEIPT_BACKUP" "$DEPLOY_RECEIPT" "$RECEIPT_BACKUP_SHA256"
    if [[ "$rollback_failed" -eq 0 ]]; then
      chown root:root "$DEPLOY_RECEIPT" || rollback_failed=1
      chmod 0644 "$DEPLOY_RECEIPT" || rollback_failed=1
    fi
    [[ "$rollback_failed" -eq 0 ]] || rm -f "$DEPLOY_RECEIPT"
  else
    rm -f "$DEPLOY_RECEIPT" || rollback_failed=1
  fi
  if [[ "$TIMER_STOPPED" -eq 1 && "$TIMER_RESTORE_BLOCKED" -eq 0 ]]; then
    if "$SYSTEMCTL" start patched-cve-sync.timer; then
      TIMER_STOPPED=0
    else
      rollback_failed=1
    fi
  fi
  if [[ "$TOOLING_TIMER_STOPPED" -eq 1 && "$TIMER_RESTORE_BLOCKED" -eq 0 ]]; then
    if "$SYSTEMCTL" start patched-tooling-cve-refresh.timer; then
      TOOLING_TIMER_STOPPED=0
    else
      echo "ROLLBACK ERROR: could not restore patched-tooling-cve-refresh.timer" >&2
      rollback_failed=1
    fi
  fi
  "$SYSTEMCTL" restart patched-api.service patched-extractor.service || rollback_failed=1
  if [[ "${pending_count:-0}" -gt 0 ]]; then
    record_migration_recovery "binaries rolled back after forward migration; timer intentionally disabled" || rollback_failed=1
    echo "RECOVERY REQUIRED: $pending_count forward migration(s) remain applied; patched-cve-sync.timer is disabled" >&2
    echo "Complete the verified full deploy before enabling the Persistent timer." >&2
  fi
  echo "Staging left in place for investigation: $STAGING_DIR" >&2
  if [[ "$rollback_failed" -ne 0 ]]; then
    echo "ROLLBACK FAILED: manual recovery is required; receipt may not describe installed files" >&2
    record_binary_rollback_required "rollback ran but could not restore every pre-deploy binary" || true
  else
    ROLLBACK_COMPLETED=1
    rm -f "$BINARY_RECOVERY_EVIDENCE" || true
  fi
  exit "$exit_code"
}

# From this point onward, every unexpected install/smoke failure restores all
# three binaries and the last successful provenance receipt.
trap 'rollback "$?" "$LINENO"' ERR
DEPLOY_PHASE=installing

# ---------------------------------------------------------------------------
log "Swapping in new binaries"
# All production executables live in root-controlled directories. The service
# accounts may execute the root-owned binaries but cannot replace production code.
chown root:root "${SECURE_DIRS[@]}"
chmod 0755 "${SECURE_DIRS[@]}"
cp "$NEW_API_BIN" "${API_BIN}.new"
cp "$NEW_EXTRACTOR_BIN" "${EXTRACTOR_BIN}.new"
cp "$NEW_CVE_SYNC_BIN" "${CVE_SYNC_BIN}.new"
chown root:root "${API_BIN}.new" "${EXTRACTOR_BIN}.new" "${CVE_SYNC_BIN}.new"
chmod 0755 "${API_BIN}.new" "${EXTRACTOR_BIN}.new" "${CVE_SYNC_BIN}.new"
mv -f "${API_BIN}.new" "$API_BIN"
mv -f "${EXTRACTOR_BIN}.new" "$EXTRACTOR_BIN"
if ! cve_sync_state_is_safe; then
  echo "patched-cve-sync.service started while installing long-running binaries" >&2
  false
fi
mv -f "${CVE_SYNC_BIN}.new" "$CVE_SYNC_BIN"

for dir in "${SECURE_DIRS[@]}"; do
  [[ "$(stat -c '%U:%G %a' "$dir")" == "root:root 755" ]] || { echo "binary directory invariant failed for $dir" >&2; false; }
done
for bin in "$API_BIN" "$EXTRACTOR_BIN" "$CVE_SYNC_BIN"; do
  [[ "$(stat -c '%U:%G %a' "$bin")" == "root:root 755" ]] || { echo "binary ownership invariant failed for $bin" >&2; false; }
done

INSTALLED_API_SHA256="$(sha256_file "$API_BIN")"
INSTALLED_EXTRACTOR_SHA256="$(sha256_file "$EXTRACTOR_BIN")"
INSTALLED_CVE_SYNC_SHA256="$(sha256_file "$CVE_SYNC_BIN")"
[[ "$INSTALLED_API_SHA256" == "$EXPECTED_API_SHA256" ]] || { echo "patched-api installed hash mismatch" >&2; false; }
[[ "$INSTALLED_EXTRACTOR_SHA256" == "$EXPECTED_EXTRACTOR_SHA256" ]] || { echo "patched-extractor installed hash mismatch" >&2; false; }
[[ "$INSTALLED_CVE_SYNC_SHA256" == "$EXPECTED_CVE_SYNC_SHA256" ]] || { echo "patched-cve-sync installed hash mismatch" >&2; false; }

log "Restarting services"
"$SYSTEMCTL" restart patched-api.service patched-extractor.service

# Keep this inside the binary rollback trap. A hardening regression therefore
# restores and restarts the binaries changed by this deploy rather than being
# discovered only after the new application release has committed.
"$HARDENING_GUARD" patched-api.service patched-extractor.service patched-cve-sync.service

log "Smoke test"
sleep "$SMOKE_DELAY_SECONDS"

if ! "$SYSTEMCTL" is-active --quiet patched-api.service; then
  echo "patched-api.service is not active" >&2
  false
fi
if ! "$SYSTEMCTL" is-active --quiet patched-extractor.service; then
  echo "patched-extractor.service is not active" >&2
  false
fi

health_status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8080/health || echo "000")"
if [[ "$health_status" != "200" ]]; then
  echo "GET /health returned $health_status (expected 200)" >&2
  false
fi

table_check="$(psql -d "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc "SELECT to_regclass('device_agent_health')" | tr -d ' ')"
if [[ -z "$table_check" ]]; then
  echo "device_agent_health table not found (0090_agent_health.sql not applied?)" >&2
  false
fi

if ! cve_sync_state_is_safe; then
  echo "patched-cve-sync.service became active while its timer was quiesced" >&2
  false
fi
CVE_INVOCATION_AFTER="$("$SYSTEMCTL" show patched-cve-sync.service --property=InvocationID --value | tr -d '[:space:]')"
# Exact equality, empty-to-empty included (PAT-1748): empty->set means this
# deploy window started the oneshot, set->empty or set->different means its
# invocation record changed. Both fail and roll back.
if [[ "$CVE_INVOCATION_AFTER" != "$CVE_INVOCATION_BEFORE" ]]; then
  echo "patched-cve-sync.service invocation changed while timer was quiesced: before='${CVE_INVOCATION_BEFORE}' after='${CVE_INVOCATION_AFTER}'" >&2
  false
fi
TOOLING_INVOCATION_AFTER="$TOOLING_INVOCATION_BEFORE"
if [[ "$TOOLING_TIMER_MANAGED" -eq 1 ]]; then
  TOOLING_INVOCATION_AFTER="$("$SYSTEMCTL" show patched-tooling-cve-refresh.service --property=InvocationID --value | tr -d '[:space:]')"
fi
if [[ "$TOOLING_TIMER_MANAGED" -eq 1 && "$TOOLING_INVOCATION_AFTER" != "$TOOLING_INVOCATION_BEFORE" ]]; then
  echo "patched-tooling-cve-refresh.service invocation changed while timer was quiesced" >&2
  exit 1
fi

restore_timer_after_deploy
if ! "$SYSTEMCTL" is-enabled --quiet patched-cve-sync.timer; then
  echo "patched-cve-sync.timer lost its enabled state" >&2
  false
fi
if ! "$SYSTEMCTL" is-active --quiet patched-cve-sync.timer; then
  echo "patched-cve-sync.timer is no longer active" >&2
  false
fi
if [[ "$TOOLING_TIMER_MANAGED" -eq 1 ]]; then
  if ! "$SYSTEMCTL" is-enabled --quiet patched-tooling-cve-refresh.timer ||
     ! "$SYSTEMCTL" is-active --quiet patched-tooling-cve-refresh.timer; then
    echo "patched-tooling-cve-refresh.timer was not restored" >&2
    exit 1
  fi
fi

echo "services active, /health returned 200, device_agent_health present, CVE timer retained"
log "Smoke test passed"

# Re-verify at the receipt boundary. The initial smoke test (is-active +
# /health) only proves the two long-running services were healthy at that
# instant; it cannot prove they stayed up through the CVE/timer verification
# window above. Never write a receipt claiming a healthy install without a
# second, closer-to-commit liveness check on both.
if ! "$SYSTEMCTL" is-active --quiet patched-api.service; then
  echo "patched-api.service is not active at receipt boundary" >&2
  false
fi
if ! "$SYSTEMCTL" is-active --quiet patched-extractor.service; then
  echo "patched-extractor.service is not active at receipt boundary" >&2
  false
fi

# Re-read the database at the receipt boundary. A deploy receipt must never
# claim a migration head that was absent from the staged set or disappeared
# from schema_migrations during the service/timer validation window.
verify_manifest_migration_head

# Durable on-box provenance. The receipt is written only after service, timer
# and byte-identity checks pass, and is restored with the binaries on rollback.
receipt_tmp="${DEPLOY_RECEIPT}.new"
{
  printf 'DEPLOYED_SHA=%s\n' "$BUILD_SHA"
  printf 'MIGRATION_HEAD=%s\n' "$MIGRATION_HEAD"
  printf 'DEPLOYED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'patched-api=%s\n' "$INSTALLED_API_SHA256"
  printf 'patched-extractor=%s\n' "$INSTALLED_EXTRACTOR_SHA256"
  printf 'patched-cve-sync=%s\n' "$INSTALLED_CVE_SYNC_SHA256"
} > "$receipt_tmp"
chown root:root "$receipt_tmp"
chmod 0644 "$receipt_tmp"
mv -f "$receipt_tmp" "$DEPLOY_RECEIPT"
DEPLOY_PHASE=committed

# The atomic receipt is the commit point. Reporting, pruning and staging
# cleanup must never roll back a successfully installed and proven release.
trap - ERR
rm -f "$RECOVERY_EVIDENCE" || echo "WARNING: could not remove stale recovery evidence" >&2
rm -f "$BINARY_RECOVERY_EVIDENCE" || echo "WARNING: could not remove stale binary rollback evidence" >&2

log "Installed binary provenance"
cat "$DEPLOY_RECEIPT" || echo "WARNING: could not print deploy receipt" >&2
"$SYSTEMCTL" list-timers --all patched-cve-sync.timer patched-tooling-cve-refresh.timer --no-pager || echo "WARNING: could not print CVE timers" >&2

prune_backup_family() {
  local pattern="$1"
  local backup
  local -a backups=()
  for backup in "$BACKUP_DIR"/$pattern; do
    [[ -f "$backup" ]] || continue
    backups+=("$backup")
  done
  [[ "${backups[0]+set}" == set ]] || return 0
  for ((i = 0; i < ${#backups[@]} - MAX_BACKUPS; i++)); do
    rm -f "${backups[$i]}"
  done
}

for deployed_file in "$API_BIN" "$EXTRACTOR_BIN" "$CVE_SYNC_BIN" "$DEPLOY_RECEIPT"; do
  prune_backup_family "$(basename "$deployed_file").bak-*" || echo "WARNING: could not prune backups for $deployed_file" >&2
done
prune_backup_family "ROLLBACK_SHA256-*" || echo "WARNING: could not prune rollback digest records" >&2

# ---------------------------------------------------------------------------
log "Cleaning up staging directory"
if [[ "${PATCHED_DEPLOY_KEEP_STAGING:-0}" != "1" ]]; then
  validate_staging_dir "$STAGING_DIR" || {
    echo "WARNING: refusing unsafe staging cleanup target $STAGING_DIR" >&2
    exit 1
  }
  rm -rf "$STAGING_DIR" || echo "WARNING: could not remove staging directory $STAGING_DIR" >&2
fi
echo "production binary deploy completed successfully"
