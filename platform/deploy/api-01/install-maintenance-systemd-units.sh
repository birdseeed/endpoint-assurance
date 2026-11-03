#!/usr/bin/env bash
# Transactionally install the maintenance facts unit pair, then enforce the
# PAT-1237 hardening floor before leaving the new loaded definition in place.
set -euo pipefail

SOURCE_DIR="${1:-/opt/patched-systemd-staging}"
SYSTEMD_DIR="${PATCHED_SYSTEMD_DIR:-/etc/systemd/system}"
SYSTEMCTL="${PATCHED_SYSTEMCTL:-systemctl}"
SERVICE=patched-maintenance-facts.service
TIMER=patched-maintenance-facts.timer
GUARD="$SOURCE_DIR/verify-systemd-hardening-floor.sh"

for source in "$SOURCE_DIR/$SERVICE" "$SOURCE_DIR/$TIMER" "$GUARD"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "missing trusted deployment source: $source" >&2; exit 1; }
done

backup_dir="$(mktemp -d)"
declare -A had_target=()
declare -A target_mode=()
declare -A target_uid=()
declare -A target_gid=()
timer_enabled=0
timer_active=0
armed=1

enabled_rc=0; enabled_state="$($SYSTEMCTL is-enabled "$TIMER" 2>/dev/null)" || enabled_rc=$?
case "$enabled_state:$enabled_rc" in enabled:0) timer_enabled=1 ;; disabled:*|static:*|indirect:*) ;; *) echo "cannot determine prior enabled state for $TIMER" >&2; exit 1 ;; esac
active_rc=0; active_state="$($SYSTEMCTL is-active "$TIMER" 2>/dev/null)" || active_rc=$?
case "$active_state:$active_rc" in active:0) timer_active=1 ;; inactive:*|failed:*) ;; *) echo "cannot determine prior active state for $TIMER" >&2; exit 1 ;; esac

# Capture every rollback decision before arming traps or changing either unit.
# A failure while installing the first unit must never make the unset state for
# the second unit look like "fresh install" and delete that untouched live file.
for unit in "$SERVICE" "$TIMER"; do
  target="$SYSTEMD_DIR/$unit"
  had_target[$unit]=0
  if [[ -f "$target" && ! -L "$target" ]]; then
    target_mode[$unit]="$(stat -c '%a' "$target")"
    target_uid[$unit]="$(stat -c '%u' "$target")"
    target_gid[$unit]="$(stat -c '%g' "$target")"
    install -m 0600 "$target" "$backup_dir/$unit"
    had_target[$unit]=1
  elif [[ -e "$target" ]]; then
    echo "refusing non-regular installed systemd unit: $target" >&2
    rm -rf "$backup_dir"
    exit 1
  fi
done

rollback_units() {
  local exit_code="${1:-1}" unit target restore_stage rollback_failed=0
  trap - EXIT HUP INT TERM
  if [[ "$armed" == "1" ]]; then
    # A fresh timer has no prior runtime state to restore. Disable it while its
    # just-loaded definition still exists; a non-zero command is harmless only
    # when systemd confirms it is already disabled and inactive.
    if [[ "${had_target[$TIMER]}" == "0" ]]; then
      if ! "$SYSTEMCTL" disable --now "$TIMER"; then
        current_enabled_rc=0; current_enabled="$($SYSTEMCTL is-enabled "$TIMER" 2>/dev/null)" || current_enabled_rc=$?
        current_active_rc=0; current_active="$($SYSTEMCTL is-active "$TIMER" 2>/dev/null)" || current_active_rc=$?
        [[ "$current_enabled:$current_enabled_rc" == disabled:* || "$current_enabled:$current_enabled_rc" == static:* ]] || rollback_failed=1
        [[ "$current_active:$current_active_rc" == inactive:* || "$current_active:$current_active_rc" == failed:* ]] || rollback_failed=1
      fi
    fi
    for unit in "$SERVICE" "$TIMER"; do
      target="$SYSTEMD_DIR/$unit"
      rm -f "${target}.pat1237-new"
      if [[ "${had_target[$unit]:-0}" == "1" ]]; then
        restore_stage="${target}.pat1237-restore"
        if ! install -m "${target_mode[$unit]}" -o "${target_uid[$unit]}" -g "${target_gid[$unit]}" "$backup_dir/$unit" "$restore_stage" || ! mv -f "$restore_stage" "$target"; then
          rm -f "$restore_stage"
          rollback_failed=1
        fi
      elif ! rm -f "$target"; then
        rollback_failed=1
      fi
    done
    "$SYSTEMCTL" daemon-reload || rollback_failed=1
    if [[ "${had_target[$TIMER]}" == "1" ]]; then
      if [[ "$timer_enabled" == "1" ]]; then
        "$SYSTEMCTL" enable "$TIMER" || rollback_failed=1
      elif ! "$SYSTEMCTL" disable "$TIMER"; then
        current_enabled_rc=0; current_enabled="$($SYSTEMCTL is-enabled "$TIMER" 2>/dev/null)" || current_enabled_rc=$?
        [[ "$current_enabled:$current_enabled_rc" == disabled:* || "$current_enabled:$current_enabled_rc" == static:* ]] || rollback_failed=1
      fi
      if [[ "$timer_active" == "1" ]]; then
        "$SYSTEMCTL" start "$TIMER" || rollback_failed=1
      elif ! "$SYSTEMCTL" stop "$TIMER"; then
        current_active_rc=0; current_active="$($SYSTEMCTL is-active "$TIMER" 2>/dev/null)" || current_active_rc=$?
        [[ "$current_active:$current_active_rc" == inactive:* || "$current_active:$current_active_rc" == failed:* ]] || rollback_failed=1
      fi
    fi
  fi
  rm -rf "$backup_dir"
  if [[ "$rollback_failed" != "0" ]]; then
    echo "CRITICAL: maintenance systemd unit rollback failed" >&2
    exit 3
  fi
  exit "$exit_code"
}
trap 'rollback_units "$?"' EXIT
trap 'rollback_units 130' HUP INT TERM

mkdir -p "$SYSTEMD_DIR"
for unit in "$SERVICE" "$TIMER"; do
  target="$SYSTEMD_DIR/$unit"
  install -m 0644 "$SOURCE_DIR/$unit" "${target}.pat1237-new"
  mv -f "${target}.pat1237-new" "$target"
done

"$SYSTEMCTL" daemon-reload
"$SYSTEMCTL" enable --now "$TIMER"
# This transaction owns only the maintenance unit pair. Application binaries
# and their units are scored inside deploy.sh, where binary rollback is armed.
"$GUARD" "$SERVICE"

armed=0
trap - EXIT HUP INT TERM
rm -rf "$backup_dir"
