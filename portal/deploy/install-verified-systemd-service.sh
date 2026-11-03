#!/usr/bin/env bash
# Transactional systemd install helpers shared by both portal installers.

resolved_systemd_dir() {
  if [[ "${PATCHED_SYSTEMD_TEST_MODE:-0}" == 1 ]]; then
    [[ "$EUID" -ne 0 ]] || { echo "systemd test override is refused for root installs" >&2; return 1; }
    printf '%s\n' "${PATCHED_SYSTEMD_DIR:?test mode requires PATCHED_SYSTEMD_DIR}"
  else
    [[ -z "${PATCHED_SYSTEMD_DIR:-}" ]] || { echo "PATCHED_SYSTEMD_DIR is test-only" >&2; return 1; }
    printf '%s\n' /etc/systemd/system
  fi
}

validate_deploy_source() {
  local source="$1" owner mode allowed_uid="${SUDO_UID:-$(id -u)}"
  [[ -f "$source" && ! -L "$source" ]] || { echo "deployment source is missing or untrusted: $source" >&2; return 1; }
  owner="$(stat -c '%u' "$source" 2>/dev/null || stat -f '%u' "$source")" || return 1
  mode="$(stat -c '%a' "$source" 2>/dev/null || stat -f '%Lp' "$source")" || return 1
  [[ "$owner" == 0 || "$owner" == "$allowed_uid" ]] || { echo "deployment source has unexpected owner: $source" >&2; return 1; }
  (( (8#$mode & 0022) == 0 )) || { echo "deployment source is group/world writable: $source" >&2; return 1; }
}

restore_unit_file() {
  local target="$1" backup="$2" had="$3" changed="$4" mode="$5" uid="$6" gid="$7" stage
  rm -f "${PATCHED_INSTALL_STAGE:-}" || return 1
  [[ "$changed" == 1 ]] || return 0
  if [[ "$had" == 1 ]]; then
    stage="$(mktemp "${target}.pat1237-restore.XXXXXX")" || return 1
    if ! install -m "$mode" -o "$uid" -g "$gid" "$backup" "$stage" || ! mv -f "$stage" "$target"; then rm -f "$stage"; return 1; fi
  else
    rm -f "$target" || return 1
  fi
  systemctl daemon-reload || return 1
}

install_and_verify_service() (
  local unit="$1" source="$REPO_DIR/deploy/$1" systemd_dir target backup_dir backup fragment
  local had=0 changed=0 failure="" mode=0644 uid=0 gid=0
  systemd_dir="$(resolved_systemd_dir)" || return 1; target="$systemd_dir/$unit"
  validate_deploy_source "$source" || return 1
  validate_deploy_source "$REPO_DIR/deploy/verify-systemd-hardening-floor.sh" || return 1
  [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] || { echo "refusing non-regular installed systemd unit: $target" >&2; return 1; }
  mkdir -p "$systemd_dir" || return 1; backup_dir="$(mktemp -d)" || return 1; backup="$backup_dir/$unit"; PATCHED_INSTALL_STAGE=""
  trap 'rm -f "${PATCHED_INSTALL_STAGE:-}"; rm -rf "$backup_dir"' EXIT
  if [[ -f "$target" ]]; then
    mode="$(stat -c '%a' "$target" 2>/dev/null || stat -f '%Lp' "$target")"; uid="$(stat -c '%u' "$target" 2>/dev/null || stat -f '%u' "$target")"; gid="$(stat -c '%g' "$target" 2>/dev/null || stat -f '%g' "$target")"
    install -m 0600 "$target" "$backup" || { echo "could not back up existing $unit" >&2; return 1; }; had=1
  fi
  PATCHED_INSTALL_STAGE="$(mktemp "${target}.pat1237-new.XXXXXX")" || return 1
  # Invoked indirectly by trap.
  # shellcheck disable=SC2329
  on_signal() { trap - HUP INT TERM; if ! restore_unit_file "$target" "$backup" "$had" "$changed" "$mode" "$uid" "$gid"; then echo "CRITICAL: interrupted install could not restore $unit" >&2; exit 3; fi; exit 130; }
  trap on_signal HUP INT TERM
  if ! install -m 0644 "$source" "$PATCHED_INSTALL_STAGE"; then failure="could not stage $unit"
  elif { changed=1; ! mv -f "$PATCHED_INSTALL_STAGE" "$target"; }; then failure="could not promote $unit"
  else
    if ! systemctl daemon-reload; then failure="daemon-reload failed after installing $unit"
    else
      fragment="$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)"
      if [[ "$fragment" != "$target" ]]; then failure="installed fragment mismatch for $unit: systemd loaded ${fragment:-nothing}, expected $target"
      elif ! cmp -s "$source" "$fragment"; then failure="installed fragment content mismatch for $unit"
      elif [[ "$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)" != loaded ]]; then failure="installed unit did not load: $unit"
      elif ! "$REPO_DIR/deploy/verify-systemd-hardening-floor.sh" "$unit"; then failure="hardening floor rejected $unit"; fi
    fi
  fi
  if [[ -n "$failure" ]]; then
    if restore_unit_file "$target" "$backup" "$had" "$changed" "$mode" "$uid" "$gid"; then
      if [[ "$had" == 1 ]]; then echo "$failure; restored previous unit" >&2; else echo "$failure; removed rejected fresh install" >&2; fi
    else echo "CRITICAL: $failure and could not restore $unit" >&2; fi
    return 1
  fi
  trap - HUP INT TERM; echo "installed and verified $unit"
)

install_systemd_timer_atomically() (
  local unit="$1" source="$REPO_DIR/deploy/$1" systemd_dir target backup_dir backup fragment
  local had=0 changed=0 failure="" mode=0644 uid=0 gid=0
  systemd_dir="$(resolved_systemd_dir)" || return 1; target="$systemd_dir/$unit"
  validate_deploy_source "$source" || return 1
  [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] || { echo "refusing non-regular installed systemd timer: $target" >&2; return 1; }
  mkdir -p "$systemd_dir" || return 1; backup_dir="$(mktemp -d)" || return 1; backup="$backup_dir/$unit"; PATCHED_INSTALL_STAGE=""
  trap 'rm -f "${PATCHED_INSTALL_STAGE:-}"; rm -rf "$backup_dir"' EXIT
  if [[ -f "$target" ]]; then
    mode="$(stat -c '%a' "$target" 2>/dev/null || stat -f '%Lp' "$target")"; uid="$(stat -c '%u' "$target" 2>/dev/null || stat -f '%u' "$target")"; gid="$(stat -c '%g' "$target" 2>/dev/null || stat -f '%g' "$target")"
    install -m 0600 "$target" "$backup" || { echo "could not back up existing timer $unit" >&2; return 1; }; had=1
  fi
  PATCHED_INSTALL_STAGE="$(mktemp "${target}.pat1237-new.XXXXXX")" || return 1
  # Invoked indirectly by trap.
  # shellcheck disable=SC2329
  on_signal() { trap - HUP INT TERM; if ! restore_unit_file "$target" "$backup" "$had" "$changed" "$mode" "$uid" "$gid"; then echo "CRITICAL: interrupted install could not restore timer $unit" >&2; exit 3; fi; exit 130; }
  trap on_signal HUP INT TERM
  if ! install -m 0644 "$source" "$PATCHED_INSTALL_STAGE"; then failure="could not stage timer $unit"
  elif { changed=1; ! mv -f "$PATCHED_INSTALL_STAGE" "$target"; }; then failure="could not promote timer $unit"
  else
    if ! systemctl daemon-reload; then failure="daemon-reload failed after installing timer $unit"
    else
      fragment="$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)"
      if [[ "$fragment" != "$target" ]]; then failure="installed timer fragment mismatch for $unit"
      elif ! cmp -s "$source" "$fragment"; then failure="installed timer content mismatch for $unit"
      elif [[ "$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)" != loaded ]]; then failure="installed timer did not load: $unit"; fi
    fi
  fi
  if [[ -n "$failure" ]]; then
    if restore_unit_file "$target" "$backup" "$had" "$changed" "$mode" "$uid" "$gid"; then echo "$failure; restored previous timer state" >&2; else echo "CRITICAL: $failure and could not restore timer $unit" >&2; fi
    return 1
  fi
  trap - HUP INT TERM; echo "installed and verified $unit"
)
