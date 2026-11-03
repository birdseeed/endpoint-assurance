# backup.sh — macOS backup status: Time Machine, OneDrive/iCloud sync, and
# third-party backup tools (Backblaze, Arq, Carbon Copy Cloner).
# Sets BACKUP_STATUS_JSON_TMP (path to the temp JSON object file) — consumed
# via $(cat "$BACKUP_STATUS_JSON_TMP") in the heredoc, same convention as
# HARDWARE_HEALTH_JSON_TMP/CERTS_JSON_TMP. Deliberately NOT a plain
# BACKUP_STATUS_JSON var with a `${VAR:-{...}}` default — nested braces in a
# parameter-expansion default corrupt in both zsh and bash (see workspace
# footgun note: grep `:-{` in agent shell code).
# Requires: FIRST_USER (set by collect_hardware), TS_UTC, PATCHED_TMPDIR, PYTHON3
# Sourced by patched-collect.sh; not executable directly.

collect_backup_status() {
    BACKUP_STATUS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/backup-status.XXXXXX")  # H11: root-owned 0700 dir, not /tmp

    local _tm_raw
    _tm_raw=$(tmutil latestbackup 2>/dev/null) || true

    local _user_home=""
    if [[ -n "$FIRST_USER" ]]; then
        _user_home=$(dscl . read /Users/"$FIRST_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    fi

    # OneDrive is sync, not backup (design decision, PAT-679) — presence-only
    # check; we don't parse the sync-state DB, just whether OneDrive is set up.
    local _onedrive_present="false"
    if [[ -n "$_user_home" ]]; then
        if [[ -d "$_user_home/Library/Application Support/OneDrive" ]]; then
            _onedrive_present="true"
        else
            for _od_candidate in "$_user_home"/Library/Containers/com.microsoft.OneDrive*; do
                [[ -d "$_od_candidate" ]] && _onedrive_present="true" && break
            done
        fi
    fi

    # iCloud Drive: the "Mobile Documents" folder only exists once iCloud
    # Drive has been enabled for this user — simpler and more reliable than
    # walking per-app NSUbiquitousContainers entries for a presence check.
    local _icloud_present="false"
    [[ -n "$_user_home" && -d "$_user_home/Library/Mobile Documents" ]] && _icloud_present="true"

    # Third-party backup tools: presence-only. None of these expose a single
    # reliable command for "last completed backup" the way tmutil does, so we
    # don't guess from log mtimes — last_backup_at stays null for these.
    local _thirdparty=""
    if [[ -d "/Applications/Backblaze.app" ]]; then
        _thirdparty="backblaze"
    else
        for _arq_candidate in /Applications/Arq*.app; do
            [[ -d "$_arq_candidate" ]] && _thirdparty="arq" && break
        done
        if [[ -z "$_thirdparty" && -d "/Applications/Carbon Copy Cloner.app" ]]; then
            _thirdparty="carbon_copy_cloner"
        fi
    fi

    local _backup_status_json
    _backup_status_json=$("$PYTHON3" - "$_tm_raw" "$_onedrive_present" "$_icloud_present" "$_thirdparty" "$TS_UTC" <<'PYEOF'
import sys, json, re, time
from datetime import datetime, timezone

tm_raw, onedrive_present, icloud_present, thirdparty, collected_at = sys.argv[1:6]

now = datetime.strptime(collected_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

result = {
    "has_backup": False,
    "backup_type": None,
    "last_backup_at": None,
    "last_backup_days_ago": None,
    "stale": False,
    "sync_only": False,
    "notes": None,
}

# tmutil latestbackup prints a path ending in a local-time directory name
# (YYYY-MM-DD-HHMMSS[.backup]). time.mktime/strptime use the process's local
# timezone (inherited from the OS), matching how tmutil generated the name.
tm_at = None
m = re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})(?:\.backup)?/?$", tm_raw.strip()) if tm_raw else None
if m:
    try:
        epoch = time.mktime(time.strptime(m.group(1), "%Y-%m-%d-%H%M%S"))
        tm_at = datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        tm_at = None

if tm_at is not None:
    # Clamp to 0: TS_UTC is captured once at script start, several collector
    # modules before this one runs, so a backup that completes during that
    # window can be fractionally "later" than TS_UTC — floor division on a
    # small negative timedelta would otherwise read as -1 days ago.
    days_ago = max(0, (now - tm_at).days)
    result.update({
        "has_backup": True,
        "backup_type": "time_machine",
        "last_backup_at": tm_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_backup_days_ago": days_ago,
        "stale": days_ago > 7,
    })
elif thirdparty:
    result.update({
        "has_backup": True,
        "backup_type": thirdparty,
        "notes": f"{thirdparty} detected; last backup timestamp not available",
    })
elif onedrive_present == "true":
    result.update({
        "backup_type": "onedrive_sync",
        "sync_only": True,
        "notes": "OneDrive sync detected; sync is not a substitute for backup",
    })
elif icloud_present == "true":
    result.update({
        "backup_type": "icloud_sync",
        "sync_only": True,
        "notes": "iCloud Drive sync detected; sync is not a substitute for backup",
    })
else:
    result["notes"] = "No backup solution detected"

print(json.dumps(result))
PYEOF
    ) || true

    printf '%s' "${_backup_status_json:-}" | "$PYTHON3" -c "import json,sys; json.loads(sys.stdin.read())" 2>/dev/null \
        || _backup_status_json='{"has_backup":false,"backup_type":null,"last_backup_at":null,"last_backup_days_ago":null,"stale":false,"sync_only":false,"notes":null}'

    printf '%s' "$_backup_status_json" > "$BACKUP_STATUS_JSON_TMP"
}
