# filesystem.sh — file system integrity signals.
# Uses find to detect world-writable items and insecure home folder permissions.
# Sourced by patched-collect.sh; not executable directly.

collect_filesystem() {
    # §5.1.1 — Home folder permissions (mode must be 700 or 711)
    local _bad_homes
    _bad_homes=$(find /System/Volumes/Data/Users \
        -mindepth 1 -maxdepth 1 -type d \
        ! \( -perm 700 -o -perm 711 \) 2>/dev/null | \
        grep -vE '/(Shared|Guest)$' | wc -l | tr -d ' ')
    if (( _bad_homes == 0 )); then HOME_FOLDERS_MODE="Yes"; else HOME_FOLDERS_MODE="No"; fi

    # §5.1.5 — No world-writable .app bundles in /Applications
    local _ww_apps
    _ww_apps=$(find /Applications -iname "*.app" -type d -perm -2 2>/dev/null | wc -l | tr -d ' ')
    if (( _ww_apps == 0 )); then SYSTEM_APPS_WORLD_WRITABLE="Yes"; else SYSTEM_APPS_WORLD_WRITABLE="No"; fi

    # §5.1.6 — No world-writable directories in /System/Volumes/Data/System
    # Known-legitimate exclusions: downloadDir and locks (Apple-owned, transient)
    local _ww_sys
    _ww_sys=$(find /System/Volumes/Data/System -type d -perm -2 2>/dev/null | \
        grep -vE '(downloadDir|locks)' | wc -l | tr -d ' ')
    if (( _ww_sys == 0 )); then SYSTEM_FOLDER_WORLD_WRITABLE="Yes"; else SYSTEM_FOLDER_WORLD_WRITABLE="No"; fi
}
