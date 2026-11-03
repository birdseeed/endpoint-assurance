# os.sh — OS version and last boot time.
# Sourced by patched-collect.sh; not executable directly.

collect_os() {
    OS_NAME=$(sw_vers -productName)
    OS_VERSION=$(sw_vers -productVersion)
    OS_BUILD=$(sw_vers -buildVersion)

    LAST_BOOT=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[ ,]' '{print $4}' || echo "0")
    if [[ "$LAST_BOOT" != "0" ]]; then
        LAST_BOOT_ISO=$(date -u -r "$LAST_BOOT" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "Unknown")
    else
        LAST_BOOT_ISO="Unknown"
    fi

    # §2.9 — Power management (power nap + wake for network access).
    # pmset -g custom shows per-profile values; sum across all profiles.
    # A sum of 0 means the feature is off in every profile (pass).
    # If pmset is unavailable (e.g. desktop Mac with no battery profile), we
    # default "Yes" because the feature simply doesn't apply.
    local _PMSET_OUT _PNAP _WOMP
    _PMSET_OUT=$(pmset -g custom 2>/dev/null || true)
    _PNAP=$(printf '%s\n' "$_PMSET_OUT" | awk '/powernap/{sum+=$2} END {print sum+0}')
    if [[ "${_PNAP:-0}" -eq 0 ]]; then
        POWER_NAP_DISABLED="Yes"
    else
        POWER_NAP_DISABLED="No"
    fi
    _WOMP=$(printf '%s\n' "$_PMSET_OUT" | awk '/womp/{sum+=$2} END {print sum+0}')
    if [[ "${_WOMP:-0}" -eq 0 ]]; then
        WAKE_ON_NETWORK_DISABLED="Yes"
    else
        WAKE_ON_NETWORK_DISABLED="No"
    fi
}
