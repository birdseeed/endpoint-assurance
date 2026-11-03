# hardware.sh — device identity, hardware specs, and FIRST_USER.
# FIRST_USER is computed here (not in screensaver or icloud sections) so that
# screensaver.sh (fallback subject when no console user is logged in,
# PAT-1723), inventory.sh and backup.sh can rely on it being set.
# Sourced by patched-collect.sh; not executable directly.

collect_hardware() {
    # SERIAL and HW_UUID are "Unknown" unless ioreg itself succeeded AND a
    # non-empty value was extracted (PAT-1723, PAT-1724). The ioreg output is
    # captured before parsing: in a `ioreg | awk || echo Unknown` pipeline the
    # fallback tests awk's exit status, so a failed or empty ioreg left the
    # value empty.
    local serial_ioreg=""
    SERIAL=""
    if serial_ioreg=$(ioreg -l 2>/dev/null); then
        SERIAL=$(print -r -- "$serial_ioreg" | awk -F'"' '/IOPlatformSerialNumber/ {print $4; exit}')
    fi
    [[ -n "$SERIAL" ]] || SERIAL="Unknown"

    local hw_ioreg=""
    HW_UUID=""
    if hw_ioreg=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null); then
        HW_UUID=$(print -r -- "$hw_ioreg" | awk -F'"' '/IOPlatformUUID/ {print $4; exit}')
    fi
    [[ -n "$HW_UUID" ]] || HW_UUID="Unknown"
    HOSTNAME=$(scutil --get LocalHostName 2>/dev/null || hostname -s)
    COMPUTER_NAME=$(scutil --get ComputerName 2>/dev/null || hostname -s)
    HW_MODEL=$(sysctl -n hw.model 2>/dev/null || echo "Unknown")
    ARCH=$(uname -m)

    # First non-system user (UID 500–59999). Used by inventory.sh and
    # backup.sh for per-user plist reads, and by screensaver.sh only when no
    # console user is logged in (PAT-1723).
    FIRST_USER=$(dscl . list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $2 < 60000 {print $1; exit}')

    CPU_MODEL=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
    CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo 0)
    RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    RAM_GB=$(awk "BEGIN { printf \"%.0f\", ${RAM_BYTES:-0}/1024/1024/1024 }")

    # /System/Volumes/Data is the data volume on modern macOS (root is sealed).
    DISK_RAW=$(df -k /System/Volumes/Data 2>/dev/null | tail -1 || df -k / 2>/dev/null | tail -1)
    DISK_TOTAL_KB=$(echo "$DISK_RAW" | awk '{print $2}')
    DISK_FREE_KB=$(echo "$DISK_RAW" | awk '{print $4}')
    DISK_TOTAL_GB=$(awk "BEGIN { printf \"%.1f\", ${DISK_TOTAL_KB:-0}/1024/1024 }")
    DISK_FREE_GB=$(awk "BEGIN { printf \"%.1f\", ${DISK_FREE_KB:-0}/1024/1024 }")
}
