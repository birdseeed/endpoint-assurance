# security.sh — core security posture signals.
# Requires: ARCH (set by collect_hardware)
# Sourced by patched-collect.sh; not executable directly.

collect_security() {
    # FileVault (CIS 2.5.1.1 / mSCP 2.6.6)
    FILEVAULT=$(fdesetup status 2>/dev/null | awk '{print $3}' | tr -d '.' || echo "Unknown")

    # SIP (CIS 2.5.3 / mSCP 2.5.1)
    SIP=$(csrutil status 2>/dev/null | awk -F'[: ]+' '/status/ {print $NF}' | tr -d '.' || echo "Unknown")

    # Gatekeeper (CIS 2.5.2.1 / mSCP 2.5.2.1)
    GATEKEEPER=$(spctl --status 2>&1 | awk '{print $2}' || echo "Unknown")

    # Application Layer Firewall (CIS 2.5.2.2 / mSCP 2.2.1)
    FW_STATE_RAW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if [[ "$FW_STATE_RAW" == *"enabled"* ]]; then
        FW_STATE="enabled"
    elif [[ "$FW_STATE_RAW" == *"disabled"* ]]; then
        FW_STATE="disabled"
    else
        FW_STATE="Unknown"
    fi

    # XProtect + MRT (anti-malware definitions)
    XPROTECT_VER=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>/dev/null || echo "Unknown")
    MRT_VER=$(defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info CFBundleShortVersionString 2>/dev/null || echo "Unknown")

    # Sealed System Volume (CIS 2.5.5)
    SSV=$(csrutil authenticated-root status 2>/dev/null | awk -F': ' '/Authenticated/ {print $2}' | tr -d '.' || echo "Unknown")
    [[ -z "$SSV" ]] && SSV="Unknown"

    # Secure Boot integrity (Apple Silicon only; macOS 26: parse "Pairing Integrity")
    SECURE_BOOT="Unknown"
    if [[ "$ARCH" == "arm64" ]]; then
        SECURE_BOOT_RAW=$(bputil --display-all-policies 2>/dev/null | awk -F': +' '/Pairing Integrity/ {print $2; exit}' || true)
        [[ -n "$SECURE_BOOT_RAW" ]] && SECURE_BOOT="$SECURE_BOOT_RAW"
    fi

    # Apple Mobile File Integrity enabled (CIS T2 / mSCP §5.1.3)
    # AMFI is disabled by adding amfi_get_out_of_my_way=1 to NVRAM boot-args.
    # Requires SIP to be disabled first, so this should never be set on a managed device.
    AMFI_ENABLED="Yes"
    if nvram -p 2>/dev/null | grep -q "amfi_get_out_of_my_way=1"; then
        AMFI_ENABLED="No"
    fi

    # §5.9 — Guest home folder absent (should not exist when guest account is disabled)
    GUEST_FOLDER_ABSENT="Yes"
    if [[ -d "/Users/Guest" ]]; then
        GUEST_FOLDER_ABSENT="No"
    fi

    # §5.10 — XProtect antivirus services running (two launchd services expected)
    XPROTECT_RUNNING="No"
    local _xp_count
    _xp_count=$(launchctl list 2>/dev/null | grep -cE 'com\.apple\.XprotectFramework\.PluginService|com\.apple\.XProtect\.daemon\.scan' || echo "0")
    (( _xp_count >= 2 )) && XPROTECT_RUNNING="Yes"
}
