# sharing.sh — remote access and sharing service states.
# Sourced by patched-collect.sh; not executable directly.

# _sharing_tm_plist: the Time Machine preferences plist. A function so the
# tests can point it at a fixture.
_sharing_tm_plist() {
    print -r -- "/Library/Preferences/com.apple.TimeMachine.plist"
}

# §2.3.4.2: Time Machine volumes encrypted (PAT-1767 three-state contract).
# Sets TIME_MACHINE_ENCRYPTED to:
#   "Yes" / "No"     Time Machine has destinations; "No" when any is
#                    NotEncrypted
#   "NotConfigured"  Time Machine has no destinations: the plist does not
#                    exist (in a searchable directory), or `defaults read`
#                    of the whole domain succeeded and lists no Destinations
#                    (an exit 0 means cfprefsd parsed the plist)
#   "" (null)        the plist exists but `defaults read` failed, or its
#                    directory cannot be searched. Before PAT-1767 a failed
#                    read and "no destinations" were both null.
_collect_time_machine_encrypted() {
    TIME_MACHINE_ENCRYPTED=""
    local tm_plist tm_raw="" tm_rc=0
    tm_plist=$(_sharing_tm_plist)
    if [[ ! -e "$tm_plist" && ! -L "$tm_plist" ]]; then
        # prefs_plists_readable only passes a missing plist when no ancestor
        # directory hides it.
        if prefs_plists_readable "$tm_plist"; then
            TIME_MACHINE_ENCRYPTED="NotConfigured"
        else
            log_warn "sharing: time_machine_encrypted undetermined ($PREFS_PLIST_REASON)"
        fi
        return 0
    fi
    tm_raw=$(defaults read "$tm_plist" 2>/dev/null) || tm_rc=$?
    if (( tm_rc != 0 )); then
        log_warn "sharing: time_machine_encrypted undetermined (defaults read exited $tm_rc)"
        return 0
    fi
    if printf '%s\n' "$tm_raw" | grep -q 'Destinations'; then
        if printf '%s\n' "$tm_raw" | grep -q 'NotEncrypted'; then
            TIME_MACHINE_ENCRYPTED="No"
        else
            TIME_MACHINE_ENCRYPTED="Yes"
        fi
    else
        TIME_MACHINE_ENCRYPTED="NotConfigured"
    fi
}

collect_sharing() {
    # Capture launchctl disabled list once — reused for all service checks below.
    # Format (older macOS): "<service-label>" => false|true
    # Format (macOS 15.7+):  "<service-label>" => enabled|disabled
    #   => false / => enabled   (disabled flag = false) = service is NOT disabled = running
    #   => true  / => disabled  (disabled flag = true)  = service is explicitly disabled
    #   absent from list                                = uses system default (disabled for sharing services)
    local _DISABLED_LIST
    _DISABLED_LIST=$(launchctl print-disabled system 2>/dev/null || true)

    # Remote Apple Events (CIS 2.4.1 / mSCP 2.3.3.6)
    REMOTE_APPLE_EVENTS=$(systemsetup -getremoteappleevents 2>/dev/null | awk '{print $NF}' || echo "Unknown")
    case "$REMOTE_APPLE_EVENTS" in
        On|Off) ;;
        *) REMOTE_APPLE_EVENTS="Unknown" ;;
    esac

    # Remote login / SSH (CIS 2.4.4 / mSCP 2.3.3.4)
    REMOTE_LOGIN=$(systemsetup -getremotelogin 2>/dev/null | awk -F': ' '{print $2}' || echo "Unknown")
    case "$REMOTE_LOGIN" in
        On|Off) ;;
        *) REMOTE_LOGIN="Unknown" ;;
    esac

    # Screen sharing (CIS 2.4.10 / mSCP 2.3.3.1)
    SCREEN_SHARING="Off"
    if printf '%s\n' "$_DISABLED_LIST" | grep -qE '"com\.apple\.screensharing" => (false|enabled)'; then
        SCREEN_SHARING="On"
    fi

    # SMB file sharing (CIS T2 / mSCP §2.3.3.2)
    SMBD_DISABLED="Yes"
    if printf '%s\n' "$_DISABLED_LIST" | grep -qE '"com\.apple\.smbd" => (false|enabled)'; then
        SMBD_DISABLED="No"
    fi

    # Printer sharing (CIS T2 / mSCP §2.3.3.3)
    # cupsctl outputs _share_printers=0 (off) or _share_printers=1 (on)
    PRINTER_SHARING_DISABLED="Yes"
    if cupsctl 2>/dev/null | grep -q '_share_printers=1'; then
        PRINTER_SHARING_DISABLED="No"
    fi

    # Remote Management / Apple Remote Desktop (CIS T2 / mSCP §2.3.3.5)
    # mdmclient QuerySecurityInfo returns RemoteDesktopEnabled = 0|1
    # On failure or unmanaged devices, defaults to "Yes" (assume disabled).
    REMOTE_MANAGEMENT_DISABLED="Yes"
    if mdmclient QuerySecurityInfo 2>/dev/null | grep -q 'RemoteDesktopEnabled = 1;'; then
        REMOTE_MANAGEMENT_DISABLED="No"
    fi

    # Internet Sharing (CIS T2 / mSCP §2.3.3.7)
    INTERNET_SHARING_DISABLED="Yes"
    if printf '%s\n' "$_DISABLED_LIST" | grep -qE '"com\.apple\.InternetSharing" => (false|enabled)'; then
        INTERNET_SHARING_DISABLED="No"
    fi

    # Built-in web server / httpd (CIS T2 / mSCP §4.2)
    HTTPD_DISABLED="Yes"
    if printf '%s\n' "$_DISABLED_LIST" | grep -qE '"org\.apache\.httpd" => (false|enabled)'; then
        HTTPD_DISABLED="No"
    fi

    # NFS server daemon (CIS T2 / mSCP §4.3)
    NFSD_DISABLED="Yes"
    if printf '%s\n' "$_DISABLED_LIST" | grep -qE '"com\.apple\.nfsd" => (false|enabled)'; then
        NFSD_DISABLED="No"
    fi

    # §2.3.2.2 — Time synchronisation daemon running
    TIMED_RUNNING="No"
    if launchctl list 2>/dev/null | grep -qF 'com.apple.timed'; then
        TIMED_RUNNING="Yes"
    fi

    # §2.12.2 — Guest access to SMB shares disabled (value 0 = disabled = good)
    SMB_GUEST_DISABLED="Yes"
    local _smb_guest
    _smb_guest=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 2>/dev/null || echo "0")
    if [[ "$_smb_guest" == "1" ]]; then
        SMB_GUEST_DISABLED="No"
    fi

    # §2.3.4.2: Time Machine volumes encrypted ("NotConfigured" = no
    # destinations; see _collect_time_machine_encrypted above)
    _collect_time_machine_encrypted
}
