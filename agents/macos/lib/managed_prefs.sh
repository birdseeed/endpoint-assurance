# managed_prefs.sh — MDM-managed NSUserDefaults preference signals.
# All signals are read via the managed_pref_read JXA helper (common.sh), which
# returns the effective value. A value of the wrong type, or a read that failed
# because osascript failed, emits null (undetermined), never a confident "No";
# the server rules score null with treat_unknown_as (PAT-1710).
#
# PAT-1767: a key that is not set at all emits "NotConfigured" (the server
# rule's treat_not_configured_as, which defaults to its treat_unknown_as), but
# only when the read succeeded AND every plist root's NSUserDefaults search
# list could have taken the key from is readable (see the absent-versus-failed
# notes in common.sh). Otherwise the signal stays null. The numeric
# update_deferral_days follows the same rule (PAT-1775): a whole number, or
# "NotConfigured", or null; the payload emits it with
# json_int_or_notconfigured so the number stays a bare JSON number and the
# string is quoted. loginwindow_text_set already reports an unset key as "No"
# and is unchanged.
#
# PAT-1720: each signal <SIGNAL> also sets <SIGNAL>_ENFORCED_BY_PROFILE from the
# same osascript call: "true" when a configuration profile forces the key,
# "false" when the read succeeded and it is not forced (set locally, or not set
# at all), and "" (emitted as null) when the read failed. The value itself is
# still the effective one, forced or not.
# Sourced by patched-collect.sh; not executable directly.

# _mp_domain_plists <domain>
# Sets _MP_PLISTS to every plist the collector's (root's) NSUserDefaults
# search list for <domain> reads from: computer-level and root's per-user
# Managed Preferences, root's own preferences (any-host and ByHost), and
# /Library/Preferences, for the domain and for the global domain. Returns 1
# when a ByHost directory exists but cannot be listed, since a plist in it
# cannot be ruled out. A function so the tests can point it at fixtures.
_mp_domain_plists() {
    local mp_domain="$1" mp_name mp_byhost="/var/root/Library/Preferences/ByHost"
    _MP_PLISTS=()
    for mp_name in "$mp_domain" ".GlobalPreferences"; do
        _MP_PLISTS+=(
            "/Library/Managed Preferences/$mp_name.plist"
            "/Library/Managed Preferences/root/$mp_name.plist"
            "/var/root/Library/Preferences/$mp_name.plist"
            "/Library/Preferences/$mp_name.plist"
        )
    done
    if [[ -e "$mp_byhost" ]]; then
        [[ -d "$mp_byhost" && -r "$mp_byhost" && -x "$mp_byhost" ]] || return 1
        _MP_PLISTS+=( "$mp_byhost/$mp_domain".*.plist(N) "$mp_byhost"/.GlobalPreferences.*.plist(N) )
    fi
    return 0
}

# _mp_read <domain> <key> <enforced-var>
# One managed_pref_read. Sets the caller's _v to the effective value, the
# global <enforced-var> to true / false ("" when the read failed), and the
# caller's _mp_state to:
#   value   the key is set (any type); _v holds it
#   absent  the read succeeded, the key is not set, and every plist the
#           search list reads for <domain> is readable (_mp_domain_plists)
#   failed  osascript failed, or the key read as unset but a plist it could
#           live in is unreadable or corrupt; <enforced-var> is "" too, since
#           the same unreadable plist could hold the forced value
# Returns 0 for value and absent, non-zero for failed.
_mp_read() {
    local _mp_rc=0
    managed_pref_read "$1" "$2" || _mp_rc=$?
    _v="$MANAGED_PREF_VALUE"
    typeset -g "$3=$MANAGED_PREF_FORCED"
    if (( _mp_rc != 0 )); then
        _mp_state="failed"
        return "$_mp_rc"
    fi
    if [[ "$MANAGED_PREF_SET" == "true" ]]; then
        _mp_state="value"
        return 0
    fi
    # Unset: trust it only when nothing that could hold the key is unreadable.
    # Checked once per domain per run.
    if (( ! ${+_mp_domain_ok[$1]} )); then
        if ! _mp_domain_plists "$1"; then
            _mp_domain_ok[$1]=0
            log_warn "managed_prefs: $1 unset keys undetermined (cannot list ByHost preferences)"
        elif ! prefs_plists_readable "${_MP_PLISTS[@]}"; then
            _mp_domain_ok[$1]=0
            log_warn "managed_prefs: $1 unset keys undetermined ($PREFS_PLIST_REASON)"
        else
            _mp_domain_ok[$1]=1
        fi
    fi
    if [[ "${_mp_domain_ok[$1]}" == "1" ]]; then
        _mp_state="absent"
        return 0
    fi
    _v=""
    typeset -g "$3="
    _mp_state="failed"
    return 1
}

# _mp_bool <signal-var> <when-true> <when-false>
# Maps the last _mp_read of a boolean key: unset -> "NotConfigured",
# true / false -> the given strings, anything else (a wrong type or a failed
# read) -> "" (null).
_mp_bool() {
    local _mp_out=""
    case "$_mp_state:$_v" in
        absent:*)    _mp_out="NotConfigured" ;;
        value:true)  _mp_out="$2" ;;
        value:false) _mp_out="$3" ;;
    esac
    typeset -g "$1=$_mp_out"
}

collect_managed_prefs() {
    local _v _mp_state  # scratch variables reused for each pref read
    local -A _mp_domain_ok
    local -a _MP_PLISTS

    # §1.7 — Software update deferral (CIS ODV ≤ 30 days)
    # Numeric signal (PAT-1775): no deferral set is "NotConfigured", which the
    # rule scores through treat_not_configured_as; a failed read or a value
    # that is not a whole number is null, scored through treat_unknown_as.
    _mp_read "com.apple.applicationaccess" "enforcedSoftwareUpdateDelay" UPDATE_DEFERRAL_DAYS_ENFORCED_BY_PROFILE
    if [[ "$_mp_state" == "absent" ]]; then UPDATE_DEFERRAL_DAYS="NotConfigured"
    elif [[ "$_mp_state" == "value" && "$_v" =~ ^[0-9]+$ ]]; then UPDATE_DEFERRAL_DAYS="$_v"
    else UPDATE_DEFERRAL_DAYS=""; fi

    # §2.2.2 — Firewall stealth mode
    _mp_read "com.apple.security.firewall" "EnableStealthMode" FIREWALL_STEALTH_MODE_ENFORCED_BY_PROFILE
    _mp_bool FIREWALL_STEALTH_MODE Yes No

    # §2.3.1.1 — AirDrop disabled (MDM sets allowAirDrop=false to block)
    _mp_read "com.apple.applicationaccess" "allowAirDrop" AIRDROP_DISABLED_ENFORCED_BY_PROFILE
    _mp_bool AIRDROP_DISABLED No Yes

    # §2.3.1.2 — AirPlay Receiver disabled
    _mp_read "com.apple.applicationaccess" "allowAirPlayIncomingRequests" AIRPLAY_RECEIVER_DISABLED_ENFORCED_BY_PROFILE
    _mp_bool AIRPLAY_RECEIVER_DISABLED No Yes

    # §2.3.2.1 — Authorised time server configured (any non-empty value = configured)
    _mp_read "com.apple.MCX" "timeServer" TIME_SERVER_HOST_ENFORCED_BY_PROFILE
    if [[ "$_mp_state" == "absent" ]]; then TIME_SERVER_HOST="NotConfigured"
    elif [[ "$_mp_state" == "value" && -n "$_v" && "$_v" != "null" ]]; then TIME_SERVER_HOST="Yes"
    else TIME_SERVER_HOST=""; fi

    # §2.3.2.1 — Time synchronisation enforced via MDM
    _mp_read "com.apple.timed" "TMAutomaticTimeOnlyEnabled" TIME_SERVER_ENFORCED_ENFORCED_BY_PROFILE
    _mp_bool TIME_SERVER_ENFORCED Yes No

    # §2.4.1 — Wi-Fi menu visible in menu bar (value 18 = shown in Control Centre)
    # Only an integer is a real answer; any other type is undetermined (null).
    _mp_read "com.apple.controlcenter" "WiFi" WIFI_MENU_VISIBLE_ENFORCED_BY_PROFILE
    if [[ "$_mp_state" == "absent" ]]; then WIFI_MENU_VISIBLE="NotConfigured"
    elif [[ "$_mp_state" == "value" && "$_v" == "18" ]]; then WIFI_MENU_VISIBLE="Yes"
    elif [[ "$_mp_state" == "value" && "$_v" =~ ^[0-9]+$ ]]; then WIFI_MENU_VISIBLE="No"
    else WIFI_MENU_VISIBLE=""; fi

    # §2.4.2 — Bluetooth menu visible (value 18 = shown)
    _mp_read "com.apple.controlcenter" "Bluetooth" BLUETOOTH_MENU_VISIBLE_ENFORCED_BY_PROFILE
    if [[ "$_mp_state" == "absent" ]]; then BLUETOOTH_MENU_VISIBLE="NotConfigured"
    elif [[ "$_mp_state" == "value" && "$_v" == "18" ]]; then BLUETOOTH_MENU_VISIBLE="Yes"
    elif [[ "$_mp_state" == "value" && "$_v" =~ ^[0-9]+$ ]]; then BLUETOOTH_MENU_VISIBLE="No"
    else BLUETOOTH_MENU_VISIBLE=""; fi

    # §2.5.1 — Siri disabled (MDM sets allowAssistant=false)
    _mp_read "com.apple.applicationaccess" "allowAssistant" SIRI_DISABLED_ENFORCED_BY_PROFILE
    _mp_bool SIRI_DISABLED No Yes

    # §2.6.4 — Personalised advertising disabled
    _mp_read "com.apple.applicationaccess" "allowApplePersonalizedAdvertising" PERSONALIZED_ADS_DISABLED_ENFORCED_BY_PROFILE
    _mp_bool PERSONALIZED_ADS_DISABLED No Yes

    # §2.10.3 — Login window custom text configured (legal/acceptable-use banner)
    # "No" only when the read itself succeeded and found no text; a failed
    # read is not evidence the banner is off, so it emits null.
    if _mp_read "com.apple.loginwindow" "LoginwindowText" LOGINWINDOW_TEXT_SET_ENFORCED_BY_PROFILE; then
        if [[ -n "$_v" && "$_v" != "null" ]]; then LOGINWINDOW_TEXT_SET="Yes"; else LOGINWINDOW_TEXT_SET="No"; fi
    else
        LOGINWINDOW_TEXT_SET=""
    fi

    # §2.10.4 — Login window prompts for username+password (not a user list)
    _mp_read "com.apple.loginwindow" "SHOWFULLNAME" LOGINWINDOW_FULLNAME_PROMPT_ENFORCED_BY_PROFILE
    _mp_bool LOGINWINDOW_FULLNAME_PROMPT Yes No

    # §2.10.5 — Password hints disabled at login window (RetriesUntilHint = 0)
    _mp_read "com.apple.loginwindow" "RetriesUntilHint" LOGINWINDOW_PASSWORD_HINTS_ENFORCED_BY_PROFILE
    if [[ "$_mp_state" == "absent" ]]; then LOGINWINDOW_PASSWORD_HINTS="NotConfigured"
    elif [[ "$_mp_state" == "value" && "$_v" == "0" ]]; then LOGINWINDOW_PASSWORD_HINTS="Yes"
    elif [[ "$_mp_state" == "value" && "$_v" =~ ^[0-9]+$ ]]; then LOGINWINDOW_PASSWORD_HINTS="No"
    else LOGINWINDOW_PASSWORD_HINTS=""; fi

    # §2.12.1 — Guest account disabled (MDM-enforced)
    _mp_read "com.apple.MCX" "DisableGuestAccount" GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE
    _mp_bool GUEST_ACCOUNT_DISABLED Yes No

    # §2.18.1 — On-device dictation enforced (prevents audio upload to Apple servers)
    _mp_read "com.apple.applicationaccess" "forceOnDeviceOnlyDictation" DICTATION_ON_DEVICE_ENFORCED_BY_PROFILE
    _mp_bool DICTATION_ON_DEVICE Yes No

    # §3.6 — Firewall logging enabled (composite: EnableLogging=true AND LoggingOption set)
    # Enforced by profile only when both keys are forced; undetermined when
    # either read failed. The value is undetermined when either read failed
    # (PAT-1767: a failed read no longer collapses into "No") and
    # "NotConfigured" only when both keys are unset.
    local _fl_enable _fl_option _fl_enable_forced _fl_option_forced _fl_enable_state _fl_option_state
    _mp_read "com.apple.security.firewall" "EnableLogging" _fl_enable_forced
    _fl_enable="$_v"; _fl_enable_state="$_mp_state"
    _mp_read "com.apple.security.firewall" "LoggingOption" _fl_option_forced
    _fl_option="$_v"; _fl_option_state="$_mp_state"
    if [[ -z "$_fl_enable_forced" || -z "$_fl_option_forced" ]]; then
        FIREWALL_LOGGING_ENFORCED_BY_PROFILE=""
    elif [[ "$_fl_enable_forced" == "true" && "$_fl_option_forced" == "true" ]]; then
        FIREWALL_LOGGING_ENFORCED_BY_PROFILE="true"
    else
        FIREWALL_LOGGING_ENFORCED_BY_PROFILE="false"
    fi
    if [[ "$_fl_enable_state" == "failed" || "$_fl_option_state" == "failed" ]]; then
        FIREWALL_LOGGING=""
    elif [[ "$_fl_enable_state" == "absent" && "$_fl_option_state" == "absent" ]]; then
        FIREWALL_LOGGING="NotConfigured"
    elif [[ "$_fl_enable" == "true" && -n "$_fl_option" && "$_fl_option" != "null" ]]; then
        FIREWALL_LOGGING="Yes"
    elif [[ -z "$_fl_enable" && -z "$_fl_option" ]]; then
        FIREWALL_LOGGING=""   # both set but empty: undetermined, as before
    else
        FIREWALL_LOGGING="No"
    fi
}
