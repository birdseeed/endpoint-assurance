# user_prefs.sh — per-console-user preference signals.
# Reads preferences for the GUI-session user via console_user() + sudo.
# Falls back to null if no interactive user is logged in.
#
# Each signal is (PAT-1767):
#   "Yes" / "No"     the key was read and holds a recognised value
#   "NotConfigured"  `defaults read` reported the key missing AND every plist
#                    that read consults for the user (the domain plist in
#                    the user's Preferences, or for -currentHost every
#                    ByHost/<domain>.*.plist) is absent or readable and
#                    parses as a dictionary. `defaults` prints the same
#                    "does not exist" line for a corrupt or unreadable plist
#                    as for a missing key, so the plist check is what makes
#                    the absence trustworthy (see common.sh)
#   "" (null)        no console user, sudo or defaults failing, a wrong-type
#                    value, a home directory that cannot be resolved, or a
#                    plist that could hold the key but cannot be read
# Requires: PATCHED_TMPDIR, PYTHON3; console_user, prefs_defaults_read,
# prefs_plists_readable and log_warn (common.sh)
# Sourced by patched-collect.sh; not executable directly.

# _up_read <user> <home> <currentHost 0|1> <domain> <key>
# Sets the caller's _v and _up_state (value / absent / failed).
_up_read() {
    local up_user="$1" up_home="$2" up_host="$3" up_domain="$4" up_key="$5"
    local up_prefs="$2/Library/Preferences"
    local -a up_cmd up_plists
    up_cmd=( sudo -u "$up_user" defaults )
    [[ "$up_host" == "1" ]] && up_cmd+=( -currentHost )
    up_cmd+=( read "$up_domain" "$up_key" )
    prefs_defaults_read "${up_cmd[@]}"
    _v="$PREFS_READ_VALUE"
    _up_state="$PREFS_READ_STATE"
    [[ "$_up_state" == "absent" ]] || return 0

    if [[ -z "$up_home" || ! -d "$up_home" ]]; then
        _up_state="failed"
        log_warn "user_prefs: $up_domain $up_key undetermined (home directory not found for $up_user)"
        return 0
    fi
    if [[ "$up_host" == "1" ]]; then
        if [[ -e "$up_prefs/ByHost" && ! ( -d "$up_prefs/ByHost" && -r "$up_prefs/ByHost" && -x "$up_prefs/ByHost" ) ]]; then
            _up_state="failed"
            log_warn "user_prefs: $up_domain $up_key undetermined (ByHost directory not readable: $up_prefs/ByHost)"
            return 0
        fi
        up_plists=( "$up_prefs/ByHost/$up_domain".*.plist(N) )
        # Names the directory so an unsearchable ancestor is still caught
        # when no ByHost plist exists.
        (( ${#up_plists[@]} )) || up_plists=( "$up_prefs/ByHost/$up_domain.plist" )
    else
        up_plists=( "$up_prefs/$up_domain.plist" )
    fi
    if ! prefs_plists_readable "${up_plists[@]}"; then
        _up_state="failed"
        log_warn "user_prefs: $up_domain $up_key undetermined ($PREFS_PLIST_REASON)"
    fi
    return 0
}

# _up_map <signal-var> <when-1> <when-0>
# Maps the last _up_read of a 0/1 key: absent -> "NotConfigured", 1 / 0 ->
# the given strings, anything else -> "" (null).
_up_map() {
    local up_out=""
    case "$_up_state:$_v" in
        absent:*) up_out="NotConfigured" ;;
        value:1)  up_out="$2" ;;
        value:0)  up_out="$3" ;;
    esac
    typeset -g "$1=$up_out"
}

collect_user_prefs() {
    local _CUSER
    _CUSER=$(console_user)

    # No GUI session: emit null for all per-user signals.
    case "$_CUSER" in
        root|loginwindow|"")
            BLUETOOTH_SHARING_DISABLED=""
            SHOW_FILE_EXTENSIONS=""
            TERMINAL_SECURE_KEYBOARD=""
            return
            ;;
    esac

    local _v _up_state _up_home="" _up_dscl=""
    # Only needed to confirm an absent key. dscl's output is captured before
    # parsing so a failed lookup leaves the home empty (absence unconfirmed).
    if _up_dscl=$(dscl . read /Users/"$_CUSER" NFSHomeDirectory 2>/dev/null) \
        && [[ "$_up_dscl" =~ '^NFSHomeDirectory:[[:space:]]+(/[^'$'\n'']*)$' ]]; then
        _up_home="${match[1]}"
    fi

    # §2.3.3.10 — Bluetooth Sharing disabled (ByHost per-user pref, value 0 = disabled)
    _up_read "$_CUSER" "$_up_home" 1 com.apple.Bluetooth PrefKeyServicesEnabled
    _up_map BLUETOOTH_SHARING_DISABLED No Yes

    # §6.1.1 — Show all filename extensions (macOS hides extensions by default)
    _up_read "$_CUSER" "$_up_home" 0 .GlobalPreferences AppleShowAllExtensions
    _up_map SHOW_FILE_EXTENSIONS Yes No

    # §6.4.1 — Secure keyboard entry in Terminal (prevents other apps reading keystrokes)
    _up_read "$_CUSER" "$_up_home" 0 com.apple.Terminal SecureKeyboardEntry
    _up_map TERMINAL_SECURE_KEYBOARD Yes No
}
