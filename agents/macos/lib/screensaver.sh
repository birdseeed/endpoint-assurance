# screensaver.sh — screensaver lock policy signals (CIS 2.10.x).
# Requires: FIRST_USER and HW_UUID (set by collect_hardware), OS_VERSION (set
# by collect_os), PYTHON3, console_user, prefs_plists_readable and log_warn
# (common.sh)
#
# Source by macOS version (PAT-1743): since macOS 13 "Require password after
# screen saver begins or display is turned off" is system-managed and no
# longer written as askForPassword / askForPasswordDelay in
# com.apple.screensaver, so on 13 and later the plists say nothing about it
# and reading them reported a 60-minute delay as "DefaultAssumed". On 13 and
# later the collector runs `sysadminctl -screenLock status` as the subject
# user (launchctl asuser + sudo -u, because the collector runs as root) and
# never reads the plists. Before 13 it reads the plists as below. An
# OS_VERSION that is not a version number is undetermined: neither source can
# be trusted without knowing which one applies. There is no timeout on the
# sysadminctl call; the macOS collector has no shell timeout helper.
#
# On macOS 12 and earlier the plists are read with PlistBuddy (file IO)
# rather than `defaults`.
#
# Precedence (PAT-1722): CFPreferences resolves the current-host domain
# (ByHost/com.apple.screensaver.<hardware UUID>.plist) before the any-host
# domain (com.apple.screensaver.plist), so the ByHost plist is read first.
# Confirmed on macOS 26 with conflicting `defaults write` and
# `defaults -currentHost write` values: CFPreferencesCopyAppValue and
# NSUserDefaults both returned the -currentHost value, in both directions.
# ByHost plists named for any other hardware UUID (left behind by Migration
# Assistant) are never consulted by macOS, so they are not read either.
#
# Subject user (PAT-1723): the lock setting is per user, so the collector
# reads the console user's preferences, chosen the same way user_prefs.sh
# chooses its subject (console_user, with root, loginwindow and empty meaning
# nobody is logged in). The two differ only when nobody is logged in:
# user_prefs.sh reports null, while this module falls back to FIRST_USER, the
# lowest local account with UID 500 or above, and says so on stderr so that
# evidence is not mistaken for a logged-in user's. The payload carries one
# screensaver value, not one per user.
# Sourced by patched-collect.sh; not executable directly.
#
# SCREENSAVER_PASSWORD values:
#   "Yes" / "No"      macOS 13+: sysadminctl reported a delay (Yes) or that
#                     the screen lock is off (No). Before 13: key read from a
#                     plist the collector could parse
#   "DefaultAssumed"  before macOS 13 only: every candidate plist was read and
#                     none sets the key, so Apple's default (password
#                     required) is in effect. Never emitted on 13 or later.
#   "Unknown"         undetermined. macOS 13+: no user, a failed uid lookup,
#                     sysadminctl exiting non-zero or missing, or output that
#                     is not exactly one recognised screenLock line; also an
#                     unparseable OS_VERSION. Before 13: no user, home not
#                     resolvable or not
#                     searchable, a plist or preferences directory unreadable,
#                     a corrupt plist, a value of the wrong type, or ByHost
#                     plists present while the hardware UUID that selects the
#                     current-host one is unknown. The reason
#                     goes to stderr. The field is a non-nullable string in the
#                     payload contract, and "Unknown" is the contract's
#                     undetermined value for sibling signals (PAT-1710).
# SCREENSAVER_DELAY_SECONDS is an integer, or empty (null) whenever it is not
# positively read, including every undetermined path above. On macOS 13+ it is
# the sysadminctl delay ("immediate" is 0) and null when the lock is off.
#
# Inactivity interval (CIS 2.10.1, PAT-1753), every macOS version:
# SCREENSAVER_IDLE_SECONDS is how long the subject user can be inactive before
# the screen saver starts: com.apple.screensaver idleTime, read through
# NSUserDefaults in a JXA call run as the subject user (launchctl asuser +
# sudo -u, the same way as sysadminctl above). Running as the user matters:
# CFPreferences then resolves the value the user's session actually gets,
# a profile-forced value (/Library/Managed Preferences, per-user or
# computer-level) over the user's current-host ByHost value over the any-host
# value, and objectIsForcedForKey reports whether a profile forces it. Read as
# root the call would see root's preferences and the computer-level managed
# plist only. This is the source CIS audits for 2.10.1.
#   positive integer  the interval in seconds, as read
#   99999             idleTime 0, which macOS means as "never start the screen
#                     saver". 0 itself is never emitted: the server rule is
#                     `lte 1200` and a literal 0 would pass a screen saver
#                     that never starts. The sentinel is the one the Windows
#                     agent already sends for the same meaning
#                     (machine_inactivity_limit_seconds, InactivityTimeoutSecs
#                     0 = no limit, SecurityOptionsParser), so the contract
#                     reads the same on both platforms.
#   "NotConfigured"   the read succeeded, idleTime is not set anywhere in the
#                     user's search list, and every plist that search list
#                     could have taken it from is absent or a readable
#                     dictionary (PAT-1775, the PAT-1767 contract; see
#                     _ss_idle_absence_confirmed). The macOS default is not
#                     verified, so this says the setting is absent, never
#                     that any interval applies; the server rule decides
#                     through treat_not_configured_as.
#   empty (null)      not positively read: no user, a failed uid lookup, a
#                     non-zero exit or unrecognised output, a value that is
#                     not a non-negative whole number, or the key not set
#                     while a plist it could live in is unreadable or
#                     corrupt, or the home directory or ByHost preferences
#                     cannot be checked. The reason goes to stderr.
# SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE follows the PAT-1720 convention
# (collect_managed_prefs): "true" when a profile forces idleTime, "false" when
# the read succeeded and it is not forced (set locally or not set at all), and
# empty (null) when the read failed, including an unset key whose absence
# could not be confirmed (the unreadable plist could hold the forced value,
# as in managed_prefs.sh). Never defaulted to "false".

# _ss_read_key <key> <candidate...>
# Walks the candidate plists in precedence order and stops at the first one
# that answers. Sets _SS_STATE to value / absent / undetermined, _SS_VALUE to
# PlistBuddy's rendering of the value, and _SS_REASON when undetermined.
# A candidate that cannot be read stops the walk: its key could be the one
# that wins, so later candidates cannot stand in for it.
_ss_read_key() {
    local key="$1"
    shift
    local ss_candidate ss_out
    _SS_STATE="absent"; _SS_VALUE=""; _SS_REASON=""
    for ss_candidate in "$@"; do
        [[ -e "$ss_candidate" ]] || continue
        if [[ ! -f "$ss_candidate" || ! -r "$ss_candidate" ]]; then
            _SS_STATE="undetermined"; _SS_REASON="unreadable plist: $ss_candidate"
            return
        fi
        # Parse the whole file first: PlistBuddy exits 1 both for a missing
        # key and for a corrupt file, so the key read alone cannot tell them
        # apart.
        if ! /usr/libexec/PlistBuddy -c "Print" "$ss_candidate" >/dev/null 2>&1; then
            _SS_STATE="undetermined"; _SS_REASON="unparseable plist: $ss_candidate"
            return
        fi
        if ss_out=$(/usr/libexec/PlistBuddy -c "Print :$key" "$ss_candidate" 2>/dev/null); then
            _SS_STATE="value"; _SS_VALUE="$ss_out"
            return
        fi
    done
}

# _ss_collect_screenlock <user>
# macOS 13+ source (PAT-1743). Runs `sysadminctl -screenLock status` as <user>
# and sets SCREENSAVER_PASSWORD / SCREENSAVER_DELAY_SECONDS only when the
# output is exactly one recognised screenLock line. sysadminctl reports
# through NSLog, so the line arrives on stderr with a timestamp and process
# prefix, which is accepted but not required. The messages match the format
# strings in /usr/sbin/sysadminctl on macOS 26:
#   screenLock delay is %d seconds   password required after that delay
#   screenLock delay is immediate    password required, delay 0
#   screenLock is off                password not required, delay null
# Anything else, including "Unknown state for screenLock (...)", a non-zero
# exit (sudo reports a missing binary that way) or a second screenLock line,
# leaves both signals undetermined and logs the reason.
_ss_collect_screenlock() {
    local ss_user="$1" ss_uid="" ss_out="" ss_rc=0 ss_line ss_lock_line="" ss_count=0
    local ss_re='^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+ sysadminctl\[[0-9]+:[0-9A-Fa-fx]+\] )?screenLock (is off|delay is immediate|delay is (0|[1-9][0-9]{0,8}) seconds)$'

    ss_uid=$(id -u "$ss_user" 2>/dev/null) || ss_uid=""
    if [[ ! "$ss_uid" =~ '^[0-9]+$' ]]; then
        log_warn "screensaver: screen lock undetermined (uid lookup failed for $ss_user)"
        return 0
    fi

    ss_out=$(launchctl asuser "$ss_uid" /usr/bin/sudo -u "$ss_user" /usr/sbin/sysadminctl -screenLock status 2>&1)
    ss_rc=$?
    if (( ss_rc != 0 )); then
        log_warn "screensaver: screen lock undetermined (sysadminctl -screenLock status exited $ss_rc)"
        return 0
    fi

    for ss_line in "${(@f)ss_out}"; do
        [[ "$ss_line" == *screenLock* ]] || continue
        ss_count=$(( ss_count + 1 ))
        ss_lock_line="$ss_line"
    done
    if (( ss_count != 1 )) || [[ ! "$ss_lock_line" =~ $ss_re ]]; then
        log_warn "screensaver: screen lock undetermined (unrecognised sysadminctl -screenLock status output)"
        return 0
    fi

    case "${match[2]}" in
        "is off")
            SCREENSAVER_PASSWORD="No"
            SCREENSAVER_DELAY_SECONDS=""
            ;;
        "delay is immediate")
            SCREENSAVER_PASSWORD="Yes"
            SCREENSAVER_DELAY_SECONDS="0"
            ;;
        *)
            SCREENSAVER_PASSWORD="Yes"
            SCREENSAVER_DELAY_SECONDS="${match[3]}"
            ;;
    esac
}

# _ss_idle_plists <user> <home>
# Sets _SS_IDLE_PLISTS to every plist the subject user's NSUserDefaults
# search list for com.apple.screensaver reads from: the user's own and the
# computer-level Managed Preferences, the user's ByHost (every host, as
# managed_prefs.sh does, so a corrupt plist for another host also blocks
# NotConfigured) and any-host preferences, and /Library/Preferences, each for
# the screensaver domain and the global domain. Returns 1 when the user's
# ByHost directory exists but cannot be listed, since a plist in it cannot be
# ruled out. A function so the tests can point it at fixtures.
_ss_idle_plists() {
    local sp_user="$1" sp_prefs="$2/Library/Preferences" sp_name
    _SS_IDLE_PLISTS=()
    for sp_name in com.apple.screensaver .GlobalPreferences; do
        _SS_IDLE_PLISTS+=(
            "/Library/Managed Preferences/$sp_user/$sp_name.plist"
            "/Library/Managed Preferences/$sp_name.plist"
            "$sp_prefs/$sp_name.plist"
            "/Library/Preferences/$sp_name.plist"
        )
    done
    if [[ -e "$sp_prefs/ByHost" ]]; then
        [[ -d "$sp_prefs/ByHost" && -r "$sp_prefs/ByHost" && -x "$sp_prefs/ByHost" ]] || return 1
        _SS_IDLE_PLISTS+=( "$sp_prefs/ByHost"/com.apple.screensaver.*.plist(N) "$sp_prefs/ByHost"/.GlobalPreferences.*.plist(N) )
    fi
    return 0
}

# _ss_idle_absence_confirmed <user>
# Called only after the idleTime read succeeded and reported the key unset.
# NSUserDefaults also returns nil for a corrupt or unreadable plist, so the
# unset key is only trusted (return 0) when the user's home directory
# resolves and every plist _ss_idle_plists names is absent or a readable
# dictionary (prefs_plists_readable). Otherwise logs the reason and returns 1.
_ss_idle_absence_confirmed() {
    local ic_user="$1" ic_dscl="" ic_home=""
    local -a match mbegin mend _SS_IDLE_PLISTS
    if ic_dscl=$(dscl . read /Users/"$ic_user" NFSHomeDirectory 2>/dev/null) \
        && [[ "$ic_dscl" =~ '^NFSHomeDirectory:[[:space:]]+(/[^'$'\n'']*)$' ]]; then
        ic_home="${match[1]}"
    fi
    if [[ -z "$ic_home" || ! -d "$ic_home" ]]; then
        log_warn "screensaver: idleTime undetermined (not set, and the home directory of $ic_user was not found)"
        return 1
    fi
    if ! _ss_idle_plists "$ic_user" "$ic_home"; then
        log_warn "screensaver: idleTime undetermined (not set, and the ByHost preferences of $ic_user cannot be listed)"
        return 1
    fi
    if ! prefs_plists_readable "${_SS_IDLE_PLISTS[@]}"; then
        log_warn "screensaver: idleTime undetermined (not set, and $PREFS_PLIST_REASON)"
        return 1
    fi
    return 0
}

# _ss_collect_idle <user>
# Inactivity interval source (PAT-1753). Runs one JXA NSUserDefaults read of
# com.apple.screensaver idleTime as <user> and sets SCREENSAVER_IDLE_SECONDS
# and SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE. The type check happens in
# JavaScript, so a string "600" or a boolean is never read as a number, and
# the script prints exactly one line: the forced flag, then "absent",
# "invalid" or "int:<n>". A real-typed plist value with no fractional part
# (600.0) is a whole number and reads as int. Output that is not exactly that
# line is undetermined: both signals stay null.
_ss_collect_idle() {
    local ss_user="$1" ss_uid="" ss_out="" ss_rc=0
    local ss_never_sentinel=99999   # idleTime 0, see the header
    local ss_re='^(true|false) (absent|invalid|int:(0|[1-9][0-9]{0,9}))$'
    local ss_js='var d = $.NSUserDefaults.alloc.initWithSuiteName("com.apple.screensaver");
var v = d.objectForKey("idleTime").js;
var r = d.objectIsForcedForKey("idleTime") ? "true" : "false";
if (v === undefined) { r += " absent"; }
else if (typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 2147483647) { r += " int:" + v; }
else { r += " invalid"; }
r'

    ss_uid=$(id -u "$ss_user" 2>/dev/null) || ss_uid=""
    if [[ ! "$ss_uid" =~ '^[0-9]+$' ]]; then
        log_warn "screensaver: idleTime undetermined (no uid for $ss_user)"
        return 0
    fi

    ss_out=$(launchctl asuser "$ss_uid" /usr/bin/sudo -u "$ss_user" /usr/bin/osascript -l JavaScript -e "$ss_js" 2>/dev/null)
    ss_rc=$?
    if (( ss_rc != 0 )); then
        log_warn "screensaver: idleTime undetermined (osascript exited $ss_rc)"
        return 0
    fi
    if [[ ! "$ss_out" =~ $ss_re ]]; then
        log_warn "screensaver: idleTime undetermined (unrecognised osascript output)"
        return 0
    fi

    # The read succeeded, so the forced flag is evidence whatever the value.
    SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE="${match[1]}"
    case "${match[2]}" in
        absent)
            if _ss_idle_absence_confirmed "$ss_user"; then
                SCREENSAVER_IDLE_SECONDS="NotConfigured"
            else
                SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE=""
            fi
            ;;
        invalid)
            log_warn "screensaver: idleTime undetermined (unexpected value type)"
            ;;
        int:0)
            SCREENSAVER_IDLE_SECONDS="$ss_never_sentinel"
            ;;
        *)
            SCREENSAVER_IDLE_SECONDS="${match[3]}"
            ;;
    esac
}

collect_screensaver() {
    # macOS 12 and earlier: askForPassword / askForPasswordDelay keys are only
    # written when the user has explicitly toggled the setting. Absent keys mean
    # Apple's default behaviour is in effect (password required, ~5s delay).
    # "DefaultAssumed" is only emitted once every place the key could live has
    # actually been read; anything short of that is "Unknown".
    SCREENSAVER_PASSWORD="Unknown"
    SCREENSAVER_DELAY_SECONDS=""  # empty → null in JSON → treat_unknown_as applies
    SCREENSAVER_IDLE_SECONDS=""   # empty → null; "NotConfigured" when unset, see the header
    SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE=""

    local ss_reason="" ss_home="" ss_prefs ss_byhost ss_host_plist="" ss_user=""
    local -a ss_candidates ss_byhost_any

    ss_user=$(console_user)
    case "$ss_user" in
        root|loginwindow|"")
            ss_user="${FIRST_USER:-}"
            if [[ -n "$ss_user" ]]; then
                log_warn "screensaver: no console user logged in, reading the lowest-UID local account ($ss_user) instead"
            fi
            ;;
    esac

    # Inactivity interval (PAT-1753): same subject user, every macOS version,
    # read before the version branch so an unparseable OS_VERSION does not
    # stop it.
    if [[ -n "$ss_user" ]]; then
        _ss_collect_idle "$ss_user"
    else
        log_warn "screensaver: idleTime undetermined (no user to read)"
    fi

    # macOS 13+ reads sysadminctl, never the plists (PAT-1743).
    local ss_os_major="${${OS_VERSION:-}%%.*}"
    if [[ ! "$ss_os_major" =~ '^[0-9]+$' ]]; then
        log_warn "screensaver: screen lock undetermined (macOS version unknown: ${OS_VERSION:-empty})"
        return 0
    fi
    if (( ss_os_major >= 13 )); then
        if [[ -z "$ss_user" ]]; then
            log_warn "screensaver: screen lock undetermined (no console user and no local user to read)"
            return 0
        fi
        _ss_collect_screenlock "$ss_user"
        return 0
    fi

    if [[ -z "$ss_user" ]]; then
        ss_reason="no console user and no local user to read"
    else
        ss_home=$(dscl . read /Users/"$ss_user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
        if [[ -z "$ss_home" ]]; then
            ss_reason="home directory lookup failed for $ss_user"
        elif [[ ! -d "$ss_home" || ! -x "$ss_home" ]]; then
            ss_reason="home directory not searchable: $ss_home"
        fi
    fi

    if [[ -z "$ss_reason" ]]; then
        ss_prefs="$ss_home/Library/Preferences"
        ss_byhost="$ss_prefs/ByHost"
        # Only a directory that exists but cannot be listed hides a plist. A
        # missing Preferences directory means the user has no preferences yet.
        if [[ -e "$ss_prefs" && ( ! -r "$ss_prefs" || ! -x "$ss_prefs" ) ]]; then
            ss_reason="preferences directory not readable: $ss_prefs"
        elif [[ -e "$ss_byhost" && ( ! -r "$ss_byhost" || ! -x "$ss_byhost" ) ]]; then
            ss_reason="ByHost directory not readable: $ss_byhost"
        fi
    fi

    if [[ -z "$ss_reason" ]]; then
        # The current-host plist is named for the hardware UUID. HW_UUID is
        # interpolated into a path, so only a well-formed UUID is used. Without
        # one the current-host plist cannot be told apart from another host's:
        # that only matters when some ByHost screensaver plist exists. (N)
        # makes the glob expand to nothing when no file matches, so the module
        # does not depend on the caller having set NULL_GLOB.
        if [[ "${HW_UUID:-}" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; then
            ss_host_plist="$ss_byhost/com.apple.screensaver.$HW_UUID.plist"
        else
            ss_byhost_any=( "$ss_byhost"/com.apple.screensaver.*.plist(N) )
            if (( ${#ss_byhost_any[@]} )); then
                ss_reason="hardware UUID unknown, cannot select the current-host ByHost plist"
            fi
        fi
    fi

    if [[ -n "$ss_reason" ]]; then
        log_warn "screensaver: askForPassword undetermined ($ss_reason)"
        return 0
    fi

    # Highest precedence first: current-host ByHost, then the any-host plist.
    # An empty ss_host_plist means no ByHost screensaver plist exists at all.
    ss_candidates=()
    [[ -n "$ss_host_plist" ]] && ss_candidates+=( "$ss_host_plist" )
    ss_candidates+=( "$ss_prefs/com.apple.screensaver.plist" )

    _ss_read_key askForPassword "${ss_candidates[@]}"
    case "$_SS_STATE" in
        value)
            case "$_SS_VALUE" in
                true|1)  SCREENSAVER_PASSWORD="Yes" ;;
                false|0) SCREENSAVER_PASSWORD="No" ;;
                *)
                    SCREENSAVER_PASSWORD="Unknown"
                    log_warn "screensaver: askForPassword undetermined (unexpected value type)"
                    ;;
            esac
            ;;
        absent)
            SCREENSAVER_PASSWORD="DefaultAssumed"
            ;;
        *)
            SCREENSAVER_PASSWORD="Unknown"
            log_warn "screensaver: askForPassword undetermined ($_SS_REASON)"
            ;;
    esac

    _ss_read_key askForPasswordDelay "${ss_candidates[@]}"
    if [[ "$_SS_STATE" == "value" && "$_SS_VALUE" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        SCREENSAVER_DELAY_SECONDS=${_SS_VALUE%.*}
    elif [[ "$_SS_STATE" == "undetermined" ]]; then
        log_warn "screensaver: askForPasswordDelay undetermined ($_SS_REASON)"
    fi
}
