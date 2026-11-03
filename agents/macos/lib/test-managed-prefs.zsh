#!/bin/zsh
##############################################################################
# test-managed-prefs.zsh — unit tests for the MDM-managed preference
# collector (collect_managed_prefs) in managed_prefs.sh (PAT-1696).
#
# Sources the live functions out of common.sh (read_managed_pref) and
# managed_prefs.sh (no top-level side effects at source time) so the tests
# exercise the real code, not a copy. The boundary is `/usr/bin/osascript`,
# shadowed with a zsh function of the same name: zsh resolves a function
# before an external command even for an absolute-path command word. The
# double reads the JXA source the readers feed it on stdin, pulls out the
# suite name and key, and answers from two fixture maps:
#   MOCK_PREFS  values a configuration profile forces (Managed Preferences)
#   MOCK_LOCAL  values set only locally (/Library/Preferences, root's domain)
# objectForKey resolves across the whole search list, so the value is
# MOCK_PREFS first, then MOCK_LOCAL. objectIsForcedForKey is true only for a
# MOCK_PREFS key, exactly as NSUserDefaults would answer. The double answers
# in the shape managed_pref_read's JXA prints: "<forced> <set|unset>", a
# newline, then the value. So the real managed_pref_read ->
# collect_managed_prefs path runs against fixture values instead of the
# runner's own preference domains.
#
# Output shape matches real JXA: booleans print as true/false, numbers as
# digits, a nil objectForKey prints nothing and reports "unset".
#
# PAT-1767 three-state contract: an unset key emits "NotConfigured" only when
# the read succeeded and every plist the search list reads for the domain is
# readable. _mp_domain_plists is overridden to name fixture plists under a
# scratch directory, which the real prefs_plists_readable (common.sh) then
# checks with the real /usr/bin/python3, so the runner's own
# /Library/Managed Preferences and /var/root are never consulted. Section 7
# checks every signal three ways: present, absent, failed read.
#
# PAT-1775: the numeric update_deferral_days follows the same contract.
# Section 9 renders its line from the real patched-collect.sh payload heredoc
# and parses it as JSON, so a present value is asserted as a JSON integer,
# an unset key as the JSON string "NotConfigured" and a failed read as null.
#
# KNOWN-GAP checks record current behaviour that breaks the "absent evidence
# is never a pass" rule. They pass today and FAIL LOUDLY if the behaviour
# changes, so a fix must update the assertion in the same change. PAT-1710
# closed the LoginwindowText and wrong-type gaps; PAT-1720 closed the
# forced-by-profile gap with the <signal>_ENFORCED_BY_PROFILE flags. Run:
#   zsh macos/lib/test-managed-prefs.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"
PATCHED_TMPDIR=$(mktemp -d)
trap 'chmod -R u+rwx "$PATCHED_TMPDIR" 2>/dev/null; rm -rf "$PATCHED_TMPDIR"' EXIT

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/managed_prefs.sh"

pass=0; fail=0; gaps=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}
# chk_known_gap <desc> <current-behaviour> <actual>
chk_known_gap() {
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); (( gaps++ )); echo "  KNOWN-GAP: $desc"
    else (( fail++ )); echo "  FAIL: KNOWN-GAP behaviour changed, update this assertion: $desc -> got=$got was=$exp"; fi
}

# ── Boundary double ────────────────────────────────────────────────────────
typeset -A MOCK_PREFS     # "<suite>/<key>" -> JXA-rendered value, forced by a profile
typeset -A MOCK_LOCAL     # "<suite>/<key>" -> JXA-rendered value, set locally only
typeset -A MOCK_FAIL_KEYS  # "<suite>/<key>" -> 1: osascript fails for that key only
MOCK_OSASCRIPT_FAIL=0
MOCK_OSASCRIPT_GARBAGE=0  # 1: osascript exits 0 but prints output of the wrong shape
MOCK_OLD_HEADER=0         # 1: osascript prints the pre-PAT-1767 bare forced flag
JXA_LOG=$(mktemp "$PATCHED_TMPDIR/jxa-log.XXXXXX")
/usr/bin/osascript() {
    local src suite key k
    src=$(cat)
    print -r -- "$src" >> "$JXA_LOG"
    if (( MOCK_OSASCRIPT_FAIL )); then
        print -u2 "execution error: Error: osascript unavailable (-1)"
        return 1
    fi
    if (( MOCK_OSASCRIPT_GARBAGE )); then
        print -r -- "Error: unexpected"
        return 0
    fi
    [[ "$src" =~ "initWithSuiteName\('([^']*)'\)" ]] || return 0
    suite="${match[1]}"
    [[ "$src" =~ "objectForKey\('([^']*)'\)" ]] || return 0
    key="${match[1]}"
    k="$suite/$key"
    if (( ${+MOCK_FAIL_KEYS[$k]} )); then
        print -u2 "execution error: Error: cfprefsd unavailable (-1)"
        return 1
    fi
    local forced=false value="" state=unset
    if (( ${+MOCK_PREFS[$k]} )); then
        forced=true; value="${MOCK_PREFS[$k]}"; state=set
    elif (( ${+MOCK_LOCAL[$k]} )); then
        value="${MOCK_LOCAL[$k]}"; state=set
    fi
    if [[ "$src" == *"objectIsForcedForKey('$key')"* ]]; then
        if (( MOCK_OLD_HEADER )); then
            print -r -- "$forced"
        elif [[ "$src" == *"'unset'"* ]]; then
            print -r -- "$forced $state"
        fi
    fi
    [[ -n "$value" ]] && print -r -- "$value"
    return 0
}

# Fixture plists: _mp_domain_plists names "<domain>.plist" and
# ".GlobalPreferences.plist" under PLIST_ROOT (none exist unless a case writes
# one), plus whatever MOCK_EXTRA_PLISTS adds. MOCK_BYHOST_UNLISTABLE=1 makes
# it report an unlistable ByHost directory.
PLIST_ROOT="$PATCHED_TMPDIR/prefs"
mkdir -p "$PLIST_ROOT"
MOCK_BYHOST_UNLISTABLE=0
typeset -a MOCK_EXTRA_PLISTS
PLISTS_LOG="$PATCHED_TMPDIR/plists-log"
_mp_domain_plists() {
    print -r -- "$1" >> "$PLISTS_LOG"
    _MP_PLISTS=( "$PLIST_ROOT/$1.plist" "$PLIST_ROOT/.GlobalPreferences.plist" "${MOCK_EXTRA_PLISTS[@]}" )
    (( MOCK_BYHOST_UNLISTABLE )) && return 1
    return 0
}
write_plist() {  # write_plist <path> <python-literal-root>
    "$PYTHON3" -c 'import plistlib,sys; plistlib.dump(eval(sys.argv[2]), open(sys.argv[1],"wb"))' "$1" "$2"
}
reset_plists() {
    chmod -R u+rwx "$PLIST_ROOT" 2>/dev/null
    rm -rf "$PLIST_ROOT"; mkdir -p "$PLIST_ROOT"
    MOCK_EXTRA_PLISTS=(); MOCK_BYHOST_UNLISTABLE=0; : > "$PLISTS_LOG"
}

# Every signal collect_managed_prefs sets, in source order.
SIGNALS=(
    UPDATE_DEFERRAL_DAYS FIREWALL_STEALTH_MODE AIRDROP_DISABLED
    AIRPLAY_RECEIVER_DISABLED TIME_SERVER_HOST TIME_SERVER_ENFORCED
    WIFI_MENU_VISIBLE BLUETOOTH_MENU_VISIBLE SIRI_DISABLED
    PERSONALIZED_ADS_DISABLED LOGINWINDOW_TEXT_SET LOGINWINDOW_FULLNAME_PROMPT
    LOGINWINDOW_PASSWORD_HINTS GUEST_ACCOUNT_DISABLED DICTATION_ON_DEVICE
    FIREWALL_LOGGING
)

# Compliant value for every key collect_managed_prefs reads (case 1 fixture).
typeset -A COMPLIANT
COMPLIANT=(
    com.apple.applicationaccess/enforcedSoftwareUpdateDelay          30
    com.apple.security.firewall/EnableStealthMode                    true
    com.apple.applicationaccess/allowAirDrop                         false
    com.apple.applicationaccess/allowAirPlayIncomingRequests         false
    com.apple.MCX/timeServer                                         time.apple.com
    com.apple.timed/TMAutomaticTimeOnlyEnabled                       true
    com.apple.controlcenter/WiFi                                     18
    com.apple.controlcenter/Bluetooth                                18
    com.apple.applicationaccess/allowAssistant                       false
    com.apple.applicationaccess/allowApplePersonalizedAdvertising    false
    com.apple.loginwindow/LoginwindowText                            "Authorised use only"
    com.apple.loginwindow/SHOWFULLNAME                               true
    com.apple.loginwindow/RetriesUntilHint                           0
    com.apple.MCX/DisableGuestAccount                                true
    com.apple.applicationaccess/forceOnDeviceOnlyDictation           true
    com.apple.security.firewall/EnableLogging                        true
    com.apple.security.firewall/LoggingOption                        detail
)

run_case() {
    local sig
    for sig in "${SIGNALS[@]}"; do
        typeset -g "$sig=__unset__"
        typeset -g "${sig}_ENFORCED_BY_PROFILE=__unset__"
    done
    : > "$JXA_LOG"
    : > "$PLISTS_LOG"
    collect_managed_prefs
}

# enforced_flags -> "NAME=flag" lines for every signal's _ENFORCED_BY_PROFILE
enforced_flags() {
    local sig ev
    for sig in "${SIGNALS[@]}"; do
        ev="${sig}_ENFORCED_BY_PROFILE"
        print -r -- "$sig=${(P)ev}"
    done
}

# signals_except <names...> -> "NAME=value" lines for every signal not named
signals_except() {
    local sig
    for sig in "${SIGNALS[@]}"; do
        (( ${@[(Ie)$sig]} )) && continue
        print -r -- "$sig=${(P)sig}"
    done
}

##############################################################################
# 1. Expected (compliant) managed values for every signal.
##############################################################################
echo "--- 1. Managed keys present with compliant values"

MOCK_OSASCRIPT_FAIL=0
MOCK_LOCAL=()
MOCK_PREFS=("${(@kv)COMPLIANT}")
run_case

chk_eq "UPDATE_DEFERRAL_DAYS" "30" "$UPDATE_DEFERRAL_DAYS"
chk_eq "helper sees the other 15 signals (guards the grep checks below)" "15" "$(signals_except UPDATE_DEFERRAL_DAYS | grep -c '=')"
chk_eq "all Yes signals" "" "$(signals_except UPDATE_DEFERRAL_DAYS | grep -v '=Yes$')"
chk_eq "17 JXA reads issued" "17" "$(grep -c 'objectForKey' "$JXA_LOG")"
chk_eq "one osascript call per key: forced-ness asked in the same 17 scripts" "17" \
    "$(grep -c 'objectIsForcedForKey' "$JXA_LOG")"
chk_eq "every key forced by a profile -> every _ENFORCED_BY_PROFILE true" "" \
    "$(enforced_flags | grep -v '=true$')"

##############################################################################
# 2. Unexpected (non-compliant) managed values.
##############################################################################
echo "--- 2. Managed keys present with non-compliant values"

MOCK_PREFS=(
    com.apple.applicationaccess/enforcedSoftwareUpdateDelay          90
    com.apple.security.firewall/EnableStealthMode                    false
    com.apple.applicationaccess/allowAirDrop                         true
    com.apple.applicationaccess/allowAirPlayIncomingRequests         true
    com.apple.timed/TMAutomaticTimeOnlyEnabled                       false
    com.apple.controlcenter/WiFi                                     24
    com.apple.controlcenter/Bluetooth                                8
    com.apple.applicationaccess/allowAssistant                       true
    com.apple.applicationaccess/allowApplePersonalizedAdvertising    true
    com.apple.loginwindow/SHOWFULLNAME                               false
    com.apple.loginwindow/RetriesUntilHint                           3
    com.apple.MCX/DisableGuestAccount                                false
    com.apple.applicationaccess/forceOnDeviceOnlyDictation           false
    com.apple.security.firewall/EnableLogging                        false
    com.apple.security.firewall/LoggingOption                        detail
)
run_case

chk_eq "UPDATE_DEFERRAL_DAYS reports raw 90" "90" "$UPDATE_DEFERRAL_DAYS"
chk_eq "all No signals (bar the two unset string keys)" "" \
    "$(signals_except UPDATE_DEFERRAL_DAYS TIME_SERVER_HOST LOGINWINDOW_TEXT_SET | grep -v '=No$')"
chk_eq "TIME_SERVER_HOST unset, plists readable -> NotConfigured" "NotConfigured" "$TIME_SERVER_HOST"
chk_eq "LOGINWINDOW_TEXT_SET unset, read succeeded -> No" "No" "$LOGINWINDOW_TEXT_SET"

##############################################################################
# 3. Managed keys absent, read succeeded, every plist readable (PAT-1767):
#    NotConfigured for every signal, the numeric deferral included
#    (PAT-1775), but LoginwindowText (No, unchanged).
##############################################################################
echo "--- 3. Managed keys absent"

MOCK_PREFS=()
run_case

chk_eq "absent keys -> NotConfigured for every signal but LOGINWINDOW_TEXT_SET" "" \
    "$(signals_except LOGINWINDOW_TEXT_SET | grep -v '=NotConfigured$')"
chk_eq "helper sees the 15 NotConfigured signals (guards the grep above)" "15" \
    "$(signals_except LOGINWINDOW_TEXT_SET | grep -c '=')"
chk_eq "absent numeric deferral -> NotConfigured, not null (PAT-1775)" "NotConfigured" "$UPDATE_DEFERRAL_DAYS"
chk_eq "absent LoginwindowText with a successful read -> No" "No" "$LOGINWINDOW_TEXT_SET"
chk_eq "absent keys, read succeeded -> every _ENFORCED_BY_PROFILE false" "" \
    "$(enforced_flags | grep -v '=false$')"
chk_eq "plist check covers all 6 domains" "6" "$(sort -u "$PLISTS_LOG" | grep -c .)"
chk_eq "plist check cached: 6 calls, not one per key" "6" "$(grep -c . "$PLISTS_LOG")"

# Readable fixture plists that exist but do not hold the key are still absent.
write_plist "$PLIST_ROOT/com.apple.MCX.plist" "{'SomethingElse': True}"
write_plist "$PLIST_ROOT/.GlobalPreferences.plist" "{'AppleLocale': 'en_GB'}"
run_case
chk_eq "readable plists without the key -> NotConfigured" "NotConfigured" "$GUEST_ACCOUNT_DISABLED"
reset_plists

##############################################################################
# 4. Missing input: osascript itself fails. Same expectation as case 3.
##############################################################################
echo "--- 4. osascript unavailable"

MOCK_PREFS=(com.apple.MCX/DisableGuestAccount true)
MOCK_OSASCRIPT_FAIL=1
run_case
MOCK_OSASCRIPT_FAIL=0

chk_eq "unreadable prefs -> null (GUEST_ACCOUNT_DISABLED not trusted)" "" "$GUEST_ACCOUNT_DISABLED"
chk_eq "unreadable prefs -> null for every signal" "" \
    "$(signals_except | grep -v '=$')"
chk_eq "osascript failure -> LOGINWINDOW_TEXT_SET null, not No" "" "$LOGINWINDOW_TEXT_SET"
chk_eq "osascript failure -> every _ENFORCED_BY_PROFILE null, never false" "" \
    "$(enforced_flags | grep -v '=$')"

MOCK_PREFS=("${(@kv)COMPLIANT}")
MOCK_OSASCRIPT_GARBAGE=1
run_case
MOCK_OSASCRIPT_GARBAGE=0
chk_eq "osascript output of the wrong shape -> every signal null" "" \
    "$(signals_except | grep -v '=$')"
chk_eq "osascript output of the wrong shape -> every _ENFORCED_BY_PROFILE null" "" \
    "$(enforced_flags | grep -v '=$')"

##############################################################################
# 5. Values of the wrong type (a profile pushing a string or integer where a
#    boolean is expected, or a string where an integer is). Every one falls
#    to null.
##############################################################################
echo "--- 5. Wrong-type values"

MOCK_PREFS=(
    com.apple.applicationaccess/enforcedSoftwareUpdateDelay   "thirty"
    com.apple.security.firewall/EnableStealthMode             1
    com.apple.MCX/DisableGuestAccount                         "yes"
    com.apple.loginwindow/RetriesUntilHint                    "none"
    com.apple.controlcenter/WiFi                              "true"
    com.apple.controlcenter/Bluetooth                         "shown"
)
run_case

chk_eq "non-numeric deferral -> null" "" "$UPDATE_DEFERRAL_DAYS"
chk_eq "integer where bool expected -> null" "" "$FIREWALL_STEALTH_MODE"
chk_eq "string where bool expected -> null" "" "$GUEST_ACCOUNT_DISABLED"
chk_eq "non-numeric RetriesUntilHint -> null" "" "$LOGINWINDOW_PASSWORD_HINTS"
chk_eq "non-integer WiFi value -> null, not No" "" "$WIFI_MENU_VISIBLE"
chk_eq "non-integer Bluetooth value -> null, not No" "" "$BLUETOOTH_MENU_VISIBLE"

##############################################################################
# 6. Present but set locally rather than by a configuration profile.
#    objectForKey resolves across the whole search list (a forced profile
#    value, root's own domain, /Library/Preferences), so the signal keeps
#    reporting the effective value: a genuinely configured Mac with no MDM
#    stays assessable (no MDM prerequisite). The same osascript call asks
#    objectIsForcedForKey, and <SIGNAL>_ENFORCED_BY_PROFILE says which it was:
#    true (forced), false (read succeeded, not forced), "" -> null (read
#    failed, undetermined). PAT-1720.
##############################################################################
echo "--- 6. Locally set value vs profile-enforced value"

# Forced by a profile.
MOCK_PREFS=(com.apple.MCX/DisableGuestAccount true)
MOCK_LOCAL=()
run_case

# The double only answers for the exact "<suite>/<key>" pair, so the Yes
# below also proves the documented suite and key were queried.
chk_eq "query reads DisableGuestAccount once" "1" \
    "$(grep -c "objectForKey('DisableGuestAccount')" "$JXA_LOG")"
chk_eq "forced-ness asked in that same script" "1" \
    "$(grep -c "objectIsForcedForKey('DisableGuestAccount')" "$JXA_LOG")"
chk_eq "forced: DisableGuestAccount=true -> Yes" "Yes" "$GUEST_ACCOUNT_DISABLED"
chk_eq "forced: enforced_by_profile true" "true" "$GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE"

# Set locally, not forced: same value, flag false.
MOCK_PREFS=()
MOCK_LOCAL=(com.apple.MCX/DisableGuestAccount true)
run_case
chk_eq "local: DisableGuestAccount=true still -> Yes (value unchanged)" "Yes" "$GUEST_ACCOUNT_DISABLED"
chk_eq "local: enforced_by_profile false" "false" "$GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE"

# osascript fails: value null as before, flag null, never false.
MOCK_LOCAL=(com.apple.MCX/DisableGuestAccount true)
MOCK_OSASCRIPT_FAIL=1
run_case
MOCK_OSASCRIPT_FAIL=0
chk_eq "osascript failure: DisableGuestAccount null (value unchanged from today)" "" "$GUEST_ACCOUNT_DISABLED"
chk_eq "osascript failure: enforced_by_profile null, not false" "" "$GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE"

# Every key set compliantly, but only locally: every value as if forced,
# every flag false.
MOCK_PREFS=()
MOCK_LOCAL=("${(@kv)COMPLIANT}")
run_case
chk_eq "local compliant values: every signal value unchanged (deferral 30)" "30" "$UPDATE_DEFERRAL_DAYS"
chk_eq "local compliant values: every other signal still Yes" "" \
    "$(signals_except UPDATE_DEFERRAL_DAYS | grep -v '=Yes$')"
chk_eq "local compliant values: every _ENFORCED_BY_PROFILE false" "" \
    "$(enforced_flags | grep -v '=false$')"

MOCK_LOCAL=(com.apple.applicationaccess/enforcedSoftwareUpdateDelay 90)
run_case
chk_eq "local 90-day deferral reported, so it still fails (rule scores null as pass)" "90" "$UPDATE_DEFERRAL_DAYS"
chk_eq "local 90-day deferral: enforced_by_profile false" "false" "$UPDATE_DEFERRAL_DAYS_ENFORCED_BY_PROFILE"

# A key that is not set at all: value null, flag false (the read succeeded
# and no profile forces the key).
MOCK_LOCAL=()
run_case
chk_eq "key not set: NotConfigured" "NotConfigured" "$SIRI_DISABLED"
chk_eq "key not set, read succeeded: enforced_by_profile false" "false" "$SIRI_DISABLED_ENFORCED_BY_PROFILE"

# Firewall logging is composite: enforced only when both keys are forced.
MOCK_PREFS=(com.apple.security.firewall/EnableLogging true com.apple.security.firewall/LoggingOption detail)
MOCK_LOCAL=()
run_case
chk_eq "firewall logging, both keys forced -> Yes, enforced true" "Yes true" \
    "$FIREWALL_LOGGING $FIREWALL_LOGGING_ENFORCED_BY_PROFILE"
MOCK_PREFS=(com.apple.security.firewall/EnableLogging true)
MOCK_LOCAL=(com.apple.security.firewall/LoggingOption detail)
run_case
chk_eq "firewall logging, one key only local -> Yes, enforced false" "Yes false" \
    "$FIREWALL_LOGGING $FIREWALL_LOGGING_ENFORCED_BY_PROFILE"
MOCK_PREFS=()
MOCK_LOCAL=()

# Forced and local keys side by side in one run.
MOCK_PREFS=(com.apple.loginwindow/LoginwindowText "Authorised use only")
MOCK_LOCAL=(com.apple.MCX/DisableGuestAccount false)
run_case
chk_eq "forced LoginwindowText -> Yes, enforced true" "Yes true" \
    "$LOGINWINDOW_TEXT_SET $LOGINWINDOW_TEXT_SET_ENFORCED_BY_PROFILE"
chk_eq "local DisableGuestAccount=false -> No, enforced false" "No false" \
    "$GUEST_ACCOUNT_DISABLED $GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE"
MOCK_PREFS=()
MOCK_LOCAL=()

##############################################################################
# 7. PAT-1767 three-state contract, every changed signal three ways:
#    present -> real value, absent -> NotConfigured, failed read -> null.
#    Plus the absent paths that must NOT become NotConfigured: an unreadable,
#    corrupt or non-dictionary plist, an unlistable ByHost directory, an
#    unsearchable parent directory, and the old header shape.
##############################################################################
echo "--- 7. Present / absent / failed, per signal"

# signal | suite/key | present value | expected for that value
THREE_WAY=(
    "UPDATE_DEFERRAL_DAYS|com.apple.applicationaccess/enforcedSoftwareUpdateDelay|90|90"
    "UPDATE_DEFERRAL_DAYS|com.apple.applicationaccess/enforcedSoftwareUpdateDelay|0|0"
    "FIREWALL_STEALTH_MODE|com.apple.security.firewall/EnableStealthMode|false|No"
    "AIRDROP_DISABLED|com.apple.applicationaccess/allowAirDrop|false|Yes"
    "AIRPLAY_RECEIVER_DISABLED|com.apple.applicationaccess/allowAirPlayIncomingRequests|true|No"
    "TIME_SERVER_HOST|com.apple.MCX/timeServer|time.example.com|Yes"
    "TIME_SERVER_ENFORCED|com.apple.timed/TMAutomaticTimeOnlyEnabled|true|Yes"
    "WIFI_MENU_VISIBLE|com.apple.controlcenter/WiFi|24|No"
    "BLUETOOTH_MENU_VISIBLE|com.apple.controlcenter/Bluetooth|18|Yes"
    "SIRI_DISABLED|com.apple.applicationaccess/allowAssistant|false|Yes"
    "PERSONALIZED_ADS_DISABLED|com.apple.applicationaccess/allowApplePersonalizedAdvertising|true|No"
    "LOGINWINDOW_FULLNAME_PROMPT|com.apple.loginwindow/SHOWFULLNAME|true|Yes"
    "LOGINWINDOW_PASSWORD_HINTS|com.apple.loginwindow/RetriesUntilHint|0|Yes"
    "GUEST_ACCOUNT_DISABLED|com.apple.MCX/DisableGuestAccount|true|Yes"
    "DICTATION_ON_DEVICE|com.apple.applicationaccess/forceOnDeviceOnlyDictation|false|No"
)
reset_plists
MOCK_LOCAL=(); MOCK_FAIL_KEYS=()
for row in "${THREE_WAY[@]}"; do
    parts=( "${(@s:|:)row}" )
    sig="${parts[1]}"; pk="${parts[2]}"; pv="${parts[3]}"; pexp="${parts[4]}"

    MOCK_PREFS=("$pk" "$pv")
    run_case
    chk_eq "$sig present ($pv) -> $pexp" "$pexp" "${(P)sig}"

    MOCK_PREFS=()
    run_case
    chk_eq "$sig absent -> NotConfigured" "NotConfigured" "${(P)sig}"

    MOCK_FAIL_KEYS=("$pk" 1)
    run_case
    MOCK_FAIL_KEYS=()
    chk_eq "$sig failed read -> null, never NotConfigured" "" "${(P)sig}"
    ev="${sig}_ENFORCED_BY_PROFILE"
    chk_eq "$sig failed read -> enforced_by_profile null" "" "${(P)ev}"
done

# An empty string is a set value of the wrong shape, not an unset key.
MOCK_PREFS=(com.apple.MCX/timeServer "")
run_case
chk_eq "timeServer set to an empty string -> null, not NotConfigured" "" "$TIME_SERVER_HOST"
chk_eq "empty timeServer: read succeeded, enforced true" "true" "$TIME_SERVER_HOST_ENFORCED_BY_PROFILE"
MOCK_PREFS=()

# Firewall logging composite, three ways plus the mixed cases.
MOCK_PREFS=(com.apple.security.firewall/EnableLogging true com.apple.security.firewall/LoggingOption detail)
run_case
chk_eq "FIREWALL_LOGGING present -> Yes" "Yes" "$FIREWALL_LOGGING"
MOCK_PREFS=()
run_case
chk_eq "FIREWALL_LOGGING both keys absent -> NotConfigured" "NotConfigured" "$FIREWALL_LOGGING"
MOCK_PREFS=(com.apple.security.firewall/EnableLogging true)
run_case
chk_eq "FIREWALL_LOGGING EnableLogging only -> No (unchanged)" "No" "$FIREWALL_LOGGING"
MOCK_PREFS=(com.apple.security.firewall/LoggingOption detail)
MOCK_FAIL_KEYS=(com.apple.security.firewall/EnableLogging 1)
run_case
chk_eq "FIREWALL_LOGGING EnableLogging read failed -> null, not No" "" "$FIREWALL_LOGGING"
MOCK_PREFS=()
MOCK_FAIL_KEYS=(com.apple.security.firewall/LoggingOption 1)
run_case
chk_eq "FIREWALL_LOGGING one absent, one failed -> null, not NotConfigured" "" "$FIREWALL_LOGGING"
MOCK_FAIL_KEYS=()
MOCK_PREFS=(com.apple.security.firewall/EnableLogging "" com.apple.security.firewall/LoggingOption "")
run_case
chk_eq "FIREWALL_LOGGING both set to empty strings -> null (unchanged)" "" "$FIREWALL_LOGGING"
MOCK_PREFS=()

echo "--- 7b. Unset key but a plist it could live in is unreadable"

# Corrupt domain plist: NSUserDefaults reports nil, which is not absence.
reset_plists
print -r -- "not a plist <dict>" > "$PLIST_ROOT/com.apple.MCX.plist"
run_case
chk_eq "corrupt com.apple.MCX plist -> GUEST_ACCOUNT_DISABLED null" "" "$GUEST_ACCOUNT_DISABLED"
chk_eq "corrupt com.apple.MCX plist -> TIME_SERVER_HOST null" "" "$TIME_SERVER_HOST"
chk_eq "corrupt com.apple.MCX plist -> enforced_by_profile null, not false" "" "$GUEST_ACCOUNT_DISABLED_ENFORCED_BY_PROFILE"
chk_eq "other domains unaffected -> SIRI_DISABLED NotConfigured" "NotConfigured" "$SIRI_DISABLED"

# A present value is never second-guessed by the plist check.
MOCK_PREFS=(com.apple.MCX/DisableGuestAccount true)
run_case
chk_eq "corrupt plist but the key read as set -> Yes (value unchanged)" "Yes" "$GUEST_ACCOUNT_DISABLED"
MOCK_PREFS=()

# A plist whose root is not a dictionary.
reset_plists
write_plist "$PLIST_ROOT/com.apple.applicationaccess.plist" "['allowAirDrop']"
run_case
chk_eq "non-dictionary plist -> AIRDROP_DISABLED null" "" "$AIRDROP_DISABLED"
chk_eq "non-dictionary plist -> DICTATION_ON_DEVICE null" "" "$DICTATION_ON_DEVICE"
chk_eq "non-dictionary plist -> UPDATE_DEFERRAL_DAYS null, never NotConfigured" "" "$UPDATE_DEFERRAL_DAYS"
chk_eq "non-dictionary plist -> deferral enforced_by_profile null" "" "$UPDATE_DEFERRAL_DAYS_ENFORCED_BY_PROFILE"
MOCK_PREFS=(com.apple.applicationaccess/enforcedSoftwareUpdateDelay 14)
run_case
chk_eq "non-dictionary plist but the deferral read as set -> 14 (value unchanged)" "14" "$UPDATE_DEFERRAL_DAYS"
MOCK_PREFS=()

# Corrupt applicationaccess plist: the deferral is undetermined, other
# domains still answer.
reset_plists
print -r -- "not a plist" > "$PLIST_ROOT/com.apple.applicationaccess.plist"
run_case
chk_eq "corrupt applicationaccess plist -> UPDATE_DEFERRAL_DAYS null" "" "$UPDATE_DEFERRAL_DAYS"
chk_eq "corrupt applicationaccess plist -> GUEST_ACCOUNT_DISABLED still NotConfigured" "NotConfigured" "$GUEST_ACCOUNT_DISABLED"

# The global domain plist is also a place the key could come from.
reset_plists
print -r -- "garbage" > "$PLIST_ROOT/.GlobalPreferences.plist"
run_case
chk_eq "corrupt global domain plist -> every signal null, the deferral included" "" \
    "$(signals_except | grep -v '=$')"
chk_eq "corrupt global domain plist -> LOGINWINDOW_TEXT_SET null, not No" "" "$LOGINWINDOW_TEXT_SET"

# Unreadable plist (skipped when the runner is root, which reads anything).
if (( EUID != 0 )); then
    reset_plists
    write_plist "$PLIST_ROOT/com.apple.timed.plist" "{}"
    chmod 000 "$PLIST_ROOT/com.apple.timed.plist"
    run_case
    chk_eq "unreadable com.apple.timed plist -> TIME_SERVER_ENFORCED null" "" "$TIME_SERVER_ENFORCED"

    reset_plists
    write_plist "$PLIST_ROOT/com.apple.applicationaccess.plist" "{}"
    chmod 000 "$PLIST_ROOT/com.apple.applicationaccess.plist"
    run_case
    chk_eq "unreadable applicationaccess plist -> UPDATE_DEFERRAL_DAYS null" "" "$UPDATE_DEFERRAL_DAYS"

    reset_plists
    mkdir -p "$PLIST_ROOT/locked"
    MOCK_EXTRA_PLISTS=( "$PLIST_ROOT/locked/sub/com.apple.timed.plist" )
    chmod 000 "$PLIST_ROOT/locked"
    run_case
    chk_eq "unsearchable ancestor directory -> TIME_SERVER_ENFORCED null" "" "$TIME_SERVER_ENFORCED"
fi

# A directory where a plist should be.
reset_plists
mkdir -p "$PLIST_ROOT/com.apple.loginwindow.plist"
run_case
chk_eq "directory in place of the plist -> LOGINWINDOW_FULLNAME_PROMPT null" "" "$LOGINWINDOW_FULLNAME_PROMPT"
chk_eq "directory in place of the plist -> LOGINWINDOW_TEXT_SET null, not No" "" "$LOGINWINDOW_TEXT_SET"

# ByHost preferences that cannot be listed.
reset_plists
MOCK_BYHOST_UNLISTABLE=1
run_case
chk_eq "unlistable ByHost directory -> every signal null" "" "$(signals_except | grep -v '=$')"
reset_plists

# Output in the pre-PAT-1767 shape (bare forced flag) is not a successful read.
MOCK_OLD_HEADER=1
MOCK_LOCAL=(com.apple.MCX/DisableGuestAccount true)
run_case
MOCK_OLD_HEADER=0
MOCK_LOCAL=()
chk_eq "bare forced-flag header -> every signal null" "" "$(signals_except | grep -v '=$')"

##############################################################################
# 8. Helper and emitter guards.
##############################################################################
echo "--- 8. Helper and emitter guards"

: > "$JXA_LOG"
managed_pref_read "com.apple.MCX');evil('" "DisableGuestAccount"
chk_eq "domain outside [A-Za-z0-9._-] refused, returns non-zero" "1" "$?"
chk_eq "refused domain never reaches osascript" "0" "$(grep -c . "$JXA_LOG")"
managed_pref_read "com.apple.MCX" "Disable Guest"
chk_eq "key outside [A-Za-z0-9._-] refused" "1 " "$? $MANAGED_PREF_FORCED"

MOCK_PREFS=(com.apple.loginwindow/LoginwindowText $'Line one\nLine two')
managed_pref_read "com.apple.loginwindow" "LoginwindowText"
chk_eq "multi-line value kept whole after the header line" $'true|true|Line one\nLine two' \
    "$MANAGED_PREF_FORCED|$MANAGED_PREF_SET|$MANAGED_PREF_VALUE"
MOCK_PREFS=()
managed_pref_read "com.apple.MCX" "DisableGuestAccount"
chk_eq "unset key: read succeeds, set=false, empty value" "0|false|false|" \
    "$?|$MANAGED_PREF_FORCED|$MANAGED_PREF_SET|$MANAGED_PREF_VALUE"
MOCK_PREFS=(com.apple.loginwindow/LoginwindowText $'Line one\nLine two')
chk_eq "read_managed_pref still prints the effective value" $'Line one\nLine two' \
    "$(read_managed_pref "com.apple.loginwindow" "LoginwindowText")"
MOCK_PREFS=()

chk_eq "json_bool_or_null true" "true" "$(json_bool_or_null true)"
chk_eq "json_bool_or_null false" "false" "$(json_bool_or_null false)"
chk_eq "json_bool_or_null empty -> null" "null" "$(json_bool_or_null "")"
chk_eq "json_bool_or_null anything else -> null" "null" "$(json_bool_or_null 'true, "x": 1')"

chk_eq "json_int_or_notconfigured 30" "30" "$(json_int_or_notconfigured 30)"
chk_eq "json_int_or_notconfigured 0" "0" "$(json_int_or_notconfigured 0)"
chk_eq "json_int_or_notconfigured leading zeros dropped" "365" "$(json_int_or_notconfigured 000365)"
chk_eq "json_int_or_notconfigured NotConfigured -> quoted string" '"NotConfigured"' "$(json_int_or_notconfigured NotConfigured)"
chk_eq "json_int_or_notconfigured empty -> null" "null" "$(json_int_or_notconfigured "")"
typeset -a BAD_NUMBERS=( "-5" "3.5" "30 " " 30" "30, \"x\": 1" "notconfigured" "Unknown" "1234567890123456789" $'30\n31' )
for bad_number in "${BAD_NUMBERS[@]}"; do
    chk_eq "json_int_or_notconfigured [${bad_number//$'\n'/|}] -> null" "null" "$(json_int_or_notconfigured "$bad_number")"
done

##############################################################################
# 9. Payload JSON type (PAT-1775). The update_deferral_days line is taken from
#    the real patched-collect.sh payload heredoc, expanded with this shell's
#    variables and parsed as JSON: a present value must arrive as a JSON
#    integer, an unset key as the JSON string "NotConfigured", a failed read
#    as null.
##############################################################################
echo "--- 9. Payload JSON type"

# payload_json_type <json-key>
# Prints int:<n>, str:<s>, null, bool:<b>, missing (no such payload line) or
# invalid (the rendered line is not JSON).
payload_json_type() {
    local pj_line pj_rendered
    pj_line=$(grep -m 1 -E "^[[:space:]]+\"$1\":" "$SCRIPT_DIR/../patched-collect.sh") || { print -r -- "missing"; return; }
    pj_rendered=$(eval "cat <<__PAYLOAD_LINE__
{${pj_line%,}}
__PAYLOAD_LINE__")
    print -r -- "$pj_rendered" | "$PYTHON3" -c '
import json, sys
try:
    v = next(iter(json.load(sys.stdin).values()))
except Exception:
    print("invalid"); sys.exit(0)
if v is None: print("null")
elif isinstance(v, bool): print("bool:%s" % v)
elif isinstance(v, int): print("int:%d" % v)
elif isinstance(v, str): print("str:" + v)
else: print("other:%r" % (v,))
'
}

reset_plists
MOCK_LOCAL=(); MOCK_FAIL_KEYS=()
MOCK_PREFS=(com.apple.applicationaccess/enforcedSoftwareUpdateDelay 30)
run_case
chk_eq "payload: deferral present -> JSON integer 30" "int:30" "$(payload_json_type update_deferral_days)"
MOCK_PREFS=()
run_case
chk_eq "payload: deferral unset -> JSON string NotConfigured" "str:NotConfigured" "$(payload_json_type update_deferral_days)"
MOCK_FAIL_KEYS=(com.apple.applicationaccess/enforcedSoftwareUpdateDelay 1)
run_case
MOCK_FAIL_KEYS=()
chk_eq "payload: deferral failed read -> JSON null" "null" "$(payload_json_type update_deferral_days)"
MOCK_PREFS=(com.apple.applicationaccess/enforcedSoftwareUpdateDelay "thirty")
run_case
MOCK_PREFS=()
chk_eq "payload: deferral wrong type -> JSON null" "null" "$(payload_json_type update_deferral_days)"
chk_eq "payload: enforced_by_profile companion still a JSON bool" "bool:True" "$(payload_json_type update_deferral_days_enforced_by_profile)"

echo
echo "RESULT: pass=$pass fail=$fail known_gaps=$gaps"
[[ $fail -eq 0 ]]
