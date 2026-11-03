#!/bin/zsh
##############################################################################
# test-screensaver.zsh — unit tests for the screensaver lock policy
# collector (collect_screensaver) in screensaver.sh (PAT-1696).
#
# Sources the live functions out of common.sh (log_warn) and screensaver.sh
# (no top-level side effects at source time) so the tests exercise the real
# code, not a copy. `dscl` is
# shadowed with a zsh function of the same name (zsh resolves a function
# before an external command) and answers NFSHomeDirectory with a scratch
# fixture home, so the runner's own user and preferences are never read.
# HW_UUID is set per case to the fixture ByHost plist's UUID, so the runner's
# own hardware UUID is never used either. `stat` (console_user's
# `stat -f %Su /dev/console`) is shadowed the same way, so the runner's own
# console session never picks the subject user (PAT-1723).
# The fixture plists are written with plistlib and read by the real
# /usr/libexec/PlistBuddy, because PlistBuddy's text rendering (true/false,
# 5.000000) is exactly what the collector parses.
#
# patched-collect.sh runs every module with `setopt NULL_GLOB`, but the
# module must not depend on it (PAT-1710), so this harness runs with
# NULL_GLOB explicitly OFF.
#
# On macOS 12 and earlier, absent askForPassword = "DefaultAssumed" is
# intended (the key is only written once the user changes the setting; see
# repo AGENTS.md), but only
# once every place the key could live was actually read. Input that could not
# be read reports "Unknown" plus a reason on stderr (PAT-1710 closed the
# PAT-1696 KNOWN-GAPs that pinned those paths to DefaultAssumed).
#
# Precedence (PAT-1722): the current-host ByHost plist wins over the main
# plist, because CFPreferences resolves current-host before any-host. That
# was confirmed on macOS 26 by writing conflicting values with `defaults write`
# and `defaults -currentHost write` to a throwaway domain and reading them
# back through CFPreferencesCopyAppValue and NSUserDefaults.
#
# Source by macOS version (PAT-1743): sections 1 to 10 run with OS_VERSION
# 12.7.6 and exercise the plist path. Section 11 covers macOS 13 and later,
# where the collector reads `sysadminctl -screenLock status` as the subject
# user instead. `id` and `launchctl` are shadowed with zsh functions, so the
# runner's own uid and screen lock setting are never read and the argv the
# collector passes to launchctl is asserted.
#
# Inactivity interval (PAT-1753): section 12 covers idleTime, read on every
# macOS version by a JXA NSUserDefaults call run as the subject user. The
# launchctl double tells the two calls apart by argv: an osascript call is
# logged to IDLE_LOG and answers MOCK_IDLE_OUT on stdout, anything else is the
# sysadminctl call above. Precedence between a profile-forced value and the
# user's own value is CFPreferences' resolution inside that call, not code in
# the collector, so the double answers with the resolved line and the tests
# pin what the collector does with it, that the call runs as the subject user
# (as root the per-user managed and ByHost values are invisible) and that it
# asks for the effective value and objectIsForcedForKey.
#
# NotConfigured (PAT-1775, the PAT-1767 contract): an unset idleTime is
# "NotConfigured" only when every plist the user's search list could have
# taken it from is absent or a readable dictionary. The real _ss_idle_plists
# is kept, and wrapped so its /Library/ paths (Managed Preferences and
# /Library/Preferences) point at a scratch FIXTURE_LIBRARY; the user's own
# plists already live under the fixture home. The real prefs_plists_readable
# then checks them, so the runner's own preferences are never read. Section
# 13 covers present / absent / failed and every plist that must block
# NotConfigured, and asserts the JSON type the real payload line emits. Run:
#   zsh macos/lib/test-screensaver.zsh
##############################################################################

set -u
unsetopt NULL_GLOB
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/screensaver.sh"

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
MOCK_HOME=""
MOCK_DSCL_FAIL=0
typeset -A MOCK_USER_HOMES   # user -> home; a user not listed gets MOCK_HOME
dscl() {
    (( MOCK_DSCL_FAIL )) && { print -u2 "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"; return 56; }
    [[ "$1" == "." && "$2" == "read" && "$4" == "NFSHomeDirectory" ]] || return 1
    local dscl_user="${3#/Users/}"
    if (( ${+MOCK_USER_HOMES[$dscl_user]} )); then
        print -r -- "NFSHomeDirectory: ${MOCK_USER_HOMES[$dscl_user]}"
    else
        print -r -- "NFSHomeDirectory: $MOCK_HOME"
    fi
}
MOCK_CONSOLE_USER=""
stat() {
    [[ "$*" == "-f %Su /dev/console" ]] || return 1
    print -r -- "$MOCK_CONSOLE_USER"
}
typeset -A MOCK_UIDS=( alice 501 bob 502 )
id() {
    [[ "$1" == "-u" && $# -eq 2 ]] || return 1
    (( ${+MOCK_UIDS[$2]} )) || { print -u2 "id: $2: no such user"; return 1; }
    print -r -- "${MOCK_UIDS[$2]}"
}
MOCK_SCREENLOCK_OUT=""      # what sysadminctl prints (stdout and stderr merged)
MOCK_SCREENLOCK_RC=0
# The collector calls launchctl inside a command substitution (a subshell),
# so each call's argv is appended to a file rather than a shell variable.
LAUNCHCTL_LOG=$(mktemp)
MOCK_IDLE_OUT="false int:600"   # what the JXA idleTime read prints (stdout)
MOCK_IDLE_RC=0
IDLE_LOG=$(mktemp)      # one line per osascript call: argv without the script
IDLE_SCRIPT=$(mktemp)   # the script text of the last osascript call
launchctl() {
    if [[ "$*" == *" /usr/bin/osascript "* ]]; then
        print -r -- "${(j: :)@[1,-2]}" >> "$IDLE_LOG"
        print -r -- "${@[-1]}" > "$IDLE_SCRIPT"
        [[ -n "$MOCK_IDLE_OUT" ]] && print -r -- "$MOCK_IDLE_OUT"
        return $MOCK_IDLE_RC
    fi
    print -r -- "$*" >> "$LAUNCHCTL_LOG"
    [[ -n "$MOCK_SCREENLOCK_OUT" ]] && print -r -- "$MOCK_SCREENLOCK_OUT" >&2
    return $MOCK_SCREENLOCK_RC
}
# Keep the real search-list builder, but map its /Library/ paths into a
# fixture so the runner's /Library/Managed Preferences is never consulted.
FIXTURE_LIBRARY=$(mktemp -d)
functions -c _ss_idle_plists _ss_idle_plists_real
_ss_idle_plists() {
    _ss_idle_plists_real "$@" || return 1
    _SS_IDLE_PLISTS=( "${_SS_IDLE_PLISTS[@]/#\/Library\//$FIXTURE_LIBRARY/}" )
    return 0
}
launchctl_calls() { wc -l < "$LAUNCHCTL_LOG" | tr -d ' '; }
launchctl_argv() { tail -n 1 "$LAUNCHCTL_LOG"; }
idle_calls() { wc -l < "$IDLE_LOG" | tr -d ' '; }
idle_argv() { tail -n 1 "$IDLE_LOG"; }
MOCK_OS_VERSION="12.7.6"

# write_plist <path> <python dict literal>
write_plist() {
    mkdir -p "${1:h}"
    "$PYTHON3" -c "
import plistlib, sys
with open(sys.argv[1], 'wb') as f:
    plistlib.dump($2, f)
" "$1"
}

new_home() {
    MOCK_HOME=$(mktemp -d)
    mkdir -p "$MOCK_HOME/Library/Preferences/ByHost"
}
MAIN_PLIST() { print -r -- "$MOCK_HOME/Library/Preferences/com.apple.screensaver.plist"; }
MOCK_HW_UUID="00000000-0000-0000-0000-000000000000"
OTHER_HW_UUID="11111111-2222-3333-4444-555555555555"
BYHOST_PLIST() { print -r -- "$MOCK_HOME/Library/Preferences/ByHost/com.apple.screensaver.${1-$MOCK_HW_UUID}.plist"; }

ERR_LOG=$(mktemp)
# run_case [first_user] [hw_uuid] [console_user]
# The console user defaults to FIRST_USER, so every case that does not name
# one reads a single logged-in account, as before PAT-1723.
run_case() {
    FIRST_USER="${1-alice}"
    HW_UUID="${2-$MOCK_HW_UUID}"
    MOCK_CONSOLE_USER="${3-$FIRST_USER}"
    OS_VERSION="$MOCK_OS_VERSION"
    : > "$LAUNCHCTL_LOG"
    : > "$IDLE_LOG"
    SCREENSAVER_PASSWORD="__unset__"
    SCREENSAVER_DELAY_SECONDS="__unset__"
    SCREENSAVER_IDLE_SECONDS="__unset__"
    SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE="__unset__"
    collect_screensaver 2> "$ERR_LOG"
}
# warned <substring> -> 1 if the last run logged a warning containing it
warned() { grep -F -c -- "$1" "$ERR_LOG"; }

##############################################################################
# 1. Set, expected: password required, integer delay.
##############################################################################
echo "--- 1. askForPassword true, delay 5"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5}"
run_case

chk_eq "SCREENSAVER_PASSWORD Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "SCREENSAVER_DELAY_SECONDS 5" "5" "$SCREENSAVER_DELAY_SECONDS"

##############################################################################
# 2. Set, unexpected: password not required, real-typed long delay.
##############################################################################
echo "--- 2. askForPassword false, delay 300.0"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 300.0}"
run_case

chk_eq "SCREENSAVER_PASSWORD No" "No" "$SCREENSAVER_PASSWORD"
chk_eq "real delay truncated to whole seconds" "300" "$SCREENSAVER_DELAY_SECONDS"

##############################################################################
# 3. ByHost plist only (integer-typed 1 / 0), and ByHost precedence over the
#    main plist when both set the key (PAT-1722).
##############################################################################
echo "--- 3. ByHost plist and precedence"

new_home
write_plist "$(BYHOST_PLIST)" "{'askForPassword': 1, 'askForPasswordDelay': 0}"
run_case
chk_eq "ByHost integer 1 -> Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "ByHost delay 0" "0" "$SCREENSAVER_DELAY_SECONDS"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 60}"
write_plist "$(BYHOST_PLIST)" "{'askForPassword': False}"
run_case
chk_eq "ByHost wins over main plist" "No" "$SCREENSAVER_PASSWORD"
chk_eq "delay falls through to main when ByHost lacks it" "60" "$SCREENSAVER_DELAY_SECONDS"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': 1, 'askForPasswordDelay': 5}"
write_plist "$(BYHOST_PLIST)" "{'askForPassword': 0, 'askForPasswordDelay': 300}"
run_case
chk_eq "main 1, ByHost 0 -> follows ByHost (No)" "No" "$SCREENSAVER_PASSWORD"
chk_eq "main 5, ByHost 300 -> ByHost delay" "300" "$SCREENSAVER_DELAY_SECONDS"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': 0, 'askForPasswordDelay': 300}"
write_plist "$(BYHOST_PLIST)" "{'askForPassword': 1, 'askForPasswordDelay': 5}"
run_case
chk_eq "main 0, ByHost 1 -> follows ByHost (Yes)" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "main 300, ByHost 5 -> ByHost delay" "5" "$SCREENSAVER_DELAY_SECONDS"

##############################################################################
# 4. Unset: plist exists without the keys, or no plist at all. Documented
#    default: password DefaultAssumed, delay null.
##############################################################################
echo "--- 4. Keys unset"

new_home
write_plist "$(MAIN_PLIST)" "{'idleTime': 600}"
run_case
chk_eq "keys absent -> DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"
chk_eq "keys absent -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"

new_home
run_case
chk_eq "no plist -> DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"
chk_eq "no plist -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "genuine default logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"

MOCK_HOME=$(mktemp -d)
run_case
chk_eq "home with no Library/Preferences yet -> DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"

##############################################################################
# 5. Wrong type. The delay falls to null correctly; a wrong-type
#    askForPassword falls to DefaultAssumed, i.e. an unparseable value is
#    reported as Apple's secure default.
##############################################################################
echo "--- 5. Wrong-type values"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': 'no', 'askForPasswordDelay': 'five'}"
run_case
chk_eq "string delay -> null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "string askForPassword='no' -> Unknown, not DefaultAssumed" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "wrong type logs a reason" "1" "$(warned 'unexpected value type')"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True}"
write_plist "$(BYHOST_PLIST)" "{'askForPassword': 2}"
run_case
chk_eq "out-of-range integer in ByHost plist -> Unknown (main cannot stand in)" "Unknown" "$SCREENSAVER_PASSWORD"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': 2}"
run_case
chk_eq "out-of-range integer in main plist, no ByHost -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"

##############################################################################
# 6. Missing or unreadable input. Delay is null and the password signal is
#    "Unknown" with a reason whenever the collector could not read everywhere
#    the key could live. Only a complete read may conclude DefaultAssumed.
##############################################################################
echo "--- 6. Missing or unreadable input"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 5}"

run_case ""
chk_eq "no FIRST_USER -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "no FIRST_USER -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "no FIRST_USER logs a reason" "1" "$(warned 'no local user')"

MOCK_DSCL_FAIL=1
run_case
MOCK_DSCL_FAIL=0
chk_eq "dscl failure -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "dscl failure (home unknown) -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "dscl failure logs a reason" "1" "$(warned 'home directory lookup failed')"

SAVED_HOME="$MOCK_HOME"
MOCK_HOME="$SAVED_HOME/does-not-exist"
run_case
MOCK_HOME="$SAVED_HOME"
chk_eq "home directory missing -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "home directory missing logs a reason" "1" "$(warned 'home directory not searchable')"

if (( EUID == 0 )); then
    echo "  SKIP: running as root, file permissions cannot make the plist unreadable"
else
    chmod 000 "$(MAIN_PLIST)"
    run_case
    chmod 644 "$(MAIN_PLIST)"
    chk_eq "unreadable plist -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
    chk_eq "unreadable plist holding askForPassword=false -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "unreadable plist logs a reason" "1" "$(warned 'askForPassword undetermined (unreadable plist')"

    new_home
    write_plist "$(MAIN_PLIST)" "{'idleTime': 600}"
    write_plist "$(BYHOST_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 5}"
    chmod 000 "$(BYHOST_PLIST)"
    run_case
    chmod 644 "$(BYHOST_PLIST)"
    chk_eq "main lacks key, ByHost plist unreadable -> Unknown, not DefaultAssumed" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "main lacks key, ByHost plist unreadable -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"

    new_home
    write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5}"
    write_plist "$(BYHOST_PLIST)" "{'askForPassword': False}"
    chmod 000 "$(BYHOST_PLIST)"
    run_case
    chmod 644 "$(BYHOST_PLIST)"
    chk_eq "ByHost plist unreadable, main holds key -> Unknown (main cannot stand in)" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "ByHost plist unreadable, main holds delay -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"

    new_home
    write_plist "$(MAIN_PLIST)" "{'askForPassword': False}"
    write_plist "$(BYHOST_PLIST)" "{'idleTime': 600}"
    chmod 000 "$(MAIN_PLIST)"
    run_case
    chmod 644 "$(MAIN_PLIST)"
    chk_eq "ByHost lacks key, main plist unreadable -> Unknown, not DefaultAssumed" "Unknown" "$SCREENSAVER_PASSWORD"

    new_home
    write_plist "$(MAIN_PLIST)" "{'askForPassword': True}"
    write_plist "$(BYHOST_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 5}"
    chmod 000 "$(MAIN_PLIST)"
    run_case
    chmod 644 "$(MAIN_PLIST)"
    chk_eq "definitive ByHost is not undone by an unreadable lower-precedence main" "No" "$SCREENSAVER_PASSWORD"
    chk_eq "definitive ByHost delay kept" "5" "$SCREENSAVER_DELAY_SECONDS"

    new_home
    write_plist "$(BYHOST_PLIST)" "{'askForPassword': False}"
    chmod 000 "$MOCK_HOME/Library/Preferences/ByHost"
    run_case
    chmod 755 "$MOCK_HOME/Library/Preferences/ByHost"
    chk_eq "ByHost directory unreadable -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "ByHost directory unreadable logs a reason" "1" "$(warned 'ByHost directory not readable')"

    new_home
    chmod 000 "$MOCK_HOME/Library/Preferences"
    run_case
    chmod 755 "$MOCK_HOME/Library/Preferences"
    chk_eq "Preferences directory unreadable -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "Preferences directory unreadable logs a reason" "1" "$(warned 'preferences directory not readable')"
fi

new_home
mkdir -p "${$(MAIN_PLIST):h}"
print -r -- "not a plist" > "$(MAIN_PLIST)"
run_case
chk_eq "corrupt plist -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "corrupt plist -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "corrupt plist logs a reason" "1" "$(warned 'askForPassword undetermined (unparseable plist')"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5}"
print -r -- "not a plist" > "$(BYHOST_PLIST)"
run_case
chk_eq "corrupt higher-precedence ByHost -> Unknown even with a definitive main" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "corrupt higher-precedence ByHost -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "corrupt ByHost logs a reason" "1" "$(warned 'askForPassword undetermined (unparseable plist')"

new_home
write_plist "$(BYHOST_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5}"
print -r -- "not a plist" > "$(MAIN_PLIST)"
run_case
chk_eq "definitive ByHost is not undone by a corrupt lower-precedence main" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "definitive ByHost delay kept" "5" "$SCREENSAVER_DELAY_SECONDS"

##############################################################################
# 7. The module does not depend on the caller's NULL_GLOB. This harness runs
#    with it off, so every case above with no ByHost plist already covers
#    the empty glob; this pins it explicitly.
##############################################################################
echo "--- 7. NULL_GLOB off"

chk_eq "harness runs with NULL_GLOB off" "off" "$([[ -o NULL_GLOB ]] && echo on || echo off)"
new_home
run_case
chk_eq "empty ByHost glob without NULL_GLOB -> DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"
chk_eq "empty ByHost glob without NULL_GLOB -> no error output" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"

##############################################################################
# 8. Only the current host's ByHost plist counts (PAT-1722). ByHost plists
#    named for another hardware UUID (Migration Assistant leaves these behind)
#    are never read by macOS. Without a usable HW_UUID the current-host plist
#    cannot be identified, which is undetermined only when a ByHost plist
#    exists.
##############################################################################
echo "--- 8. Current-host ByHost selection"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5}"
write_plist "$(BYHOST_PLIST "$OTHER_HW_UUID")" "{'askForPassword': False, 'askForPasswordDelay': 300}"
run_case
chk_eq "another host's ByHost is ignored, main applies" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "another host's ByHost delay is ignored" "5" "$SCREENSAVER_DELAY_SECONDS"

new_home
write_plist "$(BYHOST_PLIST "$OTHER_HW_UUID")" "{'askForPassword': False}"
print -r -- "not a plist" > "$(BYHOST_PLIST "${OTHER_HW_UUID/1111/9999}")"
run_case
chk_eq "only other hosts' ByHost plists (one corrupt) -> DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"
chk_eq "other hosts' ByHost plists log no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True}"
write_plist "$(BYHOST_PLIST)" "{'askForPassword': False}"
run_case alice "Unknown"
chk_eq "HW_UUID Unknown with a ByHost plist present -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "HW_UUID Unknown with a ByHost plist present -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "HW_UUID Unknown logs a reason" "1" "$(warned 'hardware UUID unknown')"

run_case alice ""
chk_eq "HW_UUID empty with a ByHost plist present -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"

run_case alice "../../../../tmp/x"
chk_eq "malformed HW_UUID is not used as a path -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"

new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 5}"
run_case alice "Unknown"
chk_eq "HW_UUID Unknown, no ByHost plist at all -> main applies" "No" "$SCREENSAVER_PASSWORD"
chk_eq "HW_UUID Unknown, no ByHost plist at all -> main delay" "5" "$SCREENSAVER_DELAY_SECONDS"

new_home
run_case alice "Unknown"
chk_eq "HW_UUID Unknown, no plists at all -> DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"

##############################################################################
# 9. Subject user (PAT-1723). Two local accounts whose settings disagree:
#    alice (lowest UID, FIRST_USER) does not require a password, bob does.
#    The logged-in console user is the subject; with nobody logged in
#    (no console owner, root, or loginwindow) the collector falls back to
#    FIRST_USER and says so on stderr.
##############################################################################
echo "--- 9. Subject user"

new_home; ALICE_HOME="$MOCK_HOME"
write_plist "$(MAIN_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 300}"
new_home; BOB_HOME="$MOCK_HOME"
write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5}"
MOCK_HOME="/nonexistent-unmapped-user-home"
MOCK_USER_HOMES=( alice "$ALICE_HOME" bob "$BOB_HOME" )

run_case alice "$MOCK_HW_UUID" bob
chk_eq "console user bob, FIRST_USER alice -> bob's value" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "console user bob, FIRST_USER alice -> bob's delay" "5" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "console user read logs no fallback reason" "0" "$(warned 'no console user logged in')"

run_case alice "$MOCK_HW_UUID" alice
chk_eq "console user alice -> alice's value" "No" "$SCREENSAVER_PASSWORD"
chk_eq "console user alice -> alice's delay" "300" "$SCREENSAVER_DELAY_SECONDS"

run_case alice "$MOCK_HW_UUID" ""
chk_eq "nobody logged in -> FIRST_USER alice's value" "No" "$SCREENSAVER_PASSWORD"
chk_eq "nobody logged in -> FIRST_USER alice's delay" "300" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "nobody logged in logs the fallback reason naming the account" "1" "$(warned 'no console user logged in, reading the lowest-UID local account (alice)')"

run_case alice "$MOCK_HW_UUID" root
chk_eq "console owner root is nobody logged in -> FIRST_USER's value" "No" "$SCREENSAVER_PASSWORD"
chk_eq "console owner root logs the fallback reason" "1" "$(warned 'no console user logged in')"

run_case alice "$MOCK_HW_UUID" loginwindow
chk_eq "console owner loginwindow is nobody logged in -> FIRST_USER's value" "No" "$SCREENSAVER_PASSWORD"
chk_eq "console owner loginwindow logs the fallback reason" "1" "$(warned 'no console user logged in')"

run_case "" "$MOCK_HW_UUID" bob
chk_eq "console user bob with no FIRST_USER -> bob's value" "Yes" "$SCREENSAVER_PASSWORD"

run_case "" "$MOCK_HW_UUID" loginwindow
chk_eq "nobody logged in and no FIRST_USER -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "nobody logged in and no FIRST_USER -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "nobody logged in and no FIRST_USER logs a reason" "1" "$(warned 'no local user')"

run_case alice "$MOCK_HW_UUID" carol
chk_eq "console user whose home cannot be searched -> Unknown, FIRST_USER does not stand in" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "console user whose home cannot be searched logs a reason" "1" "$(warned 'home directory not searchable')"
MOCK_USER_HOMES=()

##############################################################################
# 10. HW_UUID "Unknown", as collect_hardware emits when ioreg fails or is
#     empty (PAT-1723), routes to the malformed-UUID branch, not a path.
##############################################################################
echo "--- 10. HW_UUID sentinel from collect_hardware"

source "$SCRIPT_DIR/hardware.sh"
ioreg() { return 1; }
collect_hardware
unfunction ioreg
new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True}"
write_plist "$(BYHOST_PLIST)" "{'askForPassword': False}"
SS_HW_UUID="$HW_UUID"
run_case alice "$SS_HW_UUID"
chk_eq "collect_hardware with failed ioreg sets HW_UUID Unknown" "Unknown" "$SS_HW_UUID"
chk_eq "HW_UUID from failed ioreg with a ByHost plist present -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "HW_UUID from failed ioreg logs the hardware UUID reason" "1" "$(warned 'hardware UUID unknown')"

##############################################################################
# 11. macOS 13 and later (PAT-1743). The lock setting is system-managed and
#     no longer lives in com.apple.screensaver, so the collector reads
#     `sysadminctl -screenLock status` as the subject user and never the
#     plists. Output that is not exactly one recognised screenLock line, or a
#     non-zero exit, is "Unknown" with a null delay, never DefaultAssumed.
##############################################################################
echo "--- 11. macOS 13+ sysadminctl -screenLock status"

NSLOG_PREFIX="2026-09-14 10:02:40.051 sysadminctl[51089:29832649] "
MOCK_OS_VERSION="26.0.1"

# The tenant-zero case: plists carry no askForPassword, the real setting is a
# 60-minute delay. A plist that says the opposite must not be consulted.
new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 5}"
MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 3600 seconds"; MOCK_SCREENLOCK_RC=0
run_case
chk_eq "3600-second delay -> Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "3600-second delay -> 3600" "3600" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "sysadminctl runs as the console user via launchctl asuser" \
    "asuser 501 /usr/bin/sudo -u alice /usr/sbin/sysadminctl -screenLock status" "$(launchctl_argv)"
chk_eq "sysadminctl runs once" "1" "$(launchctl_calls)"
chk_eq "recognised output logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"

MOCK_OS_VERSION="13.0"
MOCK_SCREENLOCK_OUT="screenLock delay is 300 seconds"
run_case
chk_eq "macOS 13.0 uses sysadminctl" "1" "$(launchctl_calls)"
chk_eq "line without the NSLog prefix is accepted -> Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "line without the NSLog prefix is accepted -> 300" "300" "$SCREENSAVER_DELAY_SECONDS"
MOCK_OS_VERSION="26.0.1"

MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is immediate"
run_case
chk_eq "immediate -> Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "immediate -> delay 0" "0" "$SCREENSAVER_DELAY_SECONDS"

MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 0 seconds"
run_case
chk_eq "delay 0 seconds -> Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "delay 0 seconds -> 0" "0" "$SCREENSAVER_DELAY_SECONDS"

MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock is off"
run_case
chk_eq "off -> No" "No" "$SCREENSAVER_PASSWORD"
chk_eq "off -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "off logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"

# Failed reads. Each case keeps a plist with no askForPassword in the home,
# which the old path would have reported as DefaultAssumed.
new_home
write_plist "$(MAIN_PLIST)" "{'idleTime': 600}"

MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 3600 seconds"; MOCK_SCREENLOCK_RC=1
run_case
chk_eq "non-zero exit with a valid-looking line -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "non-zero exit -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "non-zero exit logs a reason" "1" "$(warned 'screen lock undetermined (sysadminctl -screenLock status exited 1)')"

MOCK_SCREENLOCK_OUT="sudo: /usr/sbin/sysadminctl: command not found"; MOCK_SCREENLOCK_RC=1
run_case
chk_eq "missing sysadminctl -> Unknown, not DefaultAssumed" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "missing sysadminctl -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
MOCK_SCREENLOCK_RC=0

typeset -a BAD_OUTPUTS=(
    "garbage output"
    ""
    "${NSLOG_PREFIX}Unknown state for screenLock (42)"
    "${NSLOG_PREFIX}screenLock delay is -1 seconds"
    "${NSLOG_PREFIX}screenLock delay is 0600 seconds"
    "${NSLOG_PREFIX}screenLock delay is 12345678901 seconds"
    "${NSLOG_PREFIX}screenLock delay is 3600 seconds trailing"
    "prefix screenLock delay is 3600 seconds"
    "${NSLOG_PREFIX}screenLock delay is 3600 seconds"$'\n'"${NSLOG_PREFIX}screenLock is off"
)
for bad_out in "${BAD_OUTPUTS[@]}"; do
    MOCK_SCREENLOCK_OUT="$bad_out"
    run_case
    chk_eq "unrecognised output [${bad_out//$'\n'/ | }] -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "unrecognised output [${bad_out//$'\n'/ | }] -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
    chk_eq "unrecognised output [${bad_out//$'\n'/ | }] logs a reason" "1" "$(warned 'unrecognised sysadminctl -screenLock status output')"
done

MOCK_SCREENLOCK_OUT="some unrelated warning"$'\n'"${NSLOG_PREFIX}screenLock delay is 60 seconds"
run_case
chk_eq "one screenLock line among unrelated lines -> Yes" "Yes" "$SCREENSAVER_PASSWORD"
chk_eq "one screenLock line among unrelated lines -> 60" "60" "$SCREENSAVER_DELAY_SECONDS"

MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 5 seconds"
run_case carol
chk_eq "uid lookup failure -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "uid lookup failure -> sysadminctl not run" "0" "$(launchctl_calls)"
chk_eq "uid lookup failure logs a reason" "1" "$(warned 'uid lookup failed for carol')"

# Subject user on 13+: the same selection as the plist path.
run_case alice "$MOCK_HW_UUID" bob
chk_eq "console user bob -> sysadminctl runs as bob" \
    "asuser 502 /usr/bin/sudo -u bob /usr/sbin/sysadminctl -screenLock status" "$(launchctl_argv)"
run_case alice "$MOCK_HW_UUID" loginwindow
chk_eq "nobody logged in -> sysadminctl runs as FIRST_USER" \
    "asuser 501 /usr/bin/sudo -u alice /usr/sbin/sysadminctl -screenLock status" "$(launchctl_argv)"
chk_eq "nobody logged in on 13+ logs the fallback reason" "1" "$(warned 'no console user logged in, reading the lowest-UID local account (alice)')"
run_case "" "$MOCK_HW_UUID" loginwindow
chk_eq "nobody logged in and no FIRST_USER on 13+ -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
chk_eq "nobody logged in and no FIRST_USER on 13+ -> sysadminctl not run" "0" "$(launchctl_calls)"
chk_eq "nobody logged in and no FIRST_USER on 13+ logs a reason" "1" "$(warned 'no local user')"

# A version that cannot be parsed selects neither source.
for bad_ver in "Unknown" "" "x.1"; do
    MOCK_OS_VERSION="$bad_ver"
    run_case
    chk_eq "OS_VERSION [$bad_ver] -> Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
    chk_eq "OS_VERSION [$bad_ver] -> delay null" "" "$SCREENSAVER_DELAY_SECONDS"
    chk_eq "OS_VERSION [$bad_ver] -> sysadminctl not run" "0" "$(launchctl_calls)"
    chk_eq "OS_VERSION [$bad_ver] logs a reason" "1" "$(warned 'macOS version unknown')"
done

# macOS 12 keeps the plist path and never calls sysadminctl.
MOCK_OS_VERSION="12.7.6"
MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 3600 seconds"
new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': False, 'askForPasswordDelay': 5}"
run_case
chk_eq "macOS 12 reads the plist -> No" "No" "$SCREENSAVER_PASSWORD"
chk_eq "macOS 12 reads the plist delay -> 5" "5" "$SCREENSAVER_DELAY_SECONDS"
chk_eq "macOS 12 does not run sysadminctl" "0" "$(launchctl_calls)"
new_home
run_case
chk_eq "macOS 12 with no plist keeps DefaultAssumed" "DefaultAssumed" "$SCREENSAVER_PASSWORD"
MOCK_SCREENLOCK_OUT=""

##############################################################################
# 12. Inactivity interval, CIS 2.10.1 (PAT-1753). idleTime is read on every
#     macOS version through NSUserDefaults as the subject user. A whole
#     number above 0 is the interval; idleTime 0 ("never") is the 99999
#     sentinel, never 0, because the server rule is lte 1200 and 0 would pass
#     a screen saver that never starts; the key not set, a wrong type and a
#     failed read are null, with a reason on stderr. The forced flag follows PAT-1720: the
#     osascript answer when the read succeeded, null when it failed.
##############################################################################
echo "--- 12. Inactivity interval (idleTime)"

MOCK_OS_VERSION="26.0.1"
MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 5 seconds"; MOCK_SCREENLOCK_RC=0
new_home

# User value present, not forced.
MOCK_IDLE_OUT="false int:600"; MOCK_IDLE_RC=0
run_case
chk_eq "user idleTime 600 -> 600" "600" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "user idleTime 600 -> not enforced by profile" "false" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "idleTime read runs once" "1" "$(idle_calls)"
chk_eq "idleTime read runs as the console user via launchctl asuser" \
    "asuser 501 /usr/bin/sudo -u alice /usr/bin/osascript -l JavaScript -e" "$(idle_argv)"
chk_eq "script reads the com.apple.screensaver suite" "1" "$(grep -F -c 'initWithSuiteName("com.apple.screensaver")' "$IDLE_SCRIPT")"
chk_eq "script reads the effective idleTime value" "1" "$(grep -F -c 'objectForKey("idleTime")' "$IDLE_SCRIPT")"
chk_eq "script reads objectIsForcedForKey for idleTime" "1" "$(grep -F -c 'objectIsForcedForKey("idleTime")' "$IDLE_SCRIPT")"
chk_eq "interval read logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"
chk_eq "idleTime read leaves the screen lock values alone" "Yes/5" "$SCREENSAVER_PASSWORD/$SCREENSAVER_DELAY_SECONDS"

# Managed overrides user: CFPreferences hands back the forced value and the
# forced flag, and the collector reports that value, not a user fallback.
MOCK_IDLE_OUT="true int:300"
run_case
chk_eq "profile-forced idleTime 300 -> 300" "300" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "profile-forced idleTime -> enforced by profile" "true" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"

MOCK_IDLE_OUT="true int:3600"
run_case
chk_eq "profile-forced idleTime over the limit is still reported as read -> 3600" "3600" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "profile-forced idleTime over the limit -> enforced" "true" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"

# idleTime 0 is "never": the 99999 sentinel, never 0 and never null.
MOCK_IDLE_OUT="false int:0"
run_case
chk_eq "idleTime 0 (never) -> 99999 sentinel, not 0" "99999" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "idleTime 0 sentinel fails lte 1200" "1" "$(( SCREENSAVER_IDLE_SECONDS > 1200 ))"
chk_eq "idleTime 0 read succeeded -> forced flag kept" "false" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "idleTime 0 is a definite read and logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"
MOCK_IDLE_OUT="true int:0"
run_case
chk_eq "profile-forced idleTime 0 -> 99999 sentinel" "99999" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "profile-forced idleTime 0 -> enforced" "true" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"

# Not set anywhere (tenant-zero on macOS 26.6.2): no default is assumed, the
# setting is reported absent (PAT-1775; section 13 covers the plist checks).
MOCK_IDLE_OUT="false absent"
run_case
chk_eq "idleTime not set, plists readable -> NotConfigured, no assumed default" "NotConfigured" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "idleTime not set, read succeeded -> not enforced" "false" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "idleTime not set and confirmed logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"

MOCK_IDLE_OUT="false invalid"
run_case
chk_eq "wrong-type idleTime -> null" "" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "wrong-type idleTime -> forced flag kept" "false" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "wrong-type idleTime logs a reason" "1" "$(warned 'idleTime undetermined (unexpected value type)')"

# Unreadable: a failed call is null for both signals, never false.
MOCK_IDLE_OUT="false int:600"; MOCK_IDLE_RC=1
run_case
chk_eq "osascript non-zero exit with a valid-looking line -> null" "" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "osascript non-zero exit -> enforced null, not false" "" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "osascript non-zero exit logs a reason" "1" "$(warned 'idleTime undetermined (osascript exited 1)')"
chk_eq "failed idleTime read leaves the screen lock values alone" "Yes/5" "$SCREENSAVER_PASSWORD/$SCREENSAVER_DELAY_SECONDS"
MOCK_IDLE_RC=0

typeset -a BAD_IDLE_OUTPUTS=(
    ""
    "garbage"
    "600"
    "false 600"
    "maybe int:600"
    "false int:-5"
    "false int:0600"
    "false int:600.5"
    "false int:12345678901"
    "false int:600 trailing"
    "false int:600"$'\n'"true int:300"
)
for bad_idle in "${BAD_IDLE_OUTPUTS[@]}"; do
    MOCK_IDLE_OUT="$bad_idle"
    run_case
    chk_eq "unrecognised idle output [${bad_idle//$'\n'/ | }] -> null" "" "$SCREENSAVER_IDLE_SECONDS"
    chk_eq "unrecognised idle output [${bad_idle//$'\n'/ | }] -> enforced null" "" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
    chk_eq "unrecognised idle output [${bad_idle//$'\n'/ | }] logs a reason" "1" "$(warned 'idleTime undetermined (unrecognised osascript output)')"
done
MOCK_IDLE_OUT="false int:600"

run_case carol
chk_eq "idle uid lookup failure -> null" "" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "idle uid lookup failure -> enforced null" "" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "idle uid lookup failure -> osascript not run" "0" "$(idle_calls)"
chk_eq "idle uid lookup failure logs a reason" "1" "$(warned 'idleTime undetermined (no uid for carol)')"

# Subject user: the same selection as the lock signals.
run_case alice "$MOCK_HW_UUID" bob
chk_eq "console user bob -> idleTime read as bob" \
    "asuser 502 /usr/bin/sudo -u bob /usr/bin/osascript -l JavaScript -e" "$(idle_argv)"
run_case alice "$MOCK_HW_UUID" loginwindow
chk_eq "nobody logged in -> idleTime read as FIRST_USER" \
    "asuser 501 /usr/bin/sudo -u alice /usr/bin/osascript -l JavaScript -e" "$(idle_argv)"
run_case "" "$MOCK_HW_UUID" loginwindow
chk_eq "no user at all -> idle null" "" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "no user at all -> enforced null" "" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "no user at all -> osascript not run" "0" "$(idle_calls)"
chk_eq "no user at all logs an idleTime reason" "1" "$(warned 'idleTime undetermined (no user to read)')"

# Every macOS version: the plist path (12) and an unparseable version both
# still read idleTime.
MOCK_OS_VERSION="12.7.6"
new_home
write_plist "$(MAIN_PLIST)" "{'askForPassword': True, 'askForPasswordDelay': 5, 'idleTime': 60}"
MOCK_IDLE_OUT="false int:900"
run_case
chk_eq "macOS 12 reads idleTime through NSUserDefaults, not the plist -> 900" "900" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "macOS 12 still runs no sysadminctl" "0" "$(launchctl_calls)"
chk_eq "macOS 12 lock values unchanged" "Yes/5" "$SCREENSAVER_PASSWORD/$SCREENSAVER_DELAY_SECONDS"
MOCK_OS_VERSION="Unknown"
run_case
chk_eq "unparseable OS_VERSION still reads idleTime -> 900" "900" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "unparseable OS_VERSION lock password still Unknown" "Unknown" "$SCREENSAVER_PASSWORD"
MOCK_OS_VERSION="12.7.6"
MOCK_IDLE_OUT="false int:600"
MOCK_SCREENLOCK_OUT=""

##############################################################################
# 13. idleTime NotConfigured versus null (PAT-1775). An unset key is
#     NotConfigured only when the home resolves and every plist in the
#     user's search list is absent or a readable dictionary; anything else
#     is null with the forced flag null too. A value that was read is never
#     second-guessed. The payload line from patched-collect.sh is rendered
#     and parsed to pin the JSON type for each state.
##############################################################################
echo "--- 13. idleTime NotConfigured versus null"

MOCK_OS_VERSION="26.0.1"
MOCK_SCREENLOCK_OUT="${NSLOG_PREFIX}screenLock delay is 5 seconds"; MOCK_SCREENLOCK_RC=0
MOCK_IDLE_RC=0
reset_library() {
    chmod -R u+rwx "$FIXTURE_LIBRARY" 2>/dev/null
    rm -rf "$FIXTURE_LIBRARY"; mkdir -p "$FIXTURE_LIBRARY"
}
PREFS_DIR() { print -r -- "$MOCK_HOME/Library/Preferences"; }

# payload_json_type <json-key>
# Renders that key's line from the real patched-collect.sh payload heredoc
# with this shell's variables and prints int:<n>, str:<s>, null, bool:<b>,
# missing (no such line) or invalid (not JSON).
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

# The real search list: both domains, per-user and computer managed
# preferences, the user's any-host and every ByHost plist, /Library/Preferences.
new_home
write_plist "$(BYHOST_PLIST)" "{}"
write_plist "$(BYHOST_PLIST "$OTHER_HW_UUID")" "{}"
write_plist "$(PREFS_DIR)/ByHost/.GlobalPreferences.$MOCK_HW_UUID.plist" "{}"
_ss_idle_plists_real alice "$MOCK_HOME"
chk_eq "real search list returns 0 for a listable ByHost directory" "0" "$?"
chk_eq "real search list names 11 plists" "11" "${#_SS_IDLE_PLISTS[@]}"
for want_plist in \
    "/Library/Managed Preferences/alice/com.apple.screensaver.plist" \
    "/Library/Managed Preferences/com.apple.screensaver.plist" \
    "$(PREFS_DIR)/com.apple.screensaver.plist" \
    "/Library/Preferences/com.apple.screensaver.plist" \
    "/Library/Managed Preferences/alice/.GlobalPreferences.plist" \
    "/Library/Managed Preferences/.GlobalPreferences.plist" \
    "$(PREFS_DIR)/.GlobalPreferences.plist" \
    "/Library/Preferences/.GlobalPreferences.plist" \
    "$(BYHOST_PLIST)" \
    "$(BYHOST_PLIST "$OTHER_HW_UUID")" \
    "$(PREFS_DIR)/ByHost/.GlobalPreferences.$MOCK_HW_UUID.plist"; do
    chk_eq "real search list includes ${want_plist/#$MOCK_HOME/<home>}" "1" "${_SS_IDLE_PLISTS[(Ie)$want_plist]:+1}"
done

# Present / absent / failed, with the payload JSON type for each.
new_home; reset_library
MOCK_IDLE_OUT="false int:600"
run_case
chk_eq "present 600 -> 600" "600" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "payload: present -> JSON integer 600" "int:600" "$(payload_json_type screensaver_idle_seconds)"
MOCK_IDLE_OUT="true int:0"
run_case
chk_eq "payload: never sentinel -> JSON integer 99999" "int:99999" "$(payload_json_type screensaver_idle_seconds)"
MOCK_IDLE_OUT="false absent"
run_case
chk_eq "absent, no plists anywhere -> NotConfigured" "NotConfigured" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "absent, confirmed -> enforced false" "false" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
chk_eq "payload: absent -> JSON string NotConfigured" "str:NotConfigured" "$(payload_json_type screensaver_idle_seconds)"
chk_eq "payload: absent -> enforced companion JSON false" "bool:False" "$(payload_json_type screensaver_idle_seconds_enforced_by_profile)"
MOCK_IDLE_OUT="false int:600"; MOCK_IDLE_RC=1
run_case
MOCK_IDLE_RC=0
chk_eq "failed read -> null, never NotConfigured" "" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "payload: failed read -> JSON null" "null" "$(payload_json_type screensaver_idle_seconds)"
chk_eq "payload: failed read -> enforced companion JSON null" "null" "$(payload_json_type screensaver_idle_seconds_enforced_by_profile)"
MOCK_IDLE_OUT="false invalid"
run_case
chk_eq "payload: wrong type -> JSON null" "null" "$(payload_json_type screensaver_idle_seconds)"

# Readable plists that exist but do not set idleTime are still absent.
new_home; reset_library
write_plist "$(PREFS_DIR)/com.apple.screensaver.plist" "{'askForPassword': True}"
write_plist "$(BYHOST_PLIST)" "{'moduleDict': {'moduleName': 'Flurry'}}"
write_plist "$(PREFS_DIR)/.GlobalPreferences.plist" "{'AppleLocale': 'en_GB'}"
write_plist "$FIXTURE_LIBRARY/Managed Preferences/alice/com.apple.screensaver.plist" "{'askForPassword': True}"
write_plist "$FIXTURE_LIBRARY/Preferences/.GlobalPreferences.plist" "{}"
MOCK_IDLE_OUT="false absent"
run_case
chk_eq "readable plists without idleTime -> NotConfigured" "NotConfigured" "$SCREENSAVER_IDLE_SECONDS"

# idle_blocked <desc> <warning substring>: the last run must be null, with
# the forced flag null and a reason logged.
idle_blocked() {
    chk_eq "$1 -> null, not NotConfigured" "" "$SCREENSAVER_IDLE_SECONDS"
    chk_eq "$1 -> enforced null, not false" "" "$SCREENSAVER_IDLE_SECONDS_ENFORCED_BY_PROFILE"
    chk_eq "$1 logs a reason" "1" "$(warned "$2")"
}

# Every place the key could live blocks NotConfigured when it is corrupt.
# HOME:<name> is under the user's Preferences, LIB:<path> under /Library.
typeset -a CORRUPT_TARGETS=(
    "HOME:com.apple.screensaver.plist"
    "HOME:.GlobalPreferences.plist"
    "BYHOST"
    "BYHOST_OTHER"
    "HOME:ByHost/.GlobalPreferences.$MOCK_HW_UUID.plist"
    "LIB:Managed Preferences/alice/com.apple.screensaver.plist"
    "LIB:Managed Preferences/alice/.GlobalPreferences.plist"
    "LIB:Managed Preferences/com.apple.screensaver.plist"
    "LIB:Managed Preferences/.GlobalPreferences.plist"
    "LIB:Preferences/com.apple.screensaver.plist"
    "LIB:Preferences/.GlobalPreferences.plist"
)
for corrupt_target in "${CORRUPT_TARGETS[@]}"; do
    new_home; reset_library
    case "$corrupt_target" in
        BYHOST)       corrupt_path="$(BYHOST_PLIST)" ;;
        BYHOST_OTHER) corrupt_path="$(BYHOST_PLIST "$OTHER_HW_UUID")" ;;
        LIB:*)        corrupt_path="$FIXTURE_LIBRARY/${corrupt_target#LIB:}" ;;
        HOME:*)       corrupt_path="$(PREFS_DIR)/${corrupt_target#HOME:}" ;;
    esac
    mkdir -p "${corrupt_path:h}"
    print -r -- "not a plist <dict>" > "$corrupt_path"
    run_case
    idle_blocked "corrupt ${${corrupt_path/#$MOCK_HOME/<home>}/#$FIXTURE_LIBRARY//Library}" "idleTime undetermined (not set, and unparseable plist among:"
done

# A plist whose root is not a dictionary.
new_home; reset_library
write_plist "$(PREFS_DIR)/com.apple.screensaver.plist" "['idleTime', 600]"
run_case
idle_blocked "non-dictionary screensaver plist" "unparseable plist among:"

# A directory where the plist should be.
new_home; reset_library
mkdir -p "$(PREFS_DIR)/com.apple.screensaver.plist"
run_case
idle_blocked "directory in place of the screensaver plist" "unreadable plist:"

# A value that was read is never second-guessed by the plist check.
new_home; reset_library
print -r -- "garbage" > "$(PREFS_DIR)/com.apple.screensaver.plist"
MOCK_IDLE_OUT="false int:300"
run_case
chk_eq "corrupt plist but idleTime read as set -> 300 (value unchanged)" "300" "$SCREENSAVER_IDLE_SECONDS"
chk_eq "corrupt plist but idleTime read as set -> no plist warning" "0" "$(warned 'unparseable plist')"
MOCK_IDLE_OUT="false absent"

# Home directory cannot be resolved or is missing.
new_home; reset_library
MOCK_DSCL_FAIL=1
run_case
MOCK_DSCL_FAIL=0
idle_blocked "dscl home lookup fails" "home directory of alice was not found"
MOCK_USER_HOMES=( alice "$MOCK_HOME/gone" )
run_case
MOCK_USER_HOMES=()
idle_blocked "home directory does not exist" "home directory of alice was not found"

# Unreadable plists and directories (skipped when the runner is root, which
# reads anything).
if (( EUID != 0 )); then
    new_home; reset_library
    write_plist "$(PREFS_DIR)/com.apple.screensaver.plist" "{}"
    chmod 000 "$(PREFS_DIR)/com.apple.screensaver.plist"
    run_case
    idle_blocked "unreadable screensaver plist" "unreadable plist:"
    chmod 644 "$(PREFS_DIR)/com.apple.screensaver.plist"

    new_home; reset_library
    chmod 000 "$(PREFS_DIR)/ByHost"
    run_case
    idle_blocked "unlistable ByHost directory" "ByHost preferences of alice cannot be listed"
    chmod 755 "$(PREFS_DIR)/ByHost"

    new_home; reset_library
    mkdir -p "$FIXTURE_LIBRARY/Managed Preferences"
    chmod 000 "$FIXTURE_LIBRARY/Managed Preferences"
    run_case
    idle_blocked "unsearchable Managed Preferences directory" "directory not searchable:"
    reset_library
fi

MOCK_OS_VERSION="12.7.6"
MOCK_IDLE_OUT="false int:600"
MOCK_SCREENLOCK_OUT=""

echo
echo "RESULT: pass=$pass fail=$fail known_gaps=$gaps"
[[ $fail -eq 0 ]]
