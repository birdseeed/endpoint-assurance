#!/bin/zsh
##############################################################################
# test-user-prefs.zsh — unit tests for the per-console-user preference
# collector (collect_user_prefs) in user_prefs.sh (PAT-1696).
#
# Sources the live functions out of common.sh (console_user) and
# user_prefs.sh (no top-level side effects at source time) so the tests
# exercise the real code, not a copy. `stat` (console_user's
# `stat -f %Su /dev/console`) and `sudo` (every `sudo -u <user> defaults ...`
# read) are shadowed with zsh functions of the same name; zsh resolves a
# function before an external command, so no real console session, sudo
# prompt or preference domain on the runner is touched. The `sudo` double
# answers from MOCK_DEFAULTS in the same text shapes real `defaults read`
# prints (bools as 1/0, a missing key as exit 1 plus stderr).
#
# PAT-1767 three-state contract: a missing key is "NotConfigured" only when
# `defaults` reported it missing AND the plist(s) that read consults in the
# user's home are absent or readable dictionaries. `dscl` is shadowed too and
# answers NFSHomeDirectory with a scratch fixture home, whose plists the real
# prefs_plists_readable (common.sh) checks with the real /usr/bin/python3.
# Section 6 checks every signal three ways: present, absent, failed read.
#
# KNOWN-GAP checks record current behaviour that breaks the "absent evidence
# is never a pass" rule; this module has none today. Run:
#   zsh macos/lib/test-user-prefs.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"
PATCHED_TMPDIR=$(mktemp -d)
trap 'chmod -R u+rwx "$PATCHED_TMPDIR" 2>/dev/null; rm -rf "$PATCHED_TMPDIR"' EXIT

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/user_prefs.sh"

pass=0; fail=0; gaps=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# ── Boundary doubles ───────────────────────────────────────────────────────
MOCK_CONSOLE_USER=""
MOCK_STAT_FAIL=0
stat() {
    (( MOCK_STAT_FAIL )) && return 1
    print -r -- "$MOCK_CONSOLE_USER"
}

# Fixture home returned by the dscl double.
MOCK_HOME="$PATCHED_TMPDIR/home/alice"
mkdir -p "$MOCK_HOME/Library/Preferences/ByHost"
MOCK_DSCL_MODE="ok"   # ok | fail | garbage
dscl() {
    case "$MOCK_DSCL_MODE" in
        ok)      print -r -- "NFSHomeDirectory: $MOCK_HOME" ;;
        fail)    print -u2 "DS Error: -14136 (eDSRecordNotFound)"; return 56 ;;
        garbage) print -r -- "No such key: NFSHomeDirectory" ;;
    esac
}
write_plist() {  # write_plist <path> <python-literal-root>
    "$PYTHON3" -c 'import plistlib,sys; plistlib.dump(eval(sys.argv[2]), open(sys.argv[1],"wb"))' "$1" "$2"
}
reset_home() {
    chmod -R u+rwx "$PATCHED_TMPDIR/home" 2>/dev/null
    rm -rf "$PATCHED_TMPDIR/home"
    mkdir -p "$MOCK_HOME/Library/Preferences/ByHost"
    MOCK_DSCL_MODE="ok"
}

typeset -A MOCK_DEFAULTS   # "[currentHost:]<domain>/<key>" -> printed value
typeset -A MOCK_READ_FAIL  # "[currentHost:]<domain>/<key>" -> 1: defaults errors for that key
MOCK_SUDO_FAIL=0
SUDO_LOG=$(mktemp "$PATCHED_TMPDIR/sudo-log.XXXXXX")
sudo() {
    # Expected shape: -u <user> defaults [-currentHost] read <domain> <key>
    print -r -- "$*" >> "$SUDO_LOG"
    (( MOCK_SUDO_FAIL )) && { print -u2 "sudo: unable to run defaults"; return 1; }
    [[ "$1" == "-u" && "$3" == "defaults" ]] || return 1
    shift 3
    local host_prefix=""
    if [[ "$1" == "-currentHost" ]]; then host_prefix="currentHost:"; shift; fi
    [[ "$1" == "read" ]] || return 1
    local k="${host_prefix}$2/$3"
    if (( ${+MOCK_READ_FAIL[$k]} )); then
        print -u2 "Could not connect to cfprefsd"
        return 1
    elif (( ${+MOCK_DEFAULTS[$k]} )); then
        print -r -- "${MOCK_DEFAULTS[$k]}"
    else
        print -u2 "The domain/default pair of ($2, $3) does not exist"
        return 1
    fi
}

run_case() {
    BLUETOOTH_SHARING_DISABLED="__unset__"
    SHOW_FILE_EXTENSIONS="__unset__"
    TERMINAL_SECURE_KEYBOARD="__unset__"
    : > "$SUDO_LOG"
    collect_user_prefs
}

signals() { print -r -- "$BLUETOOTH_SHARING_DISABLED|$SHOW_FILE_EXTENSIONS|$TERMINAL_SECURE_KEYBOARD"; }

##############################################################################
# 1. Set to the expected (compliant) values.
##############################################################################
echo "--- 1. Preferences set, compliant"

MOCK_CONSOLE_USER="alice"; MOCK_STAT_FAIL=0; MOCK_SUDO_FAIL=0
MOCK_DEFAULTS=(
    currentHost:com.apple.Bluetooth/PrefKeyServicesEnabled  0
    .GlobalPreferences/AppleShowAllExtensions               1
    com.apple.Terminal/SecureKeyboardEntry                  1
)
run_case

chk_eq "all three Yes" "Yes|Yes|Yes" "$(signals)"
chk_eq "reads run as the console user" "3" "$(grep -c '^-u alice defaults ' "$SUDO_LOG")"
chk_eq "Bluetooth read is ByHost (-currentHost)" "1" "$(grep -c -- '-currentHost read com.apple.Bluetooth PrefKeyServicesEnabled' "$SUDO_LOG")"

##############################################################################
# 2. Set to unexpected (non-compliant) values.
##############################################################################
echo "--- 2. Preferences set, non-compliant"

MOCK_DEFAULTS=(
    currentHost:com.apple.Bluetooth/PrefKeyServicesEnabled  1
    .GlobalPreferences/AppleShowAllExtensions               0
    com.apple.Terminal/SecureKeyboardEntry                  0
)
run_case
chk_eq "all three No" "No|No|No" "$(signals)"

##############################################################################
# 3. Unset: `defaults read` exits 1 with "does not exist" for a missing key
#    and the user's plists are readable. "NotConfigured" (PAT-1767), never a
#    default-derived Yes or No.
##############################################################################
echo "--- 3. Preferences unset"

MOCK_DEFAULTS=()
run_case
chk_eq "all three NotConfigured" "NotConfigured|NotConfigured|NotConfigured" "$(signals)"

# Readable plists that exist but lack the key are still absent.
write_plist "$MOCK_HOME/Library/Preferences/com.apple.Terminal.plist" "{'Default Window Settings': 'Basic'}"
write_plist "$MOCK_HOME/Library/Preferences/.GlobalPreferences.plist" "{'AppleLocale': 'en_GB'}"
write_plist "$MOCK_HOME/Library/Preferences/ByHost/com.apple.Bluetooth.0A1B2C3D-0000-0000-0000-000000000000.plist" "{}"
run_case
chk_eq "readable plists without the keys -> all three NotConfigured" "NotConfigured|NotConfigured|NotConfigured" "$(signals)"
reset_home

# A non-ByHost Bluetooth value must not be read in place of the ByHost one.
MOCK_DEFAULTS=(com.apple.Bluetooth/PrefKeyServicesEnabled 0)
run_case
chk_eq "global-domain Bluetooth value ignored, ByHost unset -> NotConfigured" "NotConfigured" "$BLUETOOTH_SHARING_DISABLED"

##############################################################################
# 4. Wrong type: a string, an array or a non-0/1 integer -> null.
##############################################################################
echo "--- 4. Wrong-type values"

MOCK_DEFAULTS=(
    currentHost:com.apple.Bluetooth/PrefKeyServicesEnabled  "YES"
    .GlobalPreferences/AppleShowAllExtensions               $'(\n    1\n)'
    com.apple.Terminal/SecureKeyboardEntry                  2
)
run_case
chk_eq "all three null" "||" "$(signals)"

##############################################################################
# 5. Missing input: no GUI session (root, loginwindow, empty), stat failing,
#    and sudo failing. Every path must be null and no read attempted without
#    a real user.
##############################################################################
echo "--- 5. No console user / unreadable input"

MOCK_DEFAULTS=(
    currentHost:com.apple.Bluetooth/PrefKeyServicesEnabled  0
    .GlobalPreferences/AppleShowAllExtensions               1
    com.apple.Terminal/SecureKeyboardEntry                  1
)
for who in root loginwindow ""; do
    MOCK_CONSOLE_USER="$who"
    run_case
    chk_eq "console user '${who}' -> all null" "||" "$(signals)"
    chk_eq "console user '${who}' -> no sudo reads" "0" "$(grep -c . "$SUDO_LOG")"
done

MOCK_CONSOLE_USER="alice"; MOCK_STAT_FAIL=1
run_case
chk_eq "stat failure -> all null" "||" "$(signals)"
chk_eq "stat failure -> no sudo reads" "0" "$(grep -c . "$SUDO_LOG")"
MOCK_STAT_FAIL=0

MOCK_SUDO_FAIL=1
run_case
chk_eq "sudo failure -> all null" "||" "$(signals)"
MOCK_SUDO_FAIL=0

##############################################################################
# 6. PAT-1767 three-state contract, every signal three ways: present ->
#    Yes/No, absent -> NotConfigured, failed read -> null. Then the absent
#    paths that must NOT become NotConfigured.
##############################################################################
echo "--- 6. Present / absent / failed, per signal"

MOCK_CONSOLE_USER="alice"; MOCK_STAT_FAIL=0; MOCK_SUDO_FAIL=0
reset_home
# signal | mock key | present value | expected
THREE_WAY=(
    "BLUETOOTH_SHARING_DISABLED|currentHost:com.apple.Bluetooth/PrefKeyServicesEnabled|1|No"
    "SHOW_FILE_EXTENSIONS|.GlobalPreferences/AppleShowAllExtensions|1|Yes"
    "TERMINAL_SECURE_KEYBOARD|com.apple.Terminal/SecureKeyboardEntry|0|No"
)
MOCK_READ_FAIL=()
for row in "${THREE_WAY[@]}"; do
    parts=( "${(@s:|:)row}" )
    sig="${parts[1]}"; mk="${parts[2]}"; mv="${parts[3]}"; mexp="${parts[4]}"
    MOCK_DEFAULTS=("$mk" "$mv")
    run_case
    chk_eq "$sig present ($mv) -> $mexp" "$mexp" "${(P)sig}"
    MOCK_DEFAULTS=()
    run_case
    chk_eq "$sig absent -> NotConfigured" "NotConfigured" "${(P)sig}"
    MOCK_READ_FAIL=("$mk" 1)
    run_case
    MOCK_READ_FAIL=()
    chk_eq "$sig failed read (other error text) -> null, never NotConfigured" "" "${(P)sig}"
done

echo "--- 6b. Missing key but absence cannot be confirmed"
MOCK_DEFAULTS=()

# Corrupt plists: defaults says "does not exist" for these too.
reset_home
print -r -- "not a plist" > "$MOCK_HOME/Library/Preferences/com.apple.Terminal.plist"
run_case
chk_eq "corrupt Terminal plist -> TERMINAL_SECURE_KEYBOARD null" "" "$TERMINAL_SECURE_KEYBOARD"
chk_eq "corrupt Terminal plist -> other signals unaffected" "NotConfigured|NotConfigured" \
    "$BLUETOOTH_SHARING_DISABLED|$SHOW_FILE_EXTENSIONS"

reset_home
write_plist "$MOCK_HOME/Library/Preferences/.GlobalPreferences.plist" "['AppleShowAllExtensions']"
run_case
chk_eq "non-dictionary global plist -> SHOW_FILE_EXTENSIONS null" "" "$SHOW_FILE_EXTENSIONS"

reset_home
print -r -- "garbage" > "$MOCK_HOME/Library/Preferences/ByHost/com.apple.Bluetooth.0A1B2C3D-0000-0000-0000-000000000000.plist"
run_case
chk_eq "corrupt ByHost Bluetooth plist -> BLUETOOTH_SHARING_DISABLED null" "" "$BLUETOOTH_SHARING_DISABLED"

# A present value is never second-guessed by the plist check.
MOCK_DEFAULTS=(currentHost:com.apple.Bluetooth/PrefKeyServicesEnabled 0)
run_case
chk_eq "corrupt ByHost plist but the key was read -> Yes (value unchanged)" "Yes" "$BLUETOOTH_SHARING_DISABLED"
MOCK_DEFAULTS=()

if (( EUID != 0 )); then
    reset_home
    write_plist "$MOCK_HOME/Library/Preferences/com.apple.Terminal.plist" "{}"
    chmod 000 "$MOCK_HOME/Library/Preferences/com.apple.Terminal.plist"
    run_case
    chk_eq "unreadable Terminal plist -> TERMINAL_SECURE_KEYBOARD null" "" "$TERMINAL_SECURE_KEYBOARD"

    reset_home
    chmod 000 "$MOCK_HOME/Library/Preferences/ByHost"
    run_case
    chk_eq "unreadable ByHost directory -> BLUETOOTH_SHARING_DISABLED null" "" "$BLUETOOTH_SHARING_DISABLED"

    reset_home
    chmod 000 "$MOCK_HOME/Library"
    run_case
    chk_eq "unsearchable Library directory -> all three null" "||" "$(signals)"
fi

reset_home
MOCK_DSCL_MODE="fail"
run_case
chk_eq "dscl failure -> absent keys null" "||" "$(signals)"
MOCK_DEFAULTS=(com.apple.Terminal/SecureKeyboardEntry 1)
run_case
chk_eq "dscl failure does not touch a value that was read" "Yes" "$TERMINAL_SECURE_KEYBOARD"
MOCK_DEFAULTS=()

reset_home
MOCK_DSCL_MODE="garbage"
run_case
chk_eq "unparseable dscl output -> absent keys null" "||" "$(signals)"

reset_home
rm -rf "$MOCK_HOME"
run_case
chk_eq "home directory missing -> absent keys null" "||" "$(signals)"
reset_home

# No scratch directory for stderr: the read cannot be classified.
SAVED_TMPDIR="$PATCHED_TMPDIR"
PATCHED_TMPDIR=""
run_case
PATCHED_TMPDIR="$SAVED_TMPDIR"
chk_eq "no PATCHED_TMPDIR -> all three null" "||" "$(signals)"

echo
echo "RESULT: pass=$pass fail=$fail known_gaps=$gaps"
[[ $fail -eq 0 ]]
