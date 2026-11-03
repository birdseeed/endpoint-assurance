#!/bin/zsh
##############################################################################
# test-sharing.zsh: unit tests for the Time Machine encryption signal
# (_collect_time_machine_encrypted, called by collect_sharing) in sharing.sh,
# PAT-1767 three-state contract.
#
# Sources the live functions out of common.sh and sharing.sh (no top-level
# side effects at source time) so the tests exercise the real code, not a
# copy. _sharing_tm_plist is overridden to name a scratch fixture path, and
# `defaults` is shadowed with a zsh function (zsh resolves a function before
# an external command) that answers from MOCK_TM_MODE, so the runner's own
# Time Machine preferences are never read. The fixture plist only needs to
# exist for the "plist missing" branch; its content is what the double says.
# The other collect_sharing commands (launchctl, systemsetup, cupsctl,
# mdmclient) are shadowed to fail, so only the Time Machine signal is
# asserted from the full collect_sharing run.
#
# Three ways: present (Yes / No), absent (NotConfigured: no plist, or no
# Destinations in a plist defaults read successfully), failed read (null,
# never NotConfigured). Run:
#   zsh macos/lib/test-sharing.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"
PATCHED_TMPDIR=$(mktemp -d)
trap 'chmod -R u+rwx "$PATCHED_TMPDIR" 2>/dev/null; rm -rf "$PATCHED_TMPDIR"' EXIT

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/sharing.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# ── Boundary doubles ───────────────────────────────────────────────────────
FIXTURE_DIR="$PATCHED_TMPDIR/prefs"
FIXTURE_PLIST="$FIXTURE_DIR/com.apple.TimeMachine.plist"
mkdir -p "$FIXTURE_DIR"
_sharing_tm_plist() { print -r -- "$FIXTURE_PLIST"; }

# Real `defaults read` renderings of com.apple.TimeMachine.
FIX_ENCRYPTED=$'{\n    AutoBackup = 1;\n    Destinations =     (\n                {\n            DestinationID = "0A1B";\n            LastKnownEncryptionState = Encrypted;\n        }\n    );\n}'
FIX_NOT_ENCRYPTED=$'{\n    AutoBackup = 1;\n    Destinations =     (\n                {\n            DestinationID = "0A1B";\n            LastKnownEncryptionState = NotEncrypted;\n        }\n    );\n}'
FIX_NO_DESTINATIONS=$'{\n    AutoBackup = 0;\n    PreferencesVersion = 5;\n}'
MOCK_TM_MODE="encrypted"
DEFAULTS_LOG="$PATCHED_TMPDIR/defaults-log"
defaults() {
    print -r -- "defaults $*" >> "$DEFAULTS_LOG"
    [[ "$1" == "read" && "$2" == "$FIXTURE_PLIST" && $# -eq 2 ]] || { print -u2 "unexpected defaults call: $*"; return 2; }
    case "$MOCK_TM_MODE" in
        encrypted)       print -r -- "$FIX_ENCRYPTED" ;;
        not_encrypted)   print -r -- "$FIX_NOT_ENCRYPTED" ;;
        no_destinations) print -r -- "$FIX_NO_DESTINATIONS" ;;
        fail)
            print -u2 "2026-09-15 10:40:05.430 defaults[1:2] "
            print -u2 "Domain $2 does not exist"
            return 1
            ;;
    esac
}
launchctl()   { return 1; }
systemsetup() { return 1; }
cupsctl()     { return 1; }
mdmclient()   { return 1; }

run_case() {
    MOCK_TM_MODE="$1"
    TIME_MACHINE_ENCRYPTED="__unset__"
    : > "$DEFAULTS_LOG"
    _collect_time_machine_encrypted
}

##############################################################################
# 1. Present: Time Machine has destinations.
##############################################################################
echo "--- 1. Destinations configured"

print -r -- "placeholder" > "$FIXTURE_PLIST"
run_case encrypted
chk_eq "encrypted destination -> Yes" "Yes" "$TIME_MACHINE_ENCRYPTED"
chk_eq "whole domain read once, from the plist path" "defaults read $FIXTURE_PLIST" "$(cat "$DEFAULTS_LOG")"
run_case not_encrypted
chk_eq "NotEncrypted destination -> No" "No" "$TIME_MACHINE_ENCRYPTED"

##############################################################################
# 2. Absent: no plist, or a successfully read plist with no Destinations.
##############################################################################
echo "--- 2. Time Machine not configured"

run_case no_destinations
chk_eq "plist read, no Destinations -> NotConfigured" "NotConfigured" "$TIME_MACHINE_ENCRYPTED"

rm -f "$FIXTURE_PLIST"
run_case encrypted
chk_eq "no plist -> NotConfigured" "NotConfigured" "$TIME_MACHINE_ENCRYPTED"
chk_eq "no plist -> defaults never called" "0" "$(grep -c . "$DEFAULTS_LOG")"

##############################################################################
# 3. Failed: the plist exists but cannot be read, or its directory hides it.
##############################################################################
echo "--- 3. Failed read"

print -r -- "placeholder" > "$FIXTURE_PLIST"
run_case fail
chk_eq "plist exists, defaults read fails -> null, never NotConfigured" "" "$TIME_MACHINE_ENCRYPTED"

rm -f "$FIXTURE_PLIST"
ln -s "$FIXTURE_DIR/missing-target.plist" "$FIXTURE_PLIST"
run_case fail
chk_eq "dangling symlink plist, defaults read fails -> null" "" "$TIME_MACHINE_ENCRYPTED"
rm -f "$FIXTURE_PLIST"

if (( EUID != 0 )); then
    chmod 000 "$FIXTURE_DIR"
    run_case encrypted
    chk_eq "unsearchable preferences directory -> null, not NotConfigured" "" "$TIME_MACHINE_ENCRYPTED"
    chmod 755 "$FIXTURE_DIR"
fi

##############################################################################
# 4. collect_sharing runs the split: the value reaches TIME_MACHINE_ENCRYPTED.
##############################################################################
echo "--- 4. Wired into collect_sharing"

print -r -- "placeholder" > "$FIXTURE_PLIST"
MOCK_TM_MODE="not_encrypted"; TIME_MACHINE_ENCRYPTED="__unset__"
collect_sharing 2>/dev/null
chk_eq "collect_sharing: present -> No" "No" "$TIME_MACHINE_ENCRYPTED"
MOCK_TM_MODE="no_destinations"; TIME_MACHINE_ENCRYPTED="__unset__"
collect_sharing 2>/dev/null
chk_eq "collect_sharing: absent -> NotConfigured" "NotConfigured" "$TIME_MACHINE_ENCRYPTED"
MOCK_TM_MODE="fail"; TIME_MACHINE_ENCRYPTED="__unset__"
collect_sharing 2>/dev/null
chk_eq "collect_sharing: failed read -> null" "" "$TIME_MACHINE_ENCRYPTED"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
