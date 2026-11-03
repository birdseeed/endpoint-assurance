#!/bin/zsh
##############################################################################
# test-updates.zsh: unit tests for the software update setting signals in
# collect_updates (updates.sh), PAT-1767 three-state contract.
#
# Sources the live functions out of common.sh and updates.sh (no top-level
# side effects at source time) so the tests exercise the real code, not a
# copy. `defaults` and `softwareupdate` are shadowed with zsh functions of the
# same name (zsh resolves a function before an external command), so the
# runner's own SoftwareUpdate preferences are never read and Apple's update
# server is never contacted. The `defaults` double answers from MOCK_SU in the
# shapes real `defaults read` prints: the value on stdout with exit 0, or exit
# 1 with "The domain/default pair of (<domain>, <key>) does not exist" on
# stderr, the same line macOS 26.6.2 prints for a missing key AND for a
# corrupt or unreadable plist. _updates_su_plist is overridden to name a
# scratch fixture plist, which the real prefs_plists_readable (common.sh)
# checks with the real /usr/bin/python3.
#
# Every signal is checked three ways: present (On / Off), absent
# (NotConfigured), failed read ("Unknown", the existing spelling for these
# signals, never NotConfigured). Run:
#   zsh macos/lib/test-updates.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"
PATCHED_TMPDIR=$(mktemp -d)
trap 'chmod -R u+rwx "$PATCHED_TMPDIR" 2>/dev/null; rm -rf "$PATCHED_TMPDIR"' EXIT

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/updates.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# ── Boundary doubles ───────────────────────────────────────────────────────
FIXTURE_DIR="$PATCHED_TMPDIR/prefs"
FIXTURE_PLIST="$FIXTURE_DIR/com.apple.SoftwareUpdate.plist"
mkdir -p "$FIXTURE_DIR"
_updates_su_plist() { print -r -- "$FIXTURE_PLIST"; }

CALL_LOG="$PATCHED_TMPDIR/calls"
typeset -A MOCK_SU          # key -> printed value
typeset -A MOCK_SU_FAIL     # key -> 1: defaults errors with other text
defaults() {
    # Expected shape: defaults read <domain-path-without-.plist> <key>
    print -r -- "defaults $*" >> "$CALL_LOG"
    [[ "$1" == "read" && "$2" == "${FIXTURE_PLIST%.plist}" ]] || { print -u2 "unexpected defaults call: $*"; return 2; }
    if (( ${+MOCK_SU_FAIL[$3]} )); then
        print -u2 "2026-09-15 10:40:05.430 defaults[1:2] Could not connect to cfprefsd"
        return 1
    elif (( ${+MOCK_SU[$3]} )); then
        print -r -- "${MOCK_SU[$3]}"
    else
        print -u2 "2026-09-15 10:40:05.430 defaults[1:2] "
        print -u2 "The domain/default pair of ($2, $3) does not exist"
        return 1
    fi
}
softwareupdate() {
    print -r -- "softwareupdate $*" >> "$CALL_LOG"
    case "$1" in
        -l) print -r -- "Software Update Tool"; print -r -- "Finding available software"; print -r -- "No new software available." ;;
    esac
    return 0
}
write_plist() {  # write_plist <python-literal-root>
    "$PYTHON3" -c 'import plistlib,sys; plistlib.dump(eval(sys.argv[2]), open(sys.argv[1],"wb"))' "$FIXTURE_PLIST" "$1"
}
reset_fixture() {
    chmod -R u+rwx "$FIXTURE_DIR" 2>/dev/null
    rm -rf "$FIXTURE_DIR"; mkdir -p "$FIXTURE_DIR"
}

SIGNALS=( AUTO_SECURITY_UPDATES UPDATE_CHECK_AUTO UPDATE_DOWNLOAD_AUTO APP_UPDATES_AUTO_INSTALL XPROTECT_DATA_AUTO_UPDATE CRITICAL_UPDATES_AUTO_INSTALL )
# signal -> the SoftwareUpdate key it reads
typeset -A KEY_OF
KEY_OF=(
    AUTO_SECURITY_UPDATES          AutomaticallyInstallMacOSUpdates
    UPDATE_CHECK_AUTO              AutomaticCheckEnabled
    UPDATE_DOWNLOAD_AUTO           AutomaticDownload
    APP_UPDATES_AUTO_INSTALL       AutomaticallyInstallAppUpdates
    XPROTECT_DATA_AUTO_UPDATE      ConfigDataInstall
    CRITICAL_UPDATES_AUTO_INSTALL  CriticalUpdateInstall
)

run_case() {
    local sig
    for sig in "${SIGNALS[@]}"; do typeset -g "$sig=__unset__"; done
    : > "$CALL_LOG"
    collect_updates
}
all_signals() {
    local sig
    for sig in "${SIGNALS[@]}"; do print -r -- "$sig=${(P)sig}"; done
}

##############################################################################
# 1. Every key set: 1 -> On, 0 -> Off.
##############################################################################
echo "--- 1. Keys present"

write_plist "{'AutomaticCheckEnabled': True}"
MOCK_SU=( AutomaticallyInstallMacOSUpdates 1 AutomaticCheckEnabled 1 AutomaticDownload 1
          AutomaticallyInstallAppUpdates 1 ConfigDataInstall 1 CriticalUpdateInstall 1 )
MOCK_SU_FAIL=()
run_case
chk_eq "six signals checked (guards the grep below)" "6" "$(all_signals | grep -c '=')"
chk_eq "all 1 -> On" "" "$(all_signals | grep -v '=On$')"
chk_eq "AutomaticCheckEnabled read before softwareupdate -l (PAT-753)" \
    "defaults read ${FIXTURE_PLIST%.plist} AutomaticCheckEnabled" "$(head -1 "$CALL_LOG")"

MOCK_SU=( AutomaticallyInstallMacOSUpdates 0 AutomaticCheckEnabled 0 AutomaticDownload 0
          AutomaticallyInstallAppUpdates 0 ConfigDataInstall 0 CriticalUpdateInstall 0 )
run_case
chk_eq "all 0 -> Off" "" "$(all_signals | grep -v '=Off$')"

MOCK_SU=( AutomaticallyInstallMacOSUpdates 2 AutomaticCheckEnabled YES AutomaticDownload ""
          AutomaticallyInstallAppUpdates true ConfigDataInstall Unknown CriticalUpdateInstall $'(\n    1\n)' )
run_case
chk_eq "wrong-type values -> Unknown (unchanged)" "" "$(all_signals | grep -v '=Unknown$')"

##############################################################################
# 2. Three ways per signal: present / absent / failed read.
##############################################################################
echo "--- 2. Present / absent / failed, per signal"

reset_fixture
for sig in "${SIGNALS[@]}"; do
    key="${KEY_OF[$sig]}"
    MOCK_SU=("$key" 1); MOCK_SU_FAIL=()
    run_case
    chk_eq "$sig present (1) -> On" "On" "${(P)sig}"

    MOCK_SU=()
    run_case
    chk_eq "$sig absent, no plist -> NotConfigured" "NotConfigured" "${(P)sig}"

    MOCK_SU_FAIL=("$key" 1)
    run_case
    chk_eq "$sig failed read -> Unknown, never NotConfigured" "Unknown" "${(P)sig}"
    MOCK_SU_FAIL=()
done

# Readable plist that lacks every key.
write_plist "{'LastSuccessfulDate': 'x'}"
MOCK_SU=()
run_case
chk_eq "readable plist without the keys -> every signal NotConfigured" "" \
    "$(all_signals | grep -v '=NotConfigured$')"

##############################################################################
# 3. Absent per defaults, but the plist cannot be confirmed readable.
##############################################################################
echo "--- 3. Absence not confirmed"

MOCK_SU=()
reset_fixture
print -r -- "corrupt <plist" > "$FIXTURE_PLIST"
run_case
chk_eq "corrupt plist -> every signal Unknown" "" "$(all_signals | grep -v '=Unknown$')"

MOCK_SU=(AutomaticDownload 1)
run_case
chk_eq "corrupt plist but the key was read -> On (value unchanged)" "On" "$UPDATE_DOWNLOAD_AUTO"
MOCK_SU=()

reset_fixture
write_plist "['AutomaticDownload']"
run_case
chk_eq "non-dictionary plist -> every signal Unknown" "" "$(all_signals | grep -v '=Unknown$')"

reset_fixture
mkdir -p "$FIXTURE_PLIST"
run_case
chk_eq "directory in place of the plist -> every signal Unknown" "" "$(all_signals | grep -v '=Unknown$')"

if (( EUID != 0 )); then
    reset_fixture
    write_plist "{}"
    chmod 000 "$FIXTURE_PLIST"
    run_case
    chk_eq "unreadable plist -> every signal Unknown" "" "$(all_signals | grep -v '=Unknown$')"

    reset_fixture
    chmod 000 "$FIXTURE_DIR"
    run_case
    chk_eq "unsearchable preferences directory -> every signal Unknown" "" "$(all_signals | grep -v '=Unknown$')"
fi
reset_fixture

SAVED_TMPDIR="$PATCHED_TMPDIR"
MOCK_SU=( AutomaticallyInstallMacOSUpdates 1 AutomaticCheckEnabled 1 AutomaticDownload 1
          AutomaticallyInstallAppUpdates 1 ConfigDataInstall 1 CriticalUpdateInstall 1 )
_updates_no_tmp_case() {
    local sig
    for sig in "${SIGNALS[@]}"; do typeset -g "$sig=__unset__"; done
    _su_setting AutomaticDownload
    print -r -- "$_SU_SETTING"
}
PATCHED_TMPDIR=""
got=$(_updates_no_tmp_case)
PATCHED_TMPDIR="$SAVED_TMPDIR"
chk_eq "no PATCHED_TMPDIR for stderr -> Unknown, not NotConfigured" "Unknown" "$got"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
