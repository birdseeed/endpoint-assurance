#!/bin/zsh
##############################################################################
# test-mdm-enrolment.zsh — unit tests for the macOS MDM enrolment signal
# (collect_mdm_enrolment) in auth.sh (PAT-1752).
#
# Sources the live function out of auth.sh (no top-level side effects at
# source time) so the tests exercise the real code, not a copy. `profiles` is
# shadowed with a zsh function of the same name (zsh resolves a function
# before an external command), so the runner's own enrolment is never read.
#
# The neutral mdm_enrolled fact and separate DEP detail are the authoritative
# new contract. The combined mdm_enrolment value remains for one compatibility
# release. A failed or unparseable read must be "Unknown" (PAT-1710). Run:
#   zsh macos/lib/test-mdm-enrolment.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/auth.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

# ── Boundary double ────────────────────────────────────────────────────────
# Fixtures match real `profiles status -type enrollment` output.
FIXTURE_UNENROLLED=$'Enrolled via DEP: No\nMDM enrollment: No'
FIXTURE_ENROLLED=$'Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)'
MOCK_PROFILES_MODE="unenrolled"
# profiles runs inside a command substitution (a subshell), so the arguments
# it was called with are recorded to a scratch file, not a variable.
ARGS_FILE=$(mktemp "${TMPDIR:-/tmp}/patched-mdm-args.XXXXXX")
trap 'rm -f "$ARGS_FILE"' EXIT
profiles() {
    print -r -- "$*" > "$ARGS_FILE"
    case "$MOCK_PROFILES_MODE" in
        unenrolled)       print -r -- "$FIXTURE_UNENROLLED" ;;
        enrolled)         print -r -- "$FIXTURE_ENROLLED" ;;
        fail)             print -u2 -- "profiles: an error occurred"; return 1 ;;
        fail_with_output) print -r -- "$FIXTURE_ENROLLED"; return 1 ;;
        empty)            return 0 ;;
        garbage)          print -r -- "Some unrelated output" ;;
        no_mdm_line)      print -r -- "Enrolled via DEP: No" ;;
        no_dep_line)      print -r -- "MDM enrollment: Yes" ;;
        empty_values)     print -r -- $'Enrolled via DEP: \nMDM enrollment: ' ;;
        malformed_yes)    print -r -- $'Enrolled via DEP: YesPlease\nMDM enrollment: YesPlease' ;;
    esac
}

run_case() {
    MOCK_PROFILES_MODE="$1"
    MDM_ENROLMENT="__unset__"
    MDM_ENROLLED="__unset__"
    MDM_ENROLLED_VIA_DEP="__unset__"
    collect_mdm_enrolment
}

echo "--- successful read (format unchanged)"

run_case unenrolled
chk_eq "profiles invoked as status -type enrollment" "status -type enrollment" "$(cat "$ARGS_FILE")"
chk_eq "unenrolled Mac -> dep=No mdm=No" "dep=No mdm=No" "$MDM_ENROLMENT"
chk_eq "unenrolled Mac -> neutral No" "No" "$MDM_ENROLLED"
chk_eq "unenrolled Mac -> DEP No" "No" "$MDM_ENROLLED_VIA_DEP"

run_case enrolled
chk_eq "enrolled Mac -> dep=Yes mdm=Yes (User Approved)" "dep=Yes mdm=Yes (User Approved)" "$MDM_ENROLMENT"
chk_eq "enrolled Mac -> neutral Yes" "Yes" "$MDM_ENROLLED"
chk_eq "enrolled Mac -> DEP Yes" "Yes" "$MDM_ENROLLED_VIA_DEP"

echo "--- failed or unparseable read -> Unknown"

run_case fail
chk_eq "profiles exits non-zero -> Unknown" "Unknown" "$MDM_ENROLMENT"
chk_eq "profiles exits non-zero -> neutral Unknown" "Unknown" "$MDM_ENROLLED"
chk_eq "profiles exits non-zero -> DEP Unknown" "Unknown" "$MDM_ENROLLED_VIA_DEP"

run_case fail_with_output
chk_eq "profiles exits non-zero even with parseable output -> Unknown" "Unknown" "$MDM_ENROLMENT"

run_case empty
chk_eq "profiles exits 0 with empty output -> Unknown" "Unknown" "$MDM_ENROLMENT"

run_case garbage
chk_eq "profiles output without enrolment lines -> Unknown" "Unknown" "$MDM_ENROLMENT"

run_case no_mdm_line
chk_eq "profiles output without MDM enrollment line -> Unknown" "Unknown" "$MDM_ENROLMENT"
chk_eq "missing MDM line -> neutral Unknown" "Unknown" "$MDM_ENROLLED"
chk_eq "valid DEP survives missing MDM line" "No" "$MDM_ENROLLED_VIA_DEP"

run_case no_dep_line
chk_eq "profiles output without Enrolled via DEP line -> Unknown" "Unknown" "$MDM_ENROLMENT"
chk_eq "valid MDM survives missing DEP line" "Yes" "$MDM_ENROLLED"
chk_eq "missing DEP line -> DEP Unknown" "Unknown" "$MDM_ENROLLED_VIA_DEP"

run_case empty_values
chk_eq "enrolment lines with empty values -> Unknown" "Unknown" "$MDM_ENROLMENT"
chk_eq "empty MDM value -> neutral Unknown" "Unknown" "$MDM_ENROLLED"
chk_eq "empty DEP value -> DEP Unknown" "Unknown" "$MDM_ENROLLED_VIA_DEP"

run_case malformed_yes
chk_eq "malformed Yes-like MDM value does not pass" "Unknown" "$MDM_ENROLLED"
chk_eq "malformed Yes-like DEP value does not pass" "Unknown" "$MDM_ENROLLED_VIA_DEP"

echo "--- collect_auth wires the helper in"
chk_eq "collect_auth calls collect_mdm_enrolment" "1" \
    "$(grep -c '^    collect_mdm_enrolment$' "$SCRIPT_DIR/auth.sh")"
chk_eq "collector emits neutral mdm_enrolled exactly once" "1" \
    "$(grep -c '^    "mdm_enrolled":' "$SCRIPT_DIR/../patched-collect.sh")"
chk_eq "collector emits separate DEP detail exactly once" "1" \
    "$(grep -c '^    "mdm_enrolled_via_dep":' "$SCRIPT_DIR/../patched-collect.sh")"
chk_eq "collector retains legacy mdm_enrolment exactly once" "1" \
    "$(grep -c '^    "mdm_enrolment":' "$SCRIPT_DIR/../patched-collect.sh")"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
