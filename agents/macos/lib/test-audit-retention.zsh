#!/bin/zsh
##############################################################################
# test-audit-retention.zsh: unit tests for the audit log retention signal
# (_audit_retention_expire, called by collect_auth) in auth.sh, PAT-1767
# three-state contract.
#
# Sources the live functions out of common.sh and auth.sh (no top-level side
# effects at source time) and calls the helper with scratch audit_control
# fixtures, read by the real grep, so the runner's /etc/security is never
# read.
#
# Three ways: present (Yes / No, and identical to the pre-PAT-1767 awk
# pipeline for every present fixture), absent (a readable audit_control with
# no expire-after line -> NotConfigured), failed read (unreadable file -> null,
# never NotConfigured). No audit_control at all stays null. Run:
#   zsh macos/lib/test-audit-retention.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"
SCRATCH=$(mktemp -d)
trap 'chmod -R u+rwx "$SCRATCH" 2>/dev/null; rm -rf "$SCRATCH"' EXIT

source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/auth.sh"

pass=0; fail=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}

AC="$SCRATCH/audit_control"

# The pre-PAT-1767 implementation, verbatim, for the present-value parity
# checks below.
old_retention() {
    local AUDIT_RETENTION_EXPIRE=""
    if [[ -f "$1" ]]; then
        local _expire_raw _expire_num _expire_unit
        _expire_raw=$(awk -F: '/^expire-after/{print $2; exit}' "$1" 2>/dev/null | tr -d ' \t' || true)
        if [[ -n "$_expire_raw" ]]; then
            _expire_num=$(printf '%s' "$_expire_raw" | grep -oE '^[0-9]+' || echo "0")
            _expire_unit=$(printf '%s' "$_expire_raw" | sed 's/^[0-9]*//' | head -c 1 | tr '[:upper:]' '[:lower:]')
            case "${_expire_unit:-d}" in
                d) ;;
                y) (( _expire_num = _expire_num * 365 )) ;;
                m) (( _expire_num = _expire_num * 30 ))  ;;
            esac
            if (( _expire_num >= 60 )); then AUDIT_RETENTION_EXPIRE="Yes"; else AUDIT_RETENTION_EXPIRE="No"; fi
        fi
    fi
    print -r -- "$AUDIT_RETENTION_EXPIRE"
}

run_case() {  # run_case <file content>
    print -r -- "$1" > "$AC"
    AUDIT_RETENTION_EXPIRE="__unset__"
    _audit_retention_expire "$AC"
}

HEAD=$'#\n# audit_control\n#\ndir:/var/audit\nflags:lo,aa\nminfree:5\nnaflags:lo,aa\npolicy:cnt,argv\nfilesz:2M'

##############################################################################
# 1. Present: an expire-after line with a value.
##############################################################################
echo "--- 1. expire-after present"

typeset -A PRESENT
PRESENT=(
    "expire-after:60d OR 5G"   Yes
    "expire-after:10M"         Yes
    "expire-after:1y"          Yes
    "expire-after:30d"         No
    "expire-after:59"          No
    $'expire-after:\t 90d '    Yes
    "expire-after:5G"          No
    "expire-afterX:90d"        Yes
    "expire-after:90d:extra"   Yes
)
for line in "${(@k)PRESENT}"; do
    run_case "$HEAD"$'\n'"$line"
    chk_eq "'$line' -> ${PRESENT[$line]}" "${PRESENT[$line]}" "$AUDIT_RETENTION_EXPIRE"
    chk_eq "'$line' matches the pre-PAT-1767 result" "$(old_retention "$AC")" "$AUDIT_RETENTION_EXPIRE"
done

run_case "$HEAD"$'\nexpire-after:90d\nexpire-after:10d'
chk_eq "first expire-after line wins, as before" "Yes" "$AUDIT_RETENTION_EXPIRE"

run_case "$HEAD"$'\nexpire-after:'
chk_eq "expire-after with no value -> null (unchanged)" "" "$AUDIT_RETENTION_EXPIRE"
chk_eq "empty value matches the pre-PAT-1767 result" "$(old_retention "$AC")" "$AUDIT_RETENTION_EXPIRE"

##############################################################################
# 2. Absent: audit_control read, no expire-after line.
##############################################################################
echo "--- 2. expire-after absent"

run_case "$HEAD"
chk_eq "no expire-after line -> NotConfigured" "NotConfigured" "$AUDIT_RETENTION_EXPIRE"
run_case $'#expire-after:90d\n  expire-after:90d'
chk_eq "commented or indented expire-after is not a setting -> NotConfigured" "NotConfigured" "$AUDIT_RETENTION_EXPIRE"
run_case ""
chk_eq "empty audit_control -> NotConfigured" "NotConfigured" "$AUDIT_RETENTION_EXPIRE"

##############################################################################
# 3. Failed read, and no audit_control at all.
##############################################################################
echo "--- 3. Failed read / no file"

if (( EUID != 0 )); then
    print -r -- "$HEAD" > "$AC"
    chmod 000 "$AC"
    AUDIT_RETENTION_EXPIRE="__unset__"
    _audit_retention_expire "$AC" 2>/dev/null
    chk_eq "unreadable audit_control -> null, never NotConfigured" "" "$AUDIT_RETENTION_EXPIRE"
    chmod 644 "$AC"
fi

rm -f "$AC"
AUDIT_RETENTION_EXPIRE="__unset__"
_audit_retention_expire "$AC"
chk_eq "no audit_control -> null (unchanged)" "" "$AUDIT_RETENTION_EXPIRE"

mkdir -p "$AC"
AUDIT_RETENTION_EXPIRE="__unset__"
_audit_retention_expire "$AC"
chk_eq "directory in place of audit_control -> null" "" "$AUDIT_RETENTION_EXPIRE"
rmdir "$AC"

grep -q '_audit_retention_expire /etc/security/audit_control' "$SCRIPT_DIR/auth.sh"
chk_eq "collect_auth calls the helper on /etc/security/audit_control" "0" "$?"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
