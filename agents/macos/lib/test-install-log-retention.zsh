#!/bin/zsh
##############################################################################
# test-install-log-retention.zsh: unit tests for the install.log retention
# signal (_install_log_retention_days, called by collect_auth) in auth.sh,
# PAT-1775 three-state contract for a numeric signal.
#
# Sources the live functions out of common.sh and auth.sh (no top-level side
# effects at source time) and calls the helper with scratch ASL config
# fixtures, read by the real grep, so the runner's /etc/asl is never read.
#
# Three ways: present (a whole number, identical to the pre-PAT-1775
# grep | head -1 | grep pipeline for every present fixture), absent (a
# readable file with no ttl= -> NotConfigured), failed read (unreadable file
# -> null, never NotConfigured). No config file at all stays null, and a ttl=
# with no number is null. Section 4 renders the install_log_retention_days
# line from the real patched-collect.sh payload heredoc and parses it, so
# each state is asserted as its JSON type. Run:
#   zsh macos/lib/test-install-log-retention.zsh
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

ASL="$SCRATCH/com.apple.install"
ERR_LOG="$SCRATCH/err.log"

# The pre-PAT-1775 implementation, verbatim, for the present-value parity
# checks below.
old_retention() {
    local INSTALL_LOG_RETENTION_DAYS=""
    local _asl_file="$1"
    if [[ -f "$_asl_file" ]]; then
        local _ttl
        _ttl=$(grep -oE 'ttl=[0-9]+' "$_asl_file" 2>/dev/null | head -1 | grep -oE '[0-9]+' || true)
        [[ "$_ttl" =~ ^[0-9]+$ ]] && INSTALL_LOG_RETENTION_DAYS="$_ttl"
    fi
    print -r -- "$INSTALL_LOG_RETENTION_DAYS"
}

run_case() {  # run_case <file content>
    print -r -- "$1" > "$ASL"
    INSTALL_LOG_RETENTION_DAYS="__unset__"
    _install_log_retention_days "$ASL" 2> "$ERR_LOG"
}

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

# The stock file on macOS 26.6.2: rotation limits, no ttl.
STOCK=$'# install messages get saved only in /var/log/install.log\n? [= Facility install] claim only\n* file /var/log/install.log format=\'$((Time)(JZ)) $Host $(Sender)[$(PID)]: $Message\' rotate=seq compress file_max=50M all_max=150M size_only'
CIS=$'# install messages get saved only in /var/log/install.log\n? [= Facility install] claim only\n* file /var/log/install.log format=\'$((Time)(JZ)) $Host $(Sender)[$(PID)]: $Message\' rotate=utc compress file_max=50M size_only ttl=365'

##############################################################################
# 1. Present: a ttl=<digits> value.
##############################################################################
echo "--- 1. ttl present"

typeset -A PRESENT
PRESENT=(
    "$CIS"                                     365
    "* file /var/log/install.log ttl=30"       30
    "* file /var/log/install.log ttl=0"        0
    "* file /var/log/install.log ttl=400days"  400
    "* file a ttl=90 ttl=10"                   90
    $'* file a ttl=abc\n* file b ttl=7'        7
    $'* file a ttl=12\n* file b ttl=99'        12
    "* file a xttl=45"                         45
    "# ttl=365"                                365
)
for content in "${(@k)PRESENT}"; do
    run_case "$content"
    chk_eq "[${content//$'\n'/ | }] -> ${PRESENT[$content]}" "${PRESENT[$content]}" "$INSTALL_LOG_RETENTION_DAYS"
    chk_eq "[${content//$'\n'/ | }] matches the pre-PAT-1775 result" "$(old_retention "$ASL")" "$INSTALL_LOG_RETENTION_DAYS"
done

##############################################################################
# 2. Absent: the file was read and has no ttl= at all.
##############################################################################
echo "--- 2. ttl absent"

run_case "$STOCK"
chk_eq "stock macOS 26.6.2 file, no ttl -> NotConfigured" "NotConfigured" "$INSTALL_LOG_RETENTION_DAYS"
chk_eq "stock file logs no warning" "0" "$(wc -l < "$ERR_LOG" | tr -d ' ')"
chk_eq "the old pipeline sent null for the same file" "" "$(old_retention "$ASL")"
run_case ""
chk_eq "empty config file -> NotConfigured" "NotConfigured" "$INSTALL_LOG_RETENTION_DAYS"

##############################################################################
# 3. Failed read, a ttl= of the wrong shape, and no config file at all.
##############################################################################
echo "--- 3. Failed read / wrong shape / no file"

run_case "* file /var/log/install.log ttl=abc"
chk_eq "ttl= without a number -> null, not NotConfigured" "" "$INSTALL_LOG_RETENTION_DAYS"
chk_eq "ttl= without a number logs a reason" "1" "$(grep -c 'ttl= without a number' "$ERR_LOG")"
run_case "* file /var/log/install.log ttl="
chk_eq "empty ttl= -> null, not NotConfigured" "" "$INSTALL_LOG_RETENTION_DAYS"
run_case "* file /var/log/install.log TTL=365"
chk_eq "TTL=365 is not read as a value (case-sensitive, as before)" "$(old_retention "$ASL")" "$INSTALL_LOG_RETENTION_DAYS"
chk_eq "TTL=365 -> null, not NotConfigured (ASL case handling unverified)" "" "$INSTALL_LOG_RETENTION_DAYS"

if (( EUID != 0 )); then
    print -r -- "$CIS" > "$ASL"
    chmod 000 "$ASL"
    INSTALL_LOG_RETENTION_DAYS="__unset__"
    _install_log_retention_days "$ASL" 2> "$ERR_LOG"
    chk_eq "unreadable config -> null, never NotConfigured" "" "$INSTALL_LOG_RETENTION_DAYS"
    chk_eq "unreadable config logs the grep exit" "1" "$(grep -c 'grep exited 2' "$ERR_LOG")"
    chmod 644 "$ASL"
fi

rm -f "$ASL"
INSTALL_LOG_RETENTION_DAYS="__unset__"
_install_log_retention_days "$ASL"
chk_eq "no config file -> null (unchanged)" "" "$INSTALL_LOG_RETENTION_DAYS"

mkdir -p "$ASL"
INSTALL_LOG_RETENTION_DAYS="__unset__"
_install_log_retention_days "$ASL"
chk_eq "directory in place of the config file -> null" "" "$INSTALL_LOG_RETENTION_DAYS"
rmdir "$ASL"

grep -q '_install_log_retention_days /etc/asl/com.apple.install' "$SCRIPT_DIR/auth.sh"
chk_eq "collect_auth calls the helper on /etc/asl/com.apple.install" "0" "$?"

##############################################################################
# 4. Payload JSON type: present is a JSON integer, absent the JSON string
#    "NotConfigured", a failed read null.
##############################################################################
echo "--- 4. Payload JSON type"

run_case "$CIS"
chk_eq "payload: ttl=365 -> JSON integer 365" "int:365" "$(payload_json_type install_log_retention_days)"
run_case "* file a ttl=0365"
chk_eq "payload: ttl=0365 -> JSON integer 365, never invalid JSON" "int:365" "$(payload_json_type install_log_retention_days)"
run_case "$STOCK"
chk_eq "payload: no ttl -> JSON string NotConfigured" "str:NotConfigured" "$(payload_json_type install_log_retention_days)"
run_case "* file a ttl=abc"
chk_eq "payload: ttl= without a number -> JSON null" "null" "$(payload_json_type install_log_retention_days)"
rm -f "$ASL"
_install_log_retention_days "$ASL"
chk_eq "payload: no config file -> JSON null" "null" "$(payload_json_type install_log_retention_days)"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
