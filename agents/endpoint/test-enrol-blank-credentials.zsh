#!/bin/zsh
##############################################################################
# test-enrol-blank-credentials.zsh: PAT-1765 regression guard.
#
# The bug: patched-fetch-config.sh called patched-enroll.sh only when
# bearer-token was ABSENT, and patched-enroll.sh exited "already enrolled" when
# the file merely existed. An empty or whitespace bearer-token next to an
# enrolment token therefore never enrolled, and PAT-1760's empty-credential
# guard then sent nothing every poll: a device that stayed dark for good.
#
# Both now use one rule, the Windows agent's: a device is enrolled only with a
# usable pair (a non-blank bearer-token first line and a non-blank hmac-secret).
#
# Part 1 runs the SHIPPED patched-enroll.sh against a loopback server that
# records requests and answers 410 (so no credential write path runs) and
# checks a blank pair plus a token does POST /v1/enrol, while a usable pair
# plus a token does not. Part 2 runs the SHIPPED patched-fetch-config.sh with a
# stub patched-enroll.sh in a scratch bundle and checks when it is invoked.
#
# Every run points PATCHED_CREDS_DIR, PATCHED_STATE_DIR, PATCHED_BUNDLE_DIR,
# PATCHED_LOG_FILE and PATCHED_JSONL_LOG_DIR at a scratch directory, so nothing
# touches /etc/patched or /Library/Application Support/Patched. Unprivileged:
# patched-enroll.sh's `install -o root` fails with EPERM and is not fatal.
#
# AGENTS.md zsh footguns: no `status` or `path` locals; everything quoted.
#
# Run: zsh endpoint/test-enrol-blank-credentials.zsh
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

pass=0; fail=0
chk() {  # chk <desc> <1-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.enrol-blank-creds-test.XXXXXX")
server_pid=""
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

REQUEST_LOG="$WORK/requests.log"
: > "$REQUEST_LOG"

port_file="$WORK/port"
"$PYTHON3" - "$port_file" "$REQUEST_LOG" <<'PYEOF' &
import http.server, sys

port_file, request_log = sys.argv[1], sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        with open(request_log, "a") as fh:
            fh.write(f"{self.command} {self.path}\n")
        self.send_response(410)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _record
    do_POST = _record

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w") as fh:
    fh.write(str(srv.server_port))
srv.serve_forever()
PYEOF
server_pid=$!

STUB_PORT=""
for _i in $(seq 1 50); do
    if [[ -s "$port_file" ]]; then
        STUB_PORT=$(cat "$port_file")
        break
    fi
    sleep 0.1
done
if [[ -z "$STUB_PORT" ]]; then
    echo "FATAL: recording server did not start"
    exit 1
fi
API="http://127.0.0.1:$STUB_PORT"

new_env() {  # new_env <name>; sets RUN_DIR, CREDS_DIR, STATE_DIR, BUNDLE_DIR, LOG_FILE
    RUN_DIR="$WORK/$1"
    CREDS_DIR="$RUN_DIR/creds"
    STATE_DIR="$RUN_DIR/state"
    BUNDLE_DIR="$RUN_DIR/bundle"
    LOG_FILE="$RUN_DIR/patched-update.log"
    mkdir -p "$CREDS_DIR" "$STATE_DIR" "$BUNDLE_DIR" "$RUN_DIR/jsonl"
    printf '11111111-1111-1111-1111-111111111111\n' > "$CREDS_DIR/tenant-id"
    printf 'test-bearer-token\n' > "$CREDS_DIR/bearer-token"
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$CREDS_DIR/hmac-secret"
    printf 'fresh-enrolment-token\n' > "$CREDS_DIR/enrollment-token"
}

apply_case() {  # apply_case <case>
    case "$1" in
        empty-bearer)      : > "$CREDS_DIR/bearer-token" ;;
        whitespace-bearer) printf '   \t\n' > "$CREDS_DIR/bearer-token" ;;
        empty-hmac)        : > "$CREDS_DIR/hmac-secret" ;;
        whitespace-hmac)   printf ' \n\t\n' > "$CREDS_DIR/hmac-secret" ;;
        usable-pair)       : ;;
        # PAT-1814: no usable credential pair (not enrolled) AND the
        # enrolment token itself is blank/whitespace-only — the token has
        # nothing usable to exchange, so this must behave as "nothing to do"
        # rather than attempt (and fail) an exchange.
        empty-token)       : > "$CREDS_DIR/bearer-token"; : > "$CREDS_DIR/enrollment-token" ;;
        whitespace-token)  : > "$CREDS_DIR/bearer-token"; printf ' \t\n' > "$CREDS_DIR/enrollment-token" ;;
    esac
}

enrol_posts() {
    grep -c '^POST /v1/enrol$' "$REQUEST_LOG" 2>/dev/null | tr -d '[:space:]'
}

typeset -a BLANK_CASES
BLANK_CASES=(empty-bearer whitespace-bearer empty-hmac whitespace-hmac)

typeset -a BLANK_TOKEN_CASES
BLANK_TOKEN_CASES=(empty-token whitespace-token)

# ---------------------------------------------------------------------------
# Part 1: patched-enroll.sh
# ---------------------------------------------------------------------------
echo "[patched-enroll.sh]"
for case_name in "${BLANK_CASES[@]}" usable-pair; do
    new_env "enroll-$case_name"
    apply_case "$case_name"
    before=$(enrol_posts)
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_API_URL="$API" \
    zsh "$SCRIPT_DIR/patched-enroll.sh" > "$RUN_DIR/enroll.out" 2>&1
    rc=$?
    after=$(enrol_posts)
    if [[ "$case_name" == "usable-pair" ]]; then
        chk "$case_name: already enrolled, no POST /v1/enrol (before=$before after=$after)" \
            "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
        chk "$case_name: exit 0 (rc=$rc)" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
        chk "$case_name: enrolment token left in place" "$([[ -f "$CREDS_DIR/enrollment-token" ]] && echo 1 || echo 0)"
    else
        chk "$case_name: POST /v1/enrol sent (before=$before after=$after)" "$(( after == before + 1 ))"
        # The stub answers 410: the terminal path runs, proving the exchange was attempted.
        chk "$case_name: 410 handled as terminal (rc=$rc)" "$([[ "$rc" == "1" ]] && echo 1 || echo 0)"
        chk "$case_name: rejected token moved aside" "$([[ -f "$CREDS_DIR/enrollment-token.rejected" ]] && echo 1 || echo 0)"
    fi
done

# PAT-1814: a blank/whitespace-only enrolment TOKEN (as opposed to a blank
# bearer/hmac pair, covered above) has nothing usable to exchange — no POST,
# exit 0, token left in place untouched (not moved to .rejected, since it was
# never sent anywhere to be rejected).
for case_name in "${BLANK_TOKEN_CASES[@]}"; do
    new_env "enroll-$case_name"
    apply_case "$case_name"
    before=$(enrol_posts)
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_API_URL="$API" \
    zsh "$SCRIPT_DIR/patched-enroll.sh" > "$RUN_DIR/enroll.out" 2>&1
    rc=$?
    after=$(enrol_posts)
    chk "$case_name: no POST /v1/enrol (before=$before after=$after)" \
        "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
    chk "$case_name: exit 0, treated as nothing to do (rc=$rc)" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
    chk "$case_name: blank token left in place, not moved to .rejected" \
        "$([[ -f "$CREDS_DIR/enrollment-token" && ! -f "$CREDS_DIR/enrollment-token.rejected" ]] && echo 1 || echo 0)"
    chk "$case_name: empty-token warning logged" \
        "$(grep -q 'enrollment-token file is empty' "$RUN_DIR/enroll.out" 2>/dev/null && echo 1 || echo 0)"
done

# ---------------------------------------------------------------------------
# Part 2: patched-fetch-config.sh decides whether to call patched-enroll.sh.
# A stub records the call and exits 1 (terminal), so fetch-config stops right
# after the enrolment block and sends nothing itself.
# ---------------------------------------------------------------------------
echo "[patched-fetch-config.sh]"
write_stub_enroll() {
    cat > "$BUNDLE_DIR/patched-enroll.sh" <<'STUBEOF'
#!/bin/zsh
print -r -- called >> "${0:A:h}/enroll-calls"
exit 1
STUBEOF
    chmod 755 "$BUNDLE_DIR/patched-enroll.sh"
}

for case_name in "${BLANK_CASES[@]}"; do
    new_env "config-$case_name"
    apply_case "$case_name"
    write_stub_enroll
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_API_URL="$API" \
    PATCHED_LOG_FILE="$LOG_FILE" \
    PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
    zsh "$SCRIPT_DIR/patched-fetch-config.sh" >/dev/null 2>&1
    rc=$?
    chk "$case_name: fetch-config invoked patched-enroll.sh" "$([[ -s "$BUNDLE_DIR/enroll-calls" ]] && echo 1 || echo 0)"
    chk "$case_name: terminal enrolment reported (rc=$rc)" \
        "$([[ "$rc" == "0" ]] && grep -q 'enrollment failed terminally' "$LOG_FILE" 2>/dev/null && echo 1 || echo 0)"
done

# Control: a usable pair never calls the enrolment script, even with a token.
new_env "config-usable-pair"
write_stub_enroll
PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
PATCHED_STATE_DIR="$STATE_DIR" \
PATCHED_CREDS_DIR="$CREDS_DIR" \
PATCHED_API_URL="$API" \
PATCHED_LOG_FILE="$LOG_FILE" \
PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
zsh "$SCRIPT_DIR/patched-fetch-config.sh" >/dev/null 2>&1
chk "usable-pair: fetch-config did not invoke patched-enroll.sh" "$([[ ! -e "$BUNDLE_DIR/enroll-calls" ]] && echo 1 || echo 0)"

# PAT-1814: a present-but-blank/whitespace-only enrolment token used to pass
# fetch-config.sh's existence-only gate, invoking patched-enroll.sh every
# poll for nothing. It must no longer be invoked at all, and the run instead
# falls through to PAT-1760's usual empty-credential guard.
for case_name in "${BLANK_TOKEN_CASES[@]}"; do
    new_env "config-$case_name"
    apply_case "$case_name"
    write_stub_enroll
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_API_URL="$API" \
    PATCHED_LOG_FILE="$LOG_FILE" \
    PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
    zsh "$SCRIPT_DIR/patched-fetch-config.sh" >/dev/null 2>&1
    rc=$?
    chk "$case_name: fetch-config did NOT invoke patched-enroll.sh" \
        "$([[ ! -e "$BUNDLE_DIR/enroll-calls" ]] && echo 1 || echo 0)"
    chk "$case_name: falls through to the empty-credential guard (rc=$rc)" \
        "$([[ "$rc" == "0" ]] && grep -q 'agent-config: bearer-token or hmac-secret' "$LOG_FILE" 2>/dev/null && echo 1 || echo 0)"
done

# Control: no enrolment token and a blank bearer-token is still PAT-1760's
# "send nothing" guard, not an enrolment attempt.
new_env "config-no-token"
rm -f "$CREDS_DIR/enrollment-token"
: > "$CREDS_DIR/bearer-token"
write_stub_enroll
PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
PATCHED_STATE_DIR="$STATE_DIR" \
PATCHED_CREDS_DIR="$CREDS_DIR" \
PATCHED_API_URL="$API" \
PATCHED_LOG_FILE="$LOG_FILE" \
PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
zsh "$SCRIPT_DIR/patched-fetch-config.sh" >/dev/null 2>&1
chk "no-token: fetch-config did not invoke patched-enroll.sh" "$([[ ! -e "$BUNDLE_DIR/enroll-calls" ]] && echo 1 || echo 0)"
chk "no-token: empty-credential guard logged" \
    "$(grep -q 'agent-config: bearer-token or hmac-secret' "$LOG_FILE" 2>/dev/null && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
