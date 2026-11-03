#!/bin/zsh
##############################################################################
# test-enrol-unusable-200.zsh: PAT-1779 regression guard (macOS parity for
# PAT-1765 item 11).
#
# The bug: a 200 from /v1/enrol consumes the single-use enrolment token, but
# patched-enroll.sh kept the token "for retry" when that 200's body did not
# parse or lacked a usable tenant_id, bearer_token, hmac_secret or device_id.
# The next poll resent the consumed token, drew a 410 and suspended the device
# with the real cause gone from the log.
#
# Each unusable shape must now take the rejected-token path: a
# PATCHED_ENROLLMENT_UNUSABLE_RESPONSE line naming the problem, exit 1, the
# suspended marker written, the token moved to enrollment-token.rejected, and
# no credential file (or .tmp) stored. A second run of patched-enroll.sh, and
# a run of the real caller patched-fetch-config.sh, must send nothing.
#
# The SHIPPED scripts run against a loopback server that records every request
# and answers POST /v1/enrol with the status and body of the current case.
# Every run points PATCHED_CREDS_DIR, PATCHED_STATE_DIR, PATCHED_BUNDLE_DIR,
# PATCHED_LOG_FILE, PATCHED_JSONL_LOG_DIR and PATCHED_AGENT_HEALTH_STORE at a
# scratch directory, so nothing touches /etc/patched or
# /Library/Application Support/Patched. Unprivileged: `install -o root` and
# `chown root:wheel` fail with EPERM and are not fatal on this path.
#
# AGENTS.md zsh footguns: no `status` or `path` locals; everything quoted.
#
# Run: zsh endpoint/test-enrol-unusable-200.zsh
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.enrol-unusable-200-test.XXXXXX")
server_pid=""
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

REQUEST_LOG="$WORK/requests.log"
RESPONSE_STATUS="$WORK/response-status"
RESPONSE_BODY="$WORK/response-body"
: > "$REQUEST_LOG"

port_file="$WORK/port"
"$PYTHON3" - "$port_file" "$REQUEST_LOG" "$RESPONSE_STATUS" "$RESPONSE_BODY" <<'PYEOF' &
import http.server, sys

port_file, request_log, status_file, body_file = sys.argv[1:5]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        with open(request_log, "a") as fh:
            fh.write(f"{self.command} {self.path}\n")
        if self.command == "POST" and self.path == "/v1/enrol":
            code = int(open(status_file).read().strip())
            body = open(body_file, "rb").read()
        else:
            code, body = 500, b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

request_count() {
    wc -l < "$REQUEST_LOG" | tr -d '[:space:]'
}

new_env() {  # new_env <name>; sets RUN_DIR, CREDS_DIR, STATE_DIR, LOG_FILE
    RUN_DIR="$WORK/$1"
    CREDS_DIR="$RUN_DIR/creds"
    STATE_DIR="$RUN_DIR/state"
    LOG_FILE="$RUN_DIR/patched-update.log"
    mkdir -p "$CREDS_DIR" "$STATE_DIR" "$RUN_DIR/jsonl"
    printf 'single-use-enrolment-token\n' > "$CREDS_DIR/enrollment-token"
}

run_enroll() {  # run_enroll; sets RUN_RC, RUN_OUT
    RUN_OUT=$(PATCHED_CREDS_DIR="$CREDS_DIR" \
        PATCHED_STATE_DIR="$STATE_DIR" \
        PATCHED_BUNDLE_DIR="$SCRIPT_DIR" \
        PATCHED_API_URL="$API" \
        zsh "$SCRIPT_DIR/patched-enroll.sh" 2>&1)
    RUN_RC=$?
}

run_fetch_config() {  # run_fetch_config
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_BUNDLE_DIR="$SCRIPT_DIR" \
    PATCHED_API_URL="$API" \
    PATCHED_LOG_FILE="$LOG_FILE" \
    PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
    PATCHED_AGENT_HEALTH_STORE="$RUN_DIR/agent-health.json" \
    zsh "$SCRIPT_DIR/patched-fetch-config.sh" >/dev/null 2>&1
}

no_credentials_stored() {  # prints 1 when no credential file or .tmp exists
    local f
    for f in tenant-id bearer-token hmac-secret device-id; do
        if [[ -e "$CREDS_DIR/$f" || -e "$CREDS_DIR/$f.tmp" ]]; then
            echo 0; return
        fi
    done
    echo 1
}

# Each case: <name> <body>. The body is what the 200 carries. Values are
# fixtures, never real credentials.
T='00000000-0000-0000-0000-000000000001'
B='fixture-bearer-token'
H='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
D='c2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e'

typeset -a CASE_NAMES
typeset -A CASE_BODY
add_case() { CASE_NAMES+=("$1"); CASE_BODY[$1]="$2"; }

add_case missing-tenant-id      "{\"bearer_token\":\"$B\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case empty-tenant-id        "{\"tenant_id\":\"\",\"bearer_token\":\"$B\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case whitespace-tenant-id   "{\"tenant_id\":\"   \",\"bearer_token\":\"$B\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case null-tenant-id         "{\"tenant_id\":null,\"bearer_token\":\"$B\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case number-tenant-id       "{\"tenant_id\":42,\"bearer_token\":\"$B\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case missing-bearer-token   "{\"tenant_id\":\"$T\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case empty-bearer-token     "{\"tenant_id\":\"$T\",\"bearer_token\":\"\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case whitespace-bearer-token "{\"tenant_id\":\"$T\",\"bearer_token\":\" \\t \",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case tab-in-bearer-token    "{\"tenant_id\":\"$T\",\"bearer_token\":\"part\\tpart\",\"hmac_secret\":\"$H\",\"device_id\":\"$D\"}"
add_case missing-hmac-secret    "{\"tenant_id\":\"$T\",\"bearer_token\":\"$B\",\"device_id\":\"$D\"}"
add_case empty-hmac-secret      "{\"tenant_id\":\"$T\",\"bearer_token\":\"$B\",\"hmac_secret\":\"\",\"device_id\":\"$D\"}"
add_case whitespace-hmac-secret "{\"tenant_id\":\"$T\",\"bearer_token\":\"$B\",\"hmac_secret\":\"  \",\"device_id\":\"$D\"}"
add_case missing-device-id      "{\"tenant_id\":\"$T\",\"bearer_token\":\"$B\",\"hmac_secret\":\"$H\"}"
add_case empty-body             ""
add_case not-json               "not json"
add_case json-array             "[]"
add_case truncated-json         "{\"tenant_id\":\"$T\",\"bearer_"

for case_name in "${CASE_NAMES[@]}"; do
    echo "[unusable 200: $case_name]"
    new_env "$case_name"
    printf '200\n' > "$RESPONSE_STATUS"
    printf '%s' "${CASE_BODY[$case_name]}" > "$RESPONSE_BODY"

    before=$(request_count)
    run_enroll
    after=$(request_count)

    chk "$case_name: one POST /v1/enrol (before=$before after=$after)" "$(( after == before + 1 ))"
    chk "$case_name: terminal exit 1 (rc=$RUN_RC)" "$([[ "$RUN_RC" == "1" ]] && echo 1 || echo 0)"
    chk "$case_name: logs the unusable response" \
        "$([[ "$RUN_OUT" == *PATCHED_ENROLLMENT_UNUSABLE_RESPONSE* ]] && echo 1 || echo 0)"
    chk "$case_name: does not claim a retry" \
        "$([[ "$RUN_OUT" != *"for retry"* && "$RUN_OUT" != *"retaining"* ]] && echo 1 || echo 0)"
    chk "$case_name: no response value in the log" \
        "$([[ "$RUN_OUT" != *"$B"* && "$RUN_OUT" != *"$H"* ]] && echo 1 || echo 0)"
    chk "$case_name: suspended marker written" "$([[ -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
    chk "$case_name: token moved to enrollment-token.rejected" \
        "$([[ ! -e "$CREDS_DIR/enrollment-token" \
            && "$(cat "$CREDS_DIR/enrollment-token.rejected" 2>/dev/null)" == single-use-enrolment-token ]] && echo 1 || echo 0)"
    chk "$case_name: no credential file or .tmp stored" "$(no_credentials_stored)"

    # Next runs: neither the enrol script nor its real caller resends the token.
    before=$(request_count)
    run_enroll
    run_fetch_config
    after=$(request_count)
    chk "$case_name: next runs send nothing (before=$before after=$after)" "$(( after == before ))"
    chk "$case_name: still no credential file stored" "$(no_credentials_stored)"
done

# Control: a 5xx did not consume the token, so it stays in place for the next poll.
echo "[control: 503 stays transient]"
new_env "transient-503"
printf '503\n' > "$RESPONSE_STATUS"
: > "$RESPONSE_BODY"
before=$(request_count)
run_enroll
run_enroll
after=$(request_count)
chk "503: both runs POST /v1/enrol (before=$before after=$after)" "$(( after == before + 2 ))"
chk "503: exit 0 (rc=$RUN_RC)" "$([[ "$RUN_RC" == "0" ]] && echo 1 || echo 0)"
chk "503: token kept, no marker" \
    "$([[ -f "$CREDS_DIR/enrollment-token" && ! -e "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
