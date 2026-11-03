#!/bin/zsh
##############################################################################
# test-fetch-empty-credentials.zsh: PAT-1760 regression guard.
#
# The bug: patched-fetch-config.sh (and a since-retired fetcher) checked only
# that bearer-token and hmac-secret EXIST. An empty or whitespace-only
# bearer-token was sent as a bare "Authorization: Bearer" header, and on the
# 401 that followed patched-fetch-config.sh wrote $CREDS_DIR/suspended for a
# request that never carried a credential. patched-fetch-posture.sh did not
# check the files at all.
#
# Runs each SHIPPED script as a real subprocess against a loopback server that
# records every request and answers 401, and checks: no request reached the
# server, the script exited 0, no suspended marker was written, and the log
# says why. A control run per script with real credentials proves the server
# and environment do receive a request, so a zero count means the guard held
# and not that the harness is broken.
#
# Unprivileged run: the 401 handler's root chown calls fail with EPERM but do
# not abort the script (no set -e), same limitation as
# test-agent-config-suspended-reachability.zsh.
#
# AGENTS.md zsh footguns: no `status` or `path` locals; everything quoted.
#
# Run: zsh endpoint/test-fetch-empty-credentials.zsh
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.fetch-empty-creds-test.XXXXXX")
server_pid=""
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

REQUEST_LOG="$WORK/requests.log"
: > "$REQUEST_LOG"

# ---------------------------------------------------------------------------
# Recording server: answers every request with 401 and appends one line per
# request to $REQUEST_LOG. Started once as a plain statement (not inside
# $(...), which would reap the background job when the subshell exits).
# ---------------------------------------------------------------------------
port_file="$WORK/port"
"$PYTHON3" - "$port_file" "$REQUEST_LOG" <<'PYEOF' &
import http.server, sys

port_file, request_log = sys.argv[1], sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        with open(request_log, "a") as fh:
            fh.write(f"{self.command} {self.path}\n")
        body = b'{"error":"unauthorized"}'
        self.send_response(401)
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

# ---------------------------------------------------------------------------
# Per-run scratch environment.
# ---------------------------------------------------------------------------
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
}

run_script() {  # run_script <script-file>; sets RUN_RC
    local script_file="$1"
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_API_URL="$API" \
    PATCHED_LOG_FILE="$LOG_FILE" \
    PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
    PATCHED_AGENT_HEALTH_STORE="$RUN_DIR/agent-health.json" \
    zsh "$SCRIPT_DIR/$script_file" >/dev/null 2>&1
    RUN_RC=$?
}

request_count() {
    wc -l < "$REQUEST_LOG" | tr -d '[:space:]'
}

# expect_no_request <label> <script-file> <log-needle>
#   Runs the script in the current environment and asserts the guard held.
expect_no_request() {
    local label="$1" script_file="$2" needle="$3" before after
    before=$(request_count)
    run_script "$script_file"
    after=$(request_count)
    chk "$label: no request reached the server (before=$before after=$after)" \
        "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
    chk "$label: clean exit (rc=$RUN_RC)" "$([[ "$RUN_RC" == "0" ]] && echo 1 || echo 0)"
    chk "$label: no suspended marker written" "$([[ ! -e "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
    chk "$label: log says no usable credentials" \
        "$(grep -q "$needle" "$LOG_FILE" 2>/dev/null && echo 1 || echo 0)"
}

# expect_request <label> <script-file>: control run with real credentials.
expect_request() {
    local label="$1" script_file="$2" before after
    before=$(request_count)
    run_script "$script_file"
    after=$(request_count)
    chk "$label: control run with credentials does reach the server (before=$before after=$after)" \
        "$(( after > before ))"
}

# ---------------------------------------------------------------------------
# Cases. Each writer leaves the other two files at their valid defaults.
# ---------------------------------------------------------------------------
typeset -a CASES
CASES=(empty-bearer whitespace-bearer empty-hmac whitespace-hmac)

apply_case() {  # apply_case <case>
    case "$1" in
        empty-bearer)      : > "$CREDS_DIR/bearer-token" ;;
        whitespace-bearer) printf '   \t\n' > "$CREDS_DIR/bearer-token" ;;
        empty-hmac)        : > "$CREDS_DIR/hmac-secret" ;;
        whitespace-hmac)   printf ' \n\t\n' > "$CREDS_DIR/hmac-secret" ;;
    esac
}

typeset -A NEEDLES
NEEDLES=(
    patched-fetch-config.sh    'agent-config: bearer-token or hmac-secret'
    patched-fetch-posture.sh   'posture: bearer-token or hmac-secret'
)

for script_file in patched-fetch-config.sh patched-fetch-posture.sh; do
    echo "[$script_file]"

    new_env "${script_file%.sh}-control"
    expect_request "$script_file" "$script_file"

    for case_name in "${CASES[@]}"; do
        new_env "${script_file%.sh}-$case_name"
        apply_case "$case_name"
        expect_no_request "$script_file $case_name" "$script_file" "${NEEDLES[$script_file]}"
    done
done

# The posture script used to read credential files that might not exist.
# PAT-1765: a missing file now exits 1, as patched-fetch-config.sh does; the
# full exit-code matrix is in test-fetch-credential-guards.zsh.
echo "[patched-fetch-posture.sh missing files]"
new_env "posture-missing"
rm -f "$CREDS_DIR/bearer-token" "$CREDS_DIR/hmac-secret"
before=$(request_count)
run_script patched-fetch-posture.sh
after=$(request_count)
chk "patched-fetch-posture.sh missing credential files: no request reached the server (before=$before after=$after)" \
    "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
chk "patched-fetch-posture.sh missing credential files: exit 1 (rc=$RUN_RC)" "$([[ "$RUN_RC" == "1" ]] && echo 1 || echo 0)"
chk "patched-fetch-posture.sh missing credential files: no suspended marker written" "$([[ ! -e "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "patched-fetch-posture.sh missing credential files: log names the missing file" \
    "$(grep -q "bearer-token missing" "$LOG_FILE" 2>/dev/null && echo 1 || echo 0)"

# fetch-config with a blank bearer-token and a suspended marker already present:
# the guard must neither clear nor rewrite it.
echo "[patched-fetch-config.sh existing marker]"
new_env "config-existing-marker"
: > "$CREDS_DIR/bearer-token"
printf 'kept\n' > "$CREDS_DIR/suspended"
before=$(request_count)
run_script patched-fetch-config.sh
after=$(request_count)
chk "existing marker: no request reached the server" "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
chk "existing marker: marker left exactly as it was" \
    "$([[ "$(cat "$CREDS_DIR/suspended" 2>/dev/null)" == "kept" ]] && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
