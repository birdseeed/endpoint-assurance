#!/bin/zsh
##############################################################################
# test-fetch-credential-guards.zsh: PAT-1765 regression guard.
#
# the credential-reading fetchers skipped a run with
# missing or blank credentials leaving only a plain-text echo, so a device
# whose credentials were blanked looked the same as a healthy one in the
# JSON-lines log. patched-fetch-posture.sh also never checked tenant-id (it
# sent a signed request and then failed verification against an empty tenant)
# and exited 0 for a missing credential file where patched-fetch-config.sh
# exits 1.
#
# Exit codes, before -> after:
#   script            missing tenant-id  missing bearer/hmac  blank bearer/hmac
#   fetch-config      1 -> 1             1 -> 1               0 -> 0
#   fetch-posture     0* -> 1            0 -> 1               0 -> 0
#   (* request sent, then verification failed)
#
# Runs each SHIPPED script as a subprocess against a loopback server that
# records every request, with every path redirected to a scratch directory,
# and checks: no request, the exit code above, and one JSON-lines record from
# the right component naming the problem.
#
# Posture also records the credentials_unusable|device_credentials
# agent-health fault (reason <file>_missing or credentials_empty), so the
# device reports degraded; not while an enrolment token is present (enrolment
# is expected to supply the credentials), and it is cleared by the next run
# that finds usable credentials.
#
# AGENTS.md zsh footguns: no `status` or `path` locals; everything quoted.
#
# Run: zsh endpoint/test-fetch-credential-guards.zsh
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.fetch-credential-guards-test.XXXXXX")
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

new_env() {  # new_env <name>; sets RUN_DIR, CREDS_DIR, STATE_DIR, BUNDLE_DIR, LOG_FILE, JSONL_FILE
    RUN_DIR="$WORK/$1"
    CREDS_DIR="$RUN_DIR/creds"
    STATE_DIR="$RUN_DIR/state"
    BUNDLE_DIR="$RUN_DIR/bundle"
    LOG_FILE="$RUN_DIR/patched-update.log"
    JSONL_FILE="$RUN_DIR/jsonl/daemon.jsonl"
    mkdir -p "$CREDS_DIR" "$STATE_DIR" "$BUNDLE_DIR" "$RUN_DIR/jsonl"
    printf '11111111-1111-1111-1111-111111111111\n' > "$CREDS_DIR/tenant-id"
    printf 'test-bearer-token\n' > "$CREDS_DIR/bearer-token"
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$CREDS_DIR/hmac-secret"
}

run_script() {  # run_script <script-file>; sets RUN_RC
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_API_URL="$API" \
    PATCHED_LOG_FILE="$LOG_FILE" \
    PATCHED_JSONL_LOG_DIR="$RUN_DIR/jsonl" \
    PATCHED_AGENT_HEALTH_STORE="$RUN_DIR/agent-health.json" \
    zsh "$SCRIPT_DIR/$1" >/dev/null 2>&1
    RUN_RC=$?
}

request_count() {
    wc -l < "$REQUEST_LOG" | tr -d '[:space:]'
}

# jsonl_has <level> <component> <msg-substring> [<credential_file>]
jsonl_has() {
    "$PYTHON3" - "$JSONL_FILE" "$1" "$2" "$3" "${4:-}" <<'PYEOF'
import json, sys
path, level, component, needle, cred_file = sys.argv[1:6]
try:
    lines = open(path).read().splitlines()
except OSError:
    print(0); sys.exit(0)
for line in lines:
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("level") != level or rec.get("component") != component or needle not in rec.get("msg", ""):
        continue
    if cred_file and rec.get("fields", {}).get("credential_file") != cred_file:
        continue
    print(1); sys.exit(0)
print(0)
PYEOF
}

# health_reason: the active credentials_unusable|device_credentials reason, or "none"
health_reason() {
    "$PYTHON3" - "$RUN_DIR/agent-health.json" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("none"); sys.exit(0)
entry = data.get("active", {}).get("credentials_unusable|device_credentials")
print(entry["reason"] if isinstance(entry, dict) else "none")
PYEOF
}

typeset -A COMPONENT PREFIX
COMPONENT=(
    patched-fetch-config.sh    daemon
    patched-fetch-posture.sh   posture
)
PREFIX=(
    patched-fetch-config.sh    fetch-config
    patched-fetch-posture.sh   fetch-posture
)

for script_file in patched-fetch-config.sh patched-fetch-posture.sh; do
    echo "[$script_file]"
    component="${COMPONENT[$script_file]}"
    prefix="${PREFIX[$script_file]}"

    for cred_file in tenant-id bearer-token hmac-secret; do
        new_env "${script_file%.sh}-missing-$cred_file"
        rm -f "$CREDS_DIR/$cred_file"
        before=$(request_count)
        run_script "$script_file"
        after=$(request_count)
        label="$script_file missing $cred_file"
        chk "$label: no request (before=$before after=$after)" "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
        chk "$label: exit 1 like fetch-config (rc=$RUN_RC)" "$([[ "$RUN_RC" == "1" ]] && echo 1 || echo 0)"
        chk "$label: JSON-lines error from $component names the file" \
            "$(jsonl_has error "$component" "$prefix skipped: credential file missing" "$cred_file")"
        if [[ "$script_file" != patched-fetch-config.sh ]]; then
            chk "$label: agent-health fault recorded" \
                "$([[ "$(health_reason)" == "${cred_file//-/_}_missing" ]] && echo 1 || echo 0)"
        fi
    done

    for case_name in blank-bearer blank-hmac; do
        new_env "${script_file%.sh}-$case_name"
        case "$case_name" in
            blank-bearer) printf '  \n' > "$CREDS_DIR/bearer-token" ;;
            blank-hmac)   : > "$CREDS_DIR/hmac-secret" ;;
        esac
        before=$(request_count)
        run_script "$script_file"
        after=$(request_count)
        label="$script_file $case_name"
        chk "$label: no request (before=$before after=$after)" "$([[ "$before" == "$after" ]] && echo 1 || echo 0)"
        chk "$label: exit 0 (rc=$RUN_RC)" "$([[ "$RUN_RC" == "0" ]] && echo 1 || echo 0)"
        chk "$label: JSON-lines warning from $component" \
            "$(jsonl_has warn "$component" "$prefix skipped: device credentials empty")"
        if [[ "$script_file" != patched-fetch-config.sh ]]; then
            chk "$label: agent-health fault recorded" \
                "$([[ "$(health_reason)" == "credentials_empty" ]] && echo 1 || echo 0)"
        fi
    done
done

for script_file in patched-fetch-posture.sh; do
    echo "[$script_file agent-health]"

    # Mid-enrolment: an enrolment token is present, so missing credentials are
    # expected and not a fault.
    new_env "${script_file%.sh}-enrolling"
    rm -f "$CREDS_DIR/bearer-token" "$CREDS_DIR/hmac-secret"
    printf 'pending-token\n' > "$CREDS_DIR/enrollment-token"
    run_script "$script_file"
    chk "$script_file enrolment token present: no agent-health fault" \
        "$([[ "$(health_reason)" == "none" ]] && echo 1 || echo 0)"

    # An empty or whitespace-only enrolment token never enrols (patched-enroll.sh
    # strips whitespace and gives up), so it must not hide the fault.
    new_env "${script_file%.sh}-blank-token"
    rm -f "$CREDS_DIR/bearer-token" "$CREDS_DIR/hmac-secret"
    printf '  \n' > "$CREDS_DIR/enrollment-token"
    run_script "$script_file"
    chk "$script_file whitespace enrolment token: agent-health fault recorded" \
        "$([[ "$(health_reason)" != "none" ]] && echo 1 || echo 0)"

    # A token moved aside by patched-enroll.sh was consumed or rejected and can
    # never explain the missing pair as an in-progress enrolment. Both platforms
    # report the same recovery reason while waiting for a fresh token.
    new_env "${script_file%.sh}-spent-token"
    rm -f "$CREDS_DIR/bearer-token" "$CREDS_DIR/hmac-secret" "$CREDS_DIR/enrollment-token"
    printf 'spent-token\n' > "$CREDS_DIR/enrollment-token.rejected"
    run_script "$script_file"
    chk "$script_file spent token: enrolment_token_spent fault recorded" \
        "$([[ "$(health_reason)" == "enrolment_token_spent" ]] && echo 1 || echo 0)"

    # Recovery: a run with usable credentials clears the fault a blank run left.
    new_env "${script_file%.sh}-recovers"
    : > "$CREDS_DIR/bearer-token"
    run_script "$script_file"
    chk "$script_file blank run: fault recorded" \
        "$([[ "$(health_reason)" == "credentials_empty" ]] && echo 1 || echo 0)"
    printf 'test-bearer-token\n' > "$CREDS_DIR/bearer-token"
    before=$(request_count)
    run_script "$script_file"
    after=$(request_count)
    chk "$script_file usable run: request sent (before=$before after=$after)" "$(( after > before ))"
    chk "$script_file usable run: fault cleared" \
        "$([[ "$(health_reason)" == "none" ]] && echo 1 || echo 0)"

    # A healthy device with no such fault does not get its store rewritten for
    # it.
    new_env "${script_file%.sh}-healthy"
    printf '{"active":{},"ever_succeeded":{}}' > "$RUN_DIR/agent-health.json"
    run_script "$script_file"
    chk "$script_file healthy run: no credentials fault" \
        "$([[ "$(health_reason)" == "none" ]] && echo 1 || echo 0)"
    if [[ "$script_file" == patched-fetch-posture.sh ]]; then
        chk "$script_file healthy run: agent-health store untouched" \
            "$([[ "$(cat "$RUN_DIR/agent-health.json")" == '{"active":{},"ever_succeeded":{}}' ]] && echo 1 || echo 0)"
    fi
done

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
