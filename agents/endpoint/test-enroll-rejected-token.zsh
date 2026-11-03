#!/bin/zsh
##############################################################################
# test-enroll-rejected-token.zsh — PAT-1203: patched-enroll.sh's 410/401
# handling must not leave the rejected single-use token sitting at the
# canonical path forever.
#
# Before this fix: on a terminal 410/401, the script wrote $CREDS_DIR/suspended
# but left $CREDS_DIR/enrollment-token untouched. patched-fetch-config.sh and
# patched-update.sh both gate calling this script on
# `-f "$CREDS_DIR/enrollment-token" && ! -f "$CREDS_DIR/bearer-token"`, so
# every subsequent poll would re-invoke patched-enroll.sh, which re-reads the
# SAME already-consumed token from disk and gets the identical 410/401 again
# — a busy retry-with-a-known-dead-token loop, forever, mirroring the
# Windows-side bug this ticket also fixes in PatchedWorker/AgentEnroller.
#
# After the fix: the rejected token is renamed (not deleted, for forensics)
# to "<enrollment-token>.rejected", so the canonical path is free for a
# fresh token an admin drops later, and the retry-gate above naturally goes
# false until one appears — no more POSTs against a token the server has
# already permanently rejected.
#
# Follows test-enroll-credential-write.zsh's proven pattern exactly: one
# single-purpose local HTTP stub server per sub-test, started directly at
# top level (not wrapped in a function/command-substitution subshell), each
# bounded to a handful of requests so a leftover process can never hang the
# suite even if cleanup is skipped.
#
# PAT-1779: every run of patched-enroll.sh gets a scratch PATCHED_CREDS_DIR,
# PATCHED_STATE_DIR and PATCHED_BUNDLE_DIR (see ENROLL_ENV below). Without the
# state dir, the successful-enrolment path (reached when this runs as root)
# classified and could remove the agent-config floor under the real
# /Library/Application Support/Patched, and without the bundle dir it read the
# floor parser from an installed /usr/local/patched-updater.
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-enroll.sh"
PYTHON3="/usr/bin/python3"

pass=0; fail=0

chk_eq() {
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then
        (( pass++ )); echo "  PASS: $desc -> $got"
    else
        (( fail++ )); echo "  FAIL: $desc"
        echo "        expected: $exp"
        echo "        got:      $got"
    fi
}

chk_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc"
        echo "        needle:   $needle"
        echo "        haystack: ${haystack:0:400}"
    fi
}

chk_not_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc — should NOT contain: $needle"
        echo "        haystack: ${haystack:0:400}"
    fi
}

CREDS_DIR=$(mktemp -d /tmp/.test-enroll-rejected.XXXXXX)
STATE_DIR=$(mktemp -d /tmp/.test-enroll-rejected-state.XXXXXX)
server_pid=""
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
    rm -rf "$CREDS_DIR" "$STATE_DIR"
}
trap cleanup EXIT

if [[ ! -d "$CREDS_DIR" || ! -d "$STATE_DIR" ]]; then
    echo "FATAL: could not create scratch directories"
    exit 1
fi

# Scratch paths for every patched-enroll.sh run, so nothing reads or writes
# /etc/patched, /Library/Application Support/Patched or an installed bundle.
typeset -a ENROLL_ENV
ENROLL_ENV=(
    "PATCHED_CREDS_DIR=$CREDS_DIR"
    "PATCHED_STATE_DIR=$STATE_DIR"
    "PATCHED_BUNDLE_DIR=$SCRIPT_DIR"
)

# ============================================================================
# 410 Gone — rejected token must be moved out of the canonical path.
# ============================================================================
echo "\n--- 410 Gone: rejected token is renamed, not left in place ---"

port_file=$(mktemp /tmp/.test-enroll-rejected-port.XXXXXX)
"$PYTHON3" - "$port_file" <<'PYEOF' &
import http.server, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        self.send_response(410)
        self.send_header("Content-Length", "0")
        self.end_headers()

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_port))
srv.timeout = 30
for _ in range(5):
    srv.handle_request()
PYEOF
server_pid=$!

port=""
for _ in $(seq 1 50); do
    if [[ -s "$port_file" ]]; then
        port=$(cat "$port_file")
        break
    fi
    sleep 0.1
done
rm -f "$port_file"

if [[ -z "$port" ]]; then
    echo "FAIL: local /v1/enrol stub server (410) did not start"
    (( fail++ ))
    echo "RESULT: pass=${pass} fail=${fail}"
    exit 1
fi
API_URL="http://127.0.0.1:${port}"

printf 'stale-single-use-token\n' > "$CREDS_DIR/enrollment-token"

out=$(env "${ENROLL_ENV[@]}" PATCHED_API_URL="$API_URL" zsh "$TARGET" 2>&1)
rc=$?

kill "$server_pid" 2>/dev/null; server_pid=""

chk_eq "exit code is 1 (terminal failure)" "1" "$rc"
chk_contains "logs the expiry" "PATCHED_ENROLLMENT_EXPIRED" "$out"
chk_eq "suspended marker written" "1" "$([ -f "$CREDS_DIR/suspended" ] && echo 1 || echo 0)"
chk_eq "canonical enrollment-token no longer present" "0" "$([ -f "$CREDS_DIR/enrollment-token" ] && echo 1 || echo 0)"
chk_eq "rejected token preserved for forensics" "1" "$([ -f "$CREDS_DIR/enrollment-token.rejected" ] && echo 1 || echo 0)"
chk_eq "rejected token content matches what was posted" "stale-single-use-token" "$(cat "$CREDS_DIR/enrollment-token.rejected" 2>/dev/null)"

# ============================================================================
# Re-running immediately with nothing changed: no enrollment-token at the
# canonical path any more, so the script has nothing to do (line "No
# enrollment token — nothing to do", exit 0, no HTTP call at all) — the
# caller-side gate (`-f enrollment-token && ! -f bearer-token`) that used to
# re-invoke this script every poll now goes false on its own. No stub server
# needed for this block: a repeat POST would be the bug.
# ============================================================================
echo "\n--- Immediate re-run with no fresh token: no-op, no repeat POST ---"

out2=$(env "${ENROLL_ENV[@]}" PATCHED_API_URL="http://127.0.0.1:1" zsh "$TARGET" 2>&1)
rc2=$?

chk_eq "exit code is 0 (nothing to do)" "0" "$rc2"
chk_eq ".rejected file untouched by the no-op run" "stale-single-use-token" "$(cat "$CREDS_DIR/enrollment-token.rejected" 2>/dev/null)"

# ============================================================================
# Admin drops a FRESH token at the canonical path (the real recovery path,
# both here and in install.sh's --enrollment-token re-provisioning flow,
# which does an atomic .tmp+mv write to this exact path regardless of
# whether a ".rejected" dead-letter file sits alongside it). The very next
# invocation must pick it up and attempt the exchange, with no manual
# cleanup required.
# ============================================================================
echo "\n--- Fresh token dropped afterward is picked up automatically ---"

port_file2=$(mktemp /tmp/.test-enroll-rejected-port2.XXXXXX)
"$PYTHON3" - "$port_file2" <<'PYEOF' &
import http.server, json, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        body = json.dumps({
            "tenant_id": "00000000-0000-0000-0000-000000000002",
            "bearer_token": "fresh-bearer-token-value",
            "hmac_secret": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "device_id": "d3d4d5d6-e7f8-4a9b-8c0d-1e2f3a4b5c6d",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_port))
srv.timeout = 30
for _ in range(5):
    srv.handle_request()
PYEOF
server_pid=$!

port2=""
for _ in $(seq 1 50); do
    if [[ -s "$port_file2" ]]; then
        port2=$(cat "$port_file2")
        break
    fi
    sleep 0.1
done
rm -f "$port_file2"

if [[ -z "$port2" ]]; then
    echo "FAIL: local /v1/enrol stub server (200) did not start"
    (( fail++ ))
    echo "RESULT: pass=${pass} fail=${fail}"
    exit 1
fi
API_URL2="http://127.0.0.1:${port2}"

printf 'brand-new-token\n' > "$CREDS_DIR/enrollment-token"

out3=$(env "${ENROLL_ENV[@]}" PATCHED_API_URL="$API_URL2" zsh "$TARGET" 2>&1)
rc3=$?

kill "$server_pid" 2>/dev/null; server_pid=""

# Landing all four credential files on a genuine 200 requires chowning them
# to root:wheel (see test-enroll-credential-write.zsh's header for why this
# repo's tests treat that as root-only), which an unprivileged CI/dev run
# cannot do. What PAT-1203 actually claims — the fresh token is picked up
# and used at all, instead of the canonical path staying blocked by the
# stale rejected token — is fully provable without root: the "exchanging
# enrollment token" banner only prints once ENROLLMENT_TOKEN is read
# successfully and the script proceeds to POST it, and a script that was
# still stuck on the old dead token would report the SAME 410 rejection
# again instead.
chk_contains "attempts the exchange using the fresh token (not silently skipped)" "exchanging enrollment token" "$out3"
chk_not_contains "does not repeat the OLD token's rejection" "PATCHED_ENROLLMENT_EXPIRED" "$out3"

if [[ "$(id -u)" == "0" ]]; then
    chk_eq "exit code is 0 (enrolled)" "0" "$rc3"
    chk_contains "reports enrollment" "Enrolled: tenant" "$out3"
    chk_eq "bearer-token landed" "fresh-bearer-token-value" "$(cat "$CREDS_DIR/bearer-token" 2>/dev/null)"
    chk_eq "canonical enrollment-token consumed again" "0" "$([ -f "$CREDS_DIR/enrollment-token" ] && echo 1 || echo 0)"
else
    echo "  NOTE: running unprivileged — full credential persistence needs root (chown root:wheel), same constraint documented in test-enroll-credential-write.zsh. Skipping the exit-code/bearer-token/file-landing assertions that depend on it; the fresh-token-is-actually-used assertions above are the PAT-1203-relevant ones and still ran."
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "RESULT: pass=${pass} fail=${fail}"
[[ $fail -eq 0 ]]
