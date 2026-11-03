#!/bin/zsh
##############################################################################
# test-agent-config-suspended-reachability.zsh — PAT-1042 top-level
# regression guard.
#
# The bug this file exists to catch: an earlier version of PAT-1042 added
# the clear-on-verified-200 logic entirely inside _agent_config_commit_verified
# (endpoint/test-agent-config-commit.zsh covers that function directly and
# thoroughly), but patched-fetch-config.sh's own SUSPENDED STATE CHECK used to
# `exit 0` before ever reaching the fetch/verify/commit code when the marker
# was present. That made the whole feature inert in the field — the clear
# existed and was correctly implemented, but nothing ever called it for an
# actually-suspended device, because the script always exited three hundred-
# odd lines before ever getting there. Calling _agent_config_commit_verified
# directly (as test-agent-config-commit.zsh does) cannot catch that: it
# bypasses the exact code path that was broken.
#
# So THIS file runs the SHIPPED patched-fetch-config.sh as a real subprocess,
# suspended marker already present, against a real loopback HTTP server (same
# pattern as endpoint/test-enroll-credential-write.zsh), and checks the
# marker's actual on-disk state afterward — the only way to prove the early
# exit is really gone and the fetch really runs while suspended.
#
# Deliberately out of scope, and why:
#   - Real Ed25519 signature verification. endpoint/test-verify-agent-config.py
#     (run by .github/workflows/test-verify-agent-config.yml) already covers
#     verify-agent-config.py's signature/anti-rollback/tenant-binding checks
#     against the real pinned key; re-deriving a valid signature here would
#     need the private key half, which does not live in this repo (only on
#     patched-api-01 — see verify-agent-config.py's own header comment).
#     PATCHED_BUNDLE_DIR here points at a scratch dir containing a STUB
#     verify-agent-config.py with the real verifier's config-path CLI
#     contract (including the last-accepted config and denial floor) that treats
#     "response JSON has an integer config_version" as its whole bar — the
#     same boundary test-agent-config-commit.zsh's own header already draws
#     around the real verifier subprocess.
#   - Root-owned ownership/mode enforcement on $CREDS_DIR/suspended
#     (root:wheel/0600, set by the 401 handler via `install -d -o root -g
#     wheel` + `chown root:wheel`). Run unprivileged, those calls fail with
#     EPERM but — no `set -e` in patched-fetch-config.sh — do not abort the
#     script; the marker file itself still ends up written/touched. Same
#     documented limitation as test-agent-config-commit.zsh's file header and
#     test-enroll-credential-write.zsh's whole premise.
#
# Run: zsh endpoint/test-agent-config-suspended-reachability.zsh
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-fetch-config.sh"
PYTHON3="/usr/bin/python3"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-suspended-reach-test.XXXXXX")
server_pid=""
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

BUNDLE_DIR="$WORK/bundle"
STATE_DIR="$WORK/state"
CREDS_DIR="$WORK/creds"
LOG_FILE="$WORK/patched-update.log"
JSONL_LOG_DIR="$WORK/jsonl-logs"
mkdir -p "$BUNDLE_DIR" "$STATE_DIR" "$CREDS_DIR" "$JSONL_LOG_DIR"

# ---------------------------------------------------------------------------
# Stub verifier — see the file header above for why this is a stub and not
# the real endpoint/verify-agent-config.py.
# ---------------------------------------------------------------------------
cat > "$BUNDLE_DIR/verify-agent-config.py" <<'PYEOF'
#!/usr/bin/env python3
import argparse, json, sys

ap = argparse.ArgumentParser()
ap.add_argument("--response-file", required=True)
ap.add_argument("--version-file", required=True)
ap.add_argument("--current-config-file")
ap.add_argument("--current-config-sha256-file")
ap.add_argument("--execution-denial-file")
ap.add_argument("--output-file", required=True)
ap.add_argument("--execution-denial-output-file")
args = ap.parse_args()

try:
    with open(args.response_file) as f:
        body = json.load(f)
except Exception as exc:
    print(f"stub-verifier: could not parse response JSON: {exc}", file=sys.stderr)
    sys.exit(1)

if not isinstance(body.get("config_version"), int):
    print("stub-verifier: rejected — no integer config_version", file=sys.stderr)
    sys.exit(1)

with open(args.output_file, "w") as f:
    json.dump(body, f)
sys.exit(0)
PYEOF
chmod +x "$BUNDLE_DIR/verify-agent-config.py"
# PAT-1763: the real shared floor parser, not a stub. The If-None-Match choice
# and the decommission gate both read the floor through it.
cp "$SCRIPT_DIR/agent_config_floor.py" "$BUNDLE_DIR/agent_config_floor.py"
# No patched-proxy-resolve.py in BUNDLE_DIR: PROXY_RESOLVE stays non-executable,
# so with_proxy() falls back to direct mode — no proxy stub needed.

# ---------------------------------------------------------------------------
# Credentials: an already-enrolled, already-suspended device. bearer-token
# present (so the ENROLLMENT block no-ops and falls straight through to the
# fetch) and the suspended marker already present (the precondition this
# whole file exists to test).
# ---------------------------------------------------------------------------
seed_creds() {
    rm -f "$CREDS_DIR/suspended" "$CREDS_DIR/enrollment-token"
    printf '11111111-1111-1111-1111-111111111111\n' > "$CREDS_DIR/tenant-id"
    printf 'test-bearer-token\n' > "$CREDS_DIR/bearer-token"
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$CREDS_DIR/hmac-secret"
    : > "$CREDS_DIR/suspended"
}

# reset_state_dir: STATE_DIR is shared across the two [1]/[2] sub-tests below
# (deliberately, matching production where the same STATE_DIR persists across
# polls) — so clear its committed artifacts between sub-tests, or [2]'s "no
# config was committed" assertion would trivially fail on [1]'s leftover file.
reset_state_dir() {
    rm -rf "$STATE_DIR"
    mkdir -p "$STATE_DIR"
}

# start_stub_server <http_status_code> <body_json>
#   Serves exactly one GET /v1/agent-config with the given status + body, then
#   exits. Sets the GLOBAL $server_pid and $STUB_PORT — deliberately NOT
#   invoked via command substitution ($(...)): zsh reaps a subshell's
#   background jobs when the subshell exits, so `port=$(start_stub_server
#   ...)` would kill the python server the instant this function returns,
#   before run_fetch_config ever got a chance to connect to it (confirmed by
#   hand — that was this test's first, silent failure mode: every request
#   came back "HTTP 000", i.e. connection refused, because the server was
#   already dead). Called as a plain statement instead, so both globals are
#   set directly in the top-level script's own shell, and the background job
#   survives.
#
# AGENTS.md zsh footgun: `status` is a read-only special (tied to $?) — a
# `local status=...` here would throw "read-only variable: status" and abort
# this function on that very line, silently. Named http_status instead.
start_stub_server() {
    local http_status="$1" body="$2"
    local port_file
    port_file=$(mktemp "${TMPDIR:-/tmp}/.test-fetchconfig-port.XXXXXX")
    STUB_STATUS="$http_status" STUB_BODY="$body" "$PYTHON3" - "$port_file" <<'PYEOF' &
import http.server, os, sys

status = int(os.environ["STUB_STATUS"])
body   = os.environ["STUB_BODY"].encode()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_port))
srv.timeout = 30
srv.handle_request()
PYEOF
    server_pid=$!

    STUB_PORT=""
    local _i
    for _i in $(seq 1 50); do
        if [[ -s "$port_file" ]]; then
            STUB_PORT=$(cat "$port_file")
            break
        fi
        sleep 0.1
    done
    rm -f "$port_file"
}

# start_conditional_stub_server <body_json> <seen-inm-file>
#   Serves exactly one GET /v1/agent-config, then exits. Models a server
#   whose CONTENT genuinely has not changed (the realistic reinstatement
#   case — revocation is a per-device auth flag, not a config-content
#   change): responds 304 if the request carries If-None-Match, or 200 with
#   <body_json> if it does not. Records "yes"/"no" into <seen-inm-file> so
#   the test can assert whether the validator was actually sent, not just
#   infer it from the response code. Same globals/subshell caveat as
#   start_stub_server above (see its own comment) — deliberately not
#   invoked via command substitution.
start_conditional_stub_server() {
    local body="$1" seen_file="$2"
    local port_file
    port_file=$(mktemp "${TMPDIR:-/tmp}/.test-fetchconfig-port.XXXXXX")
    STUB_BODY="$body" STUB_SEEN_FILE="$seen_file" "$PYTHON3" - "$port_file" <<'PYEOF' &
import http.server, os, sys

body      = os.environ["STUB_BODY"].encode()
seen_file = os.environ["STUB_SEEN_FILE"]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        got_inm = any(k.lower() == "if-none-match" for k in self.headers.keys())
        with open(seen_file, "w") as f:
            f.write("yes" if got_inm else "no")
        if got_inm:
            # Realistic 304: server's content genuinely didn't change.
            self.send_response(304)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_port))
srv.timeout = 30
srv.handle_request()
PYEOF
    server_pid=$!

    STUB_PORT=""
    local _i
    for _i in $(seq 1 50); do
        if [[ -s "$port_file" ]]; then
            STUB_PORT=$(cat "$port_file")
            break
        fi
        sleep 0.1
    done
    rm -f "$port_file"
}

run_fetch_config() {
    PATCHED_BUNDLE_DIR="$BUNDLE_DIR" \
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_API_URL="$API_URL" \
    PATCHED_LOG_FILE="$LOG_FILE" \
    PATCHED_JSONL_LOG_DIR="$JSONL_LOG_DIR" \
        zsh "$TARGET"
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] marker present + signature-verified 200: the fetch actually runs (not skipped), the marker is cleared, config is committed — this is the exact case the inert-feature bug broke"
seed_creds
reset_state_dir
: > "$LOG_FILE"
start_stub_server 200 '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":1}'
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "the log shows the script actually attempted the probe fetch (proves the early exit is gone)" \
    "$(grep -qi 'probing for reinstatement' "$LOG_FILE" && echo 1 || echo 0)"
chk "the suspended marker is GONE after a verified 200 — this is the bug: it used to survive forever" \
    "$([[ ! -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "a reinstatement line is logged" "$(grep -qi 'marker cleared' "$LOG_FILE" && echo 1 || echo 0)"
chk "the verified config was actually committed to disk" \
    "$([[ -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"
chk "the committed config's config_version is 1" \
    "$(grep -q '\"config_version\": 1' "$STATE_DIR/agent-config.json" 2>/dev/null && echo 1 || echo 0)"
chk "the heartbeat was stamped (device is back to normal enforcement-gate state)" \
    "$([[ -f "$STATE_DIR/agent-config.checked" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] marker present + 401: the fetch runs (probe still happens) but the marker stays — still suspended"
seed_creds
reset_state_dir
: > "$LOG_FILE"
start_stub_server 401 '{}'
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "the log shows the probe fetch was attempted (not early-exited)" \
    "$(grep -qi 'probing for reinstatement' "$LOG_FILE" && echo 1 || echo 0)"
chk "the log shows the 401 handler re-affirmed the suspended state" \
    "$(grep -q 'PATCHED_AUTH_REJECTED' "$LOG_FILE" && echo 1 || echo 0)"
chk "the 401 is not logged as a revocation (PAT-1745)" \
    "$(! grep -q 'PATCHED_DEVICE_REVOKED' "$LOG_FILE" && echo 1 || echo 0)"
chk "the suspended marker is STILL PRESENT — a 401 must never clear it" \
    "$([[ -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "no reinstatement line is logged" "$(! grep -qi 'marker cleared' "$LOG_FILE" && echo 1 || echo 0)"
chk "no config was committed" "$([[ ! -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1745: the server returns the same bare 401 for every authentication
# failure (expired or unknown credential, revoked tenant or device, clock
# skew, nonce replay, secret mismatch) and never says which. A healthy device
# that gets one must still suspend, exactly as before, but the log must say
# what is actually known instead of asserting a revocation.
echo "[2b] marker ABSENT + 401: the device suspends, and the log reports an undisclosed auth rejection with its possible causes, not a revocation"
seed_creds
rm -f "$CREDS_DIR/suspended"
reset_state_dir
: > "$LOG_FILE"
rm -rf "$JSONL_LOG_DIR"; mkdir -p "$JSONL_LOG_DIR"
start_stub_server 401 'unauthorized'
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "precondition: the device was not suspended, so no reinstatement probe ran" \
    "$(! grep -qi 'probing for reinstatement' "$LOG_FILE" && echo 1 || echo 0)"
chk "suspend-on-401 unchanged: the suspended marker is written" \
    "$([[ -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "the log line leads with PATCHED_AUTH_REJECTED" \
    "$(grep -q '^PATCHED_AUTH_REJECTED: /v1/agent-config returned HTTP 401\. The server does not disclose the reason\.' "$LOG_FILE" && echo 1 || echo 0)"
for _cause in 'credential expired or unknown' 'tenant or device revoked' 'clock skew outside the replay window' 'nonce replay' 'bearer token and HMAC secret mismatch'; do
    chk "the log line lists the possible cause: $_cause" \
        "$(grep -F 'PATCHED_AUTH_REJECTED' "$LOG_FILE" | grep -qF "$_cause" && echo 1 || echo 0)"
done
chk "nothing asserts a revocation: no PATCHED_DEVICE_REVOKED in the text log" \
    "$(! grep -q 'PATCHED_DEVICE_REVOKED' "$LOG_FILE" && echo 1 || echo 0)"
chk "nothing asserts a revocation: no PATCHED_DEVICE_REVOKED in the JSONL log" \
    "$(! grep -rq 'PATCHED_DEVICE_REVOKED' "$JSONL_LOG_DIR" && echo 1 || echo 0)"
chk "the JSONL record carries event=PATCHED_AUTH_REJECTED and http_code=401" \
    "$(grep -rh 'authentication rejected by server' "$JSONL_LOG_DIR" 2>/dev/null | "$PYTHON3" -c '
import json, sys
ok = False
for line in sys.stdin:
    rec = json.loads(line)
    blob = json.dumps(rec)
    if "PATCHED_AUTH_REJECTED" in blob and "401" in blob:
        ok = True
print(1 if ok else 0)
' 2>/dev/null || echo 0)"
chk "no config was committed" "$([[ ! -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1042 P1 (non-author review, round 3): the realistic reinstatement case
# is an admin re-permitting a DEVICE, which does not change the TENANT's
# agent-config CONTENT at all — so a reinstated device sending the normal
# conditional GET would get 304 Not Modified forever (content genuinely
# unchanged), and _agent_config_handle_304 never touches
# $CREDS_DIR/suspended. That is a second, independent way for the marker to
# survive forever, on top of the original inert-feature bug [1]/[2] above
# already guard against. This is the case that would have caught it: a
# server that answers 304 to ANY conditional GET (content genuinely hasn't
# changed) but 200 when no If-None-Match is sent — modeling exactly the
# post-reinstatement reality — plus a prior AGENT_CONFIG_VERSION_FILE on
# disk so the conditional GET would have fired in the first place if not
# suppressed.
echo "[3] marker present + prior version on disk + server would 304 any conditional GET: probe omits If-None-Match, gets a verifiable 200 instead, and clears — the P1 this round exists to fix"
seed_creds
reset_state_dir
: > "$LOG_FILE"
printf '{"tenant_id":"11111111-1111-1111-1111-111111111111","config_version":7}' > "$STATE_DIR/agent-config.version"
seen_inm_file="$WORK/seen-inm-3"
start_conditional_stub_server '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":7}' "$seen_inm_file"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "the probe did NOT send If-None-Match while suspended (the P1 fix)" \
    "$([[ "$(cat "$seen_inm_file" 2>/dev/null)" == "no" ]] && echo 1 || echo 0)"
chk "the log names the suppression explicitly" \
    "$(grep -qi 'suppressing If-None-Match' "$LOG_FILE" && echo 1 || echo 0)"
chk "the server answered with a full 200 (not 304), because the validator was omitted" \
    "$([[ -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"
chk "the suspended marker is GONE — reinstatement now completes even though config content never changed" \
    "$([[ ! -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "a reinstatement line is logged" "$(grep -qi 'marker cleared' "$LOG_FILE" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] marker ABSENT + same prior version on disk + same content-unchanged server: the normal path still sends If-None-Match and gets 304 — no bandwidth regression for the common healthy-device case"
seed_creds
rm -f "$CREDS_DIR/suspended"
reset_state_dir
: > "$LOG_FILE"
printf '{"tenant_id":"11111111-1111-1111-1111-111111111111","config_version":7}' > "$STATE_DIR/agent-config.version"
seen_inm_file="$WORK/seen-inm-4"
start_conditional_stub_server '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":7}' "$seen_inm_file"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "the log does NOT show the suspended-probe line (device isn't suspended)" \
    "$(! grep -qi 'probing for reinstatement' "$LOG_FILE" && echo 1 || echo 0)"
chk "the non-suspended path DID send If-None-Match (no suppression, no bandwidth regression)" \
    "$([[ "$(cat "$seen_inm_file" 2>/dev/null)" == "yes" ]] && echo 1 || echo 0)"
chk "the server answered 304 (content unchanged) and the existing 304 path ran, not a commit" \
    "$([[ ! -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1756: If-None-Match comes only from a floor that applies to the enrolled
# tenant. A floor keyed to another tenant (a device re-enrolled elsewhere) must
# not be sent: its version could equal this tenant's current version and draw
# a 304 that keeps the old tenant's config.
echo "[5] marker ABSENT + floor keyed to ANOTHER tenant + content-unchanged server: no If-None-Match, full 200 committed, floor re-keyed to the enrolled tenant"
seed_creds
rm -f "$CREDS_DIR/suspended"
reset_state_dir
: > "$LOG_FILE"
printf '{"tenant_id":"22222222-2222-2222-2222-222222222222","config_version":7}' > "$STATE_DIR/agent-config.version"
seen_inm_file="$WORK/seen-inm-5"
start_conditional_stub_server '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":3}' "$seen_inm_file"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "no If-None-Match was sent for another tenant's floor" \
    "$([[ "$(cat "$seen_inm_file" 2>/dev/null)" == "no" ]] && echo 1 || echo 0)"
chk "the log says the floor belongs to another tenant" \
    "$(grep -q 'anti-rollback floor belongs to another tenant' "$LOG_FILE" && echo 1 || echo 0)"
chk "the config for the enrolled tenant was committed" \
    "$([[ -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"
chk "the floor is re-keyed to the enrolled tenant at version 3" \
    "$([[ "$(cat "$STATE_DIR/agent-config.version" 2>/dev/null)" == '{"tenant_id":"11111111-1111-1111-1111-111111111111","config_version":3}' ]] && echo 1 || echo 0)"

echo "[6] marker ABSENT + floor keyed to THIS tenant: If-None-Match is sent and the 304 path runs"
seed_creds
rm -f "$CREDS_DIR/suspended"
reset_state_dir
: > "$LOG_FILE"
printf '{"tenant_id":"11111111-1111-1111-1111-111111111111","config_version":7}' > "$STATE_DIR/agent-config.version"
seen_inm_file="$WORK/seen-inm-6"
start_conditional_stub_server '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":7}' "$seen_inm_file"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "If-None-Match was sent for this tenant's keyed floor" \
    "$([[ "$(cat "$seen_inm_file" 2>/dev/null)" == "yes" ]] && echo 1 || echo 0)"
chk "the 304 path ran, not a commit" "$([[ ! -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"

echo "[7] marker ABSENT + corrupt floor: no If-None-Match, and the unusable floor is logged"
seed_creds
rm -f "$CREDS_DIR/suspended"
reset_state_dir
: > "$LOG_FILE"
printf 'not-a-floor' > "$STATE_DIR/agent-config.version"
seen_inm_file="$WORK/seen-inm-7"
start_conditional_stub_server '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":7}' "$seen_inm_file"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "no If-None-Match was sent for a corrupt floor" \
    "$([[ "$(cat "$seen_inm_file" 2>/dev/null)" == "no" ]] && echo 1 || echo 0)"
chk "the log names the unusable floor" \
    "$(grep -q 'anti-rollback floor at .* is unusable' "$LOG_FILE" && echo 1 || echo 0)"

echo "[8] marker ABSENT + legacy bare-integer floor + content-unchanged server: no If-None-Match (the floor has no tenant), full 200 committed, floor re-keyed"
seed_creds
rm -f "$CREDS_DIR/suspended"
reset_state_dir
: > "$LOG_FILE"
printf '7' > "$STATE_DIR/agent-config.version"
seen_inm_file="$WORK/seen-inm-8"
start_conditional_stub_server '{"tenant_id":"11111111-1111-1111-1111-111111111111","tier":"standard","config_version":7}' "$seen_inm_file"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

chk "patched-fetch-config.sh exits 0" "$([[ "$rc" == "0" ]] && echo 1 || echo 0)"
chk "no If-None-Match was sent for a legacy floor" \
    "$([[ "$(cat "$seen_inm_file" 2>/dev/null)" == "no" ]] && echo 1 || echo 0)"
chk "the log names the legacy floor" \
    "$(grep -q 'anti-rollback floor is in the legacy format' "$LOG_FILE" && echo 1 || echo 0)"
chk "the full 200 was committed" "$([[ -f "$STATE_DIR/agent-config.json" ]] && echo 1 || echo 0)"
chk "the floor is re-keyed to the enrolled tenant" \
    "$([[ "$(cat "$STATE_DIR/agent-config.version" 2>/dev/null)" == '{"tenant_id":"11111111-1111-1111-1111-111111111111","config_version":7}' ]] && echo 1 || echo 0)"

# A heartbeat-write failure on an otherwise-verified commit is covered at the
# function level in endpoint/test-agent-config-commit.zsh (needs a shadowed
# `mv` to force just that one sub-step to fail, which is only practical
# against the extracted _agent_config_commit_verified function, not a full
# subprocess run of the shipped script).

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
