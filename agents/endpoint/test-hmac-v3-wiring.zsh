#!/bin/zsh
##############################################################################
# test-hmac-v3-wiring.zsh: PAT-1155 signed==sent wiring test.
#
# endpoint/test-hmac-v3.zsh proves each shipped v3 SIGNER reproduces the two
# authoritative test vectors in isolation. It does NOT prove that a real
# caller puts the exact same TS/NONCE values into the X-Patched-Timestamp /
# X-Patched-Nonce HTTP headers that were fed into the signature it computed
# — a future edit could change what's signed without changing what's sent
# (or vice versa) and every vector test would still pass, silently breaking
# the "signed == sent" property this scheme depends on.
#
# This file runs the SHIPPED endpoint/patched-fetch-config.sh (the
# representative real caller, per the ticket) as a real subprocess against a
# real loopback HTTP server (same run-the-real-script pattern as
# endpoint/test-agent-config-suspended-reachability.zsh). The server:
#   1. Captures the X-Patched-Timestamp / X-Patched-Nonce / X-Patched-Signature
#      header values from the ACTUAL request the script sent.
#   2. Independently recomputes the v3 HMAC over those captured TS/NONCE
#      values, using the same known test secret seeded into $CREDS_DIR, and
#      the canonical signing_input shape:
#        patched-hmac-v3\nGET\nagent_config\n<TS>\n<NONCE>\n
#   3. Asserts the recomputed signature equals the X-Patched-Signature
#      header that was actually sent.
#
# Why step 3 proves "signed == sent" rather than just re-testing the signer:
# the recompute uses ONLY the header-carried TS/NONCE, never any value the
# script held internally. If a future edit made the script sign one
# TS/NONCE pair but emit a DIFFERENT pair in the headers (the exact wiring
# bug this ticket exists to catch), the recomputed signature would no
# longer match the received X-Patched-Signature, and this test would fail —
# even though every vector in test-hmac-v3.zsh would still pass, since that
# file never looks at what lands in an HTTP header at all.
#
# [2] is a negative control proving the mock's comparator actually can fail
# (not vacuously true): it sends a hand-crafted request where the signed
# nonce and the header nonce deliberately differ, and asserts the server
# detects the mismatch.
#
# Deliberately out of scope, same boundary as test-agent-config-suspended-
# reachability.zsh: real Ed25519 response verification, and root-owned
# marker file permissions. Not exercised here since every request in this
# file gets a 304 (or, in [2], a raw unauthenticated tamper probe) — no
# config body is ever committed.
#
# Run: zsh endpoint/test-hmac-v3-wiring.zsh
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.hmac-v3-wiring-test.XXXXXX")
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

# Known test secret, same convention as test-hmac-v3.zsh: hmac-secret file
# stores base64(SECRET_ASCII) — matches patched-fetch-config.sh's inline GET
# signer, which base64-decodes the credential file before use.
SECRET_ASCII="patched-wiring-test-secret"
SECRET_B64=$("$PYTHON3" -c 'import base64,sys; sys.stdout.write(base64.b64encode(sys.argv[1].encode("ascii")).decode())' "$SECRET_ASCII")

seed_creds() {
    rm -f "$CREDS_DIR/suspended" "$CREDS_DIR/enrollment-token"
    printf '11111111-1111-1111-1111-111111111111\n' > "$CREDS_DIR/tenant-id"
    printf 'test-bearer-token\n' > "$CREDS_DIR/bearer-token"
    printf '%s\n' "$SECRET_B64" > "$CREDS_DIR/hmac-secret"
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

# start_capturing_stub_server <result-file>
#   Serves exactly one GET /v1/agent-config: captures the request's
#   X-Patched-Timestamp / X-Patched-Nonce / X-Patched-Signature headers,
#   independently recomputes the v3 HMAC over the CAPTURED TS/NONCE (never
#   any value known only to the script's own process) using the known
#   SECRET_ASCII test secret, and writes a JSON verdict to <result-file>.
#   Always responds 304 so the script exits cleanly with nothing committed.
#   Same globals/subshell caveat as endpoint/test-agent-config-suspended-
#   reachability.zsh's start_stub_server (not invoked via command
#   substitution, or zsh reaps the background server before the client ever
#   connects) — see that file's comment for the full explanation.
start_capturing_stub_server() {
    local result_file="$1"
    local port_file
    port_file=$(mktemp "${TMPDIR:-/tmp}/.test-hmac-wiring-port.XXXXXX")
    HMAC_SECRET_ASCII="$SECRET_ASCII" RESULT_FILE="$result_file" "$PYTHON3" - "$port_file" <<'PYEOF' &
import hashlib, hmac, http.server, json, os, sys

secret = os.environ["HMAC_SECRET_ASCII"].encode("ascii")
result_file = os.environ["RESULT_FILE"]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        ts = self.headers.get("X-Patched-Timestamp", "")
        nonce = self.headers.get("X-Patched-Nonce", "")
        sig_received = self.headers.get("X-Patched-Signature", "")

        # Canonical v3 signing_input for a GET /v1/agent-config request
        # (empty body), built ONLY from what the mock server actually
        # received in the request headers — never from anything the caller
        # process held internally.
        msg = b"patched-hmac-v3\nGET\nagent_config\n" + ts.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n"
        sig_recomputed = hmac.new(secret, msg, hashlib.sha256).hexdigest()

        with open(result_file, "w") as f:
            json.dump({
                "ts": ts,
                "nonce": nonce,
                "sig_received": sig_received,
                "sig_recomputed": sig_recomputed,
                "match": sig_recomputed == sig_received,
            }, f)

        self.send_response(304)
        self.end_headers()

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

# ───────────────────────────────────────────────────────────────────────────
echo "[1] real caller (patched-fetch-config.sh) end to end: captured X-Patched-Timestamp/Nonce headers, recomputed server-side over the known test secret, reproduce the exact X-Patched-Signature header the script actually sent"
seed_creds
: > "$LOG_FILE"
RESULT_FILE="$WORK/result-1.json"
start_capturing_stub_server "$RESULT_FILE"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
API_URL="http://127.0.0.1:${STUB_PORT}"
run_fetch_config
rc=$?
wait "$server_pid" 2>/dev/null
server_pid=""

# Informational only, not asserted: the real proof the request happened
# (and thus that this test measured anything) is the result file below,
# which the stub server writes only after receiving and parsing the
# headers it needs. Asserting rc==0 here would make an unrelated exit-path
# bug in patched-fetch-config.sh (auth parsing, a commit-path error, etc.)
# fail this suite on the wrong signal — the property under test is
# signed-headers-match-sent-headers, not "the script's overall exit code",
# and a caller-side failure downstream of the HTTP call shouldn't mask a
# clean pass on the wiring property this file exists to prove.
echo "  (info) patched-fetch-config.sh exit code: $rc"
chk "result file was written (request was actually received)" "$([[ -s "$RESULT_FILE" ]] && echo 1 || echo 0)"

CAPTURED_TS=$("$PYTHON3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ts",""))' "$RESULT_FILE" 2>/dev/null)
CAPTURED_NONCE=$("$PYTHON3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("nonce",""))' "$RESULT_FILE" 2>/dev/null)
CAPTURED_SIG=$("$PYTHON3" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sig_received",""))' "$RESULT_FILE" 2>/dev/null)
CAPTURED_MATCH=$("$PYTHON3" -c 'import json,sys; print("1" if json.load(open(sys.argv[1])).get("match") else "0")' "$RESULT_FILE" 2>/dev/null)

chk "X-Patched-Timestamp header was sent and non-empty" "$([[ -n "$CAPTURED_TS" ]] && echo 1 || echo 0)"
chk "X-Patched-Nonce header was sent and non-empty" "$([[ -n "$CAPTURED_NONCE" ]] && echo 1 || echo 0)"
chk "X-Patched-Signature header was sent and non-empty" "$([[ -n "$CAPTURED_SIG" ]] && echo 1 || echo 0)"
# Sanity that the header really is a fresh unix timestamp, not e.g. an empty
# string coincidentally producing SOME hash — bounds it to within 5 minutes
# of "now" as measured on this machine.
NOW_TS=$(date -u +%s)
chk "X-Patched-Timestamp looks like a genuine current unix timestamp (within 300s of now)" \
    "$([[ "$CAPTURED_TS" =~ ^[0-9]+$ ]] && (( NOW_TS - CAPTURED_TS > -300 && NOW_TS - CAPTURED_TS < 300 )) && echo 1 || echo 0)"
chk "recomputing the v3 HMAC over the CAPTURED header TS/NONCE (known test secret) reproduces the CAPTURED X-Patched-Signature header exactly — proves signed == sent" \
    "$CAPTURED_MATCH"

# ───────────────────────────────────────────────────────────────────────────
# Negative control: proves the comparator above isn't vacuously true. Sends a
# hand-crafted request (not via patched-fetch-config.sh) where the signature
# is computed over one nonce but a DIFFERENT nonce is placed in the
# X-Patched-Nonce header — modeling exactly the wiring bug this ticket
# exists to catch (sign one value, send another). The mock's own recompute
# must flag this as a mismatch, or the positive check above would be
# worthless.
echo "[2] negative control: a hand-crafted request where the signed nonce and the header nonce deliberately differ is correctly detected as a mismatch"
RESULT_FILE2="$WORK/result-2.json"
start_capturing_stub_server "$RESULT_FILE2"
chk "stub server started" "$([[ -n "$STUB_PORT" ]] && echo 1 || echo 0)"
TAMPER_PORT="$STUB_PORT"

"$PYTHON3" - "$TAMPER_PORT" "$SECRET_ASCII" <<'PYEOF'
import hashlib, hmac, http.client, sys

port, secret_ascii = sys.argv[1], sys.argv[2]
secret = secret_ascii.encode("ascii")
ts = "1730000000"
signed_nonce = "nonce-that-was-signed"
sent_nonce = "DIFFERENT-nonce-actually-sent"

msg = b"patched-hmac-v3\nGET\nagent_config\n" + ts.encode("ascii") + b"\n" + signed_nonce.encode("ascii") + b"\n"
sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()

conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=10)
conn.request("GET", "/v1/agent-config", headers={
    "X-Patched-Timestamp": ts,
    "X-Patched-Nonce": sent_nonce,   # deliberately NOT signed_nonce
    "X-Patched-Signature": sig,
})
conn.getresponse().read()
conn.close()
PYEOF
wait "$server_pid" 2>/dev/null
server_pid=""

chk "tamper-probe result file was written" "$([[ -s "$RESULT_FILE2" ]] && echo 1 || echo 0)"
TAMPER_MATCH=$("$PYTHON3" -c 'import json,sys; print("1" if json.load(open(sys.argv[1])).get("match") else "0")' "$RESULT_FILE2" 2>/dev/null)
chk "the mismatch (signed nonce != sent nonce) is correctly detected — proves the check in [1] is not vacuously true" \
    "$([[ "$TAMPER_MATCH" == "0" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
