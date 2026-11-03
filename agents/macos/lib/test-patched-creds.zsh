#!/bin/zsh
##############################################################################
# test-patched-creds.zsh: tests for the PAT-881 safe-credential helpers
# (patched_curl_bearer, patched_hmac_hex, compute_hmac).
#
# The helpers ship INLINE inside patched-upload.sh (delimited by the
# PATCHED_CREDS_HELPERS_START/END sentinels) so that script stays self-contained
# for the release tarball, which ships it without a lib/ directory. This test
# extracts that exact block and sources it, so the code under test IS the
# shipped code, not a copy. Run:
#   zsh macos/lib/test-patched-creds.zsh
#
# What it proves:
#   1. The bearer token NEVER reaches curl's argv; it is delivered over stdin
#      as an `Authorization: Bearer` header (the ps-readable leak PAT-881 fixes).
#   2. The header still arrives at the server correctly, end-to-end against a
#      loopback HTTP server, with `ps` confirmed clean while the request is
#      in flight.
#   3. patched_hmac_hex is byte-identical to the openssl computations it
#      replaces: base64 mode matches the collector's historical compute_hmac,
#      raw mode matches `openssl dgst -sha256 -hmac "$KEY"` for empty and
#      file bodies (so no request signature changes on the wire).
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MACOS_DIR="${SCRIPT_DIR:h}"
PYTHON3="/usr/bin/python3"
CREDS_DIR=""   # set per-test where needed

# Extract the inline helper block from the shipped patched-upload.sh and source
# it, so the tests exercise the real definitions the collector runs.
UPLOAD_SH="$MACOS_DIR/patched-upload.sh"
HELPERS_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-creds-helpers.XXXXXX")
awk '/PATCHED_CREDS_HELPERS_START/{f=1;next} /PATCHED_CREDS_HELPERS_END/{f=0} f' \
    "$UPLOAD_SH" > "$HELPERS_TMP"
if [[ ! -s "$HELPERS_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_CREDS_HELPERS block from $UPLOAD_SH"
    exit 1
fi
source "$HELPERS_TMP"
rm -f "$HELPERS_TMP"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/patched-creds-test.XXXXXX")
trap 'rm -rf "$TMPROOT"; [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null' EXIT

SECRET_TOKEN="tok_SUPERSECRET_do_not_leak_9f3a"

# ───────────────────────────────────────────────────────────────────────────
echo "[1] patched_curl_bearer keeps the token OFF argv (fake curl shim)"
# Shadow curl with a zsh function that records its argv and its stdin. zsh
# resolves a function before the external command, so the helper's `curl` call
# lands here instead of /usr/bin/curl.
CAP_ARGV="$TMPROOT/argv.txt"
CAP_STDIN="$TMPROOT/stdin.txt"
curl() {
    print -r -- "$*" > "$CAP_ARGV"
    cat > "$CAP_STDIN"
}
HW_UUID="DEVICE-UUID-42"
device_hdr=()
[[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")
patched_curl_bearer "$SECRET_TOKEN" -s -o /dev/null -w "%{http_code}" \
    -X POST "http://example/v1/inventory" \
    -H "X-Patched-Signature: deadbeef" \
    "${device_hdr[@]}" \
    --data-binary "@/etc/hosts" >/dev/null
unfunction curl

argv_line=$(cat "$CAP_ARGV")
stdin_line=$(cat "$CAP_STDIN")
chk "token absent from curl argv" "$([[ "$argv_line" != *"$SECRET_TOKEN"* ]] && echo 1 || echo 0)"
chk "no literal Authorization header on argv" "$([[ "$argv_line" != *Authorization* ]] && echo 1 || echo 0)"
chk "'-H @-' present on argv (reads header from stdin)" "$([[ "$argv_line" == *"-H @-"* ]] && echo 1 || echo 0)"
chk "token delivered via stdin header" "$([[ "$stdin_line" == "Authorization: Bearer $SECRET_TOKEN" ]] && echo 1 || echo 0)"
chk "caller's other args preserved on argv" "$([[ "$argv_line" == *"X-Patched-Signature: deadbeef"* && "$argv_line" == *"--data-binary @/etc/hosts"* ]] && echo 1 || echo 0)"
chk "device-id passthrough preserved on argv" "$([[ "$argv_line" == *"X-Patched-Device-Id: DEVICE-UUID-42"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] end-to-end: header reaches the server, and ps is clean in flight"
RECV="$TMPROOT/received.json"
PORTFILE="$TMPROOT/port.txt"
# Ephemeral port (bind 0) written to a file, so nothing races a hardcoded port on
# a shared CI runner. GET /ready answers instantly (readiness probe); POST holds
# the connection open long enough for a ps snapshot to race the in-flight request.
cat > "$TMPROOT/mocksrv.py" <<PYEOF
import http.server, json, time
RECV = "$RECV"
PORTFILE = "$PORTFILE"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ready')
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(n)
        with open(RECV, 'w') as f:
            json.dump({'auth': self.headers.get('Authorization'),
                       'sig': self.headers.get('X-Patched-Signature'),
                       'len': len(body)}, f)
        time.sleep(1.2)  # hold the connection open so a ps snapshot can race it
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
with open(PORTFILE, 'w') as f:
    f.write(str(srv.server_port))
srv.serve_forever()
PYEOF
"$PYTHON3" "$TMPROOT/mocksrv.py" &
SRV_PID=$!

# Wait for the server to publish its port, then poll /ready until it accepts.
PORT=""
for _ in {1..50}; do
    [[ -s "$PORTFILE" ]] && { PORT=$(cat "$PORTFILE"); break; }
    sleep 0.1
done
ready=0
if [[ -n "$PORT" ]]; then
    for _ in {1..50}; do
        if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/ready"; then ready=1; break; fi
        sleep 0.1
    done
fi
chk "mock server came up (port $PORT)" "$ready"

BODY="$TMPROOT/body.json"
print -r -- '{"hello":"world"}' > "$BODY"

# Fire the real request in the background so we can snapshot ps mid-flight.
codefile="$TMPROOT/code.txt"
( patched_curl_bearer "$SECRET_TOKEN" -s -o /dev/null -w "%{http_code}" \
      --max-time 30 -X POST "http://127.0.0.1:$PORT/v1/inventory" \
      -H "X-Patched-Signature: cafe" --data-binary "@$BODY" > "$codefile" ) &
REQ_PID=$!
sleep 0.4
PS_SNAP=$(ps -ww -o command 2>/dev/null)
wait $REQ_PID
http_code=$(cat "$codefile" 2>/dev/null)

chk "request returned HTTP 200" "$([[ "$http_code" == "200" ]] && echo 1 || echo 0)"
recv_auth=$("$PYTHON3" -c 'import json,sys;print(json.load(open(sys.argv[1]))["auth"])' "$RECV" 2>/dev/null)
chk "server received correct Authorization: Bearer header" "$([[ "$recv_auth" == "Bearer $SECRET_TOKEN" ]] && echo 1 || echo 0)"
recv_sig=$("$PYTHON3" -c 'import json,sys;print(json.load(open(sys.argv[1]))["sig"])' "$RECV" 2>/dev/null)
chk "server received the X-Patched-Signature header" "$([[ "$recv_sig" == "cafe" ]] && echo 1 || echo 0)"
chk "token NOT visible in ps while request in flight" "$([[ "$PS_SNAP" != *"$SECRET_TOKEN"* ]] && echo 1 || echo 0)"

kill "$SRV_PID" 2>/dev/null; SRV_PID=""

# ───────────────────────────────────────────────────────────────────────────
echo "[3] patched_hmac_hex matches the openssl computations it replaces"
KEYFILE="$TMPROOT/key.raw"
print -rn -- "dGhpcy1pcy1hLXNlY3JldC1rZXk=" > "$KEYFILE"   # a raw key string
EMPTY="$TMPROOT/empty.bin"; : > "$EMPTY"
FILEBODY="$TMPROOT/payload.bin"; print -r -- "the quick brown fox" > "$FILEBODY"

# raw mode vs openssl (bootstrap's semantics), empty body
py_raw_empty=$(patched_hmac_hex "$EMPTY" "$KEYFILE" raw)
ossl_raw_empty=$(printf '' | openssl dgst -sha256 -hmac "$(cat "$KEYFILE")" -hex | awk '{print $NF}')
chk "raw-mode empty-body HMAC == openssl" "$([[ "$py_raw_empty" == "$ossl_raw_empty" ]] && echo 1 || echo 0)"

# raw mode vs openssl, file body
py_raw_file=$(patched_hmac_hex "$FILEBODY" "$KEYFILE" raw)
ossl_raw_file=$(openssl dgst -sha256 -hmac "$(cat "$KEYFILE")" -hex "$FILEBODY" | awk '{print $NF}')
chk "raw-mode file-body HMAC == openssl" "$([[ "$py_raw_file" == "$ossl_raw_file" ]] && echo 1 || echo 0)"

# base64 mode == an independent base64-decode-then-HMAC reference
py_b64=$(patched_hmac_hex "$FILEBODY" "$KEYFILE" base64)
ref_b64=$("$PYTHON3" -c 'import sys,hmac,hashlib,base64;k=base64.b64decode(open(sys.argv[1],"rb").read().strip());print(hmac.new(k,open(sys.argv[2],"rb").read(),hashlib.sha256).hexdigest())' "$KEYFILE" "$FILEBODY")
chk "base64-mode HMAC == base64-decode reference" "$([[ "$py_b64" == "$ref_b64" ]] && echo 1 || echo 0)"
chk "base64 and raw modes differ (key really decoded)" "$([[ "$py_b64" != "$py_raw_file" ]] && echo 1 || echo 0)"
chk "hex output carries no trailing newline" "$([[ ${#py_raw_file} -eq 64 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] compute_hmac wrapper resolves the base64 hmac-secret in \$CREDS_DIR (PAT-1154 v3 canonical form)"
CREDS_DIR="$TMPROOT/creds"; mkdir -p "$CREDS_DIR"
# store a base64-encoded key the way the collector's hmac-secret file is stored
"$PYTHON3" -c 'import base64;open("'"$CREDS_DIR"'/hmac-secret","wb").write(base64.b64encode(b"raw-key-bytes-123"))'
TEST_TS="1730000000"
TEST_NONCE="abc123nonce"
ch=$(compute_hmac "$FILEBODY" "inventory" "$TEST_TS" "$TEST_NONCE")
ref_ch=$("$PYTHON3" -c 'import sys,hmac,hashlib;ts,nonce=sys.argv[2],sys.argv[3];body=open(sys.argv[1],"rb").read();msg=b"patched-hmac-v3\nPOST\ninventory\n"+ts.encode("ascii")+b"\n"+nonce.encode("ascii")+b"\n"+body;print(hmac.new(b"raw-key-bytes-123",msg,hashlib.sha256).hexdigest())' "$FILEBODY" "$TEST_TS" "$TEST_NONCE")
chk "compute_hmac == HMAC(v3 canonical message, decoded hmac-secret)" "$([[ "$ch" == "$ref_ch" ]] && echo 1 || echo 0)"
ch_diff_nonce=$(compute_hmac "$FILEBODY" "inventory" "$TEST_TS" "different-nonce")
chk "compute_hmac binds nonce (different nonce -> different signature)" "$([[ "$ch" != "$ch_diff_nonce" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] regression guard: no secret-on-argv pattern anywhere in macos/*.sh or endpoint/*.sh"
# Directly enforces the PAT-881 verification: no bearer token passed to curl as
# an argv header, no HMAC key passed to openssl on argv. Scans shipping scripts
# (*.sh only, so test-*.zsh is excluded) and ignores comment lines. Fails closed if either
# pattern reappears in any collector/bootstrap/lib script.
# PAT-922 extended this from macos/-only to also cover endpoint/ (the update
# daemon), which had the identical bearer-token-on-argv pattern PAT-881 fixed
# in macos/ but was out of that ticket's fix scope.
MACOS_DIR="${SCRIPT_DIR:h}"
REPO_ROOT="${MACOS_DIR:h}"
ENDPOINT_DIR="$REPO_ROOT/endpoint"
code_hits() {  # <regex> -> non-comment matching lines under macos/ and endpoint/, *.sh only
    grep -rnE "$1" "$MACOS_DIR" "$ENDPOINT_DIR" --include='*.sh' 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*#'
}
bearer_hits=$(code_hits '\-H[[:space:]]+"?Authorization:[[:space:]]*Bearer')
openssl_hits=$(code_hits 'openssl[[:space:]].*-hmac')
[[ -n "$bearer_hits" ]] && echo "$bearer_hits"
[[ -n "$openssl_hits" ]] && echo "$openssl_hits"
chk "no '-H Authorization: Bearer' argv token in code" "$([[ -z "$bearer_hits" ]] && echo 1 || echo 0)"
chk "no 'openssl ... -hmac' key on argv in code" "$([[ -z "$openssl_hits" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo ""
echo "patched-creds tests: $pass passed, $fail failed"
(( fail == 0 )) || exit 1
