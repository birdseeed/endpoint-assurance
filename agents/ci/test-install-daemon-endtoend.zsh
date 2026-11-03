#!/bin/zsh --no-rcs
# End-to-end smoke test for patched-install.sh (PAT-661).
#
# Exercises the actual daemon script with stubbed dependencies so that runtime
# errors (e.g. `local` used outside a function, unset variables under set -u)
# fail CI — things `zsh -n` cannot catch.
#
# Coverage:
#   1. Tier gate: assurance tier exits 0 before touching the API.
#   2. Failed API fetch (network unreachable) exits 0 (fail-safe).
#   3. Empty pending-installs queue exits 0 cleanly.
#   4. Pending install with package_source=winget on macOS is skipped
#      (winget is Windows-only; no Installomator call made).
#   5. Pending install with package_source=vendor dispatches the Installomator
#      label; outcomes reported to the agent-logs stub.
#
# Usage: zsh ci/test-install-daemon-endtoend.zsh
# Exit 0 if all checks pass.

set -u
PASS=0
FAIL=0
DAEMON="${0:a:h}/../endpoint/patched-install.sh"

if [[ ! -f "$DAEMON" ]]; then
    print "ERROR: patched-install.sh not found at $DAEMON" >&2; exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

assert_pass() {
    local desc="$1"
    if [[ $2 -eq 0 ]]; then
        print "  PASS  [$desc]"
        (( PASS++ ))
    else
        print "  FAIL  [$desc] (exit $2)"
        (( FAIL++ ))
    fi
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        print "  PASS  [$desc]"
        (( PASS++ ))
    else
        print "  FAIL  [$desc]"
        print "        expected: $expected"
        print "        got:      $actual"
        (( FAIL++ ))
    fi
}

assert_file_not_exists() {
    local desc="$1" filepath="$2"
    if [[ ! -f "$filepath" ]]; then
        print "  PASS  [$desc]"
        (( PASS++ ))
    else
        print "  FAIL  [$desc] (file unexpectedly exists: $filepath)"
        (( FAIL++ ))
    fi
}

# ── Common fixture setup ──────────────────────────────────────────────────────

setup_fixture() {
    local tmpdir
    tmpdir=$(mktemp -d)

    local bundle_dir="$tmpdir/bundle"
    local state_dir="$tmpdir/state"
    local creds_dir="$tmpdir/creds"
    mkdir -p "$bundle_dir" "$state_dir" "$creds_dir"

    # Empty manifest — verify_bundle passes with nothing to check.
    echo "# empty manifest for test" > "$bundle_dir/manifest.sha256"

    # PAT-1481: patched-install.sh refuses to run the pending-install dispatch
    # loop at all unless legacy_app_execution_enabled() finds a manifest-covered
    # patched-legacy-app-execution-gate.py in the bundle. Stub it as an
    # always-allow script (same pattern as the Installomator.sh stub below) and
    # cover it in the manifest so the shell-side check passes. The gate script's
    # own security properties (root ownership, heartbeat freshness, revocation,
    # duplicate-key rejection) are independently covered by
    # endpoint/test-legacy-app-execution-gate.zsh via importlib monkeypatching;
    # this end-to-end test only needs patched-install.sh to call and obey it.
    cat > "$bundle_dir/patched-legacy-app-execution-gate.py" <<'GATESTUB'
#!/usr/bin/env python3
import sys
sys.exit(0)
GATESTUB
    local _gate_hash
    _gate_hash=$(shasum -a 256 "$bundle_dir/patched-legacy-app-execution-gate.py" | awk '{print $1}')
    echo "$_gate_hash patched-legacy-app-execution-gate.py" >> "$bundle_dir/manifest.sha256"
    # PAT-1773: the gate loads agent_config_tenant.py from the bundle, so the
    # caller requires that module's manifest coverage too, and the tier read
    # runs it to check the cached config belongs to the enrolled tenant.
    cp "${DAEMON:h}/agent_config_tenant.py" "$bundle_dir/agent_config_tenant.py"
    echo "$(shasum -a 256 "$bundle_dir/agent_config_tenant.py" | awk '{print $1}') agent_config_tenant.py" >> "$bundle_dir/manifest.sha256"

    # PAT-66 fix: bundle-pinned allowlist. The allowlist gate in patched-install.sh
    # requires vendor labels to be present here before Installomator dispatch.
    # Mirrors labels-allowlist.txt format: label<TAB>name<TAB>team_id<TAB>app_path<TAB>method<TAB>mirror_url<TAB>pinned_sha256
    # Two test labels used by Tests 5, 6, 7 are pre-populated; Test 8 uses a label
    # deliberately absent from this file to exercise the fail-closed gate.
    /usr/bin/python3 -c "
rows = [
    ('patchedtestlabel9999',  'Patched Test App 9999',          'AAAAAAAAAA', '/Applications/PatchedTestApplication9999.app',   'static', '', ''),
    ('patchednolabelpkg9999', 'Patched No Label Sentinel 9999',  'BBBBBBBBBB', '/Applications/PatchedNoLabelSentinelApp9999.app', 'static', '', ''),
]
with open('$bundle_dir/labels-allowlist.txt', 'w') as f:
    f.write('# labels-allowlist.txt — test fixture\n')
    for r in rows:
        f.write('\t'.join(r) + '\n')
"

    # Stub credentials.
    echo "test-tenant-id" > "$creds_dir/tenant-id"
    echo "test-bearer-token" > "$creds_dir/bearer-token"
    /usr/bin/python3 -c "import base64; print(base64.b64encode(b'test-secret-12345678').decode())" \
        > "$creds_dir/hmac-secret"

    # Agent config at assurance (tier 1) by default.
    /usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'assurance'}))" \
        > "$state_dir/agent-config.json"

    # PAT-2245: plant a fresh-looking catalogue.json with valid pins for both
    # test labels. The signed app catalogue is retired, so the daemon must
    # never read it: a leftover cache whose clean-up failed must not let the
    # quarantined install path act (Test 5).
    /usr/bin/python3 -c "
import json
print(json.dumps({'labels': {
    'patchedtestlabel9999':  {'sha256': 'a' * 64},
    'patchednolabelpkg9999': {'sha256': 'b' * 64},
}}))
" > "$state_dir/catalogue.json"

    echo "$tmpdir"
}

# Runs the daemon with overridden env vars. PATH is first argument.
run_daemon() {
    local tmpdir="$1" extra_path="${2:-}"
    local bundle_dir="$tmpdir/bundle"
    local state_dir="$tmpdir/state"
    local creds_dir="$tmpdir/creds"
    local log_file="$tmpdir/install.log"
    local effective_path="${extra_path:+${extra_path}:}${PATH}"

    PATCHED_BUNDLE_DIR="$bundle_dir" \
    PATCHED_STATE_DIR="$state_dir" \
    PATCHED_CREDS_DIR="$creds_dir" \
    PATCHED_LOG_FILE="$log_file" \
    PATCHED_API_URL="http://localhost:0" \
    PATH="$effective_path" \
    zsh "$DAEMON" >/dev/null 2>&1
}

# ── Test 1: tier gate blocks assurance ────────────────────────────────────────

print ""
print "=== Test 1: tier gate (assurance exits 0 without calling API) ==="

tmpdir=$(setup_fixture)
run_daemon "$tmpdir"
rc=$?
assert_pass "tier gate: exits 0 for assurance" $rc
assert_file_not_exists "tier gate: no install-status.json written" \
    "$tmpdir/state/install-status.json"
rm -rf "$tmpdir"

# ── Test 1b: PAT-1773 another tenant's cached config is no config ────────────

print ""
print "=== Test 1b: managed config for another tenant stays at assurance ==="

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'previous-tenant','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"
run_daemon "$tmpdir"
rc=$?
assert_pass "other tenant: exits 0" $rc
assert_eq "other tenant: tier gate skips at the no-config default" "1" \
    "$(grep -c 'Tier gate: assurance is not managed; skipping install run' "$tmpdir/install.log")"
assert_eq "other tenant: says why the cached config is not used" "1" \
    "$(grep -c 'does not belong to the enrolled tenant (other_tenant previous-tenant)' "$tmpdir/install.log")"
rm -rf "$tmpdir"

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"
run_daemon "$tmpdir"
assert_eq "enrolled tenant: the same config passes the tier gate" "1" \
    "$(grep -c 'Tier gate OK: managed' "$tmpdir/install.log")"
rm -rf "$tmpdir"

# ── Test 2: managed tier - API unreachable exits 0 ──────────────────────────

print ""
print "=== Test 2: managed tier + API unreachable exits 0 (fail-safe) ==="

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"

# No stub curl: real curl is used; localhost:0 is unreachable → exits 0 (fail-safe).
run_daemon "$tmpdir"
rc=$?
assert_pass "API unreachable: exits 0" $rc
assert_file_not_exists "API unreachable: no install-status.json written" \
    "$tmpdir/state/install-status.json"
rm -rf "$tmpdir"

# ── Test 3: empty pending-installs queue ──────────────────────────────────────
#
# FINDING 2 fix: patched-install.sh re-exports PATH prepending system dirs
# (line: export PATH="/usr/local/sbin:…:/opt/homebrew/bin:${PATH:-}"), so a
# curl-stub injected via PATH will always lose to /usr/bin/curl. Tests that rely
# on a stub curl binary are therefore shadowed — the real curl hits localhost:0,
# fails, and the script exits 0 before reaching dispatch. This makes Tests 3 and 4
# trivially pass without exercising the queue-parsing or dispatch code paths.
#
# Fix: use a real Python HTTP server on localhost (same technique as Test 5) so
# /usr/bin/curl can reach it. Now the empty-queue and winget-skip paths are
# genuinely exercised through full dispatch.

print ""
print "=== Test 3: empty pending-installs queue exits 0 cleanly ==="

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"

_t3_port_file="$tmpdir/t3_port"
PATCHED_T3_PORT_FILE="$_t3_port_file" \
/usr/bin/python3 - <<'PYEOF' &
import os, socketserver, http.server
_body     = b'{"installs":[]}'
_portfile = os.environ['PATCHED_T3_PORT_FILE']
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(_body)))
        self.end_headers()
        self.wfile.write(_body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'{}')
with socketserver.TCPServer(('127.0.0.1', 0), Handler) as srv:
    with open(_portfile, 'w') as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()
PYEOF
_t3_server_pid=$!

_waited=0
while [[ ! -s "$_t3_port_file" ]] && (( _waited < 30 )); do
    sleep 0.1; (( _waited++ ))
done
_t3_port=$(cat "$_t3_port_file" 2>/dev/null || echo "")

if [[ -z "$_t3_port" ]]; then
    print "  SKIP  [empty queue: HTTP stub server did not start — skipping]"
    (( PASS++ ))
else
    PATCHED_BUNDLE_DIR="$tmpdir/bundle" \
    PATCHED_STATE_DIR="$tmpdir/state" \
    PATCHED_CREDS_DIR="$tmpdir/creds" \
    PATCHED_LOG_FILE="$tmpdir/install.log" \
    PATCHED_API_URL="http://127.0.0.1:$_t3_port" \
    zsh "$DAEMON" >/dev/null 2>&1
    rc=$?
    assert_pass "empty queue: exits 0" $rc
    assert_file_not_exists "empty queue: no install-status.json written" \
        "$tmpdir/state/install-status.json"
fi

kill $_t3_server_pid 2>/dev/null || true
rm -rf "$tmpdir"

# ── Test 4: winget source skipped on macOS ────────────────────────────────────
#
# FINDING 2 fix: same localhost HTTP-server technique as Test 3 and Test 5.
# This ensures the daemon actually reaches dispatch (processes the item list)
# rather than exiting early at the API fetch stage. With a real winget item
# served, the dispatch genuinely exercises the winget-skip branch and we can
# assert that Installomator is NOT called.

print ""
print "=== Test 4: package_source=winget skipped on macOS (no Installomator call) ==="

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"

# Stub Installomator — counts calls.
call_count_file="$tmpdir/installomator_calls"
echo 0 > "$call_count_file"
cat > "$tmpdir/bundle/Installomator.sh" <<INSTOSTUB
#!/bin/zsh
count=\$(cat "$call_count_file")
echo \$(( count + 1 )) > "$call_count_file"
exit 0
INSTOSTUB
chmod +x "$tmpdir/bundle/Installomator.sh"

_t4_port_file="$tmpdir/t4_port"
PATCHED_T4_PORT_FILE="$_t4_port_file" \
/usr/bin/python3 - <<'PYEOF' &
import os, socketserver, http.server
_body     = b'{"installs":[{"package_id":"Microsoft.VSCode","package_source":"winget","display_name":"Visual Studio Code"}]}'
_portfile = os.environ['PATCHED_T4_PORT_FILE']
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(_body)))
        self.end_headers()
        self.wfile.write(_body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'{}')
with socketserver.TCPServer(('127.0.0.1', 0), Handler) as srv:
    with open(_portfile, 'w') as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()
PYEOF
_t4_server_pid=$!

_waited=0
while [[ ! -s "$_t4_port_file" ]] && (( _waited < 30 )); do
    sleep 0.1; (( _waited++ ))
done
_t4_port=$(cat "$_t4_port_file" 2>/dev/null || echo "")

if [[ -z "$_t4_port" ]]; then
    print "  SKIP  [winget skip: HTTP stub server did not start — skipping]"
    (( PASS++ ))
else
    PATCHED_BUNDLE_DIR="$tmpdir/bundle" \
    PATCHED_STATE_DIR="$tmpdir/state" \
    PATCHED_CREDS_DIR="$tmpdir/creds" \
    PATCHED_LOG_FILE="$tmpdir/install.log" \
    PATCHED_API_URL="http://127.0.0.1:$_t4_port" \
    zsh "$DAEMON" >/dev/null 2>&1
    rc=$?
    assert_pass "winget skip: exits 0" $rc
    instomator_calls=$(cat "$call_count_file" 2>/dev/null || echo 0)
    assert_eq "winget skip: Installomator NOT called (winget is Windows-only)" "0" "$instomator_calls"
fi

kill $_t4_server_pid 2>/dev/null || true
rm -rf "$tmpdir"

# ── Test 5: vendor source dispatches to Installomator ────────────────────────
#
# Tests that a pending install with package_source=vendor causes the daemon to
# call Installomator.sh with the package_id as the label.
#
# Technique: spin up a real Python HTTP server on localhost so that the real
# /usr/bin/curl can reach it. This sidesteps the PATH override at the top of
# patched-install.sh which prepends system dirs before the inherited PATH,
# making curl-stub injection unreliable.

print ""
print "=== Test 5: PAT-2245 a leftover valid catalogue pin never reaches Installomator ==="

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"

# Stub Installomator — records first argument (the label).
called_label_file="$tmpdir/called_label"
cat > "$tmpdir/bundle/Installomator.sh" <<INSTOSTUB
#!/bin/zsh
echo "\$1" > "$called_label_file"
exit 0
INSTOSTUB
chmod +x "$tmpdir/bundle/Installomator.sh"

# Spin up a minimal Python HTTP server. Pass config through env vars so the
# heredoc can stay single-quoted (no zsh expansion risk for the Python source).
_server_port_file="$tmpdir/server_port"

# display_name is guaranteed absent from any standard Mac /Applications path.
PATCHED_T5_INSTALL_JSON='{"installs":[{"package_id":"patchedtestlabel9999","package_source":"vendor","display_name":"PatchedTestApplication9999"}]}' \
PATCHED_T5_PORT_FILE="$_server_port_file" \
/usr/bin/python3 - <<'PYEOF' &
import os, socketserver, http.server

_body     = os.environ['PATCHED_T5_INSTALL_JSON'].encode()
_portfile = os.environ['PATCHED_T5_PORT_FILE']

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(_body)))
        self.end_headers()
        self.wfile.write(_body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'{}')

with socketserver.TCPServer(('127.0.0.1', 0), Handler) as srv:
    srv.socket.settimeout(None)
    port = srv.server_address[1]
    with open(_portfile, 'w') as f:
        f.write(str(port))
    srv.serve_forever()
PYEOF
_http_server_pid=$!

# Wait up to 3 s for the server to write its port file.
_waited=0
while [[ ! -s "$_server_port_file" ]] && (( _waited < 30 )); do
    sleep 0.1
    (( _waited++ ))
done
_server_port=$(cat "$_server_port_file" 2>/dev/null || echo "")

if [[ -z "$_server_port" ]]; then
    print "  SKIP  [vendor source: HTTP stub server did not start — skipping]"
    (( PASS++ ))
else
    PATCHED_BUNDLE_DIR="$tmpdir/bundle" \
    PATCHED_STATE_DIR="$tmpdir/state" \
    PATCHED_CREDS_DIR="$tmpdir/creds" \
    PATCHED_LOG_FILE="$tmpdir/install.log" \
    PATCHED_API_URL="http://127.0.0.1:$_server_port" \
    zsh "$DAEMON" >/dev/null 2>&1
    rc=$?
    assert_pass "retired catalogue: exits 0" $rc
    if [[ -f "$called_label_file" ]]; then
        print "  FAIL  [retired catalogue: Installomator was called from a leftover catalogue pin]"
        (( FAIL++ ))
    else
        print "  PASS  [retired catalogue: Installomator NOT called despite a fresh valid pin on disk]"
        (( PASS++ ))
    fi
    _t5_status=$(/usr/bin/python3 -c "
import json, sys
try:
    i = json.load(open(sys.argv[1])).get('installs', [])[0]
    print(i.get('outcome', 'MISSING') + '|' + str(i.get('failure_kind', '')) + '|' + str(i.get('error_message', '')))
except Exception as e:
    print('READ_ERROR:' + str(e))
" "$tmpdir/state/install-status.json" 2>/dev/null || echo "STATUS_MISSING")
    assert_eq "retired catalogue: install outcome is failed" "failed" "${_t5_status%%|*}"
    assert_eq "retired catalogue: refusal says the catalogue is retired" "1" \
        "$([[ "$_t5_status" == *'install refused: catalogue retired (PAT-2245)'* ]] && echo 1 || echo 0)"
    assert_eq "retired catalogue: the daemon log carries the refusal" "1" \
        "$(grep -q 'install refused: catalogue retired (PAT-2245)' "$tmpdir/install.log" 2>/dev/null && echo 1 || echo 0)"
fi

kill $_http_server_pid 2>/dev/null || true
rm -rf "$tmpdir"

# Tests 6 and 7 (post-install presence checks after a zero-exit Installomator
# run) were removed in PAT-2245: with the signed app catalogue retired, no
# vendor install reaches Installomator, so that code is unreachable.

# ── Test 8: vendor label NOT in allowlist → Installomator NOT called ─────────
#
# PAT-66 authorization_bypass fix: a server-supplied vendor label that is absent
# from the bundle-pinned labels-allowlist.txt must be refused before Installomator
# runs.  Installomator must NOT be called; outcome in install-status.json must be
# "failed".  The happy-path (label present) is covered by Test 5.
#
# Uses a label ("patchedunknownlabel9999") that is deliberately absent from the
# allowlist created by setup_fixture, which only contains patchedtestlabel9999
# and patchednolabelpkg9999.

print ""
print "=== Test 8: vendor label NOT in allowlist → blocked (PAT-66 authorization_bypass fix) ==="

tmpdir=$(setup_fixture)
/usr/bin/python3 -c "import json; print(json.dumps({'tenant_id':'test-tenant-id','tier':'managed'}))" \
    > "$tmpdir/state/agent-config.json"

# Stub Installomator — records any call so we can assert it was NOT invoked.
_t8_call_file="$tmpdir/t8_installomator_called"
cat > "$tmpdir/bundle/Installomator.sh" <<INSTOSTUB
#!/bin/zsh
echo "called" > "$_t8_call_file"
exit 0
INSTOSTUB
chmod +x "$tmpdir/bundle/Installomator.sh"

_t8_port_file="$tmpdir/t8_port"
# Serve a label deliberately absent from the fixture allowlist.
PATCHED_T8_INSTALL_JSON='{"installs":[{"package_id":"patchedunknownlabel9999","package_source":"vendor","display_name":"Patched Unknown Label App 9999"}]}' \
PATCHED_T8_PORT_FILE="$_t8_port_file" \
/usr/bin/python3 - <<'PYEOF' &
import os, socketserver, http.server
_body     = os.environ['PATCHED_T8_INSTALL_JSON'].encode()
_portfile = os.environ['PATCHED_T8_PORT_FILE']
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(_body)))
        self.end_headers()
        self.wfile.write(_body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'{}')
with socketserver.TCPServer(('127.0.0.1', 0), Handler) as srv:
    with open(_portfile, 'w') as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()
PYEOF
_t8_server_pid=$!

_waited=0
while [[ ! -s "$_t8_port_file" ]] && (( _waited < 30 )); do
    sleep 0.1; (( _waited++ ))
done
_t8_port=$(cat "$_t8_port_file" 2>/dev/null || echo "")

if [[ -z "$_t8_port" ]]; then
    print "  SKIP  [allowlist-gate: HTTP stub server did not start — skipping]"
    (( PASS++ ))
else
    PATCHED_BUNDLE_DIR="$tmpdir/bundle" \
    PATCHED_STATE_DIR="$tmpdir/state" \
    PATCHED_CREDS_DIR="$tmpdir/creds" \
    PATCHED_LOG_FILE="$tmpdir/install.log" \
    PATCHED_API_URL="http://127.0.0.1:$_t8_port" \
    zsh "$DAEMON" >/dev/null 2>&1
    rc=$?
    assert_pass "allowlist-gate: exits 0 (blocked install is not a daemon error)" $rc

    # Installomator must NOT have been called.
    if [[ -f "$_t8_call_file" ]]; then
        print "  FAIL  [allowlist-gate: Installomator was called for a label not in allowlist — gate is broken]"
        (( FAIL++ ))
    else
        print "  PASS  [allowlist-gate: Installomator NOT called for label absent from allowlist]"
        (( PASS++ ))
    fi

    # Outcome in install-status.json must be "failed".
    _t8_outcome=$(/usr/bin/python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    installs = d.get('installs', [])
    if installs:
        print(installs[0].get('outcome', 'MISSING'))
    else:
        print('NO_INSTALLS')
except Exception as e:
    print('READ_ERROR:' + str(e))
" "$tmpdir/state/install-status.json" 2>/dev/null || echo "STATUS_MISSING")

    assert_eq \
        "allowlist-gate: blocked label reports outcome 'failed'" \
        "failed" \
        "$_t8_outcome"
fi

kill $_t8_server_pid 2>/dev/null || true
rm -rf "$tmpdir"

# ── Summary ───────────────────────────────────────────────────────────────────

print ""
print "Results: $PASS passed, $FAIL failed"
print ""
(( FAIL == 0 ))
