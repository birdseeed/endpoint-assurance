#!/bin/zsh --no-rcs
# ci/test-fetch-config.zsh — integration tests for patched-fetch-config.sh
#                            and the tier-gate logic in patched-update.sh.
#
# Tests shell-level behaviour: credential checks, fail-safe on unreachable
# server, cached config preservation, lock exclusion, version-file ordering,
# and tier gate in patched-update.sh.
# Ed25519/crypto correctness is covered by ci/test-verify-agent-config.py.
#
# Usage: zsh ci/test-fetch-config.zsh
# Exit 0 if all checks pass.

set -u
PASS=0
FAIL=0
FETCH="${0:a:h}/../endpoint/patched-fetch-config.sh"
DAEMON="${0:a:h}/../endpoint/patched-update.sh"

[[ -f "$FETCH"  ]] || { print "ERROR: patched-fetch-config.sh not found at $FETCH" >&2; exit 1; }
[[ -f "$DAEMON" ]] || { print "ERROR: patched-update.sh not found at $DAEMON" >&2; exit 1; }

assert_pass() {
    local desc="$1" rc="$2"
    if [[ $rc -eq 0 ]]; then print "  PASS  [$desc]"; (( PASS++ ))
    else                      print "  FAIL  [$desc] (exit $rc)"; (( FAIL++ ))
    fi
}

assert_fail() {
    local desc="$1" rc="$2"
    if [[ $rc -ne 0 ]]; then print "  PASS  [$desc]"; (( PASS++ ))
    else                      print "  FAIL  [$desc] (expected non-zero, got 0)"; (( FAIL++ ))
    fi
}

assert_file_exists() {
    local desc="$1" filepath="$2"
    if [[ -f "$filepath" ]]; then print "  PASS  [$desc]"; (( PASS++ ))
    else                          print "  FAIL  [$desc] (not found: $filepath)"; (( FAIL++ ))
    fi
}

assert_file_absent() {
    local desc="$1" filepath="$2"
    if [[ ! -f "$filepath" ]]; then print "  PASS  [$desc]"; (( PASS++ ))
    else                            print "  FAIL  [$desc] (unexpected: $filepath)"; (( FAIL++ ))
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

# ── Setup ────────────────────────────────────────────────────────────────────

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT

state_dir="$tmpdir/state"
creds_dir="$tmpdir/creds"
bundle_dir="$tmpdir/bundle"
log_file="$tmpdir/test.log"
mkdir -p "$state_dir" "$creds_dir" "$bundle_dir"

setup_creds() {
    echo "test-tenant-id" > "$creds_dir/tenant-id"
    echo "test-bearer-token" > "$creds_dir/bearer-token"
    /usr/bin/python3 -c \
        "import base64; print(base64.b64encode(b'test-secret-12345678901234567890').decode())" \
        > "$creds_dir/hmac-secret"
}

# Install a stub verifier that succeeds and writes only the config output
# (NOT the version-file — the shell now writes the version-file after the mv).
install_verifier_ok() {
    cat > "$bundle_dir/verify-agent-config.py" <<'PYSTUB'
import argparse, json, sys, os
ap = argparse.ArgumentParser()
ap.add_argument("--response-file"); ap.add_argument("--version-file"); ap.add_argument("--output-file")
ap.add_argument("--current-config-file")
ap.add_argument("--current-config-sha256-file")
ap.add_argument("--execution-denial-file")
ap.add_argument("--execution-denial-output-file")
args = ap.parse_args()
with open(args.output_file, "w") as f:
    json.dump({"tenant_id": "test-tenant-id", "tier": "assurance", "config_version": 1}, f)
# Do NOT write version-file — the shell does that after the atomic mv.
sys.exit(0)
PYSTUB
    chmod +x "$bundle_dir/verify-agent-config.py"
}

install_verifier_fail() {
    cat > "$bundle_dir/verify-agent-config.py" <<'PYSTUB'
import sys
print("agent-config: rejected — test", file=sys.stderr)
sys.exit(1)
PYSTUB
    chmod +x "$bundle_dir/verify-agent-config.py"
}

# ── Test 1: missing creds → exit non-zero ────────────────────────────────────

print ""
print "=== PAT-282 fetch-config shell tests ==="
print ""
print "Test 1: missing credentials"

rm -f "$creds_dir/tenant-id" "$creds_dir/bearer-token" "$creds_dir/hmac-secret"
PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file" \
PATCHED_API_URL="http://127.0.0.1:1" \
zsh "$FETCH" >/dev/null 2>&1
assert_fail "missing creds: exit non-zero" $?

# ── Test 2: unreachable server → exit 0 (fail-safe), no config written ───────

print ""
print "Test 2: unreachable server is fail-safe (exit 0, no config written)"

setup_creds
install_verifier_ok

PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file" \
PATCHED_API_URL="http://127.0.0.1:1" \
zsh "$FETCH" >/dev/null 2>&1
assert_pass "unreachable server: exit 0 (fail-safe)" $?
assert_file_absent "unreachable server: no agent-config.json written" "$state_dir/agent-config.json"

# ── Test 3: verifier failure preserves last-good config ──────────────────────

print ""
print "Test 3: verifier failure keeps last-good config"

# Pre-seed a known-good cached config.
echo '{"tier":"assurance","config_version":99}' > "$state_dir/agent-config.json"
echo "99" > "$state_dir/agent-config.version"

install_verifier_fail

srv_port_file="$tmpdir/srv_port"

/usr/bin/python3 <<PYEOF &
import http.server
PORT_FILE = "$srv_port_file"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b'{"bad": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE, "w") as f: f.write(str(srv.server_address[1]))
srv.handle_request()
PYEOF
srv_pid=$!

srv_tries=0
while [[ ! -s "$srv_port_file" && $srv_tries -lt 30 ]]; do
    sleep 0.1; (( srv_tries++ ))
done
srv_port=$(cat "$srv_port_file" 2>/dev/null || echo "0")

if [[ "$srv_port" != "0" && -n "$srv_port" ]]; then
    PATCHED_BUNDLE_DIR="$bundle_dir" \
    PATCHED_STATE_DIR="$state_dir" \
    PATCHED_CREDS_DIR="$creds_dir" \
    PATCHED_LOG_FILE="$log_file" \
    PATCHED_API_URL="http://127.0.0.1:$srv_port" \
    zsh "$FETCH" >/dev/null 2>&1
    assert_pass "verifier fail: exit 0 (fail-safe)" $?
    existing=$(cat "$state_dir/agent-config.json" 2>/dev/null || echo "")
    assert_eq "verifier fail: last-good config preserved" \
        '{"tier":"assurance","config_version":99}' "$existing"
else
    print "  SKIP  [verifier-failure tests — server did not start]"
fi
wait $srv_pid 2>/dev/null || true

# ── Test 4: 304 response → exit 0, config unchanged ─────────────────────────

print ""
print "Test 4: 304 Not Modified — exit 0, cached config unchanged"

# Pre-seed config and version file.
echo '{"tier":"managed","config_version":5}' > "$state_dir/agent-config.json"
echo "5" > "$state_dir/agent-config.version"
# PAT-1035 finding 2 / PAT-1040: a 304 only proves the server thinks our
# recorded VERSION is current — _agent_config_handle_304 additionally checks
# the on-disk config's SHA-256 against agent-config.sha256 before treating it
# as a genuine no-op, and (PAT-1040) quarantines the file out of its
# canonical path on a mismatch. This test means to exercise the ordinary
# "nothing changed" 304, so the sidecar hash must be seeded to match the
# pre-seeded config, or the mismatch branch fires and moves the file aside
# before this test's assertion below ever gets to read it.
shasum -a 256 "$state_dir/agent-config.json" | awk '{print $1}' > "$state_dir/agent-config.sha256"

srv_port_file2="$tmpdir/srv_port2"

/usr/bin/python3 <<PYEOF2 &
import http.server
PORT_FILE = "$srv_port_file2"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(304)
        self.send_header("ETag", '"5"')
        self.end_headers()
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE, "w") as f: f.write(str(srv.server_address[1]))
srv.handle_request()
PYEOF2
srv2_pid=$!

srv2_tries=0
while [[ ! -s "$srv_port_file2" && $srv2_tries -lt 30 ]]; do
    sleep 0.1; (( srv2_tries++ ))
done
srv2_port=$(cat "$srv_port_file2" 2>/dev/null || echo "0")

if [[ "$srv2_port" != "0" && -n "$srv2_port" ]]; then
    PATCHED_BUNDLE_DIR="$bundle_dir" \
    PATCHED_STATE_DIR="$state_dir" \
    PATCHED_CREDS_DIR="$creds_dir" \
    PATCHED_LOG_FILE="$log_file" \
    PATCHED_API_URL="http://127.0.0.1:$srv2_port" \
    zsh "$FETCH" >/dev/null 2>&1
    assert_pass "304 response: exit 0" $?
    after_304=$(cat "$state_dir/agent-config.json" 2>/dev/null || echo "")
    assert_eq "304 response: cached config unchanged" \
        '{"tier":"managed","config_version":5}' "$after_304"
else
    print "  SKIP  [304 tests — server did not start]"
fi
wait $srv2_pid 2>/dev/null || true

# ── Test 5: version-file written by shell after successful fetch ──────────────
# Verifies crash-ordering: config mv happens first, then version-file is written.

print ""
print "Test 5: version-file written by shell after successful fetch (ordering)"

# Start with a clean state (no pre-existing config or version).
rm -f "$state_dir/agent-config.json" "$state_dir/agent-config.version"

setup_creds
install_verifier_ok

srv_port_file3="$tmpdir/srv_port3"

/usr/bin/python3 <<PYEOF3 &
import http.server, json
PORT_FILE = "$srv_port_file3"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"tier": "assurance", "config_version": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE, "w") as f: f.write(str(srv.server_address[1]))
srv.handle_request()
PYEOF3
srv3_pid=$!

srv3_tries=0
while [[ ! -s "$srv_port_file3" && $srv3_tries -lt 30 ]]; do
    sleep 0.1; (( srv3_tries++ ))
done
srv3_port=$(cat "$srv_port_file3" 2>/dev/null || echo "0")

if [[ "$srv3_port" != "0" && -n "$srv3_port" ]]; then
    PATCHED_BUNDLE_DIR="$bundle_dir" \
    PATCHED_STATE_DIR="$state_dir" \
    PATCHED_CREDS_DIR="$creds_dir" \
    PATCHED_LOG_FILE="$log_file" \
    PATCHED_API_URL="http://127.0.0.1:$srv3_port" \
    zsh "$FETCH" >/dev/null 2>&1
    assert_pass "ordering: fetch exits 0" $?
    assert_file_exists "ordering: agent-config.json written" "$state_dir/agent-config.json"
    ver_content=$(cat "$state_dir/agent-config.version" 2>/dev/null || echo "MISSING")
    assert_eq "ordering: version-file written by shell as the tenant-keyed floor (PAT-1756)" \
        '{"tenant_id":"test-tenant-id","config_version":1}' "$ver_content"
else
    print "  SKIP  [version ordering tests — server did not start]"
fi
wait $srv3_pid 2>/dev/null || true

# ── Test 6: lock held → exit 0, no config written ────────────────────────────

print ""
print "Test 6: lock held — fetch skips cleanly (exit 0, config unchanged)"

# Clear state, set up creds.
rm -f "$state_dir/agent-config.json" "$state_dir/agent-config.version"
setup_creds

# Simulate a held lock by creating the lock directory manually.
mkdir -p "$state_dir/.patched-config-fetch.lock"

PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file" \
PATCHED_API_URL="http://127.0.0.1:1" \
zsh "$FETCH" >/dev/null 2>&1
assert_pass "lock held: exit 0 (skip)" $?
assert_file_absent "lock held: no agent-config.json written" "$state_dir/agent-config.json"

# Clean up the simulated lock.
rm -rf "$state_dir/.patched-config-fetch.lock"

# ── Test 7: tier gate in patched-update.sh (assurance → scan) ────────────
#
# PAT-1620 note: this trigger shape ({"labels":[...]}, no "type" key) used to
# reach RUN_MODE=install via the missing-type-defaults-to-deploy fail-open,
# which is exactly what PAT-1620 closed -- it's now rejected in parse_trigger
# before ever reaching this tier gate. The gate itself (patched-update.sh's
# "Tier gate: tier=$AGENT_TIER..." check) is untouched, intentionally dead
# code: nothing can set RUN_MODE=install via any live trigger any more (the
# deploy type that used to was the only setter), pending the separate
# executor-removal ticket PAT-1617 names as out of scope for this batch. The
# real, still-live outcome this test now proves is the same as Test 8 below:
# a typeless trigger never installs, regardless of tier.

print ""
print "Test 7: tier gate — assurance tenant cannot trigger install (deploy retired, PAT-1620: trigger rejected before reaching the tier gate)"

setup_creds
echo '{"tier":"assurance","config_version":1}' > "$state_dir/agent-config.json"
echo '1' > "$state_dir/agent-config.version"
shasum -a 256 "$state_dir/agent-config.json" | awk '{print $1}' > "$state_dir/agent-config.sha256"

# Stub the entire bundle for patched-update.sh
echo "# empty manifest for test" > "$bundle_dir/manifest.sha256"
echo "# empty allowlist for test" > "$bundle_dir/labels-allowlist.txt"
cat > "$bundle_dir/Installomator.sh" <<'SHSTUB'
#!/bin/zsh
exit 0
SHSTUB
chmod +x "$bundle_dir/Installomator.sh"

# patched-fetch-config.sh already in bundle_dir; replace with no-op for this test.
cat > "$bundle_dir/patched-fetch-config.sh" <<'SHSTUB'
#!/bin/zsh
exit 0
SHSTUB
chmod +x "$bundle_dir/patched-fetch-config.sh"

# Create a trigger file requesting install mode.
triggers_dir="$state_dir/triggers"
mkdir -p "$triggers_dir"
echo '{"labels":["firefox"]}' > "$triggers_dir/test.trigger"

: > "$log_file"   # clear log

PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file" \
PATCHED_API_URL="http://127.0.0.1:1" \
zsh "$DAEMON" >/dev/null 2>&1
assert_pass "tier gate (assurance): daemon exits 0" $?

gate_count=$(grep -c "Tier gate" "$log_file" 2>/dev/null; true)
gate_count="${gate_count:-0}"
assert_eq "tier gate (assurance): trigger rejected upstream, tier gate never reached" "0" "$gate_count"

# ── Test 8: tier=managed — gate does not fire ─────────────────────────────────
#
# PAT-1620 note: same as Test 7, this typeless trigger is rejected upstream
# regardless of tier now, so "gate does not fire" is true here for the same
# reason it's now true in Test 7 too -- not because tier=managed permits
# install (nothing can reach install via a trigger any more).

print ""
print "Test 8: tier=managed — typeless trigger still does not install (deploy retired, PAT-1620)"

echo '{"tier":"managed","config_version":2}' > "$state_dir/agent-config.json"
echo '2' > "$state_dir/agent-config.version"
shasum -a 256 "$state_dir/agent-config.json" | awk '{print $1}' > "$state_dir/agent-config.sha256"

mkdir -p "$triggers_dir"
echo '{"labels":["firefox"]}' > "$triggers_dir/test2.trigger"

: > "$log_file"

PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file" \
PATCHED_API_URL="http://127.0.0.1:1" \
zsh "$DAEMON" >/dev/null 2>&1
assert_pass "tier=managed: daemon exits 0" $?

gate_count_patch=$(grep -c "Tier gate" "$log_file" 2>/dev/null; true)
gate_count_patch="${gate_count_patch:-0}"
assert_eq "tier=managed: no gate message in log" "0" "$gate_count_patch"

# ── Summary ───────────────────────────────────────────────────────────────────

print ""
print "Results: $PASS passed, $FAIL failed"
print ""
(( FAIL == 0 ))
