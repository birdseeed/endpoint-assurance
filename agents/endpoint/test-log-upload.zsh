#!/bin/zsh
##############################################################################
# test-log-upload.zsh — unit tests for patched-log-upload.sh (PAT-287).
#
# Tests:
#   (a) No directive       — exits 0, no upload attempted
#   (b) Already fulfilled  — exits 0, idempotent skip
#   (c) Device match       — own platform device id resolved from the
#                             config-injected device_id (c1) or the
#                             creds-file device-id (c2); a directive aimed at
#                             a different device is still rejected (c3); an
#                             unresolvable local identity is skipped with a
#                             message distinct from a mismatch (c4) (PAT-1026)
#   (d) Empty device_id    — no-op, NOT tenant-wide: the server never issues
#                             an empty device_id as a real directive, so the
#                             agent must not collect estate-wide (PAT-1033)
#   (e) Redaction          — home paths, proxy creds, bearer tokens stripped
#   (f) Rotation           — log file > 10 MiB is rotated; .1 appears
#   (g) Window filtering   — lines outside [since, until) are excluded
#
# Uses temp dirs for STATE_DIR, CREDS_DIR, log files — no root required.
# The upload step (curl) is never reached in these tests because we
# configure scenarios that exit before credentials are read, or we stub
# creds to provoke graceful failure before any network call is made.
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-log-upload.sh"
PYTHON3="/usr/bin/python3"

# device_id is required (PAT-1033) — tests that aren't specifically exercising
# the device-match logic itself (idempotency, jsonl path, etc.) use this
# shared id as both the config-injected own-device-id and the directive's
# target device_id so they clear the match check and reach the behavior
# under test.
MATCH_DEVICE_ID="30303030-3030-3030-3030-303030303030"

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
        echo "        haystack: ${haystack:0:200}"
    fi
}

chk_not_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc — should NOT contain: $needle"
        echo "        haystack: ${haystack:0:200}"
    fi
}

# ---- Shared temp environment -----------------------------------------------

STATE_DIR=$(mktemp -d /tmp/.test-log-upload-state.XXXXXX)
CREDS_DIR=$(mktemp -d /tmp/.test-log-upload-creds.XXXXXX)
LOG_DIR=$(mktemp -d /tmp/.test-log-upload-logs.XXXXXX)
# PAT-1773: the script reads the cached config only when it belongs to the
# enrolled tenant, decided by agent_config_tenant.py from the bundle. The test
# bundle holds only that module (no proxy resolver, as before).
TEST_BUNDLE_DIR=$(mktemp -d /tmp/.test-log-upload-bundle.XXXXXX)
cp "$SCRIPT_DIR/agent_config_tenant.py" "$TEST_BUNDLE_DIR/agent_config_tenant.py"
trap 'rm -rf "$STATE_DIR" "$CREDS_DIR" "$LOG_DIR" "$TEST_BUNDLE_DIR"' EXIT

# Stub credential files (content doesn't matter for tests that exit before
# the upload step — tests that reach curl will get a network error, which is
# not a test failure).
echo "test-bearer-token" > "$CREDS_DIR/bearer-token"
# Base64 of 32 zero bytes — a valid HMAC secret shape.
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > "$CREDS_DIR/hmac-secret"
echo "00000000-0000-0000-0000-000000000001" > "$CREDS_DIR/tenant-id"

run_script() {
    # run_script [extra-env-pairs...]
    # Runs patched-log-upload.sh in the sandbox, capturing combined output.
    # Returns the captured output; caller checks exit code via $?.
    local extra_env=("$@")
    PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_LOG_UPDATER="$LOG_DIR/update.log" \
    PATCHED_LOG_COLLECTOR="$LOG_DIR/collect.log" \
    PATCHED_LOG_UPLOAD_LOG="$LOG_DIR/upload.log" \
    PATCHED_BUNDLE_DIR="$TEST_BUNDLE_DIR" \
    PATCHED_AGENT_HEALTH_STORE="$STATE_DIR/.agent-health.json" \
    "${extra_env[@]}" \
    zsh "$TARGET" 2>&1
}

write_config() {
    # write_config <json-content>
    printf '%s' "$1" > "$STATE_DIR/agent-config.json"
}

# ============================================================================
# (a) No directive — config exists but has no log_request field
# ============================================================================
echo "\n--- (a) No directive ---"
write_config '{"tenant_id":"00000000-0000-0000-0000-000000000001","config_version":1}'

out=$(run_script)
chk_contains "no directive: reports skip" "no log_request directive" "$out"
chk_eq "no directive: fulfilled file not created" "0" "$([ -f "$STATE_DIR/log-upload-fulfilled-request-id" ] && echo 1 || echo 0)"

# ============================================================================
# (a2) PAT-1773: a log_request in another tenant's cached config is skipped as
#      if there were no config, and the reason is logged once.
# ============================================================================
echo "\n--- (a2) Cached config for another tenant ---"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-00000000000f\",\"config_version\":1,\"device_id\":\"${MATCH_DEVICE_ID}\",
  \"log_request\":{\"request_id\":\"a2a2a2a2-a2a2-a2a2-a2a2-a2a2a2a2a2a2\",\"device_id\":\"${MATCH_DEVICE_ID}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"
out=$(run_script)
chk_contains "other tenant: skipped as no config" "no agent config for the enrolled tenant" "$out"
chk_contains "other tenant: says why" "does not belong to the enrolled tenant (other_tenant 00000000-0000-0000-0000-00000000000f)" "$out"
chk_eq "other tenant: the reason is logged once" "1" "$(print -r -- "$out" | grep -c 'is not used this run')"
chk_not_contains "other tenant: directive never parsed" "log_request" "$out"

mv "$CREDS_DIR/tenant-id" "$CREDS_DIR/tenant-id.saved"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${MATCH_DEVICE_ID}\",
  \"log_request\":{\"request_id\":\"a2a2a2a2-a2a2-a2a2-a2a2-a2a2a2a2a2a3\",\"device_id\":\"${MATCH_DEVICE_ID}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"
out=$(run_script)
chk_contains "no enrolled tenant-id: skipped as no config" "no agent config for the enrolled tenant" "$out"
chk_contains "no enrolled tenant-id: says why" "no enrolled tenant is configured yet" "$out"
mv "$CREDS_DIR/tenant-id.saved" "$CREDS_DIR/tenant-id"

# ============================================================================
# (b) Already fulfilled — request_id matches the fulfilled cache
# ============================================================================
echo "\n--- (b) Already fulfilled ---"
local_req_id="11111111-1111-1111-1111-111111111111"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${MATCH_DEVICE_ID}\",
  \"log_request\":{\"request_id\":\"${local_req_id}\",\"device_id\":\"${MATCH_DEVICE_ID}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"
printf '%s' "$local_req_id" > "$STATE_DIR/log-upload-fulfilled-request-id"

out=$(run_script)
chk_contains "fulfilled: reports already-done" "already fulfilled" "$out"

rm -f "$STATE_DIR/log-upload-fulfilled-request-id"

# ============================================================================
# (c) Device match — resolves this agent's own platform device id (PAT-1026):
#     config-injected device_id first, then $CREDS_DIR/device-id. A directive
#     for a different device is still rejected; an unresolvable local
#     identity is a distinct condition from a mismatch.
# ============================================================================

# --- (c1) Config-injected device_id matches the directive -> processed. ---
echo "\n--- (c1) Device match via config-injected device_id ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id" "$CREDS_DIR/device-id"
c1_req_id="44444444-4444-4444-4444-444444444444"
c1_device_id="55555555-5555-5555-5555-555555555555"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${c1_device_id}\",
  \"log_request\":{\"request_id\":\"${c1_req_id}\",\"device_id\":\"${c1_device_id}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"

out=$(run_script)
chk_contains "config match: proceeds past device check" "processing request_id" "$out"
chk_not_contains "config match: no unknown-identity message" "local platform device id unknown" "$out"

# --- (c2) Creds-file device-id matches when config carries none -> processed. ---
echo "\n--- (c2) Device match via creds-file device-id (config has none) ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id" "$CREDS_DIR/device-id"
c2_req_id="66666666-6666-6666-6666-666666666666"
c2_device_id="77777777-7777-7777-7777-777777777777"
printf '%s\n' "$c2_device_id" > "$CREDS_DIR/device-id"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,
  \"log_request\":{\"request_id\":\"${c2_req_id}\",\"device_id\":\"${c2_device_id}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"

out=$(run_script)
chk_contains "creds-file match: proceeds past device check" "processing request_id" "$out"
rm -f "$CREDS_DIR/device-id"

# --- (c3) Directive targets a different device -> skipped (cross-device
#     guard still holds — this is the ticket's core "still rejects" case). ---
echo "\n--- (c3) Device mismatch — directive not for this device ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id" "$CREDS_DIR/device-id"
c3_local_id="88888888-8888-8888-8888-888888888888"
c3_other_id="99999999-9999-9999-9999-999999999998"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${c3_local_id}\",
  \"log_request\":{\"request_id\":\"${c3_other_id}\",\"device_id\":\"${c3_other_id}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"

out=$(run_script)
chk_contains "device mismatch: reports skip" "does not match local device_id" "$out"
# Also ensure the message correctly echoes the mismatched device_id.
chk_contains "device mismatch: reports target device_id" "$c3_other_id" "$out"
chk_eq "device mismatch: fulfilled file not created" "0" "$([ -f "$STATE_DIR/log-upload-fulfilled-request-id" ] && echo 1 || echo 0)"

# PAT-1065: the device_id mismatch fault must be recorded into the shared
# agent_health store (confined to STATE_DIR via PATCHED_AGENT_HEALTH_STORE
# above — never the real /Library/Application Support/Patched on the test
# runner). Full behavioral coverage of the store itself lives in
# test-agent-health.zsh; this is just the wiring check that this call site
# actually fires.
ah_store_content=$(cat "$STATE_DIR/.agent-health.json" 2>/dev/null)
chk_contains "device mismatch: recorded in agent-health store" '"directive_skipped"' "$ah_store_content"
chk_contains "device mismatch: recorded with device_id_mismatch reason" '"device_id_mismatch"' "$ah_store_content"

# --- (c4) Neither source resolves a local device id -> skipped, with a
#     message distinct from a mismatch ("I don't know who I am" is not the
#     same condition as "this isn't for me"). ---
echo "\n--- (c4) Unknown local identity — neither source resolves ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id" "$CREDS_DIR/device-id"
c4_req_id="10101010-1010-1010-1010-101010101010"
c4_target_id="20202020-2020-2020-2020-202020202020"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,
  \"log_request\":{\"request_id\":\"${c4_req_id}\",\"device_id\":\"${c4_target_id}\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"

out=$(run_script)
chk_contains "unknown identity: distinct message" "local platform device id unknown" "$out"
chk_not_contains "unknown identity: not reported as a mismatch" "does not match local device_id" "$out"
chk_eq "unknown identity: fulfilled file not created" "0" "$([ -f "$STATE_DIR/log-upload-fulfilled-request-id" ] && echo 1 || echo 0)"
rm -f "$CREDS_DIR/device-id"

# ============================================================================
# (d) Empty device_id — no-op, NOT tenant-wide (PAT-1033). The server's
#     validateAgentConfigReq already rejects an empty/non-UUID device_id, so
#     a signed config can never legitimately carry one; the agent must treat
#     it as "do not act", never as "collect for every device".
# ============================================================================
echo "\n--- (d) Empty device_id is a no-op, not tenant-wide ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id" "$STATE_DIR/.agent-health.json"
empty_req_id="33333333-3333-3333-3333-333333333333"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,
  \"log_request\":{\"request_id\":\"${empty_req_id}\",\"device_id\":\"\",\"components\":[\"updater\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"
# Write a small log file so a wrongful estate-wide collection would have
# something to pick up — the test proves it never gets touched.
echo "=== patched-update run started 2026-07-01T00:00:00Z ===" > "$LOG_DIR/update.log"
echo "test log line" >> "$LOG_DIR/update.log"

out=$(run_script)
chk_contains "empty device_id: explains it is not a legitimate tenant-wide request" "not a legitimate tenant-wide request" "$out"
chk_not_contains "empty device_id: does not proceed to collection" "processing request_id" "$out"
chk_not_contains "empty device_id: not reported as a mismatch" "does not match local device_id" "$out"
chk_not_contains "empty device_id: not reported as unknown identity" "local platform device id unknown" "$out"
chk_eq "empty device_id: fulfilled file not created" "0" "$([ -f "$STATE_DIR/log-upload-fulfilled-request-id" ] && echo 1 || echo 0)"

ah_store_content=$(cat "$STATE_DIR/.agent-health.json" 2>/dev/null)
chk_contains "empty device_id: recorded in agent-health store" '"directive_skipped"' "$ah_store_content"
chk_contains "empty device_id: recorded with device_id_empty reason" '"device_id_empty"' "$ah_store_content"

rm -f "$STATE_DIR/.agent-health.json"

# ============================================================================
# (e) Redaction — sensitive patterns are stripped from log content
# ============================================================================
echo "\n--- (e) Redaction ---"

"$PYTHON3" - <<'PYEOF'
import re, json, sys

REDACT = [
    (re.compile(r'/Users/[^/\s"\']+/'),           '/Users/REDACTED_USER/'),
    (re.compile(r'/home/[^/\s"\']+/'),             '/home/REDACTED_USER/'),
    (re.compile(r'https?://[^:@\s"\']+:[^@\s"\']+@'), 'https://REDACTED@'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9._\-]{10,}'), r'\1REDACTED'),
]

def redact(line):
    for pat, rep in REDACT:
        line = pat.sub(rep, line)
    return line

cases = [
    # (input, must_contain, must_not_contain, description)
    ("Installed app at /Users/alice/Applications/Foo.app/",
     "REDACTED_USER", "alice",
     "home path username redacted"),
    ("/home/bob/.config/patched/settings",
     "REDACTED_USER", "bob",
     "linux home path redacted"),
    ("proxy=https://user:s3cret@proxy.corp.example.com:3128",
     "REDACTED@", "s3cret",
     "proxy URL credentials redacted"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.signature",
     "Bearer REDACTED", "eyJhbGciOiJIUzI1NiJ9",
     "bearer token redacted"),
    ("no sensitive data here",
     "no sensitive data here", None,
     "clean line unchanged"),
]

passed = failed = 0
for inp, must_have, must_not, desc in cases:
    out = redact(inp)
    ok = must_have in out and (must_not is None or must_not not in out)
    if ok:
        passed += 1
        print(f"  PASS: {desc}")
    else:
        failed += 1
        print(f"  FAIL: {desc}")
        print(f"        input:  {inp}")
        print(f"        output: {out}")

print(f"\nredaction sub-total: pass={passed} fail={failed}")
if failed:
    sys.exit(1)
PYEOF
redaction_exit=$?
if [[ $redaction_exit -eq 0 ]]; then
    (( pass += 5 ))
else
    (( fail += 5 ))
fi

# ============================================================================
# (f) Rotation — a log file over 10 MiB is rotated to .1
# ============================================================================
echo "\n--- (f) Rotation ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id"
# Create a file that exceeds LOG_ROTATE_MAX_BYTES (10 MiB = 10485760 bytes).
# We fake size check by setting a very low threshold via python size mock.
# Simpler: write exactly 10485761 bytes (10 MiB + 1).
rotate_log="$LOG_DIR/rotate-test.log"
"$PYTHON3" -c "
with open('$rotate_log', 'wb') as f:
    f.write(b'=== patched-update run started 2026-07-01T00:00:00Z ===\n')
    f.write(b'x' * (10485760))
"

# Run the script with the oversized file as the updater log.
write_config '{"tenant_id":"00000000-0000-0000-0000-000000000001","config_version":1}'
PATCHED_LOG_UPDATER="$rotate_log" \
PATCHED_STATE_DIR="$STATE_DIR" \
PATCHED_CREDS_DIR="$CREDS_DIR" \
PATCHED_LOG_COLLECTOR="$LOG_DIR/collect.log" \
PATCHED_LOG_UPLOAD_LOG="$LOG_DIR/upload.log" \
PATCHED_BUNDLE_DIR="$TEST_BUNDLE_DIR" \
zsh "$TARGET" > /dev/null 2>&1 || true

chk_eq "rotation: .1 file created" "1" "$([ -f "${rotate_log}.1" ] && echo 1 || echo 0)"
chk_eq "rotation: original file still exists" "1" "$([ -f "$rotate_log" ] && echo 1 || echo 0)"
orig_size=$(wc -c < "$rotate_log" | tr -d '[:space:]')
chk_eq "rotation: original file truncated (< 1024 bytes)" "1" "$(( orig_size < 1024 ))"

rm -f "$rotate_log" "${rotate_log}.1"

# ============================================================================
# (g) Window filtering — lines outside [since, until) are excluded
# ============================================================================
echo "\n--- (g) Window filtering ---"

window_log="$LOG_DIR/window-test.log"
cat > "$window_log" <<'LOGEOF'
=== patched-update run started 2026-07-01T06:00:00Z ===
line in old run
=== patched-update run started 2026-12-01T12:00:00Z ===
line in target run
=== patched-update run started 2026-12-01T00:00:00Z ===
line in future run
LOGEOF

# Run the Python collection inline with a window covering only the June run.
filtered=$("$PYTHON3" - \
    "$window_log" \
    "/dev/null" \
    "/dev/null" \
    "updater" \
    "2026-11-01T00:00:00Z" \
    "2026-07-01T00:00:00Z" \
    "/dev/stdout" \
    <<'PYEOF'
import sys, re, json
from datetime import datetime, timezone

LOG_PATHS = {"updater": sys.argv[1], "collector": sys.argv[2], "upload": sys.argv[3]}
components = [c.strip() for c in sys.argv[4].split(",") if c.strip()]
since_str, until_str, out_path = sys.argv[5], sys.argv[6], sys.argv[7]

def parse_ts(s):
    try:
        return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc)
    except Exception:
        return None

since = parse_ts(since_str)
until = parse_ts(until_str)
TS_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
REDACT = [
    (re.compile(r'/Users/[^/\s"\']+/'),           '/Users/REDACTED_USER/'),
    (re.compile(r'/home/[^/\s"\']+/'),             '/home/REDACTED_USER/'),
    (re.compile(r'https?://[^:@\s"\']+:[^@\s"\']+@'), 'https://REDACTED@'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9._\-]{10,}'), r'\1REDACTED'),
]
def redact(line):
    for pat, rep in REDACT:
        line = pat.sub(rep, line)
    return line

records = []
for comp in components:
    lf = LOG_PATHS.get(comp)
    for candidate in (lf, lf + ".1", lf + ".2"):
        try:
            with open(candidate, "r", errors="replace") as fh:
                run_ts = None
                for raw in fh:
                    line = raw.rstrip("\n").rstrip("\r")
                    m = TS_RE.search(line)
                    if m:
                        t = parse_ts(m.group(0))
                        if t:
                            run_ts = t
                    if run_ts is None and (since or until):
                        continue
                    if since and run_ts and run_ts < since:
                        continue
                    if until and run_ts and run_ts >= until:
                        continue
                    ts_str = (run_ts.strftime("%Y-%m-%dT%H:%M:%SZ") if run_ts else "unknown")
                    records.append(json.dumps({"ts": ts_str, "component": comp, "msg": redact(line)}))
        except FileNotFoundError:
            continue

import io
buf = io.StringIO()
buf.write("\n".join(records))
if records:
    buf.write("\n")
if out_path == "/dev/stdout":
    sys.stdout.write(buf.getvalue())
else:
    with open(out_path, "w") as f:
        f.write(buf.getvalue())
PYEOF
)

chk_contains     "window: includes target run header"     "2026-12-01T12:00:00Z"  "$filtered"
chk_contains     "window: includes target run body line"  "line in target run"     "$filtered"
chk_not_contains "window: excludes old run"               "line in old run"        "$filtered"
chk_not_contains "window: excludes future run"            "line in future run"     "$filtered"

rm -f "$window_log"

# ============================================================================
# (h) JSONL path — daemon.jsonl is read when component="daemon"
# ============================================================================
echo "\n--- (h) JSONL path (daemon component) ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id"

JSONL_DIR=$(mktemp -d /tmp/.test-log-upload-jsonl.XXXXXX)
trap 'rm -rf "$STATE_DIR" "$CREDS_DIR" "$LOG_DIR" "$JSONL_DIR"' EXIT

# Write a valid daemon.jsonl with one record.
jsonl_req_id="88888888-8888-8888-8888-888888888888"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${MATCH_DEVICE_ID}\",
  \"log_request\":{\"request_id\":\"${jsonl_req_id}\",\"device_id\":\"${MATCH_DEVICE_ID}\",\"components\":[\"daemon\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"

printf '{"ts":"2026-07-01T00:00:00Z","level":"info","component":"daemon","msg":"fetch-config poll started","fields":{}}\n' \
    > "$JSONL_DIR/daemon.jsonl"

out=$(PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_LOG_UPDATER="$LOG_DIR/update.log" \
    PATCHED_LOG_COLLECTOR="$LOG_DIR/collect.log" \
    PATCHED_LOG_UPLOAD_LOG="$LOG_DIR/upload.log" \
    PATCHED_JSONL_DAEMON="$JSONL_DIR/daemon.jsonl" \
    PATCHED_JSONL_COLLECT="$JSONL_DIR/collect.jsonl" \
    PATCHED_JSONL_UPDATE="$JSONL_DIR/update.jsonl" \
    PATCHED_BUNDLE_DIR="$TEST_BUNDLE_DIR" \
    zsh "$TARGET" 2>&1)
chk_contains "jsonl-path: proceeds past device check" "processing request_id" "$out"
chk_contains "jsonl-path: collects from daemon component" "collected" "$out"

# ============================================================================
# (i) JSONL fallback — when jsonl absent, legacy plain-text file is used
# ============================================================================
echo "\n--- (i) JSONL fallback to legacy plain-text ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id"

fallback_req_id="99999999-9999-9999-9999-999999999999"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${MATCH_DEVICE_ID}\",
  \"log_request\":{\"request_id\":\"${fallback_req_id}\",\"device_id\":\"${MATCH_DEVICE_ID}\",\"components\":[\"daemon\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"

# Ensure no jsonl file exists (daemon.jsonl absent → fallback to legacy).
rm -f "$JSONL_DIR/daemon.jsonl"
echo "=== patched-fetch-config 2026-07-01T00:00:00Z ===" > "$LOG_DIR/update.log"
echo "fallback legacy line" >> "$LOG_DIR/update.log"

out=$(PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_LOG_UPDATER="$LOG_DIR/update.log" \
    PATCHED_LOG_COLLECTOR="$LOG_DIR/collect.log" \
    PATCHED_LOG_UPLOAD_LOG="$LOG_DIR/upload.log" \
    PATCHED_JSONL_DAEMON="$JSONL_DIR/daemon.jsonl" \
    PATCHED_JSONL_COLLECT="$JSONL_DIR/collect.jsonl" \
    PATCHED_JSONL_UPDATE="$JSONL_DIR/update.jsonl" \
    PATCHED_BUNDLE_DIR="$TEST_BUNDLE_DIR" \
    zsh "$TARGET" 2>&1)
chk_contains "jsonl-fallback: proceeds past device check" "processing request_id" "$out"
chk_contains "jsonl-fallback: collects from legacy file" "collected" "$out"

# ============================================================================
# (j) JSONL rotation — a jsonl file over 10 MiB is truncated to empty
# ============================================================================
echo "\n--- (j) JSONL rotation (truncate-and-recreate) ---"
rm -f "$STATE_DIR/log-upload-fulfilled-request-id"

rotate_jsonl_log="$JSONL_DIR/daemon.jsonl"
"$PYTHON3" -c "
with open('$rotate_jsonl_log', 'wb') as f:
    f.write(b'{\"ts\":\"2026-07-01T00:00:00Z\",\"level\":\"info\",\"component\":\"daemon\",\"msg\":\"x\",\"fields\":{}}\n')
    f.write(b'x' * (10485760))
"

write_config '{"tenant_id":"00000000-0000-0000-0000-000000000001","config_version":1}'
PATCHED_STATE_DIR="$STATE_DIR" \
PATCHED_CREDS_DIR="$CREDS_DIR" \
PATCHED_LOG_UPDATER="$LOG_DIR/update.log" \
PATCHED_LOG_COLLECTOR="$LOG_DIR/collect.log" \
PATCHED_LOG_UPLOAD_LOG="$LOG_DIR/upload.log" \
PATCHED_JSONL_DAEMON="$rotate_jsonl_log" \
PATCHED_JSONL_COLLECT="$JSONL_DIR/collect.jsonl" \
PATCHED_JSONL_UPDATE="$JSONL_DIR/update.jsonl" \
PATCHED_BUNDLE_DIR="$TEST_BUNDLE_DIR" \
zsh "$TARGET" > /dev/null 2>&1 || true

jsonl_size=$(wc -c < "$rotate_jsonl_log" | tr -d '[:space:]')
chk_eq "jsonl-rotation: file exists after truncation" "1" "$([ -f "$rotate_jsonl_log" ] && echo 1 || echo 0)"
chk_eq "jsonl-rotation: file truncated (< 1024 bytes)" "1" "$(( jsonl_size < 1024 ))"

# Verify NO .1 file is created (truncate-and-recreate, not copytruncate).
chk_eq "jsonl-rotation: no .1 file created" "0" "$([ -f "${rotate_jsonl_log}.1" ] && echo 1 || echo 0)"

rm -f "$rotate_jsonl_log"

# ============================================================================
# (k) JSONL redaction — /Users/<name>/ paths are stripped from jsonl content
# ============================================================================
echo "\n--- (k) JSONL redaction ---"

"$PYTHON3" - <<'PYEOF'
import re, json, sys

_REDACT_PATH = re.compile(r"/Users/[^/\s\"]+/")
def _r(s): return _REDACT_PATH.sub("/Users/[REDACTED]/", s)

# Simulate the upload script's redact pass over jsonl records.
REDACT = [
    (re.compile(r'/Users/[^/\s"\']+/'),              '/Users/[REDACTED]/'),
    (re.compile(r'/home/[^/\s"\']+/'),               '/home/[REDACTED]/'),
    (re.compile(r'https?://[^:@\s"\']+:[^@\s"\']+@'), 'https://[REDACTED]@'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9._\-]{10,}'),  r'\1[REDACTED]'),
]
def redact(line):
    for pat, rep in REDACT:
        line = pat.sub(rep, line)
    return line

cases = [
    # jsonl record with /Users/ path in msg — must be redacted
    ('{"ts":"2026-07-01T00:00:00Z","level":"info","component":"daemon","msg":"installed at /Users/alice/Applications/Foo.app/","fields":{}}',
     "[REDACTED]", "alice",
     "jsonl msg /Users/ path redacted"),
    # jsonl record with /Users/ in a fields value
    ('{"ts":"2026-07-01T00:00:00Z","level":"info","component":"collect","msg":"ok","fields":{"path":"/Users/bob/Library/Foo"}}',
     "[REDACTED]", "bob",
     "jsonl fields /Users/ path redacted"),
    # jsonl record with no sensitive data — unchanged
    ('{"ts":"2026-07-01T00:00:00Z","level":"info","component":"update","msg":"label processed","fields":{"label":"googlechrome","outcome":"installed"}}',
     "googlechrome", None,
     "jsonl clean record unchanged"),
]

passed = failed = 0
for raw, must_have, must_not, desc in cases:
    try:
        obj = json.loads(raw)
    except Exception as e:
        print(f"  FAIL: {desc} — parse error: {e}")
        failed += 1
        continue
    obj["msg"] = redact(obj.get("msg", ""))
    if isinstance(obj.get("fields"), dict):
        obj["fields"] = {
            k: redact(v) if isinstance(v, str) else v
            for k, v in obj["fields"].items()
        }
    out = json.dumps(obj)
    ok = must_have in out and (must_not is None or must_not not in out)
    if ok:
        passed += 1
        print(f"  PASS: {desc}")
    else:
        failed += 1
        print(f"  FAIL: {desc}")
        print(f"        output: {out}")

print(f"\njsonl redaction sub-total: pass={passed} fail={failed}")
if failed:
    sys.exit(1)
PYEOF
jsonl_redaction_exit=$?
if [[ $jsonl_redaction_exit -eq 0 ]]; then
    (( pass += 3 ))
else
    (( fail += 3 ))
fi

# ============================================================================
# (l) Idempotent re-poll for JSONL request — same request_id skipped
# ============================================================================
echo "\n--- (l) Idempotent re-poll (JSONL request) ---"
idempotent_jsonl_req_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
write_config "{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"config_version\":1,\"device_id\":\"${MATCH_DEVICE_ID}\",
  \"log_request\":{\"request_id\":\"${idempotent_jsonl_req_id}\",\"device_id\":\"${MATCH_DEVICE_ID}\",\"components\":[\"daemon\"],\"since\":\"\",\"until\":\"\",\"max_bytes\":0}}"
printf '%s' "$idempotent_jsonl_req_id" > "$STATE_DIR/log-upload-fulfilled-request-id"

out=$(PATCHED_STATE_DIR="$STATE_DIR" \
    PATCHED_CREDS_DIR="$CREDS_DIR" \
    PATCHED_LOG_UPDATER="$LOG_DIR/update.log" \
    PATCHED_LOG_COLLECTOR="$LOG_DIR/collect.log" \
    PATCHED_LOG_UPLOAD_LOG="$LOG_DIR/upload.log" \
    PATCHED_JSONL_DAEMON="$JSONL_DIR/daemon.jsonl" \
    PATCHED_JSONL_COLLECT="$JSONL_DIR/collect.jsonl" \
    PATCHED_JSONL_UPDATE="$JSONL_DIR/update.jsonl" \
    PATCHED_BUNDLE_DIR="$TEST_BUNDLE_DIR" \
    zsh "$TARGET" 2>&1)
chk_contains "jsonl-idempotent: reports already fulfilled" "already fulfilled" "$out"

rm -f "$STATE_DIR/log-upload-fulfilled-request-id"
rm -rf "$JSONL_DIR"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "RESULT: pass=${pass} fail=${fail}"
[[ $fail -eq 0 ]]
