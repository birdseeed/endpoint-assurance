#!/bin/zsh --no-rcs
# End-to-end smoke test for patched-update.sh.
#
# Exercises the actual daemon script with stubbed dependencies so that
# runtime errors (e.g. `local` used outside a function, unset variables
# under set -u) fail CI — things zsh -n / unit tests of copied logic
# cannot catch.
#
# Usage: zsh ci/test-daemon-endtoend.zsh
# Exit 0 if all checks pass.

set -u
PASS=0
FAIL=0
DAEMON="${0:a:h}/../endpoint/patched-update.sh"

if [[ ! -f "$DAEMON" ]]; then
    print "ERROR: daemon not found at $DAEMON" >&2; exit 1
fi

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

assert_file_exists() {
    local desc="$1" filepath="$2"
    if [[ -f "$filepath" ]]; then
        print "  PASS  [$desc]"
        (( PASS++ ))
    else
        print "  FAIL  [$desc] (file not found: $filepath)"
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

# ── Setup ────────────────────────────────────────────────────────────────────

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT

bundle_dir="$tmpdir/bundle"
state_dir="$tmpdir/state"
prov_queue="$tmpdir/prov"
creds_dir="$tmpdir/creds"
log_file="$tmpdir/update.log"
mkdir -p "$bundle_dir" "$state_dir" "$prov_queue" "$creds_dir"

# Empty manifest — verify_bundle passes with nothing to check.
echo "# empty manifest for test" > "$bundle_dir/manifest.sha256"

# Empty allowlist — main loop runs 0 iterations (no engine calls, no root ops).
echo "# empty allowlist for test" > "$bundle_dir/labels-allowlist.txt"

# Stub engine — counts calls so we can assert 0 calls in scan mode.
call_count_file="$tmpdir/engine_calls"
echo 0 > "$call_count_file"
cat > "$bundle_dir/Installomator.sh" <<STUB
#!/bin/zsh
count=\$(cat "$call_count_file")
echo \$(( count + 1 )) > "$call_count_file"
exit 0
STUB
chmod +x "$bundle_dir/Installomator.sh"

# Stub credentials.
echo "test-tenant-id" > "$creds_dir/tenant-id"
echo "test-bearer-token" > "$creds_dir/bearer-token"
/usr/bin/python3 -c "import base64; print(base64.b64encode(b'test-secret-12345678').decode())" \
    > "$creds_dir/hmac-secret"

# ── Run 1: scheduled scan (no trigger file) ──────────────────────────────────

print ""
print "=== PAT-45 daemon end-to-end smoke test ==="
print ""
print "Run 1: scheduled scan"

PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir" \
PATCHED_PROV_QUEUE="$prov_queue" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file" \
PATCHED_API_URL="http://localhost:0" \
zsh "$DAEMON" >/dev/null 2>&1
run1_rc=$?

assert_pass "scan run exits 0 (no runtime errors incl. local-outside-function)" $run1_rc
assert_file_exists "scan run writes status file" "$state_dir/update-status.json"

# Verify engine was NOT called in scan mode (empty allowlist → 0 labels → 0 calls).
engine_calls=$(cat "$call_count_file" 2>/dev/null || echo 0)
assert_eq "scan mode: engine called 0 times (zero full-artifact downloads)" "0" "$engine_calls"

# Verify the status file is valid JSON with expected top-level fields.
status_valid=$(/usr/bin/python3 -c "
import json, sys
try:
    d = json.load(open('$state_dir/update-status.json'))
    required = {'schema_version', 'generated_at', 'overall_state', 'apps'}
    missing = required - set(d.keys())
    if missing:
        print('missing fields: ' + ', '.join(missing))
    else:
        print('ok')
except Exception as e:
    print('error: ' + str(e))
" 2>/dev/null)
assert_eq "scan run: status file is valid JSON with required fields" "ok" "$status_valid"

# Validate against the schema (skip if jsonschema not installed).
schema_result=$(/usr/bin/python3 -c "
import json, sys
try:
    import jsonschema
except ImportError:
    print('skip:no-jsonschema'); sys.exit(0)
schema_path = '${0:a:h}/../contracts/update-status.schema.json'
schema = json.load(open(schema_path))
doc = json.load(open('$state_dir/update-status.json'))
try:
    jsonschema.validate(doc, schema)
    print('valid')
except jsonschema.ValidationError as e:
    print('invalid: ' + e.message)
" 2>/dev/null)
if [[ "$schema_result" == "skip:no-jsonschema" ]]; then
    print "  SKIP  [schema validation — jsonschema not installed]"
elif [[ "$schema_result" == "valid" ]]; then
    print "  PASS  [scan run: status file validates against schema]"
    (( PASS++ ))
else
    print "  FAIL  [scan run: status file failed schema validation: $schema_result]"
    (( FAIL++ ))
fi

# ── Run 2: mirror manifest refresh (PAT-896 regression guard) ───────────────
#
# with_proxy() must be defined before its first call site (the mirror-manifest
# refresh below) or the whole PAT-500 CDN-mirror feature is dead for any
# tenant with MIRROR_CDN_BASE set. It was previously defined 537 lines after
# that call, so zsh raised "command not found" there at script-execution time
# (the script's own `2>/dev/null` on that call swallows the message, so the
# only symptom is the surrounding if/else silently logging a benign-looking
# network-error WARN and the manifest never populating). Serves the manifest
# fixture from a file:// URL so this needs no network access and stays
# deterministic.

print ""
print "Static check: with_proxy defined before its first call site"

with_proxy_def_line=$(grep -n '^with_proxy() {' "$DAEMON" | head -1 | cut -d: -f1)
with_proxy_first_call_line=$(grep -n 'with_proxy "' "$DAEMON" | head -1 | cut -d: -f1)
if [[ -n "$with_proxy_def_line" && -n "$with_proxy_first_call_line" \
      && "$with_proxy_def_line" -lt "$with_proxy_first_call_line" ]]; then
    print "  PASS  [with_proxy() defined (line $with_proxy_def_line) before first call (line $with_proxy_first_call_line)]"
    (( PASS++ ))
else
    print "  FAIL  [with_proxy() definition (line ${with_proxy_def_line:-?}) not before first call (line ${with_proxy_first_call_line:-?})]"
    (( FAIL++ ))
fi

print ""
print "Run 2: mirror manifest refresh (MIRROR_CDN_BASE set)"

cdn_dir="$tmpdir/cdn/mirrors"
mkdir -p "$cdn_dir"
manifest_fixture='{"schema_version":1,"labels":{}}'
print -r -- "$manifest_fixture" > "$cdn_dir/manifest.json"

state_dir2="$tmpdir/state2"
mkdir -p "$state_dir2"
log_file2="$tmpdir/update2.log"

PATCHED_BUNDLE_DIR="$bundle_dir" \
PATCHED_STATE_DIR="$state_dir2" \
PATCHED_PROV_QUEUE="$prov_queue" \
PATCHED_CREDS_DIR="$creds_dir" \
PATCHED_LOG_FILE="$log_file2" \
PATCHED_API_URL="http://localhost:0" \
PATCHED_MIRROR_CDN_BASE="file://$tmpdir/cdn" \
zsh "$DAEMON" >/dev/null 2>&1
run2_rc=$?

assert_pass "mirror run exits 0" $run2_rc
assert_file_exists "mirror manifest cached to state dir" "$state_dir2/mirror-manifest.json"

warn_logged=$(grep -c "could not fetch mirror manifest" "$log_file2" 2>/dev/null)
[[ -z "$warn_logged" ]] && warn_logged=0
assert_eq "refresh does not fall into the swallowed-error WARN branch" "0" "$warn_logged"

refreshed_logged=$(grep -c "Mirror manifest refreshed from" "$log_file2" 2>/dev/null)
[[ -z "$refreshed_logged" ]] && refreshed_logged=0
assert_eq "log shows the refreshed-manifest success line" "1" "$refreshed_logged"

mirror_content=$(cat "$state_dir2/mirror-manifest.json" 2>/dev/null)
assert_eq "cached manifest content matches the served fixture" "$manifest_fixture" "$mirror_content"

# ── summary ───────────────────────────────────────────────────────────────────

print ""
print "Results: $PASS passed, $FAIL failed"
print ""

(( FAIL == 0 ))
