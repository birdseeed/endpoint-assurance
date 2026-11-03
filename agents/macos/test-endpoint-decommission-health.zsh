#!/bin/zsh
##############################################################################
# test-endpoint-decommission-health.zsh — PAT-1126 acceptance test for the
# degraded-health safety net.
#
# macos/install.sh now always installs the endpoint/ bundle alongside the
# collector, so collector-only should not be reachable through this repo's
# own installers/packaging any more. This test covers the belt-and-braces
# side of that ticket: a stale pre-PAT-1126 install (or a bundling step
# bypassed some other way) could still leave a box with no decommission
# mechanism at all. patched-upload.sh's PATCHED_ENDPOINT_DECOMMISSION_HEALTH
# block is the safety net — it must report a capability_missing /
# endpoint_decommission_daemon fault through the shared agent_health store
# whenever com.patched.config-poll's LaunchDaemon plist is absent OR present
# but not loaded, and must report a clean success when it is both present
# and loaded.
#
# Extracts the SHIPPED PATCHED_ENDPOINT_DECOMMISSION_HEALTH block (sentinel
# markers) from macos/patched-upload.sh — same extraction-and-direct-call
# convention as macos/test-agent-health-capability.zsh and
# endpoint/test-agent-tier-default.zsh — and drives it against a scratch
# store + a stubbed launchctl on PATH. No root, no real LaunchDaemons.
#
# Run: zsh macos/test-endpoint-decommission-health.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPLOAD_SH="$SCRIPT_DIR/patched-upload.sh"
PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] || PYTHON3=$(command -v python3)

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-endpoint-decommission-health-block.XXXXXX")
awk '/PATCHED_ENDPOINT_DECOMMISSION_HEALTH_START/{f=1;next} /PATCHED_ENDPOINT_DECOMMISSION_HEALTH_END/{f=0} f' \
    "$UPLOAD_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_ENDPOINT_DECOMMISSION_HEALTH block from $UPLOAD_SH"
    exit 1
fi

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.endpoint-decommission-health-test.XXXXXX")
trap 'rm -rf "$WORK" "$BLOCK_TMP"' EXIT

json_get() {
    "$PYTHON3" -c '
import json, sys
obj = json.loads(sys.argv[1])
print(eval(sys.argv[2]))
' "$1" "$2" 2>/dev/null
}

# stub_launchctl <exit-code>
#   Writes a stub launchctl to $WORK/stubbin that always exits with the
#   given code, and prepends $WORK/stubbin to PATH for this test.
stub_launchctl() {
    local rc="$1"
    mkdir -p "$WORK/stubbin"
    cat > "$WORK/stubbin/launchctl" <<EOF
#!/bin/sh
exit $rc
EOF
    chmod +x "$WORK/stubbin/launchctl"
}

run_block() {
    # $1 = plist path (may or may not exist), $2 = store path
    local plist="$1" store="$2"
    (
        export PATCHED_AGENT_HEALTH_STORE="$store"
        export PATCHED_ENDPOINT_CONFIG_POLL_PLIST="$plist"
        export PATCHED_ENDPOINT_CONFIG_POLL_LABEL="com.patched.config-poll"
        export PATH="$WORK/stubbin:$PATH"
        SCRIPT_DIR_UPLOAD="$SCRIPT_DIR"
        source "$SCRIPT_DIR/lib/agent_health.sh"
        source "$BLOCK_TMP"
    )
}

# ============================================================================
echo "\n--- [1] plist absent — fault recorded, reason launchdaemon_absent ---"
STORE_1="$WORK/case1/.agent-health.json"
mkdir -p "$WORK/case1"
PLIST_1="$WORK/case1/does-not-exist.plist"
stub_launchctl 0   # irrelevant here — plist absence is checked first

run_block "$PLIST_1" "$STORE_1"

degraded1=$(
    export PATCHED_AGENT_HEALTH_STORE="$STORE_1"
    source "$SCRIPT_DIR/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)
chk "exactly one active fault" \
    "$([[ "$(json_get "$degraded1" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
chk "kind is capability_missing" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["kind"]')" == "capability_missing" ]] && echo 1 || echo 0)"
chk "subject is endpoint_decommission_daemon" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["subject"]')" == "endpoint_decommission_daemon" ]] && echo 1 || echo 0)"
chk "reason is launchdaemon_absent" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["reason"]')" == "launchdaemon_absent" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [2] plist present but launchctl reports it not loaded — fault recorded ---"
STORE_2="$WORK/case2/.agent-health.json"
mkdir -p "$WORK/case2"
PLIST_2="$WORK/case2/com.patched.config-poll.plist"
: > "$PLIST_2"   # present on disk
stub_launchctl 1   # `launchctl print system/<label>` fails -> not loaded

run_block "$PLIST_2" "$STORE_2"

degraded2=$(
    export PATCHED_AGENT_HEALTH_STORE="$STORE_2"
    source "$SCRIPT_DIR/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)
chk "exactly one active fault" \
    "$([[ "$(json_get "$degraded2" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
chk "reason is launchdaemon_not_loaded" \
    "$([[ "$(json_get "$degraded2" 'obj[0]["reason"]')" == "launchdaemon_not_loaded" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [3] plist present AND loaded — success recorded, nothing degraded ---"
STORE_3="$WORK/case3/.agent-health.json"
mkdir -p "$WORK/case3"
PLIST_3="$WORK/case3/com.patched.config-poll.plist"
: > "$PLIST_3"
stub_launchctl 0   # `launchctl print system/<label>` succeeds -> loaded

run_block "$PLIST_3" "$STORE_3"

degraded3=$(
    export PATCHED_AGENT_HEALTH_STORE="$STORE_3"
    source "$SCRIPT_DIR/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)
chk "nothing degraded when the daemon is present and loaded" \
    "$([[ "$degraded3" == "[]" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [4] recovery: a box that WAS degraded clears on the next run once loaded ---"
STORE_4="$WORK/case4/.agent-health.json"
mkdir -p "$WORK/case4"
PLIST_4="$WORK/case4/com.patched.config-poll.plist"
# First run: absent -> degraded.
stub_launchctl 0
run_block "$WORK/case4/still-absent.plist" "$STORE_4"
degraded4a=$(
    export PATCHED_AGENT_HEALTH_STORE="$STORE_4"
    source "$SCRIPT_DIR/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)
chk "first run (absent) is degraded" \
    "$([[ "$(json_get "$degraded4a" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"

# Second run: now present + loaded -> clears.
: > "$PLIST_4"
run_block "$PLIST_4" "$STORE_4"
degraded4b=$(
    export PATCHED_AGENT_HEALTH_STORE="$STORE_4"
    source "$SCRIPT_DIR/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)
chk "second run (present+loaded) clears the fault" \
    "$([[ "$degraded4b" == "[]" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
