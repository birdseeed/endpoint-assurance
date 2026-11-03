#!/bin/zsh
##############################################################################
# test-agent-health-capability.zsh — PAT-1065/PAT-1029 acceptance test.
#
# Extracts the SHIPPED PATCHED_AGENT_HEALTH_CAPABILITY block (sentinel
# markers) from macos/patched-upload.sh — the "AGENT HEALTH" lib-source plus
# both lib-missing checks (browser_extension_control.sh /
# browser_extension_removal.sh) — and sources it directly against a scratch
# SCRIPT_DIR_UPLOAD, no root, no network, no real daemon run. Same
# extraction-and-direct-call convention as endpoint/test-agent-tier-default.zsh
# and endpoint/test-agent-health.zsh.
#
# PAT-1029 acceptance scenario, run end to end here: remove/rename the
# extension-control lib file (browser_extension_control.sh) while the
# removal lib (browser_extension_removal.sh) stays present, run the real
# shipped code path, confirm:
#   - a capability_missing/extension_blocklist fault is recorded and shows
#     up in the emitted degraded set;
#   - the extension_removal lib being genuinely present records success
#     instead, and does NOT appear in the degraded set — proving the two
#     capabilities are tracked independently (this repo's chosen design:
#     see the comment above the ext_blocklist block in patched-upload.sh for
#     why one shared subject would have let one of these silently clobber
#     the other's outcome within the same run);
#   - merging into a representative payload carries the capability_missing
#     entry for extension_blocklist while unaffected payload sections
#     (device_id, hardware, apps) are unchanged.
#
# Run: zsh macos/test-agent-health-capability.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPLOAD_SH="$SCRIPT_DIR/patched-upload.sh"
PYTHON3="/usr/bin/python3"

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-agent-health-capability-block.XXXXXX")
awk '/PATCHED_AGENT_HEALTH_CAPABILITY_START/{f=1;next} /PATCHED_AGENT_HEALTH_CAPABILITY_END/{f=0} f' \
    "$UPLOAD_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_AGENT_HEALTH_CAPABILITY block from $UPLOAD_SH"
    exit 1
fi

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.agent-health-capability-test.XXXXXX")
trap 'rm -rf "$WORK" "$BLOCK_TMP"' EXIT

json_get() {
    "$PYTHON3" -c '
import json, sys
obj = json.loads(sys.argv[1])
print(eval(sys.argv[2]))
' "$1" "$2" 2>/dev/null
}

# --- Scratch SCRIPT_DIR_UPLOAD: a real lib/agent_health.sh (the actual
# shipped copy — this test must exercise real code, not a stand-in), plus a
# scratch lib/browser_extension_removal.sh (present — content is irrelevant,
# the block never sources it when AC_GATE_ALLOWED=0) and NO
# browser_extension_control.sh (the PAT-1029 "removed/renamed" scenario). ---
mkdir -p "$WORK/lib"
cp "$SCRIPT_DIR/lib/agent_health.sh" "$WORK/lib/agent_health.sh"
: > "$WORK/lib/browser_extension_removal.sh"   # present; not sourced (AC_GATE_ALLOWED=0)
# browser_extension_control.sh deliberately absent.

export PATCHED_AGENT_HEALTH_STORE="$WORK/.agent-health.json"

echo "\n--- [1] extension-control lib missing, extension-removal lib present ---"
(
    SCRIPT_DIR_UPLOAD="$WORK"
    AC_GATE_ALLOWED=0
    source "$BLOCK_TMP"
)

degraded=$(
    source "$WORK/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)

chk "exactly one active fault (extension-control missing only)" \
    "$([[ "$(json_get "$degraded" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
chk "kind is capability_missing" \
    "$([[ "$(json_get "$degraded" 'obj[0]["kind"]')" == "capability_missing" ]] && echo 1 || echo 0)"
chk "subject is extension_blocklist (distinct from extension_removal)" \
    "$([[ "$(json_get "$degraded" 'obj[0]["subject"]')" == "extension_blocklist" ]] && echo 1 || echo 0)"
chk "reason is lib_not_installed" \
    "$([[ "$(json_get "$degraded" 'obj[0]["reason"]')" == "lib_not_installed" ]] && echo 1 || echo 0)"
chk "no entry for extension_removal (that lib IS present -> recorded as success, not a fault)" \
    "$([[ "$(json_get "$degraded" '1 if any(e["subject"]=="extension_removal" for e in obj) else 0')" == "0" ]] && echo 1 || echo 0)"

echo "\n--- [2] merge into a representative payload: unaffected sections unchanged ---"
SRC_PAYLOAD="$WORK/inventory-src.json"
DST_PAYLOAD="$WORK/inventory-merged.json"
cat > "$SRC_PAYLOAD" <<'JSONEOF'
{"device_id":"unaffected-device","hardware":{"model":"MacBookPro18,1"},"apps":[{"name":"Safari","version":"17.4.1"}],"compliance_findings":[]}
JSONEOF

(
    source "$WORK/lib/agent_health.sh"
    patched_agent_health_merge_into_payload "$SRC_PAYLOAD" "$DST_PAYLOAD"
)
merge_rc=$?
chk "merge succeeds" "$(( merge_rc == 0 ))"

merged=$(cat "$DST_PAYLOAD" 2>/dev/null)
chk "merged payload's agent_health.degraded carries the capability_missing/extension_blocklist entry" \
    "$(json_get "$merged" '1 if any(e.get("kind")=="capability_missing" and e.get("subject")=="extension_blocklist" for e in obj["agent_health"]["degraded"]) else 0')"
chk "unaffected section device_id unchanged" \
    "$([[ "$(json_get "$merged" 'obj["device_id"]')" == "unaffected-device" ]] && echo 1 || echo 0)"
chk "unaffected section hardware unchanged" \
    "$([[ "$(json_get "$merged" 'obj["hardware"]["model"]')" == "MacBookPro18,1" ]] && echo 1 || echo 0)"
chk "unaffected section apps unchanged" \
    "$([[ "$(json_get "$merged" 'obj["apps"][0]["name"]')" == "Safari" ]] && echo 1 || echo 0)"
chk "unaffected section compliance_findings unchanged" \
    "$([[ "$(json_get "$merged" 'obj["compliance_findings"]')" == "[]" ]] && echo 1 || echo 0)"

echo "\n--- [3] both libs present -> both record success, nothing degraded ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case3/.agent-health.json"
mkdir -p "$WORK/case3"
: > "$WORK/lib/browser_extension_control.sh"   # now present too

(
    SCRIPT_DIR_UPLOAD="$WORK"
    AC_GATE_ALLOWED=0
    source "$BLOCK_TMP"
)

degraded3=$(
    source "$WORK/lib/agent_health.sh"
    patched_agent_health_emit_degraded_json
)
chk "nothing degraded when both libs are present" \
    "$([[ "$degraded3" == "[]" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
