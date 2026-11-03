#!/bin/zsh
##############################################################################
# test-os-update-payload.zsh — PAT-1833 inventory upload contract tests.
#
# Extracts and exercises the exact sentinel-delimited merge helper shipped in
# macos/patched-upload.sh. No credentials, root daemon, queue, or network.
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPLOAD_SH="$SCRIPT_DIR/patched-upload.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-os-update-payload-block.XXXXXX")
awk '/PATCHED_OS_UPDATE_PAYLOAD_START/{f=1;next} /PATCHED_OS_UPDATE_PAYLOAD_END/{f=0} f' \
    "$UPLOAD_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_OS_UPDATE_PAYLOAD block from $UPLOAD_SH"
    exit 1
fi
source "$BLOCK_TMP"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.os-update-payload-test.XXXXXX")
trap 'rm -rf "$WORK" "$BLOCK_TMP"' EXIT
SOURCE="$WORK/inventory.json"
STATUS="$WORK/update-status.json"
OUTPUT="$WORK/output.json"
NOW_EPOCH=1789776000 # 2026-09-19T00:00:00Z

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

json_eval() {
    "$PYTHON3" -c 'import json,sys; obj=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$1" "$2" 2>/dev/null
}

write_source() {
    print -r -- '{"schema_version":3,"device":{"hw_uuid":"mac-test"},"apps":[],"os_update":{"state":"up_to_date"}}' > "$SOURCE"
}

write_status() {
    local checked_at="$1"
    print -r -- "{\"schema_version\":1,\"generated_at\":\"$checked_at\",\"overall_state\":\"unknown\",\"apps\":[],\"os_update\":{\"installed_os\":\"26.0\",\"latest_os\":null,\"target_os\":\"26.1\",\"state\":\"update_required\",\"severity\":\"high\",\"security_relevant\":true,\"actively_exploited\":false,\"deadline\":null,\"deferrals_remaining\":2,\"release_age_days\":10,\"checked_at\":\"$checked_at\"}}" > "$STATUS"
}

echo "--- valid computed evidence is included unchanged"
write_source
write_status "2026-09-18T23:45:00Z"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "os_update is present" "$([[ "$(json_eval "$OUTPUT" "'os_update' in obj")" == "True" ]] && echo 1 || echo 0)"
chk "nullable latest_os remains JSON null" "$([[ "$(json_eval "$OUTPUT" 'obj["os_update"]["latest_os"] is None')" == "True" ]] && echo 1 || echo 0)"
chk "checked_at is preserved, not replaced by upload time" "$([[ "$(json_eval "$OUTPUT" 'obj["os_update"]["checked_at"]')" == "2026-09-18T23:45:00Z" ]] && echo 1 || echo 0)"
chk "required integer and boolean types remain exact" "$([[ "$(json_eval "$OUTPUT" 'type(obj["os_update"]["deferrals_remaining"]).__name__ + ":" + type(obj["os_update"]["security_relevant"]).__name__')" == "int:bool" ]] && echo 1 || echo 0)"
chk "unrelated queued inventory remains unchanged" "$([[ "$(json_eval "$OUTPUT" 'obj["device"]["hw_uuid"]')" == "mac-test" ]] && echo 1 || echo 0)"

echo "--- optional latest_os absent (not just explicit null) is also accepted"
print -r -- "{\"schema_version\":1,\"generated_at\":\"2026-09-18T23:45:00Z\",\"overall_state\":\"unknown\",\"apps\":[],\"os_update\":{\"installed_os\":\"26.0\",\"target_os\":\"26.1\",\"state\":\"update_required\",\"severity\":\"high\",\"security_relevant\":true,\"actively_exploited\":false,\"deferrals_remaining\":2,\"checked_at\":\"2026-09-18T23:45:00Z\"}}" > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "os_update with latest_os key entirely absent is still included" "$([[ "$(json_eval "$OUTPUT" "'os_update' in obj")" == "True" ]] && echo 1 || echo 0)"
chk "an absent latest_os key round-trips as absent, not fabricated null" "$([[ "$(json_eval "$OUTPUT" "'latest_os' not in obj['os_update']")" == "True" ]] && echo 1 || echo 0)"

echo "--- unknown state with no target_os (PAT-2133) is included, never given a target"
print -r -- "{\"schema_version\":1,\"generated_at\":\"2026-09-18T23:45:00Z\",\"overall_state\":\"unknown\",\"apps\":[],\"os_update\":{\"installed_os\":\"26.0\",\"latest_os\":null,\"state\":\"unknown\",\"severity\":\"none\",\"security_relevant\":false,\"actively_exploited\":false,\"deadline\":null,\"deferrals_remaining\":5,\"release_age_days\":null,\"checked_at\":\"2026-09-18T23:45:00Z\"}}" > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "os_update with target_os absent is included" "$([[ "$(json_eval "$OUTPUT" "'os_update' in obj")" == "True" ]] && echo 1 || echo 0)"
chk "an absent target_os stays absent, not fabricated" "$([[ "$(json_eval "$OUTPUT" "'target_os' not in obj['os_update']")" == "True" ]] && echo 1 || echo 0)"
chk "the unknown state is carried through" "$([[ "$(json_eval "$OUTPUT" 'obj["os_update"]["state"]')" == "unknown" ]] && echo 1 || echo 0)"

print -r -- "{\"os_update\":{\"installed_os\":\"26.0\",\"target_os\":null,\"state\":\"unknown\",\"severity\":\"none\",\"security_relevant\":false,\"actively_exploited\":false,\"deferrals_remaining\":5,\"checked_at\":\"2026-09-18T23:45:00Z\"}}" > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "explicit null target_os is included as null" "$([[ "$(json_eval "$OUTPUT" 'obj["os_update"]["target_os"] is None')" == "True" ]] && echo 1 || echo 0)"

print -r -- "{\"os_update\":{\"installed_os\":\"26.0\",\"target_os\":26,\"state\":\"unknown\",\"severity\":\"none\",\"security_relevant\":false,\"actively_exploited\":false,\"deferrals_remaining\":5,\"checked_at\":\"2026-09-18T23:45:00Z\"}}" > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "non-string target_os is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

echo "--- exact 48-hour boundary is accepted"
write_status "2026-09-17T00:00:00Z"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "48-hour-old evidence is included" "$([[ "$(json_eval "$OUTPUT" "'os_update' in obj")" == "True" ]] && echo 1 || echo 0)"

echo "--- stale, future, partial, malformed, and unavailable evidence is omitted"
write_status "2026-09-16T23:59:59Z"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "older than 48 hours is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

write_status "2026-09-19T00:00:01Z"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "future checked_at is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

print -r -- '{"os_update":{"installed_os":"26.0","state":"unknown"}}' > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "partial block is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

print -r -- '{not-json' > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "malformed status is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

print -r -- '{"os_update":null}' > "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "explicitly unavailable block is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

rm -f "$STATUS"
patched_os_update_merge_into_payload "$SOURCE" "$STATUS" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "absent status is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"
chk "unavailable evidence removes any stale queued os_update" "$([[ "$(json_eval "$OUTPUT" 'obj.get("os_update")')" == "None" ]] && echo 1 || echo 0)"
chk "queued payload is never mutated" "$([[ "$(json_eval "$SOURCE" "'os_update' in obj")" == "True" ]] && echo 1 || echo 0)"

mkdir "$WORK/unreadable-status"
patched_os_update_merge_into_payload "$SOURCE" "$WORK/unreadable-status" "$OUTPUT" "$NOW_EPOCH" >/dev/null
chk "unreadable status path is omitted" "$([[ "$(json_eval "$OUTPUT" "'os_update' not in obj")" == "True" ]] && echo 1 || echo 0)"

echo "--- uploader wiring merges immediately before signing"
merge_call_line=$(grep -n 'if ! patched_os_update_merge_into_payload' "$UPLOAD_SH" | cut -d: -f1)
sign_line=$(grep -n 'SIGNATURE=$(compute_hmac "$UPLOAD_FILE"' "$UPLOAD_SH" | cut -d: -f1)
chk "main loop invokes the merge exactly once" "$([[ -n "$merge_call_line" && "$(grep -c 'if ! patched_os_update_merge_into_payload' "$UPLOAD_SH")" == "1" ]] && echo 1 || echo 0)"
chk "merge output is prepared before HMAC signing" "$(( merge_call_line < sign_line ))"

echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
