#!/bin/zsh
##############################################################################
# test-trigger-parsing.zsh: PAT-1059, the trigger-consumption fail-open.
#
# endpoint/patched-update.sh runs as root from a LaunchDaemon and consumes at
# most one .trigger file per run from $TRIGGER_DIR (world-writable-with-
# sticky-bit by deliberate design — the unprivileged, per-user menu-bar agent
# is the legitimate writer of real scan/uninstall/os_defer triggers; deploy
# was retired under PAT-1620 along with the Self Service applications that
# used to write it). os_defer markers are a persistent, separately-tallied
# exception to the "one trigger consumed per run" model this file tests —
# see the os_update posture computation elsewhere in patched-update.sh, not
# parse_trigger() below.
# Two related P0 fail-opens in that consumption logic, both fixed here:
#
#   1. Type parsing used to funnel EVERY value that wasn't literally "scan"
#      or "uninstall" into RUN_MODE="install" — including a missing "type"
#      key (legitimate: the retired Self Service deploy historically wrote no "type"
#      at all) AND any garbage/unrecognised value (typo, corruption, or a
#      crafted trigger with "type":"anything"). PAT-1620 retired the deploy
#      trigger type along with the Self Service applications that used to
#      write it: only "scan" and "uninstall" are accepted now; a missing
#      type, an explicit "deploy", or anything else is rejected outright
#      (RUN_MODE stays "scan").
#   2. Missing/invalid "labels" always produced TRIGGER_LABELS="", which the
#      loop-side filter reads as "no filter — act on the whole allowlist".
#      Correct for scan mode (read-only, never installs); wrong for install
#      mode, where it meant a trigger as minimal as {} or
#      {"type":"whatever"} installed every policy-enabled label as root.
#      Now RUN_MODE=="install" with empty TRIGGER_LABELS means zero labels
#      processed, never the whole allowlist. The documented TRIGGER_LABELS
#      == "*" wildcard (menubar/PatchedUpdater/StatusStore.swift's
#      requestUpdate(labels:): "Pass a specific Installomator label or
#      ["*"] to run all pending updates") is a distinct, deliberate
#      non-empty value and is NOT affected by this fix — it still means
#      "run everything" in both scan and install mode (round 2, Codex
#      non-author review P1: the first cut of this fix wrongly collapsed
#      the wildcard into the empty-means-nothing case for install mode).
#
# This tests parse_trigger() (PATCHED_TRIGGER_PARSE sentinel block) and the
# loop-side label filter (PATCHED_TRIGGER_LABEL_FILTER sentinel block),
# extracted from the SHIPPED patched-update.sh (not a copy), same convention
# as test-agent-tier-default.zsh.
#
# Run: zsh endpoint/test-trigger-parsing.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"

PARSE_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-trigger-parse-block.XXXXXX")
awk '/PATCHED_TRIGGER_PARSE_START/{f=1;next} /PATCHED_TRIGGER_PARSE_END/{f=0} f' \
    "$UPDATE_SH" > "$PARSE_TMP"
if [[ ! -s "$PARSE_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_TRIGGER_PARSE block from $UPDATE_SH"
    exit 1
fi

FILTER_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-trigger-filter-block.XXXXXX")
awk '/PATCHED_TRIGGER_LABEL_FILTER_START/{f=1;next} /PATCHED_TRIGGER_LABEL_FILTER_END/{f=0} f' \
    "$UPDATE_SH" > "$FILTER_TMP"
if [[ ! -s "$FILTER_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_TRIGGER_LABEL_FILTER block from $UPDATE_SH"
    exit 1
fi
FILTER_BLOCK=$(<"$FILTER_TMP")

CONSUME_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-trigger-consume-block.XXXXXX")
awk '/PATCHED_TRIGGER_CONSUME_START/{f=1;next} /PATCHED_TRIGGER_CONSUME_END/{f=0} f' \
    "$UPDATE_SH" > "$CONSUME_TMP"
if [[ ! -s "$CONSUME_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_TRIGGER_CONSUME block from $UPDATE_SH"
    exit 1
fi

PYTHON3="/usr/bin/python3"
BUNDLE_DIR="${TMPDIR:-/tmp}/.patched-trigger-parse-test-nonexistent-bundle"  # deliberately absent: uninstall branch must no-op, not fail

source "$PARSE_TMP"

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.trigger-parse-test.XXXXXX")
trap 'rm -rf "$WORK"; rm -f "$PARSE_TMP" "$FILTER_TMP" "$CONSUME_TMP"' EXIT

TRIG_FILE="$WORK/test.trigger"

# write_trigger <json>
write_trigger() {
    print -r -- "$1" > "$TRIG_FILE"
}

# reset_run_state: mirrors the defaults patched-update.sh sets right before
# it ever looks at a trigger file.
reset_run_state() {
    RUN_MODE="scan"
    TRIGGER_LABELS=""
    RUN_TRIGGER="scheduled"
}

# run_filter <run_mode> <trigger_labels> <label1> [label2 ...]
#   Feeds each label through the extracted PATCHED_TRIGGER_LABEL_FILTER
#   block inside a real loop and echoes which labels survived. Uses eval
#   rather than source: zsh's `continue`/`break` do not cross a `source`
#   file boundary even from inside an enclosing loop (confirmed empirically —
#   a sourced file's own top-level is its own jump-target scope), but eval'd
#   text is parsed inline and behaves exactly like the shipped inline block.
run_filter() {
    local RUN_MODE="$1" TRIGGER_LABELS="$2"
    shift 2
    local label processed=()
    for label in "$@"; do
        eval "$FILTER_BLOCK"
        processed+=("$label")
    done
    echo "${processed[@]}"
}

# =============================================================================
echo "=== parse_trigger(): type handling ==="

echo "[1] missing 'type' key entirely -> rejected (PAT-1620: deploy retired), RUN_MODE stays scan"
reset_run_state
write_trigger '{"labels": ["slack"]}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[2] explicit type:\"deploy\" -> rejected (PAT-1620: deploy retired), same as missing"
reset_run_state
write_trigger '{"type": "deploy", "labels": ["slack"]}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[3] type:\"scan\" -> RUN_MODE=scan"
reset_run_state
write_trigger '{"type": "scan"}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=manual" "$([[ "$RUN_TRIGGER" == "manual" ]] && echo 1 || echo 0)"

echo "[4] type:\"uninstall\" -> uninstall path unaffected (RUN_MODE=scan, RUN_TRIGGER=manual)"
reset_run_state
write_trigger '{"type": "uninstall", "labels": ["com.example.app"]}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=manual" "$([[ "$RUN_TRIGGER" == "manual" ]] && echo 1 || echo 0)"

echo "[5] type:\"garbage\" (unrecognised string) -> rejected, RUN_MODE stays scan, NOT install"
reset_run_state
write_trigger '{"type": "garbage", "labels": ["slack"]}'
parse_trigger "$TRIG_FILE"
echo "  RUN_MODE=$RUN_MODE RUN_TRIGGER=$RUN_TRIGGER"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[6] type: 123 (non-string) -> rejected, RUN_MODE stays scan, NOT install"
reset_run_state
write_trigger '{"type": 123, "labels": ["slack"]}'
parse_trigger "$TRIG_FILE"
echo "  RUN_MODE=$RUN_MODE RUN_TRIGGER=$RUN_TRIGGER"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[7] type: null -> rejected, RUN_MODE stays scan, NOT install"
reset_run_state
write_trigger '{"type": null, "labels": ["slack"]}'
parse_trigger "$TRIG_FILE"
echo "  RUN_MODE=$RUN_MODE RUN_TRIGGER=$RUN_TRIGGER"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[8] the exact P0 PoC: {} (empty object) -> rejected (PAT-1620: missing type is no longer deploy)"
reset_run_state
write_trigger '{}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[8b] the exact P0 PoC: {\"type\": \"whatever\"} -> rejected, RUN_MODE stays scan, NOT install"
reset_run_state
write_trigger '{"type": "whatever"}'
parse_trigger "$TRIG_FILE"
echo "  RUN_MODE=$RUN_MODE RUN_TRIGGER=$RUN_TRIGGER"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"

# =============================================================================
echo
echo "=== parse_trigger(): a deploy-shaped trigger is rejected regardless of its labels ==="

echo "[9] missing 'labels' on a deploy-type trigger -> rejected (PAT-1620), not RUN_MODE=install"
reset_run_state
write_trigger '{"type": "deploy"}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[10] empty labels: [] on a deploy-type trigger -> same as missing, still rejected"
reset_run_state
write_trigger '{"type": "deploy", "labels": []}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[11] non-empty valid labels but no 'type' key -> still rejected, labels alone cannot imply deploy"
reset_run_state
write_trigger '{"labels": ["some-real-label"]}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "RUN_TRIGGER=trigger_type_rejected" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

# =============================================================================
echo
echo "=== loop-side label filter (PATCHED_TRIGGER_LABEL_FILTER): the actual privileged boundary ==="

echo "[12] install-mode, empty TRIGGER_LABELS -> zero labels processed, not the whole allowlist (THE P0)"
result=$(run_filter "install" "" alpha beta gamma)
echo "  processed: '$result'"
chk "no labels survive the filter" "$([[ -z "$result" ]] && echo 1 || echo 0)"

echo "[13] install-mode, non-empty TRIGGER_LABELS -> only the requested label survives"
result=$(run_filter "install" "beta" alpha beta gamma)
echo "  processed: '$result'"
chk "exactly the requested label survives" "$([[ "$result" == "beta" ]] && echo 1 || echo 0)"

# PAT-1059 round 2 (Codex non-author review, P1): the round-1 fix collapsed
# the documented "*" wildcard ("run everything", see
# menubar/PatchedUpdater/StatusStore.swift's requestUpdate(labels:) doc
# comment: 'Pass a specific Installomator label or ["*"] to run all pending
# updates') into the same bucket as genuinely empty/missing labels for
# install mode. TRIGGER_LABELS=="*" is a deliberate non-empty value and
# must still mean "no filter, act on the whole allowlist" in install mode,
# exactly like it already does in scan mode -- only truly empty
# TRIGGER_LABELS means "install nothing".
echo "[13b] install-mode, TRIGGER_LABELS=\"*\" (documented wildcard) -> every label processed, not zero"
result=$(run_filter "install" "*" alpha beta gamma)
echo "  processed: '$result'"
chk "the wildcard still runs every label in install mode (not collapsed into the empty-means-nothing case)" \
    "$([[ "$result" == "alpha beta gamma" ]] && echo 1 || echo 0)"

echo "[14] scan-mode, empty TRIGGER_LABELS (ordinary scheduled scan, no trigger at all) -> whole allowlist, unaffected"
result=$(run_filter "scan" "" alpha beta gamma)
echo "  processed: '$result'"
chk "all labels survive in scan mode with no trigger" "$([[ "$result" == "alpha beta gamma" ]] && echo 1 || echo 0)"

echo "[15] scan-mode, non-empty TRIGGER_LABELS (e.g. a scan-type trigger) -> filtered, unaffected by this fix"
result=$(run_filter "scan" "beta" alpha beta gamma)
echo "  processed: '$result'"
chk "only the requested label survives in scan mode too" "$([[ "$result" == "beta" ]] && echo 1 || echo 0)"

# =============================================================================
echo
echo "=== end-to-end: parse_trigger() + loop filter together, the full P0 scenario ==="

echo "[16] {} (empty object) trigger, end to end -> RUN_MODE never becomes install (PAT-1620)"
reset_run_state
write_trigger '{}'
parse_trigger "$TRIG_FILE"
result=$(run_filter "$RUN_MODE" "$TRIGGER_LABELS" slack zoom docker)
echo "  RUN_MODE=$RUN_MODE processed='$result'"
chk "RUN_MODE stays scan (missing type rejected, not deploy)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
# In scan mode the filter's "process everything" behaviour is harmless by
# design (test [14]) -- scan never installs, so which labels a scan touches
# is not a privilege question. The security property here is RUN_MODE
# itself, already asserted above.

echo "[17] {\"type\": \"whatever\"} trigger, end to end -> RUN_MODE never becomes install, nothing installed"
reset_run_state
write_trigger '{"type": "whatever", "labels": ["slack", "zoom", "docker"]}'
parse_trigger "$TRIG_FILE"
result=$(run_filter "$RUN_MODE" "$TRIGGER_LABELS" slack zoom docker)
echo "  RUN_MODE=$RUN_MODE processed='$result'"
chk "RUN_MODE stays scan (rejected type)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"

echo "[18] {\"labels\": [\"some-real-label\"]} (the historical, now-retired Self Service deploy shape) -> rejected, never installs"
reset_run_state
write_trigger '{"labels": ["some-real-label"]}'
parse_trigger "$TRIG_FILE"
result=$(run_filter "$RUN_MODE" "$TRIGGER_LABELS" some-real-label other-label)
echo "  RUN_MODE=$RUN_MODE processed='$result'"
chk "RUN_MODE stays scan (deploy retired, PAT-1620) -- never install, regardless of the filter's scan-mode output" \
    "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"

echo "[19] {\"type\": \"deploy\", \"labels\": []} -> rejected, RUN_MODE stays scan, never installs"
reset_run_state
write_trigger '{"type": "deploy", "labels": []}'
parse_trigger "$TRIG_FILE"
result=$(run_filter "$RUN_MODE" "$TRIGGER_LABELS" slack zoom)
echo "  RUN_MODE=$RUN_MODE processed='$result'"
chk "RUN_MODE stays scan (rejected, not install)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"

echo "[20] {\"type\": \"uninstall\", \"labels\": [\"com.example.app\"]} end to end -> scan mode, unaffected"
reset_run_state
write_trigger '{"type": "uninstall", "labels": ["com.example.app"]}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"

echo "[21] {\"type\": \"scan\"} end to end -> scan mode, unaffected"
reset_run_state
write_trigger '{"type": "scan"}'
parse_trigger "$TRIG_FILE"
chk "RUN_MODE=scan" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"

echo "[22] malformed trigger is selected, consumed and rejected without reaching an executor"
TRIGGER_DIR="$WORK/malformed-triggers"
mkdir -p "$TRIGGER_DIR"
malformed_trigger="$TRIGGER_DIR/malformed.trigger"
print -r -- '{"type":"uninstall","labels":[' > "$malformed_trigger"
reset_run_state
legacy_app_execution_enabled() { return 0; }
record_uninstall_trigger_authority_refusal() { :; }
log_jsonl() { :; }
BUNDLE_DIR="$WORK/bundle"
mkdir -p "$BUNDLE_DIR"
print '#!/bin/sh' > "$BUNDLE_DIR/patched-uninstall.sh"
print "touch '$WORK/uninstall-invoked'" >> "$BUNDLE_DIR/patched-uninstall.sh"
chmod 755 "$BUNDLE_DIR/patched-uninstall.sh"
source "$CONSUME_TMP" >/dev/null
chk "malformed trigger file consumed" "$([[ ! -e "$malformed_trigger" ]] && echo 1 || echo 0)"
chk "malformed trigger rejected as scan-only" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" && "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "malformed trigger did not reach uninstall executor" "$([[ ! -e "$WORK/uninstall-invoked" ]] && echo 1 || echo 0)"

echo "[23] oversized trigger is read only to its bound, consumed and rejected"
TRIGGER_DIR="$WORK/oversized-triggers"
mkdir -p "$TRIGGER_DIR"
oversized_trigger="$TRIGGER_DIR/oversized.trigger"
"$PYTHON3" - "$oversized_trigger" <<'PYEOF'
import sys
with open(sys.argv[1], 'wb') as handle:
    handle.write(b'{"type":"uninstall","labels":["')
    handle.write(b'A' * 70000)
    handle.write(b'"]}')
PYEOF
reset_run_state
source "$CONSUME_TMP" >/dev/null
chk "oversized trigger file consumed" "$([[ ! -e "$oversized_trigger" ]] && echo 1 || echo 0)"
chk "oversized trigger rejected as scan-only" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" && "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "oversized trigger did not reach uninstall executor" "$([[ ! -e "$WORK/uninstall-invoked" ]] && echo 1 || echo 0)"

echo "[24] uninstall identifiers retain exact UTF-8 through bounded encoded framing"
TRIGGER_DIR="$WORK/framed-triggers"
mkdir -p "$TRIGGER_DIR"
BUNDLE_DIR="$WORK/framed-bundle"
mkdir -p "$BUNDLE_DIR"
cat > "$BUNDLE_DIR/patched-uninstall.sh" <<'STUBEOF'
#!/bin/zsh
[[ "$#" -eq 2 && "$1" == "--app-id" && -n "$2" ]] || exit 97
/usr/bin/python3 - "$PATCHED_TEST_INVOCATIONS_FILE" "$2" <<'PYEOF'
import base64, sys
with open(sys.argv[1], 'a', encoding='ascii') as handle:
    handle.write(base64.b64encode(sys.argv[2].encode('utf-8')).decode('ascii') + '\n')
PYEOF
if [[ -n "${PATCHED_TEST_REFUSE_APP_ID:-}" && "$2" == "$PATCHED_TEST_REFUSE_APP_ID" ]]; then
    exit "${PATCHED_TEST_REFUSAL_EXIT:-78}"
fi
exit 0
STUBEOF
chmod 755 "$BUNDLE_DIR/patched-uninstall.sh"
LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=78
PATCHED_TEST_INVOCATIONS_FILE="$WORK/invocations.b64"
export PATCHED_TEST_INVOCATIONS_FILE
unset PATCHED_TEST_REFUSE_APP_ID
record_uninstall_trigger_authority_refusal() { :; }

newline_identifier=$'literal-Zm9vYmFy\nsecond-line-QUJDRA=='
"$PYTHON3" - "$TRIG_FILE" "$newline_identifier" <<'PYEOF'
import json, sys
with open(sys.argv[1], 'w', encoding='utf-8') as handle:
    json.dump({'type': 'uninstall', 'labels': [sys.argv[2]]}, handle)
PYEOF
: > "$PATCHED_TEST_INVOCATIONS_FILE"
reset_run_state
parse_trigger "$TRIG_FILE" >/dev/null
newline_round_trip=$("$PYTHON3" - "$PATCHED_TEST_INVOCATIONS_FILE" <<'PYEOF'
import base64, sys
lines = open(sys.argv[1], encoding='ascii').read().splitlines()
print(base64.b64decode(lines[0], validate=True).decode('utf-8'), end='') if len(lines) == 1 else None
PYEOF
)
chk "one embedded-newline/base64-looking identifier produces exactly one --app-id" \
    "$([[ "$newline_round_trip" == "$newline_identifier" ]] && echo 1 || echo 0)"

echo "[25] 32 adversarial identifiers stay exact, non-empty and capped at 32 invocations"
"$PYTHON3" - "$TRIG_FILE" "$WORK/expected.b64" <<'PYEOF'
import base64, json, sys
identifiers = [
    f'id-{index:02d}\nQUJDRA== literal base64-looking / value {index}'
    for index in range(1, 33)
]
# Invalid/empty values and valid values beyond the execution cap cannot add
# empty or extra child calls. The 32 adversarial valid identifiers remain exact.
labels = ['', '\x00', *identifiers, *[f'beyond-cap-{index}' for index in range(33, 41)]]
with open(sys.argv[1], 'w', encoding='utf-8') as handle:
    json.dump({'type': 'uninstall', 'labels': labels}, handle)
with open(sys.argv[2], 'w', encoding='ascii') as handle:
    for identifier in identifiers:
        handle.write(base64.b64encode(identifier.encode('utf-8')).decode('ascii') + '\n')
PYEOF
: > "$PATCHED_TEST_INVOCATIONS_FILE"
reset_run_state
parse_trigger "$TRIG_FILE" >/dev/null
invocation_count=$(wc -l < "$PATCHED_TEST_INVOCATIONS_FILE" | tr -d '[:space:]')
chk "exactly 32 child invocations occur despite invalid and beyond-cap values" \
    "$([[ "$invocation_count" == "32" ]] && echo 1 || echo 0)"
chk "all 32 --app-id values exactly match the original UTF-8 identifiers" \
    "$({ cmp -s "$WORK/expected.b64" "$PATCHED_TEST_INVOCATIONS_FILE"; } && echo 1 || echo 0)"

echo "[26] a mid-cohort authority refusal preserves completed calls and exact remaining evidence"
PATCHED_TEST_REFUSE_APP_ID=$'id-17\nQUJDRA== literal base64-looking / value 17'
PATCHED_TEST_REFUSAL_FILE="$WORK/refused.b64"
export PATCHED_TEST_REFUSE_APP_ID PATCHED_TEST_REFUSAL_FILE
record_uninstall_trigger_authority_refusal() {
    shift
    "$PYTHON3" - "$PATCHED_TEST_REFUSAL_FILE" "$@" <<'PYEOF'
import base64, sys
with open(sys.argv[1], 'w', encoding='ascii') as handle:
    for identifier in sys.argv[2:]:
        handle.write(base64.b64encode(identifier.encode('utf-8')).decode('ascii') + '\n')
PYEOF
}
: > "$PATCHED_TEST_INVOCATIONS_FILE"
reset_run_state
parse_trigger "$TRIG_FILE" >/dev/null
tail -n +17 "$WORK/expected.b64" > "$WORK/expected-refused.b64"
invocation_count=$(wc -l < "$PATCHED_TEST_INVOCATIONS_FILE" | tr -d '[:space:]')
chk "partial success stops after the refusing seventeenth child" \
    "$([[ "$invocation_count" == "17" ]] && echo 1 || echo 0)"
chk "refusal evidence contains the exact refusing identifier and remaining bounded cohort" \
    "$({ cmp -s "$WORK/expected-refused.b64" "$PATCHED_TEST_REFUSAL_FILE"; } && echo 1 || echo 0)"

echo "[27] an uninstall trigger containing only invalid or empty identifiers invokes nothing"
write_trigger '{"type":"uninstall","labels":["","\u0000",null,123]}'
: > "$PATCHED_TEST_INVOCATIONS_FILE"
unset PATCHED_TEST_REFUSE_APP_ID
reset_run_state
parse_trigger "$TRIG_FILE" >/dev/null
chk "invalid/empty identifiers cannot widen uninstall into an unfiltered child call" \
    "$([[ ! -s "$PATCHED_TEST_INVOCATIONS_FILE" ]] && echo 1 || echo 0)"

echo
echo "=== PATCHED_TRIGGER_CONSUME: removal_defer markers survive exactly like os_defer (PAT-1623) ==="

echo "[28] a removal_defer marker is never selected for consumption, even as the only file present"
TRIGGER_DIR="$WORK/removal-defer-only"
mkdir -p "$TRIGGER_DIR"
removal_defer_marker="$TRIGGER_DIR/removal_defer_11111111-1111-1111-1111-111111111111.trigger"
print -r -- '{"type":"removal_defer","entry_id":42,"name":"Some App","deferred_at":"2026-09-12T00:00:00Z","requested_by":"andy"}' \
    > "$removal_defer_marker"
reset_run_state
source "$CONSUME_TMP" >/dev/null
chk "removal_defer marker file still exists (not consumed/deleted)" "$([[ -e "$removal_defer_marker" ]] && echo 1 || echo 0)"
chk "no trigger was parsed (RUN_TRIGGER stays scheduled)" "$([[ "$RUN_TRIGGER" == "scheduled" ]] && echo 1 || echo 0)"

echo "[29] a removal_defer marker alongside a real trigger: the real trigger is consumed, the marker survives"
TRIGGER_DIR="$WORK/removal-defer-plus-real"
mkdir -p "$TRIGGER_DIR"
removal_defer_marker="$TRIGGER_DIR/removal_defer_22222222-2222-2222-2222-222222222222.trigger"
real_trigger="$TRIGGER_DIR/scan.trigger"
print -r -- '{"type":"removal_defer","entry_id":7,"name":"Other App","deferred_at":"2026-09-12T00:00:00Z","requested_by":"andy"}' \
    > "$removal_defer_marker"
print -r -- '{"type":"scan"}' > "$real_trigger"
reset_run_state
source "$CONSUME_TMP" >/dev/null
chk "removal_defer marker still exists" "$([[ -e "$removal_defer_marker" ]] && echo 1 || echo 0)"
chk "the real scan trigger was consumed (deleted)" "$([[ ! -e "$real_trigger" ]] && echo 1 || echo 0)"
chk "the real trigger was parsed (RUN_MODE=scan, RUN_TRIGGER=manual)" \
    "$([[ "$RUN_MODE" == "scan" && "$RUN_TRIGGER" == "manual" ]] && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
