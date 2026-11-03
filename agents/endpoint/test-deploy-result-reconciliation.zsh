#!/bin/zsh
# PAT-1365: execute the shipped deploy-result reconciliation function and prove
# one-app and Install all requests cannot become empty success.

set -u

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-update.sh"
WORK=$(mktemp -d /tmp/patched-deploy-reconcile.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

PYTHON3=/usr/bin/python3
pass=0
fail=0

awk '/^# >>> PATCHED_DEPLOY_RESULT_RECONCILE_START$/ {copy=1; next}
     /^# <<< PATCHED_DEPLOY_RESULT_RECONCILE_END$/ {copy=0}
     copy {print}' "$TARGET" > "$WORK/reconcile.zsh"
source "$WORK/reconcile.zsh"

awk '/^# >>> PATCHED_TRIGGER_PARSE_START$/ {copy=1; next}
     /^# <<< PATCHED_TRIGGER_PARSE_END$/ {copy=0}
     copy {print}' "$TARGET" > "$WORK/parse-trigger.zsh"
source "$WORK/parse-trigger.zsh"

chk() {
    local label="$1" actual="$2"
    if [[ "$actual" == "1" ]]; then
        echo "  PASS: $label"
        (( pass++ )) || true
    else
        echo "  FAIL: $label"
        (( fail++ )) || true
    fi
}

json_value() {
    "$PYTHON3" -c 'import json,sys; print(json.loads(open(sys.argv[1]).readlines()[-1])[sys.argv[2]])' "$1" "$2"
}

# PAT-1620 note: this case used to prove the shipped trigger parser fed a
# real Self Service deploy request through to RUN_MODE=install/
# DEPLOY_REQUESTED=1 for reconciliation below. PAT-1620 retired the deploy
# trigger type along with Self Service itself (see endpoint/test-trigger-
# parsing.zsh), so the same trigger shape is now correctly rejected --
# nothing can set DEPLOY_REQUESTED any more, and reconcile_deploy_results
# below is exercised directly with synthetic arguments rather than through
# a live trigger. That function itself is intentionally untouched dead code
# pending the separate executor-removal ticket PAT-1617 calls out as out of
# scope for this batch.
echo "[0] the retired deploy trigger shape is rejected, not fed to reconciliation"
trigger="$WORK/install-all.trigger"
print -r -- '{"labels":["com.google.Chrome","com.microsoft.Word"],"source":"self-service"}' > "$trigger"
RUN_MODE=scan
RUN_TRIGGER=scheduled
TRIGGER_LABELS=""
DEPLOY_REQUESTED=0
BUNDLE_DIR="$WORK/no-uninstall-engine"
parse_trigger "$trigger"
chk "RUN_MODE stays scan (deploy retired, PAT-1620)" "$([[ "$RUN_MODE" == "scan" ]] && echo 1 || echo 0)"
chk "DEPLOY_REQUESTED never set" "$([[ "$DEPLOY_REQUESTED" == "0" ]] && echo 1 || echo 0)"
chk "trigger is rejected, not silently accepted" "$([[ "$RUN_TRIGGER" == "trigger_type_rejected" ]] && echo 1 || echo 0)"

echo "[1] one matching requested label preserves its real result"
apps="$WORK/one-match.ndjson"
print -r -- '{"label":"googlechrome","name":"Google Chrome","state":"up_to_date"}' > "$apps"
reconcile_deploy_results "$apps" "googlechrome" "2026-08-15T12:00:00Z" >/dev/null
chk "no refusal added" "$([[ $(wc -l < "$apps" | tr -d ' ') == 1 ]] && echo 1 || echo 0)"

echo "[2] one unmatched requested label becomes an explicit error"
apps="$WORK/one-missing.ndjson"
: > "$apps"
reconcile_deploy_results "$apps" "com.google.Chrome" "2026-08-15T12:00:00Z" >/dev/null
chk "error row added" "$([[ "$(json_value "$apps" state)" == "error" ]] && echo 1 || echo 0)"
chk "requested label retained" "$([[ "$(json_value "$apps" label)" == "com.google.Chrome" ]] && echo 1 || echo 0)"
chk "specific refusal is visible" "$([[ "$(json_value "$apps" message)" == *"not in this endpoint's allowlist"* ]] && echo 1 || echo 0)"

echo "[3] Install all preserves matched work and refuses each unmatched label"
apps="$WORK/install-all.ndjson"
print -r -- '{"label":"googlechrome","name":"Google Chrome","state":"up_to_date"}' > "$apps"
reconcile_deploy_results "$apps" "googlechrome com.microsoft.Word slack" "2026-08-15T12:00:00Z" >/dev/null
chk "one real plus two refusal rows" "$([[ $(wc -l < "$apps" | tr -d ' ') == 3 ]] && echo 1 || echo 0)"
chk "both missing labels are errors" "$("$PYTHON3" -c 'import json,sys; rows=[json.loads(x) for x in open(sys.argv[1])]; print(int({r["label"] for r in rows if r["state"]=="error"}=={"com.microsoft.Word","slack"}))' "$apps")"

echo "[4] an empty deploy request is a refusal, never empty success"
apps="$WORK/empty.ndjson"
: > "$apps"
reconcile_deploy_results "$apps" "" "2026-08-15T12:00:00Z" >/dev/null
chk "synthetic request row is error" "$([[ "$(json_value "$apps" state)" == "error" ]] && echo 1 || echo 0)"
chk "empty-label reason is specific" "$([[ "$(json_value "$apps" message)" == *"did not contain any valid labels"* ]] && echo 1 || echo 0)"

echo "[5] wildcard Install all succeeds only when at least one result exists"
apps="$WORK/wildcard-empty.ndjson"
: > "$apps"
reconcile_deploy_results "$apps" "*" "2026-08-15T12:00:00Z" >/dev/null
chk "empty wildcard becomes error" "$([[ "$(json_value "$apps" state)" == "error" ]] && echo 1 || echo 0)"
apps="$WORK/wildcard-work.ndjson"
print -r -- '{"label":"slack","name":"Slack","state":"up_to_date"}' > "$apps"
reconcile_deploy_results "$apps" "*" "2026-08-15T12:00:00Z" >/dev/null
chk "wildcard with work adds no refusal" "$([[ $(wc -l < "$apps" | tr -d ' ') == 1 ]] && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
