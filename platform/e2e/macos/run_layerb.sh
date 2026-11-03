#!/bin/bash
##############################################################################
# run_layerb.sh — PAT-739 T10 Layer B end-to-end driver.
#
# Orchestrates the 3 collection cycles:
#   1. baseline collect            (assumes vm.sh up + install-agent.sh already done)
#   2. induce.sh apply  -> collect (induced state)
#   3. induce.sh restore -> collect (restored state)
#
# Each collection cycle re-queries the admin API directly (rather than
# trusting run-collection.sh's own EVAL_COUNT>0 shortcut, which short-circuits
# and returns STALE evaluations once a device already has >0 evaluations from
# a prior cycle -- see e2e/data/macos-layerb-results.md "Harness quirk"
# section). This script polls for a NEW evaluated_at timestamp on a marker
# rule before treating a cycle's read as fresh.
##############################################################################
set -uo pipefail

MACOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$MACOS_DIR/.." && pwd)"
STATE="$E2E_DIR/.state"
ARTIFACTS="$MACOS_DIR/artifacts"
RULES_CSV="$E2E_DIR/data/rules.csv"
mkdir -p "$ARTIFACTS"

ADMIN_TOKEN="$(cat "$STATE/ADMIN_API_TOKEN")"
TENANT_ID="$(cat "$STATE/TENANT_ID")"
ADMIN_BASE="http://127.0.0.1:18081"
MARKER_RULE="cis_macos_2_5_2_2_firewall"   # always present; used to detect a fresh evaluation batch

if ! grep -q "^${MARKER_RULE}," "$RULES_CSV"; then
    echo "[run_layerb] ERROR: MARKER_RULE '$MARKER_RULE' not found in $RULES_CSV — renamed?" >&2
    exit 1
fi

log() { printf '[run_layerb] %s\n' "$*"; }

device_id() {
    # Requires artifacts/baseline-verdicts.json (or .device_detail.json) to already
    # contain device_id from a prior run-collection.sh; falls back to serial lookup.
    python3 -c "
import json
try:
    d = json.load(open('$MACOS_DIR/.device_detail.json'))
    print(d.get('device',{}).get('id',''))
except Exception:
    print('')
"
}

# fresh_fetch <device_id> <out_file> <prev_evaluated_at_or_empty>
# Polls the admin API until the marker rule's evaluated_at changes (or up to 90s),
# then writes the device detail JSON to out_file.
fresh_fetch() {
    local dev="$1" out="$2" prev_ts="$3"
    for i in $(seq 1 18); do
        curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" "$ADMIN_BASE/admin/devices/$dev" -o "$out"
        local ts
        ts=$(python3 -c "
import json
d = json.load(open('$out'))
for e in d['evaluations']:
    if e['rule_key'] == '$MARKER_RULE':
        print(e['evaluated_at']); break
")
        if [[ -n "$ts" && "$ts" != "$prev_ts" ]]; then
            log "Fresh evaluation batch detected (marker evaluated_at=$ts)"
            printf '%s' "$ts"
            return 0
        fi
        log "  waiting for extractor ($i/18)..."
        sleep 5
    done
    log "WARN: never observed a new evaluated_at; using last-fetched data (may be stale)"
    printf '%s' "$prev_ts"
}

log "=== Step 1: baseline collection ==="
"$MACOS_DIR/run-collection.sh" || { log "ERROR: baseline collection failed"; exit 1; }
DEV_ID=$(device_id)
[[ -n "$DEV_ID" ]] || { log "ERROR: could not determine device id"; exit 1; }
cp "$MACOS_DIR/artifacts/baseline-verdicts.json" "$ARTIFACTS/baseline-verdicts.json"
BASELINE_TS=$(python3 -c "
import json
d = json.load(open('$MACOS_DIR/.device_detail.json'))
for e in d['evaluations']:
    if e['rule_key'] == '$MARKER_RULE':
        print(e['evaluated_at']); break
")
log "Baseline marker ts: $BASELINE_TS"

log "=== Step 2: apply induction ==="
"$MACOS_DIR/induce.sh" apply || { log "ERROR: induce.sh apply failed"; exit 1; }

log "=== Step 3: induced collection ==="
"$MACOS_DIR/run-collection.sh" >/dev/null || { log "ERROR: induced collection failed"; exit 1; }
INDUCED_TS=$(fresh_fetch "$DEV_ID" "$ARTIFACTS/induced-device-detail.json" "$BASELINE_TS")

log "=== Step 4: restore induction ==="
"$MACOS_DIR/induce.sh" restore || { log "ERROR: induce.sh restore failed — VM may be left in an induced state"; exit 1; }

log "=== Step 5: restored collection ==="
"$MACOS_DIR/run-collection.sh" >/dev/null || { log "ERROR: restored collection failed"; exit 1; }
fresh_fetch "$DEV_ID" "$ARTIFACTS/restored-device-detail.json" "$INDUCED_TS" >/dev/null

log "=== Step 6: build ledger ==="
python3 "$MACOS_DIR/build_ledger.py"

log "Done. See $ARTIFACTS/layerb-ledger.json and e2e/data/macos-layerb-results.md"
