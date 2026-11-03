#!/usr/bin/env bash
# e2e/smoke.sh — end-to-end smoke test for the Patched platform.
#
# Proves the full pipeline:
#   1. POST a schema_version-2 macOS payload to patched-api /v1/inventory
#   2. Wait for patched-extractor to evaluate the payload (max 60s)
#   3. Assert via the dashboard /admin/devices/{id} that:
#        - evaluations[] is non-empty
#        - cis_macos_2_5_1_1_filevault has status "pass"
#
# Reads all credentials from e2e/.state/ (written by stack.sh up).
#
# Exit 0 = PASS, exit 1 = FAIL.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE="$SCRIPT_DIR/.state"

API_PUBLIC_PORT=18080
API_INTERNAL_PORT=18081
DASHBOARD_PORT=18000

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
log()  { printf '[smoke] %s\n' "$*"; }
fail() { printf '[smoke] FAIL: %s\n' "$*" >&2; printf '\n=== FAIL ===\n'; exit 1; }

state_get() {
    local key="$1"
    if [[ -f "$STATE/$key" ]]; then
        cat "$STATE/$key"
    else
        printf ''
    fi
}

require_state() {
    local key="$1"
    local val
    val="$(state_get "$key")"
    if [[ -z "$val" ]]; then
        fail "State file '$key' missing or empty. Run 'e2e/stack.sh up' first."
    fi
    printf '%s' "$val"
}

# json_field FILE_PATH FIELD_EXPR — extract a field from a JSON file via python3.
# FIELD_EXPR is a python expression evaluated on 'data', e.g. 'data["tenant_id"]'.
json_field() {
    local file="$1"
    local expr="$2"
    python3 -c "import json; data=json.load(open('$file')); print($expr)" 2>/dev/null || printf ''
}

# ---------------------------------------------------------------------------
# Load credentials from state
# ---------------------------------------------------------------------------
log "Loading credentials from $STATE/"

ADMIN_API_TOKEN="$(require_state ADMIN_API_TOKEN)"
DASHBOARD_API_KEY="$(require_state DASHBOARD_API_KEY)"
TENANT_ID="$(require_state TENANT_ID)"
BEARER_TOKEN="$(require_state BEARER_TOKEN)"
HMAC_SECRET_B64="$(require_state HMAC_SECRET_B64)"

log "Tenant ID : $TENANT_ID"

# ---------------------------------------------------------------------------
# Build payload
# ---------------------------------------------------------------------------
NOW_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
# Unique per-invocation serial so a prior run's device never causes a vacuous
# pass (the poll loop would match and return the old device's evaluations).
DEVICE_SERIAL="E2E-SMOKE-$(date +%s)-$(openssl rand -hex 2)"
HW_UUID="E2EAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

# Write the payload to a temp file to avoid argument-length issues.
PAYLOAD_FILE="$(mktemp /tmp/e2e-payload.XXXXXX.json)"
# shellcheck disable=SC2064
trap "rm -f '$PAYLOAD_FILE'" EXIT

cat > "$PAYLOAD_FILE" <<PAYLOAD
{"schema_version":2,"agent":"e2e-smoke","agent_version":"0.0.1","tenant_id":"${TENANT_ID}","collected_at":"${NOW_ISO}","device":{"serial":"${DEVICE_SERIAL}","hw_uuid":"${HW_UUID}","hostname":"smoke-mac","computer_name":"Smoke Mac","hw_model":"Mac14,2","arch":"arm64","last_boot":"${NOW_ISO}"},"hardware":{"cpu_model":"Apple M2","cpu_cores":8,"ram_gb":16,"disk_total_gb":500.0,"disk_free_gb":300.0},"os":{"name":"macOS","version":"15.4.1","build":"24E263"},"compliance":{"filevault":"On","sip":"enabled","pending_updates_count":0,"gatekeeper":"enabled","screen_lock":"enabled","screen_lock_timeout":300,"firewall":"enabled","remote_login":"disabled","automatic_updates":"enabled","automatic_security_updates":"enabled","os_up_to_date":true,"password_hint":""},"security_tools":[],"system_extensions":[],"background_items":[],"icloud":{"signed_in":"No"},"apps":[]}
PAYLOAD

# ---------------------------------------------------------------------------
# Compute HMAC-SHA256 signature
# ---------------------------------------------------------------------------
log "Computing HMAC signature..."

SIG="$(python3 - "$PAYLOAD_FILE" "$HMAC_SECRET_B64" <<'PYEOF'
import hmac as _hmac, hashlib, base64, sys
payload_path = sys.argv[1]
secret_b64   = sys.argv[2]
secret = base64.b64decode(secret_b64)
with open(payload_path, 'rb') as fh:
    body = fh.read()
print(_hmac.new(secret, body, hashlib.sha256).hexdigest(), end='')
PYEOF
)"

TIMESTAMP="$(date +%s)"
NONCE="$(python3 -c 'import uuid; print(str(uuid.uuid4()))')"

log "Timestamp : $TIMESTAMP"
log "Nonce     : $NONCE"

# ---------------------------------------------------------------------------
# POST payload to API
# ---------------------------------------------------------------------------
log "POSTing payload to http://127.0.0.1:${API_PUBLIC_PORT}/v1/inventory..."

INGEST_RESP_FILE="$(mktemp /tmp/e2e-ingest.XXXXXX.json)"
# shellcheck disable=SC2064
trap "rm -f '$PAYLOAD_FILE' '$INGEST_RESP_FILE'" EXIT

HTTP_CODE="$(curl -s -o "$INGEST_RESP_FILE" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${API_PUBLIC_PORT}/v1/inventory" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -H "X-Patched-Signature: ${SIG}" \
    -H "X-Patched-Timestamp: ${TIMESTAMP}" \
    -H "X-Patched-Nonce: ${NONCE}" \
    --data-binary "@${PAYLOAD_FILE}")" || HTTP_CODE="000"

if [[ "$HTTP_CODE" != "200" ]]; then
    log "Response body: $(cat "$INGEST_RESP_FILE")"
    fail "Inventory POST returned HTTP $HTTP_CODE (expected 200)."
fi

RAW_PAYLOAD_ID="$(json_field "$INGEST_RESP_FILE" 'data.get("raw_payload_id","?")')"
log "Payload accepted (raw_payload_id=${RAW_PAYLOAD_ID}, HTTP 200)."

# ---------------------------------------------------------------------------
# Poll API internal port for device to appear (extractor must have run)
# ---------------------------------------------------------------------------
log "Polling API for device (serial=$DEVICE_SERIAL, max 60s)..."

DEVICES_FILE="$(mktemp /tmp/e2e-devices.XXXXXX.json)"
# shellcheck disable=SC2064
trap "rm -f '$PAYLOAD_FILE' '$INGEST_RESP_FILE' '$DEVICES_FILE'" EXIT

DEVICE_ID=""
for i in $(seq 1 60); do
    HTTP_D="$(curl -s -o "$DEVICES_FILE" -w '%{http_code}' \
        "http://127.0.0.1:${API_INTERNAL_PORT}/admin/tenants/${TENANT_ID}/devices" \
        -H "Authorization: Bearer ${ADMIN_API_TOKEN}" 2>/dev/null)" || HTTP_D="000"

    if [[ "$HTTP_D" == "200" ]]; then
        DEVICE_ID="$(python3 - "$DEVICES_FILE" "$DEVICE_SERIAL" <<'PYEOF'
import sys, json
data = json.load(open(sys.argv[1]))
serial = sys.argv[2]
for d in data.get("devices", []):
    if d.get("serial") == serial:
        print(d["id"])
        break
PYEOF
)" || DEVICE_ID=""
    fi

    if [[ -n "$DEVICE_ID" ]]; then
        log "Device found: $DEVICE_ID (attempt $i)."
        break
    fi
    if [[ $i -eq 1 || $((i % 10)) -eq 0 ]]; then
        log "Waiting for extractor... ($i/60)"
    fi
    sleep 1
done

if [[ -z "$DEVICE_ID" ]]; then
    fail "Device did not appear within 60s. Extractor may not be running or payload was rejected."
fi

# ---------------------------------------------------------------------------
# Wait for evaluations to appear
# ---------------------------------------------------------------------------
log "Waiting for compliance evaluations (max 60s)..."

DETAIL_FILE="$(mktemp /tmp/e2e-detail.XXXXXX.json)"
# shellcheck disable=SC2064
trap "rm -f '$PAYLOAD_FILE' '$INGEST_RESP_FILE' '$DEVICES_FILE' '$DETAIL_FILE'" EXIT

EVAL_COUNT=0
for i in $(seq 1 60); do
    HTTP_DET="$(curl -s -o "$DETAIL_FILE" -w '%{http_code}' \
        "http://127.0.0.1:${API_INTERNAL_PORT}/admin/devices/${DEVICE_ID}" \
        -H "Authorization: Bearer ${ADMIN_API_TOKEN}" 2>/dev/null)" || HTTP_DET="000"

    if [[ "$HTTP_DET" == "200" ]]; then
        EVAL_COUNT="$(json_field "$DETAIL_FILE" 'len(data.get("evaluations",[]))')" || EVAL_COUNT=0
        if [[ "$EVAL_COUNT" -gt 0 ]]; then
            log "Evaluations ready: $EVAL_COUNT rule(s) evaluated (attempt $i)."
            break
        fi
    fi
    if [[ $i -eq 1 || $((i % 10)) -eq 0 ]]; then
        log "Waiting for evaluations... ($i/60)"
    fi
    sleep 1
done

if [[ "$EVAL_COUNT" -eq 0 ]]; then
    fail "No evaluations appeared within 60s."
fi

# ---------------------------------------------------------------------------
# Assert via DASHBOARD: GET /admin/devices/{device_id}
# ---------------------------------------------------------------------------
log "Asserting via dashboard (http://127.0.0.1:${DASHBOARD_PORT}/admin/devices/${DEVICE_ID})..."

DASH_FILE="$(mktemp /tmp/e2e-dash.XXXXXX.json)"
# shellcheck disable=SC2064
trap "rm -f '$PAYLOAD_FILE' '$INGEST_RESP_FILE' '$DEVICES_FILE' '$DETAIL_FILE' '$DASH_FILE'" EXIT

HTTP_DASH="$(curl -s -o "$DASH_FILE" -w '%{http_code}' \
    "http://127.0.0.1:${DASHBOARD_PORT}/admin/devices/${DEVICE_ID}" \
    -H "Authorization: Bearer ${DASHBOARD_API_KEY}")" || HTTP_DASH="000"

if [[ "$HTTP_DASH" != "200" ]]; then
    log "Dashboard response: $(cat "$DASH_FILE")"
    fail "Dashboard returned HTTP $HTTP_DASH (expected 200)."
fi

# Check evaluations[] is non-empty.
DASH_EVAL_COUNT="$(json_field "$DASH_FILE" 'len(data.get("evaluations",[]))')" || DASH_EVAL_COUNT=0

if [[ "$DASH_EVAL_COUNT" -eq 0 ]]; then
    fail "Dashboard returned empty evaluations for device $DEVICE_ID."
fi
log "Dashboard evaluations: $DASH_EVAL_COUNT rule(s)."

# Check cis_macos_2_5_1_1_filevault = "pass".
FILEVAULT_STATUS="$(python3 - "$DASH_FILE" <<'PYEOF'
import sys, json
data = json.load(open(sys.argv[1]))
for e in data.get("evaluations", []):
    if e.get("rule_key") == "cis_macos_2_5_1_1_filevault":
        print(e.get("status", "MISSING"))
        sys.exit(0)
print("NOT_FOUND")
PYEOF
)" || FILEVAULT_STATUS="ERROR"

log "cis_macos_2_5_1_1_filevault status: $FILEVAULT_STATUS"

if [[ "$FILEVAULT_STATUS" == "NOT_FOUND" ]]; then
    fail "Rule cis_macos_2_5_1_1_filevault not found in evaluations."
fi

if [[ "$FILEVAULT_STATUS" != "pass" ]]; then
    fail "Expected cis_macos_2_5_1_1_filevault=pass, got: $FILEVAULT_STATUS"
fi

# ---------------------------------------------------------------------------
# All assertions passed
# ---------------------------------------------------------------------------
log "  raw_payload_id   : ${RAW_PAYLOAD_ID}"
log "  device_id        : $DEVICE_ID"
log "  evaluations      : $DASH_EVAL_COUNT (via dashboard)"
log "  filevault status : $FILEVAULT_STATUS"
printf '\n=== PASS ===\n'
