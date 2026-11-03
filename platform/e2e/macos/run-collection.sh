#!/usr/bin/env bash
##############################################################################
# run-collection.sh — Trigger one collect+upload cycle in the VM and retrieve
# the resulting compliance verdicts from the host stack.
#
# Flow:
#   1. Reads the VM's serial number (via ioreg inside the VM) to reliably
#      identify the VM's device row in the platform DB after upload.
#   2. Derives the host gateway IP from the VM's default route.
#   3. SSH into VM; runs patched-collect.sh then patched-upload.sh as root,
#      with PATCHED_API_URL set explicitly to bypass the LaunchDaemon plist.
#   4. Polls GET /admin/tenants/{tenantID}/devices until the device whose
#      serial matches the VM appears with evaluations.
#   5. GETs /admin/devices/{deviceID} for the full per-rule verdict list.
#   6. Prints a verdict summary; writes artifacts/baseline-verdicts.json.
#
# Requires:
#   - vm.sh up (VM running, SSH key in t9/vm_key)
#   - install-agent.sh completed (agent in /usr/local/bin/ in VM)
#   - stack.sh up (local platform stack healthy)
##############################################################################
set -euo pipefail

T9_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$T9_DIR/../.." && pwd)"
STATE="$REPO_ROOT/e2e/.state"
ARTIFACTS="$T9_DIR/artifacts"
mkdir -p "$ARTIFACTS"

VM_USER="admin"
VM_KEY="$T9_DIR/vm_key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i $VM_KEY"

API_INTERNAL_PORT=18081
API_PUBLIC_PORT=18080

DEVICE_JSON_FILE="$T9_DIR/.device_detail.json"

log()  { printf '[run-collection] %s\n' "$*"; }
die()  { printf '[run-collection] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Load state
# ---------------------------------------------------------------------------
[[ -f "$VM_KEY" ]]                || die "SSH key not found. Run vm.sh up first."
[[ -f "$STATE/TENANT_ID" ]]       || die "TENANT_ID missing from state."
[[ -f "$STATE/ADMIN_API_TOKEN" ]] || die "ADMIN_API_TOKEN missing from state."

TENANT_ID="$(cat "$STATE/TENANT_ID")"
ADMIN_TOKEN="$(cat "$STATE/ADMIN_API_TOKEN")"

VM_IP=$(tart ip patched-e2e-macos 2>/dev/null || true)
[[ -n "$VM_IP" ]] || die "VM not running. Run vm.sh up first."
log "VM IP: $VM_IP"

ADMIN_BASE="http://127.0.0.1:${API_INTERNAL_PORT}"
ADMIN_HDR="Authorization: Bearer $ADMIN_TOKEN"

# ---------------------------------------------------------------------------
# Step 1: Read VM's serial number for reliable device matching
# ---------------------------------------------------------------------------
log "Reading VM serial number via system_profiler..."
VM_SERIAL=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    'system_profiler SPHardwareDataType 2>/dev/null | awk '"'"'/Serial Number/{sub(/.*: /,""); gsub(/[[:space:]]/,""); print; exit}'"'"'' 2>/dev/null || true)
if [[ -z "$VM_SERIAL" ]]; then
    # Fallback: ioreg (works when system_profiler is unavailable)
    VM_SERIAL=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
        "sudo ioreg -l -d1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\"' '/IOPlatformSerialNumber/{print \$4; exit}'" 2>/dev/null || true)
fi
log "VM serial: ${VM_SERIAL:-unknown}"

# ---------------------------------------------------------------------------
# Step 2: Derive host gateway
# ---------------------------------------------------------------------------
log "Deriving host gateway from VM default route..."
HOST_GW=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    "route -n get default 2>/dev/null | awk '/gateway/ {print \$2}' | head -1" 2>/dev/null || true)
if [[ -z "$HOST_GW" ]]; then
    HOST_GW="${VM_IP%.*}.1"
    log "WARN: could not read gateway; assuming $HOST_GW"
fi
log "Host gateway: $HOST_GW"
API_URL="http://$HOST_GW:$API_PUBLIC_PORT"

REACH=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    "curl -sf $API_URL/health 2>/dev/null || echo UNREACHABLE" 2>/dev/null || echo "UNREACHABLE")
if printf '%s' "$REACH" | grep -q "UNREACHABLE"; then
    die "VM cannot reach patched-api at $API_URL. Run install-agent.sh first (rebinds API to 0.0.0.0)."
fi
log "API reachable: $REACH"

# ---------------------------------------------------------------------------
# Step 3: Snapshot existing device IDs
# ---------------------------------------------------------------------------
log "Listing current devices (before collection)..."
BEFORE_JSON_FILE="$T9_DIR/.before_devices.json"
curl -sf -H "$ADMIN_HDR" "$ADMIN_BASE/admin/tenants/$TENANT_ID/devices" -o "$BEFORE_JSON_FILE" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 4: Collect + upload
# ---------------------------------------------------------------------------
log "Running patched-collect.sh inside VM..."
ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    'sudo /usr/local/bin/patched-collect.sh 2>&1 | tail -5' \
    || die "patched-collect.sh failed."

log "Running patched-upload.sh inside VM (PATCHED_API_URL=$API_URL)..."
# PATCHED_API_URL must be passed explicitly — direct invocation does not
# inherit the LaunchDaemon plist environment (which pins the URL), so without
# this env var it would default to https://api.patched.im (production).
ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    "sudo PATCHED_API_URL='$API_URL' /usr/local/bin/patched-upload.sh 2>&1 | tail -20" \
    || die "patched-upload.sh failed."

log "Collect + upload cycle complete."

# ---------------------------------------------------------------------------
# Step 5: Find the VM's device (by serial, then by new-device diff)
# ---------------------------------------------------------------------------
log "Locating VM's device in platform DB..."

find_by_serial() {
    local serial="$1"
    curl -sf -H "$ADMIN_HDR" "$ADMIN_BASE/admin/tenants/$TENANT_ID/devices" 2>/dev/null \
        | python3 -c "
import sys, json
serial = '$serial'
data = json.load(sys.stdin)
for d in data.get('devices', []):
    if d.get('serial','').strip() == serial.strip():
        print(d['id'])
        break
" 2>/dev/null || true
}

find_new_device() {
    curl -sf -H "$ADMIN_HDR" "$ADMIN_BASE/admin/tenants/$TENANT_ID/devices" 2>/dev/null \
        | python3 - "$BEFORE_JSON_FILE" <<'PYEOF'
import sys, json

with open(sys.argv[1]) as f:
    before_data = json.load(f)

before_ids = {d['id'] for d in before_data.get('devices', [])}
data = json.load(sys.stdin)
new_devs = [d for d in data.get('devices', []) if d['id'] not in before_ids]
if new_devs:
    print(new_devs[0]['id'])
PYEOF
}

VM_DEVICE_ID=""

# Primary: match by serial.
if [[ -n "$VM_SERIAL" && "$VM_SERIAL" != "unknown" ]]; then
    log "Polling by serial=$VM_SERIAL (up to 120s)..."
    for i in $(seq 1 24); do
        VM_DEVICE_ID=$(find_by_serial "$VM_SERIAL" 2>/dev/null || true)
        if [[ -n "$VM_DEVICE_ID" ]]; then
            log "Found VM device by serial: $VM_DEVICE_ID"
            break
        fi
        log "  (serial poll attempt $i/24 — waiting 5s...)"
        sleep 5
    done
fi

# Fallback: new-device diff.
if [[ -z "$VM_DEVICE_ID" ]]; then
    log "Falling back to new-device diff polling (up to 120s)..."
    for i in $(seq 1 24); do
        VM_DEVICE_ID=$(find_new_device 2>/dev/null || true)
        if [[ -n "$VM_DEVICE_ID" ]]; then
            log "New device found: $VM_DEVICE_ID"
            break
        fi
        log "  (diff poll attempt $i/24 — waiting 5s...)"
        sleep 5
    done
fi

# No last-resort picker: a wrong-device match is worse evidence than a
# clean failure.  If both serial and diff matching failed, die with a
# diagnostic so the operator knows exactly what to look at.
if [[ -z "$VM_DEVICE_ID" ]]; then
    log "Serial and diff matching both failed.  Candidate devices currently in DB:"
    curl -sf -H "$ADMIN_HDR" "$ADMIN_BASE/admin/tenants/$TENANT_ID/devices" 2>/dev/null \
        | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data.get('devices', []):
    print('  id=%s  serial=%s  hostname=%s' % (d.get('id','?'), d.get('serial','?'), d.get('hostname','?')))
" 2>/dev/null || log "  (could not list devices)"
    die "Could not identify VM device after serial ($VM_SERIAL) and diff-based matching. Check 'tart ip' and serial detection, then inspect the upload log: vm.sh ssh -- sudo PATCHED_API_URL=$API_URL /usr/local/bin/patched-upload.sh"
fi

# ---------------------------------------------------------------------------
# Step 6: Fetch device detail + wait for evaluations
# ---------------------------------------------------------------------------
log "Fetching device detail for $VM_DEVICE_ID ..."
curl -sf -H "$ADMIN_HDR" \
    "$ADMIN_BASE/admin/devices/$VM_DEVICE_ID" \
    -o "$DEVICE_JSON_FILE" \
    || die "Failed to fetch device detail."

EVAL_COUNT=$(python3 -c "
import json
with open('$DEVICE_JSON_FILE') as f:
    print(len(json.load(f).get('evaluations', [])))
" 2>/dev/null || echo 0)

if [[ "$EVAL_COUNT" -eq 0 ]]; then
    log "Waiting for extractor to process payload (up to 90s)..."
    for i in $(seq 1 18); do
        sleep 5
        curl -sf -H "$ADMIN_HDR" \
            "$ADMIN_BASE/admin/devices/$VM_DEVICE_ID" \
            -o "$DEVICE_JSON_FILE" 2>/dev/null || true
        EVAL_COUNT=$(python3 -c "
import json
with open('$DEVICE_JSON_FILE') as f:
    print(len(json.load(f).get('evaluations', [])))
" 2>/dev/null || echo 0)
        if [[ "$EVAL_COUNT" -gt 0 ]]; then
            log "Extractor done: $EVAL_COUNT evaluations."
            break
        fi
        log "  (waiting for extractor... $i/18)"
    done
fi

# ---------------------------------------------------------------------------
# Step 7: Print summary and write artifacts
# ---------------------------------------------------------------------------
log "Parsing $EVAL_COUNT verdicts..."
python3 "$T9_DIR/_parse_verdicts.py" "$DEVICE_JSON_FILE"

VERDICTS_FILE="$ARTIFACTS/baseline-verdicts.json"
log "Writing $VERDICTS_FILE ..."
python3 "$T9_DIR/_write_verdicts.py" "$DEVICE_JSON_FILE" "$VERDICTS_FILE"

log ""
log "=== Collection run complete ==="
