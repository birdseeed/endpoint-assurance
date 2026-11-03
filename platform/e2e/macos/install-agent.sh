#!/usr/bin/env bash
##############################################################################
# install-agent.sh — Install the Patched macOS collector into the E2E VM.
#
# Pre-conditions:
#   - Local E2E stack running (stack.sh up)
#   - VM running (vm.sh up)
#   - e2e/.state/ populated with credentials
#
# What this does:
#   1. Reads tenant credentials from e2e/.state/
#   2. Restarts patched-api with LISTEN_PUBLIC=0.0.0.0:18080 so the VM
#      (which sits on Tart's NAT subnet, ~192.168.64.0/24) can reach it.
#      The internal listener remains on 127.0.0.1:18081 — not exposed.
#   3. Copies the macOS agent source tree to the VM via scp.
#   4. Runs install.sh inside the VM with --api-url pointing at the host
#      gateway (derived from the VM's own default route).
#   5. Verifies both LaunchDaemons (collect + upload) are loaded.
#
# Networking choice (A — rebind API):
#   patched-api defaults to 127.0.0.1:18080 which the VM cannot reach.
#   We kill the existing go-run API process and restart it with
#   LISTEN_PUBLIC=0.0.0.0:18080. The stack's PID file is updated so
#   stack.sh status / down remain accurate. stack.sh itself is NOT edited.
#   Restore: run stack.sh down && stack.sh up to return to loopback-only.
##############################################################################
set -euo pipefail

T9_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$T9_DIR/../.." && pwd)"
UPDATER_DIR="${PATCHED_UPDATER_DIR:-$HOME/Development/Patched.im/updater}"
AGENT_SRC="$UPDATER_DIR/macos"
STATE="$REPO_ROOT/e2e/.state"
GOSERVICE_DIR="$REPO_ROOT/go-service"

VM_USER="admin"
VM_KEY="$T9_DIR/vm_key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i $VM_KEY"

API_PUBLIC_PORT=18080
API_INTERNAL_PORT=18081
PG_PORT=55432
PG_DB="patched_e2e"
PG_USER="patched_e2e"
PG_PASS="patched_e2e"

log()  { printf '[install-agent] %s\n' "$*"; }
die()  { printf '[install-agent] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
[[ -f "$VM_KEY" ]]             || die "SSH key not found. Run vm.sh up first."
[[ -f "$STATE/TENANT_ID" ]]   || die "e2e/.state/TENANT_ID missing. Run stack.sh up first."
[[ -f "$STATE/BEARER_TOKEN" ]] || die "e2e/.state/BEARER_TOKEN missing."
[[ -f "$STATE/HMAC_SECRET_B64" ]] || die "e2e/.state/HMAC_SECRET_B64 missing."
[[ -f "$STATE/ADMIN_API_TOKEN" ]] || die "e2e/.state/ADMIN_API_TOKEN missing."

TENANT_ID="$(cat "$STATE/TENANT_ID")"
BEARER_TOKEN="$(cat "$STATE/BEARER_TOKEN")"
HMAC_SECRET="$(cat "$STATE/HMAC_SECRET_B64")"
ADMIN_TOKEN="$(cat "$STATE/ADMIN_API_TOKEN")"
ADMIN_API_TOKEN="$ADMIN_TOKEN"
SIGNING_KEY="$(cat "$STATE/AGENT_CONFIG_SIGNING_KEY")"
DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${PG_DB}?sslmode=disable"

# Get the VM IP.
VM_IP=$(tart ip patched-e2e-macos 2>/dev/null || true)
[[ -n "$VM_IP" ]] || die "VM not running or IP unavailable. Run vm.sh up first."
log "VM IP: $VM_IP"

# ---------------------------------------------------------------------------
# Step 1: Rebind patched-api to 0.0.0.0 so the VM can reach it
# ---------------------------------------------------------------------------
log "Checking if patched-api is accessible from the VM subnet..."

# Check current binding.
CURRENT_LISTEN=$(lsof -nP -i ":$API_PUBLIC_PORT" -sTCP:LISTEN 2>/dev/null | tail -1 | awk '{print $9}' || true)
log "Current API listener: ${CURRENT_LISTEN:-none}"

if printf '%s' "${CURRENT_LISTEN:-}" | grep -qE "^(0\.0\.0\.0|\*):"; then
    log "API already bound to all interfaces (${CURRENT_LISTEN}) — no restart needed."
else
    log "Rebinding patched-api to 0.0.0.0:$API_PUBLIC_PORT ..."

    # Kill the existing API (and its go-run child).
    API_PID="$(cat "$STATE/API_PID" 2>/dev/null || true)"
    if [[ -n "$API_PID" ]]; then
        log "Stopping existing API (pid $API_PID)..."
        kill "$API_PID" 2>/dev/null || true
        pkill -P "$API_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$API_PID" 2>/dev/null || true
        pkill -9 -P "$API_PID" 2>/dev/null || true
    fi
    # Belt-and-suspenders: kill anything still on the port.
    STALE_PIDS=$(lsof -ti ":$API_PUBLIC_PORT" -sTCP:LISTEN 2>/dev/null || true)
    if [[ -n "$STALE_PIDS" ]]; then
        # shellcheck disable=SC2086
        kill -9 $STALE_PIDS 2>/dev/null || true
    fi
    sleep 1

    # Start fresh with public listen on all interfaces.
    log "Starting patched-api with LISTEN_PUBLIC=0.0.0.0:$API_PUBLIC_PORT ..."
    (
        cd "$GOSERVICE_DIR"
        DATABASE_URL="$DATABASE_URL" \
        LISTEN_PUBLIC="0.0.0.0:${API_PUBLIC_PORT}" \
        LISTEN_INTERNAL="127.0.0.1:${API_INTERNAL_PORT}" \
        ADMIN_API_TOKEN="$ADMIN_API_TOKEN" \
        AGENT_CONFIG_SIGNING_KEY="$SIGNING_KEY" \
        RATE_LIMIT_RPM=100000 \
        RATE_LIMIT_BURST=10000 \
        go run ./cmd/patched-api \
            >>"$STATE/api.log" 2>&1 &
        printf '%d' $! > "$STATE/API_PID"
    )
    sleep 2
    NEW_PID="$(cat "$STATE/API_PID" 2>/dev/null || true)"
    log "patched-api restarted (pid ${NEW_PID:-unknown})."

    # Wait for health check.
    log "Waiting for API health..."
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${API_PUBLIC_PORT}/health" >/dev/null 2>&1; then
            log "API healthy."
            break
        fi
        sleep 2
        if [[ $i -eq 30 ]]; then
            die "API did not become healthy. Check $STATE/api.log."
        fi
    done
fi

# ---------------------------------------------------------------------------
# Step 2: Determine the host's IP from the VM's perspective
# ---------------------------------------------------------------------------
# The VM uses Tart's default NAT. Its gateway is the host's vmnet interface.
# We derive it by asking the VM for its own default route.
log "Determining host IP (gateway) from inside VM..."
HOST_GW=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    "route -n get default 2>/dev/null | awk '/gateway/ {print \$2}' | head -1" 2>/dev/null || true)

if [[ -z "$HOST_GW" ]]; then
    # Fallback: derive from VM IP — Tart NAT typically uses .1 as gateway.
    HOST_GW="${VM_IP%.*}.1"
    log "WARN: could not read gateway from VM; assuming $HOST_GW"
fi
log "Host gateway (seen from VM): $HOST_GW"

# Verify the VM can reach the API.
log "Verifying VM can reach API at http://$HOST_GW:$API_PUBLIC_PORT/health ..."
REACH=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    "curl -sf http://$HOST_GW:$API_PUBLIC_PORT/health 2>/dev/null || echo UNREACHABLE" 2>/dev/null || echo "UNREACHABLE")
if printf '%s' "$REACH" | grep -q "UNREACHABLE"; then
    die "VM cannot reach patched-api at $HOST_GW:$API_PUBLIC_PORT. Check firewall / listen binding."
fi
log "Connectivity confirmed: $REACH"

API_URL="http://$HOST_GW:$API_PUBLIC_PORT"

# ---------------------------------------------------------------------------
# Step 3: Copy the agent source to the VM
# ---------------------------------------------------------------------------
REMOTE_AGENT_DIR="/tmp/patched-agent"
log "Copying macOS agent source to VM:/tmp/patched-agent ..."
ssh $SSH_OPTS "$VM_USER@$VM_IP" "rm -rf $REMOTE_AGENT_DIR && mkdir -p $REMOTE_AGENT_DIR"
scp -r $SSH_OPTS \
    "$AGENT_SRC/patched-collect.sh" \
    "$AGENT_SRC/patched-upload.sh" \
    "$AGENT_SRC/install.sh" \
    "$AGENT_SRC/uninstall.sh" \
    "$AGENT_SRC/com.patched.collect.plist" \
    "$AGENT_SRC/com.patched.upload.plist" \
    "$AGENT_SRC/lib" \
    "$VM_USER@$VM_IP:$REMOTE_AGENT_DIR/"
log "Agent source copied."

# ---------------------------------------------------------------------------
# Step 4: Run install.sh inside the VM
# ---------------------------------------------------------------------------
log "Running install.sh inside VM (api-url=$API_URL)..."
ssh $SSH_OPTS "$VM_USER@$VM_IP" "sudo bash $REMOTE_AGENT_DIR/install.sh \
    --tenant-id  '$TENANT_ID' \
    --bearer-token '$BEARER_TOKEN' \
    --hmac-secret  '$HMAC_SECRET' \
    --api-url      '$API_URL' \
    2>&1" || die "install.sh failed inside VM."
log "install.sh complete."

# ---------------------------------------------------------------------------
# Step 5: Verify LaunchDaemons are loaded
# ---------------------------------------------------------------------------
log "Verifying LaunchDaemons..."
DAEMONS=$(ssh $SSH_OPTS "$VM_USER@$VM_IP" \
    "sudo launchctl list 2>/dev/null | grep com.patched || true")
log "Loaded daemons: ${DAEMONS:-none}"

if ! printf '%s' "$DAEMONS" | grep -q "com.patched.collect"; then
    log "WARN: com.patched.collect not found in launchctl list. Check /var/log/patched-collect.log"
fi
if ! printf '%s' "$DAEMONS" | grep -q "com.patched.upload"; then
    log "WARN: com.patched.upload not found in launchctl list. Check /var/log/patched-upload.log"
fi

log ""
log "=== Agent installation complete ==="
log "  API URL (from VM): $API_URL"
log "  VM IP            : $VM_IP"
log "  Host gateway     : $HOST_GW"
log ""
log "To trigger an immediate collect+upload cycle:"
log "  ./run-collection.sh"
