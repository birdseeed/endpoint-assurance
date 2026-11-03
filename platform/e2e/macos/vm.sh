#!/usr/bin/env bash
##############################################################################
# vm.sh — Tart VM lifecycle manager for PAT-739 macOS Layer B E2E harness.
#
# Usage:
#   vm.sh up           Clone (if needed) + start headless + wait for SSH
#   vm.sh down         Stop VM (keeps the clone)
#   vm.sh ssh [-- cmd] SSH passthrough; optional command executed and exits
#   vm.sh ip           Print VM's current IP address
#   vm.sh reset        Stop + delete + re-clone from base (idempotent revert)
#   vm.sh destroy      Stop + delete VM permanently
#
# VM name : patched-e2e-macos
# Base    : ghcr.io/cirruslabs/macos-sequoia-base:latest
# Creds   : admin / admin (Cirrus default; passwordless sudo)
#
# Revert mechanism:
#   Tart has no snapshots. "reset" destroys the current clone and re-clones
#   from the base OCI image. Because APFS copy-on-write is used, re-cloning
#   is fast (~seconds). After reset, run "vm.sh up" then install-agent.sh again.
#
# SSH key:
#   On first "up", an ed25519 key pair is generated at $T9_DIR/vm_key{,.pub}
#   and installed via sshpass+ssh-copy-id so all subsequent SSH uses key auth
#   (no password prompts).
##############################################################################
set -euo pipefail

T9_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="patched-e2e-macos"
BASE_IMAGE="ghcr.io/cirruslabs/macos-sequoia-base:latest"
VM_USER="admin"
VM_PASS="admin"
VM_KEY="$T9_DIR/vm_key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i $VM_KEY"

# ---------------------------------------------------------------------------
# Helpers — ALL log output goes to stderr so functions returning values via
# stdout can be safely used in command substitution.
# ---------------------------------------------------------------------------
log()  { printf '[vm] %s\n' "$*" >&2; }
die()  { printf '[vm] ERROR: %s\n' "$*" >&2; exit 1; }

# Wait for the VM's IP to appear (tart ip returns nothing while booting).
# Prints the IP on stdout; all status messages go to stderr.
wait_for_ip() {
    log "Waiting for VM IP (macOS Sequoia can take 3-5 min to boot)..."
    for i in $(seq 1 150); do
        local ip
        ip=$(tart ip "$VM_NAME" 2>/dev/null || true)
        if [[ -n "$ip" ]]; then
            log "VM IP: $ip"
            printf '%s' "$ip"
            return 0
        fi
        sleep 4
    done
    die "VM IP did not appear within 10 minutes."
}

# Wait for SSH to accept connections on the given IP.
wait_for_ssh() {
    local ip="$1"
    log "Waiting for SSH on $ip (up to 5 min)..."
    for i in $(seq 1 100); do
        if sshpass -p "$VM_PASS" ssh \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o LogLevel=ERROR \
                -o ConnectTimeout=8 \
                "$VM_USER@$ip" "true" 2>/dev/null; then
            log "SSH ready."
            return 0
        fi
        sleep 3
    done
    die "SSH did not become ready within 5 minutes on $ip."
}

# Generate SSH key pair if missing, install it into the VM via sshpass.
install_ssh_key() {
    local ip="$1"
    if [[ ! -f "$VM_KEY" ]]; then
        log "Generating SSH key pair at $VM_KEY..."
        ssh-keygen -t ed25519 -N "" -f "$VM_KEY" >/dev/null
    fi
    log "Installing SSH public key into VM..."
    sshpass -p "$VM_PASS" ssh-copy-id \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -i "$VM_KEY.pub" \
        "$VM_USER@$ip" 2>/dev/null || {
        # ssh-copy-id can fail if key already installed — verify key works.
        if ssh $SSH_OPTS -o ConnectTimeout=5 "$VM_USER@$ip" "true" 2>/dev/null; then
            log "Key already installed."
        else
            die "Failed to install SSH key into VM."
        fi
    }
    log "Key auth ready."
}

vm_exists() {
    tart list 2>/dev/null | awk 'NR>1 {print $2}' | grep -qx "$VM_NAME"
}

vm_running() {
    # Exact match on the name column (col 2, NR>1 skips header) to avoid
    # substring matches against other VMs that share a name prefix
    # (e.g. patched-e2e-macos-2).
    tart list 2>/dev/null | awk -v n="$VM_NAME" 'NR>1 && $2==n' | grep -q "running"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_up() {
    # 1. Clone if the VM doesn't exist.
    if ! vm_exists; then
        log "Cloning $BASE_IMAGE -> $VM_NAME ..."
        tart clone "$BASE_IMAGE" "$VM_NAME"
        log "Clone complete."
    else
        log "VM $VM_NAME already exists."
    fi

    # 2. Start headless if not already running.
    if vm_running; then
        log "VM already running."
    else
        log "Starting VM headless..."
        # tart run blocks until the VM stops; run in background silently.
        nohup tart run --no-graphics "$VM_NAME" >/dev/null 2>&1 &
        log "VM process started (background pid $!)."
    fi

    # 3. Wait for IP + SSH. Both functions print status to stderr only.
    local ip
    ip=$(wait_for_ip)
    wait_for_ssh "$ip"

    # 4. Install SSH key (idempotent).
    install_ssh_key "$ip"

    # Cache IP for other scripts.
    printf '%s\n' "$ip" > "$T9_DIR/.vm_ip"
    log "VM is UP. IP=$ip  (cached in $T9_DIR/.vm_ip)"
    # Also echo to stdout so callers see it.
    printf '[vm] UP: %s\n' "$ip"
}

cmd_down() {
    log "Stopping VM $VM_NAME ..."
    tart stop "$VM_NAME" 2>/dev/null && log "Stopped." || log "VM was not running."
    rm -f "$T9_DIR/.vm_ip"
}

cmd_destroy() {
    log "Destroying VM $VM_NAME ..."
    tart stop "$VM_NAME" 2>/dev/null || true
    tart delete "$VM_NAME" 2>/dev/null && log "Deleted." || log "VM did not exist."
    rm -f "$T9_DIR/.vm_ip"
}

cmd_reset() {
    log "Resetting VM $VM_NAME (stop -> delete -> re-clone from base) ..."
    tart stop "$VM_NAME" 2>/dev/null || true
    tart delete "$VM_NAME" 2>/dev/null || true
    log "Re-cloning $BASE_IMAGE -> $VM_NAME ..."
    tart clone "$BASE_IMAGE" "$VM_NAME"
    rm -f "$T9_DIR/.vm_ip"
    log "Reset complete. Run: vm.sh up"
}

cmd_ip() {
    local ip
    ip=$(tart ip "$VM_NAME" 2>/dev/null || true)
    if [[ -z "$ip" ]]; then
        die "VM is not running or IP not available."
    fi
    printf '%s\n' "$ip"
}

cmd_ssh() {
    local ip
    ip=$(tart ip "$VM_NAME" 2>/dev/null || true)
    [[ -n "$ip" ]] || die "VM not running (no IP)."
    [[ -f "$VM_KEY" ]] || die "SSH key not found at $VM_KEY — run vm.sh up first."
    exec ssh $SSH_OPTS "$VM_USER@$ip" "$@"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
CMD="${1:-}"
shift 2>/dev/null || true

case "$CMD" in
    up)      cmd_up ;;
    down)    cmd_down ;;
    destroy) cmd_destroy ;;
    reset)   cmd_reset ;;
    ip)      cmd_ip ;;
    ssh)
        # Strip leading "--" separator if present.
        [[ "${1:-}" == "--" ]] && shift
        cmd_ssh "$@"
        ;;
    *)
        printf 'Usage: vm.sh up|down|destroy|reset|ssh [-- cmd]|ip\n' >&2
        exit 1
        ;;
esac
