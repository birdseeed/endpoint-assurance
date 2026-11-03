#!/bin/bash
##############################################################################
# induce.sh — PAT-739 T10 Layer B state induction driver.
#
# Usage: induce.sh apply|restore
#
# Copies apply_remote.sh / restore_remote.sh (+ pwpolicy XML + mobileconfig)
# into the running Tart VM and executes the requested phase as root over SSH,
# using this dir's vm_key for SSH (same key vm.sh installs on first `vm.sh up`).
##############################################################################
set -uo pipefail

MACOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_KEY="$MACOS_DIR/vm_key"
VM_USER="admin"

log()  { printf '[induce] %s\n' "$*"; }
die()  { printf '[induce] ERROR: %s\n' "$*" >&2; exit 1; }

MODE="${1:-}"
[[ "$MODE" == "apply" || "$MODE" == "restore" ]] || die "Usage: induce.sh apply|restore"

VM_IP=$(tart ip patched-e2e-macos 2>/dev/null || true)
[[ -n "$VM_IP" ]] || die "VM not running. Run vm.sh up first."
[[ -f "$VM_KEY" ]] || die "SSH key not found at $VM_KEY"

SOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$VM_KEY")

log "VM IP: $VM_IP  mode=$MODE"

log "Copying induction payload to VM:/tmp/t10-induce ..."
ssh "${SOPT[@]}" "$VM_USER@$VM_IP" "rm -rf /tmp/t10-induce && mkdir -p /tmp/t10-induce"
scp "${SOPT[@]}" \
    "$MACOS_DIR/apply_remote.sh" \
    "$MACOS_DIR/restore_remote.sh" \
    "$MACOS_DIR/original_pwpolicy.xml" \
    "$MACOS_DIR/induced_pwpolicy.xml" \
    "$MACOS_DIR/t10-test.mobileconfig" \
    "$VM_USER@$VM_IP:/tmp/t10-induce/"

if [[ "$MODE" == "apply" ]]; then
    log "Running apply_remote.sh as root ..."
    ssh "${SOPT[@]}" "$VM_USER@$VM_IP" "sudo bash /tmp/t10-induce/apply_remote.sh 2>&1"
else
    log "Running restore_remote.sh as root ..."
    ssh "${SOPT[@]}" "$VM_USER@$VM_IP" "sudo bash /tmp/t10-induce/restore_remote.sh 2>&1"
fi

RC=$?
log "Phase '$MODE' complete (rc=$RC)."
exit $RC
