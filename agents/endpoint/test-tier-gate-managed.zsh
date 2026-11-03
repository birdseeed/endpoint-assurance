#!/bin/zsh
##############################################################################
# test-tier-gate-managed.zsh: regression guard for the canonical two-value
# agent-tier vocabulary. Only managed may reach catalogue install or removal;
# assurance and every unknown value must fail closed.
#
# Extracts the SHIPPED sentinel-marked blocks (same convention as
# test-agent-tier-default.zsh / test-trigger-parsing.zsh), not
# copies, so the code under test is the code that ships. Each block is run
# in a subshell (source "$BLOCK"; ...) so its `exit 0` on the fail-closed
# path only ends that subshell, never this test script -- same pattern
# test-agent-tier-default.zsh's run_block() already uses.
#
# Run: zsh endpoint/test-tier-gate-managed.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
INSTALL_SH="$SCRIPT_DIR/patched-install.sh"
UNINSTALL_SH="$SCRIPT_DIR/patched-uninstall.sh"

INSTALL_BLOCK=$(mktemp "${TMPDIR:-/tmp}/patched-install-tier-gate.XXXXXX")
UNINSTALL_BLOCK=$(mktemp "${TMPDIR:-/tmp}/patched-uninstall-tier-gate.XXXXXX")
trap 'rm -f "$INSTALL_BLOCK" "$UNINSTALL_BLOCK"' EXIT

awk '/PATCHED_INSTALL_TIER_GATE_START/{f=1;next} /PATCHED_INSTALL_TIER_GATE_END/{f=0} f' \
    "$INSTALL_SH" > "$INSTALL_BLOCK"
awk '/PATCHED_UNINSTALL_TIER_GATE_START/{f=1;next} /PATCHED_UNINSTALL_TIER_GATE_END/{f=0} f' \
    "$UNINSTALL_SH" > "$UNINSTALL_BLOCK"

if [[ ! -s "$INSTALL_BLOCK" ]]; then
    echo "FATAL: could not extract PATCHED_INSTALL_TIER_GATE block from $INSTALL_SH"
    exit 1
fi
if [[ ! -s "$UNINSTALL_BLOCK" ]]; then
    echo "FATAL: could not extract PATCHED_UNINSTALL_TIER_GATE block from $UNINSTALL_SH"
    exit 1
fi

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# log_jsonl: patched-install.sh's tier-gate block calls this on the
# fail-closed path. Stubbed as a no-op here, same as this repo's other
# extracted-block tests stub whatever helper the block calls but doesn't
# define itself.
log_jsonl() { :; }

# run_install_gate <tier>: sources the extracted install block with
# AGENT_TIER preset, in a subshell (the block's `exit 0` only ends the
# subshell), and echoes whichever of the two log lines the block printed.
run_install_gate() {
    local AGENT_TIER="$1"
    (
        source "$INSTALL_BLOCK"
    )
}

run_uninstall_gate() {
    local AGENT_TIER="$1"
    (
        FILTER_APP_ID=""
        LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=42
        legacy_app_execution_enabled() { return 0; }
        source "$UNINSTALL_BLOCK"
    )
}

gate_passed() {  # $1 = captured output
    [[ "$1" == *"Tier gate OK:"* ]]
}

gate_rejected() {  # $1 = captured output
    [[ "$1" == *" is not managed; skipping "* ]]
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] install gate: AGENT_TIER=managed passes"
out=$(run_install_gate "managed")
chk "install gate OK for managed" "$(gate_passed "$out" && echo 1 || echo 0)"

echo "[2] uninstall gate: AGENT_TIER=managed passes"
out=$(run_uninstall_gate "managed")
chk "uninstall gate OK for managed" "$(gate_passed "$out" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] install gate: AGENT_TIER=assurance is rejected"
out=$(run_install_gate "assurance")
chk "install gate rejects assurance" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[4] uninstall gate: AGENT_TIER=assurance is rejected"
out=$(run_uninstall_gate "assurance")
chk "uninstall gate rejects assurance" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[5] install gate: retired AGENT_TIER=allowlist_scan is rejected"
out=$(run_install_gate "allowlist_scan")
chk "install gate rejects retired allowlist_scan" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[6] uninstall gate: retired AGENT_TIER=allowlist_scan is rejected"
out=$(run_uninstall_gate "allowlist_scan")
chk "uninstall gate rejects retired allowlist_scan" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[7] install gate: retired AGENT_TIER=full_remediate is rejected"
out=$(run_install_gate "full_remediate")
chk "install gate rejects retired full_remediate" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[8] uninstall gate: retired AGENT_TIER=full_remediate is rejected"
out=$(run_uninstall_gate "full_remediate")
chk "uninstall gate rejects retired full_remediate" "$(gate_rejected "$out" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[9] install gate: retired AGENT_TIER=patch is rejected"
out=$(run_install_gate "patch")
chk "install gate rejects retired patch" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[10] uninstall gate: retired AGENT_TIER=patch is rejected"
out=$(run_uninstall_gate "patch")
chk "uninstall gate rejects retired patch" "$(gate_rejected "$out" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[11] install gate: an unrecognised tier value fails closed"
out=$(run_install_gate "some-future-tier-nobody-taught-this-script-yet")
chk "install gate rejects unrecognised tier" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[12] uninstall gate: an unrecognised tier value fails closed"
out=$(run_uninstall_gate "some-future-tier-nobody-taught-this-script-yet")
chk "uninstall gate rejects unrecognised tier" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[13] install gate: an empty tier value fails closed"
out=$(run_install_gate "")
chk "install gate rejects empty tier" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[14] uninstall gate: an empty tier value fails closed"
out=$(run_uninstall_gate "")
chk "uninstall gate rejects empty tier" "$(gate_rejected "$out" && echo 1 || echo 0)"

echo "[15] requested uninstall reports authority refusal before report-tier no-op"
(
    AGENT_TIER="assurance"
    FILTER_APP_ID="Requested App"
    LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=42
    legacy_app_execution_enabled() { return 1; }
    source "$UNINSTALL_BLOCK" >/dev/null
)
requested_rc=$?
chk "requested app exits 42 when refreshed authority is revoked at report tier" \
    "$([[ $requested_rc -eq 42 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo ""
echo "Results: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
