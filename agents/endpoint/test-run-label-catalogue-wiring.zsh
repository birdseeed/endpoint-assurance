#!/bin/zsh
##############################################################################
# test-run-label-catalogue-wiring.zsh: PAT-1028 round 6, finding 1
# ("test the wiring, not just the decision functions").
#
# Every test in test-get-pinned-sha256.zsh passes even if run_label's
# suppression flags were deleted: those tests only prove
# get_pinned_sha256() COMPUTES the right answer. Nothing proved that run_label() actually READS that answer
# and REFUSES to invoke the engine because of it. That is precisely the
# PAT-1035 shape this ticket keeps citing: a control that computes the
# right answer while nothing downstream honours it.
#
# run_label() has too many transitive dependencies (bpp_*, emit_provenance,
# emit_audit_event, get_mirror_*, is_version_blocked, log_jsonl, and module-
# level globals like AGENT_TIER/BPP_ACTION_ON_TIMEOUT/TENANT_ID/HW_UUID
# populated by real top-level script code (credential reads, ioreg,
# scutil, HTTP calls) to extract and drive directly without sourcing large,
# fragile swaths of a 2600+ line file that executes real system interaction
# at the top level when sourced as a whole. That is the "restructuring" the
# round-6 instruction says not to reach for at the tail of this ticket.
#
# So this is the preferred, smaller option instead: a structural assertion
# against the SHIPPED SOURCE (an ordering test). It
# cannot prove run_label's runtime behaviour in isolation, but it DOES fail
# if any of the following regress, which is exactly the class of silent
# regression the finding is about:
#   - get_pinned_sha256's exit code stops being captured at all;
#   - either suppression flag stops being SET from that exit code;
#   - either flag is dropped from the branch condition that decides
#     scan-vs-install (the actual point that suppresses the engine call);
#   - the wiring is moved to AFTER the engine invocation, which would make
#     it compute the right answer too late to matter.
#
# Run: zsh endpoint/test-run-label-catalogue-wiring.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

line_of() {  # line_of <pattern>: first matching line number, or empty
    grep -n -- "$1" "$UPDATE_SH" | head -1 | cut -d: -f1
}

# ---------------------------------------------------------------------------
echo "[1] get_pinned_sha256's exit code is actually captured, not discarded"
_capture_line=$(line_of '_pinned_sha256=\$(get_pinned_sha256 "\$label"); _pinned_rc=\$?')
chk "the capture line exists in the shipped source" "$([[ -n "$_capture_line" ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[2] exit 2 (SHAPE_ERROR) sets catalogue_shape_failclosed=1"
_shape_flag_line=$(line_of '\[\[ \$_pinned_rc -eq 2 \]\] && catalogue_shape_failclosed=1')
chk "the shape-error flag assignment exists" "$([[ -n "$_shape_flag_line" ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[3] exit 3 (NO_PIN) sets catalogue_unverified_failclosed=1"
_unverified_if_line=$(line_of '\[\[ \$_pinned_rc -eq 3 \]\]; then')
_unverified_flag_line=$(line_of '^ *catalogue_unverified_failclosed=1$')
chk "the exit-3 check exists" "$([[ -n "$_unverified_if_line" ]] && echo 1 || echo 0)"
chk "the unverified flag assignment exists" "$([[ -n "$_unverified_flag_line" ]] && echo 1 || echo 0)"
chk "the flag assignment follows shortly after the exit-3 check (same guarded block)" \
    "$([[ -n "$_unverified_if_line" && -n "$_unverified_flag_line" && $(( _unverified_flag_line - _unverified_if_line )) -ge 0 && $(( _unverified_flag_line - _unverified_if_line )) -le 5 ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[4] BOTH flags actually appear in the branch condition that forces scan mode"
_branch_line_num=$(grep -n '"\$mode" == "scan"' "$UPDATE_SH" | head -1 | cut -d: -f1)
_branch_line_text=$(grep '"\$mode" == "scan"' "$UPDATE_SH" | head -1)
chk "the scan/install branch condition exists" "$([[ -n "$_branch_line_num" ]] && echo 1 || echo 0)"
chk "catalogue_shape_failclosed is IN that branch condition (not just computed and ignored)" \
    "$([[ "$_branch_line_text" == *'catalogue_shape_failclosed'* ]] && echo 1 || echo 0)"
chk "catalogue_unverified_failclosed is IN that branch condition (not just computed and ignored)" \
    "$([[ "$_branch_line_text" == *'catalogue_unverified_failclosed'* ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[5] the wiring happens BEFORE the branch decision, and the branch decision happens BEFORE the engine is ever invoked"
_installomator_line=$(grep -n '"\$INSTALLOMATOR" "\$label"' "$UPDATE_SH" | head -1 | cut -d: -f1)
chk "the engine invocation line exists" "$([[ -n "$_installomator_line" ]] && echo 1 || echo 0)"
chk "the pinned-hash capture happens before the branch decision" \
    "$([[ -n "$_capture_line" && -n "$_branch_line_num" && "$_capture_line" -lt "$_branch_line_num" ]] && echo 1 || echo 0)"
chk "the branch decision happens before the engine is invoked (line $_branch_line_num < line $_installomator_line)" \
    "$([[ -n "$_branch_line_num" && -n "$_installomator_line" && "$_branch_line_num" -lt "$_installomator_line" ]] && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
