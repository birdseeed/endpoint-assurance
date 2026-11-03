#!/bin/zsh
##############################################################################
# test-decommission-staging.zsh — PAT-1109 second-round finding P2 E.
#
# The gate suite (test-decommission-gate.zsh) stubs _decommission_trigger_removal
# entirely so its own assertions stay focused on the verification decision.
# The orchestrator suite (test-decommission-orchestrator.zsh) starts from
# already-staged fixtures. Between the two, the actual staging handoff — the
# real asset copy, decommission-info.json creation, plist install,
# permissions, and the launchctl bootstrap call — was exercised by nothing.
# That handoff is exactly what the "not writable by a non-admin principal"
# acceptance criterion depends on, so this file drives the REAL
# _decommission_trigger_removal (extracted from the shipped
# patched-fetch-config.sh, same sentinel-extraction pattern as every other
# test in this suite) against a scratch root.
#
# What is stubbed, and why:
#   - `launchctl` — bootout/bootstrap against a real LaunchDaemon needs root
#     and a real launchd; stubbed as a recording function so this test can
#     assert both calls happened, in order, with the right arguments.
#   - `chown` — root:wheel ownership assignment needs actual root privilege,
#     even for a directory this test process itself created. Consistent
#     with this repo's existing documented precedent (see
#     test-agent-config-commit.zsh's own "what this does NOT cover" note:
#     "ownership enforcement itself needs root and is exercised only by hand
#     / integration testing"). Stubbed as a recording function so this test
#     can still assert the SCRIPT ATTEMPTS root:wheel ownership on every
#     staged file, which is the honest, achievable version of that
#     assertion without real root.
#   - `install -o root -g wheel ...` — same root-privilege limitation as
#     chown. `install` itself is NOT stubbed; only the -o/-g arguments are
#     stripped before delegating to the real `install` binary, so directory
#     creation, mode bits, and path handling are exercised for real.
#
# Everything else — file existence, file CONTENT (byte-for-byte, so a wrong
# source-to-destination mapping would be caught), chmod mode bits (a normal
# file owner can chmod their own files without root), decommission-info.json
# shape, and idempotency — is asserted against the REAL function's REAL
# side effects in a scratch directory tree.
#
# Run: zsh endpoint/test-decommission-staging.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
FETCH_SH="$SCRIPT_DIR/patched-fetch-config.sh"

DECOMM_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-decomm-staging-extract.XXXXXX")
awk '/PATCHED_DECOMMISSION_GATE_START/{f=1;next} /PATCHED_DECOMMISSION_GATE_END/{f=0} f' \
    "$FETCH_SH" > "$DECOMM_TMP"
if [[ ! -s "$DECOMM_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_DECOMMISSION_GATE block from $FETCH_SH"
    exit 1
fi

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

mode_of() { stat -f '%Lp' "$1" 2>/dev/null; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.decomm-staging-test.XXXXXX")
trap 'rm -rf "$WORK" "$DECOMM_TMP"' EXIT

# install: strip -o/-g (need real root) but keep -d/-m/paths, so directory
# creation and mode bits are exercised for real. See file header.
install() {
    local args=() skip_next=0 a
    for a in "$@"; do
        if (( skip_next )); then skip_next=0; continue; fi
        case "$a" in
            -o|-g) skip_next=1; continue ;;
        esac
        args+=("$a")
    done
    command install "${args[@]}"
}

CHOWN_CALLS=()
chown() { CHOWN_CALLS+=("$*"); }

LAUNCHCTL_CALLS=()
LAUNCHCTL_PRINT_SUCCEEDS=0   # 0 = "not already loaded" (the common case)
LAUNCHCTL_BOOTSTRAP_SUCCEEDS=1   # 1 = bootstrap succeeds (the common case);
                                 # non-author review (third round) test [8]
                                 # flips this to simulate a failed bootstrap.
launchctl() {
    LAUNCHCTL_CALLS+=("$*")
    if [[ "${1:-}" == "print" ]]; then
        return "$LAUNCHCTL_PRINT_SUCCEEDS"
    fi
    if [[ "${1:-}" == "bootstrap" ]]; then
        [[ "$LAUNCHCTL_BOOTSTRAP_SUCCEEDS" == "1" ]] && return 0 || return 1
    fi
    return 0
}

# MV_INFO_SHOULD_FAIL (non-author review, third round, test [7]): the
# publish of decommission-info.json (`mv -f "$info_tmp" ".../decommission-info.json"`)
# used to be unchecked. `mv` itself is stubbed here — not `install`-style
# arg-stripping, since the real `mv` needs no elevated privilege the test
# lacks; this stub exists purely so the test can force that ONE specific mv
# to fail deterministically, the same way LAUNCHCTL_* toggles force
# launchctl outcomes, without touching any other invocation of `mv` this
# process might make.
MV_INFO_SHOULD_FAIL=0
mv() {
    if [[ "$MV_INFO_SHOULD_FAIL" == "1" && "$*" == *"decommission-info.json"* ]]; then
        return 1
    fi
    command mv "$@"
}

log_jsonl() { :; }
PYTHON3="/usr/bin/python3"

reset() {
    rm -rf "$WORK/bundle" "$WORK/decomm" "$WORK/launchdaemons"
    mkdir -p "$WORK/bundle" "$WORK/launchdaemons"
    BUNDLE_DIR="$WORK/bundle"
    # PATCHED_DECOMMISSION_GATE's top-level statements assign
    # DECOMMISSION_DIR/DECOMMISSION_DAEMON_PLIST unconditionally from these
    # PATCHED_*-prefixed fallbacks EVERY time the block is sourced — plain
    # (non-PATCHED_*) variable assignments made before a `source` would be
    # clobbered back to the real production paths the instant it runs. Set
    # the override env-style vars instead, exactly as production's plist
    # sets none of them and gets the real defaults.
    PATCHED_DECOMMISSION_DIR="$WORK/decomm"
    PATCHED_DECOMMISSION_DAEMON_PLIST="$WORK/launchdaemons/com.patched.decommission.plist"
    CHOWN_CALLS=()
    LAUNCHCTL_CALLS=()
    LAUNCHCTL_PRINT_SUCCEEDS=1   # print fails (nonzero) -> "not already loaded" by default
    LAUNCHCTL_BOOTSTRAP_SUCCEEDS=1
    MV_INFO_SHOULD_FAIL=0

    printf '#!/bin/zsh\n# fake patched-decommission.sh\n' > "$BUNDLE_DIR/patched-decommission.sh"
    printf '#!/bin/bash\n# fake endpoint-uninstall.sh\n'  > "$BUNDLE_DIR/endpoint-uninstall.sh"
    printf '#!/bin/bash\n# fake macos-uninstall.sh\n'     > "$BUNDLE_DIR/macos-uninstall.sh"
    printf '<plist>fake com.patched.decommission.plist</plist>\n' > "$BUNDLE_DIR/com.patched.decommission.plist"
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] real staging: every asset lands in DECOMMISSION_DIR with correct content and mode bits"
reset
source "$DECOMM_TMP"   # sources with BUNDLE_DIR/DECOMMISSION_DIR/etc already set above
if _decommission_trigger_removal 1 "offboarded" "immediate" 42; then result=ok; else result=fail; fi
chk "reports success" "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "DECOMMISSION_DIR was created" "$([[ -d "$DECOMMISSION_DIR" ]] && echo 1 || echo 0)"
chk "DECOMMISSION_DIR mode is 700" "$([[ "$(mode_of "$DECOMMISSION_DIR")" == "700" ]] && echo 1 || echo 0)"

for f in patched-decommission.sh endpoint-uninstall.sh macos-uninstall.sh com.patched.decommission.plist; do
    chk "$f staged" "$([[ -f "$DECOMMISSION_DIR/$f" ]] && echo 1 || echo 0)"
    chk "$f content matches the bundle source byte-for-byte" \
        "$(diff -q "$BUNDLE_DIR/$f" "$DECOMMISSION_DIR/$f" >/dev/null 2>&1 && echo 1 || echo 0)"
done
chk "patched-decommission.sh mode is 700 (root-only exec)" "$([[ "$(mode_of "$DECOMMISSION_DIR/patched-decommission.sh")" == "700" ]] && echo 1 || echo 0)"
chk "endpoint-uninstall.sh mode is 700" "$([[ "$(mode_of "$DECOMMISSION_DIR/endpoint-uninstall.sh")" == "700" ]] && echo 1 || echo 0)"
chk "macos-uninstall.sh mode is 700" "$([[ "$(mode_of "$DECOMMISSION_DIR/macos-uninstall.sh")" == "700" ]] && echo 1 || echo 0)"
chk "com.patched.decommission.plist staged copy mode is 644" "$([[ "$(mode_of "$DECOMMISSION_DIR/com.patched.decommission.plist")" == "644" ]] && echo 1 || echo 0)"

chk "chown root:wheel was attempted on the staged scripts/plist (real ownership needs root — see file header)" \
    "$(printf '%s\n' "${CHOWN_CALLS[@]}" | grep -q "root:wheel" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] decommission-info.json: correct shape, correct values, mode 600"
INFO="$DECOMMISSION_DIR/decommission-info.json"
chk "decommission-info.json exists" "$([[ -f "$INFO" ]] && echo 1 || echo 0)"
chk "decommission-info.json mode is 600" "$([[ "$(mode_of "$INFO")" == "600" ]] && echo 1 || echo 0)"
info_json=$(cat "$INFO" 2>/dev/null)
chk "mode field is immediate" "$(printf '%s' "$info_json" | grep -q '"mode": *"immediate"' && echo 1 || echo 0)"
chk "purge field is true" "$(printf '%s' "$info_json" | grep -q '"purge": *true' && echo 1 || echo 0)"
chk "reason field is the operator-supplied text" "$(printf '%s' "$info_json" | grep -q '"reason": *"offboarded"' && echo 1 || echo 0)"
chk "directive_version field is 42, an integer not a string" "$(printf '%s' "$info_json" | grep -qE '"directive_version": *42[^"]' && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] plist installed to DECOMMISSION_DAEMON_PLIST with correct content and mode"
chk "plist installed at the target path" "$([[ -f "$DECOMMISSION_DAEMON_PLIST" ]] && echo 1 || echo 0)"
chk "installed plist content matches the bundle source" \
    "$(diff -q "$BUNDLE_DIR/com.patched.decommission.plist" "$DECOMMISSION_DAEMON_PLIST" >/dev/null 2>&1 && echo 1 || echo 0)"
chk "installed plist mode is 644" "$([[ "$(mode_of "$DECOMMISSION_DAEMON_PLIST")" == "644" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] launchctl bootout THEN bootstrap, in that order, against the real target plist path"
chk "launchctl was called at least twice (bootout, bootstrap)" "$([[ "${#LAUNCHCTL_CALLS[@]}" -ge 2 ]] && echo 1 || echo 0)"
bootout_line=""; bootstrap_line=""
for i in {1..${#LAUNCHCTL_CALLS[@]}}; do
    [[ "${LAUNCHCTL_CALLS[$i]}" == bootout* && -z "$bootout_line" ]] && bootout_line=$i
    [[ "${LAUNCHCTL_CALLS[$i]}" == bootstrap* && -z "$bootstrap_line" ]] && bootstrap_line=$i
done
chk "a bootout call for the decommission label happened" \
    "$(printf '%s\n' "${LAUNCHCTL_CALLS[@]}" | grep -q "bootout system/com.patched.decommission" && echo 1 || echo 0)"
chk "a bootstrap call against the real installed plist path happened" \
    "$(printf '%s\n' "${LAUNCHCTL_CALLS[@]}" | grep -qF "bootstrap system $DECOMMISSION_DAEMON_PLIST" && echo 1 || echo 0)"
chk "bootout happened before bootstrap" \
    "$([[ -n "$bootout_line" && -n "$bootstrap_line" && "$bootout_line" -lt "$bootstrap_line" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] idempotency: launchctl print reports the label already loaded — no restaging, no re-bootstrap"
reset
LAUNCHCTL_PRINT_SUCCEEDS=0   # 0 = success = "already loaded"
source "$DECOMM_TMP"
if _decommission_trigger_removal 1 "offboarded again" "immediate" 43; then result=ok; else result=fail; fi
chk "reports success (treats already-staged as fine, not an error)" "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "does not create DECOMMISSION_DIR when already staged" "$([[ ! -d "$DECOMMISSION_DIR" ]] && echo 1 || echo 0)"
chk "does not call launchctl bootstrap again" "$(! printf '%s\n' "${LAUNCHCTL_CALLS[@]}" | grep -q "^bootstrap" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[6] missing bundle asset: fails cleanly, does not partially stage, does not touch launchctl"
reset
rm -f "$BUNDLE_DIR/macos-uninstall.sh"   # simulate a broken/incomplete bundle
source "$DECOMM_TMP"
if _decommission_trigger_removal 0 "" "expiry_due" 1; then result=ok; else result=fail; fi
chk "reports failure" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "does not call launchctl bootstrap on a failed staging attempt" \
    "$(! printf '%s\n' "${LAUNCHCTL_CALLS[@]}" | grep -q "^bootstrap" && echo 1 || echo 0)"
chk "the daemon plist was never installed to the target path" "$([[ ! -f "$DECOMMISSION_DAEMON_PLIST" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[7] non-author review (third round): publishing decommission-info.json fails (mv error) — must NOT proceed to install the plist or bootstrap anything, and must not leave a stale/partial info file behind"
reset
MV_INFO_SHOULD_FAIL=1
source "$DECOMM_TMP"
if _decommission_trigger_removal 1 "offboarded" "immediate" 50; then result=ok; else result=fail; fi
chk "reports failure" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "decommission-info.json was NOT published at the destination (the failed mv's target must not be trusted)" \
    "$([[ ! -f "$DECOMMISSION_DIR/decommission-info.json" ]] && echo 1 || echo 0)"
chk "no leftover .info.XXXXXX temp file was left behind either (cleaned up on failure)" \
    "$([[ -z $(print -l "$DECOMMISSION_DIR"/.info.*(N)) ]] && echo 1 || echo 0)"
chk "the daemon plist was never installed to the target path" "$([[ ! -f "$DECOMMISSION_DAEMON_PLIST" ]] && echo 1 || echo 0)"
chk "launchctl bootstrap was never called — nothing bootstrapped against an unverified/unpublished directive" \
    "$(! printf '%s\n' "${LAUNCHCTL_CALLS[@]}" | grep -q "^bootstrap" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[8] non-author review (third round): launchctl bootstrap fails — the plist and decommission-info.json just installed/published must be REMOVED, not left armed for launchd to auto-run on a later boot"
reset
LAUNCHCTL_BOOTSTRAP_SUCCEEDS=0
source "$DECOMM_TMP"
if _decommission_trigger_removal 1 "offboarded" "immediate" 60; then result=ok; else result=fail; fi
chk "reports failure" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "launchctl bootstrap WAS attempted (proves this failure is genuinely coming from the bootstrap step, not an earlier one)" \
    "$(printf '%s\n' "${LAUNCHCTL_CALLS[@]}" | grep -q "^bootstrap" && echo 1 || echo 0)"
chk "the just-installed daemon plist was removed afterward — launchd cannot auto-load it on a later boot" \
    "$([[ ! -f "$DECOMMISSION_DAEMON_PLIST" ]] && echo 1 || echo 0)"
chk "the just-published decommission-info.json was removed afterward — no stale directive left for a stray load to consume" \
    "$([[ ! -f "$DECOMMISSION_DIR/decommission-info.json" ]] && echo 1 || echo 0)"
chk "DECOMMISSION_DIR itself (the staged scripts) is left in place — only the armed plist + info.json are cleaned up, per the fix's scope" \
    "$([[ -f "$DECOMMISSION_DIR/patched-decommission.sh" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
