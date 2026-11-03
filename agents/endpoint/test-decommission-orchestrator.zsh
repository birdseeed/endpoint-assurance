#!/bin/zsh
##############################################################################
# test-decommission-orchestrator.zsh — regression tests for the detached
# removal orchestrator, endpoint/patched-decommission.sh (PAT-1109, plus
# the second-round P1 B / P1 C / 409-abort contract update).
#
# patched-decommission.sh hardcodes real system paths behind PATCHED_*-
# prefixed env-var overrides — same convention as patched-fetch-config.sh.
# This test drives a checked scratch copy with id/curl/launchctl stubs.
# Only one literal system-only PATH line is rewritten in the owned copy;
# production has no PATH override or test-injection switch.
#
# What this covers:
#   - Refuses without decommission-info.json / a valid directive_version.
#   - TWO-PHASE reporting (PAT-1109 second round P1 B): "acknowledged" is
#     posted and durable BEFORE either uninstall engine runs; the genuine
#     terminal outcome ("removed" or "failed") is posted only after removal
#     is VERIFIED, never claimed in advance.
#   - 409 Conflict on the acknowledged post is a DEFINITIVE abort: no
#     removal happens, nothing is left staged for a later boot to resurrect
#     (the exact interaction the coordinator flagged against the no-cancel
#     decision).
#   - A genuine network failure (not 409) on the acknowledged post falls
#     back to bounded-retry-then-proceed, distinct from the 409 case.
#   - VERIFY-BEFORE-CLEANUP (PAT-1109 second round P1 C): a non-zero
#     uninstall exit, and a missing staged engine that did NOT actually
#     achieve the verified state, both leave the daemon and its staging in
#     place for retry — never torn down on unverified completion.
#   - purge=true only purges (and only self-cleans) once BOTH the core
#     removal AND the purge step are independently verified.
#   - Idempotent: an already-completed acknowledge phase is not re-sent.
#
# What this does NOT cover, and why:
#   - The real endpoint/uninstall.sh and macos/uninstall.sh content this
#     script stages and runs — covered by their own existing suites. This
#     file uses configurable fake stand-ins that manipulate the same
#     VERIFY_* target paths patched-decommission.sh itself checks, so
#     failures here are unambiguously about ORCHESTRATION (report/verify/
#     cleanup ordering, purge threading, 409 handling, retry-safety), not
#     about uninstall.sh's own internals.
#   - Actual reboot/power-loss survival — cannot be exercised without real
#     hardware.
#
# Run: zsh endpoint/test-decommission-orchestrator.zsh
##############################################################################

set -u
export PATCHED_API_URL="http://127.0.0.1:1"
SCRIPT_DIR="${0:A:h}"
DECOMM_SH="$SCRIPT_DIR/patched-decommission.sh"

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# ---------------------------------------------------------------------------
# Stub bin/ dir: id (root check) and curl (status reporting). launchctl is
# also stubbed since self_cleanup calls it; bootout/bootstrap are
# best-effort in production too (`2>/dev/null || true`) so this stub always
# succeeds for them. `print` is different: verify_core_removed (non-author
# review, third round) now checks _launchd_label_loaded, which shells out to
# `launchctl print system/<label>` and trusts its exit code — 0 means
# loaded, nonzero means not-found/not-loaded, matching real launchctl. This
# stub defaults every `print` to "not loaded" (exit 1), matching a real box
# after a successful bootout — the common, happy-path case every existing
# test exercises. LOADED_LABELS (space-separated, threaded through the same
# env-var-prefix mechanism as CURL_HTTP_CODE/CURL_BODY_MODE below) lets a
# test simulate "the plist is gone but launchd still has this label loaded"
# — a `bootout` that silently failed — for exactly the labels it names.
# ---------------------------------------------------------------------------
FAKE_BIN=$(mktemp -d "${TMPDIR:-/tmp}/.decomm-orch-bin.XXXXXX")
cat > "$FAKE_BIN/id" <<'EOF'
#!/bin/sh
echo 0
EOF
cat > "$FAKE_BIN/launchctl" <<'EOF'
#!/bin/zsh
if [[ "${1:-}" == "print" ]]; then
    target="${2:-}"
    label="${target#system/}"
    for l in ${=LOADED_LABELS:-}; do
        if [[ "$l" == "$label" ]]; then
            echo "$target = { active count = 1 }"
            exit 0
        fi
    done
    echo "Could not find service \"$label\" in domain for system" >&2
    exit 1
fi
exit 0
EOF
# curl stub. patched-decommission.sh's contract is keyed off the RESPONSE
# BODY's `decommission` field, not the bare HTTP status — so this stub lets
# tests set the status code and the body shape INDEPENDENTLY:
#   CURL_HTTP_CODE   -> the numeric status to return (e.g. 200, 409). Unset
#                       (the default) means "cannot reach the platform at
#                       all" -> returns 000, matching curl's own real
#                       behaviour on a failed connection.
#   CURL_BODY_MODE   -> proceed | superseded | garbled | empty | (unset -> {})
#                       shapes the response body written to the -o target,
#                       independent of CURL_HTTP_CODE, so a test can drive
#                       exactly "200 with a garbled body" or "409 with an
#                       empty body" as their own distinct scenarios.
cat > "$FAKE_BIN/curl" <<'EOF'
#!/bin/zsh
write_body_to_dashO() {
    local args=("$@") i target
    for ((i=1; i<=$#args; i++)); do
        if [[ "${args[i]}" == "-o" ]]; then
            target="${args[i+1]}"
            case "${CURL_BODY_MODE:-}" in
                proceed)    echo '{"decommission":"proceed","device_id":"d1","recorded_status":"acknowledged"}' > "$target" ;;
                superseded) echo '{"decommission":"superseded","device_id":"d1"}' > "$target" ;;
                garbled)    printf '{"decommission": "proc' > "$target" ;;   # truncated/invalid JSON
                empty)      : > "$target" ;;
                *)          echo '{}' > "$target" ;;
            esac
        fi
    done
}
if [[ -n "${CURL_HTTP_CODE:-}" ]]; then
    write_body_to_dashO "$@"
    printf '%s' "$CURL_HTTP_CODE"
    exit 0
fi
printf '000'
exit 7
EOF
chmod +x "$FAKE_BIN/id" "$FAKE_BIN/launchctl" "$FAKE_BIN/curl"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.decomm-orch-test.XXXXXX")
trap 'rm -rf "$WORK" "$FAKE_BIN"' EXIT

DECOMM_COPY="$WORK/decommission-under-test.sh"
prepare_decomm_copy() {
    rm -f "$DECOMM_COPY"
    /usr/bin/python3 "$SCRIPT_DIR/../ci/privileged_script_fixture.py" \
        "$DECOMM_SH" "$DECOMM_COPY" "$1" || exit 1
}

CREDS="$WORK/creds"
BUNDLE_DEST="$WORK/bundle_dest"
LAUNCHDAEMONS="$WORK/launchdaemons"
BIN_DIR="$WORK/bin"
# PAT-2395: the pre-move location, verified as removed alongside BIN_DIR.
LEGACY_BIN_DIR="$WORK/legacy-bin"
QUEUE_BASE="$WORK/queue"
CALLS_LOG="$WORK/calls.log"

ENDPOINT_PLISTS=(com.patched.update.plist com.patched.config-poll.plist com.patched.install-check.plist
                 com.patched.uninstall-check.plist com.patched.catalogue-poll.plist com.patched.posture-poll.plist)
MACOS_PLISTS=(com.patched.collect.plist com.patched.upload.plist)
MACOS_BINARIES=(patched-collect.sh patched-upload.sh)

setup_creds() {
    mkdir -p "$CREDS"
    printf 'bearer-token-value\n' > "$CREDS/bearer-token"
    printf '%s\n' "$(printf 'x%.0s' {1..32} | base64)" > "$CREDS/hmac-secret"
}

# seed_installed_state
#   Populates BUNDLE_DEST/LAUNCHDAEMONS/BIN_DIR/QUEUE_BASE as if the agent
#   were genuinely installed, so verify_core_removed/verify_purge_removed
#   start out FALSE (not removed) until a fake engine actually clears them —
#   the same starting condition a real box would have.
seed_installed_state() {
    rm -rf "$BUNDLE_DEST" "$LAUNCHDAEMONS" "$BIN_DIR" "$LEGACY_BIN_DIR" "$QUEUE_BASE"
    mkdir -p "$BUNDLE_DEST" "$LAUNCHDAEMONS" "$BIN_DIR" "$LEGACY_BIN_DIR" "$QUEUE_BASE"
    touch "$BUNDLE_DEST/patched-fetch-config.sh"
    local p
    for p in "${ENDPOINT_PLISTS[@]}" "${MACOS_PLISTS[@]}"; do touch "$LAUNCHDAEMONS/$p"; done
    for p in "${MACOS_BINARIES[@]}"; do touch "$BIN_DIR/$p" "$LEGACY_BIN_DIR/$p"; done
}

# write_fake_endpoint_uninstall <dest_path> <remove:0|1> <exit_code>
#   NOTE: local var deliberately named dest_path, never `path` — zsh ties
#   `path` to `$PATH` via typeset -T; assigning a local `path` here
#   corrupted $PATH for the rest of this test run and made plain `chmod`
#   fail with "command not found" a few lines down (see AGENTS.md's
#   footgun list). Found and fixed while reconciling this suite for PAT-1136.
write_fake_endpoint_uninstall() {
    local dest_path="$1" remove="$2" exit_code="$3"
    {
        echo '#!/bin/bash'
        echo "echo endpoint-ran >> '$CALLS_LOG'"
        if [[ "$remove" == "1" ]]; then
            echo "rm -rf '$BUNDLE_DEST'"
            local p
            for p in "${ENDPOINT_PLISTS[@]}"; do echo "rm -f '$LAUNCHDAEMONS/$p'"; done
        fi
        echo "exit $exit_code"
    } > "$dest_path"
    chmod +x "$dest_path"
}

# write_fake_macos_uninstall <dest_path> <remove:0|1> <exit_code> <purge_remove:0|1> <purge_exit_code>
#   Same `path`-name footgun fix as write_fake_endpoint_uninstall above.
write_fake_macos_uninstall() {
    local dest_path="$1" remove="$2" exit_code="$3" purge_remove="$4" purge_exit="$5"
    {
        echo '#!/bin/bash'
        echo 'if [[ "${1:-}" == "--purge" ]]; then'
        echo "  echo 'macos-ran --purge' >> '$CALLS_LOG'"
        if [[ "$purge_remove" == "1" ]]; then
            echo "  rm -rf '$CREDS' '$QUEUE_BASE'"
        fi
        echo "  exit $purge_exit"
        echo 'else'
        echo "  echo macos-ran >> '$CALLS_LOG'"
        if [[ "$remove" == "1" ]]; then
            local p
            for p in "${MACOS_BINARIES[@]}"; do echo "  rm -f '$BIN_DIR/$p' '$LEGACY_BIN_DIR/$p'"; done
            for p in "${MACOS_PLISTS[@]}"; do echo "  rm -f '$LAUNCHDAEMONS/$p'"; done
        fi
        echo "  exit $exit_code"
        echo 'fi'
    } > "$dest_path"
    chmod +x "$dest_path"
}

# stage <decomm-dir> <info-json> <endpoint:remove|noop> <endpoint-exit> <macos:remove|noop> <macos-exit> [purge:remove|noop] [purge-exit]
stage() {
    local dir="$1" info_json="$2" ep_mode="$3" ep_exit="$4" mac_mode="$5" mac_exit="$6"
    local purge_mode="${7:-remove}" purge_exit="${8:-0}"
    rm -rf "$dir"; mkdir -p "$dir"
    printf '%s' "$info_json" > "$dir/decommission-info.json"
    write_fake_endpoint_uninstall "$dir/endpoint-uninstall.sh" "$([[ "$ep_mode" == "remove" ]] && echo 1 || echo 0)" "$ep_exit"
    write_fake_macos_uninstall "$dir/macos-uninstall.sh" "$([[ "$mac_mode" == "remove" ]] && echo 1 || echo 0)" "$mac_exit" \
        "$([[ "$purge_mode" == "remove" ]] && echo 1 || echo 0)" "$purge_exit"
    printf 'placeholder\n' > "$dir/patched-decommission.sh"
    printf 'placeholder\n' > "$dir/com.patched.decommission.plist"
}

# run_decomm <decomm-dir>
LOG_FILE_PATH=""
run_decomm() {
    LOG_FILE_PATH="$(dirname "$1")/decommission-$$-$RANDOM.log"
    rm -f "$LOG_FILE_PATH"
    prepare_decomm_copy "$FAKE_BIN"
    PATCHED_DECOMMISSION_DIR="$1" \
    PATCHED_CREDS_DIR="$CREDS" \
    PATCHED_API_URL="http://127.0.0.1:1" \
    PATCHED_LOG_FILE="$LOG_FILE_PATH" \
    PATCHED_DECOMMISSION_DAEMON_PLIST="$(dirname "$1")/com.patched.decommission.plist" \
    PATCHED_VERIFY_ENDPOINT_BUNDLE_DEST="$BUNDLE_DEST" \
    PATCHED_VERIFY_LAUNCHDAEMONS_DIR="$LAUNCHDAEMONS" \
    PATCHED_VERIFY_MACOS_BIN_DIR="$BIN_DIR" \
    PATCHED_VERIFY_MACOS_LEGACY_BIN_DIR="$LEGACY_BIN_DIR" \
    PATCHED_VERIFY_CREDS_DIR="$CREDS" \
    PATCHED_VERIFY_QUEUE_BASE="$QUEUE_BASE" \
    zsh "$DECOMM_COPY"
    return $?
}
log_of() { cat "$LOG_FILE_PATH" 2>/dev/null; }

DECOMM_DIR="$WORK/decomm"

# ───────────────────────────────────────────────────────────────────────────
echo "[1] no decommission-info.json staged: refuses, removes nothing, exits non-zero"
setup_creds
rm -rf "$DECOMM_DIR"; mkdir -p "$DECOMM_DIR"
run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the missing info file" "$(echo "$out" | grep -qi "decommission-info.json missing" && echo 1 || echo 0)"
chk "DECOMM_DIR still exists" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] decommission-info.json present but missing directive_version: refuses"
setup_creds
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null}' remove 0 remove 0
run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the missing directive_version" "$(echo "$out" | grep -qi "directive_version" && echo 1 || echo 0)"
chk "DECOMM_DIR still exists" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] happy path, purge=false: acknowledged reported BEFORE either engine runs, removal verified, removed reported, self-cleanup"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":"offboarded","directive_version":7}' remove 0 remove 0
touch "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist"
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits zero" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
ack_line=$(echo "$out" | grep -n "status=acknowledged reported" | head -1 | cut -d: -f1)
removed_line=$(echo "$out" | grep -n "status=removed reported" | head -1 | cut -d: -f1)
engine_line=$(echo "$out" | grep -n "running endpoint-uninstall.sh" | head -1 | cut -d: -f1)
chk "acknowledged is reported at all" "$([[ -n "$ack_line" ]] && echo 1 || echo 0)"
chk "acknowledged reported BEFORE either engine runs" \
    "$([[ -n "$ack_line" && -n "$engine_line" && "$ack_line" -lt "$engine_line" ]] && echo 1 || echo 0)"
chk "removed is reported AFTER the engines run (never claimed in advance)" \
    "$([[ -n "$engine_line" && -n "$removed_line" && "$engine_line" -lt "$removed_line" ]] && echo 1 || echo 0)"
chk "no status=failed report was ever sent" "$(! echo "$out" | grep -q "status=failed reported" && echo 1 || echo 0)"
chk "endpoint engine ran" "$(grep -qx "endpoint-ran" "$CALLS_LOG" && echo 1 || echo 0)"
chk "macos engine ran WITHOUT --purge" "$(grep -qx "macos-ran" "$CALLS_LOG" && echo 1 || echo 0)"
chk "macos engine did NOT run with --purge (purge:false)" "$(! grep -q -- '--purge' "$CALLS_LOG" && echo 1 || echo 0)"
chk "core removal is genuinely verified gone (bundle dest, plists, binaries)" \
    "$([[ ! -d "$BUNDLE_DEST" ]] && echo 1 || echo 0)"
chk "credentials/queue left in place (purge:false)" "$([[ -d "$CREDS" && -d "$QUEUE_BASE" ]] && echo 1 || echo 0)"
chk "self-cleanup removed DECOMM_DIR" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "self-cleanup removed the plist" "$([[ ! -f "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] happy path, purge=true: purge step runs and is verified after core removal; self-cleanup only after BOTH are verified"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"expiry","purge":true,"reason":null,"directive_version":11}' remove 0 remove 0 remove 0
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits zero" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "macos engine ran WITH --purge" "$(grep -qx "macos-ran --purge" "$CALLS_LOG" && echo 1 || echo 0)"
chk "credentials removed" "$([[ ! -d "$CREDS" ]] && echo 1 || echo 0)"
chk "queue removed" "$([[ ! -d "$QUEUE_BASE" ]] && echo 1 || echo 0)"
chk "self-cleanup completed" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
# non-author review P1-C: exactly ONE "removed" report, sent only after
# purge is verified (never one for core, then a second/different one for
# purge) — using the pre-purge credential snapshot, since real CREDS_DIR is
# already gone by the time this report is sent.
removed_count=$(echo "$out" | grep -c "status=removed reported")
purge_ran_line=$(echo "$out" | grep -n "running macos-uninstall.sh --purge" | head -1 | cut -d: -f1)
removed_line=$(echo "$out" | grep -n "status=removed reported" | head -1 | cut -d: -f1)
chk "P1-C: exactly one status=removed report was sent" "$([[ $removed_count -eq 1 ]] && echo 1 || echo 0)"
chk "P1-C: the removed report was sent AFTER purge ran, not before (the authoritative report reflects purge too)" \
    "$([[ -n "$purge_ran_line" && -n "$removed_line" && "$purge_ran_line" -lt "$removed_line" ]] && echo 1 || echo 0)"
chk "P1-C: the credential snapshot used to send that report was cleaned up afterward" \
    "$([[ ! -d "$DECOMM_DIR/.creds-snapshot" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# abort_test <label> <curl_http_code> <curl_body_mode> <log-grep-for-the-specific-reason>
#   Shared body for every "this must abort, nothing removed, nothing staged"
#   scenario (PAT-1109 second round, final contract wording): the platform
#   answer is keyed off the response BODY's `decommission` field, never the
#   bare HTTP status code, so these deliberately vary status code and body
#   shape independently to prove that.
abort_test() {
    local label="$1" http_code="$2" body_mode="$3" reason_grep="$4"
    echo "[$label]"
    setup_creds
    seed_installed_state
    : > "$CALLS_LOG"
    stage "$DECOMM_DIR" '{"mode":"immediate","purge":true,"reason":null,"directive_version":9}' remove 0 remove 0 remove 0
    touch "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist"
    CURL_HTTP_CODE="$http_code" CURL_BODY_MODE="$body_mode" run_decomm "$DECOMM_DIR"; local rc=$?
    local out; out=$(log_of)
    chk "exits zero (a clean, intentional abort, not a script failure)" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
    chk "log names the abort explicitly" "$(echo "$out" | grep -qi "ABORT" && echo 1 || echo 0)"
    chk "log names the specific reason ($reason_grep)" "$(echo "$out" | grep -qi "$reason_grep" && echo 1 || echo 0)"
    chk "NEITHER engine ran" "$([[ ! -f "$CALLS_LOG" || ! -s "$CALLS_LOG" ]] && echo 1 || echo 0)"
    chk "the agent is still fully installed (bundle dest untouched)" "$([[ -d "$BUNDLE_DEST" ]] && echo 1 || echo 0)"
    chk "LaunchDaemons untouched" "$([[ -f "$LAUNCHDAEMONS/com.patched.update.plist" ]] && echo 1 || echo 0)"
    chk "credentials untouched" "$([[ -d "$CREDS" ]] && echo 1 || echo 0)"
    chk "no status=removed or status=failed report was ever sent" \
        "$(! echo "$out" | grep -qE "status=(removed|failed) reported" && echo 1 || echo 0)"
    chk "DECOMM_DIR fully cleaned up — nothing staged to resurrect this attempt on a later boot" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
    chk "the daemon plist was cleaned up too" "$([[ ! -f "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" ]] && echo 1 || echo 0)"
}

# ───────────────────────────────────────────────────────────────────────────
# [5] The canonical case: HTTP 409 carrying an explicit decommission=superseded
# body — DEFINITIVE ABORT — no removal attempted, nothing left staged, agent
# fully installed and running.
abort_test "5] 409 with an explicit decommission=superseded body: DEFINITIVE ABORT" 409 superseded "superseded"

# ───────────────────────────────────────────────────────────────────────────
# [5b] PAT-1109 second round, final contract wording: a 200 whose body is
# missing/unparseable/unrecognised is NOT treated as "proceed" just because
# the status code looks successful — the body field is the actual contract,
# and a malformed body must default to abort, never be pattern-matched as
# a yes.
abort_test "5b] 200 OK status with a GARBLED (truncated/invalid JSON) body: still aborts — the status code is not the contract, the body field is" 200 garbled "unparseable"

# ───────────────────────────────────────────────────────────────────────────
# [5c] A 409 whose body is empty — same abort outcome as the canonical
# superseded case, but reached via "unparseable" (no decommission field to
# read at all) rather than an explicit superseded value, proving both paths
# converge on the same fail-closed action.
abort_test "5c] 409 with an EMPTY body: aborts (no readable decommission field is not treated as permission to proceed)" 409 empty "unparseable"

# ───────────────────────────────────────────────────────────────────────────
echo "[5d] explicit decommission=proceed body (200) lets removal continue — the positive-path counterpart to 5/5b/5c, proving the parser is not simply defaulting to abort unconditionally"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":13}' remove 0 remove 0
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits zero" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "does not abort" "$(! echo "$out" | grep -qi "ABORT" && echo 1 || echo 0)"
chk "removal proceeded" "$(grep -qx "endpoint-ran" "$CALLS_LOG" && grep -qx "macos-ran" "$CALLS_LOG" && echo 1 || echo 0)"
chk "self-cleanup completed" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[6] genuine transport failure (cannot reach the platform at all) on the acknowledged post: falls back to bounded-retry-then-proceed, distinct from a reachable-but-abort-worthy response"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":3}' remove 0 remove 0
start_ts=$(date +%s)
run_decomm "$DECOMM_DIR"; rc=$?
elapsed=$(( $(date +%s) - start_ts ))
out=$(log_of)
chk "exits zero (proceeds despite the acknowledged post going unreported)" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "logs 3 acknowledged POST attempts (bounded retry, not a single try)" \
    "$([[ $(echo "$out" | grep -c "status=acknowledged POST attempt") -eq 3 ]] && echo 1 || echo 0)"
chk "does NOT log an ABORT (a network failure is not a 409)" "$(! echo "$out" | grep -qi "ABORT" && echo 1 || echo 0)"
chk "removal still proceeded despite the unreported acknowledged post" \
    "$(grep -qx "endpoint-ran" "$CALLS_LOG" && grep -qx "macos-ran" "$CALLS_LOG" && echo 1 || echo 0)"
chk "bounded: did not hang" "$([[ $elapsed -lt 60 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1109 second round P1 C — this is the exact acceptance criterion the
# finding named: a non-zero uninstall exit must leave the daemon and its
# staging IN PLACE for retry, never torn down on unverified completion.
echo "[7] P1 C: endpoint-uninstall.sh exits non-zero AND does not actually remove its targets — verification correctly fails, status=failed is reported, DECOMM_DIR and the plist SURVIVE for retry (not self-cleaned)"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":5}' noop 1 remove 0
touch "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist"
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "status=failed was reported" "$(echo "$out" | grep -qi "status=failed reported" && echo 1 || echo 0)"
chk "log explains it is leaving staging in place for next-boot retry" "$(echo "$out" | grep -qi "retry on next boot" && echo 1 || echo 0)"
chk "DECOMM_DIR SURVIVES (not torn down on an unverified/failed attempt)" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "the daemon plist SURVIVES too" "$([[ -f "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" ]] && echo 1 || echo 0)"
chk "the staged engines are still present, ready to be retried" "$([[ -f "$DECOMM_DIR/endpoint-uninstall.sh" ]] && echo 1 || echo 0)"
chk "the acknowledge marker persists (so a retry does not re-send acknowledged)" "$([[ -f "$DECOMM_DIR/.ack-done" ]] && echo 1 || echo 0)"

echo "[7b] retrying case [7]: re-staging the same DECOMM_DIR with a working endpoint engine completes and verifies cleanly (proves the retry path actually finishes, not just survives)"
write_fake_endpoint_uninstall "$DECOMM_DIR/endpoint-uninstall.sh" 1 0
run_decomm "$DECOMM_DIR"; rc=$?
out2=$(log_of)
chk "exits zero on the successful retry" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "does not re-send acknowledged on the retry (already marked done)" "$(echo "$out2" | grep -qi "already completed in a prior run" && echo 1 || echo 0)"
chk "self-cleanup completes once verification finally succeeds" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[8] P1 C: staged endpoint-uninstall.sh is simply MISSING (simulating a prior partial run) but the target was never actually removed — verification correctly distinguishes 'script exited/absent' from 'verified gone', reports failed, survives for retry"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":6}' remove 0 remove 0
rm -f "$DECOMM_DIR/endpoint-uninstall.sh"   # gone, but BUNDLE_DEST was never actually cleared
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero (verification correctly does not trust the missing script as completion)" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the endpoint engine as already gone (not an error by itself)" "$(echo "$out" | grep -qi "endpoint-uninstall.sh already gone" && echo 1 || echo 0)"
chk "status=failed was reported (the file being gone did NOT mean verified removed)" "$(echo "$out" | grep -qi "status=failed reported" && echo 1 || echo 0)"
chk "BUNDLE_DEST is still there — the real reason verification correctly failed" "$([[ -d "$BUNDLE_DEST" ]] && echo 1 || echo 0)"
chk "DECOMM_DIR SURVIVES for retry" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[9] resumed run: staged endpoint-uninstall.sh is missing because a PRIOR run genuinely already removed it — verification correctly finds it removed, completes normally"
setup_creds
seed_installed_state
rm -rf "$BUNDLE_DEST"   # simulate: a prior run's endpoint-uninstall.sh already did its job
for p in "${ENDPOINT_PLISTS[@]}"; do rm -f "$LAUNCHDAEMONS/$p"; done
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":8}' remove 0 remove 0
touch "$DECOMM_DIR/.ack-done"   # a prior run also already passed the acknowledge phase
rm -f "$DECOMM_DIR/endpoint-uninstall.sh"
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits zero" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "does not re-send acknowledged" "$(echo "$out" | grep -qi "already completed in a prior run" && echo 1 || echo 0)"
chk "macos engine still ran (endpoint side already done, macos side was not)" "$(grep -qx "macos-ran" "$CALLS_LOG" && echo 1 || echo 0)"
chk "self-cleanup completes" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[10] non-author review P1-C: purge requested but purge verification fails: NO 'removed' report is sent (core removal alone is no longer authoritative for purge:true) — a 'failed' report is sent instead, using the pre-purge credential snapshot; purge step retried on next boot"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":true,"reason":null,"directive_version":12}' remove 0 remove 0 noop 0
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero (purge not yet verified)" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "P1-C: status=removed was NOT reported — purge:true must not claim removed before purge verifies" \
    "$(! echo "$out" | grep -qi "status=removed reported" && echo 1 || echo 0)"
chk "P1-C: status=failed WAS reported instead (mirrors the core-removal-not-verified case)" \
    "$(echo "$out" | grep -qi "status=failed reported" && echo 1 || echo 0)"
chk "credentials still present (purge did not actually run/succeed)" "$([[ -d "$CREDS" ]] && echo 1 || echo 0)"
chk "DECOMM_DIR survives to retry the purge step" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "P1-C: the credential snapshot survives too (not deleted until purge actually verifies)" \
    "$([[ -d "$DECOMM_DIR/.creds-snapshot" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[11] not running as root: refuses immediately, touches nothing"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":1}' remove 0 remove 0
NOROOT_BIN=$(mktemp -d "${TMPDIR:-/tmp}/.decomm-noroot-bin.XXXXXX")
cat > "$NOROOT_BIN/id" <<'EOF'
#!/bin/sh
echo 501
EOF
chmod +x "$NOROOT_BIN/id"
LOG_FILE_PATH="$(dirname "$DECOMM_DIR")/decommission-noroot.log"
rm -f "$LOG_FILE_PATH"
prepare_decomm_copy "$NOROOT_BIN:$FAKE_BIN"
PATCHED_DECOMMISSION_DIR="$DECOMM_DIR" \
PATCHED_CREDS_DIR="$CREDS" \
PATCHED_API_URL="http://127.0.0.1:1" \
PATCHED_LOG_FILE="$LOG_FILE_PATH" \
PATCHED_DECOMMISSION_DAEMON_PLIST="$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" \
zsh "$DECOMM_COPY"; rc=$?
out=$(log_of)
rm -rf "$NOROOT_BIN"
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the root requirement" "$(echo "$out" | grep -qi "must run as root" && echo 1 || echo 0)"
chk "nothing removed" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "no engine ran" "$([[ ! -s "$CALLS_LOG" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[12] non-author review P1-B: the acknowledge marker cannot be durably written (path forced to be a directory, simulating a write failure) — refuses to enter PHASE 2 (irreversible removal) this run, nothing removed, staging survives for a clean retry"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":20}' remove 0 remove 0
touch "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist"
rm -f "$DECOMM_DIR/.ack-done" 2>/dev/null
mkdir -p "$DECOMM_DIR/.ack-done"   # `: > "$ACK_MARKER"` cannot truncate-open a directory as a file
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "P1-B: log names the durability failure" "$(echo "$out" | grep -qi "could not durably record the acknowledge marker" && echo 1 || echo 0)"
chk "P1-B: NEITHER engine ran — PHASE 2 (irreversible removal) was never entered" "$([[ ! -f "$CALLS_LOG" || ! -s "$CALLS_LOG" ]] && echo 1 || echo 0)"
chk "the agent is still fully installed (bundle dest untouched)" "$([[ -d "$BUNDLE_DEST" ]] && echo 1 || echo 0)"
chk "P1-B: DECOMM_DIR survives for a clean retry next boot" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "the daemon plist survives too" "$([[ -f "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" ]] && echo 1 || echo 0)"
rmdir "$DECOMM_DIR/.ack-done" 2>/dev/null

# ───────────────────────────────────────────────────────────────────────────
echo "[13] non-author review (second round): sync fails while flushing the acknowledge marker — its exit code IS checked (not fire-and-forget), so this is treated exactly like the marker-not-durable case: refuses to enter PHASE 2, nothing removed, staging survives for a clean retry"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":21}' remove 0 remove 0
touch "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist"
SYNC_FAIL_BIN=$(mktemp -d "${TMPDIR:-/tmp}/.decomm-syncfail-bin.XXXXXX")
cat > "$SYNC_FAIL_BIN/sync" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$SYNC_FAIL_BIN/sync"
LOG_FILE_PATH="$(dirname "$DECOMM_DIR")/decommission-syncfail.log"
rm -f "$LOG_FILE_PATH"
prepare_decomm_copy "$SYNC_FAIL_BIN:$FAKE_BIN"
PATCHED_DECOMMISSION_DIR="$DECOMM_DIR" \
PATCHED_CREDS_DIR="$CREDS" \
PATCHED_API_URL="http://127.0.0.1:1" \
PATCHED_LOG_FILE="$LOG_FILE_PATH" \
PATCHED_DECOMMISSION_DAEMON_PLIST="$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" \
PATCHED_VERIFY_ENDPOINT_BUNDLE_DEST="$BUNDLE_DEST" \
PATCHED_VERIFY_LAUNCHDAEMONS_DIR="$LAUNCHDAEMONS" \
PATCHED_VERIFY_MACOS_BIN_DIR="$BIN_DIR" \
PATCHED_VERIFY_MACOS_LEGACY_BIN_DIR="$LEGACY_BIN_DIR" \
PATCHED_VERIFY_CREDS_DIR="$CREDS" \
PATCHED_VERIFY_QUEUE_BASE="$QUEUE_BASE" \
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed \
zsh "$DECOMM_COPY"; rc=$?
LOG_FILE_PATH_SAVED="$LOG_FILE_PATH"
out=$(cat "$LOG_FILE_PATH_SAVED" 2>/dev/null)
rm -rf "$SYNC_FAIL_BIN"
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the sync failure specifically (not a generic marker-missing message)" "$(echo "$out" | grep -qi "sync failed" && echo 1 || echo 0)"
chk "NEITHER engine ran — PHASE 2 (irreversible removal) was never entered" "$([[ ! -f "$CALLS_LOG" || ! -s "$CALLS_LOG" ]] && echo 1 || echo 0)"
chk "the agent is still fully installed (bundle dest untouched)" "$([[ -d "$BUNDLE_DEST" ]] && echo 1 || echo 0)"
chk "DECOMM_DIR survives for a clean retry next boot" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "the daemon plist survives too" "$([[ -f "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[14] non-author review (third round): plists are gone but launchd STILL reports one agent label loaded (bootout silently failed) — verify_core_removed must not trust the filesystem alone: NOT verified removed, status=failed (not removed) reported, DECOMM_DIR survives for retry"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":22}' remove 0 remove 0
touch "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist"
# The fake endpoint-uninstall.sh (remove=1) genuinely deletes every plist
# file from LAUNCHDAEMONS, same as [3]'s happy path — but this stub also
# tells the launchctl stub that com.patched.update (one of the SAME labels
# whose plist was just deleted) is still loaded, simulating a bootout that
# silently failed. The filesystem alone would say "removed"; the launchd
# check must be the one that catches it.
LOADED_LABELS="com.patched.update" CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero (verification correctly does not trust the filesystem alone)" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "P1 (third round): status=removed was NOT reported — a still-loaded label must block the 'removed' claim" \
    "$(! echo "$out" | grep -qi "status=removed reported" && echo 1 || echo 0)"
chk "P1 (third round): status=failed WAS reported instead" "$(echo "$out" | grep -qi "status=failed reported" && echo 1 || echo 0)"
chk "the plist files are indeed gone (proves the failure is coming from the launchd check, not a filesystem leftover)" \
    "$([[ ! -f "$LAUNCHDAEMONS/com.patched.update.plist" ]] && echo 1 || echo 0)"
chk "DECOMM_DIR survives to retry on next boot" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "the daemon plist survives too" "$([[ -f "$(dirname "$DECOMM_DIR")/com.patched.decommission.plist" ]] && echo 1 || echo 0)"

echo "[14b] sanity counterpart to [14]: same scenario but with NO label reported loaded — verifies cleanly and reports removed (proves [14] failed because of the loaded label, not by construction)"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":false,"reason":null,"directive_version":23}' remove 0 remove 0
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits zero" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "status=removed WAS reported" "$(echo "$out" | grep -qi "status=removed reported" && echo 1 || echo 0)"
chk "self-cleanup completed" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1344 (non-author review): the credential snapshot block used to run
# `cp`/`chmod` with `2>/dev/null` and no exit-code check, so a failed copy
# left CREDS_SNAPSHOT_DIR existing-but-empty/partial with NO log line at
# all, and the only downstream gate (`-d "$CREDS_SNAPSHOT_DIR"`) passed a
# present-but-useless directory. Purge then genuinely ran and genuinely
# verified while the platform was never told and never could be, since
# purge deletes CREDS_DIR. These two cases prove the snapshot is now
# verified BEFORE purge runs, and that purge does not run on an unusable
# snapshot.
echo "[15] PAT-1344: bearer-token unreadable so its cp into the snapshot fails: purge does NOT run, an ERROR is logged, DECOMM_DIR (and real credentials) survive, run exits for retry"
setup_creds
seed_installed_state
: > "$CALLS_LOG"
chmod 000 "$CREDS/bearer-token"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":true,"reason":null,"directive_version":30}' remove 0 remove 0 remove 0
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the cp failure as an ERROR (not silent)" "$(echo "$out" | grep -qi "ERROR.*cp .*bearer-token.*failed" && echo 1 || echo 0)"
chk "log names the snapshot as not usable ahead of the irreversible purge" "$(echo "$out" | grep -qi "credential snapshot at .* is missing or incomplete" && echo 1 || echo 0)"
chk "purge did NOT run" "$(! grep -q -- '--purge' "$CALLS_LOG" && echo 1 || echo 0)"
chk "core removal steps still ran (endpoint + macos, no --purge)" "$(grep -qx "endpoint-ran" "$CALLS_LOG" && grep -qx "macos-ran" "$CALLS_LOG" && echo 1 || echo 0)"
chk "real credentials survive untouched (purge never ran)" "$([[ -d "$CREDS" ]] && echo 1 || echo 0)"
chk "DECOMM_DIR survives for retry" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "no status=removed report was ever sent" "$(! echo "$out" | grep -qi "status=removed reported" && echo 1 || echo 0)"

echo "[15b] retrying case [15] after the real bearer-token becomes readable again: the invalid snapshot from the failed attempt is discarded and retaken, purge proceeds, reports and self-cleans normally"
chmod 600 "$CREDS/bearer-token"
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits zero on the successful retry" "$([[ $rc -eq 0 ]] && echo 1 || echo 0)"
chk "log names discarding the stale invalid snapshot" "$(echo "$out" | grep -qi "not usable .* discarding it" && echo 1 || echo 0)"
chk "macos engine ran WITH --purge on the retry" "$(grep -qx "macos-ran --purge" "$CALLS_LOG" && echo 1 || echo 0)"
chk "credentials removed (purge genuinely ran this time)" "$([[ ! -d "$CREDS" ]] && echo 1 || echo 0)"
chk "status=removed WAS reported" "$(echo "$out" | grep -qi "status=removed reported" && echo 1 || echo 0)"
chk "self-cleanup completed" "$([[ ! -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[16] PAT-1344: hmac-secret is a genuine zero-byte file (cp itself 'succeeds' copying it) so the snapshot lands present-but-empty: same fail-closed outcome as [15] — purge does NOT run, ERROR logged, DECOMM_DIR survives"
mkdir -p "$CREDS"
printf 'bearer-token-value\n' > "$CREDS/bearer-token"
: > "$CREDS/hmac-secret"   # zero bytes: passes a bare -f check, useless for compute_hmac
seed_installed_state
: > "$CALLS_LOG"
stage "$DECOMM_DIR" '{"mode":"immediate","purge":true,"reason":null,"directive_version":31}' remove 0 remove 0 remove 0
CURL_HTTP_CODE=200 CURL_BODY_MODE=proceed run_decomm "$DECOMM_DIR"; rc=$?
out=$(log_of)
chk "exits non-zero" "$([[ $rc -ne 0 ]] && echo 1 || echo 0)"
chk "log names the snapshot as not usable ahead of the irreversible purge" "$(echo "$out" | grep -qi "credential snapshot at .* is missing or incomplete" && echo 1 || echo 0)"
chk "purge did NOT run" "$(! grep -q -- '--purge' "$CALLS_LOG" && echo 1 || echo 0)"
chk "real credentials survive untouched (purge never ran)" "$([[ -d "$CREDS" ]] && echo 1 || echo 0)"
chk "DECOMM_DIR survives for retry" "$([[ -d "$DECOMM_DIR" ]] && echo 1 || echo 0)"
chk "no status=removed report was ever sent" "$(! echo "$out" | grep -qi "status=removed reported" && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
