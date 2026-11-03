#!/bin/zsh
##############################################################################
# test-agent-config-commit.zsh — tests for the PAT-1035 200-path commit
# sequence (_agent_config_commit_verified) and the 304 decision path
# (_agent_config_handle_304) in endpoint/patched-fetch-config.sh.
#
# Round 5 review finding: both P0s found in this ticket so far lived exactly
# in these two flows, and endpoint/test-agent-config-hash-gate.zsh explicitly
# documented them as out of scope, claiming they "require root and a live
# server". That claim was too broad. STATE_DIR/CREDS_DIR/API_URL/BUNDLE_DIR
# are already redirectable via PATCHED_* env vars, and the two flows that
# actually matter — the 200-path commit and the 304 decision — are now
# plain functions (_agent_config_commit_verified, _agent_config_handle_304)
# sentinel-wrapped in PATCHED_CONFIG_COMMIT_START/END, extracted from the
# SHIPPED patched-fetch-config.sh (same awk-extraction pattern
# macos/test-agent-config-gate.zsh and endpoint/test-agent-config-hash-gate.zsh
# use) and driven directly against a temp dir, no root, no network. A failed
# `mv` (the exact seam the round-5 bug lived on) is simulated by shadowing
# the `mv` builtin/command, the same technique
# macos/test-agent-config-gate.zsh already uses for `cp`.
#
# What this does NOT cover, and why:
#   - The curl/HTTP request itself (header construction, HMAC signing, proxy
#     resolution, timeouts). These functions start from the point a 200 or
#     304 response has already been received; the network call is untouched
#     by this ticket's findings and needs a real or mocked HTTP server to
#     exercise meaningfully.
#   - The verifier subprocess (verify-agent-config.py's Ed25519 signature
#     check and anti-rollback comparison). Separately covered by
#     test-verify-agent-config.yml. _agent_config_commit_verified starts
#     from $out_tmp already containing the verifier's output — exactly the
#     boundary the round-5 P0 lived on — so re-driving the verifier itself
#     here would be redundant with that suite, not additional coverage.
#   - The mkdir-based lock directory that serializes the two LaunchDaemon
#     callers. Requires two real concurrent processes to exercise
#     meaningfully; not a single-process, single-function concern.
#   - Root-owned paths and ownership/mode enforcement under
#     /Library/Application Support/Patched and /etc/patched (e.g. the 401
#     suspended-marker's root:wheel/0600). This test uses ordinary
#     user-owned temp paths; ownership enforcement itself needs root and is
#     exercised only by hand/integration testing.
#
# Run: zsh endpoint/test-agent-config-commit.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
FETCH_SH="$SCRIPT_DIR/patched-fetch-config.sh"

COMMIT_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-commit-gate.XXXXXX")
awk '/PATCHED_CONFIG_COMMIT_START/{f=1;next} /PATCHED_CONFIG_COMMIT_END/{f=0} f' \
    "$FETCH_SH" > "$COMMIT_TMP"
if [[ ! -s "$COMMIT_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_CONFIG_COMMIT block from $FETCH_SH"
    exit 1
fi
source "$COMMIT_TMP"
rm -f "$COMMIT_TMP"

# PAT-1109: _agent_config_commit_verified and _agent_config_handle_304 (just
# sourced above) both now call _decommission_poll_hook as their final step —
# same precedent as _trigger_log_upload, which this file already stubs
# below. Extract PATCHED_DECOMMISSION_GATE too so that call resolves to real
# code (not "command not found"), and stub _decommission_trigger_removal
# (see below) so none of this file's existing cases touch launchctl/install/cp.
DECOMM_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-decomm-gate.XXXXXX")
awk '/PATCHED_DECOMMISSION_GATE_START/{f=1;next} /PATCHED_DECOMMISSION_GATE_END/{f=0} f' \
    "$FETCH_SH" > "$DECOMM_TMP"
if [[ ! -s "$DECOMM_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_DECOMMISSION_GATE block from $FETCH_SH"
    exit 1
fi
source "$DECOMM_TMP"
rm -f "$DECOMM_TMP"

# PAT-1756: the tenant-keyed anti-rollback floor reader the fetch path uses for
# If-None-Match. Extracted from the shipped script like the blocks above.
FLOOR_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-floor-block.XXXXXX")
awk '/PATCHED_CONFIG_FLOOR_START/{f=1;next} /PATCHED_CONFIG_FLOOR_END/{f=0} f' \
    "$FETCH_SH" > "$FLOOR_TMP"
if [[ ! -s "$FLOOR_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_CONFIG_FLOOR block from $FETCH_SH"
    exit 1
fi
source "$FLOOR_TMP"
rm -f "$FLOOR_TMP"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

sha256_of() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

# Stubs for the two dependencies the extracted block does NOT define
# (deliberately left out of the sentinel block so it stays free of a
# BUNDLE_DIR dependency): log_jsonl (no-op — its own robustness is not this
# ticket's concern) and _trigger_log_upload (counted, so the 304 tests can
# assert it fires only on a confirmed hash match, per PAT-1035 finding 1).
log_jsonl() { :; }
LOG_UPLOAD_CALLS=0
_trigger_log_upload() { (( LOG_UPLOAD_CALLS++ )); }

# PAT-1109: stub the one side-effecting call _decommission_poll_hook can
# reach (real removal staging — install/cp/launchctl). None of this file's
# existing fixtures set a "decommission" key, so _decommission_check always
# resolves to "none:absent" and this stub is never even called by the cases
# below — it exists so the call is defined, and so a future case that DOES
# stage a decommission object can assert on DECOMM_TRIGGER_CALLS without
# touching root-only operations.
DECOMM_TRIGGER_CALLS=0
_decommission_trigger_removal() { (( DECOMM_TRIGGER_CALLS++ )); }

PYTHON3="/usr/bin/python3"
# PAT-1763: the shared floor parser the extracted blocks call.
AGENT_CONFIG_FLOOR_MODULE="$SCRIPT_DIR/agent_config_floor.py"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-commit-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

STATE_DIR="$WORK"
TENANT_ID="test-tenant"  # PAT-1756: the enrolled tenant the commit cross-checks against
CREDS_DIR="$WORK/creds"  # PAT-1109: _decommission_check's tenant re-check reads $CREDS_DIR/tenant-id
mkdir -p "$CREDS_DIR"
AGENT_CONFIG_FILE="$WORK/agent-config.json"
AGENT_CONFIG_VERSION_FILE="$WORK/agent-config.version"
AGENT_CONFIG_SHA256_FILE="$WORK/agent-config.sha256"
AGENT_CONFIG_FORCE_REFETCH_FILE="$WORK/.agent-config.force-refetch"
AGENT_CONFIG_HEARTBEAT_FILE="$WORK/agent-config.checked"
AGENT_CONFIG_EXECUTION_DENY_FILE="$WORK/agent-config.execution-denied"
# PAT-1040: quarantine destination for a confirmed 304 hash mismatch.
AGENT_CONFIG_QUARANTINE_FILE="$WORK/agent-config.json.quarantined"
# PAT-1042: suspended-marker directory the clear-on-verified-200 path checks.
# A plain user-owned temp dir here, not root:wheel/0600 — same documented
# limitation as the marker's WRITE side (the 401 handler): ownership/mode
# enforcement needs root and is exercised only by hand/integration testing.
CREDS_DIR="$WORK/creds"
mkdir -p "$CREDS_DIR"

reset_state() {
    rm -f "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_VERSION_FILE" "$AGENT_CONFIG_SHA256_FILE" \
          "$AGENT_CONFIG_FORCE_REFETCH_FILE" "$AGENT_CONFIG_HEARTBEAT_FILE" "$AGENT_CONFIG_QUARANTINE_FILE" \
          "$AGENT_CONFIG_EXECUTION_DENY_FILE" \
          "$CREDS_DIR/suspended" \
          "$WORK/out.tmp" "$WORK/denial.tmp"
    LOG_UPLOAD_CALLS=0
}

##############################################################################
# _agent_config_commit_verified (200-path commit sequence)
##############################################################################

# ───────────────────────────────────────────────────────────────────────────
echo "[1] happy path: publishes, records version, records the digest of the verified bytes, stamps the heartbeat, fires the log-upload trigger"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":42}' > "$WORK/out.tmp"
expected_digest=$(sha256_of "$WORK/out.tmp")
if _agent_config_commit_verified "$WORK/out.tmp"; then result=ok; else result=fail; fi
chk "commit reports success" "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_FILE holds the published bytes" \
    "$([[ "$(cat "$AGENT_CONFIG_FILE" 2>/dev/null)" == '{"tenant_id":"test-tenant","tier":"standard","config_version":42}' ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_VERSION_FILE holds the tenant-keyed floor for the extracted tenant_id and config_version (PAT-1756)" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE" 2>/dev/null)" == '{"tenant_id":"test-tenant","config_version":42}' ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_SHA256_FILE holds the digest of the verified bytes" \
    "$([[ "$(head -1 "$AGENT_CONFIG_SHA256_FILE" 2>/dev/null | tr -d '[:space:]')" == "$expected_digest" ]] && echo 1 || echo 0)"
chk "heartbeat is stamped" "$([[ -f "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"
chk "log-upload trigger fires exactly once on a fully durable commit (round 6 finding 2)" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 1 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[1b] authenticated newer rejected-policy revocation denies immediately while preserving diagnostic last-good state"
reset_state
LAST_GOOD='{"tenant_id":"test-tenant","tier":"managed","config_version":1,"legacy_app_execution_enabled":true,"app_control_authority":"enforce"}'
printf '%s' "$LAST_GOOD" > "$AGENT_CONFIG_FILE"
last_good_digest=$(sha256_of "$AGENT_CONFIG_FILE")
printf '%s\n' "$last_good_digest" > "$AGENT_CONFIG_SHA256_FILE"
printf '1' > "$AGENT_CONFIG_VERSION_FILE"
printf 'FRESH-OLD-GRANT\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
printf '{"config_version":2}' > "$WORK/denial.tmp"
if _agent_config_handle_verifier_rejection 42 "$WORK/denial.tmp" >/dev/null; then result=denied; else result=failed; fi
chk "authenticated revocation handler succeeds" "$([[ "$result" == "denied" ]] && echo 1 || echo 0)"
chk "execution-denial marker is durable" "$([[ -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"
chk "execution-denial marker retains authenticated revoked version" \
    "$([[ "$(cat "$AGENT_CONFIG_EXECUTION_DENY_FILE")" == '{"config_version":2}' ]] && echo 1 || echo 0)"
chk "old heartbeat is removed for mixed-version readers" "$([[ ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"
chk "diagnostic last-good config remains byte-for-byte unchanged" \
    "$([[ "$(cat "$AGENT_CONFIG_FILE")" == "$LAST_GOOD" ]] && echo 1 || echo 0)"
chk "diagnostic last-good anti-rollback floor remains unchanged" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == "1" ]] && echo 1 || echo 0)"
chk "full refetch remains forced until a complete policy verifies" \
    "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

printf '%s' "$LAST_GOOD" > "$WORK/out.tmp"
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null || true
chk "replayed older signed grant cannot clear authenticated revocation" \
    "$([[ -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" && ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" && -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

printf '{"tenant_id":"test-tenant","tier":"managed","config_version":2,"legacy_app_execution_enabled":true,"app_control_authority":"enforce"}' > "$WORK/out.tmp"
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null || true
chk "conflicting same-version signed grant cannot clear authenticated revocation" \
    "$([[ -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" && ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"

printf '{"tenant_id":"test-tenant","tier":"managed","config_version":3,"legacy_app_execution_enabled":true,"app_control_authority":"enforce"}' > "$WORK/out.tmp"
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null
chk "a later fully verified commit clears the execution-denial marker" \
    "$([[ ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"

echo "[1b-2] same-version full denial cannot erase either per-authority revocation floor"
for marker in \
    '{"config_version":2,"legacy_app_execution_revoked_at":2}' \
    '{"config_version":2,"app_control_revoked_at":2}'; do
    reset_state
    printf '%s' "$marker" > "$AGENT_CONFIG_EXECUTION_DENY_FILE"
    printf '{"tenant_id":"test-tenant","config_version":2,"legacy_app_execution_enabled":false,"app_control_authority":"report"}' > "$WORK/out.tmp"
    _agent_config_commit_verified "$WORK/out.tmp" >/dev/null || true
    chk "same-version full denial is cached without removing its authority floor" \
        "$([[ "$(cat "$AGENT_CONFIG_FILE")" == '{"tenant_id":"test-tenant","config_version":2,"legacy_app_execution_enabled":false,"app_control_authority":"report"}' && "$(cat "$AGENT_CONFIG_EXECUTION_DENY_FILE")" == "$marker" ]] && echo 1 || echo 0)"
    chk "same-version full denial remains fail-closed and forces refetch" \
        "$([[ ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" && -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

    printf '{"tenant_id":"test-tenant","config_version":3,"legacy_app_execution_enabled":true,"app_control_authority":"enforce"}' > "$WORK/out.tmp"
    if _agent_config_commit_verified "$WORK/out.tmp" >/dev/null; then result=ok; else result=fail; fi
    chk "strictly newer policy may supersede the individual authority floor" \
        "$([[ "$result" == "ok" && ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"
done

echo "[1b-3] denial publication rejects an oversized verifier handoff"
reset_state
"$PYTHON3" - "$WORK/denial.tmp" <<'PYEOF'
import sys
with open(sys.argv[1], 'wb') as handle:
    handle.write(b'X' * 1025)
PYEOF
if _agent_config_handle_verifier_rejection 42 "$WORK/denial.tmp" >/dev/null; then result=ok; else result=fail; fi
chk "oversized denial metadata is not published as trusted state" \
    "$([[ "$result" == "fail" && ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"

echo "[1c] ordinary unauthenticated verifier rejection cannot alter trusted state"
reset_state
printf '%s' "$LAST_GOOD" > "$AGENT_CONFIG_FILE"
last_good_digest=$(sha256_of "$AGENT_CONFIG_FILE")
printf '%s\n' "$last_good_digest" > "$AGENT_CONFIG_SHA256_FILE"
printf '1' > "$AGENT_CONFIG_VERSION_FILE"
printf 'FRESH-OLD-GRANT\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
_agent_config_handle_verifier_rejection 1 "$WORK/denial.tmp" >/dev/null || true
chk "unauthenticated rejection creates no execution-denial marker" \
    "$([[ ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"
chk "unauthenticated rejection leaves heartbeat untouched" \
    "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "FRESH-OLD-GRANT" ]] && echo 1 || echo 0)"
chk "unauthenticated rejection leaves config, version and hash untouched" \
    "$([[ "$(cat "$AGENT_CONFIG_FILE")" == "$LAST_GOOD" && "$(cat "$AGENT_CONFIG_VERSION_FILE")" == "1" && "$(cat "$AGENT_CONFIG_SHA256_FILE")" == "$last_good_digest" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# This is the round-5 P0 itself: something replaces agent-config.json in the
# window between the publish mv and the hash write. Simulated by shadowing
# `mv` to perform the real move and then, ONLY when the destination is
# AGENT_CONFIG_FILE (so the version-file and hash-file mv's inside this same
# call are untouched), overwrite it with different bytes — exactly as if a
# second writer landed in that window.
echo "[2] round-5 regression proof: a swap lands right after publish, before the digest is written — recorded digest must be the pre-swap verified bytes, not the swapped ones"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":9}' > "$WORK/out.tmp"
orig_digest=$(sha256_of "$WORK/out.tmp")
TAMPERED_JSON='{"tenant_id":"test-tenant","tier":"standard","config_version":9,"app_control":{"admins":["attacker"]}}'
mv() {
    command mv "$@"
    local dest="${@[-1]}"
    if [[ "$dest" == "$AGENT_CONFIG_FILE" ]]; then
        printf '%s' "$TAMPERED_JSON" > "$dest"
    fi
}
if _agent_config_commit_verified "$WORK/out.tmp"; then result=ok; else result=fail; fi
unfunction mv
recorded=$(head -1 "$AGENT_CONFIG_SHA256_FILE" 2>/dev/null | tr -d '[:space:]')
ondisk_digest=$(sha256_of "$AGENT_CONFIG_FILE")
chk "commit still reports success (publish + version + hash + heartbeat all completed)" \
    "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "sanity: the on-disk file really is the swapped/tampered bytes" \
    "$([[ "$ondisk_digest" != "$orig_digest" ]] && echo 1 || echo 0)"
chk "recorded digest is the pre-swap verified digest, NOT the tampered on-disk digest (the round-5 fix)" \
    "$([[ "$recorded" == "$orig_digest" && "$recorded" != "$ondisk_digest" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# The round-6 P0: a swap lands right after publish, before config_version is
# read. Simulated the same way as [2] above, but this time the tampered
# bytes carry a DIFFERENT config_version — if the version were still being
# read back from AGENT_CONFIG_FILE (the round-6 bug), AGENT_CONFIG_VERSION_FILE
# would end up holding the attacker's version instead of the verified one,
# which is exactly the anti-rollback floor the verifier trusts next poll.
echo "[2b] round-6 regression proof: a swap lands right after publish, before config_version is read — recorded version must be the pre-swap verified version, not the swapped one"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":9}' > "$WORK/out.tmp"
TAMPERED_JSON='{"tenant_id":"test-tenant","tier":"standard","config_version":999999,"app_control":{"admins":["attacker"]}}'
mv() {
    command mv "$@"
    local dest="${@[-1]}"
    if [[ "$dest" == "$AGENT_CONFIG_FILE" ]]; then
        printf '%s' "$TAMPERED_JSON" > "$dest"
    fi
}
if _agent_config_commit_verified "$WORK/out.tmp"; then result=ok; else result=fail; fi
unfunction mv
chk "commit still reports success (publish + version + hash + heartbeat all completed)" \
    "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "recorded version is the pre-swap verified version (9), NOT the tampered on-disk version (999999) — the round-6 fix" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE" 2>/dev/null)" == '{"tenant_id":"test-tenant","config_version":9}' ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] failed mv: publish fails — no digest, no version, no heartbeat written, no log-upload trigger, last-good state untouched"
reset_state
LAST_GOOD='{"tenant_id":"test-tenant","tier":"standard","config_version":5}'
printf '%s' "$LAST_GOOD" > "$AGENT_CONFIG_FILE"
last_good_digest=$(sha256_of "$AGENT_CONFIG_FILE")
printf '%s\n' "$last_good_digest" > "$AGENT_CONFIG_SHA256_FILE"
printf '5' > "$AGENT_CONFIG_VERSION_FILE"
printf 'UNCHANGED-MARKER\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":6}' > "$WORK/out.tmp"
mv() { return 1; }
if _agent_config_commit_verified "$WORK/out.tmp"; then result=ok; else result=fail; fi
unfunction mv
chk "commit reports failure when mv fails" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_FILE is untouched (still last-good content, not new_version)" \
    "$([[ "$(cat "$AGENT_CONFIG_FILE")" == "$LAST_GOOD" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_VERSION_FILE is untouched" "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == "5" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_SHA256_FILE is untouched (still last-good digest)" \
    "$([[ "$(head -1 "$AGENT_CONFIG_SHA256_FILE" | tr -d '[:space:]')" == "$last_good_digest" ]] && echo 1 || echo 0)"
chk "heartbeat is untouched (never stamped on a failed commit)" \
    "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "UNCHANGED-MARKER" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire on a failed commit (round 6 finding 2)" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] out_tmp missing/unreadable: hashing fails before any publish is attempted — last-good state untouched, no mv even tried, no log-upload trigger"
reset_state
LAST_GOOD='{"tenant_id":"test-tenant","tier":"standard","config_version":5}'
printf '%s' "$LAST_GOOD" > "$AGENT_CONFIG_FILE"
last_good_digest=$(sha256_of "$AGENT_CONFIG_FILE")
printf '%s\n' "$last_good_digest" > "$AGENT_CONFIG_SHA256_FILE"
mv() { echo "MV SHOULD NOT HAVE BEEN CALLED" >> "$WORK/mv-called"; command mv "$@"; }
if _agent_config_commit_verified "$WORK/does-not-exist.tmp"; then result=ok; else result=fail; fi
unfunction mv
chk "commit reports failure when out_tmp cannot be hashed" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_FILE is untouched" "$([[ "$(cat "$AGENT_CONFIG_FILE")" == "$LAST_GOOD" ]] && echo 1 || echo 0)"
chk "mv was never attempted (failure caught before publish)" "$([[ ! -f "$WORK/mv-called" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire when out_tmp cannot be hashed" "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4b] out_tmp has no config_version (or unparseable JSON): version extraction fails before any publish is attempted — last-good state untouched, no mv even tried, no log-upload trigger"
reset_state
LAST_GOOD='{"tenant_id":"test-tenant","tier":"standard","config_version":5}'
printf '%s' "$LAST_GOOD" > "$AGENT_CONFIG_FILE"
last_good_digest=$(sha256_of "$AGENT_CONFIG_FILE")
printf '%s\n' "$last_good_digest" > "$AGENT_CONFIG_SHA256_FILE"
printf '5' > "$AGENT_CONFIG_VERSION_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard"}' > "$WORK/out.tmp"   # no config_version key
mv() { echo "MV SHOULD NOT HAVE BEEN CALLED" >> "$WORK/mv-called"; command mv "$@"; }
if _agent_config_commit_verified "$WORK/out.tmp"; then result=ok; else result=fail; fi
unfunction mv
chk "commit reports failure when out_tmp has no config_version" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_FILE is untouched" "$([[ "$(cat "$AGENT_CONFIG_FILE")" == "$LAST_GOOD" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_VERSION_FILE is untouched" "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == "5" ]] && echo 1 || echo 0)"
chk "mv was never attempted (failure caught before publish)" "$([[ ! -f "$WORK/mv-called" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire when out_tmp has no config_version" "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] successful commit clears a pending force-refetch sentinel"
reset_state
: > "$AGENT_CONFIG_FORCE_REFETCH_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":11}' > "$WORK/out.tmp"
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null
chk "force-refetch sentinel is removed after a fully successful commit" \
    "$([[ ! -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[6] failed commit (mv fails) leaves a pending force-refetch sentinel in place — not cleared on a failure, no log-upload trigger"
reset_state
: > "$AGENT_CONFIG_FORCE_REFETCH_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":12}' > "$WORK/out.tmp"
mv() { return 1; }
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null
unfunction mv
chk "force-refetch sentinel survives a failed commit (still forcing a re-fetch)" \
    "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire on a failed commit (round 6 finding 2)" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1035 round 7 finding 1: the version-file write used to be a truncating
# redirect (`printf '%s' "$new_ver" > "$AGENT_CONFIG_VERSION_FILE"`), which
# truncates the file before writing the new value. A write failure in that
# window leaves the file empty, and an empty anti-rollback floor reads back
# as version 0 — permitting replay of any older validly-signed config. Shadow
# `mv` to fail ONLY for the version-file destination (the publish mv to
# AGENT_CONFIG_FILE still succeeds via the real `command mv`) to prove the
# fix: the temp-file + atomic-rename in _write_agent_config_version means a
# failed write leaves the prior value in place, never empty.
echo "[6b] version-file mv fails: AGENT_CONFIG_VERSION_FILE keeps its prior value and is never left empty"
reset_state
printf '5' > "$AGENT_CONFIG_VERSION_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":5}' > "$AGENT_CONFIG_FILE"
last_good_digest=$(sha256_of "$AGENT_CONFIG_FILE")
printf '%s\n' "$last_good_digest" > "$AGENT_CONFIG_SHA256_FILE"
printf 'UNCHANGED-MARKER\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":6}' > "$WORK/out.tmp"
mv() {
    local dest="${@[-1]}"
    if [[ "$dest" == "$AGENT_CONFIG_VERSION_FILE" ]]; then
        return 1
    fi
    command mv "$@"
}
if _agent_config_commit_verified "$WORK/out.tmp"; then result=ok; else result=fail; fi
unfunction mv
chk "commit reports failure when the version-file write fails" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_VERSION_FILE still holds the prior value (5), not the new one" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE" 2>/dev/null)" == "5" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_VERSION_FILE is never left empty by a failed write" \
    "$([[ -s "$AGENT_CONFIG_VERSION_FILE" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_SHA256_FILE untouched (commit did not complete)" \
    "$([[ "$(head -1 "$AGENT_CONFIG_SHA256_FILE" | tr -d '[:space:]')" == "$last_good_digest" ]] && echo 1 || echo 0)"
chk "heartbeat untouched (never stamped on a failed commit)" \
    "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "UNCHANGED-MARKER" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire on a failed commit" "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1042: the suspended marker is one-way today — nothing clears it, so a
# device the platform revokes (401) and later reinstates stays suspended
# forever until someone deletes $CREDS_DIR/suspended by hand. A
# signature-verified 200 is proof the device's credentials work again, so a
# fully durable commit now clears the marker if present — symmetric with the
# 401 handler's immediate suspend, no consecutive-success threshold.
echo "[16] marker present + fully durable verified commit: suspended marker is cleared, reinstatement logged"
reset_state
: > "$CREDS_DIR/suspended"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":20}' > "$WORK/out.tmp"
if _agent_config_commit_verified "$WORK/out.tmp" >"$WORK/stdout16.log" 2>&1; then result=ok; else result=fail; fi
chk "commit still reports success" "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "the suspended marker is gone" "$([[ ! -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "a reinstatement line is logged" "$(grep -qi 'reinstated' "$WORK/stdout16.log" && echo 1 || echo 0)"

echo "[17] marker absent + verified commit: byte-for-byte unchanged — no marker appears, no reinstatement line logged"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":21}' > "$WORK/out.tmp"
if _agent_config_commit_verified "$WORK/out.tmp" >"$WORK/stdout17.log" 2>&1; then result=ok; else result=fail; fi
chk "commit still reports success" "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "no suspended marker is created when none existed" "$([[ ! -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "no reinstatement line is logged when there was nothing to reinstate" \
    "$(! grep -qi 'reinstated' "$WORK/stdout17.log" && echo 1 || echo 0)"

echo "[18] marker present but the commit itself fails (mv fails): marker is NOT cleared — the clear only fires on a fully durable verified commit, never on a failed one"
reset_state
: > "$CREDS_DIR/suspended"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":22}' > "$WORK/out.tmp"
mv() { return 1; }
if _agent_config_commit_verified "$WORK/out.tmp" >"$WORK/stdout18.log" 2>&1; then result=ok; else result=fail; fi
unfunction mv
chk "commit reports failure" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "the suspended marker survives a failed commit" "$([[ -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "no reinstatement line is logged on a failed commit" \
    "$(! grep -qi 'reinstated' "$WORK/stdout18.log" && echo 1 || echo 0)"

echo "[19] marker present but the commit fails before publish (out_tmp unreadable, i.e. never reached a verified 200's durable commit): marker is NOT cleared"
reset_state
: > "$CREDS_DIR/suspended"
if _agent_config_commit_verified "$WORK/does-not-exist.tmp" >"$WORK/stdout19.log" 2>&1; then result=ok; else result=fail; fi
chk "commit reports failure" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "the suspended marker survives" "$([[ -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "no reinstatement line is logged" "$(! grep -qi 'reinstated' "$WORK/stdout19.log" && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# Round-2 non-author review: cases [16]-[19] cover a fully durable commit, a
# no-op (marker absent), and two failures BEFORE the heartbeat step (mv fails,
# out_tmp unreadable) — but not a failure AT the heartbeat step itself, the
# very last thing gating `return 0` before the suspended-clear runs. Same
# shadowed-mv technique as [6b] (version-file) and [11]'s 304 counterpart:
# force ONLY the heartbeat destination's mv to fail so publish + version +
# sha256 + force-refetch-clear all genuinely succeed, and only the heartbeat
# write itself fails.
echo "[20] marker present but the heartbeat write fails (last gate before the suspended-clear step): commit reports failure, marker is NOT cleared"
reset_state
: > "$CREDS_DIR/suspended"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":23}' > "$WORK/out.tmp"
mv() {
    local dest="${@[-1]}"
    if [[ "$dest" == "$AGENT_CONFIG_HEARTBEAT_FILE" ]]; then
        return 1
    fi
    command mv "$@"
}
if _agent_config_commit_verified "$WORK/out.tmp" >"$WORK/stdout20.log" 2>&1; then result=ok; else result=fail; fi
unfunction mv
chk "commit reports failure when the heartbeat write fails" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "publish itself did succeed (proves this is specifically a heartbeat-step failure, not an earlier one)" \
    "$([[ -f "$AGENT_CONFIG_FILE" ]] && echo 1 || echo 0)"
chk "the suspended marker survives a heartbeat-write failure" "$([[ -f "$CREDS_DIR/suspended" ]] && echo 1 || echo 0)"
chk "no reinstatement line is logged" "$(! grep -qi 'reinstated' "$WORK/stdout20.log" && echo 1 || echo 0)"

# Structural note (not a test in itself): a 401 response is handled by
# top-level script code that returns before ever reaching the VERIFY AND
# CACHE block (see the `[[ "$http_code" == "401" ]]` branch, which `exit 0`s
# immediately), so _agent_config_commit_verified — the only place this clear
# lives — can never run on a 401 response. "Marker present + 401 -> marker
# stays" therefore holds by construction: the 401 branch doesn't touch
# $CREDS_DIR/suspended at all (it only ever (re)creates it), and this
# function is never invoked on that path. Exercising the top-level 401
# branch itself needs a live/mocked HTTP response and root-owned file
# ownership (touch+chmod 600+chown root:wheel), which this no-root, no-network
# harness already documents as out of scope in the file header above.

##############################################################################
# _agent_config_handle_304 (304 decision path)
##############################################################################

# ───────────────────────────────────────────────────────────────────────────
echo "[7] 304 with matching hash: stamps the heartbeat, fires the log-upload trigger, leaves no force-refetch sentinel"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
if _agent_config_handle_304; then result=match; else result=mismatch; fi
chk "returns success on a matching hash" "$([[ "$result" == "match" ]] && echo 1 || echo 0)"
chk "heartbeat is stamped" "$([[ -f "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"
chk "log-upload trigger fires exactly once" "$([[ "$LOG_UPLOAD_CALLS" -eq 1 ]] && echo 1 || echo 0)"
chk "no force-refetch sentinel is created" "$([[ ! -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[7a] 304 cannot revive a diagnostic last-good grant while authenticated execution denial is active"
reset_state
printf '%s' "$LAST_GOOD" > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
printf 'FRESH-OLD-GRANT\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
: > "$AGENT_CONFIG_EXECUTION_DENY_FILE"
if _agent_config_handle_304 >/dev/null; then result=match; else result=denied; fi
chk "304 reports denial rather than a confirmed-current grant" \
    "$([[ "$result" == "denied" ]] && echo 1 || echo 0)"
chk "304 removes the diagnostic grant's heartbeat" \
    "$([[ ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"
chk "304 retains the authenticated execution-denial marker" \
    "$([[ -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"
chk "304 keeps forcing a full signed refetch" \
    "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"
chk "304 under execution denial fires no log-upload directive" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[8] 304 with tampered on-disk bytes: withholds the heartbeat, skips the log-upload trigger, sets the force-refetch sentinel"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
# Simulate an old, unverified uploader overwriting the config without
# touching the version sidecar or the hash file — exactly the mixed-version
# scenario finding 2 exists for.
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3,"app_control":{"admins":["attacker"]}}' > "$AGENT_CONFIG_FILE"
printf 'UNCHANGED-MARKER\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
if _agent_config_handle_304; then result=match; else result=mismatch; fi
chk "returns failure on a hash mismatch" "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"
chk "heartbeat is withheld (unchanged)" "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "UNCHANGED-MARKER" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire on unverified bytes (PAT-1035 finding 1)" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"
chk "force-refetch sentinel is created" "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[9] 304 with no hash ever recorded (pre-fix state / never verified via 200): treated as a mismatch, not a silent pass"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
if _agent_config_handle_304; then result=match; else result=mismatch; fi
chk "returns failure when AGENT_CONFIG_SHA256_FILE has never been written" "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"
chk "force-refetch sentinel is created" "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[10] integration: a force-refetch sentinel set by a 304 mismatch is cleared by the next verified commit"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3,"tampered":true}' > "$AGENT_CONFIG_FILE"
_agent_config_handle_304 >/dev/null
sentinel_after_304=$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo present || echo absent)
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":4}' > "$WORK/out.tmp"
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null
sentinel_after_commit=$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo present || echo absent)
chk "304 hash mismatch sets the sentinel" "$([[ "$sentinel_after_304" == "present" ]] && echo 1 || echo 0)"
chk "the next verified commit clears the sentinel" "$([[ "$sentinel_after_commit" == "absent" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1035 round 7 finding 2: the heartbeat write on the 304-match path used
# to be unchecked. If it silently fails, the heartbeat ages past the
# freshness window and the uploader's enforcement gate quietly stops
# enforcing on a device that is polling successfully. Shadow `mv` to fail
# only for the heartbeat destination to prove the fix reports failure,
# leaves no heartbeat file behind, and withholds the log-upload trigger.
echo "[11] 304 with matching hash but heartbeat write fails: reports failure, no heartbeat, no log-upload trigger"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
mv() {
    local dest="${@[-1]}"
    if [[ "$dest" == "$AGENT_CONFIG_HEARTBEAT_FILE" ]]; then
        return 1
    fi
    command mv "$@"
}
if _agent_config_handle_304; then result=ok; else result=fail; fi
unfunction mv
chk "returns failure when the heartbeat write fails despite a confirmed hash match" \
    "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "no stale/partial heartbeat file is left behind" \
    "$([[ ! -f "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"
chk "log-upload trigger does not fire when the heartbeat write fails" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1035 round 7 finding 3: the force-refetch sentinel write on a 304 hash
# mismatch used to discard errors (`: > "$AGENT_CONFIG_FORCE_REFETCH_FILE"
# 2>/dev/null`). That sentinel is the only thing that turns a detected
# mismatch back into a full fetch — if its creation fails, the server keeps
# answering 304 forever with no path back. Point the sentinel at a path
# whose parent directory does not exist so the write genuinely fails (no
# `mv` involved here — it's a bare redirect), and assert the failure is
# still reported and logged loudly, naming the consequence.
echo "[12] 304 hash mismatch but the sentinel write itself fails: still reports mismatch, logs loudly naming the self-heal consequence"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3,"app_control":{"admins":["attacker"]}}' > "$AGENT_CONFIG_FILE"
ORIG_SENTINEL="$AGENT_CONFIG_FORCE_REFETCH_FILE"
AGENT_CONFIG_FORCE_REFETCH_FILE="$WORK/no-such-dir/sentinel"
if _agent_config_handle_304 >"$WORK/stdout.log" 2>"$WORK/stderr.log"; then result=match; else result=mismatch; fi
AGENT_CONFIG_FORCE_REFETCH_FILE="$ORIG_SENTINEL"
chk "still reports a mismatch even when the sentinel write itself fails" \
    "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"
chk "a loud CRITICAL log line names the self-heal consequence" \
    "$(grep -qi 'CRITICAL' "$WORK/stdout.log" && echo 1 || echo 0)"
chk "no force-refetch sentinel exists at the (unreachable) path" \
    "$([[ ! -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1040: on a confirmed 304 hash mismatch, the unverified bytes used to be
# detected but left in place at AGENT_CONFIG_FILE's canonical path, readable
# by anything else on the box for up to the ~15-minute poll cycle. This
# proves the fix: the file is moved aside (quarantined), not merely flagged,
# and the quarantine copy preserves the exact mismatched bytes rather than
# just existing as a marker.
echo "[13] 304 hash mismatch quarantines the on-disk config: AGENT_CONFIG_FILE is absent afterward, and the quarantine copy holds the exact mismatched bytes"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
TAMPERED_JSON='{"tenant_id":"test-tenant","tier":"standard","config_version":3,"app_control":{"admins":["attacker"]}}'
printf '%s' "$TAMPERED_JSON" > "$AGENT_CONFIG_FILE"
printf 'UNCHANGED-MARKER\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
if _agent_config_handle_304; then result=match; else result=mismatch; fi
chk "still returns failure on a hash mismatch (unaffected by quarantine)" "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_FILE no longer exists at its canonical path" "$([[ ! -f "$AGENT_CONFIG_FILE" ]] && echo 1 || echo 0)"
chk "a quarantine copy exists" "$([[ -f "$AGENT_CONFIG_QUARANTINE_FILE" ]] && echo 1 || echo 0)"
chk "the quarantine copy holds the exact mismatched (tampered) bytes, not just a marker" \
    "$([[ "$(cat "$AGENT_CONFIG_QUARANTINE_FILE" 2>/dev/null)" == "$TAMPERED_JSON" ]] && echo 1 || echo 0)"
chk "existing behavior unaffected: heartbeat still withheld" \
    "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "UNCHANGED-MARKER" ]] && echo 1 || echo 0)"
chk "existing behavior unaffected: log-upload trigger still does not fire" \
    "$([[ "$LOG_UPLOAD_CALLS" -eq 0 ]] && echo 1 || echo 0)"
chk "existing behavior unaffected: force-refetch sentinel is still created" \
    "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# Round-1 non-author review finding (P1): a quarantine-move failure must not
# leave the unverified bytes exactly as exposed as before this ticket, with
# only a log line to show for it — nothing is watching these logs
# automatically until PAT-1029's channel exists. Mirrors case [12]'s pattern
# (point the quarantine destination at a directory that does not exist so
# the mv genuinely fails) but now asserts the fallback: AGENT_CONFIG_FILE
# ends up force-removed and therefore absent, not left in place, and the log
# line names the fallback taken (distinct from both the plain mismatch
# warning and the "both failed" CRITICAL line in case [15] below).
echo "[14] 304 hash mismatch but the quarantine move itself fails: falls back to force-removing the file so it ends up absent anyway, logs which path was taken, and the existing sentinel handling still runs"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
TAMPERED_JSON='{"tenant_id":"test-tenant","tier":"standard","config_version":3,"app_control":{"admins":["attacker"]}}'
printf '%s' "$TAMPERED_JSON" > "$AGENT_CONFIG_FILE"
printf 'UNCHANGED-MARKER\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
ORIG_QUARANTINE="$AGENT_CONFIG_QUARANTINE_FILE"
AGENT_CONFIG_QUARANTINE_FILE="$WORK/no-such-dir/quarantine"
if _agent_config_handle_304 >"$WORK/stdout14.log" 2>"$WORK/stderr14.log"; then result=match; else result=mismatch; fi
AGENT_CONFIG_QUARANTINE_FILE="$ORIG_QUARANTINE"
chk "still reports a mismatch even when the quarantine move fails" \
    "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"
chk "AGENT_CONFIG_FILE is absent after the fallback force-remove (not left in place)" \
    "$([[ ! -f "$AGENT_CONFIG_FILE" ]] && echo 1 || echo 0)"
chk "no quarantine copy exists either (the mv never succeeded)" \
    "$([[ ! -f "$AGENT_CONFIG_QUARANTINE_FILE" ]] && echo 1 || echo 0)"
chk "the log names the force-remove fallback specifically" \
    "$(grep -qi 'force-removed' "$WORK/stdout14.log" && echo 1 || echo 0)"
chk "the fallback line is distinct from the plain hash-mismatch warning line" \
    "$(grep -qi 'could not quarantine' "$WORK/stdout14.log" && echo 1 || echo 0)"
chk "the fallback line is NOT the last-resort CRITICAL wording (that's reserved for when both fail, case [15])" \
    "$(! grep -qi 'CRITICAL' "$WORK/stdout14.log" && echo 1 || echo 0)"
chk "existing behavior unaffected: heartbeat still withheld despite the quarantine failure" \
    "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "UNCHANGED-MARKER" ]] && echo 1 || echo 0)"
chk "existing behavior unaffected: force-refetch sentinel is still created despite the quarantine failure" \
    "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# Round-1 non-author review finding (P1), the truly exceptional tail: both
# the quarantine mv AND the force-remove fallback fail (e.g. STATE_DIR itself
# has gone unwritable). Shadow both `mv` and `rm` to fail unconditionally —
# same shadowing technique this file already uses for `mv` in cases
# [3]/[6]/[6b]/[11] — so this is exercised deterministically regardless of
# whether the test runs as root (which would bypass a directory-permission
# trick) or not. Must still not crash, still report the mismatch, still run
# the existing sentinel/heartbeat handling, and the CRITICAL log must name
# both failures so this is distinguishable from case [14]'s single-failure
# fallback line.
echo "[15] 304 hash mismatch but BOTH the quarantine move and the force-remove fallback fail: still reports mismatch, logs a loud CRITICAL line naming both failures, does not crash, and the existing sentinel handling still runs"
reset_state
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
TAMPERED_JSON='{"tenant_id":"test-tenant","tier":"standard","config_version":3,"app_control":{"admins":["attacker"]}}'
printf '%s' "$TAMPERED_JSON" > "$AGENT_CONFIG_FILE"
printf 'UNCHANGED-MARKER\n' > "$AGENT_CONFIG_HEARTBEAT_FILE"
mv() { return 1; }
rm() { return 1; }
if _agent_config_handle_304 >"$WORK/stdout15.log" 2>"$WORK/stderr15.log"; then result=match; else result=mismatch; fi
unfunction mv rm
chk "still reports a mismatch when both the move and the remove fail" \
    "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"
chk "the function does not crash — reset_state cleanup and the rest of this script still run" \
    "1"
chk "AGENT_CONFIG_FILE remains in place (neither fallback could remove it) — the honest worst case, not silently reported as handled" \
    "$([[ -f "$AGENT_CONFIG_FILE" && "$(cat "$AGENT_CONFIG_FILE")" == "$TAMPERED_JSON" ]] && echo 1 || echo 0)"
chk "a loud CRITICAL log line names BOTH failures" \
    "$(grep -qi 'CRITICAL' "$WORK/stdout15.log" && grep -qi 'quarantine' "$WORK/stdout15.log" && grep -qi 'force-remove' "$WORK/stdout15.log" && echo 1 || echo 0)"
chk "existing behavior unaffected: heartbeat still withheld despite both failures" \
    "$([[ "$(cat "$AGENT_CONFIG_HEARTBEAT_FILE")" == "UNCHANGED-MARKER" ]] && echo 1 || echo 0)"
chk "existing behavior unaffected: force-refetch sentinel is still created despite both failures" \
    "$([[ -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

##############################################################################
# PAT-1756: tenant-keyed anti-rollback floor
##############################################################################

echo "[21] floor reader: absent, legacy, keyed for this tenant, keyed for another tenant, corrupt"
reset_state
chk "no floor file reads as absent" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "absent" ]] && echo 1 || echo 0)"
printf '12\n' > "$AGENT_CONFIG_VERSION_FILE"
chk "a legacy bare integer reads as legacy (never a validator for If-None-Match)" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "legacy 12" ]] && echo 1 || echo 0)"
printf '{"tenant_id":"test-tenant","config_version":12}' > "$AGENT_CONFIG_VERSION_FILE"
chk "a keyed floor for the enrolled tenant applies" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "applies 12" ]] && echo 1 || echo 0)"
printf '{"tenant_id":"previous-tenant","config_version":12}' > "$AGENT_CONFIG_VERSION_FILE"
chk "a keyed floor for another tenant does not apply" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "other_tenant" ]] && echo 1 || echo 0)"
for corrupt_floor in '' '   ' '-1' '12abc' '[12]' 'garbage' \
    '{"tenant_id":"test-tenant"}' '{"config_version":3}' \
    '{"tenant_id":"","config_version":3}' '{"tenant_id":"test-tenant","config_version":-3}' \
    '{"tenant_id":"test-tenant","config_version":"3"}' '{"tenant_id":"test-tenant","config_version":true}' \
    '{"tenant_id":"test-tenant","config_version":3.0}' '{"tenant_id":["test-tenant"],"config_version":3}' \
    '{"tenant_id":7,"config_version":3}' '{"tenant_id":"x","tenant_id":"test-tenant","config_version":3}' \
    '{"tenant_id":"test-tenant","config_version":3,"config_version":9}' '{"Tenant_ID":"x","tenant_id":"test-tenant","config_version":3}' \
    '{"tenant_id":"test-tenant","config_version":3,"extra":1}' \
    '{"tenant_id":"test-tenant","tenant_id":"x","config_version":3}' \
    '{"tenant_id":"test-tenant","config_version":3'; do
    printf '%s' "$corrupt_floor" > "$AGENT_CONFIG_VERSION_FILE"
    chk "corrupt floor '$corrupt_floor' reads as corrupt" \
        "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "corrupt" ]] && echo 1 || echo 0)"
done
"$PYTHON3" -c 'import sys; open(sys.argv[1], "w").write(" " * 4096 + "12")' "$AGENT_CONFIG_VERSION_FILE"
chk "an oversized floor file reads as corrupt" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "corrupt" ]] && echo 1 || echo 0)"

echo "[22] commit re-keys a floor left by another tenant to the verified tenant and version"
reset_state
printf '{"tenant_id":"previous-tenant","config_version":12}' > "$AGENT_CONFIG_VERSION_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":3}' > "$WORK/out.tmp"
if _agent_config_commit_verified "$WORK/out.tmp" >/dev/null; then result=ok; else result=fail; fi
chk "commit succeeds" "$([[ "$result" == "ok" ]] && echo 1 || echo 0)"
chk "floor is re-keyed to test-tenant at version 3" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == '{"tenant_id":"test-tenant","config_version":3}' ]] && echo 1 || echo 0)"
chk "the re-keyed floor reads back as applying to test-tenant" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" test-tenant)" == "applies 3" ]] && echo 1 || echo 0)"
chk "and no longer applies to the previous tenant" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" previous-tenant)" == "other_tenant" ]] && echo 1 || echo 0)"

echo "[23] legacy bare-integer floor migrates to the keyed format on the next commit"
reset_state
printf '5' > "$AGENT_CONFIG_VERSION_FILE"
printf '{"tenant_id":"test-tenant","tier":"standard","config_version":6}' > "$WORK/out.tmp"
_agent_config_commit_verified "$WORK/out.tmp" >/dev/null
chk "floor rewritten as {tenant_id, config_version}" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == '{"tenant_id":"test-tenant","config_version":6}' ]] && echo 1 || echo 0)"

echo "[24] verifier output without a usable tenant_id is never published and never moves the floor"
for bad_out in '{"tier":"standard","config_version":6}' \
               '{"tenant_id":"","tier":"standard","config_version":6}' \
               '{"tenant_id":7,"tier":"standard","config_version":6}' \
               '{"tenant_id":"test-tenant","tier":"standard","config_version":"6"}'; do
    reset_state
    rm -f "$WORK/mv-called"
    printf '{"tenant_id":"test-tenant","config_version":5}' > "$AGENT_CONFIG_VERSION_FILE"
    printf '%s' "$bad_out" > "$WORK/out.tmp"
    mv() { echo "MV SHOULD NOT HAVE BEEN CALLED" >> "$WORK/mv-called"; command mv "$@"; }
    if _agent_config_commit_verified "$WORK/out.tmp" >/dev/null; then result=ok; else result=fail; fi
    unfunction mv
    chk "commit refuses '$bad_out'" "$([[ "$result" == "fail" && ! -f "$WORK/mv-called" && ! -f "$AGENT_CONFIG_FILE" ]] && echo 1 || echo 0)"
    chk "floor untouched for '$bad_out'" \
        "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == '{"tenant_id":"test-tenant","config_version":5}' ]] && echo 1 || echo 0)"
done

echo "[25] the floor writer refuses an empty tenant or a non-integer version"
reset_state
rm -f "$STATE_DIR"/.agent-config.version.*(N)   # [6b] deliberately strands one via a shadowed mv
printf '{"tenant_id":"test-tenant","config_version":5}' > "$AGENT_CONFIG_VERSION_FILE"
_write_agent_config_version "" 6 && result=ok || result=fail
chk "empty tenant refused" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
_write_agent_config_version test-tenant "6x" && result=ok || result=fail
chk "non-integer version refused" "$([[ "$result" == "fail" ]] && echo 1 || echo 0)"
chk "floor untouched by refused writes" \
    "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == '{"tenant_id":"test-tenant","config_version":5}' ]] && echo 1 || echo 0)"
_write_agent_config_version 'tenant "quoted"' 7
chk "a tenant id needing JSON escaping round-trips" \
    "$([[ "$(_agent_config_floor_state "$AGENT_CONFIG_VERSION_FILE" 'tenant "quoted"')" == "applies 7" ]] && echo 1 || echo 0)"
chk "no temp floor files are left behind" \
    "$([[ -z "$(print -l "$STATE_DIR"/.agent-config.version.*(N))" ]] && echo 1 || echo 0)"

echo "[26] defence in depth: verifier output bound to a tenant other than the enrolled one is never published and never moves the floor"
for enrolled in "test-tenant" ""; do
    reset_state
    rm -f "$WORK/mv-called"
    TENANT_ID="$enrolled"
    printf '{"tenant_id":"test-tenant","config_version":5}' > "$AGENT_CONFIG_VERSION_FILE"
    if [[ -n "$enrolled" ]]; then
        printf '{"tenant_id":"other-tenant","tier":"standard","config_version":9}' > "$WORK/out.tmp"
    else
        printf '{"tenant_id":"test-tenant","tier":"standard","config_version":9}' > "$WORK/out.tmp"
    fi
    mv() { echo "MV SHOULD NOT HAVE BEEN CALLED" >> "$WORK/mv-called"; command mv "$@"; }
    commit_out=$(_agent_config_commit_verified "$WORK/out.tmp"); commit_rc=$?
    unfunction mv
    chk "enrolled '${enrolled:-<unset>}': commit refused, nothing published" \
        "$([[ "$commit_rc" -ne 0 && ! -f "$WORK/mv-called" && ! -f "$AGENT_CONFIG_FILE" && ! -f "$WORK/out.tmp" ]] && echo 1 || echo 0)"
    chk "enrolled '${enrolled:-<unset>}': floor untouched" \
        "$([[ "$(cat "$AGENT_CONFIG_VERSION_FILE")" == '{"tenant_id":"test-tenant","config_version":5}' ]] && echo 1 || echo 0)"
    chk "enrolled '${enrolled:-<unset>}': the refusal is logged as an error" \
        "$([[ "$commit_out" == *"ERROR: verifier output is bound to a different tenant"* ]] && echo 1 || echo 0)"
done
TENANT_ID="test-tenant"

echo "[27] If-None-Match choice: only a floor keyed to the enrolled tenant; anything unexpected is unusable and logged"
_agent_config_conditional_get_version "applies 12" >/dev/null
chk "keyed floor for this tenant sends its version" "$([[ "$LAST_VERSION" == "12" ]] && echo 1 || echo 0)"
for no_validator in "legacy 12" "other_tenant" "corrupt" "absent"; do
    LAST_VERSION="stale"
    _agent_config_conditional_get_version "$no_validator" >/dev/null
    chk "'$no_validator' sends no If-None-Match" "$([[ -z "$LAST_VERSION" ]] && echo 1 || echo 0)"
done
for unexpected in "" "applies" "applies 12x" "weird-state" "applies 12
applies 13" "$(printf 'x%.0s' {1..200})"; do
    LAST_VERSION="stale"
    cg_out=$(_agent_config_conditional_get_version "$unexpected"; print -r -- "LAST=$LAST_VERSION")
    chk "unexpected state '${unexpected[1,20]}': no If-None-Match" "$([[ "$cg_out" == *"LAST=" && "$cg_out" != *"LAST="?* ]] && echo 1 || echo 0)"
    chk "unexpected state '${unexpected[1,20]}': error logged as unusable" \
        "$([[ "$cg_out" == *"ERROR: anti-rollback floor state was unexpected"*"treating the floor as unusable"* ]] && echo 1 || echo 0)"
done
absent_out=$(_agent_config_conditional_get_version "absent")
chk "no floor yet logs nothing (not an error on every poll of a fresh install)" "$([[ -z "$absent_out" ]] && echo 1 || echo 0)"
long_out=$(_agent_config_conditional_get_version "$(printf 'x%.0s' {1..200})")
chk "unexpected output is truncated to 80 characters in the log" \
    "$([[ "$long_out" == *"($(printf 'x%.0s' {1..80}))"* ]] && echo 1 || echo 0)"

##############################################################################
# PAT-1763: the execution-denial marker is keyed by tenant
##############################################################################

# commit_over_marker <marker-json> <committed-version>
#   Fresh state, the given marker on disk, then a verified commit for the
#   enrolled tenant (test-tenant) at <committed-version>. Sets result=ok|fail.
commit_over_marker() {
    reset_state
    printf '%s' "$1" > "$AGENT_CONFIG_EXECUTION_DENY_FILE"
    printf '{"tenant_id":"test-tenant","config_version":%s,"legacy_app_execution_enabled":true,"app_control_authority":"enforce"}' "$2" > "$WORK/out.tmp"
    if _agent_config_commit_verified "$WORK/out.tmp" >/dev/null; then result=ok; else result=fail; fi
}

echo "[28] a marker left by another tenant is superseded by the enrolled tenant's first verified commit, even at a lower version"
for other_marker in \
    '{"tenant_id":"previous-tenant","config_version":50}' \
    '{"tenant_id":"previous-tenant","config_version":50,"legacy_app_execution_revoked_at":50,"app_control_revoked_at":50}' \
    '{"config_version":50,"app_control_revoked_at":50,"tenant_id":"previous-tenant"}'; do
    commit_over_marker "$other_marker" 3
    chk "other-tenant marker '${other_marker[1,60]}': commit succeeds" "$([[ "$result" == ok ]] && echo 1 || echo 0)"
    chk "other-tenant marker '${other_marker[1,60]}': marker cleared, heartbeat stamped" \
        "$([[ ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" && -f "$AGENT_CONFIG_HEARTBEAT_FILE" ]] && echo 1 || echo 0)"
done

echo "[29] a marker keyed to the enrolled tenant still applies to it"
commit_over_marker '{"tenant_id":"test-tenant","config_version":50,"legacy_app_execution_revoked_at":50}' 3
chk "same-tenant marker above the committed version: not cleared, fail closed" \
    "$([[ "$result" == fail && -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" && ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" && -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"
commit_over_marker '{"tenant_id":"test-tenant","config_version":50,"legacy_app_execution_revoked_at":50}' 50
chk "same-tenant marker at the committed version: not cleared" \
    "$([[ "$result" == fail && -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"
commit_over_marker '{"tenant_id":"test-tenant","config_version":50,"legacy_app_execution_revoked_at":50}' 51
chk "same-tenant marker below the committed version: cleared" \
    "$([[ "$result" == ok && ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"

echo "[30] a legacy marker with no tenant is attributed to the enrolled tenant, so it keeps failing closed"
for legacy_marker in '{"config_version":50}' '{"config_version":50,"app_control_revoked_at":50}'; do
    commit_over_marker "$legacy_marker" 3
    chk "legacy marker '$legacy_marker' above the committed version: not cleared" \
        "$([[ "$result" == fail && "$(cat "$AGENT_CONFIG_EXECUTION_DENY_FILE" 2>/dev/null)" == "$legacy_marker" ]] && echo 1 || echo 0)"
    commit_over_marker "$legacy_marker" 51
    chk "legacy marker '$legacy_marker' below the committed version: cleared" \
        "$([[ "$result" == ok && ! -e "$AGENT_CONFIG_EXECUTION_DENY_FILE" ]] && echo 1 || echo 0)"
done

echo "[31] a marker whose tenant_id is not a non-empty string is never cleared"
for bad_marker in \
    '{"tenant_id":"","config_version":1}' \
    '{"tenant_id":"   ","config_version":1}' \
    '{"tenant_id":7,"config_version":1}' \
    '{"tenant_id":null,"config_version":1}' \
    '{"tenant_id":["previous-tenant"],"config_version":1}' \
    '{"tenant_id":"previous-tenant","Tenant_ID":"test-tenant","config_version":1}'; do
    commit_over_marker "$bad_marker" 99
    chk "malformed tenant marker '$bad_marker': kept, commit not reported as success" \
        "$([[ "$result" == fail && "$(cat "$AGENT_CONFIG_EXECUTION_DENY_FILE" 2>/dev/null)" == "$bad_marker" ]] && echo 1 || echo 0)"
done

echo "[32] enrolment is not what clears the marker: the 304 path keeps it for any tenant"
reset_state
printf '{"tenant_id":"previous-tenant","config_version":50}' > "$AGENT_CONFIG_EXECUTION_DENY_FILE"
printf '{"tenant_id":"test-tenant","config_version":3}' > "$AGENT_CONFIG_FILE"
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
if _agent_config_handle_304 >/dev/null; then result=ok; else result=fail; fi
chk "304 with another tenant's marker: marker kept, heartbeat withheld, full refetch forced" \
    "$([[ "$result" == fail && -f "$AGENT_CONFIG_EXECUTION_DENY_FILE" && ! -e "$AGENT_CONFIG_HEARTBEAT_FILE" && -f "$AGENT_CONFIG_FORCE_REFETCH_FILE" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
