#!/bin/zsh
##############################################################################
# patched-decommission.sh — PAT-1109 detached agent-decommission orchestrator.
#
# ############################################################################
# WARNING — THE MOST DESTRUCTIVE PATH IN THE PRODUCT. This script removes
# the Patched agent from this Mac: LaunchDaemons, binaries, state, and —
# when decommission-info.json records purge=true — credentials and the
# local queue too. There is no channel left to correct a mistake once
# removal is VERIFIED complete; it is strictly more destructive than the
# existing app-removal daemon (endpoint/patched-uninstall.sh /
# com.patched.uninstall-check.plist), which is still gated and carries its
# own do-not-ship warning for a narrower blast radius (one managed
# third-party app, not the agent itself).
#
# CLEARED FOR CUSTOMER ENDPOINTS, 2026-08-14, PAT-1344. This path previously
# carried a do-not-ship-until-reviewed warning. That review had never
# actually been performed — the PRs that built it (#406, #407) narrate
# review rounds in their own bodies, but the only machine-recorded review
# signal on either is a scan that failed to complete, and both merged over
# it. So the review was run for real under PAT-1344: the complete
# decommission path (this script, its plist, and the Windows
# DecommissionRunner/Handoff/HandoffScript/StatusReporter, 2358 lines) was
# put in front of three independent non-author reviewers, none of which
# wrote or orchestrated it. Every finding was checked against the code with
# citations. One was real and is fixed in the same change: the pre-purge
# credential snapshot could fail silently, letting an irreversible purge
# complete while leaving the platform permanently unable to be told (see
# the PAT-1344 comment in the purge block below). The rest did not survive
# verification.
#
# Read that as "reviewed", not as "an enforced upstream gate passed": the
# patched/non-author-review rulesets are disabled estate-wide, so this
# clearance comes from the compensating local review pipeline described in
# the workspace CLAUDE.md. The warning is lifted for THIS path only —
# a stale warning on a reviewed control is as misleading as a missing one
# on an unreviewed control, which is why it is replaced here rather than
# deleted.
# ############################################################################
#
# This script does NOT decide whether to remove the agent. That decision —
# Ed25519 signature (via the hash-pin on the verified config, read and
# parsed atomically to close a TOCTOU window — PAT-1109 second round P1 A),
# tenant binding, anti-rollback, mode/expiry sanity, clock-skew bound, all
# re-checked AT THE POINT OF ACTION — is made exactly once, by
# endpoint/patched-fetch-config.sh's PATCHED_DECOMMISSION_GATE block, before
# this script is ever staged or launched. By the time this runs, the
# decision is final and frozen into decommission-info.json.
#
# THE PLATFORM CAN STILL CALL IT OFF, ONCE, HERE (PAT-1109 second round,
# final contract wording): the pre-removal "acknowledged" report below is
# the last moment a directive can be superseded or cancelled. The decision
# is keyed off the RESPONSE BODY's `decommission` field — "proceed" or
# "superseded" — never the bare HTTP status code, per
# contracts/agent-config-schema.md (200 carries "proceed", 409 carries
# "superseded" in practice, but the body field is the actual contract). A
# reachable response whose body is missing, unparseable, or carries neither
# recognised value is treated exactly like "superseded": an unreadable
# answer to "may I destroy this agent" is not a yes. Either way this is a
# definitive, non-retried answer — not a transient failure — and this
# script aborts cleanly on it: no removal, nothing left staged to resurrect
# the attempt on a later boot, agent left installed and running. This is the
# ONLY cancellation path in the design; once the acknowledged report has
# actually reached the platform with a "proceed" outcome, or could not be
# delivered at all (a genuine transport failure — could not reach the
# platform at all, which is NOT the same thing as a reachable-but-bad
# answer), removal proceeds and is no longer abortable.
#
# WHY DETACHED: a daemon cannot `launchctl bootout` its own label and
# survive to finish — endpoint/uninstall.sh's teardown list includes
# com.patched.config-poll, the very daemon whose poll cycle decided to
# remove the agent, so the removal work cannot run inline inside that poll.
# The gate hands off to this script running under its OWN label
# (com.patched.decommission), staged into DECOMM_DIR, a directory neither
# endpoint/uninstall.sh nor macos/uninstall.sh ever touches (see the "DO NOT"
# note above SELF-CLEANUP below for why that must stay true). The
# LaunchDaemon that runs this script (RunAtLoad=true, no StartInterval) can
# retry on every boot until every step below has completed, then this script
# removes it — and itself — last.
#
# IDEMPOTENT / CRASH-SAFE BY CONSTRUCTION (PAT-1109 second round P1 C):
# staging (DECOMM_DIR, the LaunchDaemon) is torn down ONLY after removal is
# VERIFIED complete by checking the filesystem directly — never merely
# because endpoint-uninstall.sh or macos-uninstall.sh exited zero, and never
# because a staged engine script happened to already be missing. A verified
# incomplete removal leaves everything in place so RunAtLoad retries on the
# next boot rather than stranding a partly-removed agent non-retryably.
#
# CONVENTIONS (shared with patched-fetch-config.sh):
#   - `set -u` only, not `set -euo pipefail` — a single failed step must not
#     abort the whole removal; each step handles its own failure and
#     continues, or leaves state in place for a verified retry.
#   - /usr/bin/python3 hardcoded (sudo/launchd strip PATH on macOS).
#   - No zsh reserved var names: path/fpath/cdpath/manpath/infopath.
##############################################################################

set -u

# PAT-2394: root command lookup must never include Homebrew, inherited PATH
# or a test override. Runtime failure is fatal before logging or state writes.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] && "$PYTHON3" -I -c 'pass' >/dev/null 2>&1 || { printf '%s\n' "FATAL: trusted /usr/bin/python3 runtime unavailable or unusable; no work performed" >&2; exit 1; }

DECOMM_DIR="${PATCHED_DECOMMISSION_DIR:-/Library/Application Support/Patched/.decommission}"
CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"
LOG_FILE="${PATCHED_LOG_FILE:-/var/log/patched-decommission.log}"
DAEMON_LABEL="com.patched.decommission"
DAEMON_PLIST="${PATCHED_DECOMMISSION_DAEMON_PLIST:-/Library/LaunchDaemons/${DAEMON_LABEL}.plist}"

INFO_FILE="$DECOMM_DIR/decommission-info.json"
ACK_MARKER="$DECOMM_DIR/.ack-done"
ENDPOINT_UNINSTALL="$DECOMM_DIR/endpoint-uninstall.sh"
MACOS_UNINSTALL="$DECOMM_DIR/macos-uninstall.sh"
# CREDS_SNAPSHOT_DIR (non-author review P1-C): for purge:true, the terminal
# "removed" report must not be sent until purge is ALSO verified — but purge
# is exactly the step that deletes bearer-token/hmac-secret out of
# CREDS_DIR, which is what that report needs to sign and send itself. Lives
# inside DECOMM_DIR so it inherits the same "neither uninstall.sh ever
# touches this directory" guarantee documented above SELF-CLEANUP below.
CREDS_SNAPSHOT_DIR="$DECOMM_DIR/.creds-snapshot"

# ---------------------------------------------------------------------------
# VERIFICATION TARGETS (PAT-1109 P1 C) — MUST stay in sync with
# endpoint/uninstall.sh's own LAUNCHDAEMONS array and BUNDLE_DEST, and with
# macos/uninstall.sh's own AGENT_DIR/LEGACY_BIN_DIR/DAEMON_DIR/binary names. Same convention
# this repo already uses between install.sh and uninstall.sh's own
# LAUNCHDAEMONS arrays ("the two MUST stay in sync"). Overridable via
# PATCHED_* env vars for testing; production never sets them, so it always
# verifies against the real system paths.
# ---------------------------------------------------------------------------
VERIFY_ENDPOINT_BUNDLE_DEST="${PATCHED_VERIFY_ENDPOINT_BUNDLE_DEST:-/usr/local/patched-updater}"
VERIFY_LAUNCHDAEMONS_DIR="${PATCHED_VERIFY_LAUNCHDAEMONS_DIR:-/Library/LaunchDaemons}"
# PAT-2395: the collector entrypoints moved to a dedicated root-owned tree.
# Both locations are checked, because a machine installed before that still
# has them in /usr/local/bin and a removal that missed either one must not
# verify as removed.
VERIFY_MACOS_BIN_DIR="${PATCHED_VERIFY_MACOS_BIN_DIR:-/Library/Patched}"
VERIFY_MACOS_LEGACY_BIN_DIR="${PATCHED_VERIFY_MACOS_LEGACY_BIN_DIR:-/usr/local/bin}"
VERIFY_CREDS_DIR="${PATCHED_VERIFY_CREDS_DIR:-$CREDS_DIR}"
VERIFY_QUEUE_BASE="${PATCHED_VERIFY_QUEUE_BASE:-/var/db/patched}"

_ENDPOINT_LAUNCHDAEMON_NAMES=(
    com.patched.update.plist
    com.patched.config-poll.plist
    com.patched.install-check.plist
    com.patched.uninstall-check.plist
    com.patched.catalogue-poll.plist
    com.patched.posture-poll.plist
)
_MACOS_LAUNCHDAEMON_NAMES=(com.patched.collect.plist com.patched.upload.plist)
_MACOS_BINARY_NAMES=(patched-collect.sh patched-upload.sh)

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
exec >> "$LOG_FILE" 2>&1
echo "=== patched-decommission $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

if [[ "$(id -u)" != "0" ]]; then
    echo "FATAL: must run as root"
    exit 1
fi

if [[ ! -f "$INFO_FILE" ]]; then
    echo "FATAL: $INFO_FILE missing — nothing staged to act on. Refusing to guess a decision; exiting without removing anything."
    exit 1
fi

MODE=$("$PYTHON3" -c "import json,sys; print(json.load(open(sys.argv[1])).get('mode') or '')" "$INFO_FILE" 2>/dev/null) || MODE=""
PURGE=$("$PYTHON3" -c "import json,sys; print('1' if json.load(open(sys.argv[1])).get('purge') else '0')" "$INFO_FILE" 2>/dev/null) || PURGE="0"
DIRECTIVE_VERSION=$("$PYTHON3" -c "import json,sys; print(json.load(open(sys.argv[1])).get('directive_version', ''))" "$INFO_FILE" 2>/dev/null) || DIRECTIVE_VERSION=""

if [[ -z "$DIRECTIVE_VERSION" || ! "$DIRECTIVE_VERSION" =~ ^[0-9]+$ ]]; then
    echo "FATAL: $INFO_FILE has no valid directive_version — this is the config_version the gate acted on and is required by the platform contract for POST /v1/agent-decommission-status. Refusing to guess; exiting without removing anything."
    exit 1
fi

echo "decommission: mode=$MODE purge=$PURGE directive_version=$DIRECTIVE_VERSION"

# ---------------------------------------------------------------------------
# HTTP / SIGNING HELPERS
# ---------------------------------------------------------------------------

patched_curl_bearer() {
    local _token="$1"; shift
    printf 'Authorization: Bearer %s\n' "$_token" | curl -H @- "$@"
}

# compute_hmac <body-file> <endpoint-id> <ts> <nonce>
#   PAT-1154 v3 canonical signing: binds method+endpoint+timestamp+nonce+body so a captured
#   signed request cannot be replayed —
#     HMAC-SHA256(b"patched-hmac-v3\n" + method + b"\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body)
#   using the base64 hmac-secret in $CREDS_DIR/hmac-secret. ts and nonce MUST
#   be the exact strings sent in the X-Patched-Timestamp / X-Patched-Nonce
#   headers for this same request — the caller below generates ts+nonce
#   FIRST, then passes them here AND into the headers. Matches
#   endpoint/patched-fetch-config.sh's and macos/patched-upload.sh's
#   compute_hmac exactly (same domain prefix, same /usr/bin/python3, same
#   base64 secret handling). See endpoint/test-hmac-v3.zsh, which extracts
#   this function's real shipped source and checks it against the
#   authoritative vectors.
compute_hmac() {
    "$PYTHON3" - "$1" "$2" "$3" "$4" "$CREDS_DIR/hmac-secret" <<'PYEOF'
import sys, hmac, hashlib, base64
body_path, endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path, 'rb') as f:
    secret = base64.b64decode(f.read().strip())
with open(body_path, 'rb') as f:
    body = f.read()
msg = b"patched-hmac-v3\nPOST\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n" + body
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# _decommission_post_status <status> <detail>
#   POST /v1/agent-decommission-status, exact request body shape per
#   contracts/agent-config-schema.md: {"status", "detail", "directive_version"}.
#   Bounded retry: up to 3 attempts, short fixed backoff between them, hard
#   time-capped (--max-time 15 per attempt) — this must never become an
#   unbounded hang between "reported" and "died", or between "reported" and
#   "removal proceeds".
#
#   PAT-1109 second round, final contract wording: the platform's answer is
#   the RESPONSE BODY's `decommission` field ("proceed" | "superseded"), NOT
#   the HTTP status code — the two are correlated in practice (200 carries
#   "proceed", 409 carries "superseded") but the contract is explicit that
#   agents must key off the body field. This is deliberately parsed with an
#   explicit JSON decode (never a grep/pattern-match — a malformed or
#   truncated body must not accidentally look like it contains the string
#   "proceed") and an unconditional default of "abort" for anything that is
#   not exactly a recognised value.
#
#   Two distinct failure classes, kept on separate code paths as instructed:
#     - TRANSPORT failure (could not reach the platform at all — http_code
#       "000"): retried up to 3 times, then POST_RESULT="unreported" and the
#       caller falls back to proceed-anyway. An unreachable platform must
#       not block an operator-issued decommission.
#     - REACHABLE response whose body is missing, unparseable, or carries an
#       unrecognised `decommission` value: NOT retried (retrying will not
#       fix a bad body) and NOT treated as a network failure — an unreadable
#       answer to "may I destroy this agent" is not a yes, so this aborts
#       immediately, same as an explicit "superseded".
#
#   Sets POST_RESULT to one of: ok | conflict | unparseable | unreported.
#   The two abort-worthy outcomes (conflict, unparseable) are kept distinct
#   in POST_RESULT purely for honest, distinguishable logging/testing; every
#   caller that inspects POST_RESULT for the abort decision must treat both
#   identically (see the PHASE 1 case statement below).
_decommission_post_status() {
    # NOTE: local var deliberately named report_status, never `status` — zsh
    # ties `status` to `$?` as a special parameter (like path/PATH); `local
    # status=` throws "read-only variable: status" at runtime and this
    # function would never get past its first line. Found and fixed while
    # reconciling this script for PAT-1136 (not in AGENTS.md's footgun list,
    # which only names path/cdpath/fpath/manpath/infopath — worth adding).
    local report_status="$1" detail="$2"
    POST_RESULT="unreported"

    if [[ ! -f "$CREDS_DIR/bearer-token" || ! -f "$CREDS_DIR/hmac-secret" ]]; then
        echo "decommission: credentials missing in $CREDS_DIR — cannot report status=$report_status"
        return 1
    fi

    local bearer body_file sig ts nonce resp_file http_code attempt decision
    bearer=$(head -1 "$CREDS_DIR/bearer-token" | tr -d '[:space:]')
    body_file=$(mktemp /tmp/.patched-decomm-status.XXXXXX)
    "$PYTHON3" -c '
import json, sys
json.dump({
    "status": sys.argv[1],
    "detail": sys.argv[2],
    "directive_version": int(sys.argv[3]),
}, open(sys.argv[4], "w"))
' "$report_status" "$detail" "$DIRECTIVE_VERSION" "$body_file"

    attempt=0
    while (( attempt < 3 )); do
        (( attempt++ ))
        # ts/nonce generated FIRST, then signed, then the SAME strings go
        # into both the signature and the headers below (PAT-1136 v2).
        ts=$(date -u +%s)
        nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
        sig=$(compute_hmac "$body_file" "agent_decommission_status" "$ts" "$nonce")
        resp_file=$(mktemp /tmp/.patched-decomm-resp.XXXXXX)
        http_code=$(patched_curl_bearer "$bearer" -s -o "$resp_file" -w "%{http_code}" --max-time 15 \
            -X POST "$API_URL/v1/agent-decommission-status" \
            -H "X-Patched-Signature: $sig" \
            -H "X-Patched-Timestamp: $ts" \
            -H "X-Patched-Nonce: $nonce" \
            -H "Content-Type: application/json" \
            --data-binary "@$body_file" 2>/dev/null) || http_code="000"

        if [[ "$http_code" == "000" ]]; then
            # TRANSPORT failure — could not reach the platform at all.
            # Bounded-retry-then-proceed territory, kept entirely separate
            # from the body-parsing branch below.
            echo "decommission: status=$report_status POST attempt $attempt/3 could not reach the platform (transport failure)"
            rm -f "$resp_file"
            (( attempt < 3 )) && sleep 5
            continue
        fi

        # Reached the platform (some HTTP response came back, whatever its
        # status code) — the contract says decide on the BODY, not this
        # status code. Explicit JSON decode, no grep: prints exactly one of
        # proceed | superseded | unparseable, defaulting to unparseable on
        # ANY read/parse failure or unrecognised value so a malformed or
        # truncated body can never be mistaken for "proceed".
        decision=$("$PYTHON3" -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        body = f.read()
    val = json.loads(body).get("decommission")
except Exception:
    val = None
if val == "proceed":
    print("proceed")
elif val == "superseded":
    print("superseded")
else:
    print("unparseable")
' "$resp_file" 2>/dev/null) || decision="unparseable"
        [[ -n "$decision" ]] || decision="unparseable"
        rm -f "$resp_file"

        case "$decision" in
            proceed)
                echo "decommission: status=$report_status reported (attempt $attempt, HTTP $http_code, directive_version=$DIRECTIVE_VERSION) — platform response body says proceed"
                rm -f "$body_file"
                POST_RESULT="ok"
                return 0
                ;;
            superseded)
                echo "decommission: status=$report_status POST answered decommission=superseded (attempt $attempt, HTTP $http_code) — the platform reports this directive has been superseded or cancelled. Definitive, not retried, distinct from a network failure."
                rm -f "$body_file"
                POST_RESULT="conflict"
                return 0
                ;;
            *)
                echo "decommission: status=$report_status POST reached the platform (attempt $attempt, HTTP $http_code) but the response body's decommission field was missing, unparseable, or unrecognised. An unreadable answer to \"may I destroy this agent\" is not a yes — treating as a definitive abort, not retried, distinct from a network failure."
                rm -f "$body_file"
                POST_RESULT="unparseable"
                return 0
                ;;
        esac
    done

    rm -f "$body_file"
    echo "decommission: WARNING — status=$report_status could not be reported after 3 attempts, all transport failures (bounded retry window exhausted)."
    POST_RESULT="unreported"
    return 1
}

# ---------------------------------------------------------------------------
# VERIFICATION (PAT-1109 P1 C) — distinguish "verified gone" from "the
# script exited". Checks the filesystem directly rather than trusting
# either uninstall engine's own exit code or its own presence/absence on
# disk (a staged engine that is simply missing could mean "already ran
# successfully" OR "never staged correctly" — only a real filesystem check
# tells them apart).
# ---------------------------------------------------------------------------

# _launchd_label_loaded <label>
#   True (0) iff launchd currently has <label> loaded, checked via
#   `launchctl print system/<label>` — exits 0 only when the job is loaded,
#   independent of whatever its plist's on-disk state is.
#
#   non-author review, third round: verify_core_removed used to check ONLY
#   that plist files were gone from /Library/LaunchDaemons — never that the
#   corresponding launchd job was actually unloaded. `rm -f` on the plist
#   can succeed even when the `launchctl bootout` that should have preceded
#   it silently failed (queued shutdown, permission race, launchd busy), in
#   which case the job stays loaded and RUNNING while this reported the
#   agent "removed" — and self_cleanup then tears down the only retry
#   mechanism (DECOMM_DIR + this very LaunchDaemon) that could have caught
#   it on a later boot. Any label still loaded now fails verification and
#   takes the existing retry-on-next-boot path, same as a missing-plist
#   failure already does.
_launchd_label_loaded() {
    local label="$1"
    launchctl print "system/$label" >/dev/null 2>&1
}

verify_core_removed() {
    [[ -d "$VERIFY_ENDPOINT_BUNDLE_DEST" ]] && return 1
    local p label
    for p in "${_ENDPOINT_LAUNCHDAEMON_NAMES[@]}"; do
        [[ -f "$VERIFY_LAUNCHDAEMONS_DIR/$p" ]] && return 1
        label="${p%.plist}"
        _launchd_label_loaded "$label" && return 1
    done
    for p in "${_MACOS_LAUNCHDAEMON_NAMES[@]}"; do
        [[ -f "$VERIFY_LAUNCHDAEMONS_DIR/$p" ]] && return 1
        label="${p%.plist}"
        _launchd_label_loaded "$label" && return 1
    done
    for p in "${_MACOS_BINARY_NAMES[@]}"; do
        [[ -f "$VERIFY_MACOS_BIN_DIR/$p" ]] && return 1
        [[ -f "$VERIFY_MACOS_LEGACY_BIN_DIR/$p" ]] && return 1
    done
    return 0
}

verify_purge_removed() {
    [[ -d "$VERIFY_CREDS_DIR" ]] && return 1
    [[ -d "$VERIFY_QUEUE_BASE" ]] && return 1
    return 0
}

# _creds_snapshot_valid (PAT-1344, non-author review): true (0) iff every
# credential file the deferred terminal report actually reads out of
# CREDS_DIR — bearer-token (_decommission_post_status, ~line 249) and
# hmac-secret (compute_hmac, ~line 187) — is present in CREDS_SNAPSHOT_DIR
# AND non-empty. A bare `-f` would pass a zero-byte file left behind by a
# `cp` that failed partway or a `chmod` that never ran; `-s` checks
# existence and size > 0 in one test, so a present-but-useless snapshot
# fails this the same as a missing one.
_creds_snapshot_valid() {
    [[ -s "$CREDS_SNAPSHOT_DIR/bearer-token" && -s "$CREDS_SNAPSHOT_DIR/hmac-secret" ]]
}

self_cleanup() {
    # LAST, and only ever called after removal is VERIFIED complete (or, for
    # the abort path, after confirming nothing was touched at all). DO NOT
    # move any part of this into endpoint/uninstall.sh or macos/uninstall.sh:
    # this script runs staged COPIES of both from inside DECOMM_DIR, so if
    # either script also tore down DECOMM_DIR or this LaunchDaemon, it would
    # delete or kill this very running script mid-run — the self-bootout
    # problem one level up.
    #
    # Order matters for crash safety, not for "surviving to run the next
    # line": everything real has already happened by the time this runs, so
    # any interruption here is pure tidy-up, never a half-removed agent.
    #   a. rm the plist first: even if interrupted right after, launchd will
    #      not load this job on the next boot.
    #   b. rm DECOMM_DIR (holds this very running script) — safe, same
    #      pattern as any self-deleting installer.
    #   c. bootout our own label last — may terminate this process before
    #      `exit 0`, which is expected and fine; nothing after it matters.
    echo "decommission: cleaning up the decommission daemon itself"
    rm -f "$DAEMON_PLIST"
    rm -rf "$DECOMM_DIR"
    launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || true
    echo "decommission: done"
}

# ---------------------------------------------------------------------------
# PHASE 1 — ACKNOWLEDGE (the last moment removal can be called off)
#
# Marker-gated: once passed (proceed, OR a genuine transport failure that
# falls back to "proceed anyway"), never re-entered on a resumed/retried
# run — per the platform contract, the acknowledged report is deliberately
# the ONLY point the platform can abort this directive. Re-sending it after
# removal may already be underway would contradict "the last moment", and
# would risk aborting a removal that has already made irreversible progress.
# ---------------------------------------------------------------------------

if [[ ! -f "$ACK_MARKER" ]]; then
    _decommission_post_status "acknowledged" "directive received, removal starting"
    case "$POST_RESULT" in
        conflict|unparseable)
            # Both are abort-worthy and handled identically here: an
            # explicit decommission=superseded, and a reachable-but-
            # unreadable response, are both "not a yes" to "may I destroy
            # this agent" (PAT-1109 second round, final contract wording).
            # _decommission_post_status already logged which one this was.
            echo "decommission: ABORT — directive_version=$DIRECTIVE_VERSION will not be acted on (see the reason logged just above). Leaving the agent installed and running. Nothing was touched, so cleaning up the staged removal in full so nothing resurrects this attempt on a later boot."
            self_cleanup
            exit 0
            ;;
        ok|unreported)
            # P1-B (non-author review finding): the marker write used to be
            # unchecked and not flushed. If it silently failed (or was lost
            # to a crash before hitting stable storage) after PHASE 2 removal
            # had already started, the NEXT boot would find no marker, treat
            # this as a fresh run, and re-enter PHASE 1 — the cancellable
            # acknowledge phase — against an agent that is already partially
            # removed. A "superseded/conflict" answer at that point drives
            # self_cleanup, tearing down staging over a half-removed agent:
            # an inconsistent state with no LaunchDaemon left to finish the
            # job. The invariant: irreversible removal (PHASE 2) never
            # begins unless "acknowledged, do not re-cancel" is DURABLY
            # recorded first. So: write, chmod, sync (flush to stable
            # storage, not just the page cache), then verify via the
            # filesystem directly — same convention as verify_core_removed /
            # verify_purge_removed below, never trusting a redirection's own
            # exit code alone on the single most destructive path in the
            # product. sync's OWN exit code is captured and checked too
            # (non-author review, second round) — a failed flush means the
            # marker may still be sitting unflushed in the page cache only,
            # so it is treated exactly like the marker not existing at all:
            # CRITICAL, exit before PHASE 2, retry PHASE 1 cleanly next boot.
            # (This checks sync's return value, nothing more — a full
            # power-loss durability guarantee, e.g. F_FULLFSYNC, and any
            # resume-idempotency redesign are PAT-1158's, not this ticket's.)
            : > "$ACK_MARKER" 2>/dev/null
            chmod 600 "$ACK_MARKER" 2>/dev/null || true
            sync_rc=0
            sync 2>/dev/null || sync_rc=$?
            if [[ ! -f "$ACK_MARKER" || "$sync_rc" -ne 0 ]]; then
                if [[ "$sync_rc" -ne 0 ]]; then
                    echo "decommission: CRITICAL sync failed (exit $sync_rc) while flushing the acknowledge marker at $ACK_MARKER to stable storage — cannot confirm the 'acknowledged, do not re-cancel' state survives a crash between here and PHASE 2."
                else
                    echo "decommission: CRITICAL could not durably record the acknowledge marker at $ACK_MARKER — the 'acknowledged, do not re-cancel' state did not persist."
                fi
                echo "decommission: refusing to begin PHASE 2 (irreversible removal) this run: leaving DECOMM_DIR and the LaunchDaemon in place so a clean PHASE 1 retries on next boot, rather than risk losing this record mid-removal."
                exit 1
            fi
            ;;
    esac
else
    echo "decommission: acknowledge phase already completed in a prior run — resuming removal (not re-sent; see PHASE 1 comment above)"
fi

# ---------------------------------------------------------------------------
# PHASE 2 — REMOVAL, then VERIFY, then report the genuine terminal outcome
# ---------------------------------------------------------------------------

run_step() {
    local script="$1"; shift
    if [[ -f "$script" ]]; then
        echo "decommission: running $(basename "$script") $*"
        bash "$script" "$@"
        echo "decommission: $(basename "$script") exit code $?"
    else
        echo "decommission: $(basename "$script") already gone from $DECOMM_DIR — assuming a prior attempt already ran it (verifying below, not trusting this alone)"
    fi
}

run_step "$ENDPOINT_UNINSTALL"
run_step "$MACOS_UNINSTALL"   # never --purge on this first pass — see PURGE handling below

if ! verify_core_removed; then
    _decommission_post_status "failed" "removal not yet verified complete; will retry on next boot" || true
    echo "decommission: removal NOT verified complete — leaving DECOMM_DIR and the LaunchDaemon in place so RunAtLoad will retry on next boot (PAT-1109 P1 C: a non-zero exit or a missing staged engine is never treated as completion)"
    exit 1
fi

# ---------------------------------------------------------------------------
# non-author review P1-C: the terminal "removed" report must be authoritative
# — for purge:true it must not claim success until purge is ALSO verified,
# never merely because core removal (endpoint + macOS agent, no --purge) is
# done. The OLD code reported "removed" right here, unconditionally, then
# ran purge afterward; if purge then failed, the platform had already been
# told removal succeeded while bearer/HMAC credentials and the local queue
# sat on disk until a next-boot retry — exactly what the ticket's contract
# ("removed" means removed) forbids. So purge:true takes an entirely
# separate path below that reports EXACTLY ONCE, only after both steps
# verify, and purge:false keeps the original immediate-report behaviour
# (nothing to wait for).
# ---------------------------------------------------------------------------

if [[ "$PURGE" == "1" ]]; then
    echo "decommission: core agent removal verified; purge requested — deferring the terminal report until purge also verifies (non-author review P1-C: 'removed' must not be sent before purge is genuinely done)"

    # Snapshot the reporting credentials into DECOMM_DIR BEFORE running
    # purge: purge is exactly the step that deletes bearer-token/hmac-secret
    # out of CREDS_DIR, and the terminal report below (sent only once purge
    # is verified) needs live credentials to sign and send itself with. This
    # is a snapshot of two small credential files, not the uploader/daemon —
    # the "report before the uploader is gone" guarantee this script's
    # header describes is unaffected. Idempotent: skipped if a snapshot
    # already exists AND is valid from a prior attempt (retry) or if the
    # real creds are already gone with no snapshot ever taken (nothing left
    # to snapshot; the report below degrades to a logged, non-fatal skip,
    # same as any other missing-credentials case in
    # _decommission_post_status).
    #
    # PAT-1344 (non-author review): every `cp`/`chmod` here used to run with
    # `2>/dev/null` and no exit-code check, so a failed copy left an
    # existing-but-empty-or-partial CREDS_SNAPSHOT_DIR with NO log line at
    # all — the only downstream gate was a bare `-d` check (below, and at
    # the "purge verified" branch), which a present-but-useless directory
    # passes. That let purge run for real, genuinely completing and
    # genuinely verifying, while the platform was never told and never
    # could be: once purge deletes CREDS_DIR there is no credential left on
    # any later boot to sign a retry's report with. So every step below is
    # now checked explicitly, and a stale invalid snapshot from a prior
    # failed attempt is discarded and retaken rather than silently trusted.
    # If the resulting snapshot is not usable, purge does NOT run this
    # attempt — failing here, before purge, is the only point that
    # preserves the ability to ever report; failing after does not.
    if [[ -d "$CREDS_SNAPSHOT_DIR" ]] && ! _creds_snapshot_valid; then
        echo "decommission: existing $CREDS_SNAPSHOT_DIR from a prior attempt is not usable (bearer-token or hmac-secret missing or zero-byte) — discarding it so this attempt retakes a full snapshot"
        rm -rf "$CREDS_SNAPSHOT_DIR"
    fi

    if [[ ! -d "$CREDS_SNAPSHOT_DIR" && -f "$CREDS_DIR/bearer-token" && -f "$CREDS_DIR/hmac-secret" ]]; then
        snapshot_failed=""
        if mkdir -p "$CREDS_SNAPSHOT_DIR" 2>/dev/null; then
            chmod 700 "$CREDS_SNAPSHOT_DIR" 2>/dev/null || { echo "decommission: ERROR — chmod 700 $CREDS_SNAPSHOT_DIR failed while snapshotting reporting credentials ahead of purge"; snapshot_failed=1; }
            cp "$CREDS_DIR/bearer-token" "$CREDS_SNAPSHOT_DIR/bearer-token" 2>/dev/null || { echo "decommission: ERROR — cp $CREDS_DIR/bearer-token to $CREDS_SNAPSHOT_DIR failed while snapshotting reporting credentials ahead of purge"; snapshot_failed=1; }
            cp "$CREDS_DIR/hmac-secret" "$CREDS_SNAPSHOT_DIR/hmac-secret" 2>/dev/null || { echo "decommission: ERROR — cp $CREDS_DIR/hmac-secret to $CREDS_SNAPSHOT_DIR failed while snapshotting reporting credentials ahead of purge"; snapshot_failed=1; }
            chmod 600 "$CREDS_SNAPSHOT_DIR/bearer-token" "$CREDS_SNAPSHOT_DIR/hmac-secret" 2>/dev/null || { echo "decommission: ERROR — chmod 600 on the credential snapshot failed while snapshotting reporting credentials ahead of purge"; snapshot_failed=1; }
        else
            echo "decommission: ERROR — could not create $CREDS_SNAPSHOT_DIR to snapshot reporting credentials ahead of purge"
            snapshot_failed=1
        fi

        if [[ -n "$snapshot_failed" ]] || ! _creds_snapshot_valid; then
            echo "decommission: ERROR — credential snapshot at $CREDS_SNAPSHOT_DIR is missing or incomplete (bearer-token or hmac-secret absent or zero-byte) ahead of an irreversible purge; once purge runs, $CREDS_DIR is gone and no later boot could ever report the outcome. Refusing to run purge this attempt: leaving DECOMM_DIR and the LaunchDaemon in place so RunAtLoad retries the snapshot on next boot."
            exit 1
        fi
    fi

    run_step "$MACOS_UNINSTALL" --purge

    if ! verify_purge_removed; then
        echo "decommission: core agent removal verified, but purge (credentials/queue) is not yet verified complete — leaving DECOMM_DIR and the LaunchDaemon in place to retry the purge step on next boot. No 'removed' report has been sent yet (P1-C), so nothing has been over-claimed to the platform."
        if [[ -d "$CREDS_SNAPSHOT_DIR" ]]; then
            CREDS_DIR="$CREDS_SNAPSHOT_DIR" _decommission_post_status "failed" "core removal verified; purge (credentials/queue) not yet verified complete; will retry on next boot" || true
        else
            echo "decommission: WARNING — could not report status=failed for the pending purge: no credentials survived to report with (neither CREDS_DIR nor a snapshot exist)"
        fi
        exit 1
    fi

    # Purge verified complete: send the ONE authoritative "removed" report
    # now, using the pre-purge snapshot (CREDS_DIR itself is gone by
    # design at this point), then delete the snapshot — it has done its job.
    if [[ -d "$CREDS_SNAPSHOT_DIR" ]]; then
        CREDS_DIR="$CREDS_SNAPSHOT_DIR" _decommission_post_status "removed" "endpoint, macOS agent, credentials and queue all verified removed" || true
        rm -rf "$CREDS_SNAPSHOT_DIR"
    else
        echo "decommission: WARNING — purge verified complete but could not report status=removed: no credentials survived to report with"
    fi
    echo "decommission: purge verified and terminal outcome reported"
else
    _decommission_post_status "removed" "endpoint and macOS agent components verified removed" || true
    echo "decommission: core agent removal verified and reported"
fi

self_cleanup
exit 0
