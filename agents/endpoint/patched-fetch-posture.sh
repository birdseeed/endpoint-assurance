#!/bin/zsh
##############################################################################
# patched-fetch-posture.sh — fetch and cache device posture.
#
# Follows the patched-fetch-config.sh pattern:
#   1. Lock via mkdir.
#   2. Auth via Bearer + HMAC-SHA256 (GET /v1/posture).
#   3. Verify the Ed25519 signature + tenant binding + anti-rollback via
#      verify-posture.py (PAT-910), structurally validate the verified posture
#      via validate-posture.py, then commit: advance + fsync the version file
#      FIRST, then atomically update the local cache. INVARIANT: the
#      anti-rollback floor is >= the cached posture's issued_at at every
#      instant (the verifier also derives its effective floor as
#      max(version-file, cached issued_at), closing any divergence
#      structurally). FAIL CLOSED: a fetch, verify, or validation failure
#      keeps the last known-good posture and never falls back to unsigned or
#      stale posture.
#
# Context: The Self Service apps (macOS/Windows) render from this cached file,
# and patched-uninstall.sh reads app_policy.user_removable from it to gate
# root-privileged app removal — so an unverified posture must never be cached.
##############################################################################

set -u

# PAT-2394: root command lookup must never include Homebrew, inherited PATH
# or a test override. Runtime failure is fatal before logging or state writes.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] && "$PYTHON3" -I -c 'pass' >/dev/null 2>&1 || { printf '%s\n' "FATAL: trusted /usr/bin/python3 runtime unavailable or unusable; no work performed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"
LOG_FILE="${PATCHED_LOG_FILE:-/var/log/patched-update.log}"
BUNDLE_DIR="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}"

# PAT-1765: structured JSON-lines log, the same file and helper as
# patched-fetch-config.sh (PAT-652), so a skipped fetch is visible there too.
JSONL_LOG_DIR="${PATCHED_JSONL_LOG_DIR:-/Library/Logs/Patched}"
JSONL_LOG_FILE="$JSONL_LOG_DIR/daemon.jsonl"
JSONL_COMPONENT="posture"

POSTURE_FILE="$STATE_DIR/posture.json"
POSTURE_VERSION_FILE="$STATE_DIR/posture.version"
# PAT-910: authenticity is now Ed25519-verified (signature + tenant binding +
# anti-rollback) at parity with verify-agent-config.py — no longer TLS-only.
VERIFIER="$BUNDLE_DIR/verify-posture.py"
# Structural validation of the verified posture before caching (fail-closed):
# a signed-but-malformed payload must never reach the cache that root-privileged
# readers (patched-uninstall.sh) consume.
VALIDATOR="$BUNDLE_DIR/validate-posture.py"

# PAT-1765: agent-health store helpers, so this script can record a
# credentials fault (see PATCHED_CREDENTIALS_HEALTH below).
# >>> PATCHED_AGENT_HEALTH_START (keep in sync with the identically-named
# block in macos/lib/agent_health.sh and the copy inlined in
# endpoint/patched-log-upload.sh — endpoint/ has no lib/ convention:
# tools/build-bundle.sh copies its scripts individually by filename with no
# lib/ directory, so a sourced dependency here would fatal on every deployed
# release build, the same reason patched_curl_bearer above is inlined rather
# than sourced. This copy carries no caller for
# patched_agent_health_emit_degraded_json — only macos/patched-upload.sh
# emits — kept anyway for byte-parity with the other two copies, matching
# this repo's existing inline-duplication convention (patched_curl_bearer).

# patched_agent_health_record_failure <kind> <subject> <reason>
#   Creates or refreshes the active entry for (kind, subject): first_seen is
#   preserved across repeat calls, last_seen/reason/count refresh every call.
#   ever_succeeded is never set here — only looked up (from the persistent
#   ledger, defaulting false) by the caller when it later reads `active` back
#   out via patched_agent_health_emit_degraded_json.
patched_agent_health_record_failure() {
    local _kind="$1" _subject="$2" _reason="$3"
    local _ah_store _ah_dir _ah_tmp _ah_attempt _ah_py_rc _ah_reclaim_marker
    local _ah_held_start _ah_still_live _ah_current_start _ah_pid_line _ah_my_start

    _ah_store="${PATCHED_AGENT_HEALTH_STORE:-/Library/Application Support/Patched/.agent-health.json}"
    _ah_dir=$(dirname "$_ah_store")
    mkdir -p "$_ah_dir" 2>/dev/null

    # _ah_lock_dir is deliberately NOT declared local: zsh runs a
    # function-local `trap ... EXIT` after this function's own locals have
    # already been torn down (PAT-1037 finding, verified by hand there and
    # re-verified for this ticket), so under `set -u` a trap reading a local
    # variable aborts with "parameter not set" the moment it fires. Leaving
    # it as a plain assignment-only (function-scoped-by-convention) variable
    # keeps it alive for the trap below to read.
    _ah_lock_dir="$_ah_dir/.agent-health.lock"
    if ! mkdir "$_ah_lock_dir" 2>/dev/null; then
        _ah_held_pid=""
        _ah_held_start=""
        for _ah_attempt in 1 2 3; do
            _ah_pid_line=$(cat "$_ah_lock_dir/pid" 2>/dev/null)
            _ah_held_pid="${_ah_pid_line%%|*}"
            if [[ "$_ah_pid_line" == *"|"* ]]; then
                _ah_held_start="${_ah_pid_line#*|}"
            else
                _ah_held_start=""
            fi
            [[ -n "$_ah_held_pid" ]] && break
            (( _ah_attempt < 3 )) && sleep 0.1
        done
        # PAT-1065 review finding 4: kill -0 succeeding only proves SOME
        # process currently holds this pid, not that it is the SAME process
        # that acquired the lock — the OS reuses pids over time, so a
        # holder that died and was later reused by an unrelated process
        # would otherwise read as "still live" forever, wedging this lock
        # shut for that unrelated process's entire lifetime. The holder's
        # start time, recorded alongside its pid when the lock was acquired
        # (cheap, stable for the life of one process, only ever compared
        # against itself on this same machine), closes that gap: both the
        # pid must be alive AND its start time must still match before we
        # treat the lock as genuinely live. A lock written before this
        # hardening (no "|" in its pid file) has no start time to compare —
        # tolerated gracefully via pid-only liveness rather than treated as
        # a hard failure.
        _ah_still_live=0
        if [[ -n "$_ah_held_pid" ]] && kill -0 "$_ah_held_pid" 2>/dev/null; then
            if [[ -n "$_ah_held_start" ]]; then
                _ah_current_start=$(ps -o lstart= -p "$_ah_held_pid" 2>/dev/null | xargs 2>/dev/null)
                [[ -n "$_ah_current_start" && "$_ah_current_start" == "$_ah_held_start" ]] && _ah_still_live=1
            else
                _ah_still_live=1
            fi
        fi
        if (( _ah_still_live )); then
            echo "agent-health: lock held by another instance (pid $_ah_held_pid) — skipping this record (${_kind}|${_subject})"
            return 0
        fi
        echo "agent-health: lock at $_ah_lock_dir looks stale (recorded holder pid '${_ah_held_pid:-<missing>}' is not running, or its start time no longer matches — pid reuse) — reclaiming and retrying once"
        rm -rf "$_ah_lock_dir"
        if ! mkdir "$_ah_lock_dir" 2>/dev/null; then
            echo "agent-health: lock held by another instance after stale-lock reclaim attempt — skipping this record (${_kind}|${_subject})"
            return 0
        fi
        # PAT-1065 review finding C: this mkdir succeeding does not prove we
        # are the SOLE reclaimer. rm -rf + mkdir is not one atomic operation,
        # so two different processes can each independently observe the same
        # stale lock and both reclaim, interleaved so one's rm -rf destroys
        # the other's freshly-mkdir'd directory — both then believe they
        # hold it. A random, per-attempt marker (not the pid, which a second
        # reclaimer would also publish and could look superficially
        # consistent) written and read back after a brief settle (matching
        # this file's existing ~0.1s retry cadence) narrows that window: if
        # a second reclaimer's own rm+mkdir+write also landed during the
        # settle, our marker will have been overwritten and the read-back
        # will not match, so we back off rather than proceed on a lock we
        # can no longer prove is exclusively ours. Not a bulletproof
        # guarantee — no mkdir-based lock can be, absent a kernel-atomic
        # primitive like an fd-held flock, which macOS ships no standalone
        # flock(1) for — a proportionate narrowing, matching this file's
        # other staleness handling.
        _ah_reclaim_marker=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)' 2>/dev/null)
        _ah_reclaim_marker="${_ah_reclaim_marker:-$$-$RANDOM-$RANDOM}"
        echo "$_ah_reclaim_marker" > "$_ah_lock_dir/pid" 2>/dev/null
        sleep 0.1
        if [[ "$(cat "$_ah_lock_dir/pid" 2>/dev/null)" != "$_ah_reclaim_marker" ]]; then
            echo "agent-health: lost the reclaim race to a second reclaimer — skipping this record (${_kind}|${_subject})"
            return 0
        fi
    fi
    # PAT-1065 review finding 4: record OUR start time alongside our pid so a
    # future contender can tell a live holder from a pid the OS has since
    # reused for a different process.
    _ah_my_start=$(ps -o lstart= -p $$ 2>/dev/null | xargs 2>/dev/null)
    echo "$$|$_ah_my_start" > "$_ah_lock_dir/pid" 2>/dev/null
    trap 'rm -rf "$_ah_lock_dir"' EXIT

    _ah_tmp=$(mktemp "$_ah_dir/.agent-health.tmp.XXXXXX" 2>/dev/null)
    if [[ -z "$_ah_tmp" ]]; then
        echo "agent-health: could not create temp file in $_ah_dir — skipping this record (${_kind}|${_subject})"
        return 0
    fi

    "$PYTHON3" - "$_ah_store" "$_ah_tmp" "$_kind" "$_subject" "$_reason" <<'PYEOF'
import json, os, sys
from datetime import datetime, timezone

store_path, tmp_path, kind, subject, reason = sys.argv[1:6]

# PAT-1065 review findings 1 & 2: a store that EXISTS but fails to parse, or
# parses but has an unexpected internal shape (active/ever_succeeded present
# but not a dict), must NEVER be silently treated as empty here — this is
# the MUTATION path, so doing that would overwrite the store with a fresh
# copy containing only this one new entry, destroying every OTHER active
# fault and the entire ever_succeeded ledger on nothing but a transient
# glitch or an unrecognised shape. Only a genuinely absent file (first-ever
# write) starts fresh; anything else that cannot be trusted aborts this
# record attempt without writing tmp_path at all (the shell caller then
# leaves the original store completely untouched — see the "don't overwrite
# what you don't recognise" instinct in PAT-1040's config quarantine).
if not os.path.exists(store_path):
    active = {}
    ever = {}
else:
    try:
        with open(store_path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("store top level is not a JSON object")
        active = data.get("active")
        ever = data.get("ever_succeeded")
        if not isinstance(active, dict) or not isinstance(ever, dict):
            raise ValueError("store has an unexpected internal shape")
    except Exception:
        print("agent-health: existing store could not be read/parsed as the "
              "expected shape — aborting this record without touching it",
              file=sys.stderr)
        sys.exit(1)

key = kind + "|" + subject
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

existing = active.get(key)
count = 1
first_seen = now
if isinstance(existing, dict) and isinstance(existing.get("first_seen"), str):
    first_seen = existing["first_seen"]
    prev_count = existing.get("count")
    count = prev_count + 1 if isinstance(prev_count, int) and prev_count >= 1 else 1

active[key] = {
    "kind": kind,
    "subject": subject,
    "reason": reason,
    "first_seen": first_seen,
    "last_seen": now,
    "count": count,
}
data_out = {"active": active, "ever_succeeded": ever}

with open(tmp_path, "w") as f:
    json.dump(data_out, f, separators=(",", ":"))
PYEOF
    _ah_py_rc=$?

    if [[ $_ah_py_rc -eq 0 && -s "$_ah_tmp" ]]; then
        chmod 600 "$_ah_tmp" 2>/dev/null
        mv -f "$_ah_tmp" "$_ah_store"
    else
        echo "agent-health: failed to update store for ${_kind}|${_subject}"
        rm -f "$_ah_tmp"
    fi
    return 0
}

# patched_agent_health_record_success <kind> <subject>
#   Clears the active entry (so it stops being reported — the fault is
#   resolved) and marks the persistent ledger's ever_succeeded=true for this
#   (kind, subject), which is never auto-cleared: a later recurrence of the
#   same fault must still report ever_succeeded=true, since it plainly did
#   work at least once.
patched_agent_health_record_success() {
    local _kind="$1" _subject="$2"
    local _ah_store _ah_dir _ah_tmp _ah_attempt _ah_py_rc _ah_reclaim_marker
    local _ah_held_start _ah_still_live _ah_current_start _ah_pid_line _ah_my_start

    _ah_store="${PATCHED_AGENT_HEALTH_STORE:-/Library/Application Support/Patched/.agent-health.json}"
    _ah_dir=$(dirname "$_ah_store")
    mkdir -p "$_ah_dir" 2>/dev/null

    _ah_lock_dir="$_ah_dir/.agent-health.lock"
    if ! mkdir "$_ah_lock_dir" 2>/dev/null; then
        _ah_held_pid=""
        _ah_held_start=""
        for _ah_attempt in 1 2 3; do
            _ah_pid_line=$(cat "$_ah_lock_dir/pid" 2>/dev/null)
            _ah_held_pid="${_ah_pid_line%%|*}"
            if [[ "$_ah_pid_line" == *"|"* ]]; then
                _ah_held_start="${_ah_pid_line#*|}"
            else
                _ah_held_start=""
            fi
            [[ -n "$_ah_held_pid" ]] && break
            (( _ah_attempt < 3 )) && sleep 0.1
        done
        # PAT-1065 review finding 4: kill -0 succeeding only proves SOME
        # process currently holds this pid, not that it is the SAME process
        # that acquired the lock — the OS reuses pids over time, so a
        # holder that died and was later reused by an unrelated process
        # would otherwise read as "still live" forever, wedging this lock
        # shut for that unrelated process's entire lifetime. The holder's
        # start time, recorded alongside its pid when the lock was acquired
        # (cheap, stable for the life of one process, only ever compared
        # against itself on this same machine), closes that gap: both the
        # pid must be alive AND its start time must still match before we
        # treat the lock as genuinely live. A lock written before this
        # hardening (no "|" in its pid file) has no start time to compare —
        # tolerated gracefully via pid-only liveness rather than treated as
        # a hard failure.
        _ah_still_live=0
        if [[ -n "$_ah_held_pid" ]] && kill -0 "$_ah_held_pid" 2>/dev/null; then
            if [[ -n "$_ah_held_start" ]]; then
                _ah_current_start=$(ps -o lstart= -p "$_ah_held_pid" 2>/dev/null | xargs 2>/dev/null)
                [[ -n "$_ah_current_start" && "$_ah_current_start" == "$_ah_held_start" ]] && _ah_still_live=1
            else
                _ah_still_live=1
            fi
        fi
        if (( _ah_still_live )); then
            echo "agent-health: lock held by another instance (pid $_ah_held_pid) — skipping this record (${_kind}|${_subject})"
            return 0
        fi
        echo "agent-health: lock at $_ah_lock_dir looks stale (recorded holder pid '${_ah_held_pid:-<missing>}' is not running, or its start time no longer matches — pid reuse) — reclaiming and retrying once"
        rm -rf "$_ah_lock_dir"
        if ! mkdir "$_ah_lock_dir" 2>/dev/null; then
            echo "agent-health: lock held by another instance after stale-lock reclaim attempt — skipping this record (${_kind}|${_subject})"
            return 0
        fi
        # PAT-1065 review finding C: this mkdir succeeding does not prove we
        # are the SOLE reclaimer. rm -rf + mkdir is not one atomic operation,
        # so two different processes can each independently observe the same
        # stale lock and both reclaim, interleaved so one's rm -rf destroys
        # the other's freshly-mkdir'd directory — both then believe they
        # hold it. A random, per-attempt marker (not the pid, which a second
        # reclaimer would also publish and could look superficially
        # consistent) written and read back after a brief settle (matching
        # this file's existing ~0.1s retry cadence) narrows that window: if
        # a second reclaimer's own rm+mkdir+write also landed during the
        # settle, our marker will have been overwritten and the read-back
        # will not match, so we back off rather than proceed on a lock we
        # can no longer prove is exclusively ours. Not a bulletproof
        # guarantee — no mkdir-based lock can be, absent a kernel-atomic
        # primitive like an fd-held flock, which macOS ships no standalone
        # flock(1) for — a proportionate narrowing, matching this file's
        # other staleness handling.
        _ah_reclaim_marker=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)' 2>/dev/null)
        _ah_reclaim_marker="${_ah_reclaim_marker:-$$-$RANDOM-$RANDOM}"
        echo "$_ah_reclaim_marker" > "$_ah_lock_dir/pid" 2>/dev/null
        sleep 0.1
        if [[ "$(cat "$_ah_lock_dir/pid" 2>/dev/null)" != "$_ah_reclaim_marker" ]]; then
            echo "agent-health: lost the reclaim race to a second reclaimer — skipping this record (${_kind}|${_subject})"
            return 0
        fi
    fi
    # PAT-1065 review finding 4: record OUR start time alongside our pid so a
    # future contender can tell a live holder from a pid the OS has since
    # reused for a different process.
    _ah_my_start=$(ps -o lstart= -p $$ 2>/dev/null | xargs 2>/dev/null)
    echo "$$|$_ah_my_start" > "$_ah_lock_dir/pid" 2>/dev/null
    trap 'rm -rf "$_ah_lock_dir"' EXIT

    _ah_tmp=$(mktemp "$_ah_dir/.agent-health.tmp.XXXXXX" 2>/dev/null)
    if [[ -z "$_ah_tmp" ]]; then
        echo "agent-health: could not create temp file in $_ah_dir — skipping this record (${_kind}|${_subject})"
        return 0
    fi

    "$PYTHON3" - "$_ah_store" "$_ah_tmp" "$_kind" "$_subject" <<'PYEOF'
import json, os, sys

store_path, tmp_path, kind, subject = sys.argv[1:5]

# PAT-1065 review findings 1 & 2: same "never silently treat an unreadable
# or malformed store as empty on a mutation path" rule as record_failure's
# twin comment above — see there for the full reasoning.
if not os.path.exists(store_path):
    active = {}
    ever = {}
else:
    try:
        with open(store_path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("store top level is not a JSON object")
        active = data.get("active")
        ever = data.get("ever_succeeded")
        if not isinstance(active, dict) or not isinstance(ever, dict):
            raise ValueError("store has an unexpected internal shape")
    except Exception:
        print("agent-health: existing store could not be read/parsed as the "
              "expected shape — aborting this record without touching it",
              file=sys.stderr)
        sys.exit(1)

key = kind + "|" + subject
active.pop(key, None)
ever[key] = True

data_out = {"active": active, "ever_succeeded": ever}

with open(tmp_path, "w") as f:
    json.dump(data_out, f, separators=(",", ":"))
PYEOF
    _ah_py_rc=$?

    if [[ $_ah_py_rc -eq 0 && -s "$_ah_tmp" ]]; then
        chmod 600 "$_ah_tmp" 2>/dev/null
        mv -f "$_ah_tmp" "$_ah_store"
    else
        echo "agent-health: failed to update store for ${_kind}|${_subject}"
        rm -f "$_ah_tmp"
    fi
    return 0
}

# patched_agent_health_emit_degraded_json
#   Prints the current `active` entries as a compact JSON array (the
#   payload's agent_health.degraded value), each augmented with
#   ever_succeeded looked up from the persistent ledger (defaulting to
#   false, never null/omitted — the server's extractor decodes this field as
#   *bool specifically to catch a null as malformed).
#
#   Exit status distinguishes "genuinely nothing active" from "could not
#   tell" — collapsing those into the same "[]" output would be a real
#   data-loss bug: per the absent-vs-present-empty contract
#   (go-service/docs/PAYLOAD_SCHEMA.md agent_health section),
#   {"degraded": []} is not neutral, it is an EXPLICIT ALL-CLEAR that makes
#   the server delete every existing degraded row for this device. A
#   transient local read/parse glitch on the store file must never be
#   allowed to masquerade as that all-clear and wipe out genuinely active
#   fault records the server correctly has on file (PAT-1065 review finding
#   A) — that is exactly the fails-safe-so-invisible shape this whole
#   initiative exists to close, just relocated one level down.
#     - store file does not exist at all: prints "[]", returns 0. This is
#       the genuine "nothing has ever been recorded" case (e.g. a fresh
#       install, or every fault has been resolved and cleared) and is safe
#       to report as an all-clear.
#     - store file exists but could not be parsed as a JSON object
#       (corrupted, transient unreadable, wrong top-level shape): prints
#       nothing, returns 1. The caller (patched_agent_health_merge_into_payload)
#       must treat this as "no opinion" — omit the agent_health key entirely
#       from the payload, the contract's own designed-in state for exactly
#       this uncertainty — never fall back to printing "[]" in this branch.
#   Read-only: no lock needed for the store's own atomic-rename guarantee,
#   but see above — "no lock needed" is not the same as "no failure mode".
patched_agent_health_emit_degraded_json() {
    local _ah_store
    _ah_store="${PATCHED_AGENT_HEALTH_STORE:-/Library/Application Support/Patched/.agent-health.json}"

    "$PYTHON3" - "$_ah_store" <<'PYEOF'
import json, os, sys

store_path = sys.argv[1]

if not os.path.exists(store_path):
    print("[]")
    sys.exit(0)

try:
    with open(store_path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("store top level is not a JSON object")
    active = data.get("active")
    ever = data.get("ever_succeeded")
    # PAT-1065 review finding 2: a store that parses fine but has the WRONG
    # internal shape (active present but not a dict, say) must not be
    # silently coerced to empty either — that still feeds a false all-clear
    # through this same path just one layer down. Treat it exactly like the
    # unparseable case: unknown, not empty.
    if not isinstance(active, dict) or not isinstance(ever, dict):
        raise ValueError("store has an unexpected internal shape")
except Exception:
    # Exists but could not be read/parsed/trusted: genuinely unknown, not
    # empty. Print nothing and signal the caller via exit status — never
    # guess "[]" here, that would be reported upstream as a confirmed
    # all-clear.
    sys.exit(1)

# PAT-2245: sync_never_succeeded/catalogue was the retired signed app
# catalogue's transport health.
RETIRED = {("sync_never_succeeded", "catalogue")}

out = []
for key, entry in active.items():
    if not isinstance(entry, dict):
        continue
    kind = entry.get("kind")
    subject = entry.get("subject")
    reason = entry.get("reason")
    first_seen = entry.get("first_seen")
    last_seen = entry.get("last_seen")
    count = entry.get("count")
    if not (isinstance(kind, str) and isinstance(subject, str) and isinstance(reason, str)
            and isinstance(first_seen, str) and isinstance(last_seen, str)
            and isinstance(count, int) and count >= 1):
        continue
    # PAT-2245: a capability this agent no longer has. An older release can
    # have left its fault active in the store, and nothing will ever record a
    # success to clear it; the platform deletes every row a report omits.
    if (kind, subject) in RETIRED:
        continue
    out.append({
        "kind": kind,
        "subject": subject,
        "reason": reason,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "count": count,
        "ever_succeeded": bool(ever.get(key, False)),
    })

print(json.dumps(out, separators=(",", ":")))
PYEOF
}

# patched_agent_health_merge_into_payload <src-json-file> <dst-json-file>
#   Reads the inventory payload at <src-json-file> (written earlier by
#   patched-collect.sh, a separately-scheduled run), adds/overwrites its
#   top-level "agent_health" key from the current store snapshot, and writes
#   the result to <dst-json-file>. Every other top-level key is passed
#   through byte-for-byte unchanged.
#
#   Three outcomes for the agent_health key itself (PAT-1065 review finding
#   A — this is the load-bearing distinction, get it wrong and a local read
#   glitch on the store reads upstream as a false all-clear):
#     - store genuinely has nothing active (including "does not exist yet"):
#       sets {"degraded": []} — the honest, explicit all-clear.
#     - store has active entries: sets {"degraded": [...]} with them.
#     - store EXISTS but could not be read/parsed this attempt
#       (patched_agent_health_emit_degraded_json returned non-zero): the key
#       is OMITTED ENTIRELY from the merged payload. This is not an error
#       for the upload itself — it is the contract's own "no opinion" state
#       (same as an agent that predates this protocol), which the server
#       already treats safely: no upsert, no delete of existing rows. Never
#       fabricate an all-clear from a local uncertainty.
#
#   Returns non-zero (and writes nothing useful to <dst-json-file>) only if
#   <src-json-file> itself cannot be parsed as a JSON object; the caller
#   must treat THAT as "do not upload this attempt". A store read failure
#   alone is NOT a reason to skip the upload — the payload still goes out,
#   just without an opinion on agent_health.
patched_agent_health_merge_into_payload() {
    local _src="$1" _dst="$2"
    local _ah_degraded _ah_emit_rc

    _ah_degraded=$(patched_agent_health_emit_degraded_json 2>/dev/null)
    _ah_emit_rc=$?
    if (( _ah_emit_rc != 0 )); then
        echo "agent-health: store exists but could not be read/parsed — this upload will omit agent_health entirely (no opinion), not claim an all-clear"
        _ah_degraded=""   # sentinel: tells the python below to OMIT the key
    fi

    "$PYTHON3" - "$_src" "$_dst" "$_ah_degraded" <<'PYEOF'
import json, sys

src_path, dst_path, degraded_json = sys.argv[1], sys.argv[2], sys.argv[3]

with open(src_path) as f:
    payload = json.load(f)
if not isinstance(payload, dict):
    raise SystemExit("payload is not a JSON object")

if degraded_json == "":
    # Store read failed this attempt: omit the key entirely rather than
    # fabricate {"degraded": []} — see the function docstring above.
    payload.pop("agent_health", None)
else:
    try:
        degraded = json.loads(degraded_json)
        if not isinstance(degraded, list):
            degraded = []
    except Exception:
        degraded = []
    payload["agent_health"] = {"degraded": degraded}

with open(dst_path, "w") as f:
    json.dump(payload, f, separators=(",", ":"))
PYEOF
}
# <<< PATCHED_AGENT_HEALTH_END

# PAT-1765: credentials_unusable|device_credentials agent-health fault (one fault
# row for the shared credential files; a since-retired poller used to share
# it until PAT-2245). Recorded only when no enrolment token is present: a device
# waiting on patched-enroll.sh is expected to lack credentials and is not
# degraded. Cleared by the next run that finds usable credentials.
# >>> PATCHED_CREDENTIALS_HEALTH_START
_credentials_health_record_failure() {
    local _reason="$1"
    # An enrolment token only explains missing credentials when patched-enroll.sh
    # would actually send it: its first line, whitespace stripped, non-empty.
    # An empty or whitespace-only token file never enrols, so the fault stands.
    local _pending_token=""
    if [[ -f "$CREDS_DIR/enrollment-token" ]]; then
        _pending_token=$(head -1 "$CREDS_DIR/enrollment-token" 2>/dev/null | tr -d '[:space:]')
    fi
    if [[ -n "$_pending_token" ]]; then
        return 0
    fi
    # PAT-1781: patched-enroll.sh moves a token aside only after the server has
    # consumed or rejected it. Keep the fault vocabulary aligned with Windows
    # while the endpoint waits for a fresh token.
    if [[ -f "$CREDS_DIR/enrollment-token.rejected" ]]; then
        _reason="enrolment_token_spent"
    fi
    if typeset -f patched_agent_health_record_failure >/dev/null 2>&1; then
        patched_agent_health_record_failure "credentials_unusable" "device_credentials" "$_reason"
    fi
}

_credentials_health_clear() {
    local _store="${PATCHED_AGENT_HEALTH_STORE:-/Library/Application Support/Patched/.agent-health.json}"
    # Only touch the store when this fault is actually recorded, so a healthy
    # device does not rewrite it on every run.
    grep -qF '"credentials_unusable|device_credentials"' "$_store" 2>/dev/null || return 0
    if typeset -f patched_agent_health_record_success >/dev/null 2>&1; then
        patched_agent_health_record_success "credentials_unusable" "device_credentials"
    fi
}
# <<< PATCHED_CREDENTIALS_HEALTH_END

# ---------------------------------------------------------------------------
# STRUCTURED LOGGING HELPERS (PAT-652)
# Writes JSON-lines to /Library/Logs/Patched/daemon.jsonl alongside the
# existing plain-text log. Tee approach: both destinations receive output.
# Never log bearer_token, hmac_secret, or proxy credentials.
# ---------------------------------------------------------------------------

_init_jsonl_log() {
    install -d -m 755 "$JSONL_LOG_DIR" 2>/dev/null \
        || mkdir -p "$JSONL_LOG_DIR" 2>/dev/null || return 0
    touch "$JSONL_LOG_FILE" 2>/dev/null && chmod 644 "$JSONL_LOG_FILE" 2>/dev/null || true
    # Truncate-and-recreate when file exceeds 10 MiB.
    local _sz; _sz=$(wc -c < "$JSONL_LOG_FILE" 2>/dev/null | tr -d '[:space:]') || _sz=0
    (( _sz > 10485760 )) && : > "$JSONL_LOG_FILE" || true
    # Purge stale jsonl files older than 14 days.
    find "$JSONL_LOG_DIR" -maxdepth 1 -name "$(basename "$JSONL_LOG_FILE")" \
        -mtime "+14" -delete 2>/dev/null || true
}

log_jsonl() {
    # log_jsonl <level> <msg> [<fields-json>]
    # Appends one compact JSON-lines record to JSONL_LOG_FILE. Never fails.
    # Redact /Users/<name>/ → /Users/[REDACTED]/ before passing msg or fields.
    local _lvl="$1" _msg="$2" _fields="${3:-}"
    [[ -n "$_fields" ]] || _fields="{}"
    PATCHED_LOG_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    PATCHED_LOG_LEVEL="$_lvl" \
    PATCHED_LOG_COMPONENT="$JSONL_COMPONENT" \
    PATCHED_LOG_MSG="$_msg" \
    PATCHED_LOG_FIELDS="$_fields" \
    "$PYTHON3" -c '
import json, os, re, sys
_REDACT = [
    (re.compile(r"/Users/[^/\s\"]+/"), "/Users/[REDACTED]/"),
    (re.compile(r"/home/[^/\s\"]+/"), "/home/[REDACTED]/"),
    (re.compile(r"https?://[^:@\s\"]+:[^@\s\"]+@"), "https://[REDACTED]@"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{10,}"), r"\1[REDACTED]"),
]
def _r(s):
    for pat, rep in _REDACT:
        s = pat.sub(rep, s)
    return s
try:
    raw_fields = os.environ.get("PATCHED_LOG_FIELDS") or "{}"
    try:
        fields = json.loads(raw_fields)
    except Exception:
        # Malformed fields JSON must not cost us the whole record.
        fields = {"_raw": raw_fields}
    if isinstance(fields, dict):
        fields = {k: _r(v) if isinstance(v, str) else v for k, v in fields.items()}
    rec = {
        "ts":        os.environ["PATCHED_LOG_TS"],
        "level":     os.environ["PATCHED_LOG_LEVEL"],
        "component": os.environ["PATCHED_LOG_COMPONENT"],
        "msg":       _r(os.environ["PATCHED_LOG_MSG"]),
        "fields":    fields,
    }
    os.makedirs(os.path.dirname(sys.argv[1]), exist_ok=True)
    with open(sys.argv[1], "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
except Exception:
    pass
' "$JSONL_LOG_FILE" 2>/dev/null || true
}

_init_jsonl_log

mkdir -p "$STATE_DIR"
exec >> "$LOG_FILE" 2>&1

# The verified decoded posture is intentionally world-readable: the menu bar
# and Self Service run unprivileged and never hold endpoint credentials. The
# source file comes from mktemp at 0600, so the mode must be changed before the
# atomic rename or every desktop reader is locked out.
# >>> PATCHED_POSTURE_CACHE_COMMIT_START
_posture_commit_verified() {
    local _verified_tmp="$1" _posture_file="$2"
    chmod 0644 "$_verified_tmp" || return 1
    mv -f "$_verified_tmp" "$_posture_file"
}
# <<< PATCHED_POSTURE_CACHE_COMMIT_END

# ---------------------------------------------------------------------------
# LOCK
# ---------------------------------------------------------------------------

LOCK_DIR="$STATE_DIR/.patched-posture-fetch.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    exit 0
fi
trap 'rm -rf "$LOCK_DIR"' EXIT

# ---------------------------------------------------------------------------
# CREDENTIALS
# ---------------------------------------------------------------------------

# >>> PATCHED_CREDS_USABLE_START (keep in sync with endpoint/patched-fetch-config.sh, endpoint/patched-fetch-posture.sh)
# PAT-1760: patched_device_credentials_usable <creds-dir>
#   Returns 0 only when bearer-token has a non-blank first line (the line the
#   request sends) and hmac-secret has non-blank content. A missing, empty or
#   whitespace-only bearer-token would otherwise go out as a bare
#   "Authorization: Bearer" header, and the 401 it draws says nothing about this
#   device's credentials. Checks presence only: neither value is read into a
#   variable or printed.
patched_device_credentials_usable() {
    local _creds_dir="$1"
    head -1 "$_creds_dir/bearer-token" 2>/dev/null | grep -q '[^[:space:]]' || return 1
    grep -q '[^[:space:]]' "$_creds_dir/hmac-secret" 2>/dev/null || return 1
    return 0
}
# <<< PATCHED_CREDS_USABLE_END

# PAT-1765: the same existence check and exit code as patched-fetch-config.sh.
# tenant-id was never checked here, so a device without one sent a signed
# request and then failed verification against an empty tenant; a missing
# bearer-token or hmac-secret exited 0 where fetch-config exits 1.
for cred_file in tenant-id bearer-token hmac-secret; do
    if [[ ! -f "$CREDS_DIR/$cred_file" ]]; then
        echo "ERROR: $CREDS_DIR/$cred_file missing — cannot fetch posture, keeping last-good posture"
        log_jsonl "error" "fetch-posture skipped: credential file missing, no request sent" "{\"credential_file\":\"$cred_file\"}"
        _credentials_health_record_failure "${cred_file//-/_}_missing"
        exit 1
    fi
done

# PAT-1760: an empty or whitespace credential sends nothing.
if ! patched_device_credentials_usable "$CREDS_DIR"; then
    echo "posture: bearer-token or hmac-secret in $CREDS_DIR is empty, so this device has no usable credentials; no request sent, keeping last-good posture"
    log_jsonl "warn" "fetch-posture skipped: device credentials empty, no request sent"
    _credentials_health_record_failure "credentials_empty"
    exit 0
fi
_credentials_health_clear

TENANT_ID=$(head -1 "$CREDS_DIR/tenant-id" | tr -d '[:space:]')
BEARER_TOKEN=$(head -1 "$CREDS_DIR/bearer-token" | tr -d '[:space:]')
HMAC_SECRET_PATH="$CREDS_DIR/hmac-secret"

# ---------------------------------------------------------------------------
# SAFE-CREDENTIAL HELPER (PAT-922; endpoint/ counterpart to macos/'s PAT-881)
# ---------------------------------------------------------------------------
# Kept inline, not sourced from lib/ — tools/build-bundle.sh copies endpoint/
# scripts individually by filename with no lib/ directory, so a sourced
# dependency would fatal on every deployed release build.
#
# WHY: `-H "Authorization: Bearer $TOKEN"` puts the live bearer token on
# argv, readable by any local user via `ps -ww` for the life of the curl
# process. Feed it to curl over stdin instead (`-H @-`) so it never appears
# there.
#
# >>> PATCHED_CREDS_HELPERS_START (keep in sync with macos/patched-upload.sh, macos/patched-bootstrap.sh)
patched_curl_bearer() {
    local _token="$1"; shift
    printf 'Authorization: Bearer %s\n' "$_token" | curl -H @- "$@"
}
# <<< PATCHED_CREDS_HELPERS_END

# PAT-513: device identity header — forward-compatible; server ignores until
# per-device token enforcement is live in the platform.
HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}') || HW_UUID=""

# ---------------------------------------------------------------------------
# HMAC over empty body (GET)
# ---------------------------------------------------------------------------

# PAT-1154: v3 canonical signing binds method+endpoint+timestamp+nonce+body (empty body
# here, GET request) so a captured signed request cannot be replayed. TS and
# NONCE are generated FIRST so the exact same strings go into both the
# signature and the X-Patched-Timestamp / X-Patched-Nonce headers below.
TS=$(date -u +%s)
NONCE=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
SIG=$("$PYTHON3" - "$TS" "$NONCE" "$HMAC_SECRET_PATH" <<'HMACV3PYEOF'
import sys, hmac, hashlib, base64
ts, nonce, secret_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(secret_path) as f: secret = base64.b64decode(f.read().strip())
msg = b"patched-hmac-v3\nGET\nposture\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n"
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
HMACV3PYEOF
)

# ---------------------------------------------------------------------------
# FETCH
# ---------------------------------------------------------------------------

resp_file=$(mktemp "$STATE_DIR/.patched-posture.XXXXXX")

device_hdr=()
[[ -n "$HW_UUID" ]] && device_hdr=(-H "X-Patched-Device-Id: $HW_UUID")

# Using a simplified curl without proxy helper for MVP, adding back if needed
http_code=$(patched_curl_bearer "$BEARER_TOKEN" -s -o "$resp_file" -w "%{http_code}" --max-time 30 \
    -H "X-Patched-Signature: $SIG" \
    -H "X-Patched-Timestamp: $TS" \
    -H "X-Patched-Nonce: $NONCE" \
    "${device_hdr[@]}" \
    -H "Accept: application/json" \
    "$API_URL/v1/posture" 2>/dev/null) || http_code="000"

if [[ "$http_code" == "200" ]]; then
    [[ -x "$VERIFIER" ]]  || { echo "ERROR: verifier missing at $VERIFIER"; rm -f "$resp_file"; exit 1; }
    [[ -x "$VALIDATOR" ]] || { echo "ERROR: validator missing at $VALIDATOR"; rm -f "$resp_file"; exit 1; }

    # Commit order (crash-safe). INVARIANT: the anti-rollback floor is >= the
    # cached posture's issued_at at every instant.
    #   1. Verifier checks signature + tenant binding + anti-rollback, where the
    #      effective floor is max(version-file, cached posture issued_at) — even
    #      a lagging sidecar can never admit anything older than the cache.
    #   2. Validator structurally checks the verified posture (fail-closed) —
    #      a signed-but-malformed payload must never reach the cache.
    #   3. Shell extracts issued_at from the verified temp file and writes +
    #      fsyncs POSTURE_VERSION_FILE FIRST (floor advances to T2).
    #   4. Shell atomically mv's the temp file into place (POSTURE_FILE).
    # If the process dies between 3 and 4, floor=T2 while the cache is still at
    # T1 — which fail-safes: nothing older than T2 can land, and the next fetch
    # of T2 or newer restores the cache (accept-equal semantics). The previous
    # ordering (cache first, floor second) left a window where cache=T2 /
    # floor=T1 let a replayed T1.5 posture overwrite T2 (gate finding, PR #319
    # round 3); step 1's max() also closes that structurally.
    # FAIL CLOSED: a verify or validation failure leaves the last-known-good
    # posture untouched; PATCHED_TENANT_ID binds the signed body to this
    # device's tenant credential.
    out_tmp=$(mktemp "$STATE_DIR/.patched-posture-out.XXXXXX")
    if PATCHED_TENANT_ID="$TENANT_ID" "$PYTHON3" "$VERIFIER" \
            --response-file "$resp_file" \
            --version-file  "$POSTURE_VERSION_FILE" \
            --cache-file    "$POSTURE_FILE" \
            --output-file   "$out_tmp" \
       && "$PYTHON3" "$VALIDATOR" --response-file "$out_tmp"; then
        new_iat=$("$PYTHON3" -c \
            "import json,sys; print(json.load(open(sys.argv[1])).get('issued_at',''))" \
            "$out_tmp" 2>/dev/null) || new_iat=""
        if [[ -n "$new_iat" ]]; then
            # Advance the floor durably (write + fsync, file then directory)
            # BEFORE the cache commit — this is what keeps the invariant.
            if "$PYTHON3" - "$POSTURE_VERSION_FILE" "$new_iat" <<'PYEOF'
import os, sys
version_path, val = sys.argv[1], sys.argv[2]
tmp = version_path + ".tmp"
with open(tmp, "w") as f:
    f.write(val)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, version_path)
dfd = os.open(os.path.dirname(os.path.abspath(version_path)) or ".", os.O_RDONLY)
try:
    os.fsync(dfd)
finally:
    os.close(dfd)
PYEOF
            then
                if _posture_commit_verified "$out_tmp" "$POSTURE_FILE"; then
                    echo "posture: updated and cached ($POSTURE_FILE, issued_at $new_iat)"
                else
                    echo "posture: cache commit failed — keeping last-good posture"
                    rm -f "$out_tmp"
                fi
            else
                echo "posture: version-file write failed — keeping last-good posture"
                rm -f "$out_tmp"
            fi
        else
            # The verifier guarantees a valid issued_at, so failing to extract
            # it here is anomalous. Committing the cache without advancing the
            # floor would recreate the divergence window — fail closed instead.
            echo "posture: could not extract issued_at from verified posture — keeping last-good posture"
            rm -f "$out_tmp"
        fi
    else
        echo "posture: verification or validation failed — keeping last-good posture"
        rm -f "$out_tmp"
    fi
    rm -f "$resp_file"
else
    echo "posture: fetch returned HTTP $http_code — keeping last-good posture"
    rm -f "$resp_file"
fi
