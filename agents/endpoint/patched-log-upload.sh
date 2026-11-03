#!/bin/zsh
##############################################################################
# patched-log-upload.sh — on-demand agent log collection and upload (PAT-287).
#
# Called by patched-fetch-config.sh after each successful config poll
# (200 or 304 Not Modified). On every call it:
#   1. Rotates /var/log/patched-{update,collect,upload}.log if > 10 MiB;
#      purges rotated files older than 14 days.
#   2. Reads the log_request directive from agent-config.json.
#   3. Skips if no directive, device_id is empty (no-op, not tenant-wide —
#      PAT-1033), device_id doesn't match this machine's own platform device
#      id, or the request_id was already fulfilled.
#   4. Collects log lines from the requested components inside the
#      [since, until) window, wraps them in JSON-lines, and redacts
#      sensitive patterns (home paths, proxy creds, bearer tokens).
#   5. Gzips the bundle, honouring max_bytes if set (drops oldest lines).
#   6. POSTs to POST /v1/agent-logs with bearer+HMAC auth.
#   7. On 2xx: records the fulfilled request_id so re-upload is a no-op.
#
# CONVENTIONS (shared with patched-update.sh / patched-fetch-config.sh):
#   - set -u only (not set -euo pipefail).
#   - /usr/bin/python3 hardcoded (sudo strips PATH on macOS).
#   - No zsh reserved var names: path/fpath/cdpath/manpath/infopath.
#   - Empty/absent log_request.device_id is a no-op (PAT-1033): the server's
#     validateAgentConfigReq already rejects any device_id that isn't a real
#     UUID targeting one specific device, so an empty device_id can never be
#     a legitimate directive — there is no tenant-wide log-collection mode.
#   - Non-empty device_id is matched against this agent's own platform device
#     id (devices.id / tenant_credentials.device_id) — resolved from the
#     signed agent-config payload, falling back to the id persisted at enrol
#     time. This is NOT the local hardware UUID (IOPlatformUUID): that is a
#     different identifier space than the one the server targets directives
#     with, which is why the comparison previously never matched (PAT-1026).
##############################################################################

set -u

# PAT-2394: root command lookup must never include Homebrew, inherited PATH
# or a test override. Runtime failure is fatal before logging or state writes.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON3="/usr/bin/python3"
[[ -x "$PYTHON3" ]] && "$PYTHON3" -I -c 'pass' >/dev/null 2>&1 || { printf '%s\n' "FATAL: trusted /usr/bin/python3 runtime unavailable or unusable; no work performed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# CONFIG (all overridable via env for testing)
# ---------------------------------------------------------------------------

BUNDLE_DIR="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}"
STATE_DIR="${PATCHED_STATE_DIR:-/Library/Application Support/Patched}"
CREDS_DIR="${PATCHED_CREDS_DIR:-/etc/patched}"
API_URL="${PATCHED_API_URL:-https://api.patched.im}"

AGENT_CONFIG_FILE="${PATCHED_AGENT_CONFIG_FILE:-$STATE_DIR/agent-config.json}"
FULFILLED_FILE="$STATE_DIR/log-upload-fulfilled-request-id"
PROXY_RESOLVE="$BUNDLE_DIR/patched-proxy-resolve.py"

LOG_FILE_UPDATER="${PATCHED_LOG_UPDATER:-/var/log/patched-update.log}"
LOG_FILE_COLLECTOR="${PATCHED_LOG_COLLECTOR:-/var/log/patched-collect.log}"
LOG_FILE_UPLOAD_LOG="${PATCHED_LOG_UPLOAD_LOG:-/var/log/patched-upload.log}"

# PAT-652: structured JSON-lines log files (primary; legacy files are fallback).
JSONL_LOG_DIR="${PATCHED_JSONL_LOG_DIR:-/Library/Logs/Patched}"
JSONL_LOG_DAEMON="${PATCHED_JSONL_DAEMON:-$JSONL_LOG_DIR/daemon.jsonl}"
JSONL_LOG_COLLECT="${PATCHED_JSONL_COLLECT:-$JSONL_LOG_DIR/collect.jsonl}"
JSONL_LOG_UPDATE="${PATCHED_JSONL_UPDATE:-$JSONL_LOG_DIR/update.jsonl}"

LOG_ROTATE_MAX_BYTES=10485760  # 10 MiB
LOG_ROTATE_MAX_AGE_DAYS=14

# >>> PATCHED_AGENT_CONFIG_TENANT_SCOPE_START
# PAT-1773: agent-config.json is not keyed by tenant. After re-enrolment into
# another tenant it still holds the old tenant's verified config until the new
# tenant's first accepted config. agent_config_tenant_scope runs once per run,
# after the config refresh, and asks agent_config_tenant.py (manifest-covered)
# whether the cached config belongs to the enrolled tenant. Every reader tests
# agent_config_present instead of the file, so a config that does not belong
# to the enrolled tenant takes that reader's existing no-config default. The
# block is identical in every endpoint script that reads the cached config;
# endpoint/test-agent-config-tenant-scope.zsh checks that.
AGENT_CONFIG_TENANT_MODULE="$BUNDLE_DIR/agent_config_tenant.py"
AGENT_CONFIG_FOR_TENANT=0

agent_config_tenant_scope() {
    AGENT_CONFIG_FOR_TENANT=0
    local _tenant_state=""
    if [[ -f "$AGENT_CONFIG_TENANT_MODULE" && ! -L "$AGENT_CONFIG_TENANT_MODULE" ]]; then
        _tenant_state=$("$PYTHON3" "$AGENT_CONFIG_TENANT_MODULE" cached-state \
            "$AGENT_CONFIG_FILE" "$CREDS_DIR/tenant-id" 2>/dev/null) || _tenant_state=""
    fi
    case "$_tenant_state" in
        applies) AGENT_CONFIG_FOR_TENANT=1 ;;
        absent) ;;
        # PAT-1814: no enrolled tenant yet (pre-enrolment, or the tenant-id
        # credential is missing/blank) is a normal, expected state, not a
        # check failure — say so distinctly instead of the generic
        # "does not belong to the enrolled tenant" wording below, which
        # implies a real tenant mismatch or a read failure.
        no_enrolled_tenant) echo "agent-config: cached config at $AGENT_CONFIG_FILE is not used this run: no enrolled tenant is configured yet; every reader applies its no-config default" ;;
        *) echo "agent-config: cached config at $AGENT_CONFIG_FILE is not used this run: it does not belong to the enrolled tenant (${_tenant_state:-tenant check unavailable}); every reader applies its no-config default" ;;
    esac
    return 0
}

# agent_config_present: true only for a cached config agent_config_tenant_scope
# found to belong to the enrolled tenant, and only while the file exists.
agent_config_present() {
    (( AGENT_CONFIG_FOR_TENANT )) && [[ -f "$AGENT_CONFIG_FILE" ]]
}
# <<< PATCHED_AGENT_CONFIG_TENANT_SCOPE_END

# >>> PATCHED_AGENT_HEALTH_START (keep in sync with the identically-named
# block in macos/lib/agent_health.sh and the copy inlined in
# endpoint/patched-fetch-posture.sh — endpoint/ has no lib/ convention:
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

mkdir -p "$STATE_DIR"

echo "=== patched-log-upload $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# ---------------------------------------------------------------------------
# 1. ROTATE LOG FILES
#
# Copytruncate style: cp → .1/.2, then : > original to truncate in place.
# This preserves the inode so any process with the log file open (tee -a)
# keeps writing to the same fd without interruption.
# ---------------------------------------------------------------------------

rotate_log_file() {
    local logfile="$1"
    [[ -f "$logfile" ]] || return 0
    local size
    size=$(wc -c < "$logfile" 2>/dev/null | tr -d '[:space:]') || return 0
    if (( size > LOG_ROTATE_MAX_BYTES )); then
        [[ -f "${logfile}.2" ]] && rm -f "${logfile}.2"
        [[ -f "${logfile}.1" ]] && mv -f "${logfile}.1" "${logfile}.2"
        cp "${logfile}" "${logfile}.1"
        : > "${logfile}"
        echo "=== log rotated $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "${logfile}"
        echo "  log-upload: rotated ${logfile} (was ${size} bytes)"
    fi
    # Purge rotated files older than the retention window.
    find "$(dirname "$logfile")" -maxdepth 1 \
        -name "$(basename "$logfile").*" \
        -mtime "+${LOG_ROTATE_MAX_AGE_DAYS}" -delete 2>/dev/null || true
}

rotate_log_file "$LOG_FILE_UPDATER"
rotate_log_file "$LOG_FILE_COLLECTOR"
rotate_log_file "$LOG_FILE_UPLOAD_LOG"

# PAT-652: rotate JSONL files using truncate-and-recreate (not copytruncate);
# purge stale JSONL files older than the retention window.
rotate_jsonl_file() {
    local logfile="$1"
    [[ -f "$logfile" ]] || return 0
    local size
    size=$(wc -c < "$logfile" 2>/dev/null | tr -d '[:space:]') || return 0
    if (( size > LOG_ROTATE_MAX_BYTES )); then
        : > "$logfile"
        echo "  log-upload: truncated $logfile (was ${size} bytes)"
    fi
    find "$(dirname "$logfile")" -maxdepth 1 \
        -name "$(basename "$logfile")" \
        -mtime "+${LOG_ROTATE_MAX_AGE_DAYS}" -delete 2>/dev/null || true
}

rotate_jsonl_file "$JSONL_LOG_DAEMON"
rotate_jsonl_file "$JSONL_LOG_COLLECT"
rotate_jsonl_file "$JSONL_LOG_UPDATE"

# ---------------------------------------------------------------------------
# 2. READ log_request DIRECTIVE
# ---------------------------------------------------------------------------

# PAT-1773: a log_request in another tenant's cached config is not this
# tenant's directive.
agent_config_tenant_scope
agent_config_present || { echo "log-upload: no agent config for the enrolled tenant — skipping"; exit 0; }

log_req=$("$PYTHON3" - "$AGENT_CONFIG_FILE" <<'PYEOF'
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
    lr = cfg.get("log_request")
    if not lr or not isinstance(lr, dict):
        sys.exit(0)
    req_id = lr.get("request_id", "").strip()
    dev_id = lr.get("device_id", "").strip()
    since  = lr.get("since", "").strip()
    until  = lr.get("until", "").strip()
    comps  = ",".join(c for c in lr.get("components", []) if isinstance(c, str))
    max_b  = str(int(lr.get("max_bytes", 0)))
    # This agent's own platform device id, as injected by the server into the
    # signed config (PAT-1026) — top-level "device_id", not the directive's.
    cfg_device_id = cfg.get("device_id", "")
    if not isinstance(cfg_device_id, str):
        cfg_device_id = ""
    cfg_device_id = cfg_device_id.strip()
    # Pipe-separated, not tab-separated: IFS=$'\t' collapses consecutive tabs
    # (tab is POSIX whitespace), so empty fields would be swallowed.
    print(f"{req_id}|{dev_id}|{since}|{until}|{comps}|{max_b}|{cfg_device_id}")
except Exception as e:
    sys.stderr.write(f"log-upload: parse error: {e}\n")
    sys.exit(0)
PYEOF
) || { echo "log-upload: could not parse agent config"; exit 0; }

[[ -z "$log_req" ]] && { echo "log-upload: no log_request directive"; exit 0; }

IFS='|' read -r LOG_REQUEST_ID LOG_DEVICE_ID LOG_SINCE LOG_UNTIL LOG_COMPONENTS LOG_MAX_BYTES CONFIG_DEVICE_ID \
    <<< "$log_req"

[[ -z "$LOG_REQUEST_ID" ]] && { echo "log-upload: log_request missing request_id — skipping"; exit 0; }

# ---------------------------------------------------------------------------
# 3. DEVICE MATCH
#
# Resolves this agent's own platform device id — the same identifier space as
# devices.id / tenant_credentials.device_id (what the server targets a
# directive with), NOT any OS-level hardware identifier such as the macOS
# IOPlatformUUID. Precedence:
#   1. the "device_id" field of the verified agent-config payload (PAT-1026;
#      this is what reaches an already-enrolled endpoint as soon as the
#      server starts injecting it, no re-enrolment needed);
#   2. $CREDS_DIR/device-id, persisted once at enrol time by patched-enroll.sh.
#
# Empty/absent directive device_id is a no-op, not tenant-wide (PAT-1033).
# The server's validateAgentConfigReq already requires device_id to be a real
# UUID targeting one specific device before it will ever sign a config —
# there is no server-side path that produces an empty device_id as a genuine
# directive today. Treating empty as "collect for everyone" would only ever
# be reachable via something bypassing that validator (a future internal
# caller, a direct DB write), so the fail-closed reading is "do not act" —
# the same posture PAT-1026 established for an agent that cannot resolve its
# OWN device id.
#
# If neither source resolves a local platform device id (for a non-empty,
# targeted directive), this agent does not know its own identity. That is a
# distinct condition from "the directive is not for me" and must be logged
# and handled as such — skip either way, but never report an unknown
# identity as a mismatch. The cross-device guard below (an actual mismatch)
# still rejects a directive aimed at a different device.
# ---------------------------------------------------------------------------

LOCAL_DEVICE_ID="$CONFIG_DEVICE_ID"
if [[ -z "$LOCAL_DEVICE_ID" && -f "$CREDS_DIR/device-id" ]]; then
    LOCAL_DEVICE_ID=$(head -1 "$CREDS_DIR/device-id" | tr -d '[:space:]')
fi

if [[ -z "$LOG_DEVICE_ID" ]]; then
    echo "log-upload: directive device_id is empty — the server never issues an empty device_id as a real directive (validateAgentConfigReq requires a UUID targeting one device), so this is not a legitimate tenant-wide request; treating as no-op — skipping (request_id=${LOG_REQUEST_ID})"
    patched_agent_health_record_failure "directive_skipped" "log_upload" "device_id_empty"
    exit 0
fi

if [[ -z "$LOCAL_DEVICE_ID" ]]; then
    echo "log-upload: local platform device id unknown — cannot evaluate directive (request_id=${LOG_REQUEST_ID}) — skipping"
    exit 0
fi
if [[ "$LOCAL_DEVICE_ID" != "$LOG_DEVICE_ID" ]]; then
    echo "log-upload: directive device_id=${LOG_DEVICE_ID} does not match local device_id=${LOCAL_DEVICE_ID} — skipping"
    # PAT-1065: surface this as an agent_health degraded fault (server-side
    # PAT-1064) instead of only ever landing in a local log line nobody
    # reads — this exact mismatch ran silently for weeks in production.
    patched_agent_health_record_failure "directive_skipped" "log_upload" "device_id_mismatch"
    exit 0
fi

# ---------------------------------------------------------------------------
# 4. IDEMPOTENCY CHECK
# ---------------------------------------------------------------------------

if [[ -f "$FULFILLED_FILE" ]]; then
    fulfilled=$(head -1 "$FULFILLED_FILE" | tr -d '[:space:]')
    if [[ "$fulfilled" == "$LOG_REQUEST_ID" ]]; then
        echo "log-upload: request_id=${LOG_REQUEST_ID} already fulfilled — skipping"
        exit 0
    fi
fi

echo "log-upload: processing request_id=${LOG_REQUEST_ID} components=${LOG_COMPONENTS}"

# ---------------------------------------------------------------------------
# 5. LOAD CREDENTIALS
# ---------------------------------------------------------------------------

for cred_file in bearer-token hmac-secret; do
    if [[ ! -f "$CREDS_DIR/$cred_file" ]]; then
        echo "log-upload: $CREDS_DIR/$cred_file missing — cannot upload"
        exit 1
    fi
done
BEARER_TOKEN=$(head -1 "$CREDS_DIR/bearer-token" | tr -d '[:space:]')

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

# ---------------------------------------------------------------------------
# HMAC HELPER
# ---------------------------------------------------------------------------

# PAT-1154: v3 canonical signing binds method+endpoint+timestamp+nonce+body so a captured
# signed request cannot be replayed. Signing input is:
#   b"patched-hmac-v3\nPOST\n" + endpoint_id + b"\n" + ts + b"\n" + nonce + b"\n" + body
# ts and nonce MUST be the exact strings sent in the X-Patched-Timestamp /
# X-Patched-Nonce headers for this same request — callers generate ts+nonce
# FIRST, then pass them into compute_hmac AND into the headers.
compute_hmac() {  # compute_hmac <body-file> <endpoint-id> <ts> <nonce>
    "$PYTHON3" - "$1" "$2" "$3" "$4" "$CREDS_DIR/hmac-secret" <<'PYEOF'
import sys, hmac, hashlib, base64
body_path, endpoint_id, ts, nonce, secret_path = sys.argv[1:]
with open(secret_path) as f: secret = base64.b64decode(f.read().strip())
with open(body_path, 'rb') as f: body = f.read()
msg = b"patched-hmac-v3\nPOST\n" + endpoint_id.encode('ascii') + b"\n" + ts.encode('ascii') + b"\n" + nonce.encode('ascii') + b"\n" + body
print(hmac.new(secret, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

# ---------------------------------------------------------------------------
# PROXY HELPER (mirrors patched-fetch-config.sh exactly)
# ---------------------------------------------------------------------------

with_proxy() {
    local _target="$1"; shift
    local _json _parsed _pmode _purl _durl _noproxy _pwarn

    if [[ -x "${PROXY_RESOLVE:-}" ]]; then
        _json=$("$PYTHON3" "$PROXY_RESOLVE" "$_target" "${AGENT_CONFIG_FILE:-}" 2>/dev/null) \
            || _json='{"mode":"direct"}'
        _parsed=$(printf '%s' "$_json" | "$PYTHON3" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
fields = [d.get("mode", "direct"), d.get("url", ""), d.get("display_url", ""),
          d.get("no_proxy", ""), d.get("warning", "")]
sys.stdout.write("\t".join(f if isinstance(f, str) else str(f) for f in fields))
' 2>/dev/null)
        IFS=$'\t' read -r _pmode _purl _durl _noproxy _pwarn <<< "$_parsed"
    fi

    _pmode="${_pmode:-direct}"
    _purl="${_purl:-}"
    _durl="${_durl:-$_purl}"
    _noproxy="${_noproxy:-}"
    _pwarn="${_pwarn:-}"

    [[ -n "$_pwarn" ]] && echo "  proxy: warning: $_pwarn" >&2

    if [[ "$_pmode" == "proxy" && -n "$_purl" ]]; then
        echo "  proxy: $_durl" >&2
        HTTP_PROXY="$_purl" HTTPS_PROXY="$_purl" ALL_PROXY="$_purl" NO_PROXY="$_noproxy" \
        http_proxy="$_purl" https_proxy="$_purl" all_proxy="$_purl" no_proxy="$_noproxy" \
        "$@"
    else
        HTTP_PROXY="" HTTPS_PROXY="" ALL_PROXY="" NO_PROXY="" \
        http_proxy="" https_proxy="" all_proxy="" no_proxy="" \
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# 6. COLLECT, WINDOW, REDACT, WRAP
#
# Reads the log files for each requested component plus their rotated copies
# (.1, .2). Lines are grouped into run-blocks anchored on timestamp headers
# (=== ... YYYY-MM-DDTHH:MM:SSZ ===). A run-block is included when its start
# timestamp falls in [since, until). Lines before the first header are skipped
# when a time window is set. Each included line is wrapped in a JSON-lines
# record and redacted.
#
# Redaction rules (applied per-line):
#   /Users/<name>/  →  /Users/REDACTED_USER/
#   /home/<name>/   →  /home/REDACTED_USER/
#   URLs with embedded credentials  →  scheme://REDACTED@host
#   Bearer <token>  →  Bearer REDACTED
# ---------------------------------------------------------------------------

bundle_file=$(mktemp /tmp/.patched-logbundle.XXXXXX)

# PAT-652: pass JSONL paths (argv 4-6) alongside legacy paths (argv 1-3).
# The Python block tries jsonl first for "daemon"/"collect"/"update" components;
# falls back to legacy plain-text when the jsonl file does not yet exist.
"$PYTHON3" - \
    "$LOG_FILE_UPDATER" \
    "$LOG_FILE_COLLECTOR" \
    "$LOG_FILE_UPLOAD_LOG" \
    "$JSONL_LOG_DAEMON" \
    "$JSONL_LOG_COLLECT" \
    "$JSONL_LOG_UPDATE" \
    "$LOG_COMPONENTS" \
    "${LOG_SINCE:-}" \
    "${LOG_UNTIL:-}" \
    "$bundle_file" \
    <<'PYEOF'
import sys, re, json, os
from datetime import datetime, timezone

# Legacy plain-text log paths (backward compat for pre-PAT-652 agents in field).
LEGACY_PATHS = {
    "updater":   sys.argv[1],
    "collector": sys.argv[2],
    "upload":    sys.argv[3],
}
# New JSONL paths (PAT-652); fallback to legacy plain-text when file absent.
JSONL_PATHS = {
    "daemon":  sys.argv[4],
    "collect": sys.argv[5],
    "update":  sys.argv[6],
}
# When a new-style component is requested but no jsonl file exists yet, fall
# back to the corresponding legacy plain-text file so agents in the field that
# have not yet emitted jsonl logs still upload their existing plain-text data.
JSONL_LEGACY_FALLBACK = {
    "daemon":  sys.argv[1],   # /var/log/patched-update.log
    "collect": sys.argv[2],   # /var/log/patched-collect.log
    "update":  sys.argv[1],   # /var/log/patched-update.log
}
components = [c.strip() for c in sys.argv[7].split(",") if c.strip()]
since_str  = sys.argv[8]
until_str  = sys.argv[9]
out_path   = sys.argv[10]

def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc)
    except Exception:
        return None

since = parse_ts(since_str)
until = parse_ts(until_str)

TS_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')

REDACT = [
    (re.compile(r'/Users/[^/\s"\']+/'),              '/Users/[REDACTED]/'),
    (re.compile(r'/home/[^/\s"\']+/'),               '/home/[REDACTED]/'),
    (re.compile(r'https?://[^:@\s"\']+:[^@\s"\']+@'), 'https://[REDACTED]@'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9._\-]{10,}'),  r'\1[REDACTED]'),
]

def redact(line):
    for pat, rep in REDACT:
        line = pat.sub(rep, line)
    return line

def read_plain_text(log_file, comp, records):
    """Read a plain-text log using run-block timestamp anchoring."""
    for candidate in (log_file, log_file + ".1", log_file + ".2"):
        try:
            with open(candidate, "r", errors="replace") as fh:
                run_ts = None
                for raw in fh:
                    line = raw.rstrip("\n").rstrip("\r")
                    m = TS_RE.search(line)
                    if m:
                        t = parse_ts(m.group(0))
                        if t:
                            run_ts = t
                    if run_ts is None and (since or until):
                        continue
                    if since and run_ts and run_ts < since:
                        continue
                    if until and run_ts and run_ts >= until:
                        continue
                    ts_str = (run_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                              if run_ts else "unknown")
                    records.append(json.dumps({
                        "ts":        ts_str,
                        "component": comp,
                        "msg":       redact(line),
                    }))
        except FileNotFoundError:
            continue
        except Exception as e:
            records.append(json.dumps({
                "ts":        "unknown",
                "component": comp,
                "msg":       f"[log-collect error: {e}]",
            }))

def read_jsonl(log_file, comp, records):
    """Read a PAT-652 JSON-lines log; filter by time window and redact."""
    for candidate in (log_file, log_file + ".1", log_file + ".2"):
        try:
            with open(candidate, "r", errors="replace") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                    except Exception:
                        continue
                    line_ts = parse_ts(obj.get("ts", ""))
                    if since and line_ts and line_ts < since:
                        continue
                    if until and line_ts and line_ts >= until:
                        continue
                    # Redact msg and any string values in fields.
                    obj["msg"] = redact(obj.get("msg", ""))
                    if isinstance(obj.get("fields"), dict):
                        obj["fields"] = {
                            k: redact(v) if isinstance(v, str) else v
                            for k, v in obj["fields"].items()
                        }
                    records.append(json.dumps(obj, separators=(",", ":")))
        except FileNotFoundError:
            continue
        except Exception as e:
            records.append(json.dumps({
                "ts":        "unknown",
                "level":     "error",
                "component": comp,
                "msg":       f"[log-collect error: {e}]",
                "fields":    {},
            }))

if not components:
    # Default "all": the three structured components (each falls back to its
    # legacy plain-text file when the jsonl is absent) plus the upload log,
    # which has no jsonl equivalent. Listing legacy aliases here too would
    # read the same underlying files twice.
    components = list(JSONL_PATHS.keys()) + ["upload"]

records = []
seen_files = set()

def _claim(path):
    """One read per underlying file even when component aliases overlap
    (e.g. 'daemon' and 'update' both fall back to patched-update.log)."""
    key = os.path.realpath(path)
    if key in seen_files:
        return False
    seen_files.add(key)
    return True

for comp in components:
    if comp in JSONL_PATHS:
        # New-style component: try jsonl file first; fall back to legacy plain-text.
        jpath = JSONL_PATHS[comp]
        if os.path.exists(jpath):
            if _claim(jpath):
                read_jsonl(jpath, comp, records)
        else:
            # jsonl not yet present — fall back to legacy file for this component.
            fallback = JSONL_LEGACY_FALLBACK.get(comp)
            if fallback and _claim(fallback):
                read_plain_text(fallback, comp, records)
    elif comp in LEGACY_PATHS:
        if _claim(LEGACY_PATHS[comp]):
            read_plain_text(LEGACY_PATHS[comp], comp, records)
    # Unknown component names are silently skipped.

with open(out_path, "w") as fh:
    fh.write("\n".join(records))
    if records:
        fh.write("\n")
PYEOF

line_count=$(wc -l < "$bundle_file" | tr -d '[:space:]')
if [[ "$line_count" -eq 0 ]]; then
    echo "log-upload: no log lines collected for window — skipping upload"
    rm -f "$bundle_file"
    exit 0
fi

echo "log-upload: collected ${line_count} lines"

# ---------------------------------------------------------------------------
# 7. GZIP BUNDLE
# ---------------------------------------------------------------------------

# PAT-1079: template ends in X's. macOS/BSD mktemp only substitutes a TRAILING
# X run, so ".patched-logbundle.XXXXXX.gz" was not a template at all — mktemp
# returned that literal, permanently predictable path in world-writable /tmp.
# Any local user could pre-create it and permanently deny log upload (mktemp
# then fails "File exists" on every subsequent run), and any run that died
# between here and the cleanup at the end of this script left the same stale
# path behind with the same effect. The .gz extension was cosmetic: the file
# is HMAC'd and POSTed by path as application/octet-stream, and nothing globs
# or type-sniffs it. Renamed to -gz- so it stays distinguishable in ps/logs
# from $bundle_file, which uses the .patched-logbundle.XXXXXX prefix.
gz_file=$(mktemp /tmp/.patched-logbundle-gz.XXXXXX)

# Refuse to write through a symlink. mktemp created this file with
# O_CREAT|O_EXCL, which refuses any pre-existing entry (a planted symlink
# included, dangling or not), and the name is now genuinely random, so there
# is nothing predictable left to pre-plant. What this covers is the narrower
# case: the entry being unlinked and replaced with a symlink in the window
# between mktemp's create and the separate, later truncate-redirect below.
# Check-then-use is two syscalls and is not atomic — this narrows the race,
# it does not eliminate it, and is disclosed as such rather than overclaimed.
# /tmp is drwxrwxrwt: world-writable, but the sticky bit already stops a
# non-root user unlinking this root-owned file, so the swap is not reachable
# in practice today. This guards the pattern.
if [[ -L "$gz_file" ]]; then
    echo "log-upload: REFUSING to write bundle through symlinked temp path $gz_file — aborting upload"
    rm -f "$gz_file" "$bundle_file"
    # PAT-1079: the sole caller (endpoint/patched-fetch-config.sh) invokes this
    # script as `"$log_upload_script" || true`, so this exit status is thrown
    # away: nothing marks the directive fulfilled, it silently re-fires on
    # every config poll forever, and no signal leaves the box. That is exactly
    # the invisible-fail-safe shape PAT-1064/1065 exist to close, so record it
    # as a degraded fault under the same (kind, subject) pair PAT-1065 already
    # uses for the device_id_mismatch skip.
    patched_agent_health_record_failure "directive_skipped" "log_upload" "symlink_refused_bundle_gz"
    exit 1
fi

gzip -c "$bundle_file" > "$gz_file"
rm -f "$bundle_file"

# Honour max_bytes cap: if the compressed bundle exceeds the limit, drop the
# oldest lines (from the head) until it fits. A single trim pass to 75% is
# sufficient for typical log volumes; the directive max_bytes is advisory.
if [[ -n "$LOG_MAX_BYTES" && "$LOG_MAX_BYTES" -gt 0 ]]; then
    gz_size=$(wc -c < "$gz_file" | tr -d '[:space:]')
    if (( gz_size > LOG_MAX_BYTES )); then
        echo "log-upload: bundle ${gz_size}B > max_bytes ${LOG_MAX_BYTES}B — trimming oldest lines"
        trim_file=$(mktemp /tmp/.patched-logbundle-trim.XXXXXX)
        gzip -dc "$gz_file" > "$trim_file"
        total=$(wc -l < "$trim_file" | tr -d '[:space:]')
        keep=$(( total * 3 / 4 ))
        # PAT-1079: "${trim_file}.kept" is a DIFFERENT path from $trim_file. It
        # is built by string concatenation from $trim_file's name, so mktemp
        # never created it, and it therefore has none of the protection
        # $trim_file has: no O_CREAT|O_EXCL, and no unpredictability beyond the
        # six random characters an attacker can simply read off the $trim_file
        # entry that mktemp just published in /tmp.
        #
        # That makes this the one genuinely live hole among the checks in this
        # file rather than a pattern guard. A local unprivileged user polling
        # /tmp sees .patched-logbundle-trim.<rand> appear, and during the
        # `gzip -dc` above (long enough to matter for a real bundle) creates
        # <that exact name>.kept as a symlink to any file on the box. The
        # redirect below then follows it and truncates the target as root. The
        # sticky bit is no defence: the attacker creates a brand-new directory
        # entry they own, they do not unlink or rename anything of root's.
        #
        # Check-then-use is still two syscalls and still not atomic, so this
        # narrows rather than closes the window — but it turns a reliably
        # winnable race into a microsecond one, which is the same bar the other
        # refusals in this file are held to.
        if [[ -L "${trim_file}.kept" ]]; then
            echo "log-upload: REFUSING to write trimmed lines through symlinked temp path ${trim_file}.kept — aborting upload"
            # rm -f on a symlink unlinks the link itself, never the target, so
            # this removes the planted entry without touching the victim.
            rm -f "$gz_file" "$trim_file" "${trim_file}.kept"
            patched_agent_health_record_failure "directive_skipped" "log_upload" "symlink_refused_trim_kept"
            exit 1
        fi
        tail -n "$keep" "$trim_file" > "${trim_file}.kept"
        # PAT-1079: a later open() of $gz_file by path, with a wider window
        # than the first check up at the gzip step (gzip -dc, tail and a second
        # gzip run in between), so it gets its own symlink refusal. Note this
        # covers $gz_file only — the sibling check above is what covers the
        # "${trim_file}.kept" write.
        #
        # It aborts rather than degrading to "upload the untrimmed bundle":
        # if $gz_file is a symlink here then the bytes behind it are not the
        # bytes this run wrote, and the steps below HMAC and POST that path.
        # Carrying on would upload whatever the link points at, turning a
        # write-through into a read-through — worse than not uploading.
        if [[ -L "$gz_file" ]]; then
            echo "log-upload: REFUSING to rewrite trimmed bundle through symlinked temp path $gz_file — aborting upload"
            rm -f "$gz_file" "$trim_file" "${trim_file}.kept"
            patched_agent_health_record_failure "directive_skipped" "log_upload" "symlink_refused_trim_gz"
            exit 1
        fi
        gzip -c "${trim_file}.kept" > "$gz_file"
        rm -f "$trim_file" "${trim_file}.kept"
        new_size=$(wc -c < "$gz_file" | tr -d '[:space:]')
        echo "log-upload: trimmed to ${new_size}B (kept newest ${keep} of ${total} lines)"
    fi
fi

# ---------------------------------------------------------------------------
# 8. POST /v1/agent-logs
# ---------------------------------------------------------------------------

ts=$(date -u +%s)
nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
sig=$(compute_hmac "$gz_file" "agent_logs" "$ts" "$nonce")
resp_file=$(mktemp /tmp/.patched-logresp.XXXXXX)

http_code=$(with_proxy "$API_URL" \
    patched_curl_bearer "$BEARER_TOKEN" -s -o "$resp_file" -w "%{http_code}" --max-time 60 \
    -X POST "$API_URL/v1/agent-logs" \
    -H "X-Patched-Signature: $sig" \
    -H "X-Patched-Timestamp: $ts" \
    -H "X-Patched-Nonce: $nonce" \
    -H "X-Patched-Log-Request-ID: $LOG_REQUEST_ID" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$gz_file" 2>/dev/null) || http_code="000"

rm -f "$gz_file" "$resp_file"

if [[ "$http_code" == 2* ]]; then
    echo "log-upload: POST /v1/agent-logs -> ${http_code} (request_id=${LOG_REQUEST_ID})"
    printf '%s' "$LOG_REQUEST_ID" > "$FULFILLED_FILE"
    echo "log-upload: request_id recorded as fulfilled"
    # PAT-1065: a directive that reaches here has genuinely been actioned —
    # device_id matched and the upload succeeded — so this is the success
    # counterpart to the device_id_mismatch fault above.
    patched_agent_health_record_success "directive_skipped" "log_upload"
else
    echo "log-upload: POST /v1/agent-logs -> ${http_code:-network-error} — will retry on next config poll"
fi

exit 0
