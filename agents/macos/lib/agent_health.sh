# agent_health.sh — degraded-capability reporting store (PAT-1065, macOS half
# of PAT-1064's server-side agent_health channel; Windows parity is PAT-1066).
#
# Sourced by patched-upload.sh; not executable directly.
#
# Requires (set by caller before sourcing):
#   PYTHON3 — absolute path to python3 (/usr/bin/python3)
#
# WHY THIS FILE EXISTS: endpoint/patched-log-upload.sh and the (since
# retired, PAT-2245) signed-feed poller each logged and continued when they
# hit a fault they could not act on (a log-upload directive for a device_id
# that doesn't match, a feed that had never successfully synced) — three such
# faults ran silently on a real endpoint for weeks (1,119 / 1,105 / every-run
# occurrences) while the device reported itself completely healthy. This
# store is the one thing both the endpoint/ update-daemon family (its own,
# separate STATE_DIR) and this macOS inventory collector/uploader (a
# genuinely different, separately-uninstallable daemon, STATE_DIR
# /var/db/patched) can both reach, so patched-upload.sh — the only one of
# the two families that ever POSTs /v1/inventory — can report every fault
# either side recorded.
#
# STORE PATH: deliberately a single hardcoded, shared path — NOT derived
# from either daemon's own $STATE_DIR (they differ: endpoint/'s is
# /Library/Application Support/Patched, this collector's own is
# /var/db/patched) — so both families reference the exact same file
# regardless of which one's STATE_DIR convention happens to be in scope.
# /Library/Application Support/Patched is chosen (over /var/db/patched)
# because it is already the more central of the two: endpoint/ owns it as
# its primary STATE_DIR, AND this uploader already reads agent-config.json
# from that exact path today (see AC_CONFIG_FILE in patched-upload.sh) — so
# cross-daemon reads/writes against that directory are an established pattern,
# not a new one.
# Overridable via PATCHED_AGENT_HEALTH_STORE for tests; production always
# uses the hardcoded default.
#
# STORE SHAPE — see the "two-part design" note below for why `active` and
# `ever_succeeded` are separate top-level maps, not one:
#   {
#     "active": {
#       "<kind>|<subject>": {
#         "kind": "...", "subject": "...", "reason": "...",
#         "first_seen": "<RFC3339>", "last_seen": "<RFC3339>", "count": N
#       }, ...
#     },
#     "ever_succeeded": { "<kind>|<subject>": true, ... }
#   }
#
# TWO-PART DESIGN (the property PAT-1064/PAT-1029 call "the single most
# useful bit in all three faults"): `ever_succeeded` must survive a fault
# being resolved and later recurring. A design that deletes a (kind,subject)
# entry entirely on success and recreates it from scratch on the next
# failure would report ever_succeeded=false on that later recurrence, even
# though it plainly did work in between. So `active` (what patched-upload.sh
# emits — cleared on success) and `ever_succeeded` (a durable ledger,
# survives `active` clearing that same key, never auto-cleared) are separate
# maps: patched_agent_health_record_success clears the former and sets the
# latter to true; patched_agent_health_record_failure looks the durable
# ledger up (defaulting false) rather than trusting the active entry's own
# absence as "never".
#
# CONCURRENCY: patched-log-upload.sh, patched-fetch-posture.sh (both
# endpoint/), and this collector's own capability-missing checks can all call
# into this store from different processes around the same time. A
# mkdir-based lock guards every read-modify-write, with PID-liveness
# staleness detection (a bounded single reclaim) so a holder killed between
# acquiring the lock and releasing it cannot wedge every future call shut
# forever — mirrors the endpoint fetchers' LOCK_DIR skip-not-block
# convention and the staleness hardening PAT-1037 added to
# browser_extension_removal.sh's own mkdir lock, at a scale proportionate to
# a single small JSON read-modify-write-rename rather than PAT-1037's larger
# accumulated-batch problem. Lock contention is skip-not-block: a failure to
# record this call is not fatal, the next invocation will record it.
#
# UNINSTALL: endpoint/uninstall.sh and macos/uninstall.sh both remove this
# store (see those scripts). A fresh install has no legitimate basis to
# claim ever_succeeded=true for a capability it has not, as a fresh install,
# actually verified working — and a stale `active` entry surviving a
# reinstall could misreport a fault that may no longer even apply.
#
# >>> PATCHED_AGENT_HEALTH_START (keep in sync with the identically-named
# block inlined in endpoint/patched-log-upload.sh and
# endpoint/patched-fetch-posture.sh — endpoint/ has no lib/ convention:
# tools/build-bundle.sh copies its scripts individually by filename with no
# lib/ directory, so a sourced dependency there would fatal on every
# deployed release build, the same reason patched_curl_bearer is inlined
# rather than sourced in those two scripts.)

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
    local _ah_channel="" _ah_helper="${PATCHED_BUNDLE_DIR:-/usr/local/patched-updater}/agent_update_channel.py"
    if [[ -f "$_ah_helper" ]]; then
        _ah_channel=$("$PYTHON3" "$_ah_helper" health \
            --cache "${PATCHED_STATE_DIR:-/Library/Application Support/Patched}/update-channel.json" \
            --tenant-file "${PATCHED_CREDS_DIR:-/etc/patched}/tenant-id" \
            --device-file "${PATCHED_CREDS_DIR:-/etc/patched}/device-id" \
            --floor-file "${PATCHED_STATE_DIR:-/Library/Application Support/Patched}/agent-config.version" 2>/dev/null) || _ah_channel=""
    fi

    _ah_degraded=$(patched_agent_health_emit_degraded_json 2>/dev/null)
    _ah_emit_rc=$?
    if (( _ah_emit_rc != 0 )); then
        echo "agent-health: store exists but could not be read/parsed — this upload will omit agent_health entirely (no opinion), not claim an all-clear"
        _ah_degraded=""   # sentinel: tells the python below to OMIT the key
    fi

    "$PYTHON3" - "$_src" "$_dst" "$_ah_degraded" "$_ah_channel" <<'PYEOF'
import json, sys

src_path, dst_path, degraded_json = sys.argv[1], sys.argv[2], sys.argv[3]
channel_json = sys.argv[4]

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
    if channel_json:
        try:
            channel = json.loads(channel_json)
            if isinstance(channel, dict) and channel.get("effective_channel") in ("stable", "beta") and channel.get("source") in (None, "tenant", "device_override"):
                payload["agent_health"]["update_channel"] = channel
        except (ValueError, TypeError):
            pass  # uncertain metadata is omitted, never a degraded fault

with open(dst_path, "w") as f:
    json.dump(payload, f, separators=(",", ":"))
PYEOF
}
# <<< PATCHED_AGENT_HEALTH_END
