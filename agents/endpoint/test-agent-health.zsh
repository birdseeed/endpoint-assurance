#!/bin/zsh
##############################################################################
# test-agent-health.zsh — unit tests for the shared agent_health store
# (macos/lib/agent_health.sh; inlined in endpoint/patched-log-upload.sh
# and endpoint/patched-fetch-posture.sh)
# introduced by PAT-1065 (server-side contract: PAT-1064).
#
# Extracts the SHIPPED PATCHED_AGENT_HEALTH block (sentinel markers) from the
# canonical copy, macos/lib/agent_health.sh, and sources it directly against
# a scratch PATCHED_AGENT_HEALTH_STORE — no root, no network, no real
# daemons — same extraction pattern as endpoint/test-agent-tier-default.zsh.
#
# Coverage:
#   [1] record a failure -> appears active, count=1, ever_succeeded=false
#   [2] record the same failure again -> count=2, first_seen unchanged,
#       last_seen updated
#   [3] record a success -> entry no longer in the active/emitted set
#   [4] the SAME (kind, subject) failing again after that success ->
#       ever_succeeded=true this time (the two-part-design property; a naive
#       single-entry-deleted-on-success implementation would report false
#       here instead)
#   [5] a full run with nothing active still emits "[]", not an absent/null
#       value
#   [6] lock contention: a live holder's lock is respected, not stolen (the
#       call returns without corrupting the store); a dead holder's stale
#       lock is reclaimed and the call proceeds normally — mirrors
#       macos/lib/test-browser-extension-removal.zsh's live-vs-dead-pid cases
#       for PAT-1037's identical lock shape, at a scale proportionate to a
#       single JSON read-modify-write rather than that ticket's larger
#       accumulated-batch problem.
#   [7] PAT-1065 review finding A: a store that EXISTS but fails to parse
#       (corrupted JSON) must never emit "[]" — that would read upstream as
#       an explicit all-clear and wipe out genuinely active server-side
#       fault rows on nothing but a local read glitch. Confirms emit returns
#       non-zero with no output, merge_into_payload omits the agent_health
#       key entirely (not present-with-empty-array), and that this is
#       distinguishable from the genuinely-empty/absent-store case (which
#       must still emit {"degraded": []}).
#   [8] retired in PAT-2245 with the poller it exercised.
#   [9] PAT-1065 review finding C: the stale-lock reclaim's rm-rf+mkdir is
#       not atomic, so two different processes can each reclaim what they
#       both saw as the same stale lock, one's rm -rf destroying the
#       other's freshly-reclaimed directory. Simulates a second reclaimer
#       landing inside our own reclaim's settle window (background subshell
#       timing, same technique macos/lib/test-browser-extension-removal.zsh
#       uses for the analogous PAT-1037 TOCTOU) and confirms we detect the
#       marker mismatch and back off rather than proceed.
#   [10] PAT-1065 review finding 1 (a second-round, more severe instance of
#        finding A, on the MUTATION path this time): a corrupted store must
#        never be silently treated as empty by record_failure/record_success
#        either — doing so would overwrite it with a fresh copy containing
#        only the one new entry, destroying every OTHER active fault and the
#        entire ever_succeeded ledger. Seeds real pre-existing entries,
#        corrupts the file, calls both functions for a DIFFERENT
#        (kind, subject) pair, and confirms the file is byte-for-byte
#        unchanged (not overwritten) either way.
#   [11] PAT-1065 review finding 2: a store that PARSES fine but has the
#        wrong internal shape (active present but not a dict) must be
#        treated the same as unparseable — not silently coerced to empty,
#        which would still feed a false all-clear through emit, or silently
#        destroyed on a mutation call.
#   [12] PAT-1065 review finding 4: `kill -0 $pid` succeeding only proves
#        SOME process holds that pid, not that it is the ORIGINAL holder —
#        the OS reuses pids over time. Fakes a lock naming a REAL,
#        currently-alive pid (this test process's own) but a deliberately
#        wrong recorded start time, confirming it is correctly treated as
#        stale (pid reuse) and reclaimed rather than blocking forever.
#
# Run: zsh endpoint/test-agent-health.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
LIB_SH="$SCRIPT_DIR/../macos/lib/agent_health.sh"
PYTHON3="/usr/bin/python3"

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-agent-health-block.XXXXXX")
awk '/PATCHED_AGENT_HEALTH_START/{f=1;next} /PATCHED_AGENT_HEALTH_END/{f=0} f' \
    "$LIB_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_AGENT_HEALTH block from $LIB_SH"
    exit 1
fi
source "$BLOCK_TMP"

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.agent-health-test.XXXXXX")
trap 'rm -rf "$WORK" "$BLOCK_TMP"' EXIT

# json_get <json> <python-expr-on-obj>
#   Small helper: parse $1 as JSON, evaluate a python expression against the
#   decoded object (bound to `obj`), print its str().
json_get() {
    "$PYTHON3" -c '
import json, sys
obj = json.loads(sys.argv[1])
print(eval(sys.argv[2]))
' "$1" "$2" 2>/dev/null
}

# ============================================================================
echo "\n--- [1] record a failure ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case1/.agent-health.json"
mkdir -p "$WORK/case1"

patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed"
degraded1=$(patched_agent_health_emit_degraded_json)

chk "emitted set has exactly one entry" \
    "$([[ "$(json_get "$degraded1" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
chk "kind is sync_never_succeeded" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["kind"]')" == "sync_never_succeeded" ]] && echo 1 || echo 0)"
chk "subject is posture" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["subject"]')" == "posture" ]] && echo 1 || echo 0)"
chk "reason is fetch_failed" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["reason"]')" == "fetch_failed" ]] && echo 1 || echo 0)"
chk "count is 1" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["count"]')" == "1" ]] && echo 1 || echo 0)"
chk "ever_succeeded is false" \
    "$([[ "$(json_get "$degraded1" 'obj[0]["ever_succeeded"]')" == "False" ]] && echo 1 || echo 0)"

first_seen_1=$(json_get "$degraded1" 'obj[0]["first_seen"]')

# ============================================================================
echo "\n--- [2] record the same failure again ---"
sleep 1  # ensure a real clock tick so last_seen can differ from first_seen
patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed"
degraded2=$(patched_agent_health_emit_degraded_json)

chk "still exactly one entry (updated in place, not duplicated)" \
    "$([[ "$(json_get "$degraded2" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
chk "count is now 2" \
    "$([[ "$(json_get "$degraded2" 'obj[0]["count"]')" == "2" ]] && echo 1 || echo 0)"
chk "first_seen unchanged" \
    "$([[ "$(json_get "$degraded2" 'obj[0]["first_seen"]')" == "$first_seen_1" ]] && echo 1 || echo 0)"
chk "last_seen present (RFC3339 shape)" \
    "$([[ "$(json_get "$degraded2" 'obj[0]["last_seen"]')" == *T*Z ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [3] record a success -> entry no longer active ---"
patched_agent_health_record_success "sync_never_succeeded" "posture"
degraded3=$(patched_agent_health_emit_degraded_json)

chk "active set is now empty" \
    "$([[ "$(json_get "$degraded3" 'len(obj)')" == "0" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [4] the SAME fault recurs after that success -> ever_succeeded=true ---"
# This is the property a naive single-entry-deleted-on-success design gets
# wrong: it would have no memory that this (kind, subject) ever worked, so a
# fresh entry here would report ever_succeeded=false. The two-part design
# (active vs. a separate, never-auto-cleared ever_succeeded ledger) must
# report true.
patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed"
degraded4=$(patched_agent_health_emit_degraded_json)

chk "one active entry again" \
    "$([[ "$(json_get "$degraded4" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
chk "count reset to 1 for the new active episode" \
    "$([[ "$(json_get "$degraded4" 'obj[0]["count"]')" == "1" ]] && echo 1 || echo 0)"
chk "ever_succeeded is true on the recurrence (two-part design property)" \
    "$([[ "$(json_get "$degraded4" 'obj[0]["ever_succeeded"]')" == "True" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [5] nothing active still emits [], not an absent/null value ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case5/.agent-health.json"
mkdir -p "$WORK/case5"
degraded5=$(patched_agent_health_emit_degraded_json)
chk "store never touched: emits [] (a real empty JSON array)" \
    "$([[ "$degraded5" == "[]" ]] && echo 1 || echo 0)"

patched_agent_health_record_failure "capability_missing" "extension_removal" "lib_not_installed"
patched_agent_health_record_success "capability_missing" "extension_removal"
degraded5b=$(patched_agent_health_emit_degraded_json)
chk "resolved-to-clean store also emits [] (not null, not absent)" \
    "$([[ "$degraded5b" == "[]" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [5b] merge_into_payload: PAT-1029 acceptance shape ---"
# The property PAT-1029/PAT-1064 both ask for explicitly: the emitted payload
# carries the capability_missing entry while every OTHER section of the
# payload (arbitrary stand-ins for hardware/apps/compliance_findings here) is
# passed through byte-for-byte unchanged — this is the actual /v1/inventory
# merge patched-upload.sh's MAIN LOOP performs on every queued file, exercised
# here directly rather than via a hand-written copy.
export PATCHED_AGENT_HEALTH_STORE="$WORK/case5b/.agent-health.json"
mkdir -p "$WORK/case5b"
patched_agent_health_record_failure "capability_missing" "extension_blocklist" "lib_not_installed"

SRC_PAYLOAD="$WORK/case5b/inventory-src.json"
DST_PAYLOAD="$WORK/case5b/inventory-merged.json"
cat > "$SRC_PAYLOAD" <<'JSONEOF'
{"device_id":"unaffected-device","hardware":{"model":"MacBookPro18,1"},"apps":[{"name":"Safari","version":"17.4.1"}],"compliance_findings":[]}
JSONEOF

patched_agent_health_merge_into_payload "$SRC_PAYLOAD" "$DST_PAYLOAD"
merge_rc=$?
chk "merge_into_payload returns success" "$(( merge_rc == 0 ))"

merged_content=$(cat "$DST_PAYLOAD" 2>/dev/null)
chk "merged payload carries agent_health.degraded with the capability_missing entry" \
    "$(json_get "$merged_content" '1 if any(e.get("kind")=="capability_missing" and e.get("subject")=="extension_blocklist" for e in obj["agent_health"]["degraded"]) else 0')"
chk "unaffected key device_id is unchanged" \
    "$([[ "$(json_get "$merged_content" 'obj["device_id"]')" == "unaffected-device" ]] && echo 1 || echo 0)"
chk "unaffected key hardware is unchanged" \
    "$([[ "$(json_get "$merged_content" 'obj["hardware"]["model"]')" == "MacBookPro18,1" ]] && echo 1 || echo 0)"
chk "unaffected key apps is unchanged" \
    "$([[ "$(json_get "$merged_content" 'obj["apps"][0]["name"]')" == "Safari" ]] && echo 1 || echo 0)"

# A resolved-clean store still merges an explicit {"degraded": []} — never
# omits the key — matching the absent-vs-present-empty contract.
patched_agent_health_record_success "capability_missing" "extension_blocklist"
patched_agent_health_merge_into_payload "$SRC_PAYLOAD" "$DST_PAYLOAD"
merged_clean=$(cat "$DST_PAYLOAD" 2>/dev/null)
chk "clean store still merges an explicit empty degraded array (key never omitted)" \
    "$([[ "$(json_get "$merged_clean" 'obj["agent_health"]')" == "{'degraded': []}" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [6a] lock held by a live process: call is skipped, store untouched ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case6a/.agent-health.json"
mkdir -p "$WORK/case6a"
LOCK_DIR_6A="$WORK/case6a/.agent-health.lock"
mkdir -p "$LOCK_DIR_6A"
echo $$ > "$LOCK_DIR_6A/pid"   # this test process's own pid: genuinely alive

out6a=$(patched_agent_health_record_failure "capability_missing" "extension_blocklist" "lib_not_installed" 2>&1)
chk "log says the lock is held / skipping" \
    "$([[ "$out6a" == *"lock held by another instance"* ]] && echo 1 || echo 0)"
chk "no store file was written while the lock was held" \
    "$([[ ! -f "$PATCHED_AGENT_HEALTH_STORE" ]] && echo 1 || echo 0)"

rm -rf "$LOCK_DIR_6A"

# ============================================================================
echo "\n--- [6b] lock held by a dead process: stale lock is reclaimed, call proceeds ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case6b/.agent-health.json"
mkdir -p "$WORK/case6b"
LOCK_DIR_6B="$WORK/case6b/.agent-health.lock"

# A pid that is guaranteed not to be running: fork a trivial subshell, note
# its pid, then wait for it to actually exit before using it.
( : ) &
DEAD_PID=$!
wait "$DEAD_PID" 2>/dev/null

mkdir -p "$LOCK_DIR_6B"
echo "$DEAD_PID" > "$LOCK_DIR_6B/pid"

out6b=$(patched_agent_health_record_failure "capability_missing" "extension_blocklist" "lib_not_installed" 2>&1)
chk "log says the stale lock was reclaimed" \
    "$([[ "$out6b" == *"stale"*"reclaiming"* ]] && echo 1 || echo 0)"
degraded6b=$(patched_agent_health_emit_degraded_json)
chk "the record succeeded after reclaiming the stale lock" \
    "$([[ "$(json_get "$degraded6b" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"

rm -rf "$LOCK_DIR_6B"

# ============================================================================
echo "\n--- [7] Finding A: a corrupted (unreadable) store must never emit an all-clear ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case7/.agent-health.json"
mkdir -p "$WORK/case7"

# Genuinely-empty/absent-store case, for direct contrast: must still emit a
# real "[]" and return success.
degraded7_absent=$(patched_agent_health_emit_degraded_json)
rc7_absent=$?
chk "absent store: emit returns success" "$(( rc7_absent == 0 ))"
chk "absent store: emits a genuine [] " "$([[ "$degraded7_absent" == "[]" ]] && echo 1 || echo 0)"

# Now corrupt it: a file exists at the store path but is not valid JSON.
printf '{not valid json at all' > "$PATCHED_AGENT_HEALTH_STORE"

degraded7_corrupt=$(patched_agent_health_emit_degraded_json 2>/dev/null)
rc7_corrupt=$?
chk "corrupted store: emit returns non-zero (distinct from the absent case)" "$(( rc7_corrupt != 0 ))"
chk "corrupted store: emit prints nothing (never a guessed [])" "$([[ -z "$degraded7_corrupt" ]] && echo 1 || echo 0)"

SRC_PAYLOAD_7="$WORK/case7/inventory-src.json"
DST_PAYLOAD_7="$WORK/case7/inventory-merged.json"
cat > "$SRC_PAYLOAD_7" <<'JSONEOF'
{"device_id":"unaffected-device-7","hardware":{"model":"Mac14,2"}}
JSONEOF

patched_agent_health_merge_into_payload "$SRC_PAYLOAD_7" "$DST_PAYLOAD_7"
merge7_rc=$?
chk "merge still succeeds (a store read failure is not a reason to skip the upload)" "$(( merge7_rc == 0 ))"

merged7=$(cat "$DST_PAYLOAD_7" 2>/dev/null)
chk "merged payload OMITS agent_health entirely (not present-with-empty-array)" \
    "$([[ "$(json_get "$merged7" "'agent_health' not in obj")" == "True" ]] && echo 1 || echo 0)"
chk "unaffected key device_id is still passed through" \
    "$([[ "$(json_get "$merged7" 'obj["device_id"]')" == "unaffected-device-7" ]] && echo 1 || echo 0)"

# ============================================================================

# ============================================================================
echo "\n--- [9] Finding C: a second, near-simultaneous reclaimer is detected and backs off ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case9/.agent-health.json"
mkdir -p "$WORK/case9"
LOCK_DIR_9="$WORK/case9/.agent-health.lock"

( : ) &
DEAD_PID9=$!
wait "$DEAD_PID9" 2>/dev/null
mkdir -p "$LOCK_DIR_9"
echo "$DEAD_PID9" > "$LOCK_DIR_9/pid"

# Simulate a second, independent reclaimer landing inside our own reclaim's
# ~0.1s settle window: after a short delay, it performs exactly what a
# second reclaimer would (rm -rf + mkdir + its own marker write),
# overwriting whatever marker we wrote moments earlier.
( sleep 0.05; rm -rf "$LOCK_DIR_9"; mkdir -p "$LOCK_DIR_9"; echo "rival-reclaimer-marker" > "$LOCK_DIR_9/pid" ) &
RIVAL_PID=$!

out9=$(patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed" 2>&1)
wait "$RIVAL_PID" 2>/dev/null

chk "log reports losing the reclaim race" \
    "$([[ "$out9" == *"lost the reclaim race"* ]] && echo 1 || echo 0)"
chk "the store was not written by the losing side (no concurrent corruption)" \
    "$([[ ! -f "$PATCHED_AGENT_HEALTH_STORE" ]] && echo 1 || echo 0)"

rm -rf "$LOCK_DIR_9"

# ============================================================================
echo "\n--- [10] Finding 1: record_failure/record_success abort without touching a corrupted store (mutation-path guard) ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case10/.agent-health.json"
mkdir -p "$WORK/case10"

# Seed valid pre-existing entries for OTHER (kind, subject) pairs, and a
# populated ever_succeeded ledger, before corrupting the file.
patched_agent_health_record_failure "capability_missing" "extension_removal" "lib_not_installed"
patched_agent_health_record_success "capability_missing" "extension_removal"
patched_agent_health_record_failure "directive_skipped" "log_upload" "device_id_mismatch"

printf '{completely broken json, not valid at all' > "$PATCHED_AGENT_HEALTH_STORE"
corrupted_bytes_before=$(cat "$PATCHED_AGENT_HEALTH_STORE")

out10a=$(patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed" 2>&1)
after_failure_attempt=$(cat "$PATCHED_AGENT_HEALTH_STORE" 2>/dev/null)
chk "record_failure for a DIFFERENT pair aborts without touching the corrupted file" \
    "$([[ "$after_failure_attempt" == "$corrupted_bytes_before" ]] && echo 1 || echo 0)"
chk "record_failure logs that it is aborting, not silently proceeding" \
    "$([[ "$out10a" == *"aborting this record without touching it"* ]] && echo 1 || echo 0)"

out10b=$(patched_agent_health_record_success "directive_skipped" "log_upload" 2>&1)
after_success_attempt=$(cat "$PATCHED_AGENT_HEALTH_STORE" 2>/dev/null)
chk "record_success for a DIFFERENT pair also aborts without touching the corrupted file" \
    "$([[ "$after_success_attempt" == "$corrupted_bytes_before" ]] && echo 1 || echo 0)"
chk "record_success logs that it is aborting, not silently proceeding" \
    "$([[ "$out10b" == *"aborting this record without touching it"* ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [11] Finding 2: a parseable-but-malformed store (active not a dict) is also treated as untrusted, not empty ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case11/.agent-health.json"
mkdir -p "$WORK/case11"

printf '%s' '{"active": "not-a-dict", "ever_succeeded": {}}' > "$PATCHED_AGENT_HEALTH_STORE"
malformed_bytes_before=$(cat "$PATCHED_AGENT_HEALTH_STORE")

degraded11=$(patched_agent_health_emit_degraded_json 2>/dev/null)
rc11=$?
chk "emit_degraded_json treats a malformed active shape as unknown, not empty" "$(( rc11 != 0 ))"
chk "emit prints nothing for the malformed-shape case (never a guessed [])" "$([[ -z "$degraded11" ]] && echo 1 || echo 0)"

out11=$(patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed" 2>&1)
after_11=$(cat "$PATCHED_AGENT_HEALTH_STORE" 2>/dev/null)
chk "record_failure against a malformed-shape store aborts without touching it" \
    "$([[ "$after_11" == "$malformed_bytes_before" ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n--- [12] Finding 4: a live pid whose recorded start time no longer matches is treated as stale (pid reuse) ---"
export PATCHED_AGENT_HEALTH_STORE="$WORK/case12/.agent-health.json"
mkdir -p "$WORK/case12"
LOCK_DIR_12="$WORK/case12/.agent-health.lock"
mkdir -p "$LOCK_DIR_12"
# A REAL, currently-running pid (this test process's own) with a
# DELIBERATELY WRONG recorded start time, simulating the OS having reused
# this exact pid for a different process since the lock was written — the
# scenario a bare `kill -0` liveness check cannot distinguish from a
# genuinely still-live original holder.
echo "$$|not-the-real-start-time" > "$LOCK_DIR_12/pid"

out12=$(patched_agent_health_record_failure "sync_never_succeeded" "posture" "fetch_failed" 2>&1)
chk "log treats the mismatched-start-time lock as stale (pid reuse), not live" \
    "$([[ "$out12" == *"not running, or its start time no longer matches"* ]] && echo 1 || echo 0)"
chk "log reports reclaiming, not blocking on the reused pid" \
    "$([[ "$out12" == *reclaiming* ]] && echo 1 || echo 0)"
degraded12=$(patched_agent_health_emit_degraded_json)
chk "the record succeeded after correctly reclaiming the pid-reuse lock" \
    "$([[ "$(json_get "$degraded12" 'len(obj)')" == "1" ]] && echo 1 || echo 0)"
rm -rf "$LOCK_DIR_12"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
