#!/bin/zsh
##############################################################################
# test-browser-extension-removal.zsh — unit tests for the PAT-1037 durable
# audit-persistence fix in ber_remove_extensions (browser_extension_removal.sh).
#
# Sources the live function out of browser_extension_removal.sh (no top-level
# side effects at source time) so the tests exercise the real code, not a
# copy. compute_hmac and patched_curl_bearer — normally defined inline by
# patched-upload.sh before it sources this module — are shadowed here with
# controllable zsh function fakes, matching how test-app-control.zsh shadows
# dscl/stat. Each case plants a small real Chrome-extension fixture under a
# scratch "Users" root and a scratch STATE_DIR/PATCHED_TMPDIR pair, so the
# real (unmodified) Python removal logic actually deletes something and the
# tests exercise the shell wrapper's post-removal handling of the result,
# not a mock of it. Run:
#   zsh macos/lib/test-browser-extension-removal.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"
API_URL="https://example.test"
BEARER_TOKEN="test-bearer-token"
HW_UUID=""

# ── Fixture doubles for compute_hmac / patched_curl_bearer ─────────────────
# ber_remove_extensions invokes both of these through a command substitution
# ($(patched_curl_bearer ...)), which zsh runs in a forked subshell — plain
# variable mutations made inside the fake (a call counter, a captured body)
# would vanish when that subshell exits. So the fakes record their side
# effects to files under MOCK_TRACK_DIR instead, which survive across the
# fork since they're on disk, not in shell memory. reset_mocks resets both
# per test case; MOCK_TRACK_DIR itself is (re)created per scenario below.
MOCK_HMAC_FAIL=0
MOCK_NETWORK_ERROR=0
MOCK_HTTP_CODE="200"
MOCK_RESP_BODY='{"ingested":1}'
MOCK_TRACK_DIR=""

reset_mocks() {  # reset_mocks <track_dir>
    MOCK_TRACK_DIR="$1"
    mkdir -p "$MOCK_TRACK_DIR"
    : > "$MOCK_TRACK_DIR/calls"
    : > "$MOCK_TRACK_DIR/last_body"
}

curl_call_count() { wc -l < "$MOCK_TRACK_DIR/calls" | tr -d ' '; }
curl_last_body()  { cat "$MOCK_TRACK_DIR/last_body"; }

compute_hmac() {
    (( MOCK_HMAC_FAIL )) && return 1
    echo "deadbeefhmac"
}

# patched_curl_bearer <token> [curl args...] — real signature is
# `patched_curl_bearer <bearer-token> [curl args...]`; this fake records the
# --data-binary body (for merge assertions) and the -o response-file target
# (so it can drop MOCK_RESP_BODY where the real code reads it from), then
# returns either a simulated network failure or MOCK_HTTP_CODE on stdout,
# exactly like the real curl -w "%{http_code}" call.
patched_curl_bearer() {
    local _token="$1"
    shift
    echo 1 >> "$MOCK_TRACK_DIR/calls"
    local -a args
    args=("$@")
    local n=${#args[@]}
    local i resp_file="" body_ref=""
    for (( i=1; i<=n; i++ )); do
        case "${args[i]}" in
            -o) resp_file="${args[i+1]}" ;;
            --data-binary) body_ref="${args[i+1]}" ;;
        esac
    done
    local body_file="${body_ref#@}"
    if [[ -n "$body_file" && -f "$body_file" ]]; then
        cat "$body_file" > "$MOCK_TRACK_DIR/last_body"
    fi
    if (( MOCK_NETWORK_ERROR )); then
        return 1
    fi
    if [[ -n "$resp_file" ]]; then
        printf '%s' "$MOCK_RESP_BODY" > "$resp_file"
    fi
    printf '%s' "$MOCK_HTTP_CODE"
}

# mktemp <template...> — PAT-1071 fixture double, transparent unless
# MOCK_CHMOD_BODY_TMP=1. When armed, the one mktemp call that matches the
# audit-POST body template (patched-ber-audit.XXXXXX, distinct from the
# events/merge/response tmp files' own templates elsewhere in the module)
# is chmod'd 0444 the instant it exists, forcing a genuine permission-denied
# failure on the very next statement's `{ ...; } > "$_body_tmp"` brace-group
# redirect — reproducing the write failure this ticket is about instead of
# merely asserting a guard is present. Every other mktemp call (any other
# template, or no template at all e.g. `mktemp -d`) passes straight through.
MOCK_CHMOD_BODY_TMP=0
mktemp() {
    local _real
    _real=$(command mktemp "$@") || return $?
    if (( MOCK_CHMOD_BODY_TMP )) && [[ "$1" == *patched-ber-audit.XXXXXX ]]; then
        chmod 0444 "$_real"
    fi
    print -r -- "$_real"
}

source "$SCRIPT_DIR/browser_extension_removal.sh"

pass=0; fail=0
chk() {  # chk <desc> <0/1-truthy>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# make_users_fixture <users_root> <user> <ext_id> — plants a Chrome extension
# at <users_root>/<user>/Library/Application Support/Google/Chrome/Default/Extensions/<ext_id>
make_users_fixture() {
    local root="$1" user="$2" ext_id="$3"
    mkdir -p "$root/$user/Library/Application Support/Google/Chrome/Default/Extensions/$ext_id"
    echo '{}' > "$root/$user/Library/Application Support/Google/Chrome/Default/Extensions/$ext_id/manifest.json"
}

ext_exists() {  # ext_exists <users_root> <user> <ext_id>
    [[ -d "$1/$2/Library/Application Support/Google/Chrome/Default/Extensions/$3" ]]
}

# make_config <path> <ext_id-or-empty> — one one_profile removal directive
# targeting alice/Default, or an empty extension_removals list.
make_config() {
    local cfg="$1" ext_id="$2"
    if [[ -z "$ext_id" ]]; then
        printf '{"app_control":{"enabled":true,"extension_removals":[]}}' > "$cfg"
    else
        printf '{"app_control":{"enabled":true,"extension_removals":[{"browser":"chrome","extension_id":"%s","scope":"one_profile","user_account":"alice","profile":"Default"}]}}' "$ext_id" > "$cfg"
    fi
}

pending_count() {  # pending_count <path> -> event count, or -1 if unreadable
    [[ -f "$1" ]] || { echo 0; return; }
    "$PYTHON3" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d) if isinstance(d, list) else -1)
except Exception:
    print(-1)
' "$1"
}

body_event_count() {  # body_event_count <raw POST body string> -> "events" length, or -1
    local tmp
    tmp=$(mktemp)
    printf '%s' "$1" > "$tmp"
    "$PYTHON3" -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d.get("events", [])) if isinstance(d, dict) else -1)
except Exception:
    print(-1)
' "$tmp"
    rm -f "$tmp"
}

EXT_A="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"   # 32 a's — valid Chrome-style id
EXT_B="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"   # 32 b's — distinct extension

##############################################################################
# 1. POST failure -> the event persists in the durable pending file, the
# function returns 0, and the removal itself (already committed to disk) is
# unaffected by the POST outcome.
##############################################################################
echo "--- 1. POST failure persists the event; removal unaffected ---"

FIXTURE=$(mktemp -d)
USERS_ROOT="$FIXTURE/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG="$FIXTURE/agent-config.json"
make_users_fixture "$USERS_ROOT" "alice" "$EXT_A"
make_config "$CFG" "$EXT_A"
PATCHED_AC_CONFIG="$CFG"
PATCHED_BER_USERS_DIR="$USERS_ROOT"
PATCHED_DRY_RUN=0
MOCK_HMAC_FAIL=0; MOCK_NETWORK_ERROR=0; MOCK_HTTP_CODE="500"; MOCK_RESP_BODY=""
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 on POST failure" "$(( RC == 0 ))"
chk "extension actually removed from disk despite POST failure" \
    "$(! ext_exists "$USERS_ROOT" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "POST was attempted exactly once" "$(( $(curl_call_count) == 1 ))"
chk "pending file exists after a failed POST" \
    "$([[ -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "pending file holds exactly 1 event" \
    "$(( $(pending_count "$STATE_DIR/.enforcement-audit-pending.json") == 1 ))"
chk "log mentions the pending batch was left for the next run" \
    "$([[ "$OUT" == *"left at"*".enforcement-audit-pending.json"* ]] && echo 1 || echo 0)"

##############################################################################
# 2. A subsequent run with the endpoint reachable drains the pending file,
# confirms via the {"ingested": n} body (not the bare status code), and
# clears the pending file only on that confirmation.
##############################################################################
echo "--- 2. subsequent run drains pending file on confirmed ingestion ---"

# Same STATE_DIR as case 1 -> same leftover 1-event pending file. This run's
# own config has zero new removals, so the leftover pending batch is the
# entire POST.
make_config "$CFG" ""
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":1}'
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 on confirmed drain" "$(( RC == 0 ))"
chk "POST attempted exactly once to drain the leftover batch" "$(( $(curl_call_count) == 1 ))"
chk "pending file cleared after confirmed ingestion" \
    "$([[ ! -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "log confirms ingestion (not a bare status code)" \
    "$([[ "$OUT" == *"ingested confirmed"* ]] && echo 1 || echo 0)"

##############################################################################
# 2b. Regression guard: a 2xx response with a malformed/missing "ingested"
# field must NOT count as confirmed, so this can never regress to a
# bare-status-code check.
##############################################################################
echo "--- 2b. 2xx with malformed ingested body does not count as confirmed ---"

FIXTURE2=$(mktemp -d)
USERS_ROOT2="$FIXTURE2/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG2="$FIXTURE2/agent-config.json"
make_users_fixture "$USERS_ROOT2" "alice" "$EXT_A"
make_config "$CFG2" "$EXT_A"
PATCHED_AC_CONFIG="$CFG2"
PATCHED_BER_USERS_DIR="$USERS_ROOT2"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ok":true}'
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 even though ingestion could not be confirmed" "$(( RC == 0 ))"
chk "pending file still present (bare 2xx did not clear it)" \
    "$([[ -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "log says the response body did not confirm ingestion" \
    "$([[ "$OUT" == *"did not confirm ingestion"* ]] && echo 1 || echo 0)"

##############################################################################
# 2c. Regression guard (tightened confirmation, PAT-1037 review finding 4):
# a 2xx response whose "ingested" count does NOT exactly match the size of
# the batch sent (server does one atomic multi-row INSERT — a genuine
# success is always all-rows-ingested, never a smaller/larger count) must
# NOT count as confirmed.
##############################################################################
echo "--- 2c. 2xx with a mismatched ingested count does not count as confirmed ---"

FIXTURE2C=$(mktemp -d)
USERS_ROOT2C="$FIXTURE2C/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG2C="$FIXTURE2C/agent-config.json"
make_users_fixture "$USERS_ROOT2C" "alice" "$EXT_B"
make_config "$CFG2C" "$EXT_B"
PATCHED_AC_CONFIG="$CFG2C"
PATCHED_BER_USERS_DIR="$USERS_ROOT2C"

# One leftover pending event (EXT_A) plus this cycle's new event (EXT_B) ->
# a combined batch of 2. A response claiming only 1 ingested must not confirm.
printf '[{"event_type":"extension_removed","subject":"%s","details":{},"occurred_at":"2026-07-01T00:00:00Z"}]' "$EXT_A" \
    > "$STATE_DIR/.enforcement-audit-pending.json"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":1}'
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 even though the ingested count did not match" "$(( RC == 0 ))"
chk "pending file still present (mismatched count did not clear it)" \
    "$([[ -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "pending file still holds both events (nothing dropped)" \
    "$(( $(pending_count "$STATE_DIR/.enforcement-audit-pending.json") == 2 ))"
chk "log says the response body did not confirm ingestion" \
    "$([[ "$OUT" == *"did not confirm ingestion"* ]] && echo 1 || echo 0)"

##############################################################################
# 3. A run with both a pre-existing pending file AND new events this cycle:
# both merge into one POST attempt.
##############################################################################
echo "--- 3. pre-existing pending batch + new events merge into one POST ---"

FIXTURE3=$(mktemp -d)
USERS_ROOT3="$FIXTURE3/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG3="$FIXTURE3/agent-config.json"
make_users_fixture "$USERS_ROOT3" "alice" "$EXT_B"
make_config "$CFG3" "$EXT_B"
PATCHED_AC_CONFIG="$CFG3"
PATCHED_BER_USERS_DIR="$USERS_ROOT3"

# Seed a leftover pending batch by hand, same shape ber_remove_extensions
# itself writes: a bare JSON array of event dicts.
printf '[{"event_type":"extension_removed","subject":"%s","details":{},"occurred_at":"2026-07-01T00:00:00Z"}]' "$EXT_A" \
    > "$STATE_DIR/.enforcement-audit-pending.json"

MOCK_HTTP_CODE="500"; MOCK_RESP_BODY=""
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0" "$(( RC == 0 ))"
chk "exactly one POST attempted" "$(( $(curl_call_count) == 1 ))"
chk "POST body carries both the leftover and the new event (2 total)" \
    "$(( $(body_event_count "$(curl_last_body)") == 2 ))"
chk "pending file retains both events after the failed POST" \
    "$(( $(pending_count "$STATE_DIR/.enforcement-audit-pending.json") == 2 ))"

##############################################################################
# 4a. Lock held by a genuinely LIVE process -> this run is skipped entirely:
# no removal, no POST, pending file untouched, returns 0. Unaffected by the
# staleness fix (finding 3) — a live holder must still be respected.
##############################################################################
echo "--- 4a. lock held by a live process skips the whole run (removal included) ---"

FIXTURE4=$(mktemp -d)
USERS_ROOT4="$FIXTURE4/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG4="$FIXTURE4/agent-config.json"
make_users_fixture "$USERS_ROOT4" "alice" "$EXT_A"
make_config "$CFG4" "$EXT_A"
PATCHED_AC_CONFIG="$CFG4"
PATCHED_BER_USERS_DIR="$USERS_ROOT4"

mkdir -p "$STATE_DIR/.enforcement-audit-post.lock"
echo $$ > "$STATE_DIR/.enforcement-audit-post.lock/pid"   # this test process's own pid: genuinely alive
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 when lock is held by a live process" "$(( RC == 0 ))"
chk "log says the lock is held / skipping" "$([[ "$OUT" == *"lock held by another instance"* ]] && echo 1 || echo 0)"
chk "extension is NOT removed while lock is held" \
    "$(ext_exists "$USERS_ROOT4" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "no POST attempted while lock is held" "$(( $(curl_call_count) == 0 ))"
chk "no pending file created while lock is held" \
    "$([[ ! -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"

rm -rf "$STATE_DIR/.enforcement-audit-post.lock"

##############################################################################
# 4b. Lock dir left behind by a DEAD process (PAT-1037 review finding 3) ->
# this run detects the recorded holder is no longer running, reclaims the
# lock, and proceeds normally (removal happens, POST is attempted).
##############################################################################
echo "--- 4b. lock held by a dead process is reclaimed; run proceeds normally ---"

FIXTURE4B=$(mktemp -d)
USERS_ROOT4B="$FIXTURE4B/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG4B="$FIXTURE4B/agent-config.json"
make_users_fixture "$USERS_ROOT4B" "alice" "$EXT_A"
make_config "$CFG4B" "$EXT_A"
PATCHED_AC_CONFIG="$CFG4B"
PATCHED_BER_USERS_DIR="$USERS_ROOT4B"

# A pid that is guaranteed dead: fork a trivial background job, capture its
# pid, then wait for it to actually exit before using it.
( : ) &
DEAD_PID=$!
wait "$DEAD_PID" 2>/dev/null

mkdir -p "$STATE_DIR/.enforcement-audit-post.lock"
echo "$DEAD_PID" > "$STATE_DIR/.enforcement-audit-post.lock/pid"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":1}'
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 after reclaiming a stale lock" "$(( RC == 0 ))"
chk "log says the stale lock was reclaimed" "$([[ "$OUT" == *"stale"*"reclaiming"* ]] && echo 1 || echo 0)"
chk "extension IS removed after reclaiming the stale lock" \
    "$(! ext_exists "$USERS_ROOT4B" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "POST was attempted after reclaiming the stale lock" "$(( $(curl_call_count) == 1 ))"
chk "pending file cleared after a confirmed POST post-reclaim" \
    "$([[ ! -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"

rm -rf "$STATE_DIR/.enforcement-audit-post.lock"

##############################################################################
# 5. Regression: nothing to remove this cycle and no prior pending file ->
# immediate "nothing to remove" fast path, no POST attempted. Unaffected by
# this change.
##############################################################################
echo "--- 5. nothing-to-remove fast path unaffected ---"

FIXTURE5=$(mktemp -d)
USERS_ROOT5="$FIXTURE5/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG5="$FIXTURE5/agent-config.json"
mkdir -p "$USERS_ROOT5/alice"
make_config "$CFG5" ""
PATCHED_AC_CONFIG="$CFG5"
PATCHED_BER_USERS_DIR="$USERS_ROOT5"
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0" "$(( RC == 0 ))"
chk "log says nothing to remove" "$([[ "$OUT" == *"nothing to remove"* ]] && echo 1 || echo 0)"
chk "no POST attempted" "$(( $(curl_call_count) == 0 ))"
chk "no pending file created" \
    "$([[ ! -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"

##############################################################################
# 6. PAT-1037 review finding (round 3): a corrupted/truncated pending file
# must NOT be silently treated as empty and deleted. No new events this
# cycle + a pending file that exists but is not valid JSON -> the corrupted
# file survives untouched, a loud/distinguishable (CRITICAL) log line fires,
# no POST is attempted with a wrongly-assumed-empty batch, and the function
# still returns 0 (non-fatal to the caller, matching this module's style).
##############################################################################
echo "--- 6. corrupted pending file is never silently treated as empty or deleted ---"

FIXTURE6=$(mktemp -d)
USERS_ROOT6="$FIXTURE6/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG6="$FIXTURE6/agent-config.json"
mkdir -p "$USERS_ROOT6/alice"
make_config "$CFG6" ""     # no new removals this cycle
PATCHED_AC_CONFIG="$CFG6"
PATCHED_BER_USERS_DIR="$USERS_ROOT6"

CORRUPT_CONTENT='{this is not valid json,,,'
printf '%s' "$CORRUPT_CONTENT" > "$STATE_DIR/.enforcement-audit-pending.json"
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0 even with a corrupted pending file" "$(( RC == 0 ))"
chk "log fires a loud CRITICAL line naming the corruption" \
    "$([[ "$OUT" == *"CRITICAL"*"not valid JSON"* ]] && echo 1 || echo 0)"
chk "corrupted pending file is NOT deleted" \
    "$([[ -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "corrupted pending file's content is untouched (not silently overwritten)" \
    "$([[ "$(cat "$STATE_DIR/.enforcement-audit-pending.json" 2>/dev/null)" == "$CORRUPT_CONTENT" ]] && echo 1 || echo 0)"
chk "no POST attempted against a wrongly-assumed-empty batch" "$(( $(curl_call_count) == 0 ))"
chk "no leftover merge temp file in STATE_DIR" \
    "$([[ -z "$(print -l "$STATE_DIR"/.enforcement-audit-pending.tmp.*(N) 2>/dev/null)" ]] && echo 1 || echo 0)"

##############################################################################
# 7. PAT-1037 review finding (round 3): the mkdir-then-write-pid TOCTOU
# window. A lock dir exists with NO pid file yet (the window right after a
# genuine owner's mkdir, before its `echo $$ > pid` runs) but the pid
# appears — and is genuinely alive — within the bounded retry window. This
# run must respect the lock as held, NOT reclaim it as stale.
##############################################################################
echo "--- 7. a pid that appears mid-retry-window (and is alive) is respected, not reclaimed ---"

FIXTURE7=$(mktemp -d)
USERS_ROOT7="$FIXTURE7/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG7="$FIXTURE7/agent-config.json"
make_users_fixture "$USERS_ROOT7" "alice" "$EXT_A"
make_config "$CFG7" "$EXT_A"
PATCHED_AC_CONFIG="$CFG7"
PATCHED_BER_USERS_DIR="$USERS_ROOT7"

mkdir -p "$STATE_DIR/.enforcement-audit-post.lock"   # lock exists, no pid file yet
# A background holder that writes its OWN (genuinely live) pid a beat after
# the lock dir already exists, then stays alive a little longer so this
# run's kill -0 check finds it alive, not just recently written.
( sleep 0.05; echo $$ > "$STATE_DIR/.enforcement-audit-post.lock/pid"; sleep 1 ) &
BG_HOLDER_PID=$!
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

kill "$BG_HOLDER_PID" 2>/dev/null
wait "$BG_HOLDER_PID" 2>/dev/null

chk "returns 0" "$(( RC == 0 ))"
chk "lock is respected as held, not reclaimed as stale" \
    "$([[ "$OUT" == *"lock held by another instance"* ]] && echo 1 || echo 0)"
chk "log does NOT claim the lock was stale/reclaimed" \
    "$([[ "$OUT" != *"looks stale"* ]] && echo 1 || echo 0)"
chk "extension is NOT removed (lock correctly respected, not reclaimed)" \
    "$(ext_exists "$USERS_ROOT7" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "no POST attempted" "$(( $(curl_call_count) == 0 ))"

rm -rf "$STATE_DIR/.enforcement-audit-post.lock"

##############################################################################
# 8. A single cycle's own removal batch is large (all_devices scope matching
# many users, one event each) -> still handled correctly end to end. This is
# a functional regression check that the file-based rewrite (round 4:
# $_events_tmp, never argv) works correctly at a non-trivial batch size, not
# a literal reproduction of an ARG_MAX overflow — portably constructing a
# batch that actually exceeds a real ARG_MAX in a fast unit test isn't
# practical (typical modern ARG_MAX is hundreds of KB to low MB). 150 users
# is enough to prove correctness of the file-based path at a scale well
# beyond the 1-2 event cases every other test above uses.
##############################################################################
echo "--- 8. a large single-cycle batch (many users, one scope-all directive) is handled correctly ---"

FIXTURE8=$(mktemp -d)
USERS_ROOT8="$FIXTURE8/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG8="$FIXTURE8/agent-config.json"
LARGE_N=150
for i in {1..150}; do
    make_users_fixture "$USERS_ROOT8" "user$i" "$EXT_A"
done
printf '{"app_control":{"enabled":true,"extension_removals":[{"browser":"chrome","extension_id":"%s","scope":"all_devices"}]}}' "$EXT_A" > "$CFG8"
PATCHED_AC_CONFIG="$CFG8"
PATCHED_BER_USERS_DIR="$USERS_ROOT8"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY="{\"ingested\":$LARGE_N}"
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
RC=$?

chk "returns 0" "$(( RC == 0 ))"
chk "every one of the 150 users' extension was actually removed" \
    "$(( $(for i in {1..150}; do ext_exists "$USERS_ROOT8" "user$i" "$EXT_A" && echo x; done | wc -l) == 0 ))"
chk "log reports all 150 removed" "$([[ "$OUT" == *"removed 150 extension install(s)"* ]] && echo 1 || echo 0)"
chk "POST body carries all 150 events" "$(( $(body_event_count "$(curl_last_body)") == 150 ))"
chk "pending file cleared after confirmed ingestion of all 150" \
    "$([[ ! -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "no leftover events/merge temp files in either scratch dir" \
    "$([[ -z "$(find "$STATE_DIR" "$PATCHED_TMPDIR" -name '*.tmp*' 2>/dev/null)" ]] && echo 1 || echo 0)"

##############################################################################
# 9. PAT-1071: the audit-POST body write is a `{ ...; } > "$_body_tmp"`
# brace-group redirect — the exact shape verified (by hand, on this
# estate's /bin/bash 3.2.57) to make the group's own exit status unreliable
# for write-failure detection: `if ! { cmd; } > "$file"; then` does not
# fire even when the redirect genuinely fails. This case forces a REAL
# write failure (mktemp fixture double chmod's the tmp file 0444 the
# instant it's created, so the very next statement's write hits a genuine
# permission-denied) and confirms the fix actually catches it: no POST goes
# out with a truncated/empty body, and the pending batch survives
# untouched for the next run. Not a grep for the pattern's absence — a
# reproduced failure that the surrounding code must detect.
##############################################################################
echo "--- 9. a genuinely failed audit-body write is detected, not silently POSTed ---"

FIXTURE9=$(mktemp -d)
USERS_ROOT9="$FIXTURE9/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG9="$FIXTURE9/agent-config.json"
make_users_fixture "$USERS_ROOT9" "alice" "$EXT_A"
make_config "$CFG9" "$EXT_A"
PATCHED_AC_CONFIG="$CFG9"
PATCHED_BER_USERS_DIR="$USERS_ROOT9"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":1}'
reset_mocks "$(mktemp -d)"
MOCK_CHMOD_BODY_TMP=1

OUT=$(ber_remove_extensions 2>&1)
RC=$?

MOCK_CHMOD_BODY_TMP=0

chk "returns 0 even though the audit-body write failed" "$(( RC == 0 ))"
chk "extension actually removed from disk (write failure is audit-path-only)" \
    "$(! ext_exists "$USERS_ROOT9" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "log reports the truncated/incomplete write" \
    "$([[ "$OUT" == *"audit POST body write appears truncated"* ]] && echo 1 || echo 0)"
chk "no POST attempted with the truncated body" "$(( $(curl_call_count) == 0 ))"
chk "pending file survives untouched, still holding the event" \
    "$([[ -f "$STATE_DIR/.enforcement-audit-pending.json" ]] && echo 1 || echo 0)"
chk "pending file holds exactly 1 event (nothing lost)" \
    "$(( $(pending_count "$STATE_DIR/.enforcement-audit-pending.json") == 1 ))"
chk "no leftover unwritable body tmp file in PATCHED_TMPDIR" \
    "$([[ -z "$(print -l "$PATCHED_TMPDIR"/patched-ber-audit.*(N) 2>/dev/null)" ]] && echo 1 || echo 0)"

##############################################################################
# 10. Observation-bound directives must not remove an installation whose
# on-disk extension directory is newer than the operator's approval boundary.
# A fresh approval after that observation may remove it.
##############################################################################
echo "--- 10. observation boundary prevents delayed removal of a reinstall ---"

FIXTURE10=$(mktemp -d)
USERS_ROOT10="$FIXTURE10/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG10="$FIXTURE10/agent-config.json"
make_users_fixture "$USERS_ROOT10" "alice" "$EXT_A"
printf '{"app_control":{"enabled":true,"extension_removals":[{"approved_before":"2099-01-01T00:00:00","browser":"chrome","extension_id":"%s","scope":"one_observation","user_account":"alice","profile":"Default"}]}}' "$EXT_A" > "$CFG10"
PATCHED_AC_CONFIG="$CFG10"
PATCHED_BER_USERS_DIR="$USERS_ROOT10"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":0}'
reset_mocks "$(mktemp -d)"
OUT=$(ber_remove_extensions 2>&1)
chk "offsetless approval timestamp is rejected" \
    "$(ext_exists "$USERS_ROOT10" "alice" "$EXT_A" && echo 1 || echo 0)"

printf '{"app_control":{"enabled":true,"extension_removals":[{"approved_before":"2000-01-01T00:00:00Z","browser":"chrome","extension_id":"%s","scope":"one_observation","user_account":"alice","profile":"Default"}]}}' "$EXT_A" > "$CFG10"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":0}'
reset_mocks "$(mktemp -d)"

OUT=$(ber_remove_extensions 2>&1)
chk "newer reinstall remains present after stale approval" \
    "$(ext_exists "$USERS_ROOT10" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "stale approval emits no completion evidence" "$(( $(curl_call_count) == 0 ))"

printf '{"app_control":{"enabled":true,"extension_removals":[{"approved_before":"2099-01-01T00:00:00Z","browser":"chrome","extension_id":"%s","scope":"one_observation","user_account":"alice","profile":"Default"}]}}' "$EXT_A" > "$CFG10"
MOCK_RESP_BODY='{"ingested":1}'
reset_mocks "$(mktemp -d)"
OUT=$(ber_remove_extensions 2>&1)
chk "fresh approval removes the captured installation" \
    "$(! ext_exists "$USERS_ROOT10" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "fresh approval emits one completion event" "$(( $(body_event_count "$(curl_last_body)") == 1 ))"

FF_PROFILE="$USERS_ROOT10/alice/Library/Application Support/Firefox/Profiles/abc.default"
mkdir -p "$FF_PROFILE/extensions"
printf 'xpi' > "$FF_PROFILE/extensions/$EXT_B.xpi"
printf '{"addons":[{"id":"%s"},{"id":"keep@x"}]}' "$EXT_B" > "$FF_PROFILE/extensions.json"
printf '{"app_control":{"enabled":true,"extension_removals":[{"approved_before":"2000-01-01T00:00:00Z","browser":"firefox","extension_id":"%s","scope":"one_observation","user_account":"alice","profile":"abc.default"}]}}' "$EXT_B" > "$CFG10"
MOCK_RESP_BODY='{"ingested":0}'
reset_mocks "$(mktemp -d)"
OUT=$(ber_remove_extensions 2>&1)
chk "newer Firefox reinstall remains present after stale approval" \
    "$([[ -f "$FF_PROFILE/extensions/$EXT_B.xpi" ]] && echo 1 || echo 0)"
chk "stale Firefox approval leaves extensions.json unchanged" \
    "$(grep -q "$EXT_B" "$FF_PROFILE/extensions.json" && echo 1 || echo 0)"

printf '{"app_control":{"enabled":true,"extension_removals":[{"approved_before":"2099-01-01T00:00:00Z","browser":"firefox","extension_id":"%s","scope":"one_observation","user_account":"alice","profile":"abc.default"}]}}' "$EXT_B" > "$CFG10"
MOCK_RESP_BODY='{"ingested":1}'
reset_mocks "$(mktemp -d)"
OUT=$(ber_remove_extensions 2>&1)
chk "fresh Firefox approval removes the captured XPI" \
    "$([[ ! -f "$FF_PROFILE/extensions/$EXT_B.xpi" ]] && echo 1 || echo 0)"
# PAT-1316: one_observation is the same removal as one_profile, just narrowed
# to one already-observed target by the server — once the approved_before
# boundary clears, extensions.json is pruned exactly like every other scope,
# not left behind (the earlier "leaves mutable metadata untouched" behaviour
# was a bug: the addon entry silently outlived the removed XPI on every
# successful one_observation removal).
chk "fresh Firefox approval also prunes the addons.json entry" \
    "$(! grep -q "$EXT_B" "$FF_PROFILE/extensions.json" && echo 1 || echo 0)"
chk "fresh Firefox approval emits one completion event" \
    "$(( $(body_event_count "$(curl_last_body)") == 1 ))"

##############################################################################
# 11. PAT-1316: a directive whose scope this agent build does not recognise
# must be reported, not silently dropped — a dropped directive was previously
# indistinguishable from one never sent, leaving the dashboard's removal
# request pending forever with no explanation. Verifies both halves: nothing
# is touched (fail-safe, same as any other rejected field) AND the rejection
# is loud, matching the adjacent field-validation REJECT lines' shape/stream.
##############################################################################
echo "--- 11. unrecognised scope is REJECTed loudly, not silently dropped ---"

FIXTURE11=$(mktemp -d)
USERS_ROOT11="$FIXTURE11/Users"
STATE_DIR=$(mktemp -d)
PATCHED_TMPDIR=$(mktemp -d)
CFG11="$FIXTURE11/agent-config.json"
make_users_fixture "$USERS_ROOT11" "alice" "$EXT_A"
printf '{"app_control":{"enabled":true,"extension_removals":[{"browser":"chrome","extension_id":"%s","scope":"some_future_scope","user_account":"alice","profile":"Default"}]}}' "$EXT_A" > "$CFG11"
PATCHED_AC_CONFIG="$CFG11"
PATCHED_BER_USERS_DIR="$USERS_ROOT11"
MOCK_HTTP_CODE="200"; MOCK_RESP_BODY='{"ingested":0}'
reset_mocks "$(mktemp -d)"
OUT=$(ber_remove_extensions 2>&1)
chk "unrecognised scope leaves the extension untouched" \
    "$(ext_exists "$USERS_ROOT11" "alice" "$EXT_A" && echo 1 || echo 0)"
chk "unrecognised scope emits an ext_removal: REJECT line naming it" \
    "$(print -r -- "$OUT" | grep -q "ext_removal: REJECT unrecognised scope.*some_future_scope" && echo 1 || echo 0)"
chk "unrecognised scope emits no completion evidence" "$(( $(curl_call_count) == 0 ))"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
