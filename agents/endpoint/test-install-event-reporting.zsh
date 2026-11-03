#!/bin/zsh
##############################################################################
# test-install-event-reporting.zsh — PAT-1243 regression guard.
#
# report_install_event() in patched-install.sh (PAT-651) used to POST a
# custom catalogue_install payload to POST /v1/agent-logs. That endpoint is
# exclusively the on-demand gzipped log-bundle request path (it requires an
# X-Patched-Log-Request-ID this call never sent) and correctly rejected
# every call with HTTP 400 — confirmed live in production on real Firefox
# and 1Password installs. The script's own comment claimed "will retry next
# run" but nothing was ever queued, so a successful install's outcome was
# silently lost forever.
#
# PAT-1243 remaps the same reporting onto the existing, working /v1/events
# audit-event contract (docs/audit-events-contract.md) that
# patched-update.sh's emit_audit_event()/drain_events_queue() (PAT-499)
# already ship, writing into the SAME durable ring-buffer queue
# ($EVENTS_QUEUE / $PATCHED_EVENTS_QUEUE).
#
# This tests report_install_event() directly: extracts the SHIPPED
# PATCHED_REPORT_INSTALL_EVENT block (sentinel markers) from
# patched-install.sh, not a copy, so the code under test is the code that
# ships (same convention as test-trigger-parsing.zsh). curl is stubbed so nothing
# touches the real network; compute_hmac/with_proxy/patched_curl_bearer are
# stubbed minimally so only the event-shipping logic itself is exercised.
#
# No root, no network. Run: zsh endpoint/test-install-event-reporting.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
INSTALL_SH="$SCRIPT_DIR/patched-install.sh"
PYTHON3="/usr/bin/python3"

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-install-event-block.XXXXXX")
awk '/PATCHED_REPORT_INSTALL_EVENT_START/{f=1;next} /PATCHED_REPORT_INSTALL_EVENT_END/{f=0} f' \
    "$INSTALL_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_REPORT_INSTALL_EVENT block from $INSTALL_SH"
    exit 1
fi

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.install-event-test.XXXXXX")
trap 'rm -rf "$WORK"; rm -f "$BLOCK_TMP"' EXIT

# run_report <post-http-code> <package_id> <package_source> <outcome> [<error>]
#   Sources the extracted block in a clean zsh subshell with every
#   collaborator report_install_event() calls stubbed:
#     - PYTHON3, EVENTS_QUEUE, EVENTS_QUEUE_MAX, API_URL, BEARER_TOKEN,
#       TENANT_ID, HW_UUID: same-shaped globals the real script sets before
#       ever reaching this function.
#     - with_proxy: passthrough (no proxy configured in the test).
#     - compute_hmac: stubbed (HMAC computation itself is covered by
#       test-hmac-v3.zsh; this test only cares that "events" scope is
#       passed, asserted separately below via a static grep).
#     - patched_curl_bearer / curl: stubbed to return the given HTTP code
#       without touching the network, and to record the POSTed body and URL
#       so the test can assert on the envelope that was actually shipped.
#   Prints the function's stdout; queue contents are inspected by the caller
#   directly via $EVENTS_QUEUE (one fresh dir per invocation).
run_report() {
    local http_code="$1" pkg_id="$2" pkg_src="$3" outcome="$4" err="${5:-}"
    local q; q=$(mktemp -d "$WORK/evq.XXXXXX")
    local capture="$WORK/last-post-body.json"
    local capture_url="$WORK/last-post-url.txt"
    rm -f "$capture" "$capture_url"

    PAT1243_HTTP_CODE="$http_code" \
    PAT1243_CAPTURE="$capture" \
    PAT1243_CAPTURE_URL="$capture_url" \
    EVQ="$q" \
    zsh -c '
        set -u
        PYTHON3="/usr/bin/python3"
        EVENTS_QUEUE="$EVQ"
        EVENTS_QUEUE_MAX=1000
        API_URL="https://api.test.invalid"
        BEARER_TOKEN="test-bearer-token"
        TENANT_ID="11111111-1111-1111-1111-111111111111"
        HW_UUID="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

        with_proxy() { shift; "$@"; }
        compute_hmac() { echo "stub-signature"; }
        # patched_curl_bearer mirrors the real helper (feeds the bearer token
        # over stdin, forwards the rest to curl) so the real code path is
        # exercised; only curl itself is stubbed.
        patched_curl_bearer() {
            local _token="$1"; shift
            printf "Authorization: Bearer %s\n" "$_token" | curl -H @- "$@"
        }
        curl() {
            local body_file="" url=""
            while (( $# )); do
                case "$1" in
                    --data-binary) body_file="${2#@}"; shift 2 ;;
                    -X) shift 2 ;;
                    http*) url="$1"; shift ;;
                    *) shift ;;
                esac
            done
            [[ -n "$body_file" && -f "$body_file" ]] && cp "$body_file" "$PAT1243_CAPTURE"
            [[ -n "$url" ]] && print -r -- "$url" > "$PAT1243_CAPTURE_URL"
            printf "%s" "$PAT1243_HTTP_CODE"
        }
        source "$0"
        report_install_event "$1" "$2" "$3" "$4"
    ' "$BLOCK_TMP" "$pkg_id" "$pkg_src" "$outcome" "$err" 2>&1

    print -r -- "$q" > "$WORK/last-queue-dir"
}

queue_files() {
    local q="$1"
    local -a f
    f=("$q"/evt-*.json(N))
    print -r -- "${#f}"
}

field() {  # field <json-file> <key>  (prints python repr-free string, "None" if null)
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
v = d.get(sys.argv[2], '__MISSING__')
print('None' if v is None else v)
" "$1" "$2"
}

has_key() {  # has_key <json-file> <key>
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if sys.argv[2] in d else 1)
" "$1" "$2"
}

no_stale_keys() {  # no_stale_keys <json-file> <key1> [<key2> ...] — true (0) iff NONE are present
    local f="$1"; shift
    local k
    for k in "$@"; do
        has_key "$f" "$k" && return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
echo "[1] success outcome -> install_completed, well-formed envelope, no package_source"
run_report 200 "googlechrome" "vendor" "success" "" > /dev/null
q=$(cat "$WORK/last-queue-dir")
chk "delivered on 2xx: queue is empty afterward" "$([[ "$(queue_files "$q")" == "0" ]] && echo 1 || echo 0)"
chk "POST body was captured" "$([[ -f "$WORK/last-post-body.json" ]] && echo 1 || echo 0)"
chk "event_type is install_completed" \
    "$([[ "$(field "$WORK/last-post-body.json" event_type)" == "install_completed" ]] && echo 1 || echo 0)"
chk "label is the package_id" \
    "$([[ "$(field "$WORK/last-post-body.json" label)" == "googlechrome" ]] && echo 1 || echo 0)"
chk "platform is macos" \
    "$([[ "$(field "$WORK/last-post-body.json" platform)" == "macos" ]] && echo 1 || echo 0)"
chk "device_id is HW_UUID" \
    "$([[ "$(field "$WORK/last-post-body.json" device_id)" == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" ]] && echo 1 || echo 0)"
chk "tenant_id is TENANT_ID" \
    "$([[ "$(field "$WORK/last-post-body.json" tenant_id)" == "11111111-1111-1111-1111-111111111111" ]] && echo 1 || echo 0)"
chk "reason is null on a success outcome" \
    "$([[ "$(field "$WORK/last-post-body.json" reason)" == "None" ]] && echo 1 || echo 0)"
chk "version is null" \
    "$([[ "$(field "$WORK/last-post-body.json" version)" == "None" ]] && echo 1 || echo 0)"
chk "no package_source field anywhere in the envelope" \
    "$(has_key "$WORK/last-post-body.json" package_source && echo 0 || echo 1)"
chk "no bare 'event'/'outcome'/'package_id'/'package_source' keys survive from the old agent-logs shape" \
    "$(no_stale_keys "$WORK/last-post-body.json" event outcome package_id package_source && echo 1 || echo 0)"
chk "POSTed to /v1/events" \
    "$([[ "$(cat "$WORK/last-post-url.txt" 2>/dev/null)" == *"/v1/events" ]] && echo 1 || echo 0)"
chk "never POSTed to /v1/agent-logs" \
    "$([[ "$(cat "$WORK/last-post-url.txt" 2>/dev/null)" != *"/v1/agent-logs"* ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[2] already_installed outcome -> also install_completed (deliberate PAT-1243 mapping)"
run_report 200 "slack" "vendor" "already_installed" "" > /dev/null
q=$(cat "$WORK/last-queue-dir")
chk "event_type is install_completed for already_installed" \
    "$([[ "$(field "$WORK/last-post-body.json" event_type)" == "install_completed" ]] && echo 1 || echo 0)"
chk "queue drained on delivery" "$([[ "$(queue_files "$q")" == "0" ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[3] failed outcome -> install_failed, reason carries the error message"
run_report 200 "1password" "vendor" "failed" "Installomator exited 1" > /dev/null
chk "event_type is install_failed" \
    "$([[ "$(field "$WORK/last-post-body.json" event_type)" == "install_failed" ]] && echo 1 || echo 0)"
chk "reason carries the error message" \
    "$([[ "$(field "$WORK/last-post-body.json" reason)" == "Installomator exited 1" ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# The actual bug this ticket fixes: PAT-651's original code claimed "will
# retry next run" on a failed POST but never actually queued anything, so a
# real install outcome (including successful ones) was silently lost
# forever. This is the regression test for that.
echo "[4] POST failure (simulated non-2xx) -> event file is LEFT in the queue, not deleted"
run_report 400 "firefox" "vendor" "success" "" > /dev/null
q=$(cat "$WORK/last-queue-dir")
chk "exactly one event file remains queued after a failed delivery" \
    "$([[ "$(queue_files "$q")" == "1" ]] && echo 1 || echo 0)"
_left=("$q"/evt-*.json(N))
chk "the queued file is well-formed JSON with the right event_type" \
    "$([[ -n "${_left[1]:-}" && "$(field "${_left[1]}" event_type)" == "install_completed" ]] && echo 1 || echo 0)"
chk "the queued filename matches the evt-<ms>-<random>.json convention drain_events_queue globs" \
    "$([[ "${_left[1]:t}" == evt-*-*.json && "${_left[1]:t}" != *XXXXXX* ]] && echo 1 || echo 0)"

echo "[4b] network-unreachable POST (simulated 000) -> event file is also LEFT in the queue"
run_report 000 "1password" "vendor" "failed" "network unreachable" > /dev/null
q=$(cat "$WORK/last-queue-dir")
chk "exactly one event file remains queued after an unreachable POST" \
    "$([[ "$(queue_files "$q")" == "1" ]] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[5] PATCHED_EVENTS_QUEUE points patched-install.sh at the shared override"
chk "EVENTS_QUEUE reads PATCHED_EVENTS_QUEUE with the same default as patched-update.sh" \
    "$(grep -qE 'EVENTS_QUEUE="\$\{PATCHED_EVENTS_QUEUE:-/var/db/patched/events-queue\}"' "$INSTALL_SH" && echo 1 || echo 0)"
chk "EVENTS_QUEUE directory is created alongside the other state dirs" \
    "$(grep -qE 'mkdir -p .*EVENTS_QUEUE' "$INSTALL_SH" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
echo "[6] HMAC scope is 'events', not 'agent_logs'"
chk "compute_hmac is called with the events scope" \
    "$(grep -q 'compute_hmac "\$ev_file" "events" "\$ts" "\$nonce"' "$INSTALL_SH" && echo 1 || echo 0)"
chk "report_install_event no longer signs with the agent_logs scope" \
    "$(grep -q '"agent_logs"' "$BLOCK_TMP" && echo 0 || echo 1)"
# The block's header comment legitimately still mentions "/v1/agent-logs" to
# explain the bug being fixed, so this checks the actual URL construction
# (the string a POST would resolve to), not every mention of the substring.
chk "report_install_event no longer constructs a POST to \$API_URL/v1/agent-logs" \
    "$(grep -q '\$API_URL/v1/agent-logs' "$BLOCK_TMP" && echo 0 || echo 1)"
chk "report_install_event does construct a POST to \$API_URL/v1/events" \
    "$(grep -q '\$API_URL/v1/events' "$BLOCK_TMP" && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
