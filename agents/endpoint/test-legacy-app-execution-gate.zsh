#!/bin/zsh
##############################################################################
# PAT-1481 regression test: every retained macOS legacy executor accepts only
# a fresh verified config heartbeat, an unsuspended device, and the exact JSON
# boolean true from one immutable snapshot before the engine can be reached.
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

pass=0
fail=0
check() {
    local description="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        ((pass++))
        print "  PASS: $description"
    else
        ((fail++))
        print "  FAIL: $description (expected $expected, got $actual)"
    fi
}
check_present() {
    local description="$1" count="$2"
    if (( count > 0 )); then
        ((pass++))
        print "  PASS: $description"
    else
        ((fail++))
        print "  FAIL: $description (not found)"
    fi
}
check_gate_near_call() {
    local script="$1" needle="$2" max_lines="$3" line start
    # A comment may legitimately quote the executable call. Gate the actual
    # final invocation, which is the last occurrence in these executors.
    line=$(grep -n -F -- "$needle" "$script" | tail -1 | cut -d: -f1)
    start=$(( ${line:-0} - max_lines ))
    (( start < 1 )) && start=1
    if [[ -n "$line" ]] && sed -n "${start},${line}p" "$script" | grep -q 'legacy_app_execution_enabled; then'; then
        ((pass++))
        print "  PASS: gate remains immediately before $needle in ${script:t}"
    else
        ((fail++))
        print "  FAIL: gate is missing before $needle in ${script:t}"
    fi
}
check_gate_at_function_start() {
    local script="$1" function_name="$2" line end
    line=$(grep -n -F -- "$function_name() {" "$script" | head -1 | cut -d: -f1)
    end=$(( ${line:-0} + 15 ))
    if [[ -n "$line" ]] && sed -n "${line},${end}p" "$script" | grep -q 'if ! legacy_app_execution_enabled'; then
        ((pass++))
        print "  PASS: gate remains at $function_name entry seam in ${script:t}"
    else
        ((fail++))
        print "  FAIL: gate is missing at $function_name entry seam in ${script:t}"
    fi
}
check_uninstall_action_gates() {
    local result
    result=$("$PYTHON3" - "$SCRIPT_DIR/patched-uninstall.sh" <<'PYEOF'
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("execute_uninstall_macos() {"))
end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("# VERIFY REMOVAL"))
actions = ("pkgutil --forget", 'timeout 120 "$method_detail"', 'open -W "$method_detail"', "rm -rf ")
checked = 0
for index, line in enumerate(lines[start:end], start):
    if line.lstrip().startswith("#") or not any(action in line for action in actions):
        continue
    checked += 1
    preceding = lines[max(start, index - 2):index]
    if not any(
        "legacy_removal_action_allowed || return 2" in prior
        or "if ! legacy_app_execution_enabled" in prior
        for prior in preceding
    ):
        print("missing")
        raise SystemExit(1)

if checked == 0:
    print("missing")
    raise SystemExit(1)
quit_index = next(i for i, line in enumerate(lines) if line.startswith("request_quit_macos() {"))
quit_end = next(i for i in range(quit_index + 1, len(lines)) if lines[i].startswith("# METHOD RESOLUTION"))
for index in range(quit_index, quit_end):
    if "/usr/bin/osascript" not in lines[index]:
        continue
    if not any("if ! legacy_app_execution_enabled" in prior for prior in lines[max(quit_index, index - 6):index]):
        print("missing")
        raise SystemExit(1)
    break
else:
    print("missing")
    raise SystemExit(1)
print("ok")
PYEOF
)
    check "every uninstall mutation has its immediate gate" "$result" "ok"
}

check_update_uninstall_trigger_gate() {
    local result
    result=$("$PYTHON3" - "$SCRIPT_DIR/patched-update.sh" <<'PYEOF'
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next(i for i, line in enumerate(lines) if 'elif [[ "$TRIG_TYPE" == "uninstall" ]]' in line)
# PAT-1620 removed the deploy elif that used to close this block; the block's
# real end is the sibling `else` at the same indentation as the uninstall
# elif itself (4 spaces) -- not the deeper-nested `else` inside the uninstall
# handling (the "patched-uninstall.sh not found" case, 8 spaces).
indent = len(lines[start]) - len(lines[start].lstrip(" "))
end = next(i for i in range(start + 1, len(lines))
           if lines[i] == " " * indent + "else")
block = lines[start:end]
gate = next(i for i, line in enumerate(block) if 'if ! legacy_app_execution_enabled; then' in line)
engine_branch = next(i for i, line in enumerate(block) if 'elif [[ -x "$_uninst_engine" ]]; then' in line)
invoke = next(i for i, line in enumerate(block) if '"$_uninst_engine" --app-id' in line)
refusal_record = next(i for i, line in enumerate(block)
                      if 'record_uninstall_trigger_authority_refusal' in line)

# The executor must be inside the enabled `elif`, not merely after a disabled
# branch which logs and then falls through to the loop.
if not (gate < refusal_record < engine_branch < invoke):
    raise SystemExit(1)
if not any('log_jsonl "warn" "legacy app-execution gate: refusing uninstall trigger"' in line
           for line in block[gate:engine_branch]):
    raise SystemExit(1)
print("ok")
PYEOF
)
    check "disabled uninstall trigger records its refusal before the executor branch" "$result" "ok"
}

check_update_uninstall_trigger_refusal_payload() {
    local refusal_file parse_file trigger_file
    refusal_file="$WORKDIR/uninstall-trigger-refusal.zsh"
    parse_file="$WORKDIR/parse-trigger.zsh"
    trigger_file="$WORKDIR/refused-uninstall.trigger"
    awk '/PATCHED_UNINSTALL_TRIGGER_REFUSAL_START/{copy=1; next} /PATCHED_UNINSTALL_TRIGGER_REFUSAL_END/{copy=0} copy' \
        "$SCRIPT_DIR/patched-update.sh" > "$refusal_file"
    awk '/PATCHED_TRIGGER_PARSE_START/{copy=1; next} /PATCHED_TRIGGER_PARSE_END/{copy=0} copy' \
        "$SCRIPT_DIR/patched-update.sh" > "$parse_file"
    print -r -- '{"type":"uninstall","labels":["Acme App","Acme App","Example Tool"]}' > "$trigger_file"

    local result
    result=$(
        source "$refusal_file"
        source "$parse_file"
        refusal_state_dir="$WORKDIR/refused-uninstall-state"
        mkdir -p "$refusal_state_dir"
        STATE_DIR="$refusal_state_dir"
        BUNDLE_DIR="$WORKDIR/no-removal-engine"
        PYTHON3=/usr/bin/python3
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        legacy_app_execution_enabled() { return 1; }
        log_jsonl() { :; }
        typeset -i provenance_count=0
        queue_provenance() {
            local provenance_source
            for provenance_source in "$@"; do
                ((provenance_count++))
                cp "$provenance_source" "$WORKDIR/refused-uninstall-provenance-${provenance_count}.json"
            done
        }
        parse_trigger "$trigger_file" >/dev/null
        "$PYTHON3" - "$SCRIPT_DIR/../contracts/uninstall-status.schema.json" \
            "$refusal_state_dir/uninstall-status.json" \
            "$WORKDIR" <<'PYEOF'
import glob, json, jsonschema, os, sys

schema = json.load(open(sys.argv[1]))
status = json.load(open(sys.argv[2]))
records = [json.load(open(filename)) for filename in sorted(
    glob.glob(os.path.join(sys.argv[3], 'refused-uninstall-provenance-*.json')))]
jsonschema.validate(status, schema, format_checker=jsonschema.FormatChecker())
expected_names = {'Acme App', 'Example Tool'}
status_rows = status['removals']
if len(status_rows) != 2 or {row['name'] for row in status_rows} != expected_names:
    raise SystemExit(1)
if any(
    row['entry_id'] != 0
    or row['outcome'] != 'authority_refused'
    or row['verify_result'] != 'not_checked'
    or row['method'] != 'none'
    for row in status_rows
):
    raise SystemExit(1)
if (os.stat(sys.argv[2]).st_mode & 0o777) != 0o644:
    raise SystemExit(1)
if len(records) != 2 or {record['app']['name'] for record in records} != expected_names:
    raise SystemExit(1)
for record in records:
    if not (
        record['record_type'] == 'app_uninstall'
        and record['schema_version'] == 1
        and record['tenant_id'] == 'tenant-test'
        and record['device'] == {'hw_uuid': 'device-test', 'computer_name': 'test-mac'}
        and record['app'] == {
            'entry_id': 0,
            'name': record['app']['name'],
            'publisher': None,
            'platform': 'macos',
            'match_mode': 'trigger_identifier',
        }
        and record['uninstall'] == {
            'method': 'none',
            'method_detail': None,
            'queued_at': record['recorded_at'],
            'window_hours': 24,
        }
        and record['outcome'] == 'authority_refused'
        and record['verify_result'] == 'not_checked'
        and record['failure_class'] == 'hard'
        and not any('signer' in key or 'unsigned' in key for key in record)
    ):
        raise SystemExit(1)
print('ok')
PYEOF
    )
    check "refused uninstall trigger deduplicates identifiers in status and terminal provenance" \
        "$result" "ok"

    local race_trigger race_state race_bundle race_result
    race_trigger="$WORKDIR/refused-uninstall-child-race.trigger"
    race_state="$WORKDIR/refused-uninstall-child-race-state"
    race_bundle="$WORKDIR/refused-uninstall-child-race-bundle"
    mkdir -p "$race_state" "$race_bundle"
    print -r -- '{"type":"uninstall","labels":["Race App"]}' > "$race_trigger"
    print '#!/bin/sh' > "$race_bundle/patched-uninstall.sh"
    print 'exit 42' >> "$race_bundle/patched-uninstall.sh"
    chmod 755 "$race_bundle/patched-uninstall.sh"
    race_result=$(
        source "$refusal_file"
        source "$parse_file"
        STATE_DIR="$race_state"
        BUNDLE_DIR="$race_bundle"
        PYTHON3=/usr/bin/python3
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=42
        legacy_app_execution_enabled() { return 0; }
        log_jsonl() { :; }
        typeset -i queued_count=0
        queue_provenance() { ((queued_count += $#)); }
        parse_trigger "$race_trigger" >/dev/null
        "$PYTHON3" - "$race_state/uninstall-status.json" "$queued_count" <<'PYEOF'
import json, sys
rows = json.load(open(sys.argv[1]))['removals']
ok = (
    len(rows) == 1
    and rows[0]['name'] == 'Race App'
    and rows[0]['outcome'] == 'authority_refused'
    and int(sys.argv[2]) == 1
)
print('ok' if ok else 'bad')
PYEOF
    )
    check "child entry-gate revocation is converted into terminal parent refusal evidence" \
        "$race_result" "ok"

    local partial_trigger partial_state partial_bundle partial_result
    partial_trigger="$WORKDIR/refused-uninstall-partial.trigger"
    partial_state="$WORKDIR/refused-uninstall-partial-state"
    partial_bundle="$WORKDIR/refused-uninstall-partial-bundle"
    mkdir -p "$partial_state" "$partial_bundle"
    print -r -- '{"type":"uninstall","labels":["Alpha","Beta","Gamma"]}' > "$partial_trigger"
    {
        print '#!/bin/zsh'
        print 'case "$2" in'
        print '  Alpha)'
        print '    print -r -- '\''{"schema_version":1,"generated_at":"2026-09-08T10:00:01Z","last_run":{"started_at":"2026-09-08T10:00:00Z","finished_at":"2026-09-08T10:00:01Z"},"removals":[{"entry_id":7,"name":"Alpha","outcome":"removed","verify_result":"gone","method":"app_bundle","recorded_at":"2026-09-08T10:00:01Z"}]}'\'' > "${PATCHED_STATE_DIR}/uninstall-status.json"'
        print '    exit 0 ;;'
        print '  Beta) exit 42 ;;'
        print '  *) print -r -- "$2" >> "${PATCHED_STATE_DIR}/unexpected-child.log"; exit 0 ;;'
        print 'esac'
    } > "$partial_bundle/patched-uninstall.sh"
    chmod 755 "$partial_bundle/patched-uninstall.sh"
    partial_result=$(
        source "$refusal_file"
        source "$parse_file"
        STATE_DIR="$partial_state"
        PATCHED_STATE_DIR="$partial_state"
        export PATCHED_STATE_DIR
        BUNDLE_DIR="$partial_bundle"
        PYTHON3=/usr/bin/python3
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        LEGACY_EXECUTION_AUTHORITY_REFUSED_EXIT=42
        legacy_app_execution_enabled() { return 0; }
        log_jsonl() { :; }
        refusal_names_file="$partial_state/refusal-names"
        queue_provenance() {
            local provenance_source
            for provenance_source in "$@"; do
                "$PYTHON3" - "$provenance_source" >> "$refusal_names_file" <<'PYEOF'
import json, sys
print(json.load(open(sys.argv[1]))['app']['name'])
PYEOF
            done
        }
        parse_trigger "$partial_trigger" >/dev/null
        "$PYTHON3" - "$partial_state/uninstall-status.json" "$refusal_names_file" \
            "$partial_state/unexpected-child.log" <<'PYEOF'
import json, os, sys
rows = json.load(open(sys.argv[1]))['removals']
names = [line.strip() for line in open(sys.argv[2]) if line.strip()]
ok = (
    [(row['name'], row['outcome']) for row in rows]
        == [('Alpha', 'removed'), ('Beta', 'authority_refused'),
            ('Gamma', 'authority_refused')]
    and names == ['Beta', 'Gamma']
    and not os.path.exists(sys.argv[3])
)
print('ok' if ok else 'bad')
PYEOF
    )
    check "mid-trigger child revocation preserves Alpha and refuses only Beta plus unprocessed identifiers" \
        "$partial_result" "ok"

    # The first dynamic case runs in a command substitution to isolate its
    # fixtures. Source the same extracted shipping helper for the hostile-input
    # and cap cases below.
    source "$refusal_file"
    local huge_trigger huge_state huge_result
    huge_trigger="$WORKDIR/refused-uninstall-huge-identifier.trigger"
    huge_state="$WORKDIR/refused-uninstall-huge-identifier-state"
    "$PYTHON3" - "$huge_trigger" <<'PYEOF'
import json, sys
json.dump({'type': 'uninstall', 'labels': ['A' * 10000]}, open(sys.argv[1], 'w'))
PYEOF
    huge_result=$(
        STATE_DIR="$huge_state"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        mkdir -p "$STATE_DIR"
        typeset -i provenance_count=0
        queue_provenance() { ((provenance_count += $#)); }
        record_uninstall_trigger_authority_refusal "$huge_trigger" >/dev/null
        "$PYTHON3" - "$STATE_DIR/uninstall-status.json" "$provenance_count" <<'PYEOF'
import json, sys
status = json.load(open(sys.argv[1]))
print('ok' if status['removals'] == [] and int(sys.argv[2]) == 0 else 'bad')
PYEOF
    )
    check "refused uninstall trigger rejects an overlong identifier without a row or upload" \
        "$huge_result" "ok"

    local nonarray_trigger nonarray_state nonarray_result
    nonarray_trigger="$WORKDIR/refused-uninstall-nonarray.trigger"
    nonarray_state="$WORKDIR/refused-uninstall-nonarray-state"
    print -r -- '{"type":"uninstall","labels":{"0":"Example"}}' > "$nonarray_trigger"
    nonarray_result=$(
        STATE_DIR="$nonarray_state"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        mkdir -p "$STATE_DIR"
        typeset -i provenance_count=0
        queue_provenance() { ((provenance_count += $#)); }
        record_uninstall_trigger_authority_refusal "$nonarray_trigger" >/dev/null
        "$PYTHON3" - "$STATE_DIR/uninstall-status.json" "$provenance_count" <<'PYEOF'
import json, sys
status = json.load(open(sys.argv[1]))
print('ok' if status['removals'] == [] and int(sys.argv[2]) == 0 else 'bad')
PYEOF
    )
    check "refused uninstall trigger requires labels to be an array" \
        "$nonarray_result" "ok"

    local duplicate_trigger duplicate_state duplicate_result
    duplicate_trigger="$WORKDIR/refused-uninstall-duplicates.trigger"
    duplicate_state="$WORKDIR/refused-uninstall-duplicates-state"
    "$PYTHON3" - "$duplicate_trigger" <<'PYEOF'
import json, sys
json.dump({'type': 'uninstall', 'labels': ['Repeated'] * 200 + ['Beyond examined cap']}, open(sys.argv[1], 'w'))
PYEOF
    duplicate_result=$(
        STATE_DIR="$duplicate_state"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        mkdir -p "$STATE_DIR"
        typeset -i provenance_count=0
        queue_provenance() { ((provenance_count += $#)); }
        record_uninstall_trigger_authority_refusal "$duplicate_trigger" >/dev/null
        "$PYTHON3" - "$STATE_DIR/uninstall-status.json" "$provenance_count" <<'PYEOF'
import json, sys
status = json.load(open(sys.argv[1]))
names = [row['name'] for row in status['removals']]
print('ok' if names == ['Repeated'] and int(sys.argv[2]) == 1 else 'bad')
PYEOF
    )
    check "refused uninstall trigger deduplicates and examines only the bounded prefix" \
        "$duplicate_result" "ok"

    local over_limit_trigger over_limit_state over_limit_result
    over_limit_trigger="$WORKDIR/refused-uninstall-over-limit.trigger"
    over_limit_state="$WORKDIR/refused-uninstall-over-limit-state"
    "$PYTHON3" - "$over_limit_trigger" <<'PYEOF'
import json, sys
json.dump({'type': 'uninstall', 'labels': [f'App {index}' for index in range(64)]}, open(sys.argv[1], 'w'))
PYEOF
    over_limit_result=$(
        STATE_DIR="$over_limit_state"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        mkdir -p "$STATE_DIR"
        typeset -i provenance_count=0
        queue_provenance() { ((provenance_count += $#)); }
        record_uninstall_trigger_authority_refusal "$over_limit_trigger" >/dev/null
        "$PYTHON3" - "$STATE_DIR/uninstall-status.json" "$provenance_count" <<'PYEOF'
import json, sys

status = json.load(open(sys.argv[1]))
names = [row['name'] for row in status['removals']]
maximum = 32
if len(names) != maximum or int(sys.argv[2]) != maximum:
    raise SystemExit(1)
if names != [f'App {index}' for index in range(maximum)]:
    raise SystemExit(1)
print('ok')
PYEOF
    )
    check "refused uninstall trigger caps synchronous status and provenance work at 32 identifiers" \
        "$over_limit_result" "ok"

    local utf8_trigger utf8_state utf8_result
    utf8_trigger="$WORKDIR/refused-uninstall-utf8-limit.trigger"
    utf8_state="$WORKDIR/refused-uninstall-utf8-limit-state"
    "$PYTHON3" - "$utf8_trigger" <<'PYEOF'
import json, sys
json.dump({'type': 'uninstall', 'labels': ['é' * 129]}, open(sys.argv[1], 'w'))
PYEOF
    utf8_result=$(
        STATE_DIR="$utf8_state"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        mkdir -p "$STATE_DIR"
        typeset -i provenance_count=0
        queue_provenance() { ((provenance_count += $#)); }
        record_uninstall_trigger_authority_refusal "$utf8_trigger" >/dev/null
        "$PYTHON3" - "$STATE_DIR/uninstall-status.json" "$provenance_count" <<'PYEOF'
import json, sys
status = json.load(open(sys.argv[1]))
print('ok' if status['removals'] == [] and int(sys.argv[2]) == 0 else 'bad')
PYEOF
    )
    check "refused uninstall trigger enforces the UTF-8 byte limit independently" \
        "$utf8_result" "ok"

    local oversized_trigger oversized_state oversized_result
    oversized_trigger="$WORKDIR/refused-uninstall-oversized.trigger"
    oversized_state="$WORKDIR/refused-uninstall-oversized-state"
    "$PYTHON3" - "$oversized_trigger" <<'PYEOF'
import sys
with open(sys.argv[1], 'wb') as handle:
    handle.write(b'{"type":"uninstall","labels":["')
    handle.write(b'A' * 70000)
    handle.write(b'"]}')
PYEOF
    oversized_result=$(
        STATE_DIR="$oversized_state"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        mkdir -p "$STATE_DIR"
        typeset -i provenance_count=0
        queue_provenance() { ((provenance_count += $#)); }
        record_uninstall_trigger_authority_refusal "$oversized_trigger" >/dev/null
        "$PYTHON3" - "$STATE_DIR/uninstall-status.json" "$provenance_count" <<'PYEOF'
import json, sys
status = json.load(open(sys.argv[1]))
print('ok' if status['removals'] == [] and int(sys.argv[2]) == 0 else 'bad')
PYEOF
    )
    check "refused uninstall reporting rejects an oversized trigger before JSON expansion" \
        "$oversized_result" "ok"
}

check_refusal_queue_bounds() {
    local provenance_file="$WORKDIR/provenance-queue.zsh"
    local refusal_file="$WORKDIR/refusal-queue-writer.zsh"
    awk '/PATCHED_PROVENANCE_QUEUE_START/{copy=1; next} /PATCHED_PROVENANCE_QUEUE_END/{copy=0} copy' \
        "$SCRIPT_DIR/patched-update.sh" > "$provenance_file"
    awk '/PATCHED_UNINSTALL_TRIGGER_REFUSAL_START/{copy=1; next} /PATCHED_UNINSTALL_TRIGGER_REFUSAL_END/{copy=0} copy' \
        "$SCRIPT_DIR/patched-update.sh" > "$refusal_file"

    local result
    result=$(
        source "$provenance_file"
        source "$refusal_file"
        STATE_DIR="$WORKDIR/repeated-refusal-state"
        PROV_QUEUE="$WORKDIR/repeated-refusal-queue"
        mkdir -p "$STATE_DIR" "$PROV_QUEUE"
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        PYTHON3=/usr/bin/python3

        local cycle trigger_file
        for cycle in {0..5}; do
            trigger_file="$WORKDIR/repeated-refusal-${cycle}.trigger"
            "$PYTHON3" - "$trigger_file" "$cycle" <<'PYEOF'
import json, sys
cycle = int(sys.argv[2])
json.dump({
    'type': 'uninstall',
    'labels': [f'Cycle {cycle} App {index}' for index in range(32)],
}, open(sys.argv[1], 'w'))
PYEOF
            record_uninstall_trigger_authority_refusal "$trigger_file" >/dev/null
        done

        local before_calls="$PROVENANCE_NETWORK_ATTEMPTS"
        local queue_count queue_bytes status_count
        queue_count=$(find "$PROV_QUEUE" -type f -name 'prov-*.json' | wc -l | tr -d '[:space:]')
        queue_bytes=$(find "$PROV_QUEUE" -type f -name 'prov-*.json' -exec stat -f %z {} \; | awk '{s+=$1} END{print s+0}')
        status_count=$("$PYTHON3" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["removals"]))' "$STATE_DIR/uninstall-status.json")

        compute_hmac() { print test-signature; }
        with_proxy() { shift; "$@"; }
        patched_curl_bearer() {
            local args="$*"
            print -r -- "$args" >> "$WORKDIR/refusal-network-attempts.log"
            print 000
        }
        BEARER_TOKEN=test
        API_URL=https://example.invalid
        rm -f "$WORKDIR/refusal-network-attempts.log"
        drain_provenance_queue >/dev/null
        local attempts=0
        [[ -f "$WORKDIR/refusal-network-attempts.log" ]] && \
            attempts=$(wc -l < "$WORKDIR/refusal-network-attempts.log" | tr -d '[:space:]')
        local timeout_count=0
        [[ -f "$WORKDIR/refusal-network-attempts.log" ]] && \
            timeout_count=$(grep -c -- '--max-time 5' "$WORKDIR/refusal-network-attempts.log")

        print -r -- "$queue_count|$queue_bytes|$status_count|$before_calls|$attempts|$timeout_count"
    )
    local queue_count queue_bytes status_count before_calls attempts timeout_count
    IFS='|' read -r queue_count queue_bytes status_count before_calls attempts timeout_count <<< "$result"
    check "repeated 32-ID refusal triggers retain only the 128-record disk ring" "$queue_count" "128"
    check "refusal status preserves the latest trigger's 32 terminal rows" "$status_count" "32"
    check "refusal recording performs no synchronous network attempts" "$before_calls" "0"
    check "one drain cycle attempts at most four provenance deliveries" "$attempts" "4"
    check "every bounded drain attempt uses the five-second timeout" "$timeout_count" "4"
    if (( queue_bytes <= 2 * 1024 * 1024 )); then
        ((pass++)); print "  PASS: repeated refusal queue stays within the 2 MiB byte cap"
    else
        ((fail++)); print "  FAIL: refusal queue exceeded byte cap ($queue_bytes bytes)"
    fi
}

check_shared_evaluator_contract() {
    local result
    result=$("$PYTHON3" - "$SCRIPT_DIR/patched-legacy-app-execution-gate.py" <<'PYEOF'
import ast
import sys

source = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(source)
main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
body = ast.get_source_segment(source, main)

 # These structural checks complement the dynamic cases below. The evaluator
 # opens root-owned directories and files through no-follow descriptors, reads
 # one bounded snapshot, and checks revocation around the decision.
required = (
    "CONFIG_HEARTBEAT_MAX_AGE_SECONDS = 24 * 60 * 60",
    "MAX_CONFIG_BYTES = 1024 * 1024",
    "metadata.st_uid == 0",
    "os.O_DIRECTORY | os.O_NOFOLLOW",
    "os.open(filename, flags, dir_fd=directory_fd)",
    "os.fstat(file_fd)",
    "stat.S_ISREG(metadata.st_mode)",
    "age = time.time() - heartbeat_metadata.st_mtime",
    "if age < 0 or age > CONFIG_HEARTBEAT_MAX_AGE_SECONDS:",
    "snapshot = _read_bounded(config_fd, MAX_CONFIG_BYTES)",
    "hashlib.sha256(snapshot)",
    "object_pairs_hook=_reject_duplicate_keys",
    "type(config.get(\"legacy_app_execution_enabled\")) is not bool",
    "_path_still_names_open_file(",
)
if any(item not in source for item in required):
    raise SystemExit(1)
if source.count('if _entry_exists(credentials_fd, "suspended"):') != 2:
    raise SystemExit(1)
if source.count('if _entry_exists(state_fd, EXECUTION_DENIAL_FILENAME):') != 2:
    raise SystemExit(1)
if body.index('if _entry_exists(credentials_fd, "suspended"):') >= body.index("snapshot = _read_bounded(config_fd, MAX_CONFIG_BYTES)"):
    raise SystemExit(1)
second_check = body.index('if _entry_exists(credentials_fd, "suspended"):', body.index("snapshot = _read_bounded(config_fd, MAX_CONFIG_BYTES)"))
if second_check <= body.index("json.loads(snapshot.decode(\"utf-8\"), object_pairs_hook=_reject_duplicate_keys)"):
    raise SystemExit(1)
print("ok")
PYEOF
)
    check "shared evaluator rechecks denial, heartbeat identity and suspension after its trusted bounded snapshot" "$result" "ok"
}

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/patched-legacy-execution.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT
AGENT_CONFIG_FILE="$WORKDIR/agent-config.json"
AGENT_CONFIG_SHA256_FILE="$WORKDIR/agent-config.sha256"
AGENT_CONFIG_HEARTBEAT_FILE="$WORKDIR/agent-config.checked"
CREDS_DIR="$WORKDIR/creds"
mkdir -p "$CREDS_DIR"
chmod 755 "$WORKDIR" "$CREDS_DIR"
# PAT-1773: the helper reads the enrolled tenant from the credentials directory
# and denies a config for any other tenant.
write_tenant_id() {
    print -r -- "$1" > "$CREDS_DIR/tenant-id"
    chmod 600 "$CREDS_DIR/tenant-id"
}
write_tenant_id tenant-test

# The production helper correctly requires uid 0. Tests run without sudo, so
# this wrapper preserves every real mode/no-follow/read check while projecting
# test fixture descriptors as root-owned. Separate unit assertions below test
# the ownership predicate itself, including the non-root refusal.
TEST_BUNDLE="$WORKDIR/bundle"
mkdir -p "$TEST_BUNDLE"
chmod 755 "$TEST_BUNDLE"
TEST_EVALUATOR="$TEST_BUNDLE/patched-legacy-app-execution-gate.py"
cat > "$TEST_EVALUATOR" <<PYEOF
#!/usr/bin/python3
import importlib.util
import os
import types

spec = importlib.util.spec_from_file_location("patched_gate", "$SCRIPT_DIR/patched-legacy-app-execution-gate.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_fstat = module.os.fstat
real_stat = module.os.stat

def root_metadata(metadata):
    return types.SimpleNamespace(
        st_mode=metadata.st_mode,
        st_uid=0,
        st_mtime=metadata.st_mtime,
        st_dev=metadata.st_dev,
        st_ino=metadata.st_ino,
    )

module.os.fstat = lambda fd: root_metadata(real_fstat(fd))
module.os.stat = lambda *args, **kwargs: root_metadata(real_stat(*args, **kwargs))
raise SystemExit(module.main())
PYEOF
chmod 755 "$TEST_EVALUATOR"

# PAT-1773: the helper loads agent_config_tenant.py in-process, so callers
# require its manifest coverage too. The helper under test loads the module
# beside its real source; this bundle copy carries the same bytes.
cp "$SCRIPT_DIR/agent_config_tenant.py" "$TEST_BUNDLE/agent_config_tenant.py"
chmod 644 "$TEST_BUNDLE/agent_config_tenant.py"
write_test_manifest() {
    {
        shasum -a 256 "$TEST_EVALUATOR" | awk '{print $1 " patched-legacy-app-execution-gate.py"}'
        shasum -a 256 "$TEST_BUNDLE/agent_config_tenant.py" | awk '{print $1 " agent_config_tenant.py"}'
    } > "$TEST_BUNDLE/manifest.sha256"
    chmod 644 "$TEST_BUNDLE/manifest.sha256"
}
write_test_manifest

write_config() {
    print -r -- "$1" > "$AGENT_CONFIG_FILE"
    shasum -a 256 "$AGENT_CONFIG_FILE" | awk '{print $1}' > "$AGENT_CONFIG_SHA256_FILE"
    : > "$AGENT_CONFIG_HEARTBEAT_FILE"
    chmod 644 "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE" "$AGENT_CONFIG_HEARTBEAT_FILE"
}

check_shared_evaluator_races() {
    local action result
    for action in publish_denial remove_heartbeat; do
        write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
        rm -f "$WORKDIR/agent-config.execution-denied"
        result=$("$PYTHON3" - "$SCRIPT_DIR/patched-legacy-app-execution-gate.py" \
            "$action" "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE" \
            "$AGENT_CONFIG_HEARTBEAT_FILE" "$CREDS_DIR/suspended" <<'PYEOF'
import importlib.util, os, sys, types

script, action = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("patched_gate_race", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_fstat = module.os.fstat
real_stat = module.os.stat

def as_root(metadata):
    return types.SimpleNamespace(
        st_mode=metadata.st_mode, st_uid=0, st_mtime=metadata.st_mtime,
        st_dev=metadata.st_dev, st_ino=metadata.st_ino)

module.os.fstat = lambda fd: as_root(real_fstat(fd))
module.os.stat = lambda *args, **kwargs: as_root(real_stat(*args, **kwargs))
real_loads = module.json.loads
fired = False

def racing_loads(*args, **kwargs):
    global fired
    value = real_loads(*args, **kwargs)
    if not fired:
        fired = True
        if action == "publish_denial":
            open(os.path.join(os.path.dirname(sys.argv[3]),
                              module.EXECUTION_DENIAL_FILENAME), "w").close()
        else:
            os.unlink(sys.argv[5])
    return value

module.json.loads = racing_loads
sys.argv = [script] + sys.argv[3:]
print("denied" if module.main() == 1 else "allowed")
PYEOF
        )
        check "reviewer race $action denies immediately before allow" "$result" "denied"
    done
}

set_heartbeat_offset_secs() {
    # Positive is a future timestamp; negative is an age. Both must be
    # refused outside the one-day verification window.
    local offset="$1" target
    target=$(( $(date -u +%s) + offset ))
    "$PYTHON3" - "$AGENT_CONFIG_HEARTBEAT_FILE" "$target" <<'PYEOF'
import os, sys
os.utime(sys.argv[1], (int(sys.argv[2]), int(sys.argv[2])))
PYEOF
}

run_enabled_function() {
    local script="$1" evaluator_path="${2:-$TEST_EVALUATOR}" function_file="$WORKDIR/${script:t}.zsh"
    awk '/PATCHED_LEGACY_APP_EXECUTION_ENABLED_START/{copy=1; next} /PATCHED_LEGACY_APP_EXECUTION_ENABLED_END/{copy=0} copy' \
        "$script" > "$function_file"
    if [[ ! -s "$function_file" ]]; then
        print "missing"
        return
    fi
    (
        BUNDLE_DIR="$TEST_BUNDLE"
        MANIFEST="$TEST_BUNDLE/manifest.sha256"
        LEGACY_APP_EXECUTION_GATE="$evaluator_path"
        source "$function_file"
        if legacy_app_execution_enabled; then print "allowed"; else print "denied"; fi
    )
}

check_update_mode_gate_and_logging() {
    local result
    result=$("$PYTHON3" - "$SCRIPT_DIR/patched-update.sh" <<'PYEOF'
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("run_label() {"))
block = lines[start:]

mode_gate = next(i for i, line in enumerate(block)
                 if 'if [[ "$mode" == "install" ]] && ! legacy_app_execution_enabled; then' in line)
scan_branch = next(i for i, line in enumerate(block)
                   if 'if [[ "$mode" == "scan" ||' in line)
final_gate = next(i for i, line in enumerate(block[scan_branch + 1:], scan_branch + 1)
                  if 'if [[ "$mode" == "install" ]] && ! legacy_app_execution_enabled; then' in line)

# The initial denial preserves install mode for terminal audit evidence, and
# the final denial uses the dedicated refusal flag rather than deferral state.
if not (mode_gate < scan_branch < final_gate):
    raise SystemExit(1)
if not any('log_jsonl "warn" "legacy app-execution authority refused install"' in line
           for line in block[mode_gate:mode_gate + 5]):
    raise SystemExit(1)
if not any('log_jsonl "warn" "legacy app-execution authority refused Installomator"' in line
           for line in block[final_gate:final_gate + 5]):
    raise SystemExit(1)
if any('mode="scan"' in line for line in block[mode_gate:mode_gate + 8]):
    raise SystemExit(1)
if not any('_execution_authority_refused=1' in line for line in block[final_gate:final_gate + 6]):
    raise SystemExit(1)
print("ok")
PYEOF
)
    check "update gate preserves install audit mode and keeps authority refusal distinct from deferral" "$result" "ok"
}

check_update_refusal_payload() {
    local function_file="$WORKDIR/run-label.zsh"
    awk '/^run_label\(\) \{/{copy=1} /^# GATEKEEPER PREFLIGHT/{copy=0} copy' \
        "$SCRIPT_DIR/patched-update.sh" > "$function_file"
    local result
    result=$(
        source "$function_file"
        legacy_app_execution_enabled() { return 1; }
        blocked_version_policy_state() { print no_policy; }
        get_pinned_sha256() { return 3; }
        log_jsonl() { :; }
        emit_provenance() { cp "$1" "$WORKDIR/update-refusal-provenance.json"; }
        emit_audit_event() { print -r -- "$1|$4" > "$WORKDIR/update-refusal-event.txt"; }
        BPP_ACTION_ON_TIMEOUT=notify_only
        TENANT_ID=tenant-test
        HW_UUID=device-test
        COMPUTER_NAME=test-mac
        INSTALLOMATOR_TAG=test
        PYTHON3=/usr/bin/python3
        BREW_COEX_TMP=""
        run_label example Example ABCDE12345 "$WORKDIR/Example.app" install policy 0 0 >/dev/null
        print -r -- "$OUT_OUTCOME|$OUT_FAILURE_REASON|$STATE_RESULT|${OUT_VERIFIED_SIGNER:-}|${OUT_MESSAGE:-}"
    )
    check "update refusal remains terminal, unsigned and explicit in status globals" \
        "$result" \
        "authority_refused|execution_authority_refused|error||Install refused: this endpoint does not currently hold fresh signed execution authority."
    local payload
    payload=$(
        "$PYTHON3" - "$WORKDIR/update-refusal-provenance.json" "$WORKDIR/update-refusal-event.txt" <<'PYEOF'
import json
import sys

record = json.load(open(sys.argv[1]))
event = open(sys.argv[2]).read().strip()
ok = (
    record["outcome"] == "authority_refused"
    and record["failure_reason"] == "execution_authority_refused"
    and record["run_mode"] == "install"
    and record["verification"]["observed_team_id"] is None
    and event == "install_failed|execution_authority_refused"
)
print("ok" if ok else "bad")
PYEOF
    )
    check "uploaded update provenance preserves install mode and authority refusal" "$payload" "ok"
}

check_install_refusal_payload() {
    local function_file="$WORKDIR/process-install.zsh"
    awk '/^process_one_install\(\) \{/{copy=1} /^# 5\. ITERATE OVER PENDING INSTALLS/{copy=0} copy' \
        "$SCRIPT_DIR/patched-install.sh" > "$function_file"
    local fake_bin="$WORKDIR/bin"
    mkdir -p "$fake_bin"
    print '#!/bin/sh' > "$fake_bin/mas"
    print 'exit 0' >> "$fake_bin/mas"
    chmod 755 "$fake_bin/mas"
    local result
    result=$(
        source "$function_file"
        log_jsonl() { :; }
        is_installed_mas() { return 1; }
        legacy_app_execution_enabled() { return 1; }
        report_install_event() { print -r -- "$3|$4" > "$WORKDIR/install-refusal-event.txt"; }
        PYTHON3=/usr/bin/python3
        _result_file="$WORKDIR/install-refusal-result.jsonl"
        PATH="$fake_bin:$PATH"
        process_one_install 123456 mas Example >/dev/null
        "$PYTHON3" - "$_result_file" <<'PYEOF'
import json
import sys
row = json.loads(open(sys.argv[1]).read())
print("|".join((row["outcome"], row["failure_kind"], row["error_message"])))
PYEOF
    )
    check "mid-run install denial writes a terminal authority-refusal result" "$result" \
        "authority_refused|execution_authority_refused|legacy app-execution gate disabled immediately before MAS install"
    check "mid-run install denial uploads the distinct refusal outcome" \
        "$(cat "$WORKDIR/install-refusal-event.txt")" \
        "authority_refused|legacy app-execution gate disabled immediately before MAS install"
}

check_uninstall_refusal_outcomes() {
    local process_file="$WORKDIR/process-removal.zsh"
    awk '/^process_one_removal\(\) \{/{copy=1} /^_append_result\(\) \{/{copy=0} copy' \
        "$SCRIPT_DIR/patched-uninstall.sh" > "$process_file"
    local result
    result=$(
        source "$process_file"
        is_safe_app_name() { return 0; }
        is_baseline_protected() { return 1; }
        is_installed_macos() { return 0; }
        is_running_macos() { return 0; }
        request_quit_macos() { return 2; }
        _emit_uninstall_provenance() { print -r -- "$9|${11}" > "$WORKDIR/uninstall-refusal-provenance.txt"; }
        _append_result() { print -r -- "$3|$4|$5" > "$WORKDIR/uninstall-refusal-status.txt"; }
        process_one_removal 7 Example Publisher macos exact 2026-09-08T00:00:00Z >/dev/null
        print -r -- "$(cat "$WORKDIR/uninstall-refusal-provenance.txt")|$(cat "$WORKDIR/uninstall-refusal-status.txt")"
    )
    check "quit authority denial is terminal, hard and never app-running deferral" "$result" \
        "authority_refused|hard|authority_refused|not_checked|none"

    local device_file="$WORKDIR/device-removal.zsh"
    awk '/^_device_task_decide\(\) \{/{copy=1} /^# Polls GET \/v1\/devices/{copy=0} copy' \
        "$SCRIPT_DIR/patched-uninstall.sh" > "$device_file"
    result=$(
        source "$device_file"
        is_safe_app_name() { return 0; }
        is_baseline_protected() { return 1; }
        is_installed_macos() { return 0; }
        is_running_macos() { return 0; }
        request_quit_macos() { return 2; }
        _device_task_decide Example >/dev/null
        print -r -- "$_DT_STATE|$_DT_DETAIL"
    )
    check "device removal authority denial is failed, not retryable in-progress" "$result" \
        "failed|execution authority refused before quit request"

    result=$(
        "$PYTHON3" - "$SCRIPT_DIR/../contracts/uninstall-status.schema.json" <<'PYEOF'
import json
import jsonschema
import sys

schema = json.load(open(sys.argv[1]))
document = {
    "schema_version": 1,
    "generated_at": "2026-09-08T10:00:01Z",
    "last_run": {
        "started_at": "2026-09-08T10:00:00Z",
        "finished_at": "2026-09-08T10:00:01Z",
    },
    "removals": [{
        "entry_id": 7,
        "name": "Example",
        "outcome": "authority_refused",
        "verify_result": "not_checked",
        "method": "none",
        "recorded_at": "2026-09-08T10:00:01Z",
    }],
}
jsonschema.validate(document, schema, format_checker=jsonschema.FormatChecker())
print("ok")
PYEOF
    )
    check "terminal uninstall authority refusal validates against the status contract" "$result" "ok"
}

for executor in patched-install.sh patched-uninstall.sh patched-update.sh; do
    script="$SCRIPT_DIR/$executor"
    print "[$executor]"

    rm -f "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE" "$AGENT_CONFIG_HEARTBEAT_FILE" "$CREDS_DIR/suspended"
    check "missing config denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":false}'
    check "false denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":null}'
    check "null denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":"true"}'
    check "string true denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
    check "exact boolean true permits" "$(run_enabled_function "$script")" "allowed"

    : > "$WORKDIR/agent-config.execution-denied"
    check "authenticated rejected-policy marker overrides old exact true grant" \
        "$(run_enabled_function "$script")" "denied"
    rm -f "$WORKDIR/agent-config.execution-denied"

    chmod 664 "$AGENT_CONFIG_FILE"
    check "group-writable config denies" "$(run_enabled_function "$script")" "denied"
    chmod 644 "$AGENT_CONFIG_FILE"

    chmod 775 "$WORKDIR"
    check "group-writable state directory denies" "$(run_enabled_function "$script")" "denied"
    chmod 755 "$WORKDIR"

    chmod 775 "$CREDS_DIR"
    check "group-writable credentials directory denies" "$(run_enabled_function "$script")" "denied"
    chmod 755 "$CREDS_DIR"

    check "missing evaluator denies" \
        "$(run_enabled_function "$script" "$WORKDIR/missing-evaluator.py")" "denied"
    ln -s "$SCRIPT_DIR/patched-legacy-app-execution-gate.py" "$WORKDIR/evaluator-link.py"
    check "symlinked evaluator denies" \
        "$(run_enabled_function "$script" "$WORKDIR/evaluator-link.py")" "denied"
    rm -f "$WORKDIR/evaluator-link.py"

    for cache_file in "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE" "$AGENT_CONFIG_HEARTBEAT_FILE"; do
        mv "$cache_file" "$cache_file.real"
        ln -s "$cache_file.real" "$cache_file"
        check "symlinked ${cache_file:t} denies" "$(run_enabled_function "$script")" "denied"
        rm -f "$cache_file"
        mv "$cache_file.real" "$cache_file"
    done

    : > "$CREDS_DIR/suspended"
    check "revocation after an initial allow denies at the final check" "$(run_enabled_function "$script")" "denied"
    rm -f "$CREDS_DIR/suspended"

    # A marker can be a directory, regular file or symlink. In particular,
    # `os.path.exists` would miss a dangling symlink, incorrectly allowing an
    # endpoint whose suspension marker has not resolved to a live target.
    ln -s "$WORKDIR/nonexistent-suspension-target" "$CREDS_DIR/suspended"
    check "dangling-symlink suspension marker denies" "$(run_enabled_function "$script")" "denied"
    rm -f "$CREDS_DIR/suspended"

    set_heartbeat_offset_secs $(( -(24 * 60 * 60 + 1) ))
    check "stale heartbeat denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
    set_heartbeat_offset_secs 60
    check "future-dated heartbeat denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
    rm -f "$AGENT_CONFIG_HEARTBEAT_FILE"
    check "missing heartbeat denies" "$(run_enabled_function "$script")" "denied"

    print -r -- '{ not valid json' > "$AGENT_CONFIG_FILE"
    shasum -a 256 "$AGENT_CONFIG_FILE" | awk '{print $1}' > "$AGENT_CONFIG_SHA256_FILE"
    check "malformed config denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
    print -r -- '0000000000000000000000000000000000000000000000000000000000000000' > "$AGENT_CONFIG_SHA256_FILE"
    check "hash mismatch denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":false,"legacy_app_execution_enabled":true}'
    check "duplicate top-level key denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true,"LEGACY_APP_EXECUTION_ENABLED":false}'
    check "case-colliding top-level keys deny in enabled-first order" "$(run_enabled_function "$script")" "denied"

    write_config '{"LEGACY_APP_EXECUTION_ENABLED":false,"legacy_app_execution_enabled":true}'
    check "case-colliding top-level keys deny in disabled-first order" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true,"nested":{"key":1,"key":2}}'
    check "duplicate nested key denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true,"nested":{"key":1,"KEY":2}}'
    check "case-colliding nested keys deny" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true,"nested":{"Straße":1,"STRASSE":2}}'
    check "Unicode-casefold-colliding nested keys deny" "$(run_enabled_function "$script")" "denied"

    print '  [tenant scope, PAT-1773]'
    write_config '{"tenant_id":"tenant-old","legacy_app_execution_enabled":true}'
    check "exact true for another tenant denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"TENANT-TEST","legacy_app_execution_enabled":true}'
    check "exact true for a case-differing tenant denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"legacy_app_execution_enabled":true}'
    check "exact true with no tenant_id denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"","legacy_app_execution_enabled":true}'
    check "exact true with an empty tenant_id denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":7,"legacy_app_execution_enabled":true}'
    check "exact true with a non-string tenant_id denies" "$(run_enabled_function "$script")" "denied"

    write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
    rm -f "$CREDS_DIR/tenant-id"
    check "missing enrolled tenant-id denies" "$(run_enabled_function "$script")" "denied"
    write_tenant_id ""
    check "empty enrolled tenant-id denies" "$(run_enabled_function "$script")" "denied"
    write_tenant_id "  tenant-test  "
    check "enrolled tenant-id is read with whitespace removed" "$(run_enabled_function "$script")" "allowed"
    chmod 620 "$CREDS_DIR/tenant-id"
    check "group-writable tenant-id denies" "$(run_enabled_function "$script")" "denied"
    rm -f "$CREDS_DIR/tenant-id"
    print -r -- tenant-test > "$WORKDIR/tenant-id.real"
    ln -s "$WORKDIR/tenant-id.real" "$CREDS_DIR/tenant-id"
    check "symlinked tenant-id denies" "$(run_enabled_function "$script")" "denied"
    rm -f "$CREDS_DIR/tenant-id" "$WORKDIR/tenant-id.real"
    write_tenant_id tenant-new
    check "re-enrolment into another tenant denies the old tenant's exact true" "$(run_enabled_function "$script")" "denied"
    write_tenant_id tenant-test

    "$PYTHON3" - "$AGENT_CONFIG_FILE" <<'PYEOF'
import sys
with open(sys.argv[1], "wb") as config_file:
    config_file.write(b'{"tenant_id":"tenant-test","legacy_app_execution_enabled":true,"padding":"')
    config_file.write(b"x" * (1024 * 1024))
    config_file.write(b'"}')
PYEOF
    shasum -a 256 "$AGENT_CONFIG_FILE" | awk '{print $1}' > "$AGENT_CONFIG_SHA256_FILE"
    : > "$AGENT_CONFIG_HEARTBEAT_FILE"
    check "oversized config denies before unbounded decode" "$(run_enabled_function "$script")" "denied"
done

check_shared_evaluator_races

print '[manifest-bound helper]'
write_config '{"tenant_id":"tenant-test","legacy_app_execution_enabled":true}'
caller="$SCRIPT_DIR/patched-update.sh"
cp "$TEST_BUNDLE/manifest.sha256" "$WORKDIR/good-manifest.sha256"
print '# tampered after manifest generation' >> "$TEST_EVALUATOR"
check "manifest hash mismatch denies a replaced helper" "$(run_enabled_function "$caller")" "denied"
cp "$WORKDIR/good-manifest.sha256" "$TEST_BUNDLE/manifest.sha256"
print -r -- '0 dummy' > "$TEST_BUNDLE/manifest.sha256"
check "helper absent from manifest denies" "$(run_enabled_function "$caller")" "denied"
write_test_manifest
cp "$TEST_BUNDLE/manifest.sha256" "$WORKDIR/duplicate-manifest-line.txt"
cat "$WORKDIR/duplicate-manifest-line.txt" >> "$TEST_BUNDLE/manifest.sha256"
check "duplicate helper manifest entries deny" "$(run_enabled_function "$caller")" "denied"
write_test_manifest
check "one exact matching helper manifest entry permits caller evaluation" \
    "$(run_enabled_function "$caller")" "allowed"
awk '$2 != "agent_config_tenant.py"' "$TEST_BUNDLE/manifest.sha256" > "$WORKDIR/no-tenant-module.txt"
cp "$WORKDIR/no-tenant-module.txt" "$TEST_BUNDLE/manifest.sha256"
check "tenant module absent from manifest denies" "$(run_enabled_function "$caller")" "denied"
write_test_manifest
awk '$2 == "agent_config_tenant.py"' "$TEST_BUNDLE/manifest.sha256" > "$WORKDIR/tenant-module-line.txt"
cat "$WORKDIR/tenant-module-line.txt" >> "$TEST_BUNDLE/manifest.sha256"
check "duplicate tenant module manifest entries deny" "$(run_enabled_function "$caller")" "denied"
write_test_manifest
print '# tampered after manifest generation' >> "$TEST_BUNDLE/agent_config_tenant.py"
check "manifest hash mismatch denies a replaced tenant module" "$(run_enabled_function "$caller")" "denied"
cp "$SCRIPT_DIR/agent_config_tenant.py" "$TEST_BUNDLE/agent_config_tenant.py"
mv "$TEST_BUNDLE/agent_config_tenant.py" "$WORKDIR/tenant-module.real"
check "missing tenant module denies" "$(run_enabled_function "$caller")" "denied"
ln -s "$WORKDIR/tenant-module.real" "$TEST_BUNDLE/agent_config_tenant.py"
check "symlinked tenant module denies" "$(run_enabled_function "$caller")" "denied"
rm -f "$TEST_BUNDLE/agent_config_tenant.py"
mv "$WORKDIR/tenant-module.real" "$TEST_BUNDLE/agent_config_tenant.py"
check "restored tenant module permits caller evaluation" "$(run_enabled_function "$caller")" "allowed"

ownership_result=$(
    "$PYTHON3" - "$SCRIPT_DIR/patched-legacy-app-execution-gate.py" <<'PYEOF'
import importlib.util
import stat
import sys
import types

spec = importlib.util.spec_from_file_location("patched_gate", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
secure = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644)
nonroot = types.SimpleNamespace(st_uid=501, st_mode=stat.S_IFREG | 0o644)
group_writable = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o664)
print("ok" if (
    module._root_owned_nonwritable(secure)
    and not module._root_owned_nonwritable(nonroot)
    and not module._root_owned_nonwritable(group_writable)
) else "bad")
PYEOF
)
check "ownership predicate requires uid 0 and rejects group-writable entries" "$ownership_result" "ok"

print '[source boundaries]'
for required in \
    'endpoint/patched-update.sh:run_label()' \
    'endpoint/patched-update.sh:legacy_app_execution_enabled' \
    'endpoint/patched-update.sh:"$INSTALLOMATOR"' \
    'endpoint/patched-install.sh:"$mas_bin" install' \
    'endpoint/patched-install.sh:"$INSTALLOMATOR"' \
    'endpoint/patched-uninstall.sh:execute_uninstall_macos()' \
    'endpoint/patched-uninstall.sh:legacy_app_execution_enabled' \
    'endpoint/patched-legacy-app-execution-gate.py:snapshot = _read_bounded(config_fd, MAX_CONFIG_BYTES)'; do
    script="${required%%:*}"; needle="${required#*:}"
    check_present "required seam remains in $script: $needle" "$(grep -F -c -- "$needle" "$SCRIPT_DIR/${script:t}" 2>/dev/null)"
done

for script in "$SCRIPT_DIR/patched-update.sh" "$SCRIPT_DIR/patched-install.sh" "$SCRIPT_DIR/patched-uninstall.sh"; do
    check "${script:t} delegates to the shared evaluator" \
        "$(grep -F -c '"$PYTHON3" "$LEGACY_APP_EXECUTION_GATE"' "$script")" "1"
done
check "shared evaluator reads one immutable snapshot" \
    "$(grep -F -c 'snapshot = _read_bounded(config_fd, MAX_CONFIG_BYTES)' "$SCRIPT_DIR/patched-legacy-app-execution-gate.py")" "1"
check "shared snapshot is hashed" \
    "$(grep -F -c 'hashlib.sha256(snapshot)' "$SCRIPT_DIR/patched-legacy-app-execution-gate.py")" "1"
check "shared snapshot is parsed" \
    "$(grep -F -c 'json.loads(snapshot.decode' "$SCRIPT_DIR/patched-legacy-app-execution-gate.py")" "1"
check_shared_evaluator_contract
check "installer repairs root ownership and mode for the config state directory" \
    "$(grep -F -c 'chown root:wheel "$STATE_DIR"' "$SCRIPT_DIR/install.sh")" "1"
check "installer refuses a symlinked config state directory" \
    "$(grep -F -c '[[ -L "$STATE_DIR" ]]' "$SCRIPT_DIR/install.sh")" "1"
check_gate_near_call "$SCRIPT_DIR/patched-update.sh" '"$INSTALLOMATOR" "$label"' 40
check_gate_near_call "$SCRIPT_DIR/patched-install.sh" '"$mas_bin" install' 12
check_gate_near_call "$SCRIPT_DIR/patched-install.sh" '"$INSTALLOMATOR" "$package_id"' 12
check_gate_at_function_start "$SCRIPT_DIR/patched-uninstall.sh" 'execute_uninstall_macos'
check_uninstall_action_gates
check_update_uninstall_trigger_gate
check_update_uninstall_trigger_refusal_payload
check_refusal_queue_bounds
check_update_mode_gate_and_logging
check_update_refusal_payload
check_install_refusal_payload
check_uninstall_refusal_outcomes

print '[release bundle coverage]'
REPO_ROOT="${SCRIPT_DIR:h}"
if bash "$REPO_ROOT/tools/build-bundle.sh" >/dev/null; then
    built_helper="$REPO_ROOT/dist/patched-updater/patched-legacy-app-execution-gate.py"
    built_manifest="$REPO_ROOT/dist/patched-updater/manifest.sha256"
    manifest_count=$(awk '$2 == "patched-legacy-app-execution-gate.py" {count++} END {print count+0}' "$built_manifest")
    manifest_want=$(awk '$2 == "patched-legacy-app-execution-gate.py" {print $1}' "$built_manifest")
    manifest_got=$(shasum -a 256 "$built_helper" 2>/dev/null | awk '{print $1}')
    check "release bundle ships the execution gate helper" "$([[ -f "$built_helper" ]] && echo yes || echo no)" "yes"
    check "release manifest lists the helper exactly once" "$manifest_count" "1"
    check "release manifest covers the helper's exact bytes" "$manifest_got" "$manifest_want"
    built_module="$REPO_ROOT/dist/patched-updater/agent_config_tenant.py"
    module_count=$(awk '$2 == "agent_config_tenant.py" {count++} END {print count+0}' "$built_manifest")
    module_want=$(awk '$2 == "agent_config_tenant.py" {print $1}' "$built_manifest")
    module_got=$(shasum -a 256 "$built_module" 2>/dev/null | awk '{print $1}')
    check "release bundle ships the tenant module the helper loads" "$([[ -f "$built_module" ]] && echo yes || echo no)" "yes"
    check "release manifest lists the tenant module exactly once" "$module_count" "1"
    check "release manifest covers the tenant module's exact bytes" "$module_got" "$module_want"
else
    ((fail += 6))
    print "  FAIL: release bundle build failed; helper coverage could not be checked"
fi

print "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
