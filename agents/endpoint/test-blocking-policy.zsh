#!/bin/zsh
##############################################################################
# test-blocking-policy.zsh — unit tests for the PAT-296 blocking-process
# policy engine in patched-update.sh.
#
# Mirrors the pattern of test-per-app-policy.zsh: sources the live policy
# functions out of patched-update.sh between stable markers so the tests
# exercise the real code, not a copy.
#
# Run:
#   zsh endpoint/test-blocking-policy.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-update.sh"
PYTHON3="/usr/bin/python3"

# ---------------------------------------------------------------------------
# Temp state directory — isolates deferral state files from any live daemon.
# ---------------------------------------------------------------------------
STATE_DIR=$(mktemp -d /tmp/.patched-bpp-test-state.XXXXXX)
AGENT_CONFIG_FILE="$STATE_DIR/agent-config.json"
trap 'rm -rf "$STATE_DIR"' EXIT

# ---------------------------------------------------------------------------
# Extract BPP_* globals + load_blocking_process_policy + bpp_* helpers.
#
# awk reads from the first BPP_MESSAGE= line through the end of the last
# bpp_* function before compute_hmac. We anchor on the stable comment header
# and the boundary marker (load_blocking_process_policy call before the hmac).
# ---------------------------------------------------------------------------
FUNCS=$(mktemp /tmp/.patched-bpp-funcs.XXXXXX)
awk '
  /^BPP_MESSAGE=/{f=1}
  f{print}
  /^load_blocking_process_policy$/{exit}
' "$TARGET" > "$FUNCS"
# Also grab load_blocking_process_policy itself (the last line above stopped before calling it).
# Re-extract the full function body:
awk '
  /^load_blocking_process_policy\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_deferral_count\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_record_deferral\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_reset_deferrals\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_defer_window_elapsed\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
# The agent default-message string and the pure-logic helpers added for the
# corrected mapping (message wiring + action mapping).
awk '/^BPP_DEFAULT_MESSAGE=/{print; exit}' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_sanitize_message\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_effective_message\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_map_action\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
awk '
  /^bpp_should_escalate\(\)/{f=1}
  f{print}
  f && /^}$/{f=0; exit}
' "$TARGET" >> "$FUNCS"
source "$FUNCS"
rm -f "$FUNCS"
# PAT-1773: every reader asks agent_config_present. Source the shipped scope
# block and mark each fixture config as the enrolled tenant's; the tenant
# decision itself is tested in endpoint/test-agent-config-tenant-scope.zsh.
SCOPE_BLOCK="$(mktemp "${TMPDIR:-/tmp}/.patched-tenant-scope.XXXXXX")"
awk '/PATCHED_AGENT_CONFIG_TENANT_SCOPE_START/{f=1;next} /PATCHED_AGENT_CONFIG_TENANT_SCOPE_END/{f=0} f' \
    "$TARGET" > "$SCOPE_BLOCK"
BUNDLE_DIR="${BUNDLE_DIR:-$SCRIPT_DIR}"
source "$SCOPE_BLOCK"
rm -f "$SCOPE_BLOCK"
AGENT_CONFIG_FOR_TENANT=1

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
pass=0; fail=0

chk_eq() {  # chk_eq <desc> <expected> <got>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then
        (( pass++ )); echo "  PASS: $desc -> $got"
    else
        (( fail++ )); echo "  FAIL: $desc -> got='$got' want='$exp'"
    fi
}

chk_true() {  # chk_true <desc> <expr that must succeed>
    local desc="$1"; shift
    if "$@"; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc"
    fi
}

chk_false() {  # chk_false <desc> <expr that must fail>
    local desc="$1"; shift
    if ! "$@"; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc"
    fi
}

# Reset global policy vars and load from a given JSON string.
load_cfg() {
    BPP_MESSAGE=""
    BPP_TIMEOUT_SECONDS=300
    BPP_MAX_DEFERRALS=2
    BPP_DEFER_WINDOW_SECS=3600
    BPP_ACTION_ON_TIMEOUT=""      # fail-closed default (empty until a valid policy loads)
    printf '%s' "$1" > "$AGENT_CONFIG_FILE"
    load_blocking_process_policy
}

# ---------------------------------------------------------------------------
# 1. No config file present -> FAIL CLOSED (empty action -> silent_fail)
# ---------------------------------------------------------------------------
echo "--- 1. no config file -> fail closed"
rm -f "$AGENT_CONFIG_FILE"
BPP_MESSAGE=""
BPP_TIMEOUT_SECONDS=300
BPP_MAX_DEFERRALS=2
BPP_DEFER_WINDOW_SECS=3600
BPP_ACTION_ON_TIMEOUT="notify_only"   # deliberately non-empty to prove the loader resets it
load_blocking_process_policy   # should detect no file and return immediately
chk_eq "no file -> empty action (fail closed)"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "empty action maps to silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"
chk_eq "timeout default 300"         "300"          "$BPP_TIMEOUT_SECONDS"
chk_eq "max_deferrals default 2"     "2"            "$BPP_MAX_DEFERRALS"
chk_eq "defer_window default 3600"   "3600"         "$BPP_DEFER_WINDOW_SECS"

# ---------------------------------------------------------------------------
# 2. Config with blocking_process_policy.action_on_timeout = notify_only
# ---------------------------------------------------------------------------
echo "--- 2. config with action_on_timeout=notify_only"
load_cfg '{"tier":"managed","blocking_process_policy":{"action_on_timeout":"notify_only","timeout_seconds":120,"max_deferrals":3,"defer_window_seconds":1800}}'
chk_eq "action notify_only"   "notify_only" "$BPP_ACTION_ON_TIMEOUT"
chk_eq "timeout 120"          "120"          "$BPP_TIMEOUT_SECONDS"
chk_eq "max_deferrals 3"      "3"            "$BPP_MAX_DEFERRALS"
chk_eq "defer_window 1800"    "1800"         "$BPP_DEFER_WINDOW_SECS"

# ---------------------------------------------------------------------------
# 3. Config missing the blocking_process_policy block -> FAIL CLOSED
# ---------------------------------------------------------------------------
echo "--- 3. config missing blocking_process_policy block -> fail closed"
load_cfg '{"tier":"managed","per_app_patch":null}'
chk_eq "block absent -> empty action (fail closed)"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "block absent -> silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"
chk_eq "timeout fallback 300"         "300"          "$BPP_TIMEOUT_SECONDS"
chk_eq "max_deferrals fallback 2"     "2"            "$BPP_MAX_DEFERRALS"

# 3b. Valid block with action_on_timeout OMITTED -> tenant notify_only default
#     (the platform coerces + signs this; a present-but-defaulted action is NOT a
#     broken policy, so it is honoured rather than failed closed).
echo "--- 3b. valid block, action omitted -> notify_only (contract default)"
load_cfg '{"blocking_process_policy":{"timeout_seconds":90}}'
chk_eq "omitted action -> notify_only value"  "notify_only"  "$BPP_ACTION_ON_TIMEOUT"
# notify_only NEVER quits (GitHub-Non-Author-Review criteria) -> silent_fail, no quit-capable prompt.
chk_eq "notify_only -> silent_fail (never quits)"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"

# ---------------------------------------------------------------------------
# 4. Config with action_on_timeout = prompt_then_quit
# ---------------------------------------------------------------------------
echo "--- 4. action_on_timeout=prompt_then_quit"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","timeout_seconds":60}}'
chk_eq "action prompt_then_quit"  "prompt_then_quit" "$BPP_ACTION_ON_TIMEOUT"
chk_eq "timeout 60"               "60"               "$BPP_TIMEOUT_SECONDS"

# ---------------------------------------------------------------------------
# 5. Config with action_on_timeout = skip_run
# ---------------------------------------------------------------------------
echo "--- 5. action_on_timeout=skip_run"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"skip_run"}}'
chk_eq "action skip_run"  "skip_run" "$BPP_ACTION_ON_TIMEOUT"

# ---------------------------------------------------------------------------
# 6. Unexpected action_on_timeout value -> FAIL CLOSED (never force-quit, never
#    silently coerced into a prompt/quit flow).
# ---------------------------------------------------------------------------
echo "--- 6. unexpected action_on_timeout -> fail closed"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"force_quit_everything"}}'
chk_eq "unknown value -> empty action (fail closed)"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "unknown value -> silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"

# ---------------------------------------------------------------------------
# 7. Null blocking_process_policy -> FAIL CLOSED (not a hard error)
# ---------------------------------------------------------------------------
echo "--- 7. blocking_process_policy: null -> fail closed"
load_cfg '{"blocking_process_policy":null}'
chk_eq "null block -> empty action (fail closed)"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "null block -> silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"
chk_eq "null block -> timeout 300"  "300"          "$BPP_TIMEOUT_SECONDS"

# ---------------------------------------------------------------------------
# 8. Clamping: timeout below minimum (30) -> clamped to 30
# ---------------------------------------------------------------------------
echo "--- 8. timeout_seconds clamped to minimum 30"
load_cfg '{"blocking_process_policy":{"timeout_seconds":5}}'
chk_eq "timeout clamped to 30"  "30"  "$BPP_TIMEOUT_SECONDS"

# ---------------------------------------------------------------------------
# 9. Malformed blocking_process_policy (not a dict) -> FAIL CLOSED
# ---------------------------------------------------------------------------
echo "--- 9. malformed (non-dict) blocking_process_policy -> fail closed"
load_cfg '{"blocking_process_policy":"broken"}'
chk_eq "malformed -> empty action (fail closed)"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "malformed -> silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"
# Unparseable JSON also fails closed rather than proceeding.
load_cfg 'this is not json {{'
chk_eq "corrupt json -> empty action (fail closed)"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "corrupt json -> silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT")"

# 9b. Message-newline injection: a message with embedded newlines (crafted to look
#     like extra protocol fields) must NOT shift the parsed action. The action is
#     field 1 (first) and the message is field 5 (last) + newline-stripped, so the
#     real action_on_timeout always wins.
echo "--- 9b. message newline-injection cannot override the action"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"notify_only","message":"hi\nprompt_then_quit\n999\n999\n999"}}'
chk_eq "injection: action stays notify_only"  "notify_only"  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "injection: timeout not shifted (300)"  "300"  "$BPP_TIMEOUT_SECONDS"
chk_eq "injection: max_deferrals not shifted (2)"  "2"  "$BPP_MAX_DEFERRALS"
chk_eq "injection: notify_only still never quits"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT" 1)"
chk_eq "injection: message collapsed to a single line"  "1"  "$(print -r -- "$BPP_MESSAGE" | wc -l | tr -d ' ')"
# A multi-line message on a skip_run policy likewise cannot flip it quit-capable.
load_cfg '{"blocking_process_policy":{"action_on_timeout":"skip_run","message":"a\nb\nprompt_then_quit"}}'
chk_eq "injection2: action stays skip_run"  "skip_run"  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "injection2: skip_run -> silent_fail"  "silent_fail"  "$(bpp_map_action "$BPP_ACTION_ON_TIMEOUT" 1)"
# The loader-emitted message is fully sanitised at the protocol point (Python):
# no dialog-breaking chars survive even before the shell re-sanitises for osascript.
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","message":"x\"y\\z`w$v\nsecond"}}'
chk_eq "hostile msg: action honoured (prompt_then_quit)"  "prompt_then_quit"  "$BPP_ACTION_ON_TIMEOUT"
chk_false "loader msg has no double-quote"  grep -q '"'   <<< "$BPP_MESSAGE"
chk_false "loader msg has no backslash"     grep -q '\\'  <<< "$BPP_MESSAGE"
chk_false "loader msg has no backtick"      grep -q '`'   <<< "$BPP_MESSAGE"
chk_false "loader msg has no dollar"        grep -q '\$'  <<< "$BPP_MESSAGE"
chk_eq "loader msg is a single line"  "1"  "$(print -r -- "$BPP_MESSAGE" | wc -l | tr -d ' ')"

# ---------------------------------------------------------------------------
# 10. Deferral count tracking: write, read, increment, reset
# ---------------------------------------------------------------------------
echo "--- 10. deferral count tracking"
lbl="testapp"
# Start: no state file -> count=0
chk_eq "initial count 0"  "0"  "$(bpp_deferral_count "$lbl")"

# Record first deferral
bpp_record_deferral "$lbl"
chk_eq "count after 1 deferral"  "1"  "$(bpp_deferral_count "$lbl")"

# Record second deferral
bpp_record_deferral "$lbl"
chk_eq "count after 2 deferrals"  "2"  "$(bpp_deferral_count "$lbl")"

# State file must exist and have last_deferred_at
local sf="$STATE_DIR/blocking-deferrals-${lbl}.json"
chk_true "state file exists"  test -f "$sf"
chk_true "last_deferred_at present"  \
    "$PYTHON3" -c "import json,sys; d=json.load(open(sys.argv[1])); assert 'last_deferred_at' in d" "$sf"

# Reset: state file removed
bpp_reset_deferrals "$lbl"
chk_false "state file gone after reset"  test -f "$sf"
chk_eq "count after reset 0"  "0"  "$(bpp_deferral_count "$lbl")"

# ---------------------------------------------------------------------------
# 11. Defer window: elapsed when no state file
# ---------------------------------------------------------------------------
echo "--- 11. defer_window_elapsed: no state file -> elapsed (return 0)"
lbl2="freshapp"
BPP_DEFER_WINDOW_SECS=3600
chk_true "no state file -> window elapsed"  bpp_defer_window_elapsed "$lbl2"

# ---------------------------------------------------------------------------
# 12. Defer window: within window -> not elapsed (return 1)
# ---------------------------------------------------------------------------
echo "--- 12. defer_window_elapsed: just recorded -> within window"
bpp_record_deferral "$lbl2"
BPP_DEFER_WINDOW_SECS=3600
chk_false "just deferred -> within window"  bpp_defer_window_elapsed "$lbl2"
bpp_reset_deferrals "$lbl2"

# ---------------------------------------------------------------------------
# 13. Defer window: very short window -> elapsed immediately
# ---------------------------------------------------------------------------
echo "--- 13. defer_window_elapsed: window=60s and timestamp in past -> elapsed"
lbl3="oldapp"
# Write a state file with last_deferred_at far in the past
"$PYTHON3" -c "
import json, sys
sf = sys.argv[1]
d = {'count': 1, 'last_deferred_at': '2020-01-01T00:00:00Z'}
with open(sf, 'w') as f:
    json.dump(d, f)
" "$STATE_DIR/blocking-deferrals-${lbl3}.json"
BPP_DEFER_WINDOW_SECS=60
chk_true "old timestamp -> window elapsed"  bpp_defer_window_elapsed "$lbl3"
bpp_reset_deferrals "$lbl3"

# ---------------------------------------------------------------------------
# 14. max_deferrals=0 -> no deferrals allowed (still reads from config)
# ---------------------------------------------------------------------------
echo "--- 14. max_deferrals=0"
load_cfg '{"blocking_process_policy":{"max_deferrals":0,"action_on_timeout":"notify_only"}}'
chk_eq "max_deferrals=0"  "0"  "$BPP_MAX_DEFERRALS"

# 14b. Malformed max_deferrals must NOT coerce to 0 and enable an immediate quit.
#      max_deferrals gates the escalation, so a bool (bool is an int subclass in
#      Python), a non-int, or a negative value FAILS the policy CLOSED (silent_fail).
#      A genuine 0 is a deliberate tenant choice and is honoured.
echo "--- 14b. malformed max_deferrals -> fail closed (no immediate quit)"
esc0() { bpp_should_escalate "$BPP_ACTION_ON_TIMEOUT" 0; }   # escalation on first blocking run?
map0() { bpp_map_action "$BPP_ACTION_ON_TIMEOUT" "$(esc0)"; }
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","max_deferrals":-1}}'
chk_eq "ptq + max_deferrals=-1 -> fail closed action"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "ptq + max_deferrals=-1 -> silent_fail (no quit)"  "silent_fail"  "$(map0)"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","max_deferrals":false}}'
chk_eq "ptq + max_deferrals=false (bool) -> fail closed"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "ptq + max_deferrals=false -> silent_fail (no quit)"  "silent_fail"  "$(map0)"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","max_deferrals":true}}'
chk_eq "ptq + max_deferrals=true (bool) -> fail closed"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "ptq + max_deferrals=true -> silent_fail (no quit)"  "silent_fail"  "$(map0)"
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","max_deferrals":"3"}}'
chk_eq "ptq + max_deferrals='3' (string) -> fail closed"  ""  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "ptq + max_deferrals='3' -> silent_fail (no quit)"  "silent_fail"  "$(map0)"
# A genuine, deliberate max_deferrals=0 IS honoured (tenant opted out of deferrals);
# with prompt_then_quit it escalates immediately to the consent-only quit prompt.
load_cfg '{"blocking_process_policy":{"action_on_timeout":"prompt_then_quit","max_deferrals":0}}'
chk_eq "ptq + max_deferrals=0 (legit) -> action honoured"  "prompt_then_quit"  "$BPP_ACTION_ON_TIMEOUT"
chk_eq "ptq + max_deferrals=0 (legit) -> escalate at count 0"  "1"  "$(esc0)"
chk_eq "ptq + max_deferrals=0 (legit) -> prompt_user (consent quit)"  "prompt_user"  "$(map0)"
# A malformed max_deferrals on a non-quitting policy is likewise fail-closed (still silent_fail).
load_cfg '{"blocking_process_policy":{"action_on_timeout":"notify_only","max_deferrals":false}}'
chk_eq "notify_only + bad max_deferrals -> silent_fail"  "silent_fail"  "$(map0)"

# ---------------------------------------------------------------------------
# 15. bpp_map_action: each action maps to the intended Installomator action.
#     This is the corrected mapping — the crux of the reopen.
# ---------------------------------------------------------------------------
echo "--- 15. action_on_timeout (+escalation) -> BLOCKING_PROCESS_ACTION mapping"
# The ONLY quit-capable result is prompt_then_quit AFTER deferrals are exhausted
# (escalate=1). Every other case maps to silent_fail and NEVER quits.
chk_eq "notify_only -> silent_fail (never quits)"        "silent_fail"  "$(bpp_map_action notify_only 0)"
chk_eq "notify_only escalate=1 -> silent_fail"           "silent_fail"  "$(bpp_map_action notify_only 1)"
chk_eq "prompt_then_quit deferrable (esc=0) -> silent_fail" "silent_fail" "$(bpp_map_action prompt_then_quit 0)"
chk_eq "prompt_then_quit exhausted (esc=1) -> prompt_user"  "prompt_user" "$(bpp_map_action prompt_then_quit 1)"
chk_eq "skip_run -> silent_fail"                         "silent_fail"  "$(bpp_map_action skip_run 0)"
chk_eq "skip_run escalate=1 -> silent_fail"              "silent_fail"  "$(bpp_map_action skip_run 1)"
chk_eq "unknown action -> silent_fail (fail closed)"     "silent_fail"  "$(bpp_map_action force_quit_everything 1)"
chk_eq "empty action -> silent_fail (fail closed)"       "silent_fail"  "$(bpp_map_action '' 1)"
chk_eq "default escalate arg (omitted) -> silent_fail"   "silent_fail"  "$(bpp_map_action prompt_then_quit)"

# ---------------------------------------------------------------------------
# 16. SAFE INVARIANT: prompt_user is emitted for EXACTLY ONE (action,escalate)
#     combination — prompt_then_quit + escalate=1. Every other combination maps
#     to silent_fail (never quits/kills). No force-quit/kill directive is ever
#     emitted, and no non-prompt_then_quit policy is ever quit-capable.
# ---------------------------------------------------------------------------
echo "--- 16. only prompt_then_quit-when-escalated is quit-capable"
is_quit_or_kill() {  # returns 0 (true) if $1 can force an app to quit/kill
    case "$1" in
        quit|quit_kill|kill|tell_user|tell_user_then_kill|prompt_user_then_kill|prompt_user_loop) return 0 ;;
        *) return 1 ;;
    esac
}
is_agent_safe() {  # returns 0 (true) only for the actions the agent may emit
    case "$1" in
        prompt_user|silent_fail) return 0 ;;
        *) return 1 ;;
    esac
}
for esc in 0 1; do
    for act in notify_only prompt_then_quit skip_run total_garbage ''; do
        m="$(bpp_map_action "$act" $esc)"
        chk_false "map($act,esc=$esc)='$m' is NOT a force-quit/kill"  is_quit_or_kill "$m"
        chk_true  "map($act,esc=$esc)='$m' is agent-safe"            is_agent_safe "$m"
        if [[ "$act" == "prompt_then_quit" && "$esc" == "1" ]]; then
            chk_eq "map($act,esc=$esc) IS the quit prompt"  "prompt_user"  "$m"
        else
            chk_eq "map($act,esc=$esc) never quits"  "silent_fail"  "$m"
        fi
    done
done

# ---------------------------------------------------------------------------
# 16b. Escalation decision (bpp_should_escalate): ONLY prompt_then_quit escalates,
#      and only once the deferral count reaches max_deferrals.
# ---------------------------------------------------------------------------
echo "--- 16b. bpp_should_escalate: only prompt_then_quit, only at exhaustion"
BPP_MAX_DEFERRALS=2
chk_eq "prompt_then_quit count<max -> no escalate"  "0"  "$(bpp_should_escalate prompt_then_quit 0)"
chk_eq "prompt_then_quit count=max-1 -> no escalate" "0" "$(bpp_should_escalate prompt_then_quit 1)"
chk_eq "prompt_then_quit count=max -> escalate"     "1"  "$(bpp_should_escalate prompt_then_quit 2)"
chk_eq "prompt_then_quit count>max -> escalate"     "1"  "$(bpp_should_escalate prompt_then_quit 5)"
chk_eq "notify_only never escalates (count>max)"    "0"  "$(bpp_should_escalate notify_only 9)"
chk_eq "skip_run never escalates (count>max)"       "0"  "$(bpp_should_escalate skip_run 9)"
chk_eq "unknown never escalates (count>max)"        "0"  "$(bpp_should_escalate whatever 9)"
# The escalation decision + mapping compose to the ONLY quit path.
chk_eq "escalated prompt_then_quit maps to prompt_user"  "prompt_user"  "$(bpp_map_action prompt_then_quit "$(bpp_should_escalate prompt_then_quit 2)")"
chk_eq "deferrable prompt_then_quit maps to silent_fail" "silent_fail"  "$(bpp_map_action prompt_then_quit "$(bpp_should_escalate prompt_then_quit 1)")"
# max_deferrals=0 -> prompt_then_quit escalates immediately (first blocking run).
BPP_MAX_DEFERRALS=0
chk_eq "max_deferrals=0: prompt_then_quit escalates at count 0"  "1"  "$(bpp_should_escalate prompt_then_quit 0)"
chk_eq "max_deferrals=0: notify_only still never escalates"      "0"  "$(bpp_should_escalate notify_only 0)"
BPP_MAX_DEFERRALS=2

# ---------------------------------------------------------------------------
# 17. Message wiring: default fallback, sanitisation, and tenant passthrough.
# ---------------------------------------------------------------------------
echo "--- 17. BPP_MESSAGE effective-message + sanitisation"
BPP_MESSAGE=""
chk_eq "empty message -> agent default"  "$BPP_DEFAULT_MESSAGE"  "$(bpp_effective_message)"
BPP_MESSAGE="   "
chk_eq "whitespace-only -> agent default"  "$BPP_DEFAULT_MESSAGE"  "$(bpp_effective_message)"
BPP_MESSAGE="Please save and quit to update."
chk_eq "tenant message passes through"  "Please save and quit to update."  "$(bpp_effective_message)"
# Injection-hostile input must be neutralised (no " \ ` $ and no control chars).
BPP_MESSAGE=$'evil\" ) & do shell script \"rm -rf /\" $(id) `whoami` end\n\ttrailing'
sanitized="$(bpp_effective_message)"
chk_false "sanitised message has no double-quote"  grep -q '"'   <<< "$sanitized"
chk_false "sanitised message has no backslash"     grep -q '\\'  <<< "$sanitized"
chk_false "sanitised message has no backtick"      grep -q '`'   <<< "$sanitized"
chk_false "sanitised message has no dollar"        grep -q '\$'  <<< "$sanitized"
chk_eq   "sanitised message is single line"  "1"  "$(print -r -- "$sanitized" | wc -l | tr -d ' ')"
# Length cap: a 500-char message is truncated to <= 240.
BPP_MESSAGE="$(printf 'x%.0s' {1..500})"
chk_true "long message capped at 240"  test "${#$(bpp_effective_message)}" -le 240
# Escalation copy: with no tenant message, escalate=1 uses the urgent final-notice
# default; escalate=0 uses the soft deferrable default. A tenant message overrides
# BOTH states (the tenant owns the copy).
BPP_MESSAGE=""
chk_eq "escalate=0 -> soft default"        "$BPP_DEFAULT_MESSAGE"  "$(bpp_effective_message 0)"
chk_eq "escalate=1 -> final-notice default" "$BPP_FINAL_MESSAGE"   "$(bpp_effective_message 1)"
chk_false "final-notice differs from soft default"  test "$BPP_DEFAULT_MESSAGE" = "$BPP_FINAL_MESSAGE"
BPP_MESSAGE="Tenant copy wins."
chk_eq "tenant message wins even when escalated"  "Tenant copy wins."  "$(bpp_effective_message 1)"
BPP_MESSAGE=""

# ---------------------------------------------------------------------------
# 18. Deferral gate arithmetic: honour max_deferrals + defer window transitions.
#     Mirrors the run_label gate: within-window -> skip; window-elapsed +
#     deferrals-remain -> re-prompt (no escalate); window-elapsed + exhausted ->
#     escalate. Reset clears state.
# ---------------------------------------------------------------------------
echo "--- 18. deferral gate: record/window/escalate transitions"
glbl="gateapp"
BPP_MAX_DEFERRALS=2
BPP_DEFER_WINDOW_SECS=3600
bpp_reset_deferrals "$glbl"
# Fresh: no state -> window elapsed, count 0 < max -> re-prompt (escalate=0).
chk_eq "fresh count 0"  "0"  "$(bpp_deferral_count "$glbl")"
chk_true "fresh -> window elapsed (would re-prompt)"  bpp_defer_window_elapsed "$glbl"
# Record a deferral -> within window now -> would skip silently.
bpp_record_deferral "$glbl"
chk_eq "count after 1 deferral"  "1"  "$(bpp_deferral_count "$glbl")"
chk_false "within window after deferral -> skip"  bpp_defer_window_elapsed "$glbl"
# Simulate window elapsed with deferrals still remaining (count 1 < max 2).
"$PYTHON3" -c "import json,sys;json.dump({'count':1,'last_deferred_at':'2020-01-01T00:00:00Z'},open(sys.argv[1],'w'))" "$STATE_DIR/blocking-deferrals-${glbl}.json"
chk_true "window elapsed, deferrals remain -> re-prompt"  bpp_defer_window_elapsed "$glbl"
_c=$(bpp_deferral_count "$glbl"); chk_true "count(1) < max(2): not yet exhausted"  test "$_c" -lt "$BPP_MAX_DEFERRALS"
# Simulate exhaustion (count == max) with window elapsed -> escalate decision.
"$PYTHON3" -c "import json,sys;json.dump({'count':2,'last_deferred_at':'2020-01-01T00:00:00Z'},open(sys.argv[1],'w'))" "$STATE_DIR/blocking-deferrals-${glbl}.json"
_c=$(bpp_deferral_count "$glbl")
chk_true "count(2) >= max(2): exhausted"  test "$_c" -ge "$BPP_MAX_DEFERRALS"
_e=$(bpp_should_escalate prompt_then_quit "$_c")
chk_eq  "exhausted prompt_then_quit -> escalate=1"  "1"  "$_e"
chk_eq  "exhausted notify_only -> still no escalate" "0"  "$(bpp_should_escalate notify_only "$_c")"
# Escalated prompt_then_quit -> the consent-only quit prompt; a deferrable
# prompt_then_quit (escalate=0) -> silent_fail (no quit yet).
chk_eq  "exhausted prompt_then_quit action -> prompt_user"  "prompt_user"  "$(bpp_map_action prompt_then_quit "$_e")"
chk_eq  "deferrable prompt_then_quit action -> silent_fail" "silent_fail"  "$(bpp_map_action prompt_then_quit 0)"
chk_eq  "exhausted notify_only action -> silent_fail (never quits)"  "silent_fail"  "$(bpp_map_action notify_only "$(bpp_should_escalate notify_only "$_c")")"
# Reset on successful install clears the state (so a re-blocked app starts fresh).
bpp_reset_deferrals "$glbl"
chk_eq "count after reset 0"  "0"  "$(bpp_deferral_count "$glbl")"
chk_eq "post-reset prompt_then_quit -> no escalate"  "0"  "$(bpp_should_escalate prompt_then_quit "$(bpp_deferral_count "$glbl")")"

# ---------------------------------------------------------------------------
# 19. Wiring assertions against the run_label source: PROMPT_TIMEOUT and the
#     BLOCKING_PROCESS_MESSAGE env var are actually passed to the engine, the
#     deferral recorder is actually invoked, and the dead mappings are gone.
# ---------------------------------------------------------------------------
echo "--- 19. run_label wiring (source-level assertions)"
chk_true "PROMPT_TIMEOUT wired to BPP_TIMEOUT_SECONDS"  \
    grep -q 'PROMPT_TIMEOUT=\${BPP_TIMEOUT_SECONDS}' "$TARGET"
chk_true "BLOCKING_PROCESS_MESSAGE exported to engine"  \
    grep -q 'export BLOCKING_PROCESS_MESSAGE=' "$TARGET"
chk_true "engine invocation uses mapped _bpa"  \
    grep -q 'BLOCKING_PROCESS_ACTION=\${_bpa}' "$TARGET"
chk_true "_bpa comes from bpp_map_action"  \
    grep -q '_bpa=\$(bpp_map_action' "$TARGET"
chk_true "escalation decided via bpp_should_escalate"  \
    grep -q '_escalate=\$(bpp_should_escalate' "$TARGET"
chk_true "effective message threads the escalate flag"  \
    grep -q '_bpp_msg=\$(bpp_effective_message "\$_escalate")' "$TARGET"
chk_true "bpp_record_deferral is actually called in run_label"  \
    grep -q 'bpp_record_deferral "\$label"' "$TARGET"
chk_true "bpp_reset_deferrals still called on success"  \
    grep -q 'bpp_reset_deferrals "\$label"' "$TARGET"
# The corrected mapping must NOT EMIT any force-quit/kill directive. Match the
# emission syntax only (print -r -- "X" in bpp_map_action, or a legacy _bpa="X"),
# so the forbidden-action list in the docstring comment does not trip these.
chk_false "no tell_user* directive emitted"  grep -qE '(print -r -- "|_bpa=")tell_user' "$TARGET"
chk_false "no quit_kill directive emitted"   grep -qE '(print -r -- "|_bpa=")quit_kill' "$TARGET"
chk_false "no bare kill directive emitted"   grep -qE '(print -r -- "|_bpa=")kill'       "$TARGET"
chk_false "no prompt_user_then_kill emitted" grep -qE '(print -r -- "|_bpa=")prompt_user_then_kill' "$TARGET"
chk_false "no stale skip_run->ignore"        grep -qE '(print -r -- "|_bpa=")ignore'     "$TARGET"

# Fail-closed HARD refuse: an empty (no-valid-policy) BPP_ACTION_ON_TIMEOUT must
# suppress the install entirely (engine never runs), not merely map to silent_fail
# which would still install when the app is not running.
chk_true "bpp_failclosed computed from empty BPP_ACTION_ON_TIMEOUT"  \
    grep -q 'bpp_failclosed=1' "$TARGET"
chk_true "bpp_failclosed derives from empty action + install mode"  \
    grep -qE '\[\[ -z "\$BPP_ACTION_ON_TIMEOUT" && "\$mode" == "install" \]\] && bpp_failclosed=1' "$TARGET"
chk_true "bpp_failclosed is in the engine-skip condition"  \
    grep -qE 'mode.*==.*scan.*policy_skip.*ring_skip.*bpp_failclosed' "$TARGET"
chk_true "fail_closed_policy outcome is emitted"  \
    grep -q 'outcome="fail_closed_policy"' "$TARGET"
chk_true "fail_closed_policy mapped to null for the tray"  \
    grep -q '_tray_last_action" == "fail_closed_policy"' "$TARGET"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
