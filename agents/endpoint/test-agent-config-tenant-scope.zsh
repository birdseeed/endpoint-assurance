#!/bin/zsh
##############################################################################
# test-agent-config-tenant-scope.zsh: PAT-1773 tenant scope for the endpoint
# scripts that read the cached agent-config.json.
#
# patched-update.sh and patched-log-upload.sh (shipped in the endpoint bundle)
# and the quarantined patched-install.sh and patched-uninstall.sh each carry
# the PATCHED_AGENT_CONFIG_TENANT_SCOPE block.
# agent_config_tenant_scope runs once per run after the config refresh and
# asks agent_config_tenant.py whether the cached config belongs to the
# enrolled tenant; every reader tests agent_config_present instead of the file.
#
# This test proves:
#   - the block is identical in every script, and every script calls
#     agent_config_tenant_scope once, after its config refresh and before its
#     first reader, with no reader left testing the file directly;
#   - the scope decision over the shared fixtures
#     (endpoint/fixtures/agent-config-tenant.json), including a missing or
#     symlinked module, and that a refusal is logged once;
#   - each patched-update.sh reader takes its no-config default for another
#     tenant's config and honours the same config for the enrolled tenant.
#
# No root, no network, nothing under /etc/patched or
# /Library/Application Support/Patched is touched.
#
# Run: zsh endpoint/test-agent-config-tenant-scope.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"
PYTHON3="/usr/bin/python3"
READERS=(patched-update.sh patched-log-upload.sh patched-install.sh patched-uninstall.sh)

pass=0; fail=0
chk() {  # chk <desc> <1-for-true>
    if (( $2 )); then (( pass++ )); echo "  PASS: $1"
    else (( fail++ )); echo "  FAIL: $1"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.agent-config-tenant-scope.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

extract() {  # extract <start-regex> <end-regex> <file> <dest>
    awk "/$1/{f=1;next} /$2/{f=0} f" "$3" > "$4"
}
extract_function() {  # extract_function <name> <file> >> dest
    awk -v name="$1" '$0 ~ "^" name "\\(\\) \\{" {f=1} f {print} f && /^}$/ {exit}' "$2"
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] the scope block is identical in every reader script, and wired once"
extract PATCHED_AGENT_CONFIG_TENANT_SCOPE_START PATCHED_AGENT_CONFIG_TENANT_SCOPE_END "$UPDATE_SH" "$WORK/scope.zsh"
chk "patched-update.sh carries the scope block" "$([[ -s "$WORK/scope.zsh" ]] && echo 1 || echo 0)"
for reader in "${READERS[@]}"; do
    extract PATCHED_AGENT_CONFIG_TENANT_SCOPE_START PATCHED_AGENT_CONFIG_TENANT_SCOPE_END \
        "$SCRIPT_DIR/$reader" "$WORK/scope-$reader.zsh"
    chk "$reader: scope block is byte-identical to patched-update.sh's" \
        "$(cmp -s "$WORK/scope.zsh" "$WORK/scope-$reader.zsh" && echo 1 || echo 0)"
done

wiring=$("$PYTHON3" - "$SCRIPT_DIR" "${READERS[@]}" <<'PYEOF'
import re, sys
directory, readers = sys.argv[1], sys.argv[2:]
for reader in readers:
    lines = open(f"{directory}/{reader}", encoding="utf-8").read().split("\n")
    outside, inside = [], False
    for number, line in enumerate(lines, 1):
        if "PATCHED_AGENT_CONFIG_TENANT_SCOPE_START" in line:
            inside = True
            continue
        if "PATCHED_AGENT_CONFIG_TENANT_SCOPE_END" in line:
            inside = False
            continue
        if not inside and not line.lstrip().startswith("#"):
            outside.append((number, line))
    problems = []
    direct = [n for n, l in outside if re.search(r'-f\s+"\$AGENT_CONFIG_FILE"', l)]
    if direct:
        problems.append(f"direct file tests at lines {direct}")
    calls = [n for n, l in outside if l.strip() == "agent_config_tenant_scope"]
    if len(calls) != 1:
        problems.append(f"agent_config_tenant_scope called {len(calls)} times")
    uses = [n for n, l in outside if "agent_config_present" in l]
    if not uses:
        problems.append("no reader uses agent_config_present")
    elif calls and min(uses) < calls[0]:
        problems.append("a reader runs before agent_config_tenant_scope")
    refresh = [n for n, l in outside if '"$FETCH_CONFIG" || true' in l]
    if reader != "patched-log-upload.sh" and (not refresh or not calls or refresh[0] > calls[0]):
        problems.append("scope is not evaluated after the config refresh")
    print(f"{reader}:{'ok' if not problems else '; '.join(problems)}")
PYEOF
)
for reader in "${READERS[@]}"; do
    line=$(print -r -- "$wiring" | grep "^$reader:")
    chk "$reader: readers go through agent_config_present, scope evaluated once after refresh (${line#*:})" \
        "$([[ "${line#*:}" == "ok" ]] && echo 1 || echo 0)"
done
chk "patched-update.sh: tier, blocked-version, per-app, ring and blocking readers all scoped" \
    "$(( $(grep -c 'agent_config_present' "$UPDATE_SH") >= 8 ))"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] scope decision over the shared fixtures"
BUNDLE_DIR="$SCRIPT_DIR"
source "$WORK/scope.zsh"
CREDS_DIR="$WORK/creds"
AGENT_CONFIG_FILE="$WORK/state/agent-config.json"

fixture_rows=$("$PYTHON3" - "$SCRIPT_DIR/fixtures/agent-config-tenant.json" "$WORK/fixtures" <<'PYEOF'
import json, os, sys
cases = json.load(open(sys.argv[1], encoding="utf-8"))["cases"]
for index, case in enumerate(cases):
    directory = os.path.join(sys.argv[2], str(index))
    os.makedirs(os.path.join(directory, "state"))
    os.makedirs(os.path.join(directory, "creds"))
    if case.get("config_hex") is not None:
        open(os.path.join(directory, "state", "agent-config.json"), "wb").write(bytes.fromhex(case["config_hex"]))
    elif case.get("config") is not None:
        open(os.path.join(directory, "state", "agent-config.json"), "wb").write(case["config"].encode("utf-8"))
    if case.get("tenant_id_file") is not None:
        open(os.path.join(directory, "creds", "tenant-id"), "wb").write(case["tenant_id_file"].encode("utf-8"))
    print(index, case["id"], case["expected"])
PYEOF
)
fixture_count=0
while read -r fixture_index fixture_id fixture_expected; do
    [[ -n "$fixture_index" ]] || continue
    (( fixture_count++ ))
    CREDS_DIR="$WORK/fixtures/$fixture_index/creds"
    AGENT_CONFIG_FILE="$WORK/fixtures/$fixture_index/state/agent-config.json"
    scope_out=$(agent_config_tenant_scope; print "flag=$AGENT_CONFIG_FOR_TENANT")
    want_flag=0; [[ "$fixture_expected" == "applies" ]] && want_flag=1
    chk "fixture $fixture_id: applies=$want_flag" "$([[ "$scope_out" == *"flag=$want_flag" ]] && echo 1 || echo 0)"
    refusals=$(print -r -- "$scope_out" | grep -c 'is not used this run')
    want_refusals=1; [[ "$fixture_expected" == "applies" || "$fixture_expected" == "absent" ]] && want_refusals=0
    chk "fixture $fixture_id: refusal logged $want_refusals time(s)" "$(( refusals == want_refusals ))"
done <<< "$fixture_rows"
chk "every shared fixture ran through the scope" "$(( fixture_count >= 20 ))"

mkdir -p "$WORK/state" "$WORK/creds"
CREDS_DIR="$WORK/creds"
AGENT_CONFIG_FILE="$WORK/state/agent-config.json"
print -r -- '{"tenant_id":"tenant-a","tier":"managed"}' > "$AGENT_CONFIG_FILE"
print -r -- "tenant-a" > "$CREDS_DIR/tenant-id"
BUNDLE_DIR="$WORK/no-bundle"; source "$WORK/scope.zsh"
scope_out=$(agent_config_tenant_scope; print "flag=$AGENT_CONFIG_FOR_TENANT")
chk "missing agent_config_tenant.py: config not used, reason logged" \
    "$([[ "$scope_out" == *"(tenant check unavailable)"*"flag=0" ]] && echo 1 || echo 0)"
mkdir -p "$WORK/link-bundle"; ln -s "$SCRIPT_DIR/agent_config_tenant.py" "$WORK/link-bundle/agent_config_tenant.py"
BUNDLE_DIR="$WORK/link-bundle"; source "$WORK/scope.zsh"
scope_out=$(agent_config_tenant_scope; print "flag=$AGENT_CONFIG_FOR_TENANT")
chk "symlinked agent_config_tenant.py: config not used" "$([[ "$scope_out" == *"flag=0" ]] && echo 1 || echo 0)"
BUNDLE_DIR="$SCRIPT_DIR"; source "$WORK/scope.zsh"
agent_config_tenant_scope >/dev/null
chk "enrolled tenant's config: agent_config_present" "$(agent_config_present && echo 1 || echo 0)"
rm -f "$AGENT_CONFIG_FILE"
chk "config removed after the scope ran: agent_config_present is false" "$(agent_config_present && echo 0 || echo 1)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] patched-update.sh readers: another tenant's config takes each no-config default"
extract PATCHED_AGENT_TIER_DEFAULT_START PATCHED_AGENT_TIER_DEFAULT_END "$UPDATE_SH" "$WORK/tier.zsh"
extract PATCHED_BLOCKED_VERSION_PREFLIGHT_START PATCHED_BLOCKED_VERSION_PREFLIGHT_END "$UPDATE_SH" "$WORK/blocked.zsh"
{
    awk '/^POLICY_DEFAULT_ENABLED=1/{print} /^typeset -A POLICY_OVERRIDE/{print; exit}' "$UPDATE_SH"
    extract_function load_per_app_policy "$UPDATE_SH"
    awk '/^DEVICE_RING=3/{f=1} f && /^load_ring_policy\(\) \{/{exit} f{print}' "$UPDATE_SH"
    extract_function load_ring_policy "$UPDATE_SH"
    awk '/^BPP_MESSAGE=""/{f=1} f && /^load_blocking_process_policy\(\) \{/{exit} f{print}' "$UPDATE_SH"
    extract_function load_blocking_process_policy "$UPDATE_SH"
} > "$WORK/readers.zsh"
chk "reader functions extracted" "$([[ -s "$WORK/tier.zsh" && -s "$WORK/blocked.zsh" && $(grep -c '() {' "$WORK/readers.zsh") -eq 3 ]] && echo 1 || echo 0)"

log_jsonl() { :; }
AGENT_CONFIG_SHA256_FILE="$WORK/state/agent-config.sha256"
POLICY_JSON='"tier":"managed","per_app_patch":false,"ring":0,
 "blocked_versions":{"examplelabel":["1.0"]},
 "blocking_process_policy":{"action_on_timeout":"notify_only","timeout_seconds":60,"max_deferrals":1,"defer_window_seconds":600,"message":"m"}'

# run_readers <config tenant> <enrolled tenant>: prints one line per reader.
run_readers() {
    (
        mkdir -p "$WORK/state"
        print -r -- "{\"tenant_id\":\"$1\",$POLICY_JSON}" > "$AGENT_CONFIG_FILE"
        shasum -a 256 "$AGENT_CONFIG_FILE" | awk '{print $1}' > "$AGENT_CONFIG_SHA256_FILE"
        print -r -- "$2" > "$CREDS_DIR/tenant-id"
        source "$WORK/scope.zsh"
        source "$WORK/blocked.zsh"
        source "$WORK/readers.zsh"
        agent_config_tenant_scope >/dev/null
        source "$WORK/tier.zsh" 2>/dev/null
        print "tier=$AGENT_TIER"
        print "blocked=$(blocked_version_policy_state examplelabel 1.0)"
        load_per_app_policy >/dev/null
        print "per_app_default=$POLICY_DEFAULT_ENABLED"
        load_ring_policy >/dev/null 2>&1
        print "ring=$DEVICE_RING"
        load_blocking_process_policy >/dev/null
        print "bpp_action=${BPP_ACTION_ON_TIMEOUT:-<fail-closed>}"
    )
}

same=$(run_readers tenant-a tenant-a)
other=$(run_readers tenant-old tenant-a)
chk "enrolled tenant: tier from config (managed)" "$([[ "$same" == *"tier=managed"* ]] && echo 1 || echo 0)"
chk "other tenant: tier stays assurance" "$([[ "$other" == *"tier=assurance"* ]] && echo 1 || echo 0)"
chk "enrolled tenant: blocked_versions applies" "$([[ "$same" == *"blocked=blocked"* ]] && echo 1 || echo 0)"
chk "other tenant: blocked_versions is no_policy (no-config default)" "$([[ "$other" == *"blocked=no_policy"* ]] && echo 1 || echo 0)"
chk "enrolled tenant: per_app_patch false applies" "$([[ "$same" == *"per_app_default=0"* ]] && echo 1 || echo 0)"
chk "other tenant: per_app_patch estate default (no-config default)" "$([[ "$other" == *"per_app_default=1"* ]] && echo 1 || echo 0)"
chk "enrolled tenant: ring 0 applies" "$([[ "$same" == *"ring=0"* ]] && echo 1 || echo 0)"
chk "other tenant: ring stays 3 (no-config default)" "$([[ "$other" == *"ring=3"* ]] && echo 1 || echo 0)"
chk "enrolled tenant: blocking policy action applies" "$([[ "$same" == *"bpp_action=notify_only"* ]] && echo 1 || echo 0)"
chk "other tenant: blocking policy stays fail-closed" "$([[ "$other" == *"bpp_action=<fail-closed>"* ]] && echo 1 || echo 0)"

echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]]
