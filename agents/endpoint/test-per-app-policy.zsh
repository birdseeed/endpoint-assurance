#!/bin/zsh
##############################################################################
# test-per-app-policy.zsh — unit tests for the PAT-383 per-app update policy
# engine in patched-update.sh (macOS parity with the Windows PAT-381 resolver).
#
# Sources the live policy functions out of patched-update.sh (between stable
# markers) so the tests exercise the real code, not a copy. Run:
#   zsh endpoint/test-per-app-policy.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-update.sh"
PYTHON3="/usr/bin/python3"
AGENT_CONFIG_FILE="$(mktemp /tmp/.patched-policy-test.XXXXXX)"
trap 'rm -f "$AGENT_CONFIG_FILE"' EXIT

# Extract POLICY_* state + load_per_app_policy/policy_allows/policy_source.
FUNCS="$(mktemp /tmp/.patched-policy-funcs.XXXXXX)"
awk '
  /^POLICY_DEFAULT_ENABLED=1/{f=1}
  f{print}
  /^# policy_source <label>/{p=1}
  p && /^}$/{exit}
' "$TARGET" > "$FUNCS"
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

pass=0; fail=0
chk() {  # chk <desc> <expected:allow|skip> <label> <bundle_id>
    local desc="$1" exp="$2" lbl="$3" bid="$4" got
    if policy_allows "$lbl" "$bid"; then got="allow"; else got="skip"; fi
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc -> $got"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}
chk_src() {  # chk_src <expected> <label> <bundle_id>
    local exp="$1" lbl="$2" bid="$3" got; got="$(policy_source "$lbl" "$bid")"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: source=$got"
    else (( fail++ )); echo "  FAIL: source got=$got want=$exp"; fi
}
load_cfg() { POLICY_DEFAULT_ENABLED=1; typeset -gA POLICY_OVERRIDE=(); printf '%s' "$1" > "$AGENT_CONFIG_FILE"; load_per_app_policy; }

echo "--- 1. per_app_patch absent -> estate default ON (fail-open)"
load_cfg '{"tier":"managed"}'
chk "any app allowed" allow googlechrome com.google.Chrome

echo "--- 2. per_app_patch null -> estate default ON"
load_cfg '{"per_app_patch":null}'
chk "any app allowed" allow firefox org.mozilla.firefox

echo "--- 3. fleet_default_enabled=false, no overrides -> all OFF"
load_cfg '{"per_app_patch":{"fleet_default_enabled":false,"overrides":[]}}'
chk "estate off blocks app" skip slack com.tinyspeck.slackmacgap

echo "--- 4. override by LABEL enabled=false (estate on)"
load_cfg '{"per_app_patch":{"fleet_default_enabled":true,"overrides":[{"platform":"macos","identifier":"googlechrome","enabled":false}]}}'
chk "label override disables chrome" skip googlechrome com.google.Chrome
chk "other app still estate-on"      allow firefox org.mozilla.firefox

echo "--- 5. override by BUNDLE ID enabled=false, case-insensitive (estate on)"
load_cfg '{"per_app_patch":{"fleet_default_enabled":true,"overrides":[{"platform":"macos","identifier":"com.google.Chrome","enabled":false}]}}'
chk "bundle-id override disables chrome" skip googlechrome com.google.Chrome

echo "--- 6. override enabled=true while estate OFF -> that app ON"
load_cfg '{"per_app_patch":{"fleet_default_enabled":false,"overrides":[{"platform":"macos","identifier":"firefox","enabled":true}]}}'
chk "override re-enables firefox"     allow firefox org.mozilla.firefox
chk "non-overridden app stays off"    skip  slack   com.tinyspeck.slackmacgap

echo "--- 7. windows-platform override is ignored on macOS"
load_cfg '{"per_app_patch":{"fleet_default_enabled":true,"overrides":[{"platform":"windows","identifier":"googlechrome","enabled":false}]}}'
chk "windows override does not affect macOS" allow googlechrome com.google.Chrome

echo "--- 8. per_app_patch as bare bool false -> all OFF"
load_cfg '{"per_app_patch":false}'
chk "bool false blocks" skip zoom us.zoom.xos

echo "--- 9. malformed per_app_patch -> fail-open ON"
load_cfg '{"per_app_patch":"garbage"}'
chk "malformed fails open" allow zoom us.zoom.xos

echo "--- 10. policy_source resolution"
load_cfg '{"per_app_patch":{"fleet_default_enabled":true,"overrides":[{"platform":"macos","identifier":"com.google.Chrome","enabled":false}]}}'
chk_src override      googlechrome com.google.Chrome
chk_src fleet_default firefox      org.mozilla.firefox

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
