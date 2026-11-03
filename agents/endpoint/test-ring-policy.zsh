#!/bin/zsh
# PAT-1134: exercise the live macOS ring parser against the published wire
# shape. The scoped contract is authoritative when present; nobody is deny.
set -u

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-update.sh"
PYTHON3="/usr/bin/python3"
AGENT_CONFIG_FILE="$(mktemp /tmp/.patched-ring-policy.XXXXXX)"
FUNCS="$(mktemp /tmp/.patched-ring-policy-funcs.XXXXXX)"
trap 'rm -f "$AGENT_CONFIG_FILE" "$FUNCS"' EXIT

awk '/^DEVICE_RING=3/{f=1} f{print} /^load_ring_policy$/{exit}' "$TARGET" > "$FUNCS"
source "$FUNCS"
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

pass=0 fail=0
check() {
    local desc="$1" want="$2" label="$3" got=deny
    ring_allows "$label" && got=allow
    if [[ "$got" == "$want" ]]; then ((pass++)); echo "PASS: $desc"
    else ((fail++)); echo "FAIL: $desc got=$got want=$want"; fi
}
load() { print -r -- "$1" > "$AGENT_CONFIG_FILE"; load_ring_policy; }

load '{"ring":0,"ring_promotions":{"firefox":{"version":"legacy","approved_ring":3}},"ring_promotions_scoped":{"macos":{"firefox":{"version":"130.0","approval":"nobody"}}}}'
check "scoped explicit nobody denies first ring" deny firefox

load '{"ring":2,"ring_promotions":{"firefox":{"version":"legacy","approved_ring":0}},"ring_promotions_scoped":{"macos":{"firefox":{"version":"130.0","approval":"up_to_ring","approved_ring":2}}}}'
check "scoped approval overrides conservative legacy projection" allow firefox

load '{"ring":3,"ring_promotions":{"firefox":{"version":"130.0","approved_ring":0}},"ring_promotions_scoped":{}}'
check "present scoped empty map does not consult legacy" allow firefox

load '{"ring":3,"ring_promotions":{"firefox":{"version":"legacy","approved_ring":0}},"ring_promotions_scoped":{"macos":{"googlechrome":{"version":"130.0","approval":"nobody"}}}}'
check "missing label in present platform map does not consult legacy" allow firefox

load '{"ring":2,"ring_promotions":{"firefox":{"version":"130.0","approved_ring":1}}}'
check "legacy fallback remains conservative for old projection" deny firefox

load '{"ring":0,"ring_promotions_scoped":{"macos":{"firefox":{"version":"130.0","approval":"up_to_ring"}}}}'
check "malformed scoped approval without ring denies" deny firefox

load '{"ring":0,"ring_promotions_scoped":{"macos":{"firefox":{"version":"130.0","approval":"unexpected","approved_ring":3}}}}'
check "unknown scoped approval denies" deny firefox

load '{"ring":1,"ring_promotions_scoped":{"macos":{"space label":{"version":"130.0","approval":"up_to_ring","approved_ring":0}}}}'
check "tab-delimited parser preserves spaces in labels" deny "space label"

load '{"ring":0,"ring_promotions_scoped":{"macos":null}}'
check "present null macos platform section denies every label" deny firefox

echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
