#!/bin/zsh
##############################################################################
# PAT-1238: prove the macOS blocked_versions preflight reads the paired
# latest_verified_version and sha256 from the local signature-verified
# catalogue, before the install-capable Installomator invocation. Since
# PAT-2245 the catalogue is retired and that reader always refuses.
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/.blocked-version-preflight.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

extract_block() {  # <start sentinel> <end sentinel> <destination>
    awk "/$1/{f=1;next} /$2/{f=0} f" "$UPDATE_SH" > "$3"
    [[ -s "$3" ]]
}

POLICY_BLOCK="$WORK/policy.zsh"
METADATA_BLOCK="$WORK/metadata.zsh"
MIRROR_GATE_BLOCK="$WORK/mirror-gate.zsh"
extract_block PATCHED_BLOCKED_VERSION_PREFLIGHT_START PATCHED_BLOCKED_VERSION_PREFLIGHT_END "$POLICY_BLOCK" \
    || { echo "FATAL: blocked-version policy block missing"; exit 1; }
extract_block PATCHED_GET_PINNED_CATALOGUE_METADATA_START PATCHED_GET_PINNED_CATALOGUE_METADATA_END "$METADATA_BLOCK" \
    || { echo "FATAL: paired catalogue metadata block missing"; exit 1; }
extract_block PATCHED_MIRROR_SIGNED_CATALOGUE_GATE_START PATCHED_MIRROR_SIGNED_CATALOGUE_GATE_END "$MIRROR_GATE_BLOCK" \
    || { echo "FATAL: signed-catalogue mirror gate missing"; exit 1; }
source "$POLICY_BLOCK"
source "$METADATA_BLOCK"
source "$MIRROR_GATE_BLOCK"
# PAT-1773: every reader asks agent_config_present. Source the shipped scope
# block and mark each fixture config as the enrolled tenant's; the tenant
# decision itself is tested in endpoint/test-agent-config-tenant-scope.zsh.
SCOPE_BLOCK="$(mktemp "${TMPDIR:-/tmp}/.patched-tenant-scope.XXXXXX")"
awk '/PATCHED_AGENT_CONFIG_TENANT_SCOPE_START/{f=1;next} /PATCHED_AGENT_CONFIG_TENANT_SCOPE_END/{f=0} f' \
    "$UPDATE_SH" > "$SCOPE_BLOCK"
BUNDLE_DIR="${BUNDLE_DIR:-$SCRIPT_DIR}"
source "$SCOPE_BLOCK"
rm -f "$SCOPE_BLOCK"
AGENT_CONFIG_FOR_TENANT=1

PYTHON3="${PYTHON3:-/usr/bin/python3}"
AGENT_CONFIG_FILE="$WORK/agent-config.json"
CATALOGUE_FILE="$WORK/catalogue.json"
VALID_HASH=$(printf 'a%.0s' {1..64})
pass=0; fail=0
check() {
    if [[ "$2" == "1" ]]; then (( pass++ )); echo "  PASS: $1"
    else (( fail++ )); echo "  FAIL: $1"; fi
}

echo "[1] absent or empty policy preserves the normal path"
rm -f "$AGENT_CONFIG_FILE"
check "absent config returns no_policy" "$([[ "$(blocked_version_policy_state firefox)" == no_policy ]] && echo 1 || echo 0)"
print '{"blocked_versions":{"firefox":[]}}' > "$AGENT_CONFIG_FILE"
check "explicit empty label list returns no_policy" "$([[ "$(blocked_version_policy_state firefox)" == no_policy ]] && echo 1 || echo 0)"

echo "[2] a valid policy drives a local-catalogue preflight"
print '{"blocked_versions":{"firefox":["153.0.3"]}}' > "$AGENT_CONFIG_FILE"
check "active list requires a preflight" "$([[ "$(blocked_version_policy_state firefox)" == preflight_required ]] && echo 1 || echo 0)"
print "{\"labels\":{\"firefox\":{\"sha256\":\"$VALID_HASH\",\"latest_verified_version\":\"153.0.3\"}}}" > "$CATALOGUE_FILE"
metadata=$(get_pinned_catalogue_metadata firefox 2>/dev/null); rc=$?
# PAT-2245: the catalogue is retired, so even a well-formed leftover entry is
# never read; the preflight cannot resolve and an active block refuses.
check "retired catalogue: a leftover valid entry is never returned (exit 3)" "$([[ $rc -eq 3 && -z "$metadata" ]] && echo 1 || echo 0)"
check "paired version is blocked" "$([[ "$(blocked_version_policy_state firefox 153.0.3)" == blocked ]] && echo 1 || echo 0)"
check "different paired version is allowed" "$([[ "$(blocked_version_policy_state firefox 153.0.4)" == allowed ]] && echo 1 || echo 0)"

echo "[3] malformed policy or incomplete metadata fails closed"
print '[]' > "$AGENT_CONFIG_FILE"
check "non-object config is invalid" "$( [[ "$(blocked_version_policy_state firefox)" == invalid ]] && echo 1 || echo 0)"
print '{"blocked_versions":{"firefox":"153.0.3"}}' > "$AGENT_CONFIG_FILE"
check "non-list policy is invalid" "$([[ "$(blocked_version_policy_state firefox)" == invalid ]] && echo 1 || echo 0)"
print '{"blocked_versions":{"firefox":["153.0.3"]}}' > "$AGENT_CONFIG_FILE"
rm -f "$CATALOGUE_FILE"
get_pinned_catalogue_metadata firefox >/dev/null 2>&1; rc=$?
check "no catalogue at all returns exit 3" "$([[ $rc -eq 3 ]] && echo 1 || echo 0)"

echo "[4] an active block never lets a divergent mirror replace signed metadata"
MIRROR_CDN_BASE="https://mirror.patched.im"
MIRROR_MANIFEST_FILE="$WORK/mirror-manifest.json"
print "{\"entries\":[{\"label\":\"firefox\",\"url\":\"https://mirror.patched.im/firefox/153.0.3/firefox.pkg\",\"sha256\":\"$VALID_HASH\",\"version\":\"153.0.3\"}]}" > "$MIRROR_MANIFEST_FILE"
mirror_url=$(mirror_url_matching_signed_catalogue firefox "$VALID_HASH" 153.0.3); rc=$?
check "matching mirror is eligible" "$([[ $rc -eq 0 && "$mirror_url" == https://mirror.patched.im/firefox/153.0.3/firefox.pkg ]] && echo 1 || echo 0)"
print "{\"entries\":[{\"label\":\"firefox\",\"url\":\"https://mirror.patched.im/firefox/153.0.4/firefox.pkg\",\"sha256\":\"$VALID_HASH\",\"version\":\"153.0.4\"}]}" > "$MIRROR_MANIFEST_FILE"
mirror_url=$(mirror_url_matching_signed_catalogue firefox "$VALID_HASH" 153.0.3); rc=$?
check "divergent mirror version is bypassed" "$([[ $rc -ne 0 && -z "$mirror_url" ]] && echo 1 || echo 0)"
print "{\"entries\":[{\"label\":\"firefox\",\"url\":\"https://mirror.patched.im/firefox/153.0.3/firefox.pkg\",\"sha256\":\"$(printf 'b%.0s' {1..64})\",\"version\":\"153.0.3\"}]}" > "$MIRROR_MANIFEST_FILE"
mirror_url=$(mirror_url_matching_signed_catalogue firefox "$VALID_HASH" 153.0.3); rc=$?
check "divergent mirror SHA-256 is bypassed" "$([[ $rc -ne 0 && -z "$mirror_url" ]] && echo 1 || echo 0)"

echo "[5] source ordering, suppression, outcome, and event mapping"
metadata_line=$(grep -n 'get_pinned_catalogue_metadata "\$label"' "$UPDATE_SH" | head -1 | cut -d: -f1)
engine_line=$(grep -n '"\$INSTALLOMATOR" "\$label"' "$UPDATE_SH" | head -1 | cut -d: -f1)
check "paired catalogue metadata is read before Installomator (line $metadata_line < $engine_line)" \
    "$([[ -n "$metadata_line" && -n "$engine_line" && $metadata_line -lt $engine_line ]] && echo 1 || echo 0)"
check "version_blocked maps to an audit event" \
    "$(grep -q 'version_blocked)      _ev_type="version_blocked"' "$UPDATE_SH" && echo 1 || echo 0)"
check "version_blocked audit event uses the refused candidate version" \
    "$(grep -q '\[\[ "\$outcome" == "version_blocked" && -n "\$available_ver" \]\] && _ev_version="\$available_ver"' "$UPDATE_SH" && echo 1 || echo 0)"
check "every metadata failure marks blocked preflight failed" \
    "$(grep -q '\[\[ \$_pinned_rc -eq 2 || \$_pinned_rc -eq 3 || \$_pinned_rc -eq 4 \]\]' "$UPDATE_SH" && echo 1 || echo 0)"
check "both block refusal flags suppress the engine" \
    "$(grep -q '"\$blocked_version_refused" == 1 || "\$blocked_version_preflight_failed" == 1' "$UPDATE_SH" && echo 1 || echo 0)"
check "metadata failure maps to verification_failed audit evidence" \
    "$(grep -q 'outcome="verification_failed"; state="verification_failed"' "$UPDATE_SH" && grep -q 'failure_reason="blocked_version_resolution_failed"' "$UPDATE_SH" && echo 1 || echo 0)"
mirror_active_line=$(grep -n 'if (( blocked_version_policy_active )); then' "$UPDATE_SH" | head -1 | cut -d: -f1)
mirror_else_line=$(tail -n "+$mirror_active_line" "$UPDATE_SH" | grep -n '^        else$' | head -1 | cut -d: -f1)
mirror_else_line=$((mirror_active_line + mirror_else_line - 1))
mirror_end_line=$(tail -n "+$mirror_else_line" "$UPDATE_SH" | grep -n '^        fi$' | head -1 | cut -d: -f1)
mirror_end_line=$((mirror_else_line + mirror_end_line - 1))
mirror_active_branch=$(sed -n "$((mirror_active_line + 1)),$((mirror_else_line - 1))p" "$UPDATE_SH")
mirror_legacy_branch=$(sed -n "$((mirror_else_line + 1)),$((mirror_end_line - 1))p" "$UPDATE_SH")
check "active-policy mirror branch calls only the signed-catalogue gate" \
    "$( [[ -n "$mirror_active_line" && -n "$mirror_else_line" && -n "$mirror_end_line" && "$mirror_active_branch" == *'mirror_url_matching_signed_catalogue'* && "$mirror_active_branch" != *'get_mirror_url'* && "$mirror_active_branch" != *'get_mirror_pinned_sha256'* ]] && echo 1 || echo 0)"
check "legacy mirror resolution is contained in the non-active else branch" \
    "$( [[ "$mirror_legacy_branch" == *'get_mirror_url'* && "$mirror_legacy_branch" == *'get_mirror_pinned_sha256'* && "$mirror_legacy_branch" != *'mirror_url_matching_signed_catalogue'* ]] && echo 1 || echo 0)"
check "no vendor version resolver or engine VERSION_ONLY mode remains" \
    "$(! grep -qE 'resolve_available_version|VERSION_ONLY' "$UPDATE_SH" && echo 1 || echo 0)"

echo
echo "=== $pass passed, $fail failed ==="
(( fail == 0 ))
