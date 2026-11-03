#!/bin/zsh
##############################################################################
# test-agent-tier-default.zsh: regression guard for the AGENT_TIER default
# in endpoint/patched-update.sh (PAT-1040, PAT-1076).
#
# PAT-1040 makes patched-fetch-config.sh quarantine (move aside) a config
# file whose on-disk bytes fail a confirmed 304 hash-mismatch check, so
# AGENT_CONFIG_FILE can now be legitimately absent for up to one ~15-minute
# poll cycle in a scenario that previously left the file in place. This test
# does not exercise the quarantine itself (that is
# endpoint/test-agent-config-commit.zsh's job) — it proves the OTHER half of
# the safety argument: that patched-update.sh, the daemon that actually
# installs software, already treats an absent/malformed/invalid-tier config
# as assurance (the no-install tier), so quarantining is safe. This
# behavior already existed before PAT-1040 and is unchanged by it; this test
# closes a pre-existing coverage gap (endpoint/test-install-mode.zsh covers a
# different block — install.sh's file-mode mapping — and does not touch
# AGENT_TIER at all).
#
# PAT-1076 adds an independent hash check to this same block: before
# AGENT_TIER is read from AGENT_CONFIG_FILE, its on-disk bytes must hash to
# the value recorded in AGENT_CONFIG_SHA256_FILE (the hash file
# patched-fetch-config.sh writes on every verified commit — see that
# script's PATCHED_CONFIG_HASH_CHECK block, covered directly by
# endpoint/test-agent-config-hash-gate.zsh). Cases [1]-[7] below now write a
# matching hash file alongside AGENT_CONFIG_FILE so they keep exercising the
# JSON/tier-parsing behavior specifically, not the hash gate. Cases
# [8]-[9] prove the hash gate itself: a missing or mismatched hash file
# falls back to assurance — the exact same branch/result as case [1]'s
# fully-absent config, not a parallel fallback — even though the underlying
# JSON has tier=managed.
#
# Extracts the SHIPPED PATCHED_AGENT_TIER_DEFAULT block (sentinel markers,
# bare code — not a function, same extraction pattern
# endpoint/test-install-mode.zsh uses for install.sh's bare case statement)
# from patched-update.sh and sources it directly against a temp dir, no
# root, no network, no real install.
#
# Run: zsh endpoint/test-agent-tier-default.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-agent-tier-default.XXXXXX")
awk '/PATCHED_AGENT_TIER_DEFAULT_START/{f=1;next} /PATCHED_AGENT_TIER_DEFAULT_END/{f=0} f' \
    "$UPDATE_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_AGENT_TIER_DEFAULT block from $UPDATE_SH"
    exit 1
fi

pass=0; fail=0
chk() {  # chk <desc> <1-for-true, 0-for-false>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

PYTHON3="/usr/bin/python3"

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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.agent-tier-default-test.XXXXXX")
trap 'rm -rf "$WORK" "$BLOCK_TMP"' EXIT

AGENT_CONFIG_FILE="$WORK/agent-config.json"
AGENT_CONFIG_SHA256_FILE="$WORK/agent-config.sha256"

# run_block: sources the extracted bare block against the current
# AGENT_CONFIG_FILE / AGENT_CONFIG_SHA256_FILE / PYTHON3, in a subshell so
# AGENT_TIER from one case never leaks into the next, and echoes the
# resulting AGENT_TIER.
run_block() {
    (
        source "$BLOCK_TMP"
        echo "$AGENT_TIER"
    )
}

# write_matching_hash: records AGENT_CONFIG_FILE's current on-disk bytes'
# real SHA-256 into AGENT_CONFIG_SHA256_FILE, same bare-hex-line format
# patched-fetch-config.sh's _write_agent_config_sha256 writes. Used by cases
# that want to exercise the JSON/tier-parsing behavior specifically, with
# the hash gate passing.
write_matching_hash() {
    shasum -a 256 "$AGENT_CONFIG_FILE" | awk '{print $1}' > "$AGENT_CONFIG_SHA256_FILE"
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] AGENT_CONFIG_FILE does not exist: defaults to assurance (scan-only, no patching)"
rm -f "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_SHA256_FILE"
chk "AGENT_TIER == assurance when config is absent" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] AGENT_CONFIG_FILE exists but is not valid JSON: defaults to assurance"
printf 'not json{{{' > "$AGENT_CONFIG_FILE"
write_matching_hash
chk "AGENT_TIER == assurance on unparseable config" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] AGENT_CONFIG_FILE exists, valid JSON, but has no 'tier' key: defaults to assurance"
printf '{"config_version":1}' > "$AGENT_CONFIG_FILE"
write_matching_hash
chk "AGENT_TIER == assurance when tier key is absent" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] AGENT_CONFIG_FILE has an unrecognized tier value: defaults to assurance, not passed through"
printf '{"tier":"super_admin_mode"}' > "$AGENT_CONFIG_FILE"
write_matching_hash
chk "AGENT_TIER == assurance on an invalid/unrecognized tier value" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] AGENT_CONFIG_FILE has tier=assurance explicitly, hash matches: passes through"
printf '{"tier":"assurance"}' > "$AGENT_CONFIG_FILE"
write_matching_hash
chk "AGENT_TIER == assurance when explicitly set" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[6] AGENT_CONFIG_FILE has tier=patch (PAT-1807: retired name): falls back to assurance, not passed through"
printf '{"tier":"patch"}' > "$AGENT_CONFIG_FILE"
write_matching_hash
chk "AGENT_TIER == assurance when the retired 'patch' value is on disk" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[7] AGENT_CONFIG_FILE has tier=managed (the only value that actuates installs), hash matches: passes through"
printf '{"tier":"managed"}' > "$AGENT_CONFIG_FILE"
write_matching_hash
chk "AGENT_TIER == managed when explicitly set and hash matches" \
    "$([[ "$(run_block)" == "managed" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1076: the hash gate itself. Both cases below use tier=managed — the
# tier value most consequential to get wrong — with AGENT_CONFIG_SHA256_FILE
# broken in a different way, and both must land on assurance: the exact
# same result (and code path) as case [1]'s fully-absent config, proving
# this is not a parallel/bespoke fallback.
echo "[8] AGENT_CONFIG_FILE exists (tier=managed) but AGENT_CONFIG_SHA256_FILE is missing: falls back to assurance"
printf '{"tier":"managed"}' > "$AGENT_CONFIG_FILE"
rm -f "$AGENT_CONFIG_SHA256_FILE"
chk "AGENT_TIER == assurance when hash file is missing (not managed, despite tier=managed on disk)" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[9] AGENT_CONFIG_FILE exists (tier=managed) but AGENT_CONFIG_SHA256_FILE does not match its bytes: falls back to assurance"
printf '{"tier":"managed"}' > "$AGENT_CONFIG_FILE"
printf '%s\n' "0000000000000000000000000000000000000000000000000000000000000000" > "$AGENT_CONFIG_SHA256_FILE"
chk "AGENT_TIER == assurance on a hash mismatch (not managed, despite tier=managed on disk)" \
    "$([[ "$(run_block)" == "assurance" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
