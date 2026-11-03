#!/bin/zsh
##############################################################################
# test-agent-config-hash-gate.zsh — tests for the PAT-1035 finding-2 hash
# binding in endpoint/patched-fetch-config.sh (_agent_config_hash_matches,
# _agent_config_sha256).
#
# If-None-Match is sent from AGENT_CONFIG_VERSION_FILE, so a 304 only proves
# the server thinks the recorded VERSION is current — it says nothing about
# whether AGENT_CONFIG_FILE's bytes are still the ones that were actually
# verified. In the mixed-version window an old, unverified uploader can
# overwrite agent-config.json without touching the version sidecar, so the
# 304 path must not stamp a fresh heartbeat unless the on-disk bytes still
# hash to the value recorded at the last verified commit.
#
# This extracts the sentinel-delimited PATCHED_CONFIG_HASH_CHECK block from
# the SHIPPED patched-fetch-config.sh (same awk-extraction pattern
# macos/test-agent-config-gate.zsh and macos/lib/test-patched-creds.zsh use)
# and drives it directly against a temp dir, so the code under test is the
# code that ships, not a copy. No root, no network, needed.
#
# What this does NOT cover: the surrounding HTTP flow — the curl request
# itself, and the If-None-Match suppression logic that reads the
# force-refetch sentinel before the request goes out. That needs a live (or
# mocked) server. The two decision flows that consume this hash check — the
# 200-path commit sequence and the 304 decision path, including the
# force-refetch sentinel being set on a mismatch and cleared on the next
# verified commit — used to be listed here as also out of scope for the same
# reason. They are not: both are now plain functions
# (_agent_config_commit_verified, _agent_config_handle_304) and are covered
# directly, no root or live server needed, by
# endpoint/test-agent-config-commit.zsh.
#
# Run: zsh endpoint/test-agent-config-hash-gate.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
FETCH_SH="$SCRIPT_DIR/patched-fetch-config.sh"

GATE_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-hash-gate.XXXXXX")
awk '/PATCHED_CONFIG_HASH_CHECK_START/{f=1;next} /PATCHED_CONFIG_HASH_CHECK_END/{f=0} f' \
    "$FETCH_SH" > "$GATE_TMP"
if [[ ! -s "$GATE_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_CONFIG_HASH_CHECK block from $FETCH_SH"
    exit 1
fi
source "$GATE_TMP"
rm -f "$GATE_TMP"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-hash-gate-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

AGENT_CONFIG_FILE="$WORK/agent-config.json"
AGENT_CONFIG_SHA256_FILE="$WORK/agent-config.sha256"

# ───────────────────────────────────────────────────────────────────────────
echo "[1] config bytes match the recorded hash: matches"
echo '{"tier":"standard","config_version":1}' > "$AGENT_CONFIG_FILE"
_agent_config_sha256 "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
if _agent_config_hash_matches; then result=match; else result=mismatch; fi
chk "matches when on-disk bytes equal the recorded hash" "$([[ "$result" == "match" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] config bytes tampered after the hash was recorded (mixed-uploader drift): mismatches"
echo '{"tier":"standard","config_version":1,"app_control":{"admins":["attacker"]}}' > "$AGENT_CONFIG_FILE"
if _agent_config_hash_matches; then result=match; else result=mismatch; fi
chk "mismatches when on-disk bytes diverge from the recorded hash" "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] hash file missing (pre-fix state / never verified via 200): mismatches, not a silent pass"
echo '{"tier":"standard","config_version":1}' > "$AGENT_CONFIG_FILE"
rm -f "$AGENT_CONFIG_SHA256_FILE"
if _agent_config_hash_matches; then result=match; else result=mismatch; fi
chk "mismatches when AGENT_CONFIG_SHA256_FILE does not exist" "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] config file missing: mismatches"
echo "deadbeef" > "$AGENT_CONFIG_SHA256_FILE"
rm -f "$AGENT_CONFIG_FILE"
if _agent_config_hash_matches; then result=match; else result=mismatch; fi
chk "mismatches when AGENT_CONFIG_FILE does not exist" "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] recorded hash has trailing whitespace/newline (as shasum output does): still matches"
echo '{"tier":"standard","config_version":2}' > "$AGENT_CONFIG_FILE"
printf '%s  agent-config.json\n' "$(shasum -a 256 "$AGENT_CONFIG_FILE" | awk '{print $1}')" > "$AGENT_CONFIG_SHA256_FILE"
# ^ deliberately shasum's raw two-column format (hash + filename), not just
# the hex digest, to prove `head -1 | tr -d whitespace` only strips
# whitespace and does not accidentally match on a differently-formatted file.
if _agent_config_hash_matches; then result=match; else result=mismatch; fi
chk "two-column shasum-style hash file does not falsely match (format must be bare hex)" \
    "$([[ "$result" == "mismatch" ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
