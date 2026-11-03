#!/bin/zsh
##############################################################################
# test-decommission-gate.zsh — tests for the PAT-1109 decommission
# point-of-action gate (_decommission_check / _decommission_poll_hook) in
# endpoint/patched-fetch-config.sh.
#
# This is the single most destructive path in the product — an agent that
# removes itself. FAIL CLOSED is the entire point: every case below that is
# not a confident, verified "act" must leave the agent exactly as it was.
# The load-bearing property under test is the one named directly in the
# ticket: "Nothing in this path may be triggerable by an unsigned or
# locally-modified config file on disk" — cases [7]-[9] below drive that
# directly, by writing a decommission="immediate" directive straight to
# AGENT_CONFIG_FILE the way an attacker with write access (but no signing
# key) would, and proving the gate refuses every time.
#
# Same extraction pattern as macos/test-agent-config-gate.zsh and
# endpoint/test-agent-config-commit.zsh: pull the sentinel-delimited blocks
# out of the SHIPPED patched-fetch-config.sh and drive them directly, no
# root, no network. _decommission_check depends on _agent_config_hash_matches
# (defined in PATCHED_CONFIG_COMMIT, extracted first) — that dependency is
# not incidental, it is the hash-pin property this whole ticket rests on, so
# this test extracts both blocks rather than stubbing the dependency away.
#
# What this does NOT cover, and why:
#   - The real removal (_decommission_trigger_removal's launchctl/install/cp
#     calls) — stubbed here (counted, args captured) and covered instead by
#     endpoint/test-decommission-orchestrator.zsh (patched-decommission.sh
#     itself) plus the existing endpoint/uninstall.sh and macos/uninstall.sh
#     suites those scripts reuse unmodified.
#   - Ed25519 verification itself — covered by test-verify-agent-config.py.
#     This gate never re-runs that math; it trusts the hash-pin
#     (AGENT_CONFIG_SHA256_FILE) that verify-agent-config.py's own output
#     is the only thing that ever writes, which is exactly what cases
#     [7]-[9] prove cannot be bypassed by writing to the file directly.
#
# Run: zsh endpoint/test-decommission-gate.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
FETCH_SH="$SCRIPT_DIR/patched-fetch-config.sh"

extract_block() {  # extract_block <START-marker> <END-marker>
    local start="$1" end="$2" tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/patched-decomm-test.XXXXXX")
    awk -v s="$start" -v e="$end" '$0 ~ s {f=1;next} $0 ~ e {f=0} f' "$FETCH_SH" > "$tmp"
    if [[ ! -s "$tmp" ]]; then
        echo "FATAL: could not extract $start..$end block from $FETCH_SH"
        exit 1
    fi
    source "$tmp"
    rm -f "$tmp"
}

extract_block "PATCHED_CONFIG_COMMIT_START" "PATCHED_CONFIG_COMMIT_END"
extract_block "PATCHED_DECOMMISSION_GATE_START" "PATCHED_DECOMMISSION_GATE_END"

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

sha256_of() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
PYTHON3="/usr/bin/python3"
# PAT-1763: the shared floor parser the extracted blocks call.
AGENT_CONFIG_FLOOR_MODULE="$SCRIPT_DIR/agent_config_floor.py"
log_jsonl() { :; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.decomm-gate-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

STATE_DIR="$WORK"
CREDS_DIR="$WORK/creds"
AGENT_CONFIG_FILE="$WORK/agent-config.json"
AGENT_CONFIG_VERSION_FILE="$WORK/agent-config.version"
AGENT_CONFIG_SHA256_FILE="$WORK/agent-config.sha256"

TENANT="11111111-1111-1111-1111-111111111111"

reset_state() {
    rm -rf "$CREDS_DIR"
    mkdir -p "$CREDS_DIR"
    printf '%s\n' "$TENANT" > "$CREDS_DIR/tenant-id"
    rm -f "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_VERSION_FILE" "$AGENT_CONFIG_SHA256_FILE"
    DECOMM_TRIGGER_CALLS=0
    DECOMM_TRIGGER_ARGS=()
    # P1-A (non-author review): a real poll always has SOME measured skew
    # (production computes it from every HTTP response's Date header, 200 or
    # 304 — see AGENT_CONFIG_CLOCK_SKEW_SECONDS in patched-fetch-config.sh's
    # FETCH section) and the gate now fails closed on "unmeasurable"
    # (clock_skew_unmeasurable). Default every test to a small, trusted,
    # in-bound skew so tests [1]-[18] exercise mode/tenant/version/expiry
    # logic on its own merits, unaffected by the clock-trust gate; the
    # clock-skew tests themselves ([19]-[23]) override this per case.
    AGENT_CONFIG_CLOCK_SKEW_SECONDS=0
}

_decommission_trigger_removal() {
    (( DECOMM_TRIGGER_CALLS++ ))
    DECOMM_TRIGGER_ARGS=("$@")
}

# write_verified <json>
#   Writes <json> to AGENT_CONFIG_FILE, records its version-file and a
#   MATCHING sha256 hash — i.e. simulates a config that genuinely passed
#   through _agent_config_commit_verified (Ed25519-verified, then hashed
#   BEFORE publish, exactly as PATCHED_CONFIG_COMMIT does it). This is the
#   only path any test below uses to produce a config the gate should be
#   willing to act on.
write_verified() {
    local json="$1" version="$2"
    printf '%s' "$json" > "$AGENT_CONFIG_FILE"
    printf '%s' "$version" > "$AGENT_CONFIG_VERSION_FILE"
    sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"
}

cfg() {  # cfg <decommission-json-or-empty> <version>
    local decomm="$1" version="$2"
    if [[ -n "$decomm" ]]; then
        printf '{"tenant_id":"%s","config_version":%s,"decommission":%s}' "$TENANT" "$version" "$decomm"
    else
        printf '{"tenant_id":"%s","config_version":%s}' "$TENANT" "$version"
    fi
}

# Computed relative to the real clock at test time, not hardcoded literals:
# PAST must land after DECOMMISSION_BUILD_FLOOR AND before "now"
# to exercise the due-expiry path without also tripping the absurdity floor.
FUTURE=$(date -u -v+10y +%Y-%m-%dT%H:%M:%SZ)
PAST=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)

# ───────────────────────────────────────────────────────────────────────────
echo "[1] no decommission key at all: none, byte-for-byte inert — no trigger, no fault"
reset_state
write_verified "$(cfg '' 5)" 5
_decommission_check
chk "decision is none" "$([[ "$DECOMMISSION_DECISION" == "none" ]] && echo 1 || echo 0)"
chk "reason names absence" "$([[ "$DECOMMISSION_REASON" == "absent" ]] && echo 1 || echo 0)"
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] mode=none explicitly: none, no trigger"
reset_state
write_verified "$(cfg '{"mode":"none","expires_at":null,"purge":false,"reason":null}' 5)" 5
_decommission_check
chk "decision is none" "$([[ "$DECOMMISSION_DECISION" == "none" ]] && echo 1 || echo 0)"
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] mode=expiry, future expires_at: wait, no trigger (negligible per-poll cost: one bounded python invocation)"
reset_state
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$FUTURE\",\"purge\":false,\"reason\":null}" 5)" 5
_decommission_check
chk "decision is wait" "$([[ "$DECOMMISSION_DECISION" == "wait" ]] && echo 1 || echo 0)"
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] mode=expiry, past expires_at: act, purge/reason/config_version threaded through, trigger fires exactly once"
reset_state
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$PAST\",\"purge\":true,\"reason\":\"offboarded\"}" 7)" 7
_decommission_check
chk "decision is act" "$([[ "$DECOMMISSION_DECISION" == "act" ]] && echo 1 || echo 0)"
chk "purge threaded through as 1" "$([[ "$DECOMMISSION_PURGE" == "1" ]] && echo 1 || echo 0)"
chk "operator reason threaded through (audit only)" "$([[ "$DECOMMISSION_OPERATOR_REASON" == "offboarded" ]] && echo 1 || echo 0)"
chk "config_version captured AT THE POINT OF ACTING, not re-derived later" "$([[ "$DECOMMISSION_CONFIG_VERSION" == "7" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "poll hook fires the trigger exactly once for a due expiry" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 1 ]] && echo 1 || echo 0)"
chk "poll hook passes purge=1 as arg 1" "$([[ "${DECOMM_TRIGGER_ARGS[1]}" == "1" ]] && echo 1 || echo 0)"
chk "poll hook passes the operator reason as arg 2" "$([[ "${DECOMM_TRIGGER_ARGS[2]}" == "offboarded" ]] && echo 1 || echo 0)"
chk "poll hook passes config_version=7 as arg 4 (directive_version for the terminal-status report)" \
    "$([[ "${DECOMM_TRIGGER_ARGS[4]}" == "7" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] mode=immediate: act regardless of expires_at, trigger fires"
reset_state
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 3)" 3
_decommission_check
chk "decision is act" "$([[ "$DECOMMISSION_DECISION" == "act" ]] && echo 1 || echo 0)"
chk "purge threaded through as 0" "$([[ "$DECOMMISSION_PURGE" == "0" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger fires exactly once" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 1 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[6] unrecognised mode value: fault, fail closed, no trigger"
reset_state
write_verified "$(cfg '{"mode":"delete_everything_now","expires_at":null,"purge":false,"reason":null}' 3)" 3
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the unrecognised mode" "$([[ "$DECOMMISSION_REASON" == "mode_unrecognised" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[7] SECURITY: decommission=immediate written straight to AGENT_CONFIG_FILE with NO matching sha256 (never went through the verifier at all) — refuses"
reset_state
printf '%s' "$(cfg '{"mode":"immediate","expires_at":null,"purge":true,"reason":"attacker"}' 999)" > "$AGENT_CONFIG_FILE"
# Deliberately do NOT write AGENT_CONFIG_VERSION_FILE or AGENT_CONFIG_SHA256_FILE —
# this is exactly what a locally-modified/planted config file looks like.
_decommission_check
chk "decision is fault, not act" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the missing verification, not the (attacker-controlled) directive contents" \
    "$([[ "$DECOMMISSION_REASON" == "config_not_confirmed_verified" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger NEVER called for an unsigned/unverified file, regardless of its contents" \
    "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[8] SECURITY: a genuinely-verified config is tampered with AFTER the fact (PAT-1035 shape — an old/unverified writer overwrites AGENT_CONFIG_FILE without touching the hash sidecar) — refuses"
reset_state
write_verified "$(cfg '' 5)" 5
# Now overwrite the file post-verification, same as PAT-1035's own repro:
# the hash file still records the OLD (harmless) bytes' digest.
printf '%s' "$(cfg '{"mode":"immediate","expires_at":null,"purge":true,"reason":"attacker"}' 5)" > "$AGENT_CONFIG_FILE"
_decommission_check
chk "decision is fault, not act" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the hash mismatch" "$([[ "$DECOMMISSION_REASON" == "config_not_confirmed_verified" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[9] SECURITY: sha256 sidecar simply absent (fresh/partial install, never verified once) — refuses, does not treat absence as a pass"
reset_state
printf '%s' "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 1)" > "$AGENT_CONFIG_FILE"
printf '1' > "$AGENT_CONFIG_VERSION_FILE"
rm -f "$AGENT_CONFIG_SHA256_FILE"
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[10] point-of-action re-check: tenant_id in the (verified, hash-matching) config no longer matches the local tenant-id credential — fault, not act"
reset_state
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 2)" 2
printf '%s\n' "22222222-2222-2222-2222-222222222222" > "$CREDS_DIR/tenant-id"
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the tenant mismatch" "$([[ "$DECOMMISSION_REASON" == "tenant_id_mismatch" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[11] point-of-action re-check: config_version in the config regressed below the recorded anti-rollback floor — fault, not act"
reset_state
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 2)" 2
printf '9' > "$AGENT_CONFIG_VERSION_FILE"   # simulate a floor higher than the config's own version
sha256_of "$AGENT_CONFIG_FILE" > "$AGENT_CONFIG_SHA256_FILE"  # hash still matches the file's actual bytes
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the version regression" "$([[ "$DECOMMISSION_REASON" == "config_version_regressed" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[12] expires_at unparseable garbage: fault, not wait (never guesses a date)"
reset_state
write_verified "$(cfg '{"mode":"expiry","expires_at":"not-a-date","purge":false,"reason":null}' 1)" 1
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names it unparseable" "$([[ "$DECOMMISSION_REASON" == "expires_at_unparseable" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[13] expires_at null (schema allows null; only invalid when mode=expiry): fault, not a crash"
reset_state
write_verified "$(cfg '{"mode":"expiry","expires_at":null,"purge":false,"reason":null}' 1)" 1
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names it unparseable" "$([[ "$DECOMMISSION_REASON" == "expires_at_unparseable" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[14] expires_at absurd — earlier than DECOMMISSION_BUILD_FLOOR (catches malformed values AND a badly wrong on-device clock): fault, not act"
reset_state
write_verified "$(cfg '{"mode":"expiry","expires_at":"1970-01-01T00:00:00Z","purge":false,"reason":null}' 1)" 1
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names it absurd" "$([[ "$DECOMMISSION_REASON" == "expires_at_absurd" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[15] expires_at without a timezone offset (naive, ambiguous — not RFC3339 UTC): fault, not silently assumed UTC"
reset_state
write_verified "$(cfg '{"mode":"expiry","expires_at":"2020-01-01T00:00:00","purge":false,"reason":null}' 1)" 1
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names it unparseable" "$([[ "$DECOMMISSION_REASON" == "expires_at_unparseable" ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[16] decommission value present but not an object (schema violation from a misbehaving/compromised server): fault-free none, not a crash"
reset_state
write_verified "$(printf '{"tenant_id":"%s","config_version":1,"decommission":"immediate"}' "$TENANT")" 1
_decommission_check
chk "malformed shape treated as absent (none), not crashed and not acted on" \
    "$([[ "$DECOMMISSION_DECISION" == "none" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1109 second-round finding P1 A (TOCTOU): the previous shape of
# _decommission_check called _agent_config_hash_matches (one open of
# AGENT_CONFIG_FILE to hash it) and then separately re-opened
# AGENT_CONFIG_FILE two more times to parse fields — three opens of an
# untrusted local path, each a window for a concurrent local writer to swap
# the bytes between the hash check and a parse. The fix reads the file
# exactly once into memory and parses that same snapshot. Case [17] proves
# this structurally (exactly one python3 process is ever spawned). Case [18]
# proves it behaviourally: bytes are swapped in the file at the precise
# moment between "the hash was recorded for the ORIGINAL bytes" and "the
# check runs against whatever is on disk NOW" — the scenario a multi-open
# implementation could get wrong, and the single-read implementation cannot,
# because there is no window left to land the swap in.
echo "[17] TOCTOU structural proof: _decommission_check spawns exactly ONE python3 process per call, for both a fault case and an act case"
reset_state
write_verified "$(cfg '' 5)" 5
PY_INVOKE_LOG="$WORK/py-invocations.log"
: > "$PY_INVOKE_LOG"
PY_WRAPPER="$WORK/python3-counting-wrapper.sh"
cat > "$PY_WRAPPER" <<EOF
#!/bin/sh
echo x >> "$PY_INVOKE_LOG"
exec /usr/bin/python3 "\$@"
EOF
chmod +x "$PY_WRAPPER"
ORIG_PYTHON3="$PYTHON3"
PYTHON3="$PY_WRAPPER"
_decommission_check   # none:absent case — no decommission key in this fixture
chk "exactly one python3 invocation for a 'none' decision" \
    "$([[ "$(wc -l < "$PY_INVOKE_LOG" | tr -d ' ')" -eq 1 ]] && echo 1 || echo 0)"

: > "$PY_INVOKE_LOG"
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 6)" 6
_decommission_check
chk "decision is act" "$([[ "$DECOMMISSION_DECISION" == "act" ]] && echo 1 || echo 0)"
chk "exactly one python3 invocation for an 'act' decision too (the tenant_id/config_version re-checks are inside the same process, not separate opens)" \
    "$([[ "$(wc -l < "$PY_INVOKE_LOG" | tr -d ' ')" -eq 1 ]] && echo 1 || echo 0)"
PYTHON3="$ORIG_PYTHON3"

# ───────────────────────────────────────────────────────────────────────────
echo "[18] TOCTOU scenario: AGENT_CONFIG_FILE is swapped for a directly-actionable directive at the exact moment between hash-record and check — the atomic single-read must still refuse, because it hashes and parses the SAME bytes it opens, and the bytes on disk now do not match what was recorded"
reset_state
# Step 1: a harmless, genuinely-verified config is committed (hash recorded
# against THESE bytes).
write_verified "$(cfg '' 5)" 5
# Step 2: immediately before _decommission_check runs, something else — a
# concurrent local writer, exactly PAT-1035's shape — replaces the file with
# a directly-actionable "immediate" directive. AGENT_CONFIG_SHA256_FILE is
# deliberately left untouched (a real concurrent writer racing the gate has
# no reason, and typically no ability, to also recompute and rewrite the
# verifier's own recorded digest).
printf '%s' "$(cfg '{"mode":"immediate","expires_at":null,"purge":true,"reason":"attacker"}' 5)" > "$AGENT_CONFIG_FILE"
_decommission_check
chk "decision is fault, not act, even though the swapped-in bytes alone would decode as an immediate decommission" \
    "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the verification gap, not the attacker-controlled mode" \
    "$([[ "$DECOMMISSION_REASON" == "config_not_confirmed_verified" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called despite the swap" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1109 P2 D: expiry activation must not trust an implausibly-skewed local
# wall clock. AGENT_CONFIG_CLOCK_SKEW_SECONDS is the freshest-available
# signal (this poll's HTTP response Date header vs local now) — set directly
# as a plain shell variable here, the same way the real caller (the FETCH
# section) sets it before _decommission_check runs.
echo "[19] clock skew within the allowed bound: expiry evaluation unaffected (still acts when genuinely due)"
reset_state
AGENT_CONFIG_CLOCK_SKEW_SECONDS=30   # well under the 300s default bound
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$PAST\",\"purge\":false,\"reason\":null}" 1)" 1
_decommission_check
chk "decision is act (small skew does not block a genuinely due expiry)" "$([[ "$DECOMMISSION_DECISION" == "act" ]] && echo 1 || echo 0)"
AGENT_CONFIG_CLOCK_SKEW_SECONDS=""

echo "[20] clock skew far beyond the allowed bound, expiry genuinely due by real time: fault, not act — this is the exact scenario the fix exists to catch (a device whose clock reads far enough ahead would otherwise decommission itself before its real expiry)"
reset_state
AGENT_CONFIG_CLOCK_SKEW_SECONDS=99999   # ~27.7 hours ahead — implausible
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$PAST\",\"purge\":false,\"reason\":null}" 1)" 1
_decommission_check
chk "decision is fault, not act, despite expires_at genuinely being in the past" \
    "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the implausible clock skew" "$([[ "$DECOMMISSION_REASON" == "local_clock_implausibly_ahead" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"
AGENT_CONFIG_CLOCK_SKEW_SECONDS=""

echo "[21] clock skew far beyond the allowed bound, expiry NOT yet due either way: still fault, not wait — an untrustworthy clock is not trusted for ANY expiry evaluation this poll, not only the direction that would be dangerous"
reset_state
AGENT_CONFIG_CLOCK_SKEW_SECONDS=99999
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$FUTURE\",\"purge\":false,\"reason\":null}" 1)" 1
_decommission_check
chk "decision is fault, not wait" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the implausible clock skew" "$([[ "$DECOMMISSION_REASON" == "local_clock_implausibly_ahead" ]] && echo 1 || echo 0)"
AGENT_CONFIG_CLOCK_SKEW_SECONDS=""

# P1-A (non-author review finding): skew UNMEASURABLE this poll used to be
# treated as "not itself a fault" and fell through to comparing expires_at
# against the untrusted LOCAL clock — fails OPEN, because a device whose
# local clock runs fast can make a legitimately-future expires_at look due,
# and DECOMMISSION_BUILD_FLOOR only catches the BACKDATED direction. Fixed:
# unmeasurable skew now DEFERS (fault, not act) for mode=expiry,
# unconditionally — regardless of whether the directive would locally
# appear due ([22]) or not-yet-due ([22b]). Costs nothing: the same
# directive is re-evaluated on a later poll once trusted time is available.
echo "[22] P1-A regression guard: clock skew unmeasurable this poll (empty), expiry genuinely due by real time: DEFERS (fault, not act) — must not fall back to the untrusted local clock"
reset_state
AGENT_CONFIG_CLOCK_SKEW_SECONDS=""
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$PAST\",\"purge\":false,\"reason\":null}" 1)" 1
_decommission_check
chk "decision is fault, not act (unmeasurable skew must not be trusted just because local time makes it look due)" \
    "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the unmeasurable clock, not some other fault" \
    "$([[ "$DECOMMISSION_REASON" == "clock_skew_unmeasurable" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

echo "[22b] P1-A: clock skew unmeasurable this poll, expiry NOT yet due either way: still defers (fault, not wait) — unmeasurable is unmeasurable regardless of which answer it would coincidentally match"
reset_state
AGENT_CONFIG_CLOCK_SKEW_SECONDS=""
write_verified "$(cfg "{\"mode\":\"expiry\",\"expires_at\":\"$FUTURE\",\"purge\":false,\"reason\":null}" 1)" 1
_decommission_check
chk "decision is fault, not wait" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the unmeasurable clock" "$([[ "$DECOMMISSION_REASON" == "clock_skew_unmeasurable" ]] && echo 1 || echo 0)"

echo "[23] clock skew far beyond the allowed bound has no effect on mode=immediate (skew only bounds the wall-clock comparison expiry mode makes)"
reset_state
AGENT_CONFIG_CLOCK_SKEW_SECONDS=99999
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 1)" 1
_decommission_check
chk "decision is act (immediate mode does not consult the clock at all)" "$([[ "$DECOMMISSION_DECISION" == "act" ]] && echo 1 || echo 0)"
AGENT_CONFIG_CLOCK_SKEW_SECONDS=""

# ───────────────────────────────────────────────────────────────────────────
# PROXY-DATE TRUST (non-author review, second round): the Date-header parser
# that computes AGENT_CONFIG_CLOCK_SKEW_SECONDS lives in patched-fetch-config.sh
# (not in this gate), so this drives the REAL shipped source directly — same
# "no hand-copied reimplementation" discipline as endpoint/test-hmac-v3.zsh:
# extracted from between its PATCHED_CLOCK_SKEW_PARSE_START/END sentinels and
# run as a standalone python3 script against synthetic curl -D header dumps.
extract_clock_skew_parser() {
    local out="$WORK/clock-skew-parse.py"
    sed -n '/PATCHED_CLOCK_SKEW_PARSE_START/,/PATCHED_CLOCK_SKEW_PARSE_END/p' "$FETCH_SH" | sed '1d;$d' > "$out"
    if [[ ! -s "$out" ]]; then
        echo "FATAL: could not extract PATCHED_CLOCK_SKEW_PARSE_START..END from $FETCH_SH"
        exit 1
    fi
    print -r -- "$out"
}
CLOCK_SKEW_PY=$(extract_clock_skew_parser)

echo "[24] PROXY-DATE TRUST: a proxied HTTPS poll's -D dump carries the CONNECT tunnel's own header block BEFORE the origin's — the skew MUST come from the origin (LAST) block's Date, never the proxy's (FIRST) block's Date"
NOW_RFC1123=$(date -u -R)
PROXY_HDRS="$WORK/proxy-two-block-headers.txt"
printf 'HTTP/1.1 200 Connection established\r\nDate: Sat, 01 Jan 2050 00:00:00 GMT\r\n\r\nHTTP/1.1 200 OK\r\nDate: %s\r\nContent-Type: application/json\r\n\r\n' \
    "$NOW_RFC1123" > "$PROXY_HDRS"
skew=$("$PYTHON3" "$CLOCK_SKEW_PY" "$PROXY_HDRS" 2>/dev/null)
chk "origin Date wins: skew is small (near 0), not the ~-750000000s a 2050 proxy Date would produce" \
    "$([[ "$skew" =~ ^-?[0-9]+$ ]] && (( skew > -60 && skew < 60 )) && echo 1 || echo 0)"

echo "[24b] PROXY-DATE TRUST: only a CONNECT block, no origin block at all — unmeasurable (empty), never falls back to the CONNECT block's own Date"
CONNECT_ONLY_HDRS="$WORK/proxy-connect-only-headers.txt"
printf 'HTTP/1.1 200 Connection established\r\nDate: %s\r\n\r\n' "$NOW_RFC1123" > "$CONNECT_ONLY_HDRS"
skew=$("$PYTHON3" "$CLOCK_SKEW_PY" "$CONNECT_ONLY_HDRS" 2>/dev/null)
chk "no origin block -> unmeasurable (empty string), not the CONNECT block's Date" "$([[ -z "$skew" ]] && echo 1 || echo 0)"

echo "[24c] PROXY-DATE TRUST: a direct (no-proxy) single-block response is unaffected — still parses its own Date correctly"
DIRECT_HDRS="$WORK/direct-single-block-headers.txt"
printf 'HTTP/1.1 200 OK\r\nDate: %s\r\nContent-Type: application/json\r\n\r\n' "$NOW_RFC1123" > "$DIRECT_HDRS"
skew=$("$PYTHON3" "$CLOCK_SKEW_PY" "$DIRECT_HDRS" 2>/dev/null)
chk "single-block (no proxy) case still works: skew is small (near 0)" \
    "$([[ "$skew" =~ ^-?[0-9]+$ ]] && (( skew > -60 && skew < 60 )) && echo 1 || echo 0)"

echo "[24d] PROXY-DATE TRUST: a 100 Continue block ahead of the origin block is also discarded, not mistaken for the origin"
CONTINUE_HDRS="$WORK/continue-then-origin-headers.txt"
printf 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nDate: %s\r\n\r\n' "$NOW_RFC1123" > "$CONTINUE_HDRS"
skew=$("$PYTHON3" "$CLOCK_SKEW_PY" "$CONTINUE_HDRS" 2>/dev/null)
chk "100 Continue block discarded: skew is small (near 0), taken from the real origin block" \
    "$([[ "$skew" =~ ^-?[0-9]+$ ]] && (( skew > -60 && skew < 60 )) && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1756: the point-of-action anti-rollback re-check reads the tenant-keyed
# floor. A floor keyed to the local tenant vouches for the config exactly like
# the legacy bare integer above; a floor keyed to another tenant, or a corrupt
# one, cannot vouch for anything.
echo "[PAT-1756 a] keyed floor for the local tenant: point-of-action re-check passes, act"
reset_state
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 4)" 4
printf '{"tenant_id":"%s","config_version":4}' "$TENANT" > "$AGENT_CONFIG_VERSION_FILE"
_decommission_check
chk "decision is act" "$([[ "$DECOMMISSION_DECISION" == "act" ]] && echo 1 || echo 0)"
chk "config_version captured" "$([[ "$DECOMMISSION_CONFIG_VERSION" == "4" ]] && echo 1 || echo 0)"

echo "[PAT-1756 b] keyed floor for the local tenant above the config's version: fault, version regressed"
reset_state
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 4)" 4
printf '{"tenant_id":"%s","config_version":9}' "$TENANT" > "$AGENT_CONFIG_VERSION_FILE"
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the version regression" "$([[ "$DECOMMISSION_REASON" == "config_version_regressed" ]] && echo 1 || echo 0)"

echo "[PAT-1756 c] floor keyed to another tenant: fault, never act"
reset_state
write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 4)" 4
printf '{"tenant_id":"22222222-2222-2222-2222-222222222222","config_version":1}' > "$AGENT_CONFIG_VERSION_FILE"
_decommission_check
chk "decision is fault" "$([[ "$DECOMMISSION_DECISION" == "fault" ]] && echo 1 || echo 0)"
chk "reason names the unusable floor" "$([[ "$DECOMMISSION_REASON" == "rollback_floor_unusable" ]] && echo 1 || echo 0)"
_decommission_poll_hook
chk "trigger never called" "$([[ "$DECOMM_TRIGGER_CALLS" -eq 0 ]] && echo 1 || echo 0)"

echo "[PAT-1756 d] corrupt or missing floor: fault, never act"
for bad_floor in 'garbage' '' '{"tenant_id":"'"$TENANT"'","config_version":4,"extra":1}' '{"tenant_id":"'"$TENANT"'","tenant_id":"x","config_version":4}' \
    '{"tenant_id":"x","tenant_id":"'"$TENANT"'","config_version":4}' '{"tenant_id":"'"$TENANT"'","config_version":4,"config_version":1}' \
    '{"tenant_id":"'"$TENANT"'","config_version":4.0}' '{"tenant_id":"'"$TENANT"'","config_version":true}' '{"tenant_id":"'"$TENANT"'","config_version":"4"}' \
    '{"tenant_id":["'"$TENANT"'"],"config_version":4}' '{"tenant_id":7,"config_version":4}' MISSING; do
    reset_state
    write_verified "$(cfg '{"mode":"immediate","expires_at":null,"purge":false,"reason":null}' 4)" 4
    if [[ "$bad_floor" == MISSING ]]; then
        rm -f "$AGENT_CONFIG_VERSION_FILE"
    else
        printf '%s' "$bad_floor" > "$AGENT_CONFIG_VERSION_FILE"
    fi
    _decommission_check
    chk "floor '$bad_floor': decision is fault with rollback_floor_unusable" \
        "$([[ "$DECOMMISSION_DECISION" == "fault" && "$DECOMMISSION_REASON" == "rollback_floor_unusable" ]] && echo 1 || echo 0)"
done

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
