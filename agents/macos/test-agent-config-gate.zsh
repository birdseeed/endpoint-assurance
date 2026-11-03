#!/bin/zsh
##############################################################################
# test-agent-config-gate.zsh: tests for the PAT-1035 agent-config
# enforcement gate (ac_gate_check) in macos/patched-upload.sh.
#
# macos/patched-upload.sh no longer fetches or writes agent-config.json; it
# only reads the file endpoint/patched-fetch-config.sh maintains, and gates
# its three enforcement blocks (app_control, browser_extension_control,
# browser_extension_removal) on whether that file is present and its
# heartbeat is fresh. This test extracts the sentinel-delimited gate block
# from the SHIPPED patched-upload.sh (the PATCHED_AC_GATE_START/END markers,
# same pattern as macos/lib/test-patched-creds.zsh uses for the creds
# helpers) and drives it directly against a temp directory, so the code
# under test is the code that ships, not a copy. No root needed.
#
# Run: zsh macos/test-agent-config-gate.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPLOAD_SH="$SCRIPT_DIR/patched-upload.sh"

# Extract the inline gate block and source it, exactly as
# macos/lib/test-patched-creds.zsh does for PATCHED_CREDS_HELPERS.
GATE_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-ac-gate.XXXXXX")
awk '/PATCHED_AC_GATE_START/{f=1;next} /PATCHED_AC_GATE_END/{f=0} f' \
    "$UPLOAD_SH" > "$GATE_TMP"
if [[ ! -s "$GATE_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_AC_GATE block from $UPLOAD_SH"
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

PYTHON3="/usr/bin/python3"

# set_heartbeat_age_secs <file> <age-in-seconds-ago>
#   Creates (or touches) <file> and sets its mtime to now minus the given
#   number of seconds, using Python's os.utime for portable epoch-second
#   precision instead of `touch -t`'s calendar-time parsing.
set_heartbeat_age_secs() {
    local file="$1" age="$2" target
    target=$(( $(date -u +%s) - age ))
    : > "$file"
    "$PYTHON3" -c "import os,sys; os.utime(sys.argv[1], (int(sys.argv[2]), int(sys.argv[2])))" "$file" "$target"
}

# set_heartbeat_epoch_secs <file> <epoch-seconds>
#   Creates (or touches) <file> and sets its mtime to an exact epoch. This
#   lets the zero-age boundary case freeze both sides of now - mtime.
set_heartbeat_epoch_secs() {
    local file="$1" epoch="$2"
    : > "$file"
    "$PYTHON3" -c "import os,sys; os.utime(sys.argv[1], (int(sys.argv[2]), int(sys.argv[2])))" "$file" "$epoch"
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

AC_CONFIG_FILE="$WORK/agent-config.json"
AC_HEARTBEAT_FILE="$WORK/agent-config.checked"
AC_CONFIG_SHA256_FILE="$WORK/agent-config.sha256"
AC_SUSPENDED_FILE="$WORK/suspended"
AC_EXECUTION_DENY_FILE="$WORK/agent-config.execution-denied"
# PAT-1773: the enrolled tenant the staged config must belong to.
AC_TENANT_ID_FILE="$WORK/tenant-id"
print -r -- "tenant-test" > "$AC_TENANT_ID_FILE"

# write_matching_hash <file>
#   Writes AC_CONFIG_SHA256_FILE with the actual current SHA-256 of <file>,
#   using the same shasum idiom the gate itself uses.
write_matching_hash() {
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' > "$AC_CONFIG_SHA256_FILE"
}

# ───────────────────────────────────────────────────────────────────────────
echo "[1] config absent: refuses, reason is the never-synced one"
rm -f "$AC_CONFIG_FILE" "$AC_HEARTBEAT_FILE"
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when config file is absent" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names never-synced state" "$([[ "$AC_GATE_REASON" == *"never synced"* ]] && echo 1 || echo 0)"
chk "reason names the config-poll daemon" "$([[ "$AC_GATE_REASON" == *"com.patched.config-poll"* ]] && echo 1 || echo 0)"
chk "reason is not the dishonest 'keeping last-good' fallback phrasing (PAT-1028)" \
    "$([[ "$AC_GATE_REASON" != *"keeping last-good"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2] config present + heartbeat 5 minutes old + matching hash: allows"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate allows when heartbeat is 5 minutes old and hash matches" "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"
chk "reason names fresh state" "$([[ "$AC_GATE_REASON" == *"fresh"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2a] config present + heartbeat exactly now: allows at the zero-age boundary"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
fixed_now=$(command date -u +%s)
set_heartbeat_epoch_secs "$AC_HEARTBEAT_FILE" "$fixed_now"
date() { print -r -- "$fixed_now"; }
if ac_gate_check; then result=allow; else result=refuse; fi
unfunction date
chk "gate allows when the heartbeat age is exactly zero seconds and hash matches" \
    "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"
chk "zero-age boundary reports the ordinary fresh state" "$([[ "$AC_GATE_REASON" == *"fresh"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[2b] config present + heartbeat at least 60 seconds in the future: refuses, reason names future heartbeat or clock rollback"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" -60
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when heartbeat is at least 60 seconds in the future" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names future heartbeat" "$([[ "$AC_GATE_REASON" == *"future heartbeat"* ]] && echo 1 || echo 0)"
chk "reason identifies future-dated heartbeat or local clock rollback" \
    "$([[ "$AC_GATE_REASON" == *"future-dated heartbeat or local clock rollback"* ]] && echo 1 || echo 0)"
chk "future-heartbeat reason is distinct from fresh and stale reasons" \
    "$([[ "$AC_GATE_REASON" != *"AGENT-CONFIG GATE: fresh."* && "$AC_GATE_REASON" != *"AGENT-CONFIG GATE: stale."* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[3] config present + heartbeat 48 hours old: refuses, reason is the stale one"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 48 * 60 * 60 ))
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when heartbeat is 48 hours old" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names stale state" "$([[ "$AC_GATE_REASON" == *"stale"* ]] && echo 1 || echo 0)"
chk "reason reports how old the heartbeat is" "$([[ "$AC_GATE_REASON" == *"48h old"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[4] config present + heartbeat file missing: refuses (fail closed), reason names the missing heartbeat"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
rm -f "$AC_HEARTBEAT_FILE"
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when heartbeat file is missing (PAT-1035 finding 1: fail closed, not permissive)" \
    "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names the missing heartbeat" "$([[ "$AC_GATE_REASON" == *"heartbeat missing"* ]] && echo 1 || echo 0)"
chk "reason says enforcement resumes automatically" "$([[ "$AC_GATE_REASON" == *"resumes automatically"* ]] && echo 1 || echo 0)"
chk "reason is distinct from the fresh-state reason" "$([[ "$AC_GATE_REASON" != *"Config-poll heartbeat is"*"m old"* ]] && echo 1 || echo 0)"
chk "reason is distinct from the never-synced reason" "$([[ "$AC_GATE_REASON" != *"never synced"* ]] && echo 1 || echo 0)"
chk "reason is distinct from the stale reason" "$([[ "$AC_GATE_REASON" != *"stale"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[5] config present + heartbeat fresh + tampered bytes (PAT-1035 finding 2, upload side): refuses, reason names a hash mismatch"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
# Overwrite AC_CONFIG_FILE AFTER recording the hash, simulating an old
# uploader (or anything else) writing to it between the poll and this read.
echo '{"app_control_authority":"standard","app_control":{"admins":["attacker"]}}' > "$AC_CONFIG_FILE"
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when heartbeat is fresh but on-disk bytes diverge from the recorded hash" \
    "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names a hash mismatch" "$([[ "$AC_GATE_REASON" == *"hash mismatch"* ]] && echo 1 || echo 0)"
chk "reason says the config is not confirmed to be the file that was verified" \
    "$([[ "$AC_GATE_REASON" == *"not confirmed to be the file that was verified"* ]] && echo 1 || echo 0)"
chk "reason says enforcement is paused, not skipped permanently" "$([[ "$AC_GATE_REASON" == *"not skipped permanently"* ]] && echo 1 || echo 0)"
chk "reason is distinct from the fresh-state reason" "$([[ "$AC_GATE_REASON" != *"Config-poll heartbeat is"*"m old"* ]] && echo 1 || echo 0)"
chk "reason is distinct from the stale reason" "$([[ "$AC_GATE_REASON" != *"stale"* ]] && echo 1 || echo 0)"
chk "reason is distinct from the never-synced reason" "$([[ "$AC_GATE_REASON" != *"never synced"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[6] config present + heartbeat fresh + missing hash file: refuses, reason names a hash mismatch"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
rm -f "$AC_CONFIG_SHA256_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when heartbeat is fresh but AC_CONFIG_SHA256_FILE is missing (never recorded, not a silent pass)" \
    "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names a hash mismatch" "$([[ "$AC_GATE_REASON" == *"hash mismatch"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[7] all six reasons are mutually distinct (no copy-paste collision)"
rm -f "$AC_CONFIG_FILE" "$AC_HEARTBEAT_FILE" "$AC_CONFIG_SHA256_FILE"
ac_gate_check; reason_absent="$AC_GATE_REASON"
echo '{}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
ac_gate_check; reason_fresh="$AC_GATE_REASON"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 48 * 60 * 60 ))
ac_gate_check; reason_stale="$AC_GATE_REASON"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" -60
ac_gate_check; reason_future="$AC_GATE_REASON"
rm -f "$AC_HEARTBEAT_FILE"
ac_gate_check; reason_missing="$AC_GATE_REASON"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
rm -f "$AC_CONFIG_SHA256_FILE"
ac_gate_check; reason_hash_mismatch="$AC_GATE_REASON"
all_distinct=1
[[ "$reason_absent" != "$reason_fresh" && "$reason_absent" != "$reason_stale" && "$reason_absent" != "$reason_future" && "$reason_absent" != "$reason_missing" && "$reason_absent" != "$reason_hash_mismatch" \
   && "$reason_fresh" != "$reason_stale" && "$reason_fresh" != "$reason_future" && "$reason_fresh" != "$reason_missing" && "$reason_fresh" != "$reason_hash_mismatch" \
   && "$reason_stale" != "$reason_future" && "$reason_stale" != "$reason_missing" && "$reason_stale" != "$reason_hash_mismatch" \
   && "$reason_future" != "$reason_missing" && "$reason_future" != "$reason_hash_mismatch" \
   && "$reason_missing" != "$reason_hash_mismatch" ]] || all_distinct=0
chk "absent / fresh / stale / future-heartbeat / missing-heartbeat / hash-mismatch reasons are all different strings" "$all_distinct"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1035 finding 1 (round 3): ac_gate_stage_config copies the verified
# bytes into PATCHED_TMPDIR and points PATCHED_AC_CONFIG at the copy, so the
# three enforcement modules stop re-reading the shared well-known path. It
# lives in the same PATCHED_AC_GATE_START/END block, so it was extracted and
# sourced above along with ac_gate_check.
echo "[8] gate fresh + staging: copies verified bytes into PATCHED_TMPDIR and points PATCHED_AC_CONFIG at the copy"
echo '{"tenant_id":"tenant-test","app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
STAGE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-stage.XXXXXX")
PATCHED_TMPDIR="$STAGE_WORK"
unset PATCHED_AC_CONFIG
if ac_gate_check && ac_gate_stage_config; then result=allow; else result=refuse; fi
chk "gate+stage succeeds on fresh, hash-matching config" "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"
chk "PATCHED_AC_CONFIG points inside PATCHED_TMPDIR, not at AC_CONFIG_FILE" \
    "$([[ -n "${PATCHED_AC_CONFIG:-}" && "$PATCHED_AC_CONFIG" == "$STAGE_WORK"/* && "$PATCHED_AC_CONFIG" != "$AC_CONFIG_FILE" ]] && echo 1 || echo 0)"
chk "staged copy exists and its bytes match the source" \
    "$([[ -f "${PATCHED_AC_CONFIG:-/nonexistent}" ]] && diff -q "$AC_CONFIG_FILE" "$PATCHED_AC_CONFIG" >/dev/null 2>&1 && echo 1 || echo 0)"
chk "reason mentions the staged copy" "$([[ "$AC_GATE_REASON" == *"Verified copy staged"* ]] && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

# ───────────────────────────────────────────────────────────────────────────
echo "[9] staging: source vanishes between gate check and staging: refuses, distinct reason"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
STAGE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-stage.XXXXXX")
PATCHED_TMPDIR="$STAGE_WORK"
unset PATCHED_AC_CONFIG
ac_gate_check   # passes and records its own "fresh" reason
rm -f "$AC_CONFIG_FILE"   # simulate the file disappearing right after the check
if ac_gate_stage_config; then result=allow; else result=refuse; fi
chk "staging refuses when the source can no longer be hashed" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names staging failure and says it could not hash" \
    "$([[ "$AC_GATE_REASON" == *"staging failed"* && "$AC_GATE_REASON" == *"Could not hash"* ]] && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

# ───────────────────────────────────────────────────────────────────────────
echo "[10] staging: destination directory does not exist (copy fails): refuses, distinct reason"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
PATCHED_TMPDIR="/nonexistent-$$/patched-tmpdir-does-not-exist"
unset PATCHED_AC_CONFIG
if ac_gate_stage_config; then result=allow; else result=refuse; fi
chk "staging refuses when the copy itself fails" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names staging failure and says it could not copy" \
    "$([[ "$AC_GATE_REASON" == *"staging failed"* && "$AC_GATE_REASON" == *"Could not copy"* ]] && echo 1 || echo 0)"

# ───────────────────────────────────────────────────────────────────────────
echo "[11] staging: a write lands during the copy itself (simulated via a shadowed cp): refuses, distinct reason — this is the exact TOCTOU the fix closes"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
STAGE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-stage.XXXXXX")
PATCHED_TMPDIR="$STAGE_WORK"
unset PATCHED_AC_CONFIG
# Shadow cp so the "copy" lands with different (attacker-controlled) bytes,
# exactly as if AC_CONFIG_FILE changed underneath a real cp mid-copy. zsh
# resolves a function before an external command, same trick
# test-app-control.zsh uses for dscl/stat.
cp() { echo '{"app_control_authority":"standard","app_control":{"admins":["attacker"]}}' > "$2"; }
if ac_gate_stage_config; then result=allow; else result=refuse; fi
unfunction cp
chk "staging refuses when the copy's hash diverges from the pre-copy hash" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names staging failure and says something wrote mid-copy" \
    "$([[ "$AC_GATE_REASON" == *"staging failed"* && "$AC_GATE_REASON" == *"while the copy was in flight"* ]] && echo 1 || echo 0)"
chk "the tampered staged copy was removed, not left behind" "$([[ ! -f "$STAGE_WORK/agent-config.verified.json" ]] && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1035 finding 1 (round 4): the previous version of ac_gate_stage_config
# hashed the file, copied it, then compared the copy's hash to that SAME
# freshly-taken pre_hash — proving only that the file did not change DURING
# the copy. A swap landing between ac_gate_check returning "fresh" and
# ac_gate_stage_config taking its pre_hash would produce a pre_hash that
# already reflects the attacker's bytes; the post-copy hash would then match
# it trivially and staging would succeed on tampered content. The fix
# anchors both the pre-copy and post-copy hash to AC_CONFIG_SHA256_FILE (the
# digest recorded by the verified commit path in
# endpoint/patched-fetch-config.sh) instead of to each other, so this exact
# window is caught.
echo "[12] staging: a swap lands after ac_gate_check but before staging (the exact TOCTOU this fix closes): refuses, distinct reason"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
STAGE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-stage.XXXXXX")
PATCHED_TMPDIR="$STAGE_WORK"
unset PATCHED_AC_CONFIG
ac_gate_check   # passes; AC_CONFIG_SHA256_FILE records the pre-swap digest
# Simulate an attacker swap landing in the window between ac_gate_check
# returning and ac_gate_stage_config taking its pre-copy hash: overwrite
# AC_CONFIG_FILE with different bytes but leave AC_CONFIG_SHA256_FILE (the
# recorded digest from the verified commit path) untouched, exactly as a
# swap that lands after the gate check would.
echo '{"app_control_authority":"standard","app_control":{"admins":["attacker"]}}' > "$AC_CONFIG_FILE"
if ac_gate_stage_config; then result=allow; else result=refuse; fi
chk "staging refuses a swap that lands after the gate check but before staging" \
    "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason says bytes were swapped after ac_gate_check passed" \
    "$([[ "$AC_GATE_REASON" == *"staging failed"* && "$AC_GATE_REASON" == *"swapped the file after ac_gate_check passed"* ]] && echo 1 || echo 0)"
chk "no staged copy was created (attacker bytes never reach PATCHED_TMPDIR)" \
    "$([[ ! -f "$STAGE_WORK/agent-config.verified.json" ]] && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1773: agent-config.json is not keyed by tenant. After re-enrolment into
# another tenant the old tenant's verified config is still on disk, with a
# matching hash and a fresh heartbeat. ac_gate_stage_config checks the staged
# copy against AC_TENANT_ID_FILE and treats any config that does not belong to
# the enrolled tenant as absent: refuse, like never synced.
# stage_tenant_case <config-json> : write config + matching hash + fresh
#   heartbeat, run check + stage into a fresh PATCHED_TMPDIR, set result.
stage_tenant_case() {
    print -r -- "$1" > "$AC_CONFIG_FILE"
    write_matching_hash "$AC_CONFIG_FILE"
    set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
    STAGE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-stage.XXXXXX")
    PATCHED_TMPDIR="$STAGE_WORK"
    unset PATCHED_AC_CONFIG
    if ac_gate_check && ac_gate_stage_config; then result=allow; else result=refuse; fi
}
refused_as_other_tenant() {
    [[ "$result" == "refuse" && -z "${PATCHED_AC_CONFIG:-}" \
       && "$AC_GATE_REASON" == *"not the enrolled tenant's config"* \
       && "$AC_GATE_REASON" == *"treated as never synced"* \
       && ! -e "$STAGE_WORK/agent-config.verified.json" ]]
}

echo "[12a] tenant scope: config for the enrolled tenant is staged"
stage_tenant_case '{"tenant_id":"tenant-test","app_control_authority":"enforce"}'
chk "config for the enrolled tenant allows" "$([[ "$result" == "allow" && -f "${PATCHED_AC_CONFIG:-/nonexistent}" ]] && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

echo "[12b] tenant scope: a fresh, hash-matching config for another tenant refuses as never synced"
stage_tenant_case '{"tenant_id":"tenant-old","app_control_authority":"enforce"}'
chk "another tenant's config refuses, nothing staged, reason says never synced" "$(refused_as_other_tenant && echo 1 || echo 0)"
chk "reason names the other tenant state" "$([[ "$AC_GATE_REASON" == *"other_tenant tenant-old"* ]] && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

echo "[12c] tenant scope: missing tenant_id refuses"
stage_tenant_case '{"app_control_authority":"enforce"}'
chk "config with no tenant_id refuses" "$(refused_as_other_tenant && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

echo "[12d] tenant scope: malformed JSON with a matching hash refuses"
stage_tenant_case '{"tenant_id":"tenant-test","app_control_authority":"enforce"'
chk "malformed config refuses" "$(refused_as_other_tenant && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

echo "[12e] tenant scope: missing enrolled tenant-id refuses"
rm -f "$AC_TENANT_ID_FILE"
stage_tenant_case '{"tenant_id":"tenant-test","app_control_authority":"enforce"}'
chk "no enrolled tenant-id refuses" "$(refused_as_other_tenant && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"

echo "[12f] tenant scope: re-enrolment into another tenant stops the old tenant's config at the next run"
print -r -- "tenant-new" > "$AC_TENANT_ID_FILE"
stage_tenant_case '{"tenant_id":"tenant-test","app_control_authority":"enforce"}'
chk "old tenant's config refuses once tenant-id names the new tenant" "$(refused_as_other_tenant && echo 1 || echo 0)"
rm -rf "$STAGE_WORK"
print -r -- "tenant-test" > "$AC_TENANT_ID_FILE"

echo "[12g] tenant scope: the collector's rule matches endpoint/agent_config_tenant.py over the shared fixtures"
FIXTURE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ac-gate-tenant-fixtures.XXXXXX")
fixture_rows=$("$PYTHON3" - "$SCRIPT_DIR/../endpoint/fixtures/agent-config-tenant.json" "$FIXTURE_WORK" <<'PYEOF'
import json, os, sys
cases = json.load(open(sys.argv[1], encoding="utf-8"))["cases"]
for index, case in enumerate(cases):
    directory = os.path.join(sys.argv[2], str(index))
    os.mkdir(directory)
    if case.get("config_hex") is not None:
        open(os.path.join(directory, "config"), "wb").write(bytes.fromhex(case["config_hex"]))
    elif case.get("config") is not None:
        open(os.path.join(directory, "config"), "wb").write(case["config"].encode("utf-8"))
    if case.get("tenant_id_file") is not None:
        open(os.path.join(directory, "tenant-id"), "wb").write(case["tenant_id_file"].encode("utf-8"))
    print(index, case["id"], case["expected"])
PYEOF
)
fixture_count=0
while read -r fixture_index fixture_id fixture_expected; do
    [[ -n "$fixture_index" ]] || continue
    (( fixture_count++ ))
    fixture_state=$(_ac_cached_config_tenant_state "$FIXTURE_WORK/$fixture_index/config" "$FIXTURE_WORK/$fixture_index/tenant-id")
    chk "fixture $fixture_id: collector says ${fixture_expected}" \
        "$([[ "${fixture_state%% *}" == "$fixture_expected" ]] && echo 1 || echo 0)"
done <<< "$fixture_rows"
chk "every shared fixture ran through the collector's rule" "$(( fixture_count >= 20 ))"
rm -rf "$FIXTURE_WORK"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1035 finding 2 (round 4): a suspended device's last-good heartbeat can
# sit inside the 24h freshness window for up to 24h after the platform
# revokes it (endpoint/patched-fetch-config.sh's 401 handler, or a terminal
# enrollment failure in endpoint/patched-enroll.sh, both of which write
# AC_SUSPENDED_FILE). Without this check, ac_gate_check would keep reporting
# "fresh" and allowing root-level enforcement on a device the platform has
# stopped accepting (a 401 of undisclosed cause, or a terminal enrollment
# failure).
echo "[13] suspension marker present: refuses even when config, hash, and heartbeat are all present and fresh"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
: > "$AC_SUSPENDED_FILE"
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses when the suspension marker is present, even with everything else fresh" \
    "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason names suspension" "$([[ "$AC_GATE_REASON" == *"suspended"* ]] && echo 1 || echo 0)"
chk "reason says enforcement stops until a verified agent-config clears the marker" \
    "$([[ "$AC_GATE_REASON" == *"until a signature-verified agent-config clears the marker"* ]] && echo 1 || echo 0)"
# PAT-1745: the marker can come from a bare 401 whose cause the server does
# not disclose, so the reason must say that rather than assert a revocation.
chk "reason says the 401 cause is not disclosed" \
    "$([[ "$AC_GATE_REASON" == *"HTTP 401, reason not disclosed"* ]] && echo 1 || echo 0)"
chk "reason does not assert the device was revoked" \
    "$([[ "$AC_GATE_REASON" != *"revoked"* ]] && echo 1 || echo 0)"
rm -f "$AC_SUSPENDED_FILE"

# ───────────────────────────────────────────────────────────────────────────
echo "[13a] authenticated rejected-policy denial outranks a fresh exact enforce grant"
echo '{"app_control_authority":"enforce"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
: > "$AC_EXECUTION_DENY_FILE"
if ac_gate_check; then result=allow; else result=refuse; fi
chk "gate refuses while the authenticated execution-denial marker exists" \
    "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "reason distinguishes authenticated rejected-policy revocation" \
    "$([[ "$AC_GATE_REASON" == *"authenticated policy rejection"* ]] && echo 1 || echo 0)"
rm -f "$AC_EXECUTION_DENY_FILE"

# ───────────────────────────────────────────────────────────────────────────
# PAT-1042: the suspension marker used to be one-way — nothing on either
# platform ever cleared it, so a device the platform revokes and later
# reinstates stayed suspended forever until someone deleted the file by hand.
# endpoint/patched-fetch-config.sh's _agent_config_commit_verified now clears
# AC_SUSPENDED_FILE itself as soon as a signature-verified 200 durably
# commits (see endpoint/test-agent-config-commit.zsh cases [16]-[19] for that
# half). This case proves the other half of the loop from the gate's point of
# view: once the marker is gone (however it was cleared), ac_gate_check goes
# straight back to "allow" with no separate re-arming step, no reduced state,
# and no leftover trace of the suspension — resuming NORMAL operation exactly
# as the immediate 401 suspend is symmetric with an immediate clear.
echo "[13b] suspension marker cleared (reinstatement): gate returns straight back to allow, same as if it had never been suspended"
echo '{"app_control_authority":"standard"}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
: > "$AC_SUSPENDED_FILE"
ac_gate_check   # confirm it actually refuses first — the state this clears from
reason_while_suspended="$AC_GATE_REASON"
rm -f "$AC_SUSPENDED_FILE"   # the clear a verified 200 now performs
if ac_gate_check; then result=allow; else result=refuse; fi
chk "sanity: gate really did refuse before the marker was cleared" \
    "$([[ "$reason_while_suspended" == *"suspended"* ]] && echo 1 || echo 0)"
chk "gate allows again once the suspension marker is cleared, config/hash/heartbeat unchanged" \
    "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"
chk "reason is the ordinary fresh-state reason, not some separate reinstated-but-degraded state" \
    "$([[ "$AC_GATE_REASON" == *"fresh"* ]] && echo 1 || echo 0)"

echo "[14] suspended reason is distinct from every other ac_gate_check outcome"
rm -f "$AC_CONFIG_FILE" "$AC_HEARTBEAT_FILE" "$AC_CONFIG_SHA256_FILE" "$AC_SUSPENDED_FILE"
ac_gate_check; reason_absent="$AC_GATE_REASON"
echo '{}' > "$AC_CONFIG_FILE"
write_matching_hash "$AC_CONFIG_FILE"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
ac_gate_check; reason_fresh="$AC_GATE_REASON"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 48 * 60 * 60 ))
ac_gate_check; reason_stale="$AC_GATE_REASON"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" -60
ac_gate_check; reason_future="$AC_GATE_REASON"
rm -f "$AC_HEARTBEAT_FILE"
ac_gate_check; reason_missing="$AC_GATE_REASON"
set_heartbeat_age_secs "$AC_HEARTBEAT_FILE" $(( 5 * 60 ))
rm -f "$AC_CONFIG_SHA256_FILE"
ac_gate_check; reason_hash_mismatch="$AC_GATE_REASON"
write_matching_hash "$AC_CONFIG_FILE"
: > "$AC_SUSPENDED_FILE"
ac_gate_check; reason_suspended="$AC_GATE_REASON"
rm -f "$AC_SUSPENDED_FILE"
all_distinct=1
for r in "$reason_absent" "$reason_fresh" "$reason_stale" "$reason_future" "$reason_missing" "$reason_hash_mismatch"; do
    [[ "$r" != "$reason_suspended" ]] || all_distinct=0
done
chk "suspended reason differs from every one of the absent/fresh/stale/future-heartbeat/missing-heartbeat/hash-mismatch reasons" "$all_distinct"

##############################################################################
# PAT-1038: ac_authority_gate_check tests. App Control destructive actuation
# is permitted only when app_control_authority is exactly "enforce";
# everything else, including a missing or garbage value, fails closed. This
# lives in the same PATCHED_AC_GATE_START/
# END block as ac_gate_check and ac_gate_stage_config, so it was extracted
# and sourced above along with them. These tests set PATCHED_AC_CONFIG
# directly (the staged-copy variable the real gate points it at after
# ac_gate_stage_config succeeds) so the function is exercised in isolation
# from PAT-1035 staging.
##############################################################################
AUTHORITY_CONFIG_FILE="$WORK/tier-config.json"

echo "[15] authority gate: authority 'enforce': allows"
echo '{"app_control_authority":"enforce"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "authority gate allows authority 'enforce' (acceptance criterion 1)" "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"
chk "reason says actuation is allowed" "$([[ "$AC_AUTHORITY_GATE_REASON" == *"permits destructive actuation"* ]] && echo 1 || echo 0)"

echo "[16] authority gate: block / report / report_deploy / app_management all refuse (acceptance criterion 2)"
for tier_case in report block report_deploy app_management; do
    echo "{\"app_control_authority\":\"$tier_case\"}" > "$AUTHORITY_CONFIG_FILE"
    PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
    if ac_authority_gate_check; then result=allow; else result=refuse; fi
    chk "tier gate refuses tier '$tier_case'" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
done

echo "[17] tier gate: garbage tier value refuses, naming the value found"
echo '{"app_control_authority":"bogus-tier-xyz"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "tier gate refuses an unrecognised tier value" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
chk "unknown authority resolves safely to report" "$([[ "$AC_AUTHORITY_GATE_REASON" == *"'report'"* ]] && echo 1 || echo 0)"

echo "[18] tier gate: tier key absent from config refuses"
echo '{}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "tier gate refuses when tier key is absent (acceptance criterion 2)" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
echo "[19] tier gate: empty-string tier refuses"
echo '{"app_control_authority":""}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "tier gate refuses an empty-string tier (acceptance criterion 2)" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
echo "[20] tier gate: unparseable config (invalid JSON) refuses"
echo 'not valid json{{{' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "tier gate refuses when the config cannot be parsed" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo '{"app_control_authority":null}' > "$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "null authority resolves to report and refuses destructive action" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo '{"app_control_authority":"report","APP_CONTROL_AUTHORITY":"enforce"}' > "$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "duplicate-key authority ambiguity resolves to report and refuses" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo '{"app_control_authority":"BlOcK"}' > "$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "case-variant authority value resolves to report and refuses blocklist actuation" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo '{"APP_CONTROL_AUTHORITY":"block"}' > "$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "case-variant authority key resolves to report and refuses blocklist actuation" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
echo "[21] tier gate: missing config file refuses (fail closed on an unreadable config)"
rm -f "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_authority_gate_check; then result=allow; else result=refuse; fi
chk "tier gate refuses when the config file does not exist" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
echo "[22] tier-refusal reason is distinct from every PAT-1035 gate reason (never-synced, stale, future-heartbeat, heartbeat-missing, hash-mismatch, suspended, staging-failed)"
echo '{"app_control_authority":"block"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
ac_authority_gate_check
reason_tier_refused="$AC_AUTHORITY_GATE_REASON"
tier_reason_distinct=1
for r in "$reason_absent" "$reason_fresh" "$reason_stale" "$reason_future" "$reason_missing" "$reason_hash_mismatch" "$reason_suspended"; do
    [[ "$r" != "$reason_tier_refused" ]] || tier_reason_distinct=0
done
[[ "$reason_tier_refused" == *"staging failed"* ]] && tier_reason_distinct=0
chk "tier-refusal reason collides with no PAT-1035 gate reason (never-synced/stale/future-heartbeat/missing-heartbeat/hash-mismatch/suspended/staging-failed)" "$tier_reason_distinct"

##############################################################################
# PAT-1038 follow-up (2026-08-07): ac_blocklist_authority_gate_check tests. The
# reversible/preventive browser-extension blocklist actuates one tier lower
# than the destructive paths above — "block" OR "enforce" — while still
# failing closed on anything else, including a missing or garbage value.
##############################################################################
echo "[23] blocklist tier gate: tier 'block': allows"
echo '{"app_control_authority":"block"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "blocklist tier gate allows tier 'block'" "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"
chk "reason says actuation is allowed" "$([[ "$AC_BLOCKLIST_AUTHORITY_GATE_REASON" == *"permits browser-extension blocklist actuation"* ]] && echo 1 || echo 0)"

echo "[24] blocklist tier gate: tier 'enforce': allows"
echo '{"app_control_authority":"enforce"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "blocklist tier gate allows tier 'enforce'" "$([[ "$result" == "allow" ]] && echo 1 || echo 0)"

echo "[25] blocklist tier gate: report_deploy / report / app_management / garbage all refuse"
for tier_case in report report_deploy app_management bogus-tier-xyz; do
    echo "{\"app_control_authority\":\"$tier_case\"}" > "$AUTHORITY_CONFIG_FILE"
    PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
    if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
    chk "blocklist tier gate refuses tier '$tier_case'" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"
done

echo "[26] blocklist tier gate: tier key absent, empty, unparseable, or config missing all refuse (fail closed)"
echo '{}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "blocklist tier gate refuses when tier key is absent" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo '{"app_control_authority":""}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "blocklist tier gate refuses an empty-string tier" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo 'not valid json{{{' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "blocklist tier gate refuses unparseable JSON" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

rm -f "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
if ac_blocklist_authority_gate_check; then result=allow; else result=refuse; fi
chk "blocklist tier gate refuses when the config file does not exist" "$([[ "$result" == "refuse" ]] && echo 1 || echo 0)"

echo "[27] blocklist tier gate is strictly more permissive than the destructive tier gate: every tier ac_authority_gate_check allows, ac_blocklist_authority_gate_check also allows, and 'block' splits them (blocklist allows it, destructive does not)"
echo '{"app_control_authority":"enforce"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
ac_authority_gate_check; destructive_managed=$?
ac_blocklist_authority_gate_check; blocklist_managed=$?
chk "'enforce' allows both gates" "$(( destructive_managed == 0 && blocklist_managed == 0 ))"

echo '{"app_control_authority":"block"}' > "$AUTHORITY_CONFIG_FILE"
PATCHED_AC_CONFIG="$AUTHORITY_CONFIG_FILE"
ac_authority_gate_check; destructive_patch=$?
ac_blocklist_authority_gate_check; blocklist_patch=$?
chk "'block' refuses the destructive gate but allows the blocklist gate (acceptance criterion: blocklist actuates one tier lower)" \
    "$(( destructive_patch != 0 && blocklist_patch == 0 ))"

##############################################################################
# PAT-1038 acceptance criterion 4, made enforceable: each actuating-tier value
# must come from a single named constant, not repeated per call site. A
# future edit that adds a second bare `"enforce"` or `"block"` comparison
# instead of reusing PATCHED_APP_CONTROL_DESTRUCTIVE_AUTHORITY / PATCHED_APP_CONTROL_BLOCKLIST_AUTHORITIES
# would silently reintroduce the PAT-858-shaped bug Windows' ActuatingTierAllows
# was built to avoid. Scoped to the hand-maintained source (patched-upload.sh +
# lib/*.sh), not the generated dist/ bundle, and excluding this test file
# itself. There are legitimately two "enforce" literals now (the destructive
# constant's value, and one element of the blocklist tier-set array) — the
# assertion is that both are the named constants, not a stray inline
# comparison, and not a third copy.
##############################################################################
echo "[28] the two actuating-tier constants are each defined exactly once in the source, outside tests"
chk "PATCHED_APP_CONTROL_DESTRUCTIVE_AUTHORITY=\"enforce\" appears exactly once" \
    "$(grep -rc 'PATCHED_APP_CONTROL_DESTRUCTIVE_AUTHORITY="enforce"' "$SCRIPT_DIR/patched-upload.sh" "$SCRIPT_DIR"/lib/*.sh 2>/dev/null | awk -F: '{s+=$2} END{print (s==1)?1:0}')"
chk "PATCHED_APP_CONTROL_BLOCKLIST_AUTHORITIES=(\"block\" \"enforce\") appears exactly once" \
    "$(grep -rc 'PATCHED_APP_CONTROL_BLOCKLIST_AUTHORITIES=("block" "enforce")' "$SCRIPT_DIR/patched-upload.sh" "$SCRIPT_DIR"/lib/*.sh 2>/dev/null | awk -F: '{s+=$2} END{print (s==1)?1:0}')"

##############################################################################
# PAT-1038 / PAT-1038 follow-up, structural: the call sites in
# patched-upload.sh (outside the extracted gate block, so asserted here by
# reading the shipped source directly):
#   - ac_enforce_admins (admin demotion) and ber_remove_extensions (extension
#     removal) are destructive/irreversible and must gate on AC_AUTHORITY_ALLOWED
#     ("enforce" only).
#   - ac_check_app_violations is alert-only and must NOT be gated on tier at
#     all — it stays live at every tier.
#   - bec_enforce_extension_blocklist (the blocklist) is reversible/
#     preventive: it must run whenever AC_GATE_ALLOWED alone (never skipped
#     just because the blocklist tier gate refused — see test-extension-
#     blocklist.zsh case 13 for the reconcile-to-empty behavior this enables),
#     with the blocklist tier decision threaded IN as an argument rather than
#     gating the call itself.
##############################################################################
echo "[29] call site: ac_enforce_admins is nested inside an AC_AUTHORITY_ALLOWED check"
chk "ac_enforce_admins call is preceded by an AC_AUTHORITY_ALLOWED guard" \
    "$(grep -B2 'ac_enforce_admins || true' "$UPLOAD_SH" | grep -q 'if (( AC_AUTHORITY_ALLOWED' && echo 1 || echo 0)"

echo "[30] call site: ac_check_app_violations runs unconditionally on tier (acceptance criterion 3)"
chk "ac_check_app_violations call is NOT preceded by an AC_AUTHORITY_ALLOWED guard" \
    "$(grep -B2 'ac_check_app_violations || true' "$UPLOAD_SH" | grep -q 'AC_AUTHORITY_ALLOWED' && echo 0 || echo 1)"

echo "[31] call site: bec_enforce_extension_blocklist runs whenever AC_GATE_ALLOWED alone, threading AC_BLOCKLIST_AUTHORITY_ALLOWED in as an argument rather than skipping the call"
chk "bec_enforce_extension_blocklist call is preceded by an AC_GATE_ALLOWED guard (not additionally AC_AUTHORITY_ALLOWED)" \
    "$(grep -B2 'bec_enforce_extension_blocklist "\$AC_BLOCKLIST_AUTHORITY_ALLOWED" || true' "$UPLOAD_SH" | grep -q 'if (( AC_GATE_ALLOWED ))' && echo 1 || echo 0)"
chk "bec_enforce_extension_blocklist is passed \$AC_BLOCKLIST_AUTHORITY_ALLOWED, not skipped by it" \
    "$(grep -q 'bec_enforce_extension_blocklist "\$AC_BLOCKLIST_AUTHORITY_ALLOWED" || true' "$UPLOAD_SH" && echo 1 || echo 0)"

echo "[32] call site: ber_remove_extensions requires AC_AUTHORITY_ALLOWED (destructive, skipped outright below tier — no reconcile concern for a one-way removal)"
chk "ber_remove_extensions call is preceded by an AC_GATE_ALLOWED && AC_AUTHORITY_ALLOWED guard" \
    "$(grep -B2 'ber_remove_extensions || true' "$UPLOAD_SH" | grep -q 'AC_GATE_ALLOWED && AC_AUTHORITY_ALLOWED' && echo 1 || echo 0)"

##############################################################################
# NOT reachable without root, by design of this no-root test harness:
#   - That $PATCHED_TMPDIR is actually root-owned mode 0700 under /var/db/patched
#     in production (H11). Here it is an ordinary user-owned mktemp -d dir;
#     ownership/mode enforcement itself is not exercised.
#   - A genuine concurrent write landing mid-copy from a second process. [11]
#     simulates the resulting failure mode (post-copy hash mismatch) by
#     shadowing cp, not by manufacturing a real race.
#   - The staged copy actually being read by the three lib/*.sh modules when
#     sourced from patched-upload.sh itself. The lib test harnesses
#     (test-app-control.zsh, test-extension-removal.zsh,
#     test-extension-blocklist.zsh) set PATCHED_AC_CONFIG directly and
#     bypass patched-upload.sh's gate/staging entirely, so end-to-end
#     gate -> stage -> module-reads-the-copy only happens in a real run.
##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
