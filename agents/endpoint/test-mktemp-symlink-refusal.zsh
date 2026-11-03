#!/bin/zsh
##############################################################################
# test-mktemp-symlink-refusal.zsh — PAT-1079.
#
# Two production temp-file writes land in world-writable /tmp:
#
#   (A) endpoint/patched-update.sh     — the mirror-manifest refresh
#   (B) endpoint/patched-log-upload.sh — the gzip of the log bundle
#
# Both had a non-substituting mktemp template: an X run with a ".json" or
# ".gz" suffix glued onto the end of it. macOS/BSD only substitutes a
# TRAILING X run, so it handed the literal path back unsubstituted. That made
# the path permanently predictable in a world-writable directory. PAT-1079
# fixed the templates so the names really randomise, and added a symlink
# refusal immediately before the separate, later open() each site performs
# by path.
#
# WHAT THESE TESTS PROVE, AND WHAT THEY DO NOT
#
# They prove the refusal branch actually executes: the victim file survives
# untouched and a clear refusal is logged, rather than the write silently
# following the link. They do NOT reproduce the real race, which is the entry
# being swapped between mktemp's create and the later open. That window is
# microseconds wide and is not reproducible in a static shell test, so each
# test intercepts mktemp and hands the code a path that is already a symlink.
# That drives the same branch by the same mechanism, which is the half that
# regresses if someone deletes the check.
#
# The refusal narrows the race; it does not close it. A check followed by an
# open is two syscalls and is never atomic against a determined racer. It is
# also not exploitable in practice today: mktemp creates with O_CREAT|O_EXCL
# (which refuses a pre-planted entry outright), the names now randomise, and
# /tmp's sticky bit stops a non-root user unlinking a root-owned file. The
# tests guard the pattern, in the same spirit as PAT-1043's sidecar case.
#
# No root, no network. Run: zsh endpoint/test-mktemp-symlink-refusal.zsh
##############################################################################

set -u
export PATCHED_API_URL="http://127.0.0.1:1"

SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"
LOG_UPLOAD_SH="$SCRIPT_DIR/patched-log-upload.sh"
PYTHON3="/usr/bin/python3"

pass=0; fail=0

chk() {
    local desc="$1" cond="$2"
    if [[ "$cond" == "1" ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc"
    fi
}

chk_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc — expected to contain: $needle"
        echo "        got: ${haystack:0:400}"
    fi
}

chk_not_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc — should NOT contain: $needle"
        echo "        got: ${haystack:0:400}"
    fi
}

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/.pat1079-test.XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT

# ============================================================================
# (A) patched-update.sh — mirror-manifest refresh
#
# The block is sentinel-wrapped (PATCHED_MIRROR_MANIFEST_REFRESH_START/END) so
# it can be extracted and driven directly, no root and no network — the same
# idiom endpoint/test-agent-tier-default.zsh uses for the tier-default block.
# ============================================================================
echo "\n--- (A) mirror-manifest refresh (patched-update.sh) ---"

BLOCK_TMP=$(mktemp "${TMPDIR:-/tmp}/.pat1079-mirror-block.XXXXXX")
awk '/PATCHED_MIRROR_MANIFEST_REFRESH_START/{f=1;next} /PATCHED_MIRROR_MANIFEST_REFRESH_END/{f=0} f' \
    "$UPDATE_SH" > "$BLOCK_TMP"
if [[ ! -s "$BLOCK_TMP" ]]; then
    echo "  FAIL: could not extract PATCHED_MIRROR_MANIFEST_REFRESH block from $UPDATE_SH"
    exit 1
fi

# Static assertion first: the template must end in X's, or mktemp does not
# substitute at all and the path is predictable again.
chk "mirror template ends in trailing X's" \
    "$(grep -qE 'mktemp /tmp/\.patched-mirror-manifest\.X+\)?$' "$BLOCK_TMP" && echo 1 || echo 0)"

# run_mirror_block <mktemp-override-path|"">
#   Sources the extracted block with the collaborators it needs stubbed.
#   A non-empty override makes the shell function `mktemp` return that exact
#   path instead of calling the real one, which is how we hand the code a
#   path that is already a symlink.
run_mirror_block() {
    local override="$1" manifest_file="$2"
    PAT1079_MKTEMP_OVERRIDE="$override" \
    MIRROR_MANIFEST_FILE="$manifest_file" \
    zsh -c '
        set -u
        PYTHON3="/usr/bin/python3"
        # The two constants the block reads are assigned just above the
        # sentinel in the real script; set them to the same shape here.
        MIRROR_CDN_BASE="https://cdn.invalid.test"
        MIRROR_MANIFEST_CACHE_TTL=21600
        # with_proxy is a passthrough in the real script when no proxy is
        # configured; curl is stubbed so nothing touches the network. The
        # stub writes a valid manifest so the happy path is exercised too.
        with_proxy() { shift; "$@"; }
        curl() {
            local out=""
            while (( $# )); do
                [[ "$1" == "-o" ]] && { out="$2"; shift 2; continue; }
                shift
            done
            [[ -n "$out" ]] && printf "%s" "{\"labels\":{}}" > "$out"
            return 0
        }
        if [[ -n "$PAT1079_MKTEMP_OVERRIDE" ]]; then
            mktemp() { print -r -- "$PAT1079_MKTEMP_OVERRIDE"; }
        fi
        source "$0"
    ' "$BLOCK_TMP" 2>&1
}

# --- (A1) happy path: a normal temp file is written and promoted ------------
a1_manifest="$SCRATCH/a1-manifest.json"
a1_out=$(run_mirror_block "" "$a1_manifest")
chk_contains "A1 happy path: manifest refreshed" "Mirror manifest refreshed" "$a1_out"
chk_not_contains "A1 happy path: no spurious symlink refusal" "is a symlink" "$a1_out"
chk "A1 happy path: manifest written" \
    "$([[ -f "$a1_manifest" ]] && echo 1 || echo 0)"

# --- (A2) planted symlink: refused, victim untouched ------------------------
a2_victim="$SCRATCH/a2-victim.txt"
a2_link="$SCRATCH/a2-planted-link"
a2_manifest="$SCRATCH/a2-manifest.json"
printf 'ORIGINAL VICTIM CONTENT\n' > "$a2_victim"
ln -s "$a2_victim" "$a2_link"

a2_out=$(run_mirror_block "$a2_link" "$a2_manifest")
chk_contains "A2 symlink: refusal is logged" \
    "refusing to write through it" "$a2_out"
chk_not_contains "A2 symlink: does not claim a refresh happened" \
    "Mirror manifest refreshed" "$a2_out"
chk "A2 symlink: victim content untouched" \
    "$([[ "$(cat "$a2_victim")" == "ORIGINAL VICTIM CONTENT" ]] && echo 1 || echo 0)"
chk "A2 symlink: victim still exists" \
    "$([[ -f "$a2_victim" ]] && echo 1 || echo 0)"
# The refusal removes the symlink entry itself (rm -f on a symlink unlinks the
# link, never the target), so a stale planted link cannot wedge every later run.
chk "A2 symlink: planted link removed, target not followed" \
    "$([[ ! -e "$a2_link" && -f "$a2_victim" ]] && echo 1 || echo 0)"
# Fail closed: the cached manifest is left alone rather than replaced.
chk "A2 symlink: cached manifest not created from a refused write" \
    "$([[ ! -e "$a2_manifest" ]] && echo 1 || echo 0)"

rm -f "$BLOCK_TMP"

# ============================================================================
# (B) patched-log-upload.sh — gzip of the log bundle
#
# This one is top-level script flow rather than an extractable block, so the
# whole script runs in a sandbox. Only one line of the script is rewritten:
# its `export PATH=...` prelude, which would otherwise push our stub bin
# behind /usr/bin and make the mktemp stub unreachable. The mktemp call and
# the refusal under test are copied verbatim. Stubbing external commands via
# a PATH-prepended stub dir plus a sed'd copy is the idiom
# macos/test-uninstall-agent-health.zsh already uses.
# ============================================================================
echo "\n--- (B) log-bundle gzip (patched-log-upload.sh) ---"

chk "gz template ends in trailing X's" \
    "$(grep -qE 'gz_file=\$\(mktemp /tmp/\.patched-logbundle-gz\.X+\)$' "$LOG_UPLOAD_SH" && echo 1 || echo 0)"

# Every refusal in this script exits 1, but the sole caller invokes it as
# `"$log_upload_script" || true` (endpoint/patched-fetch-config.sh), so the
# status is discarded and the directive silently re-fires forever. Each refusal
# must therefore also record an agent_health fault, or it is invisible off-box.
chk "all three refusal sites record an agent_health fault" \
    "$([[ "$(grep -c 'patched_agent_health_record_failure "directive_skipped" "log_upload" "symlink_refused_' "$LOG_UPLOAD_SH")" -eq 3 ]] && echo 1 || echo 0)"

# run_log_upload <gz-mktemp-override|""> [<trim-mktemp-override|"">] [<max_bytes>]
#   Runs the real script end to end against sandbox dirs, with a device-
#   matched log_request directive (device_id is required — PAT-1033, an
#   empty device_id is a no-op, not tenant-wide) so it reaches the gzip step.
#   curl is stubbed so the POST never leaves the machine.
#
#   A non-zero <max_bytes> (with the bulk log below pushing the gzipped bundle
#   past it) is what drives execution into the trim branch; the trim override
#   then hands that branch a $trim_file whose "${trim_file}.kept" sibling is
#   already a symlink.
run_log_upload() {
    local override="$1" trim_override="${2:-}" max_bytes="${3:-0}"
    local sandbox stub_bin copy state creds logs out i

    sandbox=$(mktemp -d "$SCRATCH/lu.XXXXXX")
    stub_bin="$sandbox/stubbin"; state="$sandbox/state"
    creds="$sandbox/creds";      logs="$sandbox/logs"
    mkdir -p "$stub_bin" "$state" "$creds" "$logs"

    echo "test-bearer-token" > "$creds/bearer-token"
    echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > "$creds/hmac-secret"
    # PAT-1773: the script reads the cached config only when it belongs to the
    # enrolled tenant, decided by agent_config_tenant.py from the bundle.
    echo "00000000-0000-0000-0000-000000000001" > "$creds/tenant-id"
    mkdir -p "$sandbox/bundle"
    cp "$SCRIPT_DIR/agent_config_tenant.py" "$sandbox/bundle/agent_config_tenant.py"

    # A log file with content, so collection produces lines and the script
    # actually reaches the gzip step rather than exiting early.
    {
        echo "=== patched-update run started 2026-07-01T00:00:00Z ==="
        echo "test log line one"
        echo "test log line two"
        # Bulk, deliberately low-entropy-resistant content so the GZIPPED
        # bundle comfortably clears a small max_bytes and the trim branch is
        # genuinely entered rather than skipped.
        if (( max_bytes > 0 )); then
            for i in {1..400}; do
                echo "2026-07-01T00:00:00Z bulk line $i $RANDOM$RANDOM$RANDOM padding-$i"
            done
        fi
    } > "$logs/update.log"

    printf '%s' '{"tenant_id":"00000000-0000-0000-0000-000000000001","config_version":1,"device_id":"40404040-4040-4040-4040-404040404040",
      "log_request":{"request_id":"99999999-9999-9999-9999-999999999999","device_id":"40404040-4040-4040-4040-404040404040",
      "components":["updater"],"since":"","until":"","max_bytes":'"$max_bytes"'}}' \
        > "$state/agent-config.json"

    # Intercept ONLY the gz-bundle and trim templates; every other mktemp call
    # in the script (the plain log bundle, the curl response file) must keep
    # working, so anything else is delegated to the real binary.
    cat > "$stub_bin/mktemp" <<STUBEOF
#!/bin/sh
case "\$*" in
  *".patched-logbundle-gz."*)
    if [ -n "\${PAT1079_MKTEMP_OVERRIDE:-}" ]; then
      printf '%s\n' "\$PAT1079_MKTEMP_OVERRIDE"
      exit 0
    fi
    ;;
  *".patched-logbundle-trim."*)
    if [ -n "\${PAT1079_TRIM_MKTEMP_OVERRIDE:-}" ]; then
      printf '%s\n' "\$PAT1079_TRIM_MKTEMP_OVERRIDE"
      exit 0
    fi
    ;;
esac
exec /usr/bin/mktemp "\$@"
STUBEOF
    # Keep the upload off the network. 000 is the script's own "no response"
    # code, so this is a shape it already handles.
    cat > "$stub_bin/curl" <<'STUBEOF'
#!/bin/sh
printf '000'
exit 0
STUBEOF
    chmod +x "$stub_bin/mktemp" "$stub_bin/curl"

    # Instrument only a checked scratch copy; refuse source drift before launch.
    copy="$sandbox/patched-log-upload.sh"
    /usr/bin/python3 "$SCRIPT_DIR/../ci/privileged_script_fixture.py" \
        "$LOG_UPLOAD_SH" "$copy" "$stub_bin" || return 1

    out=$(PATH="$stub_bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        PATCHED_API_URL="http://127.0.0.1:1" \
        PAT1079_MKTEMP_OVERRIDE="$override" \
        PAT1079_TRIM_MKTEMP_OVERRIDE="$trim_override" \
        PATCHED_STATE_DIR="$state" \
        PATCHED_CREDS_DIR="$creds" \
        PATCHED_LOG_UPDATER="$logs/update.log" \
        PATCHED_LOG_COLLECTOR="$logs/collect.log" \
        PATCHED_LOG_UPLOAD_LOG="$logs/upload.log" \
        PATCHED_JSONL_LOG_DIR="$logs/jsonl" \
        PATCHED_BUNDLE_DIR="$sandbox/bundle" \
        PATCHED_AGENT_HEALTH_STORE="$state/.agent-health.json" \
        zsh "$copy" 2>&1)
    # The caller runs this in a command substitution, so a plain variable
    # assignment would not survive the subshell. Hand the exit status and the
    # sandbox path back through files instead.
    print -r -- "$?" > "$SCRATCH/last-rc"
    print -r -- "$state/.agent-health.json" > "$SCRATCH/last-health-store"
    printf '%s' "$out"
}

# --- (B1) happy path: a normal temp file gets gzipped ------------------------
b1_out=$(run_log_upload "")
b1_rc=$(cat "$SCRATCH/last-rc")
chk_contains "B1 happy path: reaches the collection step" "collected" "$b1_out"
chk_not_contains "B1 happy path: no spurious symlink refusal" \
    "REFUSING to write bundle" "$b1_out"
chk "B1 happy path: script did not abort on the refusal path (rc != 1)" \
    "$([[ "$b1_rc" != "1" ]] && echo 1 || echo 0)"

# --- (B2) planted symlink: refused, victim untouched -------------------------
b2_victim="$SCRATCH/b2-victim.txt"
b2_link="$SCRATCH/b2-planted-link"
printf 'ORIGINAL VICTIM CONTENT\n' > "$b2_victim"
ln -s "$b2_victim" "$b2_link"

b2_out=$(run_log_upload "$b2_link")
b2_rc=$(cat "$SCRATCH/last-rc")
chk_contains "B2 symlink: refusal is logged" \
    "REFUSING to write bundle through symlinked temp path" "$b2_out"
chk "B2 symlink: aborts with a non-zero status" \
    "$([[ "$b2_rc" == "1" ]] && echo 1 || echo 0)"
chk "B2 symlink: victim content untouched" \
    "$([[ "$(cat "$b2_victim")" == "ORIGINAL VICTIM CONTENT" ]] && echo 1 || echo 0)"
chk "B2 symlink: victim is still a plain text file, not gzip" \
    "$(file -b "$b2_victim" | grep -qi 'text' && echo 1 || echo 0)"
chk "B2 symlink: planted link removed, target not followed" \
    "$([[ ! -e "$b2_link" && -f "$b2_victim" ]] && echo 1 || echo 0)"
# The refusal exits 1, but the sole caller discards that status
# (patched-fetch-config.sh runs this as `"$log_upload_script" || true`), so the
# only thing that can carry a refusal off the box is the agent_health store.
# Assert the fault genuinely landed there, not just that the call was made.
b2_health=$(cat "$SCRATCH/last-health-store")
chk_contains "B2 symlink: refusal recorded as an agent_health fault" \
    "symlink_refused_bundle_gz" "$(cat "$b2_health" 2>/dev/null)"
chk_contains "B2 symlink: fault is namespaced under directive_skipped/log_upload" \
    "directive_skipped" "$(cat "$b2_health" 2>/dev/null)"

# --- (B3) the trim branch's "${trim_file}.kept" write ------------------------
#
# Unlike every other site in this ticket, "${trim_file}.kept" is NOT an mktemp
# path: it is built by concatenating ".kept" onto $trim_file's name, so it has
# neither O_CREAT|O_EXCL nor any unpredictability an attacker cannot just read
# off the $trim_file entry mktemp published moments earlier. The real attack is
# therefore reliably winnable rather than a microsecond race: poll /tmp, see
# .patched-logbundle-trim.<rand> appear, create <that name>.kept as a symlink
# while `gzip -dc` is still running, and the redirect below truncates the
# target as root. /tmp's sticky bit does not help — the attacker creates a new
# entry they own rather than unlinking one of root's.
#
# As with A2/B2 this drives the branch by handing the code a path that is
# already a symlink rather than reproducing the timing, which is the half that
# regresses if the check is deleted.
b3_victim="$SCRATCH/b3-victim.txt"
b3_trim="$SCRATCH/b3-trim"
printf 'ORIGINAL VICTIM CONTENT\n' > "$b3_victim"
ln -s "$b3_victim" "${b3_trim}.kept"

# max_bytes is tiny and the log is bulky, so the gzipped bundle must exceed it
# and the trim branch must actually run.
b3_out=$(run_log_upload "" "$b3_trim" 200)
b3_rc=$(cat "$SCRATCH/last-rc")
chk_contains "B3 trim: the trim branch was genuinely entered" \
    "trimming oldest lines" "$b3_out"
chk_contains "B3 trim: refusal is logged" \
    "REFUSING to write trimmed lines through symlinked temp path" "$b3_out"
chk "B3 trim: aborts with a non-zero status" \
    "$([[ "$b3_rc" == "1" ]] && echo 1 || echo 0)"
chk "B3 trim: victim content untouched" \
    "$([[ "$(cat "$b3_victim")" == "ORIGINAL VICTIM CONTENT" ]] && echo 1 || echo 0)"
chk "B3 trim: victim still exists and is still plain text" \
    "$([[ -f "$b3_victim" ]] && file -b "$b3_victim" | grep -qi 'text' && echo 1 || echo 0)"
chk "B3 trim: planted .kept link removed, target not followed" \
    "$([[ ! -e "${b3_trim}.kept" && -f "$b3_victim" ]] && echo 1 || echo 0)"
# Fail closed: it must not fall through and upload the untrimmed bundle.
chk_not_contains "B3 trim: does not claim a trim happened" \
    "trimmed to " "$b3_out"
chk_not_contains "B3 trim: does not go on to POST" \
    "POST /v1/agent-logs" "$b3_out"
b3_health=$(cat "$SCRATCH/last-health-store")
chk_contains "B3 trim: refusal recorded as an agent_health fault" \
    "symlink_refused_trim_kept" "$(cat "$b3_health" 2>/dev/null)"

# --- (B4) trim branch, no symlink: the happy path still trims ----------------
# Guards against the new check being written so it refuses unconditionally.
b4_out=$(run_log_upload "" "" 200)
chk_contains "B4 trim happy path: the trim branch was entered" \
    "trimming oldest lines" "$b4_out"
chk_contains "B4 trim happy path: the trim completed" "trimmed to " "$b4_out"
chk_not_contains "B4 trim happy path: no spurious symlink refusal" \
    "REFUSING" "$b4_out"

# ============================================================================
# (C) The remaining non-/tmp site in this ticket is asserted statically rather
#     than driven end to end: its directory is root-owned and unreachable by
#     an unprivileged user (/var/db/patched/events-queue is 0755 root:wheel,
#     created by a bare `mkdir -p` under the daemon's default 022 umask with
#     no chmod anywhere that loosens it). What can still regress is the
#     template and the presence of the refusal, so that is what is asserted.
# ============================================================================
echo "\n--- (C) non-/tmp sites: templates substitute and refusals present ---"

chk "audit-event template ends in trailing X's" \
    "$(grep -qE 'mktemp "\$EVENTS_QUEUE/evt-\$\{ev_ms\}-X+"\)' "$UPDATE_SH" && echo 1 || echo 0)"

# The timestamp component used to be `date +%s%3N`. BSD/macOS date has no %N,
# so it emitted the literal "3N" and the on-disk name carried
# "<epoch-seconds>3N" instead of the milliseconds docs/audit-events-contract.md
# and the Windows agent's ToUnixTimeMilliseconds() both specify. Pin the fix,
# and pin the absence of the broken incantation so it cannot creep back.
# Comment lines are stripped first: the fix's own comment names the broken
# expression in order to explain it, and that must not read as a regression.
chk "audit-event no longer uses the non-portable date +%3N in executable code" \
    "$(grep -vE '^[[:space:]]*#' "$UPDATE_SH" | grep -q '%s%3N' && echo 0 || echo 1)"
chk "audit-event computes real milliseconds" \
    "$(grep -vE '^[[:space:]]*#' "$UPDATE_SH" | grep -q 'int(time.time()\*1000)' && echo 1 || echo 0)"

# Live proof of both halves on THIS machine: that BSD date really does emit the
# literal, and that the replacement really is milliseconds.
bsd_date_ms=$(date +%s%3N)
chk "BSD date +%s%3N really does emit a literal '3N' (the bug being fixed)" \
    "$([[ "$bsd_date_ms" == *3N ]] && echo 1 || echo 0)"
real_ms=$("$PYTHON3" -c 'import time; print(int(time.time()*1000))')
chk "replacement yields 13 all-digit milliseconds" \
    "$([[ ${#real_ms} -eq 13 && "$real_ms" != *[^0-9]* ]] && echo 1 || echo 0)"
chk "audit-event keeps the .json name the drain glob and Windows agent expect" \
    "$(grep -q 'local ev_file="\${ev_tmp}.json"' "$UPDATE_SH" && echo 1 || echo 0)"
chk "audit-event write refuses a symlinked path" \
    "$(grep -q 'audit event temp path is a symlink' "$UPDATE_SH" && echo 1 || echo 0)"

# Live proof that the audit-event naming still satisfies the evt-*.json glob
# the ring-buffer cap, drain_events_queue and windows/src/Service/
# AuditEventShipper.cs all depend on.
evq="$SCRATCH/events-queue"
mkdir -p "$evq"
ev_tmp=$(mktemp "$evq/evt-$(date +%s)-XXXXXX")
mv "$ev_tmp" "${ev_tmp}.json"
matched=("$evq"/evt-*.json(N))
chk "audit-event name still matches the evt-*.json glob" \
    "$([[ ${#matched} -eq 1 ]] && echo 1 || echo 0)"
chk "audit-event name is genuinely randomised (no literal X run)" \
    "$([[ "${matched[1]}" != *XXXXXX* ]] && echo 1 || echo 0)"

# ============================================================================
echo "\n============================================"
echo "PASS: $pass   FAIL: $fail"
echo "============================================"
[[ "$fail" -eq 0 ]] || exit 1
exit 0
