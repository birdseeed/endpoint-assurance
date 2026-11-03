#!/bin/zsh
##############################################################################
# test-extension-blocklist.zsh — tests for the PAT-828 browser-extension
# managed-policy blocklist enforcer in lib/browser_extension_control.sh.
#
# Sources the live enforcement function and drives it against temp preference
# dirs / a fake Firefox bundle / a temp sidecar so no root or real browser is
# needed. `defaults` and /usr/bin/python3 are stock on macOS runners.
#
# Run: zsh macos/test-extension-blocklist.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
LIB="$SCRIPT_DIR/lib/browser_extension_control.sh"
export PYTHON3="/usr/bin/python3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.bec-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- Harness the ambient state the lib expects from patched-upload.sh --------
export PATCHED_TMPDIR="$WORK/tmp"; mkdir -p "$PATCHED_TMPDIR"
export API_URL="https://api.invalid.test"
export BEARER_TOKEN="test-bearer"
export CREDS_DIR="$WORK/creds"; mkdir -p "$CREDS_DIR"
export HW_UUID="TEST-UUID"

# Stubs: the lib expects compute_hmac (defined in the caller) + curl for the
# audit POST. Capture the posted body so we can assert on the audit payload.
POSTED_BODY="$WORK/posted-body.json"
compute_hmac() { echo "stub-sig"; }
curl() {
    local a
    # Find the --data-binary @<file> argument and snapshot it.
    local prev=""
    for a in "$@"; do
        case "$prev" in
            --data-binary) cp "${a#@}" "$POSTED_BODY" 2>/dev/null ;;
        esac
        prev="$a"
    done
    echo "200"   # http_code that the lib reads from curl stdout
}
# PAT-881: the lib now sends the audit POST via patched_curl_bearer (bearer
# token off argv, over stdin). In production patched-upload.sh defines it inline;
# here it just drops the token arg and delegates to the curl stub above, which
# still captures the posted body from --data-binary.
patched_curl_bearer() { shift; curl "$@"; }

source "$LIB"

# --- Per-test environment ----------------------------------------------------
PREFS="$WORK/prefs"
FFAPP="$WORK/Firefox.app"
STATE="$WORK/state.json"
CFG="$WORK/agent-config.json"
export PATCHED_BEC_PREFS_DIR="$PREFS"
export PATCHED_BEC_FIREFOX_APP="$FFAPP"
export PATCHED_BEC_STATE_FILE="$STATE"
export PATCHED_AC_CONFIG="$CFG"

reset_env() {
    rm -rf "$PREFS" "$FFAPP" "$STATE" "$POSTED_BODY"
    mkdir -p "$PREFS"
    mkdir -p "$FFAPP/Contents/Resources"   # Firefox "installed"
}

pass=0; fail=0
ok()   { (( pass++ )); echo "  PASS: $1"; }
bad()  { (( fail++ )); echo "  FAIL: $1"; }

# Read a chromium blocklist array back as sorted newline IDs (empty if unset).
chrome_ids() { # <domain>
    /usr/bin/defaults read "$PREFS/$1" ExtensionInstallBlocklist 2>/dev/null \
        | grep -oE '"[^"]+"|[A-Za-z0-9]+' | tr -d '"' \
        | grep -vE '^\($|^\)$|,' | sort | grep -v '^$' || true
}
ff_blocked() { # prints sorted IDs firefox policies.json blocks
    "$PYTHON3" - "$FFAPP/Contents/Resources/distribution/policies.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    es=d.get("policies",{}).get("ExtensionSettings",{})
    for k,v in sorted(es.items()):
        if isinstance(v,dict) and v.get("installation_mode")=="blocked":
            print(k)
except Exception:
    pass
PY
}
json_get() { "$PYTHON3" -c "import json,sys; print(json.load(open(sys.argv[1]))$2)" "$1" 2>/dev/null; }
posted_event_count() {
    [[ -f "$POSTED_BODY" ]] || { echo 0; return; }
    "$PYTHON3" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['events']))" "$POSTED_BODY" 2>/dev/null || echo 0
}

##############################################################################
echo "--- 1. block set across all three browsers ---"
reset_env
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"},
  {"browser":"chrome","extension_id":"dddddddddddddddddddddddddddddddd"},
  {"browser":"edge","extension_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
  {"browser":"firefox","extension_id":"blocked@example.com"}
]}}
JSON
bec_enforce_extension_blocklist >/dev/null

[[ "$(chrome_ids com.google.Chrome | tr '\n' ' ')" == "cccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddd "* ]] \
    && ok "chrome blocklist written (2 ids)" || bad "chrome blocklist: got [$(chrome_ids com.google.Chrome | tr '\n' ' ')]"
[[ "$(chrome_ids com.microsoft.Edge | tr -d '\n')" == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" ]] \
    && ok "edge blocklist written (1 id)" || bad "edge blocklist: got [$(chrome_ids com.microsoft.Edge)]"
[[ "$(ff_blocked | tr -d '\n')" == "blocked@example.com" ]] \
    && ok "firefox policies.json blocks id" || bad "firefox blocked: got [$(ff_blocked)]"
[[ "$(posted_event_count)" == "3" ]] && ok "3 audit events posted" || bad "audit events: got $(posted_event_count)"
# device-global property: the policy artifacts live under machine paths, not any
# per-user Library — one push covers every user + browser profile.
[[ -f "$PREFS/com.google.Chrome.plist" && "$PREFS" != *"/Users/"* ]] \
    && ok "policy is device-global (machine path, all users/profiles)" || bad "policy path not device-global"
# state records what we manage
[[ "$(json_get "$STATE" "['browsers']['chrome']" | tr -d ' ')" == *cccc* ]] \
    && ok "sidecar state records chrome ids" || bad "state missing chrome ids"

##############################################################################
echo "--- 2. reconcile: shrink chrome to 1 id, clear edge ---"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"},
  {"browser":"firefox","extension_id":"blocked@example.com"}
]}}
JSON
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
[[ "$(chrome_ids com.google.Chrome | tr -d '\n')" == "cccccccccccccccccccccccccccccccc" ]] \
    && ok "chrome reduced to 1 id" || bad "chrome after shrink: got [$(chrome_ids com.google.Chrome)]"
[[ -z "$(chrome_ids com.microsoft.Edge)" ]] \
    && ok "edge blocklist key cleared" || bad "edge not cleared: got [$(chrome_ids com.microsoft.Edge)]"
# firefox unchanged -> only chrome + edge changed -> 2 events
[[ "$(posted_event_count)" == "2" ]] && ok "2 events (chrome changed, edge cleared)" || bad "events: got $(posted_event_count)"

##############################################################################
echo "--- 3. no-op when policy already matches ---"
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
[[ "$(posted_event_count)" == "0" ]] && ok "idempotent second run posts nothing" || bad "expected 0 events, got $(posted_event_count)"

##############################################################################
echo "--- 4. firefox merge preserves a pre-existing admin policy ---"
reset_env
mkdir -p "$FFAPP/Contents/Resources/distribution"
cat > "$FFAPP/Contents/Resources/distribution/policies.json" <<'JSON'
{"policies":{"DisableTelemetry":true,"ExtensionSettings":{
  "admin@corp.example":{"installation_mode":"force_installed","install_url":"https://x"}
}}}
JSON
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"firefox","extension_id":"blocked@example.com"}
]}}
JSON
bec_enforce_extension_blocklist >/dev/null
[[ "$(json_get "$FFAPP/Contents/Resources/distribution/policies.json" "['policies']['DisableTelemetry']")" == "True" ]] \
    && ok "unrelated policy key preserved" || bad "DisableTelemetry lost"
[[ "$(json_get "$FFAPP/Contents/Resources/distribution/policies.json" "['policies']['ExtensionSettings']['admin@corp.example']['installation_mode']")" == "force_installed" ]] \
    && ok "admin ExtensionSettings entry preserved" || bad "admin entry clobbered"
[[ "$(ff_blocked | tr -d '\n')" == "blocked@example.com" ]] \
    && ok "our blocked id added alongside" || bad "our id missing"

##############################################################################
echo "--- 5. disabled / empty blocklist => no action, no writes ---"
reset_env
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":false,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"}]}}
JSON
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
[[ ! -f "$PREFS/com.google.Chrome.plist" && "$(posted_event_count)" == "0" ]] \
    && ok "disabled app_control writes nothing" || bad "disabled path wrote policy"

cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[]}}
JSON
bec_enforce_extension_blocklist >/dev/null
[[ ! -f "$PREFS/com.google.Chrome.plist" && "$(posted_event_count)" == "0" ]] \
    && ok "empty blocklist writes nothing" || bad "empty blocklist wrote policy"

##############################################################################
echo "--- 6. dry-run performs no writes and posts nothing ---"
reset_env
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"}]}}
JSON
rm -f "$POSTED_BODY"
PATCHED_DRY_RUN=1 bec_enforce_extension_blocklist >/dev/null
[[ ! -f "$PREFS/com.google.Chrome.plist" && ! -f "$STATE" && "$(posted_event_count)" == "0" ]] \
    && ok "dry-run mutates nothing" || bad "dry-run wrote artifacts"

##############################################################################
echo "--- 7. firefox not installed: defer, then enforce once it appears ---"
reset_env
rm -rf "$FFAPP"   # Firefox NOT installed
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"firefox","extension_id":"blocked@example.com"}]}}
JSON
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
# Must NOT record firefox as managed (nothing was written) — otherwise a later
# install would be skipped by the idempotency check and never enforced.
[[ "$(json_get "$STATE" "['browsers'].get('firefox')")" == "None" && "$(posted_event_count)" == "0" ]] \
    && ok "firefox absent: no state recorded, no event" || bad "firefox absent recorded state"
# Now Firefox appears; enforcement must actually apply on the next run.
mkdir -p "$FFAPP/Contents/Resources"
bec_enforce_extension_blocklist >/dev/null
[[ "$(ff_blocked | tr -d '\n')" == "blocked@example.com" ]] \
    && ok "firefox policy applied after install" || bad "firefox not enforced after install: got [$(ff_blocked)]"

##############################################################################
echo "--- 8. PAT-1043: symlink pre-planted at the old predictable temp path is not followed ---"
# Regression test for the local-privilege-escalation fix: the old code wrote
# through <policies_path>.patched.tmp with a plain open() (follows symlinks)
# and a fully predictable name, so any admin-group user (write access to
# /Applications) could pre-plant a symlink there pointing at any root-owned
# file and have this root-run enforcer truncate and overwrite it. The fixed
# code never opens that predictable name at all (it writes through an
# unpredictable, O_EXCL'd temp name instead), so a symlink planted at the old
# path is simply orphaned rather than followed -- and real enforcement still
# succeeds via the safe path. VICTIM stands in for a root-owned file that
# only root could otherwise reach; a non-root test can't create a literal
# root-owned target, but the on-disk mechanics (open-follows-symlink vs.
# O_EXCL-refuses) are identical regardless of who owns the far end.
reset_env
VICTIM="$WORK/victim-root-file"
echo "original-root-content" > "$VICTIM"
mkdir -p "$FFAPP/Contents/Resources/distribution"
ln -s "$VICTIM" "$FFAPP/Contents/Resources/distribution/policies.json.patched.tmp"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"firefox","extension_id":"blocked@example.com"}]}}
JSON
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
[[ "$(cat "$VICTIM")" == "original-root-content" ]] \
    && ok "PAT-1043: symlink target untouched by enforcement" \
    || bad "PAT-1043: symlink target was modified -- root file overwrite vulnerability"
[[ "$(ff_blocked | tr -d '\n')" == "blocked@example.com" ]] \
    && ok "PAT-1043: real policies.json still written correctly despite planted symlink" \
    || bad "PAT-1043: policy not applied: got [$(ff_blocked)]"
[[ -L "$FFAPP/Contents/Resources/distribution/policies.json.patched.tmp" ]] \
    && ok "PAT-1043: stale planted symlink left in place, untouched" \
    || bad "PAT-1043: planted symlink was consumed/removed unexpectedly"

##############################################################################
echo "--- 9. PAT-1043: user-writable Firefox bundle refuses to enforce (ownership, not symlink) ---"
# The other half of the fix: even with no symlink anywhere, a bundle a
# non-root user can rewrite is one where a "managed" policy is meaningless --
# the same user can just delete it again. This must produce the ownership
# refusal message specifically, not the symlink-refusal path exercised above.
reset_env
chmod 0777 "$FFAPP"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"firefox","extension_id":"blocked@example.com"}]}}
JSON
rm -f "$POSTED_BODY"
OUT=$(bec_enforce_extension_blocklist 2>&1)
chmod 0755 "$FFAPP"
[[ ! -f "$FFAPP/Contents/Resources/distribution/policies.json" ]] \
    && ok "PAT-1043: user-writable bundle -> no policy written" \
    || bad "PAT-1043: policy written despite user-writable bundle"
[[ "$(posted_event_count)" == "0" ]] \
    && ok "PAT-1043: no audit event for a refused enforcement" \
    || bad "PAT-1043: audit event posted despite refusal"
print -r -- "$OUT" | grep -qi "user-writable" \
    && ok "PAT-1043: refusal reason names ownership, not a symlink" \
    || bad "PAT-1043: expected ownership refusal message, got: $OUT"
print -r -- "$OUT" | grep -qi "REFUSING symlinked" \
    && bad "PAT-1043: ownership refusal should not also log a symlink refusal" \
    || ok "PAT-1043: ownership refusal path is distinct from the symlink-refusal path"

##############################################################################
echo "--- 10. PAT-1043: clean root-locked-down bundle still writes correctly (unchanged output) ---"
# Confirms the hardening didn't change behavior for the normal case: this is
# the same shape as test 1/4, re-asserted here explicitly against the fixed
# code path so the happy path and the two refusal paths are proven side by
# side. Fixtures here are owned by the invoking user with mode 0755 (mkdir's
# default under a standard umask), which is the exact condition the fixed
# code accepts -- see browser_extension_control.sh's _owner_locked_down
# comment for why the check is keyed off the running process's own uid
# rather than a hardcoded 0 (root-owned fixtures cannot be created without
# sudo, which this test harness deliberately does not require).
reset_env
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"firefox","extension_id":"clean@example.com"}]}}
JSON
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
[[ "$(ff_blocked | tr -d '\n')" == "clean@example.com" ]] \
    && ok "PAT-1043: clean bundle enforces normally" \
    || bad "PAT-1043: clean bundle did not enforce: got [$(ff_blocked)]"
[[ "$(posted_event_count)" == "1" ]] \
    && ok "PAT-1043: clean bundle posts its audit event" \
    || bad "PAT-1043: expected 1 event, got $(posted_event_count)"

##############################################################################
echo "--- 11. PAT-1043 follow-up: symlink planted at the bundle path itself ---"
# Non-author review finding: the original PAT-1043 fix anchored
# Contents/Resources/distribution to a bundle fd, but that fd came from a
# plain os.open(firefox_app, O_DIRECTORY) issued *after* an os.lstat
# ownership check on the path -- the check and the open were two separate
# operations on a path, not one on a handle. /Applications is
# admin-writable, so an attacker who can write there (without being root)
# could swap Firefox.app for a symlink in the window between the check and
# the reopen, and the root policy write would follow it into a directory
# tree the attacker controls.
#
# This case covers the reachable half only: PATCHED_BEC_FIREFOX_APP set to a
# symlink pointing at an attacker-controlled tree, present from before
# bec_enforce_extension_blocklist is even called -- no race required, and it
# works under the existing test override without needing real /Applications
# permissions. It does NOT reproduce the actual time-of-check-to-time-of-use
# race (real directory at check time, swapped to a symlink before the
# reopen): that is a genuine concurrency race and is not reproducible in a
# static shell test, so this suite does not claim to prove that half. The
# fix closes it structurally instead -- opening the bundle O_NOFOLLOW as the
# very first operation means there is no second, separate open left to race
# against.
#
# Note on what actually flips red-to-green here: the "no write happens"
# assertions below pass on the pre-fix code too, but only by accident -- its
# top-level ownership check does `os.lstat(firefox_app)` and then requires
# `S_ISDIR`, which a *static* symlink also fails (a symlink is never its own
# S_IFDIR), so a bundle path that is already a symlink before the call gets
# caught there regardless of the deeper bug. That incidental catch does
# nothing for the real race (a symlink swapped in *after* that check passes
# against a real directory), which is exactly the gap this fix closes. The
# assertion that actually distinguishes pre-fix from post-fix code is the
# log message: pre-fix, this case is misreported as the generic
# "is user-writable" ownership refusal (same message as case 9, wrong
# reason); post-fix, opening the bundle O_NOFOLLOW fails outright and is
# reported as an explicit symlink refusal. Proven against the actual
# pre-fix commit (ad3c60df) below; both PASS.
reset_env
rm -rf "$FFAPP"
ATTACKER_TREE="$WORK/attacker-firefox-tree"
mkdir -p "$ATTACKER_TREE/Contents/Resources"
ln -s "$ATTACKER_TREE" "$FFAPP"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"firefox","extension_id":"blocked@example.com"}]}}
JSON
rm -f "$POSTED_BODY"
OUT=$(bec_enforce_extension_blocklist 2>&1)
[[ ! -e "$ATTACKER_TREE/Contents/Resources/distribution" ]] \
    && ok "PAT-1043 follow-up: symlinked bundle path -> attacker tree receives no write" \
    || bad "PAT-1043 follow-up: attacker tree was written through the symlinked bundle path"
[[ "$(posted_event_count)" == "0" ]] \
    && ok "PAT-1043 follow-up: no audit event for a bundle-path symlink refusal" \
    || bad "PAT-1043 follow-up: audit event posted despite bundle-path symlink"
[[ -L "$FFAPP" ]] \
    && ok "PAT-1043 follow-up: planted bundle symlink left in place, untouched" \
    || bad "PAT-1043 follow-up: planted bundle symlink was consumed/removed unexpectedly"
print -r -- "$OUT" | grep -qi "REFUSING symlinked" \
    && ok "PAT-1043 follow-up: refusal names the symlink explicitly (fd-anchored check)" \
    || bad "PAT-1043 follow-up: expected an explicit symlink refusal, got: $OUT"

##############################################################################
echo "--- 12. PAT-1043: symlink pre-planted at the old predictable state-file temp path is not followed ---"
# Regression test for the other half of the PAT-1043 hardening: the sidecar
# state write got the same fd-anchored, unpredictable-temp-name treatment as
# the Firefox policy write (case 8 above), but no case here ever planted a
# symlink at *its* old predictable temp path and checked the write refuses
# it. That half was asserted only by inspection.
#
# The old code wrote through <state_file>.tmp (state_file + ".tmp") with a
# plain open() -- follows symlinks -- then os.replace(tmp, state_file). Same
# shape as the pre-fix Firefox write, just a different file. The fixed code
# never opens that predictable name at all: it creates its temp under an
# unpredictable O_EXCL'd name inside a dir fd opened O_NOFOLLOW, so a symlink
# sitting at the old "<state_file>.tmp" path is simply orphaned, not
# followed.
#
# Not exploitable in production today: this is a guard against the write
# *pattern* recurring, not a live hole. The real state directory
# (/Library/Application Support/Patched) is root-owned 755, not
# group-writable, so no other user can plant anything there to race against
# -- unlike /Applications (drwxrwxr-x root:admin), which is what made the
# Firefox write in case 8 actually reachable by a non-root admin user.
reset_env
VICTIM2="$WORK/victim-state-root-file"
echo "original-state-victim-content" > "$VICTIM2"
ln -s "$VICTIM2" "$STATE.tmp"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"}]}}
JSON
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist >/dev/null
[[ "$(cat "$VICTIM2")" == "original-state-victim-content" ]] \
    && ok "PAT-1043: state-tmp symlink target untouched by enforcement" \
    || bad "PAT-1043: state-tmp symlink target was modified -- root file overwrite vulnerability"
[[ "$(chrome_ids com.google.Chrome | tr -d '\n')" == "cccccccccccccccccccccccccccccccc" ]] \
    && ok "PAT-1043: chrome policy still enforced correctly despite planted state-tmp symlink" \
    || bad "PAT-1043: chrome policy not applied: got [$(chrome_ids com.google.Chrome)]"
[[ "$(json_get "$STATE" "['browsers']['chrome']" | tr -d ' ')" == *cccc* ]] \
    && ok "PAT-1043: sidecar state file itself still written correctly" \
    || bad "PAT-1043: sidecar state file missing expected content"
[[ -L "$STATE.tmp" ]] \
    && ok "PAT-1043: stale planted symlink at old state-tmp path left in place, untouched" \
    || bad "PAT-1043: planted state-tmp symlink was consumed/removed unexpectedly"

##############################################################################
echo "--- 13. PAT-1038 follow-up: actuation_allowed=0 reconciles to empty instead of skipping ---"
# The tier-downgrade leak this closes: a tenant previously at "block"/"enforce"
# had entries pushed; the caller's authority gate (patched-upload.sh's
# AC_BLOCKLIST_AUTHORITY_ALLOWED) then disallows actuation because the tenant
# dropped to "report". The function must still run and tear the previously-
# pushed policy down to nothing -- not be skipped, which would strand it as a
# permanent, silent enforcement leak.
reset_env
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"},
  {"browser":"edge","extension_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
  {"browser":"firefox","extension_id":"blocked@example.com"}
]}}
JSON
bec_enforce_extension_blocklist >/dev/null   # actuation allowed (default) — push it first
[[ "$(chrome_ids com.google.Chrome | tr -d '\n')" == "cccccccccccccccccccccccccccccccc" \
    && "$(chrome_ids com.microsoft.Edge | tr -d '\n')" == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
    && "$(ff_blocked | tr -d '\n')" == "blocked@example.com" ]] \
    && ok "setup: all three browsers blocked before the downgrade" \
    || bad "setup: pre-downgrade policy not fully applied"

# Same config still lists all three entries -- proves the empty result below
# comes from actuation_allowed, not from the config itself changing.
rm -f "$POSTED_BODY"
OUT=$(bec_enforce_extension_blocklist "0" 2>&1)
[[ -z "$(chrome_ids com.google.Chrome)" ]] \
    && ok "chrome blocklist torn down when actuation disallowed" \
    || bad "chrome blocklist survived downgrade: got [$(chrome_ids com.google.Chrome)]"
[[ -z "$(chrome_ids com.microsoft.Edge)" ]] \
    && ok "edge blocklist torn down when actuation disallowed" \
    || bad "edge blocklist survived downgrade: got [$(chrome_ids com.microsoft.Edge)]"
[[ -z "$(ff_blocked)" ]] \
    && ok "firefox blocklist torn down when actuation disallowed" \
    || bad "firefox blocklist survived downgrade: got [$(ff_blocked)]"
[[ "$(posted_event_count)" == "3" ]] \
    && ok "reconcile-to-empty posts one cleared-event per browser that had state" \
    || bad "expected 3 clear events, got $(posted_event_count)"
[[ "$OUT" == *"tier gate disallows actuation"* ]] \
    && ok "reconcile-to-empty logs why (tier gate disallows actuation)" \
    || bad "no log line explaining the forced-empty reconcile"

# A second disallowed run against the now-empty state must be a true no-op,
# not a repeated churn of clear events every cycle.
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist "0" >/dev/null
[[ "$(posted_event_count)" == "0" ]] \
    && ok "second disallowed run is idempotent (already empty)" \
    || bad "second disallowed run re-posted events: got $(posted_event_count)"

# Re-allowing actuation (tenant back at "block"/"enforce") must push again
# from the still-present config -- the downgrade did not corrupt anything.
rm -f "$POSTED_BODY"
bec_enforce_extension_blocklist "1" >/dev/null
[[ "$(chrome_ids com.google.Chrome | tr -d '\n')" == "cccccccccccccccccccccccccccccccc" ]] \
    && ok "re-allowing actuation re-pushes the blocklist from the unchanged config" \
    || bad "re-allowed run did not restore chrome blocklist: got [$(chrome_ids com.google.Chrome)]"

##############################################################################
echo "--- 14. ambiguous app_control config fails closed without policy churn ---"
# A malformed signed-cache representation must neither add a desired policy
# nor treat the unreadable config as an instruction to tear down already
# managed state. The existing policy and sidecar therefore remain exactly as
# they were, and no audit event is emitted.
reset_env
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_blocklist":[
  {"browser":"chrome","extension_id":"cccccccccccccccccccccccccccccccc"}]}}
JSON
bec_enforce_extension_blocklist >/dev/null
state_before=$(cat "$STATE")
rm -f "$POSTED_BODY"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"Enabled":false,"extension_blocklist":[
  {"browser":"chrome","extension_id":"dddddddddddddddddddddddddddddddd"}]}}
JSON
bec_enforce_extension_blocklist >/dev/null
[[ "$(chrome_ids com.google.Chrome | tr -d '\n')" == "cccccccccccccccccccccccccccccccc" ]] \
    && ok "ambiguous config does not apply a new blocklist" \
    || bad "ambiguous config changed chrome policy: got [$(chrome_ids com.google.Chrome)]"
[[ "$(cat "$STATE")" == "$state_before" && "$(posted_event_count)" == "0" ]] \
    && ok "ambiguous config leaves existing reconciliation state unchanged" \
    || bad "ambiguous config churned state or posted an audit event"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
