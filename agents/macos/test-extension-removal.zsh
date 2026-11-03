#!/bin/zsh
##############################################################################
# test-extension-removal.zsh — tests for the PAT-829 profile-aware, audited
# browser-extension removal primitive in lib/browser_extension_removal.sh.
#
# Sources the live removal function and drives it against a temp /Users tree
# (multi-user, multi-profile fixtures) so no root or real browser is needed.
# /usr/bin/python3 is stock on macOS runners.
#
# Run: zsh macos/test-extension-removal.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
LIB="$SCRIPT_DIR/lib/browser_extension_removal.sh"
export PYTHON3="/usr/bin/python3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ber-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- Harness the ambient state the lib expects from patched-upload.sh --------
export PATCHED_TMPDIR="$WORK/tmp"; mkdir -p "$PATCHED_TMPDIR"
# PAT-1037: durable state dir the lib now requires (holds the audit-post lock
# dir + the pending-audit-events file), matching how patched-upload.sh sets a
# real one ($STATE_DIR="/var/db/patched") before sourcing this module.
export STATE_DIR="$WORK/state"; mkdir -p "$STATE_DIR"
export API_URL="https://api.invalid.test"
export BEARER_TOKEN="test-bearer"
export HW_UUID="TEST-DEVICE-UUID"

# Stubs: the lib expects compute_hmac (defined in the caller) + curl for the
# audit POST. Capture the posted body so we can assert on the audit payload.
# PAT-1037: also honor `-o <file>` with a `{"ingested": n}` body reflecting
# how many events were actually in this POST's request body — the lib now
# requires that confirmation (not just a 2xx status) before it clears its
# durable pending file, so a stub that never wrote one would leave every
# posted batch stuck as "pending" and break the idempotency assertions below.
POSTED_BODY="$WORK/posted-body.json"
compute_hmac() { echo "stub-sig"; }
curl() {
    local a prev="" out_file="" data_file=""
    for a in "$@"; do
        case "$prev" in
            --data-binary) data_file="${a#@}" ;;
            -o) out_file="$a" ;;
        esac
        prev="$a"
    done
    if [[ -n "$data_file" ]]; then
        cp "$data_file" "$POSTED_BODY" 2>/dev/null
    fi
    if [[ -n "$out_file" ]]; then
        local n
        n=$("$PYTHON3" -c "import json,sys
try:
    print(len(json.load(open(sys.argv[1]))['events']))
except Exception:
    print(0)" "$POSTED_BODY" 2>/dev/null) || n=0
        printf '{"ingested":%s}' "$n" > "$out_file"
    fi
    echo "200"
}
# PAT-881: the lib now sends the audit POST via patched_curl_bearer (bearer
# token off argv, over stdin). In production patched-upload.sh defines it inline;
# here it just drops the token arg and delegates to the curl stub above, which
# still captures the posted body from --data-binary.
patched_curl_bearer() { shift; curl "$@"; }

source "$LIB"

USERS="$WORK/Users"
CFG="$WORK/agent-config.json"
export PATCHED_BER_USERS_DIR="$USERS"
export PATCHED_AC_CONFIG="$CFG"

pass=0; fail=0
ok()  { (( pass++ )); echo "  PASS: $1"; }
bad() { (( fail++ )); echo "  FAIL: $1"; }

reset_users() {
    rm -rf "$USERS" "$POSTED_BODY"
    mkdir -p "$USERS"
    # PAT-1037: each case below expects fully independent audit state too —
    # clear any leftover durable pending file / lock dir from a previous case
    # (normally already cleared by a successful confirmed POST, but explicit
    # here so case order can never leak state).
    rm -f "$STATE_DIR/.enforcement-audit-pending.json"
    rm -rf "$STATE_DIR/.enforcement-audit-post.lock"
}

# --- Fixture builders (macOS on-disk layout the lib walks) -------------------
chromium_base() { # <user> <browser>  -> Application Support browser dir
    local vendor; [[ "$2" == "edge" ]] && vendor="Microsoft Edge" || vendor="Google/Chrome"
    echo "$USERS/$1/Library/Application Support/$vendor"
}
seed_chromium() { # <user> <browser> <profile> <id>
    local base pdir vdir; base=$(chromium_base "$1" "$2"); pdir="$base/$3"
    vdir="$pdir/Extensions/$4/1.0"; mkdir -p "$vdir"
    echo '{"name":"X","version":"1.0"}' > "$vdir/manifest.json"
    printf '{"extensions":{"settings":{"%s":{"state":1},"keep-me":{"state":1}}}}' "$4" \
        > "$pdir/Secure Preferences"
}
chromium_dir_exists() { # <user> <browser> <profile> <id>
    [[ -d "$(chromium_base "$1" "$2")/$3/Extensions/$4" ]]
}
chromium_setting_has() { # <user> <browser> <profile> <id>
    "$PYTHON3" -c "import json,sys
try:
    d=json.load(open(sys.argv[1]))
    sys.exit(0 if sys.argv[2] in d.get('extensions',{}).get('settings',{}) else 1)
except Exception: sys.exit(1)" "$(chromium_base "$1" "$2")/$3/Secure Preferences" "$4"
}

ff_profile() { echo "$USERS/$1/Library/Application Support/Firefox/Profiles/$2"; }
seed_firefox() { # <user> <profile> <id>
    local pdir; pdir=$(ff_profile "$1" "$2"); mkdir -p "$pdir/extensions"
    printf '{"addons":[{"id":"%s","type":"extension"},{"id":"keep@x","type":"extension"}]}' "$3" \
        > "$pdir/extensions.json"
    echo "PK-fake-xpi" > "$pdir/extensions/$3.xpi"
}
ff_addon_present() { # <user> <profile> <id>
    "$PYTHON3" -c "import json,sys
try:
    d=json.load(open(sys.argv[1]))
    ids=[a.get('id') for a in d.get('addons',[])]
    sys.exit(0 if sys.argv[2] in ids else 1)
except Exception: sys.exit(1)" "$(ff_profile "$1" "$2")/extensions.json" "$3"
}
ff_xpi_exists() { [[ -f "$(ff_profile "$1" "$2")/extensions/$3.xpi" ]]; }

posted_event_count() {
    [[ -f "$POSTED_BODY" ]] || { echo 0; return; }
    "$PYTHON3" -c "import json,sys; print(len(json.load(open(sys.argv[1]))['events']))" "$POSTED_BODY" 2>/dev/null || echo 0
}
posted_detail() { # <index> <key>
    "$PYTHON3" -c "import json,sys; print(json.load(open(sys.argv[1]))['events'][int(sys.argv[2])]['details'][sys.argv[3]])" \
        "$POSTED_BODY" "$1" "$2" 2>/dev/null
}

##############################################################################
echo "--- 1. chromium: dir + settings removed, others kept, one audit ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_profiles"}]}}
JSON
ber_remove_extensions >/dev/null
! chromium_dir_exists alice chrome Default badext && ok "extension dir deleted" || bad "extension dir still present"
! chromium_setting_has alice chrome Default badext && ok "settings entry pruned" || bad "settings entry remains"
chromium_setting_has alice chrome Default keep-me && ok "unrelated settings kept" || bad "unrelated settings lost"
[[ "$(posted_event_count)" == "1" ]] && ok "1 audit event" || bad "events: $(posted_event_count)"
[[ "$(posted_detail 0 device_id)" == "TEST-DEVICE-UUID" && "$(posted_detail 0 scope)" == "all_profiles" ]] \
    && ok "audit details carry device_id + scope" || bad "audit details wrong"

##############################################################################
echo "--- 2. firefox: addon entry + xpi removed, others kept ---"
reset_users
seed_firefox alice abc.default 'blk@x'
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"firefox","extension_id":"blk@x","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
! ff_addon_present alice abc.default 'blk@x' && ok "firefox addon entry removed" || bad "addon entry remains"
! ff_xpi_exists alice abc.default 'blk@x' && ok "firefox xpi deleted" || bad "xpi remains"
ff_addon_present alice abc.default 'keep@x' && ok "other addon kept" || bad "other addon lost"
[[ "$(posted_detail 0 scope)" == "all_devices" ]] && ok "scope audited as all_devices" || bad "scope wrong"

##############################################################################
echo "--- 3. scope one_profile: only the named profile ---"
reset_users
seed_chromium alice chrome Default badext
seed_chromium alice chrome "Profile 1" badext
seed_chromium bob   chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_profile",
   "user_account":"alice","profile":"Default"}]}}
JSON
ber_remove_extensions >/dev/null
! chromium_dir_exists alice chrome Default badext   && ok "alice/Default removed" || bad "alice/Default remains"
chromium_dir_exists alice chrome "Profile 1" badext && ok "alice/Profile 1 kept" || bad "alice/Profile 1 removed"
chromium_dir_exists bob chrome Default badext       && ok "bob/Default kept" || bad "bob/Default removed"
[[ "$(posted_event_count)" == "1" ]] && ok "single audit for one_profile" || bad "events: $(posted_event_count)"

##############################################################################
echo "--- 4. scope one_user: all of that user's profiles, not others ---"
reset_users
seed_chromium alice chrome Default badext
seed_chromium alice chrome "Profile 1" badext
seed_chromium bob   chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_user","user_account":"alice"}]}}
JSON
ber_remove_extensions >/dev/null
! chromium_dir_exists alice chrome Default badext     && ok "alice/Default removed" || bad "alice/Default remains"
! chromium_dir_exists alice chrome "Profile 1" badext && ok "alice/Profile 1 removed" || bad "alice/Profile 1 remains"
chromium_dir_exists bob chrome Default badext         && ok "bob untouched" || bad "bob removed"
[[ "$(posted_event_count)" == "2" ]] && ok "2 audits (both alice profiles)" || bad "events: $(posted_event_count)"

##############################################################################
echo "--- 5. scope all_profiles: every user + profile ---"
reset_users
seed_chromium alice chrome Default badext
seed_chromium bob   chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_profiles"}]}}
JSON
ber_remove_extensions >/dev/null
! chromium_dir_exists alice chrome Default badext && ! chromium_dir_exists bob chrome Default badext \
    && ok "removed across both users" || bad "not removed across users"
[[ "$(posted_event_count)" == "2" ]] && ok "2 audits (alice + bob)" || bad "events: $(posted_event_count)"

##############################################################################
echo "--- 6. dry-run deletes nothing but reports events ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
OUT=$(PATCHED_DRY_RUN=1 ber_remove_extensions)
chromium_dir_exists alice chrome Default badext && ok "dry-run kept extension on disk" || bad "dry-run deleted"
[[ "$(posted_event_count)" == "0" ]] && ok "dry-run posted nothing" || bad "dry-run posted"
[[ "$OUT" == *"DRY_RUN"* && "$OUT" == *"would remove 1"* ]] && ok "dry-run reports would-remove count" || bad "dry-run log wrong: $OUT"

##############################################################################
echo "--- 7. idempotent: second run removes nothing ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
[[ "$(posted_event_count)" == "1" ]] && ok "first run audits once" || bad "first run events: $(posted_event_count)"
rm -f "$POSTED_BODY"
ber_remove_extensions >/dev/null
[[ "$(posted_event_count)" == "0" ]] && ok "second run posts nothing (already gone)" || bad "second run events: $(posted_event_count)"

##############################################################################
echo "--- 8. fail-safe: disabled / empty / bad scope / missing context ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":false,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
chromium_dir_exists alice chrome Default badext && ok "disabled app_control removes nothing" || bad "disabled removed"

cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_user"},
  {"browser":"chrome","extension_id":"badext","scope":"nonsense"},
  {"browser":"brave","extension_id":"badext","scope":"all_devices"}]}}
JSON
rm -f "$POSTED_BODY"
ber_remove_extensions >/dev/null
chromium_dir_exists alice chrome Default badext && [[ "$(posted_event_count)" == "0" ]] \
    && ok "missing-context / bad-scope / unsupported-browser all skipped" || bad "unsafe directive acted"

##############################################################################
# --- PAT-856: malformed extension_id/profile/user_account must be rejected
# before any path is built from them — never "best-effort" deleted. Each
# case below seeds a legitimate, unrelated extension alongside the malicious
# directive to prove this is a per-entry fail-closed reject, not deletion of
# the wrong thing, and that the rejection is actually logged. ---

echo "--- 9. malformed extension_id (path traversal) is rejected, nothing deleted, rejection logged ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"../../../../tmp/pwned","scope":"all_devices"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1 >/dev/null)
chromium_dir_exists alice chrome Default badext && ok "unrelated extension untouched" || bad "unrelated extension removed"
[[ "$(posted_event_count)" == "0" ]] && ok "no audit event for rejected extension_id" || bad "events: $(posted_event_count)"
[[ "$OUT" == *"REJECT"*"extension_id"* ]] && ok "rejection logged" || bad "no rejection logged: $OUT"

echo "--- 10. malformed profile (path traversal) is rejected, nothing deleted, rejection logged ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_profile",
   "user_account":"alice","profile":"../../.."}]}}
JSON
OUT=$(ber_remove_extensions 2>&1 >/dev/null)
chromium_dir_exists alice chrome Default badext && ok "unrelated extension untouched" || bad "unrelated extension removed"
[[ "$(posted_event_count)" == "0" ]] && ok "no audit event for rejected profile" || bad "events: $(posted_event_count)"
[[ "$OUT" == *"REJECT"*"profile"* ]] && ok "rejection logged" || bad "no rejection logged: $OUT"

echo "--- 11. malformed user_account (path traversal) is rejected, nothing deleted, rejection logged ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_user","user_account":"../root"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1 >/dev/null)
chromium_dir_exists alice chrome Default badext && ok "unrelated extension untouched" || bad "unrelated extension removed"
[[ "$(posted_event_count)" == "0" ]] && ok "no audit event for rejected user_account" || bad "events: $(posted_event_count)"
[[ "$OUT" == *"REJECT"*"user_account"* ]] && ok "rejection logged" || bad "no rejection logged: $OUT"

echo "--- 12. existing benign cases (badext, blk@x) still behave as before (regression guard) ---"
reset_users
seed_chromium alice chrome Default badext
seed_firefox alice abc.default 'blk@x'
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"},
  {"browser":"firefox","extension_id":"blk@x","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
! chromium_dir_exists alice chrome Default badext && ok "badext (chrome) still removed" || bad "badext not removed"
! ff_xpi_exists alice abc.default 'blk@x' && ok "blk@x (firefox) still removed" || bad "blk@x not removed"
[[ "$(posted_event_count)" == "2" ]] && ok "both benign directives still audited" || bad "events: $(posted_event_count)"

echo "--- 13. containment check: a profile dir that is a symlink outside the browser base is refused ---"
reset_users
seed_chromium alice chrome Default badext   # unrelated, in-scope-looking sibling
OUTSIDE="$WORK/OutsideChrome"
mkdir -p "$OUTSIDE/Extensions/badext/1.0"
echo '{"name":"Evil","version":"1.0"}' > "$OUTSIDE/Extensions/badext/1.0/manifest.json"
BASE=$(chromium_base alice chrome)
ln -s "$OUTSIDE" "$BASE/EvilProfile"   # "EvilProfile" passes the charset check; the symlink is the attack
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_profile",
   "user_account":"alice","profile":"EvilProfile"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1 >/dev/null)
[[ -d "$OUTSIDE/Extensions/badext" ]] && ok "symlink target outside base untouched" || bad "symlink target deleted"
chromium_dir_exists alice chrome Default badext && ok "unrelated Default profile untouched" || bad "unrelated Default profile removed"
[[ "$(posted_event_count)" == "0" ]] && ok "no audit event through the symlink" || bad "events: $(posted_event_count)"
[[ "$OUT" == *"REFUSING symlinked Chromium profile"* ]] && ok "symlinked profile refusal logged" || bad "no containment refusal logged: $OUT"

##############################################################################
# --- PAT-856 (review finding): the extension ROOT itself as a symlink.
# The first cut of this fix compared a resolved ext_dir against a resolved
# extensions_root — tautological the moment `Extensions`/`extensions` IS the
# symlink, since both sides then resolve under the symlink target and the
# root-running remover happily deletes outside the profile. Containment is
# now anchored to the trusted profile_dir, and a symlinked extension root is
# refused outright. These two cases lock that in. ---

echo "--- 14. chromium: a symlinked Extensions ROOT is refused, external target survives ---"
reset_users
seed_chromium alice chrome Default badext          # makes a real Default profile
BASE=$(chromium_base alice chrome)
PDIR="$BASE/Default"
EXTERNAL="$WORK/ExternalChromeExts"
mkdir -p "$EXTERNAL/badext/1.0"
echo '{"name":"Victim","version":"1.0"}' > "$EXTERNAL/badext/1.0/manifest.json"
rm -rf "$PDIR/Extensions"                          # replace the real root...
ln -s "$EXTERNAL" "$PDIR/Extensions"               # ...with a symlink pointing outside the profile
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1 >/dev/null)
[[ -d "$EXTERNAL/badext" ]] && ok "external dir behind symlinked Extensions root survives" || bad "external dir DELETED via symlinked Extensions root"
[[ "$OUT" == *"REFUSING symlinked Extensions root"* ]] && ok "symlinked Extensions root refusal logged" || bad "no refusal logged: $OUT"

echo "--- 15. firefox: a symlinked extensions ROOT is refused, external xpi survives ---"
reset_users
seed_firefox alice abc.default 'blk@x'             # makes a real profile
FPDIR=$(ff_profile alice abc.default)
EXTERNAL_FF="$WORK/ExternalFFExts"
mkdir -p "$EXTERNAL_FF"
echo "PK-victim-xpi" > "$EXTERNAL_FF/blk@x.xpi"
rm -rf "$FPDIR/extensions"                         # replace the real root...
ln -s "$EXTERNAL_FF" "$FPDIR/extensions"           # ...with a symlink pointing outside the profile
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"firefox","extension_id":"blk@x","scope":"all_devices"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1 >/dev/null)
[[ -f "$EXTERNAL_FF/blk@x.xpi" ]] && ok "external xpi behind symlinked extensions root survives" || bad "external xpi DELETED via symlinked extensions root"
[[ "$OUT" == *"REFUSING symlinked extensions root"* ]] && ok "symlinked extensions root refusal logged" || bad "no refusal logged: $OUT"

echo "--- 16. chromium: Extensions/<id> that IS a symlink to an external dir deletes nothing external ---"
reset_users
seed_chromium alice chrome Default keepother      # a real, unrelated ext so profile/Extensions exist
BASE=$(chromium_base alice chrome)
EXTDIR="$BASE/Default/Extensions"
EXTERNAL="$WORK/ExternalLeaf"
mkdir -p "$EXTERNAL/payload"
echo victim > "$EXTERNAL/payload/f"
ln -s "$EXTERNAL" "$EXTDIR/badext"                # the id entry itself is a symlink out
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
[[ -d "$EXTERNAL/payload" && -f "$EXTERNAL/payload/f" ]] && ok "external dir behind symlinked leaf survives" || bad "external dir DELETED via symlinked leaf"
[[ "$(posted_event_count)" == "0" ]] && ok "symlinked leaf produces no audit event" || bad "events: $(posted_event_count)"

echo "--- 17. chromium: a symlink NESTED inside the extension dir is not followed during recursive delete ---"
reset_users
seed_chromium alice chrome Default badext         # real Extensions/badext/1.0/...
BASE=$(chromium_base alice chrome)
EXTERNAL="$WORK/ExternalNested"
mkdir -p "$EXTERNAL"
echo victim > "$EXTERNAL/keep"
ln -s "$EXTERNAL" "$(chromium_base alice chrome)/Default/Extensions/badext/evil-link"  # symlink inside the tree
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
! chromium_dir_exists alice chrome Default badext && ok "extension dir itself removed" || bad "extension dir not removed"
[[ -d "$EXTERNAL" && -f "$EXTERNAL/keep" ]] && ok "external dir behind nested symlink survives (link unlinked, target untouched)" || bad "external dir DELETED through nested symlink"

echo "--- 18. prefs rewrite: a pre-created hardlink at the old temp name is not truncated by root ---"
reset_users
seed_chromium alice chrome Default badext          # Secure Preferences has badext + keep-me
PDIR="$(chromium_base alice chrome)/Default"
echo "VICTIM-SECRET-CONTENTS" > "$WORK/victim.txt"
# Attacker pre-creates the previously-deterministic temp name as a HARDLINK to
# an external file. O_NOFOLLOW does not defend against hardlinks; only an
# unpredictable name + O_EXCL does. Same filesystem ($WORK), so ln works.
ln "$WORK/victim.txt" "$PDIR/Secure Preferences.patched.tmp"
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
[[ "$(cat "$WORK/victim.txt")" == "VICTIM-SECRET-CONTENTS" ]] && ok "hardlinked victim not truncated/overwritten" || bad "victim file was clobbered via temp hardlink"
! chromium_setting_has alice chrome Default badext && ok "prefs prune still succeeded" || bad "prefs entry not pruned"
chromium_setting_has alice chrome Default keep-me && ok "unrelated prefs entry kept" || bad "unrelated prefs entry lost"

echo "--- 19. chromium: non-observation scope (elif branch) removes cleanly — PAT-1316 non-author-review P1 ---"
# Non-author review raised a P1 against handle_chromium: "observation_matches
# not set in elif branch ... leading to UnboundLocalError". Investigated and
# judged a FALSE POSITIVE: `observation_matches = d["scope"] != "one_observation"`
# is assigned unconditionally as the very first statement of every per-profile
# loop iteration (before the ext_root_fd/if-elif block), so by the time it is
# read at the `if observation_matches:` prefs-prune gate it already has a
# definite value on every path — the elif branch (this scope's real removal
# path) does not need to touch it because that default already computed the
# correct answer (True) for any non-one_observation scope, one_user included.
# This test pins that: exercising the elif branch end-to-end (dir removed,
# settings pruned, one audit event posted, no crash) for a scope
# ("one_user") this suite hadn't put through this exact assertion shape
# before. If the definite-assignment at the top of handle_chromium's loop
# body ever regresses (e.g. moved inside a conditional), this reproduces a
# real UnboundLocalError: ber_remove_extensions's `|| _events_json="[]"`
# fallback would swallow it, this test's event-count/removal assertions
# would fail, and dir removal (which happens before the crash) would
# outrun the audit — the exact "partially-applied removal on a
# recursive-deletion path" failure shape the review flagged.
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"one_user","user_account":"alice"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1)
[[ -z "$(print -r -- "$OUT" | grep -i 'traceback\|UnboundLocalError')" ]] && ok "no traceback / UnboundLocalError" || bad "python raised: $OUT"
! chromium_dir_exists alice chrome Default badext && ok "extension dir deleted (elif branch ran)" || bad "extension dir still present"
! chromium_setting_has alice chrome Default badext && ok "settings entry pruned (observation_matches was True)" || bad "settings entry remains — observation_matches read wrong"
[[ "$(posted_event_count)" == "1" ]] && ok "1 audit event, no partial/duplicate state" || bad "events: $(posted_event_count)"

echo "--- 20. firefox: non-observation scope (elif branch) removes cleanly — PAT-1316 non-author-review P1 ---"
# Same finding, same reasoning, mirrored for handle_firefox's xpi elif branch
# (safe_unlink_file_at) — see test 19's comment for the full analysis.
reset_users
seed_firefox alice abc.default 'ext@x'
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"extension_removals":[
  {"browser":"firefox","extension_id":"ext@x","scope":"one_user","user_account":"alice"}]}}
JSON
OUT=$(ber_remove_extensions 2>&1)
[[ -z "$(print -r -- "$OUT" | grep -i 'traceback\|UnboundLocalError')" ]] && ok "no traceback / UnboundLocalError" || bad "python raised: $OUT"
! ff_xpi_exists alice abc.default 'ext@x' && ok "xpi deleted (elif branch ran)" || bad "xpi still present"
! ff_addon_present alice abc.default 'ext@x' && ok "addon entry pruned (observation_matches was True)" || bad "addon entry remains — observation_matches read wrong"
[[ "$(posted_event_count)" == "1" ]] && ok "1 audit event, no partial/duplicate state" || bad "events: $(posted_event_count)"

##############################################################################
echo "--- 21. ambiguous app_control config fails closed before removal ---"
reset_users
seed_chromium alice chrome Default badext
cat > "$CFG" <<'JSON'
{"app_control":{"enabled":true,"Enabled":false,"extension_removals":[
  {"browser":"chrome","extension_id":"badext","scope":"all_devices"}]}}
JSON
ber_remove_extensions >/dev/null
chromium_dir_exists alice chrome Default badext \
    && ok "ambiguous config does not delete extension files" \
    || bad "ambiguous config removed extension files"
chromium_setting_has alice chrome Default badext \
    && ok "ambiguous config does not prune extension settings" \
    || bad "ambiguous config pruned extension settings"
[[ "$(posted_event_count)" == "0" ]] \
    && ok "ambiguous config emits no removal audit" \
    || bad "ambiguous config emitted removal audit events"

##############################################################################
echo ""
echo "--- PAT-1316: agent's known-scope set is a superset of the cross-repo contract ---"
# contracts/extension-removal-scopes.json is vendored verbatim in BOTH
# updater and patched.im (see that file's own note) — nothing in either repo's
# CI can see the other, so this only catches an agent build whose KNOWN_SCOPES
# regresses out from under a scope the contract says the server may emit; it
# does NOT catch the patched.im copy being edited alone (that half is this
# ticket's other repo). Deliberately a SUPERSET check, not equality: the
# server currently emits only one_observation (broader operator scopes are
# compiled down to it server-side — see go-service's
# dbGetExtensionRemovalsForDevice), while this agent still accepts the four
# legacy values too, for directives issued by an older server build or still
# in flight from before that compilation existed. The agent is allowed to
# know more than the contract requires; it must never know less.
CONTRACT_FILE="$SCRIPT_DIR/../contracts/extension-removal-scopes.json"
CONTRACT_CHECK=$("$PYTHON3" - "$LIB" "$CONTRACT_FILE" <<'PYEOF'
import json, re, sys

lib_path, contract_path = sys.argv[1], sys.argv[2]

with open(lib_path, "r", encoding="utf-8") as f:
    src = f.read()
m = re.search(r'KNOWN_SCOPES\s*=\s*\{([^}]*)\}', src)
if not m:
    print("ERROR:KNOWN_SCOPES not found in " + lib_path)
    sys.exit(0)
known = set(re.findall(r'"([^"]+)"', m.group(1)))

with open(contract_path, "r", encoding="utf-8") as f:
    contract = json.load(f)
missing = sorted(set(contract["scopes"]) - known)
print("MISSING:" + ",".join(missing) if missing else "OK")
PYEOF
)
case "$CONTRACT_CHECK" in
    OK)
        ok "KNOWN_SCOPES is a superset of contracts/extension-removal-scopes.json" ;;
    ERROR:*)
        bad "contract check itself is broken: ${CONTRACT_CHECK#ERROR:}" ;;
    MISSING:*)
        bad "KNOWN_SCOPES is missing contract scope(s): ${CONTRACT_CHECK#MISSING:}" ;;
    *)
        bad "unexpected contract-check output: $CONTRACT_CHECK" ;;
esac

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
