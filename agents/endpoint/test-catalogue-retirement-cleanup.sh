#!/bin/bash
# test-catalogue-retirement-cleanup.sh — PAT-2245: the signed app catalogue is
# retired, so every path that upgrades or removes the endpoint bundle on an
# already-enrolled Mac must stop and delete the com.patched.catalogue-poll
# LaunchDaemon, its script and verifier, and the cache it wrote.
#
# Three paths reach an enrolled Mac: install.sh (tarball upgrade), the .pkg
# postinstall (tools/pkg-scripts/postinstall) and uninstall.sh. PAT-1505 found
# that an uninstaller or upgrader that forgets one daemon leaves it running, so
# each path is exercised here against fixture directories:
#
#   [1] install.sh's PATCHED_LEGACY_PURGE block, extracted with the LEGACY_*
#       arrays that feed it (the same extraction test-install-legacy-purge.sh
#       uses), run twice to prove it is idempotent.
#   [2] the .pkg postinstall carries a byte-identical block and arrays.
#   [3] the purge never follows a symlink planted at a cache name, and skips
#       the cache entirely when the state directory itself is a symlink.
#   [4] uninstall.sh, as a scratch copy with fixture roots (the
#       test-uninstall-cleanup.sh method), including a daemon whose plist is
#       already gone but whose job may still be loaded.
#   [5] the agent-health emitter no longer reports sync_never_succeeded /
#       catalogue, which an older release may have left active in the store.
#
# launchctl is replaced by a recorder, so nothing touches the real launchd. No
# root, no real paths. PAT-2420: the scripts call /bin/launchctl and
# /usr/bin/id by absolute path, which a shell function cannot stand in for, so
# each extracted block or scratch copy has those paths rebased onto the
# recorder first; a copy that still names a real one is refused.
#
# Run: bash endpoint/test-catalogue-retirement-cleanup.sh

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_SH="$SCRIPT_DIR/install.sh"
POSTINSTALL="$REPO_ROOT/tools/pkg-scripts/postinstall"
UNINSTALL_SH="$SCRIPT_DIR/uninstall.sh"
AGENT_HEALTH_LIB="$REPO_ROOT/macos/lib/agent_health.sh"

pass=0; fail=0
chk() {
    if (( $2 )); then echo "  PASS: $1"; (( pass++ ))
    else echo "  FAIL: $1"; (( fail++ )); fi
}
absent()  { [[ ! -e "$1" && ! -L "$1" ]] && echo 1 || echo 0; }
present() { [[ -e "$1" || -L "$1" ]] && echo 1 || echo 0; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.catalogue-retirement-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

extract_arrays() {  # extract_arrays <file>
    local name
    for name in LEGACY_LAUNCHDAEMONS LEGACY_BUNDLE_FILES LEGACY_CATALOGUE_FILES LEGACY_CATALOGUE_DIRS; do
        awk -v name="$name" '
            $0 ~ "^" name "=\\(" { f=1 }
            f { print }
            f && /^\)/ { exit }
        ' "$1"
    done
}
extract_block() {  # extract_block <file>
    awk '/PATCHED_LEGACY_PURGE_START/{f=1;next} /PATCHED_LEGACY_PURGE_END/{f=0} f' "$1"
}

# The retired component names, stated here rather than read from the scripts,
# so dropping one from an array fails by name.
RETIRED_DAEMON=com.patched.catalogue-poll.plist
RETIRED_BUNDLE_FILES=(patched-fetch-catalogue.sh verify-catalogue.py com.patched.catalogue-poll.plist)
RETIRED_CACHE_FILES=(catalogue.json catalogue.etag catalogue.indeterminate-since)
RETIRED_CACHE_DIRS=(.patched-catalogue-fetch.lock)

# populate <root>: a Mac that last ran a release with the catalogue poller.
populate() {
    local root="$1" f
    mkdir -p "$root/bundle" "$root/launchdaemons" "$root/state"
    : > "$root/launchdaemons/$RETIRED_DAEMON"
    for f in "${RETIRED_BUNDLE_FILES[@]}"; do : > "$root/bundle/$f"; done
    for f in "${RETIRED_CACHE_FILES[@]}"; do echo stale > "$root/state/$f"; done
    for f in "${RETIRED_CACHE_DIRS[@]}"; do mkdir -p "$root/state/$f"; echo 123 > "$root/state/$f/pid"; done
    # Current components that must survive.
    : > "$root/bundle/patched-update.sh"
    : > "$root/launchdaemons/com.patched.update.plist"
    echo keep > "$root/state/posture.json"
    echo keep > "$root/state/agent-config.json"
}

# run_purge <label> <arrays-file> <block-file> <root>: sources the extracted
# block in a subshell with fixture roots and a recording launchctl.
run_purge() {
    local root="$4"
    # shellcheck disable=SC2034  # the fixture roots are read by the sourced purge block
    (
        BUNDLE_DEST="$root/bundle"
        LAUNCHDAEMONS_DIR="$root/launchdaemons"
        STATE_DIR="$root/state"
        LAUNCHCTL_LOG="$root/launchctl.log"
        launchctl() { echo "$*" >> "$LAUNCHCTL_LOG"; return 0; }
        # shellcheck disable=SC1090
        source "$2"
        sed 's#/bin/launchctl #launchctl #g' "$3" > "$root/purge.block"
        if grep -q '/bin/launchctl' "$root/purge.block"; then
            echo "FATAL: purge block still names the real launchctl"; exit 1
        fi
        # shellcheck disable=SC1090
        source "$root/purge.block"
    ) > "$root/purge.out" 2>&1
}

assert_purged() {  # assert_purged <label> <root>
    local label="$1" root="$2" f
    chk "$label: catalogue-poll booted out of launchd" \
        "$(grep -q "bootout system.*com\.patched\.catalogue-poll" "$root/launchctl.log" 2>/dev/null && echo 1 || echo 0)"
    chk "$label: $RETIRED_DAEMON removed from LaunchDaemons" "$(absent "$root/launchdaemons/$RETIRED_DAEMON")"
    for f in "${RETIRED_BUNDLE_FILES[@]}"; do
        chk "$label: bundle copy $f removed" "$(absent "$root/bundle/$f")"
    done
    for f in "${RETIRED_CACHE_FILES[@]}"; do
        chk "$label: cache $f removed" "$(absent "$root/state/$f")"
    done
    for f in "${RETIRED_CACHE_DIRS[@]}"; do
        chk "$label: lock directory $f removed" "$(absent "$root/state/$f")"
    done
    chk "$label: current patched-update.sh kept" "$(present "$root/bundle/patched-update.sh")"
    chk "$label: current com.patched.update.plist kept" "$(present "$root/launchdaemons/com.patched.update.plist")"
    chk "$label: posture.json kept" "$(present "$root/state/posture.json")"
    chk "$label: agent-config.json kept" "$(present "$root/state/agent-config.json")"
}

INSTALL_ARRAYS="$WORK/install.arrays"; INSTALL_BLOCK="$WORK/install.block"
PKG_ARRAYS="$WORK/pkg.arrays";         PKG_BLOCK="$WORK/pkg.block"
extract_arrays "$INSTALL_SH" > "$INSTALL_ARRAYS"; extract_block "$INSTALL_SH" > "$INSTALL_BLOCK"
extract_arrays "$POSTINSTALL" > "$PKG_ARRAYS" 2>/dev/null; extract_block "$POSTINSTALL" > "$PKG_BLOCK" 2>/dev/null

echo "--- [1] install.sh upgrade purge ---"
chk "install.sh purge block extracted" "$([[ -s "$INSTALL_BLOCK" ]] && echo 1 || echo 0)"
R="$WORK/install"; populate "$R"
run_purge install "$INSTALL_ARRAYS" "$INSTALL_BLOCK" "$R"; rc=$?
chk "install: purge exits 0" "$(( rc == 0 ))"
assert_purged install "$R"
: > "$R/launchctl.log"
run_purge install "$INSTALL_ARRAYS" "$INSTALL_BLOCK" "$R"; rc=$?
chk "install: second run with nothing left exits 0 (idempotent)" "$(( rc == 0 ))"
assert_purged "install (second run)" "$R"

echo "--- [2] .pkg postinstall upgrade purge ---"
chk "postinstall carries a purge block" "$([[ -s "$PKG_BLOCK" ]] && echo 1 || echo 0)"
chk "postinstall purge block is byte-identical to install.sh's" \
    "$(cmp -s "$INSTALL_BLOCK" "$PKG_BLOCK" && echo 1 || echo 0)"
chk "postinstall LEGACY_* arrays are byte-identical to install.sh's" \
    "$(cmp -s "$INSTALL_ARRAYS" "$PKG_ARRAYS" && echo 1 || echo 0)"
R="$WORK/pkg"; populate "$R"
run_purge pkg "$PKG_ARRAYS" "$PKG_BLOCK" "$R"; rc=$?
chk "pkg: purge exits 0" "$(( rc == 0 ))"
assert_purged pkg "$R"
chk "postinstall is valid bash" "$(bash -n "$POSTINSTALL" 2>/dev/null && echo 1 || echo 0)"

echo "--- [3] symlink safety ---"
R="$WORK/link"; mkdir -p "$R/bundle" "$R/launchdaemons" "$R/state" "$R/outside/lockdir"
echo precious > "$R/outside/target.json"
echo precious > "$R/outside/lockdir/pid"
ln -s "$R/outside/target.json" "$R/state/catalogue.json"
ln -s "$R/outside/lockdir" "$R/state/.patched-catalogue-fetch.lock"
run_purge link "$INSTALL_ARRAYS" "$INSTALL_BLOCK" "$R"
chk "link: symlink at catalogue.json removed, not followed" "$(absent "$R/state/catalogue.json")"
chk "link: symlink target file intact" "$([[ "$(cat "$R/outside/target.json" 2>/dev/null)" == precious ]] && echo 1 || echo 0)"
chk "link: symlink at the lock name removed, not followed" "$(absent "$R/state/.patched-catalogue-fetch.lock")"
chk "link: directory behind the lock symlink intact" "$([[ "$(cat "$R/outside/lockdir/pid" 2>/dev/null)" == precious ]] && echo 1 || echo 0)"

R="$WORK/linkedstate"; mkdir -p "$R/bundle" "$R/launchdaemons" "$R/realstate"
echo precious > "$R/realstate/catalogue.json"
ln -s "$R/realstate" "$R/state"
run_purge linkedstate "$INSTALL_ARRAYS" "$INSTALL_BLOCK" "$R"; rc=$?
chk "linked state dir: purge exits 0" "$(( rc == 0 ))"
chk "linked state dir: nothing deleted through it" "$(present "$R/realstate/catalogue.json")"

echo "--- [4] uninstall.sh ---"
R="$WORK/uninstall"; populate "$R"
mkdir -p "$R/state/triggers"
rm -f "$R/launchdaemons/com.patched.update.plist"   # plist already gone; job may still be loaded
COPY="$WORK/uninstall.sh"
sed \
  -e "s#^BUNDLE_DEST=\"/usr/local/patched-updater\"#BUNDLE_DEST=\"$R/bundle\"#" \
  -e "s#^LAUNCHDAEMONS_DIR=\"/Library/LaunchDaemons\"#LAUNCHDAEMONS_DIR=\"$R/launchdaemons\"#" \
  -e "s#^TRIGGERS_DIR=\"/Library/Application Support/Patched/triggers\"#TRIGGERS_DIR=\"$R/state/triggers\"#" \
  -e "s#^STATE_DIR=\"/Library/Application Support/Patched\"#STATE_DIR=\"$R/state\"#" \
  -e "s#/usr/bin/id -u#$R/stubbin/id -u#g" \
  -e "s#/bin/launchctl #$R/stubbin/launchctl #g" \
  "$UNINSTALL_SH" > "$COPY"
mkdir -p "$R/stubbin"
printf '#!/bin/sh\necho 0\n' > "$R/stubbin/id"
printf '#!/bin/sh\necho "$*" >> "%s"\nexit 0\n' "$R/launchctl.log" > "$R/stubbin/launchctl"
chmod +x "$R/stubbin/id" "$R/stubbin/launchctl"
chk "uninstall.sh fixture substitution applied" \
    "$(grep -q "^STATE_DIR=\"$R/state\"" "$COPY" && grep -q "^LAUNCHDAEMONS_DIR=\"$R/launchdaemons\"" "$COPY" && echo 1 || echo 0)"
if grep -Eq '(^|[^[:alnum:]_/.-])(/usr/bin/id|/bin/launchctl)([^[:alnum:]_/.-]|$)' "$COPY" \
    || grep -Eq '^(BUNDLE_DEST|LAUNCHDAEMONS_DIR|TRIGGERS_DIR|STATE_DIR)="/(usr|Library)/' "$COPY"; then
    echo "FATAL: scratch uninstall.sh still names a real privileged tool or system path" >&2
    exit 1
fi
bash "$COPY" > "$R/uninstall.out" 2>&1
chk "uninstall: catalogue-poll booted out of launchd" \
    "$(grep -q "bootout system.*com\.patched\.catalogue-poll" "$R/launchctl.log" 2>/dev/null && echo 1 || echo 0)"
chk "uninstall: $RETIRED_DAEMON removed" "$(absent "$R/launchdaemons/$RETIRED_DAEMON")"
chk "uninstall: a daemon whose plist is already gone is still booted out by label" \
    "$(grep -q "bootout system/com\.patched\.update$" "$R/launchctl.log" 2>/dev/null && echo 1 || echo 0)"
for f in "${RETIRED_CACHE_FILES[@]}"; do
    chk "uninstall: cache $f removed" "$(absent "$R/state/$f")"
done
for f in "${RETIRED_CACHE_DIRS[@]}"; do
    chk "uninstall: lock directory $f removed" "$(absent "$R/state/$f")"
done
chk "uninstall: bundle removed" "$(absent "$R/bundle")"

echo "--- [5] agent health ---"
STORE="$WORK/agent-health.json"
cat > "$STORE" <<'JSON'
{"active":{
 "sync_never_succeeded|catalogue":{"kind":"sync_never_succeeded","subject":"catalogue","reason":"fetch_failed","first_seen":"2026-08-27T00:00:00Z","last_seen":"2026-09-28T00:00:00Z","count":200},
 "sync_never_succeeded|posture":{"kind":"sync_never_succeeded","subject":"posture","reason":"fetch_failed","first_seen":"2026-09-28T00:00:00Z","last_seen":"2026-09-28T00:00:00Z","count":1}},
 "ever_succeeded":{"sync_never_succeeded|catalogue":true}}
JSON
BLOCK="$WORK/agent-health.block"
awk '/PATCHED_AGENT_HEALTH_START/{f=1;next} /PATCHED_AGENT_HEALTH_END/{f=0} f' "$AGENT_HEALTH_LIB" > "$BLOCK"
degraded=$(PYTHON3=/usr/bin/python3 PATCHED_AGENT_HEALTH_STORE="$STORE" zsh -c "source '$BLOCK'; patched_agent_health_emit_degraded_json")
chk "agent health: retired catalogue fault is not emitted" \
    "$([[ "$degraded" != *'"subject":"catalogue"'* ]] && echo 1 || echo 0)"
chk "agent health: other faults are still emitted" \
    "$([[ "$degraded" == *'"subject":"posture"'* ]] && echo 1 || echo 0)"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
