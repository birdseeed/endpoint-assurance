#!/bin/bash
# test-uninstall-cleanup.sh — PAT-926 regression test for endpoint/uninstall.sh's
# state-file cleanup.
#
# uninstall.sh hardcodes real system paths (/usr/local/patched-updater,
# /Library/LaunchDaemons, /Library/Application Support/Patched) with no env-var
# override — consistent with install.sh's own convention, since both are meant
# to run as root against the real machine, not be parameterised for testing.
# This test never touches those real paths: it copies uninstall.sh into a
# scratch tmpdir, substitutes the 4 path constants for scratch fixture roots,
# and rebases /usr/bin/id and /bin/launchctl onto stub scripts so the root
# check passes and there are no real LaunchDaemons to bootout. PAT-2420:
# uninstall.sh resets PATH and calls both by absolute path, so the exported
# bash functions this test used before can no longer stand in for them. Run:
#   bash endpoint/test-uninstall-cleanup.sh

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

FAKE_BUNDLE="$SCRATCH/bundle"
FAKE_LAUNCHDAEMONS="$SCRATCH/launchdaemons"
FAKE_STATE="$SCRATCH/state"
FAKE_TRIGGERS="$FAKE_STATE/triggers"
mkdir -p "$FAKE_BUNDLE" "$FAKE_LAUNCHDAEMONS" "$FAKE_STATE" "$FAKE_TRIGGERS"

# Simulate every state artifact the 5 wired daemons write, per the PAT-926
# write-path audit of patched-update.sh, patched-fetch-config.sh,
# patched-install.sh, plus the cache the retired poller (PAT-2245) left.
touch "$FAKE_STATE/update-status.json" "$FAKE_STATE/agent-config.json" \
      "$FAKE_STATE/agent-config.version" "$FAKE_STATE/agent-config.sha256" \
      "$FAKE_STATE/agent-config.checked" \
      "$FAKE_STATE/agent-config.execution-denied" \
      "$FAKE_STATE/.agent-config.force-refetch" \
      "$FAKE_STATE/agent-config.json.quarantined" \
      "$FAKE_STATE/install-status.json" \
      "$FAKE_STATE/catalogue.json" "$FAKE_STATE/catalogue.etag" \
      "$FAKE_STATE/posture.json" "$FAKE_STATE/posture.version" \
      "$FAKE_STATE/blocking-deferrals-chrome.json" \
      "$FAKE_STATE/blocking-deferrals-zoom.json" \
      "$FAKE_STATE/uninstall-status.json"

# PAT-1065: the shared agent_health store — a file plus a mkdir-based lock
# directory, the latter needing its own rm -rf rather than the -f loop above.
touch "$FAKE_STATE/.agent-health.json"
mkdir -p "$FAKE_STATE/.agent-health.lock"

STUB_BIN="$SCRATCH/stubbin"
mkdir -p "$STUB_BIN"
printf '#!/bin/sh\necho 0\n' > "$STUB_BIN/id"
printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN/launchctl"
chmod +x "$STUB_BIN/id" "$STUB_BIN/launchctl"

# make_copy <dest> <bundle> <launchdaemons> <triggers> <state>
make_copy() {
    sed \
      -e "s#^BUNDLE_DEST=\"/usr/local/patched-updater\"#BUNDLE_DEST=\"$2\"#" \
      -e "s#^LAUNCHDAEMONS_DIR=\"/Library/LaunchDaemons\"#LAUNCHDAEMONS_DIR=\"$3\"#" \
      -e "s#^TRIGGERS_DIR=\"/Library/Application Support/Patched/triggers\"#TRIGGERS_DIR=\"$4\"#" \
      -e "s#^STATE_DIR=\"/Library/Application Support/Patched\"#STATE_DIR=\"$5\"#" \
      -e "s#/usr/bin/id -u#$STUB_BIN/id -u#g" \
      -e "s#/bin/launchctl #$STUB_BIN/launchctl #g" \
      "$SCRIPT_DIR/uninstall.sh" > "$1"
    # A sed that stopped matching would run the real launchctl, or delete under
    # a real path. Refuse such a copy.
    if grep -Eq '(^|[^[:alnum:]_/.-])(/usr/bin/id|/bin/launchctl)([^[:alnum:]_/.-]|$)' "$1" \
        || grep -Eq '^(BUNDLE_DEST|LAUNCHDAEMONS_DIR|TRIGGERS_DIR|STATE_DIR)="/(usr|Library)/' "$1"; then
        echo "FATAL: scratch uninstall.sh still names a real privileged tool or system path" >&2
        exit 1
    fi
}

COPY="$SCRATCH/uninstall.sh"
make_copy "$COPY" "$FAKE_BUNDLE" "$FAKE_LAUNCHDAEMONS" "$FAKE_TRIGGERS" "$FAKE_STATE"

pass=0; fail=0
chk() {
    if [[ -e "$2" ]]; then echo "  FAIL: $1 (still present: $2)"; (( fail++ ))
    else echo "  PASS: $1"; (( pass++ )); fi
}

echo "--- running scratch-copy uninstall.sh ---"
bash "$COPY" 2>&1 | sed 's/^/    /'
echo

chk "update-status.json removed"              "$FAKE_STATE/update-status.json"
chk "agent-config.json removed"               "$FAKE_STATE/agent-config.json"
chk "agent-config.version removed"            "$FAKE_STATE/agent-config.version"
chk "agent-config.sha256 removed"             "$FAKE_STATE/agent-config.sha256"
chk "agent-config.checked removed"            "$FAKE_STATE/agent-config.checked"
chk "agent-config.execution-denied removed"   "$FAKE_STATE/agent-config.execution-denied"
chk ".agent-config.force-refetch removed"     "$FAKE_STATE/.agent-config.force-refetch"
chk "agent-config.json.quarantined removed (PAT-1040)" "$FAKE_STATE/agent-config.json.quarantined"
chk "install-status.json removed"             "$FAKE_STATE/install-status.json"
chk "catalogue.json removed"                  "$FAKE_STATE/catalogue.json"
chk "catalogue.etag removed"                  "$FAKE_STATE/catalogue.etag"
chk "posture.json removed"                    "$FAKE_STATE/posture.json"
chk "posture.version removed"                 "$FAKE_STATE/posture.version"
chk "blocking-deferrals-chrome.json removed"  "$FAKE_STATE/blocking-deferrals-chrome.json"
chk "blocking-deferrals-zoom.json removed"    "$FAKE_STATE/blocking-deferrals-zoom.json"
chk ".agent-health.json removed (PAT-1065)"   "$FAKE_STATE/.agent-health.json"
chk ".agent-health.lock removed (PAT-1065)"   "$FAKE_STATE/.agent-health.lock"

if [[ -e "$FAKE_STATE/uninstall-status.json" ]]; then
    echo "  PASS: uninstall-status.json deliberately preserved"; (( pass++ ))
else
    echo "  FAIL: uninstall-status.json was removed but should be preserved"; (( fail++ ))
fi

# ============================================================================
# PAT-1065 review finding 3: a lock naming a pid that is currently alive
# must be LEFT IN PLACE, not force-removed — an uninstall running at the
# exact moment the OTHER daemon family is genuinely mid-write must not yank
# the lock out from under it. Fresh scratch fixture set so this scenario
# doesn't interact with the first run above.
# ============================================================================
echo
echo "--- second run: a lock naming a currently-alive pid ---"
SCRATCH2=$(mktemp -d)
FAKE_STATE2="$SCRATCH2/state"
mkdir -p "$FAKE_STATE2/.agent-health.lock" "$SCRATCH2/bundle" "$SCRATCH2/launchdaemons" "$FAKE_STATE2/triggers"

# This test process's own pid is guaranteed alive for the duration of this
# script. Written in the "pid|starttime" format the library itself uses —
# the uninstall check only reads the pid half, but exercising the real
# on-disk shape is more honest than a bare pid.
echo "$$|whatever-start-time" > "$FAKE_STATE2/.agent-health.lock/pid"

COPY2="$SCRATCH2/uninstall.sh"
make_copy "$COPY2" "$SCRATCH2/bundle" "$SCRATCH2/launchdaemons" "$FAKE_STATE2/triggers" "$FAKE_STATE2"

out2=$(bash "$COPY2" 2>&1)
echo "$out2" | sed 's/^/    /'
echo

if [[ -d "$FAKE_STATE2/.agent-health.lock" ]]; then
    echo "  PASS: a lock naming a live pid is left in place, not force-removed"; (( pass++ ))
else
    echo "  FAIL: a lock naming a live pid was force-removed"; (( fail++ ))
fi

if [[ "$out2" == *"Left"*".agent-health.lock in place"* ]]; then
    echo "  PASS: log explains why the lock was left in place"; (( pass++ ))
else
    echo "  FAIL: log did not explain the left-in-place lock"; (( fail++ ))
fi

rm -rf "$SCRATCH2"

echo
echo "RESULT: pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
