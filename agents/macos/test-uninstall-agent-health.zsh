#!/bin/zsh
##############################################################################
# test-uninstall-agent-health.zsh — regression test for macos/uninstall.sh's
# handling of the shared agent_health store (PAT-1065).
#
# uninstall.sh hardcodes real system paths with no env-var override —
# consistent with install.sh's own convention, since both are meant to run
# as root against the real machine. This test never touches those real
# paths: it copies uninstall.sh into a scratch tmpdir and substitutes the
# path constants (BIN_DIR, DAEMON_DIR, CREDS_DIR, QUEUE_BASE,
# AGENT_HEALTH_STATE_DIR) for scratch fixture roots, and prepends a stub
# bin/ directory to PATH providing id/launchctl so the root check passes
# and there are no real LaunchDaemons to bootout (`kill` is a bash BUILTIN,
# not resolved via PATH, so pid liveness here is controlled with real
# pids — a genuinely-alive one (this test process's own $$) or a
# genuinely-dead one (a forked-then-waited subshell) — rather than a stub).
#
# Coverage:
#   [1] .agent-health.json is removed unconditionally.
#   [2] a lock with no pid file (never really used) is removed.
#   [3] PAT-1065 review finding 3: a lock naming a REAL, currently-alive pid
#       is left in place, not force-removed.
#   [4] a lock naming a REAL, definitely-dead pid is removed (the ordinary
#       stale case still works, this isn't a regression from finding 3).
#
# Run: zsh macos/test-uninstall-agent-health.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# run_uninstall <fake-state-dir>
#   Builds a fresh scratch copy of uninstall.sh with every path constant
#   substituted to scratch fixtures, and a stub bin/ directory prepended to
#   PATH providing id/launchctl (both real external commands, unlike `kill`,
#   which is a shell builtin and cannot be faked this way) so the root check
#   passes and there are no real LaunchDaemons to bootout. Echoes combined
#   output.
run_uninstall() {
    local fake_state="$1"
    local scratch bin_dir daemon_dir creds_dir queue_base stub_bin copy out

    scratch=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-ah-test.XXXXXX")
    bin_dir="$scratch/bin"
    daemon_dir="$scratch/launchdaemons"
    creds_dir="$scratch/creds"
    queue_base="$scratch/queue"
    stub_bin="$scratch/stubbin"
    mkdir -p "$bin_dir" "$daemon_dir" "$creds_dir" "$queue_base" "$stub_bin"

    cat > "$stub_bin/id" <<'EOF'
#!/bin/sh
echo 0
EOF
    cat > "$stub_bin/launchctl" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod +x "$stub_bin/id" "$stub_bin/launchctl"

    copy="$scratch/uninstall.sh"
    sed \
      -e "s#^AGENT_DIR=\"/Library/Patched\"#AGENT_DIR=\"$bin_dir\"#" \
      -e "s#^LEGACY_BIN_DIR=\"/usr/local/bin\"#LEGACY_BIN_DIR=\"$scratch/legacy-bin\"#" \
      -e "s#^ANCESTRY_ANCHOR=\"/\"#ANCESTRY_ANCHOR=\"$scratch\"#" \
      -e "s#^\\# <<< PATCHED_ANCESTRY_HELPERS_END\$#&\\
patched_ancestry_probe() { if [ -L \"\$1\" ]; then echo '0 755 symlink'; elif [ -d \"\$1\" ]; then echo '0 755 dir'; elif [ -e \"\$1\" ]; then echo '0 644 other'; else echo '- - missing'; fi; }#" \
      -e "s#^DAEMON_DIR=\"/Library/LaunchDaemons\"#DAEMON_DIR=\"$daemon_dir\"#" \
      -e "s#^CREDS_DIR=\"/etc/patched\"#CREDS_DIR=\"$creds_dir\"#" \
      -e "s#^QUEUE_BASE=\"/var/db/patched\"#QUEUE_BASE=\"$queue_base\"#" \
      -e "s#^AGENT_HEALTH_STATE_DIR=\"/Library/Application Support/Patched\"#AGENT_HEALTH_STATE_DIR=\"$fake_state\"#" \
      -e "s#^export PATH=\"/usr/bin:/bin:/usr/sbin:/sbin\"\$#export PATH=\"$stub_bin:/usr/bin:/bin:/usr/sbin:/sbin\"#" \
      -e "s#/usr/bin/id -u#$stub_bin/id -u#g" \
      -e "s#/bin/launchctl #$stub_bin/launchctl #g" \
      "$SCRIPT_DIR/uninstall.sh" > "$copy"
    # PAT-2420: uninstall.sh verifies AGENT_DIR's ancestry before deleting it.
    # The scratch tree is owned by the invoking user, so the anchor is rebased
    # onto it and the ownership probe replaced with one reporting uid 0 for
    # what is really on disk (same technique as test-install-endpoint-bundling.zsh).
    # Refusal itself is covered by ci/test_privileged_installer_trust.py.
    # PAT-2398: uninstall.sh resets PATH and calls /usr/bin/id and
    # /bin/launchctl by absolute path, so the stubs are rebased into the copy
    # above rather than found on the caller's PATH. A sed that stopped matching
    # would run the real launchctl, so refuse such a copy.
    if grep -Eq '(^|[^[:alnum:]_/.-])(/usr/bin/id|/bin/launchctl)([^[:alnum:]_/.-]|$)' "$copy" \
        || ! grep -q "^export PATH=\"$stub_bin:" "$copy"; then
        echo "FATAL: scratch uninstall.sh still names a real privileged tool or PATH" >&2
        exit 1
    fi

    out=$(PATH="$stub_bin:$PATH" bash "$copy" 2>&1)
    echo "$out"
    rm -rf "$scratch"
}

# ============================================================================
echo "\n--- [1] .agent-health.json removed unconditionally ---"
FAKE_STATE_1=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-ah-state1.XXXXXX")
touch "$FAKE_STATE_1/.agent-health.json"

run_uninstall "$FAKE_STATE_1" > /dev/null 2>&1
chk ".agent-health.json removed" "$([[ ! -f "$FAKE_STATE_1/.agent-health.json" ]] && echo 1 || echo 0)"
rm -rf "$FAKE_STATE_1"

# ============================================================================
echo "\n--- [2] a lock with no pid file (never really used) is removed ---"
FAKE_STATE_2=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-ah-state2.XXXXXX")
mkdir -p "$FAKE_STATE_2/.agent-health.lock"

run_uninstall "$FAKE_STATE_2" > /dev/null 2>&1
chk "lock with no pid file is removed" "$([[ ! -d "$FAKE_STATE_2/.agent-health.lock" ]] && echo 1 || echo 0)"
rm -rf "$FAKE_STATE_2"

# ============================================================================
echo "\n--- [3] PAT-1065 review finding 3: a lock naming a REAL, currently-alive pid is left in place ---"
FAKE_STATE_3=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-ah-state3.XXXXXX")
mkdir -p "$FAKE_STATE_3/.agent-health.lock"
# This test process's own pid: guaranteed alive for the duration of this
# script. Written in the "pid|starttime" format the library itself writes —
# the uninstall check only reads the pid half.
echo "$$|whatever-start-time" > "$FAKE_STATE_3/.agent-health.lock/pid"

out3=$(run_uninstall "$FAKE_STATE_3")
echo "$out3" | sed 's/^/    /'

chk "lock naming a live pid is NOT removed" "$([[ -d "$FAKE_STATE_3/.agent-health.lock" ]] && echo 1 || echo 0)"
chk "log explains the lock was left in place" \
    "$([[ "$out3" == *"Left"*".agent-health.lock in place"* ]] && echo 1 || echo 0)"
rm -rf "$FAKE_STATE_3"

# ============================================================================
echo "\n--- [4] a lock naming a REAL, definitely-dead pid is still removed (no regression) ---"
FAKE_STATE_4=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-ah-state4.XXXXXX")
mkdir -p "$FAKE_STATE_4/.agent-health.lock"
# A pid guaranteed not to be running: fork a trivial subshell, note its pid,
# then wait for it to actually exit before using it (same technique as
# endpoint/test-agent-health.zsh's [6b]).
( : ) &
DEAD_PID=$!
wait "$DEAD_PID" 2>/dev/null
echo "$DEAD_PID|whatever-start-time" > "$FAKE_STATE_4/.agent-health.lock/pid"

run_uninstall "$FAKE_STATE_4" > /dev/null 2>&1
chk "lock naming a dead pid is removed" "$([[ ! -d "$FAKE_STATE_4/.agent-health.lock" ]] && echo 1 || echo 0)"
rm -rf "$FAKE_STATE_4"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
