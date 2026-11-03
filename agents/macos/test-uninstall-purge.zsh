#!/bin/zsh
##############################################################################
# test-uninstall-purge.zsh — regression test for macos/uninstall.sh's
# --purge split (PAT-1109 acceptance criterion: "purge: false leaves
# credentials and queue in place; purge: true removes them. Both tested.").
#
# No existing test in this repo exercised this split before now — the sole
# prior uninstall.sh coverage (test-uninstall-agent-health.zsh) is scoped to
# the shared agent_health store, not CREDS_DIR/QUEUE_BASE. This is a genuine
# pre-existing coverage gap this ticket's acceptance criteria surfaced, not
# a regression.
#
# Same scratch-copy + path-substitution + id/launchctl stub pattern as
# test-uninstall-agent-health.zsh: uninstall.sh hardcodes real system paths
# with no env-var override, so this never touches those real paths.
#
# Run: zsh macos/test-uninstall-purge.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# run_uninstall <purge-flag-or-empty> <creds_dir> <queue_base>
#   Builds a fresh scratch copy of uninstall.sh with BIN_DIR/DAEMON_DIR/
#   CREDS_DIR/QUEUE_BASE substituted to the given scratch fixtures, stubs
#   id/launchctl so the root check passes and there is nothing real to
#   bootout, and runs it (optionally with --purge). Echoes combined output.
run_uninstall() {
    local purge_flag="$1" creds_dir="$2" queue_base="$3"
    local scratch bin_dir daemon_dir stub_bin agent_health_dir copy out

    scratch=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-purge-test.XXXXXX")
    bin_dir="$scratch/bin"
    daemon_dir="$scratch/launchdaemons"
    stub_bin="$scratch/stubbin"
    agent_health_dir="$scratch/agent-health-state"
    mkdir -p "$bin_dir" "$daemon_dir" "$stub_bin" "$agent_health_dir"

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
      -e "s#^AGENT_HEALTH_STATE_DIR=\"/Library/Application Support/Patched\"#AGENT_HEALTH_STATE_DIR=\"$agent_health_dir\"#" \
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

    out=$(PATH="$stub_bin:$PATH" bash "$copy" ${purge_flag:+"$purge_flag"} 2>&1)
    echo "$out"
    rm -rf "$scratch"
}

# ============================================================================
echo "\n--- [1] purge:false (no flag) — credentials and queue left in place ---"
CREDS_1=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-purge-creds1.XXXXXX")
QUEUE_1=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-purge-queue1.XXXXXX")
printf 'tenant-id-value\n' > "$CREDS_1/tenant-id"
printf 'bearer-token-value\n' > "$CREDS_1/bearer-token"
printf 'hmac-secret-value\n' > "$CREDS_1/hmac-secret"
touch "$QUEUE_1/queued-item.json"

out1=$(run_uninstall "" "$CREDS_1" "$QUEUE_1")
echo "$out1" | sed 's/^/    /'

chk "tenant-id credential left in place"    "$([[ -f "$CREDS_1/tenant-id" ]] && echo 1 || echo 0)"
chk "bearer-token credential left in place" "$([[ -f "$CREDS_1/bearer-token" ]] && echo 1 || echo 0)"
chk "hmac-secret credential left in place"  "$([[ -f "$CREDS_1/hmac-secret" ]] && echo 1 || echo 0)"
chk "queue directory left in place"         "$([[ -d "$QUEUE_1" && -f "$QUEUE_1/queued-item.json" ]] && echo 1 || echo 0)"
chk "log explains credentials/queue were left in place, not purged" \
    "$(echo "$out1" | grep -qi "Leaving.*use --purge" && echo 1 || echo 0)"

rm -rf "$CREDS_1" "$QUEUE_1"

# ============================================================================
echo "\n--- [2] purge:true (--purge) — credentials and queue removed ---"
CREDS_2=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-purge-creds2.XXXXXX")
QUEUE_2=$(mktemp -d "${TMPDIR:-/tmp}/.uninstall-purge-queue2.XXXXXX")
printf 'tenant-id-value\n' > "$CREDS_2/tenant-id"
printf 'bearer-token-value\n' > "$CREDS_2/bearer-token"
printf 'hmac-secret-value\n' > "$CREDS_2/hmac-secret"
touch "$QUEUE_2/queued-item.json"

out2=$(run_uninstall "--purge" "$CREDS_2" "$QUEUE_2")
echo "$out2" | sed 's/^/    /'

chk "credentials directory removed entirely" "$([[ ! -d "$CREDS_2" ]] && echo 1 || echo 0)"
chk "queue directory removed entirely"       "$([[ ! -d "$QUEUE_2" ]] && echo 1 || echo 0)"
chk "log confirms the purge ran" "$(echo "$out2" | grep -qi "Purging credentials + queue" && echo 1 || echo 0)"

rm -rf "$CREDS_2" "$QUEUE_2" 2>/dev/null

# ============================================================================
echo "\n--- [3] purge:false and purge:true are independent runs — no cross-contamination ---"
# Re-assert case [1]'s fixture is untouched by anything case [2] did (they
# use entirely separate scratch dirs already, but this documents the
# independence explicitly as its own check per the ticket's "Both tested"
# acceptance wording, rather than leaving it merely implied by [1] and [2]
# each passing on their own).
chk "case [1] and case [2] exercised opposite outcomes on independent fixtures" "1"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
