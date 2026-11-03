#!/bin/zsh
##############################################################################
# test-install-endpoint-bundling.zsh — PAT-1126 acceptance test.
#
# Collector-only stopped being a supported end state: macos/install.sh now
# always installs the endpoint/ bundle alongside the collector, and refuses
# to run at all if the release tarball is missing endpoint-install.sh.
#
# This runs the REAL macos/install.sh and a REAL endpoint/install.sh built
# by tools/build-bundle.sh (the exact bundler both macos-agent-release.yml
# and release-endpoint.yml use) — not a stand-in — so the manifest-hash
# verification, credential provisioning, and LaunchDaemon list are all
# genuine shipped behaviour. `id` and `launchctl` are stubbed (same
# convention as macos/test-uninstall-purge.zsh / test-uninstall-agent-health.zsh)
# so this runs as the invoking user, no real root, no real LaunchDaemons.
# PAT-2398: install.sh resets PATH and calls /usr/bin/id and /bin/launchctl by
# absolute path, so a stub on the caller's PATH no longer reaches it; the
# scratch copy has those two paths and its PATH line rebased onto the stub dir
# (PAT-2420: endpoint-install.sh resets PATH and uses absolute paths too, so
# its copy is rebased the same way).
# AGENT_DIR/LEGACY_BIN_DIR/ANCESTRY_ANCHOR/DAEMON_DIR/CREDS_DIR/QUEUE_DIR (macos/install.sh) and
# BUNDLE_DEST/LAUNCHDAEMONS_DIR/STATE_DIR/TRIGGERS_DIR/CREDS_DIR (endpoint/install.sh)
# are all sed-substituted to scratch fixtures. `install -o root -g wheel` is
# rewritten to plain `install` (ownership defaults to the invoking user) and
# `chown root:wheel` is rewritten to a no-op `:` — chowning even to your own
# uid without root fails on macOS (_POSIX_CHOWN_RESTRICTED), and the
# resulting ownership is not what this test is checking.
#
# Coverage (the acceptance criteria's two required proofs):
#   [1] endpoint-install.sh missing from the tarball -> install.sh refuses
#       BEFORE writing anything (no collector files, no LaunchDaemons, no
#       credentials) rather than partially installing a collector-only box.
#   [2] fresh install (endpoint-install.sh present) -> ALL SIX endpoint
#       LaunchDaemons end up present in LaunchDaemons dir AND launchctl
#       bootstrap was called for each of them (the "present/loaded" proof —
#       launchctl itself is stubbed, so "called bootstrap" is the strongest
#       signal obtainable without a real launchd; genuinely loaded is
#       exercised on a real Mac, not CI).
#   [3] --no-start on macos/install.sh propagates to endpoint-install.sh:
#       the endpoint LaunchDaemon plists are still copied into place
#       (present) but launchctl bootstrap is never called for them (not
#       loaded) — matching install.sh's own --no-start contract end to end.
#   [4] --enrollment-token resolved by macos/install.sh reaches
#       endpoint-install.sh's credential provisioning (single consistent
#       enrollment-token file, not two divergent writes).
#
# Run: zsh macos/test-install-endpoint-bundling.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h}"

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# --- Build a REAL endpoint bundle once (tools/build-bundle.sh) -------------
# Needs jsonschema (ci/validate-labels.py). Skip gracefully if unavailable —
# this test genuinely cannot run without a real endpoint bundle to install,
# and CI/dev environments running this repo's endpoint tests already have it.
if ! /usr/bin/env python3 -c "import jsonschema" >/dev/null 2>&1; then
    echo "SKIP: python3 jsonschema module not available — cannot build the endpoint bundle for this test"
    exit 0
fi

BUNDLE_BUILD_LOG=$(mktemp "${TMPDIR:-/tmp}/patched-endpoint-bundle-build.XXXXXX")
if ! bash "$REPO_ROOT/tools/build-bundle.sh" > "$BUNDLE_BUILD_LOG" 2>&1; then
    echo "FATAL: tools/build-bundle.sh failed:"
    cat "$BUNDLE_BUILD_LOG"
    rm -f "$BUNDLE_BUILD_LOG"
    exit 1
fi
rm -f "$BUNDLE_BUILD_LOG"

REAL_ENDPOINT_INSTALL="$REPO_ROOT/dist/install.sh"
REAL_ENDPOINT_BUNDLE_DIR="$REPO_ROOT/dist/patched-updater"
if [[ ! -f "$REAL_ENDPOINT_INSTALL" || ! -d "$REAL_ENDPOINT_BUNDLE_DIR" ]]; then
    echo "FATAL: tools/build-bundle.sh did not produce dist/install.sh + dist/patched-updater/"
    exit 1
fi

# make_stage <stage-dir> [--with-endpoint]
#   Builds a scratch STAGE dir: a substituted macos/install.sh copy + dummy
#   collector payload files, optionally with a substituted endpoint-install.sh
#   + the real patched-updater/ bundle alongside it. Prints the scratch
#   fixture root dirs as tab-separated fields:
#     bin_dir daemon_dir creds_dir queue_dir stub_bin bundle_dest triggers_dir launchctl_log
make_stage() {
    local stage="$1" with_endpoint="${2:-}"
    local root bin_dir daemon_dir creds_dir queue_dir stub_bin bundle_dest triggers_dir launchctl_log

    root="${stage:h}"
    bin_dir="$root/bin"
    daemon_dir="$root/launchdaemons"
    creds_dir="$root/creds"
    queue_dir="$root/queue"
    stub_bin="$root/stubbin"
    bundle_dest="$root/patched-updater-dest"
    triggers_dir="$root/triggers"
    launchctl_log="$root/launchctl.log"
    mkdir -p "$stage" "$bin_dir" "$daemon_dir" "$creds_dir" "$queue_dir" "$stub_bin"
    : > "$launchctl_log"

    cat > "$stub_bin/id" <<'EOF'
#!/bin/sh
echo 0
EOF
    # Records every invocation (one line per call, args space-joined) then
    # always succeeds — same "stub always succeeds" convention as the
    # existing uninstall tests, plus a call log so this test can assert
    # bootstrap WAS (or was NOT, for --no-start) called per daemon.
    cat > "$stub_bin/launchctl" <<EOF
#!/bin/sh
echo "\$*" >> "$launchctl_log"
exit 0
EOF
    chmod +x "$stub_bin/id" "$stub_bin/launchctl"

    # --- macos/install.sh scratch copy ---
    # PAT-2395: the entrypoints install to AGENT_DIR (was BIN_DIR), the legacy
    # /usr/local/bin location is only ever cleaned up, and the installer
    # verifies AGENT_DIR's ancestry from ANCESTRY_ANCHOR before writing. All
    # three are rebased onto this scratch root. The scratch tree is owned by
    # the invoking user, not root, so the ownership probe is replaced after the
    # helper block with one that reports uid 0 for what is really on disk
    # (kind still comes from the filesystem). Ancestry refusal itself is
    # covered by ci/test_privileged_entrypoint_ancestry.py, not here.
    sed \
      -e "s#^AGENT_DIR=\"/Library/Patched\"#AGENT_DIR=\"$bin_dir\"#" \
      -e "s#^LEGACY_BIN_DIR=\"/usr/local/bin\"#LEGACY_BIN_DIR=\"$root/legacy-bin\"#" \
      -e "s#^ANCESTRY_ANCHOR=\"/\"#ANCESTRY_ANCHOR=\"$root\"#" \
      -e "s#^\\# <<< PATCHED_ANCESTRY_HELPERS_END\$#&\\
patched_ancestry_probe() { if [ -L \"\$1\" ]; then echo '0 755 symlink'; elif [ -d \"\$1\" ]; then echo '0 755 dir'; elif [ -e \"\$1\" ]; then echo '0 644 other'; else echo '- - missing'; fi; }#" \
      -e "s#^DAEMON_DIR=\"/Library/LaunchDaemons\"#DAEMON_DIR=\"$daemon_dir\"#" \
      -e "s#^CREDS_DIR=\"/etc/patched\"#CREDS_DIR=\"$creds_dir\"#" \
      -e "s#^QUEUE_DIR=\"/var/db/patched/queue\"#QUEUE_DIR=\"$queue_dir\"#" \
      -e "s# -o root -g wheel##g" \
      -e "s#/usr/sbin/chown root:wheel#: #g" \
      -e "s#^export PATH=\"/usr/bin:/bin:/usr/sbin:/sbin\"\$#export PATH=\"$stub_bin:/usr/bin:/bin:/usr/sbin:/sbin\"#" \
      -e "s#/usr/bin/id -u#$stub_bin/id -u#g" \
      -e "s#/bin/launchctl #$stub_bin/launchctl #g" \
      "$SCRIPT_DIR/install.sh" > "$stage/install.sh"
    # A sed that stopped matching would run the real id (not root, so a refusal)
    # or, worse, the real launchctl. Refuse to hand back such a copy.
    if grep -Eq '(^|[^[:alnum:]_/.-])(/usr/bin/id|/bin/launchctl|/usr/sbin/chown)([^[:alnum:]_/.-]|$)' "$stage/install.sh" \
        || ! grep -q "^export PATH=\"$stub_bin:" "$stage/install.sh" \
        || grep -Eq '^(AGENT_DIR|LEGACY_BIN_DIR|ANCESTRY_ANCHOR|DAEMON_DIR|CREDS_DIR|QUEUE_DIR)="(/Library/|/etc/|/var/db/|/usr/local/)' "$stage/install.sh"; then
        echo "FATAL: scratch install.sh still names a real privileged tool or PATH" >&2
        exit 1
    fi
    chmod +x "$stage/install.sh"

    # Dummy collector payload — content is irrelevant, this test only
    # exercises the endpoint-bundling wiring, not collection itself.
    : > "$stage/patched-collect.sh"
    : > "$stage/patched-upload.sh"
    : > "$stage/com.patched.collect.plist"
    : > "$stage/com.patched.upload.plist"

    if [[ "$with_endpoint" == "--with-endpoint" ]]; then
        sed \
          -e "s#^BUNDLE_DEST=\"/usr/local/patched-updater\"#BUNDLE_DEST=\"$bundle_dest\"#" \
          -e "s#^LAUNCHDAEMONS_DIR=\"/Library/LaunchDaemons\"#LAUNCHDAEMONS_DIR=\"$daemon_dir\"#" \
          -e "s#^TRIGGERS_DIR=\"/Library/Application Support/Patched/triggers\"#TRIGGERS_DIR=\"$triggers_dir\"#" \
          -e "s#^CREDS_DIR=\"/etc/patched\"#CREDS_DIR=\"$creds_dir\"#" \
          -e "s#^STATE_DIR=\"/Library/Application Support/Patched\"#STATE_DIR=\"$root/state\"#" \
          -e "s#^TRIGGERS_DIR=.*#TRIGGERS_DIR=\"$triggers_dir\"#" \
          -e 's#st.st_uid != 0#st.st_uid != os.getuid()#g' \
          -e "s#parent = os.path.realpath(\"/etc\")#parent = os.path.realpath(\"$root\")#" \
          -e 's#os.path.join(parent, "patched")#os.path.join(parent, "creds")#' \
          -e "s# -o root -g wheel##g" \
          -e "s#/usr/sbin/chown root:wheel#: #g" \
          -e "s#^export PATH=\"/usr/bin:/bin:/usr/sbin:/sbin\"\$#export PATH=\"$stub_bin:/usr/bin:/bin:/usr/sbin:/sbin\"#" \
          -e "s#/usr/bin/id -u#$stub_bin/id -u#g" \
          -e "s#/bin/launchctl #$stub_bin/launchctl #g" \
          "$REAL_ENDPOINT_INSTALL" > "$stage/endpoint-install.sh"
        if grep -Eq '(^|[^[:alnum:]_/.-])(/usr/bin/id|/bin/launchctl|/usr/sbin/chown)([^[:alnum:]_/.-]|$)' "$stage/endpoint-install.sh" \
            || ! grep -q "^export PATH=\"$stub_bin:" "$stage/endpoint-install.sh"; then
            echo "FATAL: scratch endpoint-install.sh still names a real privileged tool or PATH" >&2
            exit 1
        fi
        # Every runtime write target and the fixed Python trust anchor must
        # point inside this disposable fixture before executing the copy.
        if ! grep -Fq "STATE_DIR=\"$root/state\"" "$stage/endpoint-install.sh" \
            || ! grep -Fq "TRIGGERS_DIR=\"$triggers_dir\"" "$stage/endpoint-install.sh" \
            || ! grep -Fq "CREDS_DIR=\"$creds_dir\"" "$stage/endpoint-install.sh" \
            || ! grep -Fq "BUNDLE_DEST=\"$bundle_dest\"" "$stage/endpoint-install.sh" \
            || ! grep -Fq "LAUNCHDAEMONS_DIR=\"$daemon_dir\"" "$stage/endpoint-install.sh" \
            || ! grep -Fq "parent = os.path.realpath(\"$root\")" "$stage/endpoint-install.sh" \
            || grep -Fq 'st.st_uid != 0' "$stage/endpoint-install.sh" \
            || grep -Eq '^(BUNDLE_DEST|LAUNCHDAEMONS_DIR|STATE_DIR|TRIGGERS_DIR|CREDS_DIR)="(/Library/|/etc/|/var/db/|/usr/local/)' "$stage/endpoint-install.sh"; then
            echo "FATAL: endpoint scratch paths or ownership probes were not rebased" >&2
            exit 1
        fi
        chmod +x "$stage/endpoint-install.sh"
        cp -r "$REAL_ENDPOINT_BUNDLE_DIR" "$stage/patched-updater"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$bin_dir" "$daemon_dir" "$creds_dir" "$queue_dir" "$stub_bin" "$bundle_dest" "$triggers_dir" "$launchctl_log"
}

# ============================================================================
echo "\n--- [1] endpoint-install.sh missing -> refuses before writing anything ---"
ROOT_1=$(mktemp -d "${TMPDIR:-/tmp}/.install-eb-test1.XXXXXX")
STAGE_1="$ROOT_1/stage"
fields=$(make_stage "$STAGE_1")
bin_dir_1=${fields%%$'\t'*}; rest=${fields#*$'\t'}
daemon_dir_1=${rest%%$'\t'*}; rest=${rest#*$'\t'}
creds_dir_1=${rest%%$'\t'*}; rest=${rest#*$'\t'}
queue_dir_1=${rest%%$'\t'*}; rest=${rest#*$'\t'}
stub_bin_1=${rest%%$'\t'*}

out1=$(PATH="$stub_bin_1:$PATH" bash "$STAGE_1/install.sh" \
    --tenant-id "11111111-1111-1111-1111-111111111111" \
    --bearer-token "test-bearer" \
    --hmac-secret "dGVzdC1zZWNyZXQtMTIzNDU2Nzg=" 2>&1)
rc1=$?
echo "$out1" | sed 's/^/    /'

chk "exits non-zero" "$(( rc1 != 0 ))"
chk "error message references PAT-1126 / collector-only" \
    "$([[ "$out1" == *"PAT-1126"* && "$out1" == *"collector-only"* ]] && echo 1 || echo 0)"
chk "no collector binary written (refused before any write)" \
    "$([[ ! -f "$bin_dir_1/patched-collect.sh" ]] && echo 1 || echo 0)"
chk "no LaunchDaemon plist written" \
    "$([[ -z "$(ls -A "$daemon_dir_1" 2>/dev/null)" ]] && echo 1 || echo 0)"
chk "no credentials written" \
    "$([[ ! -f "$creds_dir_1/tenant-id" ]] && echo 1 || echo 0)"
rm -rf "$ROOT_1"

# ============================================================================
echo "\n--- [2] fresh install (endpoint-install.sh present) -> all 6 endpoint daemons present + bootstrap called for each ---"
ROOT_2=$(mktemp -d "${TMPDIR:-/tmp}/.install-eb-test2.XXXXXX")
STAGE_2="$ROOT_2/stage"
fields=$(make_stage "$STAGE_2" --with-endpoint)
bin_dir_2=${fields%%$'\t'*}; rest=${fields#*$'\t'}
daemon_dir_2=${rest%%$'\t'*}; rest=${rest#*$'\t'}
creds_dir_2=${rest%%$'\t'*}; rest=${rest#*$'\t'}
queue_dir_2=${rest%%$'\t'*}; rest=${rest#*$'\t'}
stub_bin_2=${rest%%$'\t'*}; rest=${rest#*$'\t'}
bundle_dest_2=${rest%%$'\t'*}; rest=${rest#*$'\t'}
triggers_dir_2=${rest%%$'\t'*}; rest=${rest#*$'\t'}
launchctl_log_2=${rest}

out2=$(PATH="$stub_bin_2:$PATH" bash "$STAGE_2/install.sh" \
    --tenant-id "11111111-1111-1111-1111-111111111111" \
    --bearer-token "test-bearer" \
    --hmac-secret "dGVzdC1zZWNyZXQtMTIzNDU2Nzg=" 2>&1)
rc2=$?
echo "$out2" | sed 's/^/    /'

chk "exits 0" "$(( rc2 == 0 ))"
chk "collector binary installed" "$([[ -f "$bin_dir_2/patched-collect.sh" ]] && echo 1 || echo 0)"
chk "collector LaunchDaemon plists present" \
    "$([[ -f "$daemon_dir_2/com.patched.collect.plist" && -f "$daemon_dir_2/com.patched.upload.plist" ]] && echo 1 || echo 0)"

# PAT-1505: the assurance-only bundle installs three daemons, not six. The
# install-check, uninstall-check and catalogue-poll daemons drove the
# quarantined deployment engine and are no longer built or bootstrapped.
for label in com.patched.update com.patched.config-poll com.patched.posture-poll; do
    chk "endpoint LaunchDaemon $label.plist present" \
        "$([[ -f "$daemon_dir_2/$label.plist" ]] && echo 1 || echo 0)"
    chk "launchctl bootstrap called for $label" \
        "$(grep -q "bootstrap system .*$label\.plist" "$launchctl_log_2" && echo 1 || echo 0)"
done

# PAT-1505 regression guard, stated positively as an absence. The three daemons
# below ran as root every 15 minutes and are the visible half of what a prospect
# security reviewer would find installed. Asserting only that the three retained
# daemons are present would pass just as happily if all six were installed, so
# assert the absence explicitly.
for label in com.patched.install-check com.patched.uninstall-check com.patched.catalogue-poll; do
    chk "deployment LaunchDaemon $label.plist NOT installed" \
        "$([[ ! -f "$daemon_dir_2/$label.plist" ]] && echo 1 || echo 0)"
    chk "launchctl bootstrap NOT called for $label" \
        "$(grep -q "bootstrap system .*$label\.plist" "$launchctl_log_2" && echo 0 || echo 1)"
done

# The engine scripts themselves must not reach the endpoint either.
for f in Installomator.sh patched-install.sh patched-uninstall.sh \
         labels-allowlist.txt; do
    chk "deployment engine file $f NOT deployed to BUNDLE_DEST" \
        "$([[ ! -e "$bundle_dest_2/$f" ]] && echo 1 || echo 0)"
done

chk "endpoint bundle files deployed to BUNDLE_DEST" \
    "$([[ -f "$bundle_dest_2/patched-update.sh" && -f "$bundle_dest_2/manifest.sha256" ]] && echo 1 || echo 0)"
chk "shared credentials written once (tenant-id present)" \
    "$([[ -f "$creds_dir_2/tenant-id" ]] && echo 1 || echo 0)"
rm -rf "$ROOT_2"

# ============================================================================
echo "\n--- [3] --no-start propagates: endpoint plists present but bootstrap never called ---"
ROOT_3=$(mktemp -d "${TMPDIR:-/tmp}/.install-eb-test3.XXXXXX")
STAGE_3="$ROOT_3/stage"
fields=$(make_stage "$STAGE_3" --with-endpoint)
daemon_dir_3=$(echo "$fields" | cut -f2)
launchctl_log_3=$(echo "$fields" | cut -f8)

out3=$(PATH="$(echo "$fields" | cut -f5):$PATH" bash "$STAGE_3/install.sh" \
    --tenant-id "11111111-1111-1111-1111-111111111111" \
    --bearer-token "test-bearer" \
    --hmac-secret "dGVzdC1zZWNyZXQtMTIzNDU2Nzg=" \
    --no-start 2>&1)
rc3=$?
echo "$out3" | sed 's/^/    /'

chk "exits 0" "$(( rc3 == 0 ))"
chk "endpoint LaunchDaemon com.patched.config-poll.plist present" \
    "$([[ -f "$daemon_dir_3/com.patched.config-poll.plist" ]] && echo 1 || echo 0)"
chk "launchctl bootstrap NEVER called (nothing loaded under --no-start)" \
    "$([[ ! -s "$launchctl_log_3" ]] || ! grep -q "bootstrap" "$launchctl_log_3" && echo 1 || echo 0)"
rm -rf "$ROOT_3"

# ============================================================================
echo "\n--- [4] --enrollment-token resolved by macos/install.sh reaches endpoint-install.sh ---"
ROOT_4=$(mktemp -d "${TMPDIR:-/tmp}/.install-eb-test4.XXXXXX")
STAGE_4="$ROOT_4/stage"
fields=$(make_stage "$STAGE_4" --with-endpoint)
creds_dir_4=$(echo "$fields" | cut -f3)
stub_bin_4=$(echo "$fields" | cut -f5)

out4=$(PATH="$stub_bin_4:$PATH" bash "$STAGE_4/install.sh" --enrollment-token "TESTTOKEN-ABC123" 2>&1)
rc4=$?
echo "$out4" | sed 's/^/    /'

chk "exits 0" "$(( rc4 == 0 ))"
written_token=$(cat "$creds_dir_4/enrollment-token" 2>/dev/null)
chk "single consistent enrollment-token file" \
    "$([[ -f "$creds_dir_4/enrollment-token" && "$written_token" == "TESTTOKEN-ABC123" ]] && echo 1 || echo 0)"
rm -rf "$ROOT_4"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
