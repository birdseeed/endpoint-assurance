#!/bin/zsh
##############################################################################
# test-install-mode.zsh: tests for the PAT-1035 finding-3 mode-selection
# decision in endpoint/install.sh (the `case "$rel" in ... esac` block that
# picks 755 vs 644 for each bundled file).
#
# install.sh's extension-to-mode mapping is what broke, silently: *.py files
# (the verifiers) shipped at 644, both fetchers' `[[ -x "$VERIFIER" ]]` guard
# then failed on every run, and agent-config was never verified on a clean
# install — with no test looking at the mapping,
# nothing caught it.
#
# The full installer needs root and bootstraps launchd, so this does NOT run
# install.sh. It tests the DECISION, not the installation: it extracts the
# sentinel-delimited PATCHED_INSTALL_MODE block from the SHIPPED install.sh
# (same awk-extraction pattern macos/test-agent-config-gate.zsh and
# endpoint/test-agent-config-hash-gate.zsh use) and drives it directly,
# per filename, against a temp file — no root, no cp, no chown, no launchctl.
#
# Run: zsh endpoint/test-install-mode.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
INSTALL_SH="$SCRIPT_DIR/install.sh"

MODE_TMP=$(mktemp "${TMPDIR:-/tmp}/patched-install-mode.XXXXXX")
awk '/PATCHED_INSTALL_MODE_START/{f=1;next} /PATCHED_INSTALL_MODE_END/{f=0} f' \
    "$INSTALL_SH" > "$MODE_TMP"
if [[ ! -s "$MODE_TMP" ]]; then
    echo "FATAL: could not extract PATCHED_INSTALL_MODE block from $INSTALL_SH"
    exit 1
fi

pass=0; fail=0
chk() {  # chk <desc> <0-for-true>
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.install-mode-test.XXXXXX")
trap 'rm -rf "$WORK" "$MODE_TMP"' EXIT

BUNDLE_DEST="$WORK"

# assert_mode <rel> <expected-octal-mode>
#   Creates $BUNDLE_DEST/<rel> (mode 0000, so a no-op case arm would be
#   caught rather than accidentally matching the expectation), sets $rel,
#   sources the extracted case block against it, and checks the resulting
#   mode.
assert_mode() {
    local rel="$1" expected="$2" got
    : > "$BUNDLE_DEST/$rel"
    chmod 000 "$BUNDLE_DEST/$rel"
    # Subshell: the extracted block is a bare `case` statement (not a
    # function), so sourcing it runs immediately against the current $rel /
    # $BUNDLE_DEST — both already in scope here — without leaking state
    # between iterations.
    ( source "$MODE_TMP" )
    got=$(stat -f '%A' "$BUNDLE_DEST/$rel" 2>/dev/null || stat -c '%a' "$BUNDLE_DEST/$rel" 2>/dev/null)
    chk "$rel -> $expected" "$([[ "$got" == "$expected" ]] && echo 1 || echo 0)"
}

# ───────────────────────────────────────────────────────────────────────────
# PAT-1505: the filename lists below are the assurance-only manifest. The
# deployment-engine names they used to carry (Installomator.sh,
# patched-install.sh, patched-uninstall.sh, the retired poller and its
# verifier, labels-allowlist.txt, LICENSE, NOTICE and the three
# actuation plists) are no longer shipped, so asserting a mode for them here
# would describe a bundle that does not exist. The test itself is unchanged in
# what it proves: install.sh's case block maps extensions to modes, and the
# *.sh / *.py / everything-else arms are each still driven by real manifest
# names. This is deliberately not reduced to one name per arm — the PAT-1035
# regression it guards was specifically that *.py fell through to 644.
echo "[1] shell scripts resolve to 755"
for rel in patched-fetch-config.sh patched-fetch-posture.sh patched-enroll.sh \
           patched-log-upload.sh patched-decommission.sh \
           endpoint-uninstall.sh macos-uninstall.sh; do
    assert_mode "$rel" 755
done

# ───────────────────────────────────────────────────────────────────────────
echo "[2] the four real .py names from the endpoint manifest resolve to 755 (PAT-1035 finding 3 regression)"
for rel in verify-agent-config.py verify-posture.py validate-posture.py \
           patched-proxy-resolve.py; do
    assert_mode "$rel" 755
done

# ───────────────────────────────────────────────────────────────────────────
echo "[3] everything else in the manifest resolves to 644"
for rel in com.patched.update.plist com.patched.config-poll.plist \
           com.patched.posture-poll.plist com.patched.decommission.plist \
           manifest.sha256; do
    assert_mode "$rel" 644
done

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
