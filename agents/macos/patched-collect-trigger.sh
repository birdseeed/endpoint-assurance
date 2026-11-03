#!/bin/zsh
##############################################################################
# patched-collect-trigger.sh — user-initiated collector trigger.
#
# Forces an immediate collect+upload cycle for the macOS agent.
#
# 1. Calls patched-collect.sh to perform a full inventory run.
# 2. Invokes patched-upload.sh to flush the queue to the platform.
# 3. Triggers a post-upload posture refresh so the UI reflects current state.
##############################################################################

set -u

# PAT-2420: this trigger is not installed or scheduled by anything in this
# repository. A person runs it, as an ordinary user (it reaches root through
# the sudo calls below) or under sudo as root. Either way the caller's PATH
# must not choose which sudo receives the password or what runs as root, so
# PATH is reset and both tools are called by absolute path (PAT-2394/PAT-2398
# convention; ci/test_privileged_installer_trust.py enforces it and holds sudo
# to the fixed targets below).
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Path config.
#
# patched-collect.sh / patched-upload.sh (the inventory collector, this repo's
# macos/) and patched-fetch-posture.sh (the endpoint update-engine bundle, this
# repo's endpoint/) are deployed to two DIFFERENT directories today — they are
# not interchangeable and neither is a fallback for the other (PAT-746):
#   - Collector: both current deployment rails (Intune Platform Script's
#     one-time copy step, and the GitHub-release install.sh) install
#     patched-collect.sh / patched-upload.sh to /Library/Patched (PAT-2395;
#     /usr/local/bin before that). See macos/README.md "Deployment via
#     Intune" / "Deployment via GitHub Release" and macos/install.sh's
#     AGENT_DIR. The sudoers entry that pins these paths must name the same
#     directory.
#   - Endpoint bundle: patched-fetch-posture.sh ships as part of the
#     Installomator-based update-engine bundle, installed to
#     /usr/local/patched-updater by endpoint/install.sh (see that repo path's
#     BUNDLE_DEST and endpoint/patched-fetch-posture.sh's own BUNDLE_DIR
#     default). patched-uninstall-trigger.sh calls the same directory for the
#     same reason.
COLLECT_BIN_DIR="/Library/Patched"
BUNDLE_DIR="/usr/local/patched-updater"
# SECURITY: both directories above must be owned root:wheel with mode 755 (not
# group-writable). The sudoers entry for this script pins the exact paths; if
# either directory is writable by a non-root principal, a local attacker can
# replace the scripts invoked below and escalate to root via the
# LaunchDaemon/sudoers path.

echo "=== patched-collect-trigger starting at $(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# 1. Collect
echo "  triggering collection..."
/usr/bin/sudo "$COLLECT_BIN_DIR/patched-collect.sh"

# 2. Upload
echo "  flushing queue..."
/usr/bin/sudo "$COLLECT_BIN_DIR/patched-upload.sh"

# 3. Refresh Posture (PAT-471)
echo "  refreshing posture cache..."
/usr/bin/sudo "$BUNDLE_DIR/patched-fetch-posture.sh"

echo "=== patched-collect-trigger complete ==="
