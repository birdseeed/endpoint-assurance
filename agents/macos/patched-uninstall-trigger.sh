#!/bin/zsh
##############################################################################
# patched-uninstall-trigger.sh — user-initiated app uninstall trigger.
#
# Forces a specific app removal for the macOS agent.
#
# Usage: sudo ./patched-uninstall-trigger.sh <app_identifier>
#
# 1. Triggers the agent-level uninstall execution engine (patched-uninstall.sh).
# 2. Refreshes posture to confirm app removal.
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

[[ -z "${1:-}" ]] && { echo "Usage: sudo ./patched-uninstall-trigger.sh <app_identifier>"; exit 1; }

APP_ID="$1"
BUNDLE_DIR="/usr/local/patched-updater"
# SECURITY: BUNDLE_DIR must be owned root:wheel with mode 755 (not group-writable).
# The sudoers entry for this script pins the exact path; if BUNDLE_DIR is writable
# by a non-root principal, a local attacker can replace the engine scripts invoked
# below and escalate to root via the LaunchDaemon/sudoers path.

# Basic input validation: no path separators, reasonable length.
[[ ${#APP_ID} -gt 256 ]] && { echo "ERROR: app_identifier too long"; exit 1; }
[[ "$APP_ID" == */* || "$APP_ID" == *\\* ]] && { echo "ERROR: app_identifier contains path separators"; exit 1; }

echo "=== patched-uninstall-trigger starting for $APP_ID at $(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ==="

# Pass the validated identifier to the removal engine so it only processes this app.
echo "  triggering removal engine for '$APP_ID'..."
/usr/bin/sudo "$BUNDLE_DIR/patched-uninstall.sh" --app-id "$APP_ID"

# Refresh posture to reflect changes
echo "  refreshing posture cache..."
/usr/bin/sudo "$BUNDLE_DIR/patched-fetch-posture.sh"

echo "=== patched-uninstall-trigger complete ==="
