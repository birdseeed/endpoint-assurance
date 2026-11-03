#!/bin/bash
# uninstall.sh — remove the Patched Updater endpoint bundle.
#
# Run as root from the release tarball directory (or anywhere):
#   sudo bash uninstall.sh
#
# Leaves /etc/patched credentials in place — they are shared with the
# inventory agent. Remove them manually only if both agents are being removed.
set -euo pipefail

# PAT-2420: runs as root, so the caller's PATH must never choose a tool. PATH is
# reset to the system directories and every external tool is called by its
# absolute system path, as in macos/uninstall.sh (PAT-2398).
# ci/test_privileged_installer_trust.py enforces both.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

BUNDLE_DEST="/usr/local/patched-updater"
LAUNCHDAEMONS_DIR="/Library/LaunchDaemons"
TRIGGERS_DIR="/Library/Application Support/Patched/triggers"
STATE_DIR="/Library/Application Support/Patched"

# LaunchDaemon plists this uninstaller removes (PAT-860). This MUST remain a
# superset of install.sh's LAUNCHDAEMONS array so every daemon install.sh
# bootstraps is torn down here.
#
# PAT-1505: it is now a strict superset rather than an identical list. The
# first three below are the assurance-only bundle's daemons; the last three are
# the quarantined deployment daemons, which install.sh no longer ships or
# bootstraps but which are still present on any machine that ran a
# pre-PAT-1505 installer. Uninstall must clean up the machine it finds, not the
# machine the current bundle would have produced, so they stay listed here.
# Deleting them from this list would strand loaded root daemons on exactly the
# older estate that most needs the removal. install.sh purges the same three on
# upgrade (see its LEGACY_LAUNCHDAEMONS).
LAUNCHDAEMONS=(
    com.patched.update.plist
    com.patched.config-poll.plist
    com.patched.posture-poll.plist
    com.patched.install-check.plist
    com.patched.uninstall-check.plist
    com.patched.catalogue-poll.plist
)

if [[ "$(/usr/bin/id -u)" != "0" ]]; then
    echo "ERROR: uninstall.sh must be run as root (sudo bash uninstall.sh)."
    exit 1
fi

# --- Bootout daemons ---
echo "Stopping LaunchDaemons ..."
for plist in "${LAUNCHDAEMONS[@]}"; do
    dest="$LAUNCHDAEMONS_DIR/$plist"
    if [[ -f "$dest" ]]; then
        /bin/launchctl bootout system "$dest" 2>/dev/null || true
        /bin/rm -f "$dest"
        echo "  Removed $dest"
    else
        # PAT-2245: a job can stay loaded after its plist is deleted, so boot
        # it out by label too. Harmless when nothing by that label is loaded.
        /bin/launchctl bootout "system/${plist%.plist}" 2>/dev/null || true
        echo "  ${plist%.plist} plist not found, already removed."
    fi
done

# --- Remove bundle ---
if [[ -d "$BUNDLE_DEST" ]]; then
    echo "Removing bundle ..."
    /bin/rm -rf "$BUNDLE_DEST"
    echo "  Removed $BUNDLE_DEST"
else
    echo "  Bundle not found — already removed."
fi

# --- Remove triggers dir and state files ---
if [[ -d "$TRIGGERS_DIR" ]]; then
    /bin/rm -rf "$TRIGGERS_DIR"
    echo "  Removed $TRIGGERS_DIR"
fi
# PAT-926: full list of state artifacts the wired daemons write under
# STATE_DIR (audited against patched-update.sh, patched-fetch-config.sh,
# patched-install.sh and the retired catalogue poller, whose cache PAT-2245
# still removes from machines that ran it). uninstall-status.json is
# deliberately NOT deleted — it is written by this same uninstall run and is
# the audit record of what just happened; removing it as part of its own run
# would be self-defeating.
for state_file in update-status.json agent-config.json agent-config.version \
                  agent-config.sha256 agent-config.json.quarantined \
                  agent-config.checked agent-config.execution-denied \
                  .agent-config.force-refetch \
                  update-channel.json update-channel.json.lock \
                  install-status.json catalogue.json catalogue.etag \
                  catalogue.indeterminate-since \
                  posture.json posture.version \
                  .agent-health.json; do
    if [[ -f "$STATE_DIR/$state_file" ]]; then
        /bin/rm -f "$STATE_DIR/$state_file"
        echo "  Removed $STATE_DIR/$state_file"
    fi
done
# patched-update.sh writes one blocking-deferrals-<label>.json per app label
# it has deferred a blocking update for — a dynamic filename set, not a fixed
# name, so it needs a glob rather than an entry in the list above.
shopt -s nullglob
for deferral_file in "$STATE_DIR"/blocking-deferrals-*.json; do
    /bin/rm -f "$deferral_file"
    echo "  Removed $deferral_file"
done
shopt -u nullglob

# PAT-2245: the retired catalogue poller's mkdir lock directory. Its daemon
# was booted out above and no current component takes this lock, so it is
# removed unconditionally; a symlink at this name is removed, never followed.
if [[ -L "$STATE_DIR/.patched-catalogue-fetch.lock" ]]; then
    /bin/rm -f "$STATE_DIR/.patched-catalogue-fetch.lock"
    echo "  Removed $STATE_DIR/.patched-catalogue-fetch.lock"
elif [[ -d "$STATE_DIR/.patched-catalogue-fetch.lock" ]]; then
    /bin/rm -rf "${STATE_DIR:?}/.patched-catalogue-fetch.lock"
    echo "  Removed $STATE_DIR/.patched-catalogue-fetch.lock"
fi

# PAT-1065: .agent-health.lock is a mkdir-based lock directory, not a plain
# file, so it needs its own rm -rf rather than the -f loop above. A fresh
# install/reinstall must start with a clean slate for this store: it has no
# legitimate basis to claim ever_succeeded=true for a capability it has not,
# as a fresh install, actually verified working, and a stale `active` entry
# surviving a reinstall could misreport a fault that may no longer apply.
# This store is genuinely shared with the macOS inventory collector/uploader
# (a separate, separately-uninstallable daemon family — see
# macos/lib/agent_health.sh) — uninstalling just this update-daemon family
# while the collector stays installed will also reset the collector's own
# capability_missing/extension_removal history. Accepted as a documented
# limitation rather than surgical per-(kind,subject) cleanup: the fallout is
# a conservative one (a transient "ever_succeeded: false" for one report
# cycle on the OTHER family's fault, never a fabricated positive), and this
# repo's Tier 1/Tier 2 toggle is not expected to be exercised often enough to
# make that cost worth the extra complexity here.
#
# PAT-1065 review finding 3: an uninstall of THIS family can run at the
# exact moment the OTHER, still-installed family's daemon is mid-write to
# this same shared lock — uninstalls and normal agent operation are not
# coordinated. Force-removing the lock directory unconditionally could yank
# it out from under a live writer, and a third process racing to acquire it
# in that same window could then succeed a mkdir into space an active
# writer still believes it owns. Only remove it when it looks safely
# unused: no pid recorded, or a pid naming a process that is no longer
# running. This does not need to be — and does not attempt to be — as
# careful as the library's own staleness check (macos/lib/agent_health.sh:
# pid liveness + recorded start time + reclaim-race marker); a lock left in
# place here because it looked "maybe live" is a harmless leftover directory
# that the library's own next invocation will reclaim if it later turns out
# to have genuinely been stale. This check only needs to stop an uninstall
# from destroying something that is live right now, not fully replace that
# more careful logic.
if [[ -d "$STATE_DIR/.agent-health.lock" ]]; then
    _ah_uninstall_pid_line=$(/bin/cat "$STATE_DIR/.agent-health.lock/pid" 2>/dev/null || true)
    _ah_uninstall_pid="${_ah_uninstall_pid_line%%|*}"
    if [[ -n "$_ah_uninstall_pid" ]] && kill -0 "$_ah_uninstall_pid" 2>/dev/null; then
        echo "  Left $STATE_DIR/.agent-health.lock in place (pid $_ah_uninstall_pid appears to be actively holding it right now)"
    else
        /bin/rm -rf "$STATE_DIR/.agent-health.lock"
        echo "  Removed $STATE_DIR/.agent-health.lock"
    fi
fi

echo ""
echo "Patched Updater uninstalled."
echo "NOTE: /etc/patched credentials NOT removed (shared with inventory agent)."
