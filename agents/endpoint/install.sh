#!/bin/bash
# install.sh — no-MDM install for the Patched Updater endpoint bundle.
#
# Run as root from the release tarball directory:
#   sudo bash install.sh
#
# EXPECTED_MANIFEST_HASH is stamped by tools/build-bundle.sh at release time
# and is the v1 trust anchor — it gates the install on the exact bundle that
# was built for this release. A tampered or mismatched download is caught here
# before anything is written to disk.
#
# The plist must not set any PATCHED_* override vars. Those vars are test-only
# (see patched-update.sh); the production daemon falls back to the secure
# hardcoded defaults (/usr/local/patched-updater, /Library/Application
# Support/Patched, /etc/patched).
set -euo pipefail

# PAT-2420: this script runs as root, so the caller's PATH must never choose a
# tool. It inherits a reset PATH when macos/install.sh starts it, but not when
# it is run directly (sudo bash install.sh keeps the caller's PATH on macOS).
# Same convention as macos/install.sh (PAT-2398): PATH is reset before anything
# runs and every external tool is called by its absolute system path.
# ci/test_privileged_installer_trust.py enforces both; add a tool to its
# allowlist when adding one here.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

EXPECTED_MANIFEST_HASH="__MANIFEST_HASH__"
# PAT-687: the daemon (patched-update.sh) carries the manifest pin, so it cannot
# be listed in manifest.sha256 (it can't hash itself). It is verified separately
# against this anchor, also stamped by tools/build-bundle.sh.
EXPECTED_DAEMON_HASH="__DAEMON_HASH__"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "$0")" && pwd)"
BUNDLE_SRC="$SCRIPT_DIR/patched-updater"

# ---------------------------------------------------------------------------
# Argument parsing (PAT-544)
# ---------------------------------------------------------------------------
ENROLLMENT_TOKEN=""
ENROLLMENT_TOKEN_PROVISIONED=0
NO_START=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enrollment-token-provisioned) ENROLLMENT_TOKEN_PROVISIONED=1; shift ;;
        --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
        # PAT-1126: threaded through from macos/install.sh, which now always
        # installs this bundle too — --no-start there means "install but do
        # not load daemons or run collection"; mirror that here so passing it
        # through doesn't silently start LaunchDaemons the caller asked this
        # run not to start.
        --no-start) NO_START=1; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Auto-detect enrollment.json alongside the installer (email-link delivery path)
if [[ "$ENROLLMENT_TOKEN_PROVISIONED" -eq 0 && -z "$ENROLLMENT_TOKEN" && -f "$SCRIPT_DIR/enrollment.json" ]]; then
    ENROLLMENT_TOKEN=$(/usr/bin/python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    t = d.get('enrollment_token')
    print(t if t else '', end='')
except Exception:
    pass
" "$SCRIPT_DIR/enrollment.json" 2>/dev/null || true)
fi
BUNDLE_DEST="/usr/local/patched-updater"
LAUNCHDAEMONS_DIR="/Library/LaunchDaemons"
STATE_DIR="/Library/Application Support/Patched"
TRIGGERS_DIR="$STATE_DIR/triggers"
CREDS_DIR="/etc/patched"

# Internal wrapper handoff: use the canonical private token, or credentials
# already established by a poller that consumed it before this child started.
# No arbitrary credential path is accepted. Validate before any installation.
if [[ "$ENROLLMENT_TOKEN_PROVISIONED" -eq 1 ]]; then
    ENROLLMENT_TOKEN=""
    /usr/bin/python3 -I -c '
import os, stat, sys
try:
    # /etc is a system symlink on macOS. Resolve that fixed anchor, then
    # reject links in the credential directory and the token itself.
    parent = os.path.realpath("/etc")
    for directory in (parent, os.path.join(parent, "patched")):
        st = os.lstat(directory)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError()
    def private_value(filename):
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
                raise ValueError()
            return fh.read()
    try:
        token = private_value(sys.argv[1])
    except FileNotFoundError:
        # A successful enrolment writes all four credentials, then removes
        # this single-use token. Missing is the only permitted fallback:
        # an unsafe, linked or empty token must never be treated as absent.
        for name in ("tenant-id", "bearer-token", "hmac-secret", "device-id"):
            value = private_value(os.path.join(os.path.dirname(sys.argv[1]), name)).rstrip("\n")
            if not value.strip() or any(c in value for c in "\t\r\n"):
                raise ValueError()
    else:
        if not token.splitlines() or not token.splitlines()[0].strip():
            raise ValueError()
except Exception:
    sys.exit(1)
' "$CREDS_DIR/enrollment-token" || { echo "Untrusted or incomplete provisioned enrollment state" >&2; exit 1; }
fi

# LaunchDaemon plists to install and bootstrap (PAT-860). Single source of truth
# for this installer; uninstall.sh carries the identical list and the two MUST
# stay in sync.
#
# Posture is fetched only by com.patched.posture-poll. Its pipeline verifies
# the signed envelope, tenant binding, anti-rollback floor, and schema before
# atomically replacing posture.json with the decoded body. The inventory
# uploader is deliberately not a second writer (PAT-1116).
LAUNCHDAEMONS=(
    com.patched.update.plist
    com.patched.config-poll.plist
    com.patched.posture-poll.plist
)

# PAT-1505: components an assurance-only bundle no longer ships. This list is
# not about the bundle being installed — it is about the machine. Installing
# over a pre-PAT-1505 agent leaves that agent's root LaunchDaemons loaded and
# its engine scripts on disk: install.sh only ever adds files, and the manifest
# copy loop above cannot remove what is no longer in the manifest. Without this
# purge the "assurance-only" install would still have the deployment engine
# resident and the install-check/uninstall-check/catalogue-poll daemons still
# firing every 15 minutes, which is the exact outcome PAT-1505 exists to
# prevent and would be invisible to anyone reading the new manifest.
#
# The sources for all of these remain in the repository for PAT-1481; this
# removes them from endpoints, not from the tree.
LEGACY_LAUNCHDAEMONS=(
    com.patched.install-check.plist
    com.patched.uninstall-check.plist
    com.patched.catalogue-poll.plist
)
LEGACY_BUNDLE_FILES=(
    Installomator.sh
    patched-install.sh
    patched-uninstall.sh
    patched-fetch-catalogue.sh
    verify-catalogue.py
    labels-allowlist.txt
    LICENSE
    NOTICE
    # PAT-1505 real-device gap (2026-09-09, mac-staging): these are the
    # $BUNDLE_DEST *copies* of the three LEGACY_LAUNCHDAEMONS plists above.
    # The LEGACY_LAUNCHDAEMONS loop already purges them from
    # $LAUNCHDAEMONS_DIR, but a pre-PAT-1505 bundle also ships a copy of
    # each plist inside $BUNDLE_DEST itself, and nothing purged that copy —
    # an upgrade-in-place left it behind even though the loaded daemon was
    # gone.
    com.patched.install-check.plist
    com.patched.uninstall-check.plist
    com.patched.catalogue-poll.plist
)
# PAT-1505 real-device gap (2026-09-09, mac-staging): stale catalogue cache
# written by the retired patched-fetch-catalogue.sh (see uninstall.sh, which
# purges the same names from the same directory on a full uninstall). An
# upgrade-in-place never ran uninstall.sh, so these survive under the new
# assurance-only bundle with nothing left to refresh or consume them.
# PAT-2245 retired the signed app catalogue end to end and added the
# poller's indeterminate-since marker and its mkdir lock directory.
LEGACY_CATALOGUE_FILES=(
    catalogue.json
    catalogue.etag
    catalogue.indeterminate-since
)
LEGACY_CATALOGUE_DIRS=(
    .patched-catalogue-fetch.lock
)

# --- Root check ---
if [[ "$(/usr/bin/id -u)" != "0" ]]; then
    echo "ERROR: install.sh must be run as root (sudo bash install.sh)."
    exit 1
fi

# --- Validate source layout ---
if [[ ! -f "$BUNDLE_SRC/manifest.sha256" ]]; then
    echo "ERROR: manifest.sha256 not found in $BUNDLE_SRC"
    echo "       Is this the full release tarball?"
    exit 1
fi

# --- V1 trust anchor: verify manifest.sha256 matches the expected hash ---
echo "Verifying release integrity (v1 trust anchor)..."
actual_manifest_hash=$(/usr/bin/shasum -a 256 "$BUNDLE_SRC/manifest.sha256" | /usr/bin/awk '{print $1}')
if [[ "$actual_manifest_hash" != "$EXPECTED_MANIFEST_HASH" ]]; then
    echo "ERROR: manifest.sha256 hash mismatch — tampered or mismatched release."
    echo "  Expected: $EXPECTED_MANIFEST_HASH"
    echo "  Got:      $actual_manifest_hash"
    exit 1
fi
echo "  manifest.sha256 hash OK."

# --- Copy bundle files ---
echo "Installing bundle to $BUNDLE_DEST ..."
/usr/bin/install -d -o root -g wheel -m 755 "$BUNDLE_DEST"

while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    rel="${line##* }"
    src="$BUNDLE_SRC/$rel"
    if [[ ! -f "$src" ]]; then
        echo "ERROR: expected bundle file missing: $src"
        exit 1
    fi
    /bin/cp "$src" "$BUNDLE_DEST/$rel"
    # >>> PATCHED_INSTALL_MODE_START
    # PAT-1035 finding 3: *.py must be executable too — patched-fetch-config.sh
    # gates on `[[ -x "$VERIFIER" ]]` before running verify-agent-config.py
    # (invoked as "$PYTHON3" "$VERIFIER", so the mode itself is never needed to
    # execute it — the guard is the only thing a non-executable mode breaks).
    # Shipping the verifier at 644 makes that guard fail on every run of a
    # clean install: agent-config verification exits 1, so no config is ever
    # verified. Extend this
    # case (not a filename special-case) so a future *.py addition is covered.
    #
    # endpoint/test-install-mode.zsh extracts exactly this block (sentinel
    # markers, same pattern as the other extracted blocks in this repo) and
    # drives it over a representative set of manifest filenames, so a future
    # edit that drops *.py from the case fails a test by name rather than
    # silently landing at 644 again.
    case "$rel" in
        *.sh|*.py) /bin/chmod 755 "$BUNDLE_DEST/$rel" ;;
        *)         /bin/chmod 644 "$BUNDLE_DEST/$rel" ;;
    esac
    # <<< PATCHED_INSTALL_MODE_END
    /usr/sbin/chown root:wheel "$BUNDLE_DEST/$rel"
done < "$BUNDLE_SRC/manifest.sha256"

/bin/cp "$BUNDLE_SRC/manifest.sha256" "$BUNDLE_DEST/manifest.sha256"
/bin/chmod 644 "$BUNDLE_DEST/manifest.sha256"
/usr/sbin/chown root:wheel "$BUNDLE_DEST/manifest.sha256"

# --- Daemon (patched-update.sh): verified separately against its own anchor ---
# It is not in manifest.sha256 (it carries the manifest pin), so verify + copy
# it explicitly here (PAT-687).
DAEMON_SRC="$BUNDLE_SRC/patched-update.sh"
if [[ ! -f "$DAEMON_SRC" ]]; then
    echo "ERROR: patched-update.sh missing from bundle"
    exit 1
fi
actual_daemon_hash=$(/usr/bin/shasum -a 256 "$DAEMON_SRC" | /usr/bin/awk '{print $1}')
if [[ "$actual_daemon_hash" != "$EXPECTED_DAEMON_HASH" ]]; then
    echo "ERROR: patched-update.sh hash mismatch — tampered or mismatched release."
    echo "  Expected: $EXPECTED_DAEMON_HASH"
    echo "  Got:      $actual_daemon_hash"
    exit 1
fi
/bin/cp "$DAEMON_SRC" "$BUNDLE_DEST/patched-update.sh"
/bin/chmod 755 "$BUNDLE_DEST/patched-update.sh"
/usr/sbin/chown root:wheel "$BUNDLE_DEST/patched-update.sh"
echo "  patched-update.sh hash OK."

# --- Verify deployed bundle against manifest ---
echo "Verifying deployed bundle ..."
fail=0
while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    want="${line%% *}"
    rel="${line##* }"
    got=$(/usr/bin/shasum -a 256 "$BUNDLE_DEST/$rel" 2>/dev/null | /usr/bin/awk '{print $1}')
    if [[ "$got" != "$want" ]]; then
        echo "ERROR: deployed file integrity check failed: $rel"
        fail=1
    fi
done < "$BUNDLE_DEST/manifest.sha256"
if [[ $fail -ne 0 ]]; then
    echo "Aborting — deployed bundle failed integrity check."
    exit 1
fi
echo "  Deployed bundle integrity OK."

# --- Purge quarantined deployment components (PAT-1505) ---
# Runs only after the new bundle is in place and verified, so a failed install
# never leaves a machine with neither the old engine nor a working new agent.
# Daemons are booted out before their scripts are removed, so nothing is deleted
# out from under a running launchd job.
echo "Removing quarantined deployment components ..."
# >>> PATCHED_LEGACY_PURGE_START
# endpoint/test-install-legacy-purge.sh and
# endpoint/test-catalogue-retirement-cleanup.sh extract exactly this block
# (sentinel markers, same pattern as PATCHED_INSTALL_MODE above) and drive it
# against fixture BUNDLE_DEST/LAUNCHDAEMONS_DIR/STATE_DIR dirs with the real
# LEGACY_* arrays, so a future purge-loop or array edit is caught by name
# rather than only being found again by a real-device upgrade.
# tools/pkg-scripts/postinstall carries a byte-identical copy of this block
# and of the LEGACY_* arrays (PAT-2245: the .pkg upgrade path purged nothing);
# the second test above fails if the two drift apart.
#
# Every step is idempotent, safe when its target is absent, and non-fatal:
# the new bundle is already installed and verified by the time this runs.
# Each legacy daemon is booted out by label even when its plist is already
# gone, because a job can stay loaded after its plist is deleted. rm -f / -rf
# on a symlink removes the link itself and never follows it; the cache is
# skipped entirely if STATE_DIR is itself a symlink.
for plist in "${LEGACY_LAUNCHDAEMONS[@]}"; do
    dest="$LAUNCHDAEMONS_DIR/$plist"
    /bin/launchctl bootout "system/${plist%.plist}" 2>/dev/null || true
    if [[ -e "$dest" || -L "$dest" ]]; then
        /bin/rm -f "$dest" || echo "  WARNING: could not remove $dest"
        echo "  Removed ${plist%.plist} (left by a pre-assurance-only install)."
    fi
done
for legacy in "${LEGACY_BUNDLE_FILES[@]}"; do
    if [[ -e "$BUNDLE_DEST/$legacy" || -L "$BUNDLE_DEST/$legacy" ]]; then
        /bin/rm -f "$BUNDLE_DEST/$legacy" || echo "  WARNING: could not remove $BUNDLE_DEST/$legacy"
        echo "  Removed $BUNDLE_DEST/$legacy (left by a pre-assurance-only install)."
    fi
done
if [[ -L "${STATE_DIR:?}" ]]; then
    echo "  WARNING: $STATE_DIR is a symlink; not purging the retired catalogue cache through it."
else
    for cache in "${LEGACY_CATALOGUE_FILES[@]}"; do
        if [[ -e "$STATE_DIR/$cache" || -L "$STATE_DIR/$cache" ]]; then
            /bin/rm -f "$STATE_DIR/$cache" || echo "  WARNING: could not remove $STATE_DIR/$cache"
            echo "  Removed $STATE_DIR/$cache (retired signed app catalogue)."
        fi
    done
    for cache_dir in "${LEGACY_CATALOGUE_DIRS[@]}"; do
        if [[ -L "$STATE_DIR/$cache_dir" ]]; then
            /bin/rm -f "$STATE_DIR/$cache_dir" || echo "  WARNING: could not remove $STATE_DIR/$cache_dir"
            echo "  Removed $STATE_DIR/$cache_dir (retired signed app catalogue)."
        elif [[ -d "$STATE_DIR/$cache_dir" ]]; then
            /bin/rm -rf "${STATE_DIR:?}/${cache_dir:?}" || echo "  WARNING: could not remove $STATE_DIR/$cache_dir"
            echo "  Removed $STATE_DIR/$cache_dir (retired signed app catalogue)."
        fi
    done
fi
# <<< PATCHED_LEGACY_PURGE_END

# --- State and triggers directories ---
# The config, digest and heartbeat cache share this root-owned directory. The
# state files can be readable for diagnostics, but an unprivileged local user
# must not be able to replace their directory entries between evaluator reads.
# A root attacker is outside this local-user boundary: they can replace the
# root LaunchDaemon and bundle too, so this cache gate does not claim to defend
# against root compromise.
if [[ -L "$STATE_DIR" ]]; then
    echo "ERROR: refusing symlinked state directory: $STATE_DIR"
    exit 1
fi
# `install -d -m` does not repair every existing installation consistently.
# Enforce the cache boundary on each installer run before root LaunchDaemons
# reuse its config, digest and heartbeat entries.
/usr/bin/install -d "$STATE_DIR"
/usr/sbin/chown root:wheel "$STATE_DIR"
/bin/chmod 755 "$STATE_DIR"
# mode 1733 = sticky + rwx for owner/group, wx for others
echo "Creating triggers directory ..."
/usr/bin/install -d -o root -g wheel -m 1733 "$TRIGGERS_DIR"

# --- Install LaunchDaemon plists ---
echo "Installing LaunchDaemons ..."

for plist in "${LAUNCHDAEMONS[@]}"; do
    src="$BUNDLE_SRC/$plist"
    dest="$LAUNCHDAEMONS_DIR/$plist"
    if [[ ! -f "$src" ]]; then
        echo "ERROR: expected LaunchDaemon plist missing from bundle: $src"
        exit 1
    fi
    /bin/cp "$src" "$dest"
    /bin/chmod 644 "$dest"
    /usr/sbin/chown root:wheel "$dest"
    if [[ "$NO_START" -eq 1 ]]; then
        echo "  ${plist%.plist} installed (--no-start given: not bootstrapped)."
    else
        # Idempotent: bootout (ignores error if not loaded), then bootstrap.
        /bin/launchctl bootout system "$dest" 2>/dev/null || true
        /bin/launchctl bootstrap system "$dest"
        echo "  ${plist%.plist} bootstrapped."
    fi
done

# --- Credentials / enrollment token (PAT-544) ---
echo "Provisioning credentials ..."
/usr/bin/install -d -o root -g wheel -m 700 "$CREDS_DIR"

if [[ "$ENROLLMENT_TOKEN_PROVISIONED" -eq 1 ]]; then
    echo "  Using the provisioned enrollment state."
elif [[ -n "$ENROLLMENT_TOKEN" ]]; then
    printf '%s\n' "$ENROLLMENT_TOKEN" > "$CREDS_DIR/enrollment-token.tmp"
    /bin/chmod 600 "$CREDS_DIR/enrollment-token.tmp"
    /usr/sbin/chown root:wheel "$CREDS_DIR/enrollment-token.tmp"
    /bin/mv -f "$CREDS_DIR/enrollment-token.tmp" "$CREDS_DIR/enrollment-token"
    echo "  Enrollment token written. The agent will exchange it for per-device credentials on first run."
elif [[ -f "$CREDS_DIR/bearer-token" && -f "$CREDS_DIR/hmac-secret" && -f "$CREDS_DIR/tenant-id" ]]; then
    echo "  Credentials already present in $CREDS_DIR."
else
    echo ""
    echo "  WARNING: No enrollment token and no credentials in $CREDS_DIR."
    echo "  The daemon will refuse to run until credentials are provisioned."
    echo "  Pass --enrollment-token <token> or provision credentials from the Patched admin portal."
    echo ""
fi

echo ""
echo "=== Patched Updater installed. ==="
echo "  Bundle:      $BUNDLE_DEST"
echo "  Daemons:     ${#LAUNCHDAEMONS[@]} LaunchDaemons bootstrapped in $LAUNCHDAEMONS_DIR:"
for plist in "${LAUNCHDAEMONS[@]}"; do
    echo "                 ${plist%.plist}"
done
echo "  Triggers:    $TRIGGERS_DIR  (mode 1733)"
echo "  Creds:       $CREDS_DIR"
