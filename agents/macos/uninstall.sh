#!/bin/bash
##############################################################################
# uninstall.sh — remove the interim (GitHub-Release) macOS agent install.
#
#   sudo ./uninstall.sh            # remove agent, keep credentials + queue
#   sudo ./uninstall.sh --purge    # also remove /etc/patched and the queue
#
# Mirrors install.sh. Safe to run repeatedly; missing pieces are skipped.
#
# PAT-2420: /Library/Patched is deleted recursively only if its ancestry
# verifies, exactly as install.sh verifies it before writing. If it does not,
# everything outside that path is still removed, the tree is left in place and
# named, and the exit status is 2.
##############################################################################
set -euo pipefail

# PAT-2398: runs as root, so the caller's PATH must never choose a tool. PATH is
# reset to the system directories (PAT-2394 convention; it also covers
# endpoint-uninstall.sh, started below) and every external tool in this file is
# called by its absolute system path. ci/test_privileged_installer_trust.py
# enforces both.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"

# PAT-2395: the entrypoints live in a dedicated root-owned tree. Releases before
# that installed them into /usr/local/bin, so both are cleaned up here: an
# uninstall must clean the machine it finds. Keep both in sync with install.sh.
AGENT_DIR="/Library/Patched"
LEGACY_BIN_DIR="/usr/local/bin"
ANCESTRY_ANCHOR="/"
# Modules a source-tree install copied into $LEGACY_BIN_DIR/lib. Keep in sync
# with macos/install.sh.
LEGACY_LIB_FILES=(
    agent_health.sh
    app_control.sh
    apps.sh
    auth.sh
    backup.sh
    browser_extension_control.sh
    browser_extension_removal.sh
    browser_extensions.sh
    certs.sh
    common.sh
    compliance_findings.sh
    config_profiles.sh
    filesystem.sh
    hardware.sh
    hardware_health.sh
    homebrew.sh
    ide_extensions.sh
    inventory.sh
    local_models.sh
    managed_prefs.sh
    mcp_servers.sh
    os.sh
    package_managers.sh
    safari.sh
    screensaver.sh
    sectools.sh
    security.sh
    sharing.sh
    updates.sh
    user_prefs.sh
)
DAEMON_DIR="/Library/LaunchDaemons"
CREDS_DIR="/etc/patched"
QUEUE_BASE="/var/db/patched"
COLLECT_LABEL="com.patched.collect"
UPLOAD_LABEL="com.patched.upload"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

# PAT-2420: this script ships alone as well as beside install.sh (the endpoint
# bundle carries it as macos-uninstall.sh and the decommissioner runs that copy
# on its own), so it cannot source the helpers from install.sh. The block below
# is a byte-identical copy of the one in macos/install.sh;
# ci/test_privileged_installer_trust.py fails if the two differ. Change both.
# >>> PATCHED_ANCESTRY_HELPERS_START
# Self-contained: bash 3.2, function definitions only, no globals. Tested by
# ci/test_privileged_entrypoint_ancestry.py and
# ci/test_privileged_installer_trust.py, which source this block alone.
#
# patched_ancestry_probe <path>
#   lstat (never follows a symlink). Prints "<uid> <octal permission bits>
#   <kind>", kind one of dir | symlink | other, or "- - missing".
#   The kind comes from stat's %Hp, the file-type bits of st_mode in octal
#   (S_IFDIR 040000 prints 4, S_IFLNK 0120000 prints 12). PAT-2398: it used to
#   match the English description stat prints for its long file-type format,
#   which is prose for people and was only confirmed on one macOS release.
#   Anything that is not exactly 4 or 12 reads as "other" and is refused by the
#   caller.
patched_ancestry_probe() {
    local probed="$1" fields uid mode kind
    if [ ! -e "$probed" ] && [ ! -L "$probed" ]; then
        echo "- - missing"
        return 0
    fi
    fields="$(/usr/bin/stat -f '%u %Lp %Hp' "$probed")" || return 1
    uid="${fields%% *}"
    fields="${fields#* }"
    mode="${fields%% *}"
    case "${fields#* }" in
        4)  kind="dir" ;;
        12) kind="symlink" ;;
        *)  kind="other" ;;
    esac
    echo "$uid $mode $kind"
}

# patched_ancestry_acl_listing <path>
#   Prints the numeric long listing of <path> itself with its ACL: one header
#   line, then one line per entry,
#       " <index>: <principal uuid> [inherited] allow|deny <perm>[,<perm>...]"
#   -n keeps each principal as the UUID stored in the entry instead of asking
#   the directory service for a name, -d lists the directory rather than its
#   contents, and ls does not follow a symlink given with -l.
patched_ancestry_acl_listing() {
    LC_ALL=C /bin/ls -lden -- "$1"
}

# patched_ancestry_acl_check <dir>
#   PAT-2398. Returns 0 only when no ACL entry on <dir> lets anyone but root
#   change it. Owner and mode bits say nothing about ACLs: a root-owned 0755
#   directory can still carry "user:mallory allow add_file".
#
#   Policy, deliberately the strict reading:
#   - A deny entry grants nothing and is ignored.
#   - An allow entry is trusted only when its principal is the uid 0 user,
#     matched by the fixed UUID macOS derives for uid 0, never by a name: a
#     name is whatever the directory service resolves it to. Root can already
#     do everything such an entry allows.
#   - Every other principal is untrusted, groups included. wheel and admin are
#     memberships that can be granted to accounts other than root, so a write
#     grant to either is a write grant to a non-root user.
#   - For an untrusted principal each permission must be on the read-only list
#     below (or be an inheritance flag). Anything else is refused, whether it
#     is a known write permission (add_file, add_subdirectory, delete,
#     delete_child, writeattr, writeextattr, writesecurity, chown; on a
#     directory "write" and "append" are stored as add_file and
#     add_subdirectory) or a name this function has never heard of.
#   - The order of entries is not evaluated. A write grant that a deny entry
#     currently masks is still refused; removing the deny would unmask it.
#   Fails closed: a listing that cannot be read, is empty, or contains a line
#   that is not exactly an entry is a refusal. Names what it rejected on stderr.
patched_ancestry_acl_check() {
    local checked="$1" listing line header=1 entry index body rest verb principal perms perm
    local root_uuid="FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"
    case "$checked" in
        *$'\n'*) echo "ancestry: refusing to read the ACL of a path containing a newline" >&2; return 1 ;;
    esac
    listing="$(patched_ancestry_acl_listing "$checked" 2>/dev/null)" || listing=""
    if [ -z "$listing" ]; then
        echo "ancestry: cannot read the ACL of $checked" >&2
        return 1
    fi
    while IFS= read -r line; do
        if [ "$header" -eq 1 ]; then
            header=0
            case "$line" in
                d*) continue ;;
                *) echo "ancestry: unreadable ACL listing for $checked" >&2; return 1 ;;
            esac
        fi
        case "$line" in
            " "[0-9]*": "*" "*) : ;;
            *) echo "ancestry: unreadable ACL entry on $checked: '$line'" >&2; return 1 ;;
        esac
        entry="${line# }"
        index="${entry%%: *}"
        body="${entry#*: }"
        perms="${body##* }"
        rest="${body% *}"
        verb="${rest##* }"
        principal="${rest% *}"
        case "$index" in
            ''|*[!0-9]*) echo "ancestry: unreadable ACL entry on $checked: '$line'" >&2; return 1 ;;
        esac
        # No space left to split on means the verb or the principal is missing.
        if [ "$rest" = "$body" ] || [ "$principal" = "$rest" ]; then
            echo "ancestry: unreadable ACL entry on $checked: '$line'" >&2
            return 1
        fi
        principal="${principal% inherited}"
        case "$verb" in
            deny) continue ;;
            allow) : ;;
            *) echo "ancestry: unreadable ACL entry on $checked: '$line'" >&2; return 1 ;;
        esac
        if [ "$principal" = "$root_uuid" ]; then
            continue
        fi
        rest="$perms,"
        while [ -n "$rest" ]; do
            perm="${rest%%,*}"
            rest="${rest#*,}"
            case "$perm" in
                read|list|search|execute|readattr|readextattr|readsecurity) : ;;
                file_inherit|directory_inherit|limit_inherit|only_inherit) : ;;
                *)
                    echo "ancestry: $checked carries an ACL entry allowing '$perm' to $principal, which is not root" >&2
                    return 1
                    ;;
            esac
        done
    done <<< "$listing"
    return 0
}

# patched_verify_ancestry <dir> <anchor>
#   Returns 0 only when every existing component from <anchor> down to <dir>,
#   both included, is a real directory owned by uid 0 that neither group nor
#   other can write and whose ACL passes patched_ancestry_acl_check. Components
#   that do not exist yet are accepted (a fresh install has no tree);
#   everything above them has been checked by then. Fails closed on a relative
#   path, a "." or ".." component, a <dir> outside <anchor>, or a probe or ACL
#   listing that cannot answer. Names what it rejected on stderr.
patched_verify_ancestry() {
    local dir="$1" anchor="$2" rest current component probed uid mode kind
    case "$dir" in
        /*) : ;;
        *) echo "ancestry: refusing relative path: $dir" >&2; return 1 ;;
    esac
    case "$anchor" in
        /*) : ;;
        *) echo "ancestry: refusing relative anchor: $anchor" >&2; return 1 ;;
    esac
    case "$dir/" in
        */./*|*/../*) echo "ancestry: refusing '.' or '..' component in: $dir" >&2; return 1 ;;
    esac
    anchor="${anchor%/}"
    case "$dir/" in
        "$anchor"/*) : ;;
        *) echo "ancestry: $dir is outside the anchor ${anchor:-/}" >&2; return 1 ;;
    esac
    rest="${dir#"$anchor"}"
    current="${anchor:-/}"
    while :; do
        probed="$(patched_ancestry_probe "$current")" || probed=""
        uid="${probed%% *}"
        kind="${probed##* }"
        mode="${probed#* }"
        mode="${mode%% *}"
        if [ -z "$probed" ]; then
            echo "ancestry: cannot read ownership of $current" >&2
            return 1
        fi
        if [ "$kind" = "missing" ]; then
            return 0
        fi
        if [ "$kind" != "dir" ]; then
            echo "ancestry: $current is not a real directory ($kind; a symlink or file here is untrusted)" >&2
            return 1
        fi
        if [ "$uid" != "0" ]; then
            echo "ancestry: $current is owned by uid $uid, not root" >&2
            return 1
        fi
        case "$mode" in
            ''|*[!0-7]*) echo "ancestry: unreadable mode '$mode' for $current" >&2; return 1 ;;
        esac
        if [ $(( 0$mode & 022 )) -ne 0 ]; then
            echo "ancestry: $current is group- or other-writable (mode $mode)" >&2
            return 1
        fi
        patched_ancestry_acl_check "$current" || return 1
        # Next component, skipping empty ones from doubled or trailing slashes.
        component=""
        while [ -n "$rest" ] && [ -z "$component" ]; do
            rest="${rest#/}"
            component="${rest%%/*}"
            rest="${rest#"$component"}"
        done
        if [ -z "$component" ]; then
            return 0
        fi
        current="${current%/}/$component"
    done
}
# <<< PATCHED_ANCESTRY_HELPERS_END

[ "$(/usr/bin/id -u)" -eq 0 ] || { echo "ERROR: must run as root (use sudo)." >&2; exit 1; }

# PAT-2420: decide whether $AGENT_DIR may be deleted before anything is
# removed. "rm -rf" as root follows whatever the path resolves to, so a
# component another user controls (a symlink, a directory they own or may write
# to through mode bits or an ACL) lets that user choose what root deletes.
# Refusing leaves the agent's files in place, which is the lesser harm: the
# daemons are still stopped and their plists removed below, so nothing in the
# tree is executed again, and a stale file in a directory someone else controls
# is no worse than what that person could already put there.
# Only an existing tree is checked: with nothing there, nothing would be
# deleted through the path (a machine that only ever had the legacy
# /usr/local/bin install must still uninstall cleanly).
AGENT_DIR_REFUSED=0
agent_dir_may_be_deleted() {
    if [ ! -e "$AGENT_DIR" ] && [ ! -L "$AGENT_DIR" ]; then
        return 0
    fi
    patched_verify_ancestry "$AGENT_DIR" "$ANCESTRY_ANCHOR"
}
agent_dir_may_be_deleted || AGENT_DIR_REFUSED=1

echo "==> Stopping + removing LaunchDaemons"
for label in "$COLLECT_LABEL" "$UPLOAD_LABEL"; do
    /bin/launchctl bootout "system/$label" 2>/dev/null || true
    /bin/launchctl unload "$DAEMON_DIR/$label.plist" 2>/dev/null || true
    /bin/rm -f "$DAEMON_DIR/$label.plist"
done

echo "==> Removing binaries"
# Verified a second time, immediately before the delete, so the check that
# counts is the one closest to it. A window between that check and the delete
# remains and cannot be closed from a shell script (rm takes a path, not a
# directory handle). It does not matter here: the check passed only because
# every component from / down to $AGENT_DIR is a real directory owned by root
# that nobody else can write, by mode bits or by ACL. Renaming, replacing or
# re-linking any of those names needs write access to its parent, so only root
# can change what the path resolves to inside the window, and root does not
# need this script to delete things. What is inside the tree is not checked and
# does not need to be: rm -rf unlinks a symlink it meets, it never follows one.
if [ "$AGENT_DIR_REFUSED" -eq 0 ] && agent_dir_may_be_deleted; then
    /bin/rm -rf "$AGENT_DIR"
else
    AGENT_DIR_REFUSED=1
    echo "WARN: $AGENT_DIR was NOT removed: its ancestry is untrusted (see above)." >&2
fi
# Legacy location: only the exact names the installer wrote. /usr/local/bin and
# anything else in it belong to Homebrew and are never touched. The lib
# directory is removed only if deleting our own modules leaves it empty.
/bin/rm -f "$LEGACY_BIN_DIR/patched-collect.sh" "$LEGACY_BIN_DIR/patched-upload.sh"
if [ -d "$LEGACY_BIN_DIR/lib" ] && [ ! -L "$LEGACY_BIN_DIR/lib" ]; then
    for legacy_name in "${LEGACY_LIB_FILES[@]}"; do
        /bin/rm -f "$LEGACY_BIN_DIR/lib/$legacy_name"
    done
    /bin/rmdir "$LEGACY_BIN_DIR/lib" 2>/dev/null || true
fi

# PAT-1065: the shared agent_health store (macos/lib/agent_health.sh) lives
# under /Library/Application Support/Patched — the endpoint/ update-daemon's
# STATE_DIR, not this collector's own (/var/db/patched) — because it is
# genuinely shared cross-daemon: this uploader is the only one of the two
# families that ever POSTs /v1/inventory, so it is also the sole emitter for
# faults the endpoint/ daemons recorded. Removed here unconditionally (not
# gated on --purge, matching endpoint/uninstall.sh's own unconditional
# removal of its analogous operational-state files like
# update-status.json — this is state, not user data or credentials the
# --purge/no-purge split exists to protect). A fresh install/reinstall of
# just this collector has no legitimate basis to claim ever_succeeded=true
# for a capability it has not yet verified working, and a stale `active`
# entry could misreport a fault that may no longer apply. Since the store is
# genuinely shared, running this while the endpoint/ update-daemon family
# stays installed will also reset ITS fault history — a documented,
# accepted limitation (see the identical note in endpoint/uninstall.sh),
# not a defect: the fallout is conservative (a transient
# "ever_succeeded: false" on the other family's fault for one report cycle),
# never a fabricated positive.
AGENT_HEALTH_STATE_DIR="/Library/Application Support/Patched"
/bin/rm -f "$AGENT_HEALTH_STATE_DIR/.agent-health.json"

# PAT-1065 review finding 3: an uninstall of THIS collector can run at the
# exact moment the OTHER, still-installed endpoint/ update-daemon family is
# mid-write to this same shared lock — uninstalls and normal agent operation
# are not coordinated. Force-removing the lock directory unconditionally
# could yank it out from under a live writer, and a third process racing to
# acquire it in that same window could then succeed a mkdir into space an
# active writer still believes it owns. Only remove it when it looks safely
# unused: no pid recorded, or a pid naming a process that is no longer
# running — a lock left in place here because it looked "maybe live" is a
# harmless leftover that the library's own next invocation
# (macos/lib/agent_health.sh's fuller pid + start-time + reclaim-race check)
# will clean up if it later turns out to have genuinely been stale.
if [ -d "$AGENT_HEALTH_STATE_DIR/.agent-health.lock" ]; then
    AGENT_HEALTH_UNINSTALL_PID_LINE=$(/bin/cat "$AGENT_HEALTH_STATE_DIR/.agent-health.lock/pid" 2>/dev/null || true)
    AGENT_HEALTH_UNINSTALL_PID="${AGENT_HEALTH_UNINSTALL_PID_LINE%%|*}"
    if [ -n "$AGENT_HEALTH_UNINSTALL_PID" ] && kill -0 "$AGENT_HEALTH_UNINSTALL_PID" 2>/dev/null; then
        echo "==> Left $AGENT_HEALTH_STATE_DIR/.agent-health.lock in place (pid $AGENT_HEALTH_UNINSTALL_PID appears to be actively holding it right now)"
    else
        /bin/rm -rf "$AGENT_HEALTH_STATE_DIR/.agent-health.lock"
    fi
fi

if [ "$PURGE" -eq 1 ]; then
    echo "==> Purging credentials + queue"
    /bin/rm -rf "$CREDS_DIR" "$QUEUE_BASE"
else
    echo "==> Leaving $CREDS_DIR and $QUEUE_BASE in place (use --purge to remove)."
fi

# PAT-1126: install.sh always installs the endpoint bundle alongside the
# collector now, so an uninstall run from the same release tarball should
# remove both, not just leave the endpoint daemons orphaned. Best-effort and
# non-fatal: a bare macos/-only checkout (dev, or a pre-PAT-1126 tarball) has
# no endpoint-uninstall.sh sibling and must keep working exactly as before.
# endpoint-uninstall.sh takes no arguments (it deliberately never removes
# /etc/patched — shared with this collector, and this script's own
# PURGE branch above already owns that decision).
if [ -f "$SCRIPT_DIR/endpoint-uninstall.sh" ]; then
    echo "==> Removing endpoint bundle (update + decommission daemons)"
    /bin/bash "$SCRIPT_DIR/endpoint-uninstall.sh" || \
        echo "WARN: endpoint bundle removal did not complete cleanly; see output above" >&2
fi

if [ "$AGENT_DIR_REFUSED" -ne 0 ]; then
    /bin/cat >&2 <<REFUSED
ERROR: uninstall incomplete. $AGENT_DIR and everything in it were NOT removed.
  Why: a component of that path is a symlink, is not owned by root, or can be
       written by someone other than root (mode bits or ACL); the line
       starting "ancestry:" above names it. Deleting through such a path as
       root could delete whatever that person points it at.
  Done: the LaunchDaemons were stopped and their plists removed, so nothing in
       $AGENT_DIR runs any more; the legacy entrypoints, the shared state and
       the endpoint bundle were removed as usual.
  Next: inspect the named component, restore root ownership (or remove the
       symlink or ACL entry), then run this uninstaller again.
REFUSED
    exit 2
fi

echo "==> Done. (Logs under /var/log/patched-*.log are left for inspection.)"
