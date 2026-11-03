#!/bin/bash
##############################################################################
# install.sh — interim, unsigned, GitHub-Release install path for the
#              macOS agent (collect / queue / upload).
#
# WHY THIS EXISTS
#   The signed .pkg path (Developer ID + notarisation) is gated on company
#   incorporation + an Apple Developer account. Until then we ship the same
#   unsigned shell agent via a GitHub Release tarball. Unsigned shell scripts
#   run fine when an admin executes them in a terminal (Gatekeeper only blocks
#   Finder-launched, quarantined downloads), so this is a legitimate interim
#   for machines where you control the endpoint (your own + consenting early
#   users). It is NOT a public self-service installer.
#
# WHAT IT DOES (idempotent)
#   - Verifies the ancestry of /Library/Patched (every component a real,
#     root-owned directory that group/other cannot write and that carries no
#     ACL entry letting anyone but root change it) and refuses before writing
#     anything if that does not hold (PAT-2395, PAT-2398)
#   - Installs the collector + uploader to /Library/Patched
#   - Removes the entrypoints an older release left in /usr/local/bin, once the
#     new tree is installed and the daemons point at it
#   - Installs BOTH LaunchDaemons: com.patched.collect (daily, new for this
#     path) and com.patched.upload (every 15 min)
#   - Writes tenant credentials to /etc/patched (0600, root-owned)
#   - Loads both daemons and seeds an initial collection run
#
# USAGE (run as root, from the extracted release tarball)
#   sudo ./install.sh \
#       --tenant-id   <uuid> \
#       --bearer-token <token> \
#       --hmac-secret  <base64-32-bytes>
#
#   Credentials may instead come from the environment
#   (PATCHED_TENANT_ID / PATCHED_BEARER_TOKEN / PATCHED_HMAC_SECRET),
#   from a staging directory (--creds-dir DIR holding tenant-id / bearer-token
#   / hmac-secret files), or, if a terminal is attached, interactive prompts.
#
#   Options:
#     --api-url URL     Override ingestion endpoint (default https://api.patched.im)
#     --creds-dir DIR   Read tenant-id / bearer-token / hmac-secret from DIR
#     --no-start        Install but do not load daemons or run collection
#     -h | --help       This help
##############################################################################
set -euo pipefail

# PAT-2398: this script runs as root, so the caller's PATH must never choose a
# tool. Same convention as the endpoint scripts (PAT-2394): PATH is reset to
# the system directories before anything runs, which also covers the sibling
# scripts started below. On top of that every external tool in this file is
# called by its absolute system path, so a command here does not depend on PATH
# at all. ci/test_privileged_installer_trust.py enforces both; add a tool to
# its allowlist when adding one here.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# PAT-2395 (PAT-2368 M2): the LaunchDaemons execute these entrypoints as root,
# so the directory holding them is part of the privilege boundary. A root-owned
# file inside a directory another user owns can be replaced by that user.
# /usr/local/bin is Homebrew-owned on many Macs, so the entrypoints live in a
# dedicated tree under /Library instead, and its ancestry is verified below
# before anything is written. /usr/local and /usr/local/bin are never chowned
# or chmodded here: they belong to Homebrew, not to this agent.
AGENT_DIR="/Library/Patched"
LEGACY_BIN_DIR="/usr/local/bin"
ANCESTRY_ANCHOR="/"
DAEMON_DIR="/Library/LaunchDaemons"
CREDS_DIR="/etc/patched"
QUEUE_DIR="/var/db/patched/queue"
DEFAULT_API_URL="https://api.patched.im"

COLLECT_LABEL="com.patched.collect"
UPLOAD_LABEL="com.patched.upload"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Args / inputs
# ---------------------------------------------------------------------------
TENANT_ID="${PATCHED_TENANT_ID:-}"
BEARER_TOKEN="${PATCHED_BEARER_TOKEN:-}"
HMAC_SECRET="${PATCHED_HMAC_SECRET:-}"
API_URL="${PATCHED_API_URL:-$DEFAULT_API_URL}"
CREDS_SRC_DIR=""
NO_START=0
ENROLLMENT_TOKEN="${PATCHED_ENROLLMENT_TOKEN:-}"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  $*"; }

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

usage() {
    /bin/cat <<'USAGE'
install.sh: interim unsigned GitHub-Release install for the macOS agent.

Run as root from the extracted release tarball:
  sudo ./install.sh --tenant-id <uuid> --bearer-token <token> --hmac-secret <base64>
  sudo ./install.sh --enrollment-token <token>   # PAT-544: no-MDM enrollment path

Credentials may also come from the environment (PATCHED_TENANT_ID /
PATCHED_BEARER_TOKEN / PATCHED_HMAC_SECRET / PATCHED_ENROLLMENT_TOKEN), from
--creds-dir DIR, or prompts. If enrollment.json is present alongside this script
(email-link delivery), the enrollment token is read from it automatically.

Options:
  --tenant-id UUID       Tenant identifier (legacy direct-credential path)
  --bearer-token TOK     Bearer token from POST /admin/tenants
  --hmac-secret B64      Base64-encoded 32-byte HMAC secret
  --enrollment-token TOK Single-use enrollment token (PAT-544 no-MDM path)
  --api-url URL          Ingestion endpoint (default https://api.patched.im)
  --creds-dir DIR        Read tenant-id / bearer-token / hmac-secret files from DIR
  --no-start             Install but do not load daemons or run collection
  -h, --help             This help
USAGE
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --tenant-id)        TENANT_ID="${2:-}"; shift 2 ;;
        --bearer-token)     BEARER_TOKEN="${2:-}"; shift 2 ;;
        --hmac-secret)      HMAC_SECRET="${2:-}"; shift 2 ;;
        --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
        --api-url)          API_URL="${2:-}"; shift 2 ;;
        --creds-dir)        CREDS_SRC_DIR="${2:-}"; shift 2 ;;
        --no-start)         NO_START=1; shift ;;
        -h|--help)          usage 0 ;;
        *)                  die "unknown argument: $1 (try --help)" ;;
    esac
done

# Auto-detect enrollment.json alongside the installer (email-link delivery path)
if [ -z "$ENROLLMENT_TOKEN" ] && [ -f "$SCRIPT_DIR/enrollment.json" ]; then
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

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
[ "$(/usr/bin/id -u)" -eq 0 ] || die "must run as root (use sudo)."
[ "$(/usr/bin/uname -s)" = "Darwin" ] || die "this installer is macOS-only."

# Locate the payload files (next to this script in the extracted tarball).
COLLECT_SRC="$SCRIPT_DIR/patched-collect.sh"
UPLOAD_SRC="$SCRIPT_DIR/patched-upload.sh"
COLLECT_PLIST_SRC="$SCRIPT_DIR/com.patched.collect.plist"
UPLOAD_PLIST_SRC="$SCRIPT_DIR/com.patched.upload.plist"
# PAT-1126: endpoint-install.sh is required too — checked here, before
# anything is written to disk, so a tarball missing it refuses cleanly
# rather than partially installing a collector-only box and dying midway.
# Collector-only is no longer a supported end state: a Mac with no
# endpoint bundle has no expiry/decommission mechanism at all.
ENDPOINT_INSTALL_SRC="$SCRIPT_DIR/endpoint-install.sh"
for f in "$COLLECT_SRC" "$UPLOAD_SRC" "$COLLECT_PLIST_SRC" "$UPLOAD_PLIST_SRC"; do
    [ -f "$f" ] || die "missing payload file: $f (run from the extracted release tarball)."
done
[ -f "$ENDPOINT_INSTALL_SRC" ] || die "endpoint-install.sh missing from this release (PAT-1126: collector-only installs are no longer supported). Re-download a current release tarball."

# PAT-2395: verify the entrypoint tree's ancestry before the first write. An
# existing $AGENT_DIR is checked too: one that is a symlink, owned by anyone
# but root, or carrying an ACL that lets anyone but root change it (PAT-2398)
# is refused rather than repaired, because nothing legitimate creates it that
# way and its contents cannot be trusted afterwards. A refusal here
# leaves any earlier install (including one still in $LEGACY_BIN_DIR) exactly
# as it was.
patched_verify_ancestry "$AGENT_DIR" "$ANCESTRY_ANCHOR" \
    || die "refusing to install: the ancestry of $AGENT_DIR is untrusted (see above). Nothing was written."

# Pull credentials from a staging dir if asked.
if [ -n "$CREDS_SRC_DIR" ]; then
    [ -d "$CREDS_SRC_DIR" ] || die "--creds-dir not a directory: $CREDS_SRC_DIR"
    [ -z "$TENANT_ID" ]    && [ -f "$CREDS_SRC_DIR/tenant-id" ]    && TENANT_ID="$(/usr/bin/head -1 "$CREDS_SRC_DIR/tenant-id" | /usr/bin/tr -d '[:space:]')"
    [ -z "$BEARER_TOKEN" ] && [ -f "$CREDS_SRC_DIR/bearer-token" ] && BEARER_TOKEN="$(/usr/bin/head -1 "$CREDS_SRC_DIR/bearer-token" | /usr/bin/tr -d '[:space:]')"
    [ -z "$HMAC_SECRET" ]  && [ -f "$CREDS_SRC_DIR/hmac-secret" ]  && HMAC_SECRET="$(/usr/bin/head -1 "$CREDS_SRC_DIR/hmac-secret" | /usr/bin/tr -d '[:space:]')"
fi

# Interactive fallback (only if a TTY is attached).
prompt_if_empty() {
    # $1 = current value, $2 = prompt label, $3 = 1 for secret
    local cur="$1" label="$2" secret="$3" val=""
    if [ -n "$cur" ]; then printf '%s' "$cur"; return; fi
    if [ ! -t 0 ]; then printf ''; return; fi
    if [ "$secret" = "1" ]; then
        read -r -s -p "  $label: " val >&2; echo >&2
    else
        read -r -p "  $label: " val >&2
    fi
    printf '%s' "$val"
}

# Enrollment-token path (PAT-544): skip raw-credential prompts/validation
if [ -z "$ENROLLMENT_TOKEN" ]; then
    TENANT_ID="$(prompt_if_empty "$TENANT_ID" "Tenant ID (UUID)" 0)"
    BEARER_TOKEN="$(prompt_if_empty "$BEARER_TOKEN" "Bearer token" 1)"
    HMAC_SECRET="$(prompt_if_empty "$HMAC_SECRET" "HMAC secret (base64)" 1)"

    [ -n "$TENANT_ID" ]    || die "tenant-id is required (--tenant-id / PATCHED_TENANT_ID / --creds-dir / --enrollment-token)."
    [ -n "$BEARER_TOKEN" ] || die "bearer-token is required (or use --enrollment-token)."
    [ -n "$HMAC_SECRET" ]  || die "hmac-secret is required (or use --enrollment-token)."

    # Validate shapes (warn, don't hard-fail — formats may evolve).
    case "$TENANT_ID" in
        [0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*) : ;;
        *) echo "WARN: tenant-id does not look like a UUID: $TENANT_ID" >&2 ;;
    esac
    HMAC_BYTES="$(printf '%s' "$HMAC_SECRET" | /usr/bin/base64 -D 2>/dev/null | /usr/bin/wc -c | /usr/bin/tr -d ' ' || true)"
    if [ "$HMAC_BYTES" != "32" ]; then
        echo "WARN: hmac-secret base64-decodes to ${HMAC_BYTES:-0} bytes (expected 32). Continuing." >&2
    fi
fi

echo "==> Installing patched.im macOS agent (interim unsigned build)"
info "API endpoint : $API_URL"
if [ -n "$ENROLLMENT_TOKEN" ]; then
    info "Mode         : enrollment token (per-device credentials on first run)"
else
    info "Tenant ID    : $TENANT_ID"
fi

# ---------------------------------------------------------------------------
# Install binaries
# ---------------------------------------------------------------------------
echo "==> Installing collector + uploader to $AGENT_DIR"
/usr/bin/install -d -m 0755 -o root -g wheel "$AGENT_DIR"
# Verify again now that the tree exists, so the entrypoints are only ever
# written into a directory this run has seen to be root-owned and unwritable
# by anyone else.
patched_verify_ancestry "$AGENT_DIR" "$ANCESTRY_ANCHOR" \
    || die "refusing to install: $AGENT_DIR did not verify after creation (see above)."
/usr/bin/install -m 0755 -o root -g wheel "$COLLECT_SRC" "$AGENT_DIR/patched-collect.sh"
/usr/bin/install -m 0755 -o root -g wheel "$UPLOAD_SRC"  "$AGENT_DIR/patched-upload.sh"

# A source-tree patched-collect.sh sources its modules from LIB_DIR=
# "$SCRIPT_DIR/lib" and needs them copied alongside it. A release-built
# patched-collect.sh (via tools/build-bundle.sh) has lib/*.sh inlined
# directly into the script — no lib/ directory ships in that tarball at
# all, so unconditionally requiring it here broke every release install
# (install(1) fails on a nonexistent glob with no matches). Only copy
# lib/ when it's actually present next to install.sh.
if [ -d "$SCRIPT_DIR/lib" ]; then
    /usr/bin/install -d -m 0755 -o root -g wheel "$AGENT_DIR/lib"
    patched_verify_ancestry "$AGENT_DIR/lib" "$ANCESTRY_ANCHOR" \
        || die "refusing to install: $AGENT_DIR/lib did not verify after creation (see above)."
    /usr/bin/install -m 0644 -o root -g wheel "$SCRIPT_DIR"/lib/*.sh "$AGENT_DIR/lib/"
fi

# ---------------------------------------------------------------------------
# Credentials / enrollment token (PAT-544)
# ---------------------------------------------------------------------------
echo "==> Provisioning credentials in $CREDS_DIR (0600, root-owned)"
/usr/bin/install -d -m 0700 -o root -g wheel "$CREDS_DIR"
umask 077
if [ -n "$ENROLLMENT_TOKEN" ]; then
    printf '%s\n' "$ENROLLMENT_TOKEN" > "$CREDS_DIR/enrollment-token"
    /bin/chmod 600 "$CREDS_DIR/enrollment-token"
    /usr/sbin/chown root:wheel "$CREDS_DIR/enrollment-token"
    info "Enrollment token written. The agent will exchange it for per-device credentials on first run."
else
    printf '%s\n' "$TENANT_ID"    > "$CREDS_DIR/tenant-id"
    printf '%s\n' "$BEARER_TOKEN" > "$CREDS_DIR/bearer-token"
    printf '%s\n' "$HMAC_SECRET"  > "$CREDS_DIR/hmac-secret"
    /bin/chmod 600 "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret
    /usr/sbin/chown root:wheel "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret
fi

# Queue dir
/usr/bin/install -d -m 0700 -o root -g wheel "$QUEUE_DIR"

# ---------------------------------------------------------------------------
# LaunchDaemons
# ---------------------------------------------------------------------------
echo "==> Installing LaunchDaemons"
/usr/bin/install -m 0644 -o root -g wheel "$COLLECT_PLIST_SRC" "$DAEMON_DIR/$COLLECT_LABEL.plist"
/usr/bin/install -m 0644 -o root -g wheel "$UPLOAD_PLIST_SRC"  "$DAEMON_DIR/$UPLOAD_LABEL.plist"

# Persist a non-default API URL into the uploader daemon's environment.
if [ "$API_URL" != "$DEFAULT_API_URL" ]; then
    info "Pinning custom API URL into $UPLOAD_LABEL.plist"
    /usr/libexec/PlistBuddy -c "Delete :EnvironmentVariables" "$DAEMON_DIR/$UPLOAD_LABEL.plist" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Add :EnvironmentVariables dict" "$DAEMON_DIR/$UPLOAD_LABEL.plist"
    /usr/libexec/PlistBuddy -c "Add :EnvironmentVariables:PATCHED_API_URL string $API_URL" "$DAEMON_DIR/$UPLOAD_LABEL.plist"
fi

load_daemon() {
    # $1 = label, $2 = plist path. Reload cleanly; modern API w/ legacy fallback.
    local label="$1" plist="$2"
    /bin/launchctl bootout "system/$label" 2>/dev/null || true
    if ! /bin/launchctl bootstrap system "$plist" 2>/dev/null; then
        /bin/launchctl unload "$plist" 2>/dev/null || true
        /bin/launchctl load -w "$plist" || die "failed to load $label"
    fi
}

if [ "$NO_START" -eq 1 ]; then
    echo "==> --no-start given: daemons installed but not loaded."
else
    echo "==> Loading daemons"
    load_daemon "$UPLOAD_LABEL"  "$DAEMON_DIR/$UPLOAD_LABEL.plist"
    load_daemon "$COLLECT_LABEL" "$DAEMON_DIR/$COLLECT_LABEL.plist"

    echo "==> Seeding an initial collection run"
    # RunAtLoad already fires this; kickstart guarantees a fresh run now.
    /bin/launchctl kickstart -k "system/$COLLECT_LABEL" 2>/dev/null || \
        "$AGENT_DIR/patched-collect.sh" || \
        echo "WARN: initial collection run did not complete cleanly; check /var/log/patched-collect.log" >&2
fi

# ---------------------------------------------------------------------------
# Retire the legacy entrypoints (PAT-2395)
# ---------------------------------------------------------------------------
# Releases before PAT-2395 installed the entrypoints into $LEGACY_BIN_DIR. This
# runs only now: the new tree is verified and populated and the LaunchDaemon
# plists on disk name it, so a failure anywhere above leaves the old install
# working. Only the exact names this installer wrote are removed. The directory
# itself, and everything else in it, belongs to Homebrew and is left alone.
#
# Keep LEGACY_LIB_FILES in sync with macos/uninstall.sh.
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
LEGACY_PRESENT=0
for legacy_name in patched-collect.sh patched-upload.sh; do
    if [ -e "$LEGACY_BIN_DIR/$legacy_name" ] || [ -L "$LEGACY_BIN_DIR/$legacy_name" ]; then
        LEGACY_PRESENT=1
    fi
done
if [ "$LEGACY_PRESENT" -eq 1 ]; then
    echo "==> Removing legacy entrypoints from $LEGACY_BIN_DIR"
    if [ "$NO_START" -eq 1 ]; then
        # The daemons were not reloaded above, so a job loaded by the older
        # release still names the legacy path. Removing the file under it would
        # leave a root job pointing at a name the directory's owner can
        # recreate, so stop those jobs. They start from the new plists at the
        # next boot or explicit load.
        for legacy_label in "$COLLECT_LABEL" "$UPLOAD_LABEL"; do
            /bin/launchctl bootout "system/$legacy_label" 2>/dev/null || true
        done
    fi
    /bin/rm -f "$LEGACY_BIN_DIR/patched-collect.sh" "$LEGACY_BIN_DIR/patched-upload.sh"
fi
# A source-tree install also copied lib/*.sh into $LEGACY_BIN_DIR/lib. Remove
# those files by name and drop the directory only if that leaves it empty; a
# generic "lib" under /usr/local/bin may hold someone else's files.
if [ -d "$LEGACY_BIN_DIR/lib" ] && [ ! -L "$LEGACY_BIN_DIR/lib" ]; then
    for legacy_name in "${LEGACY_LIB_FILES[@]}"; do
        /bin/rm -f "$LEGACY_BIN_DIR/lib/$legacy_name"
    done
    /bin/rmdir "$LEGACY_BIN_DIR/lib" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Endpoint bundle (decommission-capable) — PAT-1126
# ---------------------------------------------------------------------------
# A macOS box running only the collector has no expiry/decommission
# mechanism at all: it never sees a decommission directive and never
# self-removes. This matters most for Endpoint Assurance assessment
# installs, which are supposed to expire cleanly after 2-4 weeks.
# Collector-only therefore stopped being a supported end state — every
# macOS install must also install the endpoint/ bundle, whose
# com.patched.config-poll LaunchDaemon is what polls agent-config and picks
# up a decommission directive (see endpoint/patched-fetch-config.sh).
#
# The release tarball (macos-agent-release.yml) always ships
# endpoint-install.sh + patched-updater/ alongside this script now (already
# verified present in the Pre-flight section above). A tarball missing them
# is not a supported release: fail closed rather than silently produce a
# decommission-incapable install.
#
# macos/test-install-endpoint-bundling.zsh runs this whole script (root/
# launchctl/python3 stubbed, same convention as macos/test-uninstall-*.zsh)
# against a real endpoint-install.sh built by tools/build-bundle.sh, and
# proves: missing endpoint-install.sh refuses before writing anything;
# present, it is invoked with --enrollment-token / --no-start threaded
# through exactly as resolved above; its LaunchDaemons end up copied into
# the (stubbed) LaunchDaemons dir.
echo "==> Installing endpoint bundle (decommission + update daemons)"
unset PATCHED_ENROLLMENT_TOKEN
ENDPOINT_INSTALL_ARGS=()
[ -n "$ENROLLMENT_TOKEN" ] && ENDPOINT_INSTALL_ARGS+=(--enrollment-token-provisioned)
[ "$NO_START" -eq 1 ] && ENDPOINT_INSTALL_ARGS+=(--no-start)
# Real macOS ships /bin/bash 3.2 (Apple froze it pre-GPLv3) — under `set -u`,
# bash 3.2 treats "${ARR[@]}" on a zero-element array as an unbound-variable
# error, not an empty expansion (fixed in bash 4.4+). The
# ${ARR[@]+"${ARR[@]}"} idiom below is the portable workaround: it only
# expands the array when it has at least one element, so an empty
# ENDPOINT_INSTALL_ARGS (the common case — no enrollment token, no
# --no-start) doesn't abort this script on real hardware.
/bin/bash "$ENDPOINT_INSTALL_SRC" ${ENDPOINT_INSTALL_ARGS[@]+"${ENDPOINT_INSTALL_ARGS[@]}"} || die "endpoint bundle install failed (see output above): aborting rather than leaving a decommission-incapable install."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
/bin/cat <<EOF

==> Done.

Installed:
  $AGENT_DIR/patched-collect.sh
  $AGENT_DIR/patched-upload.sh
  $DAEMON_DIR/$COLLECT_LABEL.plist   (collect: at load + daily)
  $DAEMON_DIR/$UPLOAD_LABEL.plist    (upload: every 15 min)
  $CREDS_DIR/{tenant-id,bearer-token,hmac-secret}
  /usr/local/patched-updater/        (endpoint bundle: update + decommission daemons; see above)

Verify:
  sudo launchctl list | grep com.patched
  sudo ls -lht $QUEUE_DIR
  tail -n 40 /var/log/patched-collect.log
  tail -n 40 /var/log/patched-upload.log

Uninstall:
  sudo ./uninstall.sh
EOF
