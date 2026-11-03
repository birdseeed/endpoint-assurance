# ide_extensions.sh — IDE extensions and plugins for every local user (PAT-2017).
#
# Sourced by patched-collect.sh; not executable directly.
# Requires: PATCHED_TMPDIR, PYTHON3 (set by main script before sourcing)
#
# WHAT THIS READS, AND ONLY THIS. For every home directory directly under
# _IDE_USERS_ROOT (/Users, skipping Shared, Guest and dot entries):
#   VS Code family, one directory per editor:
#     .vscode/extensions            VS Code
#     .vscode-insiders/extensions   VS Code Insiders
#     .cursor/extensions            Cursor
#     .windsurf/extensions          Windsurf
#   In each: extensions.json (the editor's own list of installed extensions).
#   When that file is missing, unreadable or does not parse, each extension
#   folder's package.json manifest instead, skipping folders the editor has
#   listed in .obsolete for deletion.
#   JetBrains, one directory per product and version:
#     Library/Application Support/JetBrains/<Product><YYYY.N>/plugins
#   Each plugin is a folder (plugin.xml unpacked at META-INF/plugin.xml, or
#   inside one of the jars in lib/) or a single jar. plugin.xml is read from
#   inside the jar as a zip member, never extracted to disk, and parsed only
#   after refusing any DTD, so no entity can be expanded or fetched.
#   <Product><YYYY.N>/disabled_plugins.txt says which plugins are switched off.
#
# READ ONLY. No editor is launched, nothing is written in the user's tree and
# nothing touches the network. test-ide-extensions.zsh carries a static guard
# that goes red if this file gains a process launch or a network client.
#
# EVERY TREE HERE IS OWNED BY AN ORDINARY USER AND THIS RUNS AS ROOT. So
# nothing is followed that the user could point somewhere else: every file is
# opened O_NOFOLLOW|O_NONBLOCK and must be a regular file with a single link,
# under a size cap; every directory level is checked with lstat and never
# entered when it is a symlink. A planted symlink, hard link or FIFO costs one
# entry (marked partial), never a read of a root-only file or a hung
# collector. Every string that leaves the device has control characters
# refused and any URL userinfo removed.
#
# The lstat checks decide what is reported; the walk is what keeps a read in
# the tree. Every open starts at / and opens each directory relative to the
# one before with O_NOFOLLOW, so a directory swapped for a symlink between its
# check and the read is refused as well (PAT-2033).
#
# ABSENCE REQUIRES AUTHORITY (PAT-1710). collection_status, overall, per user
# and per editor profile, is one of:
#   complete     everything found was read in full
#   partial      something was read but not everything (an unreadable or
#                corrupt manifest, a symlink not followed, the 5,000-extension
#                or 30-second bound): the list is what was seen, not all there is
#   not_present  every home was read and no supported editor has an
#                extensions directory in any of them; a genuine reading, so an
#                empty list is sent
#   failed       nothing trustworthy was read: the extensions list is OMITTED,
#                never sent as [], so a failed read can never look like "none"
#
# PRIVACY PROTECTION (TCC, PAT-2100). Root without Full Disk Access may lstat
# ~/Library/Application Support/JetBrains but open() fails with EPERM. That is
# the issue code tcc_denied, not unreadable; it is still a refusal like any
# other (nothing under it is read, and the profile or user is failed or
# partial, never not_present or complete). The parser's summary line starting
# "tcc <count> <denied|reached|unknown>" (by prefix) feeds patched_tcc_health
# (common.sh), which writes or clears the agent_health entry tcc_denied /
# ide_extensions / full_disk_access_missing from the LaunchDaemon run only, as
# browser_extensions.sh does (PAT-2096).
#
# ON THE WIRE since PAT-2225 (2026-09-28). _IDE_EXTENSIONS_PAYLOAD_ON_WIRE=1
# makes ide_extensions_payload_member emit the block into the inventory
# payload, which the platform (PAT-2021) validates and ingests. The block is
# sent only within the _IDE_MAX_BYTES budget below; past it the block is sent
# as failed (patched_block_within_budget, common.sh). Setting the constant
# back to 0 is the whole off switch; test-ide-extensions.zsh asserts it is 1
# and still exercises the off path, so changing it must update that test in
# the same change.

_IDE_EXTENSIONS_PAYLOAD_ON_WIRE=1

# Where home directories live. Tests reassign this after sourcing.
# ASSUMPTION: local accounts' homes are the directories directly under /Users
# (the macOS default, and what browser_extensions.sh walks). A home relocated
# elsewhere by NFSHomeDirectory, or a network home, is not seen. Likewise the
# per-user JetBrains location below is the documented default,
# ~/Library/Application Support/JetBrains/<Product><YYYY.N>; a custom
# idea.config.path or idea.plugins.path in idea.properties is not followed.
_IDE_USERS_ROOT=/Users

# Bounds (PAT-2017). Past either, collection stops and is marked partial.
_IDE_MAX_EXTENSIONS=5000
_IDE_TIME_BUDGET_SECONDS=30
# The parser checks its own budget between entries; this is the outer limit
# for a read that blocks inside one syscall. Past it the parser is killed and
# the block is failed.
_IDE_HARD_TIMEOUT_SECONDS=45
# Byte budget for the serialised block (PAT-2225), about 1,000 extensions at
# the ~500 bytes a real row takes. The four tooling blocks together stay
# within 2 MiB, as the homebrew block does, so the two leave 2 MiB of the
# server's 6 MiB inventory body cap for everything else. Past the budget the
# block is sent as failed, never cut down: the platform's tooling contract
# has no size_limit reason. Tests lower it after sourcing.
_IDE_MAX_BYTES=$(( 512 * 1024 ))

# ide_extensions_collection_status
#   Prints the wire value. Anything but the four known values is failed.
ide_extensions_collection_status() {
    case "${IDE_EXTENSIONS_COLLECTION_STATUS:-}" in
        complete|partial|not_present) print -r -- "$IDE_EXTENSIONS_COLLECTION_STATUS" ;;
        *) print -r -- "failed" ;;
    esac
}

# ide_extensions_payload_member
#   Prints `"ide_extensions": {...},` for the payload heredoc, or nothing when
#   the wire flag is 0 (see header). A failed status with no written block
#   sends only {"collection_status":"failed"}.
ide_extensions_payload_member() {
    (( _IDE_EXTENSIONS_PAYLOAD_ON_WIRE )) || return 0
    if [[ "$(ide_extensions_collection_status)" == "failed" ]] \
        || [[ -z "${IDE_EXTENSIONS_JSON_TMP:-}" || ! -s "$IDE_EXTENSIONS_JSON_TMP" ]]; then
        printf '"ide_extensions": {"collection_status": "failed"},'
        return 0
    fi
    printf '"ide_extensions": %s,' "$(cat "$IDE_EXTENSIONS_JSON_TMP")"
}

collect_ide_extensions() {
    IDE_EXTENSIONS_COLLECTION_STATUS="failed"
    IDE_EXTENSIONS_COUNT=0
    IDE_EXTENSIONS_PROFILE_COUNT=0
    IDE_EXTENSIONS_USER_COUNT=0
    # Reuse the caller's placeholder file if it made one, so it is not orphaned.
    if [[ -z "${IDE_EXTENSIONS_JSON_TMP:-}" || ! -f "$IDE_EXTENSIONS_JSON_TMP" ]]; then
        IDE_EXTENSIONS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/ide-extensions.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    fi
    printf '{"collection_status": "failed"}' > "$IDE_EXTENSIONS_JSON_TMP"

    local _ie_out _ie_summary _ie_err _ie_pid _ie_rc=0 _ie_ticks=0 _ie_line
    local -a _ie_fields
    _ie_out=$(mktemp "$PATCHED_TMPDIR/ide-extensions-out.XXXXXX")
    _ie_summary=$(mktemp "$PATCHED_TMPDIR/ide-extensions-summary.XXXXXX")
    _ie_err=$(mktemp "$PATCHED_TMPDIR/ide-extensions-err.XXXXXX")

    # The program arrives on stdin through the heredoc, so every input is an
    # argv entry, never piped (see the python3 heredoc footgun in AGENTS.md).
    "$PYTHON3" - "$_ie_out" "$_IDE_MAX_EXTENSIONS" "$_IDE_TIME_BUDGET_SECONDS" \
        "$_IDE_USERS_ROOT" > "$_ie_summary" 2> "$_ie_err" <<'PYEOF' &
import datetime
import errno
import json
import os
import re
import stat
import sys
import time
import xml.etree.ElementTree as ElementTree
import zipfile

out_path = sys.argv[1]
max_extensions = int(sys.argv[2])
budget = float(sys.argv[3])
users_root = os.path.normpath(sys.argv[4])
deadline = time.monotonic() + budget

JSON_CAP = 8 * 1024 * 1024          # extensions.json with every metadata field
MANIFEST_CAP = 1024 * 1024          # one package.json
PLUGIN_XML_CAP = 2 * 1024 * 1024    # plugin.xml, unpacked or uncompressed in a jar
JAR_CAP = 256 * 1024 * 1024         # a jar is opened for its zip directory only
DISABLED_CAP = 256 * 1024
TEXT_CAP = 512
MAX_USERS = 500
MAX_JARS_PER_PLUGIN = 200
MAX_ISSUES = 50
SKIP_HOMES = {"Shared", "Guest"}

VSCODE_EDITORS = (
    ("vscode", ".vscode"),
    ("vscode_insiders", ".vscode-insiders"),
    ("cursor", ".cursor"),
    ("windsurf", ".windsurf"),
)
JETBRAINS_BASE = ("Library", "Application Support", "JetBrains")
JETBRAINS_PRODUCT_RE = re.compile(r"^([A-Za-z][A-Za-z-]*?)(\d{4}\.\d+)$")


class Stop(Exception):
    pass


class Abort(Exception):
    """A directory could not be read; the caller records it and moves on.
    Abort("recorded") means the issue has already been written."""


# tcc_denied and unreached count every refusal, past the MAX_ISSUES cap on
# the issues list, for the agent_health verdict (PAT-2100).
state = {"truncated": False, "reason": None, "issues": [], "count": 0, "tcc_denied": set(), "unreached": 0}


def clean_path(p):
    return p if isinstance(p, str) and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in p) else "<unprintable>"


def issue(code, where):
    if len(state["issues"]) < MAX_ISSUES:
        state["issues"].append({"code": code, "path": clean_path(where)})


def check_time():
    if time.monotonic() > deadline:
        state["truncated"] = True
        state["reason"] = state["reason"] or "time_limit"
        raise Stop()


USERINFO_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s]*@")


def clean_text(value, cap=TEXT_CAP):
    """value if it is safe to put on the wire as text, else None: a non-empty
    str, no control characters, no longer than cap, with any URL userinfo
    (user:password@) removed wherever it appears."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > cap:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return USERINFO_RE.sub(r"\1", value)


def iso_ms(ms):
    if isinstance(ms, bool) or not isinstance(ms, (int, float)) or ms <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def as_bool(value):
    return value if isinstance(value, bool) else None


# Every read goes through open_parent: each directory on the way down is
# opened relative to the one above it with O_NOFOLLOW, so there is never a path
# for a user to swap for a symlink between a check and a use (PAT-2033). The
# lstat checks callers make first decide what to report; they are not what
# keeps a read inside the tree.
DIR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_LINK_HOPS = 32
# The links under / that the walk follows, each with the text macOS gives it.
SYSTEM_LINKS = {"tmp": "private/tmp", "var": "private/var", "etc": "private/etc"}


class LinkRefused(OSError):
    """A directory on the way down is a symlink the walk does not follow."""


def open_parent(path):
    """(fd, name): an open descriptor for the directory holding the last
    component of the absolute path, and that component's name. The caller
    closes fd. The only symlinks followed on the way down are the system's
    own /tmp, /var and /etc, right under /, root's, and pointing where macOS
    points them (SYSTEM_LINKS); any other raises LinkRefused. Ownership and
    mode bits cannot say who may replace a link, because a macOS ACL can
    grant that without them, so the rule is an allowlist (PAT-2040). A
    missing directory or a file where a directory should be raises
    FileNotFoundError or NotADirectoryError, anything else OSError."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise OSError("not an absolute path")
    head, _, name = path.rpartition("/")
    if name in ("", ".", ".."):
        raise OSError("no final component")
    todo = [p for p in reversed(head.split("/")) if p not in ("", ".")]
    stack = [os.open("/", DIR_FLAGS)]
    hops = 0
    try:
        while todo:
            part = todo.pop()
            if part == "..":
                if len(stack) > 1:
                    os.close(stack.pop())
                continue
            try:
                stack.append(os.open(part, DIR_FLAGS, dir_fd=stack[-1]))
                continue
            except OSError as err:
                failure = err
            # macOS reports an O_NOFOLLOW|O_DIRECTORY open of a symlink as
            # ENOTDIR, the same as a regular file, so lstat tells them apart:
            # a symlink must never read as "absent".
            try:
                link = os.lstat(part, dir_fd=stack[-1])
            except OSError:
                raise failure
            if not stat.S_ISLNK(link.st_mode):
                raise failure
            if (hops >= MAX_LINK_HOPS or len(stack) != 1 or part not in SYSTEM_LINKS
                    or link.st_uid != 0):
                raise LinkRefused("symlink not followed")
            target = os.readlink(part, dir_fd=stack[-1])
            if target != SYSTEM_LINKS[part]:
                raise LinkRefused("symlink not followed")
            hops += 1
            if target.startswith("/"):
                while len(stack) > 1:
                    os.close(stack.pop())
            todo.extend(p for p in reversed(target.split("/")) if p not in ("", "."))
        return stack.pop(), name
    finally:
        for fd in stack:
            os.close(fd)


def lstat_at(path):
    """os.stat_result of the last component itself, never following it.
    Raises as open_parent does."""
    fd, name = open_parent(path)
    try:
        return os.lstat(name, dir_fd=fd)
    finally:
        os.close(fd)


def read_link(path):
    """The text of the symlink at path, never followed. Raises OSError."""
    fd, name = open_parent(path)
    try:
        return os.readlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def open_dir(path):
    """A descriptor for the directory at path; a symlink there, or on the way
    down, is refused. Raises OSError. The caller closes it."""
    fd, name = open_parent(path)
    try:
        return os.open(name, DIR_FLAGS, dir_fd=fd)
    finally:
        os.close(fd)


def open_regular_errno(path, cap):
    """(status, fd, errno): status is open, missing or unreadable. Never
    follows a symlink, never blocks on a FIFO, refuses anything but a regular
    file with one link and at most cap bytes. The caller closes fd. errno is
    the failing call's errno for an unreadable file that could not be opened
    or statted (EPERM: macOS privacy protection, PAT-2096), else None; a file
    refused for its type, links or size carries None."""
    # O_NONBLOCK is deliberate: opening a FIFO for read blocks until a writer
    # appears, so without it a planted FIFO would hang the collector before the
    # fstat S_ISREG check below could refuse it.
    try:
        dir_fd, name = open_parent(path)
    except (FileNotFoundError, NotADirectoryError):
        return "missing", None, None
    except OSError as err:
        return "unreadable", None, err.errno
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        return "missing", None, None
    except OSError as err:
        return "unreadable", None, err.errno
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
    except OSError as err:
        os.close(fd)
        return "unreadable", None, err.errno
    # A hard link to a file the user cannot read is still a regular file that
    # O_NOFOLLOW opens, so more than one link is refused like a symlink.
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > cap:
        os.close(fd)
        return "unreadable", None, None
    return "open", fd, None


def open_regular(path, cap):
    """(status, fd): open_regular_errno without the errno."""
    return open_regular_errno(path, cap)[:2]


def read_file_errno(path, cap):
    """(status, bytes, errno): status is read, missing or unreadable; errno
    as open_regular_errno gives it, or a failed read's."""
    status, fd, err_no = open_regular_errno(path, cap)
    if status != "open":
        return status, None, err_no
    try:
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                return "unreadable", None, None
            chunks.append(chunk)
        return "read", b"".join(chunks), None
    except OSError as err:
        return "unreadable", None, err.errno
    finally:
        os.close(fd)


def read_file(path, cap):
    """(status, bytes): read_file_errno without the errno."""
    return read_file_errno(path, cap)[:2]


def lstat_kind(path):
    """(kind, errno). kind is absent, dir, symlink, file, other or error, from
    lstat (never follows); a symlink the walk refuses on the way down is
    error, never absent. errno is the failing call's errno when kind is error
    (None for a refused link), else None. The errno only names the failure:
    EPERM here is macOS privacy protection (TCC) denying root a directory it
    may lstat but not open, which callers can report as such (PAT-2096)."""
    try:
        st = lstat_at(path)
    except FileNotFoundError:
        return "absent", None
    except NotADirectoryError:
        return "absent", None
    except OSError as err:
        return "error", err.errno
    if stat.S_ISLNK(st.st_mode):
        return "symlink", None
    if stat.S_ISDIR(st.st_mode):
        return "dir", None
    if stat.S_ISREG(st.st_mode):
        return "file", None
    return "other", None


def kind(path):
    """absent, dir, symlink, file, other or error: lstat_kind without the
    errno."""
    return lstat_kind(path)[0]


def list_dir(path, hidden=False):
    """Sorted (name, kind) never following a symlink; an entry whose type
    cannot be read is "error", never dropped. Raises Abort when the directory
    itself cannot be listed, with the OSError as its __cause__ so a caller can
    read the errno (PAT-2096); Abort's own args stay empty."""
    try:
        fd = open_dir(path)
    except OSError as err:
        raise Abort() from err
    try:
        with os.scandir(fd) as it:
            rows = []
            for entry in it:
                if not hidden and entry.name.startswith("."):
                    continue
                try:
                    if entry.is_symlink():
                        k = "symlink"
                    elif entry.is_dir(follow_symlinks=False):
                        k = "dir"
                    elif entry.is_file(follow_symlinks=False):
                        k = "file"
                    else:
                        k = "other"
                except OSError:
                    k = "error"
                rows.append((entry.name, k))
            return sorted(rows)
    except OSError as err:
        raise Abort() from err
    finally:
        os.close(fd)


def denied_code(err_no, denied):
    """The issue code for a path that could not be read: tcc_denied when the
    errno is EPERM, else unreadable (PAT-2100, as PAT-2096 did for browser
    extensions). As root, EPERM here is macOS privacy protection (TCC): without
    Full Disk Access, root may lstat another app's data folder
    (~/Library/Application Support/JetBrains) but not open it. Either way nothing
    under it is read and the user is not complete. Any errno counts toward the
    agent_health verdict. denied is the folder or file that could not be
    opened; the count is of unique ones, so one denied folder above several
    configs counts once, as browser_extensions.sh counts unique refused paths."""
    if err_no == errno.EPERM:
        state["tcc_denied"].add(denied)
        return "tcc_denied"
    if err_no is not None:
        state["unreached"] += 1
    return "unreadable"


def abort_code(abort, where):
    """denied_code for the OSError list_dir raised Abort from, listing where:
    where itself is the folder that could not be opened."""
    return denied_code(getattr(abort.__cause__, "errno", None), where)


def code_for(k, err_no=None, where=None):
    """The issue code for a path whose lstat kind is not what was wanted.
    err_no is lstat_kind's errno for an error kind. Every caller has checked
    each folder above where on the way down, so an lstat of where that fails
    failed opening the folder holding it: that folder is what was denied."""
    code = {"symlink": "symlink_not_followed", "other": "not_regular"}.get(k)
    return code or denied_code(err_no, os.path.dirname(where) if where else None)


def refused(k, where, pstate, err_no=None):
    """Record an entry that is not what it should be and mark partial."""
    pstate["partial"] = True
    issue(code_for(k, err_no, where), where)


def parse_json(status, data):
    if status != "read":
        return status, None
    try:
        return "read", json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return "unparseable", None


def take_slot():
    if state["count"] >= max_extensions:
        state["truncated"] = True
        state["reason"] = state["reason"] or "extension_limit"
        raise Stop()
    state["count"] += 1


def entry(profile, **fields):
    row = {
        "user": profile["user"],
        "user_id": profile["user_id"],
        "family": profile["family"],
        "editor": profile["editor"],
        "editor_version": profile["editor_version"],
        "id": None,
        "name": None,
        "publisher": None,
        "publisher_display_name": None,
        "version": None,
        "installed_at": None,
        "source": None,
        "pre_release": None,
        "target_platform": None,
        "disabled": None,
        "directory": None,
        "manifest_source": None,
        "manifest_status": None,
    }
    row.update(fields)
    return row


# --- VS Code family ---------------------------------------------------------

def from_extensions_json(profile, data, pstate, sink):
    if not isinstance(data, list):
        return False
    for item in data:
        check_time()
        if not isinstance(item, dict):
            pstate["partial"] = True
            issue("entry_malformed", profile["dir"])
            continue
        ident = item.get("identifier")
        ext_id = clean_text(ident.get("id")) if isinstance(ident, dict) else None
        if ext_id is None or "." not in ext_id:
            pstate["partial"] = True
            issue("entry_malformed", profile["dir"])
            continue
        take_slot()
        meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        publisher, _, name = ext_id.partition(".")
        target = clean_text(meta.get("targetPlatform"))
        sink.append(entry(
            profile,
            id=ext_id.lower(),
            name=clean_text(name),
            publisher=clean_text(publisher),
            publisher_display_name=clean_text(meta.get("publisherDisplayName")),
            version=clean_text(item.get("version")),
            installed_at=iso_ms(meta.get("installedTimestamp")),
            source=clean_text(meta.get("source")),
            pre_release=as_bool(meta.get("isPreReleaseVersion")),
            target_platform=None if target in (None, "undefined") else target,
            directory=clean_text(item.get("relativeLocation")),
            manifest_source="extensions_json",
            manifest_status="read",
        ))
        pstate["count"] += 1
    return True


def obsolete_dirs(ext_dir, pstate):
    status, obj = parse_json(*read_file(os.path.join(ext_dir, ".obsolete"), MANIFEST_CAP))
    if status == "read" and isinstance(obj, dict):
        return {k for k, v in obj.items() if v is True}
    if status in ("unreadable", "unparseable") or (status == "read" and not isinstance(obj, dict)):
        pstate["partial"] = True
        issue("obsolete_unreadable", os.path.join(ext_dir, ".obsolete"))
    return set()


def from_package_manifests(profile, ext_dir, pstate, sink):
    obsolete = obsolete_dirs(ext_dir, pstate)
    for name, k in list_dir(ext_dir):
        check_time()
        where = os.path.join(ext_dir, name)
        if k == "file":
            continue
        if k != "dir":
            refused(k, where, pstate)
            continue
        if name in obsolete:
            continue
        directory = clean_text(name, 255)
        if directory is None:
            pstate["partial"] = True
            issue("name_unsafe", ext_dir)
            continue
        take_slot()
        status, manifest = parse_json(*read_file(os.path.join(where, "package.json"), MANIFEST_CAP))
        if status == "read" and not isinstance(manifest, dict):
            status, manifest = "unparseable", None
        if status == "read":
            publisher = clean_text(manifest.get("publisher"))
            ext_name = clean_text(manifest.get("name"))
            meta = manifest.get("__metadata") if isinstance(manifest.get("__metadata"), dict) else {}
            if publisher is None or ext_name is None:
                pstate["partial"] = True
                issue("manifest_incomplete", where)
            target = clean_text(meta.get("targetPlatform"))
            row = entry(
                profile,
                id=(publisher + "." + ext_name).lower() if publisher and ext_name else None,
                name=ext_name,
                publisher=publisher,
                publisher_display_name=clean_text(meta.get("publisherDisplayName")),
                version=clean_text(manifest.get("version")),
                installed_at=iso_ms(meta.get("installedTimestamp")),
                source=clean_text(meta.get("source")),
                pre_release=as_bool(meta.get("isPreReleaseVersion")),
                target_platform=None if target in (None, "undefined") else target,
                directory=directory,
                manifest_source="package_json",
                manifest_status="read",
            )
        else:
            # Still listed: an extension whose manifest cannot be read is
            # present, just not identified.
            pstate["partial"] = True
            issue("manifest_" + status, where)
            row = entry(profile, directory=directory, manifest_source="package_json", manifest_status=status)
        sink.append(row)
        pstate["count"] += 1


def collect_vscode(profile, ext_dir, pstate, sink):
    status, data = parse_json(*read_file(os.path.join(ext_dir, "extensions.json"), JSON_CAP))
    if status == "read":
        if from_extensions_json(profile, data, pstate, sink):
            profile["manifest_source"] = "extensions_json"
            return
        status = "unparseable"
    if status != "missing":
        # A corrupt list is never taken as "no extensions": the folders are
        # read instead and the profile says it is partial.
        pstate["partial"] = True
        issue("extensions_json_" + status, os.path.join(ext_dir, "extensions.json"))
    profile["manifest_source"] = "package_json"
    from_package_manifests(profile, ext_dir, pstate, sink)


# --- JetBrains --------------------------------------------------------------

def plugin_fields(data):
    """(status, fields) from plugin.xml bytes. A DTD is refused outright, so no
    entity is ever expanded and nothing external is ever resolved."""
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        return "unparseable", None
    try:
        root = ElementTree.fromstring(data)
        if root.tag != "idea-plugin":
            return "unparseable", None

        def child(tag):
            node = root.find(tag)
            return clean_text("".join(node.itertext())) if node is not None else None

        name = child("name")
        fields = {
            # JetBrains uses <name> as the id when <id> is not given.
            "id": child("id") or name,
            "name": name,
            "publisher": child("vendor"),
            "version": child("version"),
        }
    except (ElementTree.ParseError, ValueError, RecursionError):
        return "unparseable", None
    return "read", fields


def plugin_xml_from_jar(jar_path):
    """(status, fields). missing when the jar has no META-INF/plugin.xml."""
    status, fd = open_regular(jar_path, JAR_CAP)
    if status != "open":
        return status, None
    # The file object owns fd from here and the with-block closes it on every
    # path, including a jar zipfile refuses. If fdopen itself fails the fd has
    # no owner yet, so it is closed here. test-ide-extensions.zsh [4b] counts
    # open descriptors across a directory of corrupt jars.
    try:
        fh = os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        return "unreadable", None
    try:
        with fh:
            with zipfile.ZipFile(fh) as zf:
                try:
                    info = zf.getinfo("META-INF/plugin.xml")
                except KeyError:
                    return "missing", None
                if info.file_size > PLUGIN_XML_CAP:
                    return "unreadable", None
                with zf.open(info) as member:
                    data = member.read(PLUGIN_XML_CAP + 1)
                if len(data) > PLUGIN_XML_CAP:
                    return "unreadable", None
    except Exception:
        # Any failure reading a user-supplied jar is that one plugin's problem,
        # never the collection's. zipfile does not wrap every error: corrupt
        # deflate data raises zlib's own error type, which would otherwise
        # escape and fail the block for every user on the device.
        return "unparseable", None
    return plugin_fields(data)


def jetbrains_plugin(plugin_path, name, k, pstate):
    """(manifest_source, status, fields) for one entry of plugins/."""
    if k == "file":
        s, f = plugin_xml_from_jar(plugin_path)
        return "plugin_xml_jar", s, f
    # Unpacked plugin.xml first (some plugins ship it that way).
    meta_inf = os.path.join(plugin_path, "META-INF")
    m_kind, m_errno = lstat_kind(meta_inf)
    if m_kind == "dir":
        s, data = read_file(os.path.join(meta_inf, "plugin.xml"), PLUGIN_XML_CAP)
        if s == "read":
            s, f = plugin_fields(data)
            return "plugin_xml_unpacked", s, f
        if s == "unreadable":
            return "plugin_xml_unpacked", s, None
    elif m_kind not in ("absent",):
        refused(m_kind, meta_inf, pstate, m_errno)
    lib = os.path.join(plugin_path, "lib")
    l_kind, l_errno = lstat_kind(lib)
    if l_kind == "absent":
        return "directory_name", "missing", None
    if l_kind != "dir":
        refused(l_kind, lib, pstate, l_errno)
        return "directory_name", "unreadable", None
    try:
        jars = [(n, jk) for n, jk in list_dir(lib) if n.endswith(".jar")]
    except Abort as abort:
        issue(abort_code(abort, lib), lib)
        return "directory_name", "unreadable", None
    # The jar named after the plugin folder usually carries plugin.xml.
    jars.sort(key=lambda j: (not j[0].lower().startswith(name.lower()), j[0]))
    worst = "missing"
    for n, jk in jars[:MAX_JARS_PER_PLUGIN]:
        check_time()
        if jk != "file":
            refused(jk, os.path.join(lib, n), pstate)
            worst = "unreadable"
            continue
        s, f = plugin_xml_from_jar(os.path.join(lib, n))
        if s == "read":
            return "plugin_xml_jar", s, f
        if s != "missing":
            worst = s
    if len(jars) > MAX_JARS_PER_PLUGIN and worst == "missing":
        worst = "unreadable"
    return "directory_name", worst, None


def disabled_ids(config_dir, pstate):
    """Set of disabled plugin ids, or None when it cannot be said."""
    s, data = read_file(os.path.join(config_dir, "disabled_plugins.txt"), DISABLED_CAP)
    if s == "missing":
        return set()
    if s != "read":
        pstate["partial"] = True
        issue("disabled_plugins_unreadable", config_dir)
        return None
    return {line.strip() for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()}


def collect_jetbrains(profile, config_dir, pstate, sink):
    profile["manifest_source"] = "plugin_xml"
    plugins = os.path.join(config_dir, "plugins")
    p_kind, p_errno = lstat_kind(plugins)
    if p_kind == "absent":
        return
    if p_kind != "dir":
        issue(code_for(p_kind, p_errno, plugins), plugins)
        raise Abort("recorded")
    disabled = disabled_ids(config_dir, pstate)
    for name, k in list_dir(plugins):
        check_time()
        where = os.path.join(plugins, name)
        if k == "file" and not name.endswith(".jar"):
            continue
        if k not in ("dir", "file"):
            refused(k, where, pstate)
            continue
        directory = clean_text(name, 255)
        if directory is None:
            pstate["partial"] = True
            issue("name_unsafe", plugins)
            continue
        take_slot()
        source, status, fields = jetbrains_plugin(where, name, k, pstate)
        if status != "read" or not fields or not fields.get("id"):
            pstate["partial"] = True
            issue("plugin_xml_" + (status if status != "read" else "incomplete"), where)
        fields = fields or {}
        plugin_id = fields.get("id")
        sink.append(entry(
            profile,
            id=plugin_id,
            name=fields.get("name"),
            publisher=fields.get("publisher"),
            version=fields.get("version"),
            disabled=(plugin_id in disabled) if (plugin_id and disabled is not None) else None,
            directory=directory,
            manifest_source=source,
            manifest_status=status,
        ))
        pstate["count"] += 1


# --- users and profiles -----------------------------------------------------

def owner_of(path):
    try:
        uid = lstat_at(path).st_uid
    except OSError:
        return None
    return uid


def editor_profiles(home):
    """(found, jetbrains_problem): (family, editor, editor_version, path, kind,
    errno) for every editor directory present in one home, and (path, issue
    code) when the JetBrains directory could not be read (the caller records
    it; the VS Code profiles found are still collected). Without Full Disk
    Access the JetBrains folder is lstat-able but cannot be listed, which is
    tcc_denied (PAT-2100)."""
    found = []
    for editor, dot in VSCODE_EDITORS:
        base = os.path.join(home, dot)
        b_kind, b_errno = lstat_kind(base)
        if b_kind == "absent":
            continue
        if b_kind != "dir":
            found.append(("vscode", editor, None, base, b_kind, b_errno))
            continue
        ext_dir = os.path.join(base, "extensions")
        e_kind, e_errno = lstat_kind(ext_dir)
        if e_kind != "absent":
            found.append(("vscode", editor, None, ext_dir, e_kind, e_errno))
    jb = home
    for part in JETBRAINS_BASE:
        jb = os.path.join(jb, part)
        j_kind, j_errno = lstat_kind(jb)
        if j_kind == "absent":
            return found, None
        if j_kind != "dir":
            return found, (jb, code_for(j_kind, j_errno, jb))
    try:
        products = list_dir(jb)
    except Abort as abort:
        return found, (jb, abort_code(abort, jb))
    for name, k in products:
        m = JETBRAINS_PRODUCT_RE.match(name)
        if not m or k == "file":
            continue
        found.append(("jetbrains", m.group(1), m.group(2), os.path.join(jb, name), k, None))
    return found, None


def main():
    extensions, users, profiles = [], [], []
    root_kind, root_errno = lstat_kind(users_root)
    if root_kind != "dir":
        issue({"symlink": "symlink_not_followed"}.get(root_kind) or denied_code(root_errno, os.path.dirname(users_root)), users_root)
        return finish("failed", extensions, users, profiles)
    try:
        homes = list_dir(users_root)
    except Abort as abort:
        issue(abort_code(abort, users_root), users_root)
        return finish("failed", extensions, users, profiles)

    stopped = False
    for name, k in homes:
        if name in SKIP_HOMES:
            continue
        if stopped:
            break
        if len(users) >= MAX_USERS:
            state["truncated"] = True
            state["reason"] = state["reason"] or "user_limit"
            break
        home = os.path.join(users_root, name)
        user = clean_text(name, 255)
        if k == "file":
            continue
        uid = owner_of(home)
        urow = {"user": user or "<unprintable>", "user_id": str(uid) if uid is not None else None,
                "collection_status": "failed", "profiles": 0}
        users.append(urow)
        if k != "dir":
            issue(code_for(k), home)
            continue
        found, jb_problem = editor_profiles(home)
        user_partial = False
        if jb_problem:
            user_partial = True
            issue(jb_problem[1], jb_problem[0])
        statuses = []
        for family, editor, version, path, p_kind, p_errno in found:
            profile = {"user": urow["user"], "user_id": urow["user_id"], "family": family,
                       "editor": editor, "editor_version": version, "dir": path, "manifest_source": None}
            pstate = {"partial": False, "count": 0}
            p_status = None
            if p_kind != "dir":
                # A symlinked extensions directory is recorded, never entered:
                # everything under it would be read through a path the user chose.
                issue(code_for(p_kind, p_errno, path), path)
                p_status = "failed"
            else:
                try:
                    if family == "vscode":
                        collect_vscode(profile, path, pstate, extensions)
                    else:
                        collect_jetbrains(profile, path, pstate, extensions)
                except Abort as err:
                    if not err.args:
                        issue(abort_code(err, path), path)
                    p_status = "failed" if pstate["count"] == 0 else "partial"
                except Stop:
                    pstate["partial"] = True
                    stopped = True
            if p_status is None:
                p_status = "partial" if pstate["partial"] else "complete"
            statuses.append(p_status)
            profiles.append({"user": profile["user"], "user_id": profile["user_id"], "family": family,
                             "editor": editor, "editor_version": version, "collection_status": p_status,
                             "manifest_source": profile["manifest_source"], "extension_count": pstate["count"]})
            if stopped:
                break
        urow["profiles"] = len(statuses)
        if not statuses:
            urow["collection_status"] = "partial" if user_partial else "not_present"
        elif all(s == "failed" for s in statuses) and not user_partial:
            urow["collection_status"] = "failed"
        elif user_partial or any(s != "complete" for s in statuses):
            urow["collection_status"] = "partial"
        else:
            urow["collection_status"] = "complete"
    if stopped:
        state["truncated"] = True

    u_statuses = [u["collection_status"] for u in users]
    if u_statuses and all(s == "failed" for s in u_statuses):
        status = "failed"
    elif state["truncated"] or any(s in ("partial", "failed") for s in u_statuses):
        status = "partial"
    elif not profiles:
        status = "not_present"
    else:
        status = "complete"
    return finish(status, extensions, users, profiles)


def finish(status, extensions, users, profiles):
    key = lambda e: (e["user"], e["family"], e["editor"], e["editor_version"] or "", e["id"] or "", e["directory"] or "")
    block = {
        "collection_status": status,
        "truncated": state["truncated"],
        "truncation_reason": state["reason"] if state["truncated"] else None,
        "users": users,
        "profiles": profiles,
        "issues": state["issues"],
    }
    if status != "failed":
        block["extensions"] = sorted(extensions, key=key)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(block, f, separators=(",", ":"))
    print(status, len(extensions) if status != "failed" else 0, len(profiles), len(users))
    print("tcc", len(state["tcc_denied"]), tcc_verdict(status, users))


def tcc_verdict(status, users):
    """The agent_health verdict for Full Disk Access (PAT-2100): denied when
    any path was refused with EPERM; reached only when the walk ran to the
    end, no home failed and nothing was refused with any other errno, so
    every folder it would read was opened; else unknown (no opinion)."""
    if state["tcc_denied"]:
        return "denied"
    if (status != "failed" and not state["truncated"] and not state["unreached"]
            and all(u["collection_status"] != "failed" for u in users)):
        return "reached"
    return "unknown"


main()
PYEOF
    _ie_pid=$!

    # A parser this loop killed is failed whatever wait reports: one that
    # finished between the last check and the kill is reaped with a clean
    # status, and its output is not trusted (PAT-2033).
    local _ie_killed=0
    while kill -0 "$_ie_pid" 2>/dev/null; do
        if (( _ie_ticks >= _IDE_HARD_TIMEOUT_SECONDS * 10 )); then
            kill -9 "$_ie_pid" 2>/dev/null
            _ie_killed=1
            log_warn "ide_extensions: parser still running after ${_IDE_HARD_TIMEOUT_SECONDS}s, killed; block is failed"
            break
        fi
        sleep 0.1
        (( _ie_ticks++ ))
    done
    wait "$_ie_pid" 2>/dev/null || _ie_rc=$?

    _ie_line=$(head -n 1 "$_ie_summary" 2>/dev/null)
    _ie_fields=(${=_ie_line})
    if (( _ie_killed == 0 && _ie_rc == 0 )) && (( ${#_ie_fields} == 4 )) \
        && [[ "${_ie_fields[1]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_ie_fields[2]}${_ie_fields[3]}${_ie_fields[4]}" == <-> ]] \
        && "$PYTHON3" -c 'import json,sys; json.load(open(sys.argv[1]))' "$_ie_out" 2>/dev/null; then
        mv -f "$_ie_out" "$IDE_EXTENSIONS_JSON_TMP"
        IDE_EXTENSIONS_COLLECTION_STATUS="${_ie_fields[1]}"
        IDE_EXTENSIONS_COUNT="${_ie_fields[2]}"
        IDE_EXTENSIONS_PROFILE_COUNT="${_ie_fields[3]}"
        IDE_EXTENSIONS_USER_COUNT="${_ie_fields[4]}"
        # PAT-2100: the parser's "tcc <denied-count> <verdict>" line; a missing
        # or garbled one is no opinion on Full Disk Access.
        patched_tcc_health ide_extensions ${=$(patched_tcc_summary "$_ie_summary")}
        # PAT-2225: an over-budget block is sent as failed (see common.sh).
        patched_block_within_budget ide_extensions "$IDE_EXTENSIONS_JSON_TMP" "$_IDE_MAX_BYTES" \
            || IDE_EXTENSIONS_COLLECTION_STATUS="failed"
    else
        # Parser stderr can carry file names from user-owned trees: newlines
        # become spaces and every other control character is dropped, so the
        # log line cannot be split or carry terminal escapes.
        log_warn "ide_extensions: parser failed (exit $_ie_rc): $(head -c 300 "$_ie_err" 2>/dev/null | tr '\n\t' '  ' | LC_ALL=C tr -d '\000-\037\177')"
        rm -f "$_ie_out"
    fi
    rm -f "$_ie_summary" "$_ie_err"
    local _ie_wire="held off the wire"
    (( _IDE_EXTENSIONS_PAYLOAD_ON_WIRE )) && _ie_wire="sent"
    echo "ide_extensions: status=$(ide_extensions_collection_status) extensions=$IDE_EXTENSIONS_COUNT profiles=$IDE_EXTENSIONS_PROFILE_COUNT users=$IDE_EXTENSIONS_USER_COUNT ($_ie_wire)"
    return 0
}
