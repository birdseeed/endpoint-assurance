# package_managers.sh — npm global, pip user and pipx packages for every local
# user, read from disk (PAT-2018).
#
# Sourced by patched-collect.sh; not executable directly.
# Requires: PATCHED_TMPDIR, PYTHON3 (set by main script before sourcing)
#
# WHAT THIS READS, AND ONLY THIS.
#
#   npm_global  <prefix>/lib/node_modules/<name>/package.json and
#               <prefix>/lib/node_modules/@<scope>/<name>/package.json (the
#               "name" and "version" keys), for each prefix:
#                 machine-wide  /usr/local (the nodejs.org installer, Intel
#                               Homebrew) and /opt/homebrew
#                 per user      ~/.nvm/versions/node/<version>
#                               <fnm dir>/node-versions/<version>/installation
#                                 for ~/.local/share/fnm,
#                                 ~/Library/Application Support/fnm and ~/.fnm
#                               ~/.volta/tools/image/node/<version>
#                               ~/.volta/tools/image/packages/<name> and
#                                 .../packages/@<scope>/<name>
#   pip_user    <site-packages>/*.dist-info/METADATA, and *.egg-info (PKG-INFO
#               inside the directory, or the file itself), for the user site
#               of each Python found:
#                 ~/Library/Python/<X.Y>/lib/python/site-packages  (framework
#                   builds: python.org, Homebrew, the Command Line Tools)
#                 ~/.local/lib/python<X.Y>/site-packages          (pyenv, uv
#                   and other non-framework builds)
#   pipx        every venv under ~/.local/pipx/venvs, ~/.local/share/pipx/venvs
#               and ~/Library/Application Support/pipx/venvs: its pyvenv.cfg
#               (the interpreter) and lib/python<X.Y>/site-packages/*.dist-info.
#
#   Only the Name and Version headers of a METADATA file are used, and only its
#   first 64 KiB is ever read: the header section ends at the first blank line
#   and the long description after it is never loaded.
#
#   The interpreter of a user site is not recorded anywhere on disk, so it is
#   inferred from the interpreters that exist and would use that site
#   (framework builds of the same X.Y for ~/Library/Python, pyenv and uv builds
#   for ~/.local/lib). Every candidate is listed on the location; a package row
#   names an interpreter only when exactly one candidate exists. A pipx venv
#   names its own interpreter in pyvenv.cfg.
#
#   Project-local node_modules and project virtualenvs are out of scope.
#
# READ ONLY, AND NOTHING IS EXECUTED. No package manager, no Node, no Python
# other than this collector's own parser, and nothing touches the network.
# test-package-managers.zsh carries a static guard that goes red if this file
# gains a process launch, a package-manager invocation or a network client.
#
# EVERY PER-USER TREE IS OWNED BY AN ORDINARY USER AND THIS RUNS AS ROOT. So
# nothing is followed that the user could point somewhere else: every file is
# opened O_NOFOLLOW|O_NONBLOCK and must be a regular file with a single link,
# under a size cap; every directory level is checked with lstat and never
# entered when it is a symlink.
#
# The lstat checks decide what is reported; the walk is what keeps a read in
# the tree. Every open starts at / and opens each directory relative to the
# one before with O_NOFOLLOW, so a directory swapped for a symlink between its
# check and the read is refused as well (PAT-2033).
#
# VERSION-MANAGER ALIASES ARE NEVER FOLLOWED, AND NEVER NEED TO BE. nvm, fnm
# and volta point a "current" or "default" alias (~/.nvm/current,
# <fnm dir>/aliases/*, fnm_multishells, ~/.volta/bin shims) at one real version
# directory. This collector never looks at an alias: it lists the directory
# that holds the real versions (versions/node, node-versions, image/node) and
# reads each real directory once. A symlink found where a real version
# directory should be is recorded and not entered, and the location is
# partial. A machine-wide prefix that is itself a link (for example a
# hand-made /usr/local/lib/node_modules link into a version manager) is not
# entered either; its link text is read with readlink, and when it names a
# directory this run already read in full it is recorded as
# alias_not_followed and costs nothing, otherwise it is symlink_not_followed
# and the source is partial.
#
# ABSENCE REQUIRES AUTHORITY (PAT-1710). collection_status, overall, per
# source (npm_global, pip_user, pipx), per user and per location, is one of:
#   complete     everything found was read in full
#   partial      something was read but not everything (an unreadable or
#                corrupt manifest, a symlink not followed, the 5,000-package or
#                30-second bound): the list is what was seen, not all there is
#   not_present  every place was looked at and nothing of that kind exists; a
#                genuine reading, so an empty list is sent
#   failed       nothing trustworthy was read: the packages list is OMITTED,
#                never sent as [], so a failed read can never look like "none".
#                A source can be failed while the block is not; its packages
#                are then simply absent and its status says why.
#
# PRIVACY PROTECTION (TCC, PAT-2100). Root without Full Disk Access may lstat
# ~/Library/Application Support/fnm and .../pipx but open() fails with EPERM.
# That is the issue code tcc_denied, not unreadable; it is still a refusal
# like any other (nothing under it is read, and the source is failed or
# partial, never not_present or complete). The parser's summary line starting
# "tcc <count> <denied|reached|unknown>" (by prefix) feeds patched_tcc_health
# (common.sh), which writes or clears the agent_health entry tcc_denied /
# package_managers / full_disk_access_missing from the LaunchDaemon run only,
# as browser_extensions.sh does (PAT-2096).
#
# ON THE WIRE since PAT-2225 (2026-09-28). _PACKAGE_MANAGERS_PAYLOAD_ON_WIRE=1
# makes package_managers_payload_member emit the block into the inventory
# payload, which the platform (PAT-2021) validates and ingests. The block is
# sent only within the _PKG_MAX_BYTES budget below; past it the block is sent
# as failed (patched_block_within_budget, common.sh). Setting the constant
# back to 0 is the whole off switch; test-package-managers.zsh asserts it is
# 1 and still exercises the off path, so changing it must update that test in
# the same change.

_PACKAGE_MANAGERS_PAYLOAD_ON_WIRE=1

# Where home directories live, and the root the machine-wide paths hang off.
# Tests reassign both after sourcing.
# ASSUMPTION: as in ide_extensions.sh, local homes are the directories
# directly under /Users. A relocated or network home is not seen, and neither
# is an npm prefix moved by a user's ~/.npmrc or a PIPX_HOME override.
_PKG_USERS_ROOT=/Users
_PKG_SYSTEM_ROOT=/

# Bounds (PAT-2018). Past either, collection stops and is marked partial. The
# package limit applies to each source separately.
_PKG_MAX_PACKAGES=5000
_PKG_TIME_BUDGET_SECONDS=30
# The parser checks its own budget between entries; this is the outer limit
# for a read that blocks inside one syscall. Past it the parser is killed and
# the block is failed.
_PKG_HARD_TIMEOUT_SECONDS=45
# Byte budget for the serialised block (PAT-2225), about 2,400 packages at
# the ~430 bytes a real row takes. The four tooling blocks together stay
# within 2 MiB, as the homebrew block does, so the two leave 2 MiB of the
# server's 6 MiB inventory body cap for everything else. Past the budget the
# block is sent as failed, never cut down: the platform's tooling contract
# has no size_limit reason. Tests lower it after sourcing.
_PKG_MAX_BYTES=$(( 1024 * 1024 ))

# package_managers_collection_status
#   Prints the wire value. Anything but the four known values is failed.
package_managers_collection_status() {
    case "${PACKAGE_MANAGERS_COLLECTION_STATUS:-}" in
        complete|partial|not_present) print -r -- "$PACKAGE_MANAGERS_COLLECTION_STATUS" ;;
        *) print -r -- "failed" ;;
    esac
}

# package_managers_payload_member
#   Prints `"package_managers": {...},` for the payload heredoc, or nothing
#   when the wire flag is 0 (see header). A failed status with no written
#   block sends only {"collection_status":"failed"}.
package_managers_payload_member() {
    (( _PACKAGE_MANAGERS_PAYLOAD_ON_WIRE )) || return 0
    if [[ "$(package_managers_collection_status)" == "failed" ]] \
        || [[ -z "${PACKAGE_MANAGERS_JSON_TMP:-}" || ! -s "$PACKAGE_MANAGERS_JSON_TMP" ]]; then
        printf '"package_managers": {"collection_status": "failed"},'
        return 0
    fi
    printf '"package_managers": %s,' "$(cat "$PACKAGE_MANAGERS_JSON_TMP")"
}

collect_package_managers() {
    PACKAGE_MANAGERS_COLLECTION_STATUS="failed"
    PACKAGE_MANAGERS_NPM_COUNT=0
    PACKAGE_MANAGERS_PIP_COUNT=0
    PACKAGE_MANAGERS_PIPX_COUNT=0
    PACKAGE_MANAGERS_USER_COUNT=0
    PACKAGE_MANAGERS_NPM_STATUS="failed"
    PACKAGE_MANAGERS_PIP_STATUS="failed"
    PACKAGE_MANAGERS_PIPX_STATUS="failed"
    # Reuse the caller's placeholder file if it made one, so it is not orphaned.
    if [[ -z "${PACKAGE_MANAGERS_JSON_TMP:-}" || ! -f "$PACKAGE_MANAGERS_JSON_TMP" ]]; then
        PACKAGE_MANAGERS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/package-managers.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    fi
    printf '{"collection_status": "failed"}' > "$PACKAGE_MANAGERS_JSON_TMP"

    local _pm_out _pm_summary _pm_err _pm_pid _pm_rc=0 _pm_ticks=0 _pm_line
    local -a _pm_fields
    _pm_out=$(mktemp "$PATCHED_TMPDIR/package-managers-out.XXXXXX")
    _pm_summary=$(mktemp "$PATCHED_TMPDIR/package-managers-summary.XXXXXX")
    _pm_err=$(mktemp "$PATCHED_TMPDIR/package-managers-err.XXXXXX")

    # The program arrives on stdin through the heredoc, so every input is an
    # argv entry, never piped (see the python3 heredoc footgun in AGENTS.md).
    "$PYTHON3" - "$_pm_out" "$_PKG_MAX_PACKAGES" "$_PKG_TIME_BUDGET_SECONDS" \
        "$_PKG_USERS_ROOT" "$_PKG_SYSTEM_ROOT" > "$_pm_summary" 2> "$_pm_err" <<'PYEOF' &
import errno
import json
import os
import re
import stat
import sys
import time

out_path = sys.argv[1]
max_packages = int(sys.argv[2])
budget = float(sys.argv[3])
users_root = os.path.normpath(sys.argv[4])
system_root = os.path.normpath(sys.argv[5])
deadline = time.monotonic() + budget

PACKAGE_JSON_CAP = 1024 * 1024        # one package.json
METADATA_FILE_CAP = 64 * 1024 * 1024  # a METADATA file is refused past this size
METADATA_HEAD_CAP = 64 * 1024         # and only this much of it is ever read
PYVENV_CAP = 64 * 1024
TEXT_CAP = 512
MAX_USERS = 500
MAX_ISSUES = 50
SKIP_HOMES = {"Shared", "Guest"}
SOURCES = ("npm_global", "pip_user", "pipx")

NODE_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*$")
# An npm package name, or its @scope, as one directory name. Older packages
# may carry capitals; nothing else outside npm's URL-safe set is accepted.
VOLTA_PACKAGE_RE = re.compile(r"^[A-Za-z0-9~-][A-Za-z0-9._~-]{0,213}\Z")
VOLTA_SCOPE_RE = re.compile(r"^@[A-Za-z0-9~-][A-Za-z0-9._~-]{0,212}\Z")
PY_XY_RE = re.compile(r"^(\d+\.\d+)$")
PY_LIB_RE = re.compile(r"^python(\d+\.\d+)t?$")
CANON_RE = re.compile(r"[-_.]+")

FNM_BASES = ((".local", "share", "fnm"), ("Library", "Application Support", "fnm"), (".fnm",))
PIPX_BASES = ((".local", "pipx", "venvs"), (".local", "share", "pipx", "venvs"),
              ("Library", "Application Support", "pipx", "venvs"))
SYSTEM_NPM = (("system", ("usr", "local")), ("homebrew", ("opt", "homebrew")))
# (framework, Homebrew prefix): a Homebrew framework's Versions/<X.Y> link is
# only accepted into that prefix's own Cellar; nobody else links it (PAT-2040).
FRAMEWORK_PYTHONS = (
    (("Library", "Frameworks", "Python.framework"), None),
    (("opt", "homebrew", "Frameworks", "Python.framework"), ("opt", "homebrew")),
    (("usr", "local", "Frameworks", "Python.framework"), ("usr", "local")),
    (("Library", "Developer", "CommandLineTools", "Library", "Frameworks", "Python3.framework"), None),
    (("Applications", "Xcode.app", "Contents", "Developer", "Library", "Frameworks", "Python3.framework"), None),
)


class Stop(Exception):
    pass


class Abort(Exception):
    """A directory could not be read."""


class SourceFull(Exception):
    pass


# tcc_denied and unreached count every refusal, past the MAX_ISSUES cap on
# the issues list, for the agent_health verdict (PAT-2100).
state = {"truncated": False, "reason": None, "issues": [], "tcc_denied": set(), "unreached": 0}
counts = {s: 0 for s in SOURCES}
full = {s: False for s in SOURCES}


# --- helpers copied verbatim from ide_extensions.sh --------------------------
# test-package-managers.zsh [drift] fails if any of these stops matching its
# twin there, so a hardening fix to one cannot silently skip the other.

def clean_path(p):
    return p if isinstance(p, str) and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in p) else "<unprintable>"


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

# --- end of the verbatim copy -------------------------------------------------


def read_head(path, file_cap, head_cap):
    """(status, bytes) of at most the first head_cap bytes, through the same
    open_regular refusals as read_file."""
    status, fd = open_regular(path, file_cap)
    if status != "open":
        return status, None
    try:
        chunks, total = [], 0
        while total < head_cap:
            chunk = os.read(fd, min(65536, head_cap - total))
            if not chunk:
                break
            total += len(chunk)
            chunks.append(chunk)
        return "read", b"".join(chunks)
    except OSError:
        return "unreadable", None
    finally:
        os.close(fd)


def issue(code, where):
    if len(state["issues"]) < MAX_ISSUES:
        state["issues"].append({"code": code, "path": clean_path(where)})


def denied_code(err_no, denied):
    """The issue code for a path that could not be read: tcc_denied when the
    errno is EPERM, else unreadable (PAT-2100, as PAT-2096 did for browser
    extensions). As root, EPERM here is macOS privacy protection (TCC): without
    Full Disk Access, root may lstat another app's data folder
    (~/Library/Application Support/fnm, .../pipx) but not open it. Either way nothing
    under it is read and the source is not complete. Any errno counts toward the
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


def check_time():
    if time.monotonic() > deadline:
        state["truncated"] = True
        state["reason"] = state["reason"] or "time_limit"
        raise Stop()


def take_slot(source):
    if counts[source] >= max_packages:
        full[source] = True
        state["truncated"] = True
        state["reason"] = state["reason"] or "package_limit"
        raise SourceFull()
    counts[source] += 1


def walk(anchor, parts):
    """(kind, path, errno): every component below anchor is checked with lstat,
    and the walk stops at the first that is not a directory. ("dir", full
    path, None) when all of them are directories. errno is lstat_kind's for an
    error kind: without Full Disk Access, the component below a folder macOS
    privacy protection guards fails with EPERM (PAT-2100)."""
    p = anchor
    for part in parts:
        p = os.path.join(p, part)
        k, err_no = lstat_kind(p)
        if k != "dir":
            return k, p, err_no
    return "dir", p, None


def canonical(name):
    return CANON_RE.sub("-", name).lower() if isinstance(name, str) else None


def new_unit():
    return {"problems": 0, "ok": 0, "partial": False, "locations": 0}


def unit_status(u):
    if u["problems"] and u["ok"] == 0:
        return "failed"
    if u["problems"] or u["partial"]:
        return "partial"
    if u["locations"] == 0:
        return "not_present"
    return "complete"


def combine(statuses, truncated=False):
    if statuses and all(s == "failed" for s in statuses):
        return "failed"
    if truncated or any(s in ("partial", "failed") for s in statuses):
        return "partial"
    if not statuses or all(s == "not_present" for s in statuses):
        return "not_present"
    return "complete"


def refuse_unit(unit, k, where, err_no=None):
    unit["problems"] += 1
    issue(code_for(k, err_no, where), where)


locations = []
packages = []
read_dirs = []   # node_modules directories read in full, for alias coverage


def new_location(ctx, source, manager, path, runtime_version=None, interpreters=()):
    interps = [clean_path(i) for i in interpreters]
    loc = {
        "source": source,
        "manager": manager,
        "scope": ctx["scope"],
        "user": ctx["user"],
        "user_id": ctx["user_id"],
        "path": clean_path(path),
        "runtime_version": clean_text(runtime_version, 64) if runtime_version else None,
        "interpreters": interps,
        "collection_status": "failed",
        "package_count": 0,
    }
    locations.append(loc)
    ctx["units"][source]["locations"] += 1
    return loc


def package_row(loc, **fields):
    row = {
        "source": loc["source"],
        "manager": loc["manager"],
        "scope": loc["scope"],
        "user": loc["user"],
        "user_id": loc["user_id"],
        "name": None,
        "version": None,
        "prefix": loc["path"],
        "runtime_version": loc["runtime_version"],
        "interpreter": loc["interpreters"][0] if len(loc["interpreters"]) == 1 else None,
        "directory": None,
        "metadata_status": None,
        "pipx_app": None,
        "pipx_main": None,
    }
    row.update(fields)
    return row


def finish_location(ctx, loc, lp, failed=False):
    unit = ctx["units"][loc["source"]]
    if failed:
        loc["collection_status"] = "failed" if loc["package_count"] == 0 else "partial"
    else:
        loc["collection_status"] = "partial" if lp["partial"] else "complete"
    if loc["collection_status"] == "failed":
        unit["problems"] += 1
    else:
        unit["ok"] += 1
        if loc["collection_status"] == "partial":
            unit["partial"] = True


# --- npm ----------------------------------------------------------------------

def npm_package(loc, lp, modules, rel):
    directory = clean_text(rel, 255)
    if directory is None:
        lp["partial"] = True
        issue("name_unsafe", modules)
        return
    take_slot("npm_global")
    where = os.path.join(modules, rel)
    status, data = read_file(os.path.join(where, "package.json"), PACKAGE_JSON_CAP)
    obj = None
    if status == "read":
        try:
            obj = json.loads(data.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            status = "unparseable"
        if status == "read" and not isinstance(obj, dict):
            status = "unparseable"
    name = version = None
    if status == "read":
        name, version = clean_text(obj.get("name")), clean_text(obj.get("version"))
        if name is None or version is None:
            lp["partial"] = True
            issue("manifest_incomplete", where)
    else:
        # Still listed: a package whose manifest cannot be read is present,
        # just not identified.
        lp["partial"] = True
        issue("manifest_" + status, where)
    packages.append(package_row(loc, name=name, version=version, directory=directory, metadata_status=status))
    loc["package_count"] += 1


def npm_location(ctx, manager, prefix, runtime_version, modules_parts=("lib", "node_modules")):
    if full["npm_global"]:
        ctx["units"]["npm_global"]["partial"] = True
        return
    loc = new_location(ctx, "npm_global", manager, prefix, runtime_version)
    lp = {"partial": False}
    k, modules, k_errno = walk(prefix, modules_parts)
    if k == "absent":
        # A version directory with no global node_modules has no global packages.
        return finish_location(ctx, loc, lp)
    if k != "dir":
        issue(code_for(k, k_errno, modules), modules)
        return finish_location(ctx, loc, lp, failed=True)
    try:
        entries = list_dir(modules)
    except Abort as abort:
        issue(abort_code(abort, modules), modules)
        return finish_location(ctx, loc, lp, failed=True)
    try:
        for name, ek in entries:
            check_time()
            where = os.path.join(modules, name)
            if ek == "file":
                continue
            if ek != "dir":
                # npm link leaves a symlink here; it is recorded, never entered.
                lp["partial"] = True
                issue(code_for(ek), where)
                continue
            if not name.startswith("@"):
                npm_package(loc, lp, modules, name)
                continue
            try:
                scoped = list_dir(where)
            except Abort as abort:
                lp["partial"] = True
                issue(abort_code(abort, where), where)
                continue
            for child, ck in scoped:
                check_time()
                if ck == "file":
                    continue
                if ck != "dir":
                    lp["partial"] = True
                    issue(code_for(ck), os.path.join(where, child))
                    continue
                npm_package(loc, lp, modules, name + "/" + child)
    except SourceFull:
        lp["partial"] = True
    except Stop:
        lp["partial"] = True
        finish_location(ctx, loc, lp)
        raise
    finish_location(ctx, loc, lp)
    if not lp["partial"]:
        read_dirs.append(os.path.normpath(modules))


def version_dirs(ctx, source, anchor, parts, pattern):
    """Real version directories directly under anchor/parts. A symlink where a
    real version should be is recorded and not entered."""
    unit = ctx["units"][source]
    k, base, k_errno = walk(anchor, parts)
    if k == "absent":
        return []
    if k != "dir":
        refuse_unit(unit, k, base, k_errno)
        return []
    try:
        entries = list_dir(base)
    except Abort as abort:
        unit["problems"] += 1
        issue(abort_code(abort, base), base)
        return []
    found = []
    for name, ek in entries:
        if pattern is not None and not pattern.match(name):
            continue
        if ek != "dir":
            if ek != "file":
                unit["partial"] = True
                issue(code_for(ek), os.path.join(base, name))
            continue
        found.append((name, os.path.join(base, name)))
    return found


def npm_for_home(ctx, home):
    for name, path in version_dirs(ctx, "npm_global", home, (".nvm", "versions", "node"), NODE_VERSION_RE):
        npm_location(ctx, "nvm", path, name.lstrip("v"))
    for base in FNM_BASES:
        for name, path in version_dirs(ctx, "npm_global", home, base + ("node-versions",), NODE_VERSION_RE):
            k, inst, k_errno = walk(path, ("installation",))
            if k == "absent":
                continue
            if k != "dir":
                refuse_unit(ctx["units"]["npm_global"], k, inst, k_errno)
                continue
            npm_location(ctx, "fnm", inst, name.lstrip("v"))
    volta = (".volta", "tools", "image")
    for name, path in version_dirs(ctx, "npm_global", home, volta + ("node",), NODE_VERSION_RE):
        npm_location(ctx, "volta", path, name.lstrip("v"))
    # A volta-installed global package gets its own image directory, named for
    # the package (@scope/name for a scoped one). A directory whose name no
    # npm package could have is recorded and not entered (PAT-2033).
    unit = ctx["units"]["npm_global"]
    for name, path in version_dirs(ctx, "npm_global", home, volta + ("packages",), None):
        if not (VOLTA_SCOPE_RE if name.startswith("@") else VOLTA_PACKAGE_RE).match(name):
            unit["partial"] = True
            issue("name_unsafe", path)
            continue
        if not name.startswith("@"):
            npm_location(ctx, "volta", path, None)
            continue
        for child, cpath in version_dirs(ctx, "npm_global", path, (), None):
            if not VOLTA_PACKAGE_RE.match(child):
                unit["partial"] = True
                issue("name_unsafe", cpath)
                continue
            npm_location(ctx, "volta", cpath, None)


def resolve_link(path):
    """The absolute, normalised text of a symlink, read with readlink and never
    followed; None when it cannot be read."""
    try:
        target = read_link(path)
    except OSError:
        return None
    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(path), target)
    return os.path.normpath(target)


def npm_system(ctx):
    for manager, parts in SYSTEM_NPM:
        prefix = os.path.join(system_root, *parts)
        full_parts = parts + ("lib", "node_modules")
        k, where, k_errno = walk(system_root, full_parts)
        if k == "absent":
            continue
        if k == "dir":
            npm_location(ctx, manager, prefix, None)
            continue
        if k == "symlink":
            target = resolve_link(where)
            rest = full_parts[len(os.path.relpath(where, system_root).split(os.sep)):]
            covered = os.path.normpath(os.path.join(target, *rest)) if target else None
            if covered is not None and covered in read_dirs:
                issue("alias_not_followed", where)
                continue
        refuse_unit(ctx["units"]["npm_global"], k, where, k_errno)


# --- pip and pipx -------------------------------------------------------------

def parse_metadata(data):
    """(status, name, version) from the header section of a METADATA or
    PKG-INFO file: RFC 822 style headers up to the first blank line. Only Name
    and Version are taken, each the first time it appears."""
    text = data.decode("utf-8", errors="replace")
    name = version = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line[:1] in (" ", "\t"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        if key == "name" and name is None:
            name = clean_text(value)
        elif key == "version" and version is None:
            version = clean_text(value, 128)
    if name is None or version is None:
        return "unparseable", name, version
    return "read", name, version


def dist_row(loc, lp, site, name, ek, source, extra):
    where = os.path.join(site, name)
    if name.endswith(".dist-info"):
        if ek != "dir":
            lp["partial"] = True
            issue(code_for(ek), where)
            return
        meta = os.path.join(where, "METADATA")
    elif name.endswith(".egg-info"):
        if ek == "dir":
            meta = os.path.join(where, "PKG-INFO")
        elif ek == "file":
            meta = where
        else:
            lp["partial"] = True
            issue(code_for(ek), where)
            return
    else:
        return
    directory = clean_text(name, 255)
    if directory is None:
        lp["partial"] = True
        issue("name_unsafe", site)
        return
    take_slot(source)
    status, data = read_head(meta, METADATA_FILE_CAP, METADATA_HEAD_CAP)
    pkg_name = version = None
    if status == "read":
        status, pkg_name, version = parse_metadata(data)
    if status != "read":
        lp["partial"] = True
        issue("metadata_" + status, where)
    fields = dict(extra)
    if source == "pipx" and pkg_name is not None:
        fields["pipx_main"] = canonical(pkg_name) == canonical(fields.get("pipx_app"))
    packages.append(package_row(loc, name=pkg_name, version=version, directory=directory,
                                metadata_status=status, **fields))
    loc["package_count"] += 1


def read_site(loc, lp, site, source, extra=None):
    """Every dist in one site-packages directory. Raises Abort when it cannot
    be listed."""
    for name, ek in list_dir(site):
        check_time()
        dist_row(loc, lp, site, name, ek, source, extra or {})


def site_location(ctx, source, manager, site, runtime_version, interpreters):
    if full[source]:
        ctx["units"][source]["partial"] = True
        return
    loc = new_location(ctx, source, manager, site, runtime_version, interpreters)
    lp = {"partial": False}
    try:
        read_site(loc, lp, site, source)
    except Abort as abort:
        issue(abort_code(abort, site), site)
        return finish_location(ctx, loc, lp, failed=True)
    except SourceFull:
        lp["partial"] = True
    except Stop:
        lp["partial"] = True
        finish_location(ctx, loc, lp)
        raise
    finish_location(ctx, loc, lp)


def interpreters_framework(xy):
    # Machine-wide framework builds. Homebrew links Versions/<X.Y> into its
    # Cellar, and that link belongs to the user, so the walk will not pass
    # through it (PAT-2033). Its text is read instead, and the interpreter is
    # tested for existence at the target with the same no-follow walk as every
    # other path. Only that one link is read; nothing is ever opened.
    # PAT-2040: whoever owns the prefix can point the link anywhere, and the
    # existence test would then answer for any path on the machine. So the
    # normalised target must be inside the prefix's own Cellar, and a link
    # where Homebrew does not make one is not followed at all.
    found = []
    for parts, brew_prefix in FRAMEWORK_PYTHONS:
        version_dir = os.path.join(system_root, *(parts + ("Versions", xy)))
        target = version_dir
        if kind(version_dir) == "symlink":
            if brew_prefix is None:
                continue
            target = resolve_link(version_dir)
            cellar = os.path.join(system_root, *(brew_prefix + ("Cellar",)))
            if target is None or not target.startswith(cellar + "/"):
                continue
        if kind(os.path.join(target, "bin", "python" + xy)) in ("file", "symlink"):
            found.append(os.path.join(version_dir, "bin", "python" + xy))
    return found


def interpreters_local(home, xy):
    found = []
    for parts, prefix_re in (((".pyenv", "versions"), re.compile(r"^" + re.escape(xy) + r"\.\d+[0-9A-Za-z.+-]*$")),
                             ((".local", "share", "uv", "python"), re.compile(r"^cpython-" + re.escape(xy) + r"\.\d+"))):
        k, base, _ = walk(home, parts)
        if k != "dir":
            continue
        try:
            entries = list_dir(base)
        except Abort:
            continue
        for name, ek in entries:
            if ek != "dir" or not prefix_re.match(name):
                continue
            k2, bindir, _ = walk(os.path.join(base, name), ("bin",))
            if k2 == "dir" and kind(os.path.join(bindir, "python" + xy)) in ("file", "symlink"):
                found.append(os.path.join(bindir, "python" + xy))
    return found


def pip_for_home(ctx, home):
    unit = ctx["units"]["pip_user"]
    for name, path in version_dirs(ctx, "pip_user", home, ("Library", "Python"), PY_XY_RE):
        k, site, k_errno = walk(path, ("lib", "python", "site-packages"))
        if k == "absent":
            continue
        if k != "dir":
            refuse_unit(unit, k, site, k_errno)
            continue
        site_location(ctx, "pip_user", "library_python", site, name, interpreters_framework(name))
    for name, path in version_dirs(ctx, "pip_user", home, (".local", "lib"), PY_LIB_RE):
        xy = PY_LIB_RE.match(name).group(1)
        k, site, k_errno = walk(path, ("site-packages",))
        if k == "absent":
            continue
        if k != "dir":
            refuse_unit(unit, k, site, k_errno)
            continue
        site_location(ctx, "pip_user", "local_lib", site, xy, interpreters_local(home, xy))


def parse_pyvenv(data):
    cfg = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            cfg[key.strip().lower()] = value.strip()
    return cfg


def pipx_venv(ctx, app, venv):
    if full["pipx"]:
        ctx["units"]["pipx"]["partial"] = True
        return
    lp = {"partial": False}
    status, data = read_file(os.path.join(venv, "pyvenv.cfg"), PYVENV_CAP)
    cfg = parse_pyvenv(data) if status == "read" else {}
    if status != "read":
        lp["partial"] = True
        issue("pyvenv_cfg_" + status, venv)
    interpreter = clean_text(cfg.get("executable"), 1024)
    version = cfg.get("version") or cfg.get("version_info")
    loc = new_location(ctx, "pipx", "pipx", venv, version, [interpreter] if interpreter else [])
    extra = {"pipx_app": clean_text(app, 255)}
    try:
        k, lib, k_errno = walk(venv, ("lib",))
        if k != "dir":
            issue(code_for(k, k_errno, lib) if k != "absent" else "site_packages_missing", lib)
            return finish_location(ctx, loc, lp, failed=True)
        sites = [n for n, ek in list_dir(lib) if ek == "dir" and PY_LIB_RE.match(n)]
        if not sites:
            issue("site_packages_missing", lib)
            return finish_location(ctx, loc, lp, failed=True)
        for n in sites:
            k, site, k_errno = walk(lib, (n, "site-packages"))
            if k != "dir":
                lp["partial"] = True
                issue(code_for(k, k_errno, site) if k != "absent" else "site_packages_missing", site)
                continue
            try:
                read_site(loc, lp, site, "pipx", extra)
            except Abort as abort:
                lp["partial"] = True
                issue(abort_code(abort, site), site)
    except Abort as abort:
        issue(abort_code(abort, venv), venv)
        return finish_location(ctx, loc, lp, failed=True)
    except SourceFull:
        lp["partial"] = True
    except Stop:
        lp["partial"] = True
        finish_location(ctx, loc, lp)
        raise
    finish_location(ctx, loc, lp)


def pipx_for_home(ctx, home):
    for base in PIPX_BASES:
        for name, path in version_dirs(ctx, "pipx", home, base, None):
            pipx_venv(ctx, name, path)


# --- users --------------------------------------------------------------------

def owner_of(path):
    try:
        return lstat_at(path).st_uid
    except OSError:
        return None


def new_ctx(scope, user, user_id):
    return {"scope": scope, "user": user, "user_id": user_id, "units": {s: new_unit() for s in SOURCES}}


def main():
    users = []
    unit_statuses = {s: [] for s in SOURCES}
    stopped = False
    user_ctxs = []

    root_kind, root_errno = lstat_kind(users_root)
    homes = None
    if root_kind != "dir":
        issue(code_for(root_kind, root_errno, users_root), users_root)
    else:
        try:
            homes = list_dir(users_root)
        except Abort as abort:
            issue(abort_code(abort, users_root), users_root)
    if homes is None:
        # No user was looked at: every source's per-user half is failed.
        for s in SOURCES:
            unit_statuses[s].append("failed")
        homes = []

    for name, k in homes:
        if name in SKIP_HOMES or k == "file":
            continue
        if len(users) >= MAX_USERS:
            state["truncated"] = True
            state["reason"] = state["reason"] or "user_limit"
            break
        home = os.path.join(users_root, name)
        uid = owner_of(home)
        ctx = new_ctx("user", clean_text(name, 255) or "<unprintable>", str(uid) if uid is not None else None)
        urow = {"user": ctx["user"], "user_id": ctx["user_id"], "collection_status": "failed",
                "sources": {src: "failed" for src in SOURCES}}
        users.append(urow)
        user_ctxs.append((ctx, urow))
        if k != "dir":
            issue(code_for(k), home)
            for s in SOURCES:
                ctx["units"][s]["problems"] += 1
            continue
        try:
            npm_for_home(ctx, home)
            pip_for_home(ctx, home)
            pipx_for_home(ctx, home)
        except Stop:
            for s in SOURCES:
                ctx["units"][s]["partial"] = True
            stopped = True
            break

    system_ctx = new_ctx("system", None, None)
    if not stopped:
        try:
            npm_system(system_ctx)
        except Stop:
            system_ctx["units"]["npm_global"]["partial"] = True
            stopped = True

    for ctx, urow in user_ctxs:
        statuses = [unit_status(ctx["units"][s]) for s in SOURCES]
        for s, st in zip(SOURCES, statuses):
            unit_statuses[s].append(st)
        urow["collection_status"] = combine(statuses)
        urow["sources"] = dict(zip(SOURCES, statuses))
    unit_statuses["npm_global"].append(unit_status(system_ctx["units"]["npm_global"]))

    sources = {}
    for s in SOURCES:
        st = combine(unit_statuses[s], truncated=stopped or full[s])
        sources[s] = {
            "collection_status": st,
            "truncated": stopped or full[s],
            "package_count": sum(1 for p in packages if p["source"] == s),
            "location_count": sum(1 for loc in locations if loc["source"] == s),
        }
    status = combine([sources[s]["collection_status"] for s in SOURCES], truncated=state["truncated"])
    return finish(status, sources, users)


def finish(status, sources, users):
    key = lambda p: (p["source"], p["user"] or "", p["prefix"] or "", p["name"] or "", p["directory"] or "")
    block = {
        "collection_status": status,
        "truncated": state["truncated"],
        "truncation_reason": state["reason"] if state["truncated"] else None,
        "sources": sources,
        "users": users,
        "locations": locations,
        "issues": state["issues"],
    }
    if status != "failed":
        block["packages"] = sorted(packages, key=key)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(block, f, separators=(",", ":"))
    summary = [status]
    for s in SOURCES:
        summary.append(sources[s]["package_count"] if status != "failed" else 0)
    summary.append(len(users))
    summary.extend(sources[s]["collection_status"] for s in SOURCES)
    print(*summary)
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
    _pm_pid=$!

    # A parser this loop killed is failed whatever wait reports: one that
    # finished between the last check and the kill is reaped with a clean
    # status, and its output is not trusted (PAT-2033).
    local _pm_killed=0
    while kill -0 "$_pm_pid" 2>/dev/null; do
        if (( _pm_ticks >= _PKG_HARD_TIMEOUT_SECONDS * 10 )); then
            kill -9 "$_pm_pid" 2>/dev/null
            _pm_killed=1
            log_warn "package_managers: parser still running after ${_PKG_HARD_TIMEOUT_SECONDS}s, killed; block is failed"
            break
        fi
        sleep 0.1
        (( _pm_ticks++ ))
    done
    wait "$_pm_pid" 2>/dev/null || _pm_rc=$?

    _pm_line=$(head -n 1 "$_pm_summary" 2>/dev/null)
    _pm_fields=(${=_pm_line})
    if (( _pm_killed == 0 && _pm_rc == 0 )) && (( ${#_pm_fields} == 8 )) \
        && [[ "${_pm_fields[1]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_pm_fields[2]}${_pm_fields[3]}${_pm_fields[4]}${_pm_fields[5]}" == <-> ]] \
        && [[ "${_pm_fields[6]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_pm_fields[7]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_pm_fields[8]}" == (complete|partial|not_present|failed) ]] \
        && "$PYTHON3" -c 'import json,sys; json.load(open(sys.argv[1]))' "$_pm_out" 2>/dev/null; then
        mv -f "$_pm_out" "$PACKAGE_MANAGERS_JSON_TMP"
        PACKAGE_MANAGERS_COLLECTION_STATUS="${_pm_fields[1]}"
        PACKAGE_MANAGERS_NPM_COUNT="${_pm_fields[2]}"
        PACKAGE_MANAGERS_PIP_COUNT="${_pm_fields[3]}"
        PACKAGE_MANAGERS_PIPX_COUNT="${_pm_fields[4]}"
        PACKAGE_MANAGERS_USER_COUNT="${_pm_fields[5]}"
        PACKAGE_MANAGERS_NPM_STATUS="${_pm_fields[6]}"
        PACKAGE_MANAGERS_PIP_STATUS="${_pm_fields[7]}"
        PACKAGE_MANAGERS_PIPX_STATUS="${_pm_fields[8]}"
        # PAT-2100: the parser's "tcc <denied-count> <verdict>" line; a missing
        # or garbled one is no opinion on Full Disk Access.
        patched_tcc_health package_managers ${=$(patched_tcc_summary "$_pm_summary")}
        # PAT-2225: an over-budget block is sent as failed (see common.sh).
        patched_block_within_budget package_managers "$PACKAGE_MANAGERS_JSON_TMP" "$_PKG_MAX_BYTES" \
            || PACKAGE_MANAGERS_COLLECTION_STATUS="failed"
    else
        # Parser stderr can carry file names from user-owned trees: newlines
        # become spaces and every other control character is dropped, so the
        # log line cannot be split or carry terminal escapes.
        log_warn "package_managers: parser failed (exit $_pm_rc): $(head -c 300 "$_pm_err" 2>/dev/null | tr '\n\t' '  ' | LC_ALL=C tr -d '\000-\037\177')"
        rm -f "$_pm_out"
    fi
    rm -f "$_pm_summary" "$_pm_err"
    local _pm_wire="held off the wire"
    (( _PACKAGE_MANAGERS_PAYLOAD_ON_WIRE )) && _pm_wire="sent"
    echo "package_managers: status=$(package_managers_collection_status) npm_global=$PACKAGE_MANAGERS_NPM_STATUS/$PACKAGE_MANAGERS_NPM_COUNT pip_user=$PACKAGE_MANAGERS_PIP_STATUS/$PACKAGE_MANAGERS_PIP_COUNT pipx=$PACKAGE_MANAGERS_PIPX_STATUS/$PACKAGE_MANAGERS_PIPX_COUNT users=$PACKAGE_MANAGERS_USER_COUNT ($_pm_wire)"
    return 0
}
