# mcp_servers.sh — MCP server configurations for every local user, read from
# the AI clients' own config files, reduced on the device to a server's name,
# transport, executable, package and URL host (PAT-2020).
#
# Sourced by patched-collect.sh; not executable directly.
# Requires: PATCHED_TMPDIR, PYTHON3 (set by main script before sourcing)
#
# WHAT THIS READS, AND ONLY THIS. Per user, under the home directory:
#
#   claude_desktop  Library/Application Support/Claude/claude_desktop_config.json
#                   "mcpServers"
#   cursor          .cursor/mcp.json                          "mcpServers"
#   vscode          Library/Application Support/Code/User/mcp.json   "servers"
#                   Library/Application Support/Code/User/settings.json
#                   "mcp": {"servers"} and a flat "mcp.servers" (the older
#                   form, before VS Code moved servers into mcp.json)
#   windsurf        .codeium/windsurf/mcp_config.json         "mcpServers"
#   claude_code     .claude.json: the top-level "mcpServers" (user scope) and
#                   each "projects".<dir>."mcpServers" (local scope, sent as
#                   scope "project" with the project directory left out).
#                   ~/.claude/settings.json holds no server definitions and is
#                   not read.
#
#   Every file is parsed as JSONC (comments and trailing commas, as VS Code
#   writes them) by a bounded state machine; nothing is ever evaluated. A file
#   that does not parse is unparseable and its client partial or failed.
#
# SECRETS NEVER ENTER THE BLOCK. Config files routinely carry API keys in
# env, headers, arguments and URLs (Andy's decision, 2026-09-22). Each server
# entry is handed to summarise_server, which reads exactly four inputs (type,
# command, args, url or serverUrl) and returns a new dict holding only:
#   name        the server's key, if it is safe text and not secret-shaped
#   transport   stdio, http, sse or unknown; transport_source declared or
#               inferred (a command means stdio, a URL with no type is http)
#   executable  the command's basename only, never its directory
#   runner      the package runner it names (npx, uvx, pipx, docker, ...)
#   package     the runner's package: the first positional argument after the
#               runner's own subcommand and flags, kept only when it matches
#               the strict npm, PyPI or Docker image pattern and is not
#               secret-shaped. Anything else is dropped and recorded as
#               package_status unrecognised, never sent raw.
#   host        a URL's host only: no scheme, userinfo, port, path or query
# env, headers, every other argument, the URL's path and query, and every
# other key are never copied anywhere; they go out of scope with the parsed
# file. Issues carry a code and the config file's path, never a value.
# test-mcp-servers.zsh plants a token in each of those places and fails if it
# appears anywhere in the block or the collect log.
#
# NOTHING IS EXECUTED AND NOTHING TOUCHES THE NETWORK. No MCP server, client
# or package runner is started. The [static] guard in test-mcp-servers.zsh
# goes red on a process launch, a network client or a read of any other file.
#
# EVERY HOME IS OWNED BY AN ORDINARY USER AND THIS RUNS AS ROOT. Nothing is
# followed: every file is opened O_NOFOLLOW|O_NONBLOCK and must be a regular
# file with a single link, under a size cap; every directory level is checked
# with lstat and never entered when it is a symlink. A linked config (a
# dotfiles checkout, say) is recorded as symlink_not_followed and the client
# is partial; it is not read through.
#
# The lstat checks decide what is reported; the walk is what keeps a read in
# the tree. Every open starts at / and opens each directory relative to the
# one before with O_NOFOLLOW, so a directory swapped for a symlink between its
# check and the read is refused as well (PAT-2033).
#
# ABSENCE REQUIRES AUTHORITY (PAT-1710). collection_status, overall, per
# client, per user and per config file, is one of:
#   complete     every config file found was read in full
#   partial      something was read but not everything (an unparseable file,
#                a link not followed, the server or 30-second bound)
#   not_present  every place was looked at and no config file exists; a
#                genuine reading, so an empty servers list is sent
#   failed       nothing trustworthy was read: servers is OMITTED, never sent
#                as [], so a failed read can never look like "no servers"
#
# PRIVACY PROTECTION (TCC, PAT-2100). Root without Full Disk Access may lstat
# ~/Library/Application Support/Claude and .../Code/User but open() fails with
# EPERM. That is the issue code tcc_denied, not unreadable; it is still a
# refusal like any other (nothing under it is read, and the client is failed
# or partial, never not_present or complete). The parser's summary line
# starting "tcc <count> <denied|reached|unknown>" feeds patched_tcc_health
# (common.sh), which writes or clears the agent_health entry tcc_denied /
# mcp_servers / full_disk_access_missing from the LaunchDaemon run only, as
# browser_extensions.sh does (PAT-2096).
#
# ON THE WIRE since PAT-2225 (2026-09-28). _MCP_SERVERS_PAYLOAD_ON_WIRE=1 makes
# mcp_servers_payload_member emit the block into the inventory payload, which
# the platform (PAT-2021) validates, behind its privacy guard, and ingests.
# The reduced server fields above are the agreed contract; no env, header,
# argument or URL path or query ever enters the block. The block is sent only
# within the _MCP_MAX_BYTES budget below; past it the block is sent as failed
# (patched_block_within_budget, common.sh). The collect log still carries
# counts only. Setting the constant back to 0 is the whole off switch;
# test-mcp-servers.zsh asserts it is 1 and still exercises the off path, so
# changing it must update that test in the same change.

_MCP_SERVERS_PAYLOAD_ON_WIRE=1

# Where home directories live. Tests reassign it after sourcing.
# ASSUMPTION: as in ide_extensions.sh, local homes are the directories
# directly under /Users. A relocated home, a VS Code Insiders or profile
# mcp.json, or a CLAUDE_CONFIG_DIR override is not seen.
_MCP_USERS_ROOT=/Users

# Bounds (PAT-2020). Past either, collection stops and is marked partial.
_MCP_MAX_SERVERS=2000
_MCP_TIME_BUDGET_SECONDS=30
# The parser checks its own budget between entries; this is the outer limit
# for a read that blocks inside one syscall. Past it the parser is killed and
# the block is failed.
_MCP_HARD_TIMEOUT_SECONDS=45
# Byte budget for the serialised block (PAT-2225), about 800 servers at the
# ~300 bytes a real row takes. The four tooling blocks together stay within
# 2 MiB, as the homebrew block does, so the two leave 2 MiB of the server's
# 6 MiB inventory body cap for everything else. Past the budget the block is
# sent as failed, never cut down: the platform's tooling contract has no
# size_limit reason. Tests lower it after sourcing.
_MCP_MAX_BYTES=$(( 256 * 1024 ))

# mcp_servers_collection_status
#   Prints the wire value. Anything but the four known values is failed.
mcp_servers_collection_status() {
    case "${MCP_SERVERS_COLLECTION_STATUS:-}" in
        complete|partial|not_present) print -r -- "$MCP_SERVERS_COLLECTION_STATUS" ;;
        *) print -r -- "failed" ;;
    esac
}

# mcp_servers_payload_member
#   Prints `"mcp_servers": {...},` for the payload heredoc, or nothing when
#   the wire flag is 0 (see header). A failed status with no written block
#   sends only {"collection_status":"failed"}.
mcp_servers_payload_member() {
    (( _MCP_SERVERS_PAYLOAD_ON_WIRE )) || return 0
    if [[ "$(mcp_servers_collection_status)" == "failed" ]] \
        || [[ -z "${MCP_SERVERS_JSON_TMP:-}" || ! -s "$MCP_SERVERS_JSON_TMP" ]]; then
        printf '"mcp_servers": {"collection_status": "failed"},'
        return 0
    fi
    printf '"mcp_servers": %s,' "$(cat "$MCP_SERVERS_JSON_TMP")"
}

collect_mcp_servers() {
    MCP_SERVERS_COLLECTION_STATUS="failed"
    MCP_SERVERS_SERVER_COUNT=0
    MCP_SERVERS_CONFIG_COUNT=0
    MCP_SERVERS_USER_COUNT=0
    MCP_SERVERS_CLAUDE_DESKTOP_STATUS="failed"
    MCP_SERVERS_CURSOR_STATUS="failed"
    MCP_SERVERS_VSCODE_STATUS="failed"
    MCP_SERVERS_WINDSURF_STATUS="failed"
    MCP_SERVERS_CLAUDE_CODE_STATUS="failed"
    # Reuse the caller's placeholder file if it made one, so it is not orphaned.
    if [[ -z "${MCP_SERVERS_JSON_TMP:-}" || ! -f "$MCP_SERVERS_JSON_TMP" ]]; then
        MCP_SERVERS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/mcp-servers.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    fi
    printf '{"collection_status": "failed"}' > "$MCP_SERVERS_JSON_TMP"

    local _mcp_out _mcp_summary _mcp_err _mcp_pid _mcp_rc=0 _mcp_ticks=0 _mcp_line
    local -a _mcp_fields
    _mcp_out=$(mktemp "$PATCHED_TMPDIR/mcp-servers-out.XXXXXX")
    _mcp_summary=$(mktemp "$PATCHED_TMPDIR/mcp-servers-summary.XXXXXX")
    _mcp_err=$(mktemp "$PATCHED_TMPDIR/mcp-servers-err.XXXXXX")

    # The program arrives on stdin through the heredoc, so every input is an
    # argv entry, never piped (see the python3 heredoc footgun in AGENTS.md).
    "$PYTHON3" - "$_mcp_out" "$_MCP_MAX_SERVERS" "$_MCP_TIME_BUDGET_SECONDS" \
        "$_MCP_USERS_ROOT" > "$_mcp_summary" 2> "$_mcp_err" <<'PYEOF' &
import errno
import json
import os
import re
import stat
import sys
import time

out_path = sys.argv[1]
max_servers = int(sys.argv[2])
budget = float(sys.argv[3])
users_root = os.path.normpath(sys.argv[4])
deadline = time.monotonic() + budget

CONFIG_CAP = 1024 * 1024
SETTINGS_CAP = 4 * 1024 * 1024
CLAUDE_JSON_CAP = 8 * 1024 * 1024
# The Windows reader parses with JsonDocumentOptions.MaxDepth = 64; the same
# limit here keeps one file unparseable on both agents rather than deep enough
# to exhaust the interpreter on one and parse on the other.
MAX_JSON_DEPTH = 64
TEXT_CAP = 512
MAX_USERS = 500
MAX_ISSUES = 50
MAX_ARGS = 256
MAX_PROJECTS = 1000
SKIP_HOMES = {"Shared", "Guest"}
CLIENTS = ("claude_desktop", "cursor", "vscode", "windsurf", "claude_code")

APP_SUPPORT = ("Library", "Application Support")
# (client, directory under the home, file name, layout, size cap)
CONFIGS = (
    ("claude_desktop", APP_SUPPORT + ("Claude",), "claude_desktop_config.json", "mcpServers", CONFIG_CAP),
    ("cursor", (".cursor",), "mcp.json", "mcpServers", CONFIG_CAP),
    ("vscode", APP_SUPPORT + ("Code", "User"), "mcp.json", "servers", CONFIG_CAP),
    ("vscode", APP_SUPPORT + ("Code", "User"), "settings.json", "vscode_settings", SETTINGS_CAP),
    ("windsurf", (".codeium", "windsurf"), "mcp_config.json", "mcpServers", CONFIG_CAP),
    ("claude_code", (), ".claude.json", "claude_code", CLAUDE_JSON_CAP),
)


class Stop(Exception):
    pass


class Abort(Exception):
    """A directory could not be listed."""


class Full(Exception):
    pass


# tcc_denied and unreached count every refusal, past the MAX_ISSUES cap on
# the issues list, for the agent_health verdict (PAT-2100).
state = {"truncated": False, "reason": None, "issues": [], "tcc_denied": set(), "unreached": 0}
count = {"servers": 0}


# --- helpers copied verbatim from ide_extensions.sh --------------------------
# test-package-managers.zsh [drift] fails if any of these stops matching its
# twin there (it checks this file too), so a hardening fix to one cannot
# silently skip the other.

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


def issue(code, where):
    if len(state["issues"]) < MAX_ISSUES:
        state["issues"].append({"code": code, "path": clean_path(where)})


def denied_code(err_no, denied):
    """The issue code for a path that could not be read: tcc_denied when the
    errno is EPERM, else unreadable (PAT-2100, as PAT-2096 did for browser
    extensions). As root, EPERM here is macOS privacy protection (TCC): without
    Full Disk Access, root may lstat another app's data folder
    (~/Library/Application Support/Claude, .../Code/User) but not open it. Either way nothing
    under it is read and the client is not complete. Any errno counts toward the
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


def walk(anchor, parts):
    """(kind, path, errno): every component below anchor is checked with lstat,
    and the walk stops at the first that is not a directory. ("dir", full
    path, None) when all of them are directories. errno is lstat_kind's for an
    error kind."""
    p = anchor
    for part in parts:
        p = os.path.join(p, part)
        k, err_no = lstat_kind(p)
        if k != "dir":
            return k, p, err_no
    return "dir", p, None


# --- JSONC ----------------------------------------------------------------------

def strip_jsonc(text):
    """text with // and /* */ comments and trailing commas removed, outside
    strings, by one bounded pass; None for an unterminated comment or string.
    Nothing is evaluated: the result goes to json.loads."""
    out = []
    i, n = 0, len(text)
    pending_comma = None  # index in out of a comma that may turn out trailing
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == '"':
                    break
                j += 1
            if j >= n:
                return None
            out.append(text[i:j + 1])
            pending_comma = None
            i = j + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                return None
            out.append(" ")
            i = j + 2
            continue
        if ch in "}]" and pending_comma is not None:
            out[pending_comma] = " "
            pending_comma = None
        if ch == ",":
            pending_comma = len(out)
        elif not ch.isspace():
            pending_comma = None
        out.append(ch)
        i += 1
    return "".join(out)


def json_depth_ok(text):
    """False when arrays and objects nest deeper than MAX_JSON_DEPTH, counted
    outside strings, before json.loads is asked to recurse into them."""
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def parse_jsonc(data):
    """The parsed top-level object, or None when the file is not a JSON(C)
    object within the depth limit."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    text = strip_jsonc(text)
    if text is None or not json_depth_ok(text):
        return None
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


# --- the minimal server model ----------------------------------------------------
# Everything below this line sees one server entry and returns only the fields
# the header lists. Nothing here stores an argument, an env value, a header or
# a URL; the only strings that leave are ones that passed a strict pattern.

# Known credential shapes, and any unbroken run of 32 or more letters and
# digits (a key, a hash, a token). Applied to every emitted string.
SECRET_SHAPE_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:sk|pk|rk)[-_]|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|AKIA[0-9A-Z]{12}"
    r"|AIza[0-9A-Za-z_-]{8}|eyJ[A-Za-z0-9_-]{4}|ya29\.|[A-Za-z0-9]{32}")
# Words that make a package candidate look like a credential rather than a
# package; a candidate carrying one is dropped (a server name may keep them).
SECRET_WORD_RE = re.compile(r"(?i)token|secret|passw|bearer|api[-_]?key|credential|auth[-_]?key")

NAME_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9 ._@/+()\-]{0,127}\Z")
EXECUTABLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}\Z")
NPM_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._\-]*/)?[a-z0-9][a-z0-9._\-]*\Z")
PYPI_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,98}[A-Za-z0-9])?\Z")
VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,64}\Z")
DOCKER_PATH_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\Z")
DOCKER_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}\Z")
DOCKER_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
# Only public registries are named; an image from any other registry carries
# that registry's hostname, so it is dropped like any internal hostname.
PUBLIC_REGISTRIES = {"docker.io", "index.docker.io", "registry-1.docker.io", "ghcr.io", "quay.io",
                     "mcr.microsoft.com", "public.ecr.aws", "gcr.io", "registry.gitlab.com"}
URL_RE = re.compile(r"^(?:[Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?)://([^/?#]*)")
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\Z")
IPV6_RE = re.compile(r"^[0-9a-f:.]{2,45}\Z")

# Package runners: (subcommand tokens, flags that take a value, flags whose
# value is the package, flags after which no package can be named, kind).
NPX_VALUE = {"-p", "--package", "--registry", "--cache", "--userconfig", "-w", "--workspace", "--prefix",
             "--node-options", "--shell", "--script-shell", "-c", "--call"}
UV_VALUE = {"--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index",
            "--index-url", "--extra-index-url", "--default-index", "--find-links", "-f", "--directory",
            "--project", "--cache-dir", "--config-file", "--constraints", "--overrides", "--build-constraints",
            "--index-strategy", "--keyring-provider", "--exclude-newer", "--refresh-package", "--reinstall-package",
            "--upgrade-package", "--color", "--python-preference", "--env-file"}
RUNNERS = {
    "npx": ((), NPX_VALUE, {"-p", "--package"}, {"-c", "--call"}, "npm"),
    "npm": (("exec",), NPX_VALUE, {"-p", "--package"}, {"-c", "--call"}, "npm"),
    "bunx": ((), {"-p", "--package"}, {"-p", "--package"}, set(), "npm"),
    "pnpx": ((), {"--package"}, {"--package"}, set(), "npm"),
    "pnpm": (("dlx",), {"--package"}, {"--package"}, set(), "npm"),
    "yarn": (("dlx",), {"-p", "--package"}, {"-p", "--package"}, set(), "npm"),
    "uvx": ((), UV_VALUE, {"--from"}, set(), "pypi"),
    "uv": (("tool", "run"), UV_VALUE, {"--from"}, set(), "pypi"),
    "pipx": (("run",), {"--spec", "--python", "--index-url", "-i", "--pip-args"}, {"--spec"}, set(), "pypi"),
    "docker": (("run",), None, set(), set(), "docker"),
    "podman": (("run",), None, set(), set(), "docker"),
}
RUNNER_ALIASES = {"npm": {"x": "exec"}}
# docker run flags that take no value; every other flag is assumed to take one
# unless written --flag=value, so a value is never mistaken for the image.
DOCKER_BOOL_LONG = {"--rm", "--init", "--privileged", "--read-only", "--detach", "--interactive", "--tty",
                    "--publish-all", "--no-healthcheck", "--oom-kill-disable", "--quiet", "--help", "--sig-proxy"}
DOCKER_BOOL_SHORT = set("itdPq")
WRAPPERS = {"cmd": ("/c", "/k")}
RUNNER_EXTENSIONS = {"exe", "cmd", "bat", "ps1"}


def looks_secret(value):
    return SECRET_SHAPE_RE.search(value) is not None


def safe_name(value):
    v = clean_text(value, 128)
    if v is None or not NAME_RE.match(v) or looks_secret(v):
        return None
    return v


def executable_name(command):
    """The basename of a command, or None when it is not a plain executable
    name (a command line written into one string, a variable, anything
    secret-shaped)."""
    if not isinstance(command, str) or len(command) > 4096:
        return None
    base = re.split(r"[\\/]", command.strip())[-1]
    if not EXECUTABLE_RE.match(base) or looks_secret(base):
        return None
    return base


def runner_key(executable):
    low = executable.lower()
    stem, dot, ext = low.rpartition(".")
    return stem if dot and stem and ext in RUNNER_EXTENSIONS else low


def strip_version(candidate, scoped):
    at = candidate.find("@", 1 if scoped else 0)
    if at <= 0:
        return candidate
    if not VERSION_RE.match(candidate[at + 1:]):
        return None
    return candidate[:at]


def docker_image(candidate):
    """registry/path of a public image, without tag or digest, or None."""
    ref = candidate
    at = ref.find("@")
    if at >= 0:
        if not DOCKER_DIGEST_RE.match(ref[at + 1:]):
            return None
        ref = ref[:at]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        if not DOCKER_TAG_RE.match(ref[colon + 1:]):
            return None
        ref = ref[:colon]
    parts = ref.split("/")
    registry = None
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        registry = parts[0]
        parts = parts[1:]
        if registry.lower() not in PUBLIC_REGISTRIES:
            return None
    path_part = "/".join(parts)
    if not DOCKER_PATH_RE.match(path_part):
        return None
    return (registry.lower() + "/" if registry else "") + path_part


def valid_package(pkg_kind, candidate):
    """The package name candidate names, or None when it fails the strict
    pattern for its kind. Never returns a path, a URL, anything with "=" or
    anything secret-shaped."""
    if not isinstance(candidate, str) or not candidate or len(candidate) > 214:
        return None
    # A docker digest is 64 hex characters by design; it is checked by its own
    # pattern and dropped, so only the rest of the reference is secret-checked.
    probe = candidate.split("@sha256:", 1)[0] if pkg_kind == "docker" else candidate
    if ("=" in candidate or "://" in candidate or "\\" in candidate or candidate[0] in "./~$%"
            or looks_secret(probe) or SECRET_WORD_RE.search(probe)):
        return None
    if pkg_kind == "npm":
        name = strip_version(candidate, candidate.startswith("@"))
        return name if name is not None and NPM_RE.match(name) else None
    if pkg_kind == "pypi":
        name = strip_version(candidate, False)
        return name if name is not None and PYPI_RE.match(name) else None
    if pkg_kind == "docker":
        return docker_image(candidate)
    return None


def takes_value(flag, value_flags):
    if value_flags is not None:
        return flag in value_flags
    # docker: bundled short booleans (-it) take none; any other flag does.
    if flag.startswith("--"):
        return flag not in DOCKER_BOOL_LONG
    return not all(c in DOCKER_BOOL_SHORT for c in flag[1:])


def package_of(runner, args):
    """(package_status, package): extracted, unrecognised, missing or
    not_applicable. args is walked only to find the one candidate; nothing
    else is kept."""
    subs, value_flags, package_flags, terminal_flags, pkg_kind = RUNNERS[runner]
    aliases = RUNNER_ALIASES.get(runner, {})
    i, n, sub_i = 0, min(len(args), MAX_ARGS), 0
    while i < n:
        a = args[i]
        if not isinstance(a, str):
            return "unrecognised", None
        if sub_i < len(subs):
            if a.startswith("-"):
                i += 1
                continue
            if aliases.get(a, a) != subs[sub_i]:
                return "not_applicable", None
            sub_i += 1
            i += 1
            continue
        if a == "--":
            cand = args[i + 1] if i + 1 < n else None
            break
        if a.startswith("-") and len(a) > 1:
            flag, eq, val = a.partition("=")
            if flag in terminal_flags:
                return "unrecognised", None
            if flag in package_flags:
                cand = val if eq else (args[i + 1] if i + 1 < n else None)
                break
            i += 1 if eq or not takes_value(flag, value_flags) else 2
            continue
        cand = a
        break
    else:
        return ("missing", None) if sub_i == len(subs) else ("not_applicable", None)
    if cand is None:
        return "missing", None
    name = valid_package(pkg_kind, cand)
    return ("extracted", name) if name is not None else ("unrecognised", None)


def url_host(url):
    """A URL's host, lower-cased, with no scheme, userinfo, port, path or
    query, or None when it is not an http(s)/ws(s) URL with a plain host."""
    if not isinstance(url, str) or len(url) > 4096:
        return None
    m = URL_RE.match(url.strip())
    if m is None:
        return None
    authority = m.group(1).rsplit("@", 1)[-1]
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[1:end].lower() if end > 0 else ""
        # A bracketed value with no colon is not an IPv6 literal: a hex token
        # would otherwise go out as the host. The server rejects one, so it is
        # dropped here rather than fail the whole payload (PAT-2033).
        return host if ":" in host and IPV6_RE.match(host) else None
    host = authority.split(":", 1)[0].lower().rstrip(".")
    if not HOST_RE.match(host) or looks_secret(host):
        return None
    return host


def transport_of(declared, command, url):
    if isinstance(declared, str):
        t = declared.strip().lower()
        if t == "stdio":
            return "stdio", "declared"
        if t in ("http", "streamable-http", "streamable_http", "streamablehttp"):
            return "http", "declared"
        if t == "sse":
            return "sse", "declared"
        return "unknown", "declared"
    if isinstance(command, str):
        return "stdio", "inferred"
    if isinstance(url, str):
        return "http", "inferred"
    return "unknown", "inferred"


def summarise_server(name, entry):
    """(row, issue codes). The row is built from nothing but the fields the
    header lists; entry's env, headers, args and URL never reach it."""
    codes = []
    row = {"name": safe_name(name), "transport": "unknown", "transport_source": "inferred",
           "executable": None, "runner": None, "package": None, "package_status": "not_applicable",
           "host": None}
    if row["name"] is None:
        codes.append("name_unsafe")
    if not isinstance(entry, dict):
        codes.append("server_unparseable")
        return row, codes
    command = entry.get("command")
    url = entry.get("url")
    if not isinstance(url, str):
        url = entry.get("serverUrl")
    row["transport"], row["transport_source"] = transport_of(entry.get("type"), command, url)
    if command is not None:
        executable = executable_name(command)
        if executable is None:
            codes.append("executable_unrecognised")
        else:
            row["executable"] = executable
            args = entry.get("args")
            args = args if isinstance(args, list) else []
            key = runner_key(executable)
            if key in WRAPPERS and args and isinstance(args[0], str) and args[0].lower() in WRAPPERS[key]:
                inner = executable_name(args[1]) if len(args) > 1 else None
                key = runner_key(inner) if inner else None
                args = args[2:]
            if key in RUNNERS:
                row["runner"] = key
                row["package_status"], row["package"] = package_of(key, args)
                if row["package_status"] == "unrecognised":
                    codes.append("package_unrecognised")
    if url is not None:
        row["host"] = url_host(url)
        if row["host"] is None:
            codes.append("url_unrecognised")
    return row, codes


def server_maps(obj, layout):
    """([(scope, {name: entry})], capped) for one parsed file, or None when a
    key that should hold servers is there but is not an object. capped is True
    when Claude Code's projects ran past MAX_PROJECTS and the rest were not
    looked at."""
    def one(value, scope, found):
        if value is None:
            return True
        if not isinstance(value, dict):
            return False
        found.append((scope, value))
        return True

    found = []
    if layout in ("mcpServers", "servers"):
        return (found, False) if one(obj.get(layout), "user", found) else None
    if layout == "vscode_settings":
        mcp = obj.get("mcp")
        ok = one(obj.get("mcp.servers"), "user", found)
        if mcp is not None:
            ok = ok and isinstance(mcp, dict) and one(mcp.get("servers"), "user", found)
        return (found, False) if ok else None
    # claude_code: user scope at the top, local scope under each project. A
    # project entry that is not an object holds no servers and is skipped.
    ok = one(obj.get("mcpServers"), "user", found)
    projects = obj.get("projects")
    capped = False
    if isinstance(projects, dict):
        for index, project in enumerate(projects.values()):
            if index >= MAX_PROJECTS:
                capped = True
                break
            if isinstance(project, dict):
                ok = one(project.get("mcpServers"), "project", found) and ok
    elif projects is not None:
        ok = False
    return (found, capped) if ok else None


# --- units and users -------------------------------------------------------------

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


configs = []
servers = []


def read_config(ctx, home, client, parts, filename, layout, cap):
    unit = ctx["units"][client]
    check_time()
    k, where, k_errno = walk(home, parts)
    if k == "absent":
        return
    if k != "dir":
        issue(code_for(k, k_errno, where), where)
        if k == "symlink":
            unit["partial"] = True
        else:
            unit["problems"] += 1
        return
    path = os.path.join(where, filename)
    fk, fk_errno = lstat_kind(path)
    if fk == "absent":
        return
    if fk != "file":
        # A linked config (a dotfiles checkout) is recorded and not read
        # through, and not claimed as a config; anything else is a problem.
        # Without Full Disk Access the config's own folder cannot be opened,
        # so its lstat fails here with EPERM: tcc_denied (PAT-2100).
        issue(code_for(fk, fk_errno, path), path)
        if fk == "symlink":
            unit["partial"] = True
        else:
            unit["problems"] += 1
        return
    status, data, err_no = read_file_errno(path, cap)
    if status == "missing":
        return
    unit["locations"] += 1
    row = {"client": client, "user": ctx["user"], "user_id": ctx["user_id"], "path": clean_path(path),
           "collection_status": "failed", "server_count": 0}
    configs.append(row)
    if status != "read":
        issue(denied_code(err_no, path), path)
        unit["problems"] += 1
        return
    obj = parse_jsonc(data)
    data = None
    maps = server_maps(obj, layout) if obj is not None else None
    obj = None
    if maps is None:
        issue("unparseable", path)
        unit["problems"] += 1
        return
    maps, partial = maps
    if partial:
        issue("project_limit", path)
    try:
        for scope, entries in maps:
            for name, entry in entries.items():
                check_time()
                if count["servers"] >= max_servers:
                    state["truncated"] = True
                    state["reason"] = state["reason"] or "server_limit"
                    raise Full()
                count["servers"] += 1
                srow, codes = summarise_server(name, entry)
                for code in codes:
                    issue(code, path)
                if "server_unparseable" in codes:
                    partial = True
                out = {"client": client, "user": ctx["user"], "user_id": ctx["user_id"],
                       "config_path": row["path"], "scope": scope}
                out.update(srow)
                servers.append(out)
                row["server_count"] += 1
    except (Full, Stop) as stopped:
        row["collection_status"] = "partial"
        unit["partial"] = True
        unit["ok"] += 1
        if isinstance(stopped, Stop):
            raise
        return
    row["collection_status"] = "partial" if partial else "complete"
    unit["ok"] += 1
    if partial:
        unit["partial"] = True


def owner_of(path):
    try:
        return lstat_at(path).st_uid
    except OSError:
        return None


def main():
    users = []
    client_statuses = {c: [] for c in CLIENTS}
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
        for c in CLIENTS:
            client_statuses[c].append("failed")
        homes = []

    for name, k in homes:
        if stopped:
            break
        if name in SKIP_HOMES or k == "file":
            continue
        if len(users) >= MAX_USERS:
            state["truncated"] = True
            state["reason"] = state["reason"] or "user_limit"
            break
        home = os.path.join(users_root, name)
        uid = owner_of(home)
        ctx = {"user": clean_text(name, 255) or "<unprintable>", "user_id": str(uid) if uid is not None else None,
               "units": {c: new_unit() for c in CLIENTS}}
        urow = {"user": ctx["user"], "user_id": ctx["user_id"], "collection_status": "failed",
                "clients": {c: "failed" for c in CLIENTS}}
        users.append(urow)
        user_ctxs.append((ctx, urow))
        if k != "dir":
            issue(code_for(k), home)
            for c in CLIENTS:
                ctx["units"][c]["problems"] += 1
            continue
        try:
            for client, parts, filename, layout, cap in CONFIGS:
                read_config(ctx, home, client, parts, filename, layout, cap)
        except Stop:
            for c in CLIENTS:
                ctx["units"][c]["partial"] = True
            stopped = True

    for ctx, urow in user_ctxs:
        statuses = [unit_status(ctx["units"][c]) for c in CLIENTS]
        for c, st in zip(CLIENTS, statuses):
            client_statuses[c].append(st)
        urow["collection_status"] = combine(statuses)
        urow["clients"] = dict(zip(CLIENTS, statuses))

    clients = {}
    for c in CLIENTS:
        clients[c] = {
            "collection_status": combine(client_statuses[c], truncated=stopped),
            "config_count": sum(1 for r in configs if r["client"] == c),
            "server_count": sum(1 for s in servers if s["client"] == c),
        }
    status = combine([clients[c]["collection_status"] for c in CLIENTS], truncated=state["truncated"])
    finish(status, clients, users)


def finish(status, clients, users):
    key = lambda s: (s["client"], s["user"] or "", s["config_path"], s["scope"], s["name"] or "")
    block = {
        "collection_status": status,
        "truncated": state["truncated"],
        "truncation_reason": state["reason"] if state["truncated"] else None,
        "clients": clients,
        "totals": {"config_count": len(configs), "server_count": len(servers)},
        "users": users,
        "configs": configs,
        "issues": state["issues"],
    }
    if status != "failed":
        block["servers"] = sorted(servers, key=key)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(block, f, separators=(",", ":"))
    failed = status == "failed"
    print(status, 0 if failed else len(servers), len(configs), len(users),
          *(clients[c]["collection_status"] for c in CLIENTS))
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
    _mcp_pid=$!

    # A parser this loop killed is failed whatever wait reports: one that
    # finished between the last check and the kill is reaped with a clean
    # status, and its output is not trusted (PAT-2033).
    local _mcp_killed=0
    while kill -0 "$_mcp_pid" 2>/dev/null; do
        if (( _mcp_ticks >= _MCP_HARD_TIMEOUT_SECONDS * 10 )); then
            kill -9 "$_mcp_pid" 2>/dev/null
            _mcp_killed=1
            log_warn "mcp_servers: parser still running after ${_MCP_HARD_TIMEOUT_SECONDS}s, killed; block is failed"
            break
        fi
        sleep 0.1
        (( _mcp_ticks++ ))
    done
    wait "$_mcp_pid" 2>/dev/null || _mcp_rc=$?

    _mcp_line=$(head -n 1 "$_mcp_summary" 2>/dev/null)
    _mcp_fields=(${=_mcp_line})
    if (( _mcp_killed == 0 && _mcp_rc == 0 )) && (( ${#_mcp_fields} == 9 )) \
        && [[ "${_mcp_fields[1]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_mcp_fields[2]}${_mcp_fields[3]}${_mcp_fields[4]}" == <-> ]] \
        && [[ "${_mcp_fields[5]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_mcp_fields[6]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_mcp_fields[7]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_mcp_fields[8]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_mcp_fields[9]}" == (complete|partial|not_present|failed) ]] \
        && "$PYTHON3" -c 'import json,sys; json.load(open(sys.argv[1]))' "$_mcp_out" 2>/dev/null; then
        mv -f "$_mcp_out" "$MCP_SERVERS_JSON_TMP"
        MCP_SERVERS_COLLECTION_STATUS="${_mcp_fields[1]}"
        MCP_SERVERS_SERVER_COUNT="${_mcp_fields[2]}"
        MCP_SERVERS_CONFIG_COUNT="${_mcp_fields[3]}"
        MCP_SERVERS_USER_COUNT="${_mcp_fields[4]}"
        MCP_SERVERS_CLAUDE_DESKTOP_STATUS="${_mcp_fields[5]}"
        MCP_SERVERS_CURSOR_STATUS="${_mcp_fields[6]}"
        MCP_SERVERS_VSCODE_STATUS="${_mcp_fields[7]}"
        MCP_SERVERS_WINDSURF_STATUS="${_mcp_fields[8]}"
        MCP_SERVERS_CLAUDE_CODE_STATUS="${_mcp_fields[9]}"
        # PAT-2100: the parser's "tcc <denied-count> <verdict>" line; a missing
        # or garbled one is no opinion on Full Disk Access.
        patched_tcc_health mcp_servers ${=$(patched_tcc_summary "$_mcp_summary")}
        # PAT-2225: an over-budget block is sent as failed (see common.sh).
        patched_block_within_budget mcp_servers "$MCP_SERVERS_JSON_TMP" "$_MCP_MAX_BYTES" \
            || MCP_SERVERS_COLLECTION_STATUS="failed"
    else
        # Parser stderr is never logged: a traceback from json or the server
        # model could quote a config value, and config values carry secrets.
        # The exit status is enough to know it failed.
        log_warn "mcp_servers: parser failed (exit $_mcp_rc); block is failed"
        rm -f "$_mcp_out"
    fi
    rm -f "$_mcp_summary" "$_mcp_err"
    local _mcp_wire="held off the wire"
    (( _MCP_SERVERS_PAYLOAD_ON_WIRE )) && _mcp_wire="sent"
    echo "mcp_servers: status=$(mcp_servers_collection_status) claude_desktop=$MCP_SERVERS_CLAUDE_DESKTOP_STATUS cursor=$MCP_SERVERS_CURSOR_STATUS vscode=$MCP_SERVERS_VSCODE_STATUS windsurf=$MCP_SERVERS_WINDSURF_STATUS claude_code=$MCP_SERVERS_CLAUDE_CODE_STATUS configs=$MCP_SERVERS_CONFIG_COUNT servers=$MCP_SERVERS_SERVER_COUNT users=$MCP_SERVERS_USER_COUNT ($_mcp_wire)"
    return 0
}
