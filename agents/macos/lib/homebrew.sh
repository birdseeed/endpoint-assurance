# homebrew.sh — Homebrew formulae, casks and taps read from disk (PAT-2012).
#
# Sourced by patched-collect.sh; not executable directly.
# Requires: PATCHED_TMPDIR, PYTHON3 (set by main script before sourcing)
#
# WHAT THIS READS, AND ONLY THIS. For each prefix in _HOMEBREW_PREFIXES that
# carries a Homebrew layout (a Cellar, a Caskroom, or the Homebrew repository
# at Library/Homebrew or Homebrew/Library/Homebrew):
#   Cellar/<name>/<version>/INSTALL_RECEIPT.json   formula receipt (JSON)
#   Cellar/<name>/<version>/.brew/<name>.rb        homepage and source url,
#                                                  matched line by line as
#                                                  text; the Ruby is never
#                                                  loaded or evaluated
#   opt/<name>                                     symlink, read with readlink
#                                                  to tell which keg is current
#   Caskroom/<token>/<version>, .metadata/INSTALL_RECEIPT.json
#   Library/Taps/<user>/<repo>/.git/config         the remote url, read as text
#                                                  (under <prefix>/Homebrew for
#                                                  an Intel /usr/local install)
#
# NEVER EXECUTES HOMEBREW AND NEVER TOUCHES THE NETWORK. No brew command, no
# Homebrew API, no formulae site, no git. Every read is an open() of a file in
# the tree above. macos/lib/test-homebrew.zsh carries a static guard that goes
# red if this file gains a Homebrew invocation, a network client or a process
# launch inside the parser; do not spell any of those out, even in comments.
#
# THE TREE IS OWNED BY AN ORDINARY USER AND THIS RUNS AS ROOT. So nothing is
# followed that the user could point somewhere else: every file is opened
# O_NOFOLLOW|O_NONBLOCK and must be a regular file with a single link, under a
# size cap, and every directory level is checked with lstat and skipped when
# it is a symlink. A planted symlink, hard link or FIFO costs one entry (marked
# partial), never a read of a root-only file or a hung collector. URLs have
# any userinfo and secret-looking query values removed before they leave the
# device, since a private tap's remote can carry a token.
#
# The lstat checks decide what is reported; the walk is what keeps a read in
# the tree. Every open starts at / and opens each directory relative to the
# one before with O_NOFOLLOW, so a directory swapped for a symlink between its
# check and the read is refused as well (PAT-2033).
#
# ABSENCE REQUIRES AUTHORITY (PAT-1710). collection_status is one of:
#   complete     every prefix with a layout was read in full
#   partial      something was read but not everything (an unreadable
#                receipt, a symlink not followed, the 5,000-formula or
#                30-second bound): the lists are what was seen, not all there is
#   not_present  both prefixes were checked and neither has a Homebrew layout;
#                a genuine reading, so the empty lists are sent
#   failed       nothing trustworthy was read: the lists are OMITTED, never
#                sent as [], so a failed read can never look like "no packages"
#
# ON THE WIRE since PAT-2032 (2026-09-28). _HOMEBREW_PAYLOAD_ON_WIRE=1 makes
# homebrew_payload_member emit the block into the inventory payload, which the
# platform (PAT-2013) ingests. The block is sent only within the 2 MiB
# _HOMEBREW_MAX_BYTES budget below: past it, whole entries are dropped and the
# block is partial, and a block nothing honest fits in is sent as failed. The
# flip followed a Tenant Zero root run under the LaunchDaemon on the staging
# VM (release 0.19.23). Setting the constant back to 0 is the whole off
# switch; test-homebrew.zsh asserts it is 1 and still exercises the off path,
# so changing it must update that test in the same change.

_HOMEBREW_PAYLOAD_ON_WIRE=1

# Prefixes checked, in order. Tests reassign this array after sourcing.
_HOMEBREW_PREFIXES=(/opt/homebrew /usr/local)

# Bounds (PAT-2012). Past either, collection stops and is marked partial.
_HOMEBREW_MAX_FORMULAE=5000
_HOMEBREW_TIME_BUDGET_SECONDS=30
# The parser checks its own 30-second budget between entries; this is the
# outer limit for a read that blocks inside one syscall (a hung mount). Past
# it the parser is killed and the block is failed.
_HOMEBREW_HARD_TIMEOUT_SECONDS=45
# Byte budget for the serialised block (PAT-2032). The server truncates an
# inventory body at 6 MB, after which the HMAC check fails and the device gets
# a 401 on every check-in, so the block alone must stay well under that. Past
# the budget, whole entries are dropped (formulae first, then casks, then
# taps) and the block is partial with truncation_reason size_limit. Tests
# lower it after sourcing.
_HOMEBREW_MAX_BYTES=$(( 2 * 1024 * 1024 ))

# homebrew_collection_status
#   Prints the wire value. Anything but the four known values is failed.
homebrew_collection_status() {
    case "${HOMEBREW_COLLECTION_STATUS:-}" in
        complete|partial|not_present) print -r -- "$HOMEBREW_COLLECTION_STATUS" ;;
        *) print -r -- "failed" ;;
    esac
}

# homebrew_payload_member
#   Prints `"homebrew": {...},` for the payload heredoc, or nothing when the
#   wire flag is 0 (see header). A failed status sends only
#   {"collection_status":"failed"}.
homebrew_payload_member() {
    (( _HOMEBREW_PAYLOAD_ON_WIRE )) || return 0
    if [[ "$(homebrew_collection_status)" == "failed" ]] \
        || [[ -z "${HOMEBREW_JSON_TMP:-}" || ! -s "$HOMEBREW_JSON_TMP" ]]; then
        printf '"homebrew": {"collection_status": "failed"},'
        return 0
    fi
    printf '"homebrew": %s,' "$(cat "$HOMEBREW_JSON_TMP")"
}

collect_homebrew() {
    HOMEBREW_COLLECTION_STATUS="failed"
    HOMEBREW_FORMULA_COUNT=0
    HOMEBREW_CASK_COUNT=0
    HOMEBREW_TAP_COUNT=0
    # Reuse the caller's placeholder file if it made one, so it is not orphaned.
    if [[ -z "${HOMEBREW_JSON_TMP:-}" || ! -f "$HOMEBREW_JSON_TMP" ]]; then
        HOMEBREW_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/homebrew.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    fi
    printf '{"collection_status": "failed"}' > "$HOMEBREW_JSON_TMP"

    local _hb_out _hb_summary _hb_err _hb_pid _hb_rc=0 _hb_ticks=0 _hb_line
    local -a _hb_fields
    _hb_out=$(mktemp "$PATCHED_TMPDIR/homebrew-out.XXXXXX")
    _hb_summary=$(mktemp "$PATCHED_TMPDIR/homebrew-summary.XXXXXX")
    _hb_err=$(mktemp "$PATCHED_TMPDIR/homebrew-err.XXXXXX")

    # The program arrives on stdin through the heredoc, so every input is an
    # argv entry, never piped (see the python3 heredoc footgun in AGENTS.md).
    "$PYTHON3" - "$_hb_out" "$_HOMEBREW_MAX_FORMULAE" "$_HOMEBREW_TIME_BUDGET_SECONDS" \
        "$_HOMEBREW_MAX_BYTES" "${_HOMEBREW_PREFIXES[@]}" > "$_hb_summary" 2> "$_hb_err" <<'PYEOF' &
import datetime
import json
import os
import pwd
import re
import stat
import sys
import time

out_path = sys.argv[1]
max_formulae = int(sys.argv[2])
budget = float(sys.argv[3])
max_bytes = int(sys.argv[4])
prefixes = [os.path.normpath(p) for p in sys.argv[5:]]
deadline = time.monotonic() + budget

RECEIPT_CAP = 1024 * 1024
FORMULA_FILE_CAP = 256 * 1024
GIT_CONFIG_CAP = 64 * 1024
TEXT_CAP = 2048
MAX_CASKS = 5000
MAX_TAPS = 1000
MAX_ISSUES = 50
# The same nesting cap local_models.sh uses (PAT-2032). A real receipt nests a
# handful of levels.
MAX_JSON_DEPTH = 64


class Stop(Exception):
    pass


class Abort(Exception):
    """A structural read failed; the caller records it and moves on."""


state = {"truncated": False, "reason": None, "issues": [], "formulae_seen": 0}


def issue(code, where):
    if len(state["issues"]) < MAX_ISSUES:
        state["issues"].append({"code": code, "path": where})


def check_time():
    if time.monotonic() > deadline:
        state["truncated"] = True
        state["reason"] = state["reason"] or "time_limit"
        raise Stop()


def clean_text(value, cap=TEXT_CAP):
    """value if it is safe to put on the wire as text, else None: a non-empty
    str, valid UTF-8, no control characters, no longer than cap."""
    if not isinstance(value, str) or not value or len(value) > cap:
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return None
    return value


def clean_name(value):
    """A directory or package name usable as an identifier, or None."""
    return clean_text(value, 255)


SECRET_KEY = re.compile(r"(token|key|secret|pass|auth|sig|credential|access)", re.I)


def clean_url(value):
    """Drop userinfo and secret-looking query values; None if not text."""
    value = clean_text(value)
    if value is None:
        return None
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*@)?(.*)$", value)
    if not m:
        return value
    rest = m.group(3)
    if "?" in rest:
        base, _, tail = rest.partition("?")
        query, hash_mark, fragment = tail.partition("#")
        parts = []
        for pair in query.split("&"):
            k, eq, _v = pair.partition("=")
            parts.append(k + "=REDACTED" if eq and SECRET_KEY.search(k) else pair)
        rest = base + "?" + "&".join(parts) + (hash_mark + fragment if hash_mark else "")
    return m.group(1) + rest


def iso(ts):
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


# --- file-safety helpers copied verbatim from ide_extensions.sh ------------
# test-package-managers.zsh [drift] fails if any of these stops matching its
# twin there, so a hardening fix to one cannot silently skip the other.

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


def usable_dir(k, where, pstate):
    """True for a real directory. A symlink, a special file or an entry whose
    type could not be read is recorded and makes the prefix partial; a
    regular file (not a keg, cask or tap) is skipped without comment."""
    if k == "dir":
        return True
    if k in ("symlink", "other", "error"):
        pstate["partial"] = True
        issue({"symlink": "symlink_not_followed", "other": "not_regular", "error": "unreadable"}[k], where)
    return False


def owner_of(path):
    try:
        uid = lstat_at(path).st_uid
    except OSError:
        return None, None
    try:
        return pwd.getpwuid(uid).pw_name, uid
    except KeyError:
        return None, uid


# The literal is read escape-aware so an escaped quote cannot end it early,
# then literal_value refuses anything not plain text: interpolation (`#{`),
# any backslash escape, or anything after the literal other than a comma
# (url options) or a comment, such as `+ version` or an adjacent literal.
# Brew is never run and Ruby never evaluated, so a value that would need
# evaluating is left null rather than reported wrong. Single-quoted and
# parenthesised forms do not match and are left null too.
HOMEPAGE_RE = re.compile(r'^\s*homepage\s+"((?:[^"\\]|\\.)*)("?)(.*)$')
URL_RE = re.compile(r'^\s*url\s+"((?:[^"\\]|\\.)*)("?)(.*)$')
TAIL_OK_RE = re.compile(r'^\s*(?:[,#].*)?$')


def literal_value(m):
    """The field's text, or None when it is not a plain closed literal."""
    value, closed, tail = m.group(1), m.group(2), m.group(3)
    # Ruby interpolates #{expr}, #@ivar, #@@cvar and #$gvar in double quotes.
    if (not closed or "\\" in value or "#{" in value or "#@" in value
            or "#$" in value or not TAIL_OK_RE.match(tail)):
        return None
    return value


# The main source url is the first `url "..."` before any block that carries
# a url of its own (a resource, a patch, a head or platform block) or the
# first method. `head "..."` on one line is not a block and does not stop it.
# A url that only appears inside an on_arm/on_intel style block is left null
# rather than guessed.
URL_STOP_RE = re.compile(r"^\s*(?:(?:resource|patch|head|livecheck|bottle|on_[a-z0-9_]+)\b.*\bdo\b|def\b)")


def formula_file_fields(keg, name):
    path = os.path.join(keg, ".brew", name + ".rb")
    if kind(os.path.join(keg, ".brew")) not in ("dir", "absent"):
        return "unreadable", None, None
    status, data = read_file(path, FORMULA_FILE_CAP)
    if status != "read":
        return status, None, None
    homepage = source_url = None
    # Only the first homepage and the first main url count. One refused by
    # literal_value stays null; a later line is never taken in its place.
    homepage_seen = url_seen = False
    url_open = True
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not homepage_seen:
            m = HOMEPAGE_RE.match(line)
            if m:
                homepage_seen = True
                homepage = literal_value(m)
                continue
        if url_open:
            if URL_STOP_RE.match(line):
                url_open = False
            elif not url_seen:
                m = URL_RE.match(line)
                if m:
                    url_seen = True
                    source_url = literal_value(m)
        if homepage_seen and (url_seen or not url_open):
            break
    return "read", clean_url(homepage), clean_url(source_url)


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


def parse_json(status, data):
    """A receipt nested past MAX_JSON_DEPTH is unparseable, and RecursionError
    stays caught as a second line (PAT-2032), so one hostile receipt in the
    user-owned tree costs that entry, never the whole block."""
    if status != "read":
        return status, None
    try:
        text = data.decode("utf-8")
        if not json_depth_ok(text):
            return "unparseable", None
        obj = json.loads(text)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return "unparseable", None
    if not isinstance(obj, dict):
        return "unparseable", None
    return "read", obj


def as_bool(value):
    return value if isinstance(value, bool) else None


def receipt_tap(receipt):
    source = receipt.get("source")
    if isinstance(source, dict):
        return clean_name(source.get("tap")) if isinstance(source.get("tap"), str) else None
    return None


def opt_target(prefix, name):
    link = os.path.join(prefix, "opt", name)
    if kind(link) != "symlink":
        return None
    try:
        target = read_link(link)
    except OSError:
        return None
    return os.path.normpath(os.path.join(os.path.dirname(link), target))


def collect_formulae(prefix, cellar, pstate, formulae):
    rows = list_dir(cellar)
    for name, k in rows:
        check_time()
        where = os.path.join(cellar, name)
        if not usable_dir(k, where, pstate):
            continue
        safe_name = clean_name(name)
        if safe_name is None:
            pstate["partial"] = True
            issue("name_unsafe", cellar)
            continue
        try:
            kegs = list_dir(where)
        except Abort:
            pstate["partial"] = True
            issue("unreadable", where)
            continue
        current = opt_target(prefix, name)
        for version, v_kind in kegs:
            check_time()
            keg = os.path.join(where, version)
            if not usable_dir(v_kind, keg, pstate):
                continue
            safe_version = clean_name(version)
            if safe_version is None:
                pstate["partial"] = True
                issue("name_unsafe", where)
                continue
            if state["formulae_seen"] >= max_formulae:
                pstate["partial"] = True
                state["truncated"] = True
                state["reason"] = state["reason"] or "formula_limit"
                return
            state["formulae_seen"] += 1
            r_status, receipt = parse_json(*read_file(os.path.join(keg, "INSTALL_RECEIPT.json"), RECEIPT_CAP))
            if r_status in ("unreadable", "unparseable"):
                pstate["partial"] = True
                issue("receipt_" + r_status, keg)
            f_status, homepage, source_url = formula_file_fields(keg, name)
            # opt/<name> points at the keg Homebrew treats as current. No link
            # in a readable opt/ means this keg is not current; an unreadable
            # opt/ means we cannot say.
            if current is not None:
                opt_linked = current == os.path.normpath(keg)
            elif kind(os.path.join(prefix, "opt")) == "dir":
                opt_linked = False
            else:
                opt_linked = None
            if f_status == "unreadable":
                pstate["partial"] = True
                issue("formula_file_unreadable", keg)
            entry = {
                "prefix": prefix,
                "name": safe_name,
                "version": safe_version,
                "receipt_status": r_status,
                "formula_file_status": f_status,
                "homepage": homepage,
                "source_url": source_url,
                "opt_linked": opt_linked,
            }
            if receipt is not None:
                deps = []
                raw_deps = receipt.get("runtime_dependencies")
                if isinstance(raw_deps, list):
                    for dep in raw_deps:
                        if isinstance(dep, dict) and isinstance(dep.get("full_name"), str):
                            dep_name = clean_name(dep["full_name"])
                            if dep_name is not None:
                                deps.append(dep_name)
                entry.update({
                    "tap": receipt_tap(receipt),
                    "installed_on_request": as_bool(receipt.get("installed_on_request")),
                    "installed_as_dependency": as_bool(receipt.get("installed_as_dependency")),
                    "installed_at": iso(receipt.get("time")),
                    "runtime_dependencies": deps if isinstance(raw_deps, list) else None,
                })
            else:
                entry.update({
                    "tap": None,
                    "installed_on_request": None,
                    "installed_as_dependency": None,
                    "installed_at": None,
                    "runtime_dependencies": None,
                })
            formulae.append(entry)
            pstate["formulae"] += 1


def cask_app_names(receipt):
    names = []
    artifacts = receipt.get("uninstall_artifacts") if receipt else None
    if not isinstance(artifacts, list):
        return names
    for artifact in artifacts:
        if isinstance(artifact, dict) and isinstance(artifact.get("app"), list):
            for item in artifact["app"]:
                if isinstance(item, str):
                    names.append(os.path.basename(item))
    return names


def collect_casks(prefix, caskroom, pstate, casks):
    rows = list_dir(caskroom)
    for token, k in rows:
        check_time()
        where = os.path.join(caskroom, token)
        if not usable_dir(k, where, pstate):
            continue
        safe_token = clean_name(token)
        if safe_token is None:
            pstate["partial"] = True
            issue("name_unsafe", caskroom)
            continue
        if len(casks) >= MAX_CASKS:
            state["truncated"] = True
            state["reason"] = state["reason"] or "cask_limit"
            raise Stop()
        try:
            versions = list_dir(where)
        except Abort:
            pstate["partial"] = True
            issue("unreadable", where)
            continue
        # A symlinked version (Homebrew's own "latest" link) is expected here
        # and simply not counted; a special or unreadable entry is recorded.
        on_disk = []
        for v, v_kind in versions:
            if v_kind == "dir" and clean_name(v):
                on_disk.append(v)
            elif v_kind in ("other", "error"):
                usable_dir(v_kind, os.path.join(where, v), pstate)
        metadata = os.path.join(where, ".metadata")
        m_kind = kind(metadata)
        if m_kind == "dir":
            r_status, receipt = parse_json(*read_file(os.path.join(metadata, "INSTALL_RECEIPT.json"), RECEIPT_CAP))
        elif m_kind == "absent":
            r_status, receipt = "missing", None
        else:
            r_status, receipt = "unreadable", None
        if r_status in ("unreadable", "unparseable"):
            pstate["partial"] = True
            issue("receipt_" + r_status, where)
        version = None
        if receipt is not None and isinstance(receipt.get("source"), dict):
            version = clean_name(receipt["source"].get("version")) if isinstance(receipt["source"].get("version"), str) else None
        if version is None and len(on_disk) == 1:
            version = on_disk[0]
        apps = []
        version_dir = os.path.join(where, version) if version in on_disk else None
        names = cask_app_names(receipt)
        if version_dir is not None:
            try:
                for n, _n_kind in list_dir(version_dir):
                    if n.endswith(".app") and n not in names:
                        names.append(n)
            except Abort:
                pstate["partial"] = True
                issue("unreadable", version_dir)
        for app_name in names:
            safe_app = clean_name(app_name)
            if safe_app is None:
                continue
            app_path = None
            if version_dir is not None:
                candidate = os.path.join(version_dir, app_name)
                c_kind = kind(candidate)
                if c_kind == "symlink":
                    try:
                        app_path = os.path.normpath(os.path.join(version_dir, read_link(candidate)))
                    except OSError:
                        app_path = None
                elif c_kind == "dir":
                    app_path = candidate
            app_path = clean_text(app_path) if app_path else None
            apps.append({
                "name": safe_app,
                "path": app_path,
                "exists": (kind(app_path) == "dir") if app_path else None,
            })
        casks.append({
            "prefix": prefix,
            "token": safe_token,
            "version": version,
            "versions_on_disk": on_disk,
            "tap": receipt_tap(receipt) if receipt is not None else None,
            "installed_on_request": as_bool(receipt.get("installed_on_request")) if receipt is not None else None,
            "installed_at": iso(receipt.get("time")) if receipt is not None else None,
            "receipt_status": r_status,
            "apps": apps,
        })
        pstate["casks"] += 1


def remote_url(config_text):
    section = None
    first_url = None
    for raw in config_text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section and section.startswith("remote ") and "=" in line:
            key, _, value = line.partition("=")
            if key.strip().lower() == "url":
                value = value.strip()
                if section == 'remote "origin"':
                    return value
                if first_url is None:
                    first_url = value
    return first_url


def collect_taps(prefix, taps_dir, pstate, taps):
    for user, u_kind in list_dir(taps_dir):
        check_time()
        user_path = os.path.join(taps_dir, user)
        if not usable_dir(u_kind, user_path, pstate):
            continue
        try:
            repos = list_dir(user_path)
        except Abort:
            pstate["partial"] = True
            issue("unreadable", user_path)
            continue
        for repo, r_kind in repos:
            check_time()
            tap_path = os.path.join(user_path, repo)
            if not usable_dir(r_kind, tap_path, pstate):
                continue
            s_user, s_repo = clean_name(user), clean_name(repo)
            if s_user is None or s_repo is None:
                pstate["partial"] = True
                issue("name_unsafe", user_path)
                continue
            if len(taps) >= MAX_TAPS:
                state["truncated"] = True
                state["reason"] = state["reason"] or "tap_limit"
                raise Stop()
            git_dir = os.path.join(tap_path, ".git")
            g_kind = kind(git_dir)
            url = None
            if g_kind == "dir":
                c_status, data = read_file(os.path.join(git_dir, "config"), GIT_CONFIG_CAP)
                if c_status == "read":
                    url = clean_url(remote_url(data.decode("utf-8", errors="replace")))
                elif c_status == "unreadable":
                    pstate["partial"] = True
                    issue("git_config_unreadable", tap_path)
            elif g_kind == "absent":
                c_status = "missing"
            elif g_kind == "file":
                c_status = "not_a_directory"
            else:
                c_status = "unreadable"
                pstate["partial"] = True
                issue({"symlink": "symlink_not_followed", "other": "not_regular"}.get(g_kind, "git_config_unreadable"), git_dir)
            short = s_repo[len("homebrew-"):] if s_repo.startswith("homebrew-") else s_repo
            taps.append({
                "prefix": prefix,
                "name": s_user + "/" + short,
                "directory": s_user + "/" + s_repo,
                "remote_url": url,
                "config_status": c_status,
            })
            pstate["taps"] += 1


def dumps(obj):
    # ASCII-only output, so the character count is the byte count.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def apply_byte_budget(block):
    """Fit a non-failed block into max_bytes by dropping whole entries from
    the end of each sorted list: formulae first, then casks, then taps. A
    formula is dropped with every keg of that name in that prefix, so no keg
    list is sent cut part way and no opt_linked keg loses its siblings. The
    block becomes partial and truncated, truncation_reason is size_limit
    unless an earlier bound already set one (the first reason wins), and
    each prefix that lost an entry is partial with counts matching what is
    sent. Deterministic: the same tree always drops the same entries."""
    if len(dumps(block)) <= max_bytes:
        return block
    state["truncated"] = True
    state["reason"] = state["reason"] or "size_limit"
    block["collection_status"] = "partial"
    block["truncated"] = True
    block["truncation_reason"] = state["reason"]
    touched = set()

    def groups(key, lst):
        # Consecutive runs sharing key (the lists are sorted by it).
        out = []
        for e in lst:
            k = key(e)
            if out and out[-1][0] == k:
                out[-1][1].append(e)
            else:
                out.append((k, [e]))
        return out

    plan = [("formulae", lambda f: (f["prefix"], f["name"])),
            ("casks", lambda c: (c["prefix"], c["token"])),
            ("taps", lambda t: (t["prefix"], t["directory"]))]
    for key_name, key in plan:
        # Each dropped entry saves its own bytes plus one comma. That can
        # overstate the saving by one byte per list, so the loop re-measures.
        excess = len(dumps(block)) - max_bytes
        if excess <= 0:
            break
        runs = groups(key, block[key_name])
        while runs and excess > 0:
            _k, entries = runs.pop()
            excess -= sum(len(dumps(e)) + 1 for e in entries)
            touched.update(e["prefix"] for e in entries)
        block[key_name] = [e for _k, entries in runs for e in entries]
        while block[key_name] and len(dumps(block)) > max_bytes:
            _k, entries = groups(key, block[key_name])[-1]
            del block[key_name][-len(entries):]
            touched.update(e["prefix"] for e in entries)
    for row in block["prefixes"]:
        if row["path"] in touched:
            row["collection_status"] = "partial"
            row["formulae"] = sum(f["prefix"] == row["path"] for f in block["formulae"])
            row["casks"] = sum(c["prefix"] == row["path"] for c in block["casks"])
            row["taps"] = sum(t["prefix"] == row["path"] for t in block["taps"])
    # Only reachable with a budget far below any real one: issues are capped
    # at 50. Past that, nothing trustworthy fits and the block is failed.
    while block["issues"] and len(dumps(block)) > max_bytes:
        block["issues"].pop()
    if len(dumps(block)) > max_bytes:
        return {"collection_status": "failed"}
    return block


def main():
    formulae, casks, taps, prefix_rows = [], [], [], []
    any_layout = False
    stopped = False
    for prefix in prefixes:
        if stopped:
            break
        p_kind = kind(prefix)
        if p_kind in ("absent", "file"):
            continue
        if p_kind != "dir":
            # A symlinked prefix is recorded, not followed: everything under
            # it would otherwise be read through a path its owner chose.
            any_layout = True
            p_status = "partial" if p_kind == "symlink" else "failed"
            prefix_rows.append({"path": prefix, "owner": None, "owner_uid": None,
                                "collection_status": p_status, "formulae": 0, "casks": 0, "taps": 0})
            issue({"symlink": "symlink_not_followed", "other": "not_regular"}.get(p_kind, "unreadable"), prefix)
            continue
        cellar = os.path.join(prefix, "Cellar")
        caskroom = os.path.join(prefix, "Caskroom")
        # The repository sits at the prefix on Apple silicon and one level
        # down on an Intel /usr/local install.
        repo = next((r for r in (prefix, os.path.join(prefix, "Homebrew"))
                     if kind(os.path.join(r, "Library", "Homebrew")) != "absent"), None)
        kinds = {"cellar": kind(cellar), "caskroom": kind(caskroom)}
        if all(k == "absent" for k in kinds.values()) and repo is None:
            continue
        any_layout = True
        taps_dir = None
        for r in ((repo,) if repo else (prefix, os.path.join(prefix, "Homebrew"))):
            candidate = os.path.join(r, "Library", "Taps")
            if kind(candidate) != "absent":
                taps_dir = candidate
                break
        # The owner is the account Homebrew installs as: the owner of the real
        # Cellar or Caskroom directory (lstat, never through a symlink). The
        # prefix itself is not used: an Intel /usr/local is root-owned while
        # its Homebrew tree belongs to the installing user.
        owner_path = next((p for p, k in ((cellar, kinds["cellar"]), (caskroom, kinds["caskroom"]))
                           if k == "dir"), repo or prefix)
        owner, owner_uid = owner_of(owner_path)
        pstate = {"partial": False, "formulae": 0, "casks": 0, "taps": 0}
        attempted, failed = 0, 0
        sections = [(cellar, kinds["cellar"], collect_formulae, formulae),
                    (caskroom, kinds["caskroom"], collect_casks, casks)]
        if taps_dir is not None:
            sections.append((taps_dir, kind(taps_dir), collect_taps, taps))
        try:
            for path, k, fn, sink in sections:
                if k == "absent":
                    continue
                attempted += 1
                if k != "dir":
                    failed += 1
                    pstate["partial"] = True
                    issue("symlink_not_followed" if k == "symlink" else "unreadable", path)
                    continue
                try:
                    fn(prefix, path, pstate, sink)
                except Abort:
                    failed += 1
                    pstate["partial"] = True
                    issue("unreadable", path)
        except Stop:
            pstate["partial"] = True
            stopped = True
        if attempted and failed == attempted:
            p_status = "failed"
        elif pstate["partial"] or (stopped and state["truncated"]):
            p_status = "partial"
        else:
            p_status = "complete"
        prefix_rows.append({"path": prefix, "owner": owner, "owner_uid": owner_uid,
                            "collection_status": p_status, "formulae": pstate["formulae"],
                            "casks": pstate["casks"], "taps": pstate["taps"]})
    # A prefix never reached because the budget ran out is not "absent".
    if stopped:
        state["truncated"] = True
    if not any_layout:
        status = "not_present"
    elif prefix_rows and all(r["collection_status"] == "failed" for r in prefix_rows):
        status = "failed"
    elif state["truncated"] or any(r["collection_status"] != "complete" for r in prefix_rows):
        status = "partial"
    else:
        status = "complete"
    if status == "failed":
        block = {"collection_status": "failed", "prefixes": prefix_rows, "issues": state["issues"]}
    else:
        block = {
            "collection_status": status,
            "truncated": state["truncated"],
            "truncation_reason": state["reason"] if state["truncated"] else None,
            "prefixes": prefix_rows,
            "formulae": sorted(formulae, key=lambda f: (f["prefix"], f["name"], f["version"])),
            "casks": sorted(casks, key=lambda c: (c["prefix"], c["token"])),
            "taps": sorted(taps, key=lambda t: (t["prefix"], t["directory"])),
            "issues": state["issues"],
        }
    if status != "failed":
        block = apply_byte_budget(block)
        status = block["collection_status"]
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(dumps(block))
    print(status, len(block.get("formulae", [])), len(block.get("casks", [])), len(block.get("taps", [])))


main()
PYEOF
    _hb_pid=$!

    # A parser this loop killed is failed whatever wait reports: one that
    # finished between the last check and the kill is reaped with a clean
    # status, and its output is not trusted (PAT-2033).
    local _hb_killed=0
    while kill -0 "$_hb_pid" 2>/dev/null; do
        if (( _hb_ticks >= _HOMEBREW_HARD_TIMEOUT_SECONDS * 10 )); then
            kill -9 "$_hb_pid" 2>/dev/null
            _hb_killed=1
            log_warn "homebrew: parser still running after ${_HOMEBREW_HARD_TIMEOUT_SECONDS}s, killed; block is failed"
            break
        fi
        sleep 0.1
        (( _hb_ticks++ ))
    done
    wait "$_hb_pid" 2>/dev/null || _hb_rc=$?

    _hb_line=$(head -n 1 "$_hb_summary" 2>/dev/null)
    _hb_fields=(${=_hb_line})
    if (( _hb_killed == 0 && _hb_rc == 0 )) && (( ${#_hb_fields} == 4 )) \
        && [[ "${_hb_fields[1]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_hb_fields[2]}${_hb_fields[3]}${_hb_fields[4]}" == <-> ]] \
        && "$PYTHON3" -c 'import json,sys; json.load(open(sys.argv[1]))' "$_hb_out" 2>/dev/null; then
        mv -f "$_hb_out" "$HOMEBREW_JSON_TMP"
        HOMEBREW_COLLECTION_STATUS="${_hb_fields[1]}"
        HOMEBREW_FORMULA_COUNT="${_hb_fields[2]}"
        HOMEBREW_CASK_COUNT="${_hb_fields[3]}"
        HOMEBREW_TAP_COUNT="${_hb_fields[4]}"
    else
        # Parser stderr can carry file names from the user-owned tree: newlines
        # become spaces and every other control character is dropped, so the
        # log line cannot be split or carry terminal escapes.
        log_warn "homebrew: parser failed (exit $_hb_rc): $(head -c 300 "$_hb_err" 2>/dev/null | tr '\n\t' '  ' | LC_ALL=C tr -d '\000-\037\177')"
        rm -f "$_hb_out"
    fi
    rm -f "$_hb_summary" "$_hb_err"
    local _hb_wire="held off the wire"
    (( _HOMEBREW_PAYLOAD_ON_WIRE )) && _hb_wire="sent"
    echo "homebrew: status=$(homebrew_collection_status) formulae=$HOMEBREW_FORMULA_COUNT casks=$HOMEBREW_CASK_COUNT taps=$HOMEBREW_TAP_COUNT ($_hb_wire)"
    return 0
}
