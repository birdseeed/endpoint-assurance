# local_models.sh — local model runtimes (Ollama, LM Studio, llama.cpp) and
# their model stores, for the machine and every local user, read from disk
# (PAT-2019).
#
# Sourced by patched-collect.sh; not executable directly.
# Requires: PATCHED_TMPDIR, PYTHON3 (set by main script before sourcing)
#
# WHAT THIS READS, AND ONLY THIS.
#
#   Runtimes (presence and version):
#     app bundles  /Applications and ~/Applications: Ollama.app and
#                  LM Studio.app, Contents/Info.plist (CFBundleIdentifier and
#                  CFBundleShortVersionString, falling back to CFBundleVersion)
#     Homebrew     <prefix>/Cellar/ollama/<version> and
#                  <prefix>/Cellar/llama.cpp/<version> for /opt/homebrew and
#                  /usr/local: the keg directory name is the version, nothing
#                  inside the keg is opened
#     binaries     <prefix>/bin/ollama, llama-cli and llama-server for
#                  /opt/homebrew and /usr/local: presence only (lstat), no
#                  version, because a version would mean running the binary.
#                  A link there is never followed: its text is read with
#                  readlink, and when it names an installation this run
#                  already recorded (the Ollama.app CLI link, a Homebrew bin
#                  link into its keg) it is alias_not_followed and costs
#                  nothing; otherwise it is symlink_not_followed and partial.
#
#   Model stores (names and sizes only), per user:
#     Ollama     ~/.ollama/models/manifests/<registry>/<namespace>/<model>/<tag>
#                is read as JSON for the config and layer digests and sizes.
#                Each referenced blob, ~/.ollama/models/blobs/sha256-<hex>, is
#                checked with lstat only (present or missing, and its size); a
#                blob is NEVER opened. A digest that is not sha256:<64 hex> is
#                refused before it is turned into a path. A model's size_bytes
#                is what its manifest declares (what `ollama list` shows); the
#                store's total_bytes is the on-disk size of the blobs present,
#                each counted once however many tags share it.
#     LM Studio  ~/.lmstudio/models/<publisher>/<repo>/ and the older
#                ~/.cache/lm-studio/models/<publisher>/<repo>/: every file is
#                listed and its size taken from lstat. No model file is ever
#                opened. Each .gguf file is one model (tag = file name without
#                .gguf); a repo with no .gguf but weight files (.safetensors,
#                .bin, .npz, .onnx, .pt, .pth, for MLX and other formats) is one
#                model with the size of every file in it.
#     llama.cpp  has no default model store; runtime presence only.
#
#   Nothing else under ~/.ollama or ~/.lmstudio is looked at: not history,
#   not logs, not the Ollama key pair, not LM Studio conversations or
#   settings. The parser only ever walks down to the directories above.
#
# NOTHING IS EXECUTED AND NOTHING TOUCHES THE NETWORK. No runtime is started,
# no local HTTP API is called, no binary is run to ask its version.
# test-local-models.zsh carries a static guard that goes red if this file gains
# a process launch, a network client, a loopback address or a read of any
# file other than a manifest or an Info.plist.
#
# EVERY PER-USER TREE IS OWNED BY AN ORDINARY USER AND THIS RUNS AS ROOT, and
# model directories are often links to an external disk. Nothing is followed:
# every file is opened O_NOFOLLOW|O_NONBLOCK and must be a regular file with a
# single link, under a size cap; every directory level is checked with lstat
# and never entered when it is a symlink. A linked model store is recorded as
# symlink_not_followed and the runtime is partial; it is not read through.
#
# The lstat checks decide what is reported; the walk is what keeps a read in
# the tree. Every open starts at / and opens each directory relative to the
# one before with O_NOFOLLOW, so a directory swapped for a symlink between its
# check and the read is refused as well (PAT-2033).
#
# ABSENCE REQUIRES AUTHORITY (PAT-1710). collection_status, overall, per
# runtime, per user and per store, is one of:
#   complete     everything found was read in full
#   partial      something was read but not everything (an unreadable
#                manifest, a link not followed, the 5,000-model or 30-second
#                bound): the lists are what was seen, not all there is
#   not_present  every place was looked at and no runtime or store exists; a
#                genuine reading, so an empty models list is sent
#   failed       nothing trustworthy was read: models is OMITTED, never sent
#                as [], so a failed read can never look like "no models"
#
# ON THE WIRE since PAT-2225 (2026-09-28). _LOCAL_MODELS_PAYLOAD_ON_WIRE=1
# makes local_models_payload_member emit the block into the inventory payload,
# which the platform (PAT-2021) validates and ingests. The block is sent only
# within the _LM_MAX_BYTES budget below; past it the block is sent as failed
# (patched_block_within_budget, common.sh). Setting the constant back to 0 is
# the whole off switch; test-local-models.zsh asserts it is 1 and still
# exercises the off path, so changing it must update that test in the same
# change.

_LOCAL_MODELS_PAYLOAD_ON_WIRE=1

# Where home directories live, and the root the machine-wide paths hang off.
# Tests reassign both after sourcing.
# ASSUMPTION: as in ide_extensions.sh, local homes are the directories
# directly under /Users. A relocated home, an OLLAMA_MODELS override or an LM
# Studio models folder moved in its own settings is not seen.
_LM_USERS_ROOT=/Users
_LM_SYSTEM_ROOT=/

# Bounds (PAT-2019). Past either, collection stops and is marked partial.
_LM_MAX_MODELS=5000
_LM_TIME_BUDGET_SECONDS=30
# The parser checks its own budget between entries; this is the outer limit
# for a read that blocks inside one syscall (an external model disk that has
# gone away). Past it the parser is killed and the block is failed.
_LM_HARD_TIMEOUT_SECONDS=45
# Byte budget for the serialised block (PAT-2225), about 900 models at the
# ~290 bytes a real row takes. The four tooling blocks together stay within
# 2 MiB, as the homebrew block does, so the two leave 2 MiB of the server's
# 6 MiB inventory body cap for everything else. Past the budget the block is
# sent as failed, never cut down: the platform's tooling contract has no
# size_limit reason. Tests lower it after sourcing.
_LM_MAX_BYTES=$(( 256 * 1024 ))

# local_models_collection_status
#   Prints the wire value. Anything but the four known values is failed.
local_models_collection_status() {
    case "${LOCAL_MODELS_COLLECTION_STATUS:-}" in
        complete|partial|not_present) print -r -- "$LOCAL_MODELS_COLLECTION_STATUS" ;;
        *) print -r -- "failed" ;;
    esac
}

# local_models_payload_member
#   Prints `"local_models": {...},` for the payload heredoc, or nothing when
#   the wire flag is 0 (see header). A failed status with no written block
#   sends only {"collection_status":"failed"}.
local_models_payload_member() {
    (( _LOCAL_MODELS_PAYLOAD_ON_WIRE )) || return 0
    if [[ "$(local_models_collection_status)" == "failed" ]] \
        || [[ -z "${LOCAL_MODELS_JSON_TMP:-}" || ! -s "$LOCAL_MODELS_JSON_TMP" ]]; then
        printf '"local_models": {"collection_status": "failed"},'
        return 0
    fi
    printf '"local_models": %s,' "$(cat "$LOCAL_MODELS_JSON_TMP")"
}

collect_local_models() {
    LOCAL_MODELS_COLLECTION_STATUS="failed"
    LOCAL_MODELS_MODEL_COUNT=0
    LOCAL_MODELS_TOTAL_BYTES=0
    LOCAL_MODELS_USER_COUNT=0
    LOCAL_MODELS_INSTALLATION_COUNT=0
    LOCAL_MODELS_OLLAMA_STATUS="failed"
    LOCAL_MODELS_LM_STUDIO_STATUS="failed"
    LOCAL_MODELS_LLAMA_CPP_STATUS="failed"
    # Reuse the caller's placeholder file if it made one, so it is not orphaned.
    if [[ -z "${LOCAL_MODELS_JSON_TMP:-}" || ! -f "$LOCAL_MODELS_JSON_TMP" ]]; then
        LOCAL_MODELS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/local-models.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    fi
    printf '{"collection_status": "failed"}' > "$LOCAL_MODELS_JSON_TMP"

    local _lm_out _lm_summary _lm_err _lm_pid _lm_rc=0 _lm_ticks=0 _lm_line
    local -a _lm_fields
    _lm_out=$(mktemp "$PATCHED_TMPDIR/local-models-out.XXXXXX")
    _lm_summary=$(mktemp "$PATCHED_TMPDIR/local-models-summary.XXXXXX")
    _lm_err=$(mktemp "$PATCHED_TMPDIR/local-models-err.XXXXXX")

    # The program arrives on stdin through the heredoc, so every input is an
    # argv entry, never piped (see the python3 heredoc footgun in AGENTS.md).
    "$PYTHON3" - "$_lm_out" "$_LM_MAX_MODELS" "$_LM_TIME_BUDGET_SECONDS" \
        "$_LM_USERS_ROOT" "$_LM_SYSTEM_ROOT" > "$_lm_summary" 2> "$_lm_err" <<'PYEOF' &
import json
import os
import plistlib
import re
import stat
import sys
import time

out_path = sys.argv[1]
max_models = int(sys.argv[2])
budget = float(sys.argv[3])
users_root = os.path.normpath(sys.argv[4])
system_root = os.path.normpath(sys.argv[5])
deadline = time.monotonic() + budget

MANIFEST_CAP = 1024 * 1024
PLIST_CAP = 1024 * 1024
MAX_LAYERS = 1000
# The Windows reader parses with JsonDocumentOptions.MaxDepth = 64; the same limit
# here keeps one manifest unparseable on both agents rather than deep enough to
# exhaust the interpreter on one and parse on the other.
MAX_JSON_DEPTH = 64
TEXT_CAP = 512
MAX_USERS = 500
MAX_ISSUES = 50
SKIP_HOMES = {"Shared", "Guest"}
RUNTIMES = ("ollama", "lm_studio", "llama_cpp")

DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
WEIGHT_EXTS = (".safetensors", ".bin", ".npz", ".onnx", ".pt", ".pth")
OLLAMA_DEFAULT_REGISTRY = "registry.ollama.ai"

APP_BUNDLES = (("ollama", "Ollama.app"), ("lm_studio", "LM Studio.app"))
BREW_PREFIXES = (("opt", "homebrew"), ("usr", "local"))
BREW_FORMULAE = (("ollama", "ollama"), ("llama_cpp", "llama.cpp"))
BIN_NAMES = (("ollama", "ollama"), ("llama_cpp", "llama-cli"), ("llama_cpp", "llama-server"))
OLLAMA_STORE = (".ollama", "models")
LMSTUDIO_STORES = ((".lmstudio", "models"), (".cache", "lm-studio", "models"))


class Stop(Exception):
    pass


class Abort(Exception):
    """A directory could not be read."""


class Full(Exception):
    pass


state = {"truncated": False, "reason": None, "issues": []}
count = {"models": 0}


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


def list_sizes(path):
    """Sorted (name, kind, size) never following a symlink. size is the lstat
    size of a regular file (a stat, never an open) and 0 for anything else; a
    file whose size cannot be read is "error". Raises Abort when the directory
    itself cannot be listed."""
    try:
        fd = open_dir(path)
    except OSError:
        raise Abort()
    try:
        with os.scandir(fd) as it:
            rows = []
            for entry in it:
                if entry.name.startswith("."):
                    continue
                size = 0
                try:
                    if entry.is_symlink():
                        k = "symlink"
                    elif entry.is_dir(follow_symlinks=False):
                        k = "dir"
                    elif entry.is_file(follow_symlinks=False):
                        k = "file"
                        size = entry.stat(follow_symlinks=False).st_size
                    else:
                        k = "other"
                except OSError:
                    k = "error"
                rows.append((entry.name, k, size))
            return sorted(rows)
    except OSError:
        raise Abort()
    finally:
        os.close(fd)


def issue(code, where):
    if len(state["issues"]) < MAX_ISSUES:
        state["issues"].append({"code": code, "path": clean_path(where)})


def code_for(k):
    return {"symlink": "symlink_not_followed", "other": "not_regular"}.get(k, "unreadable")


def check_time():
    if time.monotonic() > deadline:
        state["truncated"] = True
        state["reason"] = state["reason"] or "time_limit"
        raise Stop()


def model_limit_hit():
    """True once the model bound is reached; a store skipped because of it is
    as truncated as one cut short, so the block says so either way."""
    if count["models"] < max_models:
        return False
    state["truncated"] = True
    state["reason"] = state["reason"] or "model_limit"
    return True


def take_slot():
    if model_limit_hit():
        raise Full()
    count["models"] += 1


def walk(anchor, parts):
    """(kind, path): every component below anchor is checked with lstat, and
    the walk stops at the first that is not a directory. ("dir", full path)
    when all of them are directories."""
    p = anchor
    for part in parts:
        p = os.path.join(p, part)
        k = kind(p)
        if k != "dir":
            return k, p
    return "dir", p


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


def refuse(unit, k, where):
    """Something where a directory or file was expected. A link (a model disk
    linked in, very common) is recorded and not followed, and makes the unit
    partial; anything else unreadable counts against it."""
    issue(code_for(k), where)
    if k == "symlink":
        unit["partial"] = True
    else:
        unit["problems"] += 1


installations = []
installed_paths = []  # raw normalised paths, for link coverage
stores = []
models = []


def new_ctx(scope, user, user_id):
    return {"scope": scope, "user": user, "user_id": user_id, "units": {r: new_unit() for r in RUNTIMES}}


def add_installation(ctx, runtime, how, path, version, version_source, identifier=None, partial=False):
    installations.append({
        "runtime": runtime,
        "scope": ctx["scope"],
        "user": ctx["user"],
        "user_id": ctx["user_id"],
        "kind": how,
        "path": clean_path(path),
        "version": version,
        "version_source": version_source if version else "none",
        "identifier": identifier,
    })
    installed_paths.append(os.path.normpath(path))
    unit = ctx["units"][runtime]
    unit["locations"] += 1
    unit["ok"] += 1
    if partial:
        unit["partial"] = True


# --- runtimes -----------------------------------------------------------------

def read_info_plist(app):
    """(status, version, identifier) from app/Contents/Info.plist."""
    k, contents = walk(app, ("Contents",))
    if k != "dir":
        return ("missing" if k == "absent" else "unreadable"), None, None
    status, data = read_file(os.path.join(contents, "Info.plist"), PLIST_CAP)
    if status != "read":
        return status, None, None
    try:
        info = plistlib.loads(data)
    except Exception:
        return "unparseable", None, None
    if not isinstance(info, dict):
        return "unparseable", None, None
    version = clean_text(info.get("CFBundleShortVersionString"), 64) or clean_text(info.get("CFBundleVersion"), 64)
    return "read", version, clean_text(info.get("CFBundleIdentifier"), 255)


def app_bundles(ctx, anchor, parts):
    for runtime, name in APP_BUNDLES:
        check_time()
        unit = ctx["units"][runtime]
        k, app = walk(anchor, parts + (name,))
        if k == "absent":
            continue
        if k != "dir":
            refuse(unit, k, app)
            continue
        status, version, identifier = read_info_plist(app)
        partial = False
        if status != "read":
            issue("info_plist_" + status, app)
            partial = True
        elif version is None:
            issue("version_missing", app)
            partial = True
        add_installation(ctx, runtime, "app_bundle", app, version, "info_plist", identifier, partial)


def brew_kegs(ctx):
    for prefix in BREW_PREFIXES:
        for runtime, formula in BREW_FORMULAE:
            check_time()
            unit = ctx["units"][runtime]
            k, rack = walk(system_root, prefix + ("Cellar", formula))
            if k == "absent":
                continue
            if k != "dir":
                refuse(unit, k, rack)
                continue
            try:
                entries = list_dir(rack)
            except Abort:
                refuse(unit, "error", rack)
                continue
            for name, ek in entries:
                where = os.path.join(rack, name)
                if ek == "dir":
                    version = clean_text(name, 64)
                    add_installation(ctx, runtime, "homebrew_formula", where, version, "homebrew_keg",
                                     partial=version is None)
                    if version is None:
                        issue("name_unsafe", rack)
                elif ek != "file":
                    unit["partial"] = True
                    issue(code_for(ek), where)


def covered(target):
    return target is not None and any(target == p or target.startswith(p + os.sep) for p in installed_paths)


def bin_links(ctx):
    """Standalone binaries in the Homebrew and /usr/local bin directories.
    Presence only; a link is never followed."""
    for prefix in BREW_PREFIXES:
        for runtime, name in BIN_NAMES:
            check_time()
            unit = ctx["units"][runtime]
            full = os.path.join(system_root, *(prefix + ("bin", name)))
            k, where = walk(system_root, prefix + ("bin", name))
            if k == "absent":
                continue
            if where == full and k == "file":
                add_installation(ctx, runtime, "binary", where, None, "none")
                continue
            if where == full and k == "symlink" and covered(resolve_link(where)):
                issue("alias_not_followed", where)
                continue
            unit["partial"] = True
            issue(code_for(k), where)


# --- model stores -------------------------------------------------------------

def new_store(ctx, runtime, path):
    store = {
        "runtime": runtime,
        "scope": ctx["scope"],
        "user": ctx["user"],
        "user_id": ctx["user_id"],
        "path": clean_path(path),
        "collection_status": "failed",
        "model_count": 0,
        "total_bytes": 0,
    }
    stores.append(store)
    ctx["units"][runtime]["locations"] += 1
    return store


def finish_store(ctx, store, sp):
    unit = ctx["units"][store["runtime"]]
    if sp["failed"]:
        store["collection_status"] = "failed" if store["model_count"] == 0 else "partial"
    else:
        store["collection_status"] = "partial" if sp["partial"] else "complete"
    if store["collection_status"] == "failed":
        unit["problems"] += 1
    else:
        unit["ok"] += 1
        if store["collection_status"] == "partial":
            unit["partial"] = True


def model_row(ctx, store, **fields):
    row = {
        "runtime": store["runtime"],
        "user": ctx["user"],
        "user_id": ctx["user_id"],
        "store_path": store["path"],
        "name": None,
        "tag": None,
        "format": None,
        "size_bytes": None,
        "file_count": None,
        "size_source": None,
        "missing_blobs": None,
        "metadata_status": None,
    }
    row.update(fields)
    models.append(row)
    store["model_count"] += 1


def sub_dirs(sp, path):
    """(name, path) of the real directories directly under path. A link is
    recorded and not entered; an unlistable directory makes the store partial."""
    try:
        entries = list_dir(path)
    except Abort:
        sp["partial"] = True
        issue("unreadable", path)
        return []
    found = []
    for name, k in entries:
        where = os.path.join(path, name)
        if k == "dir":
            found.append((name, where))
        elif k != "file":
            sp["partial"] = True
            issue(code_for(k), where)
    return found


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


def parse_manifest(data):
    """("read", [(hex digest, size)]) for the config and every layer, or
    ("unparseable", None). Nothing but digest and size is kept. Nesting past
    MAX_JSON_DEPTH is unparseable, and RecursionError stays caught as a second
    line, so one hostile manifest costs one model, never the block."""
    try:
        text = data.decode("utf-8")
        if not json_depth_ok(text):
            return "unparseable", None
        obj = json.loads(text)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return "unparseable", None
    if not isinstance(obj, dict):
        return "unparseable", None
    layers = obj.get("layers")
    if not isinstance(layers, list) or len(layers) > MAX_LAYERS:
        return "unparseable", None
    items = list(layers)
    if obj.get("config") is not None:
        items.append(obj.get("config"))
    out = []
    for item in items:
        if not isinstance(item, dict):
            return "unparseable", None
        digest, size = item.get("digest"), item.get("size")
        m = DIGEST_RE.match(digest) if isinstance(digest, str) else None
        if m is None or not isinstance(size, int) or isinstance(size, bool) or size < 0:
            return "unparseable", None
        out.append((m.group(1), size))
    return "read", out


def blob_size(path):
    """("open", size) for a regular file with one link, from lstat; never
    opens it. ("missing", None) when nothing is there, ("unreadable", None)
    when something is there that is not a plain file with one link (a
    symlink, a hard link, a directory) or cannot be looked at. PAT-2040: what
    is refused is on disk, so it is never counted as missing; the Windows
    agent reports the same."""
    try:
        st = lstat_at(path)
    except (FileNotFoundError, NotADirectoryError):
        return "missing", None
    except OSError:
        return "unreadable", None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return "unreadable", None
    return "open", st.st_size


def ollama_name(registry, namespace, model):
    if registry == OLLAMA_DEFAULT_REGISTRY and namespace == "library":
        return clean_text(model, 255)
    if registry == OLLAMA_DEFAULT_REGISTRY:
        return clean_text(namespace + "/" + model, 512)
    return clean_text(registry + "/" + namespace + "/" + model, 512)


def ollama_model(ctx, store, sp, parts, path, blobs, blobs_kind, digests):
    name = ollama_name(*parts[:3])
    tag = clean_text(parts[3], 255)
    if name is None or tag is None:
        sp["partial"] = True
        issue("name_unsafe", os.path.dirname(path))
        return
    take_slot()
    status, data = read_file(path, MANIFEST_CAP)
    layers = None
    if status == "read":
        status, layers = parse_manifest(data)
    if status != "read":
        # Still listed: a model whose manifest cannot be read is present,
        # just not sized.
        sp["partial"] = True
        issue("manifest_" + status, path)
        model_row(ctx, store, name=name, tag=tag, metadata_status=status)
        return
    unique = dict(layers)
    if blobs_kind == "dir":
        # lstat only: a blob is never opened, and a link is not a blob. The
        # store total counts what is on disk, once per blob however many tags
        # share it; a manifest can outlive its blobs. PAT-2040: only a blob
        # that is not there is missing; one that is there but refused is
        # unreadable, left out of the total, and makes the store partial.
        missing = 0
        for d in unique:
            blob = os.path.join(blobs, "sha256-" + d)
            blob_status, on_disk = blob_size(blob)
            if blob_status == "open":
                digests[d] = on_disk
            elif blob_status == "missing":
                missing += 1
            else:
                sp["partial"] = True
                issue("blob_unreadable", blob)
    elif blobs_kind == "absent":
        missing = len(unique)
    else:
        # The blobs directory was not looked into (a link): the total falls
        # back to the sizes the manifests declare, and the store is partial.
        missing = None
        digests.update(unique)
    model_row(ctx, store, name=name, tag=tag, size_bytes=sum(unique.values()), file_count=len(unique),
              size_source="manifest", missing_blobs=missing, metadata_status="read")


def ollama_store(ctx, home):
    unit = ctx["units"]["ollama"]
    k, base = walk(home, OLLAMA_STORE)
    if k == "absent":
        return
    if k != "dir":
        refuse(unit, k, base)
        return
    if model_limit_hit():
        unit["partial"] = True
        return
    store = new_store(ctx, "ollama", base)
    sp = {"partial": False, "failed": False}
    digests = {}
    blobs_kind, blobs = walk(base, ("blobs",))
    if blobs_kind not in ("dir", "absent"):
        sp["partial"] = True
        issue(code_for(blobs_kind), blobs)
    k, manifests = walk(base, ("manifests",))
    try:
        if k == "absent":
            pass
        elif k != "dir":
            issue(code_for(k), manifests)
            sp["partial" if k == "symlink" else "failed"] = True
        else:
            try:
                registries = list_dir(manifests)
            except Abort:
                issue("unreadable", manifests)
                sp["failed"] = True
                registries = []
            for reg, rk in registries:
                check_time()
                if rk == "file":
                    continue
                if rk != "dir":
                    sp["partial"] = True
                    issue(code_for(rk), os.path.join(manifests, reg))
                    continue
                for ns, ns_path in sub_dirs(sp, os.path.join(manifests, reg)):
                    for model, model_path in sub_dirs(sp, ns_path):
                        check_time()
                        try:
                            tags = list_dir(model_path)
                        except Abort:
                            sp["partial"] = True
                            issue("unreadable", model_path)
                            continue
                        for tag, tk in tags:
                            check_time()
                            where = os.path.join(model_path, tag)
                            if tk == "dir":
                                continue
                            if tk != "file":
                                sp["partial"] = True
                                issue(code_for(tk), where)
                                continue
                            ollama_model(ctx, store, sp, (reg, ns, model, tag), where, blobs, blobs_kind, digests)
    except Full:
        sp["partial"] = True
    except Stop:
        sp["partial"] = True
        store["total_bytes"] = sum(digests.values())
        finish_store(ctx, store, sp)
        raise
    store["total_bytes"] = sum(digests.values())
    finish_store(ctx, store, sp)


def lmstudio_repo(ctx, store, sp, publisher, repo, path):
    try:
        entries = list_sizes(path)
    except Abort:
        sp["partial"] = True
        issue("unreadable", path)
        return
    ggufs, other_bytes, other_files, weights = [], 0, 0, set()
    for name, k, size in entries:
        check_time()
        where = os.path.join(path, name)
        if k == "file":
            low = name.lower()
            if low.endswith(".gguf"):
                ggufs.append((name, size))
                continue
            other_bytes += size
            other_files += 1
            weights.update(e for e in WEIGHT_EXTS if low.endswith(e))
        elif k == "dir":
            # One level down (an MLX repo keeps its shards here); no deeper.
            try:
                inner = list_sizes(where)
            except Abort:
                sp["partial"] = True
                issue("unreadable", where)
                continue
            for iname, ik, isize in inner:
                if ik == "file":
                    other_bytes += isize
                    other_files += 1
                    weights.update(e for e in WEIGHT_EXTS + (".gguf",) if iname.lower().endswith(e))
                else:
                    sp["partial"] = True
                    issue("depth_limit" if ik == "dir" else code_for(ik), os.path.join(where, iname))
        else:
            sp["partial"] = True
            issue(code_for(k), where)
    name = clean_text(publisher + "/" + repo, 512)
    if name is None:
        sp["partial"] = True
        issue("name_unsafe", os.path.dirname(path))
        return
    for fname, size in ggufs:
        tag = clean_text(fname[:-5], 255)
        if tag is None:
            sp["partial"] = True
            issue("name_unsafe", path)
            continue
        take_slot()
        store["total_bytes"] += size
        model_row(ctx, store, name=name, tag=tag, format="gguf", size_bytes=size, file_count=1, size_source="stat")
    if not ggufs and weights:
        take_slot()
        store["total_bytes"] += other_bytes
        model_row(ctx, store, name=name, format="safetensors" if ".safetensors" in weights else "other",
                  size_bytes=other_bytes, file_count=other_files, size_source="stat")


def lmstudio_stores(ctx, home):
    unit = ctx["units"]["lm_studio"]
    for parts in LMSTUDIO_STORES:
        k, base = walk(home, parts)
        if k == "absent":
            continue
        if k != "dir":
            refuse(unit, k, base)
            continue
        if model_limit_hit():
            unit["partial"] = True
            continue
        store = new_store(ctx, "lm_studio", base)
        sp = {"partial": False, "failed": False}
        try:
            try:
                publishers = list_dir(base)
            except Abort:
                issue("unreadable", base)
                sp["failed"] = True
                publishers = []
            for publisher, pk in publishers:
                check_time()
                if pk == "file":
                    continue
                if pk != "dir":
                    sp["partial"] = True
                    issue(code_for(pk), os.path.join(base, publisher))
                    continue
                for repo, repo_path in sub_dirs(sp, os.path.join(base, publisher)):
                    check_time()
                    lmstudio_repo(ctx, store, sp, publisher, repo, repo_path)
        except Full:
            sp["partial"] = True
        except Stop:
            sp["partial"] = True
            finish_store(ctx, store, sp)
            raise
        finish_store(ctx, store, sp)


# --- users --------------------------------------------------------------------

def owner_of(path):
    try:
        return lstat_at(path).st_uid
    except OSError:
        return None


def main():
    users = []
    runtime_statuses = {r: [] for r in RUNTIMES}
    stopped = False
    user_ctxs = []

    system_ctx = new_ctx("system", None, None)
    try:
        app_bundles(system_ctx, system_root, ("Applications",))
        brew_kegs(system_ctx)
    except Stop:
        for u in system_ctx["units"].values():
            u["partial"] = True
        stopped = True

    root_kind = kind(users_root)
    homes = None
    if root_kind != "dir":
        issue(code_for(root_kind), users_root)
    else:
        try:
            homes = list_dir(users_root)
        except Abort:
            issue("unreadable", users_root)
    if homes is None:
        # No user was looked at: every runtime's per-user half is failed.
        for r in RUNTIMES:
            runtime_statuses[r].append("failed")
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
        ctx = new_ctx("user", clean_text(name, 255) or "<unprintable>", str(uid) if uid is not None else None)
        urow = {"user": ctx["user"], "user_id": ctx["user_id"], "collection_status": "failed",
                "runtimes": {r: "failed" for r in RUNTIMES}}
        users.append(urow)
        user_ctxs.append((ctx, urow))
        if k != "dir":
            issue(code_for(k), home)
            for r in RUNTIMES:
                ctx["units"][r]["problems"] += 1
            continue
        try:
            app_bundles(ctx, home, ("Applications",))
            ollama_store(ctx, home)
            lmstudio_stores(ctx, home)
        except Stop:
            for r in RUNTIMES:
                ctx["units"][r]["partial"] = True
            stopped = True

    if not stopped:
        try:
            bin_links(system_ctx)
        except Stop:
            for u in system_ctx["units"].values():
                u["partial"] = True
            stopped = True

    for r in RUNTIMES:
        runtime_statuses[r].append(unit_status(system_ctx["units"][r]))
    for ctx, urow in user_ctxs:
        statuses = [unit_status(ctx["units"][r]) for r in RUNTIMES]
        for r, st in zip(RUNTIMES, statuses):
            runtime_statuses[r].append(st)
        urow["collection_status"] = combine(statuses)
        urow["runtimes"] = dict(zip(RUNTIMES, statuses))

    runtimes = {}
    for r in RUNTIMES:
        rstores = [s for s in stores if s["runtime"] == r]
        runtimes[r] = {
            "collection_status": combine(runtime_statuses[r], truncated=stopped),
            "installation_count": sum(1 for i in installations if i["runtime"] == r),
            "store_count": len(rstores),
            "model_count": sum(s["model_count"] for s in rstores),
            "total_bytes": sum(s["total_bytes"] for s in rstores),
        }
    status = combine([runtimes[r]["collection_status"] for r in RUNTIMES], truncated=state["truncated"])
    return finish(status, runtimes, users)


def finish(status, runtimes, users):
    key = lambda m: (m["runtime"], m["user"] or "", m["store_path"], m["name"] or "", m["tag"] or "")
    totals = {
        "model_count": sum(runtimes[r]["model_count"] for r in RUNTIMES),
        "total_bytes": sum(runtimes[r]["total_bytes"] for r in RUNTIMES),
    }
    block = {
        "collection_status": status,
        "truncated": state["truncated"],
        "truncation_reason": state["reason"] if state["truncated"] else None,
        "runtimes": runtimes,
        "totals": totals,
        "users": users,
        "installations": installations,
        "stores": stores,
        "issues": state["issues"],
    }
    if status != "failed":
        block["models"] = sorted(models, key=key)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(block, f, separators=(",", ":"))
    failed = status == "failed"
    print(status, 0 if failed else totals["model_count"], 0 if failed else totals["total_bytes"], len(users),
          len(installations), *(runtimes[r]["collection_status"] for r in RUNTIMES))


main()
PYEOF
    _lm_pid=$!

    # A parser this loop killed is failed whatever wait reports: one that
    # finished between the last check and the kill is reaped with a clean
    # status, and its output is not trusted (PAT-2033).
    local _lm_killed=0
    while kill -0 "$_lm_pid" 2>/dev/null; do
        if (( _lm_ticks >= _LM_HARD_TIMEOUT_SECONDS * 10 )); then
            kill -9 "$_lm_pid" 2>/dev/null
            _lm_killed=1
            log_warn "local_models: parser still running after ${_LM_HARD_TIMEOUT_SECONDS}s, killed; block is failed"
            break
        fi
        sleep 0.1
        (( _lm_ticks++ ))
    done
    wait "$_lm_pid" 2>/dev/null || _lm_rc=$?

    _lm_line=$(head -n 1 "$_lm_summary" 2>/dev/null)
    _lm_fields=(${=_lm_line})
    if (( _lm_killed == 0 && _lm_rc == 0 )) && (( ${#_lm_fields} == 8 )) \
        && [[ "${_lm_fields[1]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_lm_fields[2]}${_lm_fields[3]}${_lm_fields[4]}${_lm_fields[5]}" == <-> ]] \
        && [[ "${_lm_fields[6]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_lm_fields[7]}" == (complete|partial|not_present|failed) ]] \
        && [[ "${_lm_fields[8]}" == (complete|partial|not_present|failed) ]] \
        && "$PYTHON3" -c 'import json,sys; json.load(open(sys.argv[1]))' "$_lm_out" 2>/dev/null; then
        mv -f "$_lm_out" "$LOCAL_MODELS_JSON_TMP"
        LOCAL_MODELS_COLLECTION_STATUS="${_lm_fields[1]}"
        LOCAL_MODELS_MODEL_COUNT="${_lm_fields[2]}"
        LOCAL_MODELS_TOTAL_BYTES="${_lm_fields[3]}"
        LOCAL_MODELS_USER_COUNT="${_lm_fields[4]}"
        LOCAL_MODELS_INSTALLATION_COUNT="${_lm_fields[5]}"
        LOCAL_MODELS_OLLAMA_STATUS="${_lm_fields[6]}"
        LOCAL_MODELS_LM_STUDIO_STATUS="${_lm_fields[7]}"
        LOCAL_MODELS_LLAMA_CPP_STATUS="${_lm_fields[8]}"
        # PAT-2225: an over-budget block is sent as failed (see common.sh).
        patched_block_within_budget local_models "$LOCAL_MODELS_JSON_TMP" "$_LM_MAX_BYTES" \
            || LOCAL_MODELS_COLLECTION_STATUS="failed"
    else
        # Parser stderr can carry file names from user-owned trees: newlines
        # become spaces and every other control character is dropped, so the
        # log line cannot be split or carry terminal escapes.
        log_warn "local_models: parser failed (exit $_lm_rc): $(head -c 300 "$_lm_err" 2>/dev/null | tr '\n\t' '  ' | LC_ALL=C tr -d '\000-\037\177')"
        rm -f "$_lm_out"
    fi
    rm -f "$_lm_summary" "$_lm_err"
    local _lm_wire="held off the wire"
    (( _LOCAL_MODELS_PAYLOAD_ON_WIRE )) && _lm_wire="sent"
    echo "local_models: status=$(local_models_collection_status) ollama=$LOCAL_MODELS_OLLAMA_STATUS lm_studio=$LOCAL_MODELS_LM_STUDIO_STATUS llama_cpp=$LOCAL_MODELS_LLAMA_CPP_STATUS installations=$LOCAL_MODELS_INSTALLATION_COUNT models=$LOCAL_MODELS_MODEL_COUNT bytes=$LOCAL_MODELS_TOTAL_BYTES users=$LOCAL_MODELS_USER_COUNT ($_lm_wire)"
    return 0
}
