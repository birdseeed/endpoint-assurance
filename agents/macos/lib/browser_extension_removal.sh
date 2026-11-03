# browser_extension_removal.sh — Browser Extension Control: profile-aware,
# audited extension removal for Chrome, Edge and Firefox (PAT-829, part of
# PAT-773). The destructive escalation path once the PAT-828 managed-policy
# blocklist isn't sufficient or isn't supported for a browser.
#
# Sourced by patched-upload.sh; not executable directly.
#
# Requires (set by caller before sourcing):
#   PYTHON3      — absolute path to python3 (/usr/bin/python3)
#   API_URL      — base URL, e.g. https://api.patched.im
#   BEARER_TOKEN — opaque bearer credential
#   HW_UUID      — device UUID (may be empty; used as details.device_id + header)
#   PATCHED_TMPDIR — root-owned 0700 scratch dir (ephemeral — wiped by the
#                    caller's EXIT trap at the end of the run; never use it
#                    for anything that must outlive this invocation)
#   STATE_DIR    — durable root-owned state dir, e.g. /var/db/patched (PAT-1037:
#                  holds the audit-post lock dir and the pending-audit-events
#                  file, both of which must survive across separate runs,
#                  unlike PATCHED_TMPDIR above)
#
# The compute_hmac and patched_curl_bearer helpers must be in scope; the caller
# (patched-upload.sh) defines them inline and sources this module afterwards.
# The authenticated audit POST goes through patched_curl_bearer so the bearer
# token reaches curl over stdin, never on argv (PAT-881).
#
# Policy source: the signed agent-config's app_control block, same file the
# blocklist enforcer reads. This consumes app_control.extension_removals — a list
# of {browser, extension_id, scope, user_account?, profile?} directives the tenant
# has escalated to removal (populated server-side from the PAT-826 policy store +
# inventory context). Empty/missing, or app_control disabled, = no-op (fail-safe:
# never delete anything the config didn't explicitly, sufficiently, ask for).
#
# Explicitly NOT the patched-uninstall.sh / app-removal path — extensions have no
# Add/Remove-Programs-style entry. This is a per-browser filesystem primitive:
#   - Chrome / Edge: delete the profile's Extensions/<id> directory AND prune the
#     extensions.settings.<id> entry from Secure Preferences / Preferences.
#   - Firefox: drop the addon from extensions.json AND delete extensions/<id>.xpi.
#
# Scope (per directive), matched against the walked /Users/<user>/<profile> tree:
#   one_profile  — user_account + profile required; only that one install.
#   one_user     — user_account required; every profile of that user.
#   all_profiles — every user + profile on this device.
#   all_devices  — server fanned this out to every device; locally identical to
#                  all_profiles, audited distinctly as all_devices.
#
# Every artifact actually removed posts one enforcement_audit event
# (extension_removed, subject=extension_id, details={browser, profile,
# user_account, device_id, scope}) to /v1/inventory/enforcement-audit (PAT-603),
# reusing the generic ingest path — surfaces in the Enforcement Audit tab for free.
# Nothing on disk to remove ⇒ no event, so a directive that lingers in the config
# doesn't re-post every cycle once the extension is gone (idempotent).
#
# PAT-1037: the POST is best-effort, but the event record is not allowed to be.
# Every run's newly-collected events are merged onto any leftover batch from a
# prior run and committed atomically (temp file + rename, never a truncating
# redirect) to a DURABLE file, $STATE_DIR/.enforcement-audit-pending.json,
# before the POST is even attempted. The accumulated batch is only ever read
# from or written to that file directly — never held in, or passed through,
# a shell/subprocess argv string, since it can grow unboundedly across a long
# outage and a large enough batch would blow past the OS's ARG_MAX. Only a
# confirmed 2xx response with an "ingested" count EXACTLY matching the batch
# size clears that file; anything else (network error, non-2xx, unparseable
# or mismatched body) leaves it in place for the next invocation to retry. A
# mkdir-based lock with PID-liveness staleness detection (see the comment
# block inside ber_remove_extensions()) guards the whole invocation so two
# overlapping runs can't race on that file, and a killed holder can't wedge
# it shut forever. See that same comment block for the removal-proceeds-
# unconditionally decision and the residual (not fully closable here)
# exactly-once gap around the server's nonce-based replay check.
#
# Environment overrides:
#   PATCHED_DRY_RUN=1        — log what would happen; skip deletes and POST
#   PATCHED_AC_CONFIG        — override agent-config path (for testing)
#   PATCHED_BER_USERS_DIR    — override /Users (for testing)

ber_remove_extensions() {
    local _config_file _users_dir _dry_run _device_id
    local _occurred_at _events_json _event_count
    local _body_tmp _sig _ts _nonce _http_code
    local _pending_file _combined_count _ingested_ok _resp_tmp
    local _merge_tmp _held_pid _stale_check_attempt _merge_rc _events_tmp
    local _pending_bytes _body_bytes _expected_bytes
    # _lock_dir is deliberately NOT declared local, unlike its siblings above:
    # verified by hand for this ticket, zsh runs a function-local `trap ...
    # EXIT` AFTER that function's own `local`s have already been torn down
    # (it executes in the caller's frame), so under `set -u` a trap that
    # reads a `local _lock_dir` aborts with "parameter not set" the moment it
    # fires. Leaving it as a plain (function-scoped-by-assignment-only, i.e.
    # global) variable keeps it alive for the trap below to read.

    _config_file="${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}"
    _users_dir="${PATCHED_BER_USERS_DIR:-/Users}"
    _device_id="${HW_UUID:-}"
    _dry_run=0
    [[ "${PATCHED_DRY_RUN:-0}" == "1" ]] && _dry_run=1

    if [[ ! -f "$_config_file" ]]; then
        echo "ext_removal: no agent-config at $_config_file — skipping"
        return 0
    fi

    # PAT-1037: a single mkdir-based lock guards this ENTIRE invocation —
    # the Python removal below included, not only the audit merge/POST/drain
    # further down — matching the endpoint fetchers' LOCK_DIR
    # convention (atomic mkdir, trap cleanup on return, skip-not-block on
    # contention). Two overlapping invocations (e.g. an overlapping
    # LaunchDaemon run) must never both read, merge, and drain
    # $_pending_file: one draining/clearing it while the other is mid-merge
    # is a lost-update race that can drop or duplicate an audit record.
    # Locking only the merge/POST section and letting removal run unlocked
    # would reintroduce exactly that race in a different shape (one
    # invocation's removal events landing in a pending file the other is
    # simultaneously clearing), so a held lock skips the whole cycle —
    # removal included — rather than trying to split it into a "safe" half
    # and an "unsafe" half.
    #
    # zsh scopes a `trap ... EXIT` set inside a function to that function's
    # own return (verified by hand for this ticket): it fires once when this
    # function returns and does not touch, or get touched by, the caller's
    # own `trap 'rm -rf "$PATCHED_TMPDIR"' EXIT` in patched-upload.sh, which
    # is restored automatically afterward. That is why this uses a plain
    # EXIT trap rather than manual `rm -rf` before every return below.
    #
    # PAT-1037 review finding: a bare mkdir lock with no staleness check is a
    # permanent-outage risk — a holder killed (crash, SIGKILL, power loss)
    # between `mkdir` succeeding and its EXIT trap running leaves $_lock_dir
    # behind forever, and every future invocation would then see "lock held"
    # and skip both removal and audit delivery on this device indefinitely.
    # No existing convention for this was found anywhere in this repo:
    # patched-install.sh, patched-uninstall.sh and patched-fetch-posture.sh
    # all use a bare mkdir lock with no PID/staleness check, and the only
    # unrelated precedent (a since-retired verifier's version-file lock) used
    # fcntl.flock, which the kernel releases automatically on process death
    # and so has no staleness problem to solve in the first place — not
    # applicable to a directory-based shell lock. This introduces a minimal,
    # narrow pattern instead: record the holder's PID inside the lock dir,
    # and on contention check whether that PID is still alive before
    # conceding. A single reclaim + single retry — never a retry loop — so a
    # third, still-running holder is respected rather than fought over.
    #
    # PAT-1037 review finding (round 3): `mkdir` and `echo $$ > pid` are two
    # separate steps, not atomic together — a contender that loses the mkdir
    # race can land its "is there a pid?" check in the narrow window AFTER a
    # genuine new owner's mkdir succeeded but BEFORE that owner's `echo $$`
    # has run, see an empty pid file, wrongly conclude "stale," and `rm -rf`
    # the ACTIVE owner's lock out from under it. That write is essentially
    # instant, so a full atomic-rename-based lock protocol would be
    # disproportionate engineering for a low-frequency, locally-scheduled
    # daemon (not a hot path, not a distributed system) — instead, close the
    # window with a small bounded retry: if the pid file reads empty, wait a
    # beat and recheck, up to 3 attempts total, before concluding "stale".
    # Bounded and short (at most ~0.2s of extra latency, only in the
    # already-rare contended case) so it can't meaningfully delay a normal,
    # genuinely-still-running holder.
    _lock_dir="$STATE_DIR/.enforcement-audit-post.lock"
    if ! mkdir "$_lock_dir" 2>/dev/null; then
        _held_pid=""
        for _stale_check_attempt in 1 2 3; do
            _held_pid=$(cat "$_lock_dir/pid" 2>/dev/null)
            [[ -n "$_held_pid" ]] && break
            (( _stale_check_attempt < 3 )) && sleep 0.1
        done
        if [[ -n "$_held_pid" ]] && kill -0 "$_held_pid" 2>/dev/null; then
            echo "ext_removal: lock held by another instance (pid $_held_pid) — skipping this run (removal and audit both deferred)"
            return 0
        fi
        echo "ext_removal: lock at $_lock_dir looks stale (recorded holder pid '${_held_pid:-<missing>}' is not running) — reclaiming and retrying once"
        rm -rf "$_lock_dir"
        if ! mkdir "$_lock_dir" 2>/dev/null; then
            echo "ext_removal: lock held by another instance after stale-lock reclaim attempt — skipping this run (removal and audit both deferred)"
            return 0
        fi
    fi
    echo $$ > "$_lock_dir/pid" 2>/dev/null
    trap 'rm -rf "$_lock_dir"' EXIT

    _pending_file="$STATE_DIR/.enforcement-audit-pending.json"

    _occurred_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Python does the walk + deletion + prefs/extensions.json edits, and prints one
    # audit event per artifact actually removed. In dry-run it deletes nothing but
    # still prints the events it would produce. Any internal error → "[]" (fail-safe).
    _events_json=$("$PYTHON3" - \
        "$_config_file" "$_users_dir" "$_device_id" "$_dry_run" "$_occurred_at" <<'PYEOF'
import ctypes, datetime, json, os, re, stat, sys

config_file, users_dir, device_id, dry_run_s, occurred_at = sys.argv[1:6]
dry_run = (dry_run_s == "1")

# Browser name → Chromium "Application Support" directory.
CHROMIUM = {"chrome": "Google/Chrome", "edge": "Microsoft Edge"}
KNOWN_SCOPES = {"one_profile", "one_user", "all_profiles", "all_devices", "one_observation"}

_O_NOFOLLOW_DIR = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
_RENAME_EXCL = 0x00000004


def rename_exclusive_at(dir_fd, source, destination):
    """macOS renameatx_np(RENAME_EXCL): restore without ever replacing a
    concurrently-created destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = libc.renameatx_np
    renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint]
    renameatx_np.restype = ctypes.c_int
    return renameatx_np(dir_fd, os.fsencode(source), dir_fd,
                        os.fsencode(destination), _RENAME_EXCL) == 0

# PAT-856: extension_id, user_account, and profile are network-fetched from
# the signed agent-config (unverified at this fetch — see module docstring)
# and become filesystem path components below (Extensions/<id>,
# Profiles/<name>, /Users/<user>/...) handed to a root-running remover.
# Nothing validated their charset before this hardening. This charset check
# is the FIRST of two layers: it rejects anything that isn't a single, safe
# path component. Real Chrome/Edge ids are 32 lowercase a-p letters and
# Firefox ids are a {GUID} or name@domain form; the allowlist is deliberately
# a bit wider than either exact format (it also allows the space a real
# Chrome profile name like "Profile 1" needs) so it need not track every
# vendor's exact grammar. The SECOND, load-bearing layer is the fd-anchored,
# symlink-refusing filesystem walk below (open_chain / _open_dir_nofollow /
# safe_rmtree_at): every component is opened with O_NOFOLLOW relative to the
# previous directory fd, and deletion happens through those fds, never by
# re-resolving a string path. That closes the check-then-delete (TOCTOU) race
# a charset/realpath check alone cannot: a local user who owns the profile
# tree cannot swap any component to a symlink to redirect a root delete,
# because no path is ever resolved by name a second time.
SAFE_FIELD_RE = re.compile(r"^[A-Za-z0-9 @._{}+-]+$")


def is_safe_field(value):
    """Reject anything that could escape a path, or is empty, before it is
    used as a path component. Reject: path separators, ".." (anywhere, not
    just as a standalone segment), NUL bytes, and anything outside the
    conservative charset above."""
    if not value:
        return False
    if "\x00" in value or ".." in value or "/" in value or "\\" in value:
        return False
    return bool(SAFE_FIELD_RE.match(value))


def _open_dir_nofollow(dir_fd, name, describe=None):
    """openat(name, O_NOFOLLOW|O_DIRECTORY) relative to dir_fd. Returns a new
    dir fd (caller closes) or None. A symlink, a non-directory, or a missing
    entry all return None — fail closed. When `describe` is set, a symlink is
    logged as an explicit refusal (that is the attack we are defeating)."""
    if describe is not None:
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                print(f"ext_removal: REFUSING symlinked {describe}: {name}", file=sys.stderr)
                return None
        except OSError:
            return None
    try:
        return os.open(name, _O_NOFOLLOW_DIR, dir_fd=dir_fd)
    except OSError:
        return None


def open_chain(base_path, components, describe_last=None):
    """Open `base_path` (an absolute, trusted anchor — /Users, root-owned),
    then walk `components` opening each with O_NOFOLLOW so a user-planted
    symlink at ANY level is refused rather than followed. Returns the final
    dir fd (caller closes) or None. `describe_last` labels the final
    component for symlink-refusal logging."""
    try:
        fd = os.open(base_path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    last = len(components) - 1
    for i, comp in enumerate(components):
        nxt = _open_dir_nofollow(fd, comp, describe_last if i == last else None)
        os.close(fd)
        if nxt is None:
            return None
        fd = nxt
    return fd


def safe_rmtree_at(parent_fd, name):
    """Recursively remove directory `name` located in `parent_fd`, following
    NO symlink at any step (every descent is an O_NOFOLLOW openat; every leaf
    an unlinkat that does not follow). Fails closed (deletes nothing, returns
    False) if `name` is not a real directory or anything races underneath.
    In dry-run, only confirms `name` is a real directory."""
    try:
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return False  # symlink / file / missing — never traverse it
    if dry_run:
        return True
    fd = _open_dir_nofollow(parent_fd, name)
    if fd is None:
        return False
    try:
        for entry in os.listdir(fd):
            try:
                est = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            except OSError:
                return False
            if stat.S_ISDIR(est.st_mode):
                if not safe_rmtree_at(fd, entry):
                    return False
            else:
                # regular file, symlink, socket, ... — unlinkat removes the
                # entry itself and never follows a symlink target.
                try:
                    os.unlink(entry, dir_fd=fd)
                except OSError:
                    return False
    finally:
        os.close(fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        return False
    return True


def safe_unlink_file_at(dir_fd, name):
    """Remove regular file `name` in `dir_fd`, following no symlink. Refuses
    (returns False) anything that is not a regular file. dry-run only checks
    existence."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if dry_run:
        return True
    try:
        os.unlink(name, dir_fd=dir_fd)
        return True
    except OSError:
        return False


def remove_observed_dir_at(parent_fd, name, approved_before):
    """Atomically quarantine the current name before inspecting it. A newer
    replacement is restored and never passed to the recursive deleter."""
    try:
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_mtime > approved_before:
        return False
    if dry_run:
        return True
    quarantine = ".patched-observed-%s" % os.urandom(12).hex()
    try:
        os.rename(name, quarantine, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(moved.st_mode) or moved.st_mtime > approved_before:
            rename_exclusive_at(parent_fd, quarantine, name)
            return False
        if safe_rmtree_at(parent_fd, quarantine):
            return True
        # The browser no longer resolves the extension at its active name.
        # Report that removal truthfully even if best-effort quarantine cleanup
        # left remnants for a later maintenance pass.
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            return False
        except OSError:
            return True
    except OSError:
        return False


def remove_observed_file_at(parent_fd, name, approved_before):
    """Atomically quarantine the current file before inspecting and deleting it."""
    try:
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_mtime > approved_before:
        return False
    if dry_run:
        return True
    quarantine = ".patched-observed-%s" % os.urandom(12).hex()
    try:
        os.rename(name, quarantine, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(moved.st_mode) or moved.st_mtime > approved_before:
            try:
                # Hard-link restore is create-only: unlike rename it fails
                # with EEXIST instead of overwriting a concurrent reinstall.
                os.link(quarantine, name, src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd, follow_symlinks=False)
                os.unlink(quarantine, dir_fd=parent_fd)
            except OSError:
                pass
            return False
        if safe_unlink_file_at(parent_fd, quarantine):
            return True
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            return False
        except OSError:
            return True
    except OSError:
        return False


events = []


def load_json(path):
    """Read+parse a JSON file by absolute path. Used only for the root-owned
    agent-config, which is read (never deleted) and not under a user-writable
    tree, so the fd-anchored variant is unnecessary here."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=reject_ambiguous_keys)
    except Exception:
        return None


def reject_ambiguous_keys(pairs):
    result, seen = {}, set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError("duplicate or case-colliding JSON key")
        seen.add(folded)
        result[key] = value
    return result


def load_json_fd(dir_fd, name):
    """Read+parse JSON file `name` in `dir_fd`, opened O_NOFOLLOW. None on any
    error (missing, symlink, bad JSON)."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def atomic_write_at(dir_fd, name, obj):
    """Rewrite JSON file `name` in `dir_fd` atomically, anchored to the fd so
    a swapped parent cannot redirect the write.

    PAT-856 (review finding): the temp file must be created with an
    UNPREDICTABLE name AND O_EXCL. A deterministic temp name opened
    O_CREAT|O_TRUNC lets a local user pre-create `<name>.patched.tmp` as a
    hardlink to another regular file — O_NOFOLLOW does not stop hardlinks, so
    the root process would truncate and overwrite the linked target. O_EXCL
    refuses to open any pre-existing entry (hardlink included), and the random
    name means the attacker cannot pre-create it in the first place. Owner and
    mode are copied from the original so a root rewrite does not leave the
    user's profile file root-owned."""
    try:
        orig = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return False
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    for _ in range(8):
        tmp = ".patched-%s.tmp" % os.urandom(8).hex()
        try:
            fd = os.open(tmp, flags, 0o600, dir_fd=dir_fd)
        except FileExistsError:
            continue  # astronomically unlikely; pick a new name
        except OSError:
            return False
        try:
            try:
                os.fchown(fd, orig.st_uid, orig.st_gid)
                os.fchmod(fd, stat.S_IMODE(orig.st_mode))
            except OSError:
                pass  # best-effort metadata; not worth aborting the prune
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            return True
        except Exception:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except OSError:
                pass
            return False
    return False


def normalize(cfg):
    ac = cfg.get("app_control") if isinstance(cfg, dict) else None
    if not isinstance(ac, dict) or not ac.get("enabled"):
        return []
    entries = ac.get("extension_removals")
    if not isinstance(entries, list):
        return []
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        browser = (e.get("browser") or "").strip().lower()
        ext_id = (e.get("extension_id") or "").strip()
        scope = (e.get("scope") or "").strip().lower()
        if not browser or not ext_id:
            continue
        # PAT-1316: an unrecognised scope must not vanish the same way as a
        # merely-incomplete entry above. The server (dbGetExtensionRemovalsForDevice)
        # can emit a scope this agent build predates or doesn't know — e.g.
        # one_observation before this file added it, or a still-newer scope
        # shipped after. Previously this `continue`d silently: a dropped directive
        # was indistinguishable from one never sent, so the dashboard showed a
        # removal request pending forever with no explanation, while the very next
        # validation below (invalid extension_id) already printed a REJECT line.
        # Match that adjacent shape/stream so an unknown scope is exactly as loud
        # as any other rejected field.
        if scope not in KNOWN_SCOPES:
            print(f"ext_removal: REJECT unrecognised scope (agent build does not support it): {scope!r}",
                  file=sys.stderr)
            continue
        if browser not in CHROMIUM and browser != "firefox":
            continue  # unsupported browser — no removal primitive

        # PAT-856: validate before ANY path is built from these fields. Fail
        # closed — an invalid entry is skipped and logged, never "best-effort"
        # acted on.
        if not is_safe_field(ext_id):
            print(f"ext_removal: REJECT invalid extension_id (unsafe characters): {ext_id!r}",
                  file=sys.stderr)
            continue

        user = (e.get("user_account") or "").strip() or None
        profile = (e.get("profile") or "").strip() or None
        approved_before = None
        approved_before_raw = None
        if scope == "one_observation":
            # A known scope with a malformed boundary field is the same class of
            # problem as an unsafe extension_id/user/profile below — log it the
            # same way rather than letting it vanish into the generic `continue`.
            _reject_approved_before = False
            try:
                approved_before_raw = (e.get("approved_before") or "").strip()
                if not re.search(r"(?:Z|[+-][0-9]{2}:[0-9]{2})$", approved_before_raw):
                    _reject_approved_before = True
                else:
                    approved_before = datetime.datetime.fromisoformat(
                        approved_before_raw.replace("Z", "+00:00")
                    ).timestamp()
            except (TypeError, ValueError):
                _reject_approved_before = True
            if _reject_approved_before:
                print(f"ext_removal: REJECT invalid approved_before for one_observation "
                      f"(missing/malformed or no explicit UTC offset): {approved_before_raw!r}",
                      file=sys.stderr)
                continue
        if user is not None and not is_safe_field(user):
            print(f"ext_removal: REJECT invalid user_account (unsafe characters): {user!r}",
                  file=sys.stderr)
            continue
        if profile is not None and not is_safe_field(profile):
            print(f"ext_removal: REJECT invalid profile (unsafe characters): {profile!r}",
                  file=sys.stderr)
            continue

        # Narrow scopes must carry enough to target, or we'd have to widen the
        # blast radius to act at all — never do that for a destructive op.
        if scope == "one_user" and not user:
            continue
        if scope in ("one_profile", "one_observation") and (not user or not profile):
            continue
        out.append({"browser": browser, "extension_id": ext_id, "scope": scope,
                    "user": user, "profile": profile,
                    "approved_before": approved_before,
                    "approved_before_raw": approved_before_raw})
    return out


def user_in_scope(d, user_account):
    if d["scope"] in ("all_profiles", "all_devices"):
        return True
    return d["user"] is not None and d["user"].lower() == user_account.lower()


def audit(d, profile, user_account):
    events.append({
        "event_type": "extension_removed",
        "subject": d["extension_id"],
        "details": {
            "approved_before": d["approved_before_raw"],
            "browser": d["browser"],
            "profile": profile,
            "user_account": user_account,
            "device_id": device_id,
            "scope": d["scope"],
            "dry_run": dry_run,
        },
        "occurred_at": occurred_at,
    })


def remove_chromium_settings_at(profile_fd, prefs_name, ext_id):
    """Prune extensions.settings.<id> from a Chromium prefs file, reading and
    writing through profile_fd (O_NOFOLLOW) so neither the prefs file nor its
    parent can be symlink-swapped to redirect a root write. Returns True if
    the entry existed (removed unless dry-run)."""
    d = load_json_fd(profile_fd, prefs_name)
    if not isinstance(d, dict):
        return False
    ext = d.get("extensions")
    if not isinstance(ext, dict):
        return False
    settings = ext.get("settings")
    if not isinstance(settings, dict) or ext_id not in settings:
        return False
    if dry_run:
        return True
    del settings[ext_id]
    return atomic_write_at(profile_fd, prefs_name, d)


def chromium_profile_names(base_fd, d):
    """Profile names to act on, listed via base_fd. one_profile → the named
    profile only; otherwise Default plus every real 'Profile N' directory."""
    if d["scope"] in ("one_profile", "one_observation") and d["profile"]:
        return [d["profile"]]
    names = ["Default"]
    try:
        for n in sorted(os.listdir(base_fd)):
            if not n.startswith("Profile "):
                continue
            try:
                st = os.stat(n, dir_fd=base_fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                names.append(n)
    except OSError:
        pass
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def handle_chromium(user_account, d):
    # Trusted anchor: users_dir (/Users, root-owned). Every component down to
    # the browser base is opened O_NOFOLLOW, so a user-planted symlink
    # anywhere in ~/Library/Application Support/<vendor> is refused, not
    # followed. base_fd therefore refers to the REAL browser directory.
    base_chain = [user_account, "Library", "Application Support"] + CHROMIUM[d["browser"]].split("/")
    base_fd = open_chain(users_dir, base_chain)
    if base_fd is None:
        return
    try:
        for profile in chromium_profile_names(base_fd, d):
            # Open the profile O_NOFOLLOW off the real base — a symlinked
            # profile (the TOCTOU/symlink attack) is refused and logged here.
            profile_fd = _open_dir_nofollow(base_fd, profile, describe="Chromium profile")
            if profile_fd is None:
                continue
            try:
                removed = False
                observation_matches = d["scope"] != "one_observation"
                # Extensions/<id>: open the real Extensions root O_NOFOLLOW off
                # the real profile fd, then delete <id> through fd-relative,
                # symlink-refusing syscalls. No path is re-resolved by string,
                # so nothing can be swapped between check and delete.
                ext_root_fd = _open_dir_nofollow(profile_fd, "Extensions", describe="Extensions root")
                if ext_root_fd is not None:
                    try:
                        if d["scope"] == "one_observation":
                            removed = remove_observed_dir_at(
                                ext_root_fd, d["extension_id"], d["approved_before"])
                            observation_matches = removed
                        elif safe_rmtree_at(ext_root_fd, d["extension_id"]):
                            removed = True
                    finally:
                        os.close(ext_root_fd)
                # PAT-1316: one_observation is not a functionally distinct removal
                # — the server compiles every broader scope down to one_observation
                # directives at delivery time (same removal request, narrowed to one
                # already-observed target, with the approved_before boundary as the
                # only added safety check). So once the boundary check has cleared
                # (observation_matches — for every OTHER scope this is unconditionally
                # True, matching this block's pre-PAT-1316 behaviour exactly), prune
                # the settings entry the same as any other scope. Gating this on
                # `d["scope"] != "one_observation"` as well (as an earlier version of
                # this diff did) would silently skip prefs pruning for every
                # one_observation removal — the very silent-partial-removal failure
                # mode this ticket exists to eliminate.
                if observation_matches:
                    for prefs_name in ("Secure Preferences", "Preferences"):
                        if remove_chromium_settings_at(profile_fd, prefs_name, d["extension_id"]):
                            removed = True
                if removed:
                    audit(d, profile, user_account)
            finally:
                os.close(profile_fd)
    finally:
        os.close(base_fd)


def remove_firefox_addon_at(profile_fd, ext_file, ext_id):
    """Drop the addon with id == ext_id from extensions.json, read+written
    through profile_fd (O_NOFOLLOW)."""
    d = load_json_fd(profile_fd, ext_file)
    if not isinstance(d, dict):
        return False
    addons = d.get("addons")
    if not isinstance(addons, list):
        return False
    kept = [a for a in addons if not (isinstance(a, dict) and a.get("id") == ext_id)]
    if len(kept) == len(addons):
        return False
    if dry_run:
        return True
    d["addons"] = kept
    return atomic_write_at(profile_fd, ext_file, d)


def handle_firefox(user_account, d):
    profiles_chain = [user_account, "Library", "Application Support", "Firefox", "Profiles"]
    profiles_fd = open_chain(users_dir, profiles_chain)
    if profiles_fd is None:
        return
    try:
        try:
            names = sorted(os.listdir(profiles_fd))
        except OSError:
            return
        for name in names:
            if d["scope"] in ("one_profile", "one_observation") and name != d["profile"]:
                continue
            profile_fd = _open_dir_nofollow(profiles_fd, name, describe="Firefox profile")
            if profile_fd is None:
                continue
            try:
                removed = False
                observation_matches = d["scope"] != "one_observation"
                # extensions/<id>.xpi: open the real extensions root O_NOFOLLOW
                # off the real profile fd, then unlink the file fd-relative.
                ext_root_fd = _open_dir_nofollow(profile_fd, "extensions", describe="extensions root")
                if ext_root_fd is not None:
                    try:
                        xpi_name = d["extension_id"] + ".xpi"
                        if d["scope"] == "one_observation":
                            removed = remove_observed_file_at(
                                ext_root_fd, xpi_name, d["approved_before"])
                            observation_matches = removed
                        elif safe_unlink_file_at(ext_root_fd, xpi_name):
                            removed = True
                    finally:
                        os.close(ext_root_fd)
                # PAT-1316: see the matching comment in handle_chromium above — the
                # same "prune only after the boundary check passed" rule applies
                # here, without an extra scope check that would otherwise silently
                # skip the addons.json prune for every one_observation removal.
                if observation_matches and remove_firefox_addon_at(
                        profile_fd, "extensions.json", d["extension_id"]):
                    removed = True
                if removed:
                    audit(d, name, user_account)
            finally:
                os.close(profile_fd)
    finally:
        os.close(profiles_fd)


def main():
    cfg = load_json(config_file)
    if cfg is None:
        print("[]")
        return
    directives = normalize(cfg)
    if not directives:
        print("[]")
        return
    try:
        users = sorted(os.listdir(users_dir))
    except Exception:
        print("[]")
        return
    for user_account in users:
        if user_account in ("Shared", "Guest"):
            continue
        # is_safe_field guards the user_account we build a path from. It comes
        # from os.listdir(users_dir) here (a real on-disk name), but the walk
        # below opens it O_NOFOLLOW regardless, so a symlinked home is refused.
        if not is_safe_field(user_account):
            continue
        for d in directives:
            if not user_in_scope(d, user_account):
                continue
            if d["browser"] in CHROMIUM:
                handle_chromium(user_account, d)
            elif d["browser"] == "firefox":
                handle_firefox(user_account, d)
    print(json.dumps(events))


main()
PYEOF
    ) || _events_json="[]"

    # PAT-1037 review finding (round 4): a single cycle's OWN removal batch
    # was assumed bounded ("one machine's local walk, can't grow across
    # cycles") and passed via argv below and in the merge step further down.
    # That assumption doesn't hold against a deliberately hostile local
    # user: an unprivileged account can create arbitrarily many matching
    # Chromium profile directories, and a broad-scope directive (all_
    # profiles/all_devices) would then legitimately enumerate one removal
    # event per profile — a single cycle's OWN batch can be inflated to
    # exceed ARG_MAX on purpose, not just via accumulation across an outage.
    # This file already treats a hostile local user as in-scope for its
    # threat model (the O_NOFOLLOW/symlink-refusing opens throughout), so
    # this is real, not theoretical. Fix: write $_events_json to a file
    # immediately, exactly once, and have every downstream consumer read
    # that file by path — never pass it as argv again, matching the same
    # ARG_MAX discipline already applied to the accumulated pending batch.
    # PATCHED_TMPDIR (not $STATE_DIR) is correct here: this file only needs
    # to survive within this single invocation, unlike the durable pending
    # file.
    # Matches the fail-fast style already used for _merge_tmp/_body_tmp/
    # _resp_tmp below: if this cycle's own removal results can't even be
    # durably captured to a temp file, do not silently proceed as if zero
    # extensions were removed — the removals already happened on disk.
    _events_tmp=$(mktemp "$PATCHED_TMPDIR/patched-ber-events.XXXXXX") || {
        echo "ext_removal: WARN — could not create temp file for this cycle's event batch; this cycle's removal results (if any) could not be durably recorded and are dropped"
        return 0
    }
    printf '%s' "$_events_json" > "$_events_tmp" || {
        echo "ext_removal: WARN — could not write this cycle's event batch to a temp file; this cycle's removal results (if any) could not be durably recorded and are dropped"
        rm -f "$_events_tmp"
        return 0
    }

    _event_count=$("$PYTHON3" -c "
import json, sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        print(len(json.load(f)))
except Exception:
    print(0)
" "$_events_tmp" 2>/dev/null) || _event_count=0

    if (( _dry_run )); then
        # PATCHED_DRY_RUN skips deletes AND the POST (module docstring); it is
        # a simulated run and must not touch durable state either, so it never
        # reads or writes $_pending_file. The mkdir lock above is still held
        # and released normally by the EXIT trap.
        if (( _event_count == 0 )); then
            echo "ext_removal: nothing to remove"
        else
            echo "ext_removal: DRY_RUN — would remove $_event_count extension install(s); would POST audit"
        fi
        rm -f "$_events_tmp"
        return 0
    fi

    if (( _event_count > 0 )); then
        echo "ext_removal: removed $_event_count extension install(s) across in-scope profiles"
    fi

    # PAT-1037: merge this run's events (possibly zero — a prior run's
    # leftover pending batch deserves a fresh drain attempt on every
    # invocation, not only on runs that also find new removals) onto
    # whatever is already durably persisted in $_pending_file, BEFORE
    # attempting the POST below. This ordering is the actual fix: the
    # deletions above are already the source of truth on disk (idempotent —
    # a re-run just finds nothing left to remove for anything already gone),
    # so the event list Python returned is the only copy of "what got
    # removed" once this function returns. Persisting it durably first means
    # a POST failure can never discard it — only delay it to the next run.
    #
    # PAT-1037 review findings (P1 x2, both closed by this restructuring):
    #   1. The combined batch can grow unboundedly across a long outage (days
    #      of failed POSTs all appending to the same pending file) — it must
    #      NEVER be passed as a `python3 -c` argv string. A batch large enough
    #      to exceed the OS's ARG_MAX would fail to even start python, and the
    #      `|| _combined_count=0` fallback would then make the code below
    #      believe the batch is empty and delete it — destroying the exact
    #      backlog this fix exists to protect. Nothing in this function is
    #      passed via argv to a subprocess anymore, INCLUDING this run's own
    #      new events (round 4: a hostile local user can inflate even a
    #      single cycle's own batch past ARG_MAX by creating enough matching
    #      profiles for a broad-scope directive — see $_events_tmp above,
    #      written once right after Python's removal pass returns). Every
    #      batch, accumulated or single-cycle, is read from or written to a
    #      FILE, never a shell variable passed as an argument.
    #   2. A direct `> $_pending_file` redirect is not atomic — a kill mid-
    #      write (crash, SIGKILL, power loss) can truncate/corrupt it, and
    #      the merge's own `except Exception: prior = []` would then treat
    #      that corruption as "nothing was pending" on the very next run,
    #      permanently losing the backlog. Fixed the same way PAT-1040 just
    #      landed a config-quarantine move (endpoint/patched-fetch-config.sh,
    #      `mv -f "$AGENT_CONFIG_FILE" "$AGENT_CONFIG_QUARANTINE_FILE"`):
    #      write to a temp file in the SAME directory as $_pending_file (same
    #      filesystem, so the rename is atomic), then `mv -f` it into place.
    #      Nothing downstream reads $_pending_file until after that rename
    #      lands, so a kill at any point before it leaves the previous,
    #      still-intact pending file exactly as it was.
    #
    # PAT-1037 review finding (round 3): that atomic-rename fix closed OUR
    # OWN ability to corrupt $_pending_file mid-write, but the merge's prior-
    # file read still collapsed "doesn't exist" (correct: prior = []) and
    # "exists but fails to parse" (WRONG to treat as empty — silently
    # discards whatever backlog is genuinely still sitting in it, e.g. an
    # external disk fault, or a pending file from a pre-atomic-write version
    # of this fix) into the same outcome. A corrupted-but-present pending
    # file must be a loud, distinguishable failure — never silently treated
    # as empty, never deleted (leave it for inspection, same "quarantine,
    # don't destroy evidence" instinct as PAT-1040's config quarantine). The
    # python helper below signals that distinction with a dedicated exit
    # code (3) the shell checks explicitly, separate from any other failure.
    # NOTE: the XXXXXX placeholder must be the template's trailing characters
    # — verified by hand for this ticket, this platform's mktemp silently
    # does NOT substitute it (returns the literal, non-random path, exit 0,
    # no error) when anything follows it, e.g. a ".tmp" suffix. Every other
    # mktemp call in this file already puts XXXXXX last for that reason;
    # this one must too.
    _merge_tmp=$(mktemp "$STATE_DIR/.enforcement-audit-pending.tmp.XXXXXX") || {
        echo "ext_removal: WARN — could not create temp file to merge the pending batch; this cycle's $_event_count new event(s) could not be durably recorded and are dropped (any pre-existing pending file is untouched)"
        rm -f "$_events_tmp"
        return 0
    }
    # PAT-1037 review finding (round 4): new_events_json arrived here as an
    # argv string ($_events_json) — same ARG_MAX exposure as the accumulated
    # batch, just for a single cycle's own removals instead of an outage's
    # worth of them. $_events_tmp (written above, right after this cycle's
    # Python removal pass returned) is read by path instead, exactly like
    # prior_path already is.
    "$PYTHON3" -c '
import json, os, sys
prior_path, pending_tmp_path, new_events_path = sys.argv[1], sys.argv[2], sys.argv[3]

# "Doesn'"'"'t exist" (prior = [], normal — nothing has ever been pending) is
# NOT the same outcome as "exists but fails to parse" (a loud failure — exit
# 3 lets the shell wrapper tell the two apart and refuse to touch the file).
if os.path.exists(prior_path):
    # SystemExit (from sys.exit(3) below) is not an Exception subclass in
    # Python 3, so it always propagates past this except clause unharmed —
    # only a genuine parse/read failure is caught and re-signaled as exit 3.
    try:
        with open(prior_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, list):
            sys.exit(3)
        prior = loaded
    except Exception:
        sys.exit(3)
else:
    prior = []

try:
    with open(new_events_path, "r", encoding="utf-8") as f:
        new = json.load(f)
    if not isinstance(new, list):
        new = []
except Exception:
    new = []
with open(pending_tmp_path, "w", encoding="utf-8") as f:
    json.dump(prior + new, f, separators=(",", ":"))
' "$_pending_file" "$_merge_tmp" "$_events_tmp" 2>/dev/null
    _merge_rc=$?
    rm -f "$_events_tmp"
    if (( _merge_rc == 3 )); then
        echo "ext_removal: CRITICAL — $_pending_file exists but is not valid JSON (corrupted or truncated). NOT deleting it — left in place for manual inspection. This cycle's $_event_count new event(s) could not be durably recorded and are dropped."
        rm -f "$_merge_tmp"
        return 0
    elif (( _merge_rc != 0 )); then
        echo "ext_removal: WARN — could not merge pending batch; this cycle's $_event_count new event(s) could not be durably recorded and are dropped (any pre-existing pending file is untouched)"
        rm -f "$_merge_tmp"
        return 0
    fi

    # Count the merged batch by reading the TEMP file (never argv — same
    # ARG_MAX reasoning as above) before committing it into place.
    _combined_count=$("$PYTHON3" -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        print(len(json.load(f)))
except Exception:
    print(-1)
' "$_merge_tmp" 2>/dev/null) || _combined_count=-1

    if (( _combined_count < 0 )); then
        echo "ext_removal: WARN — could not read back the merged pending batch; this cycle's $_event_count new event(s) could not be durably recorded and are dropped (any pre-existing pending file is untouched)"
        rm -f "$_merge_tmp"
        return 0
    fi

    if (( _combined_count == 0 )); then
        # No new events this cycle and no leftover pending batch either —
        # matches the original fast path exactly (same message, no POST).
        echo "ext_removal: nothing to remove"
        rm -f "$_merge_tmp" "$_pending_file" 2>/dev/null
        return 0
    fi

    # Atomic commit BEFORE the POST attempt — this file existing on disk IS
    # the durability guarantee; everything below is best-effort delivery on
    # top of it. Same filesystem as $_merge_tmp (both under $STATE_DIR), so
    # this rename is atomic — no window where $_pending_file is truncated or
    # partially written.
    mv -f "$_merge_tmp" "$_pending_file" || {
        echo "ext_removal: WARN — could not commit merged pending batch to $_pending_file; this cycle's $_event_count new event(s) could not be durably recorded and are dropped (any pre-existing pending file is untouched)"
        rm -f "$_merge_tmp"
        return 0
    }

    # PAT-1037: removal above proceeds unconditionally regardless of any
    # known audit-channel state — deliberately no "is the audit endpoint
    # reachable" gate before the Python removal step. Extension removal is a
    # security control; gating it on audit-channel health would trade a
    # stronger guarantee (enforcement happens) for a weaker one (audit
    # freshness), and that trade is no longer needed anyway: $_pending_file
    # above is now written durably before the POST is even attempted, so an
    # unreachable audit channel no longer means a LOST record, only a
    # DELAYED one that the next invocation retries.
    _body_tmp=$(mktemp "$PATCHED_TMPDIR/patched-ber-audit.XXXXXX") || {
        echo "ext_removal: WARN — could not create tmp file for audit POST; pending batch ($_combined_count event(s)) left at $_pending_file for next run"
        return 0
    }

    # Wrap $_pending_file's contents into the request body via pure shell
    # redirection (cat, not a shell variable) — same ARG_MAX/large-batch
    # reasoning as above: the merged batch's bytes never pass through
    # anything with an argument-length limit on this path either.
    #
    # PAT-1071: this is a `{ ...; } > file` brace-group redirect, and a
    # brace-group's (or subshell's) own exit status is unreliable as a
    # write-failure signal on this estate's bash 3.2 — `if ! { cmd; } >
    # "$file"; then` was verified by hand to not fire even when the
    # redirect genuinely fails to write (permission denied, disk full,
    # quota). Restructuring this into a single plain-command redirect
    # (the other safe fix for that bug) isn't available here without
    # giving up the ARG_MAX-avoidance property above — a single `printf
    # '%s' "$(cat "$_pending_file")"` would route the whole batch through
    # a shell argument again. So: read the write back and compare its
    # actual byte count to what was meant to be written (fixed
    # `{"events":` + `}` wrapper overhead, 11 bytes, plus the pending
    # file's own size). Any mismatch — including a write that fails
    # silently with no non-zero status anywhere to catch — must be
    # treated as a write failure and must NOT proceed to POST a
    # truncated/empty body.
    _pending_bytes=$(wc -c < "$_pending_file" 2>/dev/null) || _pending_bytes=""
    { printf '{"events":'; cat "$_pending_file"; printf '}'; } > "$_body_tmp"
    _body_bytes=$(wc -c < "$_body_tmp" 2>/dev/null) || _body_bytes=""
    _expected_bytes=$(( ${_pending_bytes:-0} + 11 ))
    if [[ -z "$_pending_bytes" || -z "$_body_bytes" || "$_body_bytes" -ne "$_expected_bytes" ]]; then
        echo "ext_removal: WARN — audit POST body write appears truncated/incomplete (wrote ${_body_bytes:-0} byte(s), expected $_expected_bytes); skipping audit POST; pending batch ($_combined_count event(s)) left at $_pending_file for next run"
        rm -f "$_body_tmp"
        return 0
    fi

    _ts=$(date -u +%s)
    _nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    _sig=$(compute_hmac "$_body_tmp" "enforcement_audit" "$_ts" "$_nonce") || {
        echo "ext_removal: WARN — hmac compute failed; skipping audit POST; pending batch ($_combined_count event(s)) left at $_pending_file for next run"
        rm -f "$_body_tmp"
        return 0
    }

    _resp_tmp=$(mktemp "$PATCHED_TMPDIR/patched-ber-audit-resp.XXXXXX") || {
        echo "ext_removal: WARN — could not create tmp file for audit response; pending batch ($_combined_count event(s)) left at $_pending_file for next run"
        rm -f "$_body_tmp"
        return 0
    }

    local -a _device_hdr; _device_hdr=()
    [[ -n "$HW_UUID" ]] && _device_hdr=(-H "X-Patched-Device-Id: ${HW_UUID}")

    _http_code=$(patched_curl_bearer "${BEARER_TOKEN}" -s -o "$_resp_tmp" -w "%{http_code}" \
        --max-time 30 \
        -X POST "${API_URL}/v1/inventory/enforcement-audit" \
        -H "X-Patched-Signature: ${_sig}" \
        -H "X-Patched-Timestamp: ${_ts}" \
        -H "X-Patched-Nonce: ${_nonce}" \
        "${_device_hdr[@]}" \
        -H "Content-Type: application/json" \
        --data-binary "@${_body_tmp}" \
        2>/dev/null) || _http_code=""

    rm -f "$_body_tmp"

    # PAT-1037: "confirmed" means 2xx AND a parseable {"ingested": <n>} body
    # with n EXACTLY equal to the size of the batch we sent — a bare 2xx
    # status code is not proof of ingestion (server-side precedent:
    # PAT-1011/PAT-1017). Exact equality, not merely "non-negative integer":
    # the server's dbIngestEnforcementAudit does one atomic multi-row INSERT
    # via unnest() (go-service/internal/handlers/enforcement_audit.go) — a
    # single INSERT statement has no partial-success path in Postgres, so a
    # genuine success is always all-rows-ingested, never a smaller count. A
    # mismatched count (bug, truncation, a different response body entirely)
    # must NOT be treated as confirmed, so it is exact-match, not `>= 0`.
    _ingested_ok=0
    case "$_http_code" in
        2*)
            _ingested_ok=$("$PYTHON3" -c '
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        body = json.load(f)
    n = body.get("ingested") if isinstance(body, dict) else None
    expected = int(sys.argv[2])
    print(1 if isinstance(n, int) and not isinstance(n, bool) and n == expected else 0)
except Exception:
    print(0)
' "$_resp_tmp" "$_combined_count" 2>/dev/null) || _ingested_ok=0
            ;;
    esac

    rm -f "$_resp_tmp"

    if (( _ingested_ok )); then
        echo "ext_removal: audit POST -> $_http_code, ingested confirmed ($_combined_count event(s)) — clearing pending batch"
        rm -f "$_pending_file"
    else
        # PAT-1037 (known, currently-unclosable gap — see module docstring):
        # the server has no idempotency key or dedup at the DB layer (a plain
        # INSERT, no ON CONFLICT); its only replay defense is X-Patched-Nonce,
        # which rejects a reused nonce with a bare 401 — indistinguishable
        # from a genuine auth failure (revoked token, suspended device, ...)
        # purely from the HTTP response. A 401 is therefore NOT treated as
        # "already delivered, safe to clear": it falls into this same
        # leave-it-pending branch as any other failure, so a real auth
        # failure can never silently drop an audit event. The cost is a
        # possible duplicate POST/INSERT on the next run if a 401 really was
        # a replay of an already-ingested batch. Closing that fully needs a
        # server-side idempotency key (out of scope here — different repo);
        # this fix only makes client-side loss impossible, not end-to-end
        # exactly-once delivery.
        case "$_http_code" in
            "") echo "ext_removal: audit POST -> network error or timeout; pending batch ($_combined_count event(s)) left at $_pending_file for next run" ;;
            2*) echo "ext_removal: audit POST -> $_http_code but response body did not confirm ingestion; pending batch ($_combined_count event(s)) left at $_pending_file for next run" ;;
            *)  echo "ext_removal: audit POST -> $_http_code (non-fatal); pending batch ($_combined_count event(s)) left at $_pending_file for next run" ;;
        esac
    fi

    return 0
}
