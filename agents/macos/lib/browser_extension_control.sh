# browser_extension_control.sh — Browser Extension Control: managed-policy
# blocklist enforcement for Chrome, Edge and Firefox (PAT-828, part of PAT-773).
#
# Sourced by patched-upload.sh; not executable directly.
#
# Requires (set by caller before sourcing):
#   PYTHON3      — absolute path to python3 (/usr/bin/python3)
#   API_URL      — base URL, e.g. https://api.patched.im
#   BEARER_TOKEN — opaque bearer credential
#   CREDS_DIR    — /etc/patched (for hmac-secret)
#   HW_UUID      — device UUID (may be empty; forwarded as X-Patched-Device-Id)
#   PATCHED_TMPDIR — root-owned 0700 scratch dir
#
# The compute_hmac and patched_curl_bearer helpers must be in scope; the caller
# (patched-upload.sh) defines them inline and sources this module afterwards.
# The authenticated audit POST goes through patched_curl_bearer so the bearer
# token reaches curl over stdin, never on argv (PAT-881).
#
# Policy source: the signed agent-config's app_control block, same file
# ac_enforce_admins / ac_check_app_violations read. This function consumes a new
# field, app_control.extension_blocklist — a list of {browser, extension_id}
# objects the tenant has marked "unapproved" (populated server-side from the
# PAT-826 tenant_extension_policies store). Empty/missing = no-op (fail-safe:
# the agent never blocks anything the config didn't explicitly list).
#
# Mechanism (all device-global, so a single push covers every user + profile —
# this is what satisfies the multi-user/multi-profile acceptance criterion):
#   - Chrome / Edge: ExtensionInstallBlocklist array in the computer-level
#     preference domain (/Library/Preferences/<domain>.plist), which Chromium
#     reads as mandatory managed policy.
#   - Firefox: ExtensionSettings installation_mode=blocked in the app bundle's
#     distribution/policies.json (Firefox's enterprise-policy file), merged so
#     any pre-existing policy keys are preserved.
#
# A sidecar state file records exactly which IDs we manage per browser so a
# later reconcile removes only our own entries — never a third party's policy.
#
# Every push (or clear) posts one enforcement_audit event per browser to
# /v1/inventory/enforcement-audit (PAT-603), reusing the generic ingest path.
#
# Environment overrides:
#   PATCHED_DRY_RUN=1          — log what would happen; skip writes and POST
#   PATCHED_AC_CONFIG          — override agent-config path (for testing)
#   PATCHED_BEC_PREFS_DIR      — override /Library/Preferences (for testing)
#   PATCHED_BEC_FIREFOX_APP    — override /Applications/Firefox.app (for testing)
#   PATCHED_BEC_STATE_FILE     — override the sidecar state path (for testing)
#
# Arguments:
#   $1  actuation_allowed (PAT-1038 follow-up) — "0" or "1", default "1" so
#       existing callers/tests are unaffected. The caller's local Tier gate
#       (patched-upload.sh: AC_BLOCKLIST_AUTHORITY_ALLOWED, 'block' or 'enforce').
#       When "0", desired state is forced to empty regardless of the config's
#       app_control.extension_blocklist content — this still runs the full
#       reconcile-and-apply below, so any blocklist policy already pushed
#       while the tenant WAS actuating is torn down, not left in place. A
#       below-tier client must not merely stop adding NEW entries; leaving
#       stale entries in place is itself still actuating enforcement. Mirrors
#       windows/src/Service/BrowserExtensionBlocklistEnforcer.Enforce's
#       actuationAllowed parameter.

bec_enforce_extension_blocklist() {
    local _actuation_allowed="${1:-1}"
    local _config_file _dry_run _prefs_dir _firefox_app _state_file
    local _occurred_at _events_json _event_count
    local _body_tmp _sig _ts _nonce _http_code

    _config_file="${PATCHED_AC_CONFIG:-/Library/Application Support/Patched/agent-config.json}"
    _prefs_dir="${PATCHED_BEC_PREFS_DIR:-/Library/Preferences}"
    _firefox_app="${PATCHED_BEC_FIREFOX_APP:-/Applications/Firefox.app}"
    _state_file="${PATCHED_BEC_STATE_FILE:-/Library/Application Support/Patched/extension-blocklist-state.json}"
    _dry_run=0
    [[ "${PATCHED_DRY_RUN:-0}" == "1" ]] && _dry_run=1

    # ── 1. Verify agent-config exists ──────────────────────────────────────────
    if [[ ! -f "$_config_file" ]]; then
        echo "ext_blocklist: no agent-config at $_config_file — skipping"
        return 0
    fi

    if [[ "$_actuation_allowed" != "1" ]]; then
        echo "ext_blocklist: tier gate disallows actuation — reconciling to empty (rolling back any previously-pushed policy, not adding any new entries)"
    fi

    _occurred_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # ── 2. Reconcile managed policy for every browser (Python does the work) ───
    # Python reads app_control.{enabled,extension_blocklist} from the config,
    # groups blocked IDs by browser, writes/clears each browser's managed policy
    # to match, updates the sidecar state, and prints one audit event per browser
    # it actually changed. In dry-run it performs no writes but still prints the
    # events it would push (dry_run=true). Any internal error → "[]" (fail-safe).
    # When actuation is disallowed, desired state is forced empty (see
    # desired_by_browser below) so this same reconcile tears down stale policy
    # instead of being skipped.
    _events_json=$("$PYTHON3" - \
        "$_config_file" "$_state_file" "$_prefs_dir" "$_firefox_app" \
        "$_dry_run" "$_occurred_at" "$_actuation_allowed" <<'PYEOF'
import json, os, stat, subprocess, sys

config_file, state_file, prefs_dir, firefox_app, dry_run_s, occurred_at, actuation_allowed_s = sys.argv[1:8]
dry_run = (dry_run_s == "1")
actuation_allowed = (actuation_allowed_s == "1")

# Chromium bundle-id preference domains keyed by the config's browser name.
CHROMIUM_DOMAINS = {
    "chrome": "com.google.Chrome",
    "edge":   "com.microsoft.Edge",
}
BLOCKLIST_KEY = "ExtensionInstallBlocklist"

# PAT-1043: fd-anchored, symlink-refusing helpers for the Firefox policy
# write and the sidecar state write. Same idiom browser_extension_removal.sh
# uses for its deletes (open_chain / _open_dir_nofollow / atomic_write_at),
# mirrored here rather than reinvented so the codebase has one hardening
# pattern, not two.
_O_NOFOLLOW_DIR = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)

# This process runs as root in production (the upload daemon). Checking
# ownership against os.geteuid() rather than a hardcoded 0 asserts the same
# thing there (root), while staying meaningful and testable without sudo
# under a test harness that runs as a normal user: the check becomes "does a
# user other than whoever is running this process control the directory",
# which is the actual property we care about in both cases.
_TRUSTED_UID = os.geteuid()


def _owner_locked_down(st):
    """True if `st` describes a real directory owned by the user running this
    process and not writable by group or other. A directory failing this is
    one some other user could rewrite: that means both that a symlink could
    be planted in it, and that any policy enforced into it is not actually
    trustworthy, since that same user could just undo it again."""
    return (stat.S_ISDIR(st.st_mode) and st.st_uid == _TRUSTED_UID
            and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)))


def _open_dir_nofollow(dir_fd, name, describe=None):
    """openat(name, O_NOFOLLOW|O_DIRECTORY) relative to dir_fd. Returns a new
    dir fd (caller closes) or None. A symlink, a non-directory, or a missing
    entry all return None; fail closed. When `describe` is set, a symlink is
    logged as an explicit refusal (that is the attack we are defeating)."""
    if describe is not None:
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                sys.stderr.write(f"ext_blocklist: REFUSING symlinked {describe}: {name}\n")
                return None
        except OSError:
            return None
    try:
        return os.open(name, _O_NOFOLLOW_DIR, dir_fd=dir_fd)
    except OSError:
        return None


def _open_dir_nofollow_or_create(dir_fd, name, describe=None):
    """Like _open_dir_nofollow, but creates `name` (mode 0755) if nothing is
    there yet. A pre-existing non-directory (symlink included) is refused,
    never replaced. The create is check-then-mkdir; a FileExistsError from a
    race is treated the same as "already there" and re-checked by the
    O_NOFOLLOW open that follows, so a symlink raced in during the gap is
    still refused, not followed."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        st = None
    if st is not None and not stat.S_ISDIR(st.st_mode):
        if describe is not None:
            sys.stderr.write(f"ext_blocklist: REFUSING symlinked {describe}: {name}\n")
        return None
    if st is None:
        try:
            os.mkdir(name, 0o755, dir_fd=dir_fd)
        except FileExistsError:
            pass
        except OSError:
            return None
    return _open_dir_nofollow(dir_fd, name)


def _load_json_fd(dir_fd, name):
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


def _atomic_create_json_at(dir_fd, name, obj, log_prefix):
    """Write JSON `obj` to `name` in `dir_fd`, atomically, without ever
    opening through a symlink or a re-resolved path.

    PAT-1043: the temp name is unpredictable (os.urandom) and opened with
    O_CREAT|O_EXCL|O_NOFOLLOW, so an attacker cannot pre-plant it. O_EXCL
    makes any pre-existing entry (symlink or otherwise) a hard error instead
    of something we write through, and there is nothing to guess since the
    name isn't derived from `name`. Unlike a retry-with-a-new-name loop, a
    failure here is reported and left alone: a name collision that isn't
    astronomically unlikely bad luck means something is already wrong with
    this directory, and retrying papers over that instead of surfacing it.
    The final os.stat (via dir_fd, not a path) confirms what we hold really
    is the regular file we just created before we write into it, and the
    rename is dir_fd-relative on both ends so the destination name is never
    resolved by string a second time either."""
    tmp = ".patched-%s.tmp" % os.urandom(8).hex()
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(tmp, flags, 0o644, dir_fd=dir_fd)
    except OSError as ex:
        sys.stderr.write(f"{log_prefix}: refusing write, could not create temp file: {ex}\n")
        return False

    try:
        st = os.stat(tmp, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as ex:
        sys.stderr.write(f"{log_prefix}: refusing write, could not verify temp file: {ex}\n")
        os.close(fd)
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        sys.stderr.write(f"{log_prefix}: refusing write, temp file is not the regular file just created\n")
        os.close(fd)
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        return False

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return True
    except Exception as ex:
        sys.stderr.write(f"{log_prefix}: write failed: {ex}\n")
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        return False


def load_json(path):
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


def desired_by_browser(cfg, actuation_allowed):
    """Return {browser: sorted-unique-ids} from app_control.extension_blocklist.

    Empty dict if app_control is disabled or the blocklist is absent/empty —
    the fail-safe path (agent enforces nothing the config didn't list).

    PAT-1038 follow-up: also empty, unconditionally, when actuation_allowed is
    False (the caller's Tier gate disallows the blocklist at this tenant's
    current tier) — regardless of what the config says. The reconcile in
    main() below then diffs this empty desired state against whatever was
    previously pushed and tears it down, rather than the caller skipping this
    function entirely and stranding it."""
    if not actuation_allowed:
        return {}
    ac = cfg.get("app_control") if isinstance(cfg, dict) else None
    if not isinstance(ac, dict) or not ac.get("enabled"):
        return {}
    entries = ac.get("extension_blocklist")
    if not isinstance(entries, list):
        return {}
    grouped = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        browser = e.get("browser")
        ext_id = e.get("extension_id")
        if not isinstance(browser, str) or not isinstance(ext_id, str):
            continue
        browser = browser.strip().lower()
        ext_id = ext_id.strip()
        if not browser or not ext_id:
            continue
        grouped.setdefault(browser, set()).add(ext_id)
    return {b: sorted(ids) for b, ids in grouped.items()}


def enforce_chromium(browser, domain, desired_ids, prev_ids, events):
    plist_path = os.path.join(prefs_dir, domain)  # `defaults` appends .plist
    changed = (set(desired_ids) != set(prev_ids))
    if not changed:
        return prev_ids  # already in the intended state

    if not dry_run:
        try:
            if desired_ids:
                subprocess.run(
                    ["/usr/bin/defaults", "write", plist_path, BLOCKLIST_KEY,
                     "-array", *desired_ids],
                    check=True, capture_output=True, timeout=30)
            else:
                # Clear only our key; leave any other managed keys intact.
                subprocess.run(
                    ["/usr/bin/defaults", "delete", plist_path, BLOCKLIST_KEY],
                    check=False, capture_output=True, timeout=30)
        except Exception as ex:
            sys.stderr.write(f"ext_blocklist: {browser} write failed: {ex}\n")
            return prev_ids  # leave state untouched so we retry next tick

    events.append({
        "event_type": "extension_blocklist_pushed",
        "subject": browser,
        "details": {
            "browser": browser,
            "mechanism": "chromium_managed_prefs",
            "policy_key": BLOCKLIST_KEY,
            "policy_path": plist_path + ".plist",
            "action": "set" if desired_ids else "cleared",
            "blocked_count": len(desired_ids),
            "extension_ids": desired_ids,
            "dry_run": dry_run,
        },
        "occurred_at": occurred_at,
    })
    return desired_ids


def enforce_firefox(desired_ids, prev_ids, events):
    # Firefox reads its enterprise policy from a file *inside* the app bundle, so
    # there's nothing to write unless Firefox is installed. If it isn't, drop any
    # stale managed state (the bundle — and our policies.json — are gone with it)
    # so a later reinstall re-applies the blocklist from scratch. Returning the
    # desired set here instead would wedge enforcement: `changed` would read false
    # forever and the policy would never actually be written once Firefox appears.
    if not os.path.isdir(firefox_app):
        return []
    changed = (set(desired_ids) != set(prev_ids))
    if not changed:
        return prev_ids

    dist_dir = os.path.join(firefox_app, "Contents", "Resources", "distribution")
    resources_dir = os.path.join(firefox_app, "Contents", "Resources")
    policies_path = os.path.join(dist_dir, "policies.json")

    # PAT-1043 (follow-up, non-author review): the bundle itself is now the
    # first fd in the chain, not a path resolved before the chain starts. The
    # original fix anchored Contents/Resources/distribution to a bundle_fd,
    # but that bundle_fd came from a plain os.open(firefox_app, O_DIRECTORY)
    # issued *after* an os.lstat ownership check on the path -- two separate
    # operations on a path, not one on a handle, in the one admin-writable
    # directory (/Applications) an attacker can most easily win a race
    # against. Opening with O_NOFOLLOW here makes a symlinked bundle a hard
    # open() failure instead of something a swap-after-check can redirect,
    # and ownership is verified with os.fstat on the fd we are actually going
    # to use, never os.lstat on a path we open again later. This single
    # anchored fd is reused for the read of any pre-existing policies.json
    # and, if not dry-run, the write below -- there is no second reopen of
    # the bundle path anywhere in this function.
    try:
        bundle_fd = os.open(firefox_app, _O_NOFOLLOW_DIR)
    except OSError as ex:
        sys.stderr.write(
            f"ext_blocklist: REFUSING symlinked or unopenable Firefox bundle: {firefox_app}: {ex}\n"
        )
        return prev_ids

    try:
        if not _owner_locked_down(os.fstat(bundle_fd)):
            sys.stderr.write(
                f"ext_blocklist: {firefox_app} is user-writable, refusing to enforce "
                "Firefox policy there. A managed policy cannot be trusted in a bundle "
                "the user can rewrite\n"
            )
            return prev_ids

        contents_fd = _open_dir_nofollow(bundle_fd, "Contents", describe="Contents directory")
        if contents_fd is None:
            sys.stderr.write(f"ext_blocklist: firefox bundle missing Contents: {firefox_app}\n")
            return prev_ids
        try:
            resources_fd = _open_dir_nofollow(contents_fd, "Resources", describe="Resources directory")
        finally:
            os.close(contents_fd)
        if resources_fd is None:
            sys.stderr.write(f"ext_blocklist: firefox bundle missing Resources: {firefox_app}\n")
            return prev_ids

        try:
            if not _owner_locked_down(os.fstat(resources_fd)):
                sys.stderr.write(
                    f"ext_blocklist: {resources_dir} is user-writable, refusing to "
                    "enforce Firefox policy there. A managed policy cannot be "
                    "trusted in a location the user can rewrite\n"
                )
                return prev_ids

            # Read whatever policy already exists, symlink-safe and anchored to
            # the same fd chain rather than a re-resolved string path. Missing
            # or symlinked distribution/policies.json just means "nothing to
            # merge with", not an error.
            existing = {}
            dist_fd_ro = _open_dir_nofollow(resources_fd, "distribution", describe="distribution directory")
            if dist_fd_ro is not None:
                try:
                    loaded = _load_json_fd(dist_fd_ro, "policies.json")
                    if isinstance(loaded, dict):
                        existing = loaded
                finally:
                    os.close(dist_fd_ro)

            policies = existing.get("policies")
            if not isinstance(policies, dict):
                policies = {}
            ext_settings = policies.get("ExtensionSettings")
            if not isinstance(ext_settings, dict):
                ext_settings = {}

            # Remove entries we previously managed that are no longer desired, but
            # only if they still carry exactly our managed shape -- never clobber a
            # richer policy an admin set for the same ID.
            for stale in set(prev_ids) - set(desired_ids):
                entry = ext_settings.get(stale)
                if isinstance(entry, dict) and entry.get("installation_mode") == "blocked" \
                        and set(entry.keys()) == {"installation_mode"}:
                    ext_settings.pop(stale, None)

            for ext_id in desired_ids:
                entry = ext_settings.get(ext_id)
                if not isinstance(entry, dict):
                    ext_settings[ext_id] = {"installation_mode": "blocked"}
                else:
                    entry["installation_mode"] = "blocked"

            if ext_settings:
                policies["ExtensionSettings"] = ext_settings
            else:
                policies.pop("ExtensionSettings", None)
            existing["policies"] = policies

            if not dry_run:
                dist_fd = _open_dir_nofollow_or_create(resources_fd, "distribution", describe="distribution directory")
                if dist_fd is None:
                    sys.stderr.write(
                        f"ext_blocklist: firefox write failed: {dist_dir} could not be "
                        "safely opened or created\n"
                    )
                    return prev_ids
                try:
                    # Re-verify ownership on the fd about to be written through:
                    # this is race-free, since it is the exact directory the
                    # write below uses, not a path resolved a second time.
                    dist_st = os.fstat(dist_fd)
                    if not _owner_locked_down(dist_st):
                        sys.stderr.write(
                            f"ext_blocklist: {dist_dir} is user-writable, refusing to enforce "
                            "Firefox policy there. A managed policy cannot be trusted in a "
                            "location the user can rewrite\n"
                        )
                        return prev_ids

                    if not _atomic_create_json_at(dist_fd, "policies.json", existing, "ext_blocklist"):
                        return prev_ids
                finally:
                    os.close(dist_fd)
        finally:
            os.close(resources_fd)
    finally:
        os.close(bundle_fd)

    events.append({
        "event_type": "extension_blocklist_pushed",
        "subject": "firefox",
        "details": {
            "browser": "firefox",
            "mechanism": "firefox_enterprise_policies",
            "policy_path": policies_path,
            "action": "set" if desired_ids else "cleared",
            "blocked_count": len(desired_ids),
            "extension_ids": desired_ids,
            "dry_run": dry_run,
        },
        "occurred_at": occurred_at,
    })
    return desired_ids


def main():
    cfg = load_json(config_file)
    if cfg is None:
        print("[]")
        return

    desired = desired_by_browser(cfg, actuation_allowed)

    prev_state = load_json(state_file)
    if not isinstance(prev_state, dict):
        prev_state = {}
    prev_browsers = prev_state.get("browsers")
    if not isinstance(prev_browsers, dict):
        prev_browsers = {}

    events = []
    new_browsers = {}

    # Union of browsers we've ever managed and browsers now desired, so a
    # blocklist that shrinks to empty still triggers a clear.
    all_browsers = set(CHROMIUM_DOMAINS) | {"firefox"}
    all_browsers |= set(desired) | set(prev_browsers)

    for browser in sorted(all_browsers):
        desired_ids = desired.get(browser, [])
        prev_ids = prev_browsers.get(browser, [])
        if not isinstance(prev_ids, list):
            prev_ids = []

        if browser in CHROMIUM_DOMAINS:
            resulting = enforce_chromium(
                browser, CHROMIUM_DOMAINS[browser], desired_ids, prev_ids, events)
        elif browser == "firefox":
            resulting = enforce_firefox(desired_ids, prev_ids, events)
        else:
            # Unknown browser name in the config — record desired so we don't
            # loop, but there's no mechanism to enforce it.
            resulting = desired_ids

        if resulting:
            new_browsers[browser] = list(resulting)

    # Persist reconciled state (unless dry-run, which must not mutate anything).
    # PAT-1043: same fd-anchored, unpredictable-temp-name write as the Firefox
    # policy above. state_file lives in the root-owned Patched state
    # directory rather than a third-party app bundle, so the exposure is
    # lower, but the old code had the identical predictable-temp-name /
    # follows-symlinks shape and there is no reason to leave one write path
    # hardened and its sibling not.
    if not dry_run:
        try:
            state_dir = os.path.dirname(state_file) or "."
            state_name = os.path.basename(state_file)
            os.makedirs(state_dir, exist_ok=True)
            state_dir_fd = os.open(
                state_dir, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        except OSError as ex:
            sys.stderr.write(f"ext_blocklist: state write failed: {ex}\n")
        else:
            try:
                _atomic_create_json_at(state_dir_fd, state_name, {"browsers": new_browsers}, "ext_blocklist")
            finally:
                os.close(state_dir_fd)

    print(json.dumps(events))


main()
PYEOF
    ) || _events_json="[]"

    _event_count=$("$PYTHON3" -c "
import json, sys
try:
    print(len(json.loads(sys.argv[1])))
except Exception:
    print(0)
" "$_events_json" 2>/dev/null) || _event_count=0

    if (( _event_count == 0 )); then
        echo "ext_blocklist: no policy change needed"
        return 0
    fi

    echo "ext_blocklist: reconciled managed policy for $_event_count browser(s)"

    if (( _dry_run )); then
        echo "ext_blocklist: DRY_RUN — would POST $_event_count audit event(s)"
        return 0
    fi

    # ── 3. POST audit events to /v1/inventory/enforcement-audit ────────────────
    _body_tmp=$(mktemp "$PATCHED_TMPDIR/patched-bec-audit.XXXXXX") || {
        echo "ext_blocklist: WARN — could not create tmp file for audit POST"
        return 0
    }

    printf '{"events":%s}' "$_events_json" > "$_body_tmp"

    _ts=$(date -u +%s)
    _nonce=$("$PYTHON3" -c 'import uuid; print(uuid.uuid4().hex)')
    _sig=$(compute_hmac "$_body_tmp" "enforcement_audit" "$_ts" "$_nonce") || {
        echo "ext_blocklist: WARN — hmac compute failed; skipping audit POST"
        rm -f "$_body_tmp"
        return 0
    }

    local -a _device_hdr; _device_hdr=()
    [[ -n "$HW_UUID" ]] && _device_hdr=(-H "X-Patched-Device-Id: ${HW_UUID}")

    _http_code=$(patched_curl_bearer "${BEARER_TOKEN}" -s -o /dev/null -w "%{http_code}" \
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

    case "$_http_code" in
        2*) echo "ext_blocklist: audit POST -> $_http_code (ok)" ;;
        "")  echo "ext_blocklist: audit POST -> network error or timeout" ;;
        *)   echo "ext_blocklist: audit POST -> $_http_code (non-fatal)" ;;
    esac

    return 0
}
