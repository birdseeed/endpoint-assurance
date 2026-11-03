# tcc-deny-hook.zsh — test support, sourced by test-mcp-servers.zsh,
# test-ide-extensions.zsh and test-package-managers.zsh (PAT-2100). Not a
# collector module and never bundled.
#
# Running as root without Full Disk Access, macOS privacy protection (TCC)
# lets a walk lstat another app's data folder but refuses open() with EPERM.
# A test-only sitecustomize.py does exactly that: os.open of a named path,
# reached relative to its parent as the shared walk reaches everything, raises
# the errno given. lstat is left alone, as TCC leaves it. The same hook
# test-browser-extensions.zsh [tcc] carries inline for PAT-2096.
#
# Needs WORK and REAL_PYTHON3 set by the caller. Provides:
#   deny_run <errno> <path ...>   run the caller's `run` with those opens denied
#   hook_fired                    1 when the last deny_run really denied an open
#   EPERM EACCES                  the errno numbers
#   AH_STORE, ah_true <expr>      the agent_health store the tests point at,
#                                 and a python test over its `active` and `ever`
#   store_absent                  1 when no store has been written

mkdir -p "$WORK/deny-hook"
cat > "$WORK/deny-hook/sitecustomize.py" <<'HOOKEOF'
import os

_targets = [t for t in os.environ.get("PATCHED_DENY_DIRS", "").split("\n") if t]
_errno = int(os.environ.get("PATCHED_DENY_ERRNO", "1"))
_open = os.open
_lstat = os.lstat
_hits = os.environ.get("PATCHED_DENY_HITS")


def _denied(path, dir_fd):
    if not isinstance(path, str) or dir_fd is None:
        return False
    for t in _targets:
        if path != os.path.basename(t):
            continue
        try:
            if os.fstat(dir_fd).st_ino == _lstat(os.path.dirname(t)).st_ino:
                return True
        except OSError:
            pass
    return False


def _hooked_open(path, flags, mode=0o777, *, dir_fd=None):
    if _denied(path, dir_fd):
        if _hits:
            with open(_hits, "a") as f:
                f.write(path + "\n")
        raise OSError(_errno, os.strerror(_errno))
    return _open(path, flags, mode, dir_fd=dir_fd)


if _targets:
    os.open = _hooked_open
HOOKEOF

deny_run() {
    local _e="$1"; shift
    : > "$WORK/deny-hits"
    export PYTHONPATH="$WORK/deny-hook" PATCHED_DENY_ERRNO="$_e" PATCHED_DENY_DIRS="${(F)@}" PATCHED_DENY_HITS="$WORK/deny-hits"
    run
    unset PYTHONPATH PATCHED_DENY_ERRNO PATCHED_DENY_DIRS PATCHED_DENY_HITS
}
hook_fired() { [[ -s "$WORK/deny-hits" ]] && echo 1 || echo 0; }

EPERM=$("$REAL_PYTHON3" -c 'import errno; print(errno.EPERM)')
EACCES=$("$REAL_PYTHON3" -c 'import errno; print(errno.EACCES)')

AH_STORE="$WORK/agent-health/.agent-health.json"
ah_py() {
    "$REAL_PYTHON3" -c 'import json,sys; d=json.load(open(sys.argv[1])); active=d["active"]; ever=d["ever_succeeded"]; print(eval(sys.argv[2]))' "$AH_STORE" "$1" 2>/dev/null
}
ah_true() { [[ "$(ah_py "$1")" == "True" ]] && echo 1 || echo 0; }
store_absent() { [[ ! -e "$AH_STORE" ]] && echo 1 || echo 0; }
