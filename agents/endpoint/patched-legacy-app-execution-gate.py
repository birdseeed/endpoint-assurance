#!/usr/bin/python3
"""Fail-closed permission check for quarantined legacy macOS executors.

Every caller invokes this immediately before a state-changing seam. It opens
the root-owned state and credential directories without following symlinks,
reads the verified config exactly once through directory-relative file
descriptors, hashes and parses those same immutable bytes, and rejects stale
verification or any suspension marker before and after the read. A config that
does not belong to the enrolled tenant (agent_config_tenant.py, PAT-1773) is
treated as no config and denies. The helper is
itself covered by the release manifest and callers verify that coverage before
executing it as root.
"""

import hashlib
import importlib.util
import json
import os
import stat
import sys
import time


# This is the one implementation authority for the macOS legacy-execution
# verification window. Documentation calls it 24 hours; tests exercise its
# boundary, but must not become another runtime authority.
CONFIG_HEARTBEAT_MAX_AGE_SECONDS = 24 * 60 * 60
# The signed inner config is small. Bound the local LaunchDaemon's read before
# decoding JSON so a damaged cache cannot turn every executor invocation into
# an unbounded allocation.
MAX_CONFIG_BYTES = 1024 * 1024


EXPECTED_STATE_FILES = {
    "agent-config.json",
    "agent-config.sha256",
    "agent-config.checked",
}
EXECUTION_DENIAL_FILENAME = "agent-config.execution-denied"
# PAT-1773: the enrolled tenant, read from the credentials directory the
# suspension marker lives in, and the shared module that decides whether the
# cached config belongs to it. Callers require the module's manifest coverage
# before executing this helper, exactly as they do for the helper itself.
TENANT_ID_FILENAME = "tenant-id"
TENANT_MODULE_FILENAME = "agent_config_tenant.py"


def _root_owned_nonwritable(metadata: os.stat_result) -> bool:
    return metadata.st_uid == 0 and not (metadata.st_mode & 0o022)


def _open_secure_directory(directory: str) -> int:
    """Open one root-owned directory without following its final component."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(directory, flags)
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode) or not _root_owned_nonwritable(metadata):
        os.close(directory_fd)
        raise PermissionError("insecure directory boundary")
    return directory_fd


def _open_secure_file(directory_fd: int, filename: str) -> tuple[int, os.stat_result]:
    """Open one root-owned regular file relative to a trusted directory fd."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_fd = os.open(filename, flags, dir_fd=directory_fd)
    metadata = os.fstat(file_fd)
    if not stat.S_ISREG(metadata.st_mode) or not _root_owned_nonwritable(metadata):
        os.close(file_fd)
        raise PermissionError("insecure cache file")
    return file_fd, metadata


def _read_bounded(file_fd: int, maximum: int) -> bytes:
    """Read at most maximum + 1 bytes from an already-validated descriptor."""
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(file_fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _entry_exists(directory_fd: int, filename: str) -> bool:
    """Treat every directory entry, including a dangling symlink, as present."""
    try:
        os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _path_still_names_open_file(
    directory_fd: int, filename: str, opened_metadata: os.stat_result
) -> bool:
    """Require the live directory entry to remain the fresh file we opened."""
    try:
        current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and _root_owned_nonwritable(current)
        and current.st_dev == opened_metadata.st_dev
        and current.st_ino == opened_metadata.st_ino
        and current.st_mtime == opened_metadata.st_mtime
    )


def _load_tenant_module():
    """Load agent_config_tenant.py from this helper's own directory (PAT-1773).

    Loaded by path rather than through sys.path, so nothing earlier on the
    import path can stand in for it, and without writing a bytecode cache into
    the root-owned bundle directory. A missing or broken module raises, which
    denies.
    """
    module_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TENANT_MODULE_FILENAME
    )
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(
            "patched_agent_config_tenant", module_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    seen: set[str] = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError(f"duplicate or case-colliding JSON key: {key}")
        seen.add(folded)
        result[key] = value
    return result


def main() -> int:
    if len(sys.argv) != 5:
        return 1

    config_path, digest_path, heartbeat_path, suspended_path = sys.argv[1:]
    open_fds: list[int] = []
    try:
        state_paths = (config_path, digest_path, heartbeat_path)
        state_directories = {os.path.abspath(os.path.dirname(path)) for path in state_paths}
        state_filenames = {os.path.basename(path) for path in state_paths}
        if len(state_directories) != 1 or state_filenames != EXPECTED_STATE_FILES:
            return 1
        if os.path.basename(suspended_path) != "suspended":
            return 1

        state_fd = _open_secure_directory(state_directories.pop())
        open_fds.append(state_fd)
        credentials_fd = _open_secure_directory(os.path.abspath(os.path.dirname(suspended_path)))
        open_fds.append(credentials_fd)

        # This marker is written only when the manifest-covered config verifier
        # authenticated a newer tenant policy that revoked execution authority
        # but rejected the rest of that policy. Any entry, including a dangling
        # symlink, denies. It deliberately outranks the diagnostic last-good
        # config and its still-valid hash.
        if _entry_exists(state_fd, EXECUTION_DENIAL_FILENAME):
            return 1

        # The marker is a revocation signal, so every directory entry at this
        # name, including a dangling symlink, denies.
        if _entry_exists(credentials_fd, "suspended"):
            return 1

        config_fd, _ = _open_secure_file(state_fd, "agent-config.json")
        digest_fd, _ = _open_secure_file(state_fd, "agent-config.sha256")
        heartbeat_fd, heartbeat_metadata = _open_secure_file(
            state_fd, "agent-config.checked"
        )
        open_fds.extend((config_fd, digest_fd, heartbeat_fd))

        age = time.time() - heartbeat_metadata.st_mtime
        if age < 0 or age > CONFIG_HEARTBEAT_MAX_AGE_SECONDS:
            return 1

        digest_snapshot = _read_bounded(digest_fd, 128)
        if len(digest_snapshot) > 128:
            return 1
        recorded = digest_snapshot.decode("ascii").strip()
        if len(recorded) != 64 or any(char not in "0123456789abcdefABCDEF" for char in recorded):
            return 1

        snapshot = _read_bounded(config_fd, MAX_CONFIG_BYTES)
        if len(snapshot) > MAX_CONFIG_BYTES:
            return 1
        if hashlib.sha256(snapshot).hexdigest().lower() != recorded.lower():
            return 1
        config = json.loads(snapshot.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(config, dict):
            return 1
        # PAT-1773: a cached config that does not belong to the enrolled tenant
        # is treated as no config, which denies. PAT-1814: the config snapshot
        # above and the tenant-id read below are two separate, non-atomic
        # reads with no lock between them — reading tenant-id second only
        # orders the two reads, it does not make them one atomic snapshot.
        # That ordering is still the safe direction: a re-enrolment landing in
        # the gap between them is classified using the freshly-read tenant-id
        # against the config bytes already captured above (now stale for that
        # tenant), which classify_config treats as a mismatch and denies. This
        # avoids the opposite, unsafe failure mode — validating a freshly
        # re-enrolled config against a stale tenant-id — but it is not a
        # guarantee that no race exists.
        tenant_module = _load_tenant_module()
        tenant_fd, _ = _open_secure_file(credentials_fd, TENANT_ID_FILENAME)
        open_fds.append(tenant_fd)
        tenant_snapshot = _read_bounded(tenant_fd, tenant_module.MAX_TENANT_ID_BYTES)
        enrolled_tenant = tenant_module.enrolled_tenant_from_bytes(tenant_snapshot)
        tenant_state, _ = tenant_module.classify_config(config, enrolled_tenant)
        if tenant_state != tenant_module.APPLIES:
            return 1
        if type(config.get("legacy_app_execution_enabled")) is not bool or not config["legacy_app_execution_enabled"]:
            return 1
        # Recheck every revocation/freshness path after the potentially lengthy
        # bounded read and parse, immediately before allowing the caller to act.
        # A denial marker published during those reads outranks the snapshot, and
        # an unlinked/replaced/touched heartbeat cannot lend its old descriptor's
        # freshness to the current path.
        if _entry_exists(state_fd, EXECUTION_DENIAL_FILENAME):
            return 1
        if _entry_exists(credentials_fd, "suspended"):
            return 1
        if not _path_still_names_open_file(
            state_fd, "agent-config.checked", heartbeat_metadata
        ):
            return 1
        return 0
    except Exception:
        return 1
    finally:
        for file_fd in reversed(open_fds):
            try:
                os.close(file_fd)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
