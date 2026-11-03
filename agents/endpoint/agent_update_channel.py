#!/usr/bin/python3
"""Pinned, tenant-bound self-update policy. Never use hardware UUIDs as keys.

The original envelope is retained and reverified on each process/restart. Its
verified version is a durable update-policy floor in addition to config-poll's
floor. A corrupt existing cache is no opinion, never an empty floor.
"""
import argparse
import base64
import datetime
import fcntl
import importlib.util
import json
import os
import stat
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("patched_config_verifier", os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify-agent-config.py"))
_VERIFY = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_VERIFY)
MAX_BYTES = 4 * 1024 * 1024
DEFAULT = {"effective_channel": "stable", "source": None, "pinned_version": None, "config_version": None}


def canonical_uuid(value):
    try:
        parsed = uuid.UUID(value)
        return str(parsed) if parsed.int and len(value) == 36 else None
    except (ValueError, TypeError, AttributeError):
        return None


def decode_verified(envelope):
    if not isinstance(envelope, dict) or envelope.get("key_id") != _VERIFY._PINNED_KEY_ID:
        raise ValueError("invalid envelope")
    raw = base64.b64decode(envelope["signed_payload"], validate=True)
    if not _VERIFY.ed25519_verify(_VERIFY._PINNED_PUBKEY_B64, raw, envelope["signature"]):
        raise ValueError("invalid signature")
    config = json.loads(raw, object_pairs_hook=_VERIFY._reject_ambiguous_json_keys)
    if not isinstance(config, dict) or type(config.get("config_version")) is not int or config["config_version"] < 0:
        raise ValueError("invalid config")
    return config


def resolve(config, tenant_id, device_id, verified=False):
    if not verified or not tenant_id or config.get("tenant_id") != tenant_id:
        return DEFAULT.copy()
    channel = config.get("update_channel")
    channel = channel if channel in ("beta", "stable") else "stable"
    source = "tenant"
    own = canonical_uuid(device_id)
    if "device_id" in config and config["device_id"] is not None:
        if not own or canonical_uuid(config["device_id"]) != own:
            return DEFAULT.copy()
        source = config.get("update_channel_source")
        source = source if source in ("tenant", "device_override") else None
        if source == "device_override" and channel != "beta":
            return DEFAULT.copy()
    elif own and isinstance(config.get("device_channel_overrides"), dict):
        entries = [value for key, value in config["device_channel_overrides"].items() if canonical_uuid(key) == own]
        if len(entries) == 1 and entries[0] == "beta":
            channel, source = "beta", "device_override"
    pin = config.get("pinned_version")
    pin = pin if isinstance(pin, str) and 0 < len(pin) <= 100 and "\x00" not in pin else None
    return {"effective_channel": channel, "source": source, "pinned_version": pin, "config_version": config.get("config_version")}


def read_json(path):
    with open(path, "rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("oversized state")
    return json.loads(raw, object_pairs_hook=_VERIFY._reject_ambiguous_json_keys)


def read_identity(path):
    try:
        with open(path, "rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return ""
        return raw.split(b"\n", 1)[0].decode("utf-8").strip()
    except (OSError, UnicodeError):
        return ""


def check_directory(directory):
    # Root-owned non-writable chain, no symlinks. Do not repair hostile state.
    current = os.path.abspath(directory)
    while True:
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted state directory")
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent


def check_state_file(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("untrusted state file")


def atomic_json(path, value):
    fd, temp = tempfile.mkstemp(prefix=".update-channel.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def policy_from_state(state, tenant, device, floor):
    if state.get("tenant_id") != tenant or state.get("device_id") != canonical_uuid(device):
        raise ValueError("selection identity changed")
    config = decode_verified(state["envelope"])
    if config.get("tenant_id") != tenant or config["config_version"] < floor:
        raise ValueError("cached scope or floor mismatch")
    return config, resolve(config, tenant, device, verified=True)


def select(response, cached, tenant, device, floor):
    previous = None
    if cached is not None:
        # Verify even another tenant's cache before treating it as a fresh scope.
        old_config = decode_verified(cached["envelope"])
        if old_config.get("tenant_id") == tenant:
            floor = max(floor, old_config["config_version"])
            previous = cached["envelope"]
    envelope = previous
    if response is not None:
        try:
            config = decode_verified(response)
            if config.get("tenant_id") != tenant or config["config_version"] < floor:
                raise ValueError("scope or rollback")
            envelope = response
        except (ValueError, KeyError, TypeError):
            pass  # last verified authority, never unverified response fields
    if envelope is None:
        return DEFAULT.copy(), None
    config = decode_verified(envelope)
    if config["config_version"] < floor:
        return DEFAULT.copy(), None
    policy = resolve(config, tenant, device, verified=True)
    state = {"envelope": envelope, "tenant_id": tenant, "device_id": canonical_uuid(device),
             "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    return policy, state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("select", "health"))
    parser.add_argument("--cache", required=True)
    parser.add_argument("--tenant-file", required=True)
    parser.add_argument("--device-file", required=True)
    parser.add_argument("--floor-file", required=True)
    args = parser.parse_args()
    try:
        tenant, device = read_identity(args.tenant_file), read_identity(args.device_file)
        if not tenant:
            raise ValueError("no enrolled tenant")
        floor = _VERIFY._FLOOR.read_floor(args.floor_file)
        if floor[0] in ("corrupt", "unreadable"):
            raise ValueError("invalid rollback floor")
        floor_version, _ = _VERIFY._FLOOR.floor_for_tenant(floor, tenant)
        check_directory(os.path.dirname(args.cache))
        if os.path.lexists(args.cache):
            check_state_file(args.cache)
        if args.mode == "health":
            state = read_json(args.cache)
            _, policy = policy_from_state(state, tenant, device, floor_version)
            if policy["config_version"] is None:
                raise ValueError("no verified decision")
            observed = datetime.datetime.fromisoformat(state["observed_at"])
            if observed.tzinfo is None or observed > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
                raise ValueError("invalid selection time")
            policy.pop("pinned_version")
            policy["observed_at"] = state["observed_at"]
            print(json.dumps(policy, separators=(",", ":")))
            return
        lock_path = args.cache + ".lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            cached = read_json(args.cache) if os.path.lexists(args.cache) else None
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            try:
                response = json.loads(raw, object_pairs_hook=_VERIFY._reject_ambiguous_json_keys) if len(raw) <= MAX_BYTES and raw else None
            except (ValueError, UnicodeError):
                response = None
            policy, state = select(response, cached, tenant, device, floor_version)
            if state is not None:
                atomic_json(args.cache, state)
            print(json.dumps(policy, separators=(",", ":")))
    except Exception:
        # No rejected payload, signature, credential or arbitrary exception text in logs.
        print("update-channel: verified authority unavailable", file=sys.stderr)
        if args.mode == "select":
            print(json.dumps(DEFAULT, separators=(",", ":")))
        else:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
