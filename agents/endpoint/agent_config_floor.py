#!/usr/bin/python3
"""agent_config_floor.py: the one parser for the agent-config anti-rollback floor.

PAT-1763. Before this module the macOS agent parsed the floor file in four
places that had to agree byte for byte: inline Python in patched-enroll.sh,
_agent_config_floor_state and _decommission_check in patched-fetch-config.sh,
and _read_rollback_floor in verify-agent-config.py. They now all call this
module, and endpoint/test-agent-config-floor.py drives every caller over the
same fixtures (endpoint/fixtures/agent-config-floor.json), whose expectations
were recorded from the four copies before they were removed.

Floor file format (PAT-1756), one line of JSON with exactly two members:

  {"tenant_id":"<tenant id>","config_version":<non-negative integer>}

A bare non-negative integer is the legacy pre-PAT-1756 format. Anything else
is corrupt. The Windows agent (AgentConfigRollbackFloor.cs) reads and writes
the same format.

Shipped in the endpoint bundle and covered by manifest.sha256 like every other
bundle file. It is loaded by path, never through sys.path, and never writes a
bytecode cache next to itself.

Command line (used by the shell callers, one line on stdout, exit 0):

  agent_config_floor.py enrol-state <floor-file> <tenant-id>
      absent | unreadable <OSError name> | legacy | corrupt
      | same_tenant | other_tenant
  agent_config_floor.py fetch-state <floor-file> <tenant-id>
      absent | applies <version> | legacy <version> | other_tenant | corrupt

Any other invocation exits 2 and prints nothing to stdout, which every caller
already treats as an unusable reader.
"""

import json
import sys

MAX_FLOOR_BYTES = 4096
TENANT_KEY = "tenant_id"
VERSION_KEY = "config_version"


def reject_ambiguous_json_keys(pairs):
    """Build a JSON object only when no member name repeats, ignoring case."""
    result = {}
    seen = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError(f"duplicate or case-colliding JSON key: {key!r}")
        seen.add(folded)
        result[key] = value
    return result


def parse_floor_bytes(raw):
    """Classify the bytes of a floor file.

    Returns one of:
      ("legacy", None, version)     pre-PAT-1756 bare integer
      ("keyed", tenant_id, version) the current format
      ("corrupt", None, problem)    anything else
    Never raises.
    """
    if len(raw) > MAX_FLOOR_BYTES:
        return ("corrupt", None, f"file is larger than {MAX_FLOOR_BYTES} bytes")
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return ("corrupt", None, "file is not valid UTF-8")
    if not text:
        return ("corrupt", None, "file is empty")
    if text.isascii() and text.isdigit():
        return ("legacy", None, int(text))
    if not text.startswith("{"):
        return ("corrupt", None, "file is neither a keyed floor nor a legacy integer")
    try:
        floor = json.loads(text, object_pairs_hook=reject_ambiguous_json_keys)
    except Exception:
        return ("corrupt", None, "floor is not valid JSON")
    if not isinstance(floor, dict) or set(floor) != {TENANT_KEY, VERSION_KEY}:
        return ("corrupt", None,
                "floor must hold exactly a non-empty tenant_id and a config_version")
    tenant = floor[TENANT_KEY]
    version = floor[VERSION_KEY]
    if not isinstance(tenant, str) or not tenant.strip():
        return ("corrupt", None, "tenant_id is not a non-empty string")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        return ("corrupt", None, "config_version is not a non-negative integer")
    return ("keyed", tenant, version)


def read_floor(path):
    """Read and classify the floor file at path.

    Returns ("absent", None, 0), ("unreadable", None, <OSError class name>) or
    one of the parse_floor_bytes results. Never raises for a missing or
    unreadable file. Callers decide what "unreadable" means: enrolment keeps
    such a file, every acceptance decision treats it as corrupt.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FLOOR_BYTES + 1)
    except FileNotFoundError:
        return ("absent", None, 0)
    except OSError as exc:
        return ("unreadable", None, type(exc).__name__)
    return parse_floor_bytes(raw)


def floor_for_tenant(floor, tenant_id):
    """Return (last_version, description) of a floor that is neither corrupt
    nor unreadable, for tenant_id.

    tenant_id must be the tenant every caller then requires the signed payload
    to be bound to. A legacy floor is the enrolled tenant's. A keyed floor for
    another tenant contributes nothing (0).
    """
    kind, floor_tenant, value = floor
    if kind == "absent":
        return 0, f"no stored floor for tenant {tenant_id}"
    if kind == "legacy":
        return value, (f"legacy floor {value}, applied to the enrolled tenant "
                       f"{tenant_id}")
    if floor_tenant == tenant_id:
        return value, f"floor {value} for tenant {tenant_id}"
    return 0, (f"stored floor belongs to tenant {floor_tenant} (version {value}), "
               f"so tenant {tenant_id} starts a fresh floor")


def recorded_version_for_tenant(floor, tenant_id):
    """The floor that vouches for an already committed config of tenant_id, or
    None. Used at the decommission point of action: only a legacy floor or a
    floor keyed to tenant_id counts; absent, unreadable, corrupt and
    other-tenant floors vouch for nothing."""
    kind, floor_tenant, value = floor
    if kind == "legacy":
        return value
    if kind == "keyed" and floor_tenant == tenant_id:
        return value
    return None


def enrol_state(floor, tenant_id):
    """patched-enroll.sh's classification (see the module docstring)."""
    kind, floor_tenant, value = floor
    if kind == "absent":
        return "absent"
    if kind == "unreadable":
        return f"unreadable {value}"
    if kind == "legacy":
        return "legacy"
    if kind == "corrupt":
        return "corrupt"
    return "same_tenant" if floor_tenant == tenant_id else "other_tenant"


def fetch_state(floor, tenant_id):
    """patched-fetch-config.sh's classification (see the module docstring)."""
    kind, floor_tenant, value = floor
    if kind == "absent":
        return "absent"
    if kind in ("unreadable", "corrupt"):
        return "corrupt"
    if kind == "legacy":
        return f"legacy {value}"
    return f"applies {value}" if floor_tenant == tenant_id else "other_tenant"


_COMMANDS = {"enrol-state": enrol_state, "fetch-state": fetch_state}


def main(argv):
    if len(argv) != 4 or argv[1] not in _COMMANDS:
        print("usage: agent_config_floor.py {enrol-state|fetch-state} <floor-file> <tenant-id>",
              file=sys.stderr)
        return 2
    command, floor_path, tenant_id = argv[1], argv[2], argv[3]
    print(_COMMANDS[command](read_floor(floor_path), tenant_id))
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main(sys.argv))
