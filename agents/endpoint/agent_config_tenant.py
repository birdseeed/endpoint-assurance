#!/usr/bin/python3
"""agent_config_tenant.py: does the cached agent-config belong to the enrolled tenant?

PAT-1773. agent-config.json is not keyed by tenant. After a device is enrolled
into another tenant (an assessment tenant moving to a project tenant, say) it
still holds the old tenant's verified config until the new tenant's first
config is accepted, which is up to one poll. Every reader of the cached config
asks this module first and treats any answer other than "applies" exactly as
if no cached config existed, so the old tenant's policy never governs the new
tenant. The Windows agent applies the same rule in
AgentConfigManager.BelongsToTenant (PAT-1763).

The rule:

  - The enrolled tenant is the first line of the tenant-id credential with
    every ASCII whitespace byte removed, the same value the shell scripts read
    with `head -1 | tr -d '[:space:]'` and bind every verified config to. A
    missing, unreadable, empty or non-UTF-8 credential means no enrolled
    tenant, and no cached config applies.
  - The cached config applies only when it is a JSON object with no repeated
    member names (ignoring case), whose "tenant_id" is a non-empty string equal
    to the enrolled tenant, compared exactly.
  - Anything else does not apply: no tenant_id, a tenant_id that is not a
    non-empty string, another tenant, JSON that does not parse, a config that
    cannot be read or is larger than MAX_CONFIG_BYTES.

This module only classifies. It never decides what "absent" means for a
reader: each reader keeps its own existing no-config default.

Shipped in the endpoint bundle and covered by manifest.sha256. It is loaded by
path, never through sys.path, and never writes a bytecode cache next to itself.

Command line (one line on stdout, exit 0):

  agent_config_tenant.py cached-state <config-file> <tenant-id-file>

      applies
      absent
      no_enrolled_tenant
      unreadable <OSError name>
      malformed <problem>
      no_tenant
      invalid_tenant
      other_tenant <config tenant>

Only "applies" lets a reader use the config. Any other invocation exits 2 and
prints nothing to stdout, which every caller treats as "does not apply".
"""

import json
import sys

TENANT_KEY = "tenant_id"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_TENANT_ID_BYTES = 4096
APPLIES = "applies"

_ASCII_WHITESPACE = b" \t\n\r\v\f"
# PAT-1814: widened to include / and = (already included +) so a
# base64/JWT-shaped tenant_id renders intact instead of losing every
# padding/segment character to "?" in the one-line log this feeds. All three
# are plain printable ASCII with no shell metacharacter meaning inside the
# double-quoted `echo "...($_tenant_state)..."` the caller embeds this value
# in, so widening the set carries no injection risk.
_SAFE_DETAIL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@+-/="
)


def _reject_ambiguous_json_keys(pairs):
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


def safe_detail(value, limit=64):
    """Render a value for a one-line log: no whitespace or control characters."""
    text = value if isinstance(value, str) else repr(value)
    rendered = "".join(ch if ch in _SAFE_DETAIL_CHARS else "?" for ch in text[:limit])
    return rendered + ("..." if len(text) > limit else "")


def enrolled_tenant_from_bytes(raw):
    """The enrolled tenant from tenant-id credential bytes, or None."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_TENANT_ID_BYTES:
        return None
    first_line = bytes(raw).split(b"\n", 1)[0]
    stripped = bytes(b for b in first_line if b not in _ASCII_WHITESPACE)
    try:
        tenant = stripped.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return tenant or None


def read_enrolled_tenant(path):
    """Read the tenant-id credential at path. None when there is no usable tenant."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_TENANT_ID_BYTES + 1)
    except OSError:
        return None
    return enrolled_tenant_from_bytes(raw)


def classify_config(config, enrolled_tenant):
    """Classify an already parsed config. Returns (state, detail)."""
    if not enrolled_tenant:
        return ("no_enrolled_tenant", "")
    if not isinstance(config, dict):
        return ("malformed", "config is not a JSON object")
    if TENANT_KEY not in config:
        return ("no_tenant", "")
    tenant = config[TENANT_KEY]
    if not isinstance(tenant, str) or not tenant.strip():
        return ("invalid_tenant", "")
    if tenant != enrolled_tenant:
        return ("other_tenant", safe_detail(tenant))
    return (APPLIES, "")


def classify_config_bytes(raw, enrolled_tenant):
    """Classify the bytes of a cached config. Returns (state, detail). Never raises."""
    if not enrolled_tenant:
        return ("no_enrolled_tenant", "")
    if len(raw) > MAX_CONFIG_BYTES:
        return ("malformed", f"config is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        config = json.loads(bytes(raw).decode("utf-8"),
                            object_pairs_hook=_reject_ambiguous_json_keys)
    except Exception:
        return ("malformed", "config is not valid unambiguous JSON")
    return classify_config(config, enrolled_tenant)


def cached_state(config_path, tenant_id_path):
    """Classify the cached config at config_path for the tenant-id credential."""
    try:
        with open(config_path, "rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return ("absent", "")
    except OSError as exc:
        return ("unreadable", type(exc).__name__)
    return classify_config_bytes(raw, read_enrolled_tenant(tenant_id_path))


def describe(state_detail):
    state, detail = state_detail
    return f"{state} {detail}" if detail else state


def main(argv):
    if len(argv) != 4 or argv[1] != "cached-state":
        print("usage: agent_config_tenant.py cached-state <config-file> <tenant-id-file>",
              file=sys.stderr)
        return 2
    print(describe(cached_state(argv[2], argv[3])))
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main(sys.argv))
