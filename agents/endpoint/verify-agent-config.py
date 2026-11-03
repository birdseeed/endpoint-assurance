#!/usr/bin/env python3
"""
verify-agent-config.py — verify a GET /v1/agent-config response and cache it.

Called by patched-fetch-config.sh after a successful HTTP 200.

Usage:
  verify-agent-config.py \\
      --response-file PATH   raw HTTP response body (JSON)
      --version-file  PATH   tenant-keyed anti-rollback floor (read-only; caller writes)
      --current-config-file PATH
                            last-accepted verified config (read-only)
      --current-config-sha256-file PATH
                            digest recorded when that config was committed
      --execution-denial-file PATH
                            authenticated per-authority revocation floors
                            (read-only)
      --output-file   PATH   path to write verified config JSON
      --execution-denial-output-file PATH
                            trusted revocation metadata written only on exit 42

Exit 0 on success (config written to output-file).
Exit 42 when a newer, signature-verified, tenant-bound payload explicitly
revokes endpoint execution authority but is rejected for another structural
reason. Exit 1 on every other rejection or error. Callers keep last-known-good
configuration in both rejection cases, but only exit 42 may create the
separate fail-closed execution-denial state. On exit 42 the verifier writes
bounded, authenticated per-authority floors to execution-denial-output-file;
it never overwrites output-file on a rejected policy.

The caller (patched-fetch-config.sh) writes the version-file AFTER atomically
committing the output-file so that config and version can never diverge across
a crash (see patched-fetch-config.sh VERIFY AND CACHE section).

PATCHED_TENANT_ID env var: expected tenant UUID (required; hard-rejected if empty).

Anti-rollback floor (PAT-1756). config_version is monotonic per tenant on the
server, so the floor file is keyed by tenant:

  {"tenant_id":"<tenant id>","config_version":<non-negative integer>}

exactly those two members, written by patched-fetch-config.sh after a commit
(the Windows agent writes the same format). A legacy bare integer is the floor
for the device's currently enrolled tenant only. A keyed floor is compared only
when its tenant equals the verified payload's tenant; a floor for any other
tenant means this tenant starts fresh. Tenant binding is checked before the
floor decides anything, so a signed config for a tenant the device is not
enrolled in is still rejected. A missing file means no floor. An unreadable or
malformed file is corrupt and rejects every config: it is never read as "no
floor", which would silently disable anti-rollback for the same tenant. A
successful enrolment (patched-enroll.sh) removes the file. The file is parsed
by agent_config_floor.py (PAT-1763), the one parser every caller shares.

Execution-denial marker (PAT-1763). The marker's revocation floors are
config_version numbers too, so it carries the tenant whose signed policy
revoked execution:

  {"tenant_id":"<tenant id>","config_version":N,
   "legacy_app_execution_revoked_at":N,"app_control_revoked_at":N}

A keyed marker applies only to its own tenant. A marker with no tenant_id
(written before PAT-1763) is attributed to the currently enrolled tenant, the
same rule as a legacy floor. Enrolment never removes the marker; the new
tenant's first completely verified commit supersedes another tenant's marker
(patched-fetch-config.sh), and every actuation gate refuses while it exists.

The pinned public key is a non-overridable constant. There is deliberately NO
environment or CLI override of the trust anchor in this script: a process that
merely executes the verifier (whatever its environment) can never swap the key
it verifies against. Tests inject a test key by importing this file as a module
and patching _PINNED_PUBKEY_B64 / _PINNED_KEY_ID on the module object (see
test-verify-agent-config.py), unreachable from the production execution path.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import sys

# ── Pinned public key ────────────────────────────────────────────────────────
# This is the Ed25519 *public* key — safe to commit.  The private seed lives
# only in /etc/patched-api/env on patched-api-01.
# Rotate: update AGENT_CONFIG_SIGNING_KEY on the server, restart, then ship
# a new agent with the updated _PINNED_PUBKEY_B64 / _PINNED_KEY_ID below.
_PINNED_PUBKEY_B64 = "a3voEh/OojvVNeRUrP6iE68bqFAfEUPFUDth77oevV0="  # gitleaks:allow
_PINNED_KEY_ID     = "ecd47f2c5b3d5705"

# A private caller/verifier protocol value, deliberately outside argparse's
# conventional exit-code range. Only an authenticated, tenant-bound, newer
# policy with a fail-closed authority value may produce it.
AUTHENTICATED_EXECUTION_REVOCATION_EXIT = 42
MAX_CURRENT_CONFIG_BYTES = 1024 * 1024
MAX_EXECUTION_DENIAL_BYTES = 1024


def _load_floor_module():
    """Load agent_config_floor.py from this script's own directory (PAT-1763).

    Loaded by path rather than through sys.path, so nothing earlier on the
    import path can stand in for it, and without writing a bytecode cache into
    the root-owned bundle directory. The bundle manifest covers both files. A
    missing or broken module raises here, which fails the verifier and so
    rejects the config.
    """
    module_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "agent_config_floor.py"
    )
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(
            "patched_agent_config_floor", module_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


_FLOOR = _load_floor_module()
MAX_ROLLBACK_FLOOR_BYTES = _FLOOR.MAX_FLOOR_BYTES

LEGACY_REVOCATION_FLOOR_KEY = "legacy_app_execution_revoked_at"
# PAT-1763: the execution-denial marker is keyed by the tenant whose signed
# policy revoked execution.
DENIAL_TENANT_KEY = "tenant_id"
APP_CONTROL_REVOCATION_FLOOR_KEY = "app_control_revoked_at"

# ── Pure-Python Ed25519 verification (RFC 8032 §5.1) ────────────────────────
# No external dependencies; works with Apple stock /usr/bin/python3.

_p = 2**255 - 19
_q = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _recover_x(y: int, sign: int):
    """Recover the x-coordinate from a compressed y and the sign bit of x."""
    y2 = y * y % _p
    x2 = (y2 - 1) * pow(_d * y2 + 1, _p - 2, _p) % _p
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (_p + 3) // 8, _p)
    if x * x % _p != x2:
        x = x * pow(2, (_p - 1) // 4, _p) % _p
    if x * x % _p != x2:
        return None
    if x & 1 != sign:
        x = _p - x
    return x


def _decode(s: bytes):
    """Decode a 32-byte compressed point into extended coordinates (X:Y:Z:T)."""
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ~(1 << 255)
    x = _recover_x(y, (s[31] >> 7) & 1)
    if x is None:
        return None
    return x, y, 1, x * y % _p


def _add(P, Q):
    """Unified point addition in extended twisted Edwards coordinates."""
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return E * F % _p, G * H % _p, F * G % _p, E * H % _p


def _mul(s: int, P):
    """Scalar multiplication: return [s]P."""
    Q = None
    while s:
        if s & 1:
            Q = P if Q is None else _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _compress(P) -> bytes:
    """Compress an extended-coordinates point to 32 bytes."""
    zi = pow(P[2], _p - 2, _p)
    x, y = P[0] * zi % _p, P[1] * zi % _p
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


_Gy = 4 * pow(5, _p - 2, _p) % _p
_Gx = _recover_x(_Gy, 0)
_G  = (_Gx, _Gy, 1, _Gx * _Gy % _p)


def ed25519_verify(pubkey_b64: str, message: bytes, sig_b64: str) -> bool:
    """Return True if sig_b64 is a valid Ed25519 signature of message under pubkey_b64."""
    try:
        pk  = base64.b64decode(pubkey_b64)
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    if len(sig) != 64 or len(pk) != 32:
        return False
    A = _decode(pk)
    if A is None:
        return False
    R_enc = sig[:32]
    R = _decode(R_enc)
    if R is None:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _q:
        return False
    k   = int.from_bytes(_sha512(R_enc + pk + message), "little") % _q
    lhs = _mul(S, _G)
    kA  = _mul(k, A)
    if lhs is None or kA is None:
        return False
    # Check [S]G - [k]A == R  (negate kA by flipping X and T)
    neg_kA = (-kA[0] % _p, kA[1], kA[2], -kA[3] % _p)
    result = _add(lhs, neg_kA)
    return _compress(result) == R_enc


def _reject_ambiguous_json_keys(pairs):
    """Build a JSON object only when all member names are unambiguous.

    JSON permits duplicate member names, but Python's default decoder keeps
    only the last one. Signed configuration must not turn that lossy parsing
    behaviour into authority. ``object_pairs_hook`` is invoked for every
    object, so this also protects forward-compatible nested fields.
    """
    result = {}
    seen = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError(f"duplicate or case-colliding JSON key: {key!r}")
        seen.add(folded)
        result[key] = value
    return result


class _ObjectPairs(list):
    """Distinguish JSON objects from arrays while retaining member order."""


def _read_bounded_json_object(path: str, maximum: int) -> dict:
    """Strictly decode one bounded JSON object from a local state file."""
    with open(path, "rb") as fh:
        raw = fh.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError(f"state file exceeds {maximum}-byte limit")
    parsed = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_reject_ambiguous_json_keys
    )
    if not isinstance(parsed, dict):
        raise ValueError("state file root must be an object")
    return parsed


def _read_rollback_floor(path: str) -> tuple:
    """Read the tenant-keyed anti-rollback floor (PAT-1756).

    Returns one of:
      ("absent", None, 0)           no floor file
      ("legacy", None, version)     pre-PAT-1756 bare integer
      ("keyed", tenant_id, version) the current format
      ("corrupt", None, problem)    anything else, including an unreadable file
    Never raises for a missing or unreadable file. Parsing lives in
    agent_config_floor.py (PAT-1763), shared with patched-enroll.sh and
    patched-fetch-config.sh; the verifier treats an unreadable floor as
    corrupt.
    """
    floor = _FLOOR.read_floor(path)
    if floor[0] == "unreadable":
        return ("corrupt", None, f"file could not be read ({floor[2]})")
    return floor


def _rollback_floor_for_tenant(floor: tuple, tenant_id: str) -> tuple:
    """Return (last_version, description) of a non-corrupt floor for tenant_id.

    tenant_id must be the tenant every caller then requires the signed payload
    to be bound to. A floor for another tenant contributes nothing (0).
    """
    return _FLOOR.floor_for_tenant(floor, tenant_id)


def _authority_grants(config: dict) -> dict[str, object]:
    app_control_authority = config.get("app_control_authority")
    app_control_level = (
        app_control_authority
        if isinstance(app_control_authority, str)
        and app_control_authority in {"report", "block", "enforce"}
        else "report"
    )
    return {
        "legacy": config.get("legacy_app_execution_enabled") is True,
        "app_control": app_control_level in {"block", "enforce"},
        "app_control_level": app_control_level,
    }


def _load_revocation_floors(denial: dict) -> dict[str, object]:
    """Read per-authority floors, treating the old marker as a full denial."""
    marker_version = denial.get("config_version")
    if (not isinstance(marker_version, int)
            or isinstance(marker_version, bool)):
        raise ValueError("invalid config_version")

    floor_keys = (LEGACY_REVOCATION_FLOOR_KEY, APP_CONTROL_REVOCATION_FLOOR_KEY)
    if not any(key in denial for key in floor_keys):
        # Backward compatibility: the original marker represented both
        # authorities being revoked at this version.
        return {"legacy": marker_version, "app_control": marker_version}

    floors = {
        "legacy": denial.get(LEGACY_REVOCATION_FLOOR_KEY),
        "app_control": denial.get(APP_CONTROL_REVOCATION_FLOOR_KEY),
    }
    for value in floors.values():
        if value is not None and (
                not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError("invalid per-authority revocation floor")
    values = [value for value in floors.values() if value is not None]
    if not values or marker_version != max(values):
        raise ValueError("config_version does not match revocation floors")
    return floors


def _execution_denial_tenant(denial: dict, tenant_id_expected: str) -> tuple:
    """Return (applies, description) for an execution-denial marker (PAT-1763).

    The marker's floors are config_version numbers, and config_version is
    monotonic per tenant, so the marker is keyed by the tenant whose signed
    policy revoked execution. A keyed marker applies only to that tenant: a
    device moved to another tenant is not held to the old tenant's version
    numbers. It is never cleared by enrolment; the new tenant's first
    completely verified commit supersedes it (patched-fetch-config.sh), and
    until then every actuation gate keeps refusing because the file exists.

    A marker with no tenant_id (written before PAT-1763) is attributed to the
    currently enrolled tenant, the same rule PAT-1756 applies to a legacy
    bare-integer anti-rollback floor, so it keeps failing closed for the
    tenant it came from. A tenant_id that is present but not a non-empty
    string is malformed and raises, which rejects every config.
    """
    if DENIAL_TENANT_KEY not in denial:
        return True, (f"legacy execution-denial marker with no tenant, applied to "
                      f"the enrolled tenant {tenant_id_expected}")
    marker_tenant = denial[DENIAL_TENANT_KEY]
    if not isinstance(marker_tenant, str) or not marker_tenant.strip():
        raise ValueError("execution-denial tenant_id is not a non-empty string")
    if marker_tenant == tenant_id_expected:
        return True, f"execution-denial marker for tenant {tenant_id_expected}"
    return False, (f"execution-denial marker belongs to tenant {marker_tenant}, "
                   f"so its revocation floors do not apply to tenant "
                   f"{tenant_id_expected}")


def _denial_document(floors: dict[str, object], tenant_id: str) -> dict:
    values = [value for value in floors.values() if value is not None]
    if not values:
        raise ValueError("no revocation floor to persist")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("no tenant to key the revocation floor to")
    document = {DENIAL_TENANT_KEY: tenant_id, "config_version": max(values)}
    if floors.get("legacy") is not None:
        document[LEGACY_REVOCATION_FLOOR_KEY] = floors["legacy"]
    if floors.get("app_control") is not None:
        document[APP_CONTROL_REVOCATION_FLOOR_KEY] = floors["app_control"]
    return document


def _current_authority_grants(path: object, digest_path: object,
                              last_version: int) -> dict[str, object]:
    """Return grants only from an unambiguous last-accepted config snapshot."""
    no_grants = {
        "legacy": False,
        "app_control": False,
        "app_control_level": "report",
    }
    if (not isinstance(path, str) or not path or not os.path.exists(path)
            or not isinstance(digest_path, str) or not digest_path
            or not os.path.exists(digest_path)):
        return no_grants
    try:
        with open(path, "rb") as fh:
            raw_config = fh.read(MAX_CURRENT_CONFIG_BYTES + 1)
        if len(raw_config) > MAX_CURRENT_CONFIG_BYTES:
            return no_grants
        with open(digest_path, "rb") as fh:
            raw_digest = fh.read(129)
        if len(raw_digest) > 128:
            return no_grants
        recorded_digest = raw_digest.decode("ascii").strip()
        if (len(recorded_digest) != 64
                or any(char not in "0123456789abcdefABCDEF"
                       for char in recorded_digest)
                or hashlib.sha256(raw_config).hexdigest().lower()
                != recorded_digest.lower()):
            return no_grants
        config = json.loads(
            raw_config.decode("utf-8"),
            object_pairs_hook=_reject_ambiguous_json_keys,
        )
        if not isinstance(config, dict):
            return no_grants
    except Exception:
        return no_grants
    current_version = config.get("config_version")
    if (not isinstance(current_version, int)
            or isinstance(current_version, bool)
            or current_version != last_version):
        return no_grants
    return _authority_grants(config)


def _top_level_authority_context(payload: bytes, tenant_id_expected: str,
                                 last_version: int,
                                 previous_grants: dict[str, object],
                                 denial_floors: dict[str, object],
                                 ) -> tuple[set[str], object]:
    """Return independently revoked authorities from rejected signed bytes.

    The complete JSON syntax and the top-level control fields must be
    unambiguous before this result can affect endpoint state. Nested objects
    intentionally remain as pair lists here: their ambiguity is what the full
    strict parse below rejects, but it cannot erase an authenticated top-level
    revocation fact.
    """
    parsed = json.loads(payload, object_pairs_hook=_ObjectPairs)
    if not isinstance(parsed, _ObjectPairs):
        return set(), None

    top_level = {}
    seen = set()
    for key, value in parsed:
        if not isinstance(key, str):
            return set(), None
        folded = key.casefold()
        if folded in seen:
            return set(), None
        seen.add(folded)
        top_level[key] = value

    new_version = top_level.get("config_version")
    if (top_level.get("tenant_id") != tenant_id_expected
            or not isinstance(new_version, int)
            or isinstance(new_version, bool)
            or new_version <= last_version):
        return set(), new_version if isinstance(new_version, int) else None

    revoked = set()
    legacy_floor = denial_floors.get("legacy")
    if (previous_grants.get("legacy")
            and top_level.get("legacy_app_execution_enabled") is False
            and (legacy_floor is None or new_version > legacy_floor)):
        revoked.add("legacy")

    app_control_floor = denial_floors.get("app_control")
    authority_rank = {"report": 0, "block": 1, "enforce": 2}
    previous_authority = previous_grants.get("app_control_level")
    new_authority = top_level.get("app_control_authority")
    if (previous_authority in authority_rank
            and new_authority in authority_rank
            and authority_rank[new_authority] < authority_rank[previous_authority]
            and (app_control_floor is None or new_version > app_control_floor)):
        revoked.add("app_control")
    return revoked, new_version


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--response-file", required=True,
                    help="Path to the raw HTTP 200 response body (JSON)")
    ap.add_argument("--version-file",  required=True,
                    help="Path to the last-accepted config_version file (read-only)")
    ap.add_argument(
        "--current-config-file",
        help="Path to the last-accepted verified config (read-only)",
    )
    ap.add_argument(
        "--current-config-sha256-file",
        help="Path to the digest recorded with the last-accepted config",
    )
    ap.add_argument(
        "--execution-denial-file",
        help="Path to the authenticated execution-revocation floor (read-only)",
    )
    ap.add_argument("--output-file",   required=True,
                    help="Path to write the verified config JSON")
    ap.add_argument(
        "--execution-denial-output-file",
        help="Path to write trusted revocation metadata only on exit 42",
    )
    args = ap.parse_args()

    # PATCHED_TENANT_ID must be set — an empty value means the binding cannot
    # be verified, which is a hard security failure, not a skip.
    tenant_id_expected = os.environ.get("PATCHED_TENANT_ID", "").strip()
    if not tenant_id_expected:
        print("agent-config: rejected: PATCHED_TENANT_ID is not set; "
              "tenant binding cannot be verified", file=sys.stderr)
        sys.exit(1)

    # Trust anchor: module-level constants only. Never read the pinned key or
    # key_id from the environment or argv: an env override would let any
    # process that launches this verifier substitute its own key and have
    # attacker-signed agent-config accepted and cached (gate finding, PR #319).
    pinned_pubkey = _PINNED_PUBKEY_B64
    pinned_key_id = _PINNED_KEY_ID

    def reject(reason: str) -> None:
        print(f"agent-config: rejected: {reason}", file=sys.stderr)
        sys.exit(1)

    # ── Parse response ───────────────────────────────────────────────────────
    try:
        with open(args.response_file) as fh:
            resp = json.load(fh, object_pairs_hook=_reject_ambiguous_json_keys)
    except Exception as exc:
        reject(f"parse response JSON: {exc}")

    # ── Structural checks ────────────────────────────────────────────────────
    for field in ("signed_payload", "key_id", "signature"):
        if field not in resp:
            reject(f"missing required field: {field!r}")

    if resp["key_id"] != pinned_key_id:
        reject(f"key_id mismatch (got {resp['key_id']!r}, expected {pinned_key_id!r})")

    # ── Decode and verify signed_payload ─────────────────────────────────────
    # The server returns the exact bytes it signed as base64(signed_payload).
    # Verify the Ed25519 signature over those raw bytes — no client reconstruction.
    try:
        signed_payload_bytes = base64.b64decode(resp["signed_payload"])
    except Exception as exc:
        reject(f"decode signed_payload: {exc}")

    if not ed25519_verify(pinned_pubkey, signed_payload_bytes, resp["signature"]):
        reject("Ed25519 signature is invalid")

    # Load the accepted-version floor before the strict inner parse. A signed
    # payload rejected only for nested ambiguity can still carry a trustworthy
    # newer top-level revocation, but a replay at or below this floor cannot.
    #
    # PAT-1756: the floor is keyed by tenant. last_version is the floor for
    # tenant_id_expected, and every consumer below only acts on a payload whose
    # tenant_id equals tenant_id_expected (the top-level revocation context
    # checks it first; the full path runs tenant binding before anti-rollback).
    # A corrupt floor yields no revocation context and is rejected right after
    # tenant binding, never treated as "no floor".
    rollback_floor = _read_rollback_floor(args.version_file)
    floor_corrupt = rollback_floor[0] == "corrupt"
    if floor_corrupt:
        last_version, floor_description = 0, ""
    else:
        last_version, floor_description = _rollback_floor_for_tenant(
            rollback_floor, tenant_id_expected
        )

    denial_floors = {"legacy": None, "app_control": None}
    if args.execution_denial_file and os.path.lexists(args.execution_denial_file):
        try:
            denial = _read_bounded_json_object(
                args.execution_denial_file, MAX_EXECUTION_DENIAL_BYTES
            )
            marker_floors = _load_revocation_floors(denial)
            marker_applies, marker_description = _execution_denial_tenant(
                denial, tenant_id_expected
            )
        except Exception as exc:
            reject(f"read execution-denial floor: {exc}")
        print(f"agent-config: {marker_description}")
        if marker_applies:
            denial_floors = marker_floors

    denied_versions = [
        value for value in denial_floors.values() if value is not None
    ]
    denied_version = max(denied_versions) if denied_versions else None
    authority_floor = max(
        last_version,
        denied_version if denied_version is not None else last_version,
    )
    previous_grants = _current_authority_grants(
        args.current_config_file,
        args.current_config_sha256_file,
        last_version,
    )

    authenticated_execution_revocations = set()
    authenticated_version = None
    try:
        if not floor_corrupt:
            authenticated_execution_revocations, authenticated_version = (
                _top_level_authority_context(
                    signed_payload_bytes,
                    tenant_id_expected,
                    last_version,
                    previous_grants,
                    denial_floors,
                )
            )
    except Exception:
        # Invalid JSON cannot establish tenant binding, version ordering or an
        # authority value even when the opaque bytes happened to be signed.
        pass

    # ── Parse verified config ────────────────────────────────────────────────
    try:
        config = json.loads(
            signed_payload_bytes, object_pairs_hook=_reject_ambiguous_json_keys
        )
    except Exception as exc:
        if authenticated_execution_revocations:
            if not args.execution_denial_output_file:
                reject(
                    "authenticated execution revocation cannot be persisted: "
                    "missing --execution-denial-output-file"
                )
            try:
                merged_floors = dict(denial_floors)
                for authority in authenticated_execution_revocations:
                    merged_floors[authority] = authenticated_version
                denial_document = _denial_document(
                    merged_floors, tenant_id_expected
                )
                with open(
                    args.execution_denial_output_file, "w", encoding="utf-8"
                ) as fh:
                    json.dump(denial_document, fh, separators=(",", ":"))
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as write_exc:
                reject(f"write execution-denial metadata: {write_exc}")
            print(
                "agent-config: authenticated authority revocation in newer "
                f"version {authenticated_version} "
                f"({','.join(sorted(authenticated_execution_revocations))}); "
                f"full policy rejected: {exc}",
                file=sys.stderr,
            )
            sys.exit(AUTHENTICATED_EXECUTION_REVOCATION_EXIT)
        reject(f"parse signed_payload JSON: {exc}")

    # ── Tenant binding ───────────────────────────────────────────────────────
    if config.get("tenant_id") != tenant_id_expected:
        reject("tenant_id in signed_payload does not match local tenant-id credential")

    # ── Anti-rollback (keyed by tenant, PAT-1756) ────────────────────────────
    # Only reached once tenant binding above has proven the verified payload's
    # tenant_id equals tenant_id_expected, the tenant last_version was keyed by.
    if floor_corrupt:
        reject(
            f"anti-rollback: the stored floor is unusable ({rollback_floor[2]}), "
            f"so no version can be checked for tenant {tenant_id_expected}. "
            "Every config is refused until the device re-enrols or the floor "
            "file is removed"
        )
    new_version = config.get("config_version")
    if (not isinstance(new_version, int) or isinstance(new_version, bool)
            or new_version < authority_floor):
        reject(
            f"anti-rollback: new version {new_version} < trusted floor "
            f"{authority_floor} for tenant {tenant_id_expected} "
            f"({floor_description})"
        )
    print(
        f"agent-config: anti-rollback: version {new_version} >= trusted floor "
        f"{authority_floor} for tenant {tenant_id_expected} ({floor_description})"
    )
    if denied_version is not None and new_version == denied_version:
        grants = _authority_grants(config)
        conflicts = [
            authority
            for authority, floor in denial_floors.items()
            if floor == new_version and grants[authority]
        ]
        if conflicts:
            reject(
                "same-version execution grant conflicts with authenticated "
                f"revocation floor ({','.join(sorted(conflicts))})"
            )

    # ── Write output (verified config only) ──────────────────────────────────
    # Write the verified canonical config (not the outer response envelope).
    # The caller (patched-fetch-config.sh) atomically mv's this file into place
    # and THEN writes the version-file, ensuring they can never diverge across
    # a crash.  This verifier must NOT write the version-file.
    try:
        with open(args.output_file, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        reject(f"write output: {exc}")

    print(
        f"agent-config: accepted version={new_version} "
        f"tier={config.get('tier')!r} key_id={resp.get('key_id')!r}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
