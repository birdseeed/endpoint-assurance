#!/usr/bin/env python3
"""
verify-posture.py — verify a GET /v1/posture response and cache it (PAT-910).

Called by patched-fetch-posture.sh after a successful HTTP 200. Mirrors
verify-agent-config.py: same pinned Ed25519 public key (posture is signed with
the same server key as agent-config), same {signed_payload, key_id, signature}
envelope, same verify-over-transmitted-bytes rule, same crash-ordering contract.

Usage:
  verify-posture.py \\
      --response-file PATH   raw HTTP response body (JSON envelope)
      --version-file  PATH   last-accepted issued_at (read-only; caller writes)
      --output-file   PATH   path to write the verified posture JSON
      --cache-file    PATH   currently cached verified posture (optional,
                             read-only; raises the anti-rollback floor)

Exit 0 on success (verified inner posture written to output-file).
Exit 1 on any rejection or error. FAIL CLOSED: on any failure the caller keeps
its last-known-good posture and MUST NOT fall back to unsigned or stale posture.

Anti-rollback invariant: the effective floor is max(version-file value,
issued_at of the cached verified posture at --cache-file). The caller
(patched-fetch-posture.sh) also writes and fsyncs the version-file BEFORE
committing the cache, so the sidecar floor is >= the cached issued_at at every
instant — and even if the two ever diverged, the max() here means no posture
older than the cache can be accepted. This verifier must NOT write the
version-file or the cache.

PATCHED_TENANT_ID env var: expected tenant UUID (required; hard-rejected if empty).

The pinned public key is a non-overridable constant. There is deliberately NO
environment or CLI override of the trust anchor in this script: a process that
merely executes the verifier (whatever its environment) can never swap the key
it verifies against. Tests inject a test key by importing this file as a module
and patching _PINNED_PUBKEY_B64 / _PINNED_KEY_ID on the module object (see
test-verify-posture.py) — unreachable from the production execution path.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

# ── Pinned public key ────────────────────────────────────────────────────────
# The SAME Ed25519 public key as verify-agent-config.py — posture is signed with
# the server's single AGENT_CONFIG_SIGNING_KEY. Safe to commit (public half).
# Rotate: update AGENT_CONFIG_SIGNING_KEY on the server, restart, then ship a new
# agent with the updated _PINNED_PUBKEY_B64 / _PINNED_KEY_ID in both verifiers.
_PINNED_PUBKEY_B64 = "a3voEh/OojvVNeRUrP6iE68bqFAfEUPFUDth77oevV0="  # gitleaks:allow
_PINNED_KEY_ID     = "ecd47f2c5b3d5705"

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


# ── Anti-rollback helpers ────────────────────────────────────────────────────

def _to_epoch(s: str) -> int:
    """Parse a stored/served version value to epoch seconds.

    Accepts an integer epoch (what a future caller might store) or an RFC3339 UTC
    'Z' timestamp (what the server signs into issued_at). Returns 0 on anything
    unparseable so a corrupt version-file degrades to "no floor", never crashes.
    """
    s = (s or "").strip()
    if not s:
        return 0
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
                   .replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--response-file", required=True,
                    help="Path to the raw HTTP 200 response body (JSON envelope)")
    ap.add_argument("--version-file",  required=True,
                    help="Path to the last-accepted issued_at file (read-only)")
    ap.add_argument("--output-file",   required=True,
                    help="Path to write the verified posture JSON")
    ap.add_argument("--cache-file",    default="",
                    help="Currently cached verified posture (read-only); its "
                         "issued_at raises the effective anti-rollback floor")
    args = ap.parse_args()

    # PATCHED_TENANT_ID must be set — an empty value means the tenant binding
    # cannot be verified, which is a hard security failure, not a skip.
    tenant_id_expected = os.environ.get("PATCHED_TENANT_ID", "").strip()
    if not tenant_id_expected:
        print("posture: rejected — PATCHED_TENANT_ID is not set; "
              "tenant binding cannot be verified", file=sys.stderr)
        sys.exit(1)

    # Trust anchor: module-level constants only. Never read the pinned key or
    # key_id from the environment or argv — an env override would let any
    # process that launches this verifier substitute its own key and have
    # attacker-signed posture accepted and cached (gate finding, PR #319).
    pinned_pubkey = _PINNED_PUBKEY_B64
    pinned_key_id = _PINNED_KEY_ID

    def reject(reason: str) -> None:
        print(f"posture: rejected — {reason}", file=sys.stderr)
        sys.exit(1)

    # ── Parse response envelope ──────────────────────────────────────────────
    try:
        with open(args.response_file) as fh:
            resp = json.load(fh)
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
    # Verify the Ed25519 signature over those raw bytes — no reconstruction.
    try:
        signed_payload_bytes = base64.b64decode(resp["signed_payload"])
    except Exception as exc:
        reject(f"decode signed_payload: {exc}")

    if not ed25519_verify(pinned_pubkey, signed_payload_bytes, resp["signature"]):
        reject("Ed25519 signature is invalid")

    # ── Parse verified posture ───────────────────────────────────────────────
    try:
        posture = json.loads(signed_payload_bytes)
    except Exception as exc:
        reject(f"parse signed_payload JSON: {exc}")

    # ── Tenant binding ───────────────────────────────────────────────────────
    if posture.get("tenant_id") != tenant_id_expected:
        reject("tenant_id in signed_payload does not match local tenant-id credential")

    # ── Anti-rollback (issued_at) ────────────────────────────────────────────
    # Effective floor = max(version-file value, cached posture's issued_at).
    # Deriving the floor from BOTH sources structurally eliminates the sidecar
    # divergence window (gate finding, PR #319 round 3): whatever the caller's
    # write ordering or crash timing, nothing older than the posture already in
    # the cache can ever be accepted over it.
    sidecar_epoch = 0
    if os.path.exists(args.version_file):
        try:
            sidecar_epoch = _to_epoch(open(args.version_file).read())
        except OSError:
            sidecar_epoch = 0

    cache_epoch = 0
    if args.cache_file and os.path.exists(args.cache_file):
        try:
            cached = json.load(open(args.cache_file))
            if isinstance(cached, dict):
                cache_epoch = _to_epoch(cached.get("issued_at", ""))
        except Exception as exc:
            # Defensive: an unparseable cache cannot RAISE the floor but must
            # not crash the verifier. The cache is only ever written by this
            # fetch pipeline post-verification, so a parse failure here is
            # itself anomalous — log it for investigation.
            print(f"posture: warning — cached posture at {args.cache_file} is "
                  f"unparseable ({exc}); floor from version-file only. This "
                  f"cache is written only post-verification, so this is "
                  f"anomalous.", file=sys.stderr)
            cache_epoch = 0

    last_epoch = max(sidecar_epoch, cache_epoch)

    new_issued = posture.get("issued_at")
    if not isinstance(new_issued, str):
        reject("issued_at missing or not a string")
    new_epoch = _to_epoch(new_issued)
    if new_epoch == 0:
        reject(f"issued_at is not a valid RFC3339 UTC timestamp: {new_issued!r}")
    if new_epoch < last_epoch:
        reject(f"anti-rollback: issued_at {new_issued} older than last accepted "
               f"(effective floor epoch {last_epoch} = max(version-file "
               f"{sidecar_epoch}, cache {cache_epoch}))")

    # ── Write output (verified posture only) ─────────────────────────────────
    # Write the verified inner posture (not the outer envelope). The caller
    # writes and fsyncs the version-file FIRST and then atomically mv's this
    # file into place, so the sidecar floor is >= the cached issued_at at every
    # instant (a crash between the two leaves floor ahead of cache, which
    # fail-safes under accept-equal semantics). This verifier must NOT write
    # the version-file or the cache.
    try:
        with open(args.output_file, "w", encoding="utf-8") as fh:
            json.dump(posture, fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        reject(f"write output: {exc}")

    print(
        f"posture: accepted issued_at={new_issued} "
        f"tenant={posture.get('tenant_id')!r} key_id={resp.get('key_id')!r}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
