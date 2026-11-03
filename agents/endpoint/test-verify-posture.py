#!/usr/bin/env python3
"""
test-verify-posture.py — CI self-test for verify-posture.py (PAT-910).

Exercises the full verify-and-cache flow. The test key is injected by importing
verify-posture.py as a module in a driver subprocess and patching its
_PINNED_PUBKEY_B64 / _PINNED_KEY_ID constants — the production verifier has NO
environment or CLI override of its trust anchor (gate finding, PR #319), so
tests must go through the import path, which a mere execution of the script can
never reach. No external dependencies — pure Python 3, same stdlib the daemon
uses. Mirrors the failure-mode matrix of test-verify-agent-config.py,
retargeted at the posture envelope (tenant_id binding + issued_at
anti-rollback).

Covers (18 cases):
  - Valid response: verifier accepts, output file contains the posture.
  - Non-ASCII in a value: round-trips correctly.
  - HTML special chars (<, >, &) in a value: same.
  - Tampered signed_payload: rejected.
  - Rollback attempt (older issued_at): rejected.
  - Missing required envelope field: rejected.
  - Wrong key_id: rejected.
  - Wrong tenant_id: rejected.
  - Bad (well-formed but wrong) signature: rejected.
  - Empty PATCHED_TENANT_ID: rejected.
  - Same issued_at (idempotent refetch): accepted.
  - Newer issued_at (version bump): accepted.
  - Missing issued_at: rejected (anti-rollback value absent).
  - Crash-ordering: verifier writes only the output-file, never the version-file.
  - Env override dead: running the real script with PATCHED_TEST_PUBKEY_B64 /
    PATCHED_TEST_KEY_ID set must still verify against the compiled-in pinned
    key and reject a test-key-signed response.
  - Cache floor lagging sidecar (old crash window): cache at T2, sidecar at T1,
    a replayed T1.5 posture is rejected — effective floor is max(sidecar, cache).
  - Floor ahead of cache (new ordering's crash window): sidecar T2, cache T1 —
    a refetch of T2 is accepted (accept-equal), a replayed T1.9 is rejected.
  - Unparseable cache: does not crash the verifier and does not lower the
    sidecar floor (and logs the anomaly).
"""

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

# ── Load the verifier module ─────────────────────────────────────────────────
_HERE   = os.path.dirname(os.path.abspath(__file__))
_SCRIPT = os.path.join(_HERE, "verify-posture.py")

_spec = importlib.util.spec_from_file_location("vp", _SCRIPT)
_vp   = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vp)

# ── Pure-Python Ed25519 signing (RFC 8032 §5.1) ──────────────────────────────
# Uses the same curve constants as verify-posture.py.

_p = _vp._p
_q = _vp._q
_G = _vp._G


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _sign(seed: bytes, message: bytes) -> bytes:
    h = _sha512(seed)
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    prefix = h[32:]
    pub = _vp._compress(_vp._mul(a, _G))
    r = int.from_bytes(_sha512(prefix + message), "little") % _q
    R_enc = _vp._compress(_vp._mul(r, _G))
    k = int.from_bytes(_sha512(R_enc + pub + message), "little") % _q
    S = (r + k * a) % _q
    return R_enc + S.to_bytes(32, "little")


def _public_key(seed: bytes) -> bytes:
    h = _sha512(seed)
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    return _vp._compress(_vp._mul(a, _G))


# ── Test key ─────────────────────────────────────────────────────────────────

_TEST_SEED       = bytes(range(1, 33))
_TEST_PUBKEY     = _public_key(_TEST_SEED)
_TEST_PUBKEY_B64 = base64.b64encode(_TEST_PUBKEY).decode()

# key_id = first 8 bytes of SHA-256(pubkey) as hex
_TEST_KEY_ID = hashlib.sha256(_TEST_PUBKEY).hexdigest()[:16]

_TEST_TENANT_ID = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
_DEFAULT_IAT    = "2026-07-16T12:00:00Z"


def _make_canonical_payload(
    tenant_id: str = _TEST_TENANT_ID,
    issued_at: str = _DEFAULT_IAT,
    computer_name: str = "Test Mac",
    app_name: str = "Zoom",
    user_removable: bool = False,
    omit_issued_at: bool = False,
) -> bytes:
    """Build a canonical posture payload in the shape the Go server signs."""
    payload = {
        "schema_version": 1,
        "tenant_id":      tenant_id,
        "issued_at":      issued_at,
        "generated_at":   issued_at,
        "device": {
            "id":            "d1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22",
            "serial":        "C02XYZ",
            "computer_name": computer_name,
            "os":            "macOS",
            "os_version":    "26.0",
        },
        "tier":       "assurance",
        "app_count":  1,
        "compliance": {"platform": "macOS", "benchmarks": []},
        "evidence": {
            "coverage_window_days":       30,
            "scans_logged":               3,
            "last_signed_report_digest":  None,
            "recent_scan_times":          [],
        },
        "findings": [],
        "updates":  [],
        "app_policy": {
            "apps": [
                {
                    "app_name":        app_name,
                    "identifier":      "us.zoom.xos",
                    "label":           "zoom",
                    "policy":          "mandatory" if user_removable is False else "approved",
                    "user_removable":  user_removable,
                    "enforcement_tier": "report",
                }
            ],
            "drift": [],
        },
    }
    if omit_issued_at:
        del payload["issued_at"]
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _make_response(canonical: bytes) -> dict:
    sig = _sign(_TEST_SEED, canonical)
    return {
        "signed_payload": base64.b64encode(canonical).decode(),
        "key_id":         _TEST_KEY_ID,
        "signature":      base64.b64encode(sig).decode(),
    }


# ── Test-key injection driver ────────────────────────────────────────────────
# The verifier's pinned key is a non-overridable constant (no env/CLI override —
# gate finding, PR #319). Tests therefore run the verifier through this driver:
# it imports the script as a module, patches the pinned-key constants on the
# module object, then invokes main(). Production code paths (executing the
# script directly) can never reach this injection point.
_DRIVER = r"""
import importlib.util, sys
script, pub, kid = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("vp_under_test", script)
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod._PINNED_PUBKEY_B64 = pub
mod._PINNED_KEY_ID     = kid
sys.argv = [script] + sys.argv[4:]
mod.main()
"""


def _verifier_cmd(resp_file: str, ver_file: str, out_file: str,
                  cache_file: str = "") -> list[str]:
    cmd = [sys.executable, "-c", _DRIVER,
           _SCRIPT, _TEST_PUBKEY_B64, _TEST_KEY_ID,
           "--response-file", resp_file,
           "--version-file",  ver_file,
           "--output-file",   out_file]
    if cache_file:
        cmd += ["--cache-file", cache_file]
    return cmd


def _run_verifier(response: dict, tenant_id: str = _TEST_TENANT_ID,
                  last_version: str = "",
                  cache_content: str = "") -> tuple[int, str, str]:
    """Run the verifier (test key injected via module import) and return
    (returncode, stdout+output, stderr). cache_content, when set, is written to
    a cache file passed as --cache-file (the currently cached verified posture,
    which raises the effective anti-rollback floor)."""
    with tempfile.TemporaryDirectory() as td:
        resp_file  = os.path.join(td, "response.json")
        ver_file   = os.path.join(td, "version")
        out_file   = os.path.join(td, "posture.json")
        cache_file = ""

        with open(resp_file, "w") as f:
            json.dump(response, f)
        if last_version:
            with open(ver_file, "w") as f:
                f.write(str(last_version))
        if cache_content:
            cache_file = os.path.join(td, "cached-posture.json")
            with open(cache_file, "w") as f:
                f.write(cache_content)

        env = {**os.environ, "PATCHED_TENANT_ID": tenant_id}
        result = subprocess.run(
            _verifier_cmd(resp_file, ver_file, out_file, cache_file),
            capture_output=True, text=True, env=env,
        )
        out_json = ""
        if os.path.exists(out_file):
            out_json = open(out_file).read()
        return result.returncode, result.stdout + out_json, result.stderr


# ── Tests ────────────────────────────────────────────────────────────────────

_PASS = 0
_FAIL = 0


def _ok(name: str) -> None:
    global _PASS
    _PASS += 1
    print(f"  PASS  {name}")


def _fail(name: str, detail: str) -> None:
    global _FAIL
    _FAIL += 1
    print(f"  FAIL  {name}: {detail}")


def test_valid_response():
    resp = _make_response(_make_canonical_payload())
    rc, out, err = _run_verifier(resp)
    if rc != 0:
        _fail("valid_response", f"exit {rc}: {err}")
    elif '"tenant_id"' not in out or '"app_policy"' not in out:
        _fail("valid_response", "output file missing posture fields")
    else:
        _ok("valid_response")


def test_non_ascii_in_value():
    resp = _make_response(_make_canonical_payload(computer_name="うちのMac"))
    rc, out, _ = _run_verifier(resp)
    if rc != 0:
        _fail("non_ascii_in_value", f"exit {rc}")
    elif "うちのMac" not in out:
        _fail("non_ascii_in_value", "non-ASCII chars lost in output")
    else:
        _ok("non_ascii_in_value")


def test_html_special_chars_in_value():
    resp = _make_response(_make_canonical_payload(computer_name="a&b<c>d"))
    rc, _, _ = _run_verifier(resp)
    if rc == 0:
        _ok("html_special_chars_in_value")
    else:
        _fail("html_special_chars_in_value", "verifier rejected valid special-char posture")


def test_tampered_payload_rejected():
    resp = _make_response(_make_canonical_payload())
    raw = bytearray(base64.b64decode(resp["signed_payload"]))
    raw[0] ^= 0xFF
    resp["signed_payload"] = base64.b64encode(bytes(raw)).decode()
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("tampered_payload_rejected")
    else:
        _fail("tampered_payload_rejected", "tampered payload was accepted")


def test_rollback_rejected():
    # New posture is older than the last accepted issued_at.
    resp = _make_response(_make_canonical_payload(issued_at="2026-07-16T11:00:00Z"))
    rc, _, _ = _run_verifier(resp, last_version="2026-07-16T12:00:00Z")
    if rc != 0:
        _ok("rollback_rejected")
    else:
        _fail("rollback_rejected", "rollback was accepted")


def test_missing_field_rejected():
    resp = _make_response(_make_canonical_payload())
    del resp["signature"]
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("missing_field_rejected")
    else:
        _fail("missing_field_rejected", "missing-signature response was accepted")


def test_wrong_key_id_rejected():
    resp = _make_response(_make_canonical_payload())
    resp["key_id"] = "ffffffffffffffff"
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("wrong_key_id_rejected")
    else:
        _fail("wrong_key_id_rejected", "wrong key_id was accepted")


def test_wrong_tenant_rejected():
    resp = _make_response(_make_canonical_payload(tenant_id="00000000-0000-0000-0000-000000000000"))
    rc, _, _ = _run_verifier(resp, tenant_id=_TEST_TENANT_ID)
    if rc != 0:
        _ok("wrong_tenant_rejected")
    else:
        _fail("wrong_tenant_rejected", "wrong tenant_id was accepted")


def test_bad_signature_rejected():
    # Well-formed but wrong 64-byte signature; the payload is untouched.
    resp = _make_response(_make_canonical_payload())
    resp["signature"] = base64.b64encode(b"\xff" * 64).decode()
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("bad_signature_rejected")
    else:
        _fail("bad_signature_rejected", "garbage signature was accepted")


def test_empty_tenant_rejected():
    # Empty PATCHED_TENANT_ID is a hard security failure, not a skip.
    resp = _make_response(_make_canonical_payload())
    rc, _, _ = _run_verifier(resp, tenant_id="")
    if rc != 0:
        _ok("empty_tenant_rejected")
    else:
        _fail("empty_tenant_rejected", "empty PATCHED_TENANT_ID was accepted")


def test_same_version_accepted():
    # Re-fetching the same issued_at is idempotent, not a rollback.
    resp = _make_response(_make_canonical_payload(issued_at="2026-07-16T12:00:00Z"))
    rc, _, _ = _run_verifier(resp, last_version="2026-07-16T12:00:00Z")
    if rc == 0:
        _ok("same_version_accepted")
    else:
        _fail("same_version_accepted", f"idempotent same-version rejected (exit {rc})")


def test_version_bump_accepted():
    resp = _make_response(_make_canonical_payload(issued_at="2026-07-16T13:00:00Z"))
    rc, out, _ = _run_verifier(resp, last_version="2026-07-16T12:00:00Z")
    if rc != 0:
        _fail("version_bump_accepted", f"exit {rc}")
    elif '"issued_at"' not in out:
        _fail("version_bump_accepted", "output file missing issued_at")
    else:
        _ok("version_bump_accepted")


def test_missing_issued_at_rejected():
    # No issued_at -> the anti-rollback value is absent -> must reject.
    resp = _make_response(_make_canonical_payload(omit_issued_at=True))
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("missing_issued_at_rejected")
    else:
        _fail("missing_issued_at_rejected", "posture without issued_at was accepted")


def test_cache_floor_lagging_sidecar():
    # The OLD crash window (gate finding, round 3): the cache was committed at
    # T2 but the process died before the sidecar advanced, leaving it at T1.
    # A replayed, validly-signed T1.5 posture must be REJECTED: the effective
    # floor is max(sidecar T1, cached posture T2) = T2.
    cache = _make_canonical_payload(issued_at="2026-07-16T12:00:00Z").decode()   # cache at T2
    resp  = _make_response(_make_canonical_payload(issued_at="2026-07-16T11:30:00Z"))  # replay T1.5
    rc, _, err = _run_verifier(resp,
                               last_version="2026-07-16T11:00:00Z",              # sidecar at T1
                               cache_content=cache)
    if rc != 0 and "anti-rollback" in err:
        _ok("cache_floor_lagging_sidecar")
    else:
        _fail("cache_floor_lagging_sidecar",
              f"replayed T1.5 accepted over cached T2 (rc={rc}); "
              f"effective floor must be max(sidecar, cache)")


def test_floor_ahead_of_cache():
    # The NEW ordering's crash window: the sidecar advanced to T2 but the
    # process died before the cache commit, leaving the cache at T1. This must
    # fail SAFE: a refetch of T2 is accepted (accept-equal restores the cache),
    # while a replayed T1.9 is still rejected.
    cache = _make_canonical_payload(issued_at="2026-07-16T11:00:00Z").decode()   # cache at T1
    resp_t2  = _make_response(_make_canonical_payload(issued_at="2026-07-16T12:00:00Z"))
    rc_t2, _, err_t2 = _run_verifier(resp_t2,
                                     last_version="2026-07-16T12:00:00Z",        # sidecar at T2
                                     cache_content=cache)
    resp_t19 = _make_response(_make_canonical_payload(issued_at="2026-07-16T11:54:00Z"))
    rc_t19, _, _ = _run_verifier(resp_t19,
                                 last_version="2026-07-16T12:00:00Z",
                                 cache_content=cache)
    if rc_t2 != 0:
        _fail("floor_ahead_of_cache",
              f"refetch of T2 rejected (exit {rc_t2}: {err_t2}) — accept-equal must restore the cache")
    elif rc_t19 == 0:
        _fail("floor_ahead_of_cache", "replayed T1.9 accepted despite sidecar floor T2")
    else:
        _ok("floor_ahead_of_cache")


def test_unparseable_cache_defensive():
    # A garbage cache file must not crash the verifier and must not move the
    # floor in EITHER direction: with no sidecar it contributes nothing (fetch
    # accepted, anomaly logged); with a sidecar at T2 it must not lower the
    # floor (older fetch still rejected).
    resp = _make_response(_make_canonical_payload(issued_at="2026-07-16T11:30:00Z"))
    rc_ok, _, err_ok = _run_verifier(resp, cache_content="{ this is not json")
    rc_rej, _, _ = _run_verifier(resp,
                                 last_version="2026-07-16T12:00:00Z",
                                 cache_content="{ this is not json")
    if rc_ok != 0:
        _fail("unparseable_cache_defensive",
              f"verifier crashed/rejected on unparseable cache alone (exit {rc_ok})")
    elif "unparseable" not in err_ok:
        _fail("unparseable_cache_defensive", "anomalous cache parse failure was not logged")
    elif rc_rej == 0:
        _fail("unparseable_cache_defensive",
              "unparseable cache lowered the sidecar floor (older posture accepted)")
    else:
        _ok("unparseable_cache_defensive")


def test_env_override_ignored():
    # Regression for the gate finding on PR #319: the trust anchor must NOT be
    # overrideable via the environment. Run the REAL script directly (no driver)
    # with PATCHED_TEST_PUBKEY_B64 / PATCHED_TEST_KEY_ID pointing at the test
    # key, and a response signed by that test key. The verifier must ignore the
    # env vars, verify against its compiled-in production pinned key, and
    # therefore REJECT.
    resp = _make_response(_make_canonical_payload())
    with tempfile.TemporaryDirectory() as td:
        resp_file = os.path.join(td, "response.json")
        with open(resp_file, "w") as f:
            json.dump(resp, f)
        env = {**os.environ,
               "PATCHED_TENANT_ID":       _TEST_TENANT_ID,
               "PATCHED_TEST_PUBKEY_B64": _TEST_PUBKEY_B64,
               "PATCHED_TEST_KEY_ID":     _TEST_KEY_ID}
        result = subprocess.run(
            [sys.executable, _SCRIPT,
             "--response-file", resp_file,
             "--version-file",  os.path.join(td, "version"),
             "--output-file",   os.path.join(td, "posture.json")],
            capture_output=True, text=True, env=env,
        )
        out_written = os.path.exists(os.path.join(td, "posture.json"))
    if result.returncode != 0 and not out_written:
        _ok("env_override_ignored")
    else:
        _fail("env_override_ignored",
              "verifier honoured PATCHED_TEST_* env vars — trust anchor is overrideable")


def test_crash_ordering_no_version_file_written():
    # Ownership invariant: the verifier writes ONLY the posture output-file.
    # The caller owns the version-file (written and fsynced BEFORE the cache
    # commit, keeping floor >= cached issued_at at every instant); if the
    # verifier ever wrote it, that ordering guarantee would break.
    resp = _make_response(_make_canonical_payload(issued_at="2026-07-16T14:00:00Z"))
    with tempfile.TemporaryDirectory() as td:
        resp_file = os.path.join(td, "response.json")
        ver_file  = os.path.join(td, "version")   # intentionally not pre-created
        out_file  = os.path.join(td, "posture.json")
        with open(resp_file, "w") as f:
            json.dump(resp, f)
        env = {**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID}
        result = subprocess.run(
            _verifier_cmd(resp_file, ver_file, out_file),
            capture_output=True, text=True, env=env,
        )
        out_written     = os.path.exists(out_file)
        version_written = os.path.exists(ver_file)
    if result.returncode != 0:
        _fail("crash_ordering_invariant", f"exit {result.returncode}: {result.stderr}")
    elif not out_written:
        _fail("crash_ordering_invariant", "posture output-file not written")
    elif version_written:
        _fail("crash_ordering_invariant", "verifier wrote version-file (must be the caller's job)")
    else:
        _ok("crash_ordering_invariant")


if __name__ == "__main__":
    print("verify-posture tests")
    test_valid_response()
    test_non_ascii_in_value()
    test_html_special_chars_in_value()
    test_tampered_payload_rejected()
    test_rollback_rejected()
    test_missing_field_rejected()
    test_wrong_key_id_rejected()
    test_wrong_tenant_rejected()
    test_bad_signature_rejected()
    test_empty_tenant_rejected()
    test_same_version_accepted()
    test_version_bump_accepted()
    test_missing_issued_at_rejected()
    test_cache_floor_lagging_sidecar()
    test_floor_ahead_of_cache()
    test_unparseable_cache_defensive()
    test_env_override_ignored()
    test_crash_ordering_no_version_file_written()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    sys.exit(0 if _FAIL == 0 else 1)
