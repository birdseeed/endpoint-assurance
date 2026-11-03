#!/usr/bin/env python3
"""
test-verify-agent-config.py — CI self-test for verify-agent-config.py.

Exercises the full verify-and-cache flow. The test key is injected by
importing verify-agent-config.py as a module in a driver subprocess and
patching its _PINNED_PUBKEY_B64 / _PINNED_KEY_ID constants, the production
verifier has NO environment or CLI override of its trust anchor (gate
finding, PR #319), so tests must go through the import path, which a mere
execution of the script can never reach. No external dependencies, pure
Python 3, same stdlib used by the daemon.

Covers:
  - Valid response: verifier accepts, output file contains the config.
  - Non-ASCII in config values: no escaping needed, round-trips correctly.
  - HTML special chars (<, >, &) in config values: same.
  - Tampered signed_payload: verifier rejects.
  - Rollback attempt: verifier rejects.
  - Missing required field: verifier rejects.
  - Wrong key_id: verifier rejects.
  - Wrong tenant_id: verifier rejects.
  - Env override dead: running the real script with PATCHED_TEST_PUBKEY_B64 /
    PATCHED_TEST_KEY_ID set must still verify against the compiled-in pinned
    key and reject a test-key-signed response.
  - PAT-1756 tenant-keyed anti-rollback floor: same tenant lower rejected,
    higher accepted, another tenant's floor starts fresh, legacy bare integer
    applies to the enrolled tenant, corrupt floor refuses every config, tenant
    binding still runs first, and the WIN-STAGING re-enrolment shape.
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
_SCRIPT = os.path.join(_HERE, "verify-agent-config.py")
_GATE_SCRIPT = os.path.join(_HERE, "patched-legacy-app-execution-gate.py")

_spec = importlib.util.spec_from_file_location("vac", _SCRIPT)
_vac  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vac)

# ── Pure-Python Ed25519 signing (RFC 8032 §5.1) ──────────────────────────────
# Uses the same curve constants as verify-agent-config.py.

_p = _vac._p
_q = _vac._q
_G = _vac._G


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
    pub = _vac._compress(_vac._mul(a, _G))
    r = int.from_bytes(_sha512(prefix + message), "little") % _q
    R_enc = _vac._compress(_vac._mul(r, _G))
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
    return _vac._compress(_vac._mul(a, _G))


# ── Test key ─────────────────────────────────────────────────────────────────

_TEST_SEED    = bytes(range(1, 33))
_TEST_PUBKEY  = _public_key(_TEST_SEED)
_TEST_PUBKEY_B64 = base64.b64encode(_TEST_PUBKEY).decode()

# key_id = first 8 bytes of SHA-256(pubkey) as hex
import hashlib as _hl
_TEST_KEY_ID = _hl.sha256(_TEST_PUBKEY).hexdigest()[:16]

_TEST_TENANT_ID = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"


def _make_canonical_payload(
    tenant_id: str = _TEST_TENANT_ID,
    config_version: int = 1,
    tier: str = "assurance",
    proxy_host: str = "",
    pac_url: str = "",
    extra_field: str = "",
) -> bytes:
    """Build the canonical JSON payload exactly as the Go server does."""
    payload = {
        "catalog_scope":    None,
        "config_version":   config_version,
        "issued_at":        "2026-12-12T00:00:00Z",
        "os_update_policy": None,
        "per_app_patch":    None,
        "proxy": {
            "auth_ref":             None,
            "bypass_when_off_corp": False,
            "host":                 proxy_host if proxy_host else None,
            "mode":                 "system",
            "pac_url":              pac_url if pac_url else None,
            "port":                 None,
            "type":                 None,
        },
        "scan_cadence": None,
        "tenant_id":    tenant_id,
        "tier":         tier,
    }
    if extra_field:
        payload[extra_field] = {"future_nested_field": True}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _make_response(canonical: bytes, tenant_id: str = _TEST_TENANT_ID) -> dict:
    sig = _sign(_TEST_SEED, canonical)
    return {
        "signed_payload": base64.b64encode(canonical).decode(),
        "key_id":         _TEST_KEY_ID,
        "signature":      base64.b64encode(sig).decode(),
    }


# ── Test-key injection driver ────────────────────────────────────────────────
# The verifier's pinned key is a non-overridable constant (no env/CLI override,
# gate finding, PR #319). Tests therefore run the verifier through this driver:
# it imports the script as a module, patches the pinned-key constants on the
# module object, then invokes main(). Production code paths (executing the
# script directly) can never reach this injection point.
_DRIVER = r"""
import importlib.util, sys
script, pub, kid = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("vac_under_test", script)
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod._PINNED_PUBKEY_B64 = pub
mod._PINNED_KEY_ID     = kid
sys.argv = [script] + sys.argv[4:]
mod.main()
"""

_GATE_DRIVER = r"""
import importlib.util, os, sys, types
spec = importlib.util.spec_from_file_location("gate_under_test", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
real_fstat = mod.os.fstat
def root_fstat(fd):
    metadata = real_fstat(fd)
    return types.SimpleNamespace(
        st_mode=metadata.st_mode, st_uid=0, st_mtime=metadata.st_mtime)
mod.os.fstat = root_fstat
sys.argv = [sys.argv[1]] + sys.argv[2:]
raise SystemExit(mod.main())
"""


def _verifier_cmd(resp_file: str, ver_file: str, out_file: str,
                  current_file: str = None,
                  current_digest_file: str = None) -> list[str]:
    if current_file is None:
        current_file = out_file
    if current_digest_file is None:
        current_digest_file = os.path.join(
            os.path.dirname(current_file), "agent-config.sha256"
        )
    return [sys.executable, "-c", _DRIVER,
            _SCRIPT, _TEST_PUBKEY_B64, _TEST_KEY_ID,
            "--response-file", resp_file,
            "--version-file",  ver_file,
            "--current-config-file", current_file,
            "--current-config-sha256-file", current_digest_file,
            "--execution-denial-file",
            os.path.join(os.path.dirname(out_file), "agent-config.execution-denied"),
            "--output-file",   out_file,
            "--execution-denial-output-file", out_file + ".execution-denial"]


def _write_current_config(path: str, config: dict) -> None:
    raw = json.dumps(config, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(raw)
    with open(os.path.join(os.path.dirname(path), "agent-config.sha256"), "w") as fh:
        fh.write(hashlib.sha256(raw).hexdigest())


def _run_verifier(response: dict, tenant_id: str = _TEST_TENANT_ID,
                  last_version: int = 0,
                  denied_version=None,
                  floor_content=None,
                  denial_document=None) -> tuple[int, str, str]:
    """Run the verifier (test key injected via module import) and return
    (returncode, stdout+output, stderr)."""
    with tempfile.TemporaryDirectory() as td:
        resp_file = os.path.join(td, "response.json")
        ver_file  = os.path.join(td, "version")
        out_file  = os.path.join(td, "agent-config.json")

        with open(resp_file, "w") as f:
            json.dump(response, f)
        if floor_content is not None:
            with open(ver_file, "wb") as f:
                f.write(floor_content if isinstance(floor_content, bytes)
                        else floor_content.encode("utf-8"))
        elif last_version:
            with open(ver_file, "w") as f:
                f.write(str(last_version))
        if denied_version is not None:
            with open(os.path.join(td, "agent-config.execution-denied"), "w") as f:
                json.dump({"config_version": denied_version}, f)
        if denial_document is not None:
            with open(os.path.join(td, "agent-config.execution-denied"), "w") as f:
                f.write(denial_document if isinstance(denial_document, str)
                        else json.dumps(denial_document))

        env = {**os.environ, "PATCHED_TENANT_ID": tenant_id}
        result = subprocess.run(
            _verifier_cmd(resp_file, ver_file, out_file),
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
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
    rc, out, err = _run_verifier(resp)
    if rc != 0:
        _fail("valid_response", f"exit {rc}: {err}")
    elif '"tier"' not in out:
        _fail("valid_response", "output file missing tier field")
    else:
        _ok("valid_response")


def test_non_ascii_in_value():
    # Japanese chars in a pac_url — no HTML escaping; server returns raw UTF-8.
    canonical = _make_canonical_payload(pac_url="http://プロキシ.example/wpad.dat")
    resp      = _make_response(canonical)
    rc, out, _ = _run_verifier(resp)
    if rc != 0:
        _fail("non_ascii_in_value", f"exit {rc}")
    elif "プロキシ" not in out:
        _fail("non_ascii_in_value", "non-ASCII chars lost in output")
    else:
        _ok("non_ascii_in_value")


def test_html_special_chars_in_value():
    # & < > in a proxy host — Go HTML-escapes these in JSON, but the client
    # verifies the raw server bytes and never reconstructs — so this just works.
    canonical = _make_canonical_payload(proxy_host="a&b<c>d.corp.example")
    resp      = _make_response(canonical)
    rc, _, _ = _run_verifier(resp)
    if rc == 0:
        _ok("html_special_chars_in_value")
    else:
        _fail("html_special_chars_in_value", "verifier rejected valid special-char config")


def test_forward_compatible_field_accepted():
    canonical = _make_canonical_payload(extra_field="future_policy")
    rc, out, _ = _run_verifier(_make_response(canonical))
    if rc != 0 or '"future_policy"' not in out:
        _fail("forward_compatible_field_accepted", "valid unknown field was rejected or lost")
    else:
        _ok("forward_compatible_field_accepted")


def _assert_payload_rejected_without_replacing_cache(name: str, payload: bytes) -> None:
    """A signed but ambiguous payload must leave the previous cache untouched."""
    response = _make_response(payload)
    with tempfile.TemporaryDirectory() as td:
        resp_file = os.path.join(td, "response.json")
        ver_file = os.path.join(td, "version")
        out_file = os.path.join(td, "agent-config.json")
        marker = b'{"last_known_good":true}\n'
        with open(resp_file, "w") as fh:
            json.dump(response, fh)
        with open(out_file, "wb") as fh:
            fh.write(marker)
        result = subprocess.run(
            _verifier_cmd(resp_file, ver_file, out_file), capture_output=True,
            text=True, env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
        )
        unchanged = open(out_file, "rb").read() == marker
    if result.returncode != 0 and unchanged:
        _ok(name)
    else:
        _fail(name, "ambiguous signed payload was accepted or replaced the cache")


def test_ambiguous_payload_keys_rejected_without_cache_replacement():
    base = f'"tenant_id":"{_TEST_TENANT_ID}","config_version":1'
    cases = {
        "exact_duplicate_payload_key_rejected":
            ("{" + base + ',"tier":"one","tier":"two"}').encode(),
        "case_collision_payload_key_first_order_rejected":
            ("{" + base + ',"tier":"one","TIER":"two"}').encode(),
        "case_collision_payload_key_second_order_rejected":
            ("{" + base + ',"TIER":"one","tier":"two"}').encode(),
        "nested_exact_duplicate_payload_key_rejected":
            ("{" + base + ',"future":{"key":1,"key":2}}').encode(),
        "nested_case_collision_payload_key_rejected":
            ("{" + base + ',"future":{"key":1,"KEY":2}}').encode(),
        "unicode_casefold_collision_payload_key_rejected":
            ("{" + base + ',"future":{"Straße":1,"STRASSE":2}}').encode(),
    }
    for name, payload in cases.items():
        _assert_payload_rejected_without_replacing_cache(name, payload)


def test_authenticated_newer_revocation_has_distinct_rejection():
    """Reviewer reproduction: old grant, signed newer revoke, nested collision."""
    payload = (
        "{"
        f'"tenant_id":"{_TEST_TENANT_ID}",'
        '"config_version":2,'
        '"legacy_app_execution_enabled":false,'
        '"app_control_authority":"report",'
        '"unrelated":{"key":1,"KEY":2}'
        "}"
    ).encode()
    response = _make_response(payload)
    with tempfile.TemporaryDirectory() as td:
        response_file = os.path.join(td, "response.json")
        version_file = os.path.join(td, "version")
        output_file = os.path.join(td, "agent-config.json")
        old_grant = b'{"config_version":1,"legacy_app_execution_enabled":true,"app_control_authority":"enforce"}\n'
        with open(response_file, "w") as fh:
            json.dump(response, fh)
        with open(version_file, "w") as fh:
            fh.write("1")
        with open(output_file, "wb") as fh:
            fh.write(old_grant)
        digest_file = os.path.join(td, "agent-config.sha256")
        heartbeat_file = os.path.join(td, "agent-config.checked")
        credentials_dir = os.path.join(td, "credentials")
        os.mkdir(credentials_dir)
        with open(digest_file, "w") as fh:
            fh.write(hashlib.sha256(old_grant).hexdigest())
        open(heartbeat_file, "w").close()
        result = subprocess.run(
            _verifier_cmd(response_file, version_file, output_file),
            capture_output=True, text=True,
            env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
        )
        unchanged = open(output_file, "rb").read() == old_grant
        denial_file = output_file + ".execution-denial"
        denial_version = json.load(open(denial_file)).get("config_version")
        os.replace(denial_file, os.path.join(td, "agent-config.execution-denied"))
        gate_result = subprocess.run(
            [sys.executable, "-c", _GATE_DRIVER, _GATE_SCRIPT,
             output_file, digest_file, heartbeat_file,
             os.path.join(credentials_dir, "suspended")],
            capture_output=True, text=True,
        )

        # The same bytes with a bad signature are unauthenticated and must use
        # the ordinary rejection code, never the state-changing signal.
        os.unlink(os.path.join(td, "agent-config.execution-denied"))
        response["signature"] = base64.b64encode(b"\xff" * 64).decode()
        with open(response_file, "w") as fh:
            json.dump(response, fh)
        unauthenticated = subprocess.run(
            _verifier_cmd(response_file, version_file, output_file),
            capture_output=True, text=True,
            env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
        )

        unauthenticated_denial_absent = not os.path.exists(denial_file)

    if (result.returncode == _vac.AUTHENTICATED_EXECUTION_REVOCATION_EXIT
            and unchanged and denial_version == 2
            and gate_result.returncode == 1
            and unauthenticated.returncode == 1
            and unauthenticated_denial_absent):
        _ok("authenticated_newer_revocation_has_distinct_rejection")
    else:
        _fail(
            "authenticated_newer_revocation_has_distinct_rejection",
            f"authenticated rc={result.returncode}, unchanged={unchanged}, "
            f"denial_version={denial_version}, "
            f"gate_rc={gate_result.returncode}, "
            f"unauthenticated rc={unauthenticated.returncode}, "
            f"unauthenticated_denial_absent={unauthenticated_denial_absent}",
        )


def test_authenticated_rejections_publish_independent_authority_floors():
    cases = (
        (
            "legacy_revoke_with_app_control_still_enforced",
            '"legacy_app_execution_enabled":false,',
            '"app_control_authority":"enforce",',
            _vac.LEGACY_REVOCATION_FLOOR_KEY,
        ),
        (
            "app_control_revoke_with_legacy_still_enabled",
            '"legacy_app_execution_enabled":true,',
            '"app_control_authority":"report",',
            _vac.APP_CONTROL_REVOCATION_FLOOR_KEY,
        ),
        (
            "destructive_app_control_revoke_to_block",
            '"legacy_app_execution_enabled":true,',
            '"app_control_authority":"block",',
            _vac.APP_CONTROL_REVOCATION_FLOOR_KEY,
        ),
    )
    failures = []
    for name, legacy_field, app_control_field, expected_floor in cases:
        payload = (
            "{"
            f'"tenant_id":"{_TEST_TENANT_ID}",'
            '"config_version":2,'
            + legacy_field
            + app_control_field
            + '"unrelated":{"key":1,"KEY":2}'
            + "}"
        ).encode()
        with tempfile.TemporaryDirectory() as td:
            response_file = os.path.join(td, "response.json")
            version_file = os.path.join(td, "version")
            current_file = os.path.join(td, "agent-config.json")
            output_file = os.path.join(td, "verified.tmp")
            with open(response_file, "w") as fh:
                json.dump(_make_response(payload), fh)
            with open(version_file, "w") as fh:
                fh.write("1")
            current = {
                "config_version": 1,
                "legacy_app_execution_enabled": True,
                "app_control_authority": "enforce",
            }
            _write_current_config(current_file, current)
            result = subprocess.run(
                _verifier_cmd(
                    response_file, version_file, output_file, current_file
                ),
                capture_output=True,
                text=True,
                env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
            )
            denial_path = output_file + ".execution-denial"
            denial = json.load(open(denial_path)) if os.path.exists(denial_path) else {}
        other_floor = (
            _vac.APP_CONTROL_REVOCATION_FLOOR_KEY
            if expected_floor == _vac.LEGACY_REVOCATION_FLOOR_KEY
            else _vac.LEGACY_REVOCATION_FLOOR_KEY
        )
        if not (
            result.returncode == _vac.AUTHENTICATED_EXECUTION_REVOCATION_EXIT
            and denial.get("config_version") == 2
            and denial.get(expected_floor) == 2
            and other_floor not in denial
            # PAT-1763: keyed to the tenant whose signed policy revoked it.
            and denial.get("tenant_id") == _TEST_TENANT_ID
        ):
            failures.append(
                f"{name}: rc={result.returncode}, denial={denial!r}"
            )
    if failures:
        _fail(
            "authenticated_rejections_publish_independent_authority_floors",
            "; ".join(failures),
        )
    else:
        _ok("authenticated_rejections_publish_independent_authority_floors")


def test_missing_or_ambiguous_revocation_data_does_not_publish_denial():
    payloads = (
        (
            "missing authority field",
            (
                "{"
                f'"tenant_id":"{_TEST_TENANT_ID}",'
                '"config_version":2,'
                '"app_control_authority":"enforce",'
                '"unrelated":{"key":1,"KEY":2}'
                "}"
            ).encode(),
        ),
        (
            "ambiguous authority field",
            (
                "{"
                f'"tenant_id":"{_TEST_TENANT_ID}",'
                '"config_version":2,'
                '"legacy_app_execution_enabled":false,'
                '"LEGACY_APP_EXECUTION_ENABLED":true,'
                '"app_control_authority":"enforce"'
                "}"
            ).encode(),
        ),
    )
    failures = []
    for description, payload in payloads:
        with tempfile.TemporaryDirectory() as td:
            response_file = os.path.join(td, "response.json")
            version_file = os.path.join(td, "version")
            current_file = os.path.join(td, "agent-config.json")
            output_file = os.path.join(td, "verified.tmp")
            with open(response_file, "w") as fh:
                json.dump(_make_response(payload), fh)
            with open(version_file, "w") as fh:
                fh.write("1")
            _write_current_config(current_file, {
                "config_version": 1,
                "legacy_app_execution_enabled": True,
                "app_control_authority": "enforce",
            })
            result = subprocess.run(
                _verifier_cmd(
                    response_file, version_file, output_file, current_file
                ),
                capture_output=True,
                text=True,
                env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
            )
            denial_exists = os.path.exists(output_file + ".execution-denial")
        if result.returncode != 1 or denial_exists:
            failures.append(
                f"{description}: rc={result.returncode}, denial={denial_exists}"
            )
    if failures:
        _fail(
            "missing_or_ambiguous_revocation_data_does_not_publish_denial",
            "; ".join(failures),
        )
    else:
        _ok("missing_or_ambiguous_revocation_data_does_not_publish_denial")


def test_per_authority_floor_blocks_conflicting_same_version_grant():
    cases = (
        (
            "legacy",
            False,
            "enforce",
            True,
            "report",
            _vac.LEGACY_REVOCATION_FLOOR_KEY,
        ),
        (
            "app_control",
            True,
            "report",
            False,
            "enforce",
            _vac.APP_CONTROL_REVOCATION_FLOOR_KEY,
        ),
    )
    failures = []
    for (name, rejected_legacy, rejected_app, conflicting_legacy,
         conflicting_app, expected_floor) in cases:
        with tempfile.TemporaryDirectory() as td:
            response_file = os.path.join(td, "response.json")
            version_file = os.path.join(td, "version")
            current_file = os.path.join(td, "agent-config.json")
            output_file = os.path.join(td, "verified.tmp")
            denial_file = os.path.join(td, "agent-config.execution-denied")
            with open(version_file, "w") as fh:
                fh.write("1")
            _write_current_config(current_file, {
                "config_version": 1,
                "legacy_app_execution_enabled": True,
                "app_control_authority": "enforce",
            })

            rejected_payload = (
                "{"
                f'"tenant_id":"{_TEST_TENANT_ID}",'
                '"config_version":2,'
                f'"legacy_app_execution_enabled":{str(rejected_legacy).lower()},'
                f'"app_control_authority":"{rejected_app}",'
                '"unrelated":{"key":1,"KEY":2}'
                "}"
            ).encode()
            with open(response_file, "w") as fh:
                json.dump(_make_response(rejected_payload), fh)
            rejected = subprocess.run(
                _verifier_cmd(
                    response_file, version_file, output_file, current_file
                ),
                capture_output=True,
                text=True,
                env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
            )
            if os.path.exists(output_file + ".execution-denial"):
                os.replace(output_file + ".execution-denial", denial_file)

            full_denial = json.loads(_make_canonical_payload(config_version=2))
            full_denial["legacy_app_execution_enabled"] = False
            full_denial["app_control_authority"] = "report"
            full_denial_bytes = json.dumps(
                full_denial, separators=(",", ":")
            ).encode()
            with open(response_file, "w") as fh:
                json.dump(_make_response(full_denial_bytes), fh)
            accepted = subprocess.run(
                _verifier_cmd(
                    response_file, version_file, output_file, current_file
                ),
                capture_output=True,
                text=True,
                env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
            )
            if accepted.returncode == 0:
                os.replace(output_file, current_file)
                with open(current_file, "rb") as fh:
                    committed = fh.read()
                with open(os.path.join(td, "agent-config.sha256"), "w") as fh:
                    fh.write(hashlib.sha256(committed).hexdigest())
                with open(version_file, "w") as fh:
                    fh.write("2")

            conflicting = json.loads(full_denial_bytes)
            conflicting["legacy_app_execution_enabled"] = conflicting_legacy
            conflicting["app_control_authority"] = conflicting_app
            conflicting_bytes = json.dumps(
                conflicting, separators=(",", ":")
            ).encode()
            with open(response_file, "w") as fh:
                json.dump(_make_response(conflicting_bytes), fh)
            conflict = subprocess.run(
                _verifier_cmd(
                    response_file, version_file, output_file, current_file
                ),
                capture_output=True,
                text=True,
                env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
            )
            marker = json.load(open(denial_file)) if os.path.exists(denial_file) else {}

        if not (
            rejected.returncode == _vac.AUTHENTICATED_EXECUTION_REVOCATION_EXIT
            and accepted.returncode == 0
            and marker.get(expected_floor) == 2
            and conflict.returncode == 1
            and "same-version execution grant" in conflict.stderr
        ):
            failures.append(
                f"{name}: rejected={rejected.returncode}, "
                f"accepted={accepted.returncode}, marker={marker!r}, "
                f"conflict={conflict.returncode}"
            )
    if failures:
        _fail(
            "per_authority_floor_blocks_conflicting_same_version_grant",
            "; ".join(failures),
        )
    else:
        _ok("per_authority_floor_blocks_conflicting_same_version_grant")


def test_tampered_payload_rejected():
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
    # Flip a byte in the decoded signed_payload before re-encoding.
    raw = bytearray(base64.b64decode(resp["signed_payload"]))
    raw[0] ^= 0xFF
    resp["signed_payload"] = base64.b64encode(bytes(raw)).decode()
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("tampered_payload_rejected")
    else:
        _fail("tampered_payload_rejected", "tampered payload was accepted")


def test_rollback_rejected():
    canonical = _make_canonical_payload(config_version=3)
    resp      = _make_response(canonical)
    rc, _, _ = _run_verifier(resp, last_version=5)
    if rc != 0:
        _ok("rollback_rejected")
    else:
        _fail("rollback_rejected", "rollback was accepted")


def test_missing_field_rejected():
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
    del resp["signature"]
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("missing_field_rejected")
    else:
        _fail("missing_field_rejected", "missing-signature response was accepted")


def test_wrong_key_id_rejected():
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
    resp["key_id"] = "ffffffffffffffff"
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("wrong_key_id_rejected")
    else:
        _fail("wrong_key_id_rejected", "wrong key_id was accepted")


def test_wrong_tenant_rejected():
    canonical = _make_canonical_payload(tenant_id="wrong-tenant-id")
    resp      = _make_response(canonical)
    rc, _, _ = _run_verifier(resp, tenant_id=_TEST_TENANT_ID)
    if rc != 0:
        _ok("wrong_tenant_rejected")
    else:
        _fail("wrong_tenant_rejected", "wrong tenant_id was accepted")


def test_bad_signature_rejected():
    # A well-formed but wrong 64-byte signature must be rejected (distinct from
    # tampering the payload — here the payload is untouched, the sig is garbage).
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
    resp["signature"] = base64.b64encode(b"\xff" * 64).decode()
    rc, _, _ = _run_verifier(resp)
    if rc != 0:
        _ok("bad_signature_rejected")
    else:
        _fail("bad_signature_rejected", "garbage signature was accepted")


def test_empty_tenant_rejected():
    # Empty PATCHED_TENANT_ID is a hard security failure, not a skip — the
    # tenant binding cannot be verified, so the config must be rejected.
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
    rc, _, _ = _run_verifier(resp, tenant_id="")
    if rc != 0:
        _ok("empty_tenant_rejected")
    else:
        _fail("empty_tenant_rejected", "empty PATCHED_TENANT_ID was accepted")


def test_same_version_accepted():
    # Re-fetching the same config_version is idempotent, not a rollback.
    canonical = _make_canonical_payload(config_version=3)
    resp      = _make_response(canonical)
    rc, _, _ = _run_verifier(resp, last_version=3)
    if rc == 0:
        _ok("same_version_accepted")
    else:
        _fail("same_version_accepted", f"idempotent same-version rejected (exit {rc})")


def test_denial_floor_requires_newer_version_for_either_authority():
    cases = (
        (7, False, "report", 0, "same-version full denial clears"),
        (7, True, "report", 1, "same-version legacy grant rejected"),
        (7, False, "enforce", 1, "same-version App Control grant rejected"),
        (8, True, "report", 0, "newer legacy grant accepted"),
        (8, False, "enforce", 0, "newer App Control grant accepted"),
    )
    failures = []
    for version, legacy, authority, expected_rc, description in cases:
        payload = json.loads(_make_canonical_payload(config_version=version))
        payload["legacy_app_execution_enabled"] = legacy
        payload["app_control_authority"] = authority
        canonical = json.dumps(payload, separators=(",", ":")).encode()
        rc, _, _ = _run_verifier(
            _make_response(canonical), denied_version=7
        )
        if (rc == 0) != (expected_rc == 0):
            failures.append(f"{description}: exit {rc}")
    if failures:
        _fail(
            "denial_floor_requires_newer_version_for_either_authority",
            "; ".join(failures),
        )
    else:
        _ok("denial_floor_requires_newer_version_for_either_authority")


def test_execution_denial_file_is_bounded():
    canonical = _make_canonical_payload(config_version=3)
    with tempfile.TemporaryDirectory() as td:
        response_file = os.path.join(td, "response.json")
        version_file = os.path.join(td, "version")
        output_file = os.path.join(td, "agent-config.json")
        denial_file = os.path.join(td, "agent-config.execution-denied")
        with open(response_file, "w") as fh:
            json.dump(_make_response(canonical), fh)
        with open(version_file, "w") as fh:
            fh.write("1")
        with open(denial_file, "wb") as fh:
            fh.write(b'{"config_version":2,"padding":"')
            fh.write(b"A" * _vac.MAX_EXECUTION_DENIAL_BYTES)
            fh.write(b'"}')
        result = subprocess.run(
            _verifier_cmd(response_file, version_file, output_file),
            capture_output=True,
            text=True,
            env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
        )
        output_exists = os.path.exists(output_file)
    if (result.returncode == 1 and not output_exists
            and "exceeds" in result.stderr):
        _ok("execution_denial_file_is_bounded")
    else:
        _fail(
            "execution_denial_file_is_bounded",
            f"rc={result.returncode}, output={output_exists}, "
            f"stderr={result.stderr!r}",
        )


def test_version_bump_accepted():
    canonical = _make_canonical_payload(config_version=4)
    resp      = _make_response(canonical)
    rc, out, _ = _run_verifier(resp, last_version=3)
    if rc != 0:
        _fail("version_bump_accepted", f"exit {rc}")
    elif '"config_version"' not in out:
        _fail("version_bump_accepted", "output file missing config_version")
    else:
        _ok("version_bump_accepted")


def test_large_config_version_accepted():
    # config_version is a plain JSON int — values past 2^31 must round-trip.
    canonical = _make_canonical_payload(config_version=2**31)
    resp      = _make_response(canonical)
    rc, _, _ = _run_verifier(resp)
    if rc == 0:
        _ok("large_config_version_accepted")
    else:
        _fail("large_config_version_accepted", f"large config_version rejected (exit {rc})")


def test_env_override_ignored():
    # Regression for the gate finding on PR #319: the trust anchor must NOT be
    # overrideable via the environment. Run the REAL script directly (no
    # driver) with PATCHED_TEST_PUBKEY_B64 / PATCHED_TEST_KEY_ID pointing at
    # the test key, and a response signed by that test key. The verifier must
    # ignore the env vars, verify against its compiled-in production pinned
    # key, and therefore REJECT.
    canonical = _make_canonical_payload()
    resp      = _make_response(canonical)
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
             "--output-file",   os.path.join(td, "agent-config.json")],
            capture_output=True, text=True, env=env,
        )
        out_written = os.path.exists(os.path.join(td, "agent-config.json"))
    if result.returncode != 0 and not out_written:
        _ok("env_override_ignored")
    else:
        _fail("env_override_ignored",
              "verifier honoured PATCHED_TEST_* env vars, trust anchor is overrideable")


def test_crash_ordering_no_version_file_written():
    # Crash-ordering invariant: the verifier writes ONLY the config output-file.
    # The caller (patched-fetch-config.sh) writes the version-file AFTER the
    # atomic mv, so config and version can never diverge across a crash. If the
    # verifier ever wrote the version-file itself, that guarantee would break.
    canonical = _make_canonical_payload(config_version=7)
    resp      = _make_response(canonical)
    with tempfile.TemporaryDirectory() as td:
        resp_file = os.path.join(td, "response.json")
        ver_file  = os.path.join(td, "version")   # intentionally not pre-created
        out_file  = os.path.join(td, "agent-config.json")
        with open(resp_file, "w") as f:
            json.dump(resp, f)
        env = {**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID}
        result = subprocess.run(
            _verifier_cmd(resp_file, ver_file, out_file),
            capture_output=True, text=True, env=env,
        )
        # Capture existence inside the block — the tempdir is deleted on exit.
        out_written     = os.path.exists(out_file)
        version_written = os.path.exists(ver_file)
    if result.returncode != 0:
        _fail("crash_ordering_invariant", f"exit {result.returncode}: {result.stderr}")
    elif not out_written:
        _fail("crash_ordering_invariant", "config output-file not written")
    elif version_written:
        _fail("crash_ordering_invariant", "verifier wrote version-file (must be the caller's job)")
    else:
        _ok("crash_ordering_invariant")


# ── PAT-1756: tenant-keyed anti-rollback floor ───────────────────────────────

_OTHER_TENANT_ID = "b1ffcd00-0000-4000-8000-000000000002"


def _keyed_floor(tenant_id: str, version: int) -> str:
    return json.dumps({"tenant_id": tenant_id, "config_version": version},
                      separators=(",", ":"))


def test_floor_same_tenant_lower_version_rejected():
    resp = _make_response(_make_canonical_payload(config_version=3))
    rc, out, err = _run_verifier(resp, floor_content=_keyed_floor(_TEST_TENANT_ID, 12))
    if (rc == 1 and '"config_version"' not in out
            and f"new version 3 < trusted floor 12 for tenant {_TEST_TENANT_ID}" in err
            and "\u2014" not in err):
        _ok("floor_same_tenant_lower_version_rejected")
    else:
        _fail("floor_same_tenant_lower_version_rejected", f"rc={rc} err={err!r}")


def test_floor_same_tenant_higher_version_accepted():
    resp = _make_response(_make_canonical_payload(config_version=13))
    rc, out, err = _run_verifier(resp, floor_content=_keyed_floor(_TEST_TENANT_ID, 12))
    if rc == 0 and f"version 13 >= trusted floor 12 for tenant {_TEST_TENANT_ID}" in out:
        _ok("floor_same_tenant_higher_version_accepted")
    else:
        _fail("floor_same_tenant_higher_version_accepted", f"rc={rc} out={out!r} err={err!r}")


def test_floor_other_tenant_lower_version_accepted_as_fresh_floor():
    resp = _make_response(_make_canonical_payload(config_version=3))
    rc, out, err = _run_verifier(resp, floor_content=_keyed_floor(_OTHER_TENANT_ID, 12))
    if (rc == 0 and f"stored floor belongs to tenant {_OTHER_TENANT_ID} (version 12)" in out
            and f"tenant {_TEST_TENANT_ID} starts a fresh floor" in out):
        _ok("floor_other_tenant_lower_version_accepted_as_fresh_floor")
    else:
        _fail("floor_other_tenant_lower_version_accepted_as_fresh_floor",
              f"rc={rc} out={out!r} err={err!r}")


def test_floor_legacy_integer_applies_to_enrolled_tenant():
    lower = _run_verifier(_make_response(_make_canonical_payload(config_version=3)),
                          floor_content="12\n")
    higher = _run_verifier(_make_response(_make_canonical_payload(config_version=13)),
                           floor_content="12\n")
    if (lower[0] == 1 and "legacy floor 12, applied to the enrolled tenant" in lower[2]
            and higher[0] == 0):
        _ok("floor_legacy_integer_applies_to_enrolled_tenant")
    else:
        _fail("floor_legacy_integer_applies_to_enrolled_tenant",
              f"lower={lower[0]} {lower[2]!r} higher={higher[0]} {higher[2]!r}")


_CORRUPT_FLOORS = [
    "", "   \n", "-1", "12abc", "[12]", "garbage",
    '{"tenant_id":"%s"}' % _TEST_TENANT_ID,
    '{"config_version":3}',
    '{"tenant_id":"","config_version":3}',
    '{"tenant_id":"%s","config_version":-3}' % _TEST_TENANT_ID,
    '{"tenant_id":"%s","config_version":"3"}' % _TEST_TENANT_ID,
    '{"tenant_id":"%s","config_version":true}' % _TEST_TENANT_ID,
    '{"tenant_id":"%s","config_version":3,"extra":1}' % _TEST_TENANT_ID,
    '{"tenant_id":"%s","tenant_id":"x","config_version":3}' % _TEST_TENANT_ID,
    '{"tenant_id":"x","tenant_id":"%s","config_version":3}' % _TEST_TENANT_ID,
    '{"tenant_id":"%s","config_version":3,"config_version":9}' % _TEST_TENANT_ID,
    '{"Tenant_ID":"x","tenant_id":"%s","config_version":3}' % _TEST_TENANT_ID,
    '{"tenant_id":"%s","config_version":3.0}' % _TEST_TENANT_ID,
    '{"tenant_id":["%s"],"config_version":3}' % _TEST_TENANT_ID,
    '{"tenant_id":7,"config_version":3}',
    '{"tenant_id":"%s","config_version":3' % _TEST_TENANT_ID,
    " " * 4096 + "12",
    b"1\xff2",
]


def test_floor_corrupt_rejects_every_version():
    failures = []
    for content in _CORRUPT_FLOORS:
        rc, out, err = _run_verifier(
            _make_response(_make_canonical_payload(config_version=1000)),
            floor_content=content,
        )
        if (rc != 1 or '"config_version"' in out
                or "stored floor is unusable" not in err
                or f"tenant {_TEST_TENANT_ID}" not in err):
            failures.append(f"{content!r}: rc={rc} err={err!r}")
    if failures:
        _fail("floor_corrupt_rejects_every_version", "; ".join(failures))
    else:
        _ok("floor_corrupt_rejects_every_version")


def test_floor_reader_classification():
    cases = [
        (None, ("absent", None, 0)),
        ("12", ("legacy", None, 12)),
        (_keyed_floor(_TEST_TENANT_ID, 12), ("keyed", _TEST_TENANT_ID, 12)),
        (_keyed_floor(_OTHER_TENANT_ID, 2**31), ("keyed", _OTHER_TENANT_ID, 2**31)),
    ] + [(content, "corrupt") for content in _CORRUPT_FLOORS]
    failures = []
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "agent-config.version")
        for content, expected in cases:
            if os.path.exists(path):
                os.remove(path)
            if content is not None:
                with open(path, "wb") as fh:
                    fh.write(content if isinstance(content, bytes) else content.encode())
            got = _vac._read_rollback_floor(path)
            if expected == "corrupt":
                if got[0] != "corrupt":
                    failures.append(f"{content!r} -> {got!r}")
            elif got != expected:
                failures.append(f"{content!r} -> {got!r}, expected {expected!r}")
    if failures:
        _fail("floor_reader_classification", "; ".join(failures))
    else:
        _ok("floor_reader_classification")


def test_floor_never_admits_config_for_another_tenant():
    # A signed config for a tenant this device is not enrolled in must still be
    # rejected, even when a floor keyed to that tenant would allow it.
    payload = _make_canonical_payload(tenant_id=_OTHER_TENANT_ID, config_version=50)
    rc, out, err = _run_verifier(_make_response(payload),
                                 floor_content=_keyed_floor(_OTHER_TENANT_ID, 1))
    if (rc == 1 and '"config_version"' not in out
            and "tenant_id in signed_payload does not match" in err
            and "anti-rollback" not in err):
        _ok("floor_never_admits_config_for_another_tenant")
    else:
        _fail("floor_never_admits_config_for_another_tenant", f"rc={rc} err={err!r}")


def test_floor_tenant_binding_runs_before_corrupt_floor():
    payload = _make_canonical_payload(tenant_id=_OTHER_TENANT_ID, config_version=5)
    rc, _, err = _run_verifier(_make_response(payload), floor_content="garbage")
    if rc == 1 and "tenant_id in signed_payload does not match" in err and "anti-rollback" not in err:
        _ok("floor_tenant_binding_runs_before_corrupt_floor")
    else:
        _fail("floor_tenant_binding_runs_before_corrupt_floor", f"rc={rc} err={err!r}")


def test_floor_win_staging_reenrolment_shape():
    # A bare 12 left by the previous tenant rejects the new tenant's version 3
    # (the defect). patched-enroll.sh removes the floor on a successful
    # enrolment, after which the same signed config is accepted.
    resp = _make_response(_make_canonical_payload(config_version=3))
    before = _run_verifier(resp, floor_content="12")
    after = _run_verifier(resp)  # no floor file: what enrolment leaves behind
    if before[0] == 1 and after[0] == 0:
        _ok("floor_win_staging_reenrolment_shape")
    else:
        _fail("floor_win_staging_reenrolment_shape",
              f"before={before[0]} {before[2]!r} after={after[0]} {after[2]!r}")


# ── Execution-denial marker keyed by tenant (PAT-1763) ──────────────────────

_OTHER_TENANT_ID = "b1ffcd00-0d1c-4ef8-bb6d-6bb9bd380a22"


def _denial(tenant, version, include_tenant=True):
    document = {
        "config_version": version,
        _vac.LEGACY_REVOCATION_FLOOR_KEY: version,
        _vac.APP_CONTROL_REVOCATION_FLOOR_KEY: version,
    }
    if include_tenant:
        document["tenant_id"] = tenant
    return document


def test_denial_marker_from_another_tenant_does_not_reject_a_new_tenant():
    """The tenant-switch defect: another tenant's marker at version 50 used to
    reject every config for the new tenant whose versions start low."""
    rc, out, err = _run_verifier(
        _make_response(_make_canonical_payload(config_version=3)),
        denial_document=_denial(_OTHER_TENANT_ID, 50),
    )
    if rc == 0 and f"belongs to tenant {_OTHER_TENANT_ID}" in out:
        _ok("denial_marker_from_another_tenant_does_not_reject_a_new_tenant")
    else:
        _fail("denial_marker_from_another_tenant_does_not_reject_a_new_tenant",
              f"rc={rc}, out={out[:300]!r}, err={err!r}")


def test_denial_marker_still_applies_to_the_tenant_it_came_from():
    rc, _, err = _run_verifier(
        _make_response(_make_canonical_payload(config_version=3)),
        denial_document=_denial(_TEST_TENANT_ID, 50),
    )
    same_version_payload = json.loads(_make_canonical_payload(config_version=50))
    same_version_payload["legacy_app_execution_enabled"] = True
    same_rc, _, same_err = _run_verifier(
        _make_response(json.dumps(same_version_payload, separators=(",", ":")).encode()),
        denial_document=_denial(_TEST_TENANT_ID, 50),
    )
    other_same_rc, _, _ = _run_verifier(
        _make_response(json.dumps(same_version_payload, separators=(",", ":")).encode()),
        denial_document=_denial(_OTHER_TENANT_ID, 50),
    )
    if (rc == 1 and "anti-rollback" in err and "trusted floor 50" in err
            and same_rc == 1 and "same-version execution grant conflicts" in same_err
            and other_same_rc == 0):
        _ok("denial_marker_still_applies_to_the_tenant_it_came_from")
    else:
        _fail("denial_marker_still_applies_to_the_tenant_it_came_from",
              f"rc={rc}, err={err!r}, same_rc={same_rc}, same_err={same_err!r}, "
              f"other_same_rc={other_same_rc}")


def test_legacy_denial_marker_is_attributed_to_the_enrolled_tenant():
    """A marker written before PAT-1763 has no tenant_id. It keeps failing
    closed for whichever tenant is enrolled, like a legacy floor."""
    failures = []
    for name, document in (
        ("original single-version marker", {"config_version": 50}),
        ("per-authority marker", _denial(None, 50, include_tenant=False)),
    ):
        rc, out, err = _run_verifier(
            _make_response(_make_canonical_payload(config_version=3)),
            denial_document=document,
        )
        if not (rc == 1 and "trusted floor 50" in err
                and "legacy execution-denial marker with no tenant, applied to the "
                    f"enrolled tenant {_TEST_TENANT_ID}" in out):
            failures.append(f"{name}: rc={rc}, out={out[:200]!r}, err={err!r}")
    rc, _, _ = _run_verifier(
        _make_response(_make_canonical_payload(config_version=51)),
        denial_document={"config_version": 50},
    )
    if rc != 0:
        failures.append(f"newer config over a legacy marker: rc={rc}")
    if failures:
        _fail("legacy_denial_marker_is_attributed_to_the_enrolled_tenant", "; ".join(failures))
    else:
        _ok("legacy_denial_marker_is_attributed_to_the_enrolled_tenant")


def test_denial_marker_with_malformed_tenant_rejects_every_config():
    failures = []
    for bad in ("", "   ", 7, None, [_TEST_TENANT_ID], True):
        document = _denial(_TEST_TENANT_ID, 2)
        document["tenant_id"] = bad
        rc, _, err = _run_verifier(
            _make_response(_make_canonical_payload(config_version=100)),
            denial_document=document,
        )
        if rc != 1 or "read execution-denial floor" not in err:
            failures.append(f"tenant_id={bad!r}: rc={rc}, err={err!r}")
    duplicate = ('{"tenant_id":"%s","Tenant_Id":"%s","config_version":2}'
                 % (_OTHER_TENANT_ID, _TEST_TENANT_ID))
    rc, _, err = _run_verifier(
        _make_response(_make_canonical_payload(config_version=100)),
        denial_document=duplicate,
    )
    if rc != 1 or "read execution-denial floor" not in err:
        failures.append(f"case-colliding tenant_id: rc={rc}, err={err!r}")
    if failures:
        _fail("denial_marker_with_malformed_tenant_rejects_every_config", "; ".join(failures))
    else:
        _ok("denial_marker_with_malformed_tenant_rejects_every_config")


def test_authenticated_revocation_rekeys_another_tenants_marker():
    """Exit 42 for the enrolled tenant writes a marker keyed to that tenant.
    Another tenant's floors are not merged into it: they are that tenant's
    version numbers."""
    payload = (
        "{"
        f'"tenant_id":"{_TEST_TENANT_ID}",'
        '"config_version":2,'
        '"legacy_app_execution_enabled":false,'
        '"app_control_authority":"enforce",'
        '"unrelated":{"key":1,"KEY":2}'
        "}"
    ).encode()
    with tempfile.TemporaryDirectory() as td:
        response_file = os.path.join(td, "response.json")
        version_file = os.path.join(td, "version")
        current_file = os.path.join(td, "agent-config.json")
        output_file = os.path.join(td, "verified.tmp")
        with open(response_file, "w") as fh:
            json.dump(_make_response(payload), fh)
        with open(version_file, "w") as fh:
            fh.write(json.dumps({"tenant_id": _TEST_TENANT_ID, "config_version": 1}))
        _write_current_config(current_file, {
            "config_version": 1,
            "legacy_app_execution_enabled": True,
            "app_control_authority": "enforce",
        })
        with open(os.path.join(td, "agent-config.execution-denied"), "w") as fh:
            json.dump({"tenant_id": _OTHER_TENANT_ID, "config_version": 99,
                       _vac.APP_CONTROL_REVOCATION_FLOOR_KEY: 99}, fh)
        result = subprocess.run(
            _verifier_cmd(response_file, version_file, output_file, current_file),
            capture_output=True, text=True,
            env={**os.environ, "PATCHED_TENANT_ID": _TEST_TENANT_ID},
        )
        denial_path = output_file + ".execution-denial"
        denial = json.load(open(denial_path)) if os.path.exists(denial_path) else {}
    expected = {"tenant_id": _TEST_TENANT_ID, "config_version": 2,
                _vac.LEGACY_REVOCATION_FLOOR_KEY: 2}
    if result.returncode == _vac.AUTHENTICATED_EXECUTION_REVOCATION_EXIT and denial == expected:
        _ok("authenticated_revocation_rekeys_another_tenants_marker")
    else:
        _fail("authenticated_revocation_rekeys_another_tenants_marker",
              f"rc={result.returncode}, denial={denial!r}, stderr={result.stderr!r}")


if __name__ == "__main__":
    print("verify-agent-config tests")
    test_valid_response()
    test_non_ascii_in_value()
    test_html_special_chars_in_value()
    test_forward_compatible_field_accepted()
    test_ambiguous_payload_keys_rejected_without_cache_replacement()
    test_authenticated_newer_revocation_has_distinct_rejection()
    test_authenticated_rejections_publish_independent_authority_floors()
    test_missing_or_ambiguous_revocation_data_does_not_publish_denial()
    test_per_authority_floor_blocks_conflicting_same_version_grant()
    test_tampered_payload_rejected()
    test_rollback_rejected()
    test_missing_field_rejected()
    test_wrong_key_id_rejected()
    test_wrong_tenant_rejected()
    test_bad_signature_rejected()
    test_empty_tenant_rejected()
    test_same_version_accepted()
    test_denial_floor_requires_newer_version_for_either_authority()
    test_execution_denial_file_is_bounded()
    test_version_bump_accepted()
    test_large_config_version_accepted()
    test_env_override_ignored()
    test_crash_ordering_no_version_file_written()
    test_floor_same_tenant_lower_version_rejected()
    test_floor_same_tenant_higher_version_accepted()
    test_floor_other_tenant_lower_version_accepted_as_fresh_floor()
    test_floor_legacy_integer_applies_to_enrolled_tenant()
    test_floor_corrupt_rejects_every_version()
    test_floor_reader_classification()
    test_floor_never_admits_config_for_another_tenant()
    test_floor_tenant_binding_runs_before_corrupt_floor()
    test_floor_win_staging_reenrolment_shape()
    test_denial_marker_from_another_tenant_does_not_reject_a_new_tenant()
    test_denial_marker_still_applies_to_the_tenant_it_came_from()
    test_legacy_denial_marker_is_attributed_to_the_enrolled_tenant()
    test_denial_marker_with_malformed_tenant_rejects_every_config()
    test_authenticated_revocation_rekeys_another_tenants_marker()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    sys.exit(0 if _FAIL == 0 else 1)
