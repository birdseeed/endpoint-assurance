#!/usr/bin/env python3
"""
test-agent-config-tenant.py: the cached agent-config tenant rule, over shared fixtures.

PAT-1773. endpoint/agent_config_tenant.py decides whether the cached
agent-config.json belongs to the enrolled tenant. Every reader treats any
answer other than "applies" as no cached config. This test runs the module's
functions, its command line and the legacy execution gate
(patched-legacy-app-execution-gate.py, which loads it in-process) over every
case in endpoint/fixtures/agent-config-tenant.json, checks their failure modes,
and checks the endpoint bundle ships and hashes the module.

Run: /usr/bin/python3 endpoint/test-agent-config-tenant.py
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.join(_HERE, "agent_config_tenant.py")
FIXTURES = os.path.join(_HERE, "fixtures", "agent-config-tenant.json")
GATE = os.path.join(_HERE, "patched-legacy-app-execution-gate.py")
PYTHON3 = "/usr/bin/python3"

_PASS = 0
_FAIL = 0


def _ok(name):
    global _PASS
    _PASS += 1
    print(f"  PASS  {name}")


def _fail(name, detail):
    global _FAIL
    _FAIL += 1
    print(f"  FAIL  {name}\n        {detail}")


def _check(name, expected, actual):
    if expected == actual:
        _ok(name)
    else:
        _fail(name, f"expected {expected!r}\n        got      {actual!r}")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TENANT = _load("patched_agent_config_tenant", MODULE)


def load_cases():
    with open(FIXTURES, encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def write_case(directory, case):
    """Materialise a fixture case. Returns (config_path, tenant_id_path)."""
    config_path = os.path.join(directory, "agent-config.json")
    tenant_path = os.path.join(directory, "tenant-id")
    for path in (config_path, tenant_path):
        if os.path.lexists(path):
            os.unlink(path)
    if case.get("config_hex") is not None:
        with open(config_path, "wb") as fh:
            fh.write(bytes.fromhex(case["config_hex"]))
    elif case.get("config") is not None:
        with open(config_path, "wb") as fh:
            fh.write(case["config"].encode("utf-8"))
    if case.get("tenant_id_file") is not None:
        with open(tenant_path, "wb") as fh:
            fh.write(case["tenant_id_file"].encode("utf-8"))
    return config_path, tenant_path


def test_module_over_fixtures():
    cases = load_cases()
    _check("fixtures cover every state the module can print", True,
           {c["expected"] for c in cases} >= {
               "applies", "absent", "no_enrolled_tenant", "malformed",
               "no_tenant", "invalid_tenant", "other_tenant"})
    with tempfile.TemporaryDirectory() as td:
        for case in cases:
            config_path, tenant_path = write_case(td, case)
            state, _detail = TENANT.cached_state(config_path, tenant_path)
            _check(f"{case['id']}: module cached_state", case["expected"], state)
            result = subprocess.run(
                [PYTHON3, MODULE, "cached-state", config_path, tenant_path],
                capture_output=True, text=True)
            _check(f"{case['id']}: command line", (0, case["expected"]),
                   (result.returncode, result.stdout.strip().split(" ", 1)[0]))
            _check(f"{case['id']}: command line prints exactly one line", 1,
                   len(result.stdout.splitlines()))


def test_detail_is_one_safe_line():
    with tempfile.TemporaryDirectory() as td:
        config_path, tenant_path = write_case(td, {
            "config": json.dumps({"tenant_id": "evil\ntenant $(id) " + "x" * 200}),
            "tenant_id_file": "tenant-a\n"})
        result = subprocess.run([PYTHON3, MODULE, "cached-state", config_path, tenant_path],
                                capture_output=True, text=True)
        line = result.stdout.rstrip("\n")
        _check("other_tenant detail stays on one line", 1, len(result.stdout.splitlines()))
        _check("other_tenant detail carries no whitespace, shell or control characters", True,
               line.startswith("other_tenant ")
               and not any(ch in line[len("other_tenant "):] for ch in " \t\n$()`;|&"))


def test_unreadable_and_oversized():
    with tempfile.TemporaryDirectory() as td:
        tenant_path = os.path.join(td, "tenant-id")
        with open(tenant_path, "w") as fh:
            fh.write("tenant-a\n")
        directory_as_config = os.path.join(td, "agent-config.json")
        os.mkdir(directory_as_config)
        state, detail = TENANT.cached_state(directory_as_config, tenant_path)
        _check("a config path that cannot be read is unreadable, not applies",
               "unreadable", state)
        os.rmdir(directory_as_config)

        with open(directory_as_config, "w") as fh:
            fh.write('{"tenant_id":"tenant-a","pad":"' + "x" * TENANT.MAX_CONFIG_BYTES + '"}')
        _check("a config larger than the bound is malformed",
               "malformed", TENANT.cached_state(directory_as_config, tenant_path)[0])

        with open(directory_as_config, "w") as fh:
            fh.write('{"tenant_id":"tenant-a"}')
        with open(tenant_path, "w") as fh:
            fh.write("tenant-a" + " " * TENANT.MAX_TENANT_ID_BYTES)
        _check("an oversized tenant-id credential is no enrolled tenant",
               "no_enrolled_tenant", TENANT.cached_state(directory_as_config, tenant_path)[0])

        os.unlink(tenant_path)
        os.mkdir(tenant_path)
        _check("an unreadable tenant-id credential is no enrolled tenant",
               "no_enrolled_tenant", TENANT.cached_state(directory_as_config, tenant_path)[0])


def test_classify_config_object():
    _check("classify_config: parsed object for the enrolled tenant applies",
           ("applies", ""), TENANT.classify_config({"tenant_id": "t"}, "t"))
    _check("classify_config: no enrolled tenant never applies",
           "no_enrolled_tenant", TENANT.classify_config({"tenant_id": "t"}, None)[0])
    _check("classify_config: empty enrolled tenant never applies",
           "no_enrolled_tenant", TENANT.classify_config({"tenant_id": ""}, "")[0])
    _check("classify_config: a list is malformed",
           "malformed", TENANT.classify_config(["t"], "t")[0])


def _gate_input(case):
    """The fixture's config with legacy_app_execution_enabled true added when it
    is an unambiguous JSON object, so the tenant is the only thing that can deny;
    any other config text is used as it is."""
    if case.get("config") is None or case.get("config_hex") is not None:
        return None if case.get("config") is None and case.get("config_hex") is None \
            else bytes.fromhex(case["config_hex"])
    try:
        parsed = json.loads(case["config"], object_pairs_hook=TENANT._reject_ambiguous_json_keys)
    except Exception:
        return case["config"].encode("utf-8")
    if not isinstance(parsed, dict):
        return case["config"].encode("utf-8")
    parsed["legacy_app_execution_enabled"] = True
    return json.dumps(parsed).encode("utf-8")


def _run_gate(state_dir, creds_dir, gate_path=GATE):
    """Run the legacy execution gate in-process with fixture files presented as
    root-owned, the same projection endpoint/test-legacy-app-execution-gate.zsh
    uses. Returns "allowed" or "denied"."""
    script = (
        "import importlib.util, sys, types\n"
        "spec = importlib.util.spec_from_file_location('gate', sys.argv[1])\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "root = lambda md: types.SimpleNamespace(st_mode=md.st_mode, st_uid=0, "
        "st_mtime=md.st_mtime, st_dev=md.st_dev, st_ino=md.st_ino)\n"
        "rf, rs = m.os.fstat, m.os.stat\n"
        "m.os.fstat = lambda fd: root(rf(fd))\n"
        "m.os.stat = lambda *a, **k: root(rs(*a, **k))\n"
        "sys.argv = [sys.argv[1]] + sys.argv[2:]\n"
        "print('allowed' if m.main() == 0 else 'denied')\n"
    )
    result = subprocess.run(
        [PYTHON3, "-c", script, gate_path,
         os.path.join(state_dir, "agent-config.json"),
         os.path.join(state_dir, "agent-config.sha256"),
         os.path.join(state_dir, "agent-config.checked"),
         os.path.join(creds_dir, "suspended")],
        capture_output=True, text=True)
    return result.stdout.strip() or f"error: {result.stderr.strip()}"


def _stage_gate_case(td, case):
    state_dir = os.path.join(td, "state")
    creds_dir = os.path.join(td, "creds")
    for directory in (state_dir, creds_dir):
        shutil.rmtree(directory, ignore_errors=True)
        os.mkdir(directory)
        os.chmod(directory, 0o755)
    config = _gate_input(case)
    if config is not None:
        with open(os.path.join(state_dir, "agent-config.json"), "wb") as fh:
            fh.write(config)
        with open(os.path.join(state_dir, "agent-config.sha256"), "w") as fh:
            fh.write(hashlib.sha256(config).hexdigest() + "\n")
        open(os.path.join(state_dir, "agent-config.checked"), "w").close()
        for name in ("agent-config.json", "agent-config.sha256", "agent-config.checked"):
            os.chmod(os.path.join(state_dir, name), 0o644)
    if case.get("tenant_id_file") is not None:
        path = os.path.join(creds_dir, "tenant-id")
        with open(path, "wb") as fh:
            fh.write(case["tenant_id_file"].encode("utf-8"))
        os.chmod(path, 0o600)
    return state_dir, creds_dir


def test_legacy_execution_gate_over_fixtures():
    """The legacy execution gate allows an exact-true config only when the
    shared rule says it applies; every other fixture denies."""
    with tempfile.TemporaryDirectory() as td:
        for case in load_cases():
            state_dir, creds_dir = _stage_gate_case(td, case)
            expected = "allowed" if case["expected"] == "applies" else "denied"
            _check(f"{case['id']}: legacy execution gate", expected,
                   _run_gate(state_dir, creds_dir))


def test_legacy_execution_gate_denies_without_the_module():
    with tempfile.TemporaryDirectory() as td:
        case = {"config": '{"tenant_id":"tenant-a"}', "tenant_id_file": "tenant-a\n"}
        state_dir, creds_dir = _stage_gate_case(td, case)
        bundle = os.path.join(td, "bundle")
        os.mkdir(bundle)
        gate_copy = os.path.join(bundle, "patched-legacy-app-execution-gate.py")
        shutil.copy(GATE, gate_copy)
        _check("gate with no agent_config_tenant.py beside it denies", "denied",
               _run_gate(state_dir, creds_dir, gate_copy))
        with open(os.path.join(bundle, "agent_config_tenant.py"), "w") as fh:
            fh.write("raise RuntimeError('broken module')\n")
        _check("gate with a broken agent_config_tenant.py beside it denies", "denied",
               _run_gate(state_dir, creds_dir, gate_copy))
        shutil.copy(MODULE, os.path.join(bundle, "agent_config_tenant.py"))
        _check("gate with the real module beside it allows the matching tenant", "allowed",
               _run_gate(state_dir, creds_dir, gate_copy))
        _check("gate loading the module writes no bytecode cache", False,
               os.path.exists(os.path.join(bundle, "__pycache__")))


def test_command_line_rejects_bad_invocations():
    for argv in ([], ["cached-state"], ["cached-state", "/a"],
                 ["cached-state", "/a", "/b", "extra"], ["check", "/a", "/b"]):
        result = subprocess.run([PYTHON3, MODULE, *argv], capture_output=True, text=True)
        _check(f"command line {argv!r} exits 2 with nothing on stdout",
               (2, ""), (result.returncode, result.stdout))


def test_loading_the_module_writes_no_bytecode_cache():
    with tempfile.TemporaryDirectory() as td:
        bundle = os.path.join(td, "bundle")
        os.mkdir(bundle)
        shutil.copy(MODULE, os.path.join(bundle, "agent_config_tenant.py"))
        subprocess.run([PYTHON3, os.path.join(bundle, "agent_config_tenant.py"),
                        "cached-state", os.path.join(td, "none"), os.path.join(td, "none")],
                       capture_output=True, check=True)
        _check("no __pycache__ appears in the bundle directory", False,
               os.path.exists(os.path.join(bundle, "__pycache__")))


def test_bundle_build_ships_and_hashes_the_module():
    build = os.path.join(os.path.dirname(_HERE), "tools", "build-bundle.sh")
    with open(build, encoding="utf-8") as fh:
        text = fh.read()
    _check("build-bundle.sh copies agent_config_tenant.py into the bundle", True,
           'cp "$REPO_ROOT/endpoint/agent_config_tenant.py" "$DIST_BUNDLE/agent_config_tenant.py"' in text)
    manifest_list = text[text.index("shasum -a 256 \\"):text.index("| sed 's/  / /' > manifest.sha256")]
    _check("build-bundle.sh lists agent_config_tenant.py in manifest.sha256", True,
           "agent_config_tenant.py" in manifest_list)


if __name__ == "__main__":
    print("agent-config tenant: module over the shared fixtures")
    test_module_over_fixtures()
    test_detail_is_one_safe_line()
    test_unreadable_and_oversized()
    test_classify_config_object()
    print("agent-config tenant: legacy execution gate over the shared fixtures")
    test_legacy_execution_gate_over_fixtures()
    test_legacy_execution_gate_denies_without_the_module()
    print("agent-config tenant: failure modes")
    test_command_line_rejects_bad_invocations()
    test_loading_the_module_writes_no_bytecode_cache()
    print("agent-config tenant: bundle")
    test_bundle_build_ships_and_hashes_the_module()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    sys.exit(0 if _FAIL == 0 else 1)
