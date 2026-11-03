#!/usr/bin/env python3
"""
test-agent-config-floor.py: one floor parser, every caller, shared fixtures.

PAT-1763. The agent-config anti-rollback floor file used to be parsed in four
places on macOS (inline Python in patched-enroll.sh, _agent_config_floor_state
and _decommission_check in patched-fetch-config.sh, and _read_rollback_floor
in verify-agent-config.py). They now all call endpoint/agent_config_floor.py.

This test drives every caller, as shipped, over every fixture in
endpoint/fixtures/agent-config-floor.json and requires the exact output
recorded there. Those expectations were captured by running the four inline
copies from origin/main (9b89b3da) over the same fixtures before they were
removed, so a pass proves the consolidation changed no classification, no
If-None-Match choice, no enrolment removal decision, no verifier floor or
rejection text, and no decommission decision.

It also proves:
  - the module's command line and functions give the same answers directly;
  - a missing or broken module fails safe for each caller (enrolment keeps the
    floor, the fetch path sends no If-None-Match, the decommission gate faults,
    the verifier refuses to start);
  - no caller still carries its own floor parsing, so the copies cannot come
    back and drift.

Run: python3 endpoint/test-agent-config-floor.py
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
MODULE = os.path.join(_HERE, "agent_config_floor.py")
FIXTURES = os.path.join(_HERE, "fixtures", "agent-config-floor.json")
ENROL_SH = os.path.join(_HERE, "patched-enroll.sh")
FETCH_SH = os.path.join(_HERE, "patched-fetch-config.sh")
VERIFIER = os.path.join(_HERE, "verify-agent-config.py")
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


def _block(path, marker):
    """Extract a sentinel-delimited block exactly as the zsh tests do."""
    lines, on = [], False
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().split("\n"):
            if not on and f"{marker}_START" in line:
                on = True
                continue
            if on and f"{marker}_END" in line:
                return "\n".join(lines)
            if on:
                lines.append(line)
    raise AssertionError(f"block {marker} not found in {path}")


ENROL_BLOCK = _block(ENROL_SH, "PATCHED_ENROL_FLOOR_STATE")
FLOOR_BLOCK = _block(FETCH_SH, "PATCHED_CONFIG_FLOOR")
COMMIT_BLOCK = _block(FETCH_SH, "PATCHED_CONFIG_COMMIT")
DECOMM_BLOCK = _block(FETCH_SH, "PATCHED_DECOMMISSION_GATE")


def _zsh(script, *args):
    result = subprocess.run(["zsh", "-c", script, "zsh", *args],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(f"zsh exited {result.returncode}: {result.stderr}")
    return result.stdout.rstrip("\n")


def enrol_caller(floor_path, tenant, module_path=MODULE):
    return _zsh(ENROL_BLOCK + f'\nPYTHON3={PYTHON3}\nAGENT_CONFIG_FLOOR_MODULE="$3"\n'
                '_enrol_floor_state "$1" "$2"\nprint -r -- "$floor_state"\n',
                floor_path, tenant, module_path)


def fetch_caller(floor_path, tenant, module_path=MODULE):
    return _zsh(FLOOR_BLOCK + f'\nPYTHON3={PYTHON3}\nAGENT_CONFIG_FLOOR_MODULE="$3"\n'
                '_agent_config_floor_state "$1" "$2"\n',
                floor_path, tenant, module_path)


def decommission_caller(state_dir, tenant, config_version, module_path=MODULE):
    """_decommission_check against a verified immediate directive for tenant
    at config_version, with whatever floor state_dir holds."""
    config_bytes = json.dumps({"tenant_id": tenant, "config_version": config_version,
                               "decommission": {"mode": "immediate"}}).encode()
    with open(os.path.join(state_dir, "agent-config.json"), "wb") as fh:
        fh.write(config_bytes)
    with open(os.path.join(state_dir, "agent-config.sha256"), "w") as fh:
        fh.write(hashlib.sha256(config_bytes).hexdigest() + "\n")
    os.makedirs(os.path.join(state_dir, "creds"), exist_ok=True)
    with open(os.path.join(state_dir, "creds", "tenant-id"), "w") as fh:
        fh.write(tenant + "\n")
    return _zsh(COMMIT_BLOCK + "\n" + DECOMM_BLOCK + "\n"
                f'PYTHON3={PYTHON3}\nlog_jsonl() {{ :; }}\n'
                'STATE_DIR="$1"; CREDS_DIR="$1/creds"\n'
                'AGENT_CONFIG_FILE="$1/agent-config.json"\n'
                'AGENT_CONFIG_SHA256_FILE="$1/agent-config.sha256"\n'
                'AGENT_CONFIG_VERSION_FILE="$1/agent-config.version"\n'
                'AGENT_CONFIG_FLOOR_MODULE="$2"\n'
                'AGENT_CONFIG_CLOCK_SKEW_SECONDS=0\n'
                '_decommission_check\n'
                'print -r -- "$DECOMMISSION_DECISION:$DECOMMISSION_REASON"\n',
                state_dir, module_path)


def module_cli(command, floor_path, tenant):
    result = subprocess.run([PYTHON3, MODULE, command, floor_path, tenant],
                            capture_output=True, text=True)
    return result.returncode, result.stdout.rstrip("\n")


def place(state_dir, fixture):
    floor = os.path.join(state_dir, "agent-config.version")
    kind = fixture["kind"]
    if kind == "directory":
        os.mkdir(floor)
    elif kind == "text":
        with open(floor, "wb") as fh:
            fh.write(fixture["text"].encode("utf-8"))
    elif kind == "hex":
        with open(floor, "wb") as fh:
            fh.write(bytes.fromhex(fixture["hex"]))
    elif kind != "absent":
        raise AssertionError(f"unknown fixture kind {kind}")
    return floor


_VERIFIER_VIEW = r"""
import importlib.util, json, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("vac_under_test", sys.argv[1])
vac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vac)
kind, floor_tenant, value = vac._read_rollback_floor(sys.argv[2])
view = {"kind": kind, "tenant": floor_tenant, "value": value}
if kind != "corrupt":
    last, description = vac._rollback_floor_for_tenant((kind, floor_tenant, value), sys.argv[3])
    view.update({"last_version": last, "description": description})
print(json.dumps(view))
"""


def verifier_view(floor_path, tenant):
    """The verifier's floor reading, run under the agent's own interpreter
    (/usr/bin/python3), as patched-fetch-config.sh runs it. Some problem texts
    depend on the interpreter (a deeply nested document is a RecursionError on
    Apple's Python 3.9 and parses on newer releases), so the fixtures pin the
    shipped one."""
    result = subprocess.run([PYTHON3, "-c", _VERIFIER_VIEW, VERIFIER, floor_path, tenant],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(f"verifier view failed: {result.stderr}")
    return json.loads(result.stdout)


def test_every_caller_matches_the_recorded_fixtures():
    with open(FIXTURES, encoding="utf-8") as fh:
        doc = json.load(fh)
    tenant = doc["enrolled_tenant"]
    config_version = doc["decommission_config_version"]
    floor_module = _load("floor_under_test", MODULE)
    if len(doc["fixtures"]) < 40:
        _fail("fixture file is complete", f"only {len(doc['fixtures'])} fixtures")
    for fixture in doc["fixtures"]:
        fid, expect = fixture["id"], fixture["expect"]
        with tempfile.TemporaryDirectory() as td:
            floor = place(td, fixture)
            _check(f"{fid}: patched-enroll.sh", expect["enrol"], enrol_caller(floor, tenant))
            _check(f"{fid}: patched-fetch-config.sh _agent_config_floor_state",
                   expect["fetch"], fetch_caller(floor, tenant))
            _check(f"{fid}: verify-agent-config.py", expect["verifier"],
                   verifier_view(floor, tenant))
            _check(f"{fid}: patched-fetch-config.sh _decommission_check",
                   expect["decommission"], decommission_caller(td, tenant, config_version))

            parsed = floor_module.read_floor(floor)
            _check(f"{fid}: module enrol_state", expect["enrol"],
                   floor_module.enrol_state(parsed, tenant))
            _check(f"{fid}: module fetch_state", expect["fetch"],
                   floor_module.fetch_state(parsed, tenant))
            _check(f"{fid}: module command line enrol-state", (0, expect["enrol"]),
                   module_cli("enrol-state", floor, tenant))
            _check(f"{fid}: module command line fetch-state", (0, expect["fetch"]),
                   module_cli("fetch-state", floor, tenant))
            recorded = floor_module.recorded_version_for_tenant(parsed, tenant)
            if expect["decommission"] == "fault:rollback_floor_unusable":
                _check(f"{fid}: module recorded_version_for_tenant", None, recorded)
            else:
                _check(f"{fid}: module recorded_version_for_tenant is the vouching floor",
                       True, isinstance(recorded, int) and not isinstance(recorded, bool))


def test_missing_module_fails_safe_for_every_caller():
    with tempfile.TemporaryDirectory() as td:
        floor = os.path.join(td, "agent-config.version")
        with open(floor, "w") as fh:
            fh.write('{"tenant_id":"tenant-a","config_version":3}')
        missing = os.path.join(td, "no-such-dir", "agent_config_floor.py")
        _check("missing module: enrolment classifies the reader as failed, so the floor is kept",
               "reader_failed", enrol_caller(floor, "tenant-a", missing))
        _check("missing module: the fetch path treats the floor as corrupt (no If-None-Match)",
               "corrupt", fetch_caller(floor, "tenant-a", missing))
        _check("missing module: the decommission gate faults instead of acting",
               "fault:rollback_floor_reader_unavailable",
               decommission_caller(td, "tenant-a", 12, missing))

        bundle = os.path.join(td, "bundle")
        os.mkdir(bundle)
        shutil.copy(VERIFIER, os.path.join(bundle, "verify-agent-config.py"))
        result = subprocess.run([PYTHON3, os.path.join(bundle, "verify-agent-config.py"),
                                 "--response-file", floor, "--version-file", floor,
                                 "--output-file", os.path.join(td, "out.json")],
                                capture_output=True, text=True,
                                env={"PATCHED_TENANT_ID": "tenant-a", "PATH": "/usr/bin:/bin"})
        _check("missing module: the verifier exits non-zero (the config is rejected)",
               True, result.returncode != 0)
        _check("missing module: the verifier wrote no output",
               False, os.path.exists(os.path.join(td, "out.json")))
        _check("missing module: no bytecode cache is written next to the bundle",
               False, os.path.exists(os.path.join(bundle, "__pycache__")))


def test_module_command_line_rejects_bad_invocations():
    for argv in ([], ["enrol-state"], ["verify", "/nonexistent", "t"],
                 ["fetch-state", "/nonexistent"], ["fetch-state", "/a", "t", "extra"]):
        result = subprocess.run([PYTHON3, MODULE, *argv], capture_output=True, text=True)
        _check(f"command line {argv!r} exits 2 with nothing on stdout",
               (2, ""), (result.returncode, result.stdout))


def test_loading_the_module_writes_no_bytecode_cache():
    with tempfile.TemporaryDirectory() as td:
        bundle = os.path.join(td, "bundle")
        os.mkdir(bundle)
        shutil.copy(MODULE, os.path.join(bundle, "agent_config_floor.py"))
        shutil.copy(VERIFIER, os.path.join(bundle, "verify-agent-config.py"))
        floor = os.path.join(td, "agent-config.version")
        with open(floor, "w") as fh:
            fh.write("12")
        subprocess.run([PYTHON3, os.path.join(bundle, "agent_config_floor.py"),
                        "fetch-state", floor, "t"], capture_output=True, check=True)
        subprocess.run([PYTHON3, "-c",
                        "import importlib.util,sys\n"
                        "s=importlib.util.spec_from_file_location('v',sys.argv[1])\n"
                        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\n",
                        os.path.join(bundle, "verify-agent-config.py")],
                       capture_output=True, check=True)
        decommission_caller(td, "t", 12, os.path.join(bundle, "agent_config_floor.py"))
        _check("no __pycache__ appears in the bundle directory after every caller ran",
               False, os.path.exists(os.path.join(bundle, "__pycache__")))


def test_no_caller_keeps_its_own_floor_parser():
    """Guard: the floor's shape check lives only in agent_config_floor.py."""
    markers = (
        '{"tenant_id", "config_version"}',
        "floor_path, tenant = sys.argv",
        "def _floor_pairs",
        "MAX_ROLLBACK_FLOOR_BYTES + 1",
    )
    for path in (ENROL_SH, FETCH_SH, VERIFIER):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        found = [marker for marker in markers if marker in text]
        _check(f"{os.path.basename(path)} carries no inline floor parser", [], found)
    with open(MODULE, encoding="utf-8") as fh:
        _check("agent_config_floor.py holds the shape check", True,
               "{TENANT_KEY, VERSION_KEY}" in fh.read())


def test_bundle_build_ships_and_hashes_the_module():
    """The endpoint bundle copies the module and lists it in manifest.sha256,
    so both install.sh and the daemon's verify_bundle cover its bytes."""
    build = os.path.join(os.path.dirname(_HERE), "tools", "build-bundle.sh")
    with open(build, encoding="utf-8") as fh:
        text = fh.read()
    _check("build-bundle.sh copies agent_config_floor.py into the bundle", True,
           'cp "$REPO_ROOT/endpoint/agent_config_floor.py" "$DIST_BUNDLE/agent_config_floor.py"' in text)
    manifest_list = text[text.index("shasum -a 256 \\"):text.index("| sed 's/  / /' > manifest.sha256")]
    _check("build-bundle.sh lists agent_config_floor.py in manifest.sha256", True,
           "agent_config_floor.py" in manifest_list)


if __name__ == "__main__":
    print("agent-config floor: every caller over the shared fixtures")
    test_every_caller_matches_the_recorded_fixtures()
    print("agent-config floor: failure modes")
    test_missing_module_fails_safe_for_every_caller()
    test_module_command_line_rejects_bad_invocations()
    test_loading_the_module_writes_no_bytecode_cache()
    print("agent-config floor: guards")
    test_no_caller_keeps_its_own_floor_parser()
    test_bundle_build_ships_and_hashes_the_module()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    sys.exit(0 if _FAIL == 0 else 1)
