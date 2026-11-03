#!/usr/bin/env python3
"""PAT-2394 source-statement regression; never execute an installed daemon.

Run with python3 ci/test_privileged_command_resolution.py (unprivileged, zsh
installed). Only source PATH declarations, selected early operations and runtime
preconditions are evaluated. /usr/local PATH entries are relocated into owned
scratch directories; all operation arguments reference that scratch tree.
Passing is portable source evidence, not installed privilege-boundary proof.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = tuple("endpoint/patched-" + name + ".sh" for name in (
    "update", "fetch-config", "decommission", "enroll", "log-upload", "fetch-posture",
))
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
# These commands occur before signature/bundle verification, including logging
# setup and enrolment credential detection. A stub records selection even when
# the production command redirects stdout/stderr.
TOOLS = ("mkdir", "dirname", "install", "head", "grep", "tee", "date",
         "curl", "shasum", "awk", "python3", "launchctl")


def check_optional_owner():
    """Ordinary CI needs no queue state; configured queue checks fail closed."""
    record = os.environ.get("QUEUE_RUN_TEST_OWNER_PATH")
    nonce = os.environ.get("QUEUE_RUN_TEST_OWNER_NONCE")
    if record is not None or nonce is not None:
        if not record or not nonce:
            raise RuntimeError("both queue fixture owner values must be nonempty")
        if json.loads(Path(record).read_text()).get("owner_nonce") != nonce:
            raise RuntimeError("queue fixture owner nonce mismatch")


def source_path(source):
    declarations = re.findall(r"^export PATH=.*$", source, re.M)
    if len(declarations) > 1:
        raise AssertionError("multiple PATH assignments require explicit coverage")
    # Absence must exercise inherited PATH, not be skipped or replaced with a
    # safe fixture default (patched-fetch-posture.sh at the regression base).
    return declarations[0] if declarations else ":"


def first_operation(relative, source):
    """Extract the actual early statement, not a test-invented mkdir call."""
    if relative.endswith(("fetch-config.sh", "fetch-posture.sh")):
        function = re.search(r"^_init_jsonl_log\(\) \{\n(.*?)^\}", source, re.M | re.S)
        if function is None:
            raise AssertionError("missing early logging function")
        lines = function[1].splitlines()
        # Only its first command (and continuation) is needed; avoid running
        # the subsequent rotation, cleanup or telemetry operations.
        operation = lines[0]
        index = 1
        while operation.rstrip().endswith("\\"):
            operation += "\n" + lines[index]
            index += 1
        offset = function.start(1)
    elif relative.endswith("enroll.sh"):
        match = re.search(r'^if (?:/usr/bin/)?head -1 .*?^fi$', source, re.M | re.S)
        if match is None:
            raise AssertionError("missing early enrolment credential check")
        operation, offset = match[0], match.start()
    else:
        match = re.search(r'^(?:/bin/)?mkdir -p .*$', source, re.M)
        if match is None:
            raise AssertionError("missing early directory operation")
        operation, offset = match[0], match.start()
    return operation, offset


class PrivilegedCommandResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        check_optional_owner()
        if os.geteuid() == 0:
            raise RuntimeError("run this fixture without privilege")
        cls.zsh = shutil.which("zsh")
        if not cls.zsh:
            raise RuntimeError("zsh is required; bash/sh is not a valid substitute")

    def exercise(self, declaration, operation, test_override=False):
        with tempfile.TemporaryDirectory(prefix="pat2394-resolution-") as directory:
            scratch = Path(directory)
            marker = scratch / "untrusted-command-selected"
            locations = {}
            for name in ("sbin", "bin", "inherited", "test-override"):
                location = scratch / name
                location.mkdir()
                locations[name] = location
                for tool in TOOLS:
                    stub = location / tool
                    stub.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(tool) +
                                    " >> " + shlex.quote(str(marker)) + "\nexit 0\n")
                    stub.chmod(0o700)
            for name in ("sbin", "bin"):
                declaration = declaration.replace("/usr/local/" + name, str(locations[name]))
            environment = {"PATH": str(locations["inherited"]) + ":" + SYSTEM_PATH}
            if test_override:
                environment["PATCHED_TEST_PATH_PREPEND"] = str(locations["test-override"])
            # Every variable used by extracted operations points to scratch.
            for variable in ("STATE_DIR", "PROV_QUEUE", "EVENTS_QUEUE", "JSONL_LOG_DIR", "CREDS_DIR"):
                environment[variable] = str(scratch / variable.lower())
            environment["LOG_FILE"] = str(scratch / "logs" / "operation.log")
            environment["BEARER_FILE"] = str(scratch / "absent-bearer")
            result = subprocess.run(
                [self.zsh, "-f", "-c", "set -u\n" + declaration + "\n" + operation],
                env=environment, capture_output=True, text=True, timeout=5,
            )
            selected = marker.read_text() if marker.exists() else ""
            self.assertEqual(selected, "", "untrusted command executed: " + selected)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout

    def test_secure_control_rejects_shadow_and_runs_system_operation(self):
        output = self.exercise('export PATH="' + SYSTEM_PATH + '"',
                               'mkdir -p "$STATE_DIR"\n[[ -d "$STATE_DIR" ]]\nprintf CONTROL_OK')
        self.assertEqual(output, "CONTROL_OK")

    def test_actual_early_operations_reject_shadow_tools(self):
        for relative in SCRIPTS:
            for override in (False, True):
                with self.subTest(script=relative, test_override=override):
                    source = (ROOT / relative).read_text()
                    operation, offset = first_operation(relative, source)
                    declaration = source_path(source)
                    if declaration != ":":
                        self.assertLess(source.index(declaration), offset,
                                        "PATH must be protected before the first tool call")
                    self.exercise(declaration, operation, override)

    def test_command_search_contains_only_system_directories(self):
        for relative in SCRIPTS:
            with self.subTest(script=relative):
                source = (ROOT / relative).read_text()
                output = self.exercise(source_path(source), 'printf "%s" "$PATH"', True)
                self.assertTrue(output, "empty PATH does not establish trusted command selection")
                self.assertTrue(all(entry in SYSTEM_PATH.split(":") for entry in output.split(":")),
                                "PATH admits a user-controlled or relative directory: " + output)

    def test_missing_trusted_python_stops_with_explicit_error(self):
        for relative in SCRIPTS:
            with self.subTest(script=relative):
                source = (ROOT / relative).read_text()
                assignment = re.search(r'^PYTHON3="([^"]+)"$', source, re.M)
                self.assertIsNotNone(assignment, "trusted runtime must be selected explicitly")
                self.assertEqual(assignment[1], "/usr/bin/python3",
                                 "Homebrew/local runtime is outside the system trust boundary")
                # Extract the source prerequisite, preserving its real exit code
                # and message. No daemon, network or credential code is executed.
                guard = re.search(r'^\[\[ -x "\$PYTHON3" \]\].*$', source, re.M)
                self.assertIsNotNone(guard, "missing trusted-runtime prerequisite")
                operation, offset = first_operation(relative, source)
                self.assertLess(guard.start(), offset,
                                "runtime prerequisite must precede pre-verification side effects")
                with tempfile.TemporaryDirectory(prefix="pat2394-runtime-") as directory:
                    absent = str(Path(directory) / "missing-python3")
                    body = ('PYTHON3=' + shlex.quote(absent) + '\n' + guard[0] +
                            '\nprintf RUNTIME_GUARD_FELL_THROUGH\n')
                    result = subprocess.run([self.zsh, "-f", "-c", body],
                                            env={"PATH": SYSTEM_PATH}, text=True,
                                            capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0, "missing runtime reported success")
                    self.assertNotIn("RUNTIME_GUARD_FELL_THROUGH", result.stdout)
                    self.assertRegex(result.stdout + result.stderr,
                                     r"(?i)(fatal|error|degraded).*(python|runtime)",
                                     "missing runtime needs an explicit diagnostic")

    def test_legacy_deployment_payloads_stay_excluded(self):
        source = (ROOT / "tools/build-bundle.sh").read_text()
        copied = re.findall(r'^\s*cp\s+([^\n]+)', source, re.M)
        for line in copied:
            self.assertNotRegex(line, r"(?:engine/Installomator|endpoint/patched-(?:install|uninstall))\.sh",
                                "command-resolution fix must not ship quarantined executors")
        for relative in SCRIPTS:
            self.assertTrue(any(relative in line for line in copied),
                            "retained source omitted from bundle coverage: " + relative)


if __name__ == "__main__":
    unittest.main(verbosity=2)
