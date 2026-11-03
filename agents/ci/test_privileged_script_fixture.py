"""Fixture instrumentation must refuse drift before any script is invoked."""
from pathlib import Path
import shlex
import re
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name("privileged_script_fixture.py")
SYSTEM_LINE = 'export PATH="/usr/bin:/bin:/usr/sbin:/sbin"'


class FixtureIsolationTests(unittest.TestCase):
    def test_zero_or_multiple_path_matches_never_invoke_script(self):
        for prelude in ("", SYSTEM_LINE + "\n" + SYSTEM_LINE):
            with self.subTest(prelude=prelude), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                product = root / "source"
                scratch = root / "scratch"
                stubs = root / "stubs"
                for item in (product, scratch, stubs):
                    item.mkdir(mode=0o700)
                marker = root / "invoked"
                source = product / "script.sh"
                source.write_text(prelude + "\nprintf invoked > " + shlex.quote(str(marker)) + "\n")
                destination = scratch / "copy.sh"
                command = shlex.join([sys.executable, str(HELPER), str(source), str(destination), str(stubs)])
                command += " && " + shlex.join(["/bin/sh", str(destination)])
                result = subprocess.run(["/bin/sh", "-c", command], capture_output=True,
                                        text=True, timeout=5,
                                        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                             "PATCHED_API_URL": "http://127.0.0.1:1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exactly one literal", result.stderr)
                self.assertFalse(destination.exists())
                self.assertFalse(marker.exists(), "invalid instrumentation invoked the script")

    def test_executable_but_unusable_trusted_runtime_refuses_work(self):
        root = HELPER.parent.parent
        for name in ("update", "fetch-config", "decommission", "enroll", "log-upload", "fetch-posture"):
            with self.subTest(script=name), tempfile.TemporaryDirectory() as directory:
                runtime = Path(directory) / "unusable-python"
                runtime.write_text("#!/bin/sh\nexit 69\n")
                runtime.chmod(0o700)
                source = (root / ("endpoint/patched-" + name + ".sh")).read_text()
                guard = re.search(r'^\[\[ -x "\$PYTHON3" \]\].*$', source, re.M)
                self.assertIsNotNone(guard)
                body = "PYTHON3=" + shlex.quote(str(runtime)) + "\n" + guard[0] + "\nprintf WORK_REACHED"
                result = subprocess.run(["/bin/zsh", "-f", "-c", body], capture_output=True,
                                        text=True, timeout=5,
                                        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                             "PATCHED_API_URL": "http://127.0.0.1:1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("WORK_REACHED", result.stdout)
                self.assertRegex(result.stderr, r"(?i)(fatal|error|degraded).*runtime")

    def test_valid_copy_uses_only_owned_stub_and_system_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("source", "scratch", "stubs"):
                (root / name).mkdir(mode=0o700)
            source, destination = root / "source/script.sh", root / "scratch/copy.sh"
            source.write_text(SYSTEM_LINE + '\nprintf "%s" "$PATH"\n')
            result = subprocess.run([sys.executable, str(HELPER), str(source), str(destination), str(root / "stubs")],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(["/bin/sh", str(destination)], capture_output=True, text=True, timeout=5,
                                    env={"PATH": "/untrusted", "PATCHED_API_URL": "http://127.0.0.1:1"})
            self.assertEqual(result.stdout, str(root / "stubs") + ":/usr/bin:/bin:/usr/sbin:/sbin")
            self.assertEqual(source.read_text(), SYSTEM_LINE + '\nprintf "%s" "$PATH"\n')


if __name__ == "__main__":
    unittest.main()
