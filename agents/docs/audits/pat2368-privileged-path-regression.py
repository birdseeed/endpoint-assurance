#!/usr/bin/env python3
"""PAT-2368: unprivileged command-selection regression, never run a daemon.

The production PATH statement is evaluated with only /usr/local/{sbin,bin}
mapped to owned scratch directories. A harmless mkdir stub detects selection.
Expected to FAIL on 7302d8eb; a pass is not installed privilege-boundary proof.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = (
    "endpoint/patched-update.sh",
    "endpoint/patched-fetch-config.sh",
    "endpoint/patched-decommission.sh",
)


class PrivilegedPathTests(unittest.TestCase):
    def check_resolution(self, statement):
        with tempfile.TemporaryDirectory(prefix="pat2368-path-") as directory:
            scratch = Path(directory)
            for name in ("sbin", "bin"):
                location = scratch / name
                location.mkdir()
                stub = location / "mkdir"
                stub.write_text("#!/bin/sh\nprintf 'PAT2368_UNTRUSTED_MKDIR\\n'\n")
                stub.chmod(0o700)
                statement = statement.replace("/usr/local/" + name, str(location))
            target = scratch / "created-by-system-mkdir"
            result = subprocess.run(
                ["/bin/zsh", "-f", "-c", statement + '\nmkdir -p "$1"',
                 "pat2368", str(target)],
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                text=True, capture_output=True, timeout=5, check=True,
            )
            self.assertNotIn("PAT2368_UNTRUSTED_MKDIR", result.stdout)
            self.assertTrue(target.is_dir(), "system mkdir must perform the operation")

    def test_system_only_path_control(self):
        self.check_resolution('export PATH="/usr/bin:/bin:/usr/sbin:/sbin"')

    def test_production_path_rejects_user_command(self):
        self.assertNotEqual(os.geteuid(), 0, "run this fixture without privilege")
        for relative in SCRIPTS:
            with self.subTest(script=relative):
                source = (ROOT / relative).read_text()
                statements = re.findall(r"^export PATH=.*$", source, re.MULTILINE)
                self.assertEqual(len(statements), 1)
                self.check_resolution(statements[0])


if __name__ == "__main__":
    unittest.main()
