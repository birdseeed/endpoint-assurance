"""PAT-1796: fail closed on Ubuntu Pro attachment-query availability.

The full ``pro status --format=json`` command can block while querying
canonical-livepatch in the hardened maintenance-facts unit. The bounded,
purpose-specific API has a smaller contract, so exercise the real shell
emitter with PATH shims for its command boundary rather than duplicating its
JSON decision logic in Python.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.sh"


class MaintenanceFactsProAttachmentApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.out_file = self.root / "out" / "maintenance.json"
        self.pro_args_file = self.root / "pro-args"
        self.config_backup_root = self.root / "etc"
        (self.config_backup_root / "patched-test").mkdir(parents=True)

        self._write_executable(
            "id",
            "#!/bin/bash\n"
            'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
            'exec /usr/bin/id "$@"\n',
        )
        # macOS does not provide GNU timeout. This shim preserves the command
        # boundary and lets a test model timeout's non-zero result without
        # sleeping; production still uses its real bounded timeout command.
        self._write_executable(
            "timeout",
            "#!/bin/bash\n"
            'if [ "$1" != "10" ]; then exit 64; fi\n'
            'if [ -n "${FAKE_TIMEOUT_EXIT:-}" ]; then exit "$FAKE_TIMEOUT_EXIT"; fi\n'
            "shift\n"
            'exec "$@"\n',
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_executable(self, name: str, content: str) -> None:
        path = self.fake_bin / name
        path.write_text(content)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _install_pro(self) -> None:
        self._write_executable(
            "pro",
            "#!/bin/bash\n"
            'printf "%s\\n" "$@" > "$FAKE_PRO_ARGS_FILE"\n'
            'printf "%s" "${FAKE_PRO_OUTPUT:-}"\n'
            'exit "${FAKE_PRO_EXIT:-0}"\n',
        )

    def _run(
        self,
        pro_output: str | None = None,
        *,
        pro_exit: int = 0,
        timeout_exit: int | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        self._install_pro()
        env = dict(os.environ)
        env["PATH"] = f"{self.fake_bin}:/usr/bin:/bin"
        env["OUT_FILE"] = str(self.out_file)
        env["CONFIG_BACKUP_ROOT"] = str(self.config_backup_root)
        env["FAKE_PRO_ARGS_FILE"] = str(self.pro_args_file)
        if pro_output is not None:
            env["FAKE_PRO_OUTPUT"] = pro_output
        env["FAKE_PRO_EXIT"] = str(pro_exit)
        if timeout_exit is not None:
            env["FAKE_TIMEOUT_EXIT"] = str(timeout_exit)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.out_file.exists(), result.stderr)
        return result, json.loads(self.out_file.read_text())

    @staticmethod
    def _response(*, attached: bool, contract_valid: bool, errors: list[object] | None = None) -> str:
        return json.dumps(
            {
                "result": "success",
                "errors": [] if errors is None else errors,
                "data": {
                    "attributes": {
                        "is_attached": attached,
                        "is_attached_and_contract_valid": contract_valid,
                    }
                },
            }
        )

    def test_attached_contract_valid_response_sets_true_and_uses_narrow_api(self):
        _, data = self._run(self._response(attached=True, contract_valid=True))

        self.assertTrue(data["pro_attached"])
        self.assertIsNotNone(data["esm_updates"])
        self.assertEqual(
            self.pro_args_file.read_text().splitlines(),
            ["api", "u.pro.status.is_attached.v1"],
        )

    def test_genuine_detached_response_sets_false(self):
        _, data = self._run(self._response(attached=False, contract_valid=False))

        self.assertFalse(data["pro_attached"])
        self.assertIsNone(data["esm_updates"])

    def test_timeout_or_non_zero_result_is_unknown_not_detached(self):
        for name, kwargs in (
            ("timeout", {"timeout_exit": 124}),
            ("pro-non-zero", {"pro_exit": 1}),
        ):
            with self.subTest(name=name):
                result, data = self._run(**kwargs)
                self.assertIsNone(data["pro_attached"])
                self.assertIsNone(data["esm_updates"])
                self.assertIn("WARNING: Ubuntu Pro attachment API", result.stderr)

    def test_malformed_or_empty_output_is_unknown_not_detached(self):
        for payload in ("", "not json", "[]"):
            with self.subTest(payload=payload):
                result, data = self._run(payload)
                self.assertIsNone(data["pro_attached"])
                self.assertIsNone(data["esm_updates"])
                self.assertIn("WARNING: Ubuntu Pro attachment", result.stderr)

    def test_api_errors_are_unknown_not_detached(self):
        result, data = self._run(self._response(attached=False, contract_valid=False, errors=[{"code": "x"}]))

        self.assertIsNone(data["pro_attached"])
        self.assertIsNone(data["esm_updates"])
        self.assertIn("WARNING: Ubuntu Pro attachment state unavailable", result.stderr)

    def test_attached_with_invalid_or_missing_contract_is_unknown_not_detached(self):
        invalid = self._response(attached=True, contract_valid=False)
        missing = json.dumps(
            {"result": "success", "errors": [], "data": {"attributes": {"is_attached": True}}}
        )
        for payload in (invalid, missing):
            with self.subTest(payload=payload):
                _, data = self._run(payload)
                self.assertIsNone(data["pro_attached"])
                self.assertIsNone(data["esm_updates"])

if __name__ == "__main__":
    unittest.main()
