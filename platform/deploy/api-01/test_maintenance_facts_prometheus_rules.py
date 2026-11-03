"""PAT-1423: api-vps-artefacts/patched-maintenance-facts.sh's prometheus_rules_*
reporting.

Nothing deployed api-vps-artefacts/alerting/prometheus-rules-patched.yml onto
api-01 before this ticket -- it only ever reached the box when a person
remembered to `scp` it (see api-vps-artefacts/alerting/README.md's
superseded manual "Deploy" section), and PAT-1377's fix to two dead rules sat
unshipped on main for days as a result. deploy/api-01/deploy-prometheus-
rules.sh (see test_deploy_prometheus_rules.py, same directory) now installs
the file and writes a sidecar (<dest>.sha256) recording the SHA-256 it
installed. This emitter reads both back -- the live file's current hash and
the sidecar's recorded hash -- so a hand-scp or hand-edit made directly on
the box after that deploy shows up as drift, without api-01 ever needing to
reach GitHub (it can't -- deploy keys are disabled org-wide, PAT-617).

The property under test that matters most: a missing file, an unreadable
file, or an absent/unparseable sidecar must report "unknown", never "match"
-- absence reading as clean is this estate's single most repeated defect
(PAT-912, PAT-837, PAT-960; see this repo's root AGENTS.md). Every case here
that isn't a positively-confirmed match or mismatch asserts prometheus_rules_
status == "unknown" and BOTH hash fields individually, not just the derived
status, so a regression that reports a stale/wrong hash string but still
happens to land on "unknown" is still caught.

Driven the same way test_binary_inventory.py/test_deploy_script.py in this
directory already drive shell scripts from Python: subprocess against the
real script, PATH-shimmed rather than mocked in Python, run against a temp
tree. `id` is shimmed to satisfy the script's root preflight check (this
runs as an ordinary user in CI and locally); nothing else needs shimming --
apt-check/pro/kernel/apt-config all fail gracefully under the script's own
`|| true`/`2>/dev/null` guards on a non-Linux/non-apt dev machine, which is
exactly what test_pat1408_stray_config_backups.py in the sibling dashboard
repo already relies on for its own copy of this idea.
"""

from __future__ import annotations

import json
import os
import stat as stat_module
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.sh"


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


class MaintenanceFactsPrometheusRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        id_shim = self.fake_bin / "id"
        id_shim.write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
            'exec /usr/bin/id "$@"\n'
        )
        id_shim.chmod(id_shim.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)

        self.out_file = self.root / "out" / "maintenance.json"
        self.rules_file = self.root / "etc" / "patched.yml"
        self.sidecar = self.root / "etc" / "patched.yml.sha256"
        (self.root / "etc").mkdir()

    def _run(self) -> tuple[subprocess.CompletedProcess, dict]:
        env = dict(os.environ)
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env["OUT_FILE"] = str(self.out_file)
        env["PATCHED_PROM_RULES_FILE"] = str(self.rules_file)
        env["PATCHED_PROM_RULES_SIDECAR"] = str(self.sidecar)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.out_file.exists(), result.stderr)
        data = json.loads(self.out_file.read_text())
        return result, data

    def _write_sidecar(self, sha256: str) -> None:
        self.sidecar.write_text(
            f"INSTALLED_SHA256={sha256}\n"
            "INSTALLED_AT=2026-08-19T00:00:00Z\n"
            "SOURCE_COMMIT=" + ("a" * 40) + "\n"
        )

    # ── positive: a real match and a real mismatch ──────────────────────

    def test_matching_hash_reports_match(self):
        self.rules_file.write_text("groups: []\n")
        live_sha = _sha256(self.rules_file)
        self._write_sidecar(live_sha)

        _, data = self._run()

        self.assertEqual(data["prometheus_rules_live_sha256"], live_sha)
        self.assertEqual(data["prometheus_rules_sidecar_sha256"], live_sha)
        self.assertEqual(data["prometheus_rules_status"], "match")

    def test_mismatching_hash_reports_mismatch(self):
        self.rules_file.write_text("groups: []\n")
        live_sha = _sha256(self.rules_file)
        # Sidecar recorded a DIFFERENT hash than what's live now -- the
        # hand-edit-after-deploy shape this whole mechanism exists to catch.
        stale_sha = "0" * 64
        self.assertNotEqual(live_sha, stale_sha)
        self._write_sidecar(stale_sha)

        _, data = self._run()

        self.assertEqual(data["prometheus_rules_live_sha256"], live_sha)
        self.assertEqual(data["prometheus_rules_sidecar_sha256"], stale_sha)
        self.assertEqual(data["prometheus_rules_status"], "mismatch")

    # ── negative: every absence/unreadable shape reports unknown ────────

    def test_missing_rules_file_and_missing_sidecar_is_unknown(self):
        # Neither the rules file nor the sidecar exists at all.
        _, data = self._run()

        self.assertIsNone(data["prometheus_rules_live_sha256"])
        self.assertIsNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    def test_missing_sidecar_alone_is_unknown_not_match(self):
        # The live file is present and hashable, but no deploy has ever
        # recorded a sidecar -- this must NOT read as "match" just because
        # there's nothing to disagree with.
        self.rules_file.write_text("groups: []\n")

        _, data = self._run()

        self.assertIsNotNone(data["prometheus_rules_live_sha256"])
        self.assertIsNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    def test_missing_live_file_alone_is_unknown(self):
        # The sidecar exists (a deploy ran once) but the live file is gone
        # -- e.g. deleted by hand. Must not read as "match" either.
        self._write_sidecar("1" * 64)

        _, data = self._run()

        self.assertIsNone(data["prometheus_rules_live_sha256"])
        self.assertIsNotNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    def test_unreadable_rules_file_is_unknown_not_match(self):
        # A file that exists but this process cannot read (permissions) is
        # exactly as unknown as a missing one -- the emitter must not
        # distinguish "exists but unreadable" from "hashable" by accident.
        self.rules_file.write_text("groups: []\n")
        live_sha = _sha256(self.rules_file)
        self._write_sidecar(live_sha)
        self.rules_file.chmod(0o000)
        try:
            _, data = self._run()
        finally:
            self.rules_file.chmod(0o644)

        self.assertIsNone(data["prometheus_rules_live_sha256"])
        self.assertIsNotNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    def test_unreadable_sidecar_is_unknown_not_match(self):
        self.rules_file.write_text("groups: []\n")
        live_sha = _sha256(self.rules_file)
        self._write_sidecar(live_sha)
        self.sidecar.chmod(0o000)
        try:
            _, data = self._run()
        finally:
            self.sidecar.chmod(0o644)

        self.assertIsNotNone(data["prometheus_rules_live_sha256"])
        self.assertIsNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    def test_sidecar_with_no_installed_sha256_line_is_unknown(self):
        # A sidecar file exists but is malformed/foreign content -- no
        # INSTALLED_SHA256= line to parse at all.
        self.rules_file.write_text("groups: []\n")
        self.sidecar.write_text("this is not a sidecar file\n")

        _, data = self._run()

        self.assertIsNotNone(data["prometheus_rules_live_sha256"])
        self.assertIsNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    def test_sidecar_with_malformed_hash_is_unknown(self):
        # INSTALLED_SHA256= is present but not 64 lowercase hex chars --
        # must not be trusted or half-parsed into a false match.
        self.rules_file.write_text("groups: []\n")
        self._write_sidecar("not-a-real-hash")

        _, data = self._run()

        self.assertIsNone(data["prometheus_rules_sidecar_sha256"])
        self.assertEqual(data["prometheus_rules_status"], "unknown")

    # ── schema hygiene ───────────────────────────────────────────────────

    def test_existing_fields_are_untouched(self):
        """The header comment on this script says sibling emitters share one
        schema and existing fields must never be renamed. This is a live
        regression check for that invariant, not just a comment."""
        self.rules_file.write_text("groups: []\n")
        live_sha = _sha256(self.rules_file)
        self._write_sidecar(live_sha)

        _, data = self._run()

        for key in (
            "generated_at", "hostname", "pending_updates", "security_updates",
            "esm_updates", "pro_attached", "reboot_required", "running_kernel",
            "newest_kernel", "automatic_reboot_configured", "third_party_pending",
            "timers",
        ):
            self.assertIn(key, data)


if __name__ == "__main__":
    unittest.main()
