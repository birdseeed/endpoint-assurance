"""PAT-1237: api-vps-artefacts/patched-maintenance-facts.sh's
systemd_hardening reporting.

Ported identically from dashboard/deploy/patched-maintenance-facts.sh's
PAT-1237 addition (dashboard/tests/test_pat1237_systemd_hardening.py is the
model this file mirrors), same discipline test_pat1431_stray_config_backups.py
already used for stray_config_backups: driven the same way
test_maintenance_facts_prometheus_rules.py (same directory) drives this
script from Python -- subprocess against the real script, PATH-shimmed
rather than mocked in Python.

Built because nothing checked live units against patched.im/docs/systemd-
hardening-floor.md's ceilings: a manual survey on 2026-08-19 found
patched-maintenance-facts.service (the very emitter this test drives)
shipping unhardened and breaching its own 6.0 scheduled-maintenance ceiling
on all three boxes (api-01 6.3 MEDIUM), undetected for 12 days.
test_prod01_live_output_reproduction below replays api-01's own real
`systemd-analyze security patched-maintenance-facts.service` tail line,
captured live on 2026-08-19, as the acceptance evidence that this guard
actually fires against the real incident.

  `id` -> shimmed to satisfy the script's root preflight check.
  `apt-cache` -> success no-op (same as test_pat1431).
  `timeout` -> this dev machine ships no GNU coreutils `timeout`; shim drops
      the duration arg and execs the rest.
  `systemctl` -> `list-unit-files 'patched-*.service' --no-legend` prints one
      line per configured unit; `show <unit> -p FragmentPath --value` prints
      /etc/systemd/system/<unit> by default (overridable per-unit); `show
      -p LastTriggerUSec/-p Result` answer "n/a"/"" so the pre-existing
      timers section stays empty, out of scope here.
  `systemd-analyze security <unit>` -> prints the real "Overall exposure
      level for <unit>: <score> <RATING>" tail line per configured unit.

Run with: python3 -m unittest deploy.api-01.test_pat1237_systemd_hardening -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
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

_DEFAULT_UNITS = {
    "patched-backup.service": "5.1 MEDIUM",
    "patched-maintenance-facts.service": "6.3 MEDIUM",
}


class SystemdHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.out_file = self.root / "out" / "maintenance.json"

    def _fake_bin(self, units=None, fragpaths=None, garbled_units=None, no_systemd_analyze=False) -> Path:
        units = dict(_DEFAULT_UNITS if units is None else units)
        fragpaths = fragpaths or {}
        garbled_units = garbled_units or []

        bindir = self.root / "fake-bin"
        bindir.mkdir()

        (bindir / "id").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
            'exec /usr/bin/id "$@"\n'
        )
        (bindir / "apt-cache").write_text("#!/bin/bash\nexit 0\n")
        (bindir / "timeout").write_text('#!/bin/bash\nshift\nexec "$@"\n')

        all_unit_names = list(units.keys()) + list(garbled_units)
        list_unit_files_lines = "\n".join(f"echo '{u} enabled enabled'" for u in all_unit_names)
        fragpath_cases = "\n".join(
            f'    {u}) echo "{fragpaths.get(u, f"/etc/systemd/system/{u}")}" ;;' for u in all_unit_names
        )
        (bindir / "systemctl").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "list-unit-files" ]; then\n'
            f"{list_unit_files_lines}\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = "show" ]; then\n'
            '  unit="$2"\n'
            '  if [[ "$*" == *"FragmentPath"* ]]; then\n'
            '    case "$unit" in\n'
            f"{fragpath_cases}\n"
            '      *) echo "/etc/systemd/system/$unit" ;;\n'
            "    esac\n"
            "    exit 0\n"
            "  fi\n"
            '  if [[ "$*" == *"LastTriggerUSec"* ]]; then echo "n/a"; exit 0; fi\n'
            '  if [[ "$*" == *"-p Result"* ]]; then echo ""; exit 0; fi\n'
            "  exit 1\n"
            "fi\n"
            "exit 1\n"
        )

        if not no_systemd_analyze:
            score_cases = "\n".join(
                f'    {u}) echo "→ Overall exposure level for {u}: {score} :-)" ;;' for u, score in units.items()
            )
            garbled_cases = "\n".join(
                f'    {u}) echo "Unit {u} not found, cannot analyze." ;;' for u in garbled_units
            )
            (bindir / "systemd-analyze").write_text(
                "#!/bin/bash\n"
                'if [ "$1" = "security" ]; then\n'
                '  unit="$2"\n'
                '  case "$unit" in\n'
                f"{score_cases}\n"
                f"{garbled_cases}\n"
                "  esac\n"
                "  exit 0\n"
                "fi\n"
                "exit 1\n"
            )

        for f in bindir.iterdir():
            f.chmod(f.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)
        return bindir

    def _run(self, **fake_bin_kwargs):
        bindir = self._fake_bin(**fake_bin_kwargs)
        env = dict(os.environ)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        env["OUT_FILE"] = str(self.out_file)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.out_file.exists(), result.stderr)
        data = json.loads(self.out_file.read_text())
        return result, data

    def test_known_units_scored_with_correct_class_and_ceiling(self):
        _, data = self._run()
        hardening = data["systemd_hardening"]
        self.assertTrue(hardening["available"])
        by_unit = {u["unit"]: u for u in hardening["units"]}

        mf = by_unit["patched-maintenance-facts.service"]
        self.assertEqual(mf["score"], 6.3)
        self.assertEqual(mf["class"], "scheduled-maintenance")
        self.assertEqual(mf["ceiling"], 6.0)
        self.assertTrue(mf["over_ceiling"])

        backup = by_unit["patched-backup.service"]
        self.assertEqual(backup["score"], 5.1)
        self.assertEqual(backup["class"], "credential-handling")
        self.assertEqual(backup["ceiling"], 6.7)
        self.assertFalse(backup["over_ceiling"])

    def test_unclassified_unit_gets_null_class_ceiling_over_ceiling(self):
        _, data = self._run(units={"patched-brand-new-thing.service": "2.0 OK"})
        units = data["systemd_hardening"]["units"]
        self.assertEqual(len(units), 1)
        entry = units[0]
        self.assertEqual(entry["score"], 2.0)
        self.assertIsNone(entry["class"])
        self.assertIsNone(entry["ceiling"])
        self.assertIsNone(entry["over_ceiling"])

    def test_unit_not_under_etc_systemd_system_is_excluded(self):
        _, data = self._run(
            units={"patched-vendored-elsewhere.service": "9.9 UNSAFE"},
            fragpaths={"patched-vendored-elsewhere.service": "/usr/lib/systemd/system/patched-vendored-elsewhere.service"},
        )
        self.assertEqual(data["systemd_hardening"]["units"], [])
        self.assertTrue(data["systemd_hardening"]["available"])

    def test_systemd_analyze_missing_is_available_false_units_empty(self):
        _, data = self._run(no_systemd_analyze=True)
        self.assertEqual(data["systemd_hardening"], {"available": False, "units": []})

    def test_total_parse_failure_fails_closed(self):
        _, data = self._run(units={}, garbled_units=["patched-only-unit.service"])
        self.assertEqual(data["systemd_hardening"], {"available": False, "units": []})

    def test_one_unparseable_unit_among_good_ones_is_reported_not_dropped(self):
        """The mixed case, distinct from the systemic failure above: when
        some units parse and one does not, the unparseable one must still
        appear in the array with null score/rating so the consumer can
        bucket it, rather than silently vanishing.

        A dropped unit is the worst failure available to this guard -- a unit
        missing from the array is indistinguishable from a unit that was
        never installed, so a newly-broken unit could leave the report
        looking complete and clean. PAT-1237's non-author review raised this
        as a possibility; the behaviour is correct, and this pins it.
        """
        _, data = self._run(
            units={
                "patched-api.service": "5.9 MEDIUM",
                "patched-maintenance-facts.service": "6.3 MEDIUM",
            },
            garbled_units=["patched-mystery.service"],
        )
        hardening = data["systemd_hardening"]
        self.assertTrue(hardening["available"])
        by_unit = {u["unit"]: u for u in hardening["units"]}

        self.assertIn(
            "patched-mystery.service", by_unit,
            "an unparseable unit vanished from the units array; a missing unit reads "
            "as 'not installed', the absence-reads-as-clean shape this guard prevents",
        )
        self.assertIsNone(by_unit["patched-mystery.service"]["score"])
        self.assertIsNone(by_unit["patched-mystery.service"]["rating"])
        self.assertIsNone(by_unit["patched-mystery.service"]["over_ceiling"])

        # Neighbours that did parse are unaffected. 6.3 breaches the 6.0
        # scheduled-maintenance ceiling; 5.9 clears the 6.0 application one.
        self.assertTrue(by_unit["patched-maintenance-facts.service"]["over_ceiling"])
        self.assertFalse(by_unit["patched-api.service"]["over_ceiling"])

    def test_no_candidate_units_is_available_true_empty_units(self):
        _, data = self._run(units={})
        self.assertEqual(data["systemd_hardening"], {"available": True, "units": []})

    def test_whole_document_schema_still_intact(self):
        _, data = self._run(units={})
        for key in (
            "generated_at", "hostname", "pending_updates", "security_updates",
            "esm_updates", "pro_attached", "reboot_required", "running_kernel",
            "newest_kernel", "automatic_reboot_configured", "third_party_pending",
            "timers", "prometheus_rules_live_sha256", "prometheus_rules_sidecar_sha256",
            "prometheus_rules_status", "stray_config_backups", "systemd_hardening",
        ):
            self.assertIn(key, data)

    def test_api01_live_output_reproduction(self):
        """Acceptance evidence: replay api-01's own real `systemd-analyze
        security patched-maintenance-facts.service` tail line, captured live
        via SSH on 2026-08-19, byte for byte."""
        bindir = self._fake_bin(units={})
        (bindir / "systemd-analyze").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "security" ]; then\n'
            '  if [ "$2" = "patched-maintenance-facts.service" ]; then\n'
            "    cat <<'REALOUT'\n"
            "✗ UMask=                                                      Files created by service are world-readable by default                       0.1\n"
            "\n"
            "→ Overall exposure level for patched-maintenance-facts.service: 6.3 MEDIUM :-|\n"
            "REALOUT\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "exit 1\n"
        )
        (bindir / "systemctl").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "list-unit-files" ]; then\n'
            "  echo 'patched-maintenance-facts.service disabled enabled'\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = "show" ]; then\n'
            '  unit="$2"\n'
            '  if [[ "$*" == *"FragmentPath"* ]]; then echo "/etc/systemd/system/$unit"; exit 0; fi\n'
            '  if [[ "$*" == *"LastTriggerUSec"* ]]; then echo "n/a"; exit 0; fi\n'
            '  if [[ "$*" == *"-p Result"* ]]; then echo ""; exit 0; fi\n'
            "  exit 1\n"
            "fi\n"
            "exit 1\n"
        )
        for f in bindir.iterdir():
            f.chmod(f.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)

        env = dict(os.environ)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        env["OUT_FILE"] = str(self.out_file)
        result = subprocess.run(
            ["bash", str(SCRIPT)], env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.out_file.read_text())
        units = data["systemd_hardening"]["units"]
        self.assertEqual(len(units), 1)
        entry = units[0]
        self.assertEqual(entry["unit"], "patched-maintenance-facts.service")
        self.assertEqual(entry["score"], 6.3)
        self.assertEqual(entry["rating"], "MEDIUM")
        self.assertEqual(entry["class"], "scheduled-maintenance")
        self.assertEqual(entry["ceiling"], 6.0)
        self.assertTrue(entry["over_ceiling"])


if __name__ == "__main__":
    unittest.main()
