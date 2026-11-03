"""PAT-1439: api-vps-artefacts/patched-maintenance-facts.service must carry
the full systemd-hardening-floor.md minimum directive set for the
scheduled-maintenance class.

Before this ticket the unit was 6.3 MEDIUM with 14 directives -- missing
ProtectKernelLogs, ProtectClock, ProtectHostname, ProtectProc, ProcSubset,
RestrictSUIDSGID, RestrictAddressFamilies, SystemCallFilter,
SystemCallErrorNumber and CapabilityBoundingSet -- breaching the 6.0
scheduled-maintenance ceiling (docs/systemd-hardening-floor.md). The
directive set asserted below was proven empirically against a temporary
probe unit on all three boxes (prod-01, api-01, portal-01):
Result=success, exit 0, correct output including pro_attached: true,
output file 0644 root:root, and `systemd-analyze security` = 2.0 OK on
every box.

This is a static content check over the checked-in unit file -- it does not
run systemd (this dev machine has none) and does not replace `systemd-
analyze security <unit>` run live on a box, which is the only thing that
proves the score itself (see the floor doc's "Verifying a unit meets the
floor" section).

Run with: python3 -m unittest deploy.api-01.test_pat1439_maintenance_facts_hardening -v
(or via `python3 -m unittest discover -s deploy/api-01 -p 'test_*.py'`)
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_PATH = REPO_ROOT / "api-vps-artefacts" / "patched-maintenance-facts.service"

REQUIRED_BOOLEAN_OR_FIXED_DIRECTIVES = {
    "NoNewPrivileges": "true",
    "ProtectSystem": "strict",
    "ProtectHome": "true",
    "PrivateTmp": "true",
    "PrivateDevices": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectKernelLogs": "true",
    "ProtectControlGroups": "true",
    "ProtectClock": "true",
    "ProtectHostname": "true",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictNamespaces": "true",
    "RestrictRealtime": "true",
    "RestrictSUIDSGID": "true",
    "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
    "LockPersonality": "true",
    "MemoryDenyWriteExecute": "true",
    "SystemCallArchitectures": "native",
    "SystemCallFilter": "@system-service",
    "SystemCallErrorNumber": "EPERM",
    # Empty on purpose (PAT-1439): dropping CAP_DAC_READ_SEARCH was tested
    # on all three boxes, changed nothing in the output, and improved the
    # exposure score 2.0 -> 1.8. Every file the script reads is root-owned,
    # so owner DAC permits it with no capability at all.
    "CapabilityBoundingSet": "",
}

REQUIRED_READWRITEPATHS = {
    "/var/lib/ubuntu-advantage",
    "/var/log/ubuntu-advantage.log",
    "/run/ubuntu-advantage",
}


def _service_lines() -> list[str]:
    text = UNIT_PATH.read_text(encoding="utf-8")
    in_service = False
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_service = line == "[Service]"
            continue
        if not in_service or not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _directive_values(lines: list[str], key: str) -> list[str]:
    prefix = f"{key}="
    return [line[len(prefix):] for line in lines if line.startswith(prefix)]


class MaintenanceFactsUnitHardeningTests(unittest.TestCase):
    def test_unit_file_exists(self):
        self.assertTrue(UNIT_PATH.is_file(), f"{UNIT_PATH} is missing")

    def test_every_floor_directive_present_with_correct_value(self):
        lines = _service_lines()
        for key, expected_value in REQUIRED_BOOLEAN_OR_FIXED_DIRECTIVES.items():
            values = _directive_values(lines, key)
            self.assertTrue(values, f"{key}= is missing from the [Service] block")
            self.assertEqual(
                values, [expected_value],
                f"{key} must be exactly '{expected_value}', got {values!r}",
            )

    def test_no_directive_is_duplicated(self):
        lines = _service_lines()
        keys = [line.split("=", 1)[0] for line in lines if "=" in line]
        seen = set()
        dupes = set()
        for k in keys:
            if k in seen:
                dupes.add(k)
            seen.add(k)
        self.assertFalse(dupes, f"duplicated directive(s) in [Service]: {sorted(dupes)}")

    def test_readwritepaths_includes_ubuntu_advantage_paths(self):
        lines = _service_lines()
        values = _directive_values(lines, "ReadWritePaths")
        self.assertTrue(values, "ReadWritePaths= is missing from the [Service] block")
        self.assertEqual(len(values), 1, f"ReadWritePaths must appear exactly once, got {values!r}")
        paths = set(values[0].split())
        missing = REQUIRED_READWRITEPATHS - paths
        self.assertFalse(
            missing,
            f"ReadWritePaths is missing {sorted(missing)} -- these three ubuntu-advantage "
            "paths exist because the bounded Ubuntu Pro attachment API writes lock/log "
            "files there even for a read-only query. Do not trim them as 'unused'.",
        )

    def test_state_directory_provides_the_state_dir_not_readwritepaths(self):
        """/var/lib/patched must come from StateDirectory=, never from a
        ReadWritePaths= entry.

        The two are not interchangeable. StateDirectory CREATES the directory
        if it is absent; ReadWritePaths requires it to already exist and fails
        the entire unit with status=226/NAMESPACE if it does not -- verified
        live on portal-01 under PAT-1439, not assumed. portal-01's unit used
        StateDirectory before this ticket, and an earlier draft dropped it to
        make the three units uniform; that would have traded a self-healing
        mechanism for an assumption about box state, breaking a fresh box
        build or any box where the directory was ever removed. The uniformity
        goes the other way instead: all three use StateDirectory.

        0755 matters on prod-01 specifically: the dashboard reads
        maintenance.json as www-data, so the directory must stay traversable.
        """
        lines = _service_lines()
        self.assertEqual(_directive_values(lines, "StateDirectory"), ["patched"])
        self.assertEqual(_directive_values(lines, "StateDirectoryMode"), ["0755"])
        rwp = _directive_values(lines, "ReadWritePaths")
        self.assertTrue(rwp, "ReadWritePaths= is missing from the [Service] block")
        self.assertNotIn("/var/lib/patched", set(rwp[0].split()), (
            "/var/lib/patched must not be a ReadWritePaths entry -- StateDirectory "
            "already provides it, and listing it there reintroduces the "
            "must-already-exist failure mode StateDirectory exists to avoid"
        ))

    def test_ubuntu_advantage_reasoning_comment_is_preserved(self):
        text = UNIT_PATH.read_text(encoding="utf-8")
        self.assertIn("u.pro.status.is_attached.v1", text)
        self.assertIn("pro_attached: null", text)
        self.assertIn("PAT-990", text, "the PAT-990 cross-reference must be preserved")

    def test_preexisting_fields_are_untouched(self):
        text = UNIT_PATH.read_text(encoding="utf-8")
        self.assertIn("Description=patched.im maintenance facts snapshot", text)
        self.assertIn("ExecStart=/opt/patched-api/bin/patched-maintenance-facts.sh", text)
        self.assertIn("User=root", text)
        self.assertIn("Group=root", text)
        self.assertIn("WorkingDirectory=/opt/patched-api", text)
        self.assertIn("SyslogIdentifier=patched-maintenance-facts", text)

    def test_no_probe_only_environment_override_leaked_in(self):
        text = UNIT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("OUT_FILE", text)


if __name__ == "__main__":
    unittest.main()
