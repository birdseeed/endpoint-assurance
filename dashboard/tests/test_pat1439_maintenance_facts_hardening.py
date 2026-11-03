"""PAT-1439: deploy/patched-maintenance-facts.service must carry the full
systemd-hardening-floor.md minimum directive set for the scheduled-
maintenance class.

Before this ticket the unit shipped with ZERO hardening directives at all --
9.6 UNSAFE, the worst score of any Patched unit -- for 12 days, until
PAT-1237's drift guard caught it (see docs/systemd-hardening-floor.md,
"The drift guard (PAT-1237)"). The directive set asserted below was proven
empirically against a temporary probe unit on all three boxes (prod-01,
api-01, portal-01): Result=success, exit 0, correct output including
pro_attached: true, output file 0644 root:root, and `systemd-analyze
security` = 2.0 OK on every box.

This is a static content check over the checked-in unit file -- it does not
run systemd (this dev machine has none) and does not replace `systemd-
analyze security <unit>` run live on a box, which is the only thing that
proves the score itself (see the floor doc's "Verifying a unit meets the
floor" section).

Run with: pytest tests/test_pat1439_maintenance_facts_hardening.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
UNIT_PATH = REPO_ROOT / "deploy" / "patched-maintenance-facts.service"

# The exact minimum directive set from patched.im/docs/systemd-hardening-
# floor.md, proven empirically per this ticket's brief -- copied verbatim,
# not re-derived. ReadWritePaths is checked separately below since its
# value (the four paths) matters as much as its presence.
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
    # Only the [Service] section's directive lines -- comments and blank
    # lines dropped, [Unit]/[Install] excluded so a directive that happens
    # to share a name elsewhere doesn't produce a false positive.
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


class TestMaintenanceFactsUnitHardening:
    def test_unit_file_exists(self):
        assert UNIT_PATH.is_file(), f"{UNIT_PATH} is missing"

    def test_every_floor_directive_present_with_correct_value(self):
        lines = _service_lines()
        for key, expected_value in REQUIRED_BOOLEAN_OR_FIXED_DIRECTIVES.items():
            values = _directive_values(lines, key)
            assert values, f"{key}= is missing from the [Service] block"
            assert values == [expected_value], (
                f"{key} must be exactly '{expected_value}', got {values!r}"
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
        assert not dupes, f"duplicated directive(s) in [Service]: {sorted(dupes)}"

    def test_readwritepaths_includes_ubuntu_advantage_paths(self):
        lines = _service_lines()
        values = _directive_values(lines, "ReadWritePaths")
        assert values, "ReadWritePaths= is missing from the [Service] block"
        assert len(values) == 1, f"ReadWritePaths must appear exactly once, got {values!r}"
        paths = set(values[0].split())
        missing = REQUIRED_READWRITEPATHS - paths
        assert not missing, (
            f"ReadWritePaths is missing {sorted(missing)} -- these three ubuntu-advantage "
            "paths exist because `pro status` writes lock/log files there even for a "
            "read-only query, and under ProtectSystem=strict without them the query fails, "
            "is swallowed by the script's `2>/dev/null`, and silently reports "
            "pro_attached: false (hit in production on api-01, 2026-08-07). Do not trim "
            "them as 'unused'."
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
        assert _directive_values(lines, "StateDirectory") == ["patched"]
        assert _directive_values(lines, "StateDirectoryMode") == ["0755"]
        rwp = _directive_values(lines, "ReadWritePaths")
        assert rwp, "ReadWritePaths= is missing from the [Service] block"
        assert "/var/lib/patched" not in set(rwp[0].split()), (
            "/var/lib/patched must not be a ReadWritePaths entry -- StateDirectory "
            "already provides it, and listing it there reintroduces the "
            "must-already-exist failure mode StateDirectory exists to avoid"
        )

    def test_ubuntu_advantage_reasoning_comment_is_preserved(self):
        # The comment explaining WHY those three paths must not be trimmed
        # must survive, not just the paths themselves -- a future tidy-up
        # reading the unit file with no context is exactly what re-
        # introduces the api-01 2026-08-07 incident this comment documents.
        text = UNIT_PATH.read_text(encoding="utf-8")
        assert "pro status" in text
        assert "2026-08-07" in text
        assert re.search(r"PAT-990", text), "the PAT-990 cross-reference must be preserved"

    def test_preexisting_fields_are_untouched(self):
        text = UNIT_PATH.read_text(encoding="utf-8")
        assert "Description=Write patch/reboot/timer drift snapshot for patched-prod-01 (PAT-989)" in text
        assert "ExecStart=/opt/patched-dashboard/deploy/patched-maintenance-facts.sh" in text
        assert "User=root" in text
        assert "Restart=no" in text
        assert "TimeoutStartSec=2min" in text
        assert "WantedBy=multi-user.target" in text

    def test_no_probe_only_environment_override_leaked_in(self):
        # OUT_FILE was probe-only, used to point a temporary test unit at a
        # scratch output path -- production must keep the script's default
        # output path, never an Environment=OUT_FILE= override baked into
        # the shipped unit.
        text = UNIT_PATH.read_text(encoding="utf-8")
        assert "OUT_FILE" not in text
