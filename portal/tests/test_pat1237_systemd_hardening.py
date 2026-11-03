"""PAT-1237: deploy/patched-maintenance-facts.sh's systemd_hardening
reporting (portal-01's copy).

Ported identically from dashboard/deploy/patched-maintenance-facts.sh's
PAT-1237 addition (dashboard/tests/test_pat1237_systemd_hardening.py is the
model this file mirrors) -- same discipline PAT-1431 already used to port
stray_config_backups to this repo. Driven the same way: subprocess against
the real script, PATH-shimmed rather than mocked in Python.

Built because nothing checked live units against patched.im/docs/systemd-
hardening-floor.md's ceilings: a manual survey on 2026-08-19 found
patched-maintenance-facts.service (the very emitter this test drives)
shipping unhardened and breaching its own 6.0 scheduled-maintenance ceiling
on all three boxes (portal-01 7.0 MEDIUM), undetected for 12 days.
test_portal01_live_output_reproduction below replays portal-01's own real
`systemd-analyze security patched-maintenance-facts.service` tail line,
captured live on 2026-08-19, as the acceptance evidence that this guard
actually fires against the real incident. It also covers patched-scan.service
and patched-scan-nvd-refresh.service, the two portal-01 units PAT-1237 added
to the class mapping (application / scheduled-maintenance respectively).

  `id` -> shimmed to satisfy the script's root preflight check.
  `timeout` -> this dev machine ships no GNU coreutils `timeout`; shim drops
      the duration arg and execs the rest.
  `systemctl` -> `list-unit-files 'patched-*.service' --no-legend` prints one
      line per configured unit; `show <unit> -p FragmentPath --value` prints
      /etc/systemd/system/<unit> by default (overridable per-unit); `show
      -p LastTriggerUSec/-p Result` answer "n/a"/"" so the pre-existing
      timers section stays empty, out of scope here.
  `systemd-analyze security <unit>` -> prints the real "Overall exposure
      level for <unit>: <score> <RATING>" tail line per configured unit.

Run with: pytest tests/test_pat1237_systemd_hardening.py -v
"""

import json
import os
import stat as stat_module
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"

_DEFAULT_UNITS = {
    "patched-portal.service": "4.3 OK",
    "patched-scan.service": "5.5 OK",
    "patched-scan-nvd-refresh.service": "5.9 OK",
    "patched-maintenance-facts.service": "7.0 MEDIUM",
}


def _fake_bin(
    tmp_path, units=None, fragpaths=None, garbled_units=None, no_systemd_analyze=False
) -> Path:
    units = dict(_DEFAULT_UNITS if units is None else units)
    fragpaths = fragpaths or {}
    garbled_units = garbled_units or []

    bindir = tmp_path / "fakebin"
    bindir.mkdir()

    (bindir / "id").write_text(
        "#!/bin/bash\n"
        'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
        'exec /usr/bin/id "$@"\n'
    )
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
            f'    {u}) echo "→ Overall exposure level for {u}: {score} :-)" ;;'
            for u, score in units.items()
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


def _run_script(tmp_path, **fake_bin_kwargs):
    bindir = _fake_bin(tmp_path, **fake_bin_kwargs)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["OUT_FILE"] = str(tmp_path / "maintenance.json")

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env=env, cwd=str(REPO),
        capture_output=True, text=True, timeout=30,
    )
    return result, tmp_path / "maintenance.json"


class TestEmitterScript:
    def test_known_units_scored_with_correct_class_and_ceiling(self, tmp_path):
        result, out_file = _run_script(tmp_path)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        hardening = data["systemd_hardening"]
        assert hardening["available"] is True
        by_unit = {u["unit"]: u for u in hardening["units"]}

        mf = by_unit["patched-maintenance-facts.service"]
        assert mf["score"] == 7.0
        assert mf["class"] == "scheduled-maintenance"
        assert mf["ceiling"] == 6.0
        assert mf["over_ceiling"] is True

        portal = by_unit["patched-portal.service"]
        assert portal["class"] == "application"
        assert portal["over_ceiling"] is False

        scan = by_unit["patched-scan.service"]
        assert scan["class"] == "application"
        assert scan["ceiling"] == 6.0

        scan_nvd = by_unit["patched-scan-nvd-refresh.service"]
        assert scan_nvd["class"] == "scheduled-maintenance"
        assert scan_nvd["ceiling"] == 6.0

    def test_unclassified_unit_gets_null_class_ceiling_over_ceiling(self, tmp_path):
        result, out_file = _run_script(
            tmp_path, units={"patched-brand-new-thing.service": "2.0 OK"}
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        units = data["systemd_hardening"]["units"]
        assert len(units) == 1
        entry = units[0]
        assert entry["score"] == 2.0
        assert entry["class"] is None
        assert entry["ceiling"] is None
        assert entry["over_ceiling"] is None

    def test_unit_not_under_etc_systemd_system_is_excluded(self, tmp_path):
        vendored_unit = "patched-vendored-elsewhere.service"
        result, out_file = _run_script(
            tmp_path,
            units={vendored_unit: "9.9 UNSAFE"},
            fragpaths={vendored_unit: f"/usr/lib/systemd/system/{vendored_unit}"},
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"]["units"] == []
        assert data["systemd_hardening"]["available"] is True

    def test_systemd_analyze_missing_is_available_false_units_empty(self, tmp_path):
        result, out_file = _run_script(tmp_path, no_systemd_analyze=True)
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"] == {"available": False, "units": []}

    def test_total_parse_failure_fails_closed(self, tmp_path):
        result, out_file = _run_script(
            tmp_path, units={}, garbled_units=["patched-only-unit.service"]
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"] == {"available": False, "units": []}

    def test_one_unparseable_unit_among_good_ones_is_reported_not_dropped(self, tmp_path):
        """The mixed case, distinct from the systemic failure above: when
        some units parse and one does not, the unparseable one must still
        appear in the array with null score/rating so the consumer can
        bucket it, rather than silently vanishing.

        A dropped unit is the worst failure available to this guard - a unit
        missing from the array is indistinguishable from a unit that was
        never installed, so a newly-broken unit could leave the report
        looking complete and clean. PAT-1237's non-author review raised this
        as a possibility; the behaviour is correct, and this pins it.
        """
        result, out_file = _run_script(
            tmp_path,
            units={
                "patched-portal.service": "4.3 OK",
                "patched-maintenance-facts.service": "7.0 MEDIUM",
            },
            garbled_units=["patched-mystery.service"],
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        hardening = data["systemd_hardening"]
        assert hardening["available"] is True
        by_unit = {u["unit"]: u for u in hardening["units"]}

        assert "patched-mystery.service" in by_unit, (
            "an unparseable unit vanished from the units array; a missing unit reads "
            "as 'not installed', the absence-reads-as-clean shape this guard prevents"
        )
        assert by_unit["patched-mystery.service"]["score"] is None
        assert by_unit["patched-mystery.service"]["rating"] is None
        assert by_unit["patched-mystery.service"]["over_ceiling"] is None

        # Neighbours that did parse are unaffected. 7.0 breaches the 6.0
        # scheduled-maintenance ceiling; 4.3 clears the 6.0 application one.
        assert by_unit["patched-maintenance-facts.service"]["over_ceiling"] is True
        assert by_unit["patched-portal.service"]["over_ceiling"] is False

    def test_no_candidate_units_is_available_true_empty_units(self, tmp_path):
        result, out_file = _run_script(tmp_path, units={})
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"] == {"available": True, "units": []}

    def test_whole_document_schema_still_intact(self, tmp_path):
        result, out_file = _run_script(tmp_path, units={})
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text())
        for key in (
            "generated_at", "hostname", "pending_updates", "security_updates",
            "esm_updates", "pro_attached", "reboot_required", "running_kernel",
            "newest_kernel", "automatic_reboot_configured", "third_party_pending",
            "timers", "stray_config_backups", "systemd_hardening",
        ):
            assert key in data

    def test_portal01_live_output_reproduction(self, tmp_path):
        """Acceptance evidence: replay portal-01's own real `systemd-analyze
        security patched-maintenance-facts.service` tail line, captured live
        via SSH on 2026-08-19, byte for byte."""
        # Real systemctl enumeration/FragmentPath shim from _fake_bin is
        # reused as-is (only patched-maintenance-facts.service, its real
        # FragmentPath) -- only systemd-analyze is overridden below with
        # the captured live output, so this test isn't duplicating the
        # shim-building logic already covered elsewhere in this file.
        bindir = _fake_bin(tmp_path, units={"patched-maintenance-facts.service": "unused"})
        real_output = (
            "✗ UMask=                                                      "
            "Files created by service are world-readable by default"
            "                       0.1\n"
            "\n"
            "→ Overall exposure level for patched-maintenance-facts.service: "
            "7.0 MEDIUM :-|\n"
        )
        (bindir / "systemd-analyze").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "security" ] && [ "$2" = "patched-maintenance-facts.service" ]; then\n'
            f"  cat <<'REALOUT'\n{real_output}REALOUT\n"
            "  exit 0\n"
            "fi\n"
            "exit 1\n"
        )
        (bindir / "systemd-analyze").chmod(
            (bindir / "systemd-analyze").stat().st_mode
            | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH
        )

        env = dict(os.environ)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        env["OUT_FILE"] = str(tmp_path / "maintenance.json")
        result = subprocess.run(
            ["bash", str(SCRIPT)], env=env, cwd=str(REPO),
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads((tmp_path / "maintenance.json").read_text())
        units = data["systemd_hardening"]["units"]
        assert len(units) == 1
        entry = units[0]
        assert entry["unit"] == "patched-maintenance-facts.service"
        assert entry["score"] == 7.0
        assert entry["rating"] == "MEDIUM"
        assert entry["class"] == "scheduled-maintenance"
        assert entry["ceiling"] == 6.0
        assert entry["over_ceiling"] is True
