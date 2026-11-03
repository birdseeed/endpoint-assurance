"""
PAT-1237: score every patched-owned systemd unit against
patched.im/docs/systemd-hardening-floor.md's per-class ceiling, and degrade
the maintenance_* row when any unit breaches its ceiling or can't be judged.

Built because nothing checked live units against the floor doc's ceilings --
a manual survey on 2026-08-19 found patched-maintenance-facts.service itself
(the emitter this test drives) shipping with zero hardening directives and
breaching its own 6.0 scheduled-maintenance ceiling on all three boxes
(prod-01 9.6 UNSAFE, portal-01 7.0, api-01 6.3), undetected for 12 days.
PAT-1439 hardens those units; this ticket is the guard that would have
caught the regression the day it shipped -- see deploy/patched-
maintenance-facts.sh's own PARITY-BLOCK comment for the full story.

Two halves, mirroring tests/test_pat1408_stray_config_backups.py's model for
driving a real bash script from Python via subprocess:

  * TestEmitterScript -- drives the real deploy/patched-maintenance-facts.sh
    end-to-end against a fake PATH (`id`/`apt-cache`/`systemctl`/
    `systemd-analyze`/`timeout` shimmed -- this dev machine has no systemd
    and macOS ships no GNU `timeout` at all) and asserts the JSON it writes.
    One test (test_prod01_live_output_reproduction) replays prod-01's own
    real `systemd-analyze security patched-maintenance-facts.service` output
    captured live on 2026-08-19, byte for byte, as the acceptance evidence
    that this guard actually fires against the real incident rather than
    only against a synthetic fixture.

  * TestConsumer -- exercises _systemd_hardening_findings() and
    _run_maintenance_drift_check_tick()'s handling of the field directly,
    the same way test_pat1408_stray_config_backups.py's TestConsumer half
    exercises _stray_config_backup_findings(). The single most important
    case here is the unclassified unit: a unit systemd-analyze scored but
    that isn't in the class mapping must read as degraded, NEVER as passing
    just because it has no ceiling to compare against.

Run with: pytest tests/test_pat1237_systemd_hardening.py -v
"""

import json
import os
import stat as stat_module
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"


# ═════════════════════════════════════════════════════════════════════════
# Part 1: the emitter script itself
# ═════════════════════════════════════════════════════════════════════════


# unit -> "Overall exposure level for <unit>: <score> <RATING>" line to have
# the systemd-analyze shim print (a real "systemd-analyze security" call's
# tail line, format confirmed live on prod-01/api-01/portal-01 -- exit code
# 0 regardless of rating, so this line is the only reliable signal, same
# discipline the emitter itself uses).
_DEFAULT_UNITS = {
    "patched-dashboard.service": "3.2 OK",
    "patched-maintenance-facts.service": "9.6 UNSAFE",
}


def _fake_bin(tmp_path, units=None, fragpaths=None, garbled_units=None, no_systemd_analyze=False) -> Path:
    """Shim directory for running deploy/patched-maintenance-facts.sh on a
    macOS dev box against fake systemd state.

    `id -u` -> 0: the script's root preflight check.
    `apt-cache` -> success no-op, same as test_pat1408_stray_config_backups.py.
    `systemctl` -> `list-unit-files 'patched-*.service' --no-legend` prints
        one line per unit in `units` (plus any name in `garbled_units`, which
        exists to be enumerated but produce unparseable systemd-analyze
        output); `show <unit> -p FragmentPath --value` prints
        /etc/systemd/system/<unit> unless overridden per-unit by `fragpaths`
        (used to prove the FragmentPath-under-/etc/systemd/system filter
        actually excludes a unit); `show <unit> -p LastTriggerUSec/-p Result`
        answer "n/a"/"" so the pre-existing timers section (out of scope
        here) stays empty, same as test_pat1408's shim.
    `systemd-analyze security <unit>` -> prints the "Overall exposure level
        for <unit>: <score> <RATING>" line for every name in `units`; a name
        in `garbled_units` gets unparseable output instead (proving a
        single unit's parse failure surfaces as an unjudged unit, not a
        crash); omitted entirely if `no_systemd_analyze` (proves the
        command-missing fail-closed path).
    `timeout` -> macOS ships no GNU coreutils `timeout` by default; this
        shim just drops the duration arg and execs the rest, matching real
        `timeout`'s behaviour for a command that returns promptly (which
        every command in this test does).
    """
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
    (bindir / "apt-cache").write_text("#!/bin/bash\nexit 0\n")
    (bindir / "timeout").write_text("#!/bin/bash\nshift\nexec \"$@\"\n")

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
    def test_known_unit_over_ceiling_is_flagged(self, tmp_path):
        result, out_file = _run_script(tmp_path)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        hardening = data["systemd_hardening"]
        assert hardening["available"] is True
        by_unit = {u["unit"]: u for u in hardening["units"]}

        mf = by_unit["patched-maintenance-facts.service"]
        assert mf["score"] == 9.6
        assert mf["rating"] == "UNSAFE"
        assert mf["class"] == "scheduled-maintenance"
        assert mf["ceiling"] == 6.0
        assert mf["over_ceiling"] is True

        dash = by_unit["patched-dashboard.service"]
        assert dash["score"] == 3.2
        assert dash["class"] == "application"
        assert dash["ceiling"] == 6.0
        assert dash["over_ceiling"] is False

    def test_unclassified_unit_gets_null_class_ceiling_over_ceiling(self, tmp_path):
        """The single most important case in this ticket: a unit the scan
        finds but the class mapping doesn't recognise must still be scored
        (score/rating present) but must NEVER read as passing -- class,
        ceiling and over_ceiling all come back JSON null, distinct from
        over_ceiling=false."""
        result, out_file = _run_script(
            tmp_path, units={"patched-brand-new-thing.service": "2.0 OK"}
        )
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        units = data["systemd_hardening"]["units"]
        assert len(units) == 1
        entry = units[0]
        assert entry["unit"] == "patched-brand-new-thing.service"
        assert entry["score"] == 2.0
        assert entry["rating"] == "OK"
        assert entry["class"] is None
        assert entry["ceiling"] is None
        assert entry["over_ceiling"] is None

    def test_unit_not_under_etc_systemd_system_is_excluded(self, tmp_path):
        """A unit whose FragmentPath isn't under /etc/systemd/system must be
        excluded even though its name matches the patched-* glob -- this is
        the second half of the property test (name prefix AND FragmentPath),
        and it's what naturally excludes vendor units like hc-net-scan
        without ever naming them (those already fail the name-prefix half;
        this proves the FragmentPath half also holds on its own)."""
        result, out_file = _run_script(
            tmp_path,
            units={"patched-vendored-elsewhere.service": "9.9 UNSAFE"},
            fragpaths={"patched-vendored-elsewhere.service": "/usr/lib/systemd/system/patched-vendored-elsewhere.service"},
        )
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"]["units"] == []
        # available stays true -- nothing was systemically wrong, this one
        # candidate was correctly filtered out before scoring.
        assert data["systemd_hardening"]["available"] is True

    def test_systemd_analyze_missing_is_available_false_units_empty(self, tmp_path):
        result, out_file = _run_script(tmp_path, no_systemd_analyze=True)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"] == {"available": False, "units": []}

    def test_total_parse_failure_across_every_candidate_fails_closed(self, tmp_path):
        """If systemd-analyze exists and ran but not one candidate unit's
        output was parseable (a systemically broken invocation), the field
        must not report a technically-non-empty-but-useless units array --
        it fails closed the same as the command-missing case."""
        result, out_file = _run_script(
            tmp_path, units={}, garbled_units=["patched-only-unit.service"]
        )
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        assert data["systemd_hardening"] == {"available": False, "units": []}

    def test_one_unparseable_unit_among_good_ones_is_reported_not_dropped(self, tmp_path):
        """The mixed case, distinct from the systemic failure above: when
        SOME units parse and one does not, the unparseable one must still
        appear in the array with null score/rating so the consumer can bucket
        it, rather than silently vanishing.

        A dropped unit would be the worst possible failure for this guard: a
        unit that disappears from the array is indistinguishable from a unit
        that was never installed, so an attacker-modified or
        newly-broken unit could leave the report looking complete and clean.
        PAT-1237's non-author review raised exactly this as a possibility;
        the behaviour is correct, and this test is what keeps it that way.
        """
        result, out_file = _run_script(
            tmp_path,
            units={
                "patched-dashboard.service": "3.2 OK",
                "patched-maintenance-facts.service": "9.6 UNSAFE",
            },
            garbled_units=["patched-mystery.service"],
        )
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        hardening = data["systemd_hardening"]
        assert hardening["available"] is True
        by_unit = {u["unit"]: u for u in hardening["units"]}

        assert "patched-mystery.service" in by_unit, (
            "an unparseable unit vanished from the units array; a missing unit "
            "reads as 'not installed', which is exactly the absence-reads-as-clean "
            "shape this guard exists to prevent"
        )
        mystery = by_unit["patched-mystery.service"]
        assert mystery["score"] is None
        assert mystery["rating"] is None
        assert mystery["over_ceiling"] is None

        # The units that DID parse are unaffected by their neighbour failing.
        assert by_unit["patched-maintenance-facts.service"]["over_ceiling"] is True
        assert by_unit["patched-dashboard.service"]["over_ceiling"] is False

    def test_no_candidate_units_is_available_true_empty_units(self, tmp_path):
        """Distinct from the above: zero candidates is a legitimate box
        state (nothing patched-owned installed yet), not a tool failure --
        must not be conflated with the systemd-analyze-broken case."""
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

    def test_prod01_live_output_reproduction(self, tmp_path):
        """Acceptance evidence: replay prod-01's own real `systemd-analyze
        security patched-maintenance-facts.service` tail line, captured live
        via SSH on 2026-08-19 (`ssh root@patched-prod-01.example-tailnet.ts.net
        'systemd-analyze security patched-maintenance-facts.service'`), byte
        for byte -- including the leading arrow glyph and trailing emoticon
        systemd-analyze actually prints, not a cleaned-up paraphrase. Proves
        the guard fires against the real incident's real output shape, not
        only against a synthetic fixture built to match what this code
        expects."""
        bindir = _fake_bin(tmp_path, units={})
        (bindir / "systemd-analyze").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "security" ]; then\n'
            '  if [ "$2" = "patched-maintenance-facts.service" ]; then\n'
            "    cat <<'REALOUT'\n"
            "✗ IPAddressDeny=                                              Service does not define an IP address allow list                             0.2\n"
            "✓ NotifyAccess=                                               Service child processes cannot alter service state                      \n"
            "✗ UMask=                                                      Files created by service are world-readable by default                       0.1\n"
            "\n"
            "→ Overall exposure level for patched-maintenance-facts.service: 9.6 UNSAFE :-{\n"
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
        assert entry["score"] == 9.6
        assert entry["rating"] == "UNSAFE"
        assert entry["class"] == "scheduled-maintenance"
        assert entry["ceiling"] == 6.0
        assert entry["over_ceiling"] is True


# ═════════════════════════════════════════════════════════════════════════
# Part 2: the dashboard-side consumer
# ═════════════════════════════════════════════════════════════════════════


@pytest.fixture
def db(tmp_path, monkeypatch):
    import shared
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


class _FakeResp:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        return self._payload


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _healthy_full_facts(generated_at: datetime, systemd_hardening=None) -> dict:
    facts = {
        "generated_at": _iso(generated_at),
        "hostname": "patched-prod-01",
        "pending_updates": 0,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "reboot_required": False,
        "running_kernel": "6.8.0-124-generic",
        "newest_kernel": "6.8.0-124-generic",
        "automatic_reboot_configured": True,
        "third_party_pending": [],
        "timers": [],
    }
    if systemd_hardening is not None:
        facts["systemd_hardening"] = systemd_hardening
    return facts


def _install_http(monkeypatch, api_facts, portal_body):
    def fake_get(url, timeout=None, verify=None):
        if url == f"{dashboard.PATCHED_API_INTERNAL}/admin/ops/maintenance":
            return _FakeResp(api_facts, status_code=200)
        if url == "https://app.patched.im/healthz":
            return _FakeResp(portal_body, status_code=200)
        raise AssertionError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _run(monkeypatch, now, prod01_path, prod01_facts):
    prod01_path.parent.mkdir(parents=True, exist_ok=True)
    prod01_path.write_text(json.dumps(prod01_facts))
    monkeypatch.setattr(dashboard, "MAINTENANCE_FACTS_FILE", str(prod01_path))
    other_facts = _healthy_full_facts(now)
    _install_http(
        monkeypatch,
        api_facts=other_facts,
        portal_body={"status": "ok", "maintenance": other_facts},
    )
    reason = dashboard._run_maintenance_drift_check_tick(now)
    dashboard._run_tick(
        "maintenance-drift-check",
        lambda: dashboard._run_maintenance_drift_check_tick(now),
        now,
    )
    return reason


# ── unit tests: _systemd_hardening_findings ─────────────────────────────────


def test_findings_field_absent_is_not_reported_not_clean():
    degraded, info = dashboard._systemd_hardening_findings({"generated_at": "x"})
    assert degraded == []
    assert "not reported" in info
    assert "none over ceiling" not in info


@pytest.mark.parametrize("bad_facts", [None, [], "not a dict", 42], ids=["none", "list", "str", "int"])
def test_findings_non_dict_facts_reports_not_reported_without_raising(bad_facts):
    degraded, info = dashboard._systemd_hardening_findings(bad_facts)
    assert degraded == []
    assert "not reported" in info


def test_findings_available_false_is_reported_distinctly_from_none_found():
    """available=false (systemd-analyze missing/broken on the box) must read
    as "not reported"/"unavailable", never as "clean" -- same absence-must-
    not-read-as-clean discipline PAT-912/837/960 already established."""
    degraded, info = dashboard._systemd_hardening_findings(
        {"systemd_hardening": {"available": False, "units": []}}
    )
    assert degraded == []
    assert "not available" in info or "unavailable" in info


def test_findings_available_true_empty_units_is_clean():
    degraded, info = dashboard._systemd_hardening_findings(
        {"systemd_hardening": {"available": True, "units": []}}
    )
    assert degraded == []
    assert "not available" not in info and "unavailable" not in info


def test_findings_over_ceiling_unit_is_degraded_and_names_unit_and_score():
    facts = {
        "systemd_hardening": {
            "available": True,
            "units": [
                {"unit": "patched-maintenance-facts.service", "score": 9.6,
                 "rating": "UNSAFE", "class": "scheduled-maintenance",
                 "ceiling": 6.0, "over_ceiling": True},
            ],
        }
    }
    degraded, info = dashboard._systemd_hardening_findings(facts)
    assert len(degraded) == 1
    assert "patched-maintenance-facts.service" in degraded[0]
    assert "9.6" in degraded[0]
    assert "6.0" in degraded[0]


def test_findings_a_false_over_ceiling_flag_cannot_hide_a_breaching_score():
    """The consumer must not believe over_ceiling: False when it is holding
    the score and ceiling that contradict it.

    A malformed or buggy emitter reporting 9.6 against a 6.0 ceiling as
    "passing" is the single outcome this whole guard exists to make
    impossible -- a breach rendered as clean. Verify what can be verified
    and let the emitter's flag decide only what cannot; the same
    defence-in-depth PAT-1433 established for stray_config_backups' null
    booleans. Raised by PAT-1237's non-author review.
    """
    facts = {
        "systemd_hardening": {
            "available": True,
            "units": [
                {"unit": "patched-maintenance-facts.service", "score": 9.6,
                 "rating": "UNSAFE", "class": "scheduled-maintenance",
                 "ceiling": 6.0, "over_ceiling": False},
            ],
        }
    }
    degraded, info = dashboard._systemd_hardening_findings(facts)
    assert len(degraded) == 1, (
        "a unit scoring 9.6 against a 6.0 ceiling was reported as passing "
        "because the emitter's own boolean said so"
    )
    assert "patched-maintenance-facts.service" in degraded[0]
    assert "9.6" in degraded[0]


def test_findings_an_honest_pass_is_still_a_pass():
    """The counterpart to the above: when the flag says False AND the
    numbers agree, the unit genuinely passes and must not be flagged.
    Without this, the cross-check above could be 'fixed' by degrading
    everything, which would be worse than the bug.
    """
    facts = {
        "systemd_hardening": {
            "available": True,
            "units": [
                {"unit": "patched-dashboard.service", "score": 3.2,
                 "rating": "OK", "class": "application",
                 "ceiling": 6.0, "over_ceiling": False},
            ],
        }
    }
    degraded, info = dashboard._systemd_hardening_findings(facts)
    assert degraded == []


def test_findings_unclassified_unit_is_degraded_even_with_over_ceiling_none():
    """The core case: a unit systemd-analyze scored but the class mapping
    doesn't recognise (class/ceiling/over_ceiling all null) must degrade the
    row, explicitly worded as unclassified -- never silently pass just
    because over_ceiling isn't True."""
    facts = {
        "systemd_hardening": {
            "available": True,
            "units": [
                {"unit": "patched-brand-new-thing.service", "score": 2.0,
                 "rating": "OK", "class": None, "ceiling": None, "over_ceiling": None},
            ],
        }
    }
    degraded, info = dashboard._systemd_hardening_findings(facts)
    assert len(degraded) == 1
    assert "patched-brand-new-thing.service" in degraded[0]
    assert "unclassified" in degraded[0]


def test_findings_under_ceiling_unit_is_not_degraded():
    facts = {
        "systemd_hardening": {
            "available": True,
            "units": [
                {"unit": "patched-dashboard.service", "score": 3.2,
                 "rating": "OK", "class": "application", "ceiling": 6.0,
                 "over_ceiling": False},
            ],
        }
    }
    degraded, info = dashboard._systemd_hardening_findings(facts)
    assert degraded == []


def test_findings_a_consumer_reading_only_over_ceiling_cannot_conclude_safe():
    """Documents the trap: a naive consumer that reads only `over_ceiling`
    and treats non-True as safe would wrongly pass an unclassified unit
    (over_ceiling is None, not True). The real consumer must not make that
    mistake."""
    entry = {"unit": "patched-brand-new-thing.service", "score": 2.0,
              "rating": "OK", "class": None, "ceiling": None, "over_ceiling": None}
    naive_is_over = entry.get("over_ceiling") is True
    assert naive_is_over is False, "documents the trap, not the desired behaviour"

    degraded, info = dashboard._systemd_hardening_findings(
        {"systemd_hardening": {"available": True, "units": [entry]}}
    )
    assert len(degraded) == 1
    assert "unclassified" in degraded[0]


# ── integration: wired into the maintenance_prod01 check_statuses row ──────


def test_prod01_over_ceiling_unit_degrades_the_row(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, systemd_hardening={
        "available": True,
        "units": [
            {"unit": "patched-maintenance-facts.service", "score": 9.6,
             "rating": "UNSAFE", "class": "scheduled-maintenance",
             "ceiling": 6.0, "over_ceiling": True},
        ],
    })
    prod01_path = tmp_path / "maintenance.json"

    reason = _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert "patched-maintenance-facts.service" in row["reason"]
    assert reason is not None
    assert _status("tick_maintenance_drift_check")["state"] == "degraded"


def test_prod01_unclassified_unit_degrades_the_row(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, systemd_hardening={
        "available": True,
        "units": [
            {"unit": "patched-brand-new-thing.service", "score": 2.0,
             "rating": "OK", "class": None, "ceiling": None, "over_ceiling": None},
        ],
    })
    prod01_path = tmp_path / "maintenance.json"

    reason = _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "degraded"
    assert "patched-brand-new-thing.service" in row["reason"]
    assert "unclassified" in row["reason"]
    assert reason is not None


def test_prod01_all_units_under_ceiling_is_clean(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, systemd_hardening={
        "available": True,
        "units": [
            {"unit": "patched-dashboard.service", "score": 3.2, "rating": "OK",
             "class": "application", "ceiling": 6.0, "over_ceiling": False},
        ],
    })
    prod01_path = tmp_path / "maintenance.json"

    _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "ok"


def test_prod01_field_absent_entirely_is_reported_as_unknown_not_clean(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now)  # no systemd_hardening key at all
    assert "systemd_hardening" not in facts
    prod01_path = tmp_path / "maintenance.json"

    _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "ok"
    assert "not reported" in row["reason"]


def test_prod01_available_false_is_reported_not_clean(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, systemd_hardening={"available": False, "units": []})
    prod01_path = tmp_path / "maintenance.json"

    _run(monkeypatch, now, prod01_path, facts)

    row = _status("maintenance_prod01")
    assert row["state"] == "ok"
    assert "not available" in row["reason"] or "unavailable" in row["reason"]
