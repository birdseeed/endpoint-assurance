"""
PAT-1544: detect drift between the 8 hand-provisioned api-vps-artefacts/
files on api-01 (backup.sh, patched-backup.service/.timer, patched-
maintenance-facts.sh/.service/.timer, create-partitions.sh, 52-automatic-
reboot.conf) and what this repo actually contains -- the real incident this
exists to catch: PAT-993 updated backup.sh and merged it, but api-01 ran the
pre-PAT-993 copy for weeks until found by accident, because merging a PR to
one of these files does not by itself put it on the box.

api-01 only for this pass (patched.im/api-vps-artefacts/patched-maintenance-
facts.sh's own artefact_drift comment block has the full rationale) --
prod-01 and portal-01 do not emit this field yet.

Two halves, mirroring tests/test_pat1237_systemd_hardening.py's model:

  * TestEmitterScript -- best-effort, drives the REAL emitter script
    (patched.im's api-vps-artefacts/patched-maintenance-facts.sh) end-to-end
    via subprocess against a scratch on-box tree and a scratch manifest,
    using the ARTEFACT_ONBOX_ROOT/ARTEFACT_MANIFEST_FILE test overrides that
    ticket added. Unlike test_pat1237 (which drives THIS repo's own copy of
    the script), the script under test here lives in a SIBLING repo
    (patched.im), so it is located the same way
    tests/test_pat1433_stray_config_backups_parity.py locates its siblings:
    `PAT1544_PATCHED_IM_REPO` env var override, else the conventional
    `<this repo's parent dir>/patched.im` checkout. If neither is found, or
    the sibling's copy of the script does not yet have the artefact_drift
    feature (predates this ticket merging there), every test in this class
    is skipped with a clear reason rather than failing -- same "local drift
    nudge, not a CI gate" posture as PAT-1433's parity test, for the same
    reason: there is nowhere in either repo's independent CI that both
    checkouts are ever available together.

  * TestConsumer -- exercises _artefact_drift_findings() and
    _run_maintenance_drift_check_tick()'s handling of the field directly,
    the same way test_pat1237_systemd_hardening.py's TestConsumer half
    exercises _systemd_hardening_findings(). This half needs no sibling repo
    and always runs: it proves match -> not degraded, drift -> degraded,
    missing -> degraded and at least as severe as drift (worded first, own
    distinct reason), and unknown -> neither degraded nor silently "clean".

Run with: pytest tests/test_pat1544_artefact_drift.py -v
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

FEATURE_MARKER = "artefact_drift"


def _resolve_sibling_script() -> Path | None:
    override = os.environ.get("PAT1544_PATCHED_IM_REPO")
    if override:
        candidate = Path(override) / "api-vps-artefacts" / "patched-maintenance-facts.sh"
        return candidate if candidate.is_file() else None
    candidate = REPO.parent / "patched.im" / "api-vps-artefacts" / "patched-maintenance-facts.sh"
    return candidate if candidate.is_file() else None


_SIBLING_SCRIPT = _resolve_sibling_script()
_SIBLING_HAS_FEATURE = (
    _SIBLING_SCRIPT is not None and FEATURE_MARKER in _SIBLING_SCRIPT.read_text()
)


# ═════════════════════════════════════════════════════════════════════════
# Part 1: the emitter script itself (best-effort, sibling-repo dependent)
# ═════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(
    not _SIBLING_HAS_FEATURE,
    reason=(
        "PAT-1544 artefact_drift check: could not locate the patched.im repo's "
        "api-vps-artefacts/patched-maintenance-facts.sh with the artefact_drift "
        "feature (set PAT1544_PATCHED_IM_REPO to point at a checkout/worktree that "
        "has it, or ensure ../patched.im exists) -- skipping the real-script "
        "reproduction this run. This is a local drift nudge, not a CI gate: see "
        "tests/test_pat1433_stray_config_backups_parity.py's module docstring for "
        "why no CI pipeline can see both repos at once."
    ),
)
class TestEmitterScript:
    """Drives the real shell script -- proves the match/drift/missing
    verdicts are computed correctly from real files and a real manifest,
    not just trusted at face value the way TestConsumer below necessarily
    does (it only ever sees the status string the shell script already
    decided on)."""

    def _fake_bin(self, tmp_path) -> Path:
        bindir = tmp_path / "fakebin"
        bindir.mkdir()
        (bindir / "id").write_text(
            "#!/bin/bash\n"
            'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
            'exec /usr/bin/id "$@"\n'
        )
        (bindir / "apt-cache").write_text("#!/bin/bash\nexit 0\n")
        (bindir / "systemctl").write_text("#!/bin/bash\nexit 1\n")
        for f in bindir.iterdir():
            f.chmod(0o755)
        return bindir

    def _run_script(self, tmp_path, onbox_root, manifest_path):
        bindir = self._fake_bin(tmp_path)
        env = dict(os.environ)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        env["OUT_FILE"] = str(tmp_path / "maintenance.json")
        env["ARTEFACT_ONBOX_ROOT"] = str(onbox_root)
        env["ARTEFACT_MANIFEST_FILE"] = str(manifest_path)

        result = subprocess.run(
            ["bash", str(_SIBLING_SCRIPT)],
            env=env, cwd=str(_SIBLING_SCRIPT.parent.parent),
            capture_output=True, text=True, timeout=30,
        )
        return result, tmp_path / "maintenance.json"

    def test_match_drift_missing_and_unknown_all_computed_correctly(self, tmp_path):
        import hashlib

        onbox = tmp_path / "onbox"
        (onbox / "opt" / "patched-api" / "bin").mkdir(parents=True)
        (onbox / "etc" / "systemd" / "system").mkdir(parents=True)

        matching_content = b"exactly what the manifest expects\n"
        (onbox / "opt" / "patched-api" / "bin" / "backup.sh").write_bytes(matching_content)
        (onbox / "etc" / "systemd" / "system" / "patched-backup.service").write_text(
            "this is NOT what the manifest expects\n"
        )
        # patched-backup.timer deliberately not created -> "missing"

        matching_sha = hashlib.sha256(matching_content).hexdigest()
        manifest = {
            "artifacts": [
                {
                    "path": "api-vps-artefacts/backup.sh",
                    "on_box_path": "/opt/patched-api/bin/backup.sh",
                    "sha256": matching_sha,
                },
                {
                    "path": "api-vps-artefacts/patched-backup.service",
                    "on_box_path": "/etc/systemd/system/patched-backup.service",
                    "sha256": "0" * 64,
                },
                {
                    "path": "api-vps-artefacts/patched-backup.timer",
                    "on_box_path": "/etc/systemd/system/patched-backup.timer",
                    "sha256": "0" * 64,
                },
                # No entry at all for patched-maintenance-facts.sh -> "unknown"
                # even though the on-box file exists and is hashable.
            ]
        }
        (onbox / "opt" / "patched-api" / "bin" / "patched-maintenance-facts.sh").write_text(
            "irrelevant content\n"
        )
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))

        result, out_file = self._run_script(tmp_path, onbox, manifest_path)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        by_path = {e["on_box_path"]: e for e in data["artefact_drift"]}

        assert by_path["/opt/patched-api/bin/backup.sh"]["status"] == "match"
        assert by_path["/opt/patched-api/bin/backup.sh"]["actual_sha256"] == matching_sha

        assert by_path["/etc/systemd/system/patched-backup.service"]["status"] == "drift"
        assert by_path["/etc/systemd/system/patched-backup.service"]["expected_sha256"] == "0" * 64
        assert by_path["/etc/systemd/system/patched-backup.service"]["actual_sha256"] != "0" * 64

        assert by_path["/etc/systemd/system/patched-backup.timer"]["status"] == "missing"
        assert by_path["/etc/systemd/system/patched-backup.timer"]["actual_sha256"] is None

        assert by_path["/opt/patched-api/bin/patched-maintenance-facts.sh"]["status"] == "unknown"

        # Every one of the 8 configured artefacts appears -- a dropped entry
        # would read as "not installed", the same absence-reads-as-clean
        # trap PAT-1237's mystery-unit test guards against.
        assert len(data["artefact_drift"]) == 8

    def test_manifest_entirely_missing_reports_unknown_not_a_crash(self, tmp_path):
        onbox = tmp_path / "onbox"
        (onbox / "opt" / "patched-api" / "bin").mkdir(parents=True)
        (onbox / "opt" / "patched-api" / "bin" / "backup.sh").write_text("anything\n")
        missing_manifest_path = tmp_path / "does-not-exist.json"

        result, out_file = self._run_script(tmp_path, onbox, missing_manifest_path)
        assert result.returncode == 0, result.stderr

        data = json.loads(out_file.read_text())
        statuses = {e["status"] for e in data["artefact_drift"]}
        # Nothing can be confirmed a match or drift without a manifest --
        # "missing" is still legitimate for files genuinely absent, but
        # nothing should read as "match" purely because the manifest was
        # unavailable.
        assert "match" not in statuses
        assert all(s in ("unknown", "missing") for s in statuses)


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


def _healthy_full_facts(generated_at: datetime, artefact_drift=None) -> dict:
    facts = {
        "generated_at": _iso(generated_at),
        "hostname": "patched-api-01",
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
    if artefact_drift is not None:
        facts["artefact_drift"] = artefact_drift
    return facts


def _install_http(monkeypatch, api_facts):
    prod01_healthy = _healthy_full_facts(datetime.now(timezone.utc))
    portal_healthy = _healthy_full_facts(datetime.now(timezone.utc))

    def fake_get(url, timeout=None, verify=None):
        if url == f"{dashboard.PATCHED_API_INTERNAL}/admin/ops/maintenance":
            return _FakeResp(api_facts, status_code=200)
        if url == "https://app.patched.im/healthz":
            return _FakeResp({"status": "ok", "maintenance": portal_healthy}, status_code=200)
        raise AssertionError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _run(monkeypatch, now, prod01_path, api_facts):
    prod01_path.parent.mkdir(parents=True, exist_ok=True)
    prod01_path.write_text(json.dumps(_healthy_full_facts(now)))
    monkeypatch.setattr(dashboard, "MAINTENANCE_FACTS_FILE", str(prod01_path))
    _install_http(monkeypatch, api_facts)
    reason = dashboard._run_maintenance_drift_check_tick(now)
    dashboard._run_tick(
        "maintenance-drift-check",
        lambda: dashboard._run_maintenance_drift_check_tick(now),
        now,
    )
    return reason


# ── unit tests: _artefact_drift_findings ────────────────────────────────────


def test_findings_field_absent_is_not_reported_not_clean():
    degraded, info = dashboard._artefact_drift_findings({"generated_at": "x"})
    assert degraded == []
    assert "not reported" in info


@pytest.mark.parametrize("bad_facts", [None, [], "not a dict", 42], ids=["none", "list", "str", "int"])
def test_findings_non_dict_facts_reports_not_reported_without_raising(bad_facts):
    degraded, info = dashboard._artefact_drift_findings(bad_facts)
    assert degraded == []
    assert "not reported" in info


def test_findings_empty_list_is_reported_distinctly():
    degraded, info = dashboard._artefact_drift_findings({"artefact_drift": []})
    assert degraded == []
    assert "no artefacts checked" in info


def test_findings_all_match_is_clean():
    facts = {
        "artefact_drift": [
            {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
             "status": "match", "expected_sha256": "a" * 64, "actual_sha256": "a" * 64},
            {"path": "api-vps-artefacts/create-partitions.sh", "on_box_path": "/opt/patched-api/bin/create-partitions.sh",
             "status": "match", "expected_sha256": "b" * 64, "actual_sha256": "b" * 64},
        ]
    }
    degraded, info = dashboard._artefact_drift_findings(facts)
    assert degraded == []
    assert "all match" in info


def test_findings_drift_is_degraded_and_names_the_path():
    facts = {
        "artefact_drift": [
            {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
             "status": "drift", "expected_sha256": "a" * 64, "actual_sha256": "f" * 64},
        ]
    }
    degraded, info = dashboard._artefact_drift_findings(facts)
    assert len(degraded) == 1
    assert "/opt/patched-api/bin/backup.sh" in degraded[0]
    assert "drift" in degraded[0].lower()


def test_findings_missing_is_degraded_and_at_least_as_severe_as_drift():
    """The exact PAT-949/portal-01 shape this ticket exists to catch: a
    hand-provisioned script silently absent from the box. Must be a
    degraded finding, worded distinctly from drift, and reported first."""
    facts = {
        "artefact_drift": [
            {"path": "api-vps-artefacts/patched-backup.timer",
             "on_box_path": "/etc/systemd/system/patched-backup.timer",
             "status": "missing", "expected_sha256": "a" * 64, "actual_sha256": None},
        ]
    }
    degraded, info = dashboard._artefact_drift_findings(facts)
    assert len(degraded) == 1
    assert "/etc/systemd/system/patched-backup.timer" in degraded[0]
    assert "missing" in degraded[0].lower()


def test_findings_missing_and_drift_both_degrade_missing_reported_first():
    facts = {
        "artefact_drift": [
            {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
             "status": "drift", "expected_sha256": "a" * 64, "actual_sha256": "f" * 64},
            {"path": "api-vps-artefacts/patched-backup.timer",
             "on_box_path": "/etc/systemd/system/patched-backup.timer",
             "status": "missing", "expected_sha256": "a" * 64, "actual_sha256": None},
        ]
    }
    degraded, info = dashboard._artefact_drift_findings(facts)
    assert len(degraded) == 2
    assert "missing" in degraded[0].lower()
    assert "drift" in degraded[1].lower()


def test_findings_unknown_is_not_degraded_but_is_visible_in_info_note():
    """An 'unknown' verdict (e.g. the manifest hasn't been copied to the box
    yet) is a data-quality gap in the check itself, not a positive finding
    that something is wrong -- must not read as degraded, but must also not
    silently vanish (same info_note convention as its siblings)."""
    facts = {
        "artefact_drift": [
            {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
             "status": "unknown", "expected_sha256": None, "actual_sha256": "f" * 64},
        ]
    }
    degraded, info = dashboard._artefact_drift_findings(facts)
    assert degraded == []
    assert "/opt/patched-api/bin/backup.sh" in info
    assert "could not be judged" in info


def test_findings_malformed_status_value_fails_closed_to_unknown_not_match():
    facts = {
        "artefact_drift": [
            {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
             "status": "something-a-future-version-of-the-emitter-invented"},
        ]
    }
    degraded, info = dashboard._artefact_drift_findings(facts)
    assert degraded == []
    assert "could not be judged" in info


# ── integration: wired into the maintenance_api01 check_statuses row ───────


def test_api01_drift_degrades_the_row(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, artefact_drift=[
        {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
         "status": "drift", "expected_sha256": "a" * 64, "actual_sha256": "f" * 64},
    ])

    reason = _run(monkeypatch, now, tmp_path / "prod01.json", facts)

    row = _status("maintenance_api01")
    assert row["state"] == "degraded"
    assert "/opt/patched-api/bin/backup.sh" in row["reason"]
    assert reason is not None


def test_api01_missing_artefact_degrades_the_row(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, artefact_drift=[
        {"path": "api-vps-artefacts/patched-backup.timer",
         "on_box_path": "/etc/systemd/system/patched-backup.timer",
         "status": "missing", "expected_sha256": "a" * 64, "actual_sha256": None},
    ])

    _run(monkeypatch, now, tmp_path / "prod01.json", facts)

    row = _status("maintenance_api01")
    assert row["state"] == "degraded"
    assert "/etc/systemd/system/patched-backup.timer" in row["reason"]
    assert "missing" in row["reason"].lower()


def test_api01_all_match_is_clean(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, artefact_drift=[
        {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
         "status": "match", "expected_sha256": "a" * 64, "actual_sha256": "a" * 64},
    ])

    _run(monkeypatch, now, tmp_path / "prod01.json", facts)

    row = _status("maintenance_api01")
    assert row["state"] == "ok"


def test_api01_field_absent_entirely_is_reported_as_not_reported_not_clean(db, tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now)  # no artefact_drift key at all
    assert "artefact_drift" not in facts

    _run(monkeypatch, now, tmp_path / "prod01.json", facts)

    row = _status("maintenance_api01")
    assert row["state"] == "ok"
    assert "not reported" in row["reason"]


def test_prod01_and_portal01_unaffected_by_api01_only_field(db, tmp_path, monkeypatch):
    """artefact_drift is api-01 only for this pass -- prod-01 (local file)
    and portal-01 (healthz) never carry the key, and their rows must not be
    pushed to degraded by its absence."""
    now = datetime.now(timezone.utc)
    facts = _healthy_full_facts(now, artefact_drift=[
        {"path": "api-vps-artefacts/backup.sh", "on_box_path": "/opt/patched-api/bin/backup.sh",
         "status": "match", "expected_sha256": "a" * 64, "actual_sha256": "a" * 64},
    ])

    _run(monkeypatch, now, tmp_path / "prod01.json", facts)

    assert _status("maintenance_prod01")["state"] == "ok"
    assert _status("maintenance_portal01")["state"] == "ok"
