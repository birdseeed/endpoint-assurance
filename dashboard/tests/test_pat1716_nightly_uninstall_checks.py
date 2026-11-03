"""
PAT-1716: nightly uninstall E2E verification heartbeat.

Something that fails safe looks exactly like something healthy (PAT-912,
PAT-837, PAT-960) -- the nightly macOS (PAT-1714) and Windows (PAT-1715)
uninstall E2E jobs must show up on this same automation surface when they
STOP running, not only when they fail outright.

Covers:
  - POST /admin/nightly-checks/report validates job/status/finished_at/
    platform/level and rejects an unregistered job name.
  - A passing, fresh report evaluates the job's check_statuses row to 'ok'.
  - A failing report evaluates it to 'degraded' (check_statuses has no
    fourth 'failing' state -- 'degraded' is truth.py's real-failure state,
    'unconfigured' its indeterminate/no-evidence state; see main.py's
    NIGHTLY_UNINSTALL_JOBS comment).
  - A passing report older than 36h evaluates to 'unconfigured' (stale) even
    though nothing failed.
  - A job with NO report ever recorded evaluates to 'unconfigured', not ok
    and not silently absent from check_statuses.
  - _run_nightly_uninstall_checks_tick re-evaluates every registered job
    without a new report, so a job that simply stops reporting transitions
    to unconfigured on its own, on the next scheduler tick.

Run with: pytest tests/test_pat1716_nightly_uninstall_checks.py -v
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import shared  # noqa: E402
import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


def _report(client, *, job="nightly-uninstall-e2e-macos", platform="macos", level=1,
            status="pass", finished_at=None, run_url="https://github.com/Patched-LTD/patched.im/actions/runs/1"):
    if finished_at is None:
        finished_at = datetime.now(timezone.utc).isoformat()
    return client.post(
        "/admin/nightly-checks/report",
        headers=BEARER,
        json={
            "job": job, "platform": platform, "level": level,
            "run_url": run_url, "status": status, "finished_at": finished_at,
        },
    )


class TestReportValidation:
    def test_unknown_job_rejected(self, client):
        r = _report(client, job="not-a-registered-job")
        assert r.status_code == 400
        assert "not in NIGHTLY_UNINSTALL_JOBS" in r.json()["error"]

    def test_bad_status_rejected(self, client):
        r = _report(client, status="broken")
        assert r.status_code == 400

    def test_unparseable_finished_at_rejected(self, client):
        r = _report(client, finished_at="not-a-timestamp")
        assert r.status_code == 400

    def test_missing_platform_rejected(self, client):
        r = client.post(
            "/admin/nightly-checks/report",
            headers=BEARER,
            json={"job": "nightly-uninstall-e2e-macos", "level": 1, "status": "pass",
                  "finished_at": datetime.now(timezone.utc).isoformat()},
        )
        assert r.status_code == 400

    def test_missing_level_rejected(self, client):
        r = client.post(
            "/admin/nightly-checks/report",
            headers=BEARER,
            json={"job": "nightly-uninstall-e2e-macos", "platform": "macos", "status": "pass",
                  "finished_at": datetime.now(timezone.utc).isoformat()},
        )
        assert r.status_code == 400

    def test_unauthenticated_rejected(self, client):
        r = client.post(
            "/admin/nightly-checks/report",
            json={"job": "nightly-uninstall-e2e-macos", "platform": "macos", "level": 1,
                  "status": "pass", "finished_at": datetime.now(timezone.utc).isoformat()},
        )
        assert r.status_code == 401

    def test_future_finished_at_rejected(self, client):
        future = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        r = _report(client, status="pass", finished_at=future)
        assert r.status_code == 400
        assert "ahead of server time" in r.json()["error"]
        # Rejected outright -- no row written, no check_statuses flip to ok.
        assert _status("nightly_uninstall_e2e_macos") is None

    def test_finished_at_a_few_seconds_ahead_is_tolerated(self, client):
        # Small, expected clock skew between the runner and this box must
        # not be rejected -- only a materially future timestamp.
        slightly_ahead = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
        r = _report(client, status="pass", finished_at=slightly_ahead)
        assert r.status_code == 200
        assert _status("nightly_uninstall_e2e_macos")["state"] == "ok"

    def test_platform_mismatch_rejected(self, client):
        r = _report(client, job="nightly-uninstall-e2e-macos", platform="windows")
        assert r.status_code == 400
        assert "does not match the registered platform" in r.json()["error"]
        assert _status("nightly_uninstall_e2e_macos") is None

    def test_level_mismatch_rejected(self, client):
        r = _report(client, job="nightly-uninstall-e2e-macos", level=2)
        assert r.status_code == 400
        assert "does not match the registered level" in r.json()["error"]
        assert _status("nightly_uninstall_e2e_macos") is None

    def test_matching_platform_and_level_accepted(self, client):
        r = _report(client, job="nightly-uninstall-e2e-windows", platform="windows", level=1, status="pass")
        assert r.status_code == 200
        assert _status("nightly_uninstall_e2e_windows")["state"] == "ok"


class TestCheckStatusOutcomes:
    def test_passing_fresh_report_is_ok(self, client):
        r = _report(client, status="pass")
        assert r.status_code == 200
        row = _status("nightly_uninstall_e2e_macos")
        assert row["state"] == "ok"
        assert "passed" in row["reason"]

    def test_failing_report_is_degraded(self, client):
        r = _report(client, status="fail")
        assert r.status_code == 200
        row = _status("nightly_uninstall_e2e_macos")
        assert row["state"] == "degraded"
        assert "FAILED" in row["reason"]

    def test_stale_passing_report_is_unconfigured(self, client):
        stale = (datetime.now(timezone.utc) - timedelta(hours=40)).isoformat()
        r = _report(client, status="pass", finished_at=stale)
        assert r.status_code == 200
        row = _status("nightly_uninstall_e2e_macos")
        assert row["state"] == "unconfigured"
        assert "36h" in row["reason"]

    def test_recent_pass_inside_36h_is_still_ok(self, client):
        recent = (datetime.now(timezone.utc) - timedelta(hours=35)).isoformat()
        _report(client, status="pass", finished_at=recent)
        row = _status("nightly_uninstall_e2e_macos")
        assert row["state"] == "ok"

    def test_windows_job_is_tracked_independently(self, client):
        _report(client, job="nightly-uninstall-e2e-windows", platform="windows", status="pass")
        _report(client, job="nightly-uninstall-e2e-macos", platform="macos", status="fail")
        assert _status("nightly_uninstall_e2e_windows")["state"] == "ok"
        assert _status("nightly_uninstall_e2e_macos")["state"] == "degraded"


class TestNeverReportedAndStalenessSweep:
    def test_job_with_no_report_ever_is_unconfigured_not_ok_not_absent(self, client):
        now = datetime.now(timezone.utc)
        dashboard._run_nightly_uninstall_checks_tick(now)
        row = _status("nightly_uninstall_e2e_macos")
        assert row is not None
        assert row["state"] == "unconfigured"
        assert "no nightly result" in row["reason"]
        row_win = _status("nightly_uninstall_e2e_windows")
        assert row_win is not None
        assert row_win["state"] == "unconfigured"

    def test_tick_transitions_ok_job_to_unconfigured_once_stale_with_no_new_report(self, client):
        # A job reports once, passing and fresh -- ok.
        now = datetime.now(timezone.utc)
        _report(client, status="pass", finished_at=now.isoformat())
        assert _status("nightly_uninstall_e2e_macos")["state"] == "ok"

        # No new report ever arrives (workflow disabled). 40h later, the
        # scheduler tick alone -- with no new POST -- must catch the
        # staleness and flip the check, exactly the PAT-912/837/960 shape
        # this ticket exists to close.
        later = now + timedelta(hours=40)
        dashboard._run_nightly_uninstall_checks_tick(later)
        row = _status("nightly_uninstall_e2e_macos")
        assert row["state"] == "unconfigured"
        assert "36h" in row["reason"]

    def test_stored_future_finished_at_is_unconfigured_not_ok(self, client):
        # Defence in depth: ingest already rejects a future finished_at, but
        # a row could reach the table some other way (a stored row from
        # before this guard existed, a direct DB write). Insert one directly
        # and confirm evaluation still refuses to call it ok.
        with dashboard.get_db() as db:
            future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
            db.execute(
                "INSERT INTO nightly_job_results (job, platform, level, run_url, status, finished_at, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("nightly-uninstall-e2e-macos", "macos", 1, "https://example.invalid/run/1",
                 "pass", future, datetime.now(timezone.utc).isoformat()),
            )
        dashboard._evaluate_nightly_job_check("nightly-uninstall-e2e-macos", datetime.now(timezone.utc))
        row = _status("nightly_uninstall_e2e_macos")
        assert row["state"] == "unconfigured"
        assert "in the future" in row["reason"]

    def test_tick_leaves_fresh_ok_job_untouched(self, client):
        now = datetime.now(timezone.utc)
        _report(client, status="pass", finished_at=now.isoformat())
        dashboard._run_nightly_uninstall_checks_tick(now + timedelta(hours=1))
        assert _status("nightly_uninstall_e2e_macos")["state"] == "ok"

    def test_ingestion_evaluates_immediately_without_waiting_for_tick(self, client):
        # The check_statuses row updates on POST itself, not only on the
        # next hourly sweep.
        r = _report(client, status="fail")
        assert r.status_code == 200
        assert _status("nightly_uninstall_e2e_macos")["state"] == "degraded"


class TestLatestResultWins:
    def test_second_report_replaces_first(self, client):
        _report(client, status="fail")
        assert _status("nightly_uninstall_e2e_macos")["state"] == "degraded"
        _report(client, status="pass")
        assert _status("nightly_uninstall_e2e_macos")["state"] == "ok"


class TestTruthManifestIntegration:
    def test_manifest_entries_declared_and_load_cleanly(self):
        import truth
        manifest = truth.load_manifest(dashboard.TRUTH_MANIFEST_PATH)
        ids = {e["id"] for e in manifest}
        assert "patchedim-nightly-uninstall-e2e-macos" in ids
        assert "patchedim-nightly-uninstall-e2e-windows" in ids
        for entry in manifest:
            if entry["id"].startswith("patchedim-nightly-uninstall-e2e-"):
                assert entry["evidence"]["kind"] == "check_status"

    def test_no_report_ever_renders_amber_on_truth_page(self, client):
        r = client.get("/admin/truth", headers=BEARER)
        assert r.status_code == 200
        checks = {c["id"]: c for c in r.json()["checks"]}
        assert checks["patchedim-nightly-uninstall-e2e-macos"]["state"] == "amber"
        assert checks["patchedim-nightly-uninstall-e2e-windows"]["state"] == "amber"

    def test_failing_report_renders_red_on_truth_page(self, client):
        _report(client, status="fail")
        r = client.get("/admin/truth", headers=BEARER)
        checks = {c["id"]: c for c in r.json()["checks"]}
        assert checks["patchedim-nightly-uninstall-e2e-macos"]["state"] == "red"

    def test_passing_fresh_report_renders_green_on_truth_page(self, client):
        _report(client, status="pass")
        r = client.get("/admin/truth", headers=BEARER)
        checks = {c["id"]: c for c in r.json()["checks"]}
        assert checks["patchedim-nightly-uninstall-e2e-macos"]["state"] == "green"
