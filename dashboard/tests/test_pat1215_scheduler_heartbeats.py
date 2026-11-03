"""
PAT-1215: alerting review. things that fail safe must not be invisible.

Covers two asymmetries where a healthy-looking silence could actually mean
"broken":

  * _run_automation_digest_tick returned early when SLACK_WEBHOOK_URL was
    unset without recording anything, unlike its sibling
    _run_automation_alerts_tick (which already recorded "unconfigured" in
    the same situation). Both must now read the same way.

  * public-uploads-cleanup and trial-expiry were started as bare
    threading.Thread targets in scheduler_loop, bypassing _run_tick, so a
    thread that died (or never started) wrote no heartbeat into
    check_statuses -- a dead job looked identical to one that simply hadn't
    run yet. Both are now routed through _run_tick like every other
    scheduler job, and this file confirms both the wiring (scheduler_loop
    calls _run_tick for each, not a bare Thread) and the behaviour (running
    each job through _run_tick actually writes its tick_<label> heartbeat).

Run with: pytest tests/test_pat1215_scheduler_heartbeats.py -v
"""

import inspect
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


@pytest.fixture
def db(tmp_path, monkeypatch):
    # _cleanup_old_public_uploads lives in shared.py and uses shared's own
    # get_db()/DB_PATH, not main.py's redefined one (see the PAT-814 comment
    # above main.get_db) -- both need patching, matching
    # tests/test_check_status.py's fixture.
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


# ── Item A: automation digest records unconfigured, matching its sibling ────


def test_automation_digest_without_slack_records_unconfigured(db, monkeypatch):
    """Mirrors test_automation_alerts_without_slack_records_unconfigured in
    tests/test_check_status.py: same status value (unconfigured), same
    record key convention (bare check name, no tick_ prefix), same message
    ("SLACK_WEBHOOK_URL not set")."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")

    result = dashboard._run_automation_digest_tick(datetime.now(timezone.utc))

    assert result is None
    row = _status("automation_digest")
    assert row is not None
    assert row["state"] == "unconfigured"
    assert row["reason"] == "SLACK_WEBHOOK_URL not set"


def test_automation_digest_and_alerts_agree_on_missing_webhook(db, monkeypatch):
    """The whole point of the fix: the two siblings must no longer disagree
    about whether a missing webhook is visible."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
    now = datetime.now(timezone.utc)

    dashboard._run_automation_alerts_tick(now)
    dashboard._run_automation_digest_tick(now)

    alerts_row = _status("automation_alerts")
    digest_row = _status("automation_digest")
    assert alerts_row["state"] == digest_row["state"] == "unconfigured"


# ── Item B: scheduler_loop wiring -- no more bare threading.Thread targets ──


def test_scheduler_loop_no_longer_starts_bare_uploads_cleanup_thread():
    """public-uploads-cleanup must be routed through _run_tick, not started
    as a bare Thread target that writes no heartbeat."""
    src = inspect.getsource(dashboard.scheduler_loop)
    assert "threading.Thread(target=_cleanup_old_public_uploads" not in src
    assert '_run_tick("public-uploads-cleanup", _cleanup_old_public_uploads, now)' in src


def test_scheduler_loop_no_longer_starts_bare_trial_expiry_thread():
    """trial-expiry must be routed through _run_tick, not started as a bare
    Thread target that writes no heartbeat."""
    src = inspect.getsource(dashboard.scheduler_loop)
    assert "threading.Thread(target=check_trial_expiry_emails" not in src
    assert '_run_tick("trial-expiry", check_trial_expiry_emails, now)' in src


# ── Item B: running each job through _run_tick actually heartbeats ─────────


def test_public_uploads_cleanup_heartbeats_through_run_tick(db):
    """Exercises the exact call scheduler_loop's thread target now makes.
    No public_uploads rows exist, so this only has to prove the heartbeat
    lands, not exercise the deletion logic (already covered elsewhere)."""
    now = datetime.now(timezone.utc)

    dashboard._run_tick("public-uploads-cleanup", dashboard._cleanup_old_public_uploads, now)

    row = _status("tick_public_uploads_cleanup")
    assert row is not None
    assert row["state"] == "ok"
    assert row["evaluated_at"] == now.isoformat()


def test_trial_expiry_heartbeats_through_run_tick(db):
    """Exercises the exact call scheduler_loop's thread target now makes.
    The platform fetch is mocked to return no trials, matching
    test_empty_trial_list_sends_no_emails's existing style in
    tests/test_trial_expiry.py, so this only has to prove the heartbeat
    lands, not re-cover check_trial_expiry_emails's own send logic."""
    now = datetime.now(timezone.utc)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"trials": []}
    mock_resp.content = b"..."

    with patch.object(dashboard, "http") as mock_http:
        mock_http.get.return_value = mock_resp
        dashboard._run_tick("trial-expiry", dashboard.check_trial_expiry_emails, now)

    row = _status("tick_trial_expiry")
    assert row is not None
    assert row["state"] == "ok"
    assert row["evaluated_at"] == now.isoformat()


def test_trial_expiry_thread_exception_now_heartbeats_degraded(db):
    """Before this fix, an exception inside check_trial_expiry_emails ran on
    a bare thread and had no way to reach check_statuses at all -- it would
    print to stderr via the default thread excepthook and vanish. Routed
    through _run_tick, the same exception is now caught and recorded
    degraded, exactly like every other scheduler job."""
    now = datetime.now(timezone.utc)

    # check_trial_expiry_emails itself already catches a fetch failure and
    # logs + returns (see its own try/except), so a raise has to be forced
    # past that guard directly to prove _run_tick's own exception handling
    # now applies to this job.
    with patch.object(dashboard, "check_trial_expiry_emails", side_effect=RuntimeError("boom")):
        dashboard._run_tick("trial-expiry", dashboard.check_trial_expiry_emails, now)

    row = _status("tick_trial_expiry")
    assert row is not None
    assert row["state"] == "degraded"
    assert "boom" in row["reason"]
