"""
Tests for automation staleness detection + the daily health digest, extending
PAT-643's automation-failure Slack alerting.

Coverage:
  - A job whose last run is older than 1.5x its expected interval alerts as
    "lagging" (stale).
  - A job within its threshold does not alert.
  - A job registered with no runs at all (empty recent_runs / null last_run)
    alerts immediately — it is stale by definition.
  - An unknown/newly-registered job_name (not in the explicit interval map)
    still gets monitored, using _AUTOMATION_DEFAULT_INTERVAL_HOURS.
  - Staleness alerts are deduped once per (job_name, UTC calendar day) — a
    second tick the same day does not re-alert.
  - A FAILED run still alerts exactly as before (regression guard for the
    pre-existing PAT-643 behaviour, which staleness must not weaken).
  - The daily digest fires at most once per UTC day, and only at the 09:00
    UTC hour gate.
  - The dead `dashboard.patched.im/admin#automations` link is gone from both
    the failure and the staleness alert, replaced by the build-id-independent
    console URL.

Mocks/stubs `dashboard.http.get` (the /admin/automations fetch) and
`dashboard.http.post` (the Slack webhook) throughout — no real network calls.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


class _FakeResp:
    def __init__(self, payload, status_code=200, text="ok"):
        self._payload = payload
        self.status_code = status_code
        self.content = json.dumps(payload).encode() if payload is not None else b""
        self.text = text

    def json(self):
        return self._payload


def _job(job_name, last_run=None, recent_runs=None, schedule="Daily (06:00 UTC)", last_status="success"):
    return {
        "job_name": job_name,
        "schedule": schedule,
        "description": job_name,
        "last_status": last_status,
        "last_run": last_run,
        "last_duration_s": 12.0,
        "recent_runs": recent_runs if recent_runs is not None else [],
    }


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _mock_automations(monkeypatch, jobs):
    def fake_get(url, *a, **k):
        if url.endswith("/admin/automations"):
            return _FakeResp({"jobs": jobs})
        return _FakeResp({})
    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _mock_slack_post(monkeypatch):
    posts = []

    def fake_post(url, json=None, **k):
        posts.append(json)
        return _FakeResp({"ok": True}, status_code=200)

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    return posts


def _mock_slack_post_bad_delivery(monkeypatch, status_code=200, text="Not Found"):
    """PAT-1011: simulate a syntactically valid but wrong webhook URL, where
    something answers with `status_code` but the body isn't Slack's own
    delivery confirmation ("ok"). Every call site must treat this the same
    as a hard failure: no de-dup row written, safe to retry next tick."""
    posts = []

    def fake_post(url, json=None, **k):
        posts.append(json)
        return _FakeResp({}, status_code=status_code, text=text)

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    return posts


def _flatten(posted_blocks_payload):
    return json.dumps(posted_blocks_payload)


# ── Interval map / default coverage ────────────────────────────────────────────

class TestIntervalResolution:
    def test_known_job_uses_explicit_map(self):
        assert dashboard._automation_expected_interval_hours("health_signals_recompute") == 24

    def test_unknown_job_uses_default(self):
        assert (dashboard._automation_expected_interval_hours("unmapped_scheduled_job")
                == dashboard._AUTOMATION_DEFAULT_INTERVAL_HOURS)

    def test_unknown_job_schedule_hint_wins_over_default(self):
        # Not in the explicit map, but the schedule string hints "weekly".
        assert dashboard._automation_expected_interval_hours(
            "brand_new_job", "Weekly (Sundays 02:00 UTC)"
        ) == 168

    def test_explicit_map_wins_over_schedule_hint(self):
        # health_signals_recompute is mapped to 24h even if its schedule text said otherwise.
        assert dashboard._automation_expected_interval_hours(
            "health_signals_recompute", "Weekly (Sundays 02:00 UTC)"
        ) == 24

    @pytest.mark.parametrize("job_name", [
        "installomator_sync", "daily_vendor_verify", "mirror_pipeline", "mirror_pipeline_windows",
    ])
    def test_quarantined_jobs_have_no_expected_interval(self, job_name):
        assert dashboard._automation_expected_interval_hours(job_name) is None


# ── Staleness detection ─────────────────────────────────────────────────────

class TestStalenessDetection:
    def test_quarantined_jobs_do_not_alert_as_failed_or_overdue(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        old_run = now - timedelta(days=10)
        jobs = [
            _job(name, last_run=_iso(old_run), last_status="failed",
                 recent_runs=[{"id": 1, "started_at": _iso(old_run), "status": "failed"}])
            for name in dashboard._QUARANTINED_AUTOMATIONS
        ]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert posts == []

    def test_stale_job_past_threshold_alerts(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        old_run = now - timedelta(hours=40)  # > 24h * 1.5 = 36h threshold
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old_run),
                      recent_runs=[{"id": 1, "started_at": _iso(old_run),
                                     "finished_at": _iso(old_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1
        text = _flatten(posts[0])
        assert "lagging" in text.lower()
        assert "unmapped_scheduled_job" in text
        assert ":warning:" in text
        # Dead link must be gone; correct build-id-independent console link used.
        assert "admin#automations" not in text
        assert "dashboard.patched.im/console#automations" in text

        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT * FROM automation_stale_alerts_sent WHERE job_name=?",
                ("unmapped_scheduled_job",),
            ).fetchone()
        assert row is not None

    def test_job_within_threshold_no_alert(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        recent_run = now - timedelta(hours=10)  # well under 36h threshold
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(recent_run),
                      recent_runs=[{"id": 1, "started_at": _iso(recent_run),
                                     "finished_at": _iso(recent_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert posts == []

    def test_job_with_no_runs_at_all_alerts(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        jobs = [_job("unmapped_scheduled_job", last_run=None, recent_runs=[])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1
        text = _flatten(posts[0])
        assert "unmapped_scheduled_job" in text
        assert "never" in text.lower() or "no runs" in text.lower()

    def test_unknown_job_is_monitored_with_default_interval(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        # Default interval is 24h -> stale threshold 36h. 40h old -> stale.
        old_run = now - timedelta(hours=40)
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old_run),
                      recent_runs=[{"id": 1, "started_at": _iso(old_run),
                                     "finished_at": _iso(old_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1
        assert "unmapped_scheduled_job" in _flatten(posts[0])

    def test_staleness_dedupe_no_realert_same_day(self, client, monkeypatch):
        # PAT-1039: `now` is pinned rather than datetime.now(timezone.utc).
        # The dedupe key is the UTC calendar day of the tick's own `now`
        # (main.py's _run_automation_alerts_tick: today = now.strftime
        # ("%Y-%m-%d")), and this test advances the second tick by 30 minutes.
        # With a wall-clock `now` that is correct on 47 of every 48 half-hour
        # slots and wrong on exactly one: between 23:30 and 23:59:59 UTC the
        # +30 minutes lands on the NEXT UTC day, so a second alert is the
        # right answer and the assertion below fired spuriously. That was the
        # whole of the intermittency -- a sweep of all 24 hours found 23:40Z
        # as the single failing slot and every other slot green, so the
        # production dedupe is correct and only the test's clock was at
        # fault. Midday keeps both ticks unambiguously inside one UTC day;
        # test_staleness_realerts_next_utc_day below covers the crossing
        # deliberately rather than by accident.
        now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
        old_run = now - timedelta(hours=40)
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old_run),
                      recent_runs=[{"id": 1, "started_at": _iso(old_run),
                                     "finished_at": _iso(old_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)
        dashboard._run_automation_alerts_tick(now + timedelta(minutes=30))

        assert len(posts) == 1, "second tick same UTC day must not re-alert"

    def test_staleness_realerts_next_utc_day(self, client, monkeypatch):
        """PAT-1039: the other half of the dedupe contract.

        Pinning the clock above removes the flake, but on its own it would
        also let a dedupe that never expires pass -- a job could go stale and
        alert once, ever. This asserts the crossing that the old test used to
        hit by accident: two ticks either side of UTC midnight are different
        calendar days and MUST both alert. Deliberately straddles the exact
        boundary the flake exposed.
        """
        now = datetime(2026, 7, 28, 23, 40, tzinfo=timezone.utc)
        old_run = now - timedelta(hours=40)
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old_run),
                      recent_runs=[{"id": 1, "started_at": _iso(old_run),
                                     "finished_at": _iso(old_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)                       # 28 Jul UTC
        dashboard._run_automation_alerts_tick(now + timedelta(minutes=30))  # 29 Jul UTC

        assert len(posts) == 2, "a tick on the next UTC day must re-alert"


# ── Failure alert regression guard ──────────────────────────────────────────

class TestFailureAlertRegression:
    def test_failed_run_alerts_as_before(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        recent = now - timedelta(hours=1)
        jobs = [_job("health_signals_recompute", last_run=_iso(recent), last_status="failed",
                      recent_runs=[{"id": 42, "started_at": _iso(recent),
                                     "finished_at": _iso(recent), "status": "failed",
                                     "duration_s": 3.0, "error_msg": "boom"}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1
        text = _flatten(posts[0])
        assert "Automation failure" in text
        assert ":red_circle:" in text
        assert "health_signals_recompute" in text
        assert "admin#automations" not in text
        assert "dashboard.patched.im/console#automations" in text

        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT * FROM automation_alerts_sent WHERE job_name=? AND run_id=?",
                ("health_signals_recompute", 42),
            ).fetchone()
        assert row is not None

    def test_failed_run_dedupe_by_run_id_unchanged(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        recent = now - timedelta(hours=1)
        jobs = [_job("health_signals_recompute", last_run=_iso(recent), last_status="failed",
                      recent_runs=[{"id": 42, "started_at": _iso(recent),
                                     "finished_at": _iso(recent), "status": "failed",
                                     "duration_s": 3.0, "error_msg": "boom"}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)
        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1, "same run_id must not re-alert"

    def test_failing_and_stale_are_independent_signals(self, client, monkeypatch):
        # A job whose only run FAILED a long time ago should get exactly one
        # failure alert (for the run) and, since it hasn't run since, exactly
        # one staleness alert too — they are different problems.
        now = datetime.now(timezone.utc)
        old = now - timedelta(hours=40)
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old), last_status="failed",
                      recent_runs=[{"id": 7, "started_at": _iso(old),
                                     "finished_at": _iso(old), "status": "failed",
                                     "duration_s": 3.0, "error_msg": "boom"}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 2
        headers = [_flatten(p) for p in posts]
        assert any("Automation failure" in h for h in headers)
        assert any("lagging" in h.lower() for h in headers)


# ── Daily digest ──────────────────────────────────────────────────────────────

class TestDailyDigest:
    def _healthy_jobs(self, now):
        recent = now - timedelta(hours=2)
        return [
            _job("health_signals_recompute", last_run=_iso(recent),
                 recent_runs=[{"id": 1, "started_at": _iso(recent), "finished_at": _iso(recent),
                                "status": "success", "duration_s": 5.0}]),
            _job("unmapped_scheduled_job", last_run=_iso(recent),
                 recent_runs=[{"id": 2, "started_at": _iso(recent), "finished_at": _iso(recent),
                                "status": "success", "duration_s": 5.0}]),
        ]

    def test_digest_fires_once_at_gate_hour(self, client, monkeypatch):
        now = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
        _mock_automations(monkeypatch, self._healthy_jobs(now))
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_digest_tick(now)
        dashboard._run_automation_digest_tick(now + timedelta(minutes=20))

        assert len(posts) == 1, "digest must fire at most once per UTC day"
        text = _flatten(posts[0])
        assert "digest" in text.lower()
        assert "2/2 green" in text or "All 2 automations green" in text

    def test_digest_skips_outside_gate_hour(self, client, monkeypatch):
        now = datetime.now(timezone.utc).replace(hour=14, minute=0, second=0, microsecond=0)
        _mock_automations(monkeypatch, self._healthy_jobs(now))
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_digest_tick(now)

        assert posts == []

    def test_digest_lists_failing_and_stale_jobs(self, client, monkeypatch):
        now = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
        old = now - timedelta(hours=100)
        jobs = [
            _job("health_signals_recompute", last_run=_iso(now - timedelta(hours=1)),
                 recent_runs=[{"id": 1, "started_at": _iso(now - timedelta(hours=1)),
                                "finished_at": _iso(now - timedelta(hours=1)),
                                "status": "success", "duration_s": 5.0}]),
            _job("unmapped_scheduled_job", last_status="failed",
                 last_run=_iso(now - timedelta(hours=1)),
                 recent_runs=[{"id": 2, "started_at": _iso(now - timedelta(hours=1)),
                                "finished_at": _iso(now - timedelta(hours=1)),
                                "status": "failed", "duration_s": 5.0}]),
            _job("unmapped_scheduled_job", last_run=_iso(old),
                 recent_runs=[{"id": 3, "started_at": _iso(old), "finished_at": _iso(old),
                                "status": "success", "duration_s": 5.0}]),
        ]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_digest_tick(now)

        assert len(posts) == 1
        text = _flatten(posts[0])
        assert "unmapped_scheduled_job" in text  # failing
        assert "unmapped_scheduled_job" in text     # stale
        assert "1 failing" in text
        assert "1 lagging" in text

    def test_digest_reports_no_active_automations_but_keeps_history_truthful(self, client, monkeypatch):
        now = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
        old = now - timedelta(days=10)
        jobs = [
            _job(name, last_run=_iso(old), last_status="failed",
                 recent_runs=[{"id": index, "started_at": _iso(old), "status": "failed"}])
            for index, name in enumerate(dashboard._QUARANTINED_AUTOMATIONS, start=1)
        ]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post(monkeypatch)

        dashboard._run_automation_digest_tick(now)

        assert len(posts) == 1
        text = _flatten(posts[0])
        assert "No active automations." in text
        assert "4 quarantined/retired historical job(s)" in text
        assert "failing" not in text.lower()
        assert "lagging" not in text.lower()


# ── PAT-1011: a 200 with a non-"ok" body must not count as delivered ────────
#
# Slack incoming webhooks return HTTP 200 with a plain-text body of exactly
# "ok" on a real delivery. A syntactically valid but wrong webhook URL
# (rotated Slack app, copy-paste error, misrouted proxy) can be answered
# with a 200 by something else entirely. Each site below previously checked
# only status_code == 200 and would have recorded a false "delivered",
# permanently suppressing the retry that would have surfaced the outage.

class TestBadDeliveryNotRecordedAsSent:
    def test_failure_alert_does_not_write_dedup_row_on_bad_body(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        recent = now - timedelta(hours=1)
        jobs = [_job("health_signals_recompute", last_run=_iso(recent), last_status="failed",
                      recent_runs=[{"id": 99, "started_at": _iso(recent),
                                     "finished_at": _iso(recent), "status": "failed",
                                     "duration_s": 3.0, "error_msg": "boom"}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post_bad_delivery(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1  # the POST was attempted
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT * FROM automation_alerts_sent WHERE job_name=? AND run_id=?",
                ("health_signals_recompute", 99),
            ).fetchone()
        assert row is None  # never actually delivered, so never recorded

    def test_staleness_alert_does_not_write_dedup_row_on_bad_body(self, client, monkeypatch):
        now = datetime.now(timezone.utc)
        old_run = now - timedelta(hours=40)
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old_run),
                      recent_runs=[{"id": 1, "started_at": _iso(old_run),
                                     "finished_at": _iso(old_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post_bad_delivery(monkeypatch)

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT * FROM automation_stale_alerts_sent WHERE job_name=?",
                ("unmapped_scheduled_job",),
            ).fetchone()
        assert row is None

    def test_staleness_alert_retried_next_tick_after_bad_body(self, client, monkeypatch):
        """No dedup row means the very next tick must retry, not be throttled.

        PAT-1039: `now` is pinned for test honesty rather than to fix a flake.
        This asserts 2 posts, and a tick pair straddling UTC midnight also
        yields 2 -- so between 23:55 and 23:59:59 UTC it would have passed
        because the calendar day changed, not because the missing dedup row
        allowed a retry, which is the behaviour it exists to prove. It never
        failed; it just stopped testing anything for five minutes a day.
        """
        now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
        old_run = now - timedelta(hours=40)
        jobs = [_job("unmapped_scheduled_job", last_run=_iso(old_run),
                      recent_runs=[{"id": 1, "started_at": _iso(old_run),
                                     "finished_at": _iso(old_run), "status": "success",
                                     "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post_bad_delivery(monkeypatch)

        dashboard._run_automation_alerts_tick(now)
        dashboard._run_automation_alerts_tick(now + timedelta(minutes=5))

        assert len(posts) == 2  # both attempts fired, no false throttle

    def test_digest_does_not_write_dedup_row_on_bad_body(self, client, monkeypatch):
        now = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
        recent = now - timedelta(hours=2)
        jobs = [_job("health_signals_recompute", last_run=_iso(recent),
                      recent_runs=[{"id": 1, "started_at": _iso(recent), "finished_at": _iso(recent),
                                     "status": "success", "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post_bad_delivery(monkeypatch)

        dashboard._run_automation_digest_tick(now)

        assert len(posts) == 1
        today = now.strftime("%Y-%m-%d")
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT * FROM automation_digest_sent WHERE digest_date=?", (today,)
            ).fetchone()
        assert row is None

    def test_digest_retried_next_tick_after_bad_body(self, client, monkeypatch):
        now = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
        recent = now - timedelta(hours=2)
        jobs = [_job("health_signals_recompute", last_run=_iso(recent),
                      recent_runs=[{"id": 1, "started_at": _iso(recent), "finished_at": _iso(recent),
                                     "status": "success", "duration_s": 5.0}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post_bad_delivery(monkeypatch)

        dashboard._run_automation_digest_tick(now)
        dashboard._run_automation_digest_tick(now + timedelta(minutes=10))

        assert len(posts) == 2  # digest_sent never wrote, so both ticks retried

    def test_non_200_also_not_recorded_as_sent(self, client, monkeypatch):
        """Regression guard for the pre-existing non-200 branch, now folded
        into the shared helper's single confirmation check."""
        now = datetime.now(timezone.utc)
        recent = now - timedelta(hours=1)
        jobs = [_job("health_signals_recompute", last_run=_iso(recent), last_status="failed",
                      recent_runs=[{"id": 5, "started_at": _iso(recent),
                                     "finished_at": _iso(recent), "status": "failed",
                                     "duration_s": 3.0, "error_msg": "boom"}])]
        _mock_automations(monkeypatch, jobs)
        posts = _mock_slack_post_bad_delivery(monkeypatch, status_code=500, text="")

        dashboard._run_automation_alerts_tick(now)

        assert len(posts) == 1
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT * FROM automation_alerts_sent WHERE job_name=? AND run_id=?",
                ("health_signals_recompute", 5),
            ).fetchone()
        assert row is None
