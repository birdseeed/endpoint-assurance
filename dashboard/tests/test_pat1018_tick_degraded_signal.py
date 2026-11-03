"""
PAT-1018: give a scheduler tick a third way to report itself through
_run_tick, beyond "raise" or "say nothing".

_run_automation_alerts_tick and _run_automation_digest_tick handle their own
Slack send failures internally (PAT-1011 correctly gates the de-duplication
writes on _post_slack_blocks_confirmed's return value, so a failed send stays
retryable) -- but a failed send never raised, so tick_automation_alerts and
tick_automation_digest always recorded "ok" even when every alert that tick
tried to post went nowhere.

_run_health_alerts_tick was half-fixed by PAT-1017: health_alert_delivery is
recorded degraded when a send doesn't confirm or the tenants-overview fetch
fails, but that never reached _run_tick either, so tick_health_alerts stayed
"ok" for the same tick health_alert_delivery called degraded. The two checks
contradicted each other.

Coverage:
  * _run_tick backwards compatibility -- a tick returning None still records
    ok (pre-existing behaviour, every tick written before this ticket).
  * _run_tick's new contract -- a tick returning a non-empty reason string
    records degraded with that reason, and the scheduler loop still moves on
    to the next tick (an exception is still the only thing that would need
    to be caught; a returned reason never raises).
  * _run_tick's exception path is unchanged -- still degraded with the
    exception text, truncated the same way.
  * _run_automation_alerts_tick returns a reason (so tick_automation_alerts
    reads degraded) when a Slack post inside it does not confirm delivery.
  * _run_automation_digest_tick returns a reason under the same condition.
  * _run_health_alerts_tick and health_alert_delivery agree, both when the
    tick is healthy and when a send inside it fails to confirm.

Run with: pytest tests/test_pat1018_tick_degraded_signal.py -v
"""

import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text="ok"):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text
        self.content = json.dumps(self._payload).encode() if payload is not None else b""

    def json(self):
        return self._payload


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


# ── _run_tick: the new return-value contract ─────────────────────────────────


def test_run_tick_none_return_records_ok(db):
    """Backwards compatibility: every tick written before this ticket returns
    None implicitly (a bare `return` or falling off the end) and must keep
    behaving exactly as before."""
    now = datetime.now(timezone.utc)

    dashboard._run_tick("widget-sync", lambda: None, now)

    row = _status("tick_widget_sync")
    assert row["state"] == "ok"
    assert row["reason"] == ""


def test_run_tick_empty_string_return_records_ok(db):
    """An empty string is treated the same as None -- both mean 'nothing
    wrong', not 'a zero-length problem'."""
    now = datetime.now(timezone.utc)

    dashboard._run_tick("widget-sync", lambda: "", now)

    row = _status("tick_widget_sync")
    assert row["state"] == "ok"


def test_run_tick_reason_string_records_degraded_and_loop_continues(db):
    """A tick that runs to completion without raising but returns a non-empty
    reason string is recorded degraded with that reason -- and the caller
    (standing in for scheduler_loop's next _run_tick call) still runs."""
    now = datetime.now(timezone.utc)
    calls = []

    dashboard._run_tick(
        "automation-alerts", lambda: "2 Slack alert send(s) did not confirm delivery", now
    )
    dashboard._run_tick("next-tick", lambda: calls.append("ran"), now)

    row = _status("tick_automation_alerts")
    assert row["state"] == "degraded"
    assert row["reason"] == "2 Slack alert send(s) did not confirm delivery"
    assert calls == ["ran"], "a degraded-via-return tick must not stop the loop"


def test_run_tick_long_reason_string_is_truncated_like_exception_text(db):
    """The ticket asks for one truncation rule shared by both paths, not a
    second copy of the 200-char/ellipsis logic for the return-value path."""
    now = datetime.now(timezone.utc)
    long_reason = "x" * 500

    dashboard._run_tick("widget-sync", lambda: long_reason, now)

    row = _status("tick_widget_sync")
    assert row["state"] == "degraded"
    assert len(row["reason"]) == 201  # 200 chars + the truncation marker
    assert row["reason"].endswith("…")


def test_run_tick_exception_still_records_degraded_unchanged(db, capsys):
    """An exception must still mean degraded with the exception text -- the
    new return-value path is additive, not a replacement for this."""
    now = datetime.now(timezone.utc)

    def boom():
        raise ValueError("kaboom")

    dashboard._run_tick("widget-sync", boom, now)

    row = _status("tick_widget_sync")
    assert row["state"] == "degraded"
    assert "kaboom" in row["reason"]
    captured = capsys.readouterr()
    assert "[scheduler/widget-sync] Error: kaboom" in captured.out


# ── _run_automation_alerts_tick: a failed send must surface at tick level ──


def _job(job_name, last_run=None, recent_runs=None, schedule="Daily (06:00 UTC)", last_status="success"):
    return {
        "job_name": job_name,
        "schedule": schedule,
        "description": job_name,
        "last_status": last_status,
        "last_run": last_run,
        "recent_runs": recent_runs if recent_runs is not None else [],
    }


def _mock_automations(monkeypatch, jobs):
    def fake_get(url, *a, **k):
        if url.endswith("/admin/automations"):
            return _FakeResp({"jobs": jobs})
        return _FakeResp({})
    monkeypatch.setattr(dashboard.http, "get", fake_get)


def test_automation_alerts_tick_ok_when_nothing_to_send(db, monkeypatch):
    """A tick with nothing to send is not degraded."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    _mock_automations(monkeypatch, [_job("healthy-job", last_run=datetime.now(timezone.utc).isoformat())])

    def fake_post(url, json=None, **k):
        raise AssertionError("no send should be attempted")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    reason = dashboard._run_automation_alerts_tick(datetime.now(timezone.utc))

    assert reason is None


def test_automation_alerts_tick_unconfirmed_send_is_degraded(db, monkeypatch):
    """A failed run posts an alert; when Slack doesn't confirm delivery the
    tick must return a reason so tick_automation_alerts reads degraded --
    not just automation_alerts_sent staying un-inserted (already correct
    since PAT-1011, but invisible to the outer tick)."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc)
    failed_job = _job(
        "nightly-scan",
        last_run=now.isoformat(),  # recent, so the staleness section doesn't also fire
        recent_runs=[{"id": "run-1", "status": "failed", "started_at": now.isoformat(),
                      "duration_s": 5, "error_msg": "boom"}],
    )
    _mock_automations(monkeypatch, [failed_job])

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, text="Not Found")  # 200 but not confirmed

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    reason = dashboard._run_automation_alerts_tick(now)

    assert reason is not None
    assert "did not confirm delivery" in reason

    # The existing PAT-1011 de-dup gate must still be intact: an unconfirmed
    # send must not be recorded as sent, so it retries next tick.
    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM automation_alerts_sent WHERE job_name=? AND run_id=?",
            ("nightly-scan", "run-1"),
        ).fetchone()
    assert row is None


def test_automation_alerts_tick_via_run_tick_records_degraded(db, monkeypatch):
    """End-to-end through _run_tick, the way scheduler_loop actually calls
    this: tick_automation_alerts must read degraded when the underlying
    Slack post did not confirm."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc)
    failed_job = _job(
        "nightly-scan",
        last_run=now.isoformat(),  # recent, so the staleness section doesn't also fire
        recent_runs=[{"id": "run-1", "status": "failed", "started_at": now.isoformat(),
                      "duration_s": 5, "error_msg": "boom"}],
    )
    _mock_automations(monkeypatch, [failed_job])

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, text="Not Found")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_tick(
        "automation-alerts", lambda: dashboard._run_automation_alerts_tick(now), now
    )

    tick_row = _status("tick_automation_alerts")
    assert tick_row["state"] == "degraded"
    assert "did not confirm delivery" in tick_row["reason"]

    # PAT-1018 follow-up: the dedicated automation_alerts availability check
    # must agree with the tick, not keep saying ok (as it did when it was
    # written before the fetch ran) while tick_automation_alerts says
    # degraded.
    availability_row = _status("automation_alerts")
    assert availability_row["state"] == "degraded"
    assert availability_row["reason"] == tick_row["reason"]


# ── _run_automation_alerts_tick: a fetch failure, not just a send failure ──
#
# Before this fix, a failed/non-200/unparseable /admin/automations fetch
# returned None (read as ok by the tick) while automation_alerts had already
# been recorded ok moments earlier -- no job was ever inspected and no alert
# could have been sent, and both checks said fine. These three cases mirror
# the distinction _run_health_alerts_tick already draws for its own fetch.


@pytest.mark.usefixtures("network_down")
def test_automation_alerts_tick_fetch_exception_is_degraded_and_named_check_agrees(
    db, monkeypatch
):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

    def fake_get(url, *a, **k):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "automation-alerts", lambda: dashboard._run_automation_alerts_tick(now), now
    )

    tick_row = _status("tick_automation_alerts")
    check_row = _status("automation_alerts")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    assert tick_row["reason"] == check_row["reason"]
    assert "automations request failed" in tick_row["reason"]


@pytest.mark.usefixtures("network_down")
def test_automation_alerts_tick_fetch_non200_is_degraded_and_named_check_agrees(
    db, monkeypatch
):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

    def fake_get(url, *a, **k):
        return _FakeResp(status_code=503, text="Service Unavailable")

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "automation-alerts", lambda: dashboard._run_automation_alerts_tick(now), now
    )

    tick_row = _status("tick_automation_alerts")
    check_row = _status("automation_alerts")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    assert tick_row["reason"] == check_row["reason"]
    assert "returned HTTP 503" in tick_row["reason"]


@pytest.mark.usefixtures("network_down")
def test_automation_alerts_tick_fetch_unparseable_body_is_degraded_and_named_check_agrees(
    db, monkeypatch
):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

    class _BadJsonResp:
        status_code = 200
        content = b"not json"

        def json(self):
            raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(dashboard.http, "get", lambda url, *a, **k: _BadJsonResp())
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "automation-alerts", lambda: dashboard._run_automation_alerts_tick(now), now
    )

    tick_row = _status("tick_automation_alerts")
    check_row = _status("automation_alerts")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    assert tick_row["reason"] == check_row["reason"]
    assert "not valid JSON" in tick_row["reason"]


# ── _run_automation_digest_tick: same shape, single send ────────────────────


def test_automation_digest_tick_unconfirmed_send_is_degraded(db, monkeypatch):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc).replace(hour=9)
    _mock_automations(monkeypatch, [_job("healthy-job", last_run=now.isoformat())])

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, text="Not Found")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    reason = dashboard._run_automation_digest_tick(now)

    assert reason is not None
    assert "did not confirm delivery" in reason
    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM automation_digest_sent WHERE digest_date=?",
            (now.strftime("%Y-%m-%d"),),
        ).fetchone()
    assert row is None, "an unconfirmed digest send must stay retryable next tick"


def test_automation_digest_tick_confirmed_send_records_none(db, monkeypatch):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc).replace(hour=9)
    _mock_automations(monkeypatch, [_job("healthy-job", last_run=now.isoformat())])

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, text="ok")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    reason = dashboard._run_automation_digest_tick(now)

    assert reason is None


def test_automation_digest_tick_not_due_returns_none(db, monkeypatch):
    """Not the 09:00 UTC hour -- nothing attempted, not degraded."""
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc).replace(hour=3)

    def fake_get(url, *a, **k):
        raise AssertionError("should not fetch automations outside the 09:00 UTC window")

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    reason = dashboard._run_automation_digest_tick(now)

    assert reason is None


# ── _run_automation_digest_tick: a fetch failure is the costlier case ──────
#
# The digest has one shot a day (09:00 UTC). Before this fix, a failed,
# non-200, or unparseable /admin/automations fetch returned None -- read as
# ok by tick_automation_digest -- and no digest went out, with nothing
# retrying until tomorrow. These mirror the three automation_alerts fetch
# cases above; there is no separate named availability check for the digest
# (only tick_automation_digest, via _run_tick), so agreement here means the
# tick's own reason names the cause.


@pytest.mark.usefixtures("network_down")
def test_automation_digest_tick_fetch_exception_is_degraded(db, monkeypatch):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc).replace(hour=9)

    def fake_get(url, *a, **k):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_tick(
        "automation-digest", lambda: dashboard._run_automation_digest_tick(now), now
    )

    tick_row = _status("tick_automation_digest")
    assert tick_row["state"] == "degraded"
    assert "automations request failed" in tick_row["reason"]
    with dashboard.get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM automation_digest_sent WHERE digest_date=?",
            (now.strftime("%Y-%m-%d"),),
        ).fetchone()
    assert row is None, "a fetch failure must not consume today's digest slot"


@pytest.mark.usefixtures("network_down")
def test_automation_digest_tick_fetch_non200_is_degraded(db, monkeypatch):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc).replace(hour=9)

    def fake_get(url, *a, **k):
        return _FakeResp(status_code=503, text="Service Unavailable")

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_tick(
        "automation-digest", lambda: dashboard._run_automation_digest_tick(now), now
    )

    tick_row = _status("tick_automation_digest")
    assert tick_row["state"] == "degraded"
    assert "returned HTTP 503" in tick_row["reason"]


@pytest.mark.usefixtures("network_down")
def test_automation_digest_tick_fetch_unparseable_body_is_degraded(db, monkeypatch):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    now = datetime.now(timezone.utc).replace(hour=9)

    class _BadJsonResp:
        status_code = 200
        content = b"not json"

        def json(self):
            raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(dashboard.http, "get", lambda url, *a, **k: _BadJsonResp())

    dashboard._run_tick(
        "automation-digest", lambda: dashboard._run_automation_digest_tick(now), now
    )

    tick_row = _status("tick_automation_digest")
    assert tick_row["state"] == "degraded"
    assert "not valid JSON" in tick_row["reason"]


# ── _run_health_alerts_tick and health_alert_delivery must agree ────────────


def _configure_slack_only(monkeypatch):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")


def _mock_tenants_overview(monkeypatch, tenants):
    def fake_get(url, *a, **k):
        assert url.endswith("/admin/tenants/overview")
        return _FakeResp({"tenants": tenants}, 200)
    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _at_risk_tenant(tenant_id="tenant-1", name="Acme Corp", compliance_pct=40):
    return {
        "id": tenant_id,
        "name": name,
        "health_bucket": "at_risk",
        "health_score": 30,
        "compliance_pct": compliance_pct,
    }


def test_health_alerts_tick_and_check_agree_when_healthy(db, monkeypatch):
    """The concrete contradiction this ticket fixes, healthy case: nothing
    needed sending, so both tick_health_alerts and health_alert_delivery
    must read ok."""
    _configure_slack_only(monkeypatch)
    healthy_tenant = {
        "id": "tenant-1", "name": "Acme Corp", "health_bucket": "healthy",
        "health_score": 90, "compliance_pct": 95,
    }
    _mock_tenants_overview(monkeypatch, [healthy_tenant])
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "health-alerts", lambda: dashboard._run_health_alerts_tick(now), now
    )

    tick_row = _status("tick_health_alerts")
    delivery_row = _status("health_alert_delivery")
    assert tick_row["state"] == "ok"
    assert delivery_row["state"] == "ok"


def test_health_alerts_tick_and_check_agree_when_send_fails(db, monkeypatch):
    """The concrete contradiction this ticket fixes, failing case: PAT-1017
    already recorded health_alert_delivery degraded here, but before this
    ticket tick_health_alerts still read ok for the identical tick. Both
    must now read degraded, with the same reason."""
    _configure_slack_only(monkeypatch)
    tenant = _at_risk_tenant()
    _mock_tenants_overview(monkeypatch, [tenant])

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, text="Not Found")

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "health-alerts", lambda: dashboard._run_health_alerts_tick(now), now
    )

    tick_row = _status("tick_health_alerts")
    delivery_row = _status("health_alert_delivery")
    assert tick_row["state"] == "degraded"
    assert delivery_row["state"] == "degraded"
    assert tick_row["reason"] == delivery_row["reason"]


@pytest.mark.usefixtures("network_down")
def test_health_alerts_tick_and_check_agree_on_tenants_fetch_failure(db, monkeypatch):
    """A third contradiction case: the tenants-overview fetch itself fails,
    so whether any tenant needed an alert is unknown. health_alert_delivery
    already records this as degraded (PAT-1017); tick_health_alerts must
    match it, not read ok because fn() never raised."""
    _configure_slack_only(monkeypatch)

    def fake_get(url, *a, **k):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "health-alerts", lambda: dashboard._run_health_alerts_tick(now), now
    )

    tick_row = _status("tick_health_alerts")
    delivery_row = _status("health_alert_delivery")
    assert tick_row["state"] == "degraded"
    assert delivery_row["state"] == "degraded"
    assert tick_row["reason"] == delivery_row["reason"]
    assert "tenants overview request failed" in tick_row["reason"]


def test_health_alerts_tick_unconfigured_channel_does_not_degrade_tick(db, monkeypatch):
    """Unconfigured is a standing configuration gap reported by
    health_alert_delivery itself, not a tick failure -- tick_health_alerts
    must stay ok (unchanged behaviour, in scope for the backwards-
    compatibility guarantee, not something this ticket redefines)."""
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "health-alerts", lambda: dashboard._run_health_alerts_tick(now), now
    )

    tick_row = _status("tick_health_alerts")
    delivery_row = _status("health_alert_delivery")
    assert tick_row["state"] == "ok"
    assert delivery_row["state"] == "unconfigured"
