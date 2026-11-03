"""Durable visibility for scheduled checks that cannot run."""

import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text
        self.content = json.dumps(self._payload).encode()

    def json(self):
        return self._payload


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


def test_portal_auth_missing_config_records_specific_variables(db, monkeypatch):
    monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "")
    monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", "")

    assert dashboard._check_portal_access_aud() is None

    row = _status("portal_auth")
    assert row["state"] == "unconfigured"
    assert row["reason"] == (
        "missing CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ACCESS_APP_ID, "
        "PORTAL_ACCESS_AUD"
    )
    assert row["evaluated_at"]


def test_automation_alerts_without_slack_records_unconfigured(db, monkeypatch):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")

    dashboard._run_automation_alerts_tick(datetime.now(timezone.utc))

    row = _status("automation_alerts")
    assert row["state"] == "unconfigured"
    assert row["reason"] == "SLACK_WEBHOOK_URL not set"


def test_health_alert_delivery_without_channel_records_unconfigured(db, monkeypatch):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row["state"] == "unconfigured"
    assert "TELEGRAM_BOT_TOKEN" in row["reason"]
    assert "TELEGRAM_CHAT_ID" in row["reason"]
    assert "SLACK_WEBHOOK_URL" in row["reason"]


def test_rbac_operators_unset_records_degraded(db, monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset())

    dashboard._run_rbac_operators_check_tick(now)

    row = _status("rbac_operators")
    assert row["state"] == "degraded"
    assert "no session owners configured" in row["reason"]
    assert row["evaluated_at"] == now.isoformat()


def test_rbac_operators_set_records_count_without_addresses(db, monkeypatch):
    now = datetime.now(timezone.utc)
    addresses = frozenset({"owner@example.com", "second@example.com"})
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", addresses)

    dashboard._run_rbac_operators_check_tick(now)

    row = _status("rbac_operators")
    assert row["state"] == "ok"
    assert "2 operators configured" in row["reason"]
    assert all(address not in row["reason"] for address in addresses)
    assert row["evaluated_at"] == now.isoformat()


def test_role_for_email_fails_closed_without_operators(monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset())
    assert dashboard._role_for_email(None) == "consultant"
    assert dashboard._role_for_email("anyone@example.com") == "consultant"

    monkeypatch.setattr(
        dashboard,
        "DASHBOARD_OPERATORS",
        frozenset({"owner@example.com"}),
    )
    assert dashboard._role_for_email(" OWNER@example.com ") == "owner"
    assert dashboard._role_for_email("consultant@example.com") == "consultant"
    assert dashboard._role_for_email(None) == "consultant"


def test_configured_portal_auth_behaviour_is_unchanged_and_records_ok(
    db, monkeypatch
):
    monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "account")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "app")
    monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", "expected-aud")
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return _FakeResp({"result": {"aud": "expected-aud"}})

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    assert dashboard._check_portal_access_aud() == (False, "")
    assert calls == [(
        "https://api.cloudflare.com/client/v4/accounts/account/access/apps/app",
        {
            "headers": {"Authorization": "Bearer token"},
            "timeout": 15,
        },
    )]
    row = _status("portal_auth")
    assert row["state"] == "ok"
    assert row["reason"] == ""


def test_digest_includes_unconfigured_checks(db, monkeypatch):
    now = datetime.now(timezone.utc).replace(
        hour=9, minute=0, second=0, microsecond=0
    )
    dashboard._record_check_status(
        "portal_auth",
        "unconfigured",
        "missing CLOUDFLARE_ACCOUNT_ID",
        now,
    )
    monkeypatch.setattr(
        dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake"
    )
    posts = []

    def fake_get(url, **kwargs):
        assert url.endswith("/admin/automations")
        return _FakeResp({"jobs": []})

    def fake_post(url, json=None, **kwargs):
        posts.append(json)
        return _FakeResp({"ok": True})

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_automation_digest_tick(now)

    assert len(posts) == 1
    text = json.dumps(posts[0])
    assert "Checks needing attention" in text
    assert "portal_auth" in text
    assert "unconfigured" in text
    assert "missing CLOUDFLARE_ACCOUNT_ID" in text


def test_digest_includes_degraded_rbac_state(db, monkeypatch):
    now = datetime.now(timezone.utc).replace(
        hour=9, minute=0, second=0, microsecond=0
    )
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset())
    dashboard._run_rbac_operators_check_tick(now)
    monkeypatch.setattr(
        dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake"
    )
    posts = []

    def fake_get(url, **kwargs):
        assert url.endswith("/admin/automations")
        return _FakeResp({"jobs": []})

    def fake_post(url, json=None, **kwargs):
        posts.append(json)
        return _FakeResp({"ok": True})

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_automation_digest_tick(now)

    assert len(posts) == 1
    text = json.dumps(posts[0])
    assert "rbac_operators" in text
    assert "degraded" in text
    assert "no session owners configured" in text


def test_endpoint_returns_recorded_statuses(db):
    evaluated_at = datetime(2026, 7, 26, 8, 30, tzinfo=timezone.utc)
    dashboard._record_check_status(
        "portal_auth",
        "degraded",
        "Cloudflare API returned 500",
        evaluated_at,
    )
    dashboard._record_check_status(
        "automation_alerts",
        "ok",
        "",
        evaluated_at,
    )

    with TestClient(dashboard.app) as client:
        response = client.get("/admin/check-status", headers=BEARER)

    assert response.status_code == 200
    body = response.json()
    # PAT-1427: every row also carries age_seconds/stale, computed against
    # the real current time -- evaluated_at above is weeks in the past, so
    # both rows must read as stale with a large, but not exactly pinnable
    # (test wall-clock dependent), age. Assert the stable fields exactly and
    # the freshness fields structurally.
    assert len(body["checks"]) == 2
    checks_by_name = {c["name"]: c for c in body["checks"]}

    automation = checks_by_name["automation_alerts"]
    assert automation["state"] == "ok"
    assert automation["reason"] == ""
    assert automation["evaluated_at"] == evaluated_at.isoformat()
    assert isinstance(automation["age_seconds"], int)
    assert automation["age_seconds"] > 0
    assert automation["stale"] is True

    portal = checks_by_name["portal_auth"]
    assert portal["state"] == "degraded"
    assert portal["reason"] == "Cloudflare API returned 500"
    assert portal["evaluated_at"] == evaluated_at.isoformat()
    assert isinstance(portal["age_seconds"], int)
    assert portal["age_seconds"] > 0
    assert portal["stale"] is True


# ── PAT-981: per-tick heartbeats ─────────────────────────────────────────
#
# _run_tick wraps every scheduler_loop tick so a silently-dead tick shows up
# in check_statuses as tick_<label> instead of vanishing without a trace.


def test_run_tick_success_records_ok_heartbeat(db):
    now = datetime.now(timezone.utc)
    calls = []

    dashboard._run_tick("widget-sync", lambda: calls.append(1), now)

    assert calls == [1]
    row = _status("tick_widget_sync")
    assert row["state"] == "ok"
    assert row["reason"] == ""
    assert row["evaluated_at"] == now.isoformat()


def test_run_tick_exception_records_degraded_and_does_not_propagate(db, capsys):
    now = datetime.now(timezone.utc)

    def boom():
        raise ValueError("kaboom")

    # Must not raise.
    dashboard._run_tick("widget-sync", boom, now)

    row = _status("tick_widget_sync")
    assert row["state"] == "degraded"
    assert "kaboom" in row["reason"]
    assert row["evaluated_at"] == now.isoformat()

    captured = capsys.readouterr()
    assert "[scheduler/widget-sync] Error: kaboom" in captured.out


def test_run_tick_failure_does_not_block_subsequent_ticks(db):
    now = datetime.now(timezone.utc)
    calls = []

    def boom():
        raise RuntimeError("first tick is on fire")

    dashboard._run_tick("first-tick", boom, now)
    dashboard._run_tick("second-tick", lambda: calls.append("ran"), now)

    assert calls == ["ran"]
    assert _status("tick_first_tick")["state"] == "degraded"
    assert _status("tick_second_tick")["state"] == "ok"


def test_run_tick_wraps_existing_self_recording_check_without_overwriting_it(
    db, monkeypatch
):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(
        dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@example.com"})
    )

    dashboard._run_tick(
        "rbac-operators", lambda: dashboard._run_rbac_operators_check_tick(now), now
    )

    # The check's own richer entry is untouched...
    rbac_row = _status("rbac_operators")
    assert rbac_row["state"] == "ok"
    assert "1 operators configured" in rbac_row["reason"]

    # ...and the heartbeat is recorded alongside it, not instead of it.
    tick_row = _status("tick_rbac_operators")
    assert tick_row["state"] == "ok"


# ── PAT-1011: Slack delivery must be confirmed, not just HTTP 200 ───────────
#
# _send_health_alert's Slack fallback previously recorded health_alert_delivery
# as "ok" on any HTTP 200, even if the body wasn't Slack's own "ok" delivery
# confirmation (e.g. a syntactically valid but wrong/misrouted webhook URL).
# It also logged the raw response body on failure, an untrusted-input
# log-injection surface already removed from the portal-auth path (PAT-988).


def test_health_alert_slack_bad_body_is_not_recorded_as_delivered(db, monkeypatch):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

    def fake_post(url, json=None, **kwargs):
        return _FakeResp(status_code=200, text="Not Found")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is False
    row = _status("health_alert_delivery")
    assert row["state"] == "degraded"


def test_health_alert_slack_confirmed_ok_body_is_recorded_as_delivered(db, monkeypatch):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

    def fake_post(url, json=None, **kwargs):
        return _FakeResp(status_code=200, text="ok")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is True
    row = _status("health_alert_delivery")
    assert row["state"] == "ok"


def test_health_alert_slack_failure_does_not_log_response_body(db, monkeypatch, capsys):
    """Log-injection guard: a failure response's body must never reach the
    log, only its status code. Matches the fix already applied on the
    portal-auth path under PAT-988."""
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

    injected = "INJECTED-LOG-LINE-should-never-appear"

    def fake_post(url, json=None, **kwargs):
        return _FakeResp(status_code=500, text=f"<html>{injected}</html>")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    captured = capsys.readouterr()
    assert injected not in captured.out
    assert "500" in captured.out


def test_health_alert_telegram_failure_does_not_log_response_body(db, monkeypatch, capsys):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "chat")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")

    injected = "INJECTED-TELEGRAM-BODY-should-never-appear"

    def fake_post(url, json=None, **kwargs):
        return _FakeResp(status_code=500, text=f"<html>{injected}</html>")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    captured = capsys.readouterr()
    assert injected not in captured.out
    assert "500" in captured.out
