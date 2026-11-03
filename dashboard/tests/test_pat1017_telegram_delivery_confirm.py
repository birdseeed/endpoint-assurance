"""
PAT-1017: Telegram delivery confirmation for _send_health_alert(), and the
matching tick-level health_alert_delivery accuracy fix.

Same defect class PAT-1011 fixed for the Slack fallback:

  * A bare HTTP 200 from the Telegram Bot API is not proof of delivery --
    the API answers 200 with a JSON body carrying "ok": false for real
    failures (bad chat id, bot removed from the chat, rate limited). Only
    status 200 AND a parsed body with "ok": true counts as delivered. A
    body that fails to parse as JSON is a failure too, not a success.
  * TELEGRAM_BOT_TOKEN is embedded in the request URL path, so it IS the
    credential, exactly like a Slack incoming-webhook URL. requests'
    connection/TLS exceptions often embed the full request URL in their
    string form, so only the exception type name is logged on a POST
    failure, never str(e).
  * _run_health_alerts_tick() must record health_alert_delivery from what
    the tick actually attempted, not from configuration presence alone --
    a tick where a send was attempted and did not confirm must not leave
    the check at "ok".
  * A tenants-overview fetch that fails, returns non-200, or can't be
    parsed as JSON is a third outcome, distinct from "nothing needed
    sending": whether any tenant needed an alert is unknown, and that is
    not ok either.

Run with: pytest tests/test_pat1017_telegram_delivery_confirm.py -v
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
    """Fake requests.Response. status_code + a body that is either valid
    JSON (payload) or, when json_ok is False, garbage text that .json()
    raises on -- exercising the non-JSON-body failure path explicitly."""

    def __init__(self, payload=None, status_code=200, json_ok=True, text=None):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self._json_ok = json_ok
        self.text = text if text is not None else json.dumps(self._payload)
        self.content = self.text.encode()

    def json(self):
        if not self._json_ok:
            raise json.JSONDecodeError("Expecting value", self.text, 0)
        return self._payload


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _configure_telegram_only(monkeypatch):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "secret-bot-token-123")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")


def _configure_telegram_and_slack(monkeypatch):
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", "secret-bot-token-123")
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


# ── Defect 1: bare 200 is not proof of delivery ─────────────────────────────


def test_telegram_200_with_ok_true_is_delivered(db, monkeypatch):
    _configure_telegram_only(monkeypatch)

    def fake_post(url, json=None, **k):
        assert "secret-bot-token-123" in url
        return _FakeResp({"ok": True, "result": {"message_id": 1}})

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is True
    row = _status("health_alert_delivery")
    assert row["state"] == "ok"


def test_telegram_200_with_ok_false_is_not_delivered_and_falls_back_to_slack(db, monkeypatch):
    _configure_telegram_and_slack(monkeypatch)

    posts = []

    def fake_post(url, json=None, **k):
        posts.append(url)
        if "api.telegram.org" in url:
            # Real Telegram failure shape: 200 with ok:false, e.g. a bad
            # chat id or the bot removed from the chat.
            return _FakeResp({"ok": False, "error_code": 403, "description": "Forbidden"})
        return _FakeResp(status_code=200, text="ok", json_ok=False)

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is True, "Telegram ok:false must fall through to the Slack fallback"
    assert len(posts) == 2
    assert "api.telegram.org" in posts[0]
    assert "hooks.slack.test" in posts[1]


def test_telegram_200_with_non_json_body_is_not_delivered(db, monkeypatch):
    _configure_telegram_and_slack(monkeypatch)

    posts = []

    def fake_post(url, json=None, **k):
        posts.append(url)
        if "api.telegram.org" in url:
            return _FakeResp(status_code=200, json_ok=False, text="<html>Not JSON</html>")
        return _FakeResp(status_code=200, text="ok", json_ok=False)

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is True, "a non-JSON 200 body must be treated as a failure, not success"
    assert len(posts) == 2, "Telegram must fail (not confirmed) and fall through to Slack"


def test_telegram_non_json_body_with_no_fallback_is_not_delivered(db, monkeypatch):
    """Same as above but with no Slack fallback configured, so the overall
    outcome must be False (not delivered), not True."""
    _configure_telegram_only(monkeypatch)

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, json_ok=False, text="not json at all")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is False
    row = _status("health_alert_delivery")
    assert row["state"] == "degraded"


# ── Defect 2: the bot token must never reach the logs ───────────────────────


def test_telegram_post_exception_does_not_log_token(db, monkeypatch, capsys):
    secret_token = "123456789:AAFakeBotTokenValueThatMustNeverLeak"
    monkeypatch.setattr(dashboard, "TELEGRAM_BOT_TOKEN", secret_token)
    monkeypatch.setattr(dashboard, "TELEGRAM_CHAT_ID", "chat-1")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")

    def _raise(url, json=None, **k):
        # Mirrors how requests' own connection/TLS exceptions read: the
        # full request URL (which embeds the bot token) is in the message.
        raise ConnectionError(
            f"HTTPSConnectionPool(host='api.telegram.org'): "
            f"Max retries exceeded with url: /bot{secret_token}/sendMessage"
        )

    monkeypatch.setattr(dashboard.http, "post", _raise)

    sent = dashboard._send_health_alert("Acme Corp", "at_risk", "healthy", 42)

    assert sent is False
    captured = capsys.readouterr()
    assert secret_token not in captured.out, (
        "the bot token must never appear in application logs -- it is the "
        "credential, embedded in the request URL path"
    )
    assert "ConnectionError" in captured.out


# ── Defect 3: tick-level health_alert_delivery must reflect real outcomes ──


def _mock_tenants_overview(monkeypatch, tenants):
    def fake_get(url, *a, **k):
        assert url.endswith("/admin/tenants/overview")
        return _FakeResp({"tenants": tenants}, 200)
    monkeypatch.setattr(dashboard.http, "get", fake_get)


def _at_risk_tenant(tenant_id, name, compliance_pct=40):
    return {
        "id": tenant_id,
        "name": name,
        "health_bucket": "at_risk",
        "health_score": 30,
        "compliance_pct": compliance_pct,
    }


def test_tick_with_no_transitions_records_ok_not_degraded(db, monkeypatch):
    """No tenant needs an alert this tick (nothing attempted) -- that is not
    a failure and must not report degraded."""
    _configure_telegram_and_slack(monkeypatch)
    healthy_tenant = {
        "id": "tenant-1", "name": "Acme Corp", "health_bucket": "healthy",
        "health_score": 90, "compliance_pct": 95,
    }
    _mock_tenants_overview(monkeypatch, [healthy_tenant])

    def fake_post(url, json=None, **k):
        raise AssertionError("no send should be attempted this tick")

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row["state"] == "ok"


def test_tick_with_attempted_and_unconfirmed_send_records_degraded(db, monkeypatch):
    """A tick where a send was attempted and did not confirm must not
    record health_alert_delivery as ok -- this is the defect-3 regression
    guard. Before the fix, this eagerly recorded "ok" purely from
    TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID/SLACK_WEBHOOK_URL being set, before
    the send below (which fails) was even attempted."""
    _configure_telegram_only(monkeypatch)
    tenant = _at_risk_tenant("tenant-1", "Acme Corp")
    _mock_tenants_overview(monkeypatch, [tenant])

    def fake_post(url, json=None, **k):
        return _FakeResp({"ok": False, "error_code": 400, "description": "Bad Request"})

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row["state"] == "degraded"


def test_tick_where_a_later_success_does_not_mask_an_earlier_failure(db, monkeypatch):
    """Two tenants need an alert in the same tick: the first tenant's send
    fails, the second tenant's send succeeds. Because _send_health_alert()
    writes health_alert_delivery on every individual call, a naive
    last-write-wins implementation would let the second (successful) call
    overwrite the first (failed) call's "degraded" state with "ok",
    silently hiding the first tenant's failed delivery. The tick-level
    aggregate write must catch this."""
    _configure_telegram_only(monkeypatch)
    tenant_a = _at_risk_tenant("tenant-a", "Alpha Corp")
    tenant_b = _at_risk_tenant("tenant-b", "Beta Corp")
    _mock_tenants_overview(monkeypatch, [tenant_a, tenant_b])

    def fake_post(url, json=None, **k):
        if "chat_id" in (json or {}) and json.get("text", "").startswith("⚠️ Health alert: Alpha"):
            return _FakeResp({"ok": False, "error_code": 403, "description": "Forbidden"})
        return _FakeResp({"ok": True, "result": {"message_id": 1}})

    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row["state"] == "degraded", (
        "tenant-a's failed delivery must not be masked by tenant-b's "
        "later successful delivery in the same tick"
    )

    with dashboard.get_db() as conn:
        row_a = conn.execute(
            "SELECT alert_delivered FROM health_alerts_sent WHERE tenant_id=?", ("tenant-a",)
        ).fetchone()
        row_b = conn.execute(
            "SELECT alert_delivered FROM health_alerts_sent WHERE tenant_id=?", ("tenant-b",)
        ).fetchone()
    assert row_a["alert_delivered"] == 0
    assert row_b["alert_delivered"] == 1


def test_tick_fetch_exception_records_degraded_not_ok(db, monkeypatch):
    """If the tenants-overview request itself raises (network error), no
    send is attempted -- but that means whether any tenant needed an alert
    is UNKNOWN, not "nothing needed sending". Recording "ok" here is the
    same false-success shape this ticket exists to remove, one level up:
    a failed fetch must not be indistinguishable from a healthy tick with
    nothing to do. Must be written (not skipped), so a stale "ok" from a
    previous tick can't stand in for this tick's real, unknown outcome."""
    _configure_telegram_and_slack(monkeypatch)

    def fake_get(url, *a, **k):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row is not None
    assert row["state"] == "degraded"
    assert "tenants overview request failed" in row["reason"]


def test_tick_fetch_non_200_records_degraded_with_reason(db, monkeypatch):
    """A non-200 (or empty-body) tenants-overview response does not raise --
    it takes a different code path than a request-level exception (no
    exception is ever thrown, r.status_code is just not 200). Before the
    fix this silently fell through to an empty tenant list and reported
    "ok" via the no-transitions branch. It must report degraded with a
    reason naming the HTTP status, same as the exception case, not be
    conflated with "nothing needed sending"."""
    _configure_telegram_and_slack(monkeypatch)

    def fake_get(url, *a, **k):
        assert url.endswith("/admin/tenants/overview")
        return _FakeResp({}, status_code=503)

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row is not None
    assert row["state"] == "degraded"
    assert "503" in row["reason"]


def test_tick_fetch_malformed_json_records_degraded_with_reason(db, monkeypatch):
    """A 200 response whose body isn't valid JSON is a third distinct code
    path: status_code == 200 so the non-200 branch is skipped, but
    r.json() raises, so it must not silently fall through to an empty
    tenant list either."""
    _configure_telegram_and_slack(monkeypatch)

    def fake_get(url, *a, **k):
        assert url.endswith("/admin/tenants/overview")
        return _FakeResp(status_code=200, json_ok=False, text="not json")

    monkeypatch.setattr(dashboard.http, "get", fake_get)

    dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

    row = _status("health_alert_delivery")
    assert row is not None
    assert row["state"] == "degraded"
    assert "not valid JSON" in row["reason"]
