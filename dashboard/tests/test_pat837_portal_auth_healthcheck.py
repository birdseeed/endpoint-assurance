"""
PAT-837 — portal Cloudflare Access AUD-drift health check.

Covers:
  * _check_portal_access_aud() returns None (no-op, never a false positive)
    when any required Cloudflare/expected-AUD config is missing.
  * Returns (False, "") when the live Cloudflare AUD matches, (True, detail)
    when it doesn't.
  * _run_portal_auth_healthcheck_tick(): alerts once on first break, does not
    re-alert inside 24h, re-alerts after 24h if still broken, and sends
    exactly one recovery Slack post when it clears.
  * PAT-988: portal_auth goes degraded whenever the alert channel cannot
    deliver, and a failed recovery send is never silently lost.
  * PAT-1010: the alert channel is Slack (SLACK_WEBHOOK_URL), not email —
    moved off OPS_ALERT_EMAIL because EMAIL_DRY_RUN=1 on prod-01 would have
    made an email-based channel report success while sending nothing.

Run with: pytest tests/test_pat837_portal_auth_healthcheck.py -v
"""

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._payload


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _configure(monkeypatch, live_aud="aud-live-123", expected_aud="aud-live-123"):
    monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "tok")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "acct")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "app")
    monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", expected_aud)
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    monkeypatch.setattr(
        dashboard.http, "get",
        lambda *a, **k: _FakeResp({"result": {"aud": live_aud}}, 200),
    )


def _mock_slack(monkeypatch, status_code=200, body="ok"):
    """Mock dashboard.http.post (the Slack webhook) and capture every posted
    payload. Returns the list of {"blocks": [...]} payloads posted, in order.

    `body` mirrors what Slack's incoming-webhook contract actually returns —
    HTTP 200 with a plain-text body of exactly "ok" on a real delivery
    (https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).
    Tests simulating a "200 but not really delivered" response (a
    misrouted/wrong-but-live URL answering with some other 200) should pass
    a different `body` — that is the PAT-988 P1 finding this file guards."""
    posts = []

    def fake_post(url, json=None, **k):
        posts.append(json)
        return _FakeResp(status_code=status_code, text=body)

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    return posts


def _subject(post):
    """The header block's plain_text — equivalent to the old email subject."""
    return post["blocks"][0]["text"]["text"]


def _text(post):
    """All mrkdwn/plain_text strings in a posted payload, joined, for substring checks."""
    return " ".join(
        block["text"]["text"]
        for block in post["blocks"]
        if "text" in block
    )


class TestCheckPortalAccessAud:
    def test_returns_none_when_unconfigured(self, monkeypatch):
        monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "")
        monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "acct")
        monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "app")
        monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", "aud")
        assert dashboard._check_portal_access_aud() is None

    def test_returns_none_when_expected_aud_unset(self, monkeypatch):
        monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "tok")
        monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "acct")
        monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "app")
        monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", "")
        assert dashboard._check_portal_access_aud() is None

    def test_returns_none_on_cf_api_error(self, monkeypatch):
        _configure(monkeypatch)
        monkeypatch.setattr(dashboard.http, "get", lambda *a, **k: _FakeResp({}, 500, "boom"))
        assert dashboard._check_portal_access_aud() is None

    def test_returns_none_on_network_failure(self, monkeypatch):
        _configure(monkeypatch)

        def _raise(*a, **k):
            raise ConnectionError("no route")
        monkeypatch.setattr(dashboard.http, "get", _raise)
        assert dashboard._check_portal_access_aud() is None

    def test_matching_aud_not_drifted(self, monkeypatch):
        _configure(monkeypatch, live_aud="same", expected_aud="same")
        drifted, detail = dashboard._check_portal_access_aud()
        assert drifted is False
        assert detail == ""

    def test_mismatched_aud_is_drifted(self, monkeypatch):
        _configure(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
        drifted, detail = dashboard._check_portal_access_aud()
        assert drifted is True
        assert "does not match" in detail


# ── PAT-1010: _send_portal_auth_alert posts to Slack ─────────────────────────


class TestSendPortalAuthAlert:
    def test_noop_when_slack_unconfigured(self, monkeypatch):
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
        calls = []
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: calls.append(a) or _FakeResp())
        sent = dashboard._send_portal_auth_alert("subject", "detail")
        assert sent is False
        assert calls == []  # no send attempted at all

    def test_posts_expected_shape(self, monkeypatch):
        # PAT-1635: block construction moved into the shared
        # _build_alert_blocks, which prepends its own severity-driven icon
        # to the title -- the caller no longer bakes an emoji into the
        # subject string itself, so this now checks the subject text is
        # present rather than an exact match on a caller-supplied emoji.
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
        posts = _mock_slack(monkeypatch, status_code=200)
        sent = dashboard._send_portal_auth_alert(
            "Portal auth broken: Cloudflare Access AUD drift on app.patched.im",
            "the detail text",
            severity="critical",
        )
        assert sent is True
        assert len(posts) == 1
        assert "blocks" in posts[0]
        assert "Portal auth broken: Cloudflare Access AUD drift on app.patched.im" in _subject(posts[0])
        assert "the detail text" in _text(posts[0])
        assert "RUNBOOK-portal-auth-healthcheck.md" in _text(posts[0])

    def test_non_200_is_treated_as_failed_delivery(self, monkeypatch):
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
        _mock_slack(monkeypatch, status_code=500)
        sent = dashboard._send_portal_auth_alert("subject", "detail")
        assert sent is False

    def test_200_with_wrong_body_is_not_treated_as_delivered(self, monkeypatch):
        """P1 finding: a syntactically valid but wrong webhook URL (a
        misrouted load balancer, a catch-all route, etc.) can answer with
        HTTP 200 without ever reaching Slack. Slack's own contract for an
        actually-delivered message is 200 + plain-text body "ok"; a 200
        with any other body must not be mistaken for delivery."""
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
        _mock_slack(monkeypatch, status_code=200, body="<html>Not Found</html>")
        sent = dashboard._send_portal_auth_alert("subject", "detail")
        assert sent is False

    def test_post_exception_is_treated_as_failed_delivery(self, monkeypatch):
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")

        def _raise(*a, **k):
            raise ConnectionError("no route")
        monkeypatch.setattr(dashboard.http, "post", _raise)
        sent = dashboard._send_portal_auth_alert("subject", "detail")
        assert sent is False

    def test_posts_to_configured_url_with_10s_timeout(self, monkeypatch):
        """Guard against a silent regression on the call itself — e.g. the
        webhook URL or timeout getting dropped/changed — which none of the
        other tests here would otherwise catch since they only inspect the
        posted JSON body."""
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
        calls = []

        def fake_post(url, json=None, **kwargs):
            calls.append({"url": url, "json": json, "kwargs": kwargs})
            return _FakeResp(status_code=200, text="ok")

        monkeypatch.setattr(dashboard.http, "post", fake_post)
        dashboard._send_portal_auth_alert("subject", "detail")

        assert len(calls) == 1
        assert calls[0]["url"] == "https://hooks.slack.test/fake"
        assert calls[0]["kwargs"].get("timeout") == 10


class TestPortalAuthHealthcheckTick:
    def test_noop_when_unconfigured(self, db, monkeypatch):
        monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "")
        posts = _mock_slack(monkeypatch)
        dashboard._run_portal_auth_healthcheck_tick(datetime.now(timezone.utc))
        assert posts == []

    def test_alerts_once_on_first_break(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="new", expected_aud="old")
        posts = _mock_slack(monkeypatch)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        assert len(posts) == 1
        assert "Portal auth broken" in _subject(posts[0])

    def test_does_not_realert_within_24h(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="new", expected_aud="old")
        posts = _mock_slack(monkeypatch)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=1))
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=23))
        assert len(posts) == 1

    def test_realerts_after_24h_if_still_broken(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="new", expected_aud="old")
        posts = _mock_slack(monkeypatch)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=25))
        assert len(posts) == 2

    def test_sends_exactly_one_recovery_post(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="new", expected_aud="old")
        posts = _mock_slack(monkeypatch)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)  # breaks -> alert #1
        # Recovery: live aud now matches expected
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **k: _FakeResp({"result": {"aud": "old"}}, 200),
        )
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=1))  # recovers -> alert #2
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=2))  # still ok -> no more alerts
        assert len(posts) == 2
        assert "recovered" in _subject(posts[1]).lower()

    def test_never_alerts_when_never_broken(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="same", expected_aud="same")
        posts = _mock_slack(monkeypatch)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=1))
        assert posts == []

    def test_outage_alert_non_200_retried_next_tick_not_throttled(self, db, monkeypatch):
        """A failed outage-alert post must not be mistaken for a delivered
        one: portal_auth_alerted_at must only advance on an actual 200, so
        the 24h dedup window doesn't start ticking on a send that never
        landed — the very next tick (even seconds later) must retry."""
        _configure(monkeypatch, live_aud="new", expected_aud="old")
        posts = _mock_slack(monkeypatch, status_code=500)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(minutes=1))
        assert len(posts) == 2  # both attempts fired — no false throttle
        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT value FROM kv WHERE key='portal_auth_alerted_at'"
            ).fetchone()
        assert row is None  # never successfully delivered, so never recorded

    def test_outage_alert_200_wrong_body_retried_next_tick_not_throttled(self, db, monkeypatch):
        """Same guarantee as the non-200 case above, but the failure mode is
        a 200 response whose body isn't Slack's "ok" (P1 finding) — e.g. a
        misrouted/wrong-but-live webhook URL. Must not be mistaken for a
        delivered alert, or the 24h throttle would start on a message
        nobody received."""
        _configure(monkeypatch, live_aud="new", expected_aud="old")
        posts = _mock_slack(monkeypatch, status_code=200, body="Not Found")
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(minutes=1))
        assert len(posts) == 2  # both attempts fired — no false throttle
        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT value FROM kv WHERE key='portal_auth_alerted_at'"
            ).fetchone()
        assert row is None  # never actually delivered, so never recorded


# ── PAT-988: portal_auth must go degraded when it cannot alert ──────────────
#
# _check_portal_access_aud() only knows about the AUD comparison; it has no
# idea whether SLACK_WEBHOOK_URL is configured. A healthy AUD reading with a
# dead alert channel is still a real problem (a future break would go
# unreported), so _run_portal_auth_healthcheck_tick must downgrade portal_auth
# to degraded whenever the channel is missing — whether or not drift was also
# detected — and must not let one fact's detail clobber the other's.


def _status(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, state, reason, evaluated_at FROM check_statuses WHERE name=?",
            (name,),
        ).fetchone()


class TestPortalAuthAlertChannelDegraded:
    def test_channel_unconfigured_no_drift_is_degraded(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="same", expected_aud="same")
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
        calls = []
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: calls.append(a) or _FakeResp())

        dashboard._run_portal_auth_healthcheck_tick(datetime.now(timezone.utc))

        assert calls == []  # no send attempted
        row = _status("portal_auth")
        assert row["state"] == "degraded"
        assert "SLACK_WEBHOOK_URL" in row["reason"]
        assert "alerts cannot be delivered" in row["reason"]

    def test_channel_unconfigured_with_drift_is_degraded_and_names_both_problems(
        self, db, monkeypatch
    ):
        _configure(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
        calls = []
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: calls.append(a) or _FakeResp())

        dashboard._run_portal_auth_healthcheck_tick(datetime.now(timezone.utc))

        assert calls == []  # no channel to send through
        row = _status("portal_auth")
        assert row["state"] == "degraded"
        # Both facts survive in the recorded detail — neither clobbers the other.
        assert "does not match" in row["reason"]  # the AUD drift fact
        assert "SLACK_WEBHOOK_URL" in row["reason"]  # the dead-channel fact
        assert "alerts cannot be delivered" in row["reason"]

    def test_channel_configured_no_drift_stays_ok(self, db, monkeypatch):
        _configure(monkeypatch, live_aud="same", expected_aud="same")
        posts = _mock_slack(monkeypatch)

        dashboard._run_portal_auth_healthcheck_tick(datetime.now(timezone.utc))

        assert posts == []  # no drift, nothing to alert about
        row = _status("portal_auth")
        assert row["state"] == "ok"


def _kv(key):
    with dashboard.get_db() as conn:
        return conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()


class TestPortalAuthRecoveryNotificationNotLost:
    """PAT-988 (Codex review finding, preserved under the PAT-1010 Slack
    move): the old code called _send_portal_auth_alert() for the recovery
    message, ignored its return value, unconditionally printed "recovery
    email sent", and advanced portal_auth_state to "ok" regardless. If the
    channel died (or its post failed) between the break-alert and the
    recovery, the recovery notification silently vanished forever —
    prev_state was already "ok" by the time the channel came back, so
    nothing ever retried it, and the log claimed success that never
    happened.

    _run_portal_auth_healthcheck_tick must track a still-owed recovery
    notification (kv.portal_auth_recovery_pending) independently of the AUD
    drift state (kv.portal_auth_state), so: (a) the AUD state itself stays
    accurate — a later genuinely-new break is never misclassified as a
    continuation of the old one — and (b) the pending recovery survives
    until it actually sends, visibly (portal_auth degraded), not silently.
    """

    def test_recovery_send_failure_via_unset_channel_is_not_lost_or_falsely_claimed(
        self, db, monkeypatch, capsys
    ):
        # 1. Break while the channel works: alerts once, state -> "broken".
        _configure(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
        posts = _mock_slack(monkeypatch)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        assert len(posts) == 1
        assert _kv("portal_auth_state")["value"] == "broken"

        # 2. Channel dies, then AUD recovers. The recovery send must fail
        # (no channel to send through) rather than being falsely reported.
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **k: _FakeResp({"result": {"aud": "old-aud-abc"}}, 200),
        )
        capsys.readouterr()  # clear captured output from tick 1
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=1))

        # No second post was actually sent...
        assert len(posts) == 1
        # ...and the log must not claim otherwise.
        out = capsys.readouterr().out
        assert "recovery Slack post sent" not in out
        # AUD state itself is still recorded accurately (not drifted) so a
        # future genuinely-new break isn't misclassified as a continuation
        # of this one under the 24h dedup window...
        assert _kv("portal_auth_state")["value"] == "ok"
        # ...but the obligation to notify is NOT dropped: it's tracked
        # separately and portal_auth is visibly degraded, not silently ok.
        assert _kv("portal_auth_recovery_pending") is not None
        row = _status("portal_auth")
        assert row["state"] == "degraded"
        assert "recovery notification" in row["reason"]
        assert "SLACK_WEBHOOK_URL" in row["reason"]

        # 3. Channel comes back. The next tick must actually deliver the
        # recovery notification the earlier failure owed — proving the
        # obligation genuinely survived rather than being silently dropped.
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=2))

        assert len(posts) == 2
        assert "recovered" in _subject(posts[1]).lower()
        assert _kv("portal_auth_recovery_pending") is None
        row = _status("portal_auth")
        assert row["state"] == "ok"

    def test_recovery_send_failure_via_non_200_is_not_lost_or_falsely_claimed(
        self, db, monkeypatch, capsys
    ):
        """Same obligation-survives guarantee, but the failure mode is a
        configured webhook that rejects the post (e.g. revoked/rate-limited)
        rather than an unset SLACK_WEBHOOK_URL — a non-200 must be treated
        exactly like "no channel" for delivery-tracking purposes."""
        # 1. Break while Slack works: alerts once, state -> "broken".
        _configure(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
        posts = _mock_slack(monkeypatch, status_code=200)
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        assert len(posts) == 1
        assert _kv("portal_auth_state")["value"] == "broken"

        # 2. AUD recovers, but Slack now rejects the post (non-200).
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **k: _FakeResp({"result": {"aud": "old-aud-abc"}}, 200),
        )
        _mock_slack(monkeypatch, status_code=503)
        capsys.readouterr()
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=1))

        out = capsys.readouterr().out
        assert "recovery Slack post sent" not in out
        assert _kv("portal_auth_state")["value"] == "ok"
        assert _kv("portal_auth_recovery_pending") is not None
        row = _status("portal_auth")
        assert row["state"] == "degraded"
        assert "recovery notification" in row["reason"]

        # 3. Slack starts accepting posts again — the owed recovery notice
        # must go out on the very next tick, not be dropped.
        posts2 = _mock_slack(monkeypatch, status_code=200)
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=2))

        assert len(posts2) == 1
        assert "recovered" in _subject(posts2[0]).lower()
        assert _kv("portal_auth_recovery_pending") is None
        row = _status("portal_auth")
        assert row["state"] == "ok"

    def test_recovery_send_failure_via_200_wrong_body_is_not_lost_or_falsely_claimed(
        self, db, monkeypatch, capsys
    ):
        """Same obligation-survives guarantee again, but the failure mode is
        the P1 finding specifically: a 200 response whose body isn't
        Slack's "ok" — e.g. a wrong-but-live webhook URL answering with its
        own success page. Proves the delivery check is on the body, not
        just the status code, for the recovery path too."""
        # 1. Break while Slack works: alerts once, state -> "broken".
        _configure(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
        posts = _mock_slack(monkeypatch, status_code=200, body="ok")
        now = datetime.now(timezone.utc)
        dashboard._run_portal_auth_healthcheck_tick(now)
        assert len(posts) == 1
        assert _kv("portal_auth_state")["value"] == "broken"

        # 2. AUD recovers, but the recovery post gets a 200 with the wrong body.
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **k: _FakeResp({"result": {"aud": "old-aud-abc"}}, 200),
        )
        _mock_slack(monkeypatch, status_code=200, body="Not Found")
        capsys.readouterr()
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=1))

        out = capsys.readouterr().out
        assert "recovery Slack post sent" not in out
        # AUD state itself is still recorded accurately...
        assert _kv("portal_auth_state")["value"] == "ok"
        # ...but the recovery obligation is NOT dropped just because the
        # response happened to carry a 200.
        assert _kv("portal_auth_recovery_pending") is not None
        row = _status("portal_auth")
        assert row["state"] == "degraded"
        assert "recovery notification" in row["reason"]

        # 3. Slack starts genuinely confirming delivery again — the owed
        # recovery notice must go out on the very next tick, not be dropped.
        posts2 = _mock_slack(monkeypatch, status_code=200, body="ok")
        dashboard._run_portal_auth_healthcheck_tick(now + timedelta(hours=2))

        assert len(posts2) == 1
        assert "recovered" in _subject(posts2[0]).lower()
        assert _kv("portal_auth_recovery_pending") is None
        row = _status("portal_auth")
        assert row["state"] == "ok"
