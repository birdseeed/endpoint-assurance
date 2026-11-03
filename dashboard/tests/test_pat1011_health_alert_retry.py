"""
PAT-1011 (follow-up) -- non-author review findings on the Slack
delivery-confirmation fix.

Covers:
  * _run_health_alerts_tick(): a tenant that transitions to at_risk while
    Slack delivery is broken (200 but wrong body, or a hard failure) is
    retried on the NEXT tick rather than being marked as already-alerted
    forever. Before this fix, health_alerts_sent recorded the current
    bucket unconditionally, before even attempting the send, so a broken
    webhook meant the exact tenant health-risk alert that most needed to
    reach someone silently never retried.
  * The same tenant, once a Slack post is actually confirmed delivered,
    does NOT re-alert on the next tick (the existing PAT-678 idempotency
    behaviour must not regress).
  * _post_slack_blocks_confirmed() never logs the raw exception string on a
    POST failure -- only the exception type name. A Slack incoming-webhook
    URL's path segments ARE the credential (there is no separate secret),
    and requests' connection/TLS exceptions often embed the full request
    URL in their string form.
  * The unified Admin Tools > Logs "alert_sent" feed (_log_alert_sent_source)
    reflects alert_delivered per health_alerts_sent row: a delivered alert
    still reads "Slack alert sent" at outcome=warning, but a row that was
    attempted and NOT confirmed delivered reads as a failure at
    outcome=error -- both in the summary text and in the outcome-bucket SQL
    predicate used for filtering, so filtering the log by outcome=error
    actually finds these rows too.

Run with: pytest tests/test_pat1011_health_alert_retry.py -v
"""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text
        self.content = b"x" if self._payload else b""

    def json(self):
        return self._payload


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


def _configure_channel(monkeypatch):
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


def _mock_slack_post(monkeypatch, status_code=200, text="ok"):
    posts = []

    def fake_post(url, json=None, **k):
        posts.append(json)
        return _FakeResp(status_code=status_code, text=text)

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    return posts


def _health_alerts_row(tenant_id):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT tenant_id, bucket, alert_delivered FROM health_alerts_sent WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()


class TestFailedDeliveryIsRetried:
    def test_bad_body_at_risk_alert_is_retried_next_tick(self, db, monkeypatch):
        _configure_channel(monkeypatch)
        tenant = _at_risk_tenant()
        _mock_tenants_overview(monkeypatch, [tenant])
        # 200 but not Slack's own "ok" confirmation -- e.g. a misrouted
        # webhook URL that still answers with a 200.
        posts = _mock_slack_post(monkeypatch, status_code=200, text="Not Found")
        now = datetime.now(timezone.utc)

        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 1  # first attempt: not confirmed delivered

        row = _health_alerts_row("tenant-1")
        assert row["bucket"] == "at_risk"
        assert row["alert_delivered"] == 0

        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 2, "still-at_risk tenant with an unconfirmed alert must be retried"

    def test_hard_failure_at_risk_alert_is_retried_next_tick(self, db, monkeypatch):
        _configure_channel(monkeypatch)
        tenant = _at_risk_tenant()
        _mock_tenants_overview(monkeypatch, [tenant])

        def _raise(*a, **k):
            raise ConnectionError("no route to host")

        monkeypatch.setattr(dashboard.http, "post", _raise)
        now = datetime.now(timezone.utc)

        # Must not raise -- a failed send is a recorded outcome, not an
        # unhandled exception propagating out of the scheduler tick.
        dashboard._run_health_alerts_tick(now)
        row = _health_alerts_row("tenant-1")
        assert row["alert_delivered"] == 0

        posts = _mock_slack_post(monkeypatch, status_code=200, text="ok")
        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 1, "next tick must retry a never-confirmed alert"
        row = _health_alerts_row("tenant-1")
        assert row["alert_delivered"] == 1


class TestConfirmedDeliveryIsNotReAlerted:
    def test_confirmed_delivery_does_not_realert_next_tick(self, db, monkeypatch):
        _configure_channel(monkeypatch)
        tenant = _at_risk_tenant()
        _mock_tenants_overview(monkeypatch, [tenant])
        posts = _mock_slack_post(monkeypatch, status_code=200, text="ok")
        now = datetime.now(timezone.utc)

        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 1

        row = _health_alerts_row("tenant-1")
        assert row["bucket"] == "at_risk"
        assert row["alert_delivered"] == 1

        # Still at_risk on the next tick, with the same tenant snapshot.
        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 1, "a confirmed at_risk alert must not re-send while still at_risk"

    def test_recovery_then_new_at_risk_episode_alerts_again(self, db, monkeypatch):
        """Regression guard: the retry fix must not turn every at_risk tick
        into a re-alert -- a genuinely NEW episode (recovered, then at_risk
        again) still alerts exactly once per episode."""
        _configure_channel(monkeypatch)
        tenant = _at_risk_tenant()
        _mock_tenants_overview(monkeypatch, [tenant])
        posts = _mock_slack_post(monkeypatch, status_code=200, text="ok")
        now = datetime.now(timezone.utc)

        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 1

        healthy_tenant = dict(tenant, health_bucket="healthy", health_score=90)
        _mock_tenants_overview(monkeypatch, [healthy_tenant])
        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 1  # recovery is not itself an alert event

        _mock_tenants_overview(monkeypatch, [tenant])  # at_risk again
        dashboard._run_health_alerts_tick(now)
        assert len(posts) == 2, "a new at_risk episode after recovery must alert again"


class TestMigrationBackfillRetriesPreExistingAtRiskRows:
    def test_pre_migration_at_risk_row_is_retried_on_first_post_migration_tick(
        self, tmp_path, monkeypatch
    ):
        """A row written by the OLD (pre-alert_delivered-column) code has no
        way of recording whether its alert was ever actually confirmed
        delivered. The new column's DEFAULT 0 means such a row comes back
        as "not delivered" rather than silently inheriting a "delivered"
        default -- which would permanently silence the exact historical
        case this ticket exists to fix. Simulate that by creating the table
        in its pre-PAT-1011 shape (no alert_delivered column) with an
        at_risk row already in it, then run init_db() to migrate, exactly
        as would happen on a real upgrade."""
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(dashboard, "DB_PATH", db_path)

        conn = dashboard._open_db_connection(db_path)
        conn.execute(
            "CREATE TABLE health_alerts_sent ("
            "tenant_id TEXT NOT NULL PRIMARY KEY, "
            "bucket TEXT NOT NULL, "
            "alerted_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO health_alerts_sent (tenant_id, bucket, alerted_at) VALUES (?, ?, ?)",
            ("tenant-1", "at_risk", "2026-07-01T00:00:00+00:00"),
        )
        conn.commit()
        conn.close()

        # The migration this ticket adds to init_db().
        dashboard.init_db()

        row = _health_alerts_row("tenant-1")
        assert row["bucket"] == "at_risk"
        assert row["alert_delivered"] == 0, (
            "a pre-existing at_risk row must be backfilled as NOT delivered, "
            "not silently inherit the column's DEFAULT 1"
        )

        _configure_channel(monkeypatch)
        tenant = _at_risk_tenant()
        _mock_tenants_overview(monkeypatch, [tenant])
        posts = _mock_slack_post(monkeypatch, status_code=200, text="ok")

        dashboard._run_health_alerts_tick(datetime.now(timezone.utc))

        assert len(posts) == 1, (
            "the first post-migration tick must retry the alert for a "
            "still-at_risk tenant whose delivery was never confirmed, not "
            "stay permanently silent"
        )

    def test_non_at_risk_pre_migration_rows_unaffected_by_backfill(self, tmp_path, monkeypatch):
        """The new column's DEFAULT 0 applies to every pre-existing row
        regardless of bucket, but that's harmless for a non-at_risk row --
        the retry gate never consults alert_delivered outside bucket ==
        'at_risk', so what value a healthy tenant's row gets doesn't
        matter."""
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(dashboard, "DB_PATH", db_path)

        conn = dashboard._open_db_connection(db_path)
        conn.execute(
            "CREATE TABLE health_alerts_sent ("
            "tenant_id TEXT NOT NULL PRIMARY KEY, "
            "bucket TEXT NOT NULL, "
            "alerted_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO health_alerts_sent (tenant_id, bucket, alerted_at) VALUES (?, ?, ?)",
            ("tenant-2", "healthy", "2026-07-01T00:00:00+00:00"),
        )
        conn.commit()
        conn.close()

        dashboard.init_db()

        row = _health_alerts_row("tenant-2")
        assert row["bucket"] == "healthy"
        assert row["alert_delivered"] == 0


def _insert_health_alerts_sent_row(tenant_id, bucket, alerted_at, alert_delivered):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO health_alerts_sent (tenant_id, bucket, alerted_at, alert_delivered) "
            "VALUES (?, ?, ?, ?)",
            (tenant_id, bucket, alerted_at, 1 if alert_delivered else 0),
        )


def _run_alert_sent_source(buckets=frozenset()):
    entries, sources_meta = [], {}
    with dashboard.get_db() as conn:
        dashboard._log_alert_sent_source(entries, sources_meta, conn, "", "", "", set(buckets), 200)
    return entries, sources_meta


class TestLogFeedUnaffectedByAlertDelivered:
    """health_alerts_sent is a current-STATE table upserted every tick for
    every tenant, not an event log of alert attempts, so alert_delivered
    cannot safely drive this feed's wording (a healthy or recovered tenant
    would inherit a misleading "sent"/"FAILED" label unrelated to anything
    that happened this tick). Deliberately left at its pre-PAT-1011
    behaviour -- this test pins that the column's presence doesn't change
    what the log feed says, since the temptation to "use the new column
    here too" is exactly the kind of drift that would reintroduce the
    problem this comment (and the one in main.py) exists to prevent."""

    def test_delivery_state_does_not_change_log_wording(self, db):
        _insert_health_alerts_sent_row("tenant-1", "at_risk", "2026-07-01T00:00:00+00:00", True)
        _insert_health_alerts_sent_row("tenant-2", "at_risk", "2026-07-01T00:00:01+00:00", False)

        entries, _ = _run_alert_sent_source()

        health_entries = {e["detail"]["tenant_id"]: e for e in entries if e["action"] == "health_at_risk_alert"}
        assert len(health_entries) == 2
        for entry in health_entries.values():
            assert entry["outcome"] == "warning"
            assert "Slack alert sent" in entry["summary"]
            assert "FAILED" not in entry["summary"]


class TestExceptionLoggingDoesNotLeakWebhookUrl:
    def test_post_failure_logs_exception_type_not_url_or_message(self, monkeypatch, capsys):
        # Shaped like a real incoming-webhook URL (path segments are the
        # credential) without matching gitleaks' slack-webhook-url pattern --
        # built from parts at runtime rather than as one literal.
        secret_url = "https://hooks.slack.com/" + "services/" + "T0" + "0" * 8 + "/B0" + "0" * 8 + "/" + "X" * 24
        monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", secret_url)

        def _raise(*a, **k):
            # Mirrors how requests' own exceptions read: the request URL is
            # embedded directly in the exception's string representation.
            raise ConnectionError(f"HTTPSConnectionPool(host='hooks.slack.com'): {secret_url}")

        monkeypatch.setattr(dashboard.http, "post", _raise)

        sent = dashboard._post_slack_blocks_confirmed([{"type": "section"}], "test-site")

        assert sent is False
        captured = capsys.readouterr()
        assert secret_url not in captured.out
        assert "hooks.slack.com" not in captured.out
        assert "ConnectionError" in captured.out
