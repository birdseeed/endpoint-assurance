"""
PAT-1171: surface degraded check_statuses rows to a human.

Two layers:
  1. A tile: GET /api/ops/data now returns a `checks_attention` array of
     every check_statuses row currently degraded or unconfigured, generic
     across every check name (not hardcoded to portal_auth/deploy_drift).
  2. A Slack alert, via the already-confirmed-delivery helper
     (_post_slack_blocks_confirmed), fired only on the transition INTO
     degraded, with a recovery notice when a check clears back to ok.
     Idempotency lives in check_status_alerts_sent, keyed by check `name`,
     mirroring health_alerts_sent's last_state + alert_delivered shape
     (PAT-678/PAT-1011): a persistently-degraded check does not re-alert
     every cycle, and an alert Slack never confirmed delivered is retried.

Covers the three ticket-mandated scenarios plus the generic-coverage and
retry-on-undelivered-alert cases those scenarios' pattern already commits
this codebase to (see PAT-1011).

Run with: pytest tests/test_pat1171_check_status_alerts.py -v
"""

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
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


@pytest.fixture
def client(db, monkeypatch):
    # Isolate /api/ops/data from every data source it pulls from besides
    # check_statuses -- none of that is under test here.
    def _no_network(url, timeout=None, verify=None):
        raise ConnectionError("network disabled in test")

    monkeypatch.setattr(dashboard.http, "get", _no_network)
    monkeypatch.setattr(dashboard, "_ops_cert_expiry", lambda hostname, port=443: None)
    monkeypatch.setattr(dashboard, "_ops_get_systemctl_prop", lambda unit, *props: {})

    with TestClient(dashboard.app) as value:
        yield value


def _configure_slack(monkeypatch, status_code=200, text="ok"):
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    posts = []

    def fake_post(url, json=None, **kwargs):
        posts.append(json)
        return _FakeResp(status_code=status_code, text=text)

    monkeypatch.setattr(dashboard.http, "post", fake_post)
    return posts


def _alert_row(name):
    with dashboard.get_db() as conn:
        return conn.execute(
            "SELECT name, last_state, alert_delivered FROM check_status_alerts_sent WHERE name=?",
            (name,),
        ).fetchone()


def _blocks_text(posts):
    return " ".join(str(p) for p in posts)


# ── Ticket-mandated scenarios ────────────────────────────────────────────


def test_ok_to_degraded_alerts_exactly_once(db, monkeypatch):
    posts = _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._record_check_status("portal_auth", "ok", "", now)
    assert len(posts) == 0  # no alert on an ok reading

    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", now)

    assert len(posts) == 1
    assert "degraded" in _blocks_text(posts)
    assert "portal_auth" in _blocks_text(posts)

    row = _alert_row("portal_auth")
    assert row["last_state"] == "degraded"
    assert row["alert_delivered"] == 1


def test_degraded_to_degraded_same_state_next_cycle_does_not_duplicate(db, monkeypatch):
    posts = _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._record_check_status("portal_auth", "ok", "", now)
    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", now)
    assert len(posts) == 1

    # Next cycle, still degraded -- same underlying problem.
    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", now)
    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", now)

    assert len(posts) == 1, "a persistently-degraded check must not re-alert every cycle"


def test_degraded_to_ok_fires_recovery_exactly_once(db, monkeypatch):
    posts = _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._record_check_status("portal_auth", "ok", "", now)
    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", now)
    assert len(posts) == 1

    dashboard._record_check_status("portal_auth", "ok", "", now)

    assert len(posts) == 2
    assert "recovered" in _blocks_text(posts).lower()

    row = _alert_row("portal_auth")
    assert row["last_state"] == "ok"
    assert row["alert_delivered"] == 1

    # And staying ok afterwards does not re-announce recovery.
    dashboard._record_check_status("portal_auth", "ok", "", now)
    assert len(posts) == 2


# ── Generic coverage -- not hardcoded to any one check name ─────────────


def test_covers_arbitrary_check_names_generically(db, monkeypatch):
    """The alert path must not special-case portal_auth/deploy_drift -- any
    row ever written via _record_check_status gets the same treatment."""
    posts = _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)

    for name in ("some_future_check", "another_brand_new_thing"):
        dashboard._record_check_status(name, "ok", "", now)
        dashboard._record_check_status(name, "degraded", "widget on fire", now)

    assert len(posts) == 2
    text = _blocks_text(posts)
    assert "some_future_check" in text
    assert "another_brand_new_thing" in text


def test_first_ever_observation_as_degraded_still_alerts(db, monkeypatch):
    """No prior 'ok' baseline is required -- a check degraded on its very
    first report must still reach a human, not wait for a first-ok row."""
    posts = _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._record_check_status("brand_new_check", "degraded", "never configured", now)

    assert len(posts) == 1


def test_unconfigured_does_not_alert_and_does_not_forgive_pending_degraded(db, monkeypatch):
    posts = _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._record_check_status("rbac_operators", "ok", "", now)
    dashboard._record_check_status("rbac_operators", "unconfigured", "not set up yet", now)
    assert len(posts) == 0

    dashboard._record_check_status("rbac_operators", "degraded", "broken", now)
    assert len(posts) == 1, "transition into degraded from unconfigured must still alert"


# ── Retry-on-undelivered-alert (same PAT-1011 shape as health_alerts_sent) ─


def test_undelivered_degraded_alert_is_retried_next_cycle(db, monkeypatch):
    now = datetime.now(timezone.utc)
    dashboard._record_check_status("deploy_drift", "ok", "", now)

    # First attempt: Slack answers 200 but not its own "ok" body -- not
    # confirmed delivered.
    posts = _configure_slack(monkeypatch, status_code=200, text="Not Found")
    dashboard._record_check_status("deploy_drift", "degraded", "SHA mismatch", now)
    assert len(posts) == 1

    row = _alert_row("deploy_drift")
    assert row["last_state"] == "degraded"
    assert row["alert_delivered"] == 0

    # Next cycle, still degraded -- must retry since the last attempt was
    # never confirmed delivered.
    posts2 = _configure_slack(monkeypatch, status_code=200, text="ok")
    dashboard._record_check_status("deploy_drift", "degraded", "SHA mismatch", now)
    assert len(posts2) == 1, "an unconfirmed degraded alert must retry, not stay silent forever"

    row = _alert_row("deploy_drift")
    assert row["alert_delivered"] == 1

    # And now that it IS confirmed delivered, a further degraded cycle does
    # not re-post.
    posts3 = _configure_slack(monkeypatch, status_code=200, text="ok")
    dashboard._record_check_status("deploy_drift", "degraded", "SHA mismatch", now)
    assert len(posts3) == 0


def test_undelivered_recovery_alert_is_retried_next_ok_cycle(db, monkeypatch):
    now = datetime.now(timezone.utc)
    dashboard._record_check_status("deploy_drift", "ok", "", now)
    _configure_slack(monkeypatch, status_code=200, text="ok")
    dashboard._record_check_status("deploy_drift", "degraded", "SHA mismatch", now)

    # Recovery attempt fails to confirm delivery.
    posts = _configure_slack(monkeypatch, status_code=500, text="")
    dashboard._record_check_status("deploy_drift", "ok", "", now)
    assert len(posts) == 1

    row = _alert_row("deploy_drift")
    assert row["last_state"] == "degraded", (
        "an unconfirmed recovery alert must keep last_state as degraded so "
        "the next ok reading retries it"
    )
    assert row["alert_delivered"] == 0

    posts2 = _configure_slack(monkeypatch, status_code=200, text="ok")
    dashboard._record_check_status("deploy_drift", "ok", "", now)
    assert len(posts2) == 1, "an unconfirmed recovery alert must retry on the next ok reading"

    row = _alert_row("deploy_drift")
    assert row["last_state"] == "ok"
    assert row["alert_delivered"] == 1


# ── Tile: GET /api/ops/data checks_attention ─────────────────────────────


def test_checks_attention_lists_non_ok_rows_generically(client, monkeypatch):
    now = datetime.now(timezone.utc)
    dashboard._record_check_status("portal_auth", "degraded", "Cloudflare API returned 500", now)
    dashboard._record_check_status("some_other_check", "unconfigured", "missing config", now)
    dashboard._record_check_status("healthy_check", "ok", "", now)

    response = client.get("/api/ops/data", headers=BEARER)
    assert response.status_code == 200
    body = response.json()
    assert "checks_attention" in body

    names = {c["name"] for c in body["checks_attention"]}
    assert names == {"portal_auth", "some_other_check"}
    assert "healthy_check" not in names

    by_name = {c["name"]: c for c in body["checks_attention"]}
    assert by_name["portal_auth"]["state"] == "degraded"
    assert by_name["portal_auth"]["reason"] == "Cloudflare API returned 500"
    assert by_name["some_other_check"]["state"] == "unconfigured"


def test_checks_attention_empty_when_all_ok(client):
    now = datetime.now(timezone.utc)
    dashboard._record_check_status("portal_auth", "ok", "", now)

    response = client.get("/api/ops/data", headers=BEARER)
    assert response.status_code == 200
    assert response.json()["checks_attention"] == []


def test_checks_attention_reflects_recovery(client, monkeypatch):
    _configure_slack(monkeypatch)
    now = datetime.now(timezone.utc)
    dashboard._record_check_status("portal_auth", "ok", "", now)
    dashboard._record_check_status("portal_auth", "degraded", "broken", now)

    response = client.get("/api/ops/data", headers=BEARER)
    assert [c["name"] for c in response.json()["checks_attention"]] == ["portal_auth"]

    dashboard._record_check_status("portal_auth", "ok", "", now)

    response = client.get("/api/ops/data", headers=BEARER)
    assert response.json()["checks_attention"] == []
