"""
PAT-1045: three scheduler ticks compute a degraded state, record it under
their own named check, then return None -- so tick_<label> read "ok" while
the named check read "degraded" for the identical run. PAT-1018 fixed this
shape for _run_health_alerts_tick (see test_pat1018_tick_degraded_signal.py);
this ticket applies the same fix, following that pattern exactly, to:

  * _run_portal_auth_healthcheck_tick / portal_auth
  * _run_rbac_operators_check_tick / rbac_operators
  * _run_email_delivery_check_tick / email_delivery

Policy (decided under PAT-1018, applied here unchanged): "unconfigured" does
NOT degrade the tick -- an unset channel/credential is a standing
configuration gap reported by the named check itself, not a tick failure.
Only "degraded" states produce a returned reason.

For each of the three: force the degraded condition, run the tick (through
_run_tick, the way scheduler_loop actually calls it), and confirm tick_<label>
and the named check agree. Then confirm a healthy run still records both ok.
portal_auth and email_delivery also get an "unconfigured" case: named check
unconfigured, tick ok.

portal_auth gets one more case beyond the brief's headline drift/channel/
recovery combinations: _check_portal_access_aud() also records portal_auth
"degraded" (not "unconfigured") when a required-config check passes but the
live Cloudflare API call itself fails/errors, and it returns None for that
case exactly like the missing-config case. Before this fix that collapsed to
the same "return None" tick outcome as unconfigured; this suite proves the
tick now tells the two apart.

Run with: pytest tests/test_pat1045_tick_degraded_agreement.py -v
"""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text

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


# ── rbac_operators ───────────────────────────────────────────────────────────


def test_rbac_operators_degraded_path_tick_and_check_agree(db, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset())
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "rbac-operators", lambda: dashboard._run_rbac_operators_check_tick(now), now
    )

    tick_row = _status("tick_rbac_operators")
    check_row = _status("rbac_operators")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    assert tick_row["reason"] == check_row["reason"]
    assert "no session owners configured" in tick_row["reason"]


def test_rbac_operators_healthy_path_tick_and_check_agree_ok(db, monkeypatch):
    monkeypatch.setattr(
        dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@example.com"})
    )
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "rbac-operators", lambda: dashboard._run_rbac_operators_check_tick(now), now
    )

    tick_row = _status("tick_rbac_operators")
    check_row = _status("rbac_operators")
    assert tick_row["state"] == "ok"
    assert check_row["state"] == "ok"


# ── email_delivery ───────────────────────────────────────────────────────────


def _clear_email_config(monkeypatch):
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "")


def test_email_delivery_degraded_path_tick_and_check_agree(db, monkeypatch):
    """EMAIL_DRY_RUN=1 is email_delivery_check()'s degraded case."""
    _clear_email_config(monkeypatch)
    monkeypatch.setattr(shared, "EMAIL_DRY_RUN", True)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "email-delivery-check",
        lambda: dashboard._run_email_delivery_check_tick(now),
        now,
    )

    tick_row = _status("tick_email_delivery_check")
    check_row = _status("email_delivery")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    assert tick_row["reason"] == check_row["reason"]
    assert "EMAIL_DRY_RUN" in tick_row["reason"]


def test_email_delivery_healthy_path_tick_and_check_agree_ok(db, monkeypatch):
    _clear_email_config(monkeypatch)
    monkeypatch.setattr(shared, "GRAPH_MAIL_TENANT_ID", "tenant")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_ID", "client")
    monkeypatch.setattr(shared, "GRAPH_MAIL_CLIENT_SECRET", "secret")
    monkeypatch.setattr(shared, "_graph_mail_token", lambda: "token")
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "email-delivery-check",
        lambda: dashboard._run_email_delivery_check_tick(now),
        now,
    )

    tick_row = _status("tick_email_delivery_check")
    check_row = _status("email_delivery")
    assert tick_row["state"] == "ok"
    assert check_row["state"] == "ok"


def test_email_delivery_unconfigured_does_not_degrade_tick(db, monkeypatch):
    """Policy: unconfigured is a standing configuration gap, not a tick
    failure -- named check unconfigured, tick stays ok."""
    _clear_email_config(monkeypatch)
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "email-delivery-check",
        lambda: dashboard._run_email_delivery_check_tick(now),
        now,
    )

    tick_row = _status("tick_email_delivery_check")
    check_row = _status("email_delivery")
    assert check_row["state"] == "unconfigured"
    assert tick_row["state"] == "ok"


# ── portal_auth ──────────────────────────────────────────────────────────────


def _configure_portal_auth(monkeypatch, live_aud="aud-live-123", expected_aud="aud-live-123"):
    monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "tok")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "acct")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "app")
    monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", expected_aud)
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "https://hooks.slack.test/fake")
    monkeypatch.setattr(
        dashboard.http, "get",
        lambda *a, **k: _FakeResp({"result": {"aud": live_aud}}, 200),
    )


def test_portal_auth_drift_only_tick_and_check_agree(db, monkeypatch):
    """Drift detected, channel fine, no recovery obligation -- the case
    called out in the brief where _record_check_status is never called by
    the tick's own final block (drift is recorded by
    _check_portal_access_aud itself), so the tick must return that same
    detail rather than falling through to None."""
    _configure_portal_auth(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
    now = datetime.now(timezone.utc)

    def fake_post(url, json=None, **k):
        return _FakeResp(status_code=200, text="ok")
    monkeypatch.setattr(dashboard.http, "post", fake_post)

    dashboard._run_tick(
        "portal-auth-check",
        lambda: dashboard._run_portal_auth_healthcheck_tick(now),
        now,
    )

    tick_row = _status("tick_portal_auth_check")
    check_row = _status("portal_auth")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    # The AUD-drift detail text is longer than 200 chars, so _run_tick's
    # pre-existing truncation (_truncate_check_reason, same rule an
    # exception's text already gets) applies to the tick_* row but not to
    # portal_auth's own row -- that is truncation, not disagreement, so
    # compare through the same truncation the tick applied.
    assert tick_row["reason"] == dashboard._truncate_check_reason(check_row["reason"])
    assert "does not match" in tick_row["reason"]


def test_portal_auth_drift_plus_missing_channel_tick_and_check_agree(db, monkeypatch):
    """Drift AND a missing alert channel -- the combined-detail path through
    the tick's own final _record_check_status block."""
    _configure_portal_auth(monkeypatch, live_aud="new-aud-xyz", expected_aud="old-aud-abc")
    monkeypatch.setattr(dashboard, "SLACK_WEBHOOK_URL", "")
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "portal-auth-check",
        lambda: dashboard._run_portal_auth_healthcheck_tick(now),
        now,
    )

    tick_row = _status("tick_portal_auth_check")
    check_row = _status("portal_auth")
    assert tick_row["state"] == "degraded"
    assert check_row["state"] == "degraded"
    assert tick_row["reason"] == dashboard._truncate_check_reason(check_row["reason"])
    assert "does not match" in tick_row["reason"]
    # Both facts survive in the full (untruncated) portal_auth reason -- the
    # 200-char truncation is _run_tick's own, applied only to the tick_* row.
    assert "does not match" in check_row["reason"]
    assert "SLACK_WEBHOOK_URL" in check_row["reason"]


def test_portal_auth_healthy_path_tick_and_check_agree_ok(db, monkeypatch):
    _configure_portal_auth(monkeypatch, live_aud="same", expected_aud="same")
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "portal-auth-check",
        lambda: dashboard._run_portal_auth_healthcheck_tick(now),
        now,
    )

    tick_row = _status("tick_portal_auth_check")
    check_row = _status("portal_auth")
    assert tick_row["state"] == "ok"
    assert check_row["state"] == "ok"


def test_portal_auth_unconfigured_does_not_degrade_tick(db, monkeypatch):
    """Policy: missing required config is a standing configuration gap, not
    a tick failure -- named check unconfigured, tick stays ok."""
    monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "")
    monkeypatch.setattr(dashboard, "PORTAL_ACCESS_AUD_EXPECTED", "")
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "portal-auth-check",
        lambda: dashboard._run_portal_auth_healthcheck_tick(now),
        now,
    )

    tick_row = _status("tick_portal_auth_check")
    check_row = _status("portal_auth")
    assert check_row["state"] == "unconfigured"
    assert tick_row["state"] == "ok"


@pytest.mark.usefixtures("network_down")
def test_portal_auth_cloudflare_api_error_is_degraded_not_unconfigured(db, monkeypatch):
    """Beyond the brief's headline cases: _check_portal_access_aud() returns
    None both for missing config (unconfigured) and for a live Cloudflare API
    error (degraded) -- config is present here, but the API call itself
    fails, so this must NOT be treated like the unconfigured case."""
    _configure_portal_auth(monkeypatch)
    monkeypatch.setattr(
        dashboard.http, "get",
        lambda *a, **k: _FakeResp({}, 500, "boom"),
    )
    now = datetime.now(timezone.utc)

    dashboard._run_tick(
        "portal-auth-check",
        lambda: dashboard._run_portal_auth_healthcheck_tick(now),
        now,
    )

    tick_row = _status("tick_portal_auth_check")
    check_row = _status("portal_auth")
    assert check_row["state"] == "degraded"
    assert tick_row["state"] == "degraded"
    assert tick_row["reason"] == check_row["reason"]
    assert "Cloudflare API returned 500" in tick_row["reason"]
