"""
PAT-815 / PAT-816 / PAT-818 — silently swallowed failure bugs found by a
bug-hunt sweep of main.py (bundled with PAT-817, covered separately in
tests/test_trial_expiry.py).

Covers:
  * PAT-815 — _run_cert_digest_tick and _run_report_tick must NOT record a
    digest/report as delivered when _send_email() actually failed. (The
    historic provider-selection guard made a False `ok` irrelevant.)
  * PAT-816 — _check_tenant_report_schedules must not write the
    report_schedule_sends idempotency row for a period unless EVERY resolved
    recipient's send succeeded — a partial failure must not permanently skip
    that period for the recipients who failed.
  * PAT-818 — admin_account_post must surface an upstream agent-config PUT
    failure as a non-200 JSON error response, not swallow it behind
    {"ok": True} while leaving the local tier/version stale.

Run with: pytest tests/test_pat815_816_818_silent_failures.py -v
"""

import os
import sys
import uuid
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


class _FakeResp:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.content = b"x"
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


# ══════════════════════════════════════════════════════════════════════════
# PAT-815 — cert digest tick
# ══════════════════════════════════════════════════════════════════════════

def _seed_cert_client(tenant_id="t-cert", recipient="ops@acme.test"):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO clients (id, company, tenant_id, "
            "created_at, cert_digest_enabled, cert_digest_recipient, cert_digest_severity, "
            "cert_digest_frequency, last_cert_digest_sent_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("id-cert", "Acme", tenant_id,
             datetime.now(timezone.utc).isoformat(), 1, recipient,
             "expired_plus_critical", "daily", None),
        )


class TestCertDigestTickHonoursSendFailure:
    def test_send_failure_does_not_mark_delivered(self, db, monkeypatch):
        _seed_cert_client()
        now = datetime.now(timezone.utc)
        expired_cert = {
            "device_id": "d1", "subject_cn": "x", "issuer_cn": "",
            "not_after": (now - timedelta(days=2)).isoformat(),
            "ext_key_usage": [], "basic_constraints_ca": False, "is_self_signed": False,
        }

        def fake_get(url, *a, **k):
            if url.endswith("/certs"):
                return _FakeResp([expired_cert])
            return _FakeResp({})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        # Simulate a Graph token failure / throttle: _send_email returns False.
        monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: False)

        dashboard._run_cert_digest_tick(now)

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT last_cert_digest_sent_at FROM clients WHERE tenant_id='t-cert'"
            ).fetchone()
        assert row["last_cert_digest_sent_at"] is None, \
            "a failed send must not be recorded as delivered"

    def test_send_success_marks_delivered(self, db, monkeypatch):
        _seed_cert_client()
        now = datetime.now(timezone.utc)
        expired_cert = {
            "device_id": "d1", "subject_cn": "x", "issuer_cn": "",
            "not_after": (now - timedelta(days=2)).isoformat(),
            "ext_key_usage": [], "basic_constraints_ca": False, "is_self_signed": False,
        }

        def fake_get(url, *a, **k):
            if url.endswith("/certs"):
                return _FakeResp([expired_cert])
            return _FakeResp({})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)

        dashboard._run_cert_digest_tick(now)

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT last_cert_digest_sent_at FROM clients WHERE tenant_id='t-cert'"
            ).fetchone()
        assert row["last_cert_digest_sent_at"] is not None


# ══════════════════════════════════════════════════════════════════════════
# PAT-815 — scheduled report tick
# ══════════════════════════════════════════════════════════════════════════

def _seed_report_sub(tenant_id="t-rep"):
    with dashboard.get_db() as conn:
        conn.execute(
            "INSERT INTO clients (id, company, tenant_id, "
            "created_at, primary_contact_email) VALUES (?,?,?,?,?)",
            ("id-rep", "Acme", tenant_id,
             datetime.now(timezone.utc).isoformat(), "primary@acme.test"),
        )
        conn.execute(
            "INSERT INTO report_subscriptions (tenant_id, report_type, enabled, frequency, "
            "recipient, last_sent_at) VALUES (?,?,?,?,?,?)",
            (tenant_id, "executive-summary", 1, "monthly", None, None),
        )


class TestReportTickHonoursSendFailure:
    def test_send_failure_does_not_mark_delivered(self, db, monkeypatch):
        _seed_report_sub()
        now = datetime.now(timezone.utc)

        def fake_get(url, *a, **k):
            r = MagicMock()
            r.status_code = 200
            r.content = b"%PDF-fake"
            return r

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: False)

        dashboard._run_report_tick(now)

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT last_sent_at FROM report_subscriptions "
                "WHERE tenant_id='t-rep' AND report_type='executive-summary'"
            ).fetchone()
        assert row["last_sent_at"] is None, \
            "a failed send must not be recorded as delivered — must retry next tick"


# ══════════════════════════════════════════════════════════════════════════
# PAT-816 — report-schedule partial recipient failure
# ══════════════════════════════════════════════════════════════════════════

def _daily_schedule(schedule_id="sched-1", ad_hoc_emails=None):
    return {
        "id": schedule_id,
        "cadence": "daily",
        "cadence_config": {},
        "name": "Monthly Report",
        "content_type": "full",
        "recipient_ids": [],
        "ad_hoc_emails": ad_hoc_emails or [],
    }


class TestReportScheduleGate:
    def test_partial_failure_does_not_mark_period_sent(self, db, monkeypatch):
        today = datetime.now(timezone.utc).date()
        sched = _daily_schedule(ad_hoc_emails=["ok@x.test", "fails@x.test"])

        def fake_get(url, *a, **k):
            if url.endswith("/report-schedules"):
                return _FakeResp([sched])
            return _FakeResp({})

        def fake_post(url, *a, **k):
            if url.endswith("/generate"):
                return _FakeResp({"id": "record-1"}, status_code=201)
            return _FakeResp({})

        def fake_send(to_email, *a, **k):
            return to_email == "ok@x.test"

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(dashboard.http, "post", fake_post)
        monkeypatch.setattr(dashboard, "_send_email", fake_send)

        dashboard._check_tenant_report_schedules("t-sched", "Acme", today)

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM report_schedule_sends WHERE tenant_id='t-sched' "
                "AND schedule_id='sched-1'"
            ).fetchone()
        assert row is None, \
            "a partial-failure period must not be marked sent — the failed " \
            "recipient would otherwise never get that period's report"

    def test_full_success_marks_period_sent(self, db, monkeypatch):
        today = datetime.now(timezone.utc).date()
        sched = _daily_schedule(ad_hoc_emails=["a@x.test", "b@x.test"])

        def fake_get(url, *a, **k):
            if url.endswith("/report-schedules"):
                return _FakeResp([sched])
            return _FakeResp({})

        def fake_post(url, *a, **k):
            if url.endswith("/generate"):
                return _FakeResp({"id": "record-1"}, status_code=201)
            return _FakeResp({})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(dashboard.http, "post", fake_post)
        monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: True)

        dashboard._check_tenant_report_schedules("t-sched", "Acme", today)

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM report_schedule_sends WHERE tenant_id='t-sched' "
                "AND schedule_id='sched-1'"
            ).fetchone()
        assert row is not None

    def test_full_failure_does_not_mark_period_sent(self, db, monkeypatch):
        today = datetime.now(timezone.utc).date()
        sched = _daily_schedule(ad_hoc_emails=["a@x.test"])

        def fake_get(url, *a, **k):
            if url.endswith("/report-schedules"):
                return _FakeResp([sched])
            return _FakeResp({})

        def fake_post(url, *a, **k):
            if url.endswith("/generate"):
                return _FakeResp({"id": "record-1"}, status_code=201)
            return _FakeResp({})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        monkeypatch.setattr(dashboard.http, "post", fake_post)
        monkeypatch.setattr(dashboard, "_send_email", lambda *a, **k: False)

        dashboard._check_tenant_report_schedules("t-sched", "Acme", today)

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM report_schedule_sends WHERE tenant_id='t-sched' "
                "AND schedule_id='sched-1'"
            ).fetchone()
        assert row is None


# ══════════════════════════════════════════════════════════════════════════
# PAT-818 — admin_account_post tier push failure
# ══════════════════════════════════════════════════════════════════════════

class TestAdminAccountTierPushFailure:
    def _seed_tenant(self, tenant_id):
        with dashboard.get_db() as conn:
            conn.execute(
                "INSERT INTO clients (id, company, tenant_id, "
                "created_at, agent_config_tier) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), "Acme", tenant_id,
                 datetime.now(timezone.utc).isoformat(), "report_deploy"),
            )

    def test_upstream_non_200_returns_error_not_ok_true(self, client, monkeypatch):
        tenant_id = str(uuid.uuid4())
        self._seed_tenant(tenant_id)
        bad = MagicMock()
        bad.status_code = 500
        bad.text = "internal error"
        with patch.object(dashboard.http, "put", return_value=bad):
            r = client.post(
                f"/admin/tenants/{tenant_id}/account",
                headers=BEARER,
                json={"agent_config_tier": "patch"},
            )
        assert r.status_code != 200
        assert "error" in r.json()
        assert r.json().get("ok") is not True

        # Local tier must remain unchanged (stale), not silently updated.
        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT agent_config_tier FROM clients WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        assert row["agent_config_tier"] == "report_deploy"

    def test_upstream_exception_returns_error_not_ok_true(self, client, monkeypatch):
        tenant_id = str(uuid.uuid4())
        self._seed_tenant(tenant_id)
        with patch.object(dashboard.http, "put", side_effect=ConnectionError("unreachable")):
            r = client.post(
                f"/admin/tenants/{tenant_id}/account",
                headers=BEARER,
                json={"agent_config_tier": "patch"},
            )
        assert r.status_code != 200
        assert "error" in r.json()

    def test_upstream_success_still_returns_ok_true(self, client, monkeypatch):
        tenant_id = str(uuid.uuid4())
        self._seed_tenant(tenant_id)
        good = MagicMock()
        good.status_code = 200
        good.json.return_value = {"config_version": 3}
        with patch.object(dashboard.http, "put", return_value=good):
            r = client.post(
                f"/admin/tenants/{tenant_id}/account",
                headers=BEARER,
                json={"agent_config_tier": "patch"},
            )
        assert r.status_code == 200
        assert r.json() == {"ok": True}

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT agent_config_tier, agent_config_version FROM clients WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        assert row["agent_config_tier"] == "patch"
        assert row["agent_config_version"] == 3

    def test_upstream_200_malformed_body_returns_error_not_ok_true(self, client, monkeypatch):
        """A 200 upstream response whose body can't be parsed as JSON must still
        surface as an explicit error, not a silent {"ok": True} with a stale
        local tier — the original bug's swallow happened in this exact spot."""
        tenant_id = str(uuid.uuid4())
        self._seed_tenant(tenant_id)
        bad_body = MagicMock()
        bad_body.status_code = 200
        bad_body.json.side_effect = ValueError("not JSON")
        with patch.object(dashboard.http, "put", return_value=bad_body):
            r = client.post(
                f"/admin/tenants/{tenant_id}/account",
                headers=BEARER,
                json={"agent_config_tier": "patch"},
            )
        assert r.status_code != 200
        assert "error" in r.json()

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT agent_config_tier FROM clients WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        assert row["agent_config_tier"] == "report_deploy"

    def test_unrelated_fields_still_persisted_on_tier_push_failure(self, client, monkeypatch):
        """Contact/billing fields committed before the tier-push block must survive
        even when the tier push itself fails — only the swallow-and-lie behaviour
        around the upstream PUT is being fixed, not the rest of the route."""
        tenant_id = str(uuid.uuid4())
        self._seed_tenant(tenant_id)
        bad = MagicMock()
        bad.status_code = 502
        bad.text = "bad gateway"
        with patch.object(dashboard.http, "put", return_value=bad):
            r = client.post(
                f"/admin/tenants/{tenant_id}/account",
                headers=BEARER,
                json={
                    "agent_config_tier": "patch",
                    "primary_contact_name": "Jane Doe",
                    "primary_contact_email": "jane@acme.test",
                },
            )
        assert r.status_code != 200

        with dashboard.get_db() as conn:
            row = conn.execute(
                "SELECT primary_contact_name, primary_contact_email FROM clients WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        assert row["primary_contact_name"] == "Jane Doe"
        assert row["primary_contact_email"] == "jane@acme.test"

    def test_no_tier_change_still_ok_true(self, client, monkeypatch):
        """A route call that doesn't touch agent_config_tier must be unaffected
        by the PAT-818 fix — no upstream call happens, so no error path fires."""
        tenant_id = str(uuid.uuid4())
        self._seed_tenant(tenant_id)
        with patch.object(dashboard.http, "put") as mock_put:
            r = client.post(
                f"/admin/tenants/{tenant_id}/account",
                headers=BEARER,
                json={"primary_contact_name": "Jane Doe"},
            )
        assert r.status_code == 200
        assert r.json() == {"ok": True}
        mock_put.assert_not_called()
