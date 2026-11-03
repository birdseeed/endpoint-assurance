"""
PAT-801 — tenant/recipient confirmation + audit for report sends.

Covers:
  * _recipient_category() classifies primary contact / delivery contact /
    external-ad-hoc.
  * GET /admin/tenants/{tid}/reports/recipient-category surfaces that
    classification for the client-side confirmation modal.
  * POST /admin/tenants/{tid}/reports/email writes one report_send_audit_log
    row per attempt (rejected / failed / sent), with actor, tenant, report
    type, recipient, and outcome.
  * A failed send (mail provider returns False) is NOT recorded in
    report_deliveries — that table's existing "successful sends only"
    semantics stay accurate — and the response carries actionable error text.
  * A successful send still populates report_deliveries exactly as before.
"""

import os
import sys
import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


def _seed_client(tenant_id="0a4c2c91-7412-575c-b544-dea3a596dd31", primary_email="primary@acme.test"):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at, primary_contact_email) "
            "VALUES (?,?,?,?,?)",
            ("id-1", "Acme", tenant_id, datetime.now(timezone.utc).isoformat(), primary_email),
        )


class _FakeResp:
    def __init__(self, payload=None, status_code=200, content=b"x"):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.content = content

    def json(self):
        return self._payload


_REPORT_CATALOGUE = {"reports": [{
    "type": "executive-summary",
    "label": "Executive Estate Summary",
    "description": "Platform-owned report metadata.",
    "default_frequency": "monthly",
    "customer_facing": True,
    "subject_scope": "tenant",
    "admin_pdf_path": "/admin/reports/executive-summary/{tenantID}.pdf",
}]}


def _report_get(pdf_status=200):
    def get(url, **kwargs):
        if url.endswith("/admin/reports/catalogue"):
            return _FakeResp(_REPORT_CATALOGUE, 200)
        return _FakeResp({}, pdf_status)
    return get


# ── _recipient_category ────────────────────────────────────────────────────

class TestRecipientCategory:
    def test_matches_primary_contact(self, client):
        _seed_client(primary_email="Primary@Acme.test")
        category, label = dashboard._recipient_category("0a4c2c91-7412-575c-b544-dea3a596dd31", "primary@acme.test")
        assert category == "primary"
        assert "Primary" in label

    def test_matches_delivery_contact(self, client):
        _seed_client(primary_email="primary@acme.test")
        contacts = [{"id": "c1", "label": "IT Manager", "email": "it@acme.test"}]
        with patch.object(dashboard.http, "get", return_value=_FakeResp(contacts)):
            category, label = dashboard._recipient_category("0a4c2c91-7412-575c-b544-dea3a596dd31", "it@acme.test")
        assert category == "delivery"
        assert "IT Manager" in label

    def test_falls_back_to_external(self, client):
        _seed_client(primary_email="primary@acme.test")
        with patch.object(dashboard.http, "get", return_value=_FakeResp([])):
            category, label = dashboard._recipient_category("0a4c2c91-7412-575c-b544-dea3a596dd31", "randomguy@gmail.com")
        assert category == "external"

    def test_falls_back_to_external_when_upstream_unreachable(self, client):
        _seed_client(primary_email="primary@acme.test")
        with patch.object(dashboard.http, "get", side_effect=Exception("boom")):
            category, label = dashboard._recipient_category("0a4c2c91-7412-575c-b544-dea3a596dd31", "randomguy@gmail.com")
        assert category == "external"


class TestRecipientCategoryEndpoint:
    def test_returns_classification(self, client):
        _seed_client(primary_email="primary@acme.test")
        r = client.get(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/reports/recipient-category?recipient=primary@acme.test",
            headers=_cookie("owner@patched.im"),
        )
        assert r.status_code == 200
        assert r.json()["category"] == "primary"

    def test_rejects_invalid_email(self, client):
        _seed_client()
        r = client.get(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/reports/recipient-category?recipient=not-an-email",
            headers=_cookie("owner@patched.im"),
        )
        assert r.status_code == 400


# ── proxy_report_email — audit log + delivery-log accuracy ────────────────

class TestReportEmailAudit:
    def _send_payload(self, client, body, email="owner@patched.im"):
        return client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/reports/email",
            headers=_cookie(email),
            json=body,
        )

    def test_successful_send_is_audited_and_delivered(self, client):
        _seed_client(primary_email="primary@acme.test")
        dashboard._REPORT_CATALOGUE_CACHE.update(
            entries=None, fetched_at=0.0, failure_reason=None, failure_at=0.0,
        )
        with patch.object(dashboard.http, "get", side_effect=_report_get()), \
             patch.object(dashboard, "_send_email", return_value=True):
            r = self._send_payload(
                client,
                {"report_type": "executive-summary", "recipient": "primary@acme.test"},
                email="alice@patched.im",
            )
        assert r.status_code == 200
        assert r.json() == {"ok": True}

        with dashboard.get_db() as db:
            audit_rows = db.execute(
                "SELECT * FROM report_send_audit_log WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()
            delivery_rows = db.execute(
                "SELECT * FROM report_deliveries WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()

        assert len(audit_rows) == 1
        assert audit_rows[0]["outcome"] == "sent"
        assert audit_rows[0]["actor_email"] == "alice@patched.im"
        assert audit_rows[0]["report_type"] == "executive-summary"
        assert audit_rows[0]["recipient"] == "primary@acme.test"
        assert audit_rows[0]["recipient_category"] == "primary"

        assert len(delivery_rows) == 1
        assert delivery_rows[0]["status"] == "sent"

    def test_failed_send_is_audited_and_not_delivered(self, client):
        _seed_client(primary_email="primary@acme.test")
        dashboard._REPORT_CATALOGUE_CACHE.update(
            entries=None, fetched_at=0.0, failure_reason=None, failure_at=0.0,
        )
        with patch.object(dashboard.http, "get", side_effect=_report_get()), \
             patch.object(dashboard, "_send_email", return_value=False):
            r = self._send_payload(
                client,
                {"report_type": "executive-summary", "recipient": "primary@acme.test"},
            )

        assert r.status_code == 502
        assert "Email delivery failed" in r.json()["error"]

        with dashboard.get_db() as db:
            audit_rows = db.execute(
                "SELECT * FROM report_send_audit_log WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()
            delivery_rows = db.execute(
                "SELECT * FROM report_deliveries WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()

        assert len(audit_rows) == 1
        assert audit_rows[0]["outcome"] == "failed"
        # The existing delivery log's "did this actually get sent" semantics
        # must stay accurate — no phantom delivery row for a failed send.
        assert len(delivery_rows) == 0

    def test_invalid_recipient_is_audited_as_rejected(self, client):
        _seed_client()
        r = self._send_payload(
            client, {"report_type": "executive-summary", "recipient": "not-an-email"}
        )
        assert r.status_code == 400
        with dashboard.get_db() as db:
            rows = db.execute(
                "SELECT outcome FROM report_send_audit_log WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "rejected"

    def test_unknown_report_type_is_audited_as_rejected(self, client):
        _seed_client()
        r = self._send_payload(
            client, {"report_type": "not-a-real-type", "recipient": "primary@acme.test"}
        )
        assert r.status_code == 400
        with dashboard.get_db() as db:
            rows = db.execute(
                "SELECT outcome FROM report_send_audit_log WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "rejected"

    def test_platform_error_is_audited_as_failed(self, client):
        _seed_client(primary_email="primary@acme.test")
        dashboard._REPORT_CATALOGUE_CACHE.update(
            entries=None, fetched_at=0.0, failure_reason=None, failure_at=0.0,
        )
        with patch.object(dashboard.http, "get", side_effect=_report_get(pdf_status=503)):
            r = self._send_payload(
                client,
                {"report_type": "executive-summary", "recipient": "primary@acme.test"},
            )
        assert r.status_code == 503
        with dashboard.get_db() as db:
            rows = db.execute(
                "SELECT outcome FROM report_send_audit_log WHERE tenant_id='0a4c2c91-7412-575c-b544-dea3a596dd31'"
            ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "failed"
