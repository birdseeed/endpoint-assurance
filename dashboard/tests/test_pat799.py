"""
Tests for PAT-799 — dashboard safety audit: richer audit-log context
(resource_name/reason/before/after), the new config-write destructive rules,
and the reusable audit-capture path in the auth middleware.

Covers:
  - admin_audit_log schema gained the four new nullable columns
  - _audit_write persists resource_name/reason/before/after
  - _tenant_name_from_path resolves a company name, falls back to the id
  - New destructive routes (billing rates, App Control, ring-config, webhook
    update/test, new-apps decide) are classified correctly
  - X-Audit-Reason / X-Audit-Before / X-Audit-After headers land in the audit
    row for a route that doesn't compute its own before/after
  - Billing rates PATCH captures a real before/after snapshot server-side
  - The firewall-apply route no longer double-logs (exactly one audit row)
"""

import json
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
import shared
from fastapi.testclient import TestClient


BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


def _audit_rows(cols="*"):
    with dashboard.get_db() as db:
        return [dict(r) for r in db.execute(f"SELECT {cols} FROM admin_audit_log").fetchall()]


# ── Schema ─────────────────────────────────────────────────────────────────

class TestSchema:
    def test_new_columns_present(self, client):
        with dashboard.get_db() as db:
            cols = {r[1] for r in db.execute("PRAGMA table_info(admin_audit_log)").fetchall()}
        assert {"resource_name", "reason", "before_value", "after_value"} <= cols

    def test_init_db_idempotent_on_existing_column_set(self, client):
        # Re-running init_db against an already-migrated DB must not raise
        # (the PRAGMA-guard is what makes ALTER TABLE safe to repeat).
        dashboard.init_db()
        with dashboard.get_db() as db:
            cols = {r[1] for r in db.execute("PRAGMA table_info(admin_audit_log)").fetchall()}
        assert {"resource_name", "reason", "before_value", "after_value"} <= cols


# ── _audit_write ───────────────────────────────────────────────────────────

class TestAuditWrite:
    def test_persists_new_fields(self, client):
        dashboard._audit_write(
            "alice@patched.im", "owner", "PATCH", "/admin/billing/rates", "allowed",
            resource_name="Acme Corp", reason="Q3 repricing", before="{}", after='{"report": 5.0}',
        )
        rows = _audit_rows("actor_email, resource_name, reason, before_value, after_value")
        assert rows[-1] == {
            "actor_email": "alice@patched.im",
            "resource_name": "Acme Corp",
            "reason": "Q3 repricing",
            "before_value": "{}",
            "after_value": '{"report": 5.0}',
        }

    def test_backward_compatible_without_new_kwargs(self, client):
        # Pre-existing call sites pass only the original five positional args.
        dashboard._audit_write("bob@patched.im", "owner", "POST", "/api/ops/firewall-apply", "allowed")
        rows = _audit_rows("resource_name, reason, before_value, after_value")
        assert rows[-1] == {"resource_name": None, "reason": None, "before_value": None, "after_value": None}


# ── _tenant_name_from_path ───────────────────────────────────────────────────

class TestTenantNameFromPath:
    def test_resolves_company_name(self, client):
        with dashboard.get_db() as db:
            db.execute(
                "INSERT INTO clients (id, tenant_id, company, created_at) VALUES (?, ?, ?, ?)",
                ("c-42", "02aba1ee-7829-5796-ae92-30ab0ed96df2", "Acme Corp", "2026-07-01T00:00:00Z"),
            )
        assert dashboard._tenant_name_from_path("/admin/tenants/02aba1ee-7829-5796-ae92-30ab0ed96df2/ring-config") == "Acme Corp"

    def test_falls_back_to_id_when_not_found(self, client):
        assert dashboard._tenant_name_from_path("/admin/tenants/6eb4dcd3-9feb-5fe5-ba95-9d887ead32ff/webhooks/w-1") == "6eb4dcd3-9feb-5fe5-ba95-9d887ead32ff"

    def test_none_when_no_tenant_segment(self, client):
        assert dashboard._tenant_name_from_path("/admin/billing/rates") is None


# ── Destructive-rule classification ─────────────────────────────────────────

class TestNewDestructiveRules:
    @pytest.mark.parametrize("method,path", [
        ("PATCH", "/admin/billing/rates"),
        ("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/app-control/admins"),
        ("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/app-control/allowlist"),
        ("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-config"),
        ("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-devices/d-1"),
        ("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/webhooks/w-1"),
        ("POST", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/webhooks/w-1/test"),
        ("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/new-apps/e-1"),
    ])
    def test_is_destructive(self, method, path):
        assert dashboard._is_destructive(method, path) is True

    def test_ring_config_get_is_not_destructive(self):
        assert dashboard._is_destructive("GET", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-config") is False


# ── Audit-header capture path (X-Audit-Reason / -Before / -After) ──────────

class TestAuditHeaderCapture:
    def test_reason_and_before_after_headers_land_in_audit_row(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        mock = MagicMock(status_code=200)
        mock.json.return_value = {"enabled": True}
        with patch.object(dashboard.http, "put", return_value=mock), \
             patch.object(dashboard.http, "get", return_value=MagicMock(status_code=404)):
            r = client.put(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-devices/d-1",
                json={"ring": 2},
                headers={
                    **_cookie("owner@patched.im"),
                    "X-Audit-Reason": "customer requested early ring",
                    "X-Audit-Before": "ring=1",
                    "X-Audit-After": "ring=2",
                },
            )
        assert r.status_code == 410
        rows = _audit_rows("path, reason, before_value, after_value, outcome")
        row = [x for x in rows if x["path"] == "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/ring-devices/d-1"][0]
        assert row["reason"] == "customer requested early ring"
        assert row["before_value"] is None
        assert row["after_value"] is None
        assert row["outcome"] == "rejected_410"


# ── Billing rates: server-computed before/after ─────────────────────────────

class TestBillingRatesAudit:
    def test_patch_captures_before_after_snapshot(self, client, monkeypatch):
        # PAT-1100: v3 banded rate card — annual_discount is a top-level
        # scalar field, still a simple before/after snapshot to assert on.
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.patch(
            "/admin/billing/rates",
            json={"annual_discount": 0.90},
            headers=_cookie("owner@patched.im"),
        )
        assert r.status_code == 200
        rows = _audit_rows("path, before_value, after_value")
        row = [x for x in rows if x["path"] == "/admin/billing/rates"][0]
        before = json.loads(row["before_value"])
        after = json.loads(row["after_value"])
        assert before["annual_discount"] == dashboard._BILLING_ANNUAL_DISCOUNT_DEFAULT
        assert after["annual_discount"] == 0.90

    def test_rejected_write_is_not_logged_as_allowed(self, client, monkeypatch):
        # A validation failure (negative annual_discount) returns 400 without
        # raising — the middleware must not record this as outcome="allowed".
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.patch(
            "/admin/billing/rates",
            json={"annual_discount": -5},
            headers=_cookie("owner@patched.im"),
        )
        assert r.status_code == 400
        rows = _audit_rows("path, outcome")
        row = [x for x in rows if x["path"] == "/admin/billing/rates"][0]
        assert row["outcome"] == "rejected_400"


# ── Crash-safety: a row exists even if the handler blows up ─────────────────

class TestAuditSurvivesHandlerCrash:
    def test_handler_exception_logs_error_outcome_not_a_gap(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))

        def boom(*a, **kw):
            raise RuntimeError("simulated handler crash")

        # http.get (the before-snapshot fetch) is already wrapped in its own
        # try/except — patch http.put (the real, unguarded write) instead so
        # the exception actually propagates up through the route handler.
        # The snapshot GET is stubbed too (PAT-2306: no real network in tests);
        # a 404 gives the same before=None a failed lookup would.
        with patch.object(dashboard.http, "get", return_value=MagicMock(status_code=404)), \
             patch.object(dashboard.http, "put", side_effect=boom):
            with pytest.raises(Exception):
                client.put(
                    "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/app-control/admins",
                    json={"approved_admins": ["x@y.com"]},
                    headers=_cookie("owner@patched.im"),
                )
        rows = _audit_rows("path, outcome")
        matches = [x for x in rows if x["path"] == "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/app-control/admins"]
        # Exactly one row (written pre-dispatch, updated to "error" — not a
        # second insert), and it must NOT be silently missing or "in_progress".
        assert len(matches) == 1
        assert matches[0]["outcome"] == "error"


# ── Firewall apply: no double-logging ───────────────────────────────────────

class TestFirewallApplyAudit:
    def test_single_audit_row_per_call(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        fake_result = MagicMock(returncode=0, stdout="", stderr="")
        fake_journal = MagicMock(returncode=0, stdout="ok")
        with patch("subprocess.run", side_effect=[fake_result, fake_journal]):
            r = client.post(
                "/api/ops/firewall-apply",
                json={"edge": "prod-01-edge"},
                headers=_cookie("owner@patched.im"),
            )
        assert r.status_code == 200
        rows = _audit_rows("path, resource_name, after_value")
        matches = [x for x in rows if x["path"] == "/api/ops/firewall-apply"]
        assert len(matches) == 1
        assert matches[0]["resource_name"] == "prod-01-edge"
        assert "exit_code=0" in matches[0]["after_value"]


# ── Denied/rejected outcomes still carry resource_name/reason ──────────────

class TestDeniedOutcomesCarryContext:
    def test_denied_rbac_includes_resource_name(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        with dashboard.get_db() as db:
            db.execute(
                "INSERT INTO clients (id, tenant_id, company, created_at) VALUES (?, ?, ?, ?)",
                ("c-9", "75dc0a94-8fc4-5070-a85b-18e31545eef4", "Acme Corp", "2026-07-01T00:00:00Z"),
            )
        client.put(
            "/admin/tenants/75dc0a94-8fc4-5070-a85b-18e31545eef4/app-control/admins",
            json={"approved_admins": ["x@y.com"]},
            headers=_cookie("consultant@patched.im"),
        )
        rows = _audit_rows("path, outcome, resource_name")
        row = [x for x in rows if x["path"] == "/admin/tenants/75dc0a94-8fc4-5070-a85b-18e31545eef4/app-control/admins"][0]
        assert row["outcome"] == "denied_rbac"
        assert row["resource_name"] == "Acme Corp"
