"""
Tests for PAT-695 — session-cookie auth, owner/consultant RBAC, server-side
destructive-action confirmations, and the destructive-write audit log.

Covers:
  - Session cookie mint/verify round-trip + tamper/expiry rejection
  - Auth middleware matrix (no auth 401; bearer 200; valid cookie 200; expired 401)
  - RBAC classifier + matrix (operators unset → everyone consultant; consultant →
    GET 200, destructive 403, allow-listed write 200)
  - X-Confirm-Resource echo-back (missing 428; wrong 409; right → passes through)
  - Rendered /console template contains no DASHBOARD_TOKEN / api_token
"""

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
    # get_db() closes over shared.DB_PATH — patch it (and the mirror in main) so
    # the test writes to a throwaway DB, not the real dashboard.db.
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    """Build a Cookie header for a freshly-minted session."""
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


# ── Session cookie primitives ─────────────────────────────────────────────────

class TestSessionCookie:
    def test_round_trip(self):
        exp = int(time.time()) + 100
        tok = dashboard._session_encode("alice@patched.im", exp)
        assert dashboard._session_decode(tok) == "alice@patched.im"

    def test_expired_rejected(self):
        tok = dashboard._session_encode("alice@patched.im", int(time.time()) - 5)
        assert dashboard._session_decode(tok) is None

    def test_tampered_mac_rejected(self):
        tok = dashboard._session_encode("alice@patched.im", int(time.time()) + 100)
        # flip the last hex char of the mac
        bad = tok[:-1] + ("0" if tok[-1] != "0" else "1")
        assert dashboard._session_decode(bad) is None

    def test_tampered_email_rejected(self):
        import base64
        exp = int(time.time()) + 100
        tok = dashboard._session_encode("alice@patched.im", exp)
        mac = tok.rsplit(".", 1)[1]
        # swap the payload to a different email but keep the honest mac
        forged_b = base64.urlsafe_b64encode(
            f"attacker@evil.com|{exp}".encode()).decode().rstrip("=")
        forged = f"{forged_b}.{mac}"
        assert dashboard._session_decode(forged) is None

    def test_garbage_rejected(self):
        assert dashboard._session_decode("") is None
        assert dashboard._session_decode("nonsense") is None


# ── Auth middleware matrix ────────────────────────────────────────────────────

class TestAuthMatrix:
    def test_no_auth_is_401(self, client):
        r = client.get("/admin/tenants")
        assert r.status_code == 401
        assert r.json()["error"] == "Unauthorized"

    def test_bearer_is_200(self, client):
        mock = MagicMock(status_code=200)
        mock.json.return_value = {"tenants": []}
        with patch.object(dashboard.http, "get", return_value=mock):
            r = client.get("/admin/tenants", headers=BEARER)
        assert r.status_code == 200

    def test_valid_cookie_is_200(self, client):
        mock = MagicMock(status_code=200)
        mock.json.return_value = {"tenants": []}
        with patch.object(dashboard.http, "get", return_value=mock):
            r = client.get("/admin/tenants", headers=_cookie("owner@patched.im"))
        assert r.status_code == 200

    def test_expired_cookie_is_401(self, client):
        r = client.get("/admin/tenants", headers=_cookie("owner@patched.im", ttl=-5))
        assert r.status_code == 401


# ── RBAC classifier (unit) ────────────────────────────────────────────────────

class TestClassifier:
    def test_report_generate_allowed_for_consultant(self):
        assert dashboard._consultant_write_allowed(
            "POST", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/report-records/generate") is True

    def test_report_email_allowed_for_consultant(self):
        assert dashboard._consultant_write_allowed(
            "POST", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/reports/email") is True

    def test_account_notes_allowed_for_consultant(self):
        assert dashboard._consultant_write_allowed(
            "POST", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/account") is True

    def test_purge_not_in_consultant_allow(self):
        assert dashboard._consultant_write_allowed(
            "DELETE", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge") is False

    def test_purge_is_destructive(self):
        assert dashboard._is_destructive("DELETE", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge") is True

    def test_credentials_is_destructive(self):
        assert dashboard._is_destructive("POST", "/api/credentials") is True

    def test_confirm_rule_purge(self):
        assert dashboard._confirm_rule("DELETE", "/admin/tenants/75dc0a94-8fc4-5070-a85b-18e31545eef4/purge") == ("tenant", "75dc0a94-8fc4-5070-a85b-18e31545eef4")

    def test_confirm_rule_device_delete(self):
        assert dashboard._confirm_rule(
            "DELETE", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/devices/d-7") == ("device", "d-7")

    def test_confirm_rule_none_for_get(self):
        assert dashboard._confirm_rule("GET", "/admin/tenants") is None


# ── RBAC matrix (integration) ─────────────────────────────────────────────────

class TestRbacMatrix:
    def test_operators_unset_everyone_consultant(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset())
        upstream = MagicMock()
        monkeypatch.setattr(dashboard.http, "delete", upstream)
        r = client.delete(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge",
            headers={**_cookie("anyone@patched.im"), "X-Confirm-Resource": "acme"},
        )
        assert r.status_code == 403
        upstream.assert_not_called()

    def test_consultant_get_allowed(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        mock = MagicMock(status_code=200)
        mock.json.return_value = {"tenants": []}
        with patch.object(dashboard.http, "get", return_value=mock):
            r = client.get("/admin/tenants", headers=_cookie("consultant@patched.im"))
        assert r.status_code == 200

    def test_consultant_destructive_403(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.delete(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge",
            headers={**_cookie("consultant@patched.im"), "X-Confirm-Resource": "acme"},
        )
        assert r.status_code == 403

    def test_consultant_report_post_allowed(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        mock = MagicMock(status_code=200, content=b"{}")
        mock.json.return_value = {"ok": True}
        with patch.object(dashboard.http, "post", return_value=mock):
            r = client.post(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/delivery-contacts",
                json={"email": "x@y.com"},
                headers=_cookie("consultant@patched.im"),
            )
        assert r.status_code != 403


# ── X-Confirm-Resource echo-back ──────────────────────────────────────────────

class TestConfirmResource:
    def test_missing_header_is_428(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.delete("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge", headers=_cookie("owner@patched.im"))
        assert r.status_code == 428

    def test_wrong_value_is_409(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        monkeypatch.setattr(dashboard, "_resolve_confirm_resource", lambda k, i, *a: {"acme"})
        r = client.delete(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge",
            headers={**_cookie("owner@patched.im"), "X-Confirm-Resource": "wrongco"},
        )
        assert r.status_code == 409

    def test_right_value_passes_through(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        monkeypatch.setattr(dashboard, "_resolve_confirm_resource", lambda k, i, *a: {"acme"})
        mock = MagicMock(status_code=204)
        with patch.object(dashboard.http, "delete", return_value=mock) as m:
            r = client.delete(
                "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge",
                headers={**_cookie("owner@patched.im"), "X-Confirm-Resource": "Acme"},  # case-insensitive
            )
        assert r.status_code == 204
        assert m.called

    def test_device_delete_missing_header_is_428(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        r = client.delete(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/devices/d-7", headers=_cookie("owner@patched.im"))
        assert r.status_code == 428


# ── _resolve_confirm_resource ─────────────────────────────────────────────────

class TestResolveConfirmResource:
    def test_purge_of_offboarded_tenant_resolves_via_revoked_list(self, client):
        # Purge targets tenants that are already offboarded — they only appear
        # in /admin/tenants/revoked, not /admin/tenants.
        def fake_get(url, **kw):
            m = MagicMock(status_code=200)
            if url.endswith("/admin/tenants/revoked"):
                m.json.return_value = {"tenants": [{"id": "75dc0a94-8fc4-5070-a85b-18e31545eef4", "name": "Acme Corp"}]}
            else:
                m.json.return_value = {"tenants": []}
            return m
        with patch.object(dashboard.http, "get", side_effect=fake_get):
            vals = dashboard._resolve_confirm_resource("tenant", "75dc0a94-8fc4-5070-a85b-18e31545eef4")
        assert "acme corp" in vals

    def test_resource_id_always_acceptable(self, client):
        # Echoing the exact resource id demonstrates intent even when the
        # upstream is unreachable or the resource has no display name.
        err = MagicMock(status_code=502)
        err.json.side_effect = ValueError
        with patch.object(dashboard.http, "get", return_value=err):
            vals = dashboard._resolve_confirm_resource("device", "D-42")
        assert "d-42" in vals

    def test_device_names_resolved_from_upstream(self, client):
        m = MagicMock(status_code=200)
        m.json.return_value = {"device": {"hostname": "MacBook-Pro", "serial": "C02XY"}}
        with patch.object(dashboard.http, "get", return_value=m):
            vals = dashboard._resolve_confirm_resource("device", "d-7")
        assert {"macbook-pro", "c02xy", "d-7"} <= vals


# ── Audit log ─────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_denied_purge_is_audited(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        client.delete(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/purge",
            headers={**_cookie("consultant@patched.im"), "X-Confirm-Resource": "acme"},
        )
        with dashboard.get_db() as db:
            rows = db.execute(
                "SELECT actor_email, role, method, outcome FROM admin_audit_log"
            ).fetchall()
        assert any(
            r["outcome"] == "denied_rbac" and r["role"] == "consultant"
            and r["actor_email"] == "consultant@patched.im"
            for r in rows
        )


# ── Console template no longer leaks the token ────────────────────────────────

class TestConsoleNoToken:
    def test_console_has_no_embedded_token(self, client):
        r = client.get("/console")
        assert r.status_code == 200
        assert "DASHBOARD_TOKEN" not in r.text
        assert "test-key" not in r.text

    def test_console_mints_cookie_from_verified_access(self, client, verified_access_headers):
        r = client.get(
            "/console",
            headers=verified_access_headers("owner@patched.im"),
        )
        assert r.status_code == 200
        setc = r.headers.get("set-cookie", "")
        assert dashboard.SESSION_COOKIE in setc
        assert "HttpOnly" in setc and "Secure" in setc
        # extract the value from the Set-Cookie header (Secure cookies aren't
        # persisted by the http test client) and verify it decodes to the CF email
        val = setc.split(f"{dashboard.SESSION_COOKIE}=", 1)[1].split(";", 1)[0]
        assert dashboard._session_decode(val) == "owner@patched.im"

    def test_console_no_cookie_without_cf_header_in_prod(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "_DEV_ENV", False)
        r = client.get("/console")
        assert r.status_code == 200
        assert dashboard.SESSION_COOKIE not in r.headers.get("set-cookie", "")
