"""
Tests for PAT-283 agent-config endpoints.

Covers:
  - GET /api/tenant/{id}/agent-config — returns defaults, 404 for unknown
  - PATCH /api/tenant/{id}/agent-config — valid round-trip, enum validation,
    platform body shape, write-only auth_ref, local SQLite update
"""

import os
import sys
import json
import uuid
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient


def _auth_headers():
    return {"Authorization": "Bearer test-key"}


def _mock_platform_ok(config_version=1):
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {
        "tenant_id": "some-uuid",
        "config_version": config_version,
        "key_id": "k1",
    }
    return mock


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


@pytest.fixture
def client_with_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    tenant_id = str(uuid.uuid4())
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), "ACME Ltd", tenant_id, "2026-07-01T00:00:00Z"),
        )
    with TestClient(dashboard.app) as c:
        yield c, tenant_id


# ── GET ────────────────────────────────────────────────────────────────────────

class TestAgentConfigGet:
    def test_returns_defaults_for_new_tenant(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.get(f"/api/tenant/{tenant_id}/agent-config", headers=_auth_headers())
        assert r.status_code == 200
        d = r.json()
        assert d["agent_config_tier"] == "report_deploy"
        assert d["agent_proxy_mode"] == "system"
        assert d["agent_proxy_bypass_when_off_corp"] is False
        assert d["agent_config_version"] is None

    def test_404_for_unknown_tenant(self, client):
        r = client.get("/api/tenant/5e7fd201-4445-5262-bfc4-29c06774d04b/agent-config", headers=_auth_headers())
        assert r.status_code == 404

    def test_requires_auth(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.get(f"/api/tenant/{tenant_id}/agent-config")
        assert r.status_code == 401


# ── PATCH ──────────────────────────────────────────────────────────────────────

class TestAgentConfigPatch:
    def test_tier_patch_round_trips(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        with patch.object(dashboard.http, "put", return_value=_mock_platform_ok(2)):
            r = c.patch(
                f"/api/tenant/{tenant_id}/agent-config",
                headers={**_auth_headers(), "Content-Type": "application/json"},
                json={
                    "agent_config_tier": "patch",
                    "agent_proxy_mode": "system",
                },
            )
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["config_version"] == 2

        # Verify persisted to SQLite
        get_r = c.get(f"/api/tenant/{tenant_id}/agent-config", headers=_auth_headers())
        assert get_r.json()["agent_config_tier"] == "patch"
        assert get_r.json()["agent_config_version"] == 2

    def test_proxy_manual_round_trips(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        with patch.object(dashboard.http, "put", return_value=_mock_platform_ok(1)) as mock_put:
            r = c.patch(
                f"/api/tenant/{tenant_id}/agent-config",
                headers={**_auth_headers(), "Content-Type": "application/json"},
                json={
                    "agent_config_tier": "report_deploy",
                    "agent_proxy_mode": "manual",
                    "agent_proxy_type": "http",
                    "agent_proxy_host": "proxy.corp.example.com",
                    "agent_proxy_port": 8080,
                    "agent_proxy_auth_ref": "patched",
                    "agent_proxy_bypass_when_off_corp": True,
                },
            )
        assert r.status_code == 200

        # Verify platform PUT body shape
        call_kwargs = mock_put.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["tier"] == "report_deploy"
        assert body["proxy"]["mode"] == "manual"
        assert body["proxy"]["host"] == "proxy.corp.example.com"
        assert body["proxy"]["port"] == 8080
        assert body["proxy"]["auth_ref"] == "patched"
        assert body["proxy"]["bypass_when_off_corp"] is True
        assert body["updated_by"] == "dashboard"

        # GET must NOT echo auth_ref as a secret — it IS returned (it's a ref, not a cred)
        # but proxy creds themselves are never stored
        get_r = c.get(f"/api/tenant/{tenant_id}/agent-config", headers=_auth_headers())
        d = get_r.json()
        assert d["agent_proxy_host"] == "proxy.corp.example.com"
        assert d["agent_proxy_auth_ref"] == "patched"

    def test_invalid_tier_rejected(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.patch(
            f"/api/tenant/{tenant_id}/agent-config",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            json={"agent_config_tier": "enterprise", "agent_proxy_mode": "system"},
        )
        assert r.status_code == 400
        assert "tier" in r.json()["error"]

    def test_invalid_proxy_mode_rejected(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.patch(
            f"/api/tenant/{tenant_id}/agent-config",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            json={"agent_config_tier": "report_deploy", "agent_proxy_mode": "auto"},
        )
        assert r.status_code == 400
        assert "proxy mode" in r.json()["error"]

    def test_invalid_proxy_type_rejected(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.patch(
            f"/api/tenant/{tenant_id}/agent-config",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            json={
                "agent_config_tier": "report_deploy",
                "agent_proxy_mode": "manual",
                "agent_proxy_type": "ftp",
            },
        )
        assert r.status_code == 400
        assert "proxy type" in r.json()["error"]

    def test_invalid_port_rejected(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.patch(
            f"/api/tenant/{tenant_id}/agent-config",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            json={
                "agent_config_tier": "report_deploy",
                "agent_proxy_mode": "manual",
                "agent_proxy_port": 99999,
            },
        )
        assert r.status_code == 400
        assert "port" in r.json()["error"]

    def test_platform_502_propagated(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        bad = MagicMock()
        bad.status_code = 500
        bad.json.return_value = {"error": "internal"}
        with patch.object(dashboard.http, "put", return_value=bad):
            r = c.patch(
                f"/api/tenant/{tenant_id}/agent-config",
                headers={**_auth_headers(), "Content-Type": "application/json"},
                json={"agent_config_tier": "report_deploy", "agent_proxy_mode": "system"},
            )
        assert r.status_code == 502

    def test_404_for_unknown_tenant(self, client):
        r = client.patch(
            "/api/tenant/5e7fd201-4445-5262-bfc4-29c06774d04b/agent-config",
            headers={**_auth_headers(), "Content-Type": "application/json"},
            json={"agent_config_tier": "report_deploy", "agent_proxy_mode": "system"},
        )
        assert r.status_code == 404

    def test_requires_auth(self, client_with_tenant):
        c, tenant_id = client_with_tenant
        r = c.patch(
            f"/api/tenant/{tenant_id}/agent-config",
            headers={"Content-Type": "application/json"},
            json={"agent_config_tier": "report_deploy", "agent_proxy_mode": "system"},
        )
        assert r.status_code == 401
