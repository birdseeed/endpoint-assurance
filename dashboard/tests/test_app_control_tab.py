"""
Tests for the (frontend-retired) PAT-607 Application Control proxy routes.

PAT-2239 removed the Application Control tab, its panel markup and its JS
entirely (App Control is no longer on the roadmap). The three proxy routes
below stay: they are the platform's own `/admin/tenants/{id}/app-control*`
contract, explicitly out of scope for that ticket.

Covers:
  - Three proxy routes: GET /app-control, PUT /app-control/admins,
    PUT /app-control/allowlist — with mocked upstream responses

Run with: pytest tests/test_app_control_tab.py -v
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test-key"}

_POLICY = {
    "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
    "app_control_enabled": True,
    "approved_admins": ["alice", "DOMAIN\\bob"],
    "app_allowlist": ["chrome.exe", "com.google.Chrome"],
}


def _mock_upstream(payload, status=200):
    m = MagicMock()
    m.status_code = status
    m.json.return_value = payload
    m.text = str(payload)
    return m


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def test_app_control_tab_markup_and_js_fully_removed():
    # PAT-2239: unlike the other PAT-1965 retired surfaces, App Control is
    # gone outright, with no inert template and no dead JS. Assert absence
    # directly against the template source (the panel HTML never carried a
    # `tab-app-control` id, so a rendered-page fixture adds nothing here).
    console_html_path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
    with open(console_html_path, encoding="utf-8") as f:
        console_source = f.read()
    for needle in (
        'data-retired-surface="app-control"',
        'id="ac-loading"', 'id="ac-error"', 'id="ac-content"', 'id="ac-disabled-banner"',
        'id="ac-admins-textarea"', 'id="ac-allowlist-textarea"',
        "_acActivate", "_acLoad(", "_acSaveAdmins", "_acSaveAllowlist", "_acDiffBodyHtml",
        "Application Control", "App Allowlist", "Approved Admins",
    ):
        assert needle not in console_source, needle


# ── Proxy route: GET /admin/tenants/{tenant_id}/app-control ──────────────────

def test_get_app_control_proxies_upstream(client):
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_POLICY)):
        r = client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/app-control", headers=_AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["app_control_enabled"] is True
    assert data["approved_admins"] == ["alice", "DOMAIN\\bob"]
    assert data["app_allowlist"] == ["chrome.exe", "com.google.Chrome"]


def test_get_app_control_url_contains_tenant_and_resource(client):
    captured = []

    def _fake_get(url, **kwargs):
        captured.append(url)
        return _mock_upstream(_POLICY)

    with patch.object(dashboard.http, "get", side_effect=_fake_get):
        client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/app-control", headers=_AUTH)

    app_control_calls = [u for u in captured if "app-control" in u]
    assert any("a5effb0c-c4c3-5d57-af50-5c7fd102599e" in u for u in app_control_calls)
    assert any("app-control" in u for u in app_control_calls)


def test_get_app_control_propagates_upstream_error(client):
    with patch.object(dashboard.http, "get", return_value=_mock_upstream({"detail": "not found"}, status=404)):
        r = client.get("/admin/tenants/1238067e-31a3-53b5-a524-ee2b2ce27ac0/app-control", headers=_AUTH)
    assert r.status_code == 404


# ── Proxy route: PUT /admin/tenants/{tenant_id}/app-control/admins ────────────

def test_put_admins_proxies_upstream(client):
    updated = {**_POLICY, "approved_admins": ["alice"]}
    # The PUT handler first GETs the current policy as the audit before-state.
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_POLICY)), \
         patch.object(dashboard.http, "put", return_value=_mock_upstream(updated)) as mock_put:
        r = client.put(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/app-control/admins",
            json={"approved_admins": ["alice"]},
            headers=_AUTH,
        )
    assert r.status_code == 200
    data = r.json()
    assert data["approved_admins"] == ["alice"]
    url = mock_put.call_args[0][0]
    assert "a5effb0c-c4c3-5d57-af50-5c7fd102599e" in url
    assert "app-control/admins" in url


def test_put_admins_forwards_body(client):
    captured_body = []

    def _fake_put(url, **kwargs):
        captured_body.append(kwargs.get("json"))
        return _mock_upstream(_POLICY)

    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_POLICY)), \
         patch.object(dashboard.http, "put", side_effect=_fake_put):
        client.put(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/app-control/admins",
            json={"approved_admins": ["alice", "bob"]},
            headers=_AUTH,
        )

    assert captured_body[0] == {"approved_admins": ["alice", "bob"]}


# ── Proxy route: PUT /admin/tenants/{tenant_id}/app-control/allowlist ─────────

def test_put_allowlist_proxies_upstream(client):
    updated = {**_POLICY, "app_allowlist": ["chrome.exe"]}
    # The PUT handler first GETs the current policy as the audit before-state.
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_POLICY)), \
         patch.object(dashboard.http, "put", return_value=_mock_upstream(updated)) as mock_put:
        r = client.put(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/app-control/allowlist",
            json={"app_allowlist": ["chrome.exe"]},
            headers=_AUTH,
        )
    assert r.status_code == 200
    data = r.json()
    assert data["app_allowlist"] == ["chrome.exe"]
    url = mock_put.call_args[0][0]
    assert "a5effb0c-c4c3-5d57-af50-5c7fd102599e" in url
    assert "app-control/allowlist" in url


def test_put_allowlist_forwards_body(client):
    captured_body = []

    def _fake_put(url, **kwargs):
        captured_body.append(kwargs.get("json"))
        return _mock_upstream(_POLICY)

    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_POLICY)), \
         patch.object(dashboard.http, "put", side_effect=_fake_put):
        client.put(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/app-control/allowlist",
            json={"app_allowlist": ["com.google.Chrome", "chrome.exe"]},
            headers=_AUTH,
        )

    assert captured_body[0] == {"app_allowlist": ["com.google.Chrome", "chrome.exe"]}
