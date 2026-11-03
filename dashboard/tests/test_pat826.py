"""
Tests for PAT-826 — per-tenant browser-extension approve/unapprove policy.

Covers:
  - Browser Extensions tab wiring in /console HTML: Policy + Actions columns,
    policy summary chips, and the policy-aware JS functions.
  - Four proxy routes forwarding to the Go admin API:
      GET  /extension-policies/scan
      GET  /extension-policies
      POST /extension-policies
      PUT  /extension-policies/{entry_id}
    with mocked upstream responses (URL correctness, body forwarding, status
    propagation). There is deliberately no DELETE proxy — the tab has no
    removal action (policy plane only).

Run with: pytest tests/test_pat826.py -v
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test-key"}

_SCAN = {
    "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
    "generated_at": "2026-07-11T00:00:00Z",
    "summary": {
        "total_fleet_extensions": 2,
        "approved": 1,
        "unapproved": 0,
        "ignored": 0,
        "unreviewed": 1,
    },
    "extensions": [
        {
            "browser": "chrome",
            "extension_id": "aaa",
            "name": "uBlock Origin",
            "risk_level": "low",
            "device_count": 3,
            "last_seen": "2026-07-10T00:00:00Z",
            "status": "approved",
            "entry_id": 7,
        },
        {
            "browser": "edge",
            "extension_id": "bbb",
            "name": "Some Extension",
            "risk_level": "high",
            "device_count": 1,
            "last_seen": "2026-07-10T00:00:00Z",
            "status": "unreviewed",
            "entry_id": None,
        },
    ],
}

_LIST = {
    "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
    "entries": [
        {
            "id": 7,
            "browser": "chrome",
            "extension_id": "aaa",
            "name": "uBlock Origin",
            "publisher": None,
            "webstore_id": None,
            "policy": "approved",
            "approved_by": "",
            "notes": "keep it",
            "created_at": "2026-07-01T00:00:00Z",
            "updated_at": "2026-07-01T00:00:00Z",
        }
    ],
}


def _mock_upstream(payload, status=200):
    m = MagicMock()
    m.status_code = status
    m.content = json.dumps(payload).encode()
    m.json.return_value = payload
    m.text = json.dumps(payload)
    return m


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


@pytest.fixture
def console_html(client):
    r = client.get("/console")
    assert r.status_code == 200
    return r.text


# ── Tab wiring in the console HTML ────────────────────────────────────────────

def test_browser_extensions_tab_still_present(console_html):
    assert 'id="tab-browser-extensions"' in console_html
    assert 'data-tab="browser-extensions"' in console_html


def test_policy_and_actions_columns_present(console_html):
    assert "<th>Decision</th>" in console_html
    assert ">Review</th>" in console_html


def test_policy_summary_chips_present(console_html):
    for pid in ("bx-pol-unapproved", "bx-pol-unreviewed"):
        assert 'id="%s"' % pid in console_html


def test_policy_js_functions_present(console_html):
    # PAT-1170 split the tab into review/inventory/restriction/removal pieces;
    # these are the live renderer + policy-modal functions that back it now
    # (the pre-split _bx{SetPolicy,ActionsHtml,...} renderers were deleted as
    # dead code under PAT-1198 — they had zero call sites).
    for fn in ("_bxLoad", "_bxMerge", "_bxRenderRows", "_bxPolicyChip", "_bxPolicyOpen", "_bxPolicySubmit"):
        assert "function %s" % fn in console_html


def test_policy_actions_call_scan_and_crud(console_html):
    assert "/extension-policies/scan" in console_html
    assert "_bxPolicySubmit(" in console_html
    # The explicit decision dialog supports all three policy states.
    assert "Approve" in console_html
    assert "Restrict" in console_html
    assert "Ignore" in console_html


def test_css_cache_bust_bumped(console_html):
    assert "console.css?v=" + dashboard.CONSOLE_BUILD_ID in console_html


# ── Proxy: GET /extension-policies/scan ───────────────────────────────────────

def test_scan_proxies_upstream(client):
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_SCAN)):
        r = client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies/scan", headers=_AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["approved"] == 1
    assert data["extensions"][0]["entry_id"] == 7


def test_scan_url_targets_upstream(client):
    captured = []

    def _fake_get(url, **kwargs):
        captured.append(url)
        return _mock_upstream(_SCAN)

    with patch.object(dashboard.http, "get", side_effect=_fake_get):
        client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies/scan", headers=_AUTH)

    assert any("a5effb0c-c4c3-5d57-af50-5c7fd102599e" in u and u.endswith("/extension-policies/scan") for u in captured)


# ── Proxy: GET /extension-policies (list) ─────────────────────────────────────

def test_list_proxies_upstream(client):
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_LIST)):
        r = client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies", headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["entries"][0]["notes"] == "keep it"


# ── Proxy: POST /extension-policies (create) ──────────────────────────────────

def test_create_forwards_body(client):
    captured = []

    def _fake_post(url, **kwargs):
        captured.append((url, kwargs.get("data")))
        return _mock_upstream({"id": 9, "policy": "approved"}, status=201)

    payload = {"browser": "edge", "extension_id": "bbb", "name": "Some Extension", "policy": "approved"}
    with patch.object(dashboard.http, "post", side_effect=_fake_post):
        r = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies", json=payload, headers=_AUTH)

    assert r.status_code == 201
    url, body = captured[0]
    assert "a5effb0c-c4c3-5d57-af50-5c7fd102599e" in url and url.endswith("/extension-policies")
    assert json.loads(body) == payload


def test_create_propagates_conflict(client):
    with patch.object(dashboard.http, "post", return_value=_mock_upstream({"error": "exists"}, status=409)):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies",
            json={"extension_id": "bbb", "policy": "approved"},
            headers=_AUTH,
        )
    assert r.status_code == 409


# ── Proxy: PUT /extension-policies/{entry_id} (update) ────────────────────────

def test_update_forwards_body_and_entry_id(client):
    captured = []

    def _fake_put(url, **kwargs):
        captured.append((url, kwargs.get("data")))
        return _mock_upstream({}, status=204)

    payload = {"policy": "unapproved", "notes": "keep it"}
    with patch.object(dashboard.http, "put", side_effect=_fake_put):
        r = client.put("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies/7", json=payload, headers=_AUTH)

    assert r.status_code == 204
    url, body = captured[0]
    assert url.endswith("/extension-policies/7")
    assert json.loads(body) == payload


def test_no_delete_proxy_registered(client):
    # Policy plane only — a DELETE on an entry must not be a real route.
    with patch.object(dashboard.http, "delete", return_value=_mock_upstream({}, status=204)):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-policies/7", headers=_AUTH)
    assert r.status_code == 405
