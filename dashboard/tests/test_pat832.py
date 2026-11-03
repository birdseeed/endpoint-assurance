"""
Tests for PAT-832 — browser-extension "Remove now" dashboard surface.

Covers:
  - Remove-now action + scope-selection modal + pending-removals panel wiring
    in the /console HTML, and the JS functions that drive them.
  - Three proxy routes forwarding to the Go admin API:
      GET    /extension-removals            (list pending)
      POST   /extension-removals            (queue a removal)
      DELETE /extension-removals/{id}        (cancel a pending request)
    including URL correctness, body/status propagation, and the server-side
    requested_by stamp (never client-supplied).

Run with: pytest tests/test_pat832.py -v
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

_LIST = {
    "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
    "requests": [
        {
            "id": 42,
            "browser": "chrome",
            "extension_id": "aaa",
            "scope": "one_profile",
            "user_account": "jsmith",
            "profile": "Default",
            "requested_by": "op@patched.im",
            "requested_at": "2026-07-11T00:00:00Z",
            "fulfilled": False,
        }
    ],
}


def _mock_upstream(payload, status=200):
    m = MagicMock()
    m.status_code = status
    m.content = json.dumps(payload).encode() if payload is not None else b""
    m.json.return_value = payload
    m.text = json.dumps(payload) if payload is not None else ""
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

def test_remove_now_action_present(console_html):
    assert "_bxRemoveOpen(" in console_html


def test_scope_modal_present(console_html):
    assert 'id="modal-bx-remove"' in console_html
    # The three truthful estate scopes are explicit. The redundant legacy
    # all_profiles alias remains accepted by the API but is not offered here.
    for scope in ("one_profile", "one_user", "all_devices"):
        assert 'value="%s"' % scope in console_html
    assert 'value="all_profiles"' not in console_html


def test_scope_not_defaulted(console_html):
    # No scope radio is pre-checked — the operator must choose one, and the
    # widest scope is never the default (PAT-773 blast-radius concern).
    start = console_html.index('id="modal-bx-remove"')
    modal = console_html[start:start + 2500]
    assert 'name="bx-remove-scope"' in modal
    assert "checked" not in modal


def test_pending_removals_panel_present(console_html):
    assert 'id="bx-removals"' in console_html
    assert 'id="bx-removals-list"' in console_html
    assert 'id="bx-removals-count"' in console_html


def test_remove_js_functions_present(console_html):
    for fn in ("_bxRemoveOpen", "_bxRemoveScopeChanged", "_bxRemoveValidate",
               "_bxRemoveSubmit", "_bxRemoveCancel", "_bxRenderRemovals",
               "_bxScopeLabel"):
        assert "function %s" % fn in console_html


def test_css_cache_bust_bumped(console_html):
    assert "console.css?v=" + dashboard.CONSOLE_BUILD_ID in console_html


# ── Proxy: GET /extension-removals (list pending) ─────────────────────────────

def test_list_proxies_upstream(client):
    with patch.object(dashboard.http, "get", return_value=_mock_upstream(_LIST)):
        r = client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals", headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["requests"][0]["id"] == 42


def test_list_url_targets_upstream(client):
    captured = []

    def _fake_get(url, **kwargs):
        captured.append(url)
        return _mock_upstream(_LIST)

    with patch.object(dashboard.http, "get", side_effect=_fake_get):
        client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals", headers=_AUTH)

    assert any("a5effb0c-c4c3-5d57-af50-5c7fd102599e" in u and u.endswith("/extension-removals") for u in captured)


# ── Proxy: POST /extension-removals (queue a removal) ─────────────────────────

def test_create_forwards_body_and_stamps_requested_by(client):
    captured = []

    def _fake_post(url, **kwargs):
        captured.append((url, kwargs.get("json")))
        return _mock_upstream({"id": 7}, status=201)

    payload = {"browser": "chrome", "extension_id": "aaa", "scope": "all_devices"}
    with patch.object(dashboard.http, "post", side_effect=_fake_post):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals",
            json=payload,
            headers=_AUTH,
        )

    assert r.status_code == 201
    url, body = captured[0]
    assert "a5effb0c-c4c3-5d57-af50-5c7fd102599e" in url and url.endswith("/extension-removals")
    assert body["browser"] == "chrome"
    assert body["scope"] == "all_devices"
    # requested_by is stamped server-side from the authenticated identity.
    assert body["requested_by"] == "bearer-token"


def test_create_requested_by_not_client_controlled(client):
    captured = []

    def _fake_post(url, **kwargs):
        captured.append(kwargs.get("json"))
        return _mock_upstream({"id": 8}, status=201)

    payload = {
        "browser": "edge",
        "extension_id": "bbb",
        "scope": "all_devices",
        "requested_by": "attacker@evil.example",
    }
    with patch.object(dashboard.http, "post", side_effect=_fake_post):
        client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals", json=payload, headers=_AUTH)

    assert captured[0]["requested_by"] == "bearer-token"


def test_create_propagates_conflict(client):
    with patch.object(dashboard.http, "post", return_value=_mock_upstream({"error": "dup"}, status=409)):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals",
            json={"browser": "chrome", "extension_id": "aaa", "scope": "all_devices"},
            headers=_AUTH,
        )
    assert r.status_code == 409


def test_create_propagates_bad_scope(client):
    with patch.object(dashboard.http, "post", return_value=_mock_upstream({"error": "bad"}, status=400)):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals",
            json={"browser": "chrome", "extension_id": "aaa", "scope": "one_profile"},
            headers=_AUTH,
        )
    assert r.status_code == 400


# ── Proxy: DELETE /extension-removals/{id} (cancel) ───────────────────────────

def test_cancel_forwards_and_propagates_204(client):
    captured = []

    def _fake_delete(url, **kwargs):
        captured.append(url)
        return _mock_upstream(None, status=204)

    with patch.object(dashboard.http, "delete", side_effect=_fake_delete):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals/42", headers=_AUTH)

    assert r.status_code == 204
    assert captured[0].endswith("/extension-removals/42")


def test_cancel_propagates_not_found(client):
    with patch.object(dashboard.http, "delete", return_value=_mock_upstream({"error": "gone"}, status=404)):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals/999", headers=_AUTH)
    assert r.status_code == 404


# ── Audit posture: removal is destructive → logged (queues file deletion) ─────

def test_removal_routes_are_destructive():
    # Both create and cancel must be in the audit-logged destructive set so the
    # actor (and any consultant RBAC denial) is recorded dashboard-side.
    assert dashboard._is_destructive("POST", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/extension-removals")
    assert dashboard._is_destructive("DELETE", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/extension-removals/7")


def test_removal_create_denied_for_consultant():
    # Not in the consultant write allow-list → owner-only.
    assert not dashboard._consultant_write_allowed("POST", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/extension-removals")
    assert not dashboard._consultant_write_allowed("DELETE", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/extension-removals/7")
