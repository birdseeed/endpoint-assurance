"""
Tests for PAT-2090 — portal user role (admin/viewer) surfaced on the Customer
Access tab, on top of the platform's PAT-2007 `portal_users.role` column and
its extended `POST /admin/portal-users` contract.

Scope: this dashboard proxies `role` through to the upstream go-service
upsert, allowlisting exactly `admin`/`viewer` before ever calling upstream,
and renders the role the upstream list returns (or "—" when an older
upstream row carries none). It does not implement the role model itself --
that lives entirely in the go-service (PAT-2007).

Covers:
  - POST /admin/tenants/{id}/portal-users forwards an optional role
  - an invalid role is rejected with 400 before any upstream call
  - portal-user writes remain owner-only (consultant denied)
  - the console renders a role for a user row
  - a missing/unrecognised role renders as "—", not a guess

Run with: pytest tests/test_pat2090_portal_user_role.py -v
"""

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

_AUTH = {"Authorization": "Bearer test-key"}


def _cookie(email):
    token = dashboard._session_encode(email, int(time.time()) + 3600)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


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


# No-conflict stand-in for the pre-create global lookup, matching test_pat128.py.
_NO_CONFLICT = _mock_upstream({"users": [], "total": 0})


# ── Proxy: POST forwards role ─────────────────────────────────────────────────

def test_create_forwards_role(client):
    captured = []

    def _fake_post(url, **kwargs):
        captured.append(kwargs.get("json"))
        return _mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                "role": "admin", "created_at": "2026-09-24T00:00:00Z",
                                "disabled_at": None}, status=201)

    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", side_effect=_fake_post):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "jane@client.com", "role": "admin"},
            headers=_AUTH,
        )

    assert r.status_code == 201
    assert captured[0] == {"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e", "role": "admin"}
    assert r.json()["role"] == "admin"


def test_create_without_role_does_not_add_the_key(client):
    # Omitted role must stay omitted going upstream -- the upstream upsert
    # treats "key absent" (defaults/keeps existing role) differently from an
    # explicit value, so this dashboard must not silently invent one.
    captured = []

    def _fake_post(url, **kwargs):
        captured.append(kwargs.get("json"))
        return _mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                "role": "viewer"}, status=201)

    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", side_effect=_fake_post):
        client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "jane@client.com"},
            headers=_AUTH,
        )

    assert "role" not in captured[0]


# ── Proxy: invalid role is refused before any upstream call ──────────────────

@pytest.mark.parametrize("bad_role", ["Admin", "superuser", "", 1, True, ["admin"]])
def test_create_rejects_invalid_role_without_calling_upstream(client, bad_role):
    post_mock = MagicMock()
    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", post_mock):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "jane@client.com", "role": bad_role},
            headers=_AUTH,
        )

    assert r.status_code == 400
    post_mock.assert_not_called()


def test_create_accepts_viewer_role(client):
    captured = []

    def _fake_post(url, **kwargs):
        captured.append(kwargs.get("json"))
        return _mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                "role": "viewer"}, status=201)

    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", side_effect=_fake_post):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "jane@client.com", "role": "viewer"},
            headers=_AUTH,
        )

    assert r.status_code == 201
    assert captured[0]["role"] == "viewer"


# ── RBAC: portal-user writes remain owner-only ────────────────────────────────

def test_role_change_route_is_still_owner_only():
    # Same POST route as grant/re-enable -- a role change is just another
    # upsert on it, so it must not be newly added to the consultant allow-list.
    assert not dashboard._consultant_write_allowed("POST", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/portal-users")


def test_consultant_is_denied_a_role_change(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    post_mock = MagicMock()
    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", post_mock):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "jane@client.com", "role": "admin"},
            headers=_cookie("consultant@patched.im"),
        )

    assert r.status_code == 403
    post_mock.assert_not_called()


# ── Console rendering ─────────────────────────────────────────────────────────

def test_role_selector_and_change_handler_present(console_html):
    assert 'id="ca-add-role"' in console_html
    assert 'value="viewer"' in console_html
    assert 'value="admin"' in console_html
    assert "function _caChangeRole" in console_html
    assert "onchange=\"_caChangeRole(this)\"" in console_html


def test_role_change_confirms_before_granting_admin(console_html):
    # The admin path must go through dangerConfirm, not a bare submit --
    # find the _caChangeRole function body and check it branches on it.
    start = console_html.index("function _caChangeRole")
    end = console_html.index("\n}", start)
    body = console_html[start:end]
    assert "dangerConfirm" in body
    assert "newRole !== 'admin'" in body or "newRole === 'admin'" in body


# The renderer itself is JS run in the browser; assert the source contract
# instead of executing it (matches this repo's console-JS testing style for
# non-behavioural template strings -- behavioural JS lives in static/js and
# is covered by npm run test:console).

def test_role_render_falls_back_to_em_dash_for_missing_role(console_html):
    start = console_html.index("function _caRender")
    end = console_html.index("\nfunction ", start + 1)
    body = console_html[start:end]
    assert "u.role === 'admin' || u.role === 'viewer'" in body
    # The repo-wide "no data" placeholder glyph (dozens of other call sites
    # use the same literal), not prose punctuation -- see roleLabel below.
    assert "roleLabel = role ? (role === 'admin' ? 'Admin' : 'Viewer') : '—'" in body


def test_role_not_offered_as_selector_on_a_disabled_row(console_html):
    # Re-posting the upsert with a new role also clears disabled_at upstream
    # (same upsert grant/re-enable uses) -- a disabled row must not expose the
    # selector, or changing role would silently re-enable that person.
    start = console_html.index("function _caRender")
    end = console_html.index("\nfunction ", start + 1)
    body = console_html[start:end]
    assert "!disabled && role" in body
