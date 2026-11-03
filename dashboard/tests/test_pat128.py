"""
Tests for PAT-128 — Customer Access tab: view/invite/revoke portal users for a
tenant, on top of the already-existing go-service admin CRUD for
`portal_users` (PAT-693, `internal/handlers/portal_users.go`).

Scope note: this ticket was narrowed after investigation found most of the
backend (auth via Cloudflare Access + `portal_users` mapping, admin CRUD,
`portal_access_log` audit) already shipped under PAT-693. What was missing —
and what this covers — is a dashboard UI + proxy routes over that existing
API, wired through the existing destructive-write audit middleware. No new
auth/session/role system, no new audit table.

Covers:
  - Tab wiring in the console HTML (nav link, panel, JS functions).
  - GET  /admin/tenants/{id}/portal-users            — list, tenant-scoped query param
  - POST /admin/tenants/{id}/portal-users            — grant/invite (and re-enable),
    tenant_id always taken from the URL path, never a client-supplied body value
  - DELETE /admin/tenants/{id}/portal-users/{email}  — revoke, gated on a
    membership check so tenant A can't disable a tenant B user
  - Destructive-write classification + RBAC (owner-only) + audit-log wiring,
    matching the PAT-799/PAT-832/PAT-833 audit conventions.

Run with: pytest tests/test_pat128.py -v
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


def _audit_rows(cols="*"):
    with dashboard.get_db() as db:
        return [dict(r) for r in db.execute(f"SELECT {cols} FROM admin_audit_log").fetchall()]


# ── Tab wiring in the console HTML ────────────────────────────────────────────

def test_nav_link_present(console_html):
    assert 'data-tab="customer-access"' in console_html
    assert "tenantTab('customer-access')" in console_html


def test_tab_panel_present(console_html):
    assert 'id="tab-customer-access"' in console_html
    assert 'id="ca-tbody"' in console_html


def test_grant_form_present(console_html):
    assert 'id="ca-add-email"' in console_html
    assert "_caGrantAccess()" in console_html


def test_js_functions_present(console_html):
    for fn in ("_caActivate", "_caLoad", "_caRender", "_caGrantAccess", "_caRevoke", "_caReenable"):
        assert "function %s" % fn in console_html


def test_render_passes_email_via_data_attribute_not_inline_js_string(console_html):
    # _esc() (used to build these rows) doesn't escape single quotes, and RFC
    # 5322 allows an apostrophe in a local-part (o'brien@...). Interpolating
    # the email directly into onclick="_caRevoke('...')" would let such an
    # email break out of the JS string literal. Row actions must instead read
    # it off a data-email attribute (this.dataset.email), which only needs
    # the escaping _esc() already provides for a double-quoted HTML attribute.
    assert "data-email=" in console_html
    assert "_caRevoke(this.dataset.email)" in console_html
    assert "_caReenable(this.dataset.email)" in console_html
    assert "_caRevoke('" not in console_html
    assert "_caReenable('" not in console_html


def test_copy_does_not_imply_an_email_is_sent(console_html):
    # Real risk: an operator reading this tab could assume "grant access"
    # triggers a customer-facing invite email. It doesn't -- CF Access identity
    # provisioning is a separate manual step. Assert the tab copy says so.
    start = console_html.index('id="tab-customer-access"')
    end = console_html.index("<!-- /#tab-customer-access -->")
    panel = console_html[start:end]
    assert "does not send" in panel
    assert "manual" in panel
    # Guard against copy regressing to imply an automatic send.
    assert "an email will be sent" not in panel.lower()


# ── Proxy: GET list (tenant-scoped) ───────────────────────────────────────────

def test_list_proxies_upstream_with_tenant_filter(client):
    # NOTE: dashboard.http is patched process-wide, and a background scheduler
    # thread also calls it independently of this request -- filter for our
    # own call rather than assuming captured[0] is it (matches the same
    # precaution test_pat832.py's test_list_url_targets_upstream takes).
    captured = []

    def _fake_get(url, **kwargs):
        captured.append((url, kwargs.get("params")))
        return _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                           "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}],
                                "total": 1})

    with patch.object(dashboard.http, "get", side_effect=_fake_get):
        r = client.get("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", headers=_AUTH)

    assert r.status_code == 200
    assert r.json()["users"][0]["email"] == "jane@client.com"
    matches = [(u, p) for (u, p) in captured if u.endswith("/admin/portal-users")]
    assert len(matches) == 1, f"expected exactly one matching call, got {captured}"
    url, params = matches[0]
    assert params == {"tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}


# ── Proxy: POST create/invite (grant / re-enable) ─────────────────────────────

# No-conflict stand-in for the pre-create global lookup (_portal_user_current_tenant)
# -- an empty global user list means "not mapped anywhere yet", so the create
# proceeds without the 409 conflict path.
_NO_CONFLICT = _mock_upstream({"users": [], "total": 0})


def test_create_forwards_email_and_path_tenant_id(client):
    captured = []

    def _fake_post(url, **kwargs):
        captured.append((url, kwargs.get("json")))
        return _mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                "created_at": "2026-07-12T00:00:00Z", "disabled_at": None}, status=201)

    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", side_effect=_fake_post):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "Jane@Client.com"},
            headers=_AUTH,
        )

    assert r.status_code == 201
    url, body = captured[0]
    assert url.endswith("/admin/portal-users")
    assert body == {"email": "Jane@Client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}


def test_create_ignores_client_supplied_tenant_id(client):
    # Cross-tenant safety: a body tenant_id must never override the URL path's
    # tenant_id -- the dashboard proxy doesn't even read it out of the body.
    captured = []

    def _fake_post(url, **kwargs):
        captured.append(kwargs.get("json"))
        return _mock_upstream({"email": "x@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}, status=201)

    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post", side_effect=_fake_post):
        client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "x@client.com", "tenant_id": "tenant-OTHER"},
            headers=_AUTH,
        )

    assert captured[0]["tenant_id"] == "a5effb0c-c4c3-5d57-af50-5c7fd102599e"


def test_create_requires_email(client):
    r = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={}, headers=_AUTH)
    assert r.status_code == 400


def test_create_reinvite_is_idempotent_reenable(client):
    # Matches the underlying go-service API's documented upsert behaviour:
    # re-POSTing an already-mapped email re-enables it. The dashboard proxy
    # just forwards this -- no extra state of its own to go stale. The
    # "current tenant" pre-check sees the row already under tenant-abc on the
    # second call, so no conflict is raised for a same-tenant re-invite.
    get_responses = [
        _NO_CONFLICT,
        _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}], "total": 1}),
    ]
    post_responses = [
        _mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                         "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}, status=201),
        _mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                         "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}, status=201),
    ]

    with patch.object(dashboard.http, "get", side_effect=get_responses), \
         patch.object(dashboard.http, "post", side_effect=post_responses):
        r1 = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={"email": "jane@client.com"}, headers=_AUTH)
        r2 = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={"email": "jane@client.com"}, headers=_AUTH)

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r2.json()["disabled_at"] is None


# ── Cross-tenant safety: grant/invite conflict (moving an email between tenants) ──

def test_create_blocks_silent_move_from_another_tenant(client):
    # The email is currently active under tenant-OTHER. Granting it here
    # (tenant-abc) would silently move it per the upstream upsert semantics --
    # must 409 instead of proceeding, and must NOT call the upstream POST.
    conflict_list = _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "tenant-OTHER",
                                                "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}],
                                     "total": 1})
    post_mock = MagicMock()
    with patch.object(dashboard.http, "get", return_value=conflict_list), \
         patch.object(dashboard.http, "post", post_mock):
        r = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={"email": "jane@client.com"}, headers=_AUTH)

    assert r.status_code == 409
    assert r.json()["current_tenant_id"] == "tenant-OTHER"
    post_mock.assert_not_called()


def test_create_force_true_proceeds_despite_conflict(client):
    # Operator has seen the 409 and deliberately wants to move the email --
    # force=true bypasses the pre-check and lets the upsert through.
    conflict_list = _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "tenant-OTHER"}],
                                     "total": 1})
    post_mock = MagicMock(return_value=_mock_upstream(
        {"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}, status=201))
    with patch.object(dashboard.http, "get", return_value=conflict_list), \
         patch.object(dashboard.http, "post", post_mock):
        r = client.post(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users",
            json={"email": "jane@client.com", "force": True},
            headers=_AUTH,
        )

    assert r.status_code == 201
    post_mock.assert_called_once()


def test_create_no_conflict_when_same_tenant(client):
    # Email is already mapped to THIS tenant (e.g. re-enabling a disabled row)
    # -- not a cross-tenant move, so no 409 even without force=true.
    same_tenant_list = _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}],
                                        "total": 1})
    with patch.object(dashboard.http, "get", return_value=same_tenant_list), \
         patch.object(dashboard.http, "post", return_value=_mock_upstream(
             {"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}, status=201)):
        r = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={"email": "jane@client.com"}, headers=_AUTH)

    assert r.status_code == 201


def test_create_conflict_check_fails_open_on_upstream_error(client):
    # The pre-check is advisory, not a security boundary (the real safety
    # property -- tenant_id never comes from the client -- holds regardless).
    # If the global lookup itself fails, don't block a legitimate grant.
    with patch.object(dashboard.http, "get", return_value=_mock_upstream({"error": "boom"}, status=500)), \
         patch.object(dashboard.http, "post", return_value=_mock_upstream(
             {"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}, status=201)):
        r = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={"email": "jane@client.com"}, headers=_AUTH)

    assert r.status_code == 201


# ── Proxy: DELETE revoke, gated on tenant membership ──────────────────────────

def test_revoke_calls_upstream_when_email_belongs_to_tenant(client):
    list_resp = _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                            "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}],
                                 "total": 1})
    delete_calls = []

    def _fake_delete(url, **kwargs):
        delete_calls.append(url)
        return _mock_upstream({"email": "jane@client.com", "disabled_at": "2026-07-12T00:00:00Z"})

    with patch.object(dashboard.http, "get", return_value=list_resp), \
         patch.object(dashboard.http, "delete", side_effect=_fake_delete):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/jane@client.com", headers=_AUTH)

    assert r.status_code == 200
    assert len(delete_calls) == 1
    # The email is URL-quoted (including '@' -> %40) when building the
    # outbound path segment -- see test_revoke_quotes_email_in_upstream_url
    # for why ('?'/'#'/'&' must never be read as query-string/fragment).
    assert delete_calls[0].endswith("/admin/portal-users/jane%40client.com")


def test_revoke_rejects_email_belonging_to_a_different_tenant(client):
    # Cross-tenant check: tenant-abc's list doesn't include this email (it's
    # actually tenant-other's user) -- the dashboard must 404 WITHOUT ever
    # calling the upstream (tenant-unaware) disable endpoint.
    list_resp = _mock_upstream({"users": [], "total": 0})
    delete_mock = MagicMock()

    with patch.object(dashboard.http, "get", return_value=list_resp), \
         patch.object(dashboard.http, "delete", delete_mock):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/bob@other-tenant.com", headers=_AUTH)

    assert r.status_code == 404
    delete_mock.assert_not_called()


def test_revoke_membership_check_is_case_insensitive(client):
    list_resp = _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                            "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}],
                                 "total": 1})
    with patch.object(dashboard.http, "get", return_value=list_resp), \
         patch.object(dashboard.http, "delete", return_value=_mock_upstream({"email": "jane@client.com"})):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/Jane@Client.com", headers=_AUTH)
    assert r.status_code == 200


def test_revoke_fails_closed_on_upstream_list_error(client):
    # Upstream failure (couldn't even check membership) is distinct from a
    # genuine "not this tenant's user" -- 502, not 404, so an operator can
    # tell "go-service is down" apart from "wrong tenant/typo".
    delete_mock = MagicMock()
    with patch.object(dashboard.http, "get", return_value=_mock_upstream({"error": "boom"}, status=500)), \
         patch.object(dashboard.http, "delete", delete_mock):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/jane@client.com", headers=_AUTH)
    assert r.status_code == 502
    delete_mock.assert_not_called()


def test_revoke_quotes_email_in_upstream_url(client):
    # An RFC-5322-legal (if unusual) local part containing '?' must not be
    # read as the start of a query string by the outbound request -- it has
    # to survive as a literal path segment all the way to the go-service.
    list_resp = _mock_upstream({"users": [{"email": "a?b@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                            "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}],
                                 "total": 1})
    delete_calls = []

    def _fake_delete(url, **kwargs):
        delete_calls.append(url)
        return _mock_upstream({"email": "a?b@client.com"})

    with patch.object(dashboard.http, "get", return_value=list_resp), \
         patch.object(dashboard.http, "delete", side_effect=_fake_delete):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/a%3Fb@client.com", headers=_AUTH)

    assert r.status_code == 200
    assert delete_calls[0].endswith("/admin/portal-users/a%3Fb%40client.com")


# ── Destructive classification + RBAC ─────────────────────────────────────────

def test_invite_and_revoke_routes_are_destructive():
    assert dashboard._is_destructive("POST", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/portal-users")
    assert dashboard._is_destructive("DELETE", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/portal-users/jane@client.com")


def test_invite_and_revoke_are_owner_only():
    # Not in the consultant write allow-list -- granting/revoking portal access
    # is high-blast-radius enough to default to owner-only, matching the
    # extension-removals (PAT-832) precedent.
    assert not dashboard._consultant_write_allowed("POST", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/portal-users")
    assert not dashboard._consultant_write_allowed("DELETE", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/portal-users/jane@client.com")


def test_list_is_not_classified_destructive():
    # A read should never show up in the destructive/audit set.
    assert not dashboard._is_destructive("GET", "/admin/tenants/22854930-d664-5dc3-a278-372b48002d00/portal-users")


# ── Audit logging — reuse of the existing PAT-695/799/833 middleware ─────────

def test_invite_produces_admin_audit_log_row(client):
    with patch.object(dashboard.http, "get", return_value=_NO_CONFLICT), \
         patch.object(dashboard.http, "post",
                       return_value=_mock_upstream({"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e"}, status=201)):
        r = client.post("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users", json={"email": "jane@client.com"}, headers=_AUTH)
    assert r.status_code == 201

    rows = _audit_rows("path, method, outcome")
    matches = [x for x in rows if x["path"] == "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users"]
    assert len(matches) == 1
    assert matches[0]["method"] == "POST"
    assert matches[0]["outcome"] == "allowed"


def test_revoke_produces_admin_audit_log_row(client):
    list_resp = _mock_upstream({"users": [{"email": "jane@client.com", "tenant_id": "a5effb0c-c4c3-5d57-af50-5c7fd102599e",
                                            "created_at": "2026-07-01T00:00:00Z", "disabled_at": None}],
                                 "total": 1})
    with patch.object(dashboard.http, "get", return_value=list_resp), \
         patch.object(dashboard.http, "delete", return_value=_mock_upstream({"email": "jane@client.com"})):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/jane@client.com", headers=_AUTH)
    assert r.status_code == 200

    rows = _audit_rows("path, method, outcome")
    matches = [x for x in rows if x["path"] == "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/jane@client.com"]
    assert len(matches) == 1
    assert matches[0]["method"] == "DELETE"
    assert matches[0]["outcome"] == "allowed"


def test_revoke_rejected_membership_check_is_still_audited(client):
    # Even the fail-closed 404 (email not in this tenant) is a "write attempt"
    # worth a trail -- matches the audit middleware writing a pre-dispatch row
    # for every destructive-classified request regardless of outcome.
    list_resp = _mock_upstream({"users": [], "total": 0})
    with patch.object(dashboard.http, "get", return_value=list_resp):
        r = client.delete("/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/bob@other-tenant.com", headers=_AUTH)
    assert r.status_code == 404

    rows = _audit_rows("path, method, outcome")
    matches = [x for x in rows if x["path"] == "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/portal-users/bob@other-tenant.com"]
    assert len(matches) == 1
    assert matches[0]["outcome"] == "rejected_404"
