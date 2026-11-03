"""PAT-2097: staff console for the cross-tenant Unapproved-software alert
queue.

The platform (go-service, PAT-2097) added an operator queue over every
active tenant's Unapproved-software alerts:

  GET  /admin/software-alerts?status=open,acknowledged&tenant_id=<uuid>&limit=&offset=
  POST /admin/tenants/{tenantID}/software-alerts/{id}/acknowledge  {"note": "optional"}

(internal/handlers/software_alerts.go, internal/softwaregov/alert_views.go).
This dashboard adds a thin authenticated proxy (main.py, same shape as the
PAT-2046 Homebrew review proxies) and a console page (templates/console.html)
so staff can see what needs chasing and acknowledge it.

Coverage:
  - GET /admin/software-alerts forwards status/tenant_id/limit/offset query
    params unchanged to the platform.
  - POST .../software-alerts/{id}/acknowledge posts to the tenant/id in the
    path and forwards an optional note in the body.
  - Both routes require authentication (401 with no credential).
  - The acknowledge write is registered destructive/audit-logged and is
    owner-only (consultant denied).
  - The acknowledge write requires a JSON object body (400 on garbage).
  - Upstream 409 (already resolved) and 404 (unknown id) pass through with
    their body intact so the console can render a clear message from
    softwareAlertErr's "message" field, not just its short "error" code.
  - console.html: the nav link, section markup, filters and acknowledge
    modal exist; rows render tenant/product/device/status/age/acknowledged-by;
    the empty state says plainly there are no open alerts; filter values feed
    the query string; acknowledge posts the right tenant/id/note.
"""

import os
import sys
import time
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


def _cookie(email):
    token = dashboard._session_encode(email, int(time.time()) + 3600)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


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


def _extract_fn(text, name):
    start = text.index("function " + name + "(")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError("unbalanced braces for " + name)


class _FakeResp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.content = b"x"
        self.text = str(self._body)

    def json(self):
        return self._body


# ── GET /admin/software-alerts ───────────────────────────────────────────────

class TestListProxy:
    def test_forwards_query_params(self, client, monkeypatch):
        captured = {}
        page = {
            "generated_at": "2026-09-24T00:00:00Z", "total": 1, "limit": 50, "offset": 0,
            "returned": 1,
            "alerts": [{
                "id": 9, "tenant_id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "tenant_name": "Acme", "status": "open",
                "trigger": "observed",
                "product": {"type": "application", "product_key": "macos:com.acme.app:",
                             "name": "Acme App"},
                "policy": {"kind": "application", "id": 3},
                "device": {"device_id": "d-1", "hostname": "acme-mbp", "platform": "macos",
                            "last_seen": None},
                "notification_id": None, "raised_at": "2026-09-20T00:00:00Z",
                "status_changed_at": "2026-09-20T00:00:00Z", "acknowledged_at": None,
                "acknowledged_by": None, "resolved_at": None, "resolved_reason": None,
                "reopened_count": 0, "last_reopened_at": None,
                "open_since": "2026-09-20T00:00:00Z", "age_seconds": 345600,
            }],
        }

        def _fake_get(url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["timeout"] = kwargs.get("timeout")
            return _FakeResp(200, page)

        monkeypatch.setattr(dashboard.http, "get", _fake_get)
        r = client.get(
            "/admin/software-alerts?status=open,acknowledged&tenant_id=0a4c2c91-7412-575c-b544-dea3a596dd31&limit=50&offset=0",
            headers=BEARER,
        )
        assert r.status_code == 200
        assert r.json() == page
        assert captured["url"].endswith("/admin/software-alerts")
        assert captured["params"] == {
            "status": "open,acknowledged", "tenant_id": "0a4c2c91-7412-575c-b544-dea3a596dd31", "limit": "50", "offset": "0",
        }
        assert captured["timeout"] is not None

    def test_no_params_forwards_empty(self, client, monkeypatch):
        captured = {}

        def _fake_get(url, **kwargs):
            captured["params"] = kwargs.get("params")
            return _FakeResp(200, {"alerts": [], "total": 0})

        monkeypatch.setattr(dashboard.http, "get", _fake_get)
        r = client.get("/admin/software-alerts", headers=BEARER)
        assert r.status_code == 200
        assert captured["params"] == {}

    def test_requires_authentication(self, client):
        r = client.get("/admin/software-alerts")
        assert r.status_code == 401


# ── POST /admin/tenants/{id}/software-alerts/{id}/acknowledge ───────────────

class TestAcknowledgeProxy:
    def test_posts_correct_tenant_and_id_and_note(self, client, monkeypatch):
        captured = {}

        def _fake_post(url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json")
            captured["timeout"] = kwargs.get("timeout")
            return _FakeResp(200, {"changed": True, "id": 9, "status": "acknowledged"})

        monkeypatch.setattr(dashboard.http, "post", _fake_post)
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge",
            headers=BEARER,
            json={"note": "spoke to IT, replacing with the approved client"},
        )
        assert r.status_code == 200
        assert captured["url"].endswith("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge")
        assert captured["json"] == {"note": "spoke to IT, replacing with the approved client"}
        assert captured["timeout"] is not None

    def test_note_is_optional(self, client, monkeypatch):
        captured = {}

        def _fake_post(url, **kwargs):
            captured["json"] = kwargs.get("json")
            return _FakeResp(200, {"changed": True})

        monkeypatch.setattr(dashboard.http, "post", _fake_post)
        r = client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge", headers=BEARER, json={})
        assert r.status_code == 200
        assert captured["json"] == {}

    def test_requires_authentication(self, client):
        r = client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge", json={})
        assert r.status_code == 401

    def test_requires_json_object_body(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge",
            headers=BEARER,
            content=b"not json",
        )
        assert r.status_code == 400

    def test_consultant_denied(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        post_mock = MagicMock()
        monkeypatch.setattr(dashboard.http, "post", post_mock)
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge",
            json={},
            headers=_cookie("consultant@patched.im"),
        )
        assert r.status_code == 403
        post_mock.assert_not_called()


class TestAcknowledgeIsAuditedAndOwnerOnly:
    def test_route_registered_as_destructive(self):
        assert dashboard._is_destructive("POST", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge")

    def test_route_not_in_consultant_write_allowlist(self):
        assert not dashboard._consultant_write_allowed(
            "POST", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge"
        )


# ── Upstream errors pass through readably ────────────────────────────────────

class TestUpstreamErrorsPassThrough:
    def test_409_already_resolved_passes_through(self, client, monkeypatch):
        monkeypatch.setattr(
            dashboard.http, "post",
            lambda url, **kw: _FakeResp(409, {
                "error": "alert_resolved",
                "message": "this alert is resolved; it re-opens by itself if the software is found again",
            }),
        )
        r = client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/9/acknowledge", headers=BEARER, json={})
        assert r.status_code == 409
        assert r.json()["error"] == "alert_resolved"
        assert "re-opens by itself" in r.json()["message"]

    def test_404_unknown_id_passes_through(self, client, monkeypatch):
        monkeypatch.setattr(
            dashboard.http, "post",
            lambda url, **kw: _FakeResp(404, {"error": "not_found", "message": "alert not found"}),
        )
        r = client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/software-alerts/999/acknowledge", headers=BEARER, json={})
        assert r.status_code == 404
        assert r.json()["message"] == "alert not found"


# ── console.html: nav + page markup ──────────────────────────────────────────

class TestConsoleMarkupPresent:
    def test_nav_link_present(self, console_html):
        assert 'id="nav-software-alerts"' in console_html
        assert "consoleNav('software-alerts')" in console_html

    def test_section_and_table_present(self, console_html):
        assert 'id="section-software-alerts"' in console_html
        assert 'id="swa-tbody"' in console_html
        assert 'id="swa-status-filter"' in console_html
        assert 'id="swa-tenant-filter"' in console_html

    def test_ack_modal_present(self, console_html):
        assert 'id="modal-swa-ack"' in console_html
        assert 'id="swa-ack-note"' in console_html
        assert 'id="swa-ack-save"' in console_html

    def test_section_registered_in_nav_tables(self, console_html):
        assert "'software-alerts'" in console_html
        fn = _extract_fn(console_html, "consoleNav")
        assert "_swaLoad" in fn

    def test_empty_state_says_no_open_alerts(self, console_html):
        # Static markup default (before any filter narrows it) and the
        # equivalent JS-rendered wording both say plainly there are none.
        assert "No open alerts." in console_html


# ── Row rendering ─────────────────────────────────────────────────────────────

class TestRowRendering:
    def test_row_renderer_includes_every_required_field(self, console_html):
        fn = _extract_fn(console_html, "_swaRowHtml")
        assert "r.tenant_name" in fn
        assert "product" in fn
        assert "device" in fn
        assert "_swaStatusBadge(r.status)" in fn
        assert "_swaAgeText(r.age_seconds)" in fn
        assert "_swaAckByText(r)" in fn

    def test_acknowledge_action_only_offered_for_open_rows(self, console_html):
        fn = _extract_fn(console_html, "_swaRowHtml")
        assert "r.status === 'open'" in fn
        assert "_swaOpenAck" in fn


# ── Filters feed the request ─────────────────────────────────────────────────

class TestFiltersFeedTheRequest:
    def test_build_params_reads_status_and_tenant_filters(self, console_html):
        fn = _extract_fn(console_html, "_swaBuildParams")
        assert "swa-status-filter" in fn
        assert "swa-tenant-filter" in fn
        assert "params.set('status'" in fn
        assert "params.set('tenant_id'" in fn
        assert "params.set('limit'" in fn
        assert "params.set('offset'" in fn

    def test_status_filter_change_forces_a_reload(self, console_html):
        assert "id=\"swa-status-filter\" onchange=\"_swaLoad(true)\"" in console_html
        assert "id=\"swa-tenant-filter\" onchange=\"_swaLoad(true)\"" in console_html


# ── Acknowledge submit posts the right tenant/id/note ────────────────────────

class TestAckSubmit:
    def test_submit_posts_to_the_target_tenant_and_id_with_the_typed_note(self, console_html):
        fn = _extract_fn(console_html, "_swaAckSubmit")
        assert "alert.tenant_id" in fn
        assert "alert.id" in fn
        assert "/software-alerts/" in fn
        assert "/acknowledge" in fn
        assert "body.note = note" in fn

    def test_error_text_prefers_message_field_over_error_code(self, console_html):
        fn = _extract_fn(console_html, "_swaAckErrorText")
        assert "parsed.message" in fn
