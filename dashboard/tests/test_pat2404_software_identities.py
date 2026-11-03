"""PAT-2404: Software identities screen, staff console half.

The console stores nothing: four proxies to the platform's
/admin/software-catalogue/* routes. Coverage:
  - each proxy forwards to the right platform path (the internal bearer is
    attached by _ApiSession, checked at that layer);
  - candidates require a known platform (400 without calling the platform);
  - both writes overwrite `actor` with the server-resolved staff email, drop
    unknown fields, and (retire) refuse a non-UUID id without a platform call;
  - a platform 4xx message reaches the client, a 5xx body never does;
  - both writes are in _DESTRUCTIVE_RULES, owner-only, and refused (and
    audited) for a consultant;
  - the screen is registered in the sidebar in alphabetical order.
"""

import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BEARER = {"Authorization": "Bearer test-key"}
ALIAS_ID = "3f0c1d2e-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
SECRET_UPSTREAM = "internal-stack-trace-do-not-reflect"


@pytest.fixture
def client(tmp_path, monkeypatch):
    # These owner-workflow fixtures name their privileged identities explicitly.
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


class _Resp:
    def __init__(self, status_code=200, body=None, text=None):
        self.status_code = status_code
        self._body = {} if body is None else body
        self.content = b"x"
        self.text = text if text is not None else str(self._body)

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _session(email):
    tok = dashboard._session_encode(email, int(time.time()) + 3600)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


REVIEW_BODY = {
    "platform": "macos",
    "identity_kind": "bundle_id",
    "identity_value_normalized": "com.example.app",
    "companion_value_normalized": "ABCDE12345",
    "canonical_name": "Example",
    "vendor_name": "Example Ltd",
    "reason": "Seen on three tenants",
}


# ── Reads ────────────────────────────────────────────────────────────────────

class TestReads:
    def test_candidates_forward_platform_query_limit(self, client, monkeypatch):
        seen = {}

        def fake_get(url, **kw):
            seen.update(url=url, params=kw.get("params"))
            return _Resp(200, {"candidates": []})

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        r = client.get(
            "/admin/software-catalogue/candidates?platform=windows&query=zoom&limit=50&evil=1",
            headers=BEARER,
        )
        assert r.status_code == 200
        assert seen["url"] == dashboard.PATCHED_API_INTERNAL + "/admin/software-catalogue/candidates"
        assert seen["params"] == {"platform": "windows", "query": "zoom", "limit": "50"}

    @pytest.mark.parametrize("qs", ["", "?platform=", "?platform=linux", "?query=x"])
    def test_candidates_require_known_platform(self, client, monkeypatch, qs):
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **k: pytest.fail("platform must not be called"),
        )
        r = client.get("/admin/software-catalogue/candidates" + qs, headers=BEARER)
        assert r.status_code == 400
        assert "platform" in r.json()["error"]

    def test_candidates_reject_non_numeric_limit(self, client, monkeypatch):
        monkeypatch.setattr(
            dashboard.http, "get",
            lambda *a, **k: pytest.fail("platform must not be called"),
        )
        r = client.get("/admin/software-catalogue/candidates?platform=macos&limit=abc", headers=BEARER)
        assert r.status_code == 400

    def test_aliases_forward(self, client, monkeypatch):
        seen = {}
        body = {"aliases": [{"alias_id": ALIAS_ID, "canonical_name": "Example", "retired_at": None}]}

        def fake_get(url, **kw):
            seen["url"] = url
            return _Resp(200, body)

        monkeypatch.setattr(dashboard.http, "get", fake_get)
        r = client.get("/admin/software-catalogue/aliases", headers=BEARER)
        assert r.status_code == 200
        assert r.json() == body
        assert seen["url"] == dashboard.PATCHED_API_INTERNAL + "/admin/software-catalogue/aliases"

    def test_reads_require_authentication(self, client):
        assert client.get("/admin/software-catalogue/aliases").status_code == 401
        assert client.get("/admin/software-catalogue/candidates?platform=macos").status_code == 401

    def test_internal_bearer_is_attached_on_the_platform_call(self, monkeypatch):
        """_ApiSession adds ADMIN_API_TOKEN to calls to PATCHED_API_INTERNAL."""
        monkeypatch.setattr(dashboard, "ADMIN_API_TOKEN", "internal-token")
        captured = {}

        def fake_request(self, method, url, *a, **kw):
            captured["headers"] = kw.get("headers")
            return _Resp(200, {"aliases": []})

        import requests
        monkeypatch.setattr(requests.Session, "request", fake_request)
        dashboard.http.get(dashboard.PATCHED_API_INTERNAL + "/admin/software-catalogue/aliases")
        assert captured["headers"]["Authorization"] == "Bearer internal-token"


# ── Writes ───────────────────────────────────────────────────────────────────

class TestReviewWrite:
    def test_actor_is_server_resolved_and_unknown_fields_dropped(self, client, monkeypatch):
        seen = {}

        def fake_post(url, **kw):
            seen.update(url=url, json=kw.get("json"))
            return _Resp(201, {"alias_id": ALIAS_ID})

        monkeypatch.setattr(dashboard.http, "post", fake_post)
        r = client.post(
            "/admin/software-catalogue/reviews",
            headers={**_session("owner@patched.im")},
            json={**REVIEW_BODY, "actor": "forged@evil.example", "installer_url": "http://x",
                  "label": "pkg", "tenant_id": "t1"},
        )
        assert r.status_code == 201
        assert seen["url"] == dashboard.PATCHED_API_INTERNAL + "/admin/software-catalogue/reviews"
        assert seen["json"] == {**REVIEW_BODY, "actor": "owner@patched.im"}

    def test_bearer_caller_gets_bearer_actor(self, client, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            dashboard.http, "post",
            lambda url, **kw: (seen.update(json=kw["json"]), _Resp(201, {}))[1],
        )
        client.post("/admin/software-catalogue/reviews", headers=BEARER, json={**REVIEW_BODY, "actor": "x"})
        assert seen["json"]["actor"] == "bearer-token"

    def test_non_object_body_is_400(self, client, monkeypatch):
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: pytest.fail("no platform call"))
        r = client.post("/admin/software-catalogue/reviews", headers=BEARER, json=["x"])
        assert r.status_code == 400

    @pytest.mark.parametrize("status,msg", [
        (422, "below the evidence bar"),
        (409, "already reviewed"),
        (404, "unknown candidate"),
        (400, "reason is required"),
    ])
    def test_platform_refusal_message_reaches_client(self, client, monkeypatch, status, msg):
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: _Resp(status, {"error": msg, "debug": "x"}))
        r = client.post("/admin/software-catalogue/reviews", headers=BEARER, json=REVIEW_BODY)
        assert r.status_code == status
        assert r.json() == {"error": msg}

    @pytest.mark.parametrize("resp", [
        _Resp(500, {"error": SECRET_UPSTREAM}),
        _Resp(503, {"error": "upstream unreachable", "degraded": True, "detail": SECRET_UPSTREAM}),
        _Resp(502, ValueError("not json"), text=SECRET_UPSTREAM),
    ])
    def test_platform_5xx_body_is_never_reflected(self, client, monkeypatch, resp):
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: resp)
        r = client.post("/admin/software-catalogue/reviews", headers=BEARER, json=REVIEW_BODY)
        assert r.status_code == 502
        assert SECRET_UPSTREAM not in r.text
        assert "detail" not in r.json()


class TestRetireWrite:
    def test_forwards_reason_with_server_actor_only(self, client, monkeypatch):
        seen = {}

        def fake_post(url, **kw):
            seen.update(url=url, json=kw.get("json"))
            return _Resp(200, {"alias_id": ALIAS_ID, "retired_at": "2026-10-04T10:00:00Z"})

        monkeypatch.setattr(dashboard.http, "post", fake_post)
        r = client.post(
            f"/admin/software-catalogue/aliases/{ALIAS_ID}/retire",
            headers=_session("owner@patched.im"),
            json={"reason": "Wrong vendor", "actor": "forged@evil.example", "canonical_name": "x"},
        )
        assert r.status_code == 200
        assert seen["url"] == (
            dashboard.PATCHED_API_INTERNAL + f"/admin/software-catalogue/aliases/{ALIAS_ID}/retire"
        )
        assert seen["json"] == {"reason": "Wrong vendor", "actor": "owner@patched.im"}

    @pytest.mark.parametrize("bad", ["not-a-uuid", "123", "..%2Fadmin", "{" + ALIAS_ID + "}",
                                     ALIAS_ID.replace("-", "")])
    def test_non_uuid_alias_id_refused_without_platform_call(self, client, monkeypatch, bad):
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: pytest.fail("no platform call"))
        r = client.post(f"/admin/software-catalogue/aliases/{bad}/retire", headers=BEARER, json={"reason": "x"})
        assert r.status_code in (400, 404)

    @pytest.mark.parametrize("status,msg", [(409, "already retired"), (404, "unknown alias"), (400, "reason is required")])
    def test_platform_refusal_message_reaches_client(self, client, monkeypatch, status, msg):
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: _Resp(status, {"error": msg}))
        r = client.post(f"/admin/software-catalogue/aliases/{ALIAS_ID}/retire", headers=BEARER, json={"reason": "x"})
        assert (r.status_code, r.json()) == (status, {"error": msg})

    def test_platform_5xx_body_is_never_reflected(self, client, monkeypatch):
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: _Resp(500, {"error": SECRET_UPSTREAM}))
        r = client.post(f"/admin/software-catalogue/aliases/{ALIAS_ID}/retire", headers=BEARER, json={"reason": "x"})
        assert r.status_code == 502
        assert SECRET_UPSTREAM not in r.text


# ── RBAC and audit ───────────────────────────────────────────────────────────

WRITES = [
    "/admin/software-catalogue/reviews",
    f"/admin/software-catalogue/aliases/{ALIAS_ID}/retire",
]


class TestRbac:
    @pytest.mark.parametrize("path", WRITES)
    def test_writes_are_destructive_logged_and_not_consultant_allowed(self, path):
        assert dashboard._is_destructive("POST", path)
        assert not dashboard._consultant_write_allowed("POST", path)

    @pytest.mark.parametrize("path", WRITES)
    def test_consultant_is_refused_audited_and_platform_not_called(self, client, monkeypatch, path):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: pytest.fail("no platform call"))
        r = client.post(path, headers=_session("consultant@patched.im"), json=REVIEW_BODY)
        assert r.status_code == 403
        with dashboard.get_db() as db:
            rows = db.execute("SELECT role, path, outcome FROM admin_audit_log").fetchall()
        assert any(x["outcome"] == "denied_rbac" and x["role"] == "consultant" and x["path"] == path for x in rows)

    def test_consultant_can_still_read(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        monkeypatch.setattr(dashboard.http, "get", lambda *a, **k: _Resp(200, {"aliases": []}))
        r = client.get("/admin/software-catalogue/aliases", headers=_session("consultant@patched.im"))
        assert r.status_code == 200

    def test_owner_write_is_audited(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        monkeypatch.setattr(dashboard.http, "post", lambda *a, **k: _Resp(201, {}))
        r = client.post(WRITES[0], headers=_session("owner@patched.im"), json=REVIEW_BODY)
        assert r.status_code == 201
        with dashboard.get_db() as db:
            rows = db.execute("SELECT actor_email, path FROM admin_audit_log").fetchall()
        assert any(x["path"] == WRITES[0] and x["actor_email"] == "owner@patched.im" for x in rows)


# ── Screen registration ──────────────────────────────────────────────────────

class TestScreen:
    def _html(self):
        return (REPO / "templates" / "console.html").read_text(encoding="utf-8")

    def test_sidebar_item_is_alphabetical_within_intelligence(self):
        html = self._html()
        start = html.index('id="nav-section-intelligence"')
        group = html[start:html.index("Customer workflow", start)]
        labels = re.findall(r'<a href="#" id="nav-[^"]+"[^>]*>([^<]+)</a>', group)
        assert labels == ["Homebrew review", "Software identities"]
        assert labels == sorted(labels, key=str.lower)

    def test_section_script_and_helpers_are_wired(self):
        html = self._html()
        assert 'id="section-software-identities"' in html
        assert "console-software-identities.js?v={{ console_build_id }}" in html
        assert "'software-identities'" in html
        assert "_swidLoad(false)" in html

    def test_screen_has_no_package_or_deployment_fields(self):
        html = self._html()
        start = html.index('id="section-software-identities"')
        block = html[start:html.index("PAT-2097: Unapproved software alerts", start)]
        block = re.sub(r"<!--.*?-->", "", block, flags=re.S)
        for word in ("installer", "package label", "deploy", "update workflow", "fleet", "—"):
            assert word not in block.lower()

    def test_module_never_assigns_innerhtml(self):
        src = (REPO / "static" / "js" / "console-software-identities.js").read_text(encoding="utf-8")
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith(("//", "*", "/*")))
        assert "innerHTML" not in code
        assert "insertAdjacentHTML" not in code

    def test_served_console_loads_the_module_with_current_build_id(self, client):
        r = client.get("/console", headers=BEARER, follow_redirects=True)
        assert r.status_code == 200
        assert f"/static/js/console-software-identities.js?v={dashboard.CONSOLE_BUILD_ID}" in r.text
        assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
