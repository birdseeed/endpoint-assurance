"""PAT-2046: staff console form for the Homebrew CVE mapping review queue.

Unmapped/auto-seeded Homebrew formulae and casks land in the platform's
global, tenant-free homebrew_cpe_review_queue (PAT-2023). This dashboard adds
a thin authenticated proxy (main.py, same PAT-852 catalogue-review shape) and
a console page (templates/console.html) so staff can map, accept a suggested
mapping, or dismiss a row without a migration.

Coverage:
  - GET /admin/homebrew/review proxies to PATCHED_API_INTERNAL and forwards
    status/kind/sort query params unchanged.
  - POST .../{id}/map, .../accept-suggestion, .../dismiss all inject the
    server-resolved actor unconditionally (a client-supplied "actor" is
    overridden, never merely defaulted) and forward the rest of the body.
  - The three write routes are registered as destructive/audit-logged.
  - Every route requires authentication (401 with no credential), matching
    every other /admin/* proxy in this file.
  - Upstream 400/409 errors pass through with their body intact so
    adminErrorText() on the console can render them.
  - console.html: the nav link and page markup exist; homepage/source_url
    are rendered as plain escaped text only — _hbrRowHtml never builds an
    <a href> from them, so a hostile javascript:/`<script>` value can never
    become executable or a live link in the authenticated console.
  - Accept-suggestion's confirmation logic requires confirm_conflict when
    metadata_conflict is set and confirm_single_reporter when
    reporting_tenant_count < 2, and sends the corresponding flag(s) only
    when needed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


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


# ── GET /admin/homebrew/review ───────────────────────────────────────────────

class TestListProxy:
    def test_forwards_query_params_and_body(self, client, monkeypatch):
        captured = {}
        reviews = {"reviews": [{"id": "r1", "name": "wget", "package_kind": "formula"}]}

        def _fake_get(url, **kwargs):
            captured["url"] = url
            captured["params"] = kwargs.get("params")
            captured["timeout"] = kwargs.get("timeout")
            return _FakeResp(200, reviews)

        monkeypatch.setattr(dashboard.http, "get", _fake_get)
        r = client.get("/admin/homebrew/review?status=pending&kind=formula&sort=prevalence", headers=BEARER)
        assert r.status_code == 200
        assert r.json() == reviews
        assert captured["url"].endswith("/admin/homebrew/review")
        assert captured["params"] == {"status": "pending", "kind": "formula", "sort": "prevalence"}
        assert captured["timeout"] is not None

    def test_requires_authentication(self, client):
        r = client.get("/admin/homebrew/review")
        assert r.status_code == 401


# ── Write proxies inject the server-resolved actor ──────────────────────────

class TestWriteProxiesInjectActor:
    def test_map_injects_actor_and_forwards_body(self, client, monkeypatch):
        captured = {}

        def _fake_post(url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json")
            captured["timeout"] = kwargs.get("timeout")
            return _FakeResp(200, {"review": {"id": "r1", "status": "mapped"}})

        monkeypatch.setattr(dashboard.http, "post", _fake_post)
        r = client.post(
            "/admin/homebrew/review/r1/map",
            headers=BEARER,
            json={"cpe_vendor": "gnu", "cpe_product": "wget", "actor": "someone-untrusted@evil.example"},
        )
        assert r.status_code == 200
        assert captured["url"].endswith("/admin/homebrew/review/r1/map")
        assert captured["json"]["cpe_vendor"] == "gnu"
        assert captured["json"]["cpe_product"] == "wget"
        # Server-resolved actor always wins -- the client-forged value is
        # dropped entirely, not merely defaulted.
        assert captured["json"]["actor"] == "bearer-token"
        assert captured["timeout"] is not None

    def test_accept_suggestion_injects_actor_and_forwards_confirm_flags(self, client, monkeypatch):
        captured = {}

        def _fake_post(url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json")
            return _FakeResp(200, {"review": {"id": "r1", "status": "mapped"}})

        monkeypatch.setattr(dashboard.http, "post", _fake_post)
        r = client.post(
            "/admin/homebrew/review/r1/accept-suggestion",
            headers=BEARER,
            json={"confirm_conflict": True, "confirm_single_reporter": True},
        )
        assert r.status_code == 200
        assert captured["url"].endswith("/admin/homebrew/review/r1/accept-suggestion")
        assert captured["json"]["confirm_conflict"] is True
        assert captured["json"]["confirm_single_reporter"] is True
        assert captured["json"]["actor"] == "bearer-token"

    def test_dismiss_injects_actor(self, client, monkeypatch):
        captured = {}

        def _fake_post(url, **kwargs):
            captured["json"] = kwargs.get("json")
            return _FakeResp(200, {"review": {"id": "r1", "status": "dismissed"}})

        monkeypatch.setattr(dashboard.http, "post", _fake_post)
        r = client.post("/admin/homebrew/review/r1/dismiss", headers=BEARER, json={})
        assert r.status_code == 200
        assert captured["json"]["actor"] == "bearer-token"

    @pytest.mark.parametrize("path", [
        "/admin/homebrew/review/r1/map",
        "/admin/homebrew/review/r1/accept-suggestion",
        "/admin/homebrew/review/r1/dismiss",
    ])
    def test_requires_authentication(self, client, path):
        r = client.post(path, json={})
        assert r.status_code == 401

    @pytest.mark.parametrize("path", [
        "/admin/homebrew/review/r1/map",
        "/admin/homebrew/review/r1/accept-suggestion",
        "/admin/homebrew/review/r1/dismiss",
    ])
    def test_write_routes_require_json_object_body(self, client, path):
        r = client.post(path, headers=BEARER, content=b"not json")
        assert r.status_code == 400


class TestWriteProxiesAreAudited:
    def test_write_routes_registered_as_destructive(self):
        assert dashboard._is_destructive("POST", "/admin/homebrew/review/r1/map")
        assert dashboard._is_destructive("POST", "/admin/homebrew/review/r1/accept-suggestion")
        assert dashboard._is_destructive("POST", "/admin/homebrew/review/r1/dismiss")


# ── Upstream errors pass through readably ────────────────────────────────────

class TestUpstreamErrorsPassThrough:
    def test_map_409_row_not_pending_passes_through(self, client, monkeypatch):
        monkeypatch.setattr(
            dashboard.http, "post",
            lambda url, **kw: _FakeResp(409, {"error": "row is not pending"}),
        )
        r = client.post(
            "/admin/homebrew/review/r1/map",
            headers=BEARER,
            json={"cpe_vendor": "gnu", "cpe_product": "wget"},
        )
        assert r.status_code == 409
        assert r.json()["error"] == "row is not pending"

    def test_accept_suggestion_400_unknown_key_passes_through(self, client, monkeypatch):
        monkeypatch.setattr(
            dashboard.http, "post",
            lambda url, **kw: _FakeResp(400, {"error": "unknown CPE key"}),
        )
        r = client.post("/admin/homebrew/review/r1/accept-suggestion", headers=BEARER, json={})
        assert r.status_code == 400
        assert r.json()["error"] == "unknown CPE key"


# ── console.html: nav + page markup ──────────────────────────────────────────

class TestConsoleMarkupPresent:
    def test_nav_link_present(self, console_html):
        assert 'id="nav-homebrew-review"' in console_html
        assert "consoleNav('homebrew-review')" in console_html

    def test_section_and_table_present(self, console_html):
        assert 'id="section-homebrew-review"' in console_html
        assert 'id="hbr-tbody"' in console_html
        assert 'id="hbr-status-filter"' in console_html
        assert 'id="hbr-kind-filter"' in console_html
        assert 'id="hbr-sort"' in console_html

    def test_map_and_accept_modals_present(self, console_html):
        assert 'id="modal-hbr-map"' in console_html
        assert 'id="hbr-map-vendor"' in console_html
        assert 'id="hbr-map-product"' in console_html
        assert 'id="modal-hbr-accept"' in console_html
        assert 'id="hbr-accept-confirm-conflict"' in console_html
        assert 'id="hbr-accept-confirm-single"' in console_html

    def test_section_registered_in_nav_tables(self, console_html):
        assert "'homebrew-review'" in console_html
        fn = _extract_fn(console_html, "consoleNav")
        # the dispatch line that loads the page on navigation
        assert "_hbrLoad" in console_html


# ── Homepage/source_url: plain escaped text only, never a link ──────────────

class TestHomepageAndSourceUrlNeverLinked:
    def test_row_renderer_never_builds_an_anchor(self, console_html):
        fn = _extract_fn(console_html, "_hbrRowHtml")
        assert "<a href" not in fn
        assert "_escHtml(r.homepage)" in fn
        assert "_escHtml(r.source_url)" in fn

    def test_row_renderer_does_not_fetch_the_urls(self, console_html):
        fn = _extract_fn(console_html, "_hbrRowHtml")
        assert "fetch(" not in fn


# ── Accept-suggestion confirmation gating (client-side mirror of the
# platform's 409 gates) ──────────────────────────────────────────────────────

class TestAcceptSuggestionConfirmationGating:
    def test_open_accept_shows_conflict_row_when_metadata_conflict(self, console_html):
        fn = _extract_fn(console_html, "_hbrOpenAccept")
        assert "review.metadata_conflict" in fn
        assert "hbr-accept-conflict-row" in fn

    def test_open_accept_shows_single_reporter_row_below_two_tenants(self, console_html):
        fn = _extract_fn(console_html, "_hbrOpenAccept")
        assert "reporting_tenant_count" in fn
        assert "< 2" in fn
        assert "hbr-accept-single-row" in fn

    def test_submit_refuses_without_required_checkbox(self, console_html):
        fn = _extract_fn(console_html, "_hbrAcceptSubmit")
        assert "needsConflict && !confirmConflict" in fn
        assert "needsSingle && !confirmSingle" in fn

    def test_submit_only_sends_flags_that_are_needed(self, console_html):
        fn = _extract_fn(console_html, "_hbrAcceptSubmit")
        assert "body.confirm_conflict = true" in fn
        assert "body.confirm_single_reporter = true" in fn
