"""PAT-852 / PAT-847: earlier catalogue retirements stay retired.

PAT-852 replaced the local-SQLite "Suggested" tab with a platform-backed
Approvals surface, and PAT-847 removed the dead PAT-794 mirror proxies and the
local catalogue_mirror_approvals store. PAT-2249 then retired the Approvals
surface and the catalogue review proxies themselves (see
test_pat2249_catalogue_pipeline_retired.py). What this file still guards:

  - The PAT-627 Suggested endpoints stay gone (404) and init_db() does not
    recreate catalogue_suggestions or catalogue_mirror_approvals.
  - The PAT-794 /admin/mirror/* proxies and the per-app mirror-approval route
    stay gone, with no _DESTRUCTIVE_RULES entries left behind.
  - _mirror_actor_email, which outlived all of them, is still present.
  - No render site builds an href straight from an escaped homepage value.
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


class TestHomepageHrefXssGuard:
    def test_no_unguarded_homepage_href_remains(self, console_html):
        # The vulnerable pattern (href built directly from an escaped-only
        # homepage value) must be gone from every render site.
        assert '_escHtml(p.homepage) + \'" target' not in console_html
        assert '_escHtml(a.homepage) + \'" target' not in console_html


# ── Suggested tab fully retired ──────────────────────────────────────────────

class TestSuggestedRetired:
    @pytest.mark.parametrize("method,path", [
        ("POST", "/admin/catalogue/suggestions/sync"),
        ("POST", "/admin/catalogue/suggestions/1/dismiss"),
        ("POST", "/admin/catalogue/suggestions/1/promote"),
        ("GET",  "/admin/catalogue/suggestions"),
    ])
    def test_suggestions_endpoints_gone(self, client, method, path):
        r = client.request(method, path, headers=BEARER)
        assert r.status_code == 404

    def test_catalogue_suggestions_table_not_created(self, client):
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='catalogue_suggestions'"
            ).fetchone()
        assert row is None

    def test_console_html_has_no_suggested_markup(self, console_html):
        assert 'id="cat-tab-suggested"' not in console_html
        assert 'id="cat-panel-suggested"' not in console_html
        assert 'id="modal-cat-promote"' not in console_html
        assert "_catSugg" not in console_html
        assert "_catPromote" not in console_html

    def test_console_html_has_no_old_mirror_only_tab(self, console_html):
        assert 'id="cat-tab-mirror"' not in console_html
        assert 'id="cat-panel-mirror"' not in console_html


# ── PAT-847: dead PAT-794 mirror proxies removed ─────────────────────────────

class TestMirrorProxiesRetired:
    @pytest.mark.parametrize("method,path", [
        ("GET",    "/admin/mirror/candidates"),
        ("GET",    "/admin/mirror/approved"),
        ("POST",   "/admin/mirror/approvals"),
        ("DELETE", "/admin/mirror/approvals/1"),
    ])
    def test_mirror_proxy_routes_gone(self, client, method, path):
        r = client.request(method, path, headers=BEARER)
        assert r.status_code == 404

    def test_mirror_routes_no_longer_registered_as_destructive(self):
        # The _DESTRUCTIVE_RULES entries for these routes must be gone too,
        # not just the route handlers — a stale regex entry matching nothing
        # is harmless but is a sign the removal was incomplete.
        assert not dashboard._is_destructive("POST", "/admin/mirror/approvals")
        assert not dashboard._is_destructive("DELETE", "/admin/mirror/approvals/1")

    def test_mirror_actor_email_helper_still_present(self):
        # _mirror_actor_email outlived the mirror proxies and the catalogue
        # review proxies (PAT-2249); the extension-removal queue and the
        # Homebrew review proxies still use it to stamp the authenticated
        # actor server-side.
        assert hasattr(dashboard, "_mirror_actor_email")


# ── PAT-847: vestigial local catalogue_mirror_approvals store removed ───────

class TestLocalMirrorApprovalsStoreRetired:
    def test_mirror_approval_put_route_gone(self, client):
        r = client.put(
            "/admin/catalogue/zoom/mirror-approval",
            headers=BEARER,
            json={"approved": True},
        )
        assert r.status_code == 404

    def test_catalogue_mirror_approvals_table_not_created(self, client):
        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='catalogue_mirror_approvals'"
            ).fetchone()
        assert row is None

    def test_console_html_has_no_eula_checkbox_ui(self, console_html):
        assert "_catalogueMirrorApproval" not in console_html
        assert "EULA approved" not in console_html
        assert "mirror-approval" not in console_html
