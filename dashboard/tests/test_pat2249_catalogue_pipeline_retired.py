"""PAT-2249: the catalogue review, hosting and discovery pipeline is retired.

Covers the dashboard half:
  - Every removed route (local Software Catalogue, PAT-960 hosting reviews and
    vendor outreach, the public supported-apps feed, the platform catalogue
    proxies, the dead PAT-660 tenant catalogue proxy and the PAT-1548
    execution-policy proxy) now answers 404 and never reaches patched-api-01.
  - None of them is still named in the audit, confirm or quarantine rule
    lists, so no dead rule claims to protect a route that no longer exists.
  - init_db() no longer creates the catalogue tables, and leaves a box's
    leftover tables and rows exactly as they were.
  - The console no longer ships the catalogue section, its modals, the
    execution-policy view or any call to a removed route.
  - _read_capped_json, which outlived the catalogue proxies, still enforces
    its size cap and JSON check for the proxies that use it.

PAT-2299 adds the leftovers that served only the retired path:
  - The quarantined ring-rollout create proxy is gone, along with its
    quarantine and audit rules, while the retained rollout evidence, recovery
    and ring proxies stay registered.
  - The console no longer ships the catalogue-only filter, the rollout-create
    and catalogue CSS, or a policy note waiting on a catalogue that will not
    land.
  - The nginx config no longer carries the /public/supported-apps.json block.
"""

import os
import re
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}
ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()

RETIRED_ADMIN_ROUTES = [
    ("GET", "/admin/catalogue"),
    ("PUT", "/admin/catalogue/zoom/mirrored"),
    ("POST", "/admin/catalogue/apps"),
    ("DELETE", "/admin/catalogue/apps/zoom"),
    ("POST", "/admin/catalogue/refresh"),
    ("GET", "/admin/catalogue/hosting-reviews"),
    ("GET", "/admin/catalogue/hosting-reviews/zoom"),
    ("PATCH", "/admin/catalogue/hosting-reviews/zoom"),
    ("POST", "/admin/catalogue/hosting-reviews/zoom/draft-email"),
    ("POST", "/admin/catalogue/hosting-reviews/draft-all"),
    ("POST", "/admin/catalogue/hosting-reviews/zoom/approve-email"),
    ("POST", "/admin/catalogue/hosting-reviews/zoom/send-email"),
    ("POST", "/admin/catalogue/hosting-replies/sync"),
    ("GET", "/admin/catalogue/products"),
    ("GET", "/admin/catalogue/candidates"),
    ("GET", "/admin/catalogue/target-operations"),
    ("POST", "/admin/catalogue/add"),
    ("POST", "/admin/catalogue/review"),
    ("POST", "/admin/catalogue/review/bulk"),
    ("POST", "/admin/catalogue/dismiss"),
    ("POST", "/admin/catalogue/revoke"),
    ("GET", "/admin/tenants/tenant-1/catalogue"),
    ("POST", "/admin/tenants/tenant-1/catalogue"),
    ("DELETE", "/admin/tenants/tenant-1/catalogue/pkg-1"),
    ("GET", "/admin/tenants/tenant-1/execution-policies"),
]

RETIRED_TABLES = (
    "catalogue_apps",
    "catalogue_hosting_reviews",
    "catalogue_hosting_events",
    "catalogue_hosting_messages",
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def _no_upstream(monkeypatch):
    for verb in ("get", "post", "put", "patch", "delete"):
        monkeypatch.setattr(
            dashboard.http, verb,
            lambda *_a, _verb=verb, **_k: pytest.fail(f"upstream {_verb.upper()} called"),
        )


@pytest.mark.parametrize(("method", "path"), RETIRED_ADMIN_ROUTES)
def test_retired_admin_routes_are_gone_and_never_reach_the_platform(client, monkeypatch, method, path):
    _no_upstream(monkeypatch)
    response = client.request(method, path, json={}, headers=BEARER)
    assert response.status_code == 404, (method, path, response.status_code)


def test_public_supported_apps_feed_is_gone(client, monkeypatch):
    _no_upstream(monkeypatch)
    assert client.get("/public/supported-apps.json").status_code == 404


def test_no_registered_route_serves_a_retired_path():
    registered = {
        (method, route.path)
        for route in dashboard.app.routes
        for method in getattr(route, "methods", set()) or set()
    }
    for method, path in registered:
        assert not path.startswith("/admin/catalogue"), (method, path)
        assert path != "/public/supported-apps.json"
        assert not path.endswith("/execution-policies"), (method, path)
        assert path not in {
            "/admin/tenants/{tenant_id}/catalogue",
            "/admin/tenants/{tenant_id}/catalogue/{package_id}",
        }


@pytest.mark.parametrize(("method", "path"), RETIRED_ADMIN_ROUTES)
def test_no_rule_list_still_names_a_retired_route(method, path):
    assert not dashboard._is_destructive(method, path)
    assert not dashboard._is_legacy_execution_quarantined(method, path)
    assert not dashboard._consultant_write_allowed(method, path)
    assert all(not (m == method and rx.match(path)) for (m, rx, _kind) in dashboard._CONFIRM_RULES)


def test_init_db_no_longer_creates_catalogue_tables(client):
    with dashboard.get_db() as db:
        present = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert present.isdisjoint(RETIRED_TABLES)


def test_init_db_leaves_leftover_catalogue_tables_and_rows_alone(tmp_path, monkeypatch):
    db_path = tmp_path / "leftover.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE catalogue_apps (label TEXT PRIMARY KEY, name TEXT NOT NULL)")
    conn.execute("INSERT INTO catalogue_apps (label, name) VALUES ('zoom', 'Zoom')")
    conn.execute(
        "CREATE TABLE catalogue_hosting_events (id TEXT PRIMARY KEY, label TEXT NOT NULL, "
        "event_type TEXT NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', "
        "created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO catalogue_hosting_events VALUES "
        "('e1', 'zoom', 'email_sent', 'owner@patched.im', '', '2026-07-20T11:00:00+00:00')"
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(shared, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    dashboard.init_db()
    dashboard.init_db()  # idempotent across restarts

    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT label, name FROM catalogue_apps").fetchall() == [("zoom", "Zoom")]
        assert conn.execute("SELECT id FROM catalogue_hosting_events").fetchall() == [("e1",)]
        columns = {row[1] for row in conn.execute("PRAGMA table_info(catalogue_apps)").fetchall()}
        assert columns == {"label", "name"}  # no ALTER TABLE migration ran against it
    finally:
        conn.close()


def test_logs_feed_no_longer_offers_catalogue_hosting():
    assert "catalogue_hosting" not in dashboard._LOG_SOURCES
    assert "'catalogue_hosting'" not in HTML
    assert "catalogue hosting" not in HTML


@pytest.mark.parametrize("marker", [
    'data-retired-surface="catalogue"',
    'data-retired-section="catalogue"',
    'id="modal-cat-review"',
    'id="cho-modal"',
    'id="sc-view-execution"',
    'id="sc-panel-execution"',
    "adminFetch('/admin/catalogue",
    "/execution-policies'",
    "function _catalogueLoad",
    "function _choLoad",
    "function _caprLoad",
    "function _ctopLoad",
    "function _sepLoad",
    "function _pdRolloutPromptFromButton",
])
def test_console_no_longer_ships_the_retired_surfaces(marker):
    assert marker not in HTML


def test_retired_catalogue_hash_still_lands_on_home():
    # An old bookmark to #catalogue must not resurrect anything.
    assert "const _QUARANTINED_SECTIONS = ['catalogue']" in HTML
    assert "if (_QUARANTINED_SECTIONS.indexOf(section) !== -1) section = 'home';" in HTML


def test_software_policy_keeps_its_three_governance_views():
    policy = HTML[HTML.index('id="tab-software-catalogue"'):HTML.index('<!-- /#tab-software-catalogue -->')]
    for view in ("sc-view-review", "sc-view-installed", "sc-view-drift"):
        assert f'id="{view}"' in policy
    assert "['review', 'installed', 'drift'].indexOf(view) === -1" in HTML


# ── PAT-2299: leftovers of the retired catalogue and rollout path ──────────────

CSS = (ROOT / "static" / "css" / "console.css").read_text()
NGINX = (ROOT / "deploy" / "nginx-dashboard.conf").read_text()
CONSOLE_JS = {p.name: p.read_text() for p in (ROOT / "static" / "js").glob("*.js")}

RING_ROLLOUTS_COLLECTION = "/admin/tenants/{tenant_id}/ring-rollouts"
RING_ROLLOUT_CREATE = ("POST", "/admin/tenants/tenant-1/ring-rollouts")

# The rollout evidence view still lists rollouts and offers pause, resume,
# skip and emergency. Ring config and ring devices feed the signed agent-config
# `ring` field, and removing them is a separate decision.
RETAINED_RING_ROUTES = [
    ("GET", RING_ROLLOUTS_COLLECTION),
    ("POST", "/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/pause"),
    ("POST", "/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/resume"),
    ("POST", "/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/skip"),
    ("POST", "/admin/tenants/{tenant_id}/ring-rollouts/{rollout_id}/emergency"),
    ("GET", "/admin/tenants/{tenant_id}/ring-config"),
    ("PUT", "/admin/tenants/{tenant_id}/ring-config"),
    ("GET", "/admin/tenants/{tenant_id}/ring-devices"),
    ("PUT", "/admin/tenants/{tenant_id}/ring-devices/{device_id}"),
]


def _registered_methods(path):
    return {
        method
        for route in dashboard.app.routes
        if getattr(route, "path", None) == path
        for method in (getattr(route, "methods", set()) or set())
    }


def test_ring_rollout_create_proxy_is_gone_and_never_reaches_the_platform(client, monkeypatch):
    _no_upstream(monkeypatch)
    method, path = RING_ROLLOUT_CREATE
    response = client.request(method, path, json={"reason": "test"}, headers=BEARER)
    # The collection path still answers GET for the evidence view, so routing
    # rejects the POST as 405 rather than 404. Before PAT-2299 this was the
    # quarantine 410 from a handler that still existed.
    assert response.status_code == 405, response.status_code
    assert "POST" not in _registered_methods(RING_ROLLOUTS_COLLECTION)


def test_no_rule_list_still_names_the_ring_rollout_create_route():
    method, path = RING_ROLLOUT_CREATE
    assert not dashboard._is_destructive(method, path)
    assert not dashboard._is_legacy_execution_quarantined(method, path)
    assert not dashboard._consultant_write_allowed(method, path)
    assert all(not (m == method and rx.match(path)) for (m, rx, _kind) in dashboard._CONFIRM_RULES)


@pytest.mark.parametrize(("method", "path"), RETAINED_RING_ROUTES)
def test_retained_rollout_and_ring_proxies_are_still_registered(method, path):
    assert method in _registered_methods(path), (method, path)


_CREATE_CALL = re.compile(r"""/ring-rollouts['"]\s*,\s*\{""")


def test_console_never_posts_to_the_ring_rollout_collection():
    # The retained list call passes no options. An options object on the bare
    # collection path would be a create call.
    assert "adminFetch('/admin/tenants/' + tid + '/ring-rollouts')," in HTML
    assert not _CREATE_CALL.search(HTML)
    for name, source in CONSOLE_JS.items():
        assert not _CREATE_CALL.search(source), name


def test_create_call_guard_would_catch_a_create_call():
    assert _CREATE_CALL.search("adminFetch('/admin/tenants/' + tid + '/ring-rollouts', {method:'POST'})")
    assert _CREATE_CALL.search('adminFetch("/admin/tenants/" + tid + "/ring-rollouts", { method: "POST" })')


@pytest.mark.parametrize("marker", [
    "function _scPassCatalogueFilter",
    ".catalogue-vendor-link",
    ".cat-tab",
])
def test_console_no_longer_ships_catalogue_only_code(marker):
    assert marker not in HTML


@pytest.mark.parametrize("selector", [
    ".as-cat-link",
    ".pd-start-rollout",
    ".pd-rollout-confirm",
    ".pd-rollout-contract-note",
])
def test_console_css_no_longer_styles_retired_catalogue_or_rollout_create_markup(selector):
    assert selector not in CSS


def test_software_policy_note_says_execution_is_retired():
    policy = HTML[HTML.index('id="tab-software-catalogue"'):HTML.index('<!-- /#tab-software-catalogue -->')]
    note = policy[policy.index('id="sc-catalogue-policy-note"'):]
    note = note[:note.index("</div>")]
    assert "Policy only, not endpoint execution." in note
    assert "The software execution path is retired. Patched records policy only." in note
    assert "catalogue" not in note.split(">", 1)[1].lower()
    assert "not yet available" not in note
    assert "—" not in note
    assert "PAT-" not in note


def test_nginx_no_longer_proxies_the_retired_supported_apps_feed():
    assert "supported-apps.json" not in NGINX
    # The rest of the edge contract is unchanged.
    assert "location /public/ {\n        return 301 https://scan.patched.im$request_uri;" in NGINX
    assert "location /static/ {" in NGINX
    assert "location / {\n        proxy_pass http://127.0.0.1:8000;" in NGINX


class _FakeResp:
    status_code = 200
    content = b"{}"
    text = "{}"

    def json(self):
        return {}


def test_capped_json_reader_still_rejects_an_oversized_body_before_upstream(client, monkeypatch):
    _no_upstream(monkeypatch)
    huge = b'{"cpe":"' + (b"x" * (dashboard.ADMIN_JSON_MAX_BODY_BYTES + 1)) + b'"}'
    response = client.post(
        "/admin/homebrew/review/r1/map",
        headers={**BEARER, "content-type": "application/json"},
        content=huge,
    )
    assert response.status_code == 413
    assert response.json() == {"error": "request body too large"}


def test_capped_json_reader_still_rejects_malformed_json_before_upstream(client, monkeypatch):
    _no_upstream(monkeypatch)
    response = client.post(
        "/admin/homebrew/review/r1/map",
        headers={**BEARER, "content-type": "application/json"},
        content=b"not json",
    )
    assert response.status_code == 400
    assert response.json() == {"error": "JSON body required"}


def test_capped_json_reader_still_forwards_a_valid_body(client, monkeypatch):
    captured = {}

    def _fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        return _FakeResp()

    monkeypatch.setattr(dashboard.http, "post", _fake_post)
    response = client.post("/admin/homebrew/review/r1/map", headers=BEARER, json={"cpe": "cpe:2.3:a:x:y"})
    assert response.status_code == 200
    assert captured["url"].endswith("/admin/homebrew/review/r1/map")
    assert captured["json"]["cpe"] == "cpe:2.3:a:x:y"
    assert captured["json"]["actor"] == "bearer-token"
