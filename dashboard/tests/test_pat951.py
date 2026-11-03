"""Regression coverage for PAT-951 console design-audit remediation."""

import os
import sys
from datetime import datetime, timezone

import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.content = b"x"

    def json(self):
        return self._payload


def _console_html():
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "console.html")
    with open(path, encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(shared, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def test_reusable_empty_state_covers_leads_and_infrastructure():
    html = _console_html()
    assert "function _emptyStateHtml(" in html
    assert "No Calendly leads yet." in html
    assert 'id="leads-empty" class="shared-empty-state"' in html
    assert "No infrastructure telemetry is available yet." in html
    assert "Infrastructure data could not be loaded." in html
    assert 'id="ops-empty"' in html


def test_console_css_cache_bust_is_current(client):
    # PAT-967: the query is rendered from CONSOLE_BUILD_ID, so assert against the
    # rendered page (the raw template now holds the Jinja placeholder).
    r = client.get("/console")
    assert r.status_code == 200
    assert "console.css?v=" + dashboard.CONSOLE_BUILD_ID in r.text


def test_theme_js_cache_bust_is_current(client):
    # PAT-966/967: theme.js runs the stale-console redirect using its OWN
    # CONSOLE_BUILD_ID; if this <script> query is stale a browser keeps a cached
    # older theme.js whose build-id disagrees with the server, and the two loop
    # endlessly (/console/<old> <-> /console/<new>) — the page flashes / never
    # loads. It's now rendered from CONSOLE_BUILD_ID so it can't drift; assert the
    # rendered page carries the current build-id.
    r = client.get("/console")
    assert r.status_code == 200
    assert "theme.js?v=" + dashboard.CONSOLE_BUILD_ID in r.text


def test_billing_uses_overview_name_and_keeps_tenant_id(client, monkeypatch):
    tenant_id = "5c048e12-1111-2222-3333-444444444444"
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at) VALUES (?,?,?,?)",
            ("client-1", tenant_id, tenant_id, datetime.now(timezone.utc).isoformat()),
        )

    monkeypatch.setattr(
        dashboard.http,
        "get",
        lambda *args, **kwargs: _FakeResp(
            {"tenants": [{"id": tenant_id, "name": "Resolved Customer", "device_count": 4}]}
        ),
    )

    response = client.get("/admin/billing/summary", headers=BEARER)
    assert response.status_code == 200
    row = response.json()["rows"][0]
    assert row["company"] == "Resolved Customer"
    assert row["tenant_id"] == tenant_id


def test_surgical_console_design_fixes_are_present():
    html = _console_html()
    # PAT-1009: the single-open nav-group accordion this used to protect
    # (_initNavAccordions/`other.open = false`) was retired — both sidebars
    # now share one always-expanded .nav-section structure with no
    # <details>/<summary> disclosure left to accordion between.
    assert "bill-customer-id" in html
    assert "home-health-dot ' + dotCls" in html
    assert "&#9989;" not in html
    assert "&#128308;" not in html
    assert 'class="cred-delete-btn owner-only"' in html
    assert "confirmWord: name" in html


def test_customers_adopts_shared_table_pattern():
    html = _console_html()
    assert 'class="page-header data-table-page-header"' in html
    assert 'id="cl-search"' in html
    assert "function _clApplyFilters(" in html
    assert 'class="data-table-shell cl-table-shell"' in html
    assert 'class="data-table-scroll cl-table-wrap"' in html
    assert 'class="data-table cl-table"' in html
    assert "No customers match these filters." in html

    css_path = os.path.join(os.path.dirname(__file__), "..", "static", "css", "console.css")
    with open(css_path, encoding="utf-8") as handle:
        css = handle.read()
    assert ".data-table-page-header" in css
    assert ".data-table thead th" in css
    assert "position: sticky" in css
    assert "@media (max-width: 1180px)" in css
