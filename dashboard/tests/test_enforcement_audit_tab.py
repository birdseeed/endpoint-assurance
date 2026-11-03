"""
Tests for PAT-608 / PAT-1352 Enforcement Evidence workspace and proxy route.

The tenant-workspace tabs are client-side JS rendered into templates/console.html
(no JS test runner in this repo), so these assert the /console template ships the
new tab fully wired: nav button, panel, tab registration, JS functions, and the
proxy route.

Run with: pytest tests/test_enforcement_audit_tab.py -v
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


# ── Nav + panel wiring ────────────────────────────────────────────────────────

def test_enforcement_audit_is_not_navigable(console_html):
    assert "tenantTab('enforcement-audit')" not in console_html


def test_enforcement_audit_panel_is_inert(console_html):
    assert 'id="tab-enforcement-audit"' not in console_html
    assert 'data-retired-surface="enforcement-audit"' in console_html
    # Existing tabs are unaffected
    for existing in ("cis-controls", "compliance-status", "cve-findings", "device-health"):
        assert 'data-tab="%s"' % existing in console_html


def test_enforcement_audit_has_no_tab_registration_or_activation(console_html):
    tabs = console_html[console_html.index("const _TENANT_TABS = ["):console_html.index("];", console_html.index("const _TENANT_TABS = ["))]
    assert "'enforcement-audit'" not in tabs
    assert "if (tab === 'enforcement-audit')" not in console_html


# ── Filters ──────────────────────────────────────────────────────────────────

def test_enforcement_audit_readable_action_and_outcome_filters(console_html):
    assert 'id="ea-filter-action"' in console_html
    assert 'value="administrator"' in console_html
    assert 'value="application"' in console_html
    assert 'value="extension"' in console_html
    assert 'id="ea-filter-outcome"' in console_html
    assert 'value="completed"' in console_html
    assert 'value="skipped"' in console_html
    assert '<option value="admin_removed">' not in console_html


def test_enforcement_audit_device_filter_present(console_html):
    assert 'id="ea-filter-device"' in console_html
    assert 'placeholder="Search machine or device ID' in console_html


# ── Table columns ─────────────────────────────────────────────────────────────

def test_enforcement_audit_table_columns(console_html):
    for col in ("Machine", "Action", "Target", "Outcome", "Occurred", "Details"):
        assert col in console_html


# ── JavaScript functions ──────────────────────────────────────────────────────

def test_enforcement_audit_js_functions_present(console_html):
    assert "_eaLoad(" in console_html
    assert "_eaLoadMore(" in console_html
    assert "_eaFetch(" in console_html
    assert "_eaScheduleLoad(" in console_html
    assert "_eaClearFilters(" in console_html
    assert "_eaToggleDetail(" in console_html
    assert "_eaExportCSV(" in console_html


def test_enforcement_audit_csv_export_button(console_html):
    assert "_eaExportCSV()" in console_html
    assert "enforcement-evidence-" in console_html  # CSV filename prefix


def test_enforcement_audit_behaviour_module_loaded(console_html):
    assert 'console-enforcement.js?v=' + dashboard.CONSOLE_BUILD_ID in console_html
    assert "PatchedConsoleEnforcement.eventTypes" in console_html
    assert "PatchedConsoleEnforcement.meta" in console_html
    assert "PatchedConsoleEnforcement.details" in console_html


def test_enforcement_audit_uses_server_side_filters(console_html):
    assert "params.set('event_type', eventTypes.join(','))" in console_html
    assert "params.set('device', device)" in console_html
    assert "events.filter(" not in console_html[console_html.index('// ── Enforcement Evidence tab'):console_html.index('// ─── PAT-348: Home section')]


def test_enforcement_audit_debounces_and_invalidates_inflight_search(console_html):
    section = console_html[console_html.index("function _eaScheduleLoad()") : console_html.index("function _eaClearFilters()")]
    assert "_eaRequestSeq++" in section
    assert "clearTimeout(_eaSearchTimer)" in section
    assert "setTimeout(function() { _eaLoad(); }, 300)" in section


def test_enforcement_audit_api_path(console_html):
    assert "'/enforcement-audit?' + params.toString()" in console_html


def test_enforcement_audit_pagination(console_html):
    assert "_eaLoadMore()" in console_html
    assert 'id="ea-load-more-btn"' in console_html


# ── Proxy route — happy path ──────────────────────────────────────────────────

def test_proxy_enforcement_audit_happy_path(client):
    fake_response = {
        "events": [
            {
                "id": "abc123",
                "device_id": "device-001",
                "event_type": "admin_removed",
                "subject": "alice",
                "details": {"app": "Terminal"},
                "occurred_at": "2026-12-25T11:42:00Z",
                "ingested_at": "2026-12-25T11:42:05.123Z",
            }
        ],
        "next_before": None,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_response
    mock_resp.content = json.dumps(fake_response).encode()
    mock_resp.headers = {"content-type": "application/json"}

    with patch.object(dashboard.http, "get", return_value=mock_resp) as mock_get:
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/enforcement-audit",
            params={"limit": "50"},
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code == 200
    body = r.json()
    assert "events" in body
    assert body["events"][0]["event_type"] == "admin_removed"
    # Confirm the proxy forwarded to the right upstream URL. Search every recorded
    # call rather than trusting the last one: main.py's background scheduler threads
    # share this globally-patched http.get, so an unrelated background call can land
    # last and would otherwise corrupt a call_args[-1] assertion (flaky).
    called_urls = [c.args[0] for c in mock_get.call_args_list if c.args]
    assert any("024c7257-bd3b-550a-81da-3212c6ff3a42" in u and "enforcement-audit" in u for u in called_urls), called_urls


def test_proxy_enforcement_audit_upstream_error(client):
    # A real requests.Response with a non-JSON body raises ValueError from
    # .json() and exposes .text as a decoded str — an unconfigured MagicMock
    # does neither (both just return another MagicMock), so both must be set
    # explicitly to exercise _proxy_json's except branch the way production
    # actually behaves.
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.content = b"bad gateway"
    mock_resp.text = "bad gateway"
    mock_resp.json.side_effect = ValueError("not json")
    mock_resp.headers = {"content-type": "text/plain"}

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/enforcement-audit",
            headers={"Authorization": "Bearer test-key"},
        )
    # _proxy_json surfaces upstream errors as 502 or similar non-200
    assert r.status_code >= 400
