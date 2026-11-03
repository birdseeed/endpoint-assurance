"""Regression coverage for PAT-1148's Needs Attention screen retirement."""

import os
import re
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()
MAIN = (ROOT / "main.py").read_text()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def _function(name: str) -> str:
    start = TEMPLATE.index(f"function {name}(")
    brace = TEMPLATE.index("{", start)
    depth = 0
    for index in range(brace, len(TEMPLATE)):
        if TEMPLATE[index] == "{":
            depth += 1
        elif TEMPLATE[index] == "}":
            depth -= 1
            if depth == 0:
                return TEMPLATE[start:index + 1]
    raise AssertionError(f"unbalanced function {name}")


def test_needs_attention_navigation_and_panel_are_retired():
    nav_start = TEMPLATE.index('<nav class="cwf-nav" id="cwf-nav"')
    nav_end = TEMPLATE.index("\n        </nav>", nav_start)
    nav = TEMPLATE[nav_start:nav_end]
    assert 'data-tab="needs-attention"' not in nav
    assert ">Needs Attention<" not in nav
    assert 'id="tab-needs-attention"' not in TEMPLATE
    # PAT-1609 added a second, unrelated tab (disposition-queue) to the
    # devices workload -- subtabbar-devices now legitimately exists for that
    # reason, not for needs-attention, which stays retired.
    assert "'devices':        ['device-health', 'disposition-queue', 'device-lifecycle']" in TEMPLATE
    assert "'devices':        ['device-health', 'needs-attention']" not in TEMPLATE
    assert "const _SUBTABBAR_WORKLOADS = ['devices', 'software-governance', 'evidence', 'customer-setup'];" in TEMPLATE


def test_pat275_frontend_javascript_and_css_are_gone():
    for retired in (
        "NA_USE_MOCK", "NA_MOCK", "fetchNeedsAttention", "_naActivate",
        "_naRender", "_naRowHtml", "_naSevClass", "_naEsc", "_naTrackClick",
    ):
        assert retired not in TEMPLATE
    assert not re.search(r"(?m)^\.na-[a-z]", CSS)
    # New Apps uses the separate _nap* namespace and must survive the cleanup.
    assert "function _napActivate()" in TEMPLATE


def test_retired_tab_is_not_registered_or_dispatched():
    tabs_start = TEMPLATE.index("const _TENANT_TABS =")
    tabs_end = TEMPLATE.index(";", tabs_start)
    assert "needs-attention" not in TEMPLATE[tabs_start:tabs_end]
    activated = _function("_onTabActivated")
    assert "needs-attention" not in activated
    assert "_naActivate" not in activated


def test_enter_tenant_normalises_stale_deep_link_before_tab_validation():
    enter = _function("enterTenant")
    normalise = enter.index("if (tab === 'needs-attention') tab = 'device-health';")
    validate = enter.index("_TENANT_TABS.indexOf(tab)")
    assert normalise < validate
    # consoleNav writes the canonical active tab into the hash after normalisation.
    assert "consoleNav('tenant-workspace')" in enter


def test_tenant_tab_normalises_and_replaces_stale_hash():
    import subprocess

    switch = _function("tenantTab")
    normalise = switch.index("if (tab === 'needs-attention') tab = 'device-health';")
    validate = switch.index("_TENANT_TABS.indexOf(tab)")
    replace_hash = switch.index("PatchedConsoleShell.navigate(")
    assert normalise < validate < replace_hash
    assert "'/' + tab, true" in switch
    # Execute the actual tab handler and browser-loaded history helper, so
    # delegation cannot hide a stale alias or create a Back-loop entry.
    script = r"""
const assert = require('node:assert/strict');
const PatchedConsoleShell = require('./static/js/console-shell.js');
const PatchedConsoleGovernance = require('./static/js/console-governance.js');
const _consoleState = {tenantId: 'tenant one', tenantData: {}, activeTab: 'account'};
const _TENANT_TABS = ['account', 'device-health'];
const calls = [];
const history = {replaceState: (...args) => calls.push(args), pushState: () => assert.fail('Alias must replace history')};
const location = {hash: '#tenant/tenant%20one/needs-attention', pathname: '/console', search: '?view=1'};
const document = {getElementById: () => ({classList: {contains: () => true}})};
const _applyTenantTab = () => {};
const _onTabActivated = () => {};
""" + switch + r"""
tenantTab('needs-attention');
assert.equal(_consoleState.activeTab, 'device-health');
assert.deepEqual(calls, [[null, '', '/console?view=1#tenant/tenant%20one/device-health']]);
location.hash = '#tenant/tenant%20one/device-health';
tenantTab('needs-attention');
assert.equal(calls.length, 1);
tenantTab('invalid-tab');
assert.equal(calls.length, 1);
assert.equal(_consoleState.activeTab, 'device-health');
"""
    subprocess.run(["node", "-e", script], cwd=ROOT, check=True, capture_output=True, text=True)


def test_priorities_still_fetches_needs_attention_rollup():
    overview = _function("_ov2Load")
    assert "adminFetch('/admin/tenants/' + tid + '/needs-attention')" in overview
    # Existing Priorities drill targets are intentionally stale-compatible and
    # now flow through tenantTab's canonical device-health normalisation.
    assert "tab:'needs-attention'" in TEMPLATE


def test_home_rollup_and_proxy_remain_in_backend():
    assert 'f"{PATCHED_API_INTERNAL}/admin/tenants/{_seg(tid)}/needs-attention"' in MAIN
    assert '@app.get("/admin/tenants/{tenant_id}/needs-attention")' in MAIN
    assert "def proxy_tenant_needs_attention" in MAIN


def test_needs_attention_proxy_still_forwards_to_upstream(client, monkeypatch):
    class Upstream:
        status_code = 200
        content = b'{"summary":{"total":2}}'
        headers = {"content-type": "application/json"}

        @staticmethod
        def json():
            return {"summary": {"total": 2}}

    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen["params"] = kwargs.get("params")
        return Upstream()

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    response = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/needs-attention?limit=12",
        headers={"Authorization": "Bearer test-key"},
    )
    assert response.status_code == 200
    assert seen["url"].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/needs-attention")
    assert seen["params"] == {"limit": "12"}


def test_conversion_events_table_and_audit_source_are_preserved(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with sqlite3.connect(tmp_path / "test.db") as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(conversion_events)")}
    assert columns == {"id", "tenant_id", "event_name", "category", "severity", "recorded_at"}
    assert '"conversion_event", "conversion_events", "recorded_at"' in MAIN


def test_conversion_events_api_history_contract_is_preserved(client):
    response = client.post(
        "/admin/conversion-events",
        json={
            "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
            "event_name": "historical_upgrade_cta",
            "category": "vulnerable",
            "severity": "high",
        },
        headers={"Authorization": "Bearer test-key"},
    )
    assert response.status_code == 200
    assert "id" in response.json()


def test_conversion_event_validation_is_unchanged(client):
    response = client.post(
        "/admin/conversion-events",
        json={"event_name": "missing_tenant"},
        headers={"Authorization": "Bearer test-key"},
    )
    assert response.status_code == 400
