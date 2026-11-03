"""
Tests for PAT-402 CVE Findings tab (frontend slice).

The tenant-workspace tabs are client-side JS rendered into templates/console.html
(no JS test runner in this repo), so — in the same shape as the other tab work —
these assert the /console template ships the new tab fully wired: nav button,
panel, tab registration, the PAT-402 API contract, and the feature-flagged mock.

Run with: pytest tests/test_cve_findings_tab.py -v
"""

import os
import sys

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
    # /console is not under /api/* so the bearer middleware does not guard it;
    # CF Access handles it at the edge in production.
    r = client.get("/console")
    assert r.status_code == 200
    return r.text


# ── Nav + panel wiring ────────────────────────────────────────────────────────

def test_cve_findings_reachable_via_compliance_subtab(console_html):
    # PAT-961: CVE Findings no longer has its own top-level sidebar button — CIS,
    # Compliance and CVE merged under the "Compliance & CVEs" destination and CVE
    # is reached through the shared CIS / Compliance / CVE sub-tab bar. tenantTab
    # routing (and the panel) are unchanged.
    assert "tenantTab('cve-findings')" in console_html
    assert ">CVE Findings<" in console_html
    assert 'class="subtab-nav cc-subtab-nav"' in console_html


def test_cve_findings_panel_present(console_html):
    assert 'id="tab-cve-findings"' in console_html
    # Existing tabs are still present.
    for existing in (
        "cis-controls", "software-metering", "compliance-status",
        "device-health", "browser-extensions",
    ):
        assert 'data-tab="%s"' % existing in console_html


def test_cve_findings_registered_in_tab_list_and_dispatch(console_html):
    # Registered in _TENANT_TABS (drives hash routing + panel toggling)…
    assert "'cis-controls', 'compliance-status', 'cve-findings'" in console_html
    # …and dispatched on activation.
    assert "if (tab === 'cve-findings')" in console_html
    assert "_cveActivate()" in console_html


# ── Default list view: columns, sort, filters ────────────────────────────────

def test_cve_list_columns_and_sortable_headers(console_html):
    # Columns from the spec.
    for col in ("CVE", "Severity (CVSS)", "Affected Devices", "First Seen", "Most Recent Seen"):
        assert col in console_html
    # Sortable on severity / affected count / first-seen.
    assert "_cveSortBy('severity')" in console_html
    assert "_cveSortBy('affected')" in console_html
    assert "_cveSortBy('first_seen')" in console_html


def test_cve_list_filters(console_html):
    assert 'data-minsev="critical"' in console_html      # severity ≥ X
    assert 'data-os="macOS"' in console_html              # OS family
    assert 'data-os="Windows"' in console_html
    assert 'data-patch="yes"' in console_html             # has-patch-available
    assert "_cveFilterMinSev(" in console_html
    assert "_cveFilterOs(" in console_html
    assert "_cveFilterPatch(" in console_html


# ── Drill panel + device routing ─────────────────────────────────────────────

def test_cve_drill_panel_and_device_columns(console_html):
    assert 'id="cve-detail"' in console_html
    assert "_cveOpenDetail(" in console_html
    assert "_cveCloseDetail()" in console_html
    for col in ("Installed Version", "Agent Last Seen"):
        assert col in console_html
    # Clicking a device routes to the existing device-detail page.
    assert "consoleNav('device-detail'" in console_html


# ── Empty state (positive, not an error) + pagination ────────────────────────

def test_cve_empty_state_is_positive(console_html):
    assert 'id="cve-empty"' in console_html
    assert "no known vulnerabilities detected" in console_html


def test_cve_pagination_present(console_html):
    assert 'id="cve-pagination"' in console_html
    assert "_cvePage(-1)" in console_html
    assert "_cvePage(1)" in console_html


# ── API contract + feature-flagged mock ──────────────────────────────────────

def test_cve_api_contract_paths(console_html):
    assert "/admin/tenants/' + tenantId + '/cve-findings'" in console_html
    assert "/cve-findings/' +" in console_html and "'/devices'" in console_html


def test_cve_findings_live_path(console_html):
    # PAT-698 removed the CVE_FINDINGS_USE_MOCK scaffolding; the fetch helpers now
    # hit adminFetch directly (live path) and the mock machinery is gone.
    assert "fetchTenantCveFindings" in console_html
    assert "fetchTenantCveDevices" in console_html
    assert "CVE_FINDINGS_USE_MOCK" not in console_html
    assert "_cveMockList" not in console_html
    assert "_cveMockDevices" not in console_html
    assert 'id="cve-mock-banner"' not in console_html
