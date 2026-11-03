"""
PAT-1606 — Console slice 3: tenant overview (KPI strip, coverage card,
what-changed placeholder, top findings). docs/design/console-redesign/
02-tenant-overview.html + 08-empty-states.html panels 2/3.

console.html ships one hash-routed SPA with no JS test runner in this repo
(see AGENTS.md), so — same convention as test_pat1554_coverage_gap.py and
test_pat1320_metering_collection_health.py — the client-side pieces are
asserted structurally (markup presence, function source extraction), not
executed; behavioural coverage for the pure derivations lives in
tests/js/console-tenant-overview.test.js (npm run test:console). The
device-lifecycle proxy route (added in PAT-1595/PAT-1607, never directly
exercised via TestClient before this ticket) is exercised for real here,
same as test_pat1554_coverage_gap.py's enrolled-devices route.

Run with: pytest tests/test_pat1606_tenant_overview.py -v
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")
TOV_JS = (ROOT / "static" / "js" / "console-tenant-overview.js").read_text(encoding="utf-8")


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


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


# ── 1. device-lifecycle proxy route — exercised for real (no prior coverage) ─

def _sample_device_lifecycle():
    return {
        "tenant_id": "024c7257-bd3b-550a-81da-3212c6ff3a42",
        "computed_at": "2026-09-17T00:00:00Z",
        "thresholds": {"quiet_days": 3, "stale_days": 14, "dormant_days": 45},
        "reconciliation": {
            "normal_count": 2, "coverage_gap_count": 1, "untracked_count": 1, "unmatchable_count": 0,
        },
        "devices": [
            {"bucket": "normal", "state": "reporting", "device_id": "d1", "hostname": "alpha"},
            {"bucket": "normal", "state": "stale", "device_id": "d2", "hostname": "beta"},
            {"bucket": "coverage_gap", "state": "never_seen", "external_id": "ext-1", "hostname": "gamma"},
            {"bucket": "untracked", "state": "reporting", "device_id": "d3", "hostname": "delta"},
        ],
        "upload": {"id": 1, "uploaded_at": "2026-09-01T00:00:00Z", "uploaded_by": "andy", "device_count": 3},
    }


def test_proxy_device_lifecycle_happy_path(client):
    fake = _sample_device_lifecycle()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake
    mock_resp.content = json.dumps(fake).encode()
    mock_resp.headers = {"content-type": "application/json"}

    with patch.object(dashboard.http, "get", return_value=mock_resp) as mock_get:
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/device-lifecycle",
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["reconciliation"]["normal_count"] == 2
    assert len(body["devices"]) == 4
    called_urls = [c.args[0] for c in mock_get.call_args_list if c.args]
    assert any("024c7257-bd3b-550a-81da-3212c6ff3a42" in u and "device-lifecycle" in u for u in called_urls), called_urls


def test_proxy_device_lifecycle_upstream_error(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.content = b"bad gateway"
    mock_resp.text = "bad gateway"
    mock_resp.json.side_effect = ValueError("not json")
    mock_resp.headers = {"content-type": "text/plain"}

    with patch.object(dashboard.http, "get", return_value=mock_resp):
        r = client.get(
            "/admin/tenants/024c7257-bd3b-550a-81da-3212c6ff3a42/device-lifecycle",
            headers={"Authorization": "Bearer test-key"},
        )
    assert r.status_code >= 400


# ── 2. Markup — the four new tenant-overview blocks exist inside tab-overview ─

def _overview_markup():
    start = HTML.index('id="tab-overview"')
    end = HTML.index('id="tab-account"')
    return HTML[start:end]


def test_tenant_overview_script_included():
    assert '/static/js/console-tenant-overview.js?v={{ console_build_id }}"' in HTML


def test_overview_panel_contains_all_four_new_blocks():
    markup = _overview_markup()
    for el_id in ("tov-kpi-strip", "tov-coverage", "tov-changed", "tov-top-findings"):
        assert 'id="' + el_id + '"' in markup, el_id


def test_coverage_card_has_bar_legend_and_disposition_link():
    markup = _overview_markup()
    assert 'id="tov-coverage-bar"' in markup
    assert 'id="tov-coverage-legend"' in markup
    assert "counted as compliant" in markup
    assert 'id="tov-disposition-link"' in markup


def test_what_changed_is_always_the_placeholder_not_a_loader():
    markup = _overview_markup()
    start = markup.index('id="tov-changed"')
    end = markup.index('id="tov-top-findings"')
    block = markup[start:end]
    assert "Drift detection has not shipped yet." in block
    assert "sample data" in block.lower()
    # No display:none toggle keyed to a fetch — this block never hides
    # behind a loading/empty state, it always renders.
    assert '<div id="tov-changed" class="panel tov-panel">' in markup


def test_top_findings_links_back_to_the_full_findings_tab():
    markup = _overview_markup()
    assert "data-tab=\"cve-findings\"" in markup
    assert 'id="tov-version-confirmed"' in markup


# ── 3. Loader/render functions — wired up and reuse PAT-1607's PF module ────

def test_ov_activate_calls_tov_load():
    fn = _extract_fn(HTML, "_ovActivate")
    assert "_tovLoad(tid);" in fn


def test_tov_load_fetches_lifecycle_cve_cis_and_drift_in_parallel():
    fn = _extract_fn(HTML, "_tovLoad")
    assert "/device-lifecycle" in fn
    assert "fetchTenantCveFindings(tid" in fn
    assert "fetchTenantFindings(tid" in fn
    assert "/app-policy-drift" in fn
    assert "Promise.all([pLifecycle, pCve, pCis, pDrift])" in fn


def test_tov_load_tenant_switch_guard():
    """A slow response for a superseded tenant must not render onto the
    now-active tenant's Overview -- same guard shape as _ov2Load/_fLoadedTenantId."""
    fn = _extract_fn(HTML, "_tovLoad")
    assert "_tovLoadedTenantId !== tid" in fn
    assert "_consoleState.tenantId !== tid" in fn


def test_tov_render_kpi_uses_established_unknown_tile_pattern_for_undeployed_signals():
    """Past 14-day deadline (PAT-367) and Advisory hours (PAT-1100/PAT-1314)
    are not real data anywhere in this database -- must reuse the same
    explicit-unknown tile PAT-1605 already established on the Customers
    landing screen, never fabricate a number for either."""
    fn = _extract_fn(HTML, "_tovRenderKpi")
    assert "_clKpiUnknownTile('Past 14-day deadline', _CL_UNKNOWN_REASON.ceBreach)" in fn
    assert "_clKpiUnknownTile('Advisory hours', _CL_UNKNOWN_REASON.hours)" in fn


def test_tov_render_top_findings_reuses_pf_evidence_basis_not_reinvented():
    fn = _extract_fn(HTML, "_tovRenderTopFindings")
    assert "PF.cveEvidenceBasis(f)" in fn
    assert "PF.cisEvidenceBasis()" in fn
    assert "PTO.aggregateByKey" in fn
    assert "PTO.rankFindings" in fn


def test_tov_render_coverage_uses_pto_device_lifecycle_coverage():
    fn = _extract_fn(HTML, "_tovLoad")
    assert "PTO.deviceLifecycleCoverage(lifecycle)" in fn


def test_no_em_dashes_in_new_tenant_overview_copy():
    for fn_name in ("_tovLoad", "_tovRenderKpi", "_tovRenderCoverage", "_tovRenderTopFindings"):
        fn = _extract_fn(HTML, fn_name)
        assert "—" not in fn, fn_name


# ── 4. CSS — the coverage-card component reuses the existing rdx-bar-coverage
#    library (defined, previously unused, ahead of this ticket) plus one new
#    sixth-segment modifier for "dispositioned". ─────────────────────────────

def test_coverage_bar_reuses_existing_rdx_component_plus_one_new_segment():
    assert ".rdx-bar-coverage-seg--dispositioned" in CSS
    # The five pre-existing segment colours are untouched, not redefined.
    assert CSS.count(".rdx-bar-coverage-seg--ok") == 1
    assert CSS.count(".rdx-bar-coverage-seg--dispositioned") == 1


def test_tov_css_introduces_no_new_colour_literals():
    start = CSS.index("PAT-1606")
    block = CSS[start:start + 4000]
    # Every rule in the PAT-1606 block must reference a var(--...) token or
    # be a structural property (layout, spacing, border-radius) -- no raw
    # hex/rgb colour literals invented for this ticket.
    import re
    hex_literals = re.findall(r"#[0-9a-fA-F]{3,8}\b", block)
    rgb_literals = re.findall(r"rgba?\(", block)
    assert not hex_literals, hex_literals
    assert not rgb_literals, rgb_literals


# ── 5. Pure module wiring — the file exists, exports what console.html uses ──

def test_tenant_overview_js_exports_match_what_console_html_calls():
    for fn_name in ("deviceLifecycleCoverage", "unapprovedSummary", "aggregateByKey", "rankFindings", "magnitudeFillClass"):
        assert "function " + fn_name + "(" in TOV_JS
        assert fn_name + ": " + fn_name in TOV_JS


# ── 6. CONSOLE_BUILD_ID bump (mandatory for any console.html/CSS change) ────

def test_console_build_id_bumped_for_pat1606():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
