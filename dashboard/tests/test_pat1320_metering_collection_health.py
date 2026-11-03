"""PAT-1320 dashboard-side collection-health regression coverage.

The API half of PAT-1320 (patched.im repo, commit dfe1df3) added
metering_status / metering_status_at fields the console did not yet consume,
so every app with no evidence rendered as a confident "Never used". These
are markup/source guards in the style of test_pat1337_software_metering_
workspace.py: they assert the render path actually consults the new
collection-health helper functions and that the summary tiles are computed
from the query+platform filtered set rather than the raw, unfiltered data.
Behavioural coverage for the helpers themselves lives in
tests/js/console-metering.test.js (npm run test:console).
"""

from pathlib import Path

import main as dashboard

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates/console.html").read_text()
CSS = (ROOT / "static/css/console.css").read_text()
METERING_JS = (ROOT / "static/js/console-metering.js").read_text()


def _meter_markup() -> str:
    start = HTML.index('id="tab-software-metering"')
    end = HTML.index('id="tab-compliance-status"', start)
    return HTML[start:end]


def test_console_build_id_bumped_for_this_ticket():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"


def test_metering_module_exports_collection_health_helpers():
    assert "function collectionHealth(app)" in METERING_JS
    assert "function healthReason(app)" in METERING_JS
    assert "collectionHealth: collectionHealth" in METERING_JS
    assert "healthReason: healthReason" in METERING_JS


def test_never_verdict_requires_ok_collection_health():
    # usageState must gate the 'never' branch on collectionHealth(app) === 'ok'
    # rather than launches === 0 alone — that's the exact bug PAT-1320 fixes.
    assert "collectionHealth(app) === 'ok' ? 'never' : 'unavailable'" in METERING_JS


def test_health_banner_element_exists_in_metering_panel():
    markup = _meter_markup()
    assert 'id="meter-health"' in markup
    # Banner sits above the summary tiles, inside the same content block.
    assert markup.index('id="meter-health"') < markup.index('id="meter-summary"')


def test_health_banner_css_defined_for_ok_and_gap_states():
    assert ".meter-health-banner" in CSS
    assert ".meter-health-ok" in CSS
    assert ".meter-health-degraded" in CSS or ".meter-health-unknown" in CSS


def test_health_banner_copy_has_no_em_dashes():
    start = HTML.index("function _meterRenderHealthBanner")
    end = HTML.index("function _meterRender()", start)
    banner_fn = HTML[start:end]
    assert "—" not in banner_fn


def test_render_path_consults_collection_health_and_reason():
    assert "PatchedConsoleMetering.collectionHealth" in HTML
    assert "PatchedConsoleMetering.healthReason" in HTML


def test_row_reason_uses_health_reason_for_non_windows_unavailable_rows():
    assert (
        "platform === 'windows' ? 'Windows pending' : (PatchedConsoleMetering.healthReason(app)"
        in HTML
    )


def test_per_device_evidence_cell_renders_device_status():
    start = HTML.index("function _meterDrillOpen")
    end = HTML.index("function ", start + 20)
    drill_fn = HTML[start:end]
    assert "metering_status: device.metering_status" in drill_fn
    assert "PatchedConsoleMetering.collectionHealth(evidenceApp)" in drill_fn
    assert "PatchedConsoleMetering.healthReason(evidenceApp)" in drill_fn


def test_summary_and_view_tab_counts_use_scoped_not_raw_data():
    start = HTML.index("function _meterRender()")
    end = HTML.index("function _meterFilterThreshold")
    render_fn = HTML[start:end]
    assert "PatchedConsoleMetering.summary(_meterScopedApps()" in render_fn
    # Must not regress to summarising the whole unfiltered tenant dataset.
    assert "PatchedConsoleMetering.summary(_meterData" not in render_fn


def test_scoped_apps_helper_filters_by_query_and_platform_not_view():
    start = HTML.index("function _meterScopedApps()")
    end = HTML.index("function _meterSortedApps")
    scoped_fn = HTML[start:end]
    assert "view: 'all'" in scoped_fn
    assert "query: _meterQuery" in scoped_fn
    assert "platform: _meterPlatform" in scoped_fn
