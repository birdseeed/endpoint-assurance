"""PAT-1337 truth-first Software Metering workspace regression coverage."""

from pathlib import Path

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates/console.html").read_text()
CSS = (ROOT / "static/css/console.css").read_text()


def _meter_markup() -> str:
    start = HTML.index('id="tab-software-metering"')
    end = HTML.index('<template data-retired-surface="patch-deploy">', start)
    return HTML[start:end]


def test_metering_has_heading_truthful_summary_and_three_views():
    markup = _meter_markup()
    assert "<h2>Software metering</h2>" in markup
    assert 'id="meter-unused-count"' in markup
    assert 'id="meter-never-count"' in markup
    assert 'id="meter-unavailable-count"' in markup
    assert 'data-view="reclaim"' in markup
    assert 'data-view="gaps"' in markup
    assert 'data-view="all"' in markup


def test_metering_has_compact_composable_controls():
    markup = _meter_markup()
    assert 'id="meter-search" type="search"' in markup
    assert 'id="meter-platform-filter"' in markup
    assert 'id="meter-age-filter"' in markup
    assert 'class="meter-sort-btn"' in markup
    assert "padding: 7px 8px;" in CSS


def test_metering_detail_expands_inside_the_table_and_keeps_cross_link():
    markup = _meter_markup()
    assert 'id="meter-detail"' not in markup
    assert "className = 'meter-detail-row'" in HTML
    assert "Manage Updates" in HTML
    assert "_meterCrossLink(this.dataset.appId)" in HTML


def test_metering_uses_tested_truth_helper():
    assert 'console-metering.js?v={{ console_build_id }}' in HTML
    assert "PatchedConsoleMetering.usageState" in HTML
    assert "PatchedConsoleMetering.summary" in HTML
    assert "state === 'unavailable'" in HTML


def test_metering_copy_does_not_claim_missing_evidence_is_never_used():
    markup = _meter_markup()
    assert "Windows pending" in HTML
    assert "Evidence unavailable" in markup
    assert "macOS &middot; Windows pending" not in markup
    assert 'class="sev-count high"' not in markup


def test_console_build_advances_for_metering_release():
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
