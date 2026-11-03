"""Regression coverage for PAT-1145's operator-first Device Inventory layout."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def _device_panel() -> str:
    start = HTML.index('<div id="tab-device-health"')
    end = HTML.index('<!-- /#tab-device-health -->', start)
    return HTML[start:end]


def _fn(name: str) -> str:
    start = HTML.index(f"function {name}(")
    brace = HTML.index("{", start)
    depth = 0
    for index in range(brace, len(HTML)):
        if HTML[index] == "{":
            depth += 1
        elif HTML[index] == "}":
            depth -= 1
            if depth == 0:
                return HTML[start:index + 1]
    raise AssertionError(f"unbalanced function {name}")


def test_summary_is_one_compact_surface_with_all_five_live_counts():
    panel = _device_panel()
    summary_start = panel.index('class="dh-summary-surface"')
    controls_start = panel.index('id="dh-controls"')
    summary = panel[summary_start:controls_start]
    assert 'id="dh-freshness"' in summary
    assert 'id="dh-stats-row"' in summary

    render = _fn("_dhRender")
    for label in ("Total Devices", "Active (&lt;", "Stale (", "Silent (", "Never seen"):
        assert label in render

    assert "grid-template-columns: repeat(5, minmax(0, 1fr))" in CSS
    # PAT-1615: the stat row moved to .rdx-kpi-strip/.rdx-kpi-tile (PAT-1601);
    # Overview's own stat row (_ovStatTile) is untouched and still emits
    # .dh-stat-val, so that class stays defined for Overview alone.
    assert "#tab-device-health .rdx-kpi-tile-value { font-size: 1.15rem" in CSS


def test_controls_are_one_surface_and_selects_are_not_in_table_headers():
    panel = _device_panel()
    controls_start = panel.index('id="dh-controls"')
    table_start = panel.index('id="dh-table-wrap"')
    controls = panel[controls_start:table_start]
    table = panel[table_start:]

    for element_id in (
        "dh-view-risk", "dh-view-stale", "dh-view-all", "dh-filter-search",
        "dh-filter-state", "dh-filter-os", "dh-filter-backup", "dh-filter-count",
    ):
        assert f'id="{element_id}"' in controls
    for label in (">State<", ">OS<", ">Backup<"):
        assert label in controls
    assert "_dhExportCSV()" in controls
    assert "<select" not in table


def test_table_headers_are_sort_only_and_compliance_is_consolidated():
    panel = _device_panel()
    table = panel[panel.index('id="dh-table-wrap"'):]
    for sort in ("severity", "os", "backup", "primary_user", "compliance", "last_seen"):
        assert f"_dhSortBy('{sort}')" in table
    assert ">Attention " in table
    assert 'class="col-compliance' not in table
    assert ">Compliance " not in table

    attention = _fn("_dhReasonCellHtml")
    assert "pct.toFixed(0)" in attention
    assert "% compliant" in attention
    assert "dh-attention-severity" in attention
    assert "dh-attention-reason" in attention
    assert "background:" not in attention
    assert "border:" not in attention


def test_device_actions_and_existing_data_paths_are_preserved():
    render = _fn("_dhRender")
    actions = _fn("_dhActionCellHtml")
    for data in ("d.hostname", "d.os_version", "_dhBackupBadgeHtml(d)", "primaryUser", "d.last_seen"):
        assert data in render
    assert "_dhReasonCellHtml(d)" in render
    assert "consoleNav(\\'device-detail\\'" in actions
    assert "tenantTab('" not in actions  # tabs are read from the fixed reason map, not interpolated
    assert "tenantTab(\\'" in actions
    assert "_dhDeleteDevice(this.closest" in render
    assert "owner-only" in render


def test_responsive_contract_contains_scroll_without_document_widening():
    assert "#dh-table-wrap" in CSS
    assert "max-width: 100%" in CSS
    assert "overflow-x: auto" in CSS
    assert "#dh-table { min-width: 760px" in CSS
    assert "@media (max-width: 1050px)" in CSS
    assert "@media (max-width: 900px)" in CSS
    assert "@media (max-width: 520px)" in CSS
    assert ".dh-filter-row { grid-template-columns: 1fr; }" in CSS


def test_controls_visibility_tracks_inventory_state():
    activate = _fn("_dhActivate")
    render = _fn("_dhRender")
    assert "document.getElementById('dh-controls').style.display   = 'none'" in activate
    zero = render[render.index("total === 0"):render.index("document.getElementById('dh-filter-row').style.display = '';", render.index("total === 0"))]
    assert "_dhControls.style.display = 'none'" in zero
    assert "_dhControls.style.display = ''" in render
