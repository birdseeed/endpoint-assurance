"""PAT-1144 customer Priorities composition contracts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def _overview_markup() -> str:
    start = HTML.index('<div id="tab-overview"')
    end = HTML.index('<!-- ═══ Account tab', start)
    return HTML[start:end]


def test_priorities_has_full_width_summary_then_operator_grid():
    overview = _overview_markup()
    hero = overview.index('id="ov2-hero"')
    grid = overview.index('class="tenant-priorities-grid"')
    attention = overview.index('id="ov2-actions-wrap"')
    estate = overview.index('id="ov2-glance-wrap"')
    activity = overview.index('class="panel ov2-activity-panel"')

    assert hero < grid < attention < estate < activity
    assert 'grid-template-columns: minmax(0, 1fr) 300px;' in CSS


def test_estate_context_is_compact_two_column_and_keeps_five_destinations():
    overview = _overview_markup()
    assert 'id="ov2-glance" class="dh-stat-row ov2-glance-grid"' in overview
    assert '.tenant-priorities-layout .ov2-glance-grid {' in CSS
    assert 'grid-template-columns: repeat(2, minmax(0, 1fr));' in CSS
    assert '.ov2-glance-grid .dh-stat-card:last-child:nth-child(odd)' in CSS
    assert '.ov2-glance-heading .freshness-stamp {' in CSS
    assert 'text-align: left;' in CSS

    glance_fn = HTML[HTML.index('function _ov2RenderGlance'):HTML.index('function _ovActivate')]
    assert glance_fn.count('_ovStatTile(') == 5
    assert glance_fn.count("'device-health'") == 4
    assert glance_fn.count("'cve-findings'") == 1


def test_narrow_layout_has_deliberate_reading_order_and_compact_activity():
    assert '@media (max-width: 1100px)' in CSS
    assert '.tenant-priorities-grid #ov2-actions-wrap { order: 1; }' in CSS
    assert '.tenant-priorities-grid .ov2-glance-panel { order: 4; }' in CSS
    assert '.tenant-priorities-grid .ov2-activity-panel { order: 5; }' in CSS
    assert '.ov2-activity-panel .empty-state { padding: 14px 0; }' in CSS
    assert '.tenant-priorities-grid .ov2-gaps-note {' in CSS
    assert 'max-width: 100%;' in CSS


def test_existing_priority_handlers_do_not_restore_retired_audit_navigation():
    overview = _overview_markup()
    assert 'data-tab="enforcement-audit"' not in overview
    assert 'View enforcement evidence' not in overview

    actions_fn = HTML[HTML.index('function _ov2RenderActions'):HTML.index('function _ov2RenderGlance')]
    assert 'data-tab="' in actions_fn
    assert 'tenantTab(this.dataset.tab);return false;' in actions_fn
