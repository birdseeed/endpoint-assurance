"""PAT-1140: coherent Work landing hierarchy."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")
THEME = (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")


def _home_region():
    start = HTML.index('<div id="section-home"')
    end = HTML.index("<!-- ═══ SECTION: REPORTS", start)
    return HTML[start:end]


def test_work_has_one_page_level_primary_and_context_grid():
    home = _home_region()

    assert 'class="work-landing-grid" id="home-list-detail"' in home
    assert 'class="list-detail" id="home-list-detail"' not in home
    assert 'class="home-operations-row"' not in home
    assert ".work-landing-grid {" in CSS
    assert "grid-template-columns: minmax(0, 1fr) 340px;" in CSS
    assert ".work-primary-column,\n.work-context-rail {" in CSS


def test_work_preserves_decision_flow_and_context_rail_order():
    home = _home_region()

    primary = home.index('class="work-primary-column"')
    exceptions = home.index('id="home-service-exceptions"')
    rail = home.index('class="work-context-rail"')
    health = home.index('<h2>Service health</h2>')
    assert primary < exceptions < rail < health
    assert 'id="home-inspector"' not in home
    assert 'id="home-attention"' not in home
    assert 'id="home-estate-posture"' not in home
    assert 'data-retired-surface="estate-posture"' in home


def test_work_collapses_before_the_primary_and_context_columns_cramp():
    narrow = CSS[CSS.index("@media (max-width: 1100px)"):CSS.index("@media (max-width: 720px)")]
    assert ".work-landing-grid {\n    display: flex;" in narrow
    assert "align-items: stretch;" in narrow
    assert ".work-primary-column,\n  .work-context-rail { display: contents; }" in narrow
    assert "#home-attention { order: 1; }" in narrow
    assert "#home-inspector { order: 2; }" in narrow
    assert ".work-context-rail > section:nth-of-type(1) { order: 4; }" in narrow
    assert ".work-context-rail > section:nth-of-type(2) { order: 5; }" in narrow
    assert ".work-context-inspector { position: static; }" in CSS


def test_work_preserves_existing_render_targets_and_actions():
    home = _home_region()

    for element_id in (
        "home-service-exceptions", "service-exceptions-heading", "home-health-rows",
        "home-loading", "home-verdict", "home-freshness",
    ):
        assert 'id="' + element_id + '"' in home
    assert 'id="home-attention"' not in home
    assert "consoleNav('ops')" in home
    assert '/static/js/console-service-exceptions.js?v={{ console_build_id }}' in HTML
    assert "_renderHomeAttention(_clData" not in home
    assert "_renderHomeInspector(t)" in HTML
    assert "function _bindSelectableRows" in HTML


def test_work_has_one_freshness_marker_without_stale_status_strip_writes():
    home = _home_region()

    assert 'id="home-freshness"' in home
    assert "home-stat-updated" not in HTML
    assert "Last updated" not in home


def test_phone_topbar_compresses_without_removing_customer_or_identity_access():
    phone = THEME[THEME.index("@media (max-width: 480px)"):THEME.index("@media (max-width: 360px)")]
    narrowest = THEME[THEME.index("@media (max-width: 360px)"):]

    assert ".topbar { padding-right: 10px; padding-left: 10px; gap: 8px; }" in phone
    assert ".topbar-customer { max-width: 42vw; gap: 5px; padding: 5px 7px; }" in phone
    assert ".topbar-customer select { min-width: 80px; }" in phone
    assert ".identity-btn { gap: 4px; padding: 6px 5px; }" in phone
    assert ".identity-name { display: none; }" in phone
    assert ".brand-lockup .brand-name { display: none; }" in narrowest
    for element_id in ("tw-switcher", "identity-btn"):
        assert 'id="' + element_id + '"' in HTML
    assert 'class="operator-logo logo-light"' in HTML
    assert 'class="operator-logo logo-dark"' in HTML
    assert HTML.count('alt="Patched"') == 2
    assert 'class="brand-lockup" aria-label="Home"' in HTML
