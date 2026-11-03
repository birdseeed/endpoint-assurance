"""PAT-956/PAT-1047 v2: Work (formerly Home) — customer-priority command centre.

REDESIGN_V2.md replaces Home with Work: a customer-attention decision flow
with Estate posture directly below it, plus a supporting context rail for the
selected customer, Service Health and Automations. There is no leading row of
metric cards — the compact stat line sits under the page header.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")
WORK_JS = (ROOT / "static" / "js" / "console-work.js").read_text(encoding="utf-8")


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


def _home_region():
    start = HTML.index('<div id="section-home"')
    end = HTML.index("<!-- ═══ SECTION: REPORTS", start)
    return HTML[start:end]


def test_home_is_relabelled_work():
    home = _home_region()
    assert "<h1>Service overview</h1>" in home
    assert "<h1>Home</h1>" not in home
    assert "'home': 'Service overview'" in HTML


def test_work_leads_with_a_primary_flow_and_context_rail_not_metric_cards():
    home = _home_region()
    # Service evidence leads the retained context rail, without posture or
    # the retired metric-card wrapper.
    assert 'class="home-dashboard-grid"' not in home
    assert '.home-dashboard-grid {' not in CSS
    assert 'class="work-landing-grid" id="home-list-detail"' in home
    assert 'class="work-primary-column"' in home
    assert 'class="work-context-rail"' in home
    assert 'aria-labelledby="service-exceptions-heading"' in home
    assert 'id="home-service-exceptions"' in home
    assert 'id="home-inspector-empty"' not in home
    assert 'id="home-inspector-content"' not in home
    assert "Service exceptions" in home
    assert "Customer attention" not in home


def test_selecting_a_row_populates_the_inspector_without_navigating():
    fn = _extract_fn(HTML, "_homeSelectTenant")
    assert "PatchedConsoleWork.selectWorkTenant" in fn
    assert "renderInspector: _renderHomeInspector" in fn
    assert "consoleNav" not in fn  # selection must not navigate away

    inspector_fn = _extract_fn(HTML, "_renderHomeInspector")
    assert "data-tenant-id" in inspector_fn
    assert "Open customer" in inspector_fn
    # Signals link into existing tenant destinations only (no invented action).
    assert "'cve-findings'" in inspector_fn
    assert "'compliance-status'" in inspector_fn
    assert "'device-health'" in inspector_fn
    assert "'software-catalogue'" in inspector_fn


def test_home_verdict_hero_aggregates_estate_health():
    # PAT-961: the estate verdict is computed from the same per-tenant fields the
    # attention list ranks on, plus a service-health infra deduction.
    fn = _extract_fn(HTML, "_renderHomeVerdict")
    assert "_homeTenantScore(t)" in fn        # at-risk tenant count
    assert "estatePct" in fn                  # device-weighted estate compliance
    assert "_homeServiceHealth" in fn         # infra deduction folded in
    assert "ov2-hstat" in fn                  # reuses the Overview hero stat tiles


def test_attention_renderer_filters_clear_tenants_and_offers_fast_drill():
    fn = _extract_fn(HTML, "_renderHomeAttention")

    assert ".filter(function(item) { return item.score > 0; })" in fn
    assert "data-tenant-id" in fn
    assert "_triageDrill" not in fn
    assert "No customer attention rows are available from the current evidence" in fn
    assert "This does not confirm every device is reporting" in fn
    assert "_homeClearSelection()" in fn
    assert "All customers look current" not in fn
    assert "service exceptions" not in fn.lower()
    findings = _extract_fn(HTML, "_ensureFindingsAgg")
    assert "ok: false, sevCounts: null, oldestFirstSeen: null" in findings
    assert "if (!f || !f.ok) return -1" in _extract_fn(HTML, "_clFindingsTotal")
    assert "Findings unavailable for this tenant" in _extract_fn(HTML, "_renderClientTable")
    # Row selection wires into the inspector (event delegation on tbody).
    assert "_homeSelectTenant(row.getAttribute('data-tenant-id'))" in fn


def test_service_health_uses_compact_rows_not_a_card_strip():
    fn = _extract_fn(HTML, "_renderHomeHealth")

    assert "PatchedConsoleWork.renderServiceHealth" in fn
    assert 'class="home-health-row' in WORK_JS
    assert 'class="home-health-card' not in WORK_JS
    assert ".home-health-row" in CSS


def test_service_health_and_automations_are_in_the_supporting_context_rail():
    home = _home_region()
    assert "consoleNav('ops')" in home
    assert '<div id="section-ops" class="console-section">' in HTML
    assert '<div id="section-ops" class="console-section" style="display:none;">' not in HTML
    rail_pos = home.index('class="work-context-rail"')
    health_pos = home.index('<h2>Service health</h2>')
    assert rail_pos < health_pos
    assert 'id="home-inspector"' not in home
    assert 'id="home-automations-content"' not in home
    assert 'id="home-service-exceptions"' in home


def test_estate_posture_follows_customer_attention_in_the_primary_flow():
    home = _home_region()
    attention_pos = home.index('id="home-service-exceptions"')
    verdict_pos = home.index('id="home-verdict"')
    rail_pos = home.index('class="work-context-rail"')
    assert attention_pos < verdict_pos < rail_pos
    assert "<h2>Estate posture</h2>" in home


def test_home_automations_filter_quarantined_and_show_failure_first():
    # PAT-1539: quarantined/retired legacy jobs belong on the dedicated
    # Automations page, not competing with real failures in this compact rail.
    fn = _extract_fn(HTML, "_renderHomeAutomations")

    assert "state !== 'quarantined' && state !== 'retired'" in fn
    assert "active.slice().sort" in fn
    assert "failed: 0" in fn
    assert "quarantined: 5" not in fn
    assert "recent_runs" in fn
    assert 'class="home-automation-row"' in fn


def test_home_attention_deemphasizes_internal_tenants():
    # PAT-1562: internal/test tenants must never compete with real customer
    # urgency. tenant_kind ships from a parallel API rollout that may not be
    # deployed yet, so missing/undefined MUST fall back to 'customer'.
    fn = _extract_fn(HTML, "_renderHomeAttention")

    assert "!t.tenant_kind || t.tenant_kind === 'customer'" in fn
    assert "t.tenant_kind === 'internal'" in fn
    assert 'id="home-internal-tenants"' in fn
    assert "badgeClass(muted, modifier)" in fn or "function badgeClass(muted" in fn
    # Muted rows drop to the bare neutral .badge class, never a color modifier.
    assert "muted ? 'badge' :" in fn


def test_home_verdict_excludes_internal_tenants():
    # PAT-1562: Estate posture score and the Customers/Devices/Need-attention
    # stat strip must only reflect real customers.
    fn = _extract_fn(HTML, "_renderHomeVerdict")

    assert "!t.tenant_kind || t.tenant_kind === 'customer'" in fn


def test_home_zero_real_customers_shows_content_not_blank_panels():
    # PAT-1562 follow-up: flipping every tenant to 'internal' (the actual
    # state right after this ticket's own data step) must not leave Work
    # looking empty/broken -- the internal-tenant section opens by default
    # and gets auto-selected into the inspector when it's the only content,
    # and Estate posture shows an explicit empty state instead of a header
    # with nothing rendered under it.
    home = _home_region()
    assert 'id="home-verdict-empty"' in home
    assert 'class="empty-state"' in home  # the new sibling element itself

    attention_fn = _extract_fn(HTML, "_renderHomeAttention")
    assert "customerTenants.length ? '' : ' open'" in attention_fn
    assert "customerTenants.length ? null : function()" in attention_fn

    verdict_fn = _extract_fn(HTML, "_renderHomeVerdict")
    assert "home-verdict-empty" in verdict_fn
    assert "hero.style.display = 'none'" in verdict_fn


def test_home_layout_collapses_responsively():
    assert "@media (max-width: 1100px)" in CSS
    assert "#home-attention { order: 1; }" in CSS
    assert "#home-inspector { order: 2; }" in CSS
