"""PAT-1843 shared portal layout, reporting tabs and overflow contracts."""

import re
from pathlib import Path

from tests.conftest import STUB_STATE
from tests.test_devices_groups import GROUPED_DEVICES

ROOT = Path(__file__).resolve().parent.parent


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_shared_layout_macros_are_defined_once_and_consumed_by_devices():
    macros = (ROOT / "templates" / "_macros.html").read_text()
    devices = (ROOT / "templates" / "devices.html").read_text()
    for name in ("kpi_summary", "segmented_control", "group_card_head"):
        assert macros.count(f"{{% macro {name}(") == 1
        assert name in devices.splitlines()[1]
        assert re.search(rf"\b{name}\(", devices)


def test_every_portal_table_has_a_horizontal_overflow_container():
    templates = [*sorted((ROOT / "templates").glob("*.html"))]
    for template in templates:
        source = template.read_text()
        tables = source.count('<table class="data-table')
        wrapped = len(re.findall(
            r'<div class="table-scroll"[^>]*>\s*<table class="data-table', source,
        ))
        assert tables == wrapped, f"unwrapped data table in {template.name}"


def test_devices_page_is_one_table_with_three_server_bucketed_views(client, make_token):
    STUB_STATE["devices_data"] = GROUPED_DEVICES
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=quiet")

    assert response.status_code == 200
    assert response.text.count('<table class="data-table device-table table-stack"') == 1
    assert 'data-row-filter="view" data-query-param="view" data-initial="quiet"' in response.text
    assert 'data-filter-tab="silent"' in response.text
    assert 'data-filter-tab="quiet" class="tab-active" aria-current="true"' in response.text
    assert 'data-filter-tab="normal"' in response.text
    assert response.text.count('data-filter-view="silent"') == 2
    assert response.text.count('data-filter-view="quiet"') == 1
    assert response.text.count('data-filter-view="normal"') == 1
    assert "Cyber Essentials v3.3" in response.text
    assert "critical and high-severity security updates within 14 days" in response.text
    assert "Reporting to us" not in response.text


def test_shared_filter_script_composes_filters_search_and_current_url():
    script = (ROOT / "static" / "js" / "portal.js").read_text()
    assert 'querySelectorAll("[data-table-search]")' in script
    assert 'querySelectorAll("[data-table-search], #device-search")' not in script
    global_table_fallback = (
        'return Array.prototype.slice.call(document.querySelectorAll(".data-table"));'
    )
    assert global_table_fallback not in script
    assert "if (nearest)" in script and "return [];" in script
    assert 'querySelectorAll("[data-row-filter]")' in script
    assert 'filters.some(function (filter)' in script
    assert 'row-hide-filter' in script
    assert 'row-hide-search' in script
    assert "new URL(window.location.href)" in script
    assert "url.searchParams.set(parameter, value)" in script
    assert '"/software"' not in script


def test_every_search_input_declares_its_table_scope():
    for template in (ROOT / "templates").glob("*.html"):
        source = template.read_text()
        for search in re.findall(r'<input\b[^>]*type="search"[^>]*>', source):
            assert "data-table-search=" in search, (
                f"unscoped search input in {template.name}: {search}"
            )


def test_device_columns_responsive_rules_and_theme_contract_remain_explicit():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    assert ".table-scroll" in css and "overflow-x: auto" in css
    # PAT-2179: Brand v3's wider rail reduces the 1280px card viewport to
    # 966px, so the table floor must remain within that real desktop budget.
    # (Updates widened, Hostname moved from an unreliable min-width to a
    # real width and then widened again to stop it wrapping at its own
    # hyphen - see portal.css's own comment on .device-table).
    assert ".device-table { min-width: 0; table-layout: fixed; }" in css
    assert ".group-card__search" in css
    assert "@media (max-width: 820px)" in css
    assert "@media (max-width: 680px)" in css
    assert ':root[data-theme="dark"]' in css
    for token in ("--snow:", "--paper:", "--graphite:", "--mute:", "--rule:"):
        assert token not in css.split(":root {", 1)[1].split("}", 1)[0]


def test_changed_assets_are_cache_busted_everywhere_they_are_referenced():
    """PAT-2237: the cache-buster is now derived from each asset's own
    content hash (static_url()) rather than a hand-bumped literal, so every
    reference to a given asset resolves through the same call rather than a
    string that has to be kept in step by hand across templates."""
    base = (ROOT / "templates" / "base.html").read_text()
    assert "{{ static_url('css/portal.css') }}" in base
    for template in (ROOT / "templates").glob("*.html"):
        source = template.read_text()
        assert '<script src="/static/js/portal.js' not in source, (
            f"{template} still hardcodes the portal.js src"
        )
        if "static_url('js/portal.js')" in source:
            assert "<script src=\"{{ static_url('js/portal.js') }}\"></script>" in source


def test_repo_guidance_matches_current_routes_filters_and_theme():
    guidance = (ROOT / "AGENTS.md").read_text()
    assert "`/exceptions`" in guidance
    assert "client-side `?type=application|extension` kind filter" in guidance
    assert "same compact staff-console design language" in guidance
    assert "Portal has no dark theme" not in guidance
    assert "light-mode pin" not in guidance
    assert "does not re-declare the kit's theme-following colour primitives" in guidance
