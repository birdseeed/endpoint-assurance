"""Type filter navigation and layout, including a JavaScript-free browser."""
import pytest

from e2e.test_pat2324_server_display import (
    DOC_OVERFLOW_JS,
    _context,
    mixed_roster,  # noqa: F401
)


@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("javascript_enabled", [True, False])
def test_type_and_reporting_controls_compose(browser, harness_url, mixed_roster,  # noqa: F811
                                            width, javascript_enabled):
    context = _context(browser, harness_url, viewport={"width": width, "height": 900},
                       java_script_enabled=javascript_enabled)
    try:
        page = context.new_page()
        page.goto("/devices?view=normal&list_group=never_seen", wait_until="networkidle")
        types = page.get_by_role("navigation", name="Device type", exact=True)
        types.get_by_role("link", name="Servers (1)", exact=True).click()
        page.wait_for_url("**/devices?*type=server*")
        assert page.locator("#device-table tbody tr:visible").count() == 1
        assert page.locator("#device-table tbody tr:visible").inner_text().startswith("HOMESERVER")
        assert page.locator(".device-type-pill").count() == 0
        assert page.locator("#device-list-card").inner_text().find("ghost-01") >= 0
        states = page.get_by_role("navigation", name="Device reporting state", exact=True)
        states.get_by_role("link", name="Quiet 3–14 days (0)", exact=True).click()
        page.wait_for_url("**/devices?view=quiet**")
        assert "type=server" in page.url and "list_group=never_seen" in page.url
        assert page.locator("#device-table tbody tr:visible").count() == 0
        assert page.locator("[data-filter-empty]").is_visible()
        empty_text = page.locator("[data-filter-empty]").inner_text()
        assert "No servers in this reporting state." in empty_text
        types = page.get_by_role("navigation", name="Device type", exact=True)
        assert types.get_by_role("link", name="Servers (0)", exact=True).is_visible()
        types.get_by_role("link", name="Workstations (1)", exact=True).click()
        page.wait_for_url("**/devices?*type=workstation*")
        assert page.locator("#device-table tbody tr:visible").count() == 1
        assert page.evaluate(DOC_OVERFLOW_JS) <= 1
        assert page.locator(".kpi").first.inner_text().find("5") >= 0
    finally:
        context.close()
