"""Version sprawl at phone width, in a real browser (PAT-2303).

The Product cell of /reports/software/version-sprawl holds a closed
<details> with the per-version breakdown. Once the table stacks at 680px and
narrower, every cell is a block, and Chromium still reports the closed
panel's text at a position just below the summary, which is the next cell.
The walker's `cells` check reported that as four products' Product cells
running into their Platform cells (8 findings across the two themes). Nothing
was painted there, but a closed panel should not take up layout at all.

The guard runs the walker's own `check_cells` against the page, so it fails
whenever the walker would. The stub carries five products with a breakdown.
"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import THEME_STORAGE_KEY, check_cells

ROUTE = "/reports/software/version-sprawl"
# Direct children only: each Product cell holds a nested breakdown table of its own.
OUTER_ROWS = "#vs-products-table > tbody > tr"


def _context(browser, harness_url, theme, width):
    context = browser.new_context(
        base_url=harness_url, viewport={"width": width, "height": 900})
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    context.add_init_script(
        f"try {{ localStorage.setItem('{THEME_STORAGE_KEY}', '{theme}'); }} catch (e) {{}}")
    return context


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("width", [390, 1280, 1440])
def test_version_sprawl_cells_do_not_run_into_each_other(browser, harness_url, width, theme):
    context = _context(browser, harness_url, theme, width)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}{ROUTE}", wait_until="networkidle")
        assert page.locator(OUTER_ROWS).count() == 5
        findings = check_cells(page, ROUTE, width, theme)
    finally:
        context.close()

    assert not findings, "\n".join(f.detail for f in findings)


def test_a_closed_breakdown_takes_no_room_and_an_opened_one_does(browser, harness_url):
    """The fix must not hide the breakdown from anyone who opens it: closed, the
    inner table is out of layout; opened, it is back, in flow, still without a
    cell running into the next."""
    context = _context(browser, harness_url, "light", 390)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}{ROUTE}", wait_until="networkidle")
        first_row = page.locator(OUTER_ROWS).first
        panel = first_row.locator("details > .table-scroll")
        assert panel.count() == 1
        assert not panel.is_visible()

        first_row.locator("details > summary").click()
        assert panel.is_visible()
        box = panel.bounding_box()
        cell = first_row.locator("> td").first.bounding_box()
        assert box["y"] + box["height"] <= cell["y"] + cell["height"] + 1, (
            "the opened breakdown should sit inside its own Product cell")
        findings = check_cells(page, ROUTE, 390, "light")
    finally:
        context.close()

    assert not findings, "\n".join(f.detail for f in findings)
