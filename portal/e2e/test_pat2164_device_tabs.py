"""PAT-2164 in a real browser: the device page's six tabs (Overview,
Hardware, Software, Vulnerabilities, Compliance, Evidence).

Covers what a stub-only pytest test cannot: that every tab actually renders
at both 1280 and 390px, that the active tab is marked `aria-current="page"`
at both widths, and that the tab bar itself does not force the page to
scroll sideways at 390px (rubric L12). Clicking the CVEs/CIS issues tiles
and the back button returning to the previous tab are covered in
e2e/test_pat2141_count_strip.py (the count-strip tiles that trigger the
navigation); full-page horizontal-overflow coverage for every tab at
1280/390/1920px, with typical and worst-case data, lives generically in
e2e/test_table_overflow.py's PAGES sweep (all six tab routes are in that
list). Column/state-logic coverage for each section's own content lives in
its own PAT-1868/1879/2025/2099/2141/2156 test file.
"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN

DEVICE_ID = "dev-mac-001"

TAB_CHECKS = [
    ("overview", f"/devices/{DEVICE_ID}", "Identification"),
    ("hardware", f"/devices/{DEVICE_ID}/hardware", "Apple M2"),
    ("software", f"/devices/{DEVICE_ID}/software", "Example App"),
    ("vulnerabilities", f"/devices/{DEVICE_ID}/vulnerabilities", "ExampleBrowser"),
    ("compliance", f"/devices/{DEVICE_ID}/compliance", "Firewall enabled"),
    ("evidence", f"/devices/{DEVICE_ID}/evidence", "Hardware health: battery"),
]

WIDTHS = [1280, 390]


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("tab_key,path,marker_text", TAB_CHECKS)
def test_each_tab_renders_and_is_marked_active(
    browser, harness_url, tab_key, path, marker_text, width,
):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{harness_url}{path}", wait_until="networkidle")

        assert marker_text in page.content(), f"{tab_key} at {width}px missing {marker_text!r}"

        active = page.locator('.view-tabs a[aria-current="page"]')
        assert active.count() == 1, f"{tab_key} at {width}px: no single active tab marked"
        assert active.get_attribute("href") == path

        doc = page.evaluate(
            "() => ({scrollWidth: document.documentElement.scrollWidth,"
            " clientWidth: document.documentElement.clientWidth})"
        )
        assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
            f"{tab_key} at {width}px scrolls the page sideways: {doc}"
        )
    finally:
        context.close()


def test_tab_bar_scrolls_inside_itself_not_the_page_at_390(browser, harness_url):
    # rubric L12: the tab bar's own container may scroll horizontally; the
    # page (document.documentElement) must never do so.
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/{DEVICE_ID}", wait_until="networkidle")
        metrics = page.evaluate(
            """() => {
              const bar = document.querySelector('.device-tab-bar');
              const doc = document.documentElement;
              return {
                barScrollWidth: bar.scrollWidth, barClientWidth: bar.clientWidth,
                docScrollWidth: doc.scrollWidth, docClientWidth: doc.clientWidth,
              };
            }"""
        )
    finally:
        context.close()
    # The six-tab bar is wider than a 390px viewport, so its own container
    # scrolls (this is the point of the chosen idiom)...
    assert metrics["barScrollWidth"] > metrics["barClientWidth"]
    # ...but the page itself never does.
    assert metrics["docScrollWidth"] <= metrics["docClientWidth"] + 1, metrics


def test_active_tab_is_scrolled_into_view_on_a_later_tab(browser, harness_url):
    # portal.js enhancement (see templates/_macros.html's device_page_head):
    # landing directly on a later tab (Evidence, the last one) scrolls the
    # bar so the active tab is visible, not left off-screen to the right.
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/{DEVICE_ID}/evidence", wait_until="networkidle")
        in_view = page.evaluate(
            """() => {
              const bar = document.querySelector('.device-tab-bar');
              const active = bar.querySelector('.tab-active');
              const barRect = bar.getBoundingClientRect();
              const activeRect = active.getBoundingClientRect();
              return activeRect.left >= barRect.left - 1 && activeRect.right <= barRect.right + 1;
            }"""
        )
    finally:
        context.close()
    assert in_view
