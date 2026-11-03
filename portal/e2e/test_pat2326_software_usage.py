"""PAT-2326 in a real browser: the usage filter and the usage line on /software.

tests/test_pat2326_software_usage.py covers the rendering, the filter rules
and the URL round trip against the stub; this file is what only a browser can
show:

  1. `?usage=unused` is already applied at first paint, with JavaScript off;
  2. the Usage group in the "More filters" panel filters the rows in place,
     keeps the address bar and the chips in step, and clears back to the full
     list (static/js/portal.js's applyFilters() mirrors the server rule);
  3. at 1680px, where the Evidence column is shown, the usage line sits under
     the date and is not clipped.

Red-proof: against the tree before this ticket the panel has no Usage group
and `?usage=unused` hides nothing, so 1 and 2 fail on their first assertion.
"""

from urllib.parse import parse_qs, urlsplit

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_device_detail_layout import WIDE_FALLBACK_FONT_CSS

MORE_FILTERS_SUMMARY = "details[data-more-filters] summary"
UNUSED_BOX = 'fieldset[data-row-filter="usage"] input[value="unused"]'
USED_BOX = 'fieldset[data-row-filter="usage"] input[value="used"]'


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _visible_names(page):
    rows = page.locator("tr[data-approval-row]")
    names = []
    for i in range(rows.count()):
        row = rows.nth(i)
        if row.is_visible():
            names.append(row.locator(".product-name").inner_text())
    return names


def _chips(page):
    return page.locator(".filter-chips a.filter-chip:not(.filter-chip--clear)").evaluate_all(
        "els => els.map(el => el.firstChild.textContent.trim())")


def _usage_param(page):
    return parse_qs(urlsplit(page.url).query).get("usage")


# ── 1. Applied at first paint, without JavaScript ─────────────────────────

def test_usage_unused_is_applied_at_first_paint_with_javascript_off(browser, harness_url):
    context = _context(browser, harness_url, java_script_enabled=False)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software?usage=unused", wait_until="load")
        assert _visible_names(page) == ["ArchiveTool"]
    finally:
        context.close()


# ── 2. The panel's Usage group filters in place and keeps the URL ─────────

def test_usage_group_filters_in_place_keeps_the_url_and_clears(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software", wait_until="networkidle")
        everything = _visible_names(page)
        assert {"ArchiveTool", "UsedTool", "MeteringGap", "MysteryApp"} <= set(everything)

        page.locator(MORE_FILTERS_SUMMARY).click()
        page.locator(UNUSED_BOX).check()
        assert _visible_names(page) == ["ArchiveTool"]
        assert _usage_param(page) == ["unused"]
        assert _chips(page) == ["Unused"]

        page.locator(USED_BOX).check()
        assert set(_visible_names(page)) == {"ArchiveTool", "UsedTool"}
        assert _usage_param(page) == ["unused,used"]
        assert _chips(page) == ["Unused", "Used"]

        page.locator(UNUSED_BOX).uncheck()
        page.locator(USED_BOX).uncheck()
        assert _visible_names(page) == everything
        assert _usage_param(page) is None
        assert _chips(page) == []
    finally:
        context.close()


def test_a_shared_usage_link_opens_with_the_box_ticked_and_the_chip_on(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software?usage=unmetered", wait_until="networkidle")
        assert _visible_names(page) == ["MeteringGap"]
        assert _chips(page) == ["Not metered or no evidence"]
        page.locator(MORE_FILTERS_SUMMARY).click()
        box = page.locator('fieldset[data-row-filter="usage"] input[value="unmetered"]')
        assert box.is_checked()
    finally:
        context.close()


# ── 3. The usage line under the Evidence date, where Evidence shows ───────

@pytest.mark.parametrize("wide_font", [False, True])
def test_usage_line_sits_under_the_evidence_date_at_1680_and_is_not_clipped(
        browser, harness_url, wide_font):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1680, "height": 1000})
        page.goto("/software", wait_until="networkidle")
        if wide_font:
            page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        row = page.locator("tr[data-approval-row]", has=page.locator(
            ".product-name", has_text="ArchiveTool"))
        line = row.locator(".cell-usage")
        assert line.is_visible()
        assert line.inner_text().strip() == "Unused · last used 01 Nov 2026"
        clipped = line.evaluate("el => el.scrollWidth > el.clientWidth + 1")
        assert not clipped, "the usage line is ellipsised at 1680px"
        assert line.evaluate("el => el.getBoundingClientRect().height <= "
                             "parseFloat(getComputedStyle(el).lineHeight) * 1.6"), \
            "the usage line wraps beyond the Evidence cell's two-line budget"
        date = row.locator(".cell-evidence__main").bounding_box()
        below = line.bounding_box()
        assert below["y"] >= date["y"] + date["height"] - 1
        # A governance-only row has no verdict to show.
        assert page.locator("tr[data-approval-row]", has=page.locator(
            ".product-name", has_text="MysteryApp")).locator(".cell-usage").count() == 0
    finally:
        context.close()
