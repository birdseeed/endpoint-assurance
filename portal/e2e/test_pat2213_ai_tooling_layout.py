"""PAT-2213 filter composition and overflow regression guards.

PAT-2243 replaces the earlier four-tile summary with a compact line;
combined filters, zero-count choices and viewport safety remain guarded.

Parsing/rendering/chip coverage against the stub lives in
tests/test_pat2022_ai_tooling.py; this file is the Done-when's own browser
checks:

  1. picking a Type and a State together narrows the Products table to
     only rows matching both, and each chip's own remove link narrows
     further (Type) or restores (state) rather than clearing everything;
  2. nothing overflows the viewport at 1280px or 390px, light or dark.

Fixture data is tests/conftest.py's AI_TAGGED_PRODUCTS (imported verbatim
by e2e/conftest.py's stub): ChatGPT (desktop_app, unreviewed), AI Search
Helper (browser_extension, unapproved), Copilot (ide_extension, approved),
ai-helper (cli, unreviewed).
"""

from e2e.conftest import HARNESS_VALID_TOKEN

TYPE_SUMMARY = "details[data-row-filter='ai_type'] summary"
STATE_SUMMARY = "details[data-row-filter='ai_state'] summary"


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _visible_product_names(page):
    rows = page.locator("tr[data-approval-row]")
    names = []
    for i in range(rows.count()):
        row = rows.nth(i)
        if row.is_visible():
            names.append(row.locator("td[data-label='Product'] .product-name").inner_text())
    return names


def test_type_and_state_filters_combine_and_chips_narrow_or_restore(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/ai-tooling", wait_until="networkidle")

        before = set(_visible_product_names(page))
        assert {"ChatGPT", "AI Search Helper", "Copilot", "ai-helper"} <= before

        # Type: desktop_app + cli.
        page.locator(TYPE_SUMMARY).click()
        type_panel = page.locator("details[data-row-filter='ai_type']")
        type_panel.locator('input[type="checkbox"][value="desktop_app"]').check()
        type_panel.locator('input[type="checkbox"][value="cli"]').check()
        type_panel.locator('[data-filter-dropdown-apply]').click()

        after_type = set(_visible_product_names(page))
        assert after_type == {"ChatGPT", "ai-helper"}
        assert page.locator(".filter-chip", has_text="Desktop app").count() == 1
        assert page.locator(".filter-chip", has_text="CLI").count() == 1

        # State: unreviewed only, combined with the Type filter above -
        # both ChatGPT and ai-helper are already unreviewed, so this must
        # not drop either of them (an AND across dimensions, not a
        # replace).
        page.locator(STATE_SUMMARY).click()
        state_panel = page.locator("details[data-row-filter='ai_state']")
        state_panel.locator('input[type="checkbox"][value="unreviewed"]').check()
        state_panel.locator('[data-filter-dropdown-apply]').click()

        after_state = set(_visible_product_names(page))
        assert after_state == {"ChatGPT", "ai-helper"}
        assert page.locator(".filter-chip", has_text="Unreviewed").count() == 1

        # Removing the CLI chip narrows further (AND, not a reset).
        page.locator(".filter-chip", has_text="CLI").click()
        page.wait_for_load_state("networkidle")
        narrowed = set(_visible_product_names(page))
        assert narrowed == {"ChatGPT"}
        assert page.locator(".filter-chip", has_text="Desktop app").count() == 1
        assert page.locator(".filter-chip", has_text="CLI").count() == 0

        # Clear all restores every row.
        page.locator(".filter-chip--clear").click()
        page.wait_for_load_state("networkidle")
        restored = set(_visible_product_names(page))
        assert restored == before
        assert page.locator(".filter-chip").count() == 0
    finally:
        context.close()


def test_no_horizontal_overflow_at_1280_and_390(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        for width in (1280, 390):
            page.set_viewport_size({"width": width, "height": 1000})
            page.goto("/ai-tooling", wait_until="networkidle")
            assert page.evaluate(
                "() => document.documentElement.scrollWidth <= window.innerWidth"
            ), f"horizontal overflow at {width}px"
            page.get_by_role("button", name="Dark").click()
            assert page.evaluate(
                "() => document.documentElement.scrollWidth <= window.innerWidth"
            ), f"horizontal overflow at {width}px in dark theme"
    finally:
        context.close()


def test_compact_summary_stays_above_the_products_list(browser, harness_url):
    """PAT-2243 owner direction supersedes the earlier four-tile layout."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        for width in (1280, 390):
            page.set_viewport_size({"width": width, "height": 1000})
            page.goto("/ai-tooling", wait_until="networkidle")
            summary = page.locator(".ai-review-summary")
            assert summary.locator(".ai-summary__item").count() == 4
            assert summary.bounding_box()["y"] < page.locator("#products").bounding_box()["y"]
            products_top = page.locator("#products").bounding_box()["y"]
            assert products_top < page.locator("#notifications").bounding_box()["y"]
    finally:
        context.close()
