"""Guards PAT-2188: the footer stays in document flow and never overlays content.

The desktop rail remains pinned, but the footer appears only after the page
content. The former sticky footer covered the bottom of cards while scrolling
and created an intrusive wordmark strip beside the rail's Support block.
"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN

# /findings is a long page in the stub; any page taller than the viewport
# exercises the same rule.
LONG_PAGE = "/findings"


def _context(browser, harness_url, color_scheme):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _footer_top_and_viewport(page):
    return page.evaluate(
        "() => [document.querySelector('.footer').getBoundingClientRect().top,"
        " document.querySelector('.footer').getBoundingClientRect().bottom,"
        " window.innerHeight,"
        " document.documentElement.scrollHeight]"
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_footer_stays_below_viewport_mid_scroll_on_desktop(browser, harness_url, color_scheme):
    context = _context(browser, harness_url, color_scheme)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 700})
        page.goto(f"{harness_url}{LONG_PAGE}", wait_until="networkidle")
        _, _, vh, scroll_height = _footer_top_and_viewport(page)
        assert scroll_height > vh * 1.5, "stub page must be long enough to scroll"

        page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight / 3)")
        top, _, vh, _ = _footer_top_and_viewport(page)
        assert top >= vh, f"footer overlays the viewport mid-scroll ({top} < {vh})"

        position = page.evaluate(
            "() => getComputedStyle(document.querySelector('.footer')).position"
        )
        assert position == "static", f"footer is {position} at 1280px"

        # The rail remains pinned independently of the footer.
        support = page.evaluate(
            "() => document.querySelector('.rail__specialist').getBoundingClientRect().bottom"
        )
        assert support <= vh + 1, f"rail Support block below the viewport ({support} > {vh})"
    finally:
        context.close()


def test_last_content_visible_above_footer_at_end(browser, harness_url):
    context = _context(browser, harness_url, "light")
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 700})
        page.goto(f"{harness_url}{LONG_PAGE}", wait_until="networkidle")
        page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
        last_bottom, footer_top = page.evaluate(
            "() => { const main = document.querySelector('main.page');"
            " const kids = Array.from(main.children).filter("
            "  (el) => el.getBoundingClientRect().height > 0);"
            " const last = kids[kids.length - 1];"
            " return [last.getBoundingClientRect().bottom,"
            "  document.querySelector('.footer').getBoundingClientRect().top]; }"
        )
        assert last_bottom <= footer_top + 1, (
            f"last content ends at {last_bottom}, hidden behind footer at {footer_top}"
        )
    finally:
        context.close()


def test_footer_not_pinned_on_phone(browser, harness_url):
    context = _context(browser, harness_url, "light")
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 800})
        page.goto(f"{harness_url}{LONG_PAGE}", wait_until="networkidle")
        position = page.evaluate(
            "() => getComputedStyle(document.querySelector('.footer')).position"
        )
        assert position == "static", f"footer is {position} at 390px"
        page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight / 3)")
        top, _, vh, _ = _footer_top_and_viewport(page)
        assert top >= vh, "footer pinned into view mid-scroll on a phone"
    finally:
        context.close()
