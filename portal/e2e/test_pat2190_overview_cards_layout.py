"""PAT-2190 in a real browser: the ten Overview information cards reflow
cleanly across desktop and phone widths and render in both themes (PAT-2190
acceptance: "Cards reflow cleanly across desktop, tablet and phone" /
"Visual QA covers light and dark themes at desktop and phone widths").

Full state-matrix coverage (every contract state, every reason code) lives
in tests/test_pat2190_overview_cards.py; this file is layout/theme/overflow
smoke against a real rendered page, the same split PAT-2160's own e2e file
uses for the welcome block.

Written before main.py/overview.html carry this feature, so every test here
is expected to fail red right now - on a locator count of 0, not an
exception, because no `[data-card]` element exists yet.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS, WIDE_FALLBACK_FONT_CSS
from tests.conftest import OVERVIEW_CARDS, STUB_STATE

CARD_KEYS = [
    "devices", "os_updates", "vulnerabilities", "cis_posture",
    "browser_extensions", "high_risk_software", "software_awaiting_approval",
    "exceptions_review", "agent_health", "recent_activity",
]


def _context(browser, harness_url, color_scheme="light"):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _assert_no_document_overflow(page):
    doc = page.evaluate(MEASURE_JS)
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"document scrollWidth={doc['scrollWidth']} > clientWidth={doc['clientWidth']}"
    )


def _goto_overview(page, width, height=1000, dark_fallback_font=False):
    if dark_fallback_font:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
    page.set_viewport_size({"width": width, "height": height})
    page.goto("/", wait_until="networkidle")


def test_ten_cards_render_at_desktop_1440(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        for key in CARD_KEYS:
            assert page.locator(f'[data-card="{key}"]').count() == 1, key
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_ten_cards_render_and_stack_at_phone_390_with_no_overflow(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 390, dark_fallback_font=True)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_cards_render_in_dark_theme_at_desktop_and_phone(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    context = _context(browser, harness_url, color_scheme="dark")
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_no_document_overflow(page)

        _goto_overview(page, 390, dark_fallback_font=True)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_each_card_is_a_single_focusable_link_with_an_accessible_name(browser, harness_url):
    """PAT-2190 keyboard/screen-reader acceptance: the whole card is one
    link with a meaningful accessible name. recent_activity is the one
    exception (Orchestrator review correction): it has no real destination (the
    platform marks it permanently unavailable, and /whats-new is the
    changelog, not estate activity), so it is a plain, non-focusable <div>
    instead - still readable, just not a link that goes nowhere useful."""
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        cards = page.locator("[data-card]")
        count = cards.count()
        assert count == len(CARD_KEYS)
        for i in range(count):
            card = cards.nth(i)
            key = card.get_attribute("data-card")
            tag = card.evaluate("el => el.tagName.toLowerCase()")
            name = card.evaluate(
                "el => el.getAttribute('aria-label') || el.textContent"
            ).strip()
            assert name, f"{key} card has no accessible name"
            if key == "recent_activity":
                assert tag == "div", "recent_activity must not be a link"
                tabindex = card.evaluate("el => el.getAttribute('tabindex')")
                assert tabindex is None, "recent_activity must not be focusable"
            else:
                assert tag == "a", f"{key} card must be a link"
    finally:
        context.close()


def test_grid_columns_5_at_1440_and_4_at_1280(browser, harness_url):
    """PAT-2190 review: explicit column targets, not just "no overflow" -
    5 columns (two rows) at 1440px, 3 or 4 at 1280px."""
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        cols_1440 = page.evaluate(
            "() => getComputedStyle(document.querySelector('.overview-cards__grid'))"
            ".gridTemplateColumns.split(' ').length"
        )
        assert cols_1440 == 5, f"expected 5 columns at 1440px, got {cols_1440}"
        _assert_no_document_overflow(page)

        _goto_overview(page, 1280)
        cols_1280 = page.evaluate(
            "() => getComputedStyle(document.querySelector('.overview-cards__grid'))"
            ".gridTemplateColumns.split(' ').length"
        )
        assert cols_1280 in (3, 4), f"expected 3 or 4 columns at 1280px, got {cols_1280}"
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_cards_section_has_no_console_errors(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    context = _context(browser, harness_url)
    page = context.new_page()
    errors = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    try:
        _goto_overview(page, 1440)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        assert not errors, f"console errors on Overview: {errors}"
    finally:
        context.close()
