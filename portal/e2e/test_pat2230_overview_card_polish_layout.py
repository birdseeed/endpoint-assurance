"""PAT-2230 in a real browser: the CIS posture headline no longer overflows
the card at 1162px (the width where the raw unrounded float created a
whole-page horizontal scrollbar in production, 2026-09-28), in both themes,
and the freshness line pins to the same y across every card in a grid row -
the vertical-rhythm acceptance criterion from the ticket.

Full state/tone coverage lives in tests/test_pat2230_overview_card_polish.py;
this file is layout/overflow/alignment smoke against a real rendered page,
the same split PAT-2190's own e2e file uses.

Written before portal.css/overview.html/main.py carry this fix, so every
test here is expected to fail red on the long-float fixture - a document
scrollWidth > clientWidth at 1162px, or freshness bottoms that don't match
within a row.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS, WIDE_FALLBACK_FONT_CSS
from tests.conftest import STUB_STATE
from tests.test_pat2230_overview_card_polish import OVERVIEW_CARDS_PAT2230

CARD_KEYS = [
    "devices", "os_updates", "vulnerabilities", "cis_posture",
    "browser_extensions", "high_risk_software", "software_awaiting_approval",
    "exceptions_review", "agent_health", "recent_activity",
]

ROW_Y_MEASURE_JS = """
() => {
  const cards = Array.from(document.querySelectorAll('[data-card]'));
  return cards.map((card) => {
    const rect = card.getBoundingClientRect();
    const fresh = card.querySelector('.ov-card__freshness');
    const freshRect = fresh ? fresh.getBoundingClientRect() : null;
    return {
      key: card.getAttribute('data-card'),
      top: Math.round(rect.top),
      freshBottom: (fresh && fresh.textContent.trim())
        ? Math.round(freshRect.bottom) : null,
    };
  });
}
"""


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


def _goto_overview(page, width, height=1200, dark_fallback_font=False):
    if dark_fallback_font:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
    page.set_viewport_size({"width": width, "height": height})
    page.goto("/", wait_until="networkidle")


def _assert_freshness_rows_align(page):
    """Cards sharing the same top (a grid row) must have freshness lines
    at the same bottom y, for every card in that row that has one."""
    cards = page.evaluate(ROW_Y_MEASURE_JS)
    rows = {}
    for c in cards:
        rows.setdefault(c["top"], []).append(c)
    for top, row_cards in rows.items():
        bottoms = {c["freshBottom"] for c in row_cards if c["freshBottom"] is not None}
        assert len(bottoms) <= 1, (
            f"freshness lines misaligned in row at top={top}: {row_cards}"
        )


def test_no_document_overflow_at_1162_with_long_float_fixture_light(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    context = _context(browser, harness_url, color_scheme="light")
    page = context.new_page()
    try:
        _goto_overview(page, 1162)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_no_document_overflow_at_1162_with_long_float_fixture_dark(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    context = _context(browser, harness_url, color_scheme="dark")
    page = context.new_page()
    try:
        _goto_overview(page, 1162, dark_fallback_font=True)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_no_document_overflow_at_1440_with_long_float_fixture(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_cis_headline_has_overflow_protection_like_every_other_card_slot(browser, harness_url):
    """The label and support slots already clip with an ellipsis
    (portal.css); the headline slot never did, which is exactly what let
    the raw unrounded float blow the card out in production. Font
    metrics differ by environment, so this checks the deterministic
    thing (the computed style), not a pixel measurement that can pass or
    fail by a few px depending on the renderer."""
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1162)
        style = page.evaluate(
            "() => { const el = document.querySelector('.ov-card__headline');"
            " const cs = getComputedStyle(el);"
            " return {overflow: cs.overflowX, textOverflow: cs.textOverflow,"
            " whiteSpace: cs.whiteSpace}; }"
        )
        assert style["overflow"] == "hidden"
        assert style["textOverflow"] == "ellipsis"
        assert style["whiteSpace"] == "nowrap"
    finally:
        context.close()


def test_freshness_lines_share_the_same_y_within_a_row_at_1440(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_freshness_rows_align(page)
    finally:
        context.close()


def test_freshness_lines_share_the_same_y_within_a_row_at_1162(browser, harness_url):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        _goto_overview(page, 1162)
        assert page.locator("[data-card]").count() == len(CARD_KEYS)
        _assert_freshness_rows_align(page)
    finally:
        context.close()
