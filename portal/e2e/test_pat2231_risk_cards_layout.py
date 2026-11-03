"""PAT-2231 in a real browser: High-risk software and Browser extensions are
redesigned as a consistent pair - balanced side by side at desktop widths
(equal height, per the ticket's own acceptance criterion) and stacking
cleanly, with no page-wide horizontal overflow, at 390px. Both in light and
dark theme.

Full state-matrix coverage of the two view functions
(_high_risk_software_view/_extension_risk_view) lives in
tests/test_pat2177_overview_hierarchy.py; this file is layout/overflow smoke
against a real rendered page, the same split PAT-2190/PAT-2230's own e2e
files use.

Written before portal.css/overview.html carried the PAT-2231 redesign, so
every test here is expected to fail red on the pre-redesign markup: the old
`.grid-review { align-items: start; }` let the two cards sit at different
heights, and this file's height-parity assertion catches exactly that.
"""

import tests.conftest as tests_conftest
from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS, WIDE_FALLBACK_FONT_CSS
from tests.conftest import OVERVIEW, STUB_STATE
from tests.test_pat2093_new_software import _new_software, _product

# A populated High-risk software card (more products than the top-N preview
# shows, so the "more" line and full badge row render) paired with the
# default EXTENSIONS fixture's own Browser extensions card (one elevated,
# one waiting) - two cards with genuinely different content, which is
# exactly the case the old `align-items: start` broke.
RISK_OVERVIEW_DATA = {
    **OVERVIEW,
    "new_software": _new_software(
        window_days=14, total=4,
        counts={"critical": 2, "high": 2, "not_assessed": 1, "medium": 0, "low": 0},
        products=[
            _product("RiskyTool", "critical", device_count=12, reasons=[
                {"code": "unsigned", "level": "critical", "detail": "Unsigned"},
                {"code": "publisher_unknown", "level": "high", "detail": "Unknown publisher"},
            ]),
            _product("OtherTool", "high", device_count=3),
            _product("ThirdTool", "critical", device_count=1),
            _product("FourthTool", "high", device_count=1),
        ],
    ),
}

# PAT-2231 review: a Browser extensions fixture with more elevated-risk rows
# than the top-N preview shows, so the card's own preview also fills to 3
# rows instead of the default fixture's single elevated row - the exact
# case the coordinator asked be checked (extensions with 3+ items, not just
# High-risk).
MANY_EXTENSIONS = {
    "total": 5,
    "truncated": False,
    "estate_too_large": False,
    "extensions": [
        {"extension_id": "ext-1", "name": "ShadyCoupons", "browser": "chrome",
         "risk_level": "elevated", "device_count": 9, "approval_state": "unreviewed"},
        {"extension_id": "ext-2", "name": "WideAccessVPN", "browser": "chrome",
         "risk_level": "elevated", "device_count": 6, "approval_state": "unreviewed"},
        {"extension_id": "ext-3", "name": "ScreenGrabberPro", "browser": "edge",
         "risk_level": "elevated", "device_count": 4, "approval_state": "unapproved"},
        {"extension_id": "ext-4", "name": "AdBlock Plus", "browser": "chrome",
         "risk_level": "elevated", "device_count": 2, "approval_state": "approved"},
        {"extension_id": "ext-5", "name": "TeamChat", "browser": "firefox",
         "risk_level": "normal", "device_count": 12, "approval_state": "approved"},
    ],
}

RISK_CARD_MEASURE_JS = """
() => Array.from(document.querySelectorAll('.risk-card')).map((el) => {
  const r = el.getBoundingClientRect();
  const foot = el.querySelector('.card-foot');
  const prev = foot ? foot.previousElementSibling : null;
  const footRect = foot ? foot.getBoundingClientRect() : null;
  const prevRect = prev ? prev.getBoundingClientRect() : null;
  const rows = el.querySelectorAll('.risk-list--compact > .risk-list__row').length;
  return {
    top: r.top, bottom: r.bottom, left: r.left, height: r.height, rows: rows,
    footGap: (footRect && prevRect) ? footRect.top - prevRect.bottom : null,
  };
})
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


def _goto_overview(page, width, height=1400, dark_fallback_font=False):
    if dark_fallback_font:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
    page.set_viewport_size({"width": width, "height": height})
    page.goto("/", wait_until="networkidle")


def _assert_equal_height_pair(browser, harness_url, color_scheme):
    STUB_STATE["overview_data"] = RISK_OVERVIEW_DATA
    context = _context(browser, harness_url, color_scheme=color_scheme)
    page = context.new_page()
    try:
        _goto_overview(page, 1440, dark_fallback_font=(color_scheme == "dark"))
        cards = page.evaluate(RISK_CARD_MEASURE_JS)
        assert len(cards) == 2, f"expected exactly 2 .risk-card elements, got {cards}"
        heights = [c["height"] for c in cards]
        assert abs(heights[0] - heights[1]) <= 1, (
            f"High-risk software and Browser extensions cards are not equal "
            f"height at 1440px ({color_scheme}): {cards}"
        )
        # They must actually be side by side (same row), not one above the
        # other reporting a coincidentally equal height.
        assert abs(cards[0]["top"] - cards[1]["top"]) <= 1, (
            f"cards are not on the same row at 1440px ({color_scheme}): {cards}"
        )
        _assert_no_document_overflow(page)
    finally:
        context.close()


def _assert_clean_stack_no_overflow(browser, harness_url, color_scheme):
    STUB_STATE["overview_data"] = RISK_OVERVIEW_DATA
    context = _context(browser, harness_url, color_scheme=color_scheme)
    page = context.new_page()
    try:
        _goto_overview(page, 390, dark_fallback_font=(color_scheme == "dark"))
        cards = page.evaluate(RISK_CARD_MEASURE_JS)
        assert len(cards) == 2, f"expected exactly 2 .risk-card elements, got {cards}"
        first, second = cards
        # Single column: same left edge, second card starts at or below the
        # first card's bottom (no overlap).
        assert abs(first["left"] - second["left"]) <= 1, (
            f"cards are not stacked in a single column at 390px ({color_scheme}): {cards}"
        )
        assert second["top"] >= first["bottom"] - 1, (
            f"cards overlap when stacked at 390px ({color_scheme}): {cards}"
        )
        _assert_no_document_overflow(page)
    finally:
        context.close()


def test_risk_cards_equal_height_at_1440_light(browser, harness_url):
    _assert_equal_height_pair(browser, harness_url, "light")


def test_risk_cards_equal_height_at_1440_dark(browser, harness_url):
    _assert_equal_height_pair(browser, harness_url, "dark")


def test_risk_cards_stack_without_overflow_at_390_light(browser, harness_url):
    _assert_clean_stack_no_overflow(browser, harness_url, "light")


def test_risk_cards_stack_without_overflow_at_390_dark(browser, harness_url):
    _assert_clean_stack_no_overflow(browser, harness_url, "dark")


def _assert_no_dead_gap_before_primary_action(browser, harness_url, max_gap_px):
    """PAT-2231 review: the grid stretching the pair to equal height must
    not leave a large blank gap between a card's preview content and its
    primary action - that gap is what let the shorter card read as mostly
    empty space. A small gap from ordinary margin/padding is fine; the
    pre-fix defect was on the order of hundreds of pixels (see
    _assert_equal_height_pair's own red-proof run: a 499px height
    mismatch, all of it dead space in the shorter card)."""
    STUB_STATE["overview_data"] = RISK_OVERVIEW_DATA
    context = _context(browser, harness_url, color_scheme="light")
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        cards = page.evaluate(RISK_CARD_MEASURE_JS)
        assert len(cards) == 2, f"expected exactly 2 .risk-card elements, got {cards}"
        for card in cards:
            assert card["footGap"] is not None, f"card has no measurable gap: {card}"
            assert card["footGap"] <= max_gap_px, (
                f"primary action sits {card['footGap']:.0f}px below its "
                f"card's content, not right after it: {card}"
            )
    finally:
        context.close()


def test_no_dead_gap_before_primary_action_with_one_elevated_extension(browser, harness_url):
    _assert_no_dead_gap_before_primary_action(browser, harness_url, max_gap_px=40)


def test_extensions_card_shows_up_to_three_preview_rows_with_more_than_three(
    browser, harness_url, monkeypatch,
):
    # PAT-2231 review: "show up to 3 preview rows there too" - a fixture
    # with 4 elevated-risk extensions still caps the preview at
    # OVERVIEW_RISK_TOP_N (3), matching High-risk's own cap, rather than
    # only ever showing the single row the default fixture happens to have.
    monkeypatch.setattr(tests_conftest, "EXTENSIONS", MANY_EXTENSIONS)
    STUB_STATE["overview_data"] = RISK_OVERVIEW_DATA
    context = _context(browser, harness_url, color_scheme="light")
    page = context.new_page()
    try:
        _goto_overview(page, 1440)
        cards = page.evaluate(RISK_CARD_MEASURE_JS)
        assert len(cards) == 2, f"expected exactly 2 .risk-card elements, got {cards}"
        rows_by_card = [c["rows"] for c in cards]
        assert 3 in rows_by_card, (
            f"expected one card with exactly 3 preview rows, got {cards}"
        )
        # And the pair still balances - equal height, no dead gap - with a
        # fuller extensions card, not just the sparse default fixture.
        heights = [c["height"] for c in cards]
        assert abs(heights[0] - heights[1]) <= 1, (
            f"cards are not equal height with a fuller extensions fixture: {cards}"
        )
        for card in cards:
            assert card["footGap"] <= 40, (
                f"primary action sits {card['footGap']:.0f}px below its "
                f"card's content with a fuller extensions fixture: {card}"
            )
        _assert_no_document_overflow(page)
    finally:
        context.close()
