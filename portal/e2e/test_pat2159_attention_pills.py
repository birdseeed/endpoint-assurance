"""PAT-2159 in a real browser: the Overview's CIS and CVE attention render
as severity pills inside one merged "Needs attention" card, a zero pill's
computed colour differs from a non-zero High pill's (PAT-2140's lesson - a
class name alone is not the check that matters), the New software card is
absent, present, or present-with-an-unavailable-line depending on the
new_software read, and none of this overflows at 390px.

Full state-matrix coverage (unit level) lives in
tests/test_pat1951_overview_attention.py, tests/test_pat1953_cve_attention.py
and tests/test_pat2093_new_software.py; this file is layout + colour smoke
against a real rendered page, the same split the PAT-2093/PAT-2140 e2e files
already use.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS, WIDE_FALLBACK_FONT_CSS
from tests.conftest import OVERVIEW, STUB_STATE


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _assert_no_document_overflow(page):
    doc = page.evaluate(MEASURE_JS)
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"document scrollWidth={doc['scrollWidth']} > clientWidth={doc['clientWidth']}"
    )


def test_cis_and_cve_pills_render_inside_one_card_at_1280(browser, harness_url):
    STUB_STATE["overview_data"] = {
        **OVERVIEW,
        "findings_open": {"critical": 1, "high": 3, "medium": 5, "low": 2},
        "cve_attention": {"available": True, "critical": 0, "high": 6},
    }
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")

        cards = page.locator(".attention-summary")
        assert cards.count() == 1, "CIS and CVE attention must sit in one card, not two"
        card = cards.first
        # .attention-row__label is CSS text-transform: uppercase, which
        # changes inner_text()'s rendered case but not the underlying
        # label - compare case-insensitively rather than fight the
        # stylesheet (same idiom PAT-2140's e2e coverage already uses).
        card_text = card.inner_text().casefold()
        assert "cis checks failing" in card_text
        assert "confirmed cves" in card_text

        cis_row = page.locator(".attention-row", has_text="CIS checks failing")
        cve_row = page.locator(".attention-row", has_text="Confirmed CVEs")
        assert cis_row.locator(".pill").count() == 2
        assert cve_row.locator(".pill").count() == 2
    finally:
        context.close()


def test_zero_pill_and_nonzero_high_pill_have_different_computed_colour(browser, harness_url):
    STUB_STATE["overview_data"] = {
        **OVERVIEW,
        "findings_open": {"critical": 0, "high": 4, "medium": 0, "low": 0},
        "cve_attention": {"available": True, "critical": 0, "high": 0},
    }
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")

        cis_row = page.locator(".attention-row", has_text="CIS checks failing")
        zero_pill = cis_row.locator(".pill").first  # "0 critical" - pill-muted
        high_pill = cis_row.locator(".pill").nth(1)  # "4 high" - pill-high
        # .pill is CSS text-transform: uppercase too - compare case-
        # insensitively, same as the card-level label check above.
        assert "0 critical" in zero_pill.inner_text().casefold()
        assert "4 high" in high_pill.inner_text().casefold()

        def colour(locator):
            return locator.evaluate(
                "el => { const c = getComputedStyle(el); return [c.color, c.backgroundColor]; }"
            )

        zero_colour = colour(zero_pill)
        high_colour = colour(high_pill)
        # Computed colour, not class names - PAT-2140's lesson: a rule
        # ordering bug can leave two differently-classed elements rendering
        # identically.
        assert zero_colour != high_colour, (zero_colour, high_colour)
    finally:
        context.close()


NEW_SOFTWARE_NONZERO = {
    "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
    "until": "2026-09-25T12:00:00Z", "window_days": 14, "last_review_at": None,
    "total": 1,
    "counts": {"critical": 1, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
    "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
    "truncated": False, "limit": 50,
    "products": [{
        "name": "FreshTool", "platform": "macos", "identifier": "com.example.fresh",
        "team_id": "ABCDE12345", "product_key": "application:macos:com.example.fresh",
        "approval_state": "unreviewed", "first_seen_at": "2026-09-24T08:00:00Z",
        "device_count": 1, "urgency": "critical",
        "reasons": [{"code": "unsigned", "level": "critical", "detail": "unsigned binary"}],
    }],
}

NEW_SOFTWARE_ZERO = {
    "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
    "until": "2026-09-25T12:00:00Z", "window_days": 14, "last_review_at": None,
    "total": 0,
    "counts": {"critical": 0, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
    "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
    "truncated": False, "limit": 50, "products": [],
}


def test_new_software_card_absent_present_and_unavailable_per_state(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})

        # Non-zero read: the card is shown, with the real row.
        STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": NEW_SOFTWARE_NONZERO}
        page.goto("/", wait_until="networkidle")
        assert page.locator("#new-software-heading").count() == 1
        assert "FreshTool" in page.content()

        # A successful read reporting zero new products: the card is gone
        # entirely, not shown with an empty state.
        STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": NEW_SOFTWARE_ZERO}
        page.goto("/", wait_until="networkidle")
        assert page.locator("#new-software-heading").count() == 0
        assert "New software" not in page.content()

        # A failed/untrustworthy read: the card stays, with an explicit
        # unavailable line - it must never look like the zero-read case.
        STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": None}
        page.goto("/", wait_until="networkidle")
        assert page.locator("#new-software-heading").count() == 1
        assert "could not be read" in page.content()
    finally:
        context.close()


def test_no_overflow_at_390px(browser, harness_url):
    STUB_STATE["overview_data"] = {
        **OVERVIEW,
        "findings_open": {"critical": 1, "high": 3, "medium": 5, "low": 2},
        "cve_attention": {"available": True, "critical": 2, "high": 6},
        "new_software": NEW_SOFTWARE_NONZERO,
    }
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto("/", wait_until="networkidle")
        _assert_no_document_overflow(page)
        assert page.locator(".attention-summary").count() == 1
    finally:
        context.close()
