"""PAT-2093 in a real browser: the overview's "New software" card renders
in both themes with no horizontal document or table-scroll overflow at
1280px and 1440px (the .col-secondary reveal tier boundary). Reuses
test_table_overflow.py's WIDE_FALLBACK_FONT_CSS/_force_wide_fallback_font
and MEASURE_JS/TABLE_SCROLL_MEASURE_JS helpers rather than inventing a
second copy of the overflow guard - see that module's docstring for why
both the whole-document and the table's-own-scroll-container checks matter.

Full write-path and lock-rule coverage lives in
tests/test_pat2093_new_software.py against the same stub; this file is
smoke + layout only.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import (
    MEASURE_JS,
    TABLE_SCROLL_MEASURE_JS,
    WIDE_FALLBACK_FONT_CSS,
)
from tests.conftest import OVERVIEW, STUB_STATE

WIDTHS = (1280, 1440)

# A long product name and a long reason detail - the same class of stress
# value test_table_overflow.py's long_data_stub uses elsewhere - so the
# reveal-tier table and the reasons disclosure are both exercised at a
# realistic worst case, not just short fixture strings.
LONG_PRODUCT_NAME = (
    "Really Quite A Long Third-Party Enterprise Application Name For "
    "Accounting And Payroll Reconciliation Suite Professional Edition"
)
LONG_REASON_DETAIL = (
    "the collector could not establish a signing authority on the installation "
    "(codesign could not read it, or an agent too old to say whether it is "
    "unsigned or ad hoc signed) and no Team ID was reported either"
)

NEW_SOFTWARE = {
    "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
    "until": "2026-09-24T12:00:00Z", "window_days": 14, "last_review_at": None,
    "total": 2,
    "counts": {"critical": 1, "high": 1, "not_assessed": 0, "medium": 0, "low": 0},
    "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
    "truncated": False, "limit": 50,
    "products": [
        {
            "name": LONG_PRODUCT_NAME, "platform": "macos",
            "identifier": "com.example.longtool", "team_id": "LONGT12345",
            "product_key": "application:macos:com.example.longtool",
            "approval_state": "unreviewed", "first_seen_at": "2026-09-23T08:00:00Z",
            "device_count": 3, "urgency": "critical",
            "reasons": [
                {"code": "unsigned", "level": "critical", "detail": LONG_REASON_DETAIL},
                {"code": "unknown_publisher", "level": "high", "detail": "no Team ID reported"},
            ],
        },
        {
            "name": "AnotherNewTool", "platform": "windows", "identifier": None,
            "team_id": None, "product_key": None,
            "approval_state": "unreviewed", "first_seen_at": "2026-09-22T08:00:00Z",
            "device_count": 1, "urgency": "high",
            "reasons": [{"code": "signing_unknown", "level": "high",
                        "detail": "no signing evidence was reported"}],
        },
    ],
}


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _assert_no_overflow(page):
    doc = page.evaluate(MEASURE_JS)
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"document scrollWidth={doc['scrollWidth']} > clientWidth={doc['clientWidth']}"
    )
    for r in page.evaluate(TABLE_SCROLL_MEASURE_JS):
        raise AssertionError(
            f"table {r['tableCls']} scroll container overflows: "
            f"scrollWidth={r['scrollWidth']} > clientWidth={r['clientWidth']}"
        )


def test_new_software_card_renders_in_both_themes_with_no_overflow(browser, harness_url):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": NEW_SOFTWARE}
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        page.goto("/", wait_until="networkidle")
        assert "New software" in page.content()
        assert LONG_PRODUCT_NAME in page.content()
        assert "AnotherNewTool" in page.content()

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            _assert_no_overflow(page)

        # Light theme (default) is visible and rendered.
        assert page.locator("#new-software-heading").is_visible()
        light_bg = page.evaluate(
            "getComputedStyle(document.querySelector('.new-software')).backgroundColor"
        )

        # Switch to dark and re-check both the overflow guard and that the
        # card actually re-themes rather than only toggling an attribute.
        page.click('.theme-toggle__btn[data-theme-choice="dark"]')
        assert page.evaluate(
            "document.documentElement.getAttribute('data-theme')"
        ) == "dark"
        assert page.locator("#new-software-heading").is_visible()
        dark_bg = page.evaluate(
            "getComputedStyle(document.querySelector('.new-software')).backgroundColor"
        )
        assert dark_bg != light_bg

        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            _assert_no_overflow(page)
    finally:
        context.close()
