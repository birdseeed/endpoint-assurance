"""PAT-2140 in a real browser: the Overview's New software card is
colour-coded (urgency counters and Urgency pills reuse the portal's
existing severity tones, in both themes), First seen reads on at most two
lines at 1280px (date, then time - never the old one-word-per-line wrap of
"24 Sep 2026 20:51 UTC"), and Platform reads macOS/Windows rather than the
raw macos/windows platform key.

Full write-path and lock-rule coverage lives in
tests/test_pat2093_new_software.py; this file is layout + tone smoke
against a real rendered page, the same split e2e/test_pat2093_new_software.py
already uses.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import (
    MEASURE_JS,
    TABLE_SCROLL_MEASURE_JS,
    WIDE_FALLBACK_FONT_CSS,
)
from tests.conftest import OVERVIEW, STUB_STATE

NEW_SOFTWARE = {
    "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
    "until": "2026-09-25T12:00:00Z", "window_days": 14, "last_review_at": None,
    "total": 5,
    "counts": {"critical": 1, "high": 1, "not_assessed": 1, "medium": 1, "low": 1},
    "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
    "truncated": False, "limit": 50,
    "products": [
        {"name": "CriticalTool", "platform": "macos", "identifier": "com.example.critical",
         "team_id": "ABCDE12345", "product_key": "application:macos:com.example.critical",
         "approval_state": "unreviewed", "first_seen_at": "2026-09-24T20:51:00Z",
         "device_count": 3, "urgency": "critical",
         "reasons": [{"code": "unsigned", "level": "critical", "detail": "unsigned binary"}]},
        {"name": "HighTool", "platform": "windows", "identifier": "high-tool.exe",
         "team_id": None, "product_key": None,
         "approval_state": "unreviewed", "first_seen_at": "2026-09-24T09:05:00Z",
         "device_count": 2, "urgency": "high",
         "reasons": [{"code": "unknown_publisher", "level": "high", "detail": "no publisher"}]},
        {"name": "NotAssessedTool", "platform": "macos", "identifier": "com.example.na",
         "team_id": "ABCDE12345", "product_key": "application:macos:com.example.na",
         "approval_state": "unreviewed", "first_seen_at": "2026-09-23T14:30:00Z",
         "device_count": 1, "urgency": "not_assessed",
         "reasons": [{"code": "signing_unknown", "level": "not_assessed",
                      "detail": "not yet assessed"}]},
        {"name": "MediumTool", "platform": "macos", "identifier": "com.example.medium",
         "team_id": "ABCDE12345", "product_key": "application:macos:com.example.medium",
         "approval_state": "unreviewed", "first_seen_at": "2026-09-22T08:00:00Z",
         "device_count": 1, "urgency": "medium", "reasons": []},
        {"name": "LowTool", "platform": "windows", "identifier": "low-tool.exe",
         "team_id": None, "product_key": None,
         "approval_state": "unreviewed", "first_seen_at": "2026-09-21T23:59:00Z",
         "device_count": 1, "urgency": "low", "reasons": []},
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


LINE_COUNT_JS = """
sel => Array.prototype.map.call(document.querySelectorAll(sel), el => el.getClientRects().length)
"""


def test_first_seen_reads_on_two_lines_at_1280(browser, harness_url):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": NEW_SOFTWARE}
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")
        _assert_no_overflow(page)

        date_lines = page.evaluate(LINE_COUNT_JS, ".new-software-table .cell-evidence__main")
        time_lines = page.evaluate(LINE_COUNT_JS, ".new-software-table .cell-evidence .cell-subtle")
        assert date_lines, "no First seen date cells rendered"
        assert time_lines, "no First seen time cells rendered"
        # Each half (date, then time) is one line on its own - together at
        # most two lines total, never the old one-word-per-line wrap of a
        # single "24 Sep 2026 20:51 UTC" string.
        assert all(n == 1 for n in date_lines), date_lines
        assert all(n == 1 for n in time_lines), time_lines

        row = page.locator("tr", has_text="CriticalTool")
        assert "24 Sep 2026" in row.inner_text()
        assert "20:51" in row.inner_text()
    finally:
        context.close()


def test_platform_reads_macos_and_windows_not_raw_key(browser, harness_url):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": NEW_SOFTWARE}
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")
        body = page.content()
        assert "macOS" in body
        assert "Windows" in body
        table = page.locator(".new-software-table")
        assert "macos" not in table.inner_text()
        assert "windows" not in table.inner_text()
    finally:
        context.close()


def _pill_colour(page, locator):
    return locator.evaluate(
        "el => { const c = getComputedStyle(el); return [c.color, c.backgroundColor]; }"
    )


def test_urgency_pills_and_kpi_counters_are_colour_coded_in_both_themes(browser, harness_url):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": NEW_SOFTWARE}
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/", wait_until="networkidle")

        for theme in ("light", "dark"):
            if theme == "dark":
                page.click('.theme-toggle__btn[data-theme-choice="dark"]')
                assert page.evaluate(
                    "document.documentElement.getAttribute('data-theme')") == "dark"

            pills = {
                name: page.locator(".new-software-table tr", has_text=name).locator(".pill")
                for name in ("CriticalTool", "HighTool", "NotAssessedTool", "MediumTool", "LowTool")
            }
            colours = {name: _pill_colour(page, loc) for name, loc in pills.items()}
            # Every pill is coloured (background/foreground pair not pure
            # black-on-transparent), and no two severities share an
            # identical colour pair - the exact defect Andy's live review
            # flagged ("no colour coding").
            values = list(colours.values())
            assert len(set(tuple(v) for v in values)) == len(values), colours

            kpi_values = page.locator(".new-software .kpi__value")
            classes = kpi_values.evaluate_all("els => els.map(el => el.className)")
            assert any("bad-text" in c for c in classes)
            assert any("warn-text" in c for c in classes)
            assert any("graphite-text" in c for c in classes)
            assert any("mute-text" in c for c in classes)
            # The class alone is not the check that matters - portal.css
            # declares .kpi__value's own color AFTER .bad-text/.warn-text/
            # .ok-text in the file, so on equal (single-class) specificity
            # the later .kpi__value rule silently won the cascade and the
            # class had no visible effect at all. A first pass at this
            # test only checked className and would have stayed green
            # through that; assert the actual rendered colours differ
            # instead, which is what a screenshot review would catch.
            kpi_colours = kpi_values.evaluate_all(
                "els => els.map(el => getComputedStyle(el).color)")
            assert len(set(kpi_colours)) > 1, kpi_colours
            # Colour is never the only signal: every counter's label text
            # (Critical/High/Not assessed/Medium/Low) is still present.
            # .kpi__label is CSS text-transform: uppercase, which changes
            # innerText's rendered case but not the underlying label -
            # compare case-insensitively rather than fight the stylesheet.
            labels = [t.casefold() for t in
                      page.locator(".new-software .kpi__label").all_inner_texts()]
            for label in ("Critical", "High", "Not assessed", "Medium", "Low"):
                assert label.casefold() in labels
    finally:
        context.close()
