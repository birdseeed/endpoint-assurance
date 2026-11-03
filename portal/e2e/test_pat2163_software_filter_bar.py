"""PAT-2163 in a real browser: /software's filter bar (templates/_macros.html's
filter_bar macro - a Type <select>, a Publisher <select>, an Approval
checkbox <details> popover, a "More filters" <details> popover (minimum
devices) and the search box, with removable chips underneath) replacing the
two rows of segmented-tab boxes plus a separate Publisher/devices/
Unreviewed/Select-all-shown toolbar that used to eat ~540-990px of a phone
screen before any software showed (Andy, live, 2026-09-25 on the original
tabs screenshot; the orchestrator's live follow-up review on the rest,
including the bulk-action bar now hiding until something is selected and
"Select all shown" moving into the table's own select column).

Parsing/rendering/chip/return-path coverage lives in
tests/test_pat2163_software_filter_bar.py against the same stub this file
uses; this is the Done-when's own browser checks:

  1. at 390px, the first filter control plus its active-filter chips take
     no more than ~140px before the table's top, with nothing selected (the
     bulk bar hidden);
  2. picking two approval states shows only those rows, and clicking
     "Clear all" restores every row;
  3. at 1280px, approving a product from a filtered view lands back on
     that same filtered view (URL and dropdown state both);
  4. the bulk-action bar stays hidden until at least one row is selected
     (via the table header's own "Select all shown" checkbox or a row's
     own checkbox), then shows - pinned to the viewport bottom on a phone,
     inline above the table on desktop.

Red-proof: every assertion below fails against origin/main - the old
/software has no [data-filter-bar]/[data-more-filters]/.filter-chips markup
and no hidden-until-selected bulk bar at all, so every locator here finds
nothing and every measurement or interaction times out or asserts against
an empty/wrong result. See the ticket report for the captured red output.
"""

import re

from e2e.conftest import HARNESS_VALID_TOKEN

BAR_TO_TABLE_JS = """
() => {
  const bar = document.querySelector('[data-filter-bar]');
  const table = document.querySelector('.software-table-card');
  if (!bar || !table) return null;
  const barTop = bar.getBoundingClientRect().top;
  const tableTop = table.getBoundingClientRect().top;
  return tableTop - barTop;
}
"""

# Only the Approval popover carries data-row-filter (the More filters one
# does not - it feeds approvalFilterExcludes instead, not the row-filter/
# data-selected system - see static/js/portal.js), so this is unambiguous
# even though there are now two [data-filter-dropdown] elements on the page.
APPROVAL_SUMMARY = "details[data-row-filter] summary"
MORE_FILTERS_SUMMARY = "details[data-more-filters] summary"


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _visible_product_names(page):
    rows = page.locator("tr[data-approval-row]")
    names = []
    count = rows.count()
    for i in range(count):
        row = rows.nth(i)
        if row.is_visible():
            names.append(row.locator(".product-name").inner_text())
    return names


# ── 1. 390px: bar + chips height budget, nothing selected ────────────────

def test_filter_bar_height_at_390_is_under_140px(browser, harness_url):
    """Two active chips (one Type, one Approval) plus Clear all - the
    "two chips active" screenshot scenario - is the realistic worst case
    the budget has to hold under, not the empty/collapsed bar. Nothing is
    selected, so the bulk bar (hidden until a row is selected - see the
    tests below) contributes nothing to this measurement, matching the
    Done-when's own "nothing selected" scenario."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto("/software?type=application&approval=waiting", wait_until="networkidle")
        assert not page.locator("[data-bulk-bar]").is_visible()
        gap = page.evaluate(BAR_TO_TABLE_JS)
        assert gap is not None, "filter bar or table not found on the page"
        assert gap <= 140, (
            f"filter bar top to table top is {gap:.1f}px, over the ~140px budget "
            "(the original two-rows-of-tabs layout measured ~540px here, and the "
            "pre-fold Publisher/devices/Unreviewed/Select-all-shown toolbar plus "
            "always-visible bulk bar added a further ~450px on top of that - PAT-2163)"
        )
    finally:
        context.close()


# ── 2. pick two approval states, then Clear all restores everything ──────

def test_two_approval_states_filter_rows_and_clear_all_restores_them(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software", wait_until="networkidle")

        before = set(_visible_product_names(page))
        # Sanity: rows from at least three different decision groups are on
        # the unfiltered page (waiting/not_wanted/approved default fixture -
        # tests/conftest.py), or the filter check below would be vacuous.
        assert "MysteryApp" in before  # waiting
        assert "Slack" in before  # approved
        assert "TorrentBox" in before  # not wanted

        page.locator(APPROVAL_SUMMARY).click()
        approval_panel = page.locator("details[data-row-filter]")
        approval_panel.locator('input[type="checkbox"][value="approved"]').check()
        approval_panel.locator('input[type="checkbox"][value="not_wanted"]').check()
        approval_panel.locator('[data-filter-dropdown-apply]').click()

        filtered = set(_visible_product_names(page))
        # Only approved + not_wanted rows show.
        assert "Slack" in filtered
        assert "CorpVPN" in filtered  # mandatory, grouped with approved
        assert "TeamChat" in filtered  # approved extension
        assert "TorrentBox" in filtered
        assert "ShadyCoupons" in filtered  # not_wanted extension
        # Waiting/ignored/unrecognised rows are hidden.
        assert "MysteryApp" not in filtered
        assert "GuessWho" not in filtered
        assert "OldTheme" not in filtered
        assert "OddPolicy" not in filtered

        chips = page.locator(".filter-chip")
        # PAT-2255: "Unapproved" contains "approved", so match from the start.
        assert chips.filter(has_text=re.compile(r"^Approved")).count() == 1
        assert chips.filter(has_text=re.compile(r"^Unapproved")).count() == 1

        page.locator(".filter-chip--clear").click()
        page.wait_for_load_state("networkidle")
        restored = set(_visible_product_names(page))
        assert restored == before
        assert page.locator(".filter-chip").count() == 0
    finally:
        context.close()


def test_removing_one_chip_narrows_further_not_wider(browser, harness_url):
    """A single chip's remove link drops only that one value - checked
    separately from the "Clear all" round trip above so a bug that makes
    every chip behave like Clear all (removing the whole filter instead of
    just its own value) still gets caught."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software?approval=approved,not_wanted", wait_until="networkidle")
        filtered = set(_visible_product_names(page))
        assert "Slack" in filtered
        assert "TorrentBox" in filtered

        page.locator(".filter-chip", has_text="Unapproved").click()
        page.wait_for_load_state("networkidle")
        narrowed = set(_visible_product_names(page))
        assert "Slack" in narrowed
        assert "TorrentBox" not in narrowed
        assert page.locator(".filter-chip", has_text="Approved").count() == 1
        assert page.locator(".filter-chip", has_text="Unapproved").count() == 0
    finally:
        context.close()


# ── 3. 1280px: approve from a filtered view, land back on it ─────────────

def test_approving_from_a_filtered_view_returns_to_it_at_1280(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software?type=application&approval=waiting", wait_until="networkidle")
        assert "MysteryApp" in _visible_product_names(page)

        row = page.locator("tr[data-approval-row]", has_text="MysteryApp")
        row.locator("select[data-approval-row-state]").select_option("approved")
        row.get_by_role("button", name="Apply").click()
        page.wait_for_selector("[data-approval-result]")

        # Done-when: same filtered view, not a bare /software bounce.
        assert re.search(r"/software\?.*type=application", page.url)
        assert re.search(r"/software\?.*approval=waiting", page.url)
        assert "approval_result=" not in page.url
        assert "1 of 1 product changed to Approved." in page.locator(
            "[data-approval-result]"
        ).inner_text()

        # The dropdown state itself survived the swap too, not just the URL.
        assert page.locator("#software-search-type").input_value() == "application"
        assert page.locator(
            '[data-filter-dropdown] input[type="checkbox"][value="waiting"]'
        ).is_checked()

        # MysteryApp itself moved out of the still-active "waiting" filter -
        # it is now Approved, which the current filter does not show, and
        # that is correct: the customer stays on their filtered view, not
        # a view that keeps showing a row that no longer matches it.
        assert "MysteryApp" not in _visible_product_names(page)
    finally:
        context.close()


# ── 4. bulk bar: hidden until selected, "Select all shown" in the header ──

def test_bulk_bar_hidden_until_a_row_is_selected_at_1280(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software", wait_until="networkidle")
        bar = page.locator("[data-bulk-bar]")
        assert not bar.is_visible()

        row = page.locator("tr[data-approval-row]", has_text="MysteryApp")
        row.locator("input.approval-select").check()
        assert bar.is_visible()
        assert "1 product selected" in bar.locator("[data-bulk-count]").inner_text()
        # Inline above the table on desktop, not pinned to the viewport.
        assert bar.evaluate("el => getComputedStyle(el).position") == "static"

        bar.locator("[data-bulk-clear]").click()
        assert not bar.is_visible()
    finally:
        context.close()


def test_select_all_shown_header_checkbox_selects_visible_rows(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software", wait_until="networkidle")
        bar = page.locator("[data-bulk-bar]")
        assert not bar.is_visible()

        page.locator("[data-select-visible]").check()
        assert bar.is_visible()
        count_text = bar.locator("[data-bulk-count]").inner_text()
        assert "products selected" in count_text
        # Every visible row's own checkbox followed suit.
        row = page.locator("tr[data-approval-row]", has_text="MysteryApp")
        assert row.locator("input.approval-select").is_checked()

        page.locator("[data-select-visible]").uncheck()
        assert not bar.is_visible()
    finally:
        context.close()


def test_bulk_bar_pins_to_the_viewport_bottom_when_active_at_390(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto("/software", wait_until="networkidle")
        bar = page.locator("[data-bulk-bar]")
        assert not bar.is_visible()

        page.locator("[data-select-visible]").check()
        assert bar.is_visible()
        assert bar.evaluate("el => getComputedStyle(el).position") == "fixed"
        box = bar.bounding_box()
        assert box is not None
        # Pinned to the bottom of the 900px-tall viewport, not scrolled away.
        assert abs((box["y"] + box["height"]) - 900) <= 2
    finally:
        context.close()
