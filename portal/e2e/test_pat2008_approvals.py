"""PAT-2008 in a real browser: inline and bulk approval writes on /software,
the history drawer, and the viewer's read-only page.

PAT-2120 merged the five decision-group tables into one, so every row's
Approval cell is now the select + Apply pattern (data-approval-row-form),
never the old per-action button list - see main.py's _software_row and
templates/_macros.html's approval_form_cell.

The harness stub (tests/conftest.py StubPlatformHandler) reads each write
back the way the platform does, so a marked product really moves between
decision-state buckets on the re-rendered page. Screenshots at 1280px are
written to /tmp for the ticket record: admin, viewer, and the bulk bar
active.
"""

import copy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import SOFTWARE_INVENTORY, STUB_STATE

SCREENSHOT_DIR = "/tmp"


def _context(browser, harness_url, color_scheme="light"):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _settle(page):
    """Wait for CSS transitions (the tabs fade colour over 160ms) to end.
    Round 3: a screenshot taken straight after a tab click caught the new
    active tab mid-transition, grey on a translucent background."""
    page.mouse.move(1, 1)
    page.evaluate("() => Promise.all(document.getAnimations().map(a => a.finished))")


def _group_rows(page, group):
    """Every row currently in decision bucket `group`
    (waiting/not_wanted/approved/ignored/unrecognised - main.py's
    data-filter-decision), the one merged table's replacement for the old
    per-group #group-waiting etc containers."""
    return page.locator(f'tr[data-approval-row][data-filter-decision="{group}"]')


def _row(page, group, name):
    return _group_rows(page, group).filter(has_text=name)


def _apply(row, state):
    """Select `state` in a row's compact form and click Apply - the one
    Approval control shape every row on /software uses (PAT-2120)."""
    row.locator("select[data-approval-row-state]").select_option(state)
    row.get_by_role("button", name="Apply").click()


def _set_type(page, value):
    """PAT-2163: the Type filter is a single <select>, applied instantly on
    change - value is "" for "All types", or "application"/"extension"."""
    page.locator("#software-search-type").select_option(value)


def _set_approval(page, values):
    """PAT-2163: the Approval filter is a multi-select checkbox <details>
    popover, applied via its own Apply button (not per-checkbox) - checks
    exactly `values` (unchecking anything else already checked) and clicks
    Apply once, the same batch shape a customer uses. Scoped to
    details[data-row-filter] specifically - the orchestrator's follow-up
    added a second popover ("More filters", data-more-filters) that also
    carries data-filter-dropdown, so that attribute alone is no longer
    unique to Approval."""
    panel = page.locator("details[data-row-filter]")
    panel.locator("summary").click()
    for box in panel.locator('input[type="checkbox"]').all():
        value = box.get_attribute("value")
        if value in values and not box.is_checked():
            box.check()
        elif value not in values and box.is_checked():
            box.uncheck()
    panel.locator("[data-filter-dropdown-apply]").click()


def test_single_mark_moves_a_row_between_groups_without_a_reload(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software?type=extension", wait_until="networkidle")
    page.screenshot(path=f"{SCREENSHOT_DIR}/pat2008_admin.png", full_page=True)
    # A marker on window survives only if the page is not reloaded.
    page.evaluate("window.__noReload = true")
    assert _row(page, "waiting", "MysteryHelper").count() == 1
    _apply(_row(page, "waiting", "MysteryHelper"), "approved")
    page.wait_for_selector("[data-approval-result]")
    assert page.evaluate("window.__noReload") is True
    assert _row(page, "waiting", "MysteryHelper").count() == 0
    assert _row(page, "approved", "MysteryHelper").count() == 1
    assert "1 of 1 product changed to Approved." in page.locator(
        "[data-approval-result]").inner_text()
    # The extension filter survives the write, in the URL and on screen.
    assert "type=extension" in page.url
    assert "approval_result" not in page.url
    assert page.locator("#software-search-type").input_value() == "extension"
    put = STUB_STATE["approval_puts"][-1]["body"]
    assert put == {"state": "approved", "items": [
        {"type": "browser_extension", "browser": "firefox",
         "extension_id": "mysteryhelper-ext-id"}]}
    context.close()


def test_bulk_mark_with_a_reason(browser, harness_url):
    """PAT-2163 (orchestrator follow-up): "Unreviewed only" is gone -
    Approval = Waiting on a decision is the identical row set (main.py's
    _software_approval_filter) - and the bulk bar stays hidden until
    something is selected instead of showing with disabled buttons."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    bar = page.locator("[data-bulk-bar]")
    assert not bar.is_visible()
    _set_approval(page, ["waiting"])
    assert _row(page, "approved", "TeamChat").is_hidden()
    page.get_by_label("Select all shown").check()
    assert bar.is_visible()
    assert "2 products selected" in bar.inner_text()  # MysteryApp and MysteryHelper
    bar.get_by_placeholder("Reason (optional)").fill("Not used by anyone")
    page.screenshot(path=f"{SCREENSHOT_DIR}/pat2008_bulk.png", full_page=False)
    assert "approval=waiting" in page.url
    bar.get_by_role("button", name="Ignore").click()
    page.wait_for_selector("[data-approval-result]")
    body = STUB_STATE["approval_puts"][-1]["body"]
    assert body["state"] == "ignored"
    assert body["reason"] == "Not used by anyone"
    names = sorted(i.get("identifier") or i.get("extension_id") for i in body["items"])
    assert names == ["com.example.mysteryapp", "mysteryhelper-ext-id"]
    # The filter survives the re-render, so the newly ignored rows are
    # hidden by it until it is cleared.
    assert page.locator(
        'details[data-row-filter] input[type="checkbox"][value="waiting"]'
    ).is_checked()
    assert _row(page, "waiting", "MysteryApp").count() == 0
    _set_approval(page, [])
    assert _row(page, "ignored", "MysteryApp").count() == 1
    assert _row(page, "ignored", "MysteryHelper").count() == 1
    context.close()


def test_protected_unapprove_asks_first_and_can_be_cancelled(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    page.goto("/software", wait_until="networkidle")
    # Mark the waiting app's row-form protected in the DOM the way the
    # server does for a protected-list match (data-protected on the form
    # itself, PAT-2008 review fix P3), then decline the confirmation.
    page.evaluate("""() => {
      const row = [...document.querySelectorAll('tr[data-approval-row]')]
        .find(r => r.textContent.includes('MysteryApp'));
      row.querySelector('[data-approval-row-form]').setAttribute('data-protected', '1');
    }""")
    page.once("dialog", lambda dialog: dialog.dismiss())
    row = _row(page, "waiting", "MysteryApp")
    row.locator("select[data-approval-row-state]").select_option("unapproved")
    row.get_by_role("button", name="Apply").click()
    page.wait_for_timeout(300)
    assert STUB_STATE["approval_puts"] == []
    context.close()


def test_history_drawer_shows_who_when_before_after_and_why(browser, harness_url):
    context = _context(browser, harness_url, color_scheme="dark")
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    _apply(_row(page, "waiting", "MysteryHelper"), "unapproved")
    page.wait_for_selector("[data-approval-result]")
    # PAT-2255: the product name opens the product detail (history plus
    # identifiers).
    _row(page, "not_wanted", "MysteryHelper").locator("a.product-name").click()
    drawer = page.locator("[data-history-panel]")
    drawer.locator(".history__item").first.wait_for()
    text = drawer.inner_text().casefold()  # pills are upper-cased by CSS
    assert "mysteryhelper" in text
    assert "unreviewed" in text and "unapproved" in text
    assert "alice@tenant-a.example" in text
    assert "24 sep 2026 10:00 utc" in text
    page.screenshot(path=f"{SCREENSHOT_DIR}/pat2008_history_dark.png", full_page=False)
    page.keyboard.press("Escape")
    assert drawer.is_hidden()
    context.close()


def test_viewer_sees_no_controls(browser, harness_url):
    STUB_STATE["portal_role"] = "viewer"
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    assert page.locator(".approval__btn").count() == 0
    assert page.locator("input.approval-select").count() == 0
    assert page.locator("#approval-form").count() == 0
    assert page.locator("a[data-history-drawer]").count() > 0
    page.screenshot(path=f"{SCREENSHOT_DIR}/pat2008b_viewer.png", full_page=True)
    context.close()


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_decision_tables_fit_their_card_at_1280(browser, harness_url, role):
    """The PAT-2092 guards run as admin (the stub default); this adds the
    viewer's narrower table and checks neither scrolls sideways at 1280."""
    STUB_STATE["portal_role"] = role
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    overflow = page.evaluate("""() => [...document.querySelectorAll('.table-scroll')]
      .filter(el => el.offsetParent !== null && el.scrollWidth > el.clientWidth + 1)
      .map(el => el.querySelector('table').className + ' ' +
        el.scrollWidth + '>' + el.clientWidth)""")
    assert overflow == []
    context.close()


def test_type_filter_hides_rows_without_changing_approval_option_counts(browser, harness_url):
    """PAT-2120/PAT-2163: the Approval option counts are server-rendered
    once for the whole estate, not live-recounted as the Type filter
    narrows what is visible - switching Type hides rows but never changes
    an Approval checkbox's own count label."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    page.screenshot(path=f"{SCREENSHOT_DIR}/pat2008b_admin_all.png", full_page=True)
    approval_summary = page.locator("details[data-row-filter] summary")
    approval_summary.click()
    # PAT-2255: the option uses the row's own approval word, Unreviewed.
    waiting_option = page.locator(
        "details[data-row-filter] .filter-dropdown__option", has_text="Unreviewed")
    # The option text is visually all-caps in places (CSS text-transform
    # elsewhere on the page), so compare case-insensitively for parity with
    # the rest of this file's approach - the source HTML/accessible name
    # stays sentence case.
    assert waiting_option.inner_text().casefold() == "unreviewed (9)"
    page.keyboard.press("Escape")
    assert _group_rows(page, "unrecognised").first.is_visible()
    _set_type(page, "extension")
    # OddPolicy is the only unrecognised product and it is an application.
    assert _group_rows(page, "unrecognised").first.is_hidden()
    # The Approval option's own count is unaffected by the Type filter.
    approval_summary.click()
    assert waiting_option.inner_text().casefold() == "unreviewed (9)"
    page.keyboard.press("Escape")
    _settle(page)
    page.screenshot(path=f"{SCREENSHOT_DIR}/pat2008c_admin_ext.png", full_page=True)
    _set_type(page, "")
    assert _group_rows(page, "unrecognised").first.is_visible()
    context.close()


def test_approval_filter_and_type_filter_compose(browser, harness_url):
    """PAT-2120 non-author review fix (P2), carried into PAT-2163's Approval
    checkbox dropdown: picking exactly one Approval state shows only rows
    in that bucket, clearing it restores every row, and the Type filter and
    the Approval filter compose (AND, not one overriding the other) -
    OldTheme is the one ignored extension and OddPolicy is the one
    unrecognised application (see tests/test_software.py's module
    docstring for the full fixture breakdown), so each pairing narrows to
    exactly the row, or no row, that matches both."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    visible_rows = page.locator("tr[data-approval-row]:visible")

    assert visible_rows.count() == 18

    for value, expected_count in (
        ("waiting", 9), ("approved", 3), ("not_wanted", 4),
        ("ignored", 1), ("unrecognised", 1),
    ):
        _set_approval(page, [value])
        assert visible_rows.count() == expected_count, value
        # Every visible row belongs to this bucket - none from another
        # decision state leaks through.
        assert page.locator(
            f'tr[data-approval-row][data-filter-decision="{value}"]:visible'
        ).count() == expected_count, value
        for other in ("waiting", "not_wanted", "approved", "ignored", "unrecognised"):
            if other == value:
                continue
            assert page.locator(
                f'tr[data-approval-row][data-filter-decision="{other}"]:visible'
            ).count() == 0, (value, other)

    _set_approval(page, [])
    assert visible_rows.count() == 18

    # Compose with the Type filter: OldTheme (an ignored extension) shows
    # only under Ignored + Extensions, never Ignored + Applications.
    _set_approval(page, ["ignored"])
    _set_type(page, "application")
    assert visible_rows.count() == 0
    _set_type(page, "extension")
    assert visible_rows.count() == 1
    assert _row(page, "ignored", "OldTheme").is_visible()

    # OddPolicy (an unrecognised application) is the mirror case - still
    # on the Extensions type filter from above, it stays hidden until the
    # type filter changes too.
    _set_approval(page, ["unrecognised"])
    assert visible_rows.count() == 0
    _set_type(page, "application")
    assert visible_rows.count() == 1
    assert _row(page, "unrecognised", "OddPolicy").is_visible()

    context.close()


def test_approval_filter_selects_more_than_one_state_at_once(browser, harness_url):
    """PAT-2163's own reason for being a checkbox popover rather than
    single-select tabs: two states picked together show the union of both
    buckets, not just the last one clicked."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    visible_rows = page.locator("tr[data-approval-row]:visible")

    _set_approval(page, ["approved", "not_wanted"])
    assert visible_rows.count() == 7  # 3 approved + 4 not_wanted
    assert page.locator(
        'tr[data-approval-row][data-filter-decision="approved"]:visible'
    ).count() == 3
    assert page.locator(
        'tr[data-approval-row][data-filter-decision="not_wanted"]:visible'
    ).count() == 4
    assert page.locator(
        'tr[data-approval-row][data-filter-decision="waiting"]:visible'
    ).count() == 0
    context.close()


def test_inventory_row_applies_a_state_in_one_line(browser, harness_url):
    # PAT-2104: /v1/portal/software now carries its own team_id/product_key/
    # policy_state, so _inventory_approval no longer borrows identity from a
    # matching /v1/portal/applications row - a macOS row still needs a valid
    # Team ID of its own or it locks with "no Team ID" (0a54605). The shared
    # ArchiveTool fixture (tests/conftest.py SOFTWARE_INVENTORY) carries
    # neither by default, so this test needs its own software_inventory_data
    # override rather than the shared fixture, which many other tests
    # assert exact counts against. No applications row shares its identity,
    # so it renders as its own row (PAT-2120 merge) in the Waiting bucket.
    inventory = copy.deepcopy(SOFTWARE_INVENTORY)
    for product in inventory["products"]:
        if product["identifier"] == "com.acme.archive":
            product["team_id"] = "ARCH123456"
            product["product_key"] = "application:macos:com.acme.archive:ARCH123456"
            product["policy_state"] = None
    STUB_STATE["software_inventory_data"] = inventory

    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto("/software", wait_until="networkidle")
    row = _row(page, "waiting", "ArchiveTool")
    form = row.locator("[data-approval-row-form]")
    select_box = form.locator("select").bounding_box()
    apply_box = form.get_by_role("button", name="Apply").bounding_box()
    assert abs(select_box["y"] - apply_box["y"]) < 8  # same line, no wrap
    apply = form.get_by_role("button", name="Apply")
    assert form.locator("select").input_value() == ""
    assert apply.is_disabled()
    form.locator("select").select_option("ignored")
    assert apply.is_enabled()
    form.get_by_role("button", name="Apply").click()
    page.wait_for_selector("[data-approval-result]")
    assert STUB_STATE["approval_puts"][-1]["body"] == {"state": "ignored", "items": [
        {"type": "application", "platform": "macos", "identifier": "com.acme.archive",
         "team_id": "ARCH123456"}]}
    context.close()


# PAT-2163: the old "active tab looks like the All tab" colour-parity test
# (test_active_tab_looks_like_the_all_tab_when_active) no longer applies -
# Type is a native <select> and Approval is a checkbox <details> popover,
# neither styled as a tab with its own active-state colour to compare. The
# one behaviour that test also covered - a filter seeded by the URL
# surviving an approval write - is still guarded above by
# test_single_mark_moves_a_row_between_groups_without_a_reload.
