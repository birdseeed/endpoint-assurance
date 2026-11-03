"""PAT-2212/PAT-2271 in a real browser: the /devices "Your device list"
reconciliation card's count tiles, matched group and the two confirm-gated
row/header actions (Clear list, Remove from list).

Covers what a stub-only pytest test (tests/test_pat2135_device_selfservice.py)
cannot: that clicking a tile actually navigates and re-renders the intended
group with no JavaScript required (each tile is a plain link carrying
?list_group=, per main.py's DEVICE_LIST_GROUPS), that the Matched group
renders behind a real collapsed <details> (not open on load) with itemised
rows once the platform's PAT-2271 `matched` array is present, that the
Serial column disappears when no row in the visible group has one, and that
Clear list's and Remove from list's confirm steps are not reachable without
an explicit second click.
"""

import re

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_LIST_VIEW_OLD_API, STUB_STATE

CARD = "#device-list-card"


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


@pytest.fixture(autouse=True)
def _reset_device_list_state():
    STUB_STATE["device_list_data"] = None
    yield
    STUB_STATE["device_list_data"] = None


def test_tiles_filter_each_group_with_no_js_needed(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices", wait_until="networkidle")

        card = page.locator(CARD)
        # Default landing group is "not reporting" (never_seen): its entry
        # is visible, the "reporting, not on your list" entry is not.
        assert "PF3ABCDE" in card.inner_text()
        assert "acme-win-accounts" not in card.inner_text()

        page.locator(f'{CARD} a.dl-tile[href*="list_group=not_on_list"]').click()
        page.wait_for_load_state("networkidle")
        card = page.locator(CARD)
        assert "acme-win-accounts" in card.inner_text()
        assert "PF3ABCDE" not in card.inner_text()
        assert 'list_group=not_on_list' in page.url

        page.locator(f'{CARD} a.dl-tile[href*="list_group=never_seen"]').click()
        page.wait_for_load_state("networkidle")
        card = page.locator(CARD)
        assert "PF3ABCDE" in card.inner_text()
        assert "acme-win-accounts" not in card.inner_text()
    finally:
        context.close()


def test_matched_group_renders_behind_a_collapsed_details(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?list_group=matched", wait_until="networkidle")

        details = page.locator(f"{CARD} details.dl-matched")
        assert details.count() == 1
        # Collapsed by default - the itemised rows exist in the DOM (a
        # requests-level check would already see them) but are not visible
        # until the summary is opened.
        assert details.get_attribute("open") is None
        table = page.locator(f"{CARD} details.dl-matched table")
        assert not table.is_visible()
        # text_content() reads the raw DOM regardless of visibility - the
        # collapsed <details> still carries the real content, it is just
        # not rendered yet.
        assert "acme-mbp-frontdesk" in table.text_content()

        page.locator(f"{CARD} details.dl-matched summary").click()
        assert table.is_visible()
        assert "acme-mbp-frontdesk" in table.inner_text()
        # One matched entry's device is retired (tests/conftest.py's
        # DEVICE_LIST_VIEW) - shown as a pill, not silently dropped.
        assert "Retired" in table.inner_text()
    finally:
        context.close()


def test_matched_group_falls_back_to_count_only_on_old_api(browser, harness_url):
    # PAT-2271's `matched` array is additive - an upstream that has not
    # deployed it yet must still get an honest count-only group, not a
    # false-empty itemised one.
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW_OLD_API
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?list_group=matched", wait_until="networkidle")

        details = page.locator(f"{CARD} details.dl-matched")
        assert details.get_attribute("open") is None
        assert page.locator(f"{CARD} details.dl-matched table").count() == 0
        count_text = page.locator(f"{CARD} details.dl-matched p.meta")
        assert "3 entries" in count_text.text_content()

        page.locator(f"{CARD} details.dl-matched summary").click()
        assert count_text.is_visible()
        assert "1 of those retired" in count_text.inner_text()
    finally:
        context.close()


def test_remove_from_list_requires_confirm_then_removes_the_entry(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?list_group=never_seen", wait_until="networkidle")

        row = page.locator(f"{CARD} table tbody tr", has_text="ghost-01")
        remove_summary = row.locator("details.retire-panel summary")
        remove_button = row.locator("details.retire-panel button[type='submit']")
        assert remove_summary.is_visible()
        assert not remove_button.is_visible()

        remove_summary.click()
        assert remove_button.is_visible()
        remove_button.click()
        page.wait_for_load_state("networkidle")

        assert "Entry removed from your list" in page.content()
        card = page.locator(CARD)
        assert "ghost-01" not in card.inner_text()
    finally:
        context.close()


def test_serial_column_hidden_when_no_row_in_the_group_has_one(browser, harness_url):
    # The default fixture's "not on your list" entry already carries no
    # serial (tests/conftest.py's DEVICE_LIST_VIEW) - the Serial header
    # must not render for that group.
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(
            f"{harness_url}/devices?list_group=not_on_list", wait_until="networkidle",
        )
        card = page.locator(CARD)
        headers = card.locator("table thead th").all_inner_texts()
        assert not any(h.strip() == "Serial" for h in headers)
        assert "acme-win-accounts" in card.inner_text()
    finally:
        context.close()


def test_serial_column_shows_when_a_row_in_the_group_has_one(browser, harness_url):
    # Contrast case: the default fixture's "never seen" group does carry a
    # serial on one row, so the column must render there.
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(
            f"{harness_url}/devices?list_group=never_seen", wait_until="networkidle",
        )
        card = page.locator(CARD)
        headers = card.locator("table thead th").all_inner_texts()
        assert any(h.strip() == "Serial" for h in headers)
        assert "PF3ABCDE" in card.inner_text()
    finally:
        context.close()


def test_clear_list_requires_an_explicit_confirm_click(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices", wait_until="networkidle")

        clear_summary = page.locator(f"{CARD} form[action='/devices/device-list/clear'] summary")
        confirm_button = page.locator(
            f"{CARD} form[action='/devices/device-list/clear'] button[type='submit']"
        )
        assert clear_summary.is_visible()
        # Collapsed: the confirm button exists but is not interactable yet.
        assert not confirm_button.is_visible()

        clear_summary.click()
        assert confirm_button.is_visible()
        assert re.search(r"clears your uploaded list", page.locator(
            f"{CARD} form[action='/devices/device-list/clear'] p.meta"
        ).inner_text(), re.IGNORECASE)
    finally:
        context.close()
