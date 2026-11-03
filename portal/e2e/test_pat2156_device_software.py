"""PAT-2156 in a real browser: the device page's Software installed view.

Covers the three things a stub-only pytest test cannot: following the real
link from the device page, switching between the Applications and Browser
extensions tabs, and the full approve-from-this-view round trip landing
back on this exact device (not bounced to /software) with the signed
notice. Column/state-logic coverage (not-assessed never 0, not-metered
never "unused", 400/404 mapping, _approval_return_to's strict UUID
acceptance) lives in tests/test_pat2156_device_software.py; phone-width
(390px) overflow is covered generically for this page by adding it to
e2e/test_table_overflow.py's PAGES list.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_SOFTWARE_UUID_ID

DEVICE_ID = "dev-mac-001"

# Same technique as e2e/test_pat2155_alerts_layout.py's own
# test_no_date_cell_wraps_beyond_two_lines_at_1280: getClientRects().length
# on the date/time spans is exactly the line count each renders as (1 rect
# per visual line), independent of font metrics or column-width arithmetic.
LINE_COUNT_JS = """
sel => Array.prototype.map.call(document.querySelectorAll(sel), el => el.getClientRects().length)
"""


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_navigate_from_device_page_to_software_view(browser, harness_url):
    # PAT-2164: the old "Software installed" meta-line link is gone -
    # Software is one of the tabs in the shared tab bar now.
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"/devices/{DEVICE_ID}", wait_until="networkidle")
        page.click(f'.view-tabs a[href="/devices/{DEVICE_ID}/software"]')
        page.wait_for_load_state("networkidle")
        assert page.url == f"{harness_url}/devices/{DEVICE_ID}/software"
        assert "Example App" in page.content()
        assert page.locator(
            f'.view-tabs a.tab-active[aria-current="page"][href="/devices/{DEVICE_ID}/software"]'
        ).count() == 1
    finally:
        context.close()


def test_both_tabs_render_their_own_rows(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"/devices/{DEVICE_ID}/software", wait_until="networkidle")
        assert "Example App" in page.content()
        assert "AdBlock Plus" not in page.content()

        page.get_by_role("link", name="Browser extensions", exact=False).click()
        page.wait_for_load_state("networkidle")
        assert "tab=extension" in page.url
        assert "AdBlock Plus" in page.content()
        assert "Slack" in page.content()
        assert "Example App" not in page.content()
    finally:
        context.close()


def test_no_date_cell_wraps_beyond_two_lines_at_1280(browser, harness_url):
    """Rubric L13 (portal-rubric.md): the Usage and First-seen date cells
    each render as date-on-one-line, time-on-one-line - never a third line
    from the date itself wrapping mid-value ("24 Sep" / "2026" / "10:00
    UTC"). The walker's own L13 check only runs at 1440px (portal-walk),
    so a regression at 1280px specifically needs this guard."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto(f"/devices/{DEVICE_ID}/software?tab=application", wait_until="networkidle")
        date_lines = page.evaluate(LINE_COUNT_JS, ".device-software-table .cell-evidence__main")
        time_lines = page.evaluate(
            LINE_COUNT_JS, ".device-software-table .cell-evidence .cell-subtle")
        assert date_lines, "no date cells rendered on the applications tab"
        assert all(n == 1 for n in date_lines), date_lines
        assert all(n == 1 for n in time_lines), time_lines
    finally:
        context.close()


def test_approve_from_this_view_lands_back_here_with_notice(browser, harness_url):
    """Uses the UUID-id device (not "dev-mac-001") - _approval_return_to's
    device-software return path is strict-UUID-only by design (main.py),
    so this is the one fixture that actually exercises the full round trip
    rather than falling back to /software."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software", wait_until="networkidle")
        assert "Example App" in page.content()

        row = page.locator("tr", has_text="Example App")
        row.locator("select[data-approval-row-state]").select_option("unapproved")
        row.get_by_role("button", name="Apply").click()
        page.wait_for_selector("[data-approval-result]")

        assert page.url.startswith(f"{harness_url}/devices/{DEVICE_SOFTWARE_UUID_ID}/software")
        assert "changed to Unapproved" in page.locator("[data-approval-result]").inner_text()
    finally:
        context.close()
