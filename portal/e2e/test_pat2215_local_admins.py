"""PAT-2215 in a real browser: /local-admins (Governance) - the standing
local-administrator roster by account and by device.

Parsing/rendering coverage against the stub lives in
tests/test_pat2215_local_admins.py; this file is the Done-when's own
browser checks: both views actually render and switch, an unreadable
device renders as unknown rather than a false zero/pass, a directory
group and an unresolved SID are labelled as such, the filter bar narrows
rows and its chips restore them, and nothing overflows the viewport at
1280px or 390px, light or dark.

Fixture data is tests/conftest.py's LOCAL_ADMINS_DATA (imported verbatim
by e2e/conftest.py's stub): acme-mbp-frontdesk (macOS, compliant, alice),
acme-win-dc1 (Windows, over the limit, a disabled built-in Administrator,
a directory group, an unresolved SID and a second named user), and
acme-win-unreadable (Windows, membership could not be read, no count
signal at all).
"""

from e2e.conftest import HARNESS_VALID_TOKEN

PLATFORM_SUMMARY = "details[data-row-filter='la_platform'] summary"
PRINCIPAL_SUMMARY = "details[data-row-filter='la_principal_type'] summary"
OVER_LIMIT_SUMMARY = "details[data-row-filter='la_over_limit'] summary"


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _visible_account_names(page):
    rows = page.locator("tr[data-filter-view='account']")
    names = []
    for i in range(rows.count()):
        row = rows.nth(i)
        if row.is_visible():
            names.append(row.locator("td[data-label='Account'] strong").inner_text())
    return names


def test_by_account_is_the_default_view_and_labels_group_and_unresolved(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/local-admins", wait_until="networkidle")

        assert page.get_by_role("heading", name="Local admins").is_visible()
        assert page.locator(".la-accounts-table").is_visible()
        assert not page.locator(".la-devices-table").count()

        names = _visible_account_names(page)
        assert "ACME\\Domain Admins" in names
        assert "S-1-5-21-999-999-999-9999" in names
        assert "alice" in names

        group_row = page.locator("tr[data-filter-view='account']", has_text="ACME\\Domain Admins")
        assert group_row.get_by_text("Group", exact=True).is_visible()
        assert group_row.get_by_text("Directory group, not a person").is_visible()

        unresolved_row = page.locator(
            "tr[data-filter-view='account']", has_text="S-1-5-21-999-999-999-9999")
        assert unresolved_row.get_by_text("Unresolved", exact=True).is_visible()
        assert unresolved_row.get_by_text(
            "Unresolved - could not be matched to a name").is_visible()
    finally:
        context.close()


def test_by_device_view_shows_the_unreadable_device_as_unknown_never_zero(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/local-admins", wait_until="networkidle")

        page.get_by_role("link", name="By device").click()
        page.wait_for_load_state("networkidle")
        assert page.locator(".la-devices-table").is_visible()
        assert not page.locator(".la-accounts-table").count()

        row = page.locator("tr[data-filter-view='device']", has_text="acme-win-unreadable")
        assert row.get_by_text("Could not be read").is_visible()
        # Both the Count cell and the Against-the-limit cell read "Unknown"
        # for this device (no roster, no count signal at all).
        assert row.get_by_text("Unknown").count() == 2
        assert not row.get_by_text("Within limit").count()
        assert not row.get_by_text("Over limit").count()

        over_row = page.locator("tr[data-filter-view='device']", has_text="acme-win-dc1")
        assert over_row.get_by_text("Over limit").is_visible()
        assert over_row.get_by_text("Built-in Administrator, disabled").is_visible()

        compliant_row = page.locator(
            "tr[data-filter-view='device']", has_text="acme-mbp-frontdesk")
        assert compliant_row.get_by_text("Within limit").is_visible()

        # By-device links straight to that device's own Compliance tab.
        assert over_row.locator(
            'a[href="/devices/dev-win-101/compliance#compliance-signals"]'
        ).is_visible()
    finally:
        context.close()


def test_filters_narrow_rows_and_chips_restore_them(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/local-admins", wait_until="networkidle")

        before = set(_visible_account_names(page))
        assert {"alice", "ACME\\Administrator", "ACME\\Domain Admins",
                "S-1-5-21-999-999-999-9999", "ACME\\bob"} <= before

        page.locator(PLATFORM_SUMMARY).click()
        platform_panel = page.locator("details[data-row-filter='la_platform']")
        platform_panel.locator('input[type="checkbox"][value="windows"]').check()
        platform_panel.locator("[data-filter-dropdown-apply]").click()
        page.wait_for_load_state("networkidle")

        after_platform = set(_visible_account_names(page))
        assert "alice" not in after_platform
        assert "ACME\\bob" in after_platform
        assert page.locator(".filter-chip", has_text="Windows").count() == 1

        page.locator(PRINCIPAL_SUMMARY).click()
        principal_panel = page.locator("details[data-row-filter='la_principal_type']")
        principal_panel.locator('input[type="checkbox"][value="group"]').check()
        principal_panel.locator("[data-filter-dropdown-apply]").click()
        page.wait_for_load_state("networkidle")

        after_principal = set(_visible_account_names(page))
        assert after_principal == {"ACME\\Domain Admins"}
        assert page.locator(".filter-chip", has_text="Group").count() == 1

        # Removing the Windows chip should not restore anything by itself
        # (Group is still active) - both filters must compose (AND), not
        # cancel one another.
        page.locator(".filter-chip", has_text="Windows").click()
        page.wait_for_load_state("networkidle")
        still_narrowed = set(_visible_account_names(page))
        assert still_narrowed == {"ACME\\Domain Admins"}

        page.locator(".filter-chip--clear").click()
        page.wait_for_load_state("networkidle")
        restored = set(_visible_account_names(page))
        assert restored == before
        assert page.locator(".filter-chip").count() == 0
    finally:
        context.close()


def test_over_limit_filter_from_the_summary_tile(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/local-admins", wait_until="networkidle")

        page.get_by_role("link", name="Over the limit").click()
        page.wait_for_load_state("networkidle")
        page.locator(OVER_LIMIT_SUMMARY).wait_for()
        assert page.locator(".filter-chip", has_text="Over the limit").count() == 1

        names = set(_visible_account_names(page))
        # Every account over the limit lives on acme-win-dc1 only.
        assert names == {"ACME\\Administrator", "ACME\\Domain Admins",
                          "S-1-5-21-999-999-999-9999", "ACME\\bob"}
        assert "alice" not in names
    finally:
        context.close()


def test_no_horizontal_overflow_at_1280_and_390_light_and_dark(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        for width in (1280, 390):
            page.set_viewport_size({"width": width, "height": 1000})
            page.goto("/local-admins", wait_until="networkidle")
            assert page.evaluate(
                "() => document.documentElement.scrollWidth <= window.innerWidth"
            ), f"horizontal overflow at {width}px (light, by account)"

            page.get_by_role("link", name="By device").click()
            page.wait_for_load_state("networkidle")
            assert page.evaluate(
                "() => document.documentElement.scrollWidth <= window.innerWidth"
            ), f"horizontal overflow at {width}px (light, by device)"

            page.get_by_role("button", name="Dark").click()
            assert page.evaluate(
                "() => document.documentElement.scrollWidth <= window.innerWidth"
            ), f"horizontal overflow at {width}px (dark, by device)"
    finally:
        context.close()
