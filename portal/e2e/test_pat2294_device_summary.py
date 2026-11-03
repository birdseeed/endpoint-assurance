"""The device page and the Devices list read one Failing checks figure (PAT-2294).

dev-win-002 is served the way the real platform sends it (device fields under
`device`): its roster row and its device response both say six failing checks,
while its signals list holds only one. The page must show six, the same as the
list, and its Summary must say once that a Windows device has no update state
(its `patch_pending` is null). The unit suite proves the rule; this proves it
in a browser against the real templates, without a stray horizontal scroll.
"""

import re

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN

UNKNOWN_NOTE = "This device hasn't reported a recent update state."


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _issues_tile(page):
    return page.locator(
        '[data-device-section="compliance"] .device-tab-label'
    ).inner_text().strip().removeprefix("Compliance (").removesuffix(" failing)")


@pytest.mark.parametrize("width", [1280, 390])
def test_device_page_shows_the_same_failing_checks_figure_as_the_list(
    browser, harness_url, width,
):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        row = page.locator("#device-table tbody tr", has_text="acme-win-accounts")
        listed = row.locator(".device-checks").inner_text().strip().removesuffix(" failing")

        page.goto(f"{harness_url}/devices/dev-win-002", wait_until="networkidle")
        on_page = _issues_tile(page)
        tab = page.locator(".view-tabs a", has_text="Compliance").inner_text().strip()
    finally:
        context.close()
    assert listed == on_page == "6"
    assert re.search(r"Compliance \(6 failing\)", tab), tab


@pytest.mark.parametrize("width", [1280, 390])
def test_windows_device_summary_says_once_that_it_has_no_update_state(
    browser, harness_url, width,
):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{harness_url}/devices/dev-win-002", wait_until="networkidle")
        body = page.locator("body").inner_text()
        doc = page.evaluate(
            "() => ({scrollWidth: document.documentElement.scrollWidth,"
            " clientWidth: document.documentElement.clientWidth})"
        )
    finally:
        context.close()
    assert "Update evidence stale" in body
    assert UNKNOWN_NOTE not in body
    assert "Update state not reported" not in body
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, doc
