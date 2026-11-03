"""Native controls and downloaded rows agree in both representations, without JS."""

import csv
import io
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN


@pytest.mark.parametrize("javascript", [True, False])
@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("view", ["account", "device"])
def test_filters_sort_download_roundtrip(browser, harness_url, javascript, width, theme, view):
    context = browser.new_context(
        base_url=harness_url,
        java_script_enabled=javascript,
        viewport={"width": width, "height": 1000},
        color_scheme=theme,
    )
    context.add_cookies(
        [{"name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url}]
    )
    try:
        page = context.new_page()
        response = page.goto(f"/local-admins?view={view}", wait_until="networkidle")
        assert response.status == 200
        # evaluate is only test setup: the production page has JS disabled in
        # half the contexts. Set the explicit theme without relying on its JS.
        page.locator("html").evaluate("(el, theme) => el.dataset.theme = theme", theme)
        page.get_by_label("Search local admins", exact=True).fill("acme")
        platform = page.locator('details[data-query-param="platform"]')
        platform.locator("summary").click()
        platform.locator('input[value="windows"]').check()
        platform.get_by_role("button", name="Apply", exact=True).click()
        assert "search=acme" in page.url and "platform=windows" in page.url
        principal = page.locator('details[data-query-param="principal_type"]')
        principal.locator("summary").click()
        principal.locator('input[value="user"]').check()
        principal.get_by_role("button", name="Apply", exact=True).click()
        heading = "Account" if view == "account" else "Device"
        if width < 680:
            # Stacked mobile tables hide their headers; the same sort options
            # are also available in the native filter form.
            page.get_by_label("Sort direction", exact=True).select_option("desc")
            page.get_by_role("button", name="Apply filters and search").click()
        else:
            page.locator("thead").get_by_role("link", name=heading, exact=False).first.click()
        params = parse_qs(urlsplit(page.url).query)
        assert params["direction"] == ["desc"]
        assert params["search"] == ["acme"]
        assert params["platform"] == ["windows"]
        assert params["principal_type"] == ["user"]
        assert page.locator('th[aria-sort="descending"]').count() == 1
        rows = page.locator("tbody tr:visible")
        visible = rows.locator("td:first-child").all_inner_texts()
        names = [text.split("\n")[0] for text in visible]
        assert len(names) == (2 if view == "account" else 1)
        with page.expect_download() as download_info:
            page.get_by_role("link", name="Export filtered view", exact=True).click()
        downloaded = list(csv.DictReader(io.StringIO(Path(download_info.value.path()).read_text())))
        assert [row["account" if view == "account" else "hostname"] for row in downloaded] == names
        assert not page.locator('form[method="post"]').count()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        page.reload(wait_until="networkidle")
        assert page.locator("tbody tr:visible td:first-child").all_inner_texts() == visible
        page.locator("html").evaluate("(el, theme) => el.dataset.theme = theme", theme)
        screenshot_dir = os.environ.get("PAT2340_SCREENSHOTS")
        if screenshot_dir:
            path = Path(screenshot_dir)
            path.mkdir(parents=True, exist_ok=True)
            page.screenshot(
                path=str(path / f"{view}-{width}-{theme}-js{int(javascript)}.png"), full_page=True
            )
        page.get_by_role("link", name="Clear all", exact=True).click()
        assert "platform=" not in page.url and "search=" not in page.url
        page.get_by_role(
            "link", name="By device" if view == "account" else "By account", exact=False
        ).click()
        assert parse_qs(urlsplit(page.url).query)["view"] == [
            "device" if view == "account" else "account"
        ]
    finally:
        context.close()
