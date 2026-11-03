"""Collected installed versions remain visible in compact Software review rows."""

import copy
import os
from pathlib import Path

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import check_overflow
from tests.conftest import SOFTWARE_INVENTORY, STUB_STATE

CASES = [
    (["2.0"], 0),
    (["1.2.3", "4.5.6"], 2),
    (['2026.09.30-release-candidate-"Research & reporting"-build-123456789'], 0),
    ([], 3),
    ([], 0),
]


@pytest.fixture
def installed_versions():
    source = copy.deepcopy(SOFTWARE_INVENTORY)
    for product, (versions, unknown) in zip(source["products"][:len(CASES)], CASES, strict=True):
        product.update(versions=versions, unknown_version_installation_count=unknown)
    previous = STUB_STATE.get("software_inventory_data")
    STUB_STATE["software_inventory_data"] = source
    try:
        yield source["products"][:len(CASES)]
    finally:
        STUB_STATE["software_inventory_data"] = previous


@pytest.mark.parametrize("font", ["native", "wide"])
@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_installed_version_context_is_visible_without_hover(
    browser, harness_url, installed_versions, width, theme, font,
):
    context = browser.new_context(
        base_url=harness_url, viewport={"width": width, "height": 800}, color_scheme=theme,
    )
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.goto("/software", wait_until="networkidle")
        if font == "wide":
            # Verdana reproduces the wider Linux CI metrics on macOS too.
            page.add_style_tag(content=":root { --sans: Verdana, sans-serif; }")
        for product in installed_versions:
            row = page.locator('tr[data-approval-row]', has=page.locator(
                '.product-name', has_text=product["name"]))
            version = row.locator('.installed-versions')
            assert version.is_visible(), f"No labelled installed version for {product['name']}"
            assert "Installed:" in version.inner_text()
            visible = version.locator('.installed-versions__value')
            expected = ", ".join(product["versions"]) or "Not reported"
            assert visible.inner_text() == expected
            assert expected in version.get_attribute("title")
            # A real visible prefix must fit after the label, not just exist
            # in textContent inside a fully clipped Installs line.
            prefix = visible.evaluate("""el => {
                const first = el.textContent.split(", ")[0];
                const prefixLength = first.length <= 20 ? first.length : 3;
                const range = document.createRange();
                range.setStart(el.firstChild, 0);
                range.setEnd(el.firstChild, Math.min(prefixLength, el.firstChild.length));
                const r = range.getBoundingClientRect(), b = el.getBoundingClientRect();
                return r.width > 0 && r.right <= b.right + 1;
            }""")
            assert prefix, f"Installed value is entirely clipped: {product['name']}"
            unknown = product["unknown_version_installation_count"]
            if unknown:
                badge = version.locator('.installed-versions__unknown')
                assert badge.inner_text() == f"{unknown} unknown"
                assert badge.evaluate("el => el.scrollWidth <= el.clientWidth + 1")
                assert (f"{unknown} installations without a version"
                        in version.get_attribute("title"))
            assert row.locator('[data-label="Installs"]').get_attribute("data-value")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not check_overflow(page, "/software", width, theme)
        if width >= 1280:
            heights = page.locator('.software-table tbody tr').evaluate_all("""rows =>
                rows.filter(r => r.offsetParent !== null)
                    .map(r => r.getBoundingClientRect().height)""")
            assert max(heights) <= 44, heights
            if width == 1280:
                in_view = page.evaluate("""() => {
                    const top = document.querySelector('.topbar').getBoundingClientRect().height;
                    const head = document.querySelector('.software-table thead');
                    window.scrollTo(0, head.getBoundingClientRect().top + scrollY - top);
                    return [...document.querySelectorAll('.software-table tbody tr')]
                        .filter(r => r.offsetParent !== null).filter(r => {
                            const b = r.getBoundingClientRect();
                            return b.top >= top - 1 && b.bottom <= innerHeight + 1;
                        }).length;
                }""")
                assert in_view >= 15, in_view
        screenshots = os.environ.get("PAT2335_SCREENSHOTS")
        if screenshots:
            Path(screenshots).mkdir(parents=True, exist_ok=True)
            page.evaluate("""() => {
                const top = document.querySelector('.topbar').getBoundingClientRect().height;
                const row = document.querySelector('.software-table tbody tr');
                window.scrollTo(0, row.getBoundingClientRect().top + scrollY - top);
            }""")
            page.screenshot(path=str(Path(screenshots) / f"software-{width}-{theme}-{font}.png"))
            for name, label in (("PartialEvidence", "long"), ("OldMetering", "missing")):
                row = page.locator('tr[data-approval-row]', has=page.locator(
                    '.product-name', has_text=name))
                row.evaluate("""el => {
                    const top = document.querySelector('.topbar').getBoundingClientRect().height;
                    window.scrollTo(0, el.getBoundingClientRect().top + scrollY - top);
                }""")
                page.screenshot(path=str(Path(screenshots) / f"{label}-{width}-{theme}-{font}.png"))
        # The version line survives a shareable filter without altering usage.
        page.goto("/software?usage=unused&search=ArchiveTool", wait_until="networkidle")
        row = page.locator('tr[data-approval-row]:visible')
        assert row.count() == 1
        assert row.locator('.installed-versions__value').inner_text() == "2.0"
        assert row.get_attribute("data-filter-usage") == "unused"
    finally:
        context.close()
