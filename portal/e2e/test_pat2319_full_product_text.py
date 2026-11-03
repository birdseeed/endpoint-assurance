"""Full values survive real ellipsis on Software and Homebrew (PAT-2319)."""

import copy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import check_overflow
from tests.conftest import (
    APPLICATIONS,
    HOMEBREW_CASKS,
    HOMEBREW_FORMULAE,
    SOFTWARE_INVENTORY,
    STUB_STATE,
)

LONG_NAME = 'Long product "Research & reporting" edition for the entire customer estate'
LONG_PUBLISHER = 'Research & reporting "Publisher" with a deliberately long organisation name'
CANONICAL_NAME = 'Reviewed Research & reporting product'


@pytest.fixture
def long_product_values():
    """Exercise both Homebrew tables and retain Software's reviewed identity."""
    overrides = {
        "applications_data": copy.deepcopy(APPLICATIONS),
        "software_inventory_data": copy.deepcopy(SOFTWARE_INVENTORY),
        "homebrew_casks_data": copy.deepcopy(HOMEBREW_CASKS),
        "homebrew_formulae_data": copy.deepcopy(HOMEBREW_FORMULAE),
    }
    app = overrides["applications_data"]["applications"][0]
    app.update(name=LONG_NAME, signed_by=LONG_PUBLISHER,
               identifier="com.acme.archive", platform="macos")
    product = overrides["software_inventory_data"]["products"][0]
    product.update(name=LONG_NAME, names=[LONG_NAME], canonical_name=CANONICAL_NAME)
    cask = overrides["homebrew_casks_data"]["casks"][0]
    cask.update(token=LONG_NAME, tap=LONG_PUBLISHER)
    formula = overrides["homebrew_formulae_data"]["formulae"][0]
    formula.update(name=LONG_NAME, tap=LONG_PUBLISHER)
    saved = {key: STUB_STATE.get(key) for key in overrides}
    STUB_STATE.update(overrides)
    try:
        yield
    finally:
        STUB_STATE.update(saved)


@pytest.mark.parametrize("route", ["/software", "/homebrew"])
@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_full_values_remain_available_with_real_ellipsis(
    browser, harness_url, long_product_values, route, width, theme,
):
    context = browser.new_context(
        base_url=harness_url, viewport={"width": width, "height": 900}, color_scheme=theme,
    )
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.goto(route, wait_until="networkidle")
        values = page.locator(".product-name, .product-publisher").evaluate_all("""els =>
            els.filter(el => el.offsetParent !== null).map(el => ({
                text: el.textContent.trim(), title: el.getAttribute('title'),
                clipped: el.scrollWidth > el.clientWidth + 2
                    && getComputedStyle(el).textOverflow === 'ellipsis',
            }))""")
        names = [v for v in values if v["text"] == LONG_NAME]
        publishers = [v for v in values if v["text"] == LONG_PUBLISHER]
        assert len(names) == len(publishers) == (1 if route == "/software" else 2), values
        # Prove the check covers actual clipping, rather than passing because
        # short fixture names fit. Phone rows wrap, preserving the same values.
        if route == "/software" and width >= 1280:
            assert any(v["clipped"] for v in publishers), values
        findings = check_overflow(page, route, width, theme)
        assert not [f for f in findings if f.check == "truncation-no-full-text"], findings
        expected_title = (f"{LONG_NAME} (reviewed identity: {CANONICAL_NAME})"
                          if route == "/software" else LONG_NAME)
        assert all(v["title"] == expected_title for v in names), names
        assert all(v["title"] == LONG_PUBLISHER for v in publishers), publishers
        # Attribute escaping must preserve the complete quoted values without
        # creating markup, and CSS truncation must not shorten the link's name.
        assert (page.locator('.product-name').filter(has_text=LONG_NAME).first.inner_text()
                == LONG_NAME)
    finally:
        context.close()
