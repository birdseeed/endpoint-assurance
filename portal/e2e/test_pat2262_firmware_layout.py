"""Guards PAT-2262 - the Firmware section on the device Hardware tab
(BIOS/system/baseboard identity) renders without overflow at 1280px and
390px, light and dark, using a fully-populated fixture so the three-column
BIOS/System/Baseboard grid is actually exercised rather than the single
muted not_reported line the default dev-mac-001 stub renders (no
"firmware" key at all).

Red-proof: every assertion here fails before the Firmware section exists
(no #firmware element at all) and passes once templates/device_hardware.html
and static/css/portal.css carry it.
"""

from copy import deepcopy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_DETAIL, STUB_STATE

FULL_FIRMWARE = {
    "status": "complete",
    "reported_at": "2026-09-28T09:00:00Z", "observed_at": "2026-09-28T08:59:40Z",
    "errors": [],
    "bios": {
        "status": "complete", "reported_at": "2026-09-28T09:00:00Z",
        "manufacturer": "LENOVO", "version": "N3HET82W (1.54 )",
        "smbios_version": "3.2", "release_date": "2022-03-15", "release_date_raw": None,
    },
    "system": {"status": "complete", "reported_at": "2026-09-28T09:00:00Z",
               "manufacturer": "LENOVO", "model": "20XW0026UK"},
    "baseboard": {"status": "complete", "reported_at": "2026-09-28T09:00:00Z",
                  "manufacturer": "LENOVO", "product": "LNVNB161216"},
}

OVERFLOW_JS = """
(selector) => {
  const failures = [];
  const card = document.querySelector(selector);
  if (!card) { failures.push(selector + ': not found'); return failures; }
  const cr = card.getBoundingClientRect();
  card.querySelectorAll('*').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return;
    if (r.right > cr.right + 1 || r.left < cr.left - 1) {
      failures.push(el.tagName + ' ' +
        JSON.stringify((el.textContent || '').trim().slice(0, 40)) +
        ' right=' + r.right.toFixed(1) + ' cardRight=' + cr.right.toFixed(1));
    }
  });
  return failures;
}
"""

DOCUMENT_SCROLLWIDTH_JS = """
() => ({scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth})
"""


@pytest.fixture
def full_firmware_stub():
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = FULL_FIRMWARE
    STUB_STATE["device_detail_data"] = detail
    yield
    STUB_STATE["device_detail_data"] = None


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [1280, 390])
def test_firmware_section_renders_without_overflow(
    browser, harness_url, full_firmware_stub, color_scheme, width
):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")

        firmware_section = page.locator("#firmware")
        assert firmware_section.count() == 1
        text = firmware_section.inner_text()

        overflow = page.evaluate(OVERFLOW_JS, "#firmware")
        doc = page.evaluate(DOCUMENT_SCROLLWIDTH_JS)
    finally:
        context.close()

    assert "LENOVO" in text
    assert "N3HET82W (1.54 )" in text
    assert "20XW0026UK" in text
    assert "LNVNB161216" in text
    assert "Released March 2022" in text
    assert not overflow, (
        f"[{width}px, {color_scheme}] element(s) overflowed #firmware:\n" + "\n".join(overflow)
    )
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"[{width}px, {color_scheme}] document scrolls horizontally: {doc}"
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_not_reported_firmware_shows_macos_wording_without_overflow(
    browser, harness_url, color_scheme
):
    """The default dev-mac-001 stub (platform macOS) carries no "firmware"
    key at all - the not_reported/absent path, exercised here at phone
    width to prove the muted fallback line itself never overflows."""
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")

        firmware_section = page.locator("#firmware")
        assert firmware_section.count() == 1
        text = firmware_section.inner_text()

        overflow = page.evaluate(OVERFLOW_JS, "#firmware")
    finally:
        context.close()

    assert "follows the macOS version shown above" in text
    assert not overflow, (
        f"[{color_scheme}] element(s) overflowed #firmware:\n" + "\n".join(overflow)
    )
