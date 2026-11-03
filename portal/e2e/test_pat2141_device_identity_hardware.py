"""Guards PAT-2141 - the top Device card (Identification) and the compacted
Hardware card, per Andy's live follow-up feedback, 25 Sept 2026:
"Identification section should be at the top. Evidence collection can be
in the same section alongside the ID details. Hardware tab could also be
compacted / tidied."

PAT-2164 follow-up: Identification (Overview tab) and Evidence collection
(its own Evidence tab) are on separate pages now - superseding the "merged
into one Device card, side by side" structure this file originally guarded.
They can no longer sit side by side on one page at all, so those two tests
(test_identity_and_evidence_sit_side_by_side_at_1280,
test_identity_and_evidence_stack_at_phone_width) are gone; every other
guarantee here - card order, real values, the compacted Hardware card's
height, the Compute/Battery pairing, no overflow, not_collected/absent
fail-soft - still holds, just against the tab it now lives on.

**Hardware card height baseline.** Measured against the unmodified
templates/device_detail.html + static/css/portal.css at origin/main 39704dd
(a throwaway `git worktree add --detach origin/main`, `#hardware`
`getBoundingClientRect().height` at 1280px against the default dev-mac-001
stub fixture, the fully-collected device): **620.2px**. 25% smaller is
465.15px. This suite's own build renders at 440.6px in the ordinary case
and 438.6px under the wide system-ui fallback font Linux CI resolves
(PAT-2070's `WIDE_FALLBACK_FONT_CSS`), both comfortably under the 25% bar
(a 28.9% reduction) - so HARDWARE_CARD_HEIGHT_CEILING_PX below is fixed at
460px: below the 465.15px quarter-off bar with no dependency on a live
baseline measurement at test time, and above the 438.6px worst case this
suite itself measured, so it does not flap on ordinary rendering variance
between environments.

Red-proof: every assertion in this file fails against the unmodified
templates/device_detail.html + static/css/portal.css (origin/main 39704dd)
- there is no `.device-card`/`.device-card__grid` at all (Identification and
Evidence collection are two separate cards, Evidence collection first,
Identification third), Compute and Battery are two blocks in a single-column
stack rather than a side-by-side pair, and the Hardware card renders at
620.2px, above the 460px ceiling - see the module-level report for the
actual red output this ticket captured before the fix landed.
"""

from copy import deepcopy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_DETAIL, STUB_STATE

# See the module docstring for how this was derived from the origin/main
# 39704dd baseline measurement (620.2px whole-card height at 1280px).
HARDWARE_CARD_HEIGHT_CEILING_PX = 460

WIDE_FALLBACK_FONT_CSS = '* { font-family: "Verdana", "DejaVu Sans", sans-serif !important; }'

# Same shape as e2e/test_pat2136_device_detail_phone.py's OVERFLOW_JS -
# nothing inside any of the named cards may render wider than the card's
# own box.
OVERFLOW_JS = """
(selectors) => {
  const failures = [];
  selectors.forEach((sel) => {
    const card = document.querySelector(sel);
    if (!card) { failures.push(sel + ': card not found'); return; }
    const cr = card.getBoundingClientRect();
    card.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (r.right > cr.right + 1 || r.left < cr.left - 1) {
        failures.push(sel + ': ' + el.tagName + ' ' +
          JSON.stringify((el.textContent || '').trim().slice(0, 40)) +
          ' right=' + r.right.toFixed(1) + ' cardRight=' + cr.right.toFixed(1));
      }
    });
  });
  return failures;
}
"""

DOCUMENT_SCROLLWIDTH_JS = """
() => ({scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth})
"""


def _context(browser, harness_url, viewport):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_identity_and_assurance_share_the_only_overview_card(browser, harness_url):
    """PAT-2339 removes the duplicate Summary and its extra card padding."""
    context = _context(browser, harness_url, {"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        assert page.locator('.card').count() == 1
        assert page.locator('.device-card #identification').is_visible()
        assert page.locator('.device-card #device-assurance').is_visible()
        assert page.locator('.card h2', has_text='Summary').count() == 0
    finally:
        context.close()


def test_compute_and_battery_sit_side_by_side_at_1280(browser, harness_url):
    context = _context(browser, harness_url, {"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")
        compute_box = page.locator('.hardware-block:has(h3:text-is("Compute"))').bounding_box()
        battery_box = page.locator('.hardware-block:has(h3:text-is("Battery"))').bounding_box()
    finally:
        context.close()
    assert compute_box and battery_box
    assert battery_box["x"] >= compute_box["x"] + compute_box["width"] - 1, (
        f"battery block left edge {battery_box['x']:.1f} is not right of "
        f"compute's right edge {compute_box['x'] + compute_box['width']:.1f}"
    )
    assert abs(compute_box["y"] - battery_box["y"]) <= 4, (
        f"blocks are not top-aligned: compute y={compute_box['y']:.1f}, "
        f"battery y={battery_box['y']:.1f}"
    )


@pytest.mark.parametrize("wide_font", [False, True])
def test_hardware_card_is_at_least_a_quarter_shorter_than_baseline(browser, harness_url, wide_font):
    context = _context(browser, harness_url, {"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")
        if wide_font:
            page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        # The 620.2px baseline was measured with a one-volume fixture. The
        # fixture now mirrors a real Mac (PAT-2141 polish: an extra external
        # volume plus the collapsed macOS system volumes line), so content
        # added since the baseline is subtracted to keep this a like-for-like
        # compaction check rather than a fixture-size check. PAT-2262 added a
        # whole new Firmware section below Storage volumes (the default
        # dev-mac-001 fixture has no "firmware" key, so it renders as one
        # muted not_reported line) - genuinely new content this pinned
        # ceiling predates, not a regression in the Compute/Battery/Disks/
        # Volumes compaction this test exists to guard, so it is subtracted
        # the same way the system-volumes disclosure already is above.
        height = page.evaluate(
            """() => {
              const card = document.querySelector('#hardware');
              let h = card.getBoundingClientRect().height;
              const rows = card.querySelectorAll(
                '.hardware-volumes-table:not(.hardware-volumes-table--system) tbody tr');
              for (let i = 1; i < rows.length; i++) h -= rows[i].getBoundingClientRect().height;
              const sys = card.querySelector('.hardware-system-volumes');
              if (sys) h -= sys.getBoundingClientRect().height
                + parseFloat(getComputedStyle(sys).marginTop || '0');
              const firmware = card.querySelector('#firmware');
              if (firmware) h -= firmware.getBoundingClientRect().height
                + parseFloat(getComputedStyle(firmware).marginTop || '0');
              return h;
            }"""
        )
    finally:
        context.close()
    assert height <= HARDWARE_CARD_HEIGHT_CEILING_PX, (
        f"[wide_font={wide_font}] Hardware card is {height:.1f}px tall, "
        f"ceiling is {HARDWARE_CARD_HEIGHT_CEILING_PX}px "
        f"(25% under the 620.2px origin/main baseline)"
    )


def test_identification_card_shows_real_values_at_1280(browser, harness_url):
    context = _context(browser, harness_url, {"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        assert page.locator("#identification").count() == 1
        identification_text = page.locator("#identification").inner_text()
    finally:
        context.close()
    assert "Identification" in identification_text
    assert "C02XL0GTJGH5" in identification_text  # serial
    assert "Mac16,1" in identification_text  # model identifier
    assert "arm64" in identification_text


def test_hardware_card_shows_real_values_at_1280(browser, harness_url):
    context = _context(browser, harness_url, {"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")
        assert page.locator("#hardware").count() == 1
        hardware_text = page.locator("#hardware").inner_text()
    finally:
        context.close()
    assert "Hardware" in hardware_text
    assert "Apple M2" in hardware_text
    assert "disk0" in hardware_text
    assert "Verified" in hardware_text
    assert "93%" in hardware_text


def test_evidence_chip_links_to_the_hardware_tab(browser, harness_url):
    # PAT-2164: the chip now deep-links across tabs (Evidence -> Hardware)
    # rather than to an in-page #hardware anchor on the same page.
    context = _context(browser, harness_url, {"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/evidence", wait_until="networkidle")
        battery_chip = page.locator('.evidence-chip:has-text("Hardware health: battery")')
        assert battery_chip.count() == 1
        assert battery_chip.get_attribute("href") == "/devices/dev-mac-001/hardware#hardware"
    finally:
        context.close()


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_identification_card_does_not_overflow_at_phone_width(browser, harness_url, color_scheme):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")

        assert page.locator("#identification").count() == 1

        overflow = page.evaluate(OVERFLOW_JS, [".device-card"])
        doc = page.evaluate(DOCUMENT_SCROLLWIDTH_JS)
    finally:
        context.close()

    assert not overflow, (
        f"[{color_scheme}] element(s) overflowed their card:\n" + "\n".join(overflow)
    )
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"[{color_scheme}] document scrolls horizontally at 390px: {doc}"
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_hardware_card_does_not_overflow_at_phone_width(browser, harness_url, color_scheme):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")

        assert page.locator("#hardware").count() == 1

        overflow = page.evaluate(OVERFLOW_JS, ["#hardware"])
        doc = page.evaluate(DOCUMENT_SCROLLWIDTH_JS)
    finally:
        context.close()

    assert not overflow, (
        f"[{color_scheme}] element(s) overflowed their card:\n" + "\n".join(overflow)
    )
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"[{color_scheme}] document scrolls horizontally at 390px: {doc}"
    )


def test_not_collected_identity_renders_explicit_status_at_phone_width(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-003", wait_until="networkidle")
        identification_text = page.locator("#identification").inner_text()
        overflow = page.evaluate(OVERFLOW_JS, ["#identification"])
    finally:
        context.close()

    assert "This device has not sent an inventory report yet." in identification_text
    assert not overflow, "element(s) overflowed their card:\n" + "\n".join(overflow)


def test_not_collected_hardware_renders_explicit_status_at_phone_width(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-003/hardware", wait_until="networkidle")
        hardware_text = page.locator("#hardware").inner_text()
        overflow = page.evaluate(OVERFLOW_JS, ["#hardware"])
    finally:
        context.close()

    assert "Not collected" in hardware_text
    assert not overflow, "element(s) overflowed their card:\n" + "\n".join(overflow)


def test_identity_absent_entirely_renders_200_with_neutral_line(browser, harness_url):
    """An older platform build predating this ticket may omit `identity`/
    `hardware` from the response entirely - the page must fail soft (a
    neutral line, never a crash, never a zero)."""
    detail = deepcopy(DEVICE_DETAIL)
    del detail["identity"]
    del detail["hardware"]
    STUB_STATE["device_detail_data"] = detail

    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        response = page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        assert response.status == 200
        body = page.content()
    finally:
        context.close()
        STUB_STATE["device_detail_data"] = None

    assert "Identification is not available on this device page yet." in body
    assert "C02XL0GTJGH5" not in body


def test_hardware_absent_entirely_renders_200_with_neutral_line(browser, harness_url):
    detail = deepcopy(DEVICE_DETAIL)
    del detail["identity"]
    del detail["hardware"]
    STUB_STATE["device_detail_data"] = detail

    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        response = page.goto(
            f"{harness_url}/devices/dev-mac-001/hardware", wait_until="networkidle")
        assert response.status == 200
        body = page.content()
    finally:
        context.close()
        STUB_STATE["device_detail_data"] = None

    assert "Hardware information is not available on this device page yet." in body
    assert "Apple M2" not in body
