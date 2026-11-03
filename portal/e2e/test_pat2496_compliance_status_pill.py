"""PAT-2496 in a real browser: the Compliance tab's Status pill stays clear of
the Verification cell.

The Status column is a fixed 84px (`.signals-table th:nth-child(4)`), about
52px of content once padded. "Not assessed" (an undetermined rule) is wider
than that on one line, and `.pill` is `white-space: nowrap`, so the pill ran
over the Verification cell beside it. `.signals-table .pill` now wraps the way
the roster's pills do (`.device-table .pill`).

This measures the pill's box against everything inside the Verification cell
and hit-tests the cell's text, at 1440 and 1280px in both themes. Wrapping
alone leaves the pill a few pixels wider than the 52px content box ("assessed"
is about 71px with its padding, "applicable" about 76px), so its right edge can
sit inside the neighbouring cell's own padding; it never reaches that cell's
content, which is what these assertions pin. Widening the column would make it
sit wholly inside its own cell, and is a separate decision.

The fixture is dev-win-101 (acme-win-dc1), whose BitLocker rule is undetermined.
"Not applicable" is the other long status word in that column; no fixture device
carries one, so the second test serves a one-off detail response that does.
"""

import copy

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_DETAIL, STUB_STATE

BITLOCKER = "BitLocker protects the system drive"

# For the row whose Control cell starts with `title`: the Status pill's box,
# its own cell's box, every element box inside the Verification cell, and
# what the browser hit-tests just inside the left edge of the first of those.
MEASURE_JS = """
(title) => {
  const row = Array.from(document.querySelectorAll('.signals-table tbody tr')).find(
    (tr) => tr.children[1].textContent.trim().startsWith(title));
  if (!row) return {error: 'no row for ' + title};
  const box = (el) => {
    const r = el.getBoundingClientRect();
    return {left: r.left, right: r.right, top: r.top, bottom: r.bottom,
            width: r.width, height: r.height};
  };
  const statusCell = row.children[3];
  const verifyCell = row.children[4];
  const pill = statusCell.querySelector('.pill');
  const inVerify = Array.from(verifyCell.querySelectorAll('*'))
    .filter((el) => el.getBoundingClientRect().width > 0);
  const probe = inVerify[0];
  let covered = null;
  if (probe) {
    const r = probe.getBoundingClientRect();
    const hit = document.elementFromPoint(r.left + 2, r.top + r.height / 2);
    covered = !(hit && verifyCell.contains(hit));
  }
  return {
    text: pill ? pill.textContent.trim() : null,
    pill: pill ? box(pill) : null,
    cell: box(statusCell),
    verifyCell: box(verifyCell),
    verifyInner: inVerify.map(box),
    verifyCovered: covered,
  };
}
"""


def _page(browser, harness_url, theme, width):
    context = browser.new_context(base_url=harness_url, color_scheme=theme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1000})
    return context, page


def _assert_fits(measured, expected_text):
    assert "error" not in measured, measured
    assert measured["text"] == expected_text, measured
    pill, cell = measured["pill"], measured["cell"]
    # The pill starts in its own cell and stays within the row's height.
    assert pill["left"] >= cell["left"] - 0.5, measured
    assert pill["top"] >= cell["top"] - 0.5 and pill["bottom"] <= cell["bottom"] + 0.5, measured
    # It reaches nothing inside the Verification cell beside it.
    assert measured["verifyInner"], "the Verification cell has no content to check"
    for inner in measured["verifyInner"]:
        overlaps = (pill["left"] < inner["right"] and pill["right"] > inner["left"]
                    and pill["top"] < inner["bottom"] and pill["bottom"] > inner["top"])
        assert not overlaps, (pill, inner)
    # And the Verification text is not covered by another element.
    assert measured["verifyCovered"] is False, measured


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("width", [1440, 1280])
def test_not_assessed_pill_stays_clear_of_the_verification_cell(browser, harness_url, width, theme):
    context, page = _page(browser, harness_url, theme, width)
    try:
        resp = page.goto("/devices/dev-win-101/compliance", wait_until="networkidle")
        assert resp.status == 200
        assert page.evaluate("document.documentElement.getAttribute('data-theme')") == theme
        _assert_fits(page.evaluate(MEASURE_JS, BITLOCKER), "Not assessed")
    finally:
        context.close()


@pytest.fixture
def not_applicable_stub():
    detail = copy.deepcopy(DEVICE_DETAIL)
    detail["compliance_signals"] = [{
        "rule_id": "cis_not_applicable_probe", "title": "Rule that does not apply here",
        "severity": "medium", "status": "not_applicable", "advisory": "",
    }]
    STUB_STATE["device_detail_data"] = detail
    yield
    STUB_STATE["device_detail_data"] = None


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("width", [1440, 1280])
def test_not_applicable_pill_stays_clear_of_the_verification_cell(
        browser, harness_url, not_applicable_stub, width, theme):
    context, page = _page(browser, harness_url, theme, width)
    try:
        resp = page.goto("/devices/dev-mac-001/compliance", wait_until="networkidle")
        assert resp.status == 200
        _assert_fits(page.evaluate(MEASURE_JS, "Rule that does not apply here"),
                     "Not applicable")
    finally:
        context.close()
