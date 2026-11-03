"""Layout guards for the devices list, the alerts list and the theme toggle,
in a real browser.

The stub the walker uses had no Windows row with an unreported update state
and no realistic Windows build number, so it reported nothing while the live
page overlapped and wrapped (first authenticated prod walk, 29 Sept 2026):

- the "Update state not reported" pill was wider than its 145px column and
  ran over the Last seen value;
- `10.0.20348.5499` and `10.0.26200.8457` wrapped mid-number in the OS
  version column;
- the Acknowledged pill on /software/alerts touched the Raised date;
- the header theme toggle must show the active theme on every route.

Every assertion here fails on the pre-fix templates and portal.css.
"""

from datetime import UTC, datetime, timedelta

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE

CELL_CONTENT_JS = """
(tableSelector) => {
  // The painted extent of a cell's content (pills, text) as a left/right pair,
  // measured from the content itself and not the cell box, so a pill spilling
  // out of a narrow column is caught even though the cell box is fine.
  const extent = (td) => {
    const range = document.createRange();
    range.selectNodeContents(td);
    let left = Infinity, right = -Infinity;
    Array.from(range.getClientRects()).forEach((r) => {
      if (r.width === 0 && r.height === 0) return;
      left = Math.min(left, r.left);
      right = Math.max(right, r.right);
    });
    return left === Infinity ? null : {left, right};
  };
  const problems = [];
  document.querySelectorAll(tableSelector + ' tbody tr').forEach((tr) => {
    const cells = Array.from(tr.children).filter((td) => td.getClientRects().length > 0);
    cells.forEach((td, i) => {
      const box = td.getBoundingClientRect();
      const own = extent(td);
      if (!own) return;
      const clip = getComputedStyle(td).overflow === 'hidden';
      const next = cells[i + 1];
      if (!next || next.getBoundingClientRect().top >= box.bottom - 1) {
        // The last cell has no neighbour to run into, so it must stay inside its own box.
        if (!clip && own.right > box.right + 0.5) {
          problems.push('last cell (' + td.textContent.trim().slice(0, 30) +
            ') content ends at ' + own.right.toFixed(1) +
            ' past its cell edge ' + box.right.toFixed(1));
        }
        return;
      }
      // A pill may use its cell's right padding (the cell is budgeted to the
      // ordinary labels), but must always leave a visible gap before the next
      // cell's content. That gap, not the cell edge, is what "overlap" means.
      const nextExtent = extent(next);
      if (nextExtent && own.right > nextExtent.left - 4 && !clip) {
        problems.push('cell ' + (i + 1) + ' content (' + own.right.toFixed(1) +
          ') is within 4px of the next cell content (' + nextExtent.left.toFixed(1) + ')');
      }
    });
  });
  return problems;
}
"""

VERSION_LINES_JS = """
() => Array.from(document.querySelectorAll('#device-table tbody .os-build')).map((td) => {
  const range = document.createRange();
  range.selectNodeContents(td);
  const tops = new Set(Array.from(range.getClientRects()).map((r) => Math.round(r.top)));
  return {text: td.textContent.trim(), lines: tops.size,
          clipped: td.scrollWidth > td.clientWidth + 1};
})
"""

SCORE_LINES_JS = """
() => Array.from(document.querySelectorAll('#device-table .score')).map((el) => {
  const range = document.createRange();
  range.selectNodeContents(el);
  return {text: el.textContent.trim(),
          lines: new Set(Array.from(range.getClientRects()).map((r) => Math.round(r.top))).size};
})
"""

PILL_HEIGHTS_JS = """
() => Array.from(document.querySelectorAll('#device-table tbody tr'))
  .filter((tr) => tr.getClientRects().length > 0)
  .flatMap((tr) => Array.from(tr.querySelectorAll('.pill')))
  .map((p) => {
    const range = document.createRange();
    range.selectNodeContents(p);
    const lines = new Set(Array.from(range.getClientRects()).map((r) => Math.round(r.top))).size;
    const style = getComputedStyle(p);
    const chrome = ['paddingTop', 'paddingBottom', 'borderTopWidth', 'borderBottomWidth']
      .reduce((sum, key) => sum + parseFloat(style[key]), 0);
    return {text: p.textContent.trim(), height: p.getBoundingClientRect().height, lines,
            expectedHeight: lines * parseFloat(style.lineHeight) + chrome};
  })
"""


def _assert_compact_pills(pills):
    # Measured at 1280/1440px, including Verdana: long evidence labels need
    # at most three text lines (60.8px). Allow subpixel rounding, not spare
    # vertical space that could hide an extra line or inflated pill padding.
    assert pills and all(
        1 <= p["lines"] <= 3 and p["height"] <= min(62, p["expectedHeight"] + 0.5)
        for p in pills
    ), f"a pill exceeds its compact line/geometry budget: {pills}"

DOC_OVERFLOW_JS = (
    "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
)


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _row(device_id, hostname, platform, os_version, patch_pending, hours_ago=1):
    return {
        "device_id": device_id, "hostname": hostname, "platform": platform,
        "os_version": os_version,
        "last_seen": (datetime.now(UTC) - timedelta(hours=hours_ago)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "cis_score": 38.4, "findings_open": 35, "encryption_ok": True,
        "patch_pending": patch_pending,
        "cve_assessment": {
            "state": "not_assessed", "last_matched_at": None, "finding_count": None,
            "assessed_products": 0, "pending_products": 0, "not_assessed_products": 1,
        },
    }


@pytest.fixture
def realistic_roster():
    STUB_STATE["devices_data"] = {"devices": [
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499", None),
        _row("dev-mac-901", "MacBook-Pro", "macOS", "15.5", None),
        _row("dev-mac-902", "acme-mbp-ok", "macOS", "15.5", False),
        _row("dev-mac-903", "acme-mbp-behind", "macOS", "14.7", True),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.8457", None),
        # Stale evidence: both assurance pills read "... evidence stale".
        _row("dev-mac-904", "acme-mbp-stale", "macOS", "14.5", False, hours_ago=24 * 10),
    ]}
    try:
        yield
    finally:
        STUB_STATE["devices_data"] = None


@pytest.fixture
def ordinary_roster():
    """No stale evidence and no unreported Mac: every pill is one of the short
    labels the column widths are budgeted for."""
    STUB_STATE["devices_data"] = {"devices": [
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499", None),
        _row("dev-mac-902", "acme-mbp-ok", "macOS", "15.5", False),
        _row("dev-mac-903", "acme-mbp-behind", "macOS", "14.7", True),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.8457", None),
    ]}
    STUB_STATE["devices_data"]["devices"][1]["encryption_ok"] = False
    try:
        yield
    finally:
        STUB_STATE["devices_data"] = None


@pytest.mark.parametrize("width", [1440, 1280])
def test_an_ordinary_devices_tab_fits_its_card_without_scrolling_sideways(
    browser, harness_url, ordinary_roster, width,
):
    """The compact Normal roster fits its card at desktop widths, with
    ordinary labels wrapping only as much as their columns require."""
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        scroll = page.evaluate(
            "() => { const c = document.querySelector('.group-card .table-scroll');"
            " return c.scrollWidth - c.clientWidth; }")
        problems = page.evaluate(CELL_CONTENT_JS, "#device-table")
        pills = page.evaluate(PILL_HEIGHTS_JS)
    finally:
        context.close()

    assert scroll <= 1, f"the table scrolls sideways inside its card by {scroll}px at {width}px"
    assert not problems, "\n".join(problems)
    _assert_compact_pills(pills)


@pytest.mark.parametrize("view,visible_rows", [("normal", 5), ("quiet", 1)])
@pytest.mark.parametrize("width", [1440, 1280, 390])
def test_devices_table_cells_do_not_run_into_each_other(
    browser, harness_url, realistic_roster, width, view, visible_rows,
):
    # "quiet" is the tab holding the stale Mac, whose Encryption and Updates
    # pills read "... evidence stale" (the longest labels in the table).
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view={view}", wait_until="networkidle")
        assert page.locator("#device-table tbody tr:visible").count() == visible_rows
        problems = page.evaluate(CELL_CONTENT_JS, "#device-table")
        scores = page.evaluate(SCORE_LINES_JS)
        pills = page.evaluate(PILL_HEIGHTS_JS)
        overflow = page.evaluate(DOC_OVERFLOW_JS)
    finally:
        context.close()

    assert not problems, "\n".join(problems)
    # Roster pills may wrap at spaces, within the measured compact budget.
    _assert_compact_pills(pills)
    shown = [s for s in scores if s["lines"] > 0]  # rows of the other tabs are hidden
    assert len(shown) == visible_rows and all(s["lines"] == 1 for s in shown), (
        f"a score wraps: {scores}")
    assert overflow <= 1, f"the page scrolls sideways at {width}px by {overflow}px"



@pytest.mark.parametrize("view", ["normal", "quiet", "silent", "retired", "stale"])
@pytest.mark.parametrize("width", [1440, 1280])
def test_desktop_roster_pills_keep_their_line_budget_with_verdana(
    browser, harness_url, realistic_roster, width, view,
):
    """The wider fallback font must fit long labels in every reporting group."""
    rows = STUB_STATE["devices_data"]["devices"]
    rows.append(_row("dev-mac-silent", "silent-mac", "macOS", "15.5", None, hours_ago=24 * 40))
    retired = _row("dev-mac-retired", "retired-mac", "macOS", "15.5", None, hours_ago=24 * 40)
    retired["retirement"] = {"retired_at": "2026-09-01T00:00:00Z"}
    rows.append(retired)
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view={view}", wait_until="networkidle")
        page.add_style_tag(content=(
            ":root { --sans: Verdana, sans-serif; --display: Verdana, sans-serif; }"))
        _assert_compact_pills(page.evaluate(PILL_HEIGHTS_JS))
        assert not page.evaluate(CELL_CONTENT_JS, "#device-table")
        assert page.evaluate(DOC_OVERFLOW_JS) <= 1
        assert page.locator("#device-table").evaluate(
            "el => el.parentElement.scrollWidth <= el.parentElement.clientWidth + 1")
    finally:
        context.close()


def test_windows_version_numbers_stay_on_one_line_and_are_not_clipped(
    browser, harness_url, realistic_roster,
):
    context = _context(browser, harness_url, viewport={"width": 1440, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        versions = page.evaluate(VERSION_LINES_JS)
    finally:
        context.close()

    windows = [v for v in versions if v["text"].startswith("10.0.")]
    assert len(windows) == 2
    for version in windows:
        assert version["lines"] == 1, f"{version['text']} wraps over {version['lines']} lines"
        assert not version["clipped"], f"{version['text']} is cut off by its column"


def test_windows_rows_show_the_single_note_and_the_mac_null_pill_stays_inside_its_cell(
    browser, harness_url, realistic_roster,
):
    context = _context(browser, harness_url, viewport={"width": 1440, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        body = page.locator("main").inner_text()
        pills = page.evaluate("""() => Array.from(document.querySelectorAll(
            "#device-table td [title]" )).filter(p => p.textContent === 'Not reported')
            .map(p => { const c = p.closest('td').getBoundingClientRect();
                        const r = p.getBoundingClientRect();
                        return {right: r.right, cellRight: c.right}; })""")
    finally:
        context.close()

    assert body.count("This device hasn't reported a recent update state.") == 1
    assert len(pills) == 3  # unknown evidence on both platforms
    assert all(p["right"] <= p["cellRight"] + 0.5 for p in pills)


@pytest.mark.parametrize("status", ["acknowledged", "all", "resolved"])
@pytest.mark.parametrize("width", [1440, 1280])
def test_alerts_status_pill_sits_inside_its_own_cell(browser, harness_url, status, width):
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/software/alerts?status={status}", wait_until="networkidle")
        if page.locator("#alerts-table tbody tr").count() == 0:
            pytest.skip(f"the stub has no {status} alerts")
        problems = page.evaluate(CELL_CONTENT_JS, "#alerts-table")
    finally:
        context.close()

    assert not problems, "\n".join(problems)


THEME_STATE_JS = """
() => {
  const group = document.querySelector('.theme-toggle');
  const applied = document.documentElement.getAttribute('data-theme');
  const buttons = Array.from(group.querySelectorAll('[data-theme-choice]')).map((b) => ({
    choice: b.getAttribute('data-theme-choice'),
    cls: b.classList.contains('is-active'),
    pressed: b.getAttribute('aria-pressed') === 'true',
    paint: getComputedStyle(b).backgroundColor,
  }));
  return {applied, buttons};
}
"""

# Strips the script-set state (class and aria-pressed) to prove the highlight
# follows <html data-theme> in CSS rather than depending on it surviving.
STRIP_THEME_SCRIPT_STATE_JS = """
() => {
  document.querySelectorAll('.theme-toggle [data-theme-choice]').forEach((b) => {
    b.classList.remove('is-active');
    b.removeAttribute('aria-pressed');
  });
}
"""

THEME_PAINT_JS = """
() => Array.from(document.querySelectorAll('.theme-toggle [data-theme-choice]')).map((b) => ({
  choice: b.getAttribute('data-theme-choice'),
  paint: getComputedStyle(b).backgroundColor,
}))
"""

DEVICE_ROUTES = [
    "/devices/dev-mac-001", "/devices/dev-mac-001/hardware",
    "/devices/dev-mac-001/software", "/devices/dev-mac-001/vulnerabilities",
    "/devices/dev-mac-001/compliance", "/devices/dev-mac-001/evidence",
    "/devices/dev-win-002", "/devices", "/",
]


@pytest.mark.parametrize("route", DEVICE_ROUTES)
@pytest.mark.parametrize("stored,os_scheme,expected", [
    (None, "light", "light"),
    (None, "dark", "dark"),
    ("dark", "light", "dark"),
    ("light", "dark", "light"),
    ("system", "dark", "dark"),
])
def test_theme_toggle_shows_exactly_the_active_theme(
    browser, harness_url, route, stored, os_scheme, expected,
):
    context = _context(browser, harness_url, color_scheme=os_scheme,
                       viewport={"width": 1440, "height": 900})
    try:
        if stored is not None:
            context.add_init_script(
                "try { localStorage.setItem('patched-portal-theme', '" + stored + "'); }"
                " catch (e) {}")
        page = context.new_page()
        page.goto(f"{harness_url}{route}", wait_until="networkidle")
        state = page.evaluate(THEME_STATE_JS)
        page.evaluate(STRIP_THEME_SCRIPT_STATE_JS)
        page.wait_for_timeout(400)  # let any background transition finish
        css_only = page.evaluate(THEME_PAINT_JS)
    finally:
        context.close()

    assert state["applied"] == expected
    active = [b for b in state["buttons"] if b["cls"] and b["pressed"]]
    assert [b["choice"] for b in active] == [expected]
    other = [b for b in state["buttons"] if b["choice"] != expected][0]
    assert active[0]["paint"] != other["paint"], "active and inactive look the same"
    # And with the script-set state removed, the theme still reads as chosen.
    painted = {b["choice"]: b["paint"] for b in css_only}
    other_choice = "dark" if expected == "light" else "light"
    assert painted[expected] != painted[other_choice], (
        "the active theme is only highlighted while a script-set class survives")
