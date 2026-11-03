"""Servers are told apart from workstations without breaking the Devices
table's layout (PAT-2324).

HOMESERVER (Windows Server 2022) read exactly like WINDOWS11 (Windows 11).
A server row now reads "Windows Server" in Platform, leads its OS cell with
"Server 2022" over the build,
and shows "n/a" for the CIS score (there is no server benchmark yet). None of
that may change a column width: the Normal tab must still fit its card at
1280px, no cell's content may run into its neighbour at 1440, 1280 or 390px,
and a build number must stay whole. The unit suite proves the markup and the
absent-field fallback (tests/test_pat2324_server_display.py); this proves it
in a browser, and that the search box finds a server by typing "server".
"""

from datetime import UTC, datetime, timedelta

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_pat2256_devices_layout import CELL_CONTENT_JS
from tests.conftest import STUB_STATE

SERVER_CAPTION = "Microsoft Windows Server 2022 Standard"

# Every named line of the OS cell, one entry per line, so a build that wraps or
# is clipped is caught: text and how many lines it fills.
OS_CELL_JS = """
() => Array.from(document.querySelectorAll('#device-table tbody td.cell-os-named:has(.os-name)'))
  .filter((td) => td.getClientRects().length > 0)
  .map((td) => {
    const build = td.querySelector('.os-build');
    const name = td.querySelector('.os-name');
    const lines = (el) => {
      const range = document.createRange();
      range.selectNodeContents(el);
      return new Set(Array.from(range.getClientRects()).map((r) => Math.round(r.top))).size;
    };
    return {name: name.textContent.trim(), nameLines: lines(name),
            build: build ? build.textContent.trim() : null,
            buildLines: build ? lines(build) : 0,
            buildClipped: build ? build.scrollWidth > build.clientWidth + 1 : false,
            top: build ? build.getBoundingClientRect().top - name.getBoundingClientRect().top : 0};
  })
"""

PILL_JS = """
() => Array.from(document.querySelectorAll('#device-table .device-type-pill'))
  .filter((p) => p.getClientRects().length > 0)
  .map((p) => {
    const cell = p.closest('td').getBoundingClientRect();
    const box = p.getBoundingClientRect();
    return {text: p.textContent.trim(), height: box.height,
            insideCell: box.left >= cell.left && box.right <= cell.right + 0.5};
  })
"""

NOTE_JS = """
() => Array.from(document.querySelectorAll('[data-server-score-note]'))
  .map((n) => getComputedStyle(n).display !== 'none' && n.getClientRects().length > 0)
"""

DOC_OVERFLOW_JS = (
    "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
)


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _row(device_id, hostname, platform, os_version, hours_ago=1, **over):
    row = {
        "device_id": device_id, "hostname": hostname, "platform": platform,
        "os_version": os_version,
        "last_seen": (datetime.now(UTC) - timedelta(hours=hours_ago)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "cis_score": 38.4, "findings_open": 35, "encryption_ok": True,
        "patch_pending": None,
        "cve_assessment": {
            "state": "not_assessed", "last_matched_at": None, "finding_count": None,
            "assessed_products": 0, "pending_products": 0, "not_assessed_products": 1,
        },
    }
    row.update(over)
    return row


@pytest.fixture
def mixed_roster():
    """HOMESERVER and WINDOWS11 as the platform now sends them, a Mac, a
    Windows device from a platform that has not deployed the fields, and one
    stale Mac so the Quiet tab holds no server."""
    STUB_STATE["devices_data"] = {"devices": [
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499",
             device_class="server", os_caption=SERVER_CAPTION),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.9457",
             device_class="workstation", os_caption="Microsoft Windows 11 Enterprise"),
        _row("dev-mac-901", "MacBook-Pro", "macOS", "15.5", patch_pending=False,
             device_class="workstation", os_caption=None),
        _row("dev-win-903", "OLD-PLATFORM", "Windows", "10.0.19045.5000"),
        _row("dev-mac-902", "acme-mbp-stale", "macOS", "14.5", hours_ago=24 * 5,
             device_class="workstation", os_caption=None, patch_pending=False),
    ]}
    try:
        yield
    finally:
        STUB_STATE["devices_data"] = None


@pytest.mark.parametrize("width", [1440, 1280, 390])
def test_a_server_row_reads_cleanly_at_every_width(browser, harness_url, mixed_roster, width):
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        row = page.locator("#device-table tbody tr", has_text="HOMESERVER")
        platform = row.locator("td").nth(1).inner_text().replace("\n", " ").strip()
        score = row.locator(".score").inner_text().strip()
        problems = page.evaluate(CELL_CONTENT_JS, "#device-table")
        pills = page.evaluate(PILL_JS)
        overflow = page.evaluate(DOC_OVERFLOW_JS)
        scroll = page.evaluate(
            "() => { const c = document.querySelector('.group-card .table-scroll');"
            " return c.scrollWidth - c.clientWidth; }")
    finally:
        context.close()

    assert platform == "Windows Server"
    assert score == "n/a"
    assert not problems, "\n".join(problems)
    assert pills == []
    assert overflow <= 1, f"the page scrolls sideways at {width}px by {overflow}px"
    if width >= 1280:
        # The Normal tab keeps its 966px budget: adding a server changes no column.
        assert scroll <= 1, f"the table scrolls sideways inside its card by {scroll}px"


def test_os_cells_put_the_name_over_a_whole_unclipped_build(browser, harness_url, mixed_roster):
    context = _context(browser, harness_url, viewport={"width": 1440, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        cells = page.evaluate(OS_CELL_JS)
        bare = page.locator("#device-table tbody tr", has_text="OLD-PLATFORM").locator(
            "td").nth(2).inner_text().strip()
    finally:
        context.close()

    by_build = {c["build"]: c for c in cells}
    assert set(by_build) == {"10.0.20348.5499", "10.0.26200.9457"}
    assert by_build["10.0.20348.5499"]["name"] == "Server 2022"
    assert by_build["10.0.26200.9457"]["name"] == "Windows 11"
    for cell in cells:
        assert cell["nameLines"] == 1 and cell["buildLines"] == 1, cell
        assert not cell["buildClipped"], f"{cell['build']} is cut off by its column"
        assert cell["top"] > 0, "the build sits under the name"
    # A device from a platform without the fields keeps the bare build.
    assert bare == "10.0.19045.5000"


def test_score_note_shows_only_while_a_server_row_is_visible(browser, harness_url, mixed_roster):
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        on_normal = page.evaluate(NOTE_JS)
        text = page.locator("[data-server-score-note]").inner_text().strip()
        page.goto(f"{harness_url}/devices?view=quiet", wait_until="networkidle")
        on_quiet = page.evaluate(NOTE_JS)
        visible = page.locator("#device-table tbody tr:visible").count()
    finally:
        context.close()

    assert on_normal == [True]
    assert text == ("Servers are not scored against a CIS benchmark yet. "
                    "Their failing checks come from Patched's baseline checks.")
    assert visible == 1 and on_quiet == [False]  # the stale Mac only


def test_searching_for_server_finds_the_server_rows_only(browser, harness_url, mixed_roster):
    context = _context(browser, harness_url, viewport={"width": 1440, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices?view=normal", wait_until="networkidle")
        search = page.locator("#device-search")

        def visible_hostnames():
            return sorted(
                t.strip() for t in page.locator(
                    "#device-table tbody tr:visible td:first-child a").all_inner_texts())

        search.fill("server")
        by_server = visible_hostnames()
        search.fill("windows 11")
        by_release = visible_hostnames()
        search.fill("Windows Server")
        by_platform = visible_hostnames()
        search.fill("")
        everything = visible_hostnames()
    finally:
        context.close()

    assert by_server == ["HOMESERVER"]
    assert by_release == ["WINDOWS11"]
    assert by_platform == ["HOMESERVER"]
    assert len(everything) == 4


@pytest.mark.parametrize("width", [1440, 1280, 390])
def test_the_server_device_page_reads_cleanly(browser, harness_url, width):
    """dev-win-101 is the stub's Windows Server (tests/conftest.py)."""
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices/dev-win-101", wait_until="networkidle")
        meta = page.locator(".page-head .meta").inner_text().strip()
        summary = page.locator("#device-assurance")
        rows = {
            dt.strip(): dd.strip() for dt, dd in zip(
                summary.locator("dt").all_inner_texts(),
                summary.locator("dd").all_inner_texts(), strict=True)
        }
        overflow = page.evaluate(DOC_OVERFLOW_JS)
        date_lines = page.evaluate("""() => {
          const spans = document.querySelectorAll('.page-head .meta .nowrap');
          const el = spans[spans.length - 1];
          const range = document.createRange(); range.selectNodeContents(el);
          return new Set(Array.from(range.getClientRects()).map((r) => Math.round(r.top))).size;
        }""")
    finally:
        context.close()

    assert meta.startswith("Windows Server · 10.0.20348.5499 · last seen ")
    assert rows["Type"] == "Server"
    assert rows["Windows version"] == "Server 2022 · 10.0.20348.5499"
    assert rows["CIS Level 1 score"] == "Not available for servers yet"
    assert overflow <= 1, f"the page scrolls sideways at {width}px by {overflow}px"
    assert date_lines == 1, "the last seen date breaks across lines"
