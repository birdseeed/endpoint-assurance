"""PAT-2155 in a real browser: Andy, live, 2026-09-25: "This looks shit"
(the /alerts Open tab - a raised date wrapping over four lines, the raw
"macos" platform key, an Acknowledged/Resolved column reading "-" down
every row, "Product key"/"Device ID" filter boxes, and a note input
stacking above its Acknowledge button). This file is the layout guard at
1280px (and a phone-width overflow check at 390px); the write path, guard
and filter-passthrough behaviour are covered in full by
tests/test_pat2097_alerts.py and tests/test_pat2155_alerts_layout.py
against the same stub - the same split e2e/test_pat2140_new_software_layout.py
already uses for its own page.

Red-proof (verified by hand for this ticket, not kept as a permanent
test): every assertion below fails against the pre-PAT-2155 template and
portal.css (temporarily restored from HEAD, tested, then reverted) - see
the ticket's own report for the captured red output. Restoring this
diff's real template/CSS brings every assertion back to green.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import MEASURE_JS, TABLE_SCROLL_MEASURE_JS
from tests.conftest import STUB_STATE

LINE_COUNT_JS = """
sel => Array.prototype.map.call(document.querySelectorAll(sel), el => el.getClientRects().length)
"""


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _assert_no_overflow(page):
    doc = page.evaluate(MEASURE_JS)
    assert doc["scrollWidth"] <= doc["clientWidth"] + 1, (
        f"document scrollWidth={doc['scrollWidth']} > clientWidth={doc['clientWidth']}"
    )
    for r in page.evaluate(TABLE_SCROLL_MEASURE_JS):
        raise AssertionError(
            f"table {r['tableCls']} scroll container overflows: "
            f"scrollWidth={r['scrollWidth']} > clientWidth={r['clientWidth']}"
        )


# ── No date cell wraps beyond two lines at 1280px (every tab that has one) ──

def test_no_date_cell_wraps_beyond_two_lines_at_1280(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        for status in ("open", "acknowledged", "resolved", "all"):
            page.goto(f"/software/alerts?status={status}", wait_until="networkidle")
            date_lines = page.evaluate(LINE_COUNT_JS, ".alerts-table .cell-evidence__main")
            time_lines = page.evaluate(
                LINE_COUNT_JS, ".alerts-table .cell-evidence .cell-subtle")
            assert date_lines, f"no date cells rendered on the {status} tab"
            # Each half (date, then time) renders on one line of its own -
            # together at most two, never the reported "25 / Sep / 2026 /
            # 11:42" one-word-per-line wrap.
            assert all(n == 1 for n in date_lines), (status, date_lines)
            assert all(n == 1 for n in time_lines), (status, time_lines)
    finally:
        context.close()


# ── Platform reads macOS/Windows, never the raw key ─────────────────────

def test_platform_reads_macos_and_windows_not_raw_key(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software/alerts?status=all", wait_until="networkidle")
        body = page.content()
        assert "macOS" in body
        assert "Windows" in body
        table_text = page.locator("#alerts-table").inner_text()
        assert "macos" not in table_text
        assert "windows" not in table_text
    finally:
        context.close()


# ── Open tab has no Acknowledged/Resolved header ─────────────────────────

def test_open_tab_has_no_acknowledged_or_resolved_header(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software/alerts?status=open", wait_until="networkidle")
        # .data-table th is CSS text-transform: uppercase, which changes
        # innerText's rendered case but not the underlying header text -
        # compare case-insensitively, the same approach PAT-2140's own
        # KPI label test uses for the same reason.
        headers = [h.casefold() for h in page.locator("#alerts-table thead th").all_inner_texts()]
        assert "raised" in headers
        assert "acknowledged" not in headers
        assert "resolved" not in headers
    finally:
        context.close()


# ── No raw product_key/device_id text or placeholder anywhere ───────────

def test_no_product_key_or_device_id_text_or_placeholder(browser, harness_url):
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        for status in ("open", "acknowledged", "resolved", "all"):
            page.goto(f"/software/alerts?status={status}", wait_until="networkidle")
            body = page.content()
            assert "Product key" not in body
            assert "Device ID" not in body
            placeholders = page.eval_on_selector_all(
                "input", "els => els.map(el => el.getAttribute('placeholder'))")
            for placeholder in placeholders:
                if placeholder:
                    assert "Product key" not in placeholder
                    assert "Device ID" not in placeholder
    finally:
        context.close()


# ── Note + Acknowledge button share one row ──────────────────────────────

def test_note_and_acknowledge_button_share_one_row(browser, harness_url):
    STUB_STATE["portal_role"] = "admin"
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.goto("/software/alerts?status=open", wait_until="networkidle")
        row = page.locator("tr", has_text="Tor Browser")
        note = row.get_by_placeholder("Note (optional)")
        button = row.get_by_role("button", name="Acknowledge")
        note_box = note.bounding_box()
        button_box = button.bounding_box()
        assert note_box is not None and button_box is not None
        assert abs(note_box["y"] - button_box["y"]) <= 4, (note_box, button_box)
    finally:
        context.close()


# ── 390px: no overflow, table-stack takes over ───────────────────────────

def test_no_overflow_at_390(browser, harness_url):
    STUB_STATE["portal_role"] = "admin"
    context = _context(browser, harness_url)
    page = context.new_page()
    try:
        page.set_viewport_size({"width": 390, "height": 900})
        for status in ("open", "acknowledged", "resolved", "all"):
            page.goto(f"/software/alerts?status={status}", wait_until="networkidle")
            _assert_no_overflow(page)
    finally:
        context.close()
