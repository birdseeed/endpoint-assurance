"""PAT-2255 in a real browser: /software as the review workspace.

tests/test_pat2255_software_review.py covers parsing, counts, filters and
the redirect contract against the stub; this file is the ticket's Done-when
checks that only a browser can make:

  1. approving a row from a filtered view keeps the customer on that same
     filtered view, the row drops out (the filter excludes it now) and the
     next row is in view - with JavaScript (in-place swap) and without it
     (server redirect to the filtered URL with the next row as the anchor);
  2. bulk actions work on the checkbox selection from a filtered view;
  3. at least 15 rows are visible at 1280x800, in light and in dark;
  4. at 390px the table stacks into labelled blocks with no sideways
     scroll;
  5. the "N new since your last review" banner opens the review queue,
     which states how many products it holds;
  6. a URL filter (search) is on the page at first paint and typing keeps
     the URL in step.

Red-proof: run against the PAT-2254 commit (5cae282) every test here fails
except the bulk one, which guards behaviour that already worked - there was
no return_anchor, no review-queue link, no row ids, no search box value
from the URL, rows were up to 155px tall (5 fully in view at 1280x800) and
the table scrolled sideways inside its card at 390px instead of stacking.
"""

import copy
from urllib.parse import parse_qs, urlsplit

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import APPLICATIONS, NEW_SOFTWARE_REPORT, STUB_STATE


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _visible_rows(page):
    return page.evaluate("""() => Array.from(document.querySelectorAll('tr[data-approval-row]'))
        .filter(r => r.offsetParent !== null)
        .map(r => ({id: r.id,
                    name: (r.querySelector('.product-name') || r).textContent.trim()}))""")


def _in_viewport(page, row_id):
    return page.evaluate("""(id) => {
        const el = document.getElementById(id);
        if (!el || el.offsetParent === null) return false;
        const r = el.getBoundingClientRect();
        const bar = document.querySelector('.topbar');
        const top = bar ? bar.getBoundingClientRect().bottom : 0;
        return r.top >= top - 1 && r.bottom <= innerHeight + 1;
    }""", row_id)


def _next_after(rows, name):
    names = [r["name"] for r in rows]
    i = names.index(name)
    return rows[i + 1] if i + 1 < len(rows) else rows[i - 1]


# ── 1. Approve from a filtered view keeps the customer in place ───────────

def test_approve_from_a_filtered_view_stays_in_place_with_js(browser, harness_url):
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800})
    try:
        page = context.new_page()
        page.goto("/software?approval=waiting&type=application", wait_until="networkidle")
        before = _visible_rows(page)
        target = _next_after(before, "MysteryApp")
        row = page.locator("tr[data-approval-row]", has_text="MysteryApp")
        row.locator("select[data-approval-row-state]").select_option("approved")
        row.locator("[data-approval-row-apply]").click()
        page.wait_for_selector("[data-approval-result]")

        parts = urlsplit(page.url)
        query = parse_qs(parts.query)
        assert parts.path == "/software"
        assert query.get("approval") == ["waiting"] and query.get("type") == ["application"]
        assert "approval_result" not in query
        after = [r["name"] for r in _visible_rows(page)]
        assert "MysteryApp" not in after, "the approved row is still in the Unreviewed view"
        assert target["name"] in after
        assert _in_viewport(page, target["id"]), "the next row is not in view"
        # The filter bar still shows the filter the customer was on.
        assert page.locator(".filter-chips", has_text="Unreviewed").is_visible()
    finally:
        context.close()


def test_approve_without_js_lands_on_the_next_row(browser, harness_url):
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800},
                       java_script_enabled=False)
    try:
        page = context.new_page()
        page.goto("/software?approval=waiting", wait_until="networkidle")
        row = page.locator("tr[data-approval-row]", has_text="MysteryApp")
        anchor = row.locator("input[name='return_anchor']").get_attribute("value")
        assert anchor and anchor.startswith("sw-")
        row.locator("select[data-approval-row-state]").select_option("approved")
        with page.expect_navigation():
            row.locator("[data-approval-row-apply]").click()
        parts = urlsplit(page.url)
        assert parts.path == "/software"
        assert parse_qs(parts.query).get("approval") == ["waiting"]
        assert parts.fragment == anchor
        assert page.locator("tr[data-approval-row]", has_text="MysteryApp").is_hidden()
        assert _in_viewport(page, anchor), "the anchored next row is not in view"
    finally:
        context.close()


# ── 2. Bulk actions on the checkbox selection ─────────────────────────────

def test_bulk_approve_on_the_selection_from_a_filtered_view(browser, harness_url):
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800})
    try:
        page = context.new_page()
        page.goto("/software?approval=waiting", wait_until="networkidle")
        for name in ("MysteryApp", "MysteryHelper"):
            page.locator("tr[data-approval-row]", has_text=name).locator(
                "input.approval-select").check()
        assert page.locator("[data-bulk-count]").inner_text() == "2 products selected"
        page.locator("#approval-form [data-bulk-submit][value='approved']").click()
        page.wait_for_selector("[data-approval-result]")
        assert "2 products" in page.locator("[data-approval-result]").inner_text()
        assert parse_qs(urlsplit(page.url).query).get("approval") == ["waiting"]
        after = [r["name"] for r in _visible_rows(page)]
        assert "MysteryApp" not in after and "MysteryHelper" not in after
        puts = STUB_STATE["approval_puts"]
        assert len(puts) == 1 and len(puts[0]["body"]["items"]) == 2
    finally:
        context.close()


# ── 3. Density: at least 15 rows per screen at 1280x800 ───────────────────

ROWS_PER_SCREEN_JS = """() => {
  const table = document.querySelector('.software-table');
  const bar = document.querySelector('.topbar').getBoundingClientRect().bottom;
  const head = table.tHead.getBoundingClientRect().height;
  const rows = Array.from(table.tBodies[0].rows).filter(r => r.offsetParent !== null);
  const inView = rows.filter(r => {
    const b = r.getBoundingClientRect();
    return b.top >= bar - 1 && b.bottom <= innerHeight + 1;
  });
  return {inView: inView.length, total: rows.length,
          tallest: Math.max(...rows.map(r => r.getBoundingClientRect().height)),
          theme: document.documentElement.getAttribute('data-theme')};
}"""


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_at_least_15_rows_fit_a_1280x800_screen(browser, harness_url, theme):
    """The ticket measured about 9 rows per screen. Rows are now one line;
    with the table header scrolled to just under the sticky top bar (a
    customer working down the list), at least 15 rows are fully in view."""
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800},
                       color_scheme=theme)
    try:
        page = context.new_page()
        page.goto("/software", wait_until="networkidle")
        page.evaluate("""() => {
            const bar = document.querySelector('.topbar').getBoundingClientRect().height;
            const head = document.querySelector('.software-table thead');
            window.scrollTo(0, head.getBoundingClientRect().top + window.scrollY - bar);
        }""")
        result = page.evaluate(ROWS_PER_SCREEN_JS)
        assert result["theme"] == theme
        assert result["total"] >= 15, "the stub estate is too small to measure density"
        assert result["inView"] >= 15, result
        assert result["tallest"] <= 46, result
    finally:
        context.close()


# ── 4. Phone: the table stacks cleanly ────────────────────────────────────

def test_phone_width_stacks_rows_without_sideways_scroll(browser, harness_url):
    context = _context(browser, harness_url, viewport={"width": 390, "height": 844})
    try:
        page = context.new_page()
        page.goto("/software", wait_until="networkidle")
        result = page.evaluate("""() => {
            const scroller = document.querySelector('.software-table-card .table-scroll');
            const row = document.querySelector('.software-table tbody tr');
            const cells = Array.from(row.cells).filter(c => c.offsetParent !== null);
            const card = scroller.getBoundingClientRect();
            return {
              doc: document.documentElement.scrollWidth, win: innerWidth,
              scroll: scroller.scrollWidth, box: scroller.clientWidth,
              rowDisplay: getComputedStyle(row).display,
              outside: cells.filter(c => {
                const r = c.getBoundingClientRect();
                return r.left < card.left - 1 || r.right > card.right + 1;
              }).length,
            };
        }""")
        assert result["doc"] <= result["win"], result
        assert result["scroll"] <= result["box"] + 1, result
        assert result["rowDisplay"] == "block", result
        assert result["outside"] == 0, result
    finally:
        context.close()


# ── 5. The banner opens the review queue ──────────────────────────────────

def test_new_since_review_banner_opens_the_review_queue(browser, harness_url):
    apps = copy.deepcopy(APPLICATIONS)
    apps["applications"].append({
        **apps["applications"][3], "name": "New Tool", "identifier": "vendor.newtool",
        "platform": "windows",
    })
    STUB_STATE["applications_data"] = apps
    saved = STUB_STATE.get("new_software_data")
    STUB_STATE["new_software_data"] = NEW_SOFTWARE_REPORT
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800})
    try:
        page = context.new_page()
        page.goto("/software", wait_until="networkidle")
        banner = page.locator(".review-queue-banner")
        assert "2 new since your last review" in banner.inner_text()
        banner.locator("[data-review-queue-link]").click()
        page.wait_for_load_state("networkidle")
        query = parse_qs(urlsplit(page.url).query)
        assert query.get("new_since") == [NEW_SOFTWARE_REPORT["since"]]
        assert query.get("approval") == ["waiting"]
        assert "Reviewing 2 new products" in page.locator("#review-queue").inner_text()
        assert [r["name"] for r in _visible_rows(page)] == ["New Tool"]
        assert page.locator(".filter-chips", has_text="New since your last review").is_visible()
    finally:
        STUB_STATE["new_software_data"] = saved
        context.close()


# ── 6. A URL filter is there at first paint and the URL follows edits ─────

def test_search_param_is_applied_on_load_and_kept_in_the_url(browser, harness_url):
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800})
    try:
        page = context.new_page()
        page.goto("/software?search=Mystery", wait_until="networkidle")
        box = page.locator("#software-search")
        assert box.input_value() == "Mystery"
        assert sorted(r["name"] for r in _visible_rows(page)) == ["MysteryApp", "MysteryHelper"]
        box.fill("Slack")
        assert [r["name"] for r in _visible_rows(page)] == ["Slack"]
        assert parse_qs(urlsplit(page.url).query).get("search") == ["Slack"]
    finally:
        context.close()
