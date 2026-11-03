"""Guards PAT-2092 - a layout-quality pass across the whole portal,
prompted by four live screenshots at the owner's normal (desktop) window
size:

1. `test_kpi_tiles_share_one_row_on_every_page` - the overview's three
   control-coverage counter cards, plus every other kpi_summary() card
   on /devices, /software and /exceptions, rendered as one narrow column
   of stacked label/value pairs instead of a row of tiles. Root cause: a
   code comment above `.kpi { display: flex; ... }` in portal.css read
   "pill-*/card families", whose literal asterisk-slash closed that CSS
   comment block early (PAT-1642, pre-existing - not a PAT-2070
   regression), silently dropping the .kpi rule and leaving every .kpi
   element at its default block display. Fixed at the shared .kpi rule,
   so this test covers every page that calls kpi_summary(), not just the
   overview.

2. `test_no_pill_or_cve_id_wraps_mid_word` - PAT-2070 added a
   `white-space: normal` override to several tables' `.pill` rule so a
   pill could shrink into a narrow reveal-tiered column, which combined
   with the blanket `.data-table td { overflow-wrap: anywhere }` broke
   pill and CVE-id text apart mid-word ("CRITI/CAL", "CVE-2026-/0001").
   Roster pills may wrap at spaces within their compact line budget;
   other pills and CVE ids must stay on one line.

3. `test_no_table_header_cells_overlap` - findings-table's "Devices
   affected" and "Verification" headers collided because
   .findings-table th (unlike control-coverage-table th and device-table
   th) had no wrap override, so a nowrap two-word header spilled onto the
   neighbouring column instead of wrapping. Fixed by moving the wrap
   behaviour onto the shared .data-table th rule.

4. `test_tables_fill_their_card` - findings-table and exception-table's
   row content stopped short of their card even though the <table>
   element's own box correctly filled it: a table with any hidden
   .col-secondary/.col-tertiary column does not redistribute width: 100%'s
   spare space to any visible column in this Chromium build, it becomes
   dead space after the last visible cell. The guard measures the last
   visible cell's right edge, not the <table> box, which is what let this
   through the first time. Fixed with per-reveal-tier explicit widths on
   each table's one flexible column, computed from the measured container
   width at each tested viewport.

5. `test_lifecycle_history_is_collapsed_by_default` - the Verification
   column's lifecycle history is a native <details> the template never
   marks open and no script touches; this guards that it never renders
   open on first load, however many lifecycle events a finding has.

Reuses e2e/test_table_overflow.py's typical_data_stub/long_data_stub
fixtures rather than inventing a third copy of the same override
machinery.
"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.test_table_overflow import long_data_stub, typical_data_stub  # noqa: F401

# Every page that renders at least one kpi_summary() card (templates/
# _macros.html) - grep `kpi_summary(` across templates/*.html to keep this
# list honest if a future page adds or removes one. PAT-2120 removed
# /software's two kpi_summary() calls (estate coverage, and the
# waiting/not-wanted/approved counts, now the decision-state segmented
# control's tab labels instead) as part of merging its two tables into one.
KPI_PAGES = ["/", "/devices", "/exceptions"]

TILE_ROW_JS = """
() => {
  const out = [];
  document.querySelectorAll('.kpi').forEach((kpi) => {
    const items = Array.from(kpi.querySelectorAll(':scope > .kpi__item'));
    if (items.length < 2) return;
    const tops = items.map((el) => el.getBoundingClientRect().top);
    out.push({count: items.length, minTop: Math.min(...tops), maxTop: Math.max(...tops)});
  });
  return out;
}
"""

NOWRAP_HEIGHTS_JS = r"""
() => {
  const out = {pill: [], cveId: []};
  document.querySelectorAll('.pill').forEach((el) => {
    const r = el.getBoundingClientRect();
    let splitWord = false;
    const node = el.firstChild;
    if (node && node.nodeType === Node.TEXT_NODE) {
      for (const word of node.textContent.matchAll(/\S+/g)) {
        const range = document.createRange();
        range.setStart(node, word.index); range.setEnd(node, word.index + word[0].length);
        const tops = new Set(Array.from(range.getClientRects()).map(x => Math.round(x.top)));
        if (tops.size > 1) splitWord = true;
      }
    }
    if (r.width > 0) {
      const tops = new Set();
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        if (!node.textContent.trim()) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        for (const rect of range.getClientRects()) {
          if (rect.width > 0) tops.add(Math.round(rect.top));
        }
      }
      out.pill.push({text: el.textContent.trim(), height: r.height, lines: tops.size,
                     roster: !!el.closest('.device-table'), splitWord});
    }
  });
  document.querySelectorAll('a.cve-id').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width > 0) out.cveId.push({text: el.textContent.trim(), height: r.height});
  });
  return out;
}
"""

HEADER_OVERLAP_JS = """
() => {
  const overlaps = [];
  document.querySelectorAll('table').forEach((table) => {
    const ths = Array.from(table.querySelectorAll('thead th')).map((th) => ({
      text: th.textContent.trim(), r: th.getBoundingClientRect(),
      scrollWidth: th.scrollWidth, clientWidth: th.clientWidth,
    })).filter((x) => x.r.width > 0 && x.r.height > 0);
    // Two distinct ways one header collides with its neighbour: its own
    // box genuinely overlaps another th's box (a wrapped multi-line
    // header pushed too tall and drifted sideways), or - the shape the
    // owner actually hit - a nowrap header's text is wider than its own
    // th box and visually spills onto the next column while the boxes
    // themselves stay politely non-overlapping (scrollWidth > clientWidth
    // catches this even though getBoundingClientRect cannot).
    ths.forEach((th) => {
      if (th.scrollWidth > th.clientWidth + 1) {
        overlaps.push(
          th.text + ' overflows its own header cell (' + th.scrollWidth +
          'px of text in a ' + th.clientWidth + 'px cell) in ' + table.className
        );
      }
    });
    for (let i = 0; i < ths.length; i++) {
      for (let j = i + 1; j < ths.length; j++) {
        const a = ths[i].r, b = ths[j].r;
        const overlapsX = a.left < b.right - 1 && b.left < a.right - 1;
        const overlapsY = a.top < b.bottom - 1 && b.top < a.bottom - 1;
        if (overlapsX && overlapsY) {
          overlaps.push(ths[i].text + ' x ' + ths[j].text + ' in ' + table.className);
        }
      }
    }
  });
  return overlaps;
}
"""

LIFECYCLE_OPEN_JS = """
() => Array.from(document.querySelectorAll('.lifecycle__history')).map((d) => d.open)
"""


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
        "url": harness_url,
    }])
    context.route(
        "https://fonts.googleapis.com/**",
        lambda route: route.fulfill(status=200, content_type="text/css", body=""),
    )
    context.route(
        "https://fonts.gstatic.com/**",
        lambda route: route.fulfill(status=200, content_type="text/css", body=""),
    )
    return context


@pytest.mark.parametrize("width", [1280, 1440])
def test_kpi_tiles_share_one_row_on_every_page(browser, harness_url, typical_data_stub, width):  # noqa: F811
    """At 1280 and 1440, every kpi_summary() card's tiles sit within a few
    px of the same top offset - one row, not a stacked column. Red on the
    pre-fix CSS (each .kpi__item's top increased by a whole tile height
    per item); green once the shared .kpi rule's flex layout applies."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    failures = []
    for path in KPI_PAGES:
        page.goto(path, wait_until="networkidle")
        for row in page.evaluate(TILE_ROW_JS):
            spread = row["maxTop"] - row["minTop"]
            if spread > 5:
                failures.append(
                    f"{path} at {width}px: a {row['count']}-tile .kpi row spans "
                    f"{spread:.1f}px of vertical offset (tiles are stacked, not a row)"
                )
    context.close()
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("width", [1280, 1440])
def test_no_pill_or_cve_id_wraps_mid_word(browser, harness_url, long_data_stub, width):  # noqa: F811
    """Roster pills may wrap at spaces; no word may split. Other pills and
    CVE identifiers retain their one-line contract across every page."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions", "/homebrew"]:
        page.goto(path, wait_until="networkidle")
        heights = page.evaluate(NOWRAP_HEIGHTS_JS)
        for kind in ("pill", "cveId"):
            rows = heights[kind]
            if not rows:
                continue
            min_h = min(r["height"] for r in rows)
            for r in rows:
                if path == "/software" and kind == "pill":
                    # Software's protected, assessment and approval pills have
                    # different padding/line-height. Compare actual text lines,
                    # not the box height of a different pill family.
                    if r["lines"] > 1:
                        failures.append(
                            f"{path} at {width}px: pill {r['text']!r} "
                            f"wraps across {r['lines']} text lines"
                        )
                elif r.get("splitWord") or (not r.get("roster") and r["height"] > min_h + 4):
                    failures.append(
                        f"{path} at {width}px: {kind} {r['text']!r} is {r['height']:.1f}px "
                        f"tall (single-line reference is {min_h:.1f}px) - looks wrapped"
                    )
    context.close()
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("width", [1280, 1440])
def test_no_table_header_cells_overlap(browser, harness_url, long_data_stub, width):  # noqa: F811
    """No two <th> cells in any table, on any page, occupy overlapping
    screen space. Red on findings-table before the shared .data-table th
    wrap fix ("Devices affected" spilling onto "Verification")."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions", "/homebrew"]:
        page.goto(path, wait_until="networkidle")
        overlaps = page.evaluate(HEADER_OVERLAP_JS)
        failures.extend(f"{path} at {width}px: {o}" for o in overlaps)
    context.close()
    assert not failures, "\n".join(failures)


ALL_TABLES_FILL_JS = """
() => {
  const out = [];
  const sel = '.card-table .table-scroll, .group-card .table-scroll';
  document.querySelectorAll(sel).forEach((cont) => {
    const table = cont.querySelector('table');
    if (!table) return;
    const containerWidth = cont.getBoundingClientRect().width;
    if (containerWidth === 0) return;
    // PAT-2092, third round: table.getBoundingClientRect().width alone is
    // the wrong measurement - table-layout: fixed can stretch the TABLE's
    // own box to fill width: 100% while leaving the space past the last
    // VISIBLE cell as unusable dead space (confirmed: a table with any
    // hidden .col-secondary/.col-tertiary column does not actually
    // redistribute that space to any column). The real question is
    // whether the rendered ROW content reaches the container's edge, so
    // this measures the last visible cell in the first body row instead.
    const firstRow = table.querySelector('tbody tr');
    if (!firstRow) return;
    const visibleCells = Array.from(firstRow.querySelectorAll('td, th'))
      .filter((c) => getComputedStyle(c).display !== 'none');
    if (!visibleCells.length) return;
    const lastCell = visibleCells[visibleCells.length - 1];
    const contentRight = lastCell.getBoundingClientRect().right;
    const filledWidth = contentRight - cont.getBoundingClientRect().left;
    out.push({cls: table.className, filledWidth, containerWidth});
  });
  return out;
}
"""

WORD_BREAK_JS = """
() => {
  const failures = [];
  const exempt = (cell) =>
    cell.closest('.cell-anywrap') || cell.querySelector('.cell-anywrap') ||
    cell.closest('.row-summary');
  document.querySelectorAll('table').forEach((table) => {
    table.querySelectorAll('th, td').forEach((cell) => {
      if (exempt(cell)) return;
      if (getComputedStyle(cell).display === 'none') return;
      const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const text = node.textContent;
        // Alphanumeric runs only: a hyphen, "@" or "." is a real CSS/UAX14
        // soft-wrap opportunity (compound hostnames, emails), not a word
        // fragmenting mid-letter - splitting on them here keeps this test
        // from flagging a legitimate break at "acme-win-/accounts" as the
        // same defect as "ArchiveTo/ol", which has no such opportunity.
        const re = /[A-Za-z0-9]+/g;
        let m;
        while ((m = re.exec(text))) {
          const word = m[0];
          if (word.length < 3) continue;
          const range = document.createRange();
          range.setStart(node, m.index);
          range.setEnd(node, m.index + word.length);
          // text-overflow: ellipsis elements (truncated identifiers,
          // truncated pills) return a spurious duplicate rect at the same
          // x/y for a Range - not an actual second line - so distinct
          // rects are counted by rounded position, not raw rect count.
          const seen = new Set();
          Array.from(range.getClientRects()).forEach((r) => {
            seen.add(Math.round(r.top) + ':' + Math.round(r.left));
          });
          if (seen.size > 1) {
            failures.push(
              cell.tagName + ' ' + JSON.stringify(word) + ' in ' +
              JSON.stringify(cell.textContent.trim().slice(0, 50)) +
              ' (' + table.className + ')'
            );
          }
        }
      }
    });
  });
  return failures;
}
"""

CELL_OVERFLOW_JS = """
() => {
  const failures = [];
  const exempt = (td) =>
    td.closest('.cell-anywrap') || td.querySelector('.cell-anywrap') ||
    td.closest('.row-summary');
  document.querySelectorAll('table td').forEach((td) => {
    if (exempt(td)) return;
    if (getComputedStyle(td).display === 'none') return;
    if (td.scrollWidth > td.clientWidth + 1) {
      failures.push(
        td.textContent.trim().slice(0, 40) + ' overflows its own cell (' +
        td.scrollWidth + 'px of content in a ' + td.clientWidth + 'px cell), ' +
        'risking touching the next column'
      );
    }
  });
  return failures;
}
"""


@pytest.mark.parametrize("width", [1280, 1440, 1920])
def test_tables_fill_their_card(browser, harness_url, typical_data_stub, width):  # noqa: F811
    """Every table on every page has its last VISIBLE cell reach at least
    98% of its .table-scroll container's width at 1280, 1440 and 1920 -
    the general form of the findings-table-specific check above, covering
    the device, software, inventory and exception tables the coordinator
    asked to check too. Measures the last visible cell's right edge, not
    the <table> element's own box - table-layout: fixed can stretch the
    table's own box to fill width: 100% while the row content itself
    stops well short of the card, once any column is hidden (see
    findings-table's own portal.css comment for the confirmed mechanism);
    measuring the table element alone missed this every time."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions"]:
        page.goto(path, wait_until="networkidle")
        for row in page.evaluate(ALL_TABLES_FILL_JS):
            ratio = row["filledWidth"] / row["containerWidth"] if row["containerWidth"] else 0
            if ratio < 0.98:
                failures.append(
                    f"{path} at {width}px: {row['cls']!r} row content reaches "
                    f"{row['filledWidth']:.0f}px of a {row['containerWidth']:.0f}px "
                    f"container ({ratio:.0%})"
                )
    context.close()
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("width", [1280, 1440])
def test_no_word_breaks_mid_word_anywhere(browser, harness_url, long_data_stub, width):  # noqa: F811
    """No word in any table header or cell breaks across a line - checked
    with a DOM Range per word (if a word's Range produces more than one
    client rect, part of it rendered on a different line, i.e. it broke
    mid-word). Cells inside .cell-anywrap or .row-summary are exempt -
    they may hold a genuinely unbroken identifier (a path, a SID, a
    bundle id) that has nowhere else to break. Red on the pre-fix CSS
    ("CVS/S", "APPLICATI/ON", "ArchiveTo/ol", "unknow/n", "device/s")."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions", "/homebrew"]:
        page.goto(path, wait_until="networkidle")
        for f in page.evaluate(WORD_BREAK_JS):
            failures.append(f"{path} at {width}px: {f}")
    context.close()
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("width", [1280, 1440])
def test_adjacent_table_cells_never_touch(browser, harness_url, long_data_stub, width):  # noqa: F811
    """No table cell's content is wider than the cell itself - the shape
    of the "Application0"/"Application4" bug, where a Type cell's nowrap
    icon-plus-word content overflowed into the Installs column with no
    visible gap between them, even though the two <td> boxes themselves
    were correctly adjacent by the table's own column layout."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions", "/homebrew"]:
        page.goto(path, wait_until="networkidle")
        for f in page.evaluate(CELL_OVERFLOW_JS):
            failures.append(f"{path} at {width}px: {f}")
    context.close()
    assert not failures, "\n".join(failures)


def test_lifecycle_history_is_collapsed_by_default(browser, harness_url, long_data_stub):  # noqa: F811
    """Every finding's lifecycle-history <details> is closed on first
    load, regardless of how many lifecycle events it holds - the
    Verification column shows only the status pill and a toggle until a
    person opens it."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1440, "height": 1400})
    page.goto("/findings", wait_until="networkidle")
    open_states = page.evaluate(LIFECYCLE_OPEN_JS)
    context.close()
    assert open_states, "expected at least one .lifecycle__history on /findings"
    assert not any(open_states), f"a lifecycle history rendered open by default: {open_states}"


ROW_CELL_COUNT_JS = """
() => {
  const failures = [];
  // Visible only - counting DOM cells regardless of display: none would
  // never catch the real defect (a hidden .col-secondary <td> with no
  // matching class on its <th>, or vice versa): the DOM cell count stays
  // right either way, only what a viewer actually sees shifts out of
  // alignment.
  const visible = (el) => getComputedStyle(el).display !== 'none';
  document.querySelectorAll('table').forEach((table) => {
    const headerRow = table.querySelector('thead tr');
    if (!headerRow) return;
    let headerCount = 0;
    Array.from(headerRow.querySelectorAll('th')).filter(visible).forEach((th) => {
      headerCount += parseInt(th.getAttribute('colspan') || '1', 10);
    });
    table.querySelectorAll('tbody tr').forEach((tr) => {
      // A full-width summary/description row (colspan spanning the whole
      // table on its own, e.g. .row-summary) is a deliberate exception,
      // not a mismatched row - it never claims to carry one cell per
      // column.
      const cells = Array.from(tr.querySelectorAll('td, th')).filter(visible);
      if (cells.length === 1) {
        const only = parseInt(cells[0].getAttribute('colspan') || '1', 10);
        if (only >= headerCount) return;
      }
      let bodyCount = 0;
      cells.forEach((c) => {
        bodyCount += parseInt(c.getAttribute('colspan') || '1', 10);
      });
      if (bodyCount !== headerCount) {
        failures.push(
          table.className + ': header has ' + headerCount + ' visible column(s), a row has ' +
          bodyCount + ' (' + tr.textContent.trim().slice(0, 50) + ')'
        );
      }
    });
  });
  return failures;
}
"""


def test_every_row_has_one_cell_per_header_column(browser, harness_url, long_data_stub):  # noqa: F811
    """For every data table on every page, each body row's cell count
    (colspan counted) equals the header's - a full-width summary row
    (one cell whose own colspan already spans the table) is the one
    deliberate exception. Red on the pre-fix "State not recognised"
    table on /software: its Type <th> had no .col-secondary class while
    the matching <td> did, so at any width below 1440px the header kept
    7 visible columns while the body row rendered only 6, shifting every
    later cell one column left (OddPolicy's "1 device" installs count
    displaying under the Type header, "Identifier match" under Installs,
    and so on)."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1280, "height": 1400})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions", "/homebrew"]:
        page.goto(path, wait_until="networkidle")
        for f in page.evaluate(ROW_CELL_COUNT_JS):
            failures.append(f"{path}: {f}")
    context.close()
    assert not failures, "\n".join(failures)


CARD_GAP_JS = """
() => {
  const failures = [];
  const sel = '.page > .card, .page > section.card, .page > .grid';
  const cards = Array.from(document.querySelectorAll(sel));
  for (let i = 1; i < cards.length; i++) {
    const prevBottom = cards[i - 1].getBoundingClientRect().bottom;
    const top = cards[i].getBoundingClientRect().top;
    const gap = top - prevBottom;
    if (gap < 12) {
      failures.push({
        prev: cards[i - 1].querySelector('h2')?.textContent.trim() || cards[i - 1].className,
        next: cards[i].querySelector('h2')?.textContent.trim() || cards[i].className,
        gap,
      });
    }
  }
  return failures;
}
"""


def test_sibling_cards_have_a_vertical_gap(browser, harness_url, typical_data_stub):  # noqa: F811
    """Top-level cards down a page - including a .grid's last row against
    whatever follows it - keep at least 12px of vertical gap between
    them. Red on the overview: .grid .card zeroes each stat card's own
    margin-bottom (the grid's own gap handles spacing within the grid),
    but nothing restored spacing after the grid itself, so its bottom
    row sat flush against control_coverage_card()'s top border with no
    gap at all."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": 1440, "height": 2000})
    failures = []
    for path in ["/", "/devices", "/findings", "/software", "/exceptions"]:
        page.goto(path, wait_until="networkidle")
        for f in page.evaluate(CARD_GAP_JS):
            failures.append(
                f"{path}: {f['prev']!r} to {f['next']!r} is only {f['gap']:.1f}px apart"
            )
    context.close()
    assert not failures, "\n".join(failures)


CONFIDENCE_HEADER_VISIBLE_JS = """
() => {
  const th = Array.from(document.querySelectorAll('.findings-table thead th'))
    .find((t) => t.textContent.trim() === 'Confidence');
  if (!th) return 'missing';
  return getComputedStyle(th).display === 'none' ? 'hidden' : 'visible';
}
"""


@pytest.mark.parametrize("width", [1280, 1440, 1920])
def test_confidence_header_always_visible(browser, harness_url, typical_data_stub, width):  # noqa: F811
    """Confidence is the evidence qualifier on a CVE claim (root AGENTS.md:
    CVE claims require evidence), so unlike CVSS it must never be demoted
    to .col-secondary - checked at 1280, 1440 and 1920. Only CVSS may stay
    hidden below 1440px."""
    context = _context(browser, harness_url)
    page = context.new_page()
    page.set_viewport_size({"width": width, "height": 1400})
    page.goto("/findings", wait_until="networkidle")
    state = page.evaluate(CONFIDENCE_HEADER_VISIBLE_JS)
    context.close()
    assert state == "visible", f"Confidence header is {state} at {width}px"


def test_software_pill_line_guard_detects_wrapping(browser, harness_url):
    """Prove the direct line measurement fails on the original wrap shape."""
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 800})
        page.goto("/software", wait_until="networkidle")
        assert all(row["lines"] <= 1 for row in page.evaluate(NOWRAP_HEIGHTS_JS)["pill"])
        page.add_style_tag(content=".software-table .cell-cve .pill { "
                            "white-space: normal; width: 35px; overflow-wrap: anywhere; }")
        assert any(row["lines"] > 1 for row in page.evaluate(NOWRAP_HEIGHTS_JS)["pill"])
    finally:
        context.close()
