"""Guards PAT-2137 - the Homebrew pages at phone width (390px).

`/homebrew`'s Devices table (`.homebrew-devices-table`) sets
`table-layout: fixed` and `min-width: 760px` (portal.css) with six fixed
pixel columns (Owner, Formulae, Casks, Taps, Collection, the blank Actions
column). At 390px those fixed columns alone already exceed the card's
available width, so the two remaining columns (Mac, Prefix - both also
`.cell-anywrap`, `overflow-wrap: anywhere`, needed for genuinely long
hostnames/paths at desktop width) compute to a near-zero share and their
text renders broken mid-word: "mac-01" as "mac" / "-01", "/opt/homebrew"
as "opt" / "homebrew" - the exact shape PAT-2136 already fixed once on the
device detail page's Compliance signals table with the reusable
`.table-stack` pattern. This ticket reuses that pattern here instead of
inventing a second one.

Per the ticket's own instruction ("check the other tables on /homebrew ...
and its device drill-down ... at 390px; fix any with the same mid-word
problem the same way"), this test checks every table on both pages, not
just the one named in the bug report - see TABLE_SELECTORS. Investigation
(this ticket) found only `.homebrew-devices-table` exhibits the defect:
the Casks, Formulae and Taps tables on `/homebrew`, and the entries table
on `/homebrew/devices/{id}`, have no `table-layout: fixed`/forced
`min-width` and no `.cell-anywrap` cell, so the browser's own auto table
layout already wraps their (shorter, space-containing) values at ordinary
word boundaries with no fixed-pixel column starving another column to
~0px - only the Devices table got the `table-stack`/`data-label`
treatment.

Red-proof: every assertion here fails on current main (the pre-fix Devices
table renders near-0px-wide Mac/Prefix columns whose text breaks mid-word)
and passes once portal.css's `.table-stack` rule (min-width reset added)
and templates/homebrew.html's `table-stack` class/`data-label` attributes
land.
"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN

WORD_BREAK_JS = """
(selectors) => {
  const failures = [];
  document.querySelectorAll(selectors.join(',')).forEach((table) => {
    table.querySelectorAll('th, td').forEach((cell) => {
      if (getComputedStyle(cell).display === 'none') return;
      const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const text = node.textContent;
        // Alphanumeric runs only - hyphens/dots are legitimate break
        // points a real hostname or path already relies on (see
        // e2e/test_pat2092_layout.py's WORD_BREAK_JS for the same call).
        const re = /[A-Za-z0-9]+/g;
        let m;
        while ((m = re.exec(text))) {
          const word = m[0];
          if (word.length < 3) continue;
          const range = document.createRange();
          range.setStart(node, m.index);
          range.setEnd(node, m.index + word.length);
          const seen = new Set();
          Array.from(range.getClientRects()).forEach((r) => {
            seen.add(Math.round(r.top) + ':' + Math.round(r.left));
          });
          if (seen.size > 1) {
            failures.push(
              cell.tagName + ' ' + JSON.stringify(word) + ' in ' +
              JSON.stringify(cell.textContent.trim().slice(0, 60))
            );
          }
        }
      }
    });
  });
  return failures;
}
"""

# A cell whose own box renders narrower than a single average character at
# this app's table font-size (14px, portal.css .data-table) but still holds
# real text content is the "one character per line" shape directly.
ONE_CHAR_PER_LINE_JS = """
(selectors) => {
  const failures = [];
  document.querySelectorAll(selectors.join(',')).forEach((table) => {
    table.querySelectorAll('td').forEach((cell) => {
      if (getComputedStyle(cell).display === 'none') return;
      const text = cell.textContent.trim();
      if (!text) return;
      const r = cell.getBoundingClientRect();
      if (r.width > 0 && r.width < 14) {
        failures.push(cell.tagName + ' is ' + r.width.toFixed(1) + 'px wide: ' +
          JSON.stringify(text.slice(0, 30)));
      }
    });
  });
  return failures;
}
"""

# Nothing belonging to a `table-stack` table may escape the card that holds
# it - stacking is the point, so once a table opts in it must never need its
# own horizontal scroll again. A table that has NOT opted into table-stack
# is allowed its own `.table-scroll` horizontal scroll (PAT-2136's
# "acceptable" fallback for a table that does not need the stacked
# treatment) - checked against the table's own box instead, so nothing
# escapes the scrollable region itself via a stray absolute position or
# negative margin.
OVERFLOW_JS = """
(selectors) => {
  const failures = [];
  document.querySelectorAll(selectors.join(',')).forEach((table) => {
    const stacked = table.classList.contains('table-stack');
    const box = stacked ? table.closest('.card') : table;
    if (!box) return;
    const br = box.getBoundingClientRect();
    table.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (r.right > br.right + 1 || r.left < br.left - 1) {
        failures.push(table.className + ': ' + el.tagName + ' ' +
          JSON.stringify((el.textContent || '').trim().slice(0, 40)) +
          ' right=' + r.right.toFixed(1) + ' boxRight=' + br.right.toFixed(1));
      }
    });
  });
  return failures;
}
"""

# Every table on both pages, including the unclassed Taps table - see
# module docstring for why the check runs against all of them rather than
# only the one named in the bug report.
HOMEBREW_TABLE_SELECTORS = ['.card.group-card table']
HOMEBREW_DEVICE_TABLE_SELECTORS = ['.card.group-card table']


def _context(browser, harness_url, color_scheme):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_homebrew_phone_tables_are_readable(browser, harness_url, color_scheme):
    context = _context(browser, harness_url, color_scheme)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/homebrew", wait_until="networkidle")

        # Sanity: the tables actually rendered with rows, or the checks
        # below would vacuously pass on an empty page.
        assert page.locator(".homebrew-casks-table tbody tr").count() > 0
        assert page.locator(".homebrew-formulae-table tbody tr").count() > 0
        assert page.locator(".homebrew-devices-table tbody tr").count() > 0

        word_breaks = page.evaluate(WORD_BREAK_JS, HOMEBREW_TABLE_SELECTORS)
        one_char = page.evaluate(ONE_CHAR_PER_LINE_JS, HOMEBREW_TABLE_SELECTORS)
        overflow = page.evaluate(OVERFLOW_JS, HOMEBREW_TABLE_SELECTORS)
    finally:
        context.close()

    assert not word_breaks, (
        f"[{color_scheme}] /homebrew: word(s) broke mid-word:\n" + "\n".join(word_breaks)
    )
    assert not one_char, (
        f"[{color_scheme}] /homebrew: cell(s) rendered ~one character per line:\n"
        + "\n".join(one_char)
    )
    assert not overflow, (
        f"[{color_scheme}] /homebrew: element(s) overflowed their card:\n" + "\n".join(overflow)
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_homebrew_device_drilldown_phone_table_is_readable(browser, harness_url, color_scheme):
    context = _context(browser, harness_url, color_scheme)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/homebrew/devices/hb-mac-01", wait_until="networkidle")

        assert page.locator(".card.group-card table tbody tr").count() > 0

        word_breaks = page.evaluate(WORD_BREAK_JS, HOMEBREW_DEVICE_TABLE_SELECTORS)
        one_char = page.evaluate(ONE_CHAR_PER_LINE_JS, HOMEBREW_DEVICE_TABLE_SELECTORS)
        overflow = page.evaluate(OVERFLOW_JS, HOMEBREW_DEVICE_TABLE_SELECTORS)
    finally:
        context.close()

    assert not word_breaks, (
        f"[{color_scheme}] /homebrew/devices/hb-mac-01: word(s) broke mid-word:\n"
        + "\n".join(word_breaks)
    )
    assert not one_char, (
        f"[{color_scheme}] /homebrew/devices/hb-mac-01: cell(s) rendered "
        "~one character per line:\n" + "\n".join(one_char)
    )
    assert not overflow, (
        f"[{color_scheme}] /homebrew/devices/hb-mac-01: element(s) overflowed their card:\n"
        + "\n".join(overflow)
    )
