"""Guards PAT-2136 - the device detail page at phone width (390px).

Found in the first `/portal-walk` run against portal main 7d9bd79
(2026-09-25): at 390px the Compliance signals table's control-name column
collapsed to about one character wide (table-layout: fixed's three fixed
pixel columns - Severity 108px, Status 84px, Verification 250px, 442px
total - already exceeded the ~300px available inside the card, so the
Rule and Control columns' remaining share computed to 0px and their text
rendered one letter per line), and the Verification column's pill/link
text sat right at the visible edge. The CVE assessment product table's
CVE-state pill and explanation text looked cut off at the right edge for
the same underlying reason - the table itself scrolls correctly inside
its `.table-scroll` wrapper (confirmed: `scrollWidth` 443px vs `clientWidth`
300px, fully contained, no mid-word breaks), so a static screenshot taken
without scrolling shows it looking truncated even though nothing actually
overflows its card. That matches this ticket's "acceptable" fallback for
the CVE table (let it scroll horizontally); only Compliance signals needed
a real fix (a `.table-stack` label/value layout - see portal.css).

Uses the default DEVICE_DETAIL stub (dev-mac-001 / acme-mbp-frontdesk),
the same stub device the original portal-walk screenshot rendered - no
long-data override needed, the default fixture's "Firewall enabled" /
"Enable the application firewall in System Settings." row alone was
enough to collapse the pre-fix column to one character per line.

Red-proof: every assertion here fails on current main (the pre-fix
Compliance signals table renders 0px-wide Rule/Control columns whose text
breaks a word across many single-character lines) and passes once
portal.css's `.table-stack` rule and the template's `table-stack`
class/`data-label` attributes land.
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
        // Alphanumeric runs only - see e2e/test_pat2092_layout.py's
        // WORD_BREAK_JS for why hyphens/dots are excluded.
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
# this app's table font-size (14px, portal.css .data-table) but still
# holds real text content is the "one character per line" shape directly -
# distinct from (and a stricter net than) the word-break check above,
# which only catches runs of 3+ alphanumeric characters.
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

# Compliance signals must fit its card with no scrolling required (the
# preferred, stacked fix). The CVE assessment product table's "acceptable"
# fallback is to scroll horizontally inside its own .table-scroll, so it is
# checked against its own <table> box (the true scrollable extent) instead
# of the card - nothing may escape that scrollable region itself (e.g. via
# a stray absolute position or negative margin), which is the genuine
# "overflows its card" shape this ticket cares about.
OVERFLOW_JS = """
() => {
  const failures = [];
  document.querySelectorAll('.signals-table').forEach((table) => {
    const card = table.closest('.card');
    if (!card) return;
    const cr = card.getBoundingClientRect();
    table.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (r.right > cr.right + 1) {
        failures.push('signals-table: ' + el.tagName + ' ' +
          JSON.stringify((el.textContent || '').trim().slice(0, 40)) +
          ' right=' + r.right.toFixed(1) + ' cardRight=' + cr.right.toFixed(1));
      }
    });
  });
  document.querySelectorAll('.cve-assessment-card table').forEach((table) => {
    const tr = table.getBoundingClientRect();
    table.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      if (r.right > tr.right + 1 || r.left < tr.left - 1) {
        failures.push('cve-assessment: ' + el.tagName + ' ' +
          JSON.stringify((el.textContent || '').trim().slice(0, 40)) +
          ' escapes its own table box');
      }
    });
  });
  return failures;
}
"""

TABLE_SELECTORS = ['.signals-table', '.cve-assessment-card table']


def _context(browser, harness_url, color_scheme):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_compliance_table_is_readable_at_phone_width(browser, harness_url, color_scheme):
    # PAT-2164: Compliance signals moved to their own tab.
    context = _context(browser, harness_url, color_scheme)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/compliance", wait_until="networkidle")

        # Sanity: the table actually rendered with rows, or the checks below
        # would vacuously pass on an empty page.
        assert page.locator(".signals-table tbody tr").count() > 0

        word_breaks = page.evaluate(WORD_BREAK_JS, ['.signals-table'])
        one_char = page.evaluate(ONE_CHAR_PER_LINE_JS, ['.signals-table'])
        overflow = page.evaluate(OVERFLOW_JS)
    finally:
        context.close()

    assert not word_breaks, (
        f"[{color_scheme}] word(s) broke mid-word:\n" + "\n".join(word_breaks)
    )
    assert not one_char, (
        f"[{color_scheme}] cell(s) rendered ~one character per line:\n" + "\n".join(one_char)
    )
    assert not overflow, (
        f"[{color_scheme}] element(s) overflowed their card/table:\n" + "\n".join(overflow)
    )


@pytest.mark.parametrize("color_scheme", ["light", "dark"])
def test_cve_assessment_table_is_readable_at_phone_width(browser, harness_url, color_scheme):
    # PAT-2164: CVE assessment moved to the Vulnerabilities tab.
    context = _context(browser, harness_url, color_scheme)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001/vulnerabilities", wait_until="networkidle")

        assert page.locator(".cve-assessment-card table tbody tr").count() > 0

        word_breaks = page.evaluate(WORD_BREAK_JS, ['.cve-assessment-card table'])
        one_char = page.evaluate(ONE_CHAR_PER_LINE_JS, ['.cve-assessment-card table'])
        overflow = page.evaluate(OVERFLOW_JS)
    finally:
        context.close()

    assert not word_breaks, (
        f"[{color_scheme}] word(s) broke mid-word:\n" + "\n".join(word_breaks)
    )
    assert not one_char, (
        f"[{color_scheme}] cell(s) rendered ~one character per line:\n" + "\n".join(one_char)
    )
    assert not overflow, (
        f"[{color_scheme}] element(s) overflowed their card/table:\n" + "\n".join(overflow)
    )
