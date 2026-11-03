"""PAT-2298: dates in the Verification column of the device Compliance tab
(and /findings, same macro) render on one line, in a real browser.

The stub walker found ten `break` findings on /devices/dev-mac-001/compliance:
"04 Dec 2026" split across two lines in the closure sentence and in the event
timeline, then two more in the driver list on /findings. The same defect sat in
table cells and evidence lists on other pages, so the second test below reads
every date and version on those pages the way the walker's `break` check does.
The lifecycle history is a closed <details> by default, so every check here also
opens it. Layout is measured under the default font and under Verdana (the
repo's stand-in for the wider Linux CI fonts).

Every date assertion fails on the pre-fix templates.
"""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN

WIDE_FALLBACK_FONT_CSS = '* { font-family: "Verdana", "DejaVu Sans", sans-serif !important; }'

DATE_LINES_JS = """
() => {
  const re = /\\b\\d{1,2}\\s+[A-Z][a-z]{2}\\s+\\d{4}\\b/g;
  const out = [];
  document.querySelectorAll('.lifecycle').forEach((root) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      let m;
      re.lastIndex = 0;
      while ((m = re.exec(node.textContent))) {
        const range = document.createRange();
        range.setStart(node, m.index);
        range.setEnd(node, m.index + m[0].length);
        const tops = [];
        for (const r of range.getClientRects()) {
          if (r.width === 0 && r.height === 0) continue;
          if (!tops.some((t) => Math.abs(t - r.top) <= 3)) tops.push(r.top);
        }
        out.push({text: m[0], lines: tops.length});
      }
    }
  });
  return out;
}
"""

TIMELINE_SIDEWAYS_JS = """
() => Array.from(document.querySelectorAll('.lifecycle__timeline'))
  .map((ol) => ol.scrollWidth - ol.clientWidth)
"""

# The walker's `break` check (e2e/walk/walk.py _BREAK_JS): a version- or
# date-shaped string that renders across more than one line, anywhere.
BREAK_JS = """
() => {
  const PATTERNS = [
    ['version', /\\b\\d+(?:\\.\\d+){1,3}\\b/g],
    ['date', /\\b\\d{1,2}\\s+[A-Z][a-z]{2}\\s+\\d{4}\\b/g],
    ['date', /\\b\\d{4}-\\d{2}-\\d{2}\\b/g],
  ];
  const out = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    const parent = node.parentElement;
    if (!parent || ['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE'].includes(parent.tagName)) continue;
    for (const [kind, re] of PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(node.textContent))) {
        const range = document.createRange();
        range.setStart(node, m.index);
        range.setEnd(node, m.index + m[0].length);
        const tops = [];
        for (const r of range.getClientRects()) {
          if (r.width === 0 && r.height === 0) continue;
          if (!tops.some((t) => Math.abs(t - r.top) <= 3)) tops.push(r.top);
        }
        if (tops.length > 1) out.push({kind: kind, text: m[0], lines: tops.length,
                                       tag: parent.tagName.toLowerCase()});
      }
    }
  }
  return out;
}
"""

# Pages whose cells or evidence lists carried an unwrapped date or version.
PAGES = [
    "/",
    "/findings",
    "/devices/dev-mac-001/compliance",
    "/devices/dev-mac-001/vulnerabilities",
    "/ce-readiness",
    "/reports",
    "/reports/software/duplicate-tools",
    "/reports/software/publishers",
    "/reports/software/remote-access",
    "/reports/software/unsupported",
    "/homebrew",
    "/homebrew/devices/hb-mac-01",
    "/ai-tooling",
    "/ai-tooling/devices/dev-mac-001",
    "/exceptions",
]

DOC_OVERFLOW_JS = (
    "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
)


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


@pytest.mark.parametrize("path", ["/devices/dev-mac-001/compliance", "/findings"])
@pytest.mark.parametrize("wide_font", [False, True], ids=["system-font", "verdana"])
@pytest.mark.parametrize("width", [1440, 1280, 390])
def test_lifecycle_dates_stay_on_one_line(browser, harness_url, path, wide_font, width):
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}{path}", wait_until="networkidle")
        if wide_font:
            page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        page.evaluate("document.querySelectorAll('.lifecycle details').forEach(d => d.open = true)")
        dates = page.evaluate(DATE_LINES_JS)
        sideways = page.evaluate(TIMELINE_SIDEWAYS_JS)
        overflow = page.evaluate(DOC_OVERFLOW_JS)
    finally:
        context.close()

    assert dates, f"no lifecycle dates rendered on {path}"
    broken = [d for d in dates if d["lines"] != 1]
    assert not broken, f"dates wrap at {width}px: {broken}"
    assert all(s <= 1 for s in sideways), f"a timeline scrolls sideways: {sideways}"
    assert overflow <= 1, f"{path} scrolls sideways at {width}px by {overflow}px"


@pytest.mark.parametrize("path", PAGES)
@pytest.mark.parametrize("wide_font", [False, True], ids=["system-font", "verdana"])
@pytest.mark.parametrize("width", [1440, 1280, 390])
def test_dates_and_versions_on_swept_pages_stay_on_one_line(
    browser, harness_url, path, wide_font, width,
):
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto(f"{harness_url}{path}", wait_until="networkidle")
        if wide_font:
            page.add_style_tag(content=WIDE_FALLBACK_FONT_CSS)
        page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
        broken = page.evaluate(BREAK_JS)
    finally:
        context.close()

    assert not broken, f"{path} at {width}px: {broken}"
