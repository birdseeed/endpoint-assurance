"""Long collected versions stay intact, without making the table wider."""

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import check_break, check_cells, check_overflow
from tests.conftest import DEVICE_SOFTWARE

VERSIONS = ["154.0.8037.58", "26225.1708.5124.9749", "26.928.21956"]

# Measure each actual text substring, not a CSS class or wrapper's rect:
# a Range crossing two painted lines is the production defect.
VERSION_RECTS_JS = """versions => {
  const cell = document.querySelector('.device-software-table td[data-label="Version(s)"]');
  const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  return versions.map(version => {
    const node = nodes.find(n => n.textContent.includes(version));
    if (!node) return {version, missing: true};
    const start = node.textContent.indexOf(version);
    const range = document.createRange();
    range.setStart(node, start); range.setEnd(node, start + version.length);
    const rects = [...range.getClientRects()];
    const box = cell.getBoundingClientRect();
    return {version, lines: new Set(rects.map(r => Math.round(r.y))).size,
      top: rects[0].top, inside: rects.every(r => r.left >= box.left && r.right <= box.right)};
  });
}"""


@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_long_device_versions_keep_each_value_intact(
    browser, harness_url, monkeypatch, width, theme,
):
    monkeypatch.setitem(DEVICE_SOFTWARE["products"][0], "versions", VERSIONS)
    context = browser.new_context(base_url=harness_url, viewport={"width": width, "height": 900})
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    context.add_init_script(f"localStorage.setItem('patched.theme', '{theme}')")
    try:
        page = context.new_page()
        response = page.goto("/devices/dev-mac-001/software", wait_until="networkidle")
        assert response.status == 200
        page.locator("html").evaluate("(el, theme) => el.dataset.theme = theme", theme)
        metrics = page.evaluate(VERSION_RECTS_JS, VERSIONS)
        assert all(m.get("lines") == 1 and m.get("inside") for m in metrics), metrics
        # A list too wide for the cell must wrap between distinct values.
        assert len({m["top"] for m in metrics}) > 1, metrics
        dimensions = page.evaluate("""() => {
          const table = document.querySelector('.device-software-table');
          const scroll = table.closest('.table-scroll');
          return {page: document.documentElement.scrollWidth,
            viewport: innerWidth, table: table.scrollWidth, box: scroll.clientWidth};
        }""")
        assert dimensions["page"] <= width, dimensions
        assert dimensions["table"] <= dimensions["box"] + 1, dimensions
        route = "/devices/dev-mac-001/software"
        findings = (check_break(page, route, width, theme)
                    + check_cells(page, route, width, theme)
                    + check_overflow(page, route, width, theme))
        assert not findings, findings
    finally:
        context.close()


@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_oversize_version_is_bounded_and_full_title_is_escaped(
    browser, harness_url, monkeypatch, width, theme,
):
    version = "1234567890." * 20 + '\"<img src=x onerror=alert(1)> & build'
    monkeypatch.setitem(DEVICE_SOFTWARE["products"][0], "versions", [version, *VERSIONS])
    context = browser.new_context(base_url=harness_url, viewport={"width": width, "height": 900})
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    try:
        page = context.new_page()
        response = page.goto("/devices/dev-mac-001/software", wait_until="networkidle")
        assert response.status == 200
        page.locator("html").evaluate("(el, theme) => el.dataset.theme = theme", theme)
        cell = page.locator('.device-software-table td[data-label="Version(s)"]').first
        value = cell.locator(".device-software-version").first
        metrics = value.evaluate("""el => {
          const box = el.getBoundingClientRect(), cell = el.closest('td').getBoundingClientRect();
          const style = getComputedStyle(el);
          return {inside: box.left >= cell.left && box.right <= cell.right,
            clipped: el.scrollWidth > el.clientWidth,
            ellipsis: style.textOverflow, overflow: style.overflowX};
        }""")
        assert metrics["inside"], metrics
        assert metrics["clipped"] and metrics["ellipsis"] == "ellipsis", metrics
        assert metrics["overflow"] == "hidden", metrics
        assert value.get_attribute("title") == version
        assert value.text_content() == version + ","
        assert cell.locator("img").count() == 0
        assert value.evaluate("el => el.getAttributeNames()") == ["class", "title"]
        # Every ordinary long value remains fully visible, without ellipsis.
        for known in VERSIONS:
            ordinary = cell.locator(".device-software-version", has_text=known)
            assert ordinary.evaluate("el => el.scrollWidth <= el.clientWidth"), known
        assert all(m["inside"] for m in page.evaluate(VERSION_RECTS_JS, VERSIONS))
        route = "/devices/dev-mac-001/software"
        findings = (check_break(page, route, width, theme)
                    + check_cells(page, route, width, theme)
                    + check_overflow(page, route, width, theme))
        assert not findings, findings
    finally:
        context.close()
