"""AI review density, first paint, evidence and permissions in a real browser."""
import copy
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import AI_TAGGED_PRODUCTS, AI_TOOLING_DEVICE_ITEMS, STUB_STATE

ROUTES = ("/ai-tooling", "/ai-tooling/devices/dev-mac-001")


@pytest.mark.parametrize("width", (1280, 390))
@pytest.mark.parametrize("role", ("admin", "viewer"))
def test_compact_ai_summary_preserves_local_admins_layout(browser, harness_url, width, role):
    """The unrelated admin-only summary retains its original responsive card grid."""
    STUB_STATE["portal_role"] = role
    context = _context(browser, harness_url, viewport={"width": width, "height": 900})
    try:
        page = context.new_page()
        page.goto("/local-admins", wait_until="networkidle")
        if role == "viewer":
            assert page.get_by_label("Local admins is admin only").is_visible()
            assert page.locator(".ai-summary").count() == 0
            assert page.locator("#local-admins-table").count() == 0
            assert page.get_by_role("link", name="Download CSV").count() == 0
        else:
            summary = page.locator(".ai-summary")
            grid = summary.locator(".ai-summary-grid")
            assert summary.evaluate("e => getComputedStyle(e).display") == "block"
            assert summary.evaluate("e => getComputedStyle(e).marginBottom") == "18px"
            assert grid.evaluate("e => getComputedStyle(e).display") == "grid"
            columns = grid.evaluate("e => getComputedStyle(e).gridTemplateColumns.split(' ')")
            assert len(columns) == (4 if width >= 680 else 2)
            assert grid.evaluate("e => getComputedStyle(e).gap") == "12px"
            actions = summary.locator(".ai-summary-actions")
            assert actions.evaluate("e => getComputedStyle(e).marginTop") == "10px"
            grid_box = grid.bounding_box()
            assert actions.bounding_box()["y"] >= grid_box["y"] + grid_box["height"]
            # Exercise the retained zero treatment even when the stub has no zero tile.
            card = grid.locator(".ov-card").first
            card.evaluate("e => e.classList.add('ov-card--zero')")
            headline = card.locator(".ov-card__headline")
            assert headline.evaluate("e => getComputedStyle(e).fontSize") == "18px"
            assert headline.evaluate("e => getComputedStyle(e).fontWeight") == "600"
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.goto("/ai-tooling", wait_until="networkidle")
        assert page.locator(".ai-summary-grid").count() == 0
        ai_summary = page.locator(".ai-review-summary")
        assert ai_summary.evaluate("e => getComputedStyle(e).display") == "flex"
        assert page.locator("#approval-form").count() == (1 if role == "admin" else 0)
    finally:
        context.close()


@pytest.fixture(autouse=True)
def _ai_fixture_isolation(monkeypatch):
    for key in ("ai_tagged_products_data", "ai_tooling_device_items_data",
                "ai_tooling_devices_data"):
        monkeypatch.setitem(STUB_STATE, key, None)


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{"name": "CF_Authorization", "value": HARNESS_VALID_TOKEN,
                         "url": harness_url}])
    return context


def _dense_fixture(route):
    device = route != ROUTES[0]
    data = copy.deepcopy(AI_TOOLING_DEVICE_ITEMS if device else AI_TAGGED_PRODUCTS)
    key = "items" if device else "products"
    rows = []
    for i in range(24):
        row = copy.deepcopy(data[key][0])
        row["name"] = (f'AI assistant {i:02d} "quoted" <img src=x onerror=alert(1)> '
                       + "long name " * 12)
        row["item_id" if device else "product_key"] = f"dense-{i}"
        row["approval_target"]["identifier"] = f"ai.dense.{i}"
        if not device:
            row["identifier"] = f"ai.dense.{i}"
        rows.append(row)
    data[key], data["total"] = rows, len(rows)
    STUB_STATE["ai_tooling_device_items_data" if device else "ai_tagged_products_data"] = data
    return rows[0]["name"]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("width", (1440, 1280, 390))
@pytest.mark.parametrize("theme", ("light", "dark"))
def test_compact_rows_fit_and_keep_full_names(browser, harness_url, route, width, theme):
    full_name = _dense_fixture(route)
    context = _context(browser, harness_url, viewport={"width": width, "height": 800},
                       color_scheme=theme)
    try:
        page = context.new_page()
        page.goto(route, wait_until="networkidle")
        rows = page.locator("tr[data-approval-row]")
        assert rows.count() == 24
        assert rows.first.locator("img").count() == 0
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        if width > 680:
            assert rows.first.bounding_box()["y"] < 600, "the list is buried under supporting cards"
            page.evaluate("""() => {
              const head = document.querySelector('tr[data-approval-row]').closest('table').tHead;
              const bar = document.querySelector('.topbar').getBoundingClientRect().height;
              scrollTo(0, head.getBoundingClientRect().top + scrollY - bar);
            }""")
            geometry = rows.evaluate_all("""rs => ({
              tallest: Math.max(...rs.map(r => r.getBoundingClientRect().height)),
              inView: rs.filter(r => {const b=r.getBoundingClientRect();
                return b.top >= document.querySelector('.topbar').getBoundingClientRect().bottom-1
                  && b.bottom <= innerHeight+1;}).length
            })""")
            assert geometry["tallest"] <= 42, geometry
            assert geometry["inView"] >= 15, geometry
        else:
            assert rows.first.evaluate("r => getComputedStyle(r).display") == "block"
            assert rows.first.evaluate("""r => {const s=r.closest('.table-scroll');
                return s.scrollWidth <= s.clientWidth + 1;}""")
        assert rows.first.locator(".product-name").get_attribute("title") == full_name
        assert rows.first.locator(".cell-review .pill-state").count() == 1
        assert rows.first.locator("[data-approval-row-form]").is_visible()
        output = os.environ.get("PAT2243_SCREENSHOTS")
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
            name = f"{'device' if route != ROUTES[0] else 'estate'}-{width}-{theme}.png"
            page.screenshot(path=str(Path(output) / name), full_page=False)
    finally:
        context.close()


@pytest.mark.parametrize("javascript", (True, False))
@pytest.mark.parametrize("route", ROUTES)
def test_filters_search_and_removal_work_on_first_paint(browser, harness_url, javascript, route):
    context = _context(browser, harness_url, java_script_enabled=javascript)
    try:
        page = context.new_page()
        state = "unreviewed" if route == ROUTES[0] else "approved"
        page.goto(f"{route}?type=desktop_app&state={state}&search=ChatGPT",
                  wait_until="networkidle")
        visible = page.locator("tr[data-approval-row]:visible")
        assert visible.count() == 1
        assert "ChatGPT" in visible.first.inner_text()
        search = page.get_by_role("searchbox", name="Search AI tooling")
        assert search.input_value() == "ChatGPT"
        search.fill("absent-name")
        page.locator(".filter-bar button[type=submit]").last.click()
        # A no-script form navigation must load its visibility stylesheet.
        page.wait_for_load_state("networkidle")
        assert page.locator("tr[data-approval-row]:visible").count() == 0
        assert page.locator("[data-filter-empty]").is_visible()
        assert parse_qs(urlsplit(page.url).query)["search"] == ["absent-name"]
        page.locator(".filter-chip--clear").click()
        page.wait_for_load_state("networkidle")
        assert page.locator("tr[data-approval-row]:visible").count() == 4
    finally:
        context.close()


@pytest.mark.parametrize("role", ("admin", "viewer"))
@pytest.mark.parametrize("route", ROUTES)
def test_review_permissions_and_ai_evidence_remain_accessible(browser, harness_url, role, route):
    STUB_STATE["portal_role"] = role
    context = _context(browser, harness_url, viewport={"width": 1280, "height": 800})
    try:
        page = context.new_page()
        page.goto(route, wait_until="networkidle")
        row = page.locator("tr[data-approval-row]").first
        assert row.locator(".pill-state").count() == 1
        assert row.locator("[data-approval-row-form]").count() == (1 if role == "admin" else 0)
        assert page.locator("#approval-form").count() == (1 if role == "admin" else 0)
        evidence = row.locator("details")
        evidence.locator("summary").click()
        assert evidence.get_by_text("Version", exact=False).first.is_visible()
        assert evidence.get_by_role("link", name="Approval history").is_visible()
        if route == ROUTES[0]:
            cli = page.locator("tr[data-approval-row]", has_text="ai-helper")
            assessment = cli.locator("td[data-label='Vulnerability findings']")
            assert "Incomplete" in assessment.inner_text()
        if route != ROUTES[0]:
            mcp = page.locator("tr[data-approval-row]", has_text="GitHub")
            mcp.locator("details summary").click()
            assert mcp.get_by_text("@modelcontextprotocol/server-github", exact=False).is_visible()
            assert mcp.get_by_text("CVE-2026-1234", exact=False).is_visible()
            assert "Partial" in mcp.inner_text() and "Lower bound" in mcp.inner_text()
    finally:
        context.close()


def test_large_estate_collection_is_optional_and_bounded(browser, harness_url):
    from tests.conftest import AI_TOOLING_DEVICES
    data = copy.deepcopy(AI_TOOLING_DEVICES)
    data["devices"] = [dict(copy.deepcopy(data["devices"][-1]),
                            device_id=f"coverage-{i}", hostname=f"device-{i:03d}")
                       for i in range(100)]
    data["total"] = 100
    STUB_STATE["ai_tooling_devices_data"] = data
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto("/ai-tooling?type=desktop_app&search=ChatGPT", wait_until="networkidle")
        assert page.locator(".ai-devices-table tbody tr:visible").count() == 0
        page.locator("#devices > summary").click()
        assert page.locator(".ai-devices-table tbody tr:visible").count() == 25
        row = page.locator(".ai-devices-table tbody tr").first
        assert row.locator(".pill").count() == 0
        assert "All four collectors have not yet reported" in row.inner_text()
        assert row.get_by_role("link", name="device-000").is_visible()
        page.get_by_role("link", name="Next devices").click()
        page.wait_for_load_state("networkidle")
        assert page.locator(".ai-devices-table tbody tr:visible").count() == 25
        next_row = page.locator(".ai-devices-table tbody tr").first
        assert next_row.get_by_text("device-025").is_visible()
        query = parse_qs(urlsplit(page.url).query)
        assert query["type"] == ["desktop_app"] and query["search"] == ["ChatGPT"]
    finally:
        context.close()


@pytest.mark.parametrize("javascript", (True, False))
@pytest.mark.parametrize("route", ROUTES)
def test_inline_review_keeps_filter_and_exact_target(browser, harness_url, javascript, route):
    context = _context(browser, harness_url, java_script_enabled=javascript)
    try:
        page = context.new_page()
        page.goto(route + "?type=desktop_app&search=ChatGPT", wait_until="networkidle")
        row = page.locator("tr[data-approval-row]:visible").first
        state = "approved" if route == ROUTES[0] else "unapproved"
        row.locator("select[data-approval-row-state]").select_option(state)
        row.locator("[data-approval-row-apply]").click()
        page.wait_for_selector("#approval-result")
        assert len(STUB_STATE["approval_puts"]) == 1
        write = STUB_STATE["approval_puts"][0]["body"]
        assert write["state"] == state and len(write["items"]) == 1
        assert write["items"][0]["identifier"] == (
            "ChatGPT.ChatGPT" if route == ROUTES[0] else "com.openai.chat")
        query = parse_qs(urlsplit(page.url).query)
        assert query["type"] == ["desktop_app"] and query["search"] == ["ChatGPT"]
        assert urlsplit(page.url).path == route
    finally:
        context.close()


@pytest.mark.parametrize("route", ROUTES)
def test_bulk_review_submits_only_the_visible_selection(browser, harness_url, route):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(route + "?type=desktop_app", wait_until="networkidle")
        page.locator("tr[data-approval-row]:visible input.approval-select").check()
        page.locator("#approval-form button[value=ignored]").click()
        page.wait_for_selector("#approval-result")
        assert len(STUB_STATE["approval_puts"]) == 1
        write = STUB_STATE["approval_puts"][0]["body"]
        assert write["state"] == "ignored" and len(write["items"]) == 1
    finally:
        context.close()
