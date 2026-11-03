"""PAT-2185/PAT-2022 browser coverage for grouped rail and live AI Tooling."""

from e2e.conftest import HARNESS_VALID_TOKEN


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_ai_tooling_rail_item_is_active_and_mobile_drawer_is_usable(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 900})
        page.goto(f"{harness_url}/ai-tooling", wait_until="networkidle")

        assert page.get_by_role("heading", name="AI Tooling").is_visible()
        assert not page.get_by_role("main").get_by_text("In development", exact=True).count()
        assert page.get_by_role("heading", name="Products").is_visible()
        assert page.get_by_text("presence, version and configuration shape only").is_visible()
        assert not page.get_by_text("Coming soon", exact=True).count()

        page.locator("#rail-burger").click()
        rail = page.locator("#rail")
        rail.wait_for(state="visible")
        active = rail.locator('a[href="/ai-tooling"]')
        assert active.is_visible()
        assert "active" in (active.get_attribute("class") or "")
        assert page.locator(".rail__group-label").all_inner_texts() == [
            "Your estate", "Governance", "Operations",
        ]
        icons = page.locator(
            ".rail__nav .rail__item svg[aria-hidden=\"true\"][focusable=\"false\"]"
        )
        assert icons.count() == 14
        assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        context.close()


def test_ai_tooling_device_detail_notifications_and_dark_theme(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/ai-tooling", wait_until="networkidle")
        assert page.get_by_text("AI tooling first seen", exact=True).is_visible()
        assert page.get_by_text("New software first seen", exact=True).is_visible()

        page.get_by_role("button", name="Dark").click()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        assert page.locator(".ai-products-table").is_visible()

        # PAT-2243: collection rows are an optional bounded drill-down.
        page.locator("#devices > summary").click()
        page.get_by_role("link", name="acme-mbp-frontdesk", exact=True).click()
        page.wait_for_load_state("networkidle")
        assert page.get_by_role("heading", name="acme-mbp-frontdesk").is_visible()
        # The item name opens its AI evidence; the compact row stays one line.
        page.locator("tr[data-approval-row]", has_text="GitHub").locator("details summary").click()
        for text in (
            "ChatGPT", "AI Search Helper", "Llama 3 8B", "GitHub", "stdio",
            "CVE-2026-1234",
        ):
            assert page.get_by_text(text, exact=False).first.is_visible()
        assert page.get_by_role("link", name="Download device CSV").is_visible()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        body = page.get_by_role("main").inner_text().lower()
        for secret in ("super-secret-value", "/users/alice", "token=ghp_"):
            assert secret not in body
    finally:
        context.close()
