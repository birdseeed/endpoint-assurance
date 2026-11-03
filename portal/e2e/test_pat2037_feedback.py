"""PAT-2037 browser coverage: feedback modal, screenshot and responsive theme UI."""

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE


def _context(browser, harness_url, color_scheme="light"):
    context = browser.new_context(base_url=harness_url, color_scheme=color_scheme)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_feedback_modal_traps_focus_escapes_restores_and_handles_screenshot(browser, harness_url):
    STUB_STATE["feedback_enabled"] = True
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        # A direct canonical read refreshes the harness's availability cache
        # if an earlier browser test saw the disabled platform state.
        page.goto("/requests", wait_until="networkidle")
        page.goto("/", wait_until="networkidle")
        trigger = page.locator("[data-feedback-open]")
        trigger.click()
        dialog = page.get_by_role("dialog", name="Suggest an improvement")
        assert dialog.is_visible()
        assert "Patched team's issue tracker" in dialog.inner_text()
        dialog.get_by_text("What we send with this").click()
        assert "Portal build" in dialog.inner_text()
        page.locator("[data-feedback-screenshot]").set_input_files({
            "name": "screen.png", "mimeType": "image/png", "buffer": b"png bytes",
        })
        assert page.locator("[data-feedback-preview]").is_visible()
        page.keyboard.press("Escape")
        assert dialog.is_hidden()
        assert page.evaluate(
            "() => document.activeElement === document.querySelector('[data-feedback-open]')"
        )
        trigger.click()
        assert page.locator("[data-feedback-preview]").is_hidden()
        file_count = page.locator("[data-feedback-screenshot]").evaluate(
            "input => input.files.length"
        )
        assert file_count == 0
        page.locator("[data-feedback-screenshot]").set_input_files({
            "name": "screen.png", "mimeType": "image/png", "buffer": b"png bytes",
        })
        page.get_by_role("button", name="Remove screenshot").click()
        assert page.locator("[data-feedback-preview]").is_hidden()
        page.keyboard.press("Shift+Tab")
        assert page.evaluate("() => document.activeElement.closest('#feedback-dialog') !== null")
    finally:
        context.close()


def test_feedback_success_dark_mobile_and_no_overflow(browser, harness_url):
    STUB_STATE["feedback_enabled"] = True
    context = _context(browser, harness_url, color_scheme="dark")
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("/requests", wait_until="networkidle")
        page.goto("/devices", wait_until="networkidle")
        page.locator("[data-feedback-open]").click()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.locator("#feedback-type").select_option("feature")
        page.locator("#feedback-title-input").fill("Please add an export filter")
        page.locator("#feedback-description").fill(
            "An export filter would make this report easier to use."
        )
        page.get_by_role("button", name="Send feedback").click()
        page.get_by_text("Feedback sent").wait_for()
        assert page.get_by_text("Feedback sent").is_visible()
        assert page.get_by_text("FB-0001").is_visible()
        metrics = page.evaluate(
            "() => ({scrollWidth: document.documentElement.scrollWidth, "
            "clientWidth: document.documentElement.clientWidth})"
        )
        assert metrics["scrollWidth"] <= metrics["clientWidth"]
    finally:
        context.close()
