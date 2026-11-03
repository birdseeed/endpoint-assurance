"""PAT-2216 browser coverage: the feedback type switch, stale-session retry
and the no-JavaScript form.

Both improvement types omit severity and category, including without JavaScript.
"""

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE


def _context(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def _open_modal(page):
    page.goto("/requests", wait_until="networkidle")
    page.goto("/devices", wait_until="networkidle")
    page.locator("[data-feedback-open]").click()
    dialog = page.get_by_role("dialog", name="Suggest an improvement")
    assert dialog.is_visible()
    return dialog


def test_switching_feature_to_design_has_no_severity_or_category(browser, harness_url):
    STUB_STATE["feedback_enabled"] = True
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        _open_modal(page)
        for feedback_type in ("feature", "design"):
            page.locator("#feedback-type").select_option(feedback_type)
            assert page.locator('[name="severity"], [data-feedback-severity]').count() == 0
            assert page.locator('[name="category"]').count() == 0
        page.locator("#feedback-title-input").fill("Please add an export filter")
        page.locator("#feedback-description").fill("An owner filter on the export.")
        before = len(STUB_STATE["feedback_posts"])
        page.get_by_role("button", name="Send feedback").click()
        page.get_by_text("Feedback sent").wait_for()
        posts = STUB_STATE["feedback_posts"][before:]
        assert len(posts) == 1
        assert b'name="type"\r\n\r\ndesign' in posts[0]["body"]
        assert b'name="category"' not in posts[0]["body"]
        assert b'name="severity"' not in posts[0]["body"]

        # Reopening and switching back retains only the two improvement types.
        page.goto("/devices", wait_until="networkidle")
        page.locator("[data-feedback-open]").click()
        page.locator("#feedback-type").select_option("design")
        assert page.locator('[name="severity"], [name="category"]').count() == 0
        page.locator("#feedback-type").select_option("feature")
        assert page.locator('[name="severity"], [name="category"]').count() == 0
    finally:
        context.close()


def test_stale_page_token_is_refreshed_and_the_draft_is_sent(browser, harness_url):
    STUB_STATE["feedback_enabled"] = True
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        _open_modal(page)
        # Simulate an Access session that rotated while the page sat open.
        page.locator('#feedback-form input[name="csrf_token"]').evaluate(
            "input => { input.value = '0'.repeat(64); }"
        )
        page.locator("#feedback-type").select_option("design")
        page.locator("#feedback-title-input").fill("How often do devices report?")
        page.locator("#feedback-description").fill("I would like to know the cadence.")
        before = len(STUB_STATE["feedback_posts"])
        page.get_by_role("button", name="Send feedback").click()
        page.get_by_text("Feedback sent").wait_for()
        assert len(STUB_STATE["feedback_posts"]) == before + 1
        body = STUB_STATE["feedback_posts"][-1]["body"]
        assert b'name="severity"' not in body
        assert b'name="category"' not in body
    finally:
        context.close()


def test_feedback_form_works_without_javascript(browser, harness_url):
    STUB_STATE["feedback_enabled"] = True
    context = _context(browser, harness_url, java_script_enabled=False)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("/requests", wait_until="networkidle")
        page.goto("/devices", wait_until="networkidle")
        page.locator("[data-feedback-open]").click()
        page.wait_for_url("**/feedback?route=/devices")
        for feedback_type in ("design", "feature"):
            page.locator("#feedback-type").select_option(feedback_type)
            assert page.locator('[name="severity"], [data-feedback-severity]').count() == 0
            assert page.locator('[name="category"]').count() == 0
        page.locator("#feedback-title-input").fill("Please add an export filter")
        page.locator("#feedback-description").fill("An owner filter on the export.")
        before = len(STUB_STATE["feedback_posts"])
        page.get_by_role("button", name="Send feedback").click()
        page.wait_for_url("**/requests?sent=1")
        assert page.get_by_role("heading", name="Feedback sent", exact=True).is_visible()
        assert len(STUB_STATE["feedback_posts"]) == before + 1
        body = STUB_STATE["feedback_posts"][-1]["body"]
        assert b'name="severity"' not in body
        assert b'name="category"' not in body
    finally:
        context.close()
