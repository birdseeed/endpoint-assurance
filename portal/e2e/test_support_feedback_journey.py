"""Offline browser acceptance for the two customer doors and their drafts."""

from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import expect

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import STUB_STATE, StubPlatformHandler


@pytest.fixture
def doors(monkeypatch):
    """Serve the deployed per-door list contract on the existing loopback stub."""
    STUB_STATE["feedback_enabled"] = True
    STUB_STATE["feedback_rows"] = [
        {"reference": "FB-101", "type": "support", "title": "A report needs explanation",
         "status": "received", "created_at": "2026-10-01T12:00:00Z"},
        {"reference": "FB-102", "type": "question", "title": "Earlier support question",
         "status": "closed_merged", "created_at": "2026-10-01T12:00:00Z"},
        {"reference": "FB-103", "type": "design", "title": "Make report filters easier to use",
         "status": "planned", "created_at": "2026-10-01T12:00:00Z"},
    ]
    original = StubPlatformHandler.do_GET

    def get(handler):
        parsed = urlsplit(handler.path)
        door = parse_qs(parsed.query).get("door", [""])[0]
        if parsed.path != "/v1/portal/feedback" or not door:
            return original(handler)
        if handler._fail_if_wrong_jwt():
            return
        if STUB_STATE["feedback_status"] or not STUB_STATE["feedback_enabled"]:
            return original(handler)
        kinds = {"support", "bug", "question"} if door == "support" else {"feature", "design"}
        return handler._send(200, [r for r in STUB_STATE["feedback_rows"] if r["type"] in kinds])

    monkeypatch.setattr(StubPlatformHandler, "do_GET", get)


def context_for(browser, harness_url, **kwargs):
    context = browser.new_context(base_url=harness_url, **kwargs)
    context.route("**/*", lambda route: route.continue_()
                  if urlsplit(route.request.url).netloc == urlsplit(harness_url).netloc
                  else route.abort())
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def fill(form, door):
    if door == "support":
        form.locator('[name="category"]').select_option("findings_or_reports")
    else:
        form.locator('[name="type"]').select_option("design")
        form.locator('[name="title"]').fill("Make report filters easier to use")
    form.locator('[name="description"]').fill("Keep my <b>private draft</b> exactly as typed.")


def no_overflow(page):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


@pytest.mark.parametrize("width", [390, 1280, 1440])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_door_pages_and_modal_at_supported_viewports(browser, harness_url, doors, tmp_path,
                                                    width, theme):
    with context_for(browser, harness_url, color_scheme=theme,
                     viewport={"width": width, "height": 900}) as context:
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("/support?route=/devices/dev-mac-001")
        expect(page.locator("html")).to_have_attribute("data-theme", theme)
        expect(page.locator(".support-device")).to_contain_text("acme-mbp-frontdesk")
        expect(page.locator("#support-form")).to_be_visible()
        expect(page.get_by_text("Earlier support question")).to_be_visible()
        expect(page.locator(".feedback-requests")).not_to_contain_text("Make report filters")
        expect(page.locator('#support-form [name="title"]')).to_have_count(0)
        no_overflow(page)
        page.screenshot(path=str(tmp_path / f"support-{width}-{theme}.png"), full_page=True)
        page.goto("/feedback?route=/devices")
        fill(page.locator("#feedback-form"), "feedback")
        expect(page.locator('#feedback-form [name="severity"]')).to_have_count(0)
        no_overflow(page)
        page.screenshot(path=str(tmp_path / f"feedback-{width}-{theme}.png"), full_page=True)
        page.goto("/requests")
        expect(page.locator(".feedback-requests")).to_contain_text("Make report filters")
        expect(page.locator(".feedback-requests")).not_to_contain_text("Earlier support")
        page.locator("[data-feedback-open]").click()
        expect(page.get_by_role("dialog")).to_be_visible()
        fill(page.locator("#feedback-form"), "feedback")
        no_overflow(page)
        assert page.locator(".feedback-panel").evaluate("e => e.scrollWidth <= e.clientWidth")
        page.screenshot(path=str(tmp_path / f"modal-{width}-{theme}.png"), full_page=True)
        page.keyboard.press("Escape")
        expect(page.locator("#feedback-dialog")).to_be_hidden()
        expect(page.locator("[data-feedback-open]")).to_be_focused()
        assert not errors


@pytest.mark.parametrize("failure", [404, 503])
def test_modal_failure_keeps_draft_and_screenshot_then_retries(
        browser, harness_url, doors, failure):
    with context_for(browser, harness_url) as context:
        page = context.new_page()
        page.goto("/requests")
        page.locator("[data-feedback-open]").click()
        form = page.locator("#feedback-form")
        fill(form, "feedback")
        form.locator('[name="screenshot"]').set_input_files({
            "name": "private.png", "mimeType": "image/png", "buffer": b"synthetic png",
        })
        STUB_STATE["feedback_post_status"] = failure
        form.get_by_role("button", name="Send feedback").click()
        expect(form.locator("[data-feedback-error]")).to_be_visible()
        expect(form.locator('[name="description"]')).to_have_value(
            "Keep my <b>private draft</b> exactly as typed.")
        expect(form.locator('[name="type"]')).to_have_value("design")
        assert form.locator('[name="screenshot"]').evaluate("e => e.files.length") == 1
        expect(page.locator("#feedback-dialog")).to_be_visible()
        STUB_STATE["feedback_post_status"] = None
        form.get_by_role("button", name="Send feedback").click()
        expect(page.locator("[data-feedback-success]")).to_be_visible()
        page.get_by_role("link", name="View feedback", exact=True).click()
        page.wait_for_url("**/requests?sent=1")
        assert len(STUB_STATE["feedback_posts"]) == 2
        assert b'name="severity"' not in STUB_STATE["feedback_posts"][-1]["body"]


def test_modal_expired_csrf_retries_once_with_same_draft(browser, harness_url, doors):
    with context_for(browser, harness_url) as context:
        page = context.new_page()
        page.goto("/requests")
        page.locator("[data-feedback-open]").click()
        form = page.locator("#feedback-form")
        fill(form, "feedback")
        form.locator('[name="csrf_token"]').evaluate("e => e.value = '0'.repeat(64)")
        responses = []
        page.on("response", lambda r: responses.append(r.status)
                if r.request.method == "POST" and urlsplit(r.url).path == "/feedback" else None)
        form.get_by_role("button", name="Send feedback").click()
        expect(page.locator("[data-feedback-success]")).to_be_visible()
        assert responses == [403, 201]
        assert len(STUB_STATE["feedback_posts"]) == 1
        assert b"private draft" in STUB_STATE["feedback_posts"][0]["body"]


@pytest.mark.parametrize("door", ["support", "feedback"])
@pytest.mark.parametrize("javascript", [True, False])
@pytest.mark.parametrize("failure", ["expired", "unavailable"])
def test_page_drafts_and_retry_with_or_without_javascript(browser, harness_url, doors,
                                                         door, javascript, failure):
    with context_for(browser, harness_url, java_script_enabled=javascript,
                     viewport={"width": 390, "height": 844}) as context:
        page = context.new_page()
        page.goto(f"/{door}?route=/devices/dev-mac-001")
        form = page.locator(f"#{door}-form")
        fill(form, door)
        if failure == "expired":
            # Playwright evaluation works even with page JavaScript disabled.
            form.locator('[name="csrf_token"]').evaluate("e => e.value = '0'.repeat(64)")
        else:
            STUB_STATE["feedback_post_status"] = 503
        with page.expect_navigation() as navigation:
            form.locator('button[type="submit"]').click()
        assert navigation.value.status == (403 if failure == "expired" else 502)
        expect(form.locator("[data-feedback-error]")).to_be_visible()
        expect(form.locator('[name="description"]')).to_have_value(
            "Keep my <b>private draft</b> exactly as typed.")
        expect(form.locator("textarea b")).to_have_count(0)
        assert form.locator('[name="csrf_token"]').input_value() != "0" * 64
        if door == "support":
            expect(form.locator('[name="category"]')).to_have_value("findings_or_reports")
        else:
            expect(form.locator('[name="type"]')).to_have_value("design")
        no_overflow(page)
        STUB_STATE["feedback_post_status"] = None
        form.locator('button[type="submit"]').click()
        destination = "support" if door == "support" else "requests"
        page.wait_for_url(f"**/{destination}?sent=1")
        expected_posts = 1 if failure == "expired" else 2
        assert len(STUB_STATE["feedback_posts"]) == expected_posts
        fields = STUB_STATE["feedback_posts"][-1]["body"]
        assert b'name="tenant_id"' not in fields
        assert b'name="actor"' not in fields
        assert b'name="device_id"' not in fields


def test_no_script_support_link_preserves_device_context(browser, harness_url, doors):
    with context_for(browser, harness_url, java_script_enabled=False) as context:
        page = context.new_page()
        page.goto("/devices/dev-mac-001")
        page.locator('.rail__item', has_text="Support").click()
        page.wait_for_url("**/support?route=/devices/dev-mac-001")
        expect(page.locator(".support-device")).to_contain_text("acme-mbp-frontdesk")
        expect(page.locator('#support-form [name="route"]')).to_have_value("/devices/dev-mac-001")
