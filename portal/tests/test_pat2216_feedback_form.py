"""PAT-2216: Support and both Feedback types submit without severity, and an
expired page never costs the customer what they typed.

Found in production on 2026-09-28: a Suggest a feature report failed after
the customer had first picked a bug severity, and a Feedback form left open
long enough for the Access session to rotate came back with "This page has
expired", losing the title and description on reload.

The server is the authority. With JavaScript the modal posts with
``Accept: application/json``; without it the same form posts as a normal
browser form and must get a page back, never a JSON body.
"""

import html
import re

import pytest

import main
from tests.conftest import STUB_STATE

ORIGIN = "https://testserver"
JSON = {"Accept": "application/json"}
PAGE = {"Accept": "text/html,application/xhtml+xml"}


def _token(make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["feedback_enabled"] = True
    return token


def _headers(token, accept):
    return {"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN, **accept}


def _form(token, **overrides):
    data = {
        "csrf_token": main._csrf_token(token),
        "type": "feature",
        "severity": "cosmetic",
        "title": "Export filter would help",
        "description": "Filtering the export <b>by owner</b> would save me time.",
        "route": "/devices",
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


def _hidden_csrf(page_html: str) -> str:
    match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page_html)
    assert match, "the re-rendered form must carry a CSRF token"
    return match.group(1)


# ── Every intake type submits; stale severity is never forwarded ─────────

@pytest.mark.parametrize(("feedback_type", "endpoint", "category"), [
    ("support", "/support", "not_working"),
    ("feature", "/feedback", None),
    ("design", "/feedback", None),
])
def test_each_feedback_type_submits(client, make_token, feedback_type, endpoint, category):
    token = _token(make_token)
    response = client.post(
        endpoint, data=_form(token, type=feedback_type, category=category, severity="cosmetic"),
        headers=_headers(token, JSON),
    )
    assert response.status_code == 201, response.text
    body = STUB_STATE["feedback_posts"][-1]["body"]
    assert f'name="type"\r\n\r\n{feedback_type}'.encode() in body
    assert b'name="severity"' not in body
    if category is None:
        assert b'name="category"' not in body
    else:
        assert f'name="category"\r\n\r\n{category}'.encode() in body


@pytest.mark.parametrize("feedback_type", ["feature", "design"])
def test_switching_from_bug_never_forwards_a_stale_severity(client, make_token, feedback_type):
    """The browser in production still sent severity=cosmetic after the
    customer switched away from Report a bug. Whatever the page sends, the
    platform must never receive a severity for a non-bug type."""
    token = _token(make_token)
    response = client.post(
        "/feedback", data=_form(token, type=feedback_type, severity="cosmetic"),
        headers=_headers(token, JSON),
    )
    assert response.status_code == 201, response.text
    assert b'name="severity"' not in STUB_STATE["feedback_posts"][-1]["body"]


def test_platform_refusal_reason_is_shown_to_the_customer(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_post_status"] = 400
    STUB_STATE["feedback_post_body"] = {
        "error": "invalid_feedback", "message": "Severity applies only to bug reports.",
    }
    response = client.post("/feedback", data=_form(token), headers=_headers(token, JSON))
    assert response.status_code == 502
    assert response.json()["error"] == "Severity applies only to bug reports."


# ── Expired page: the draft survives ─────────────────────────────────────

def test_expired_token_with_javascript_returns_a_fresh_token_for_a_retry(client, make_token):
    token = _token(make_token)
    response = client.post(
        "/feedback", data=_form(token, csrf_token="0" * 64), headers=_headers(token, JSON),
    )
    assert response.status_code == 403
    payload = response.json()
    assert payload["csrf_token"] == main._csrf_token(token)
    assert "has not been sent yet" in payload["error"]
    assert STUB_STATE["feedback_posts"] == []


def test_expired_token_without_javascript_rerenders_the_draft(client, make_token):
    token = _token(make_token)
    form = _form(token, csrf_token="0" * 64, type="feature", severity=None)
    response = client.post("/feedback", data=form, headers=_headers(token, PAGE))
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    page = response.text
    assert html.escape(form["title"]) in page
    # The description is escaped, never rendered as markup.
    assert html.escape(form["description"]) in page
    assert "<b>by owner</b>" not in page
    assert '<option value="feature" selected>' in page
    assert _hidden_csrf(page) == main._csrf_token(token)
    assert "has not been sent yet" in page
    assert STUB_STATE["feedback_posts"] == []


def test_expired_rerender_then_resubmit_succeeds(client, make_token):
    token = _token(make_token)
    expired = client.post(
        "/feedback", data=_form(token, csrf_token="0" * 64, type="design", severity=None),
        headers=_headers(token, PAGE),
    )
    fresh = _hidden_csrf(expired.text)
    sent = client.post(
        "/feedback", data=_form(token, csrf_token=fresh, type="design", severity=None),
        headers=_headers(token, PAGE), follow_redirects=False,
    )
    assert sent.status_code == 303
    assert sent.headers["location"] == "/requests?sent=1"
    assert len(STUB_STATE["feedback_posts"]) == 1


# ── Without JavaScript the form is still a working form ──────────────────

def test_feedback_page_renders_the_form_without_javascript(client, make_token):
    token = _token(make_token)
    response = client.get(
        "/feedback?route=/devices", headers={"Cf-Access-Jwt-Assertion": token},
    )
    assert response.status_code == 200
    page = response.text
    assert 'action="/feedback"' in page
    assert 'name="route" data-feedback-route value="/devices"' in page
    assert _hidden_csrf(page) == main._csrf_token(token)
    # The page is the form: the modal copy is not rendered a second time.
    assert 'id="feedback-dialog"' not in page


def test_feedback_page_refuses_a_non_path_route(client, make_token):
    token = _token(make_token)
    response = client.get(
        "/feedback?route=https://evil.example/", headers={"Cf-Access-Jwt-Assertion": token},
    )
    assert response.status_code == 200
    assert 'name="route" data-feedback-route value="/"' in response.text


def test_feedback_page_redirects_home_when_feedback_is_disabled(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = False
    response = client.get(
        "/feedback", headers={"Cf-Access-Jwt-Assertion": token}, follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_header_feedback_control_is_a_link_to_the_form_page(client, make_token):
    token = _token(make_token)
    page = client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token}).text
    assert re.search(r'<a [^>]*href="/feedback\?route=/devices"[^>]*data-feedback-open', page)


def test_submission_without_javascript_redirects_to_my_requests(client, make_token):
    token = _token(make_token)
    response = client.post(
        "/feedback", data=_form(token, type="feature", severity="cosmetic"),
        headers=_headers(token, PAGE), follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/requests?sent=1"
    assert b'name="severity"' not in STUB_STATE["feedback_posts"][-1]["body"]
    landing = client.get("/requests?sent=1", headers={"Cf-Access-Jwt-Assertion": token})
    assert "Feedback sent" in landing.text


def test_validation_error_without_javascript_keeps_the_draft(client, make_token):
    token = _token(make_token)
    response = client.post(
        "/feedback", data=_form(token, title="no"), headers=_headers(token, PAGE),
    )
    assert response.status_code == 422
    assert "Title must be between 5 and 120 characters." in response.text
    assert html.escape(_form(token)["description"]) in response.text
    assert '<option value="feature" selected>' in response.text
    assert 'name="severity"' not in response.text
    assert STUB_STATE["feedback_posts"] == []


def test_feedback_types_have_no_severity_without_javascript(client, make_token):
    """Both actual no-JavaScript forms omit severity; hidden fields still hide."""
    css = open("static/css/portal.css", encoding="utf-8").read()
    assert re.search(r"\.feedback-field\[hidden\]\s*\{\s*display:\s*none", css)
    token = _token(make_token)
    for feedback_type in ("feature", "design"):
        response = client.post(
            "/feedback", data=_form(token, type=feedback_type, title="no"),
            headers=_headers(token, PAGE),
        )
        assert response.status_code == 422
        assert '<form' in response.text and 'action="/feedback"' in response.text
        assert f'<option value="{feedback_type}" selected>' in response.text
        assert 'name="severity"' not in response.text
        assert 'data-feedback-severity' not in response.text
        assert 'name="category"' not in response.text
    assert STUB_STATE["feedback_posts"] == []
