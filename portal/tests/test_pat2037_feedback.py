"""PAT-2037: customer feedback is a guarded, stateless platform proxy."""

import asyncio

import pytest
from starlette.requests import Request

import main
from tests.conftest import STUB_STATE

ORIGIN = "https://testserver"


def _headers(token):
    # The modal's fetch sends Accept: application/json and gets the JSON
    # contract; a plain form post gets pages instead (PAT-2216).
    return {"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN, "Accept": "application/json"}


def _form(token, **overrides):
    data = {
        "csrf_token": main._csrf_token(token),
        "type": "feature",
        "severity": "blocking",
        "title": "A useful bug title",
        "description": "The filter does not update after I choose a value.",
        "route": "/software?type=application",
    }
    data.update(overrides)
    return data


def _token(make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    return token


def _feedback_guard_refusal(headers):
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request({
        "type": "http", "http_version": "1.1", "method": "POST",
        "scheme": "https", "path": "/feedback", "raw_path": b"/feedback",
        "query_string": b"", "client": ("testclient", 50000),
        "server": ("testserver", 443),
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
    }, receive)
    form, refusal = asyncio.run(main._guarded_feedback_form(request))
    # PAT-2216: an expired token is the one refusal that keeps the parsed
    # form, so the customer's draft can be handed back.
    assert (form is not None) == refusal.expired
    return refusal


def test_feedback_404_hides_optional_controls_and_requests_page(client, make_token):
    token = _token(make_token)
    page = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert page.status_code == 200
    assert "data-feedback-open" not in page.text
    assert 'href="/requests"' not in page.text

    response = client.get(
        "/requests", headers={"Cf-Access-Jwt-Assertion": token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


@pytest.mark.parametrize(("headers", "status", "message"), [
    ({"host": "testserver", "origin": ORIGIN}, 411,
     "That feedback could not be read. Reload the page and try again."),
    ({"host": "testserver", "origin": ORIGIN, "content-length": "not-a-number"}, 400,
     "That feedback could not be read."),
    ({"host": "testserver", "origin": ORIGIN,
      "content-length": str(main.FEEDBACK_UPLOAD_MAX_BYTES + 1)}, 413,
     "Screenshots up to 5 MiB are accepted."),
    ({"host": "testserver", "origin": "https://evil.example", "content-length": "0"}, 403,
     main._STATE_CHANGE_ORIGIN_REFUSAL),
    ({"host": "testserver", "origin": ORIGIN, "content-length": "0"}, 403,
     main._FEEDBACK_EXPIRED_REFUSAL),
])
def test_feedback_guard_refusals_carry_status_and_customer_message(headers, status, message):
    refusal = _feedback_guard_refusal(headers)
    assert refusal.status == status
    assert refusal.message == message


@pytest.mark.parametrize(("platform_status", "expected_status", "heading"), [
    (401, 401, "Session expired"),
    (403, 403, "Account not linked"),
])
def test_feedback_discovery_preserves_auth_and_unlinked_account_responses(
    client, make_token, platform_status, expected_status, heading
):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    STUB_STATE["feedback_status"] = platform_status
    response = client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == expected_status
    assert heading in response.text


@pytest.mark.parametrize("platform_status", [404, 429, 500, 503])
def test_feedback_discovery_keeps_optional_failures_out_of_the_page(
    client, make_token, platform_status
):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    STUB_STATE["feedback_status"] = platform_status
    response = client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == 200
    assert "data-feedback-open" not in response.text


def test_feedback_availability_uses_a_bounded_ttl_cache_and_expires(
    client, make_token, monkeypatch
):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = False
    first = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    second = client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token})
    assert "data-feedback-open" not in first.text
    assert "data-feedback-open" not in second.text
    assert STUB_STATE["feedback_gets"] == 1

    # A platform enablement is discovered on expiry, without a process restart.
    STUB_STATE["feedback_enabled"] = True
    monkeypatch.setattr(main, "FEEDBACK_UNAVAILABLE_CACHE_TTL_SECONDS", 0)
    refreshed = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert "data-feedback-open" in refreshed.text
    assert STUB_STATE["feedback_gets"] == 2


def test_feedback_availability_cache_selects_ttls_by_cached_state(
    client, make_token, monkeypatch
):
    token = _token(make_token)
    monkeypatch.setattr(main, "FEEDBACK_AVAILABLE_CACHE_TTL_SECONDS", 0)
    monkeypatch.setattr(main, "FEEDBACK_UNAVAILABLE_CACHE_TTL_SECONDS", 60)

    STUB_STATE["feedback_enabled"] = True
    client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token})
    assert STUB_STATE["feedback_gets"] == 2

    main._clear_feedback_availability_cache()
    STUB_STATE["feedback_enabled"] = False
    client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token})
    assert STUB_STATE["feedback_gets"] == 3


def test_requests_and_submit_refresh_availability_without_a_second_discovery(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    requests_page = client.get("/requests", headers={"Cf-Access-Jwt-Assertion": token})
    assert requests_page.status_code == 200
    assert STUB_STATE["feedback_gets"] == 1
    portal_page = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert "data-feedback-open" in portal_page.text
    assert STUB_STATE["feedback_gets"] == 1

    main._clear_feedback_availability_cache()
    response = client.post("/feedback", data=_form(token), headers=_headers(token))
    assert response.status_code == 201
    assert STUB_STATE["feedback_gets"] == 1
    client.get("/devices", headers={"Cf-Access-Jwt-Assertion": token})
    assert STUB_STATE["feedback_gets"] == 1


def test_feedback_availability_cache_reset_is_deterministic(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert STUB_STATE["feedback_gets"] == 1
    main._clear_feedback_availability_cache()
    client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert STUB_STATE["feedback_gets"] == 2


def test_feedback_forwards_canonical_multipart_and_omits_stale_severity(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    response = client.post(
        "/feedback", data=_form(token),
        files={"screenshot": ("before.png", b"png bytes", "image/png")},
        headers=_headers(token),
    )
    assert response.status_code == 201
    assert response.json() == {"reference": "FB-0001"}
    post = STUB_STATE["feedback_posts"][-1]
    assert "multipart/form-data" in post["content_type"]
    assert post["portal_build"] == main.PORTAL_BUILD
    assert post["user_agent"]
    assert b'name="route"' in post["body"]
    assert b"/software?type=application" in post["body"]
    assert b'name="severity"' not in post["body"]
    assert b"critical" not in post["body"]
    assert b'name="screenshot"; filename="before.png"' in post["body"]


def test_feedback_without_screenshot_is_still_sent_as_multipart(client, make_token):
    """PAT-2233: a text-only report is the common case. With no screenshot
    the portal must still send multipart, because the platform parses only
    multipart; urlencoded failed every such submission in production."""
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    response = client.post("/feedback", data=_form(token), headers=_headers(token))
    assert response.status_code == 201, response.text
    post = STUB_STATE["feedback_posts"][-1]
    assert "multipart/form-data" in post["content_type"]
    assert b'name="title"' in post["body"]
    assert b'name="screenshot"' not in post["body"]


def test_feedback_validation_and_429_keep_the_client_form_unmodified(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    invalid = client.post(
        "/feedback", data=_form(token, title="no"), headers=_headers(token)
    )
    assert invalid.status_code == 422
    assert "Title must be" in invalid.json()["error"]
    assert STUB_STATE["feedback_posts"] == []

    STUB_STATE["feedback_post_status"] = 429
    limited = client.post("/feedback", data=_form(token), headers=_headers(token))
    assert limited.status_code == 429
    assert "wait" in limited.json()["error"].lower()


def test_feedback_rejects_non_image_and_oversize_screenshot(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    wrong_type = client.post(
        "/feedback", data=_form(token),
        files={"screenshot": ("notes.txt", b"not an image", "text/plain")}, headers=_headers(token),
    )
    assert wrong_type.status_code == 422
    assert "PNG or JPEG" in wrong_type.json()["error"]

    too_large = client.post(
        "/feedback", data=_form(token),
        files={"screenshot": (
            "large.png", b"x" * (main.FEEDBACK_SCREENSHOT_MAX_BYTES + 1), "image/png",
        )},
        headers=_headers(token),
    )
    assert too_large.status_code == 413, too_large.text
    assert STUB_STATE["feedback_posts"] == []


def test_customer_support_categories_have_only_the_contract_backed_mapping(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    for category in ("not_working", "findings_or_reports", "account_billing"):
        response = client.post(
            "/support", data=_form(token, type="support", category=category),
            headers=_headers(token),
        )
        assert response.status_code == 201, response.text
        body = STUB_STATE["feedback_posts"][-1]["body"]
        assert b'name="type"\r\n\r\nsupport' in body
        assert f'name="category"\r\n\r\n{category}'.encode() in body
        assert b'name="severity"' not in body
    before = len(STUB_STATE["feedback_posts"])
    refused = client.post(
        "/support", data=_form(token, type="support", category="other"), headers=_headers(token),
    )
    assert refused.status_code == 422
    assert len(STUB_STATE["feedback_posts"]) == before


def test_requests_map_platform_statuses_to_customer_labels(client, make_token):
    token = _token(make_token)
    STUB_STATE["feedback_enabled"] = True
    STUB_STATE["feedback_rows"] = [
        {
            "reference": "FB-1", "type": "feature", "title": "One", "status": "received",
            "created_at": "2026-09-27T10:00:00Z", "last_status_change": "2026-09-27T10:00:00Z",
        },
        {
            "reference": "FB-2", "type": "feature", "title": "Two", "status": "on_the_roadmap",
            "created_at": "2026-09-27T10:00:00Z", "last_status_change": "2026-09-27T10:00:00Z",
        },
        {
            "reference": "FB-3", "type": "design", "title": "Three", "status": "closed_merged",
            "created_at": "2026-09-27T10:00:00Z", "last_status_change": "2026-09-27T10:00:00Z",
        },
    ]
    response = client.get("/requests", headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == 200
    assert "Received" in response.text
    assert "On the roadmap" in response.text
    assert "Closed" in response.text
