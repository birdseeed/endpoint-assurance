"""Additional context and read-only controls for the shared customer intake."""

# Imported pytest fixtures are intentionally injected by name.
# ruff: noqa: F811

from urllib.parse import urlsplit

import pytest

from tests.conftest import STUB_STATE, StubPlatformHandler
from tests.test_support_feedback_doors_acceptance import (
    Page,
    form,
    headers,
    intake,  # noqa: F401
    make_service_token,  # noqa: F401
    parts,
    service_on,  # noqa: F401
    text_part,
)


@pytest.mark.parametrize("description", ["x", "x" * 5000, "A very long description " * 200])
def test_description_only_support_title_satisfies_backend_bounds(client, intake, description):
    token, _ = intake
    response = client.post("/support", data=form(token, "support", description=description),
                           headers=headers(token, json=True))
    assert response.status_code == 201
    fields = parts()
    assert 5 <= len(text_part(fields, "title")) <= 120
    assert text_part(fields, "description") == description.strip()


@pytest.mark.parametrize("status", [404, 500, 403])
def test_device_context_is_revalidated_on_post_and_cannot_bypass_missing_access(
        client, intake, monkeypatch, status):
    token, _ = intake
    path = "/devices/dev-mac-001"
    initial = client.get("/support", params={"route": path}, headers=headers(token))
    assert "acme-mbp-frontdesk" in initial.text
    original = StubPlatformHandler.do_GET

    def gone(handler):
        if urlsplit(handler.path).path == "/v1/portal/devices/dev-mac-001":
            return handler._send(status, {"error": "synthetic device no longer accessible"})
        return original(handler)

    monkeypatch.setattr(StubPlatformHandler, "do_GET", gone)
    response = client.post("/support", data=form(token, "support", route=path),
                           headers=headers(token, json=True))
    assert response.status_code == (403 if status == 403 else 502)
    assert STUB_STATE["feedback_posts"] == []


def test_device_context_sends_only_validated_route_and_strips_query(client, intake):
    token, _ = intake
    response = client.post("/support", data=form(
        token, "support", route="/devices/dev-mac-001?tenant_id=untrusted#private",
        device_id="untrusted", reporter_email="untrusted@example.com"),
        headers=headers(token, json=True))
    assert response.status_code == 201
    fields = parts()
    assert text_part(fields, "route") == "/devices/dev-mac-001"
    assert not {"device_id", "reporter_email", "tenant_id", "actor"} & fields.keys()


@pytest.mark.parametrize("route", ["/invented", "//evil.example/", "/devices/not-in-estate"])
def test_unvalidated_support_route_never_reaches_intake(client, intake, route):
    token, _ = intake
    response = client.post("/support", data=form(token, "support", route=route),
                           headers=headers(token, json=True))
    assert response.status_code in {422, 502}
    assert STUB_STATE["feedback_posts"] == []


@pytest.mark.parametrize("status", [404, 503])
def test_unavailable_support_list_is_not_an_empty_success(client, intake, status):
    token, _ = intake
    STUB_STATE["feedback_status"] = status
    response = client.get("/support", headers=headers(token))
    assert response.status_code == 200
    assert "Support requests are unavailable" in response.text
    assert "No support requests sent yet" not in response.text
    assert any(a.get("href", "").startswith("mailto:") for a in Page(response.text).links)


@pytest.mark.parametrize("path", ["/support", "/feedback", "/requests"])
def test_readonly_identity_sees_lists_but_no_submission_controls(
        client, intake, service_on, make_service_token, path):
    token = make_service_token()
    STUB_STATE["expected_jwt"] = token
    response = client.get(path, headers=headers(token))
    assert response.status_code == 200
    assert not any(f["attrs"].get("action") in {"/support", "/feedback"}
                   for f in Page(response.text).forms)
    assert "data-feedback-open" not in response.text
