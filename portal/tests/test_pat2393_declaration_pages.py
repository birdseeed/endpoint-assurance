"""PAT-2393 portal: detail page, refusals, no existence leak, no raw platform text.

Complements tests/test_pat2393_software_declarations.py (frozen). Only the
platform boundary is stubbed.
"""
import copy
from urllib.parse import urlencode

import pytest

import main
import upstream
from tests.conftest import STUB_STATE

DECLARATION_ID = "00000000-0000-4000-8000-000000002393"
ALIAS_ID = "00000000-0000-4000-8000-000000002394"
ROW = {
    "id": DECLARATION_ID, "name": "Synthetic unseen editor",
    "publisher": "Synthetic Publisher", "platform": "macos",
    "approval_state": "approved", "source": "portal", "identity_state": "unmatched",
    "observation_state": "not_observed", "observed_installation_count": 0,
    "min_version": "2.0", "review_date": "2099-12-31",
    "justification": "Accepted before deployment", "approved_by": "admin@example.com",
    "approved_at": "2026-10-04T09:00:00Z",
}
HISTORY = {"decisions": [{"action": "created", "actor_email": "admin@example.com",
                          "decided_at": "2026-10-04T09:00:00Z",
                          "justification": "Accepted before deployment"}]}


@pytest.fixture
def platform(client, monkeypatch):
    state = {"row": copy.deepcopy(ROW), "get_error": None, "post_error": None,
             "posts": [], "list": None}
    original_get = upstream.get_json

    def get(path, token, params=None):
        if state["get_error"] and path.startswith("/v1/portal/software-declarations/"):
            raise state["get_error"]
        if path == "/v1/portal/software-declarations":
            rows = state["list"] if state["list"] is not None else [state["row"]]
            return {"total": len(rows), "declarations": copy.deepcopy(rows)}
        if path == f"/v1/portal/software-declarations/{DECLARATION_ID}":
            return copy.deepcopy(state["row"])
        if path == f"/v1/portal/software-declarations/{DECLARATION_ID}/history":
            return copy.deepcopy(HISTORY)
        if path == "/v1/portal/software-products":
            return {"products": [{"alias_id": ALIAS_ID, "canonical_name": "Known editor",
                                  "vendor_name": "Synthetic Publisher", "platform": "macos"}]}
        return original_get(path, token, params=params)

    def post(path, token, payload=None):
        state["posts"].append((path, token, copy.deepcopy(payload)))
        if state["post_error"]:
            raise state["post_error"]
        return {}

    monkeypatch.setattr(upstream, "get_json", get)
    monkeypatch.setattr(upstream, "post_json", post)
    return state


def hdr(token):
    return {"Cf-Access-Jwt-Assertion": token}


def post_form(client, token, path, fields):
    fields = dict(fields, csrf_token=main._csrf_token(token))
    return client.post(path, content=urlencode(fields), follow_redirects=False,
                       headers={**hdr(token), "Origin": "https://testserver",
                                "Content-Type": "application/x-www-form-urlencoded"})


CREATE = {"name": "Synthetic unseen editor", "publisher": "Synthetic Publisher",
          "platform": "macos", "justification": "Accepted before deployment"}


def test_detail_shows_history_and_the_match_form_for_an_admin(client, make_token, platform):
    page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    assert page.status_code == 200
    assert "Not observed" in page.text and "Identity not yet matched" in page.text
    assert "Accepted before deployment" in page.text
    assert f'action="/software/declarations/{DECLARATION_ID}/resolve"' in page.text
    assert ALIAS_ID in page.text
    assert "does not show that the software is installed" in page.text


def test_detail_hides_the_match_form_from_a_viewer(client, make_token, platform):
    STUB_STATE["portal_role"] = "viewer"
    page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    assert page.status_code == 200
    assert "/resolve" not in page.text


@pytest.mark.parametrize("kind,status", [("not_found", 404), ("forbidden", 403),
                                         ("invalid", 400)])
def test_other_tenants_or_unknown_declaration_reads_as_not_found(
        client, make_token, platform, kind, status):
    platform["get_error"] = upstream.UpstreamError(kind, "x", status=status)
    page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    assert page.status_code == 404
    assert "could not be found" in page.text
    assert "linked" not in page.text.lower()


def test_malformed_declaration_id_is_not_found_without_a_platform_call(
        client, make_token, platform):
    page = client.get("/software/declarations/not-a-uuid", headers=hdr(make_token()))
    assert page.status_code == 404


def test_resolve_on_another_tenants_declaration_is_not_found(client, make_token, platform):
    platform["post_error"] = upstream.UpstreamError("forbidden", "x", status=403)
    token = make_token()
    response = post_form(client, token, f"/software/declarations/{DECLARATION_ID}/resolve",
                         {"alias_id": ALIAS_ID, "justification": "Verified"})
    assert response.status_code == 404


@pytest.mark.parametrize("status,fragment", [(409, "already approved"), (422, "could not be used")])
def test_platform_refusal_text_is_fixed_and_never_reflected(
        client, make_token, platform, status, fragment):
    body = '{"message":"<script>alert(1)</script> secret"}'
    platform["post_error"] = upstream.UpstreamError("error", "x", status=status, body=body)
    response = post_form(client, make_token(), "/software/add", CREATE)
    assert response.status_code == status
    assert fragment in response.text
    assert "<script>alert(1)" not in response.text
    assert "secret" not in response.text
    assert 'value="Synthetic unseen editor"' in response.text  # draft kept, escaped


@pytest.mark.parametrize("change", [
    {"alias_id": "not-a-uuid"}, {"review_date": "2099-13-45"}, {"review_date": "31/12/2099"},
    {"platform": "linux"}, {"name": ""}, {"justification": ""}])
def test_invalid_create_input_never_reaches_the_platform(client, make_token, platform, change):
    response = post_form(client, make_token(), "/software/add", {**CREATE, **change})
    assert response.status_code == 400
    assert not platform["posts"]


def test_repeated_fields_are_refused(client, make_token, platform):
    token = make_token()
    body = urlencode(list(CREATE.items()) + [("name", "Second"),
                                            ("csrf_token", main._csrf_token(token))])
    response = client.post("/software/add", content=body, follow_redirects=False,
                           headers={**hdr(token), "Origin": "https://testserver",
                                    "Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert not platform["posts"]


@pytest.mark.parametrize("extra", [{"tenant_id": "x"}, {"actor_email": "x@example.com"},
                                  {"team_id": "ABCDE12345"}])
def test_resolve_refuses_client_supplied_scope_or_trust(client, make_token, platform, extra):
    response = post_form(client, make_token(),
                         f"/software/declarations/{DECLARATION_ID}/resolve",
                         {"alias_id": ALIAS_ID, "justification": "Verified", **extra})
    assert response.status_code == 400
    assert not platform["posts"]


def test_resolve_with_a_bad_alias_makes_no_write(client, make_token, platform):
    response = post_form(client, make_token(),
                         f"/software/declarations/{DECLARATION_ID}/resolve",
                         {"alias_id": "nope", "justification": "Verified"})
    assert response.status_code == 303
    assert not platform["posts"]


def test_add_form_is_refused_for_a_viewer(client, make_token, platform):
    STUB_STATE["portal_role"] = "viewer"
    assert client.get("/software/add", headers=hdr(make_token())).status_code == 403


def test_observed_declarations_are_not_listed_as_not_observed(client, make_token, platform):
    observed = {**ROW, "observation_state": "observed", "observed_installation_count": 3}
    platform["list"] = [observed]
    page = client.get("/software", headers=hdr(make_token()))
    assert page.status_code == 200
    assert "Approved before it was seen" not in page.text


def test_declaration_list_failure_is_said_not_silent(client, make_token, platform, monkeypatch):
    original = upstream.get_json

    def failing(path, token, params=None):
        if path == "/v1/portal/software-declarations":
            raise upstream.UpstreamError("unavailable", "x")
        return original(path, token, params=params)

    monkeypatch.setattr(upstream, "get_json", failing)
    page = client.get("/software", headers=hdr(make_token()))
    assert page.status_code == 200
    assert "could not be loaded just now" in page.text


def test_success_redirect_carries_a_signed_notice(client, make_token, platform):
    token = make_token()
    response = post_form(client, token, "/software/add", CREATE)
    assert response.status_code == 303
    page = client.get(response.headers["location"], headers=hdr(token))
    assert "Approved software added" in page.text


# The same flows against the real stub platform (no monkeypatching), so the
# stub in tests/conftest.py is held to the contract too.

def test_stub_platform_create_list_resolve_roundtrip(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    created = post_form(client, token, "/software/add", {**CREATE, "min_version": "2.0"})
    assert created.status_code == 303
    listing = client.get("/software", headers=hdr(token))
    assert "Approved before it was seen" in listing.text
    declaration_id = STUB_STATE["declarations"][0]["id"]
    detail = client.get(f"/software/declarations/{declaration_id}?query=Synthetic",
                        headers=hdr(token))
    assert "Accepted before deployment" in detail.text
    assert ALIAS_ID in detail.text
    resolved = post_form(client, token, f"/software/declarations/{declaration_id}/resolve",
                         {"alias_id": ALIAS_ID, "justification": "Verified"})
    assert resolved.status_code == 303
    assert STUB_STATE["declarations"][0]["identity_state"] == "matched"
    again = post_form(client, token, f"/software/declarations/{declaration_id}/resolve",
                      {"alias_id": ALIAS_ID, "justification": "Verified"})
    follow = client.get(again.headers["location"], headers=hdr(token))
    assert "already been matched" in follow.text


def test_stub_platform_duplicate_create_is_refused_with_fixed_text(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    assert post_form(client, token, "/software/add", CREATE).status_code == 303
    second = post_form(client, token, "/software/add", CREATE)
    assert second.status_code == 409
    assert "already approved" in second.text


def test_stub_platform_unknown_declaration_is_not_found(client, make_token):
    token = make_token()
    page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(token))
    assert page.status_code == 404


def test_stub_platform_search_with_any_platform_lists_both_platforms(client, make_token):
    # The platform refuses a product lookup without a platform, so "Any" has
    # to become one lookup per platform. Found in production on 2026-10-04:
    # the search said the lookup was unavailable for every "Any" search.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    page = client.get("/software/add?query=Synthetic&platform=", headers=hdr(token))
    assert page.status_code == 200
    assert "Synthetic known editor" in page.text
    assert "Synthetic known browser" in page.text
    assert "not available right now" not in page.text
    one = client.get("/software/add?query=Synthetic&platform=windows", headers=hdr(token))
    assert "Synthetic known browser" in one.text
    assert "Synthetic known editor" not in one.text
