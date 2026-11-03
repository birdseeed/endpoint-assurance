"""PAT-2404: no product search is offered while the platform has nothing to match to.

An empty catalogue and an unreadable one both mean "nothing to offer", so the
Add approved software page drops its lookup card and the declaration page
replaces its match card with a plain statement. Adding by name is unchanged.
Only the platform boundary is stubbed.
"""
import copy
from urllib.parse import urlencode

import pytest

import main
import upstream
from tests import conftest
from tests.conftest import STUB_STATE

DECLARATION_ID = "00000000-0000-4000-8000-000000002404"
ALIAS_ID = "00000000-0000-4000-8000-000000002394"
ROW = {
    "id": DECLARATION_ID, "name": "Synthetic unseen editor",
    "publisher": "Synthetic Publisher", "platform": "macos",
    "approval_state": "approved", "source": "portal", "identity_state": "unmatched",
    "observation_state": "not_observed", "observed_installation_count": 0,
    "justification": "Accepted before deployment", "approved_by": "admin@example.com",
    "approved_at": "2026-10-04T09:00:00Z",
}
PRODUCT = {"alias_id": ALIAS_ID, "canonical_name": "Known editor",
           "vendor_name": "Synthetic Publisher", "platform": "macos"}
# One lookup per platform; a failing one stops the check at the first.
CHECK_CALLS = {"empty": ["macos", "windows"], "fail": ["macos"]}
STATEMENT = "Not yet matched to a known product"


@pytest.fixture
def lookup(client, monkeypatch):
    """mode: "empty" (no products), "fail" (the platform answers 500) or
    "some". `calls` records every software-products lookup."""
    state = {"mode": "empty", "calls": [], "posts": []}
    original_get = upstream.get_json

    def get(path, token, params=None):
        if path == "/v1/portal/software-products":
            state["calls"].append(dict(params or {}))
            if state["mode"] == "fail":
                raise upstream.UpstreamError("error", "x", status=500)
            if state["mode"] == "empty":
                return {"total": 0, "products": []}
            return {"products": [PRODUCT]}
        if path == f"/v1/portal/software-declarations/{DECLARATION_ID}":
            return copy.deepcopy(ROW)
        if path == f"/v1/portal/software-declarations/{DECLARATION_ID}/history":
            return {"decisions": []}
        return original_get(path, token, params=params)

    def post(path, token, payload=None):
        state["posts"].append((path, copy.deepcopy(payload)))
        return {}

    monkeypatch.setattr(upstream, "get_json", get)
    monkeypatch.setattr(upstream, "post_json", post)
    return state


def hdr(token):
    return {"Cf-Access-Jwt-Assertion": token}


def assert_no_lookup_card(page):
    assert page.status_code == 200
    assert "Approval details" in page.text and 'action="/software/add"' in page.text
    assert "Look up a known product" not in page.text
    assert 'name="query"' not in page.text
    assert 'method="get" action="/software/add"' not in page.text
    assert "Use this product" not in page.text


def assert_statement_only(page):
    assert page.status_code == 200
    assert STATEMENT in page.text
    assert "stands as recorded" in page.text
    assert "Match to a known product" not in page.text
    assert 'name="query"' not in page.text
    assert "/resolve" not in page.text
    assert 'name="alias_id"' not in page.text


@pytest.mark.parametrize("mode", ["empty", "fail"])
def test_add_page_has_no_lookup_card_with_nothing_to_offer(client, make_token, lookup, mode):
    lookup["mode"] = mode
    assert_no_lookup_card(client.get("/software/add", headers=hdr(make_token())))


@pytest.mark.parametrize("mode", ["empty", "fail"])
def test_add_page_ignores_query_platform_and_alias_id(client, make_token, lookup, mode):
    lookup["mode"] = mode
    query = urlencode({"query": "Synthetic", "platform": "windows", "alias_id": ALIAS_ID})
    page = client.get(f"/software/add?{query}", headers=hdr(make_token()))
    assert_no_lookup_card(page)
    assert 'name="alias_id"' not in page.text
    assert "Using the known product" not in page.text
    assert 'value="Synthetic' not in page.text
    assert 'value="Known editor"' not in page.text
    assert '<option value="windows" selected>' not in page.text
    # Only the one "anything to offer?" check ran: one lookup per platform.
    assert [c["platform"] for c in lookup["calls"]] == CHECK_CALLS[mode]
    assert all(c["query"] == "" for c in lookup["calls"])


@pytest.mark.parametrize("mode", ["empty", "fail"])
def test_declaration_page_replaces_the_match_card_with_a_statement(
        client, make_token, lookup, mode):
    lookup["mode"] = mode
    page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    assert_statement_only(page)
    assert "approval of Synthetic unseen editor stands as recorded" in page.text
    assert [c["platform"] for c in lookup["calls"]] == CHECK_CALLS[mode]


def test_declaration_page_does_not_check_for_a_viewer(client, make_token, lookup):
    STUB_STATE["portal_role"] = "viewer"
    page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    assert page.status_code == 200
    assert STATEMENT not in page.text and "/resolve" not in page.text
    assert lookup["calls"] == []


def test_declaration_page_does_not_check_for_a_matched_declaration(
        client, make_token, lookup, monkeypatch):
    original = copy.deepcopy(ROW)
    ROW["identity_state"] = "matched"
    try:
        page = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    finally:
        ROW.clear()
        ROW.update(original)
    assert page.status_code == 200
    assert STATEMENT not in page.text and "/resolve" not in page.text
    assert lookup["calls"] == []


def test_pages_are_unchanged_when_there_are_products(client, make_token, lookup):
    lookup["mode"] = "some"
    add = client.get("/software/add", headers=hdr(make_token()))
    assert "Look up a known product" in add.text and 'name="query"' in add.text
    detail = client.get(f"/software/declarations/{DECLARATION_ID}", headers=hdr(make_token()))
    assert "Match to a known product" in detail.text and STATEMENT not in detail.text
    assert f'action="/software/declarations/{DECLARATION_ID}/resolve"' in detail.text


def test_adding_by_name_still_works_with_nothing_to_offer(client, make_token, monkeypatch):
    monkeypatch.setattr(conftest, "DECLARATION_PRODUCTS", [])
    token = make_token()
    fields = {"name": "Synthetic by name", "publisher": "Synthetic Publisher",
              "platform": "macos", "justification": "Accepted before deployment",
              "csrf_token": main._csrf_token(token)}
    response = client.post(
        "/software/add", content=urlencode(fields), follow_redirects=False,
        headers={**hdr(token), "Origin": "https://testserver",
                 "Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 303
    page = client.get("/software", headers=hdr(token))
    assert "Synthetic by name" in page.text
