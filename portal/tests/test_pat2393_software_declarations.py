"""PAT-2393 portal acceptance: pre-observation policy, safe proxy and honest UI.

Only the platform boundary is stubbed. JWT middleware, guarded forms, roles,
route handling and rendered templates are real. Database acceptance lives in
platform cmd/patched-api/software_declarations_pat2393_test.go.
"""
import copy
import re
from urllib.parse import urlencode

import pytest

import main
import upstream
from tests.conftest import STUB_STATE

DECLARATION_ID = "00000000-0000-4000-8000-000000002393"
ALIAS_ID = "00000000-0000-4000-8000-000000002394"
DECLARATION = {
    "id": DECLARATION_ID, "declaration_id": DECLARATION_ID,
    "name": "Synthetic unseen editor", "publisher": "Synthetic Publisher",
    "platform": "macos", "approval_state": "approved", "source": "portal",
    "identity_state": "unmatched", "observation_state": "not_observed",
    "observed_installation_count": 0, "outside_constraint_count": 0,
    "min_version": "2.0", "review_date": "2099-12-31",
    "justification": "Accepted before deployment", "approved_by": "admin@example.com",
    "approved_via": "portal", "approved_at": "2026-10-04T09:00:00Z",
}


@pytest.fixture
def declarations(client, monkeypatch):
    original_get = upstream.get_json
    calls = []
    row = copy.deepcopy(DECLARATION)

    def get(path, token, params=None):
        if path == "/v1/portal/software-declarations":
            calls.append(("GET", path, token, params))
            return {"total": 1, "declarations": [copy.deepcopy(row)]}
        if path == f"/v1/portal/software-declarations/{DECLARATION_ID}":
            return copy.deepcopy(row)
        if path == "/v1/portal/software-products":
            calls.append(("GET", path, token, params))
            return {"total": 1, "products": [{"alias_id": ALIAS_ID,
                    "canonical_name": "Synthetic known editor",
                    "vendor_name": "Synthetic Publisher",
                    "platform": "macos", "identity_kind": "macos_bundle_team",
                    "identity_value_normalized": "com.synthetic.editor",
                    "companion_value_normalized": "SYNTHETIC1"}]}
        if path == "/v1/portal/software/approved":
            return {"total": 1, "products": [copy.deepcopy(row)]}
        return original_get(path, token, params=params)

    def post(path, token, payload=None):
        calls.append(("POST", path, token, copy.deepcopy(payload)))
        assert path in {"/v1/portal/software-declarations",
                        f"/v1/portal/software-declarations/{DECLARATION_ID}/resolve"}
        return copy.deepcopy(row)

    monkeypatch.setattr(upstream, "get_json", get)
    monkeypatch.setattr(upstream, "post_json", post)
    return row, calls


def headers(token):
    return {"Cf-Access-Jwt-Assertion": token}


def submit(client, token, path="/software/add", *, csrf=True,
           origin="https://testserver", **changes):
    fields = {"name": DECLARATION["name"], "publisher": DECLARATION["publisher"],
              "platform": "macos", "justification": "Accepted before deployment",
              "min_version": "2.0", "review_date": "2099-12-31"}
    fields.update(changes)
    if csrf:
        fields["csrf_token"] = main._csrf_token(token)
    return client.post(path, content=urlencode(fields), follow_redirects=False,
                       headers={**headers(token), "Origin": origin,
                                "Content-Type": "application/x-www-form-urlencoded"})


def writes(calls):
    return [c for c in calls if c[0] == "POST"]


def test_admin_can_open_add_form_from_software(client, make_token, declarations):
    token = make_token()
    page = client.get("/software", headers=headers(token))
    assert page.status_code == 200
    assert 'href="/software/add"' in page.text
    assert "Add approved software" in page.text
    form = client.get("/software/add", headers=headers(token))
    assert form.status_code == 200
    for field in ("name", "publisher", "platform", "justification", "min_version", "review_date"):
        assert f'name="{field}"' in form.text
    assert "Minimum approved version" in form.text
    assert main._csrf_token(token) in form.text


def test_known_product_search_uses_curated_alias_id(client, make_token, declarations):
    token = make_token()
    page = client.get("/software/add?query=Synthetic&platform=macos", headers=headers(token))
    assert page.status_code == 200
    assert "Synthetic known editor" in page.text
    assert ALIAS_ID in page.text
    assert any(c[1] == "/v1/portal/software-products" and c[2] == token
               for c in declarations[1])


def test_declared_policy_renders_with_zero_observed_count(client, make_token, declarations):
    page = client.get("/software?decision=approved", headers=headers(make_token()))
    assert page.status_code == 200
    assert DECLARATION["name"] in page.text
    rows = re.findall(r"<tr\b[^>]*>.*?</tr>", page.text, flags=re.S)
    row, = [r for r in rows if DECLARATION["name"] in r]
    assert "Not observed" in row
    assert "Identity not yet matched" in row
    assert re.search(r">\s*0\s*<", row), "explicit zero observed count missing"
    assert "Declared" in row
    assert "Synthetic Publisher" in row


def test_create_forwards_only_declared_policy_and_verified_jwt(client, make_token, declarations):
    token = make_token()
    response = submit(client, token)
    assert response.status_code == 303, response.text
    call, = writes(declarations[1])
    assert call == ("POST", "/v1/portal/software-declarations", token, {
        "name": DECLARATION["name"], "publisher": DECLARATION["publisher"],
        "platform": "macos", "justification": "Accepted before deployment",
        "min_version": "2.0", "review_date": "2099-12-31"})
    assert response.headers["location"].startswith("/software")


@pytest.mark.parametrize("extra", [{"tenant_id": "other"}, {"actor_email": "forged@example.com"},
                                  {"publisher_key": "forged"}, {"identity_state": "matched"}])
def test_forged_scope_actor_or_trust_never_reaches_platform(
        client, make_token, declarations, extra):
    response = submit(client, make_token(), **extra)
    assert response.status_code == 400
    assert not writes(declarations[1])


@pytest.mark.parametrize("path", [
    "/software/add", f"/software/declarations/{DECLARATION_ID}/resolve"])
@pytest.mark.parametrize("guard", ["csrf", "origin", "viewer", "stale_role"])
def test_new_writes_preserve_guards(client, make_token, declarations, path, guard):
    token = make_token()
    if guard == "stale_role":
        assert client.get("/software", headers=headers(token)).status_code == 200
    if guard in {"viewer", "stale_role"}:
        STUB_STATE["portal_role"] = "viewer"
    response = submit(client, token, path, csrf=guard != "csrf",
                      origin="https://other.invalid" if guard == "origin" else "https://testserver")
    assert response.status_code == 403
    assert not writes(declarations[1])


def test_viewer_sees_policy_without_add_control(client, make_token, declarations):
    STUB_STATE["portal_role"] = "viewer"
    page = client.get("/software?decision=approved", headers=headers(make_token()))
    assert page.status_code == 200
    assert DECLARATION["name"] in page.text
    assert 'href="/software/add"' not in page.text


def test_resolution_forwards_alias_and_reason_only(client, make_token, declarations):
    token = make_token()
    path = f"/software/declarations/{DECLARATION_ID}/resolve"
    response = client.post(path, content=urlencode({"alias_id": ALIAS_ID,
        "justification": "Verified curated tuple", "csrf_token": main._csrf_token(token)}),
        headers={**headers(token), "Origin": "https://testserver",
                 "Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    assert response.status_code == 303
    call, = writes(declarations[1])
    assert call == ("POST", f"/v1/portal/software-declarations/{DECLARATION_ID}/resolve", token,
                    {"alias_id": ALIAS_ID, "justification": "Verified curated tuple"})


def test_new_pages_require_verified_jwt(client, declarations):
    for path in ("/software/add", f"/software/declarations/{DECLARATION_ID}"):
        assert client.get(path).status_code == 401
    assert not writes(declarations[1])


def test_declared_names_are_escaped(client, make_token, declarations):
    declarations[0]["name"] = '<img src=x onerror="alert(1)">'
    page = client.get("/software?decision=approved", headers=headers(make_token()))
    assert page.status_code == 200
    assert "&lt;img" in page.text
    assert '<img src=x onerror="alert(1)">' not in page.text
