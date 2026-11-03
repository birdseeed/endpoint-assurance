"""PAT-2407: the one-off install token (POST /install/enrolment) is admin only.

The platform now answers 403 admin_role_required to a non-admin on
POST /v1/portal/enrolment. The portal refuses a non-admin itself, before
any upstream mint call (same gate and position as the estate enrolment key
create route), and still shows the same refusal if the platform says 403
because the role changed between page load and submit.
"""

import main
from tests.conftest import ENROLMENT_TOKEN, STUB_STATE

ORIGIN = "https://testserver"
REFUSAL = "Only an administrator on your account can generate an install token."


def _get(client, token, path="/install"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _post(client, token, csrf=True):
    STUB_STATE["expected_jwt"] = token
    data = {"csrf_token": main._csrf_token(token)} if csrf else {}
    return client.post(
        "/install/enrolment", data=data, follow_redirects=False,
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN})


def test_viewer_post_is_refused_with_no_upstream_mint(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _post(client, make_token())
    assert resp.status_code == 403
    assert REFUSAL in resp.text
    assert ENROLMENT_TOKEN["enrollment_token"] not in resp.text
    assert STUB_STATE["enrolment_calls"] == 0


def test_viewer_without_csrf_still_hits_the_guard_first(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _post(client, make_token(), csrf=False)
    assert resp.status_code == 403
    assert REFUSAL not in resp.text
    assert STUB_STATE["enrolment_calls"] == 0


def test_admin_post_still_renders_the_token(client, make_token):
    resp = _post(client, make_token())
    assert resp.status_code == 200
    assert ENROLMENT_TOKEN["enrollment_token"] in resp.text
    assert STUB_STATE["enrolment_calls"] == 1


def test_upstream_admin_role_required_renders_the_refusal(client, make_token):
    """Role changed between page load and submit: the portal's role read says
    admin, the platform says 403 admin_role_required."""
    STUB_STATE["enrolment_admin_required"] = True
    resp = _post(client, make_token())
    assert resp.status_code == 403
    assert REFUSAL in resp.text
    assert "Account not linked" not in resp.text
    assert STUB_STATE["enrolment_calls"] == 1


def test_viewer_install_page_has_no_token_form_but_explains(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    html = _get(client, make_token()).text
    assert 'action="/install/enrolment"' not in html
    assert "Generate a one-off install token</button>" not in html
    assert "Only an administrator on your account can generate install tokens" in html
    assert "fleet" not in html.lower()
    assert "—" not in html and "–" not in html


def test_admin_install_page_has_the_token_form(client, make_token):
    html = _get(client, make_token()).text
    assert 'action="/install/enrolment"' in html
    assert "Generate a one-off install token" in html
    assert "Only an administrator on your account can generate install tokens" not in html
