"""PAT-2251: estate enrolment keys on /install.

A reusable, revocable enrolment credential for estate rollouts (Intune,
Jamf, an RMM) - contracts/portal-api.md "Tenant enrolment keys (PAT-2250)".
Unlike the existing single-use "one-off install token" (PAT-453), one key
may enrol many devices, over weeks, until it expires or is revoked.

GET /v1/portal/enrolment-keys is every role; POST /v1/portal/enrolment-keys
(create) and POST /v1/portal/enrolment-keys/{id}/revoke are admin only,
guarded exactly like every other write in this repo (_guarded_form: size
cap, then Origin, then CSRF - see test_pat2105_csrf.py for the route-
enumeration side of that guarantee).

Security-critical: the plaintext key is returned to the browser exactly
once, directly in the create POST's own response body - never via a
redirect, a flash, a query string or the session - with Cache-Control:
no-store, and it must never appear in any later GET /install.
"""

from urllib.parse import urlencode

import main
from tests.conftest import ENROLMENT_KEY_ROW, STUB_STATE

ORIGIN = "https://testserver"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path="/install"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers=_headers(token))


def _post(client, token, path, fields, origin=ORIGIN, csrf=True):
    STUB_STATE["expected_jwt"] = token
    form = list(fields)
    if csrf is True:
        form.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        form.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    return client.post(path, content=urlencode(form), headers=headers, follow_redirects=False)


def _create(client, token, label="Intune rollout", max_devices="50", expires_in_days=None):
    fields = [("label", label), ("max_devices", max_devices)]
    if expires_in_days is not None:
        fields.append(("expires_in_days", expires_in_days))
    return _post(client, token, "/install/enrolment-keys", fields)


# ── List (every role) ───────────────────────────────────────────────────────

def test_install_page_lists_existing_keys(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "Estate enrolment keys" in resp.text
    assert "Intune rollout" in resp.text
    assert "pek_Ab3x" in resp.text
    assert "3 / 250" in resp.text
    assert "Active" in resp.text


def test_install_page_shows_every_status_label(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [
        {**ENROLMENT_KEY_ROW, "key_id": "k-active", "label": "Active key", "status": "active"},
        {**ENROLMENT_KEY_ROW, "key_id": "k-expired", "label": "Expired key", "status": "expired"},
        {**ENROLMENT_KEY_ROW, "key_id": "k-revoked", "label": "Revoked key", "status": "revoked",
         "revoked_at": "2026-09-01T00:00:00Z"},
        {**ENROLMENT_KEY_ROW, "key_id": "k-full", "label": "Full key", "status": "exhausted",
         "devices_enrolled": 250},
    ]
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "Active" in resp.text
    assert "Expired" in resp.text
    assert "Revoked" in resp.text
    # House copy calls "exhausted" "Full" (ticket wording), never the raw
    # platform status string.
    assert "Full" in resp.text
    assert "exhausted" not in resp.text.lower()


def test_no_keys_shows_empty_state(client, make_token):
    STUB_STATE["enrolment_keys_data"] = []
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "No estate enrolment keys yet." in resp.text


def test_keys_list_unavailable_does_not_break_the_page(client, make_token):
    """A platform hiccup on the list read must not take the whole page down
    - only hide the list (fail soft, same shape as devices_jamf_setup's own
    connector_unavailable)."""
    STUB_STATE["enrolment_keys_list_status_override"] = 500
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "temporarily unavailable" in resp.text.lower()
    assert "Install the agent" in resp.text


# ── Non-admin sees no controls (ticket requirement) ─────────────────────────

def test_non_admin_sees_list_but_no_create_or_revoke_controls(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "Intune rollout" in resp.text  # list still visible
    assert "Create an estate enrolment key" not in resp.text
    assert "Revoke" not in resp.text
    assert "administrator on your account manages estate enrolment keys" in resp.text


def test_role_unavailable_hides_controls_with_its_own_message(client, make_token):
    STUB_STATE["me_status"] = 500
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "Create an estate enrolment key" not in resp.text
    assert "role could not be checked" in resp.text


# ── Create: happy path, one-time display ────────────────────────────────────

def test_create_key_renders_plaintext_once_with_no_store(client, make_token):
    token = make_token()
    resp = _create(client, token, label="Intune rollout", max_devices="50")
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-store"
    assert resp.headers.get("pragma") == "no-cache"
    assert "location" not in resp.headers  # never a redirect - PAT-2251 brief
    assert "pek_teststubkey0001" in resp.text
    assert "will not be shown again" in resp.text
    assert STUB_STATE["enrolment_key_create_posts"] == [
        {"label": "Intune rollout", "max_devices": 50}]


def test_create_key_default_expiry_is_omitted_from_payload(client, make_token):
    token = make_token()
    resp = _create(client, token, expires_in_days="")
    assert resp.status_code == 200
    assert "expires_in_days" not in STUB_STATE["enrolment_key_create_posts"][-1]


def test_create_key_sends_explicit_expiry(client, make_token):
    token = make_token()
    resp = _create(client, token, expires_in_days="90")
    assert resp.status_code == 200
    assert STUB_STATE["enrolment_key_create_posts"][-1]["expires_in_days"] == 90


def test_plaintext_never_appears_on_a_later_get(client, make_token):
    token = make_token()
    create_resp = _create(client, token)
    assert create_resp.status_code == 200
    plaintext = None
    for line in create_resp.text.splitlines():
        if "pek_teststubkey0001" in line:
            plaintext = "pek_teststubkey00010000000000000000000000000000"
    assert plaintext, "expected the stub plaintext key in the create response"

    follow_up = _get(client, token, "/install")
    assert follow_up.status_code == 200
    assert plaintext not in follow_up.text
    assert "pek_teststubkey0001" not in follow_up.text


def test_created_key_appears_in_the_list_afterwards(client, make_token):
    token = make_token()
    resp = _create(client, token, label="Brand new key", max_devices="12")
    assert resp.status_code == 200
    assert "Brand new key" in resp.text  # shown on the create response itself
    follow_up = _get(client, token, "/install")
    assert follow_up.status_code == 200
    assert "Brand new key" in follow_up.text
    assert "0 / 12" in follow_up.text


# ── Create: validation ───────────────────────────────────────────────────────

def test_create_key_rejects_blank_label(client, make_token):
    token = make_token()
    resp = _create(client, token, label="   ")
    assert resp.status_code == 400
    assert STUB_STATE["enrolment_key_create_posts"] == []


def test_create_key_rejects_label_over_limit(client, make_token):
    token = make_token()
    resp = _create(client, token, label="x" * 101)
    assert resp.status_code == 400
    assert STUB_STATE["enrolment_key_create_posts"] == []


def test_create_key_rejects_max_devices_out_of_range(client, make_token):
    token = make_token()
    resp = _create(client, token, max_devices="0")
    assert resp.status_code == 400
    resp2 = _create(client, token, max_devices="100001")
    assert resp2.status_code == 400
    assert STUB_STATE["enrolment_key_create_posts"] == []


def test_create_key_rejects_non_numeric_max_devices(client, make_token):
    token = make_token()
    resp = _create(client, token, max_devices="fifty")
    assert resp.status_code == 400
    assert STUB_STATE["enrolment_key_create_posts"] == []


def test_create_key_rejects_expiry_out_of_range(client, make_token):
    token = make_token()
    resp = _create(client, token, expires_in_days="0")
    assert resp.status_code == 400
    resp2 = _create(client, token, expires_in_days="366")
    assert resp2.status_code == 400
    assert STUB_STATE["enrolment_key_create_posts"] == []


# ── Create: role and upstream failure modes ──────────────────────────────────

def test_non_admin_cannot_create_a_key(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _create(client, token)
    assert resp.status_code == 403
    assert "administrator" in resp.text
    assert STUB_STATE["enrolment_key_create_posts"] == []


def test_create_key_rate_limited_is_friendly(client, make_token):
    STUB_STATE["enrolment_key_create_status_override"] = (429, {"error": "rate_limited"})
    token = make_token()
    resp = _create(client, token)
    assert resp.status_code == 429
    assert "wait" in resp.text.lower()


def test_create_key_upstream_401_reauths(client, make_token):
    STUB_STATE["mode"] = "auth401"
    token = make_token()
    resp = _create(client, token)
    assert resp.status_code == 401
    assert "session has expired" in resp.text.lower()


# ── Revoke: confirmation without JS, CSRF-guarded ────────────────────────────

def test_revoke_control_is_a_no_js_confirm_disclosure(client, make_token):
    """The confirm step must work with no JavaScript: a <details>/<summary>
    disclosure around the real POST form, the same idiom the Jamf webhook
    token revoke uses (PAT-2145) - not a JS confirm() dialog."""
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    resp = _get(client, token)
    html = resp.text
    assert "<details" in html
    assert "Revoke" in html
    form_action = f'action="/install/enrolment-keys/{ENROLMENT_KEY_ROW["key_id"]}/revoke"'
    assert form_action in html
    start = html.index(form_action)
    form_region = html[max(0, start - 400):html.index("</form>", start)]
    assert "<details" in html[:start]
    assert "csrf_token" in form_region
    assert "Revoking stops new enrolments" in form_region


def test_revoked_key_never_offers_a_second_revoke_control(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [
        {**ENROLMENT_KEY_ROW, "status": "revoked", "revoked_at": "2026-09-01T00:00:00Z"}]
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert f'action="/install/enrolment-keys/{ENROLMENT_KEY_ROW["key_id"]}/revoke"' not in resp.text


def test_revoke_succeeds_and_shows_notice(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    key_id = ENROLMENT_KEY_ROW["key_id"]
    resp = _post(client, token, f"/install/enrolment-keys/{key_id}/revoke", [])
    assert resp.status_code == 303
    assert STUB_STATE["enrolment_key_revokes"] == 1
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "revoked" in follow_up.text.lower()
    assert "Revoked" in follow_up.text


def test_revoking_an_already_revoked_key_is_a_no_op_notice(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [
        {**ENROLMENT_KEY_ROW, "status": "revoked", "revoked_at": "2026-09-01T00:00:00Z"}]
    token = make_token()
    key_id = ENROLMENT_KEY_ROW["key_id"]
    resp = _post(client, token, f"/install/enrolment-keys/{key_id}/revoke", [])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "already revoked" in follow_up.text.lower()


def test_revoke_unknown_key_shows_a_friendly_notice_not_a_crash(client, make_token):
    token = make_token()
    resp = _post(client, token, "/install/enrolment-keys/does-not-exist/revoke", [])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert follow_up.status_code == 200


def test_non_admin_cannot_revoke_a_key(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    key_id = ENROLMENT_KEY_ROW["key_id"]
    resp = _post(client, token, f"/install/enrolment-keys/{key_id}/revoke", [])
    assert resp.status_code == 403
    assert STUB_STATE["enrolment_key_revokes"] == 0


# ── CSRF / Origin guard (defence in depth on top of test_pat2105_csrf.py) ───

def test_create_refuses_cross_origin(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _post(client, token, "/install/enrolment-keys",
                 [("label", "x"), ("max_devices", "10")], origin="https://evil.example")
    assert resp.status_code == 403
    assert STUB_STATE["enrolment_key_create_posts"] == []


def test_revoke_refuses_missing_csrf(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _post(client, token, f"/install/enrolment-keys/{ENROLMENT_KEY_ROW['key_id']}/revoke",
                 [], csrf=False)
    assert resp.status_code == 403
    assert STUB_STATE["enrolment_key_revokes"] == 0


# ── Per-platform deployment guidance (ticket scope) ──────────────────────────

def test_deployment_guidance_uses_placeholder_never_a_real_key(client, make_token):
    token = make_token()
    resp = _get(client, token)
    html = resp.text
    assert "&lt;your-key&gt;" in html
    assert 'ENROLLMENT_TOKEN="&lt;your-key&gt;"' in html
    assert "msiexec /qn /i PatchedAgent-&lt;version&gt;.msi" in html
    assert "/etc/patched/enrollment-token" in html
    assert "enrollment.json" in html
    assert "Win32" in html


def test_deployment_guidance_never_uses_fleet_or_em_dash(client, make_token):
    STUB_STATE["enrolment_keys_data"] = [dict(ENROLMENT_KEY_ROW)]
    token = make_token()
    resp = _get(client, token)
    assert "fleet" not in resp.text.lower()
    assert "—" not in resp.text


def test_one_off_token_section_is_relabelled_and_still_works(client, make_token):
    """PAT-453's flow must keep working unchanged, just relabelled per the
    ticket ("One-off install token")."""
    token = make_token()
    resp = _get(client, token)
    assert "One-off install token" in resp.text
    create_resp = _post(client, token, "/install/enrolment", [])
    assert create_resp.status_code == 200
    assert STUB_STATE["enrolment_calls"] == 1


def test_onboarding_notice_still_present_and_honest(client, make_token):
    """The 'how the installer is obtained today' line must stay, and must
    not claim Patched staff perform the deployment."""
    token = make_token()
    resp = _get(client, token)
    assert "provided by Patched during onboarding" in resp.text
    assert "through your MDM" in resp.text
