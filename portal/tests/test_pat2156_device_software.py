"""PAT-2156: one device's Software installed view
(/devices/{device_id}/software) - applications and browser extensions
scoped to a single device, the exact evidence and approval model /software
already gives the whole estate (contracts/portal-api.md "device_id
(PAT-2156)").

Columns, tabs, the CVE/usage absence rules (never "0 CVEs" for not yet
assessed, never "Unused" for a product that simply isn't metered), the
400/404 not-found mapping, and _approval_return_to's strict UUID-only
acceptance of this view's own return path are all red-proofed here against
origin/main, which has none of this route.
"""

import re
from urllib.parse import urlencode, urlsplit

import main
from tests.conftest import DEVICE_SOFTWARE_UUID_ID, STUB_STATE

DEVICE_ID = "dev-mac-001"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path):
    return client.get(path, headers=_headers(token))


def _post_approval(client, token, fields, origin="https://testserver"):
    body = list(fields) + [("csrf_token", main._csrf_token(token))]
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded",
                                 "Origin": origin})
    return client.post("/software/approvals", content=urlencode(body), headers=headers,
                       follow_redirects=False)


# ── Rendering, tabs, columns ───────────────────────────────────────────────

def test_device_software_applications_tab_renders_expected_columns(client, make_token):
    token = make_token()
    resp = _get(client, token, f"/devices/{DEVICE_ID}/software")
    assert resp.status_code == 200
    page = resp.text
    assert "acme-mbp-frontdesk" in page
    assert "Software installed" in page
    # Name + identifier (two-line product cell).
    assert "Example App" in page
    assert "com.example.app" in page
    # Version(s).
    assert "2.1" in page
    # Approval pill (undecided/unreviewed reads "unreviewed" for
    # policy_state "undecided" via _inventory_approval/_app_approval_state).
    assert "Approved" in page  # Example App's policy_state is "approved"
    # First seen on this device (PAT-2140 two-line date pattern).
    assert "01 Aug 2026" in page
    # Usage: a metered, used product shows its last-used date.
    assert "24 Sep 2026" in page


def test_device_software_not_assessed_never_reads_as_zero_cves(client, make_token):
    """NotMeteredApp's cve_assessment.state is not_assessed - it must never
    render as "0 CVEs" or "No known CVEs" (root AGENTS.md: absence requires
    authority), and Example App's genuine assessed-clean (finding_count 0)
    result must stay visually and textually distinct from it."""
    token = make_token()
    resp = _get(client, token, f"/devices/{DEVICE_ID}/software")
    page = resp.text
    assert "Not yet assessed" in page
    assert "0 CVEs" not in page
    assert "No known CVEs" in page  # Example App's genuine clean result


def test_device_software_not_metered_never_reads_as_unused(client, make_token):
    """NotMeteredApp is usage_state="unmetered" - the Usage cell must say
    "Not metered", and must never fall back to the generic "Unused" usage
    label, which is a distinct, different claim (metered evidence showing
    no use) that this row does not have."""
    token = make_token()
    resp = _get(client, token, f"/devices/{DEVICE_ID}/software")
    page = resp.text
    assert "Not metered" in page
    not_metered_row = re.search(
        r"<tr>(?:(?!</tr>).)*NotMeteredApp(?:(?!</tr>).)*</tr>", page, re.DOTALL,
    )
    assert not_metered_row, "could not find NotMeteredApp's row"
    assert "Unused" not in not_metered_row.group(0)
    assert "Not metered" in not_metered_row.group(0)


def test_device_software_extensions_tab(client, make_token):
    token = make_token()
    resp = _get(client, token, f"/devices/{DEVICE_ID}/software?tab=extension")
    assert resp.status_code == 200
    page = resp.text
    assert "AdBlock Plus" in page
    assert "Slack" in page
    assert "Chrome" in page
    # The Applications tab's own rows must not also be present.
    assert "Example App" not in page
    assert "WindowsTool" not in page


def test_device_software_search_is_forwarded_to_the_platform(client, make_token):
    # "Example App" (with the space) rather than "Example" - all three
    # fixture products share the "com.example.*" identifier prefix, so a
    # bare "Example" would match every row via identifier search too.
    token = make_token()
    resp = _get(
        client, token,
        f"/devices/{DEVICE_ID}/software?" + urlencode({"search": "Example App"}),
    )
    assert resp.status_code == 200
    page = resp.text
    assert "Example App" in page
    assert "WindowsTool" not in page
    assert "NotMeteredApp" not in page


def test_device_software_page_head_links_back_to_the_device(client, make_token):
    token = make_token()
    resp = _get(client, token, f"/devices/{DEVICE_ID}/software")
    assert f"/devices/{DEVICE_ID}\"" in resp.text


def test_device_detail_links_to_the_software_view(client, make_token):
    # PAT-2164: the old "Software installed" meta-line link is gone - the
    # Software tab in the shared tab bar is the one way there now.
    token = make_token()
    resp = _get(client, token, f"/devices/{DEVICE_ID}")
    assert resp.status_code == 200
    assert f'href="/devices/{DEVICE_ID}/software"' in resp.text
    assert ">Software<" in resp.text or "Software (" in resp.text


# ── 400/404 (device_id validation, contracts/portal-api.md) ───────────────

def test_unknown_device_id_is_not_found(client, make_token):
    # Asserting main.py's own device_software not-found copy, not just any
    # 404 - main.py's generic catch-all 404 handler ("That page does not
    # exist.") would otherwise make this pass on origin/main too, where the
    # route does not exist at all (red-proofed: fails on origin/main).
    token = make_token()
    resp = _get(client, token, "/devices/dev-mac-999/software")
    assert resp.status_code == 404
    assert "That device could not be found in your estate." in resp.text


def test_malformed_device_id_is_also_not_found(client, make_token):
    """The platform gives a malformed (non-UUID) device_id the identical 404
    a well-formed-but-unknown one gets - device_id can never be used as a
    cross-tenant existence oracle. This route must not tell the two apart
    either (contracts/portal-api.md "device_id (PAT-2156)")."""
    token = make_token()
    resp = _get(client, token, "/devices/Not_Valid/software")
    assert resp.status_code == 404
    assert "That device could not be found in your estate." in resp.text


def test_extensions_endpoint_same_404_for_unknown_device(client, make_token):
    token = make_token()
    resp = _get(client, token, "/devices/dev-mac-999/software?tab=extension")
    assert resp.status_code == 404
    assert "That device could not be found in your estate." in resp.text


# ── Read-only role ──────────────────────────────────────────────────────────

def test_viewer_sees_states_only_no_approval_controls(client, make_token):
    token = make_token()
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, token, f"/devices/{DEVICE_ID}/software")
    assert resp.status_code == 200
    page = resp.text
    assert "approval-row-form" not in page
    # State is still readable.
    assert "Approved" in page


# ── Approve from this view, land back here with the notice ────────────────

def test_approve_from_device_software_returns_here_with_notice(client, make_token):
    token = make_token()
    return_to = f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software?tab=application"
    item = (
        '{"type":"application","platform":"macos","identifier":"com.example.app",'
        '"team_id":"ABCDE12345","name":"Example App"}'
    )
    resp = _post_approval(client, token, [
        ("state", "unapproved"), ("item", item), ("return_to", return_to),
    ])
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert urlsplit(location).path == f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software"
    follow = client.get(location, headers=_headers(token))
    assert follow.status_code == 200
    assert "approval-result" in follow.text
    assert "changed to Unapproved" in follow.text


# ── _approval_return_to: strict UUID-only device path (security-sensitive) ─

def test_approval_return_to_accepts_the_device_software_uuid_path():
    accepted = main._approval_return_to(f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software")
    assert accepted == f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software"


def test_approval_return_to_preserves_query_on_the_device_software_path():
    raw = f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software?tab=extension&search=slack&offset=20"
    accepted = main._approval_return_to(raw)
    parts = urlsplit(accepted)
    assert parts.path == f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software"
    assert "tab=extension" in parts.query
    assert "search=slack" in parts.query
    assert "offset=20" in parts.query


def test_approval_return_to_rejects_non_uuid_device_id():
    # A test-suite-convention id ("dev-mac-001") is not a UUID and must not
    # be accepted, even though it is a perfectly real device elsewhere in
    # this file.
    assert main._approval_return_to(f"/devices/{DEVICE_ID}/software") == "/software"


def test_approval_return_to_rejects_path_traversal():
    assert main._approval_return_to(
        f"/devices/../{DEVICE_SOFTWARE_UUID_ID}/software",
    ) == "/software"
    assert main._approval_return_to(
        f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software/../../evil",
    ) == "/software"


def test_approval_return_to_rejects_extra_segments():
    assert main._approval_return_to(
        f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software/extra",
    ) == "/software"


def test_approval_return_to_rejects_an_external_url():
    assert main._approval_return_to(
        f"https://evil.example/devices/{DEVICE_SOFTWARE_UUID_ID}/software",
    ) == "/software"
    assert main._approval_return_to(
        f"//evil.example/devices/{DEVICE_SOFTWARE_UUID_ID}/software",
    ) == "/software"


def test_approval_return_to_rejects_a_non_uuid_looking_id():
    for bad_id in ("not-a-uuid", "042c97f3-58cf-4a11-9c2e", "'; drop table x --"):
        assert main._approval_return_to(f"/devices/{bad_id}/software") == "/software"


# ── Changelog (PAT-2157 rule: every customer-visible PR adds an entry) ────

def test_changelog_mentions_the_device_software_view(client, make_token):
    token = make_token()
    resp = _get(client, token, "/whats-new")
    assert resp.status_code == 200
    assert "Software installed" in resp.text


def test_return_to_rejects_trailing_newline_after_device_software_path():
    # `$` in a Python regex also matches before a trailing newline; the
    # guard uses fullmatch so "/devices/<uuid>/software\n" can't pass.
    import main

    good = "/devices/0b39cbe5-1111-2222-3333-444444444444/software"
    assert main.DEVICE_SOFTWARE_RETURN_RE.fullmatch(good)
    assert not main.DEVICE_SOFTWARE_RETURN_RE.fullmatch(good + "\n")
    assert not main.DEVICE_SOFTWARE_RETURN_RE.fullmatch(good + "/../../x")
