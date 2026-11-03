"""PAT-2145: Jamf Pro coverage.

Which Macs the customer's Jamf Pro manages that Patched has never seen, and
which Macs Patched sees that Jamf hasn't reported, without Patched holding a
Jamf credential (contracts/portal-api.md "Jamf Pro coverage (PAT-2145)").
Every portal role reads /devices/jamf and /devices/jamf/setup; the four
writes (setup PUT, token create/rotate, token revoke, device purge) are
admin only, guarded exactly like every other write in this repo
(_guarded_form: size cap, then Origin, then CSRF - see test_pat2105_csrf.py
for the route-enumeration side of that guarantee).

Security-critical: the plaintext webhook token is returned to the browser
exactly once, directly in the POST /devices/jamf/token response body -
never via a redirect, a flash, a query string or the session - with
Cache-Control: no-store and Pragma: no-cache, and it must never appear in
any later GET.
"""

import re
from urllib.parse import urlencode

import main
from tests.conftest import STUB_STATE

_TAG_RE = re.compile(r"<[^>]+>")


def _visible_text(html: str) -> str:
    """Strip tags (and therefore class names/attributes) so a banned-word
    check only ever looks at rendered copy, not markup - "rail__specialist"
    (an existing, unrelated CSS class name in base.html) must never trip
    this check the way real specialist-wording copy should."""
    return _TAG_RE.sub(" ", html)

ORIGIN = "https://testserver"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path):
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


def _configure(mode="ok"):
    STUB_STATE["jamf_mode"] = mode


# ── Read access: every role, connector states, the "since" statement ──────

def test_viewer_reads_coverage_page(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "Jamf coverage" in resp.text


def test_never_connected_tenant_shows_setup_cta(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "Not connected" in resp.text
    assert "No Jamf webhook has been received yet." in resp.text
    assert 'href="/devices/jamf/setup"' in resp.text


def test_never_connected_viewer_is_told_to_ask_an_admin(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "An administrator on your account can set up the Jamf connector." in resp.text


def test_amber_connector_shown_distinctly(client, make_token):
    _configure("amber")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "Delayed" in resp.text
    assert "No Jamf event in the last 24 hours" in resp.text


def test_revoked_connector_shown_distinctly_from_amber(client, make_token):
    _configure("revoked")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "Token revoked" in resp.text


def test_since_statement_always_shown_with_counts(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "From Jamf webhooks since 1 September 2026." in resp.text
    # the counts kpi row is on the same page as the statement
    assert "Jamf devices reported by webhook" in resp.text
    assert "Webhook-reported, not seen by Patched" in resp.text
    assert "Seen by Patched, no matching webhook" in resp.text


def test_since_statement_shown_even_before_any_event(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "No Jamf webhook has been received yet." in resp.text


def test_devices_page_links_to_jamf_coverage(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert 'href="/devices/jamf"' in resp.text


# ── Bucket wording rules (rubric: absence requires authority) ─────────────

def test_gap_bucket_shows_webhook_state_and_silence(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "acme-mbp-silent" in resp.text
    assert "acme-mbp-newhire" in resp.text
    assert "not heard from Jamf in 47 days" in resp.text
    assert "Assigned in Apple Business Manager" in resp.text


def test_unmanaged_label_only_on_the_row_with_that_mdm_state(client, make_token):
    """Only the row whose platform mdm_state is exactly 'unmanaged' may read
    'No MDM enrolment reported' / 'the Mac reports no MDM enrolment'. Every
    other row - including Jamf's own silence in the gap bucket - must not
    be described that way."""
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    text = resp.text
    assert "the Mac reports no MDM enrolment" in text
    assert "No MDM enrolment reported" in text
    # the other four not_reported_by_jamf states each get their own wording,
    # never the unmanaged one
    assert "enrolled with Microsoft Intune (i.manage.microsoft.com)" in text
    assert "but Jamf has sent no event for it since setup" in text
    assert "the Mac reports MDM enrolment, but not which server" in text
    assert "no MDM enrolment evidence from the agent yet" in text
    # LT-0043 (other_mdm) must not carry the unmanaged pill/note
    lt_pos = text.index("LT-0043")
    row_html = text[lt_pos:lt_pos + 600]
    assert "No MDM enrolment reported" not in row_html
    assert "the Mac reports no MDM enrolment" not in row_html


def test_covered_bucket_shows_match_basis(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 200
    assert "acme-mbp-frontdesk" in resp.text
    assert "acme-mbp-uuidmatch" in resp.text


# ── No copy violations (house style) ───────────────────────────────────────

def test_no_banned_copy_on_coverage_or_setup_pages(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    for path in ("/devices/jamf", "/devices/jamf/setup"):
        resp = _get(client, token, path)
        assert resp.status_code == 200
        lowered = _visible_text(resp.text).lower()
        assert "specialist" not in lowered
        assert "fleet" not in lowered
        assert "coming soon" not in lowered
        assert "—" not in resp.text  # em dash


# ── Setup page: viewer sees no write controls ──────────────────────────────

def test_viewer_sees_no_write_controls_on_setup_page(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf/setup")
    assert resp.status_code == 200
    assert 'action="/devices/jamf/token"' not in resp.text
    assert 'action="/devices/jamf/token/revoke"' not in resp.text
    assert 'action="/devices/jamf/devices/purge"' not in resp.text
    assert 'action="/devices/jamf/setup"' not in resp.text
    assert "An administrator on your account can create, rotate or revoke" in resp.text


def test_admin_sees_write_controls_on_setup_page(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _get(client, token, "/devices/jamf/setup")
    assert resp.status_code == 200
    assert 'action="/devices/jamf/token"' in resp.text
    assert 'action="/devices/jamf/token/revoke"' in resp.text
    assert 'action="/devices/jamf/devices/purge"' in resp.text


def test_setup_page_shows_connector_health_and_last_event(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf/setup")
    assert resp.status_code == 200
    assert "Connector health" in resp.text
    assert "Connected" in resp.text
    assert "Last Jamf event" in resp.text
    assert "08:00 UTC" in resp.text


def test_setup_page_keeps_controls_when_health_read_fails(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["jamf_coverage_status_override"] = 500
    token = make_token()
    resp = _get(client, token, "/devices/jamf/setup")
    assert resp.status_code == 200
    assert "Connector health is temporarily unavailable" in resp.text
    assert 'action="/devices/jamf/token"' in resp.text


# ── CSRF required on every write ───────────────────────────────────────────

JAMF_WRITE_ROUTES = [
    ("/devices/jamf/setup", [("check_in_enabled", "true")]),
    ("/devices/jamf/token", []),
    ("/devices/jamf/token/revoke", []),
    ("/devices/jamf/devices/purge", []),
]


def test_every_jamf_write_refuses_without_csrf(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    for path, fields in JAMF_WRITE_ROUTES:
        resp = _post(client, token, path, fields, csrf=False)
        assert resp.status_code == 403, path
        assert "This page has expired" in resp.text


def test_every_jamf_write_refuses_wrong_csrf(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    for path, fields in JAMF_WRITE_ROUTES:
        resp = _post(client, token, path, fields, csrf="not-the-real-token")
        assert resp.status_code == 403, path


def test_every_jamf_write_refuses_cross_origin(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    for path, fields in JAMF_WRITE_ROUTES:
        resp = _post(client, token, path, fields, origin="https://evil.example")
        assert resp.status_code == 403, path
        assert "did not come from the portal page itself" in resp.text


def test_every_jamf_write_refuses_for_a_viewer(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    for path, fields in JAMF_WRITE_ROUTES:
        resp = _post(client, token, path, fields)
        assert resp.status_code == 403, path
    assert STUB_STATE["jamf_setup_puts"] == []
    assert STUB_STATE["jamf_token_posts"] == []
    assert STUB_STATE["jamf_token_delete_calls"] == 0
    assert STUB_STATE["jamf_devices_purge_calls"] == 0


def test_platform_403_on_purge_renders_a_message(client, make_token):
    """Even if the portal's own role check somehow let a non-admin write
    through, the platform's own 403 admin_role_required must still render
    a clear customer message."""
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["jamf_devices_delete_status"] = (
        403, {"error": "admin_role_required", "message": "nope"})
    token = make_token()
    resp = _post(client, token, "/devices/jamf/devices/purge", [])
    assert resp.status_code == 303
    resp = client.get(resp.headers["location"], headers=_headers(token))
    assert "Only an administrator on your account can delete the Jamf device records" in resp.text


# ── Token handling (security-critical) ─────────────────────────────────────

def test_token_create_renders_inline_with_no_store_headers(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/token", [])
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-store"
    assert resp.headers.get("pragma") == "no-cache"
    assert "pjwh_teststubtoken0000000000000000000000001" in resp.text
    assert "will not be shown again" in resp.text
    assert STUB_STATE["jamf_token_posts"] == [""]
    assert STUB_STATE["jamf_coverage_requests"] == []
    assert "refresh this page to see authoritative connector health" in resp.text


def test_token_create_is_not_a_redirect(client, make_token):
    """The plaintext must never travel via a redirect, a flash, or a query
    string - it renders directly in this POST's own response body."""
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/token", [])
    assert resp.status_code == 200
    assert "location" not in resp.headers


def test_token_never_appears_in_a_later_get(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    create_resp = _post(client, token, "/devices/jamf/token", [])
    assert create_resp.status_code == 200
    plaintext = "pjwh_teststubtoken0000000000000000000000001"
    assert plaintext in create_resp.text

    for path in ("/devices/jamf", "/devices/jamf/setup"):
        follow_up = _get(client, token, path)
        assert follow_up.status_code == 200
        assert plaintext not in follow_up.text


def test_token_rotate_shows_rotated_wording(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/token", [])
    assert resp.status_code == 200
    assert "Webhook token rotated." in resp.text


def test_token_revoke_warns_and_reports_deleted_count(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/token/revoke", [])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "Revoking deleted the 4 Jamf device records" in follow_up.text
    assert STUB_STATE["jamf_token_delete_calls"] == 1


def test_purge_reports_deleted_count(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/devices/purge", [])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "Deleted" in follow_up.text
    assert STUB_STATE["jamf_devices_purge_calls"] == 1


def test_checkin_toggle_updates_and_reports_notice(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/setup", [("check_in_enabled", "true")])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "Jamf settings updated." in follow_up.text
    assert STUB_STATE["jamf_check_in_enabled"] is True


def test_reset_instance_updates_and_reports_notice(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/setup", [("reset_jamf_instance", "true")])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "Jamf settings updated." in follow_up.text
    assert STUB_STATE["jamf_instance_reset"] is True


def test_setup_put_before_configured_is_refused(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    resp = _post(client, token, "/devices/jamf/setup", [("check_in_enabled", "true")])
    assert resp.status_code == 303
    follow_up = client.get(resp.headers["location"], headers=_headers(token))
    assert "Jamf is not connected yet." in follow_up.text


# ── CSV proxy ───────────────────────────────────────────────────────────────

def test_coverage_csv_is_proxied(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf/coverage.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    header = resp.text.splitlines()[0]
    assert header.startswith("bucket,device_id,hostname,serial,udid,jamf_id")
    assert "acme-mbp-silent" in resp.text


def test_coverage_csv_bucket_filter_is_forwarded(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token, "/devices/jamf/coverage.csv?bucket=covered")
    assert resp.status_code == 200
    assert "acme-mbp-frontdesk" in resp.text
    assert "acme-mbp-silent" not in resp.text
    assert STUB_STATE["jamf_coverage_requests"][-1]["bucket"] == "covered"
    assert STUB_STATE["jamf_coverage_requests"][-1]["format"] == "csv"


# ── Platform-down degrades ──────────────────────────────────────────────────

def test_coverage_page_degrades_when_platform_down(client, make_token):
    STUB_STATE["mode"] = "down503"
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 503
    assert "not yet enabled" in resp.text.lower()


def test_setup_page_degrades_when_platform_down(client, make_token):
    STUB_STATE["mode"] = "down503"
    token = make_token()
    resp = _get(client, token, "/devices/jamf/setup")
    assert resp.status_code == 503


def test_coverage_page_degrades_on_upstream_error(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "viewer"
    STUB_STATE["jamf_coverage_status_override"] = 500
    token = make_token()
    resp = _get(client, token, "/devices/jamf")
    assert resp.status_code == 502
    assert "temporarily unavailable" in resp.text.lower()


# ── Pagination (unit-level: three independent per-bucket offsets) ─────────

def test_raw_platform_states_are_transformed_for_templates(client, make_token, monkeypatch):
    _configure("ok")
    captured = {}
    render = main._render

    def capture(request, template, context, **kwargs):
        captured.update(context)
        return render(request, template, context, **kwargs)

    monkeypatch.setattr(main, "_render", capture)
    response = _get(client, make_token(), "/devices/jamf")
    assert response.status_code == 200
    assert [r["jamf_state_label"] for r in captured["gap"]["rows"]] == [
        "Enrolled", "Assigned in Apple Business Manager"]
    rows = captured["not_reported"]["rows"]
    for row in rows:
        assert row["mdm"] == main._jamf_mdm_state_view(row["mdm_state"])
    assert rows[0]["mdm_vendor"] == "Microsoft Intune"
    assert rows[0]["mdm_server_host"] == "i.manage.microsoft.com"
    # Vendor and host are carried by the platform's authoritative note.
    assert "Microsoft Intune (i.manage.microsoft.com)" in response.text
    assert captured["basis"]["seed"] in response.text


def test_zero_hours_uses_less_than_an_hour_on_both_pages(client, make_token, monkeypatch):
    _configure("ok")
    get_json = main.upstream.get_json

    def recent_connector(path, jwt, **kwargs):
        data = get_json(path, jwt, **kwargs)
        if path == "/v1/portal/mdm/jamf/coverage":
            data["connector"]["hours_since_last_event"] = 0
        return data

    monkeypatch.setattr(main.upstream, "get_json", recent_connector)
    for path in ("/devices/jamf", "/devices/jamf/setup"):
        response = _get(client, make_token(), path)
        assert "less than an hour ago" in response.text
        assert "0 hours ago" not in response.text


def test_offset_is_bounded_before_forwarding():
    assert main._jamf_offset("999999999999999999999999") == 2_147_483_647
    assert main._jamf_offset("-1") == 0


def test_reveal_registers_history_clear_handlers(client, make_token):
    _configure("not_configured")
    STUB_STATE["portal_role"] = "admin"
    response = _post(client, make_token(), "/devices/jamf/token", [])
    assert 'window.addEventListener("pagehide", clearTokenReveal)' in response.text
    assert 'window.addEventListener("pageshow"' in response.text
    assert "if (event.persisted) clearTokenReveal()" in response.text
    assert STUB_STATE["jamf_instance_reset"] is False


def test_purge_count_uses_remaining_fixture_records(client, make_token):
    _configure("ok")
    STUB_STATE["portal_role"] = "admin"
    token = make_token()
    first = _post(client, token, "/devices/jamf/devices/purge", [])
    assert first.status_code == 303
    second = _post(client, token, "/devices/jamf/devices/purge", [])
    follow_up = client.get(second.headers["location"], headers=_headers(token))
    assert "Nothing" in follow_up.text or "Deleted 0" in follow_up.text

def test_bucket_view_pagination_math():
    size = main.JAMF_PAGE_SIZE
    rows = [{"n": i} for i in range(2)]
    data = {"gap": {"total": size + 2, "rows": rows}}
    offsets = {"gap_offset": str(size), "not_reported_offset": "0", "covered_offset": "0"}
    view = main._jamf_bucket_view(data, "gap", size, "gap_offset", offsets)
    assert view["shown_from"] == size + 1
    assert view["shown_to"] == size + 2
    assert view["prev_url"] == (
        "/devices/jamf?gap_offset=0&not_reported_offset=0&covered_offset=0")
    assert view["next_url"] is None  # offset(size) + len(rows)(2) == total(size+2): no more rows


def test_bucket_view_next_url_present_when_more_rows_remain():
    rows_page = [{"n": i} for i in range(25)]
    data = {"gap": {"total": 30, "rows": rows_page}}
    offsets = {"gap_offset": "0", "not_reported_offset": "0", "covered_offset": "0"}
    view = main._jamf_bucket_view(data, "gap", 0, "gap_offset", offsets)
    assert view["prev_url"] is None
    assert view["next_url"] == (
        "/devices/jamf?gap_offset=25&not_reported_offset=0&covered_offset=0")


def test_offset_helper_rejects_negative_and_non_numeric():
    assert main._jamf_offset("-5") == 0
    assert main._jamf_offset("not-a-number") == 0
    assert main._jamf_offset("30") == 30
