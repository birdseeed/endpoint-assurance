"""PAT-2135: customer self-service device retirement and the device list.

Replaces the old "Tell us it's gone"/"Ask us to check" mailto links
(PAT-1642) and the "send us a device list" placeholder card on /devices
with two portal writes against the platform's own retirement and
device-list endpoints (contracts/portal-api.md "Device retirement and the
customer device list (PAT-2135)"). Nobody at Patched acts on the
customer's behalf any more (rubric C1) - these tests are mostly about
what must not happen: a viewer with no controls, a missing/wrong CSRF
token, a cross-origin request, an over-cap upload - and about the CSV
parser main.parse_device_list_csv owns entirely (the platform never
parses a CSV; it only ever sees structured JSON).
"""

import io
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

import pytest

import main
from tests.conftest import (
    DEVICE_LIST_VIEW,
    DEVICE_LIST_VIEW_OLD_API,
    NO_DEVICE_LIST,
    STUB_STATE,
)

ORIGIN = "https://testserver"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers=_headers(token))


def _post_retirement(client, token, device_id, retired, reason=None, origin=ORIGIN,
                     csrf=True, return_to=None):
    fields = [("device_id", device_id), ("retired", "true" if retired else "false")]
    if reason is not None:
        fields.append(("reason", reason))
    if return_to is not None:
        fields.append(("return_to", return_to))
    if csrf is True:
        fields.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        fields.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    return client.post("/devices/retirement", content=urlencode(fields), headers=headers,
                       follow_redirects=False)


def _post_clear(client, token, origin=ORIGIN, csrf=True):
    fields = []
    if csrf is True:
        fields.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        fields.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    return client.post("/devices/device-list/clear", content=urlencode(fields),
                       headers=headers, follow_redirects=False)


def _device_list_card_html(resp_text):
    """The "Your device list" card's own markup, so an assertion about what
    it does or doesn't render cannot be satisfied by an unrelated match
    elsewhere on the page (the main roster table can share a hostname with
    a device-list fixture, e.g. "acme-win-accounts")."""
    start = resp_text.index('id="device-list-card"')
    end = resp_text.index('id="jamf-coverage-card"')
    return resp_text[start:end]


def _post_upload(client, token, csv_bytes, filename="devices.csv", origin=ORIGIN, csrf=True):
    data = {}
    if csrf is True:
        data["csrf_token"] = main._csrf_token(token)
    elif isinstance(csrf, str):
        data["csrf_token"] = csrf
    headers = _headers(token)
    if origin is not None:
        headers["Origin"] = origin
    files = {"device_list_file": (filename, io.BytesIO(csv_bytes), "text/csv")}
    return client.post("/devices/device-list", data=data, files=files, headers=headers,
                       follow_redirects=False)


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


# ── Role gating: a viewer sees no controls, a 403 from the platform renders
#    a clear message ─────────────────────────────────────────────────────
def test_viewer_sees_no_retire_controls_on_devices(client, token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert "Retire device" not in resp.text
    assert "Return to active" not in resp.text
    assert 'action="/devices/retirement"' not in resp.text


def test_viewer_sees_no_device_list_upload_form(client, token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert 'action="/devices/device-list"' not in resp.text
    assert 'action="/devices/device-list/clear"' not in resp.text


def test_viewer_sees_no_retire_control_on_device_page(client, token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, token, "/devices/dev-mac-001")
    assert resp.status_code == 200
    assert "Retire device" not in resp.text
    assert 'action="/devices/retirement"' not in resp.text


def test_admin_sees_retire_controls_on_devices(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert 'action="/devices/retirement"' in resp.text
    assert "Retire device" in resp.text


def test_viewer_retirement_post_is_refused_before_any_platform_write(client, token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _post_retirement(client, token, "dev-mac-001", True)
    assert resp.status_code == 403
    assert "Only an administrator on your account can retire or reactivate" in resp.text
    assert STUB_STATE["retirement_puts"] == []


def test_platform_403_on_retirement_renders_a_message(client, token):
    """Even if the portal's own role check somehow let a non-admin write
    through, the platform's own 403 admin_role_required must still render
    a clear customer message, never a raw error."""
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["retirement_status_override"] = 403
    resp = _post_retirement(client, token, "dev-mac-001", True)
    assert resp.status_code in (303, 200)
    if resp.status_code == 303:
        resp = client.get(resp.headers["location"], headers=_headers(token))
    assert resp.status_code == 200
    assert "administrator" in resp.text.lower() or "refused" in resp.text.lower()


# ── CSRF required ──────────────────────────────────────────────────────
def test_retirement_missing_csrf_token_is_refused(client, token):
    resp = _post_retirement(client, token, "dev-mac-001", True, csrf=False)
    assert resp.status_code == 403
    assert "This page has expired" in resp.text
    assert STUB_STATE["retirement_puts"] == []


def test_retirement_bad_origin_is_refused(client, token):
    resp = _post_retirement(client, token, "dev-mac-001", True, origin="https://evil.example")
    assert resp.status_code == 403
    assert STUB_STATE["retirement_puts"] == []


def test_device_list_upload_missing_csrf_token_is_refused(client, token):
    resp = _post_upload(client, token, b"hostname\nLT-0001\n", csrf=False)
    assert resp.status_code == 403
    assert "This page has expired" in resp.text
    assert STUB_STATE["device_list_puts"] == []


def test_device_list_clear_missing_csrf_token_is_refused(client, token):
    resp = _post_clear(client, token, csrf=False)
    assert resp.status_code == 403
    assert STUB_STATE["device_list_delete_calls"] == 0


def test_device_list_upload_missing_content_length_is_refused_before_form_is_read(
    client, token,
):
    """A chunked request (no Content-Length) must be refused outright,
    not treated as "no size limit given" - Starlette's request.form()
    would otherwise spool an unbounded body to disk before our own size
    cap ever ran. request.form must never even be called."""
    STUB_STATE["portal_role"] = "admin"
    boundary = "x" * 20
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="csrf_token"\r\n\r\n'
        f"{main._csrf_token(token)}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="device_list_file"; filename="a.csv"\r\n'
        "Content-Type: text/csv\r\n\r\n"
        "hostname\nLT-0001\n\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    def _stream():
        yield body

    headers = _headers(token, **{
        "Origin": ORIGIN, "Content-Type": f"multipart/form-data; boundary={boundary}",
    })
    with patch(
        "starlette.requests.Request.form", new_callable=AsyncMock,
    ) as mock_form:
        resp = client.post(
            "/devices/device-list", content=_stream(), headers=headers,
            follow_redirects=False,
        )
    assert resp.status_code == 411
    assert "That upload could not be read. Try again from the Devices page." in resp.text
    mock_form.assert_not_called()
    assert STUB_STATE["device_list_puts"] == []


# ── Retire / unretire call the right endpoint with the right body ────────
def test_retire_calls_the_platform_endpoint_with_the_right_body(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_retirement(client, token, "dev-mac-001", True, reason="Written off after theft")
    assert resp.status_code == 303
    assert len(STUB_STATE["retirement_puts"]) == 1
    put = STUB_STATE["retirement_puts"][0]
    assert put["device_id"] == "dev-mac-001"
    assert put["body"] == {"retired": True, "reason": "Written off after theft"}
    location = resp.headers["location"]
    assert location.startswith("/devices")
    assert "#device-result" in location
    follow = client.get(location, headers=_headers(token))
    assert "Device retired" in follow.text


def test_retire_with_no_reason_omits_it_from_the_body(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_retirement(client, token, "dev-mac-001", True)
    assert resp.status_code == 303
    assert STUB_STATE["retirement_puts"][0]["body"] == {"retired": True}


def test_unretire_calls_the_platform_endpoint_with_retired_false(client, token):
    STUB_STATE["portal_role"] = "admin"
    # dev-mac-004 starts retired in the DEVICES fixture.
    resp = _post_retirement(client, token, "dev-mac-004", False, reason="Found it")
    assert resp.status_code == 303
    put = STUB_STATE["retirement_puts"][0]
    assert put["device_id"] == "dev-mac-004"
    assert put["body"] == {"retired": False, "reason": "Found it"}
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "returned to active" in follow.text.lower()


def test_retiring_an_already_retired_device_is_a_no_op_notice(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_retirement(client, token, "dev-mac-004", True)
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "already" in follow.text.lower()


def test_retirement_reason_over_limit_is_refused_with_nothing_changed(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_retirement(client, token, "dev-mac-001", True, reason="x" * 501)
    assert resp.status_code == 303
    assert STUB_STATE["retirement_puts"] == []
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "at most 500 characters" in follow.text


def test_retirement_return_to_device_page_lands_back_there(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_retirement(client, token, "dev-mac-001", True, return_to="/devices/dev-mac-001")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/devices/dev-mac-001")


def test_retirement_return_to_is_restricted_to_devices_paths(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_retirement(client, token, "dev-mac-001", True,
                            return_to="https://evil.example/steal")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/devices/dev-mac-001")


# ── Reported-after-retirement warning pill ───────────────────────────────
def test_reported_after_retirement_pill_renders_on_devices(client, token):
    resp = _get(client, token, "/devices?view=retired")
    assert resp.status_code == 200
    assert "Reported after retirement" in resp.text


def test_reported_after_retirement_pill_renders_on_device_page(client, token):
    resp = _get(client, token, "/devices/dev-mac-005")
    assert resp.status_code == 200
    assert "Reported after retirement" in resp.text


def test_retired_device_carries_a_retired_pill_with_no_warning_when_quiet(client, token):
    resp = _get(client, token, "/devices/dev-mac-004")
    assert resp.status_code == 200
    assert "Retired" in resp.text
    assert "Reported after retirement" not in resp.text


# ── Retirement history ────────────────────────────────────────────────────
def test_retirement_history_renders_on_the_device_page(client, token):
    STUB_STATE["portal_role"] = "admin"
    _post_retirement(client, token, "dev-mac-001", True, reason="Written off after theft")
    resp = _get(client, token, "/devices/dev-mac-001")
    assert resp.status_code == 200
    assert "Retirement history" in resp.text
    assert "Written off after theft" in resp.text


# ── Retired devices are excluded from silent/quiet/normal and get their
#    own group (D1/D2: never read as "missing") ──────────────────────────
def test_retired_devices_are_not_counted_as_silent_or_missing(client, token):
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    # Neither retired fixture device (40 and 0.5 days silent) inflates the
    # Silent count - they get their own Retired tab instead (D1/D2: a
    # retired device never reads as missing).
    assert "Silent over 14 days (0)" in resp.text
    assert "Retired (2)" in resp.text
    assert resp.text.count('data-filter-view="retired"') == 2


def test_not_reporting_24h_excludes_retired_devices(client, token):
    resp = _get(client, token, "/devices?view=not_reporting_24h")
    assert resp.status_code == 200
    assert "acme-mbp-retired" not in resp.text


def test_overview_coverage_carves_out_retired_devices(client, token):
    STUB_STATE["overview_data"] = {
        "tenant_name": "Acme Trust Ltd", "generated_at": "2026-07-02T10:15:00Z",
        "devices_total": 12, "devices_reporting_24h": 10, "devices_retired": 1,
        "cis_score_current": 84, "cis_trend": [], "findings_open": {},
        "patch_status": {},
    }
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "1 device not reporting in 24 hours" in resp.text
    assert "Retired <strong>1</strong>" in resp.text


# ── Device list: render of tiles + both groups (PAT-2212) ─────────────────
def test_device_list_renders_tiles_and_default_group(client, token):
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    # Count tiles replace the old "N entries matched" sentence and the
    # prose section headings.
    assert "Matched" in card
    assert "Not reporting" in card
    assert "Reporting, not on your list" in card
    assert "list_group=never_seen" in card
    assert "list_group=not_on_list" in card
    assert "list_group=matched" in card
    # Default landing group is never_seen (most actionable), so its rows
    # render with no further navigation.
    assert "PF3ABCDE" in card
    assert "acme-win-accounts" not in card


def test_device_list_group_tile_filters_to_not_on_list(client, token):
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices?list_group=not_on_list")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    assert "acme-win-accounts" in card
    assert "PF3ABCDE" not in card


def test_device_list_matched_group_renders_itemised(client, token):
    # PAT-2271: the platform now returns a `matched` array, so the customer
    # can check which uploaded entry matched which device, not just a count.
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices?list_group=matched")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    assert "<details" in card
    # An active match and a retired match, each linking to its real device.
    assert 'href="/devices/dev-mac-001"' in card
    assert 'href="/devices/dev-mac-004"' in card
    assert "acme-mbp-frontdesk" in card
    assert card.count("Retired") >= 1


def test_device_list_matched_group_falls_back_to_count_only_on_old_api(client, token):
    # PAT-2271 is additive - an upstream that has not deployed it yet omits
    # `matched` entirely, and the portal must still render an honest
    # count-only group rather than crashing or lying about an empty list.
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW_OLD_API
    resp = _get(client, token, "/devices?list_group=matched")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    assert "<details" in card
    assert "3 entries on your list matched a known device" in card
    assert "1 of those retired" in card
    assert "Remove from list" not in card


def test_device_list_serial_column_hidden_when_no_row_has_one(client, token):
    no_serials = {
        **DEVICE_LIST_VIEW,
        "on_list_never_seen": [{"index": 2, "hostname": "ghost-02", "serial": None}],
        "on_list_never_seen_total": 1,
    }
    STUB_STATE["device_list_data"] = no_serials
    resp = _get(client, token, "/devices?list_group=never_seen")
    assert resp.status_code == 200
    assert "ghost-02" in resp.text
    assert "<th>Serial</th>" not in resp.text


def test_device_list_empty_group_is_one_line_with_a_tick(client, token):
    empty_never_seen = {
        **DEVICE_LIST_VIEW, "on_list_never_seen": [], "on_list_never_seen_total": 0,
    }
    STUB_STATE["device_list_data"] = empty_never_seen
    resp = _get(client, token, "/devices?list_group=never_seen")
    assert resp.status_code == 200
    assert "Every device on your list has been seen" in resp.text
    assert "On your list, never seen" not in resp.text


def test_device_list_header_shows_upload_meta_no_badge(client, token):
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert "estate.csv" in resp.text
    assert "admin@tenant-a.example" in resp.text
    # The grey "N devices" badge pill is gone (PAT-2212).
    assert "pill-muted\">4 devices</span>" not in resp.text


def test_device_list_never_seen_row_offers_install_and_remove_for_admin(client, token):
    # PAT-2271: the platform now has a per-entry removal endpoint, so an
    # admin sees both actions on a never-seen row.
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices?list_group=never_seen")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    assert 'href="/install"' in card
    assert "Install the agent" in card
    assert "Remove from list" in card
    assert 'action="/devices/device-list/entries/204"' in card


def test_device_list_never_seen_row_hides_remove_for_viewer(client, token):
    STUB_STATE["portal_role"] = "viewer"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices?list_group=never_seen")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    assert "Install the agent" in card
    assert "Remove from list" not in card


def test_device_list_never_seen_row_hides_remove_on_old_api(client, token):
    # No entry_id from an upstream not yet on PAT-2271: no remove control,
    # never a broken one that posts to a made-up id.
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW_OLD_API
    resp = _get(client, token, "/devices?list_group=never_seen")
    assert resp.status_code == 200
    card = _device_list_card_html(resp.text)
    assert "Install the agent" in card
    assert "Remove from list" not in card


# ── device-list entry removal (PAT-2271) ──────────────────────────────────
def _post_remove_entry(client, token, entry_id, origin=ORIGIN, csrf=True):
    fields = []
    if csrf is True:
        fields.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        fields.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    return client.post(f"/devices/device-list/entries/{entry_id}", content=urlencode(fields),
                       headers=headers, follow_redirects=False)


def test_remove_entry_viewer_is_refused(client, token):
    STUB_STATE["portal_role"] = "viewer"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _post_remove_entry(client, token, 204)
    assert resp.status_code == 403
    assert STUB_STATE["device_list_entry_delete_calls"] == []


def test_remove_entry_admin_succeeds_and_shows_notice(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _post_remove_entry(client, token, 204)
    assert resp.status_code == 303
    assert STUB_STATE["device_list_entry_delete_calls"] == ["204"]
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "Entry removed from your list" in follow.text
    # The removed entry no longer appears in the re-rendered card.
    card = _device_list_card_html(follow.text)
    assert "PF3ABCDE" not in card


def test_remove_entry_unknown_id_reads_as_already_removed(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _post_remove_entry(client, token, 999999)
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "already been removed" in follow.text


def test_remove_entry_missing_csrf_token_is_refused(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _post_remove_entry(client, token, 204, csrf=False)
    assert resp.status_code == 403
    assert STUB_STATE["device_list_entry_delete_calls"] == []


def test_remove_entry_cross_origin_is_refused(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _post_remove_entry(client, token, 204, origin="https://evil.example")
    assert resp.status_code == 403
    assert STUB_STATE["device_list_entry_delete_calls"] == []


def test_ce_sentence_moved_off_device_list_card_onto_silent_tab(client, token):
    # PAT-2212: the sentence is server-rendered on every view (portal.js's
    # tab switch never reloads the page, so the markup carries both states
    # and CSS - not Jinja - decides which one is visible; see
    # .toolbar-hint[data-silent-only] in static/css/portal.css). What must
    # hold without executing CSS/JS is: it is marked data-silent-only (so
    # it is hidden except on Silent) and it is no longer inside the
    # device-list card.
    resp = _get(client, token, "/devices")
    assert 'data-silent-only' in resp.text
    card = _device_list_card_html(resp.text)
    assert "Cyber Essentials" not in card


def test_device_list_empty_state_invites_upload_in_self_service_terms(client, token):
    STUB_STATE["device_list_data"] = NO_DEVICE_LIST
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert "No device list on file yet." in resp.text
    assert "Send us a device list" not in resp.text
    assert 'action="/devices/device-list"' in resp.text


def test_device_list_clear_action_present_for_admin(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _get(client, token, "/devices")
    assert 'action="/devices/device-list/clear"' in resp.text
    assert "Clear list" in resp.text


def test_device_list_clear_calls_delete_and_shows_notice(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_data"] = DEVICE_LIST_VIEW
    resp = _post_clear(client, token)
    assert resp.status_code == 303
    assert STUB_STATE["device_list_delete_calls"] == 1
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "Device list cleared" in follow.text


# ── No "Ask us"/"Tell us" text left on /devices ───────────────────────────
def test_no_staff_action_copy_remains_on_devices(client, token):
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert "Ask us to check" not in resp.text
    assert "Tell us it's gone" not in resp.text
    assert "Ask us to decide" not in resp.text  # would be an exceptions.html leak, sanity check
    assert "Send us a device list" not in resp.text
    assert "Telling us a device is gone" not in resp.text


# ── device-list upload: role gating, size cap, CSV parsing end to end ────
def test_device_list_upload_viewer_is_refused(client, token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _post_upload(client, token, b"hostname\nLT-0001\n")
    assert resp.status_code == 403
    assert STUB_STATE["device_list_puts"] == []


def test_device_list_upload_success_calls_platform_and_shows_count(client, token):
    STUB_STATE["portal_role"] = "admin"
    csv_bytes = b"hostname,serial\nLT-0001,C02ABC\nLT-0002,\n"
    resp = _post_upload(client, token, csv_bytes)
    assert resp.status_code == 303
    assert len(STUB_STATE["device_list_puts"]) == 1
    payload = STUB_STATE["device_list_puts"][0]
    assert payload["filename"] == "devices.csv"
    assert payload["entries"] == [
        {"hostname": "LT-0001", "serial": "C02ABC"},
        {"hostname": "LT-0002"},
    ]
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "Device list uploaded" in follow.text


def test_device_list_upload_over_2mib_is_refused_before_parsing(client, token):
    STUB_STATE["portal_role"] = "admin"
    # Just over the 2 MiB cap, but still under the multipart framing
    # overhead allowance _guarded_multipart_form's Content-Length check
    # gives it, so this reaches the route's own byte-count check (below)
    # rather than being refused early as an oversized request.
    over_cap = b"hostname\n" + b"a" * (2 * 1024 * 1024)
    resp = _post_upload(client, token, over_cap)
    assert resp.status_code == 303
    assert STUB_STATE["device_list_puts"] == []
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "larger than 2 MiB" in follow.text


def test_device_list_upload_no_recognisable_column_is_refused(client, token):
    STUB_STATE["portal_role"] = "admin"
    resp = _post_upload(client, token, b"colour,size\nred,large\n")
    assert resp.status_code == 303
    assert STUB_STATE["device_list_puts"] == []
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "no column named Hostname" in follow.text or "no recognisable" in follow.text.lower()


def test_device_list_upload_platform_400_maps_to_a_human_message(client, token):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_status_override"] = 400
    STUB_STATE["device_list_error_body"] = {
        "error": "invalid_entry",
        "message": "entries[0]: hostname contains control characters",
        "items": [{"index": 0, "code": "invalid_hostname",
                   "message": "hostname contains control characters"}],
    }
    resp = _post_upload(client, token, b"hostname\nLT-0001\n")
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "row 2 of your file" in follow.text
    assert "hostname contains control characters" in follow.text


# ── CSV parsing (main.parse_device_list_csv) ──────────────────────────────
def test_csv_parsing_header_variants():
    for header in ("hostname", "Host Name", "DEVICE NAME", "computer name", "Name"):
        entries, lines, error = main.parse_device_list_csv(
            f"{header}\nLT-0001\n".encode())
        assert error is None, header
        assert entries == [{"hostname": "LT-0001"}], header
        assert lines == [2], header


def test_csv_parsing_serial_header_variants():
    for header in ("serial", "Serial Number", "SERIALNUMBER"):
        entries, lines, error = main.parse_device_list_csv(
            f"{header}\nC02ABC123\n".encode())
        assert error is None, header
        assert entries == [{"serial": "C02ABC123"}], header
        assert lines == [2], header


def test_csv_parsing_both_columns_case_insensitive():
    entries, lines, error = main.parse_device_list_csv(
        b"Hostname,Serial\nLT-0001,C02ABC\n")
    assert error is None
    assert entries == [{"hostname": "LT-0001", "serial": "C02ABC"}]
    assert lines == [2]


def test_csv_parsing_utf8_bom():
    raw = "﻿hostname\nLT-0001\n".encode()
    entries, lines, error = main.parse_device_list_csv(raw)
    assert error is None
    assert entries == [{"hostname": "LT-0001"}]
    assert lines == [2]


def test_csv_parsing_cp1252_fallback():
    # Byte 0x92 is a right single quotation mark in cp1252 (U+2019) and is
    # not valid UTF-8 on its own - a real "Excel CSV" export footgun.
    raw = b"hostname\nAlice" + bytes([0x92]) + b"s MacBook\n"
    entries, lines, error = main.parse_device_list_csv(raw)
    assert error is None
    assert entries == [{"hostname": "Alice’s MacBook"}]
    assert lines == [2]


def test_csv_parsing_missing_column_is_a_clear_error():
    entries, lines, error = main.parse_device_list_csv(b"colour\nred\n")
    assert entries == [] and lines == []
    assert error is not None
    assert "no column named" in error.lower() or "no recognisable" in error.lower()


def test_csv_parsing_skips_blank_rows():
    entries, lines, error = main.parse_device_list_csv(
        b"hostname\nLT-0001\n\n   \nLT-0002\n")
    assert error is None
    assert entries == [{"hostname": "LT-0001"}, {"hostname": "LT-0002"}]
    # PAT-2135: entry_lines is the true file line, not header+index - the
    # blank line (3) and the whitespace-only line (4) are skipped, so
    # LT-0002 is line 5, not the 3 a naive header+count would give.
    assert lines == [2, 5]


def test_csv_parsing_line_numbers_survive_a_blank_row_before_a_later_entry():
    """A blank row ahead of a bad entry must not shift the reported line -
    this is exactly what the old index + 2 guess got wrong."""
    entries, lines, error = main.parse_device_list_csv(
        b"hostname\nLT-0001\n\nLT-0002\nLT-0003\n")
    assert error is None
    assert entries == [
        {"hostname": "LT-0001"}, {"hostname": "LT-0002"}, {"hostname": "LT-0003"},
    ]
    # Line 3 is blank and skipped; LT-0002 is really on line 4, LT-0003 on
    # line 5 - index+2 would have claimed 3 and 4 instead.
    assert lines == [2, 4, 5]


def test_csv_parsing_over_cap_size_is_refused():
    huge = b"hostname\n" + b"a\n" * (2 * 1024 * 1024)
    entries, lines, error = main.parse_device_list_csv(huge)
    assert entries == [] and lines == []
    assert "larger than 2 MiB" in error


def test_csv_parsing_over_10000_rows_is_refused():
    rows = "\n".join(f"host-{i}" for i in range(10002))
    raw = f"hostname\n{rows}\n".encode()
    entries, lines, error = main.parse_device_list_csv(raw)
    assert entries == [] and lines == []
    assert "more than 10,000 rows" in error


def test_csv_parsing_exactly_10000_rows_succeeds():
    rows = "\n".join(f"host-{i}" for i in range(10000))
    raw = f"hostname\n{rows}\n".encode()
    entries, lines, error = main.parse_device_list_csv(raw)
    assert error is None
    assert len(entries) == 10000
    assert len(lines) == 10000
    assert lines[0] == 2 and lines[-1] == 10001


def test_csv_parsing_empty_file_is_a_clear_error():
    entries, lines, error = main.parse_device_list_csv(b"")
    assert entries == [] and lines == []
    assert error == "That file is empty."


def test_csv_parsing_header_only_no_rows_is_a_clear_error():
    entries, lines, error = main.parse_device_list_csv(b"hostname\n")
    assert entries == [] and lines == []
    assert error == "That file has no rows to upload."


# ── Platform invalid_entry row index maps to the true file line, even
#    across a skipped blank row (not the old header+index guess) ─────────
def test_device_list_upload_platform_400_maps_to_the_true_file_line_across_a_blank_row(
    client, token,
):
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["device_list_status_override"] = 400
    # entries[1] ("LT-0002") is the bad one. Without line tracking this
    # would be mis-reported as "row 3" (1-based index + 2); the blank row
    # on line 3 pushes it to the real line 4.
    STUB_STATE["device_list_error_body"] = {
        "error": "invalid_entry",
        "message": "entries[1]: hostname contains control characters",
        "items": [{"index": 1, "code": "invalid_hostname",
                   "message": "hostname contains control characters"}],
    }
    resp = _post_upload(client, token, b"hostname\nLT-0001\n\nLT-0002\n")
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "row 4 of your file" in follow.text
    assert "row 3 of your file" not in follow.text
