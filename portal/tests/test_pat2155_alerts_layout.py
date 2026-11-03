"""PAT-2155: /alerts layout - the per-tab column set (no empty Acknowledged/
Resolved columns on a tab that doesn't need them, a compact Last updated
column on All) and the device-picker filter that replaced the old raw
"Device ID" text box with a real hostname-to-device_id mapping built from
the tenant's own device roster (main._alert_device_options).

Browser-rendered wrap/overflow/platform-label/spacing coverage lives in
e2e/test_pat2155_alerts_layout.py; this file is the fast, template-and-
filter-level check, the same split PAT-2140's own test file documents.
"""

import pytest

import main
from tests.conftest import STUB_STATE


def _get(client, token, path="/software/alerts?status=all"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


# ── Device picker: hostname -> device_id mapping, never a raw id shown ────

def test_device_options_are_sorted_by_hostname(client, token):
    # `client` is unused directly but its fixture chain sets PLATFORM_BASE_URL
    # to the stub platform server - upstream.get_json has nowhere real to
    # call without it.
    options = main._alert_device_options(token)
    hostnames = [o["hostname"] for o in options]
    assert hostnames == sorted(hostnames, key=str.lower)
    assert hostnames == [
        "acme-mbp-frontdesk", "acme-mbp-retired", "acme-mbp-storeroom", "acme-mbp-zombie",
        "acme-win-accounts", "acme-win-dc1",
    ]


def test_device_options_carry_the_real_device_id_as_the_value(client, token):
    options = main._alert_device_options(token)
    by_hostname = {o["hostname"]: o["device_id"] for o in options}
    assert by_hostname["acme-mbp-frontdesk"] == "dev-mac-001"
    assert by_hostname["acme-win-accounts"] == "dev-win-002"
    assert by_hostname["acme-mbp-storeroom"] == "dev-mac-003"


def test_device_options_fail_soft_to_empty_list_on_upstream_error(client, token):
    STUB_STATE["devices_page_statuses"] = {0: 503}
    assert main._alert_device_options(token) == []


def test_device_picker_renders_hostnames_with_device_id_as_the_value_only(client, token):
    body = _get(client, token).text
    assert '<option value="dev-mac-001">acme-mbp-frontdesk</option>' in body
    # The raw id must never appear as visible option TEXT, only as the
    # value attribute the picked option submits - "never show raw IDs"
    # (PAT-2155's own instruction).
    assert ">dev-mac-001<" not in body


def test_selecting_the_current_device_filter_marks_that_option_selected(client, token):
    body = _get(client, token, "/software/alerts?status=all&device=dev-win-002").text
    option_start = body.index('value="dev-win-002"')
    option = body[option_start:body.index("</option>", option_start)]
    assert "selected" in option


def test_no_product_key_or_device_id_field_remains(client, token):
    body = _get(client, token).text
    assert "Product key" not in body
    assert "Device ID" not in body


def test_clear_filters_link_actually_clears_the_filters(client, token):
    # Red on current main: the old link reused the current tab's own
    # filtered URL (tab_urls[status_filter]), which never dropped
    # product/device - a "Clear filters" control that did nothing.
    body = _get(client, token, "/software/alerts?status=all&device=dev-win-002").text
    clear_start = body.index("Clear filters")
    href_start = body.rindex('href="', 0, clear_start)
    href = body[href_start + len('href="'):body.index('"', href_start + len('href="'))]
    assert "device=" not in href
    assert "product=" not in href


# ── Per-tab columns ─────────────────────────────────────────────────────

def test_open_tab_has_no_acknowledged_resolved_or_last_updated_header(client, token):
    body = _get(client, token, "/software/alerts?status=open").text
    assert "<th>Raised</th>" in body
    assert "<th>Acknowledged</th>" not in body
    assert "<th>Resolved</th>" not in body
    assert "<th>Last updated</th>" not in body


def test_acknowledged_tab_shows_acknowledged_detail_not_resolved(client, token):
    body = _get(client, token, "/software/alerts?status=acknowledged").text
    assert "<th>Acknowledged</th>" in body
    assert "<th>Resolved</th>" not in body
    assert "<th>Raised</th>" in body
    assert "alice@tenant-a.example" in body


def test_resolved_tab_shows_resolved_detail_not_acknowledged(client, token):
    body = _get(client, token, "/software/alerts?status=resolved").text
    assert "<th>Resolved</th>" in body
    assert "<th>Acknowledged</th>" not in body
    assert "Product approved." in body


def test_all_tab_shows_a_compact_last_updated_column_only(client, token):
    body = _get(client, token, "/software/alerts?status=all").text
    assert "<th>Last updated</th>" in body
    assert "<th>Raised</th>" not in body
    assert "<th>Acknowledged</th>" not in body
    assert "<th>Resolved</th>" not in body


def test_open_tab_shows_no_actions_column_to_a_viewer(client, token):
    STUB_STATE["portal_role"] = "viewer"
    body = _get(client, token, "/software/alerts?status=open").text
    assert 'action="/software/alerts/1/acknowledge"' not in body


def test_status_changed_at_is_carried_by_alert_row():
    row = main._alert_row({
        "id": 9, "status": "open", "trigger": "observed",
        "product": {"type": "application", "name": "X"}, "device": {},
        "raised_at": "2026-09-24T14:05:02Z", "status_changed_at": "2026-09-25T08:00:00Z",
    })
    assert row["status_changed_at"] == "2026-09-25T08:00:00Z"


def test_all_tab_last_updated_column_renders_status_changed_at(client, token):
    body = _get(client, token, "/software/alerts?status=all").text
    # Alert 2 (acknowledged) has status_changed_at 2026-09-21, distinct from
    # its own raised_at (2026-09-20) - the All tab must show the former.
    row_start = body.index("ShadyCoupons")
    row = body[row_start:body.index("</tr>", row_start)]
    assert "21 Sep 2026" in row
    assert "20 Sep 2026" not in row


# ── Acknowledge: note and button in one form, one row ────────────────────

def test_ack_form_holds_only_the_note_and_the_button(client, token):
    body = _get(client, token, "/software/alerts?status=open").text
    form_start = body.index('class="alert-ack-form"')
    form = body[form_start:body.index("</form>", form_start)]
    assert "Note (optional)" in form
    assert ">Acknowledge<" in form


def test_device_picker_fails_soft_on_malformed_roster(monkeypatch):
    # A roster that isn't a list, or holds non-dict rows, drops the picker
    # rather than breaking the Alerts page (review finding on PAT-2155).
    import main

    monkeypatch.setattr(main, "get_device_roster", lambda _jwt: {"devices": "nope"})
    assert main._alert_device_options("jwt") == []
    monkeypatch.setattr(
        main, "get_device_roster",
        lambda _jwt: ["junk", None, {"device_id": "d-1", "hostname": "mac-01"}],
    )
    assert main._alert_device_options("jwt") == [{"device_id": "d-1", "hostname": "mac-01"}]
