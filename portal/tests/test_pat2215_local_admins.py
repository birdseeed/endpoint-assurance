"""PAT-2215: Local admins page (Governance) - standing local-administrator
roster by account and by device, admin role only."""

import csv
import io
import re

from tests.conftest import STUB_STATE


def _get(client, token, path="/local-admins"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _row(page, needle):
    for match in re.finditer(r"<tr[^>]*>.*?</tr>", page, re.DOTALL):
        if needle in match.group(0):
            return match.group(0)
    raise AssertionError(f"no <tr> found containing {needle!r}")


def test_local_admins_requires_auth(client):
    assert client.get("/local-admins").status_code == 401


def test_local_admins_is_in_the_governance_rail_alphabetically(client, make_token):
    resp = _get(client, make_token(), "/")
    body = resp.text
    gov_start = body.index('id="rail-governance"')
    gov_section = body[gov_start:body.index("</section>", gov_start)]
    assert '<span>Exceptions</span>' in gov_section
    assert '<span>Homebrew</span>' in gov_section
    assert '<span>Local admins</span>' in gov_section
    assert (
        gov_section.index("Exceptions")
        < gov_section.index("Homebrew")
        < gov_section.index("Local admins")
    )
    assert 'href="/local-admins"' in gov_section


def test_viewer_sees_an_admin_only_notice_not_the_roster(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, make_token())
    assert resp.status_code == 403
    assert "admins only" in resp.text.lower() or "admin" in resp.text.lower()
    # The roster itself must never reach the page for a viewer.
    assert "acme-win-dc1" not in resp.text
    assert "Domain Admins" not in resp.text
    assert "acme-mbp-frontdesk" not in resp.text


def test_admin_sees_summary_tiles_from_the_platform_response(client, make_token):
    resp = _get(client, make_token())
    assert resp.status_code == 200
    body = resp.text
    assert "Over the limit" in body
    assert "Distinct accounts" in body
    assert "Membership could not be read" in body
    # over_limit_devices=1, distinct_accounts=5, unreadable_devices=1.
    assert '<span class="ov-card__headline">1</span>' in body
    assert '<span class="ov-card__headline">5</span>' in body


def test_by_account_view_labels_group_and_unresolved_principals(client, make_token):
    resp = _get(client, make_token())
    body = resp.text
    assert "acme-win-dc1" in body  # device list link text, by-account view

    group_row = _row(body, "ACME\\Domain Admins")
    assert ">Group<" in group_row
    assert "Directory group, not a person" in group_row

    unresolved_row = _row(body, "S-1-5-21-999-999-999-9999")
    assert ">Unresolved<" in unresolved_row
    assert "could not be matched to a name" in unresolved_row.lower()

    assert 'href="/devices/dev-win-101/compliance#compliance-signals"' in group_row
    assert 'href="/devices/dev-win-101/compliance#compliance-signals"' in unresolved_row


def test_by_device_view_shows_unknown_for_unreadable_membership_and_count(client, make_token):
    resp = _get(client, make_token(), "/local-admins?view=device")
    row = _row(resp.text, "acme-win-unreadable")
    assert "Could not be read" in row
    assert "Unknown" in row
    # Never a fabricated zero/pass claim for a device this page has no
    # evidence for.
    assert ">0<" not in row
    assert "Within limit" not in row
    assert "Over limit" not in row


def test_by_device_view_shows_the_disabled_builtin_administrator_note(client, make_token):
    resp = _get(client, make_token(), "/local-admins?view=device")
    row = _row(resp.text, "acme-win-dc1")
    assert "ACME\\Administrator" in row
    assert "Built-in Administrator, disabled" in row
    assert "Over limit" in row


def test_by_device_view_links_to_the_compliance_tab(client, make_token):
    resp = _get(client, make_token(), "/local-admins?view=device")
    assert 'href="/devices/dev-mac-001/compliance#compliance-signals"' in resp.text
    assert 'href="/devices/dev-win-101/compliance#compliance-signals"' in resp.text
    assert 'href="/devices/dev-win-102/compliance#compliance-signals"' in resp.text


def test_filter_bar_seeds_initial_checked_state_from_query_params(client, make_token):
    resp = _get(client, make_token(), "/local-admins?platform=windows&principal_type=group")
    body = resp.text
    assert 'data-initial="windows"' in body
    assert 'data-initial="group"' in body
    # Removable chip for each active filter.
    assert "filter-chip" in body
    assert "Windows" in body
    assert "Group" in body


def test_over_limit_filter_link_from_the_summary_tile_round_trips(client, make_token):
    resp = _get(client, make_token())
    assert 'href="/local-admins?over_limit=yes#local-admins-table"' in resp.text
    resp2 = _get(client, make_token(), "/local-admins?over_limit=yes")
    assert resp2.status_code == 200
    assert 'data-initial="yes"' in resp2.text


def test_no_wording_suggests_patched_removes_admin_rights(client, make_token):
    """Rubric C1: read-only, no removal wording anywhere on the page."""
    resp = _get(client, make_token())
    body_lower = resp.text.lower()
    for banned in ("remove admin", "revoke admin", "we will remove", "patched removes"):
        assert banned not in body_lower


def test_local_admins_csv_export_admin_only_and_has_expected_rows(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    forbidden = client.get("/local-admins.csv", headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert forbidden.status_code == 403

    STUB_STATE["portal_role"] = "admin"
    resp = client.get("/local-admins.csv", headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(resp.text)))
    header = rows[0]
    assert header == [
        "device_id", "hostname", "platform", "reported_admin_count",
        "assessed_admin_count", "pass", "membership_readable", "collection_status",
        "principal_name", "principal_type", "builtin", "account_state", "note",
    ]
    by_device = {}
    for row in rows[1:]:
        by_device.setdefault(row[1], []).append(row)
    assert len(by_device["acme-mbp-frontdesk"]) == 1
    assert len(by_device["acme-win-dc1"]) == 4
    # An unreadable device still gets exactly one row, with blank principal
    # columns, rather than being missing from the export entirely.
    unreadable_rows = by_device["acme-win-unreadable"]
    assert len(unreadable_rows) == 1
    assert unreadable_rows[0][8:] == ["", "", "", "", ""]
    assert unreadable_rows[0][3] == ""  # reported_admin_count blank, not 0
    assert unreadable_rows[0][6] == "False"  # membership_readable


def test_no_estate_linked_forbidden_is_distinct_from_admin_only(client, make_token):
    """A tenant-level 403 (PAT-699, no estate linked) must still render the
    generic not_linked page, never be mistaken for the admin-role notice."""
    STUB_STATE["mode"] = "forbidden403"
    resp = _get(client, make_token())
    assert resp.status_code == 403
    assert "not linked" in resp.text.lower() or "account not linked" in resp.text.lower()


def test_local_admins_default_view_is_by_account(client, make_token):
    resp = _get(client, make_token())
    body = resp.text
    assert "By account" in body
    account_heading = body.index("By account")
    device_heading_idx = body.find("By device")
    # The active tab is "By account" and its table (not the device table)
    # is the one actually rendered server-side by default.
    assert '<table class="data-table table-stack la-accounts-table">' in body
    assert '<table class="data-table table-stack la-devices-table">' not in body
    assert account_heading != -1 and device_heading_idx != -1
