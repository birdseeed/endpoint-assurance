"""PAT-2152: SAM report - software publishers.

Exercises /reports/software/publishers and its device drill-down against the
stubbed platform (contracts/portal-api.md "GET /v1/portal/reports/software/
publishers" and ".../devices"): the unsigned, invalid and unverified groups
render ahead of verified publishers, a publisher name is never shown for
anything but a verified row, the Trusted/Not trusted pill renders correctly,
filters and paging are forwarded to the platform, CSV downloads proxy the
platform's own bytes, and an unavailable platform degrades honestly.
"""

import re

from tests.conftest import PUBLISHERS_CSV, PUBLISHERS_SUMMARY, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_unverified_groups_render_ahead_of_verified(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers")
    assert resp.status_code == 200
    body = resp.text
    assert body.index('id="pub-callout-title"') < body.index('id="pub-verified-title"')


def test_plain_explanations_are_shown(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers")
    assert resp.status_code == 200
    body = resp.text
    assert "No signing evidence: Patched can&#39;t verify who published this." in body \
        or "No signing evidence: Patched can't verify who published this." in body


def test_no_publisher_name_shown_for_a_call_out_row(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers")
    assert resp.status_code == 200
    body = resp.text
    callout_start = body.index('id="pub-callout-table"')
    callout_end = body.index("</table>", callout_start)
    callout_section = body[callout_start:callout_end]
    assert "ABCDE12345" not in callout_section
    assert "Contoso" not in callout_section


def test_verified_publishers_show_trusted_and_not_trusted_pills(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers")
    assert resp.status_code == 200
    body = resp.text
    assert "ABCDE12345" in body
    assert "CN=Contoso Software Ltd" in body
    assert ">Trusted<" in body
    assert ">Not trusted<" in body


def test_group_platform_publisher_key_params_are_forwarded(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token,
               "/reports/software/publishers?group=verified&platform=macos"
               "&publisher_key=team%3AABCDE12345")
    assert resp.status_code == 200
    sent = STUB_STATE["publishers_requests"][-1]
    assert sent.get("group") == "verified"
    assert sent.get("platform") == "macos"
    assert sent.get("publisher_key") == "team:ABCDE12345"
    assert "ABCDE12345" in resp.text
    assert "Contoso" not in resp.text


def test_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == PUBLISHERS_CSV
    STUB_STATE["publishers_requests"] = []
    resp = _get(client, token, "/reports/software/publishers.csv?group=verified")
    assert resp.status_code == 200
    assert resp.headers.get("x-patched-export-rows") == "2"


def test_devices_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers/devices.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


def test_drill_down_filters_to_one_publisher(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token,
               "/reports/software/publishers/devices?publisher_key=team%3AABCDE12345")
    assert resp.status_code == 200
    sent = STUB_STATE["publishers_devices_requests"][-1]
    assert sent.get("publisher_key") == "team:ABCDE12345"
    assert "TrustedTool" in resp.text
    assert "ContosoApp" not in resp.text


def test_devices_drill_down_link_from_publishers_table_carries_publisher_key(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers")
    assert "publisher_key=team%3AABCDE12345" in resp.text


def test_devices_drill_down_never_shows_a_name_for_an_unverified_row(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers/devices")
    assert resp.status_code == 200
    body = resp.text
    assert "UnpinnedTool" in body
    idx = body.index("UnpinnedTool")
    row_start = body.rindex("<tr>", 0, idx)
    row_end = body.index("</tr>", idx)
    row = body[row_start:row_end]
    assert "Unverified" in row
    # No real publisher identity anywhere in this specific row.
    assert "ABCDE12345" not in row
    assert "Contoso" not in row


def test_devices_drill_down_shows_the_identity_basis_for_a_verified_row(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/publishers/devices")
    assert resp.status_code == 200
    body = resp.text
    idx = body.index("TrustedTool")
    row_start = body.rindex("<tr>", 0, idx)
    row_end = body.index("</tr>", idx)
    row = body[row_start:row_end]
    assert "ABCDE12345" in row
    assert "Apple Developer Team ID" in row


def test_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["publishers_status"] = 500
    resp = _get(client, token, "/reports/software/publishers")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_devices_drill_down_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["publishers_devices_status"] = 500
    resp = _get(client, token, "/reports/software/publishers/devices")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_no_copy_violations(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for path in ("/reports/software/publishers", "/reports/software/publishers/devices"):
        resp = _get(client, token, path)
        body = resp.text
        assert not re.search(r"\bspecialist\b", body, re.IGNORECASE)
        assert not re.search(r"\bfleet\b", body, re.IGNORECASE)
        assert "coming soon" not in body.lower()
        assert "—" not in body


def test_reports_page_links_to_the_new_report(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/software/publishers"' in resp.text


def test_row_builder_never_carries_a_publisher_name_outside_verified():
    from main import _publisher_row
    for raw in PUBLISHERS_SUMMARY["publishers"]:
        row = _publisher_row(raw)
        if row["group"] != "verified":
            assert row["publisher"] is None


def test_row_builder_orders_call_outs_ahead_of_verified_in_the_stub():
    order = [p["group"] for p in PUBLISHERS_SUMMARY["publishers"]]
    assert order.index("unsigned_or_adhoc") < order.index("verified")
    assert order.index("invalid") < order.index("verified")
    assert order.index("unverified") < order.index("verified")
