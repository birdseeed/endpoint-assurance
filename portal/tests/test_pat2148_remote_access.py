"""PAT-2148: SAM report - remote access tools.

Exercises /reports/software/remote-access and its device drill-down against
the stubbed platform (contracts/portal-api.md "GET /v1/portal/reports/
software/remote-access" and ".../devices"): unsanctioned states render ahead
of approved ones in the summary, RMM agents render in their own section
rather than as findings, the catalogue-limited caveat is shown, filters and
paging are forwarded to the platform, CSV downloads proxy the platform's own
bytes, and an unavailable platform degrades honestly.
"""

import re

from tests.conftest import REMOTE_ACCESS_CSV, REMOTE_ACCESS_SUMMARY, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_unsanctioned_states_render_ahead_of_approved_in_summary(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access")
    assert resp.status_code == 200
    body = resp.text
    assert "Unapproved" in body
    assert "Unreviewed" in body
    assert "Ignored" in body
    assert "Approved" in body
    assert body.index("Unapproved") < body.index("Approved")


def test_rmm_agents_render_in_their_own_section_not_as_a_finding(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access")
    assert resp.status_code == 200
    body = resp.text
    assert "RMM agents" in body
    assert "NinjaOne Agent" in body
    # The RMM card sits in its own section, separate from the products table.
    rmm_idx = body.index("RMM agents")
    products_idx = body.index('id="ra-products-table"')
    assert rmm_idx < products_idx
    ninja_idx = body.index("NinjaOne Agent")
    assert rmm_idx < ninja_idx < products_idx


def test_catalogue_limited_caveat_is_shown(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access")
    assert resp.status_code == 200
    body = resp.text
    assert "is not evidence that no remote access tool is installed" in body
    assert "only that none of the catalogued ones were found" in body


def test_partial_basis_states_coverage_is_partial(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access")
    assert resp.status_code == 200
    assert "Coverage is partial" in resp.text


def test_per_user_install_shows_the_user(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access")
    assert resp.status_code == 200
    body = resp.text
    anydesk_idx = body.index("AnyDesk")
    row_end = body.index("</tr>", anydesk_idx)
    row = body[body.rindex("<tr>", 0, anydesk_idx):row_end]
    assert "alice" in row


def test_category_kind_state_platform_params_are_forwarded(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token,
               "/reports/software/remote-access?category=remote_access&kind=app"
               "&state=approved&platform=windows")
    assert resp.status_code == 200
    sent = STUB_STATE["remote_access_requests"][-1]
    assert sent.get("category") == "remote_access"
    assert sent.get("kind") == "app"
    assert sent.get("state") == "approved"
    assert sent.get("platform") == "windows"
    assert sent.get("limit") == "50"
    assert sent.get("offset") == "0"
    assert "TeamViewer" in resp.text
    assert "AnyDesk" not in resp.text


def test_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == REMOTE_ACCESS_CSV
    STUB_STATE["remote_access_requests"] = []
    resp = _get(client, token, "/reports/software/remote-access.csv?state=unapproved")
    assert resp.status_code == 200
    assert resp.headers.get("x-patched-export-rows") == "2"


def test_devices_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access/devices.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


def test_drill_down_filters_to_one_product(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token,
               "/reports/software/remote-access/devices"
               "?product_key=remote_access%3Aapp%3Acom.philandro.anydesk")
    assert resp.status_code == 200
    sent = STUB_STATE["remote_access_devices_requests"][-1]
    assert sent.get("product_key") == "remote_access:app:com.philandro.anydesk"
    assert "acme-mbp-frontdesk" in resp.text
    assert "acme-win-accounts" not in resp.text


def test_drill_down_link_from_products_table_carries_product_key(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/remote-access")
    assert "product_key=remote_access%3Aapp%3Acom.philandro.anydesk" in resp.text


def test_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["remote_access_status"] = 500
    resp = _get(client, token, "/reports/software/remote-access")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_devices_drill_down_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["remote_access_devices_status"] = 500
    resp = _get(client, token, "/reports/software/remote-access/devices")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_no_copy_violations(client, make_token):
    """Neutral copy per this ticket's own instruction: 'not approved' or
    'not reviewed', never 'threat' or 'malicious'; plus the walker's own
    banned-word set (docs/portal-rubric.md C5-C7)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for path in ("/reports/software/remote-access", "/reports/software/remote-access/devices"):
        resp = _get(client, token, path)
        body = resp.text
        assert not re.search(r"\bspecialist\b", body, re.IGNORECASE)
        assert not re.search(r"\bfleet\b", body, re.IGNORECASE)
        assert "coming soon" not in body.lower()
        assert "—" not in body
        assert "threat" not in body.lower()
        assert "malicious" not in body.lower()


def test_reports_page_links_to_the_new_report(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/software/remote-access"' in resp.text


def test_summary_view_orders_unsanctioned_states_first():
    from main import _remote_access_summary_view
    view = _remote_access_summary_view(REMOTE_ACCESS_SUMMARY["summary"])
    order = [s["state"] for s in view["remote_access"]]
    assert order == ["unapproved", "unreviewed", "ignored", "approved"]
    assert view["rmm_agent_tool_count"] == 1
    assert view["remote_access_tool_count"] == 4
