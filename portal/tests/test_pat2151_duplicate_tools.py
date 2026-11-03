"""PAT-2151: SAM report - duplicate tools by category.

Exercises /reports/software/duplicate-tools against the stubbed platform
(contracts/portal-api.md "GET /v1/portal/reports/software/duplicate-tools"):
flagged categories (three or more distinct products) render ahead of
unflagged ones and expanded, unflagged categories render collapsed, the
pending "two or more paid products" rule is stated, the category filter is
forwarded to the platform, CSV downloads proxy the platform's own bytes, and
an unavailable platform degrades honestly.
"""

import re

from tests.conftest import DUPLICATE_TOOLS_CSV, DUPLICATE_TOOLS_SUMMARY, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_flagged_categories_render_ahead_of_unflagged(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    body = resp.text
    assert "Password managers" in body
    assert "VPN clients" in body
    assert body.index("Password managers") < body.index("VPN clients")


def test_flagged_category_shows_consolidation_pill(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    body = resp.text
    assert "Consolidation candidate" in body
    # The flagged card sits ahead of the unflagged "Other categories" card.
    flagged_idx = body.index("Consolidation candidate")
    other_idx = body.index("Other categories")
    assert flagged_idx < other_idx


def test_unflagged_category_is_collapsed(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    body = resp.text
    assert "<details>" in body
    details_idx = body.index("<details>")
    vpn_idx = body.index("VPN clients")
    summary_close_idx = body.index("</summary>", details_idx)
    assert details_idx < vpn_idx < summary_close_idx


def test_products_table_shows_installs_devices_users_and_pill(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    body = resp.text
    assert "1Password" in body
    assert "Bitwarden" in body
    assert "alice" in body
    assert "Unapproved" in body
    assert "Unreviewed" in body


def test_paid_products_rule_pending_is_stated(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    assert "two or more paid products" in resp.text.lower()


def test_partial_basis_states_coverage_is_partial(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 200
    assert "Coverage is partial" in resp.text


def test_category_param_is_forwarded(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools?category=vpn_client")
    assert resp.status_code == 200
    sent = STUB_STATE["duplicate_tools_requests"][-1]
    assert sent.get("category") == "vpn_client"
    assert "VPN clients" in resp.text
    assert "Password managers" not in resp.text


def test_unknown_category_param_is_dropped(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools?category=not_a_real_category")
    assert resp.status_code == 200
    sent = STUB_STATE["duplicate_tools_requests"][-1]
    assert "category" not in sent


def test_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == DUPLICATE_TOOLS_CSV
    assert resp.headers.get("x-patched-export-rows") == "6"


def test_csv_download_filters_by_category(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools.csv?category=vpn_client")
    assert resp.status_code == 200
    assert resp.headers.get("x-patched-export-rows") == "2"


def test_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["duplicate_tools_status"] = 500
    resp = _get(client, token, "/reports/software/duplicate-tools")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_no_copy_violations(client, make_token):
    """Neutral copy per this ticket's own instruction: 'consolidation
    candidates', never 'waste'; plus the walker's own banned-word set
    (docs/portal-rubric.md C5-C7)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/duplicate-tools")
    body = resp.text
    assert not re.search(r"\bspecialist\b", body, re.IGNORECASE)
    assert not re.search(r"\bfleet\b", body, re.IGNORECASE)
    assert "coming soon" not in body.lower()
    assert "—" not in body
    assert not re.search(r"\bwaste\b", body, re.IGNORECASE)


def test_reports_page_links_to_the_new_report(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/software/duplicate-tools"' in resp.text


def test_category_row_builder_marks_flagged_category():
    from main import _duplicate_tools_category_row
    row = _duplicate_tools_category_row(DUPLICATE_TOOLS_SUMMARY["categories"][0])
    assert row["flagged"] is True
    assert row["product_count"] == 3
    assert len(row["products"]) == 3


def test_basis_view_carries_paid_products_rule_pending():
    from main import _duplicate_tools_basis_view
    basis = _duplicate_tools_basis_view(DUPLICATE_TOOLS_SUMMARY["basis"])
    assert basis["paid_products_rule_pending"] is True
