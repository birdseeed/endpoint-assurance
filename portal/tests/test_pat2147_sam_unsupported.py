"""PAT-2147: SAM report - unsupported software.

Exercises /reports/software/unsupported and its device drill-down against
the stubbed platform (contracts/portal-api.md "GET /v1/portal/reports/
software/unsupported" and ".../devices"): all four states render honestly
(Unknown is never folded into Supported), the basis panel states partial
coverage plainly, CSV downloads proxy the platform's own bytes rather than
re-serialising portal-side, paging/filter query params are forwarded to the
platform, the drill-down filters to one product, and an unavailable
platform degrades to the portal's normal error page rather than crashing.
"""

import re

from tests.conftest import SAM_UNSUPPORTED_CSV, SAM_UNSUPPORTED_SUMMARY, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_all_four_states_render_and_unknown_is_never_supported(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported")
    assert resp.status_code == 200
    body = resp.text
    assert "Unsupported" in body
    assert "Ending within 90 days" in body
    assert "Unknown" in body
    assert "Supported" in body
    # The Unknown row (Proposed App) must carry the muted "unknown" pill
    # class, never the "ok"/pill-ok class Supported rows get.
    unknown_idx = body.index("Proposed App")
    row_start = body.rindex("<tr>", 0, unknown_idx)
    row_end = body.index("</tr>", unknown_idx)
    unknown_row = body[row_start:row_end]
    assert "pill-muted" in unknown_row
    assert "pill-ok" not in unknown_row
    assert "no published lifecycle mapping for this product" in unknown_row


def test_partial_basis_states_coverage_is_partial(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported")
    assert resp.status_code == 200
    body = resp.text
    assert "Coverage is partial" in body
    assert "not an audit or a compliance position" in body
    # The not_counted reason with a non-zero count is named, with its count.
    assert "IDE extensions, language packages" in body


def test_complete_basis_does_not_claim_partial_coverage(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    complete = dict(SAM_UNSUPPORTED_SUMMARY)
    complete["basis"] = {**complete["basis"], "complete": True}
    STUB_STATE["sam_unsupported_data"] = complete
    resp = _get(client, token, "/reports/software/unsupported")
    assert resp.status_code == 200
    assert "Coverage is partial" not in resp.text


def test_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers.get("x-patched-export-rows") == "4"
    assert resp.text == SAM_UNSUPPORTED_CSV
    # Filters reach the platform's CSV read too (format=csv, not re-derived).
    STUB_STATE["sam_unsupported_requests"] = []
    resp = _get(client, token, "/reports/software/unsupported.csv?state=unsupported")
    assert resp.status_code == 200
    assert resp.headers.get("x-patched-export-rows") == "1"
    sent = STUB_STATE["sam_unsupported_requests"][-1]
    assert sent.get("state") == "unsupported"
    assert sent.get("format") == "csv"


def test_devices_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported/devices.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == SAM_UNSUPPORTED_CSV


def test_state_and_paging_params_are_forwarded_to_the_platform(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token,
               "/reports/software/unsupported?state=ending_within_90_days&kind=operating_system"
               "&platform=windows&page=1")
    assert resp.status_code == 200
    sent = STUB_STATE["sam_unsupported_requests"][-1]
    assert sent.get("state") == "ending_within_90_days"
    assert sent.get("kind") == "operating_system"
    assert sent.get("platform") == "windows"
    assert sent.get("limit") == "50"
    assert sent.get("offset") == "0"
    # Only the matching Windows OS product row renders (not the macOS row):
    # the Windows edition string appears, the macOS version does not.
    assert "Microsoft Windows 10 Pro" in resp.text
    assert "13.6.1" not in resp.text


def test_drill_down_filters_to_one_product(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported/devices?product_key=os:macos")
    assert resp.status_code == 200
    sent = STUB_STATE["sam_devices_requests"][-1]
    assert sent.get("product_key") == "os:macos"
    assert "acme-mbp-frontdesk" in resp.text
    assert "acme-win-accounts" not in resp.text


def test_drill_down_link_from_products_table_carries_product_key(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported")
    assert "/reports/software/unsupported/devices?product_key=os%3Amacos" in resp.text


def test_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["sam_unsupported_status"] = 500
    resp = _get(client, token, "/reports/software/unsupported")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_devices_drill_down_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["sam_devices_status"] = 500
    resp = _get(client, token, "/reports/software/unsupported/devices")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_no_copy_violations(client, make_token):
    """Same banned-word set the walker's `copy` check enforces (docs/
    portal-rubric.md C5-C7), matched on word boundaries so an unrelated CSS
    class like "rail__specialist" (part of every page's chrome, not this
    report's own copy) does not produce a false positive."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for path in ("/reports/software/unsupported", "/reports/software/unsupported/devices"):
        resp = _get(client, token, path)
        body = resp.text
        assert not re.search(r"\bspecialist\b", body, re.IGNORECASE)
        assert not re.search(r"\bfleet\b", body, re.IGNORECASE)
        assert "coming soon" not in body.lower()
        assert "—" not in body
        assert "you fail" not in body.lower()
        assert "non-compliant" not in body.lower()


def test_cyber_essentials_block_is_evidence_only_language(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/unsupported")
    assert resp.status_code == 200
    body = resp.text
    assert "Cyber Essentials" in body
    assert "you fail" not in body.lower()
    assert "non-compliant" not in body.lower()


def test_cyber_essentials_missing_block_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    data = dict(SAM_UNSUPPORTED_SUMMARY)
    data.pop("cyber_essentials", None)
    STUB_STATE["sam_unsupported_data"] = data
    resp = _get(client, token, "/reports/software/unsupported")
    assert resp.status_code == 200
    assert "Cyber Essentials evidence is not available right now." in resp.text


def test_reports_page_links_to_the_new_sam_report(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/software/unsupported"' in resp.text
