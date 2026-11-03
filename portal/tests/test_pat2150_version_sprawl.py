"""PAT-2150: SAM report - version sprawl.

Exercises /reports/software/version-sprawl against the stubbed platform
(contracts/portal-api.md "GET /v1/portal/reports/software/version-sprawl"):
a CVE count that was never assessed renders "Not assessed", never a bare 0;
an unknown latest-released version renders "Not known" (PAT-2509); the basis panel and
per-product version breakdown render; platform filters/paging are forwarded;
CSV downloads proxy the platform's own bytes; and an unavailable platform
degrades honestly.
"""

import re

from tests.conftest import STUB_STATE, VERSION_SPRAWL_CSV, VERSION_SPRAWL_SUMMARY


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _row(body, name):
    """The full outer <tr>...</tr> for a product, skipping past its nested
    per-version <details> table so the boundary lands on the outer row's own
    closing tag rather than the first nested one."""
    name_idx = body.index(name)
    row_start = body.rindex("<tr>", 0, name_idx)
    window = body[name_idx:name_idx + 4000]
    after_details = body.index("</details>", name_idx) if "</details>" in window else name_idx
    row_end = body.index("</tr>", after_details)
    return body[row_start:row_end]


def test_not_assessed_cve_never_renders_as_zero(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 200
    body = resp.text
    assert "NotAssessedApp" in body
    row = _row(body, "NotAssessedApp")
    assert "Not assessed" in row
    # Never a bare 0 rendered for the not-assessed row's CVE cell.
    assert ">0 CVE" not in row.replace(" ", "")


def test_real_zero_cve_count_still_renders_as_zero(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 200
    body = resp.text
    row = _row(body, "SingleVersionApp")
    assert "0 CVEs" in row


def test_unknown_latest_released_shows_not_known(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 200
    body = resp.text
    row = _row(body, "UnknownLatestApp")
    # The product's own name contains "Unknown", so check the cell, not the row.
    cell = re.search(r'<td data-label="Latest released">(.*?)</td>', row, re.DOTALL)
    assert cell
    assert cell.group(1).strip() == "Not known"


def test_known_latest_released_shows_its_source(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 200
    body = resp.text
    row = _row(body, "ManyVersionApp")
    assert "10.4.0" in row
    assert "endoflife.date" in row


def test_per_product_version_breakdown_is_an_expandable_details_element(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 200
    body = resp.text
    assert "<details>" in body
    assert "<summary>3 versions</summary>" in body
    assert "9.5.0" in body


def test_partial_basis_states_coverage_is_partial(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 200
    assert "Coverage is partial" in resp.text


def test_platform_param_is_forwarded_to_the_platform(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl?platform=windows")
    assert resp.status_code == 200
    sent = STUB_STATE["version_sprawl_requests"][-1]
    assert sent.get("platform") == "windows"
    assert sent.get("limit") == "50"
    assert sent.get("offset") == "0"
    assert "SingleVersionApp" in resp.text
    assert "ManyVersionApp" not in resp.text


def test_csv_download_proxies_platform_bytes(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == VERSION_SPRAWL_CSV
    assert resp.headers.get("x-patched-export-rows") == "5"


def test_unavailable_platform_degrades_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["version_sprawl_status"] = 500
    resp = _get(client, token, "/reports/software/version-sprawl")
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_no_copy_violations(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/version-sprawl")
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
    assert 'href="/reports/software/version-sprawl"' in resp.text


def test_product_row_builder_never_reports_zero_when_not_assessed():
    from main import _version_sprawl_product_row
    raw = next(p for p in VERSION_SPRAWL_SUMMARY["products"] if p["name"] == "NotAssessedApp")
    row = _version_sprawl_product_row(raw)
    assert row["cve_not_assessed_on_oldest_version"] is True
    assert row["cve_count_on_oldest_version"] is None
