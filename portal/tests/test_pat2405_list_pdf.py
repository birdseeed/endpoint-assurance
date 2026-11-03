"""Every CSV list export has a matching PDF download (PAT-2405).

The PDF is rendered by the platform (POST /v1/portal/exports/table-pdf); the
portal sends it the same header and rows its CSV twin writes, for the same
request, and streams back the platform's bytes. These tests stub that
endpoint (tests/conftest.py `_table_pdf_post`) and prove, for every route:
the PDF body equals the CSV's own table, the filters travel, the role rule
is the CSV's, and a platform refusal is the portal's normal error page.
"""

import copy
import csv
import io
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import main
import upstream
from tests.conftest import (
    AI_TAGGED_PRODUCTS,
    LOCAL_ADMINS_DATA,
    STUB_STATE,
    TABLE_PDF_BYTES,
)

ROOT = Path(__file__).resolve().parent.parent

# (id, csv path, pdf path, export key, expected filters, request-log key, params that must
# reach the data fetch). Every query is one a page link or a bookmark can carry.
ROUTES = [
    ("devices", "/devices.csv", "/devices.pdf", "devices", [], None, {}),
    ("devices-stale", "/devices.csv?stale_days=30", "/devices.pdf?stale_days=30",
     "devices-stale", [("Stale for at least", "30 days")], None, {}),
    ("jamf", "/devices/jamf/coverage.csv", "/devices/jamf/coverage.pdf",
     "jamf-coverage", [], "jamf_coverage_requests", {"format": "csv"}),
    ("jamf-gap", "/devices/jamf/coverage.csv?bucket=gap", "/devices/jamf/coverage.pdf?bucket=gap",
     "jamf-coverage", [("Show", "Managed by Jamf, not seen by Patched")],
     "jamf_coverage_requests", {"format": "csv", "bucket": "gap"}),
    ("findings", "/findings.csv", "/findings.pdf", "findings", [], None, {}),
    ("homebrew", "/homebrew.csv", "/homebrew.pdf", "homebrew", [], None, {}),
    ("local-admins", "/local-admins.csv", "/local-admins.pdf", "local-admins", [], None, {}),
    ("local-admins-view",
     "/local-admins.csv?scope=view&view=device&platform=windows&over_limit=yes&search=acme",
     "/local-admins.pdf?scope=view&view=device&platform=windows&over_limit=yes&search=acme",
     "local-admins",
     [("View", "By device"), ("Search", "acme"), ("Platform", "Windows"),
      ("Admin count", "Over the limit")], None, {}),
    ("ai-tooling", "/ai-tooling.csv", "/ai-tooling.pdf", "ai-tooling", [], None, {}),
    ("ai-device", "/ai-tooling/devices/dev-mac-001.csv", "/ai-tooling/devices/dev-mac-001.pdf",
     "ai-tooling-device", [("Device", "dev-mac-001")], "ai_tooling_item_requests", {}),
    ("unsupported", "/reports/software/unsupported.csv",
     "/reports/software/unsupported.pdf", "software-unsupported", [],
     "sam_unsupported_requests", {"format": "csv"}),
    ("unsupported-filtered",
     "/reports/software/unsupported.csv?state=unsupported&kind=operating_system&platform=macos",
     "/reports/software/unsupported.pdf?state=unsupported&kind=operating_system&platform=macos",
     "software-unsupported",
     [("State", "Unsupported"), ("Kind", "Operating system"), ("Platform", "macOS")],
     "sam_unsupported_requests",
     {"format": "csv", "state": "unsupported", "kind": "operating_system", "platform": "macos"}),
    ("unsupported-devices", "/reports/software/unsupported/devices.csv",
     "/reports/software/unsupported/devices.pdf", "software-unsupported-devices", [],
     "sam_devices_requests", {"format": "csv"}),
    ("unsupported-devices-filtered",
     "/reports/software/unsupported/devices.csv?state=unknown&product_key=os:macos",
     "/reports/software/unsupported/devices.pdf?state=unknown&product_key=os:macos",
     "software-unsupported-devices",
     [("State", "Unknown"), ("Product", "os:macos")], "sam_devices_requests",
     {"format": "csv", "state": "unknown", "product_key": "os:macos"}),
    ("remote-access", "/reports/software/remote-access.csv",
     "/reports/software/remote-access.pdf", "software-remote-access", [],
     "remote_access_requests", {"format": "csv"}),
    ("remote-access-filtered",
     "/reports/software/remote-access.csv?category=remote_access&state=unapproved&platform=macos",
     "/reports/software/remote-access.pdf?category=remote_access&state=unapproved&platform=macos",
     "software-remote-access",
     [("Category", "Remote access"), ("Approval state", "Unapproved"), ("Platform", "macOS")],
     "remote_access_requests",
     {"format": "csv", "category": "remote_access", "state": "unapproved", "platform": "macos"}),
    ("remote-access-devices", "/reports/software/remote-access/devices.csv",
     "/reports/software/remote-access/devices.pdf", "software-remote-access-devices", [],
     "remote_access_devices_requests", {"format": "csv"}),
    ("version-sprawl", "/reports/software/version-sprawl.csv",
     "/reports/software/version-sprawl.pdf", "software-version-sprawl", [],
     "version_sprawl_requests", {"format": "csv"}),
    ("version-sprawl-filtered", "/reports/software/version-sprawl.csv?platform=windows",
     "/reports/software/version-sprawl.pdf?platform=windows", "software-version-sprawl",
     [("Platform", "Windows")], "version_sprawl_requests",
     {"format": "csv", "platform": "windows"}),
    ("duplicate-tools", "/reports/software/duplicate-tools.csv",
     "/reports/software/duplicate-tools.pdf", "software-duplicate-tools", [],
     "duplicate_tools_requests", {"format": "csv"}),
    ("duplicate-tools-filtered", "/reports/software/duplicate-tools.csv?category=vpn_client",
     "/reports/software/duplicate-tools.pdf?category=vpn_client", "software-duplicate-tools",
     [("Category", "VPN client")], "duplicate_tools_requests",
     {"format": "csv", "category": "vpn_client"}),
    ("publishers", "/reports/software/publishers.csv", "/reports/software/publishers.pdf",
     "software-publishers", [], "publishers_requests", {"format": "csv"}),
    ("publishers-filtered", "/reports/software/publishers.csv?group=unverified&platform=macos",
     "/reports/software/publishers.pdf?group=unverified&platform=macos",
     "software-publishers", [("Publisher group", "Unverified"), ("Platform", "macOS")],
     "publishers_requests", {"format": "csv", "group": "unverified", "platform": "macos"}),
    ("publishers-devices", "/reports/software/publishers/devices.csv",
     "/reports/software/publishers/devices.pdf", "software-publishers-devices", [],
     "publishers_devices_requests", {"format": "csv"}),
]
IDS = [r[0] for r in ROUTES]


def _get(client, path, token, role="admin"):
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = role
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _unneutralise(cell):
    """The inverse of the spreadsheet formula prefix: one leading apostrophe
    in front of a formula trigger."""
    if cell.startswith("'"):
        rest = cell[1:]
        if rest.startswith(("\t", "\r", "\n")) or rest.lstrip().startswith(("=", "+", "-", "@")):
            return rest
    return cell


def _csv_table(response):
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig")), strict=True))
    return rows[0], [[_unneutralise(c) for c in r] for r in rows[1:]]


@pytest.fixture(autouse=True)
def _configured(client):
    STUB_STATE["jamf_mode"] = "configured"
    yield


def _logged(key):
    entries = STUB_STATE[key]
    assert entries, f"no data fetch recorded in {key}"
    last = entries[-1]
    if "query" in last:
        return {k: v[0] for k, v in last["query"].items()}
    return {k: str(v) for k, v in last.items() if k != "jwt"}


# ── (1) the PDF body is the CSV's own table ──────────────────────────────────

@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_pdf_body_equals_the_csv_twins_table(client, make_token, route):
    _, csv_path, pdf_path, export, filters, log_key, params = route
    token = make_token()
    csv_resp = _get(client, csv_path, token)
    assert csv_resp.status_code == 200
    columns, rows = _csv_table(csv_resp)
    assert rows, "fixture must give the comparison at least one data row"

    pdf = _get(client, pdf_path, token)
    assert pdf.status_code == 200, pdf.text[:300]
    assert len(STUB_STATE["table_pdf_posts"]) == 1
    post = STUB_STATE["table_pdf_posts"][0]
    assert post["jwt"] == token
    assert post["content_type"].startswith("application/json")
    body = post["body"]
    assert body["export"] == export
    assert body["columns"] == columns
    assert body["rows"] == rows
    assert body["filters"] == [{"label": a, "value": b} for a, b in filters]
    assert "total_rows" not in body or body["total_rows"] == len(rows)
    assert set(body) <= {"export", "filters", "columns", "rows", "total_rows"}


# ── (2) response framing ─────────────────────────────────────────────────────

@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_pdf_response_is_the_platforms_bytes_as_an_attachment(client, make_token, route):
    _, csv_path, pdf_path, *_ = route
    token = make_token()
    csv_resp = _get(client, csv_path, token)
    pdf = _get(client, pdf_path, token)
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content == TABLE_PDF_BYTES
    disposition = pdf.headers["content-disposition"]
    assert re.fullmatch(r'attachment; filename="[A-Za-z0-9._-]+\.pdf"', disposition), disposition
    assert pdf.headers["cache-control"] == "private, no-store"
    # The PDF mirrors the CSV's own name with the extension changed.
    csv_name = re.search(r'filename="([^"]+)\.csv"', csv_resp.headers["content-disposition"])
    assert csv_name
    assert disposition == f'attachment; filename="{csv_name.group(1)}.pdf"'


# ── (3) filters reach the data fetch ─────────────────────────────────────────

@pytest.mark.parametrize("route", [r for r in ROUTES if r[5]], ids=[r[0] for r in ROUTES if r[5]])
def test_query_filters_reach_the_upstream_data_fetch(client, make_token, route):
    _, _csv, pdf_path, _export, _filters, log_key, params = route
    pdf = _get(client, pdf_path, make_token())
    assert pdf.status_code == 200
    seen = _logged(log_key)
    for key, value in params.items():
        assert seen.get(key) == value, (key, seen)


def test_stale_filter_selects_the_same_rows_as_the_csv(client, make_token):
    token = make_token()
    unfiltered = _get(client, "/devices.pdf", token)
    all_rows = STUB_STATE["table_pdf_posts"][-1]["body"]["rows"]
    stale = _get(client, "/devices.pdf?stale_days=14", token)
    stale_rows = STUB_STATE["table_pdf_posts"][-1]["body"]["rows"]
    assert unfiltered.status_code == stale.status_code == 200
    assert 0 < len(stale_rows) < len(all_rows)
    _, csv_rows = _csv_table(_get(client, "/devices.csv?stale_days=14", token))
    assert stale_rows == csv_rows


def test_local_admins_bare_pdf_ignores_filters_exactly_as_the_csv_does(client, make_token):
    token = make_token()
    csv_resp = _get(client, "/local-admins.csv?platform=windows", token)
    _get(client, "/local-admins.pdf?platform=windows", token)
    body = STUB_STATE["table_pdf_posts"][-1]["body"]
    assert body["rows"] == _csv_table(csv_resp)[1]
    assert body["filters"] == []


# ── Preamble-free: every table is one header plus rows ───────────────────────

def test_jamf_coverage_pdf_is_the_one_row_table(client, make_token):
    _get(client, "/devices/jamf/coverage.pdf", make_token())
    body = STUB_STATE["table_pdf_posts"][-1]["body"]
    assert body["columns"][0] == "bucket"
    assert all(len(r) == len(body["columns"]) for r in body["rows"])


# ── Neutralisation is a spreadsheet concern, not a PDF one ───────────────────

def test_local_admins_formula_cell_is_neutralised_in_csv_but_real_in_pdf(client, make_token):
    data = copy.deepcopy(LOCAL_ADMINS_DATA)
    data["devices"][0]["hostname"] = "=HYPERLINK(\"http://x\")"
    STUB_STATE["local_admins_data"] = data
    token = make_token()
    csv_resp = _get(client, "/local-admins.csv", token)
    assert "'=HYPERLINK" in csv_resp.text
    _get(client, "/local-admins.pdf", token)
    cells = [c for r in STUB_STATE["table_pdf_posts"][-1]["body"]["rows"] for c in r]
    assert '=HYPERLINK("http://x")' in cells
    assert not any(c.startswith("'=") for c in cells)


def test_ai_tooling_formula_cell_is_neutralised_in_csv_but_real_in_pdf(client, make_token):
    data = copy.deepcopy(AI_TAGGED_PRODUCTS)
    data["products"] = [{**data["products"][0], "name": "\t=TAB"},
                        {**data["products"][1], "name": "+SUM(1)"}]
    STUB_STATE["ai_tagged_products_data"] = data
    token = make_token()
    csv_resp = _get(client, "/ai-tooling.csv", token)
    assert "'\t=TAB" in csv_resp.text
    _get(client, "/ai-tooling.pdf", token)
    names = [r[0] for r in STUB_STATE["table_pdf_posts"][-1]["body"]["rows"]]
    assert names == ["\t=TAB", "+SUM(1)"]


def test_platform_neutralised_proxy_cell_arrives_without_the_prefix(client, make_token):
    STUB_STATE["sam_csv_data"] = (
        "device_id,hostname,name\r\ndev-1,mac-1,'=cmd|' /C calc'!A1\r\n"
        "dev-2,mac-2,it's fine\r\n")
    token = make_token()
    assert "'=cmd" in _get(client, "/reports/software/unsupported.csv", token).text
    _get(client, "/reports/software/unsupported.pdf", token)
    rows = STUB_STATE["table_pdf_posts"][-1]["body"]["rows"]
    assert rows == [["dev-1", "mac-1", "=cmd|' /C calc'!A1"], ["dev-2", "mac-2", "it's fine"]]


def test_all_pdf_cells_are_strings_with_none_empty(client, make_token):
    for path in ("/devices.pdf", "/findings.pdf", "/homebrew.pdf", "/local-admins.pdf",
                 "/ai-tooling.pdf"):
        _get(client, path, make_token())
        body = STUB_STATE["table_pdf_posts"][-1]["body"]
        assert all(isinstance(c, str) for r in body["rows"] for c in r), path
        assert all("None" != c for r in body["rows"] for c in r), path


# ── Row cap ──────────────────────────────────────────────────────────────────

def _many_findings(count):
    return {"total": count, "findings": [
        {"cve_id": f"CVE-2026-{i:05d}", "severity": "high", "cvss": 7.5, "app": "App",
         "version": "1.0", "match_confidence": "high", "fixed_version": "1.1",
         "devices_affected": 1, "first_seen": "2026-09-01T00:00:00Z", "summary": "s"}
        for i in range(count)]}


def _serve_findings(monkeypatch, findings):
    """Serve `findings` from the findings endpoint in the pages asked for;
    every other platform read goes to the stub as normal."""
    real = upstream.get_json

    def fake(path, jwt, params=None):
        if path == "/v1/portal/findings":
            off, lim = params["offset"], params["limit"]
            return {"total": len(findings), "findings": findings[off:off + lim]}
        return real(path, jwt, params=params)

    monkeypatch.setattr(upstream, "get_json", fake)


def test_more_than_ten_thousand_rows_sends_ten_thousand_and_the_real_total(
        client, make_token, monkeypatch):
    # The findings walk is capped at 50 pages of 500; serve 12,000 in 500s.
    full = _many_findings(12000)

    _serve_findings(monkeypatch, full["findings"])
    token = make_token()
    resp = _get(client, "/findings.pdf", token)
    assert resp.status_code == 200
    body = STUB_STATE["table_pdf_posts"][-1]["body"]
    assert len(body["rows"]) == 10000
    assert body["total_rows"] == 12000
    assert body["rows"][0][0] == "CVE-2026-00000" and body["rows"][-1][0] == "CVE-2026-09999"
    # The CSV is never capped.
    assert _get(client, "/findings.csv", token).text.count("\r\n") == 12001


def test_exactly_ten_thousand_rows_needs_no_total(client, make_token, monkeypatch):
    full = _many_findings(10000)
    _serve_findings(monkeypatch, full["findings"])
    _get(client, "/findings.pdf", make_token())
    body = STUB_STATE["table_pdf_posts"][-1]["body"]
    assert len(body["rows"]) == 10000
    assert body.get("total_rows") in (None, 10000)


def test_body_over_the_size_limit_is_trimmed_to_fit_with_the_real_total(
        client, make_token, monkeypatch):
    big = "x" * 4000
    rows = [{**_many_findings(1)["findings"][0], "cve_id": f"CVE-{i}", "summary": big}
            for i in range(5000)]
    _serve_findings(monkeypatch, rows)
    resp = _get(client, "/findings.pdf", make_token())
    assert resp.status_code == 200
    post = STUB_STATE["table_pdf_posts"][-1]
    assert post["raw_length"] < 16 * 1024 * 1024
    assert 0 < len(post["body"]["rows"]) < 5000
    assert post["body"]["total_rows"] == 5000


# ── Role rule ────────────────────────────────────────────────────────────────

def test_local_admins_pdf_is_refused_to_a_viewer_with_no_pdf_call(client, make_token):
    token = make_token()
    csv_resp = _get(client, "/local-admins.csv", token, role="viewer")
    pdf = _get(client, "/local-admins.pdf", token, role="viewer")
    assert pdf.status_code == csv_resp.status_code == 403
    assert pdf.text == csv_resp.text
    assert pdf.headers["content-type"] == csv_resp.headers["content-type"]
    assert STUB_STATE["table_pdf_posts"] == []


def test_local_admins_pdf_refusal_from_the_platform_is_the_same_refusal(client, make_token):
    token = make_token()
    csv_refusal = _get(client, "/local-admins.csv", token, role="viewer")
    STUB_STATE["portal_role"] = "admin"
    # The roster read succeeds but the PDF endpoint answers 403 admin_role_required.
    STUB_STATE["table_pdf_status"] = 403
    pdf = client.get("/local-admins.pdf", headers={"Cf-Access-Jwt-Assertion": token})
    assert pdf.status_code == 403
    assert pdf.text == csv_refusal.text
    assert "content-disposition" not in pdf.headers


@pytest.mark.parametrize("route", ROUTES, ids=IDS)
def test_requires_auth(client, route):
    assert client.get(route[2]).status_code == 401
    assert STUB_STATE["table_pdf_posts"] == []


# ── Errors are the portal's own pages ────────────────────────────────────────

@pytest.mark.parametrize("status,expected,marker", [
    (403, 403, "not linked"),
    (400, 502, "Temporarily unavailable"),
    (500, 502, "Temporarily unavailable"),
    (503, 503, "not yet enabled"),
    (401, 401, None),
])
@pytest.mark.parametrize("route", [ROUTES[0], ROUTES[2], ROUTES[4], ROUTES[10], ROUTES[8]],
                         ids=["devices", "jamf", "findings", "unsupported", "ai-tooling"])
def test_platform_pdf_errors_render_the_portals_error_pages(
        client, make_token, route, status, expected, marker):
    STUB_STATE["table_pdf_status"] = status
    resp = _get(client, route[2], make_token())
    assert resp.status_code == expected
    assert resp.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in resp.headers
    assert "Traceback" not in resp.text
    if marker:
        assert marker.lower() in resp.text.lower()


def test_unreachable_pdf_service_is_the_unavailable_page(client, make_token, monkeypatch):
    def boom(*a, **k):
        raise upstream.UpstreamError("unavailable", "timeout")
    monkeypatch.setattr(upstream, "post_bytes", boom)
    resp = _get(client, "/devices.pdf", make_token())
    assert resp.status_code == 502
    assert "Temporarily unavailable" in resp.text


def test_a_non_pdf_answer_is_not_forwarded_as_a_download(client, make_token):
    STUB_STATE["table_pdf_content_type"] = "text/html"
    resp = _get(client, "/devices.pdf", make_token())
    assert resp.status_code == 502
    assert "content-disposition" not in resp.headers
    assert "not a pdf" not in resp.text


@pytest.mark.parametrize(
    "path", ["/devices.pdf", "/findings.pdf", "/reports/software/unsupported.pdf"])
def test_data_fetch_failure_makes_no_pdf_call(client, make_token, path):
    STUB_STATE["mode"] = "down503"
    resp = _get(client, path, make_token())
    assert resp.status_code == 503
    assert STUB_STATE["table_pdf_posts"] == []


def test_a_ragged_platform_csv_is_refused_not_guessed_at(client, make_token):
    STUB_STATE["sam_csv_data"] = "a,b\r\n1,2,3\r\n"
    resp = _get(client, "/reports/software/unsupported.pdf", make_token())
    assert resp.status_code == 502
    assert STUB_STATE["table_pdf_posts"] == []


# ── Upstream helper ──────────────────────────────────────────────────────────

def test_post_bytes_sends_json_with_the_jwt_and_returns_bytes(client, stub_platform):
    STUB_STATE["expected_jwt"] = "tok"
    payload = {"export": "x", "filters": [], "columns": ["a"], "rows": [["1"]]}
    assert upstream.post_bytes("/v1/portal/exports/table-pdf", "tok", payload) == TABLE_PDF_BYTES
    assert STUB_STATE["table_pdf_posts"][-1]["body"] == payload


# ── Templates: every CSV link has its PDF twin with the same query ───────────

TEMPLATE_LINKS = {
    "devices.html": ["/devices.csv"],
    "devices_stale.html": ["/devices.csv?stale_days={{ stale_days }}"],
    "devices_jamf.html": ["/devices/jamf/coverage.csv"],
    "homebrew.html": ["/homebrew.csv"],
    "local_admins.html": ["/local-admins.csv", "{{ export_view_url }}"],
    "ai_tooling.html": ["/ai-tooling.csv"],
    "ai_tooling_device.html": ["/ai-tooling/devices/{{ device_id }}.csv"],
}
CSV_URL_TEMPLATES = [
    "software_report_unsupported.html", "software_report_unsupported_devices.html",
    "software_report_remote_access.html", "software_report_remote_access_devices.html",
    "software_report_version_sprawl.html", "software_report_duplicate_tools.html",
    "software_report_publishers.html", "software_report_publishers_devices.html",
]


@pytest.mark.parametrize("name,links", sorted(TEMPLATE_LINKS.items()))
def test_templates_link_the_pdf_twin_with_the_same_query(name, links):
    text = (ROOT / "templates" / name).read_text()
    for link in links:
        assert f'href="{link}"' in text
        twin = link.replace(".csv", ".pdf")
        if link.startswith("{{ export_view_url"):
            twin = "{{ export_view_pdf_url }}"
        assert f'href="{twin}"' in text, f"{name} lacks a PDF twin for {link}"


@pytest.mark.parametrize("name", CSV_URL_TEMPLATES)
def test_report_templates_link_the_pdf_twin(name):
    text = (ROOT / "templates" / name).read_text()
    assert 'href="{{ csv_url }}"' in text
    assert 'href="{{ pdf_url }}"' in text
    assert "Download PDF" in text


@pytest.mark.parametrize("path,twin", [
    ("/devices", "/devices.pdf"),
    ("/devices?view=stale&stale_days=14", "/devices.pdf?stale_days=14"),
    ("/devices/jamf", "/devices/jamf/coverage.pdf"),
    ("/homebrew", "/homebrew.pdf"),
    ("/local-admins", "/local-admins.pdf"),
    ("/ai-tooling", "/ai-tooling.pdf"),
    ("/ai-tooling/devices/dev-mac-001", "/ai-tooling/devices/dev-mac-001.pdf"),
    ("/reports/software/unsupported?state=unsupported",
     "/reports/software/unsupported.pdf?state=unsupported"),
    ("/reports/software/unsupported/devices?platform=macos",
     "/reports/software/unsupported/devices.pdf?platform=macos"),
    ("/reports/software/remote-access?platform=macos",
     "/reports/software/remote-access.pdf?platform=macos"),
    ("/reports/software/remote-access/devices?platform=macos",
     "/reports/software/remote-access/devices.pdf?platform=macos"),
    ("/reports/software/version-sprawl?platform=macos",
     "/reports/software/version-sprawl.pdf?platform=macos"),
    ("/reports/software/duplicate-tools?category=vpn_client",
     "/reports/software/duplicate-tools.pdf?category=vpn_client"),
    ("/reports/software/publishers?group=unverified",
     "/reports/software/publishers.pdf?group=unverified"),
    ("/reports/software/publishers/devices?platform=macos",
     "/reports/software/publishers/devices.pdf?platform=macos"),
])
def test_rendered_pages_carry_a_download_pdf_link_beside_the_csv_link(
        client, make_token, path, twin):
    resp = _get(client, path, make_token())
    assert resp.status_code == 200
    html = resp.text.replace("&amp;", "&")
    assert f'href="{twin}"' in html, twin
    assert "Download PDF" in html or "Export" in html or "PDF" in html


def test_local_admins_page_links_both_pdf_exports(client, make_token):
    html = _get(client, "/local-admins?view=device&platform=windows", make_token()).text
    html = html.replace("&amp;", "&")
    assert 'href="/local-admins.pdf"' in html
    link = re.search(r'href="(/local-admins\.pdf\?[^"]+)"', html)
    assert link
    query = parse_qs(urlsplit(link.group(1)).query)
    assert query["scope"] == ["view"] and query["platform"] == ["windows"]
    assert query["view"] == ["device"]
    # Same query string as the filtered CSV twin beside it.
    csv_link = re.search(r'href="(/local-admins\.csv\?[^"]+)"', html).group(1)
    assert parse_qs(urlsplit(csv_link).query) == query


def test_no_pdf_routes_for_the_exports_that_already_have_one():
    paths = {route.path for route in main.app.routes}
    for path in ("/reports/new-software.pdf", "/reports/software-drift.pdf",
                 "/reports/software/approved.pdf"):
        assert path not in paths
    assert "/ce-readiness.pdf" in paths and "/reports/insurance-evidence.pdf" in paths


def test_every_list_csv_route_has_a_pdf_twin():
    skipped = {"/reports/new-software.csv", "/reports/software-drift.csv",
               "/reports/software/approved.csv", "/ce-readiness.csv",
               "/reports/insurance-evidence.csv"}
    paths = {route.path for route in main.app.routes}
    for path in paths:
        if path.endswith(".csv") and path not in skipped:
            assert path[:-4] + ".pdf" in paths, path
