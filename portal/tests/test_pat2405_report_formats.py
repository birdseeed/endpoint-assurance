"""Every generated report downloads as a PDF or a CSV (PAT-2405, portal half).

The stub platform in conftest.py models the fixed contract: GET
/v1/portal/reports/{id}?format=pdf|csv, `formats` on history entries, an old
record with PDF only (rep-0002) and an older-platform record with no
`formats` field at all (rep-0003).
"""

import re

import pytest

from tests.conftest import CSV_BYTES, PDF_BYTES, STREAM_FAIL_DECLARED_LENGTH, STUB_STATE

NOTE = "CSV is available for newly generated reports."


def _get(client, token, path):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _row(html, report_id):
    """The history row's actions cell for one report."""
    match = re.search(
        rf'<tr>(?:(?!</tr>).)*?/reports/{report_id}/download.*?</tr>', html, re.S)
    assert match, f"no history row for {report_id}"
    return match.group(0)


# ── Download route ──────────────────────────────────────────────────────

def test_csv_download_streams_text_csv_with_a_csv_filename(client, make_token):
    resp = _get(client, make_token(), "/reports/rep-0001/download?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/csv; charset=utf-8"
    assert resp.headers["content-disposition"] == 'attachment; filename="acme-report.csv"'
    assert resp.content == CSV_BYTES
    assert resp.headers["content-length"] == str(len(CSV_BYTES))
    assert STUB_STATE["report_download_calls"] == [("rep-0001", "csv")]


@pytest.mark.parametrize("path", [
    "/reports/rep-0001/download",
    "/reports/rep-0001/download?format=",
    "/reports/rep-0001/download?format=pdf",
])
def test_default_and_pdf_download_are_unchanged(client, make_token, path):
    resp = _get(client, make_token(), path)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/pdf")
    assert "acme-report.pdf" in resp.headers["content-disposition"]
    assert resp.content == PDF_BYTES
    assert STUB_STATE["report_download_calls"] == [("rep-0001", "pdf")]


@pytest.mark.parametrize("query", [
    "format=xlsx", "format=PDF", "format=csv&format=pdf", "format=pdf&format=pdf",
    "format=csv%0d%0a", "format=..%2Fsecret", "format=pdf%20",
])
def test_unknown_or_repeated_format_is_a_400_without_an_upstream_call(
        client, make_token, query):
    resp = _get(client, make_token(), f"/reports/rep-0001/download?{query}")
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in resp.headers
    assert "Back to Reports" in resp.text
    assert STUB_STATE["report_download_calls"] == []


def test_csv_for_a_report_generated_before_csv_explains_itself(client, make_token):
    resp = _get(client, make_token(), "/reports/rep-0002/download?format=csv")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in resp.headers
    assert "generated before CSV downloads existed" in resp.text
    assert 'href="/reports"' in resp.text
    # The platform's own body is never reflected.
    assert "csv_not_available" not in resp.text
    assert "stub-platform-internal-body" not in resp.text
    # Its PDF still downloads.
    pdf = _get(client, make_token(), "/reports/rep-0002/download")
    assert pdf.status_code == 200 and pdf.content == PDF_BYTES


@pytest.mark.parametrize("fmt", ["pdf", "csv"])
def test_another_tenants_report_is_the_normal_not_found(client, make_token, fmt):
    resp = _get(client, make_token(), f"/reports/rep-other-tenant/download?format={fmt}")
    assert resp.status_code == 404
    assert "That item could not be found in your estate." in resp.text
    assert "generated before CSV" not in resp.text


def test_report_id_stays_out_of_the_query_and_format_stays_out_of_the_path(
        client, make_token):
    resp = _get(client, make_token(), "/reports/rep-0001%3Fformat=csv/download?format=pdf")
    assert resp.status_code == 404
    assert all(fmt in ("pdf", "csv") for _, fmt in STUB_STATE["report_download_calls"])


def test_csv_mid_stream_failure_is_not_a_clean_200(client, make_token):
    STUB_STATE["mode"] = "stream_fail"
    resp = _get(client, make_token(), "/reports/rep-0001/download?format=csv")
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-length"] == str(STREAM_FAIL_DECLARED_LENGTH)
    assert len(resp.content) < STREAM_FAIL_DECLARED_LENGTH


# ── History links ───────────────────────────────────────────────────────

def test_history_offers_both_links_when_the_report_has_a_csv(client, make_token):
    row = _row(_get(client, make_token(), "/reports").text, "rep-0001")
    assert 'href="/reports/rep-0001/download">Download PDF</a>' in row
    assert 'href="/reports/rep-0001/download?format=csv">Download CSV</a>' in row
    assert NOTE not in row


def test_history_shows_pdf_and_a_note_for_a_report_without_csv(client, make_token):
    row = _row(_get(client, make_token(), "/reports").text, "rep-0002")
    assert "Download PDF" in row
    assert "Download CSV" not in row
    assert NOTE in row


def test_history_from_an_older_platform_shows_pdf_only_with_no_note(client, make_token):
    row = _row(_get(client, make_token(), "/reports").text, "rep-0003")
    assert "Download PDF" in row
    assert "Download CSV" not in row
    assert NOTE not in row and "newly generated" not in row


def test_viewer_sees_both_links_and_can_download_both(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    row = _row(_get(client, token, "/reports").text, "rep-0001")
    assert "Download PDF" in row and "Download CSV" in row
    assert _get(client, token, "/reports/rep-0001/download?format=csv").content == CSV_BYTES
    assert _get(client, token, "/reports/rep-0001/download").content == PDF_BYTES


def test_page_says_once_that_reports_come_in_both_formats(client, make_token):
    html = _get(client, make_token(), "/reports").text
    assert html.count("can be downloaded as a PDF or a CSV") == 1
    assert "produced as both a PDF and a CSV" in html
