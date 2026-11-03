"""Download framing must describe the bytes delivered, including at a gzip edge."""

import csv
import gzip
import io

import pytest

import main
from tests import conftest as stub


def _header(text):
    return next(csv.reader(io.StringIO(text)))


CSV_EXPORTS = [
    ("/devices.csv", list(main.CSV_COLUMNS)),
    ("/findings.csv", list(main.FINDINGS_CSV_COLUMNS)),
    ("/homebrew.csv", "kind,name,tap,third_party_tap,versions,device_count,installation_count,"
     "on_request_device_count,dependency_device_count,first_seen_at,evidence_at".split(",")),
    ("/local-admins.csv", "device_id,hostname,platform,reported_admin_count,assessed_admin_count,"
     "pass,membership_readable,collection_status,principal_name,principal_type,builtin,"
     "account_state,note".split(",")),
    ("/ai-tooling.csv", "product,type,vendor,platforms,versions,device_count,user_count,first_seen,"
     "last_seen,last_used_at,last_used_state,approval_state,assessment_state,"
     "vulnerability_finding_count,highest_severity".split(",")),
    ("/devices/jamf/coverage.csv", stub.JAMF_COVERAGE_CSV_HEADER),
    ("/ai-tooling/devices/dev-mac-001.csv",
     "item_id,device_id,hostname,block,name,assessment_state,finding_count".split(",")),
    ("/reports/new-software.csv", _header(stub.NEW_SOFTWARE_CSV)),
    ("/reports/software-drift.csv", _header(stub.SOFTWARE_DRIFT_CSV)),
    ("/reports/software/approved.csv", _header(stub.SOFTWARE_APPROVED_CSV)),
    ("/reports/software/unsupported.csv", _header(stub.SAM_UNSUPPORTED_CSV)),
    ("/reports/software/unsupported/devices.csv", _header(stub.SAM_UNSUPPORTED_CSV)),
    ("/reports/software/remote-access.csv", _header(stub.REMOTE_ACCESS_CSV)),
    ("/reports/software/remote-access/devices.csv", _header(stub.REMOTE_ACCESS_CSV)),
    ("/reports/software/version-sprawl.csv", _header(stub.VERSION_SPRAWL_CSV)),
    ("/reports/software/duplicate-tools.csv", _header(stub.DUPLICATE_TOOLS_CSV)),
    ("/reports/software/publishers.csv", _header(stub.PUBLISHERS_CSV)),
    ("/reports/software/publishers/devices.csv", _header(stub.PUBLISHERS_CSV)),
    ("/ce-readiness.csv", _header(stub.CE_READINESS_CSV)),
    ("/reports/insurance-evidence.csv", _header(stub.INSURANCE_EVIDENCE_CSV)),
]
PDF_EXPORTS = [
    ("/ce-readiness.pdf", stub.CE_READINESS_PDF),
    ("/reports/rep-0001/download", stub.PDF_BYTES),
    ("/reports/insurance-evidence.pdf", stub.INSURANCE_EVIDENCE_PDF),
]


@pytest.fixture(params=[False, True], ids=["plain", "gzip-edge"])
def download_edge(request, monkeypatch):
    """A local upstream edge that honours Accept-Encoding, as an HTTP proxy does."""
    original = stub.StubPlatformHandler.do_GET
    edge = {"encodings": [], "force": False}

    def serve(handler):
        output = handler.wfile
        handler.wfile = io.BytesIO()
        try:
            original(handler)
            captured = handler.wfile.getvalue()
        finally:
            handler.wfile = output
        headers, body = captured.split(b"\r\n\r\n", 1)
        if b"Content-Type: text/csv" in headers or b"Content-Type: application/pdf" in headers:
            accept = handler.headers.get("Accept-Encoding", "")
            edge["encodings"].append(accept)
            if edge["force"] or (request.param and "gzip" in accept):
                body = gzip.compress(body)
                lines = [line for line in headers.split(b"\r\n")
                         if not line.lower().startswith(b"content-length:")]
                headers = b"\r\n".join(lines + [b"Content-Encoding: gzip",
                                               f"Content-Length: {len(body)}".encode()])
        output.write(headers + b"\r\n\r\n" + body)

    monkeypatch.setattr(stub.StubPlatformHandler, "do_GET", serve)
    return edge


def _download(client, make_token, path):
    response = client.get(path, headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert response.status_code == 200
    assert response.content
    if "content-length" in response.headers:
        assert len(response.content) == int(response.headers["content-length"])
    return response


@pytest.mark.parametrize("path,header", CSV_EXPORTS, ids=[p for p, _ in CSV_EXPORTS])
def test_csv_downloads_are_complete(client, make_token, download_edge, path, header):
    stub.STUB_STATE["jamf_mode"] = "configured"
    response = _download(client, make_token, path)
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig")), strict=True))
    assert all(value == "identity" for value in download_edge["encodings"])
    assert rows[0] == header
    assert all(len(row) == len(header) for row in rows[1:])


@pytest.mark.parametrize("path,expected", PDF_EXPORTS, ids=[p for p, _ in PDF_EXPORTS])
def test_pdf_downloads_are_complete(client, make_token, download_edge, path, expected):
    response = _download(client, make_token, path)
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content == expected
    assert download_edge["encodings"] == ["identity"]


def test_every_csv_route_is_covered():
    expected = {path.replace("dev-mac-001", "{device_id}") for path, _ in CSV_EXPORTS}
    actual = {route.path for route in main.app.routes if route.path.endswith(".csv")}
    assert actual == expected


@pytest.mark.parametrize("path", [p for p, _ in CSV_EXPORTS[5:]] + [p for p, _ in PDF_EXPORTS])
def test_unnegotiated_compression_is_refused_before_download(
        client, make_token, download_edge, path):
    stub.STUB_STATE["jamf_mode"] = "configured"
    download_edge["force"] = True
    response = client.get(path, headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert response.status_code == 502
    assert response.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in response.headers
    assert len(response.content) == int(response.headers["content-length"])
