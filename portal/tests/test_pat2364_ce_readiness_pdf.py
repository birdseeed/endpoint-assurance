"""Customer CE PDF downloads retain the platform's evidence and tenant scope."""

import asyncio
from types import SimpleNamespace

import pytest
import requests

import main
import upstream
from tests.conftest import STUB_STATE

PDF = b"%PDF-1.7\nSynthetic dated customer evidence\n%%EOF\n"
DISPOSITION = 'attachment; filename="ce-readiness-2026-10-02.pdf"'


class PDFResponse:
    headers = {
        "Content-Type": "application/pdf",
        "Content-Disposition": DISPOSITION,
        "Content-Length": str(len(PDF)),
        "Cache-Control": "private, no-store",
    }

    def __init__(self, interrupted=False):
        self.closed = False
        self.interrupted = interrupted

    def iter_content(self, chunk_size):
        yield PDF[:12]
        if self.interrupted:
            raise requests.exceptions.ChunkedEncodingError("synthetic interrupted transfer")
        yield PDF[12:]

    def close(self):
        self.closed = True


@pytest.fixture
def pdf_upstream(monkeypatch):
    calls = []
    response = PDFResponse()

    def stream(path, jwt, params=None):
        calls.append((path, jwt, params))
        return response

    monkeypatch.setattr(upstream, "stream", stream)
    return response, calls


@pytest.mark.parametrize("role", ["admin", "viewer", "service_readonly"])
def test_ce_page_offers_pdf_alongside_existing_csv(client, make_token, role):
    STUB_STATE["portal_role"] = role
    response = client.get("/ce-readiness", headers={"Cf-Access-Jwt-Assertion": make_token()})
    assert response.status_code == 200
    assert 'href="/ce-readiness.pdf"' in response.text
    assert "Download evidence pack (PDF)" in response.text
    assert 'href="/ce-readiness.csv"' in response.text


@pytest.mark.parametrize("role", ["admin", "viewer", "service_readonly"])
def test_pdf_is_a_verbatim_read_for_each_ce_role(client, make_token, pdf_upstream, role):
    STUB_STATE["portal_role"] = role
    token = make_token()
    response = client.get(
        "/ce-readiness.pdf?tenant=other&tenant_id=other&format=csv",
        headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == DISPOSITION
    assert response.headers["content-length"] == str(len(PDF))
    assert response.content == PDF
    streamed, calls = pdf_upstream
    assert calls == [("/v1/portal/ce-readiness", token, {"format": "pdf"})]
    assert streamed.closed


@pytest.mark.parametrize("identity", ["missing", "no-email", "expired"])
def test_pdf_requires_verified_identity(client, make_token, pdf_upstream, identity):
    token = (make_token(drop_email=True) if identity == "no-email"
             else make_token(exp_delta=-60) if identity == "expired" else None)
    headers = {"Cf-Access-Jwt-Assertion": token} if token else {}
    response = client.get("/ce-readiness.pdf", headers=headers)
    assert response.status_code == 401
    assert not pdf_upstream[1]
    assert "content-disposition" not in response.headers


def test_pdf_customer_evidence_is_private_and_not_stored(client, make_token, pdf_upstream):
    response = client.get("/ce-readiness.pdf", headers={
        "Cf-Access-Jwt-Assertion": make_token()})
    assert response.status_code == 200
    assert response.headers.get("cache-control") == "private, no-store"


@pytest.mark.parametrize("kind,status", [
    ("auth", 401), ("forbidden", 403), ("not_enabled", 503), ("unavailable", 502),
])
def test_platform_refusal_never_downloads_an_error_as_pdf(
        client, make_token, monkeypatch, kind, status):
    def refuse(*args, **kwargs):
        raise upstream.UpstreamError(kind, "synthetic refusal")

    monkeypatch.setattr(upstream, "stream", refuse)
    response = client.get("/ce-readiness.pdf", headers={
        "Cf-Access-Jwt-Assertion": make_token()})
    assert response.status_code == status
    assert response.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in response.headers
    assert not response.content.startswith(b"%PDF")


def test_interrupted_pdf_closes_upstream_and_preserves_truncation_guard(monkeypatch):
    route = next((r for r in main.app.routes if r.path == "/ce-readiness.pdf"), None)
    assert route is not None, "authenticated CE PDF route is missing"
    streamed = PDFResponse(interrupted=True)
    monkeypatch.setattr(upstream, "stream", lambda *args, **kwargs: streamed)
    response = route.endpoint(SimpleNamespace(state=SimpleNamespace(jwt="synthetic assertion")))
    assert response.headers["content-length"] == str(len(PDF))

    async def consume():
        chunks = []
        with pytest.raises(upstream.UpstreamStreamError, match="interrupted"):
            async for chunk in response.body_iterator:
                chunks.append(chunk)
        assert chunks == [PDF[:12]]

    asyncio.run(consume())
    assert streamed.closed
