"""
Tests for PAT-1813: two of the five parallel fetches tenant Overview issues
(`_ov2Load` in templates/console.html) came back as raw HTTP 500s with
patched-api-01 unreachable, instead of the clean degraded 503 PAT-1369 was
supposed to guarantee for every `/admin/*` proxy route.

Root cause: PAT-1369's fix only caught requests.exceptions.ConnectionError
and requests.exceptions.Timeout in `_ApiSession.request()`. Those two cover
a connection that never happens at all (refused, timed out mid-connect,
DNS failure). They do NOT cover a connection that succeeds, receives
headers, and then dies while the body is being read (peer reset,
a Tailscale path dropping mid-transfer) — that raises
requests.exceptions.ChunkedEncodingError (or ContentDecodingError from the
same code path), a plain RequestException subclass that is not a
ConnectionError or a Timeout.

The critical detail: requests.Session.send() eagerly reads `r.content` for
any non-streamed call (`if not stream: r.content`), and every proxy route
in main.py calls `http.get/post/...` without `stream=True`. That means the
body read — and any exception it raises — happens INSIDE the same
`super().request(...)` call `_ApiSession.request()` already wraps in
try/except, not after it returns. So this is case (a): the except clause's
exception tuple was incomplete, not a route-specific bug — reproduced below
identically through five different proxy routes with a single shared
mechanism (a raw socket server that sends a truncated body then resets the
connection), matching how only *some* of a parallel fetch fan-out would hit
this depending on how far each individual connection got before dying.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import requests  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


class _ResetMidBodyServer:
    """A real TCP server (not mocked) that accepts a connection, sends valid
    HTTP headers declaring a Content-Length larger than the body it actually
    sends, then closes the socket — reproducing a connection that dies
    mid-transfer rather than one that never connects. Not a mock: this is
    the same "peer reset while streaming the body" failure a Tailscale path
    drop or a crashing upstream produces."""

    def __init__(self, requests_to_serve: int = 1):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self._n = requests_to_serve
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        for _ in range(self._n):
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 100\r\n"
                    b"\r\n"
                    b'{"partial":'
                )
                time.sleep(0.05)
            finally:
                conn.close()
        self._sock.close()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app, raise_server_exceptions=False) as test_client:
        yield test_client


# ── The exact exception, isolated from any route/HTTP plumbing ────────────


def test_connection_reset_mid_body_raises_chunked_encoding_error_unwrapped():
    """Establishes the premise directly against requests.Session (bypassing
    _ApiSession entirely): a connection that dies mid-body raises
    ChunkedEncodingError, not ConnectionError/Timeout. If this assertion
    ever starts failing, requests' internals changed and the fix below
    should be revisited, not deleted."""
    server = _ResetMidBodyServer(requests_to_serve=1)
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        requests.get(f"{server.base_url}/x", timeout=5)


# ── _ApiSession.request() no longer lets it escape ─────────────────────────


class TestChunkedEncodingErrorDegrades:
    @pytest.mark.parametrize(
        "path",
        [
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/needs-attention",
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/devices",
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/apps",
            "/api/tenant/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/certs",
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/enrolled-devices",
        ],
    )
    def test_ov2load_fanout_route_degrades_instead_of_500(self, client, monkeypatch, path):
        """All five routes _ov2Load fans out to: reproduced against each
        individually, since the original report only saw it on two of the
        five — the failure mode is about how far each connection got before
        the peer reset it, not something specific to any one route."""
        server = _ResetMidBodyServer(requests_to_serve=1)
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", server.base_url)
        r = client.get(path, headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        body = r.json()
        assert body.get("degraded") is True
        assert "error" in body

    def test_generic_proxy_route_degrades_on_chunked_encoding_error(self, client, monkeypatch):
        """Direct route to the shared _ApiSession.request() code path, mirroring
        test_pat1369's own generic-route coverage for ConnectionError/Timeout."""
        server = _ResetMidBodyServer(requests_to_serve=1)
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", server.base_url)
        r = client.get("/admin/tenants/revoked", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        body = r.json()
        assert body.get("degraded") is True

    def test_content_decoding_error_also_degrades(self, client, monkeypatch):
        """Same code path in requests (models.py Response.iter_content's
        generate()) also converts a DecodeError into ContentDecodingError —
        added to the same except tuple for the same reason."""

        def _raise(self, method, url, *a, **kw):
            raise requests.exceptions.ContentDecodingError("simulated bad content-encoding")

        monkeypatch.setattr(requests.Session, "request", _raise)
        r = client.get("/admin/tenants/revoked", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        assert r.json().get("degraded") is True
