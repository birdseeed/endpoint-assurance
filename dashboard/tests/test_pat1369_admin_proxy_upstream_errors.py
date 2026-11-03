"""
Tests for PAT-1369: an unreachable/timed-out PATCHED_API_INTERNAL let a bare
requests.ConnectionError/Timeout escape every `/admin/*` proxy route. Neither
of the two stacked BaseHTTPMiddleware instances in main.py (api_bearer_auth,
impersonation_write_guard) catch it, so it reached FastAPI's default handler
as an unhandled 500 for every one of the ~150 routes that call out to
PATCHED_API_INTERNAL.

Coverage:
  - Connection refused (a real closed TCP port, not mocked) no longer 500s.
  - A request that times out mid-connect no longer 500s.
  - A real upstream 5xx (no exception at all) also degrades sensibly:
    /admin/health/proxy previously hard-coded `return JSONResponse(data)`
    with no status_code, silently turning a real upstream failure into an
    outward 200.
  - The degraded response is distinguishable from "upstream answered with
    nothing" (PAT-912/PAT-837/PAT-960 shape) via an explicit `degraded` flag,
    not just an empty body.
  - proxy_tenant_removal_summary specifically: it used to collapse any
    non-200 upstream response into the exact same {"apps": {}} shape a
    tenant with genuinely zero removals returns.
  - Every PATCHED_API_INTERNAL call site has both a timeout and now sits
    behind the shared connection/timeout handling (regression guard against
    a new call site being added without either).
"""

import json
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import requests  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def _closed_port() -> int:
    """A real TCP port on localhost that nothing is listening on: bind then
    immediately release it, so connecting to it gets a genuine, immediate
    ECONNREFUSED from the OS. Not mocked."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fake_response(status_code: int, body: dict) -> requests.Response:
    """A real requests.Response standing in for a completed (non-exception)
    upstream reply, e.g. a genuine HTTP 500 from patched-api-01."""
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = json.dumps(body).encode("utf-8")
    resp.headers["Content-Type"] = "application/json"
    return resp


# ── Connection refused: real closed port, not mocked ──────────────────────

class TestConnectionRefused:
    def test_admin_health_proxy_degrades_instead_of_500(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", f"http://127.0.0.1:{_closed_port()}")
        r = client.get("/admin/health/proxy", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        body = r.json()
        assert body.get("degraded") is True
        assert "error" in body

    def test_generic_proxy_route_degrades_instead_of_500(self, client, monkeypatch):
        """proxy_tenants_revoked is a plain `r = http.get(...); return _proxy_json(r)`
        route, representative of the ~110 routes sharing that shape."""
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", f"http://127.0.0.1:{_closed_port()}")
        r = client.get("/admin/tenants/revoked", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        body = r.json()
        assert body.get("degraded") is True
        assert "error" in body

    def test_removal_summary_degrades_instead_of_500(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", f"http://127.0.0.1:{_closed_port()}")
        r = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/removal-summary", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        body = r.json()
        assert body.get("degraded") is True

    def test_route_with_no_json_body_still_returns_a_real_status(self, client, monkeypatch):
        """proxy_tenant_offboard-style routes only ever forward r.status_code:
        a synthetic 503 must still surface as a non-2xx, not crash."""
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", f"http://127.0.0.1:{_closed_port()}")
        r = client.delete(
            "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
            headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
        )
        assert r.status_code != 500, r.text
        assert r.status_code == 503


# ── Timeout mid-connect ─────────────────────────────────────────────────────

class TestUpstreamTimeout:
    def test_admin_health_proxy_degrades_on_timeout(self, client, monkeypatch):
        def _raise_timeout(self, method, url, *a, **kw):
            raise requests.exceptions.ConnectTimeout("simulated connect timeout")

        monkeypatch.setattr(requests.Session, "request", _raise_timeout)
        r = client.get("/admin/health/proxy", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        assert r.json().get("degraded") is True

    def test_generic_proxy_route_degrades_on_timeout(self, client, monkeypatch):
        def _raise_timeout(self, method, url, *a, **kw):
            raise requests.exceptions.ReadTimeout("simulated read timeout")

        monkeypatch.setattr(requests.Session, "request", _raise_timeout)
        r = client.get("/admin/tenants/revoked", headers=BEARER)
        assert r.status_code != 500, r.text
        assert r.status_code == 503
        assert r.json().get("degraded") is True


# ── Real upstream 5xx (no exception at all) ────────────────────────────────

class TestUpstream5xx:
    def test_admin_health_proxy_forwards_real_upstream_5xx(self, client, monkeypatch):
        """Independent of any connection/timeout handling: proxy_health used to
        hard-code `return JSONResponse(data)` with no status_code, so even a
        real, cleanly-answered upstream 500 came back to the console as 200."""

        def _fake_request(self, method, url, *a, **kw):
            return _fake_response(500, {"error": "internal error on api-01"})

        monkeypatch.setattr(requests.Session, "request", _fake_request)
        r = client.get("/admin/health/proxy", headers=BEARER)
        assert r.status_code == 500
        assert r.status_code != 200

    def test_generic_proxy_route_forwards_real_upstream_5xx(self, client, monkeypatch):
        def _fake_request(self, method, url, *a, **kw):
            return _fake_response(502, {"error": "bad gateway"})

        monkeypatch.setattr(requests.Session, "request", _fake_request)
        r = client.get("/admin/tenants/revoked", headers=BEARER)
        assert r.status_code == 502


# ── Degraded must be distinguishable from a genuinely empty upstream reply ──

class TestDegradedIsDistinguishableFromEmpty:
    def test_removal_summary_empty_success_has_no_degraded_flag(self, client, monkeypatch):
        """Control case: a tenant with zero enrolled devices is a real, healthy
        200. Must NOT be flagged degraded."""

        def _fake_request(self, method, url, *a, **kw):
            return _fake_response(200, {"devices": []})

        monkeypatch.setattr(requests.Session, "request", _fake_request)
        r = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/removal-summary", headers=BEARER)
        assert r.status_code == 200
        body = r.json()
        assert body == {"apps": {}}
        assert "degraded" not in body

    def test_removal_summary_failure_is_flagged_degraded(self, client, monkeypatch):
        """The failure case must not collapse into the exact same {"apps": {}}
        shape as the control case above, which was the PAT-912/PAT-837/PAT-960
        anti-pattern this ticket exists to close off."""
        monkeypatch.setattr(dashboard, "PATCHED_API_INTERNAL", f"http://127.0.0.1:{_closed_port()}")
        r = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/removal-summary", headers=BEARER)
        assert r.status_code != 200
        body = r.json()
        assert body.get("apps") == {}
        assert body.get("degraded") is True
        assert "error" in body


# ── Every PATCHED_API_INTERNAL call site: timeout present, no bare except ──

class TestEveryUpstreamCallSiteHasATimeout:
    def test_no_admin_proxy_call_is_missing_a_timeout(self):
        """Static regression guard: every `http.<verb>(` call in main.py must
        carry an explicit `timeout=` in the same call. A call with no
        timeout is its own outage waiting to happen. Mirrors the audit done
        for PAT-1369; keeps a future call site from being added without one."""
        import re

        text = (dashboard.BASE / "main.py").read_text() if hasattr(dashboard, "BASE") else open(
            os.path.join(os.path.dirname(__file__), "..", "main.py")
        ).read()

        pattern = re.compile(r"http\.(get|post|put|delete|patch)\(")
        missing = []
        for m in pattern.finditer(text):
            start = m.end() - 1
            depth = 0
            j = start
            while j < len(text):
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            call_text = text[start:j + 1]
            if "timeout=" not in call_text:
                lineno = text.count("\n", 0, m.start()) + 1
                missing.append(lineno)

        assert not missing, f"http call(s) missing an explicit timeout= at line(s): {missing}"

    def test_api_session_only_catches_connection_and_timeout_errors(self):
        """Guard against the catch widening into a bare `except Exception`,
        which would also swallow real programming errors. PAT-1813 added
        ChunkedEncodingError/ContentDecodingError to the same tuple (both
        raised from the same "upstream never answered" family, just from the
        body read instead of the connect) — assert the named exception types
        explicitly rather than pinning the tuple's exact source formatting."""
        import inspect

        src = inspect.getsource(dashboard._ApiSession.request)
        assert "except Exception" not in src
        for exc_name in (
            "requests.exceptions.ConnectionError",
            "requests.exceptions.Timeout",
            "requests.exceptions.ChunkedEncodingError",
            "requests.exceptions.ContentDecodingError",
        ):
            assert exc_name in src, f"{exc_name} no longer caught by _ApiSession.request"
