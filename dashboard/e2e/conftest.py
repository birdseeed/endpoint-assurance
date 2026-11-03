"""
e2e/conftest.py — spins up a real `uvicorn main:app` subprocess so Playwright
can drive an actual Chromium browser against the staff console (PAT-1021).

Deliberately NOT under tests/: `python -m pytest tests/` must keep passing
with no browser installed, and everything here needs Playwright + a live
server. The tests/ DB-isolation trick (`monkeypatch.setattr(dashboard,
"DB_PATH", tmp_path / "test.db")`) only works in-process against the FastAPI
TestClient — it can't reach an out-of-process uvicorn, hence the
DASHBOARD_DB_PATH env override added to shared.py for this suite.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent

# Fixed (not random) so a run's credentials are reproducible/greppable in
# failure output; the server + DB are throwaway per session regardless.
DASHBOARD_API_KEY = "e2e-test-bearer-key-pat-1021"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_up(proc: subprocess.Popen, base_url: str, timeout: float = 30.0) -> None:
    """Poll the server until it answers, or raise with whatever the
    subprocess printed if it exited early (e.g. an import-time error)."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            output = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(
                f"dashboard server exited early (code {proc.returncode}) "
                f"before answering:\n{output}"
            )
        try:
            r = requests.get(f"{base_url}/console", timeout=2, allow_redirects=True)
            if r.status_code < 500:
                return
            last_err = f"HTTP {r.status_code}"
        except requests.RequestException as exc:
            last_err = exc
        time.sleep(0.2)
    raise RuntimeError(f"dashboard server never came up at {base_url}: {last_err}")


@pytest.fixture(scope="session")
def dashboard_api_key() -> str:
    return DASHBOARD_API_KEY


@pytest.fixture(scope="session")
def api_headers(dashboard_api_key) -> dict:
    """The shared Bearer token — the same credential the Jarvis Job Scout
    bot and the rollback path use (see AGENTS.md's auth model section).
    Attaching it to the whole Playwright browser context means every fetch()
    the console's own JS makes is authenticated identically to a real
    scripted caller, with no dependency on the CF-Access-minted session
    cookie (which requires an HTTPS origin the local test server doesn't
    have)."""
    return {"Authorization": f"Bearer {dashboard_api_key}"}


class _StubInternalAPIHandler(BaseHTTPRequestHandler):
    """Always-200, generically-shaped JSON for every method/path. Stands in
    for the real internal Go API (patched-api-01, Tailscale-only, not
    reachable from this harness) that every /admin/* route in main.py
    proxies to.

    This isn't just a convenience — it's load-bearing. Several of those
    proxy routes (e.g. proxy_health at main.py's `/admin/health/proxy`)
    don't wrap the outbound `http.get(...)` in try/except, so an unreachable
    target raises an unhandled ConnectionError. That propagates up through
    the two stacked `@app.middleware("http")` functions (api_bearer_auth,
    impersonation_write_guard — both Starlette BaseHTTPMiddleware), and was
    observed during this ticket's work to destabilise the whole
    single-process dev server for several seconds per exception: unrelated
    requests on other connections (e.g. a fresh page's GET /console/<rev>)
    would hang for the client's full navigation timeout before completing.
    That's a genuine, pre-existing gap (missing exception handling, and
    arguably a BaseHTTPMiddleware/exception-propagation issue) — flagged as
    a follow-up, not fixed here (out of this ticket's file scope). Routing
    PATCHED_API_INTERNAL at this stub instead of a closed port means every
    proxy call gets an ordinary response and that whole crash path is never
    exercised, which also means every proxied panel renders real (if
    generic) content instead of a permanent error state.
    """

    def _respond(self):
        body = json.dumps({
            "tenants": [], "jobs": [], "service_health": {}, "devices": [],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_PUT(self):
        self._respond()

    def do_DELETE(self):
        self._respond()

    def do_PATCH(self):
        self._respond()

    def log_message(self, format, *args):  # noqa: A002 — BaseHTTPRequestHandler's signature
        pass  # keep pytest -v output free of the stub's own request log


@pytest.fixture(scope="session")
def _stub_internal_api():
    """Start/stop the stub above once for the whole E2E session. Yields its
    base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubInternalAPIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def dashboard_server(tmp_path_factory, dashboard_api_key, _stub_internal_api):
    """Launch `uvicorn main:app` as a real subprocess against a throwaway
    sqlite DB, and tear it down after the whole E2E session. Yields the
    server's base URL.
    """
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    db_path = tmp_path_factory.mktemp("dashboard-e2e-db") / "e2e.db"

    env = os.environ.copy()
    env["DASHBOARD_DB_PATH"] = str(db_path)
    env["DASHBOARD_API_KEY"] = dashboard_api_key
    # PAT-740: PATCHED_API_INTERNAL is deliberately env-overridable so a
    # local E2E harness can avoid depending on the real internal Go API
    # (patched-api-01, Tailscale-only). Point it at the local stub above
    # instead — see _StubInternalAPIHandler's docstring for why a closed
    # port isn't safe here — keeping this suite self-contained with no real
    # external services, matching the "uvicorn main:app starts with no
    # external services" baseline.
    env["PATCHED_API_INTERNAL"] = _stub_internal_api
    # Keep role/env deterministic: an unset operator list grants session users
    # consultant only, while an unset environment keeps the production banner.
    # This harness authenticates its admin requests via the separate Bearer path.
    env.pop("DASHBOARD_OPERATORS", None)
    env.pop("DASHBOARD_ENV", None)

    # main.py's startup() event spawns daemon threads (scheduler_loop,
    # report-schedule/trial-expiry checks, retention sweep) unless "pytest"
    # is already in sys.modules — a guard added under PAT-917 so
    # `TestClient`-based tests don't accumulate never-joined threads that
    # fire uncontrolled outbound HTTP calls mid-suite. Those threads call
    # real external services this harness never stands up (Graph,
    # Slack — separate from the PATCHED_API_INTERNAL stub above), so the
    # same rationale applies here: `import pytest` before importing
    # uvicorn/main so the *exact same* PAT-917 guard trips for this
    # subprocess too, reusing the intentional skip instead of duplicating
    # or forking it.
    bootstrap = (
        "import pytest\n"
        "import uvicorn\n"
        f"uvicorn.run('main:app', host='127.0.0.1', port={port})\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", bootstrap],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_until_up(proc, base_url)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        if proc.stdout:
            proc.stdout.close()
