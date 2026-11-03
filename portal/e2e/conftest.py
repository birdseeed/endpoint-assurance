"""Session fixtures for the browser-driven E2E suite (PAT-1021).

Two moving parts, both started once per test session:

  1. A stub of the go-service platform API, reusing tests/conftest.py's
     StubPlatformHandler and fixture data verbatim rather than inventing a
     second copy - same OVERVIEW/DEVICES/FINDINGS/... fixtures, same
     STUB_STATE call-count bookkeeping the mutation tests assert against.
  2. A `uvicorn e2e._harness:app` subprocess - the real portal app with
     Cloudflare Access verification stubbed (see e2e/_harness.py) - pointed
     at that stub backend.

Excluded from the default `pytest` run: pyproject.toml's `testpaths` is
`["tests", "scan/tests"]`, so a plain `pytest` never collects this
directory or needs Playwright installed. Run explicitly with `pytest e2e/`.

The stub-platform-server / harness-subprocess bodies below are exposed as
plain `@contextlib.contextmanager` functions (`stub_platform_server`,
`harness_process`) rather than only as pytest fixtures, so `e2e/walk/walk.py`
(PAT-2126 - a standalone CLI, not a pytest run) can start the exact same two
moving parts without a second, drifting copy of this subprocess-management
code. The pytest fixtures below are now thin wrappers over them.
"""

import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import requests
from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.conftest import (  # noqa: E402
    STUB_STATE,
    StubPlatformHandler,
    reset_approval_stub,
    reset_feedback_stub,
)

# Must match e2e/_harness.py's HARNESS_VALID_TOKEN - see that module's
# docstring for why the two are duplicated rather than shared via import.
HARNESS_VALID_TOKEN = "e2e-harness-token-do-not-use-in-prod"

HARNESS_STARTUP_TIMEOUT_SECONDS = 20.0
HARNESS_POLL_INTERVAL_SECONDS = 0.1


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def browser():
    """One Chromium instance for the whole e2e session, shared by every test
    module. sync_playwright()'s own event-loop guard means only one such
    context can be open per thread at a time (PAT-2070) - a second test
    module opening its own `with sync_playwright()` while this one is still
    live raises "already in an asyncio loop", so every test file gets its
    browser from this single session fixture instead of launching its own."""
    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch()
        yield chromium
        chromium.close()


@contextlib.contextmanager
def stub_platform_server():
    """Same stub server tests/conftest.py's `stub_platform` fixture starts,
    reused here (and by e2e/walk/walk.py) so every consumer exercises pages
    against the identical fixture data the pytest suite already covers."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), StubPlatformHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


@pytest.fixture(scope="session")
def stub_platform_url():
    with stub_platform_server() as url:
        yield url


@contextlib.contextmanager
def harness_process(stub_platform_url):
    """Launches the harness subprocess, polls /healthz (exempt from auth)
    until it answers, yields the base URL, and tears the process down
    reliably even if the caller raised."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    log_file = tempfile.NamedTemporaryFile(
        prefix="portal-e2e-harness-", suffix=".log", delete=False
    )
    env = dict(os.environ)
    env["PORTAL_E2E_HARNESS"] = "1"
    env["PLATFORM_BASE_URL"] = stub_platform_url
    # auth.verify_token is stubbed (see _harness.py) so no real JWT
    # verification happens here, but PAT-1585's sign-out link still calls
    # auth.issuer()/team_domain() directly on every authenticated render -
    # unset, that raises ConfigError on every page. Nothing needed this env
    # var before that link existed.
    env.setdefault("PORTAL_ACCESS_TEAM_DOMAIN", "e2e-harness.cloudflareaccess.com")

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "e2e._harness:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(REPO_ROOT), env=env, stdout=log_file, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + HARNESS_STARTUP_TIMEOUT_SECONDS
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break  # process exited early - definitely not ready
            try:
                resp = requests.get(f"{base_url}/healthz", timeout=1)
                if resp.status_code == 200:
                    ready = True
                    break
            except requests.RequestException:
                pass
            time.sleep(HARNESS_POLL_INTERVAL_SECONDS)

        if not ready:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            log_file.flush()
            output = Path(log_file.name).read_text(errors="replace")
            raise RuntimeError(
                "e2e harness subprocess never became healthy.\n"
                f"---- harness stdout/stderr ----\n{output}"
            )

        yield base_url
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        log_file.close()
        try:
            os.unlink(log_file.name)
        except OSError:
            pass


@pytest.fixture(scope="session")
def harness_url(stub_platform_url):
    with harness_process(stub_platform_url) as url:
        yield url


@pytest.fixture(autouse=True)
def reset_stub_state():
    """Mirrors tests/conftest.py's `client` fixture reset. Each e2e test
    starts from a clean call-count/mode baseline so the mutation
    assertions (schedule_puts, generate_calls, enrolment_posts) never see
    a previous test's writes."""
    STUB_STATE["mode"] = "ok"
    STUB_STATE["expected_jwt"] = None
    STUB_STATE["generate_calls"] = 0
    STUB_STATE["schedule"] = None
    STUB_STATE["schedule_puts"] = []
    STUB_STATE["enrolment_calls"] = 0
    STUB_STATE["enrolment_posts"] = []
    STUB_STATE["findings_data"] = None
    # PAT-2097 review fix: overview_data was missing from this reset (a
    # pre-existing gap this ticket's own e2e test exposed) - a test that
    # sets it to a custom overview payload otherwise leaks that payload
    # into every later e2e test in the same session, since STUB_STATE is
    # one module-level dict shared by the whole harness/stub server.
    STUB_STATE["overview_data"] = None
    STUB_STATE["overview_cards_data"] = None
    STUB_STATE["overview_cards_requests"] = []
    STUB_STATE["alerts_data"] = None
    STUB_STATE["alert_overrides"] = {}
    STUB_STATE["alert_history_overrides"] = {}
    STUB_STATE["alert_list_requests"] = []
    STUB_STATE["alert_acknowledge_posts"] = []
    STUB_STATE["ce_readiness_data"] = None
    STUB_STATE["ce_readiness_status"] = None
    STUB_STATE["ce_readiness_requests"] = []
    STUB_STATE["ce_readiness_csv_data"] = None
    STUB_STATE["local_admins_data"] = None
    STUB_STATE["local_admins_status"] = None
    STUB_STATE["local_admins_requests"] = []
    STUB_STATE["insurance_evidence_data"] = None
    STUB_STATE["insurance_evidence_status"] = None
    STUB_STATE["insurance_evidence_requests"] = []
    reset_approval_stub()
    reset_feedback_stub()
    yield
