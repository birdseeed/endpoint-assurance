"""
PAT-2306: tests must not make real outbound HTTP requests.

Before this, a few tests reached the real PATCHED_API_INTERNAL default
(https://patched-api-01.example-tailnet.ts.net:8443) and, on a tailnet machine,
production api-01. tests/conftest.py now pins PATCHED_API_INTERNAL to an
unroutable address and installs an autouse guard on requests' adapter.

Every URL in this file is a reserved documentation address (RFC 5737), so
even if the guard were broken these tests could not reach a real host.

Run with: pytest tests/test_pat2306_no_real_network.py -v
"""

import ipaddress
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests
import requests.adapters

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from tests.conftest import NetworkBlockedError  # noqa: E402

# Captured at import (collection) time, before any per-test fixture runs.
_REAL_SEND = requests.adapters.HTTPAdapter.send

TEST_NET_3 = "https://203.0.113.10"  # RFC 5737, never routed


def test_patched_api_internal_is_the_unroutable_test_value():
    assert dashboard.PATCHED_API_INTERNAL == "https://192.0.2.1:9"
    assert os.environ["PATCHED_API_INTERNAL"] == dashboard.PATCHED_API_INTERNAL
    host = ipaddress.ip_address(urlparse(dashboard.PATCHED_API_INTERNAL).hostname)
    assert host in ipaddress.ip_network("192.0.2.0/24")  # TEST-NET-1
    assert "example-tailnet" not in dashboard.PATCHED_API_INTERNAL


def test_guard_is_installed_for_the_test(block_real_network):
    assert requests.adapters.HTTPAdapter.send is not _REAL_SEND
    assert block_real_network == []


def test_app_http_helper_raises_instead_of_leaving_the_machine(block_real_network):
    url = f"{dashboard.PATCHED_API_INTERNAL}/admin/tenants"
    # The app's real HTTP helper, with the real URL a route would build. It
    # must raise. It must not come back as the degraded 503 that _ApiSession
    # substitutes for requests' own connection errors, which would look like a
    # working (if unhappy) code path.
    with pytest.raises(NetworkBlockedError) as excinfo:
        dashboard.http.get(url, timeout=1, verify=dashboard._VERIFY_INTERNAL)
    assert url in str(excinfo.value)
    assert block_real_network == [f"GET {url}"]
    block_real_network.clear()  # attempt asserted on; don't fail teardown


@pytest.mark.parametrize(
    "call",
    [
        lambda: requests.get(f"{TEST_NET_3}/x", timeout=1),
        lambda: requests.post(f"{TEST_NET_3}/x", json={}, timeout=1),
        lambda: requests.Session().put(f"{TEST_NET_3}/x", timeout=1),
        lambda: requests.request("DELETE", f"{TEST_NET_3}/x", timeout=1),
    ],
    ids=["requests.get", "requests.post", "Session.put", "requests.request"],
)
def test_direct_requests_calls_are_blocked_too(block_real_network, call):
    # A call that skips main._ApiSession and uses requests directly (truth.py
    # does this) is caught at the adapter, so a new direct call cannot bypass
    # the guard.
    with pytest.raises(NetworkBlockedError):
        call()
    assert len(block_real_network) == 1
    assert TEST_NET_3 in block_real_network[0]
    block_real_network.clear()


def test_loopback_is_not_blocked(block_real_network):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        session = requests.Session()
        session.trust_env = False  # ignore any proxy in the developer's shell
        r = session.get(f"http://127.0.0.1:{server.server_address[1]}/", timeout=5)
    finally:
        server.shutdown()
        server.server_close()
    assert r.status_code == 200
    assert block_real_network == []


@pytest.mark.allow_network
def test_allow_network_marker_leaves_the_real_layer_in_place():
    # No request is made: the marker only has to leave requests untouched.
    assert requests.adapters.HTTPAdapter.send is _REAL_SEND


def test_network_down_degrades_like_an_unreachable_api(network_down):
    # An internal call goes through _ApiSession, which turns a connection
    # failure into a degraded 503 (PAT-1369). Same as a real dead upstream.
    r = dashboard.http.get(f"{dashboard.PATCHED_API_INTERNAL}/admin/tenants", timeout=1)
    assert r.status_code == 503
    assert r.json()["degraded"] is True
    # Anything else gets requests' own error, which callers already handle.
    with pytest.raises(requests.exceptions.ConnectionError):
        dashboard.http.post("https://hooks.slack.test/fake", json={}, timeout=1)


def test_an_attempt_swallowed_by_the_app_still_fails_the_test(tmp_path):
    """A route wrapped in `except Exception` would otherwise let an un-stubbed
    call pass by accident. Run the real conftest in a throwaway session and
    check that such a test is reported as failing."""
    shutil.copy(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_swallows.py").write_text(
        "import requests\n"
        "\n"
        "def test_swallows_the_block():\n"
        "    try:\n"
        "        requests.get('https://198.51.100.7/swallowed', timeout=1)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "GET https://198.51.100.7/swallowed" in output, output
