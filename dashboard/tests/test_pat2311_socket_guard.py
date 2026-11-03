"""PAT-2311: the test network guard also covers urllib and raw sockets.

PAT-2306's guard sits on requests' HTTPAdapter.send. scanner.py downloads the
NVD feed with urllib, and main._ops_cert_expiry opens a raw TLS socket with
socket.create_connection; neither goes through requests. tests/conftest.py now
also guards socket.socket.connect/connect_ex and socket.create_connection for
non-loopback destinations, with the same error and the same teardown check.

Every non-loopback address here is a reserved documentation address (RFC 5737)
or a reserved .invalid name (RFC 2606), so even with the guard broken these
tests could not reach a real host.

Run with: pytest tests/test_pat2311_socket_guard.py -v
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from tests.conftest import NetworkBlockedError, _socket_allowed  # noqa: E402

# Captured at import (collection) time, before any per-test fixture runs.
_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_REAL_CREATE_CONNECTION = socket.create_connection

TEST_NET_3 = "203.0.113.10"  # RFC 5737, never routed


def test_the_socket_guard_is_installed_for_the_test(block_real_network):
    assert socket.socket.connect is not _REAL_CONNECT
    assert socket.socket.connect_ex is not _REAL_CONNECT_EX
    assert socket.create_connection is not _REAL_CREATE_CONNECTION


def test_a_urllib_request_is_blocked(block_real_network):
    """scanner.sync_nvd_local_dataset fetches the NVD feed this way."""
    with pytest.raises(NetworkBlockedError) as excinfo:
        urllib.request.urlopen(f"https://{TEST_NET_3}/feed.zip", timeout=1)
    assert TEST_NET_3 in str(excinfo.value)
    assert block_real_network == [f"socket.create_connection {TEST_NET_3}:443"]
    block_real_network.clear()


def test_a_raw_socket_connect_is_blocked(block_real_network):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(NetworkBlockedError):
            sock.connect((TEST_NET_3, 443))
        with pytest.raises(NetworkBlockedError):
            sock.connect_ex((TEST_NET_3, 443))
    finally:
        sock.close()
    assert block_real_network == [
        f"socket connect {TEST_NET_3}:443",
        f"socket connect_ex {TEST_NET_3}:443",
    ]
    block_real_network.clear()


def test_a_blocked_name_is_never_resolved(block_real_network, monkeypatch):
    lookups = []
    real_getaddrinfo = socket.getaddrinfo

    def recording_getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", recording_getaddrinfo)
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("blocked.example.invalid", 8443), timeout=1)
    assert lookups == []
    block_real_network.clear()


def test_the_tls_cert_expiry_probe_is_blocked_even_though_it_swallows_errors(block_real_network):
    """_ops_cert_expiry catches every exception and returns it as an error
    field, so without the socket guard an un-stubbed call from a test would
    open a real TLS connection and pass. The attempt is still recorded, and
    an unasserted one fails the test at teardown."""
    result = dashboard._ops_cert_expiry(TEST_NET_3)
    assert "real network blocked in tests" in result["error"]
    assert block_real_network == [f"socket.create_connection {TEST_NET_3}:443"]
    block_real_network.clear()


def test_loopback_sockets_are_not_blocked(block_real_network):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    # Three connections are made and none is accepted: a backlog of 1 fills
    # on Linux and the third SYN is dropped until it times out.
    server.listen(8)
    port = server.getsockname()[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        with socket.create_connection(("localhost", port), timeout=5):
            pass
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(("127.0.0.1", port))
        finally:
            client.close()
    finally:
        server.close()
    assert block_real_network == []


def test_unix_domain_sockets_are_not_network(block_real_network):
    assert _socket_allowed("/run/some.sock")
    assert _socket_allowed(b"/run/some.sock")
    # A short directory: AF_UNIX paths are limited to about 100 bytes.
    directory = tempfile.mkdtemp(prefix="p2311", dir="/tmp")
    path = os.path.join(directory, "s")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        server.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(path)
        finally:
            client.close()
    finally:
        server.close()
        shutil.rmtree(directory, ignore_errors=True)
    assert block_real_network == []


@pytest.mark.parametrize(
    "address, allowed",
    [
        (("127.0.0.1", 80), True),
        (("127.8.9.10", 80), True),
        (("::1", 80, 0, 0), True),
        (("localhost", 80), True),
        (("LOCALHOST", 80), True),
        (("203.0.113.10", 443), False),
        (("::ffff:203.0.113.10", 443, 0, 0), False),
        (("0.0.0.0", 443), False),
        (("blocked.example.invalid", 8443), False),
        (("", 80), False),
    ],
)
def test_only_loopback_destinations_are_allowed(address, allowed):
    assert _socket_allowed(address) is allowed


@pytest.mark.allow_network
def test_allow_network_leaves_the_socket_layer_in_place():
    # No connection is made: the marker only has to leave sockets untouched.
    assert socket.socket.connect is _REAL_CONNECT
    assert socket.create_connection is _REAL_CREATE_CONNECTION


def test_a_socket_attempt_swallowed_by_the_app_still_fails_the_test(tmp_path):
    """Same as the PAT-2306 requests case, one layer down: run the real
    conftest in a throwaway session with a test that swallows a blocked
    socket connect, and check the session reports it as failing."""
    shutil.copy(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_swallows.py").write_text(
        "import socket\n"
        "\n"
        "def test_swallows_the_block():\n"
        "    try:\n"
        "        socket.create_connection(('198.51.100.7', 443), timeout=1)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "socket.create_connection 198.51.100.7:443" in output, output
