"""
Suite-wide test isolation (PAT-2306).

Some tests used to make REAL HTTPS requests to PATCHED_API_INTERNAL, whose
default in main.py is the Tailscale-only patched-api-01 admin endpoint. On a
tailnet machine those requests reached production, and were harmless only
because no ADMIN_API_TOKEN was set. This conftest closes that off two ways:

  1. PATCHED_API_INTERNAL is pinned to an unroutable address before main is
     imported, so an un-stubbed call cannot resolve to a real host even if
     the guard below were bypassed.
  2. An autouse fixture blocks real outbound HTTP from every test. It fails
     loudly: the block raises NetworkBlockedError naming the URL, and any
     attempt the app swallowed (a broad `except Exception` around an HTTP
     call) is still reported as a failure at teardown, so an un-stubbed call
     cannot pass silently.

The same fixture also blocks outbound connections below `requests` (PAT-2311):
socket.socket.connect, socket.socket.connect_ex and socket.create_connection.
That covers urllib (scanner.py's NVD feed download), http.client, and raw
sockets such as the TLS certificate-expiry probe in main.py
(_ops_cert_expiry), none of which go through requests' adapter.
create_connection is checked before it resolves the name, so a blocked host
is never even looked up. Unix-domain sockets (a path, not a host and port)
are not network and are left alone.

A test that needs a response stubs the HTTP function it exercises (for
example `monkeypatch.setattr(dashboard.http, "get", fake)`). That replaces the
call before it reaches the adapter this fixture guards, so stubs are
unaffected. `@pytest.mark.allow_network` opts a single test out; nothing uses
it today and a new use needs a stated reason.

Loopback (127.0.0.0/8, ::1, localhost) is allowed: a request to it cannot
leave the machine, and a few tests drive the real session against a local
fake server to reproduce connection failures (PAT-1369, PAT-1813).
"""

import ipaddress
import os
import socket
from urllib.parse import urlparse

import pytest
import requests
import requests.adapters

# RFC 5737 TEST-NET-1: reserved for documentation, never routed. Forced rather
# than setdefault so a developer with the real endpoint exported in their shell
# cannot point the suite at production. main.py reads this at import time, so
# it must be set here, before any test module imports main.
UNROUTABLE_API_INTERNAL = "https://192.0.2.1:9"
os.environ["PATCHED_API_INTERNAL"] = UNROUTABLE_API_INTERNAL


class NetworkBlockedError(Exception):
    """A test tried to make a real outbound HTTP request.

    Deliberately not a requests exception: main._ApiSession converts
    requests.ConnectionError/Timeout for PATCHED_API_INTERNAL into a degraded
    503 response, which would hide the attempt and let the test pass.
    """


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "allow_network: let this test make real outbound HTTP requests "
        "(bypasses the PAT-2306 network guard in tests/conftest.py)",
    )


def _is_loopback_host(host) -> bool:
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    if not isinstance(host, str) or not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        # An IPv6 literal may carry a zone ("fe80::1%en0"); the zone is not
        # part of the address.
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _is_loopback(url: str) -> bool:
    return _is_loopback_host(urlparse(url).hostname)


def _socket_destination(address):
    """Describe a connect() address for the block message, or return None
    when it is not a network destination at all (a Unix-domain socket path)."""
    if isinstance(address, (str, bytes, bytearray, os.PathLike)):
        return None
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]!s}:{address[1]!s}"
    return repr(address)


def _socket_allowed(address) -> bool:
    if _socket_destination(address) is None:
        return True
    return isinstance(address, tuple) and _is_loopback_host(address[0])


@pytest.fixture(autouse=True)
def block_real_network(request, monkeypatch):
    """Fail any real outbound HTTP request or non-loopback socket connection.

    Patches requests.adapters.HTTPAdapter.send, the single point every
    requests call passes through (Session.request, requests.get, and so on),
    so a new direct call in app code cannot bypass it. Also patches
    socket.socket.connect/connect_ex and socket.create_connection, which
    urllib, http.client, ssl and raw-socket code all reach (PAT-2311).

    Yields the list of blocked URLs. A test that deliberately provokes the
    block clears the list once it has asserted on it; otherwise a non-empty
    list fails the test at teardown.
    """
    blocked: list[str] = []

    if request.node.get_closest_marker("allow_network"):
        yield blocked
        return

    real_send = requests.adapters.HTTPAdapter.send

    def guarded_send(self, req, *args, **kwargs):
        if _is_loopback(req.url):
            return real_send(self, req, *args, **kwargs)
        blocked.append(f"{req.method} {req.url}")
        raise NetworkBlockedError(
            f"real network blocked in tests: {req.method} {req.url}. "
            "Stub the HTTP call in the test (for example "
            "monkeypatch.setattr(dashboard.http, 'get', fake)), or, for a "
            "test that genuinely needs the real layer, mark it "
            "@pytest.mark.allow_network."
        )

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", guarded_send)

    # PAT-2311: the socket layer, for everything that does not go through
    # requests. Same loopback allowance, same error, same list.
    def refuse_socket(kind: str, address) -> None:
        destination = _socket_destination(address)
        blocked.append(f"{kind} {destination}")
        raise NetworkBlockedError(
            f"real network blocked in tests: {kind} to {destination}. "
            "Stub the function that opens the connection (for example "
            "monkeypatch.setattr(dashboard, '_ops_cert_expiry', fake)), or, "
            "for a test that genuinely needs the real layer, mark it "
            "@pytest.mark.allow_network."
        )

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create_connection = socket.create_connection

    def guarded_connect(self, address):
        if not _socket_allowed(address):
            refuse_socket("socket connect", address)
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        if not _socket_allowed(address):
            refuse_socket("socket connect_ex", address)
        return real_connect_ex(self, address)

    def guarded_create_connection(address, *args, **kwargs):
        # Before the name is resolved: a blocked host is never looked up.
        if not _socket_allowed(address):
            refuse_socket("socket.create_connection", address)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)
    yield blocked
    if blocked:
        pytest.fail(
            "test attempted real outbound network connection(s), blocked by "
            "the PAT-2306/PAT-2311 guard (an application handler may have "
            "swallowed the error, so the test passed by accident):\n  "
            + "\n  ".join(blocked),
            pytrace=False,
        )


@pytest.fixture
def network_down(block_real_network, monkeypatch):
    """Simulate a network where every outbound request fails to connect.

    For tests whose subject is how the app behaves when an upstream (the
    platform API, Slack) cannot be reached, or which pass only because that
    lookup fails harmlessly. Raises requests' own ConnectionError at the
    adapter, so it goes through main._ApiSession exactly as a real
    unreachable PATCHED_API_INTERNAL does (a degraded 503 response), and
    through the Slack helpers' error handling for everything else. Explicit
    and visible in the test, unlike an accidental real connection failure.
    """

    def refuse(self, req, *args, **kwargs):
        raise requests.exceptions.ConnectionError(
            f"network down in test: {req.method} {req.url}"
        )

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", refuse)


@pytest.fixture
def verified_access_headers(monkeypatch):
    """Explicit signed human identity for UI tests, with a local JWKS stub.

    Opt-in only: security tests still exercise the complete origin boundary.
    """
    import json
    import time
    import jwt
    import dashboard_access
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid'] = 'ui-test-key'
    monkeypatch.setenv('DASHBOARD_ACCESS_TEAM_DOMAIN', 'test-team.cloudflareaccess.com')
    monkeypatch.setenv('DASHBOARD_ACCESS_AUD', 'dashboard-test')
    monkeypatch.setattr(dashboard_access, '_fetch_jwks', lambda issuer: {'keys': [jwk]})
    dashboard_access.reset_jwks_cache()

    def headers(email):
        now = int(time.time())
        token = jwt.encode({'email': email, 'sub': 'test-person',
                            'iss': 'https://test-team.cloudflareaccess.com',
                            'aud': 'dashboard-test', 'iat': now, 'exp': now + 600},
                           key, algorithm='RS256', headers={'kid': 'ui-test-key'})
        return {'Cf-Access-Jwt-Assertion': token}
    yield headers
    dashboard_access.reset_jwks_cache()
