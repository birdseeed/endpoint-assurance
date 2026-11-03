"""PAT-2118: the CF Access JWT check must never block the event loop.

require_cf_access_jwt (main.py) is an async middleware that calls
auth.verify_token on every request. verify_token keeps a JWKS cache
(_jwks_keys/_jwks_fetched_at, under a threading.Lock) and refreshes it with
a blocking `requests.get` when the cache is stale or the token's kid is
unknown. Called straight from the async middleware, that fetch would run on
the event loop and stall every other request on the worker while it waits
on Cloudflare's certs endpoint - the same shape PAT-2105 fixed for platform
calls with run_in_threadpool (see tests/test_pat2105_csrf.py's
test_upstream_calls_never_run_on_the_event_loop, which this test mirrors).
"""

import asyncio

import pytest

import auth

# Grabbed at collection time, before the autouse access_env fixture
# monkeypatches auth._fetch_jwks to a network-free stub for every other
# test in the suite - this is the one test that needs the real function.
_REAL_FETCH_JWKS = auth._fetch_jwks


@pytest.fixture
def token(make_token):
    return make_token()


def test_jwks_fetch_never_runs_on_the_event_loop(client, token, monkeypatch, jwks):
    """A cold cache (the normal per-test state - access_env resets it) forces
    a JWKS fetch on the very next authenticated request. That fetch must not
    happen on the event loop's thread."""
    calls = []

    def watch_fetch():
        try:
            asyncio.get_running_loop()
            on_loop = True
        except RuntimeError:
            on_loop = False
        calls.append(on_loop)
        return jwks

    monkeypatch.setattr(auth, "_fetch_jwks", watch_fetch)
    auth.reset_jwks_cache()

    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code in (200, 303), resp.text[:400]
    assert calls, "expected the cold cache to trigger a JWKS fetch"
    assert calls == [False], (
        "auth._fetch_jwks ran on the event loop's thread - it must go "
        "through run_in_threadpool the way PAT-2105 does for platform calls"
    )


def test_verify_token_never_runs_on_the_event_loop(client, token, monkeypatch):
    """Broader guard: whatever verify_token ends up doing internally
    (JWKS fetch, decode, or both), none of it may run on the loop thread."""
    calls = []
    real_verify_token = auth.verify_token

    def watch_verify(tok):
        try:
            asyncio.get_running_loop()
            on_loop = True
        except RuntimeError:
            on_loop = False
        calls.append(on_loop)
        return real_verify_token(tok)

    monkeypatch.setattr(auth, "verify_token", watch_verify)

    resp = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code in (200, 303), resp.text[:400]
    assert calls, "expected the middleware to call auth.verify_token"
    assert calls == [False], (
        "auth.verify_token ran on the event loop's thread - the middleware "
        "must await run_in_threadpool(auth.verify_token, token)"
    )


def test_jwks_fetch_uses_a_bounded_timeout(monkeypatch):
    """auth._fetch_jwks must bound its wait on Cloudflare's certs endpoint -
    an unbounded requests.get would let a hung endpoint stall whichever
    thread runs it (loop or threadpool) for the life of the connection."""
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": []}

    def fake_get(url, *args, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return FakeResponse()

    monkeypatch.setattr(auth.requests, "get", fake_get)

    try:
        _REAL_FETCH_JWKS()
    except auth.AuthError:
        pass  # empty keys -> _load_keys raises; we only care about the call

    assert captured.get("timeout") is not None, (
        "auth._fetch_jwks called requests.get with no timeout - a hung "
        "certs endpoint would then block forever"
    )
    assert 0 < captured["timeout"] <= 10, (
        f"JWKS fetch timeout {captured['timeout']!r} is not a sane bound"
    )
