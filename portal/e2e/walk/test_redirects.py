"""Local-only credential containment regressions. No environment credentials."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from playwright.sync_api import Error as PlaywrightError

from e2e.walk import walk

CREDS = walk.ProdCredentials("local-id-placeholder", "local-secret-placeholder")


@pytest.fixture
def origins():
    servers = []

    def serve():
        received, redirects = [], {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append((self.path, dict(self.headers.items())))
                self.send_response(302 if self.path in redirects else 200)
                if self.path in redirects:
                    self.send_header("Location", redirects[self.path])
                body = (b'<html><img src="relative.png"></html>'
                        if self.path == "/nested/html" else b"")
                self.send_header("Content-Type", "text/html" if body else "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_HEAD = do_GET

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}", received, redirects

    yield serve
    for server in servers:
        server.shutdown()
        server.server_close()


def exercise(context, base, path, mode, tmp_path):
    if mode == "api":
        return walk._walk_one(context, base, base + path, path, "light", 1440,
                              tmp_path, {}, probe_headers=CREDS.headers(),
                              secrets=CREDS.secrets())
    return walk.navigate_portal(context.new_page(), base + path)


@pytest.mark.parametrize("mode", ["api", "browser"])
def test_cross_origin_redirect_never_sends_service_headers_or_cookie(
        browser, origins, tmp_path, mode):
    base, source_log, redirects = origins()
    other, destination_log, _ = origins()
    redirects["/redirect"] = other + "/landing"
    context = browser.new_context()
    context.add_cookies([{"name": "CF_Authorization", "value": "local-cookie", "url": base}])
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        try:
            exercise(context, base, "/redirect", mode, tmp_path)
        except (PlaywrightError, walk.ProdConfigError):
            pass  # A refusal is expected; the receiver is the security oracle.
        assert source_log
        assert not destination_log, "unsafe redirect was followed with portal authentication"
    finally:
        context.close()


@pytest.mark.parametrize("mode", ["api", "browser"])
def test_same_origin_redirect_preserves_authentication(browser, origins, tmp_path, mode):
    base, received, redirects = origins()
    redirects["/redirect"] = "/nested/landing"
    context = browser.new_context()
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        exercise(context, base, "/redirect", mode, tmp_path)
        assert [path for path, _ in received] == ["/redirect", "/nested/landing"]
        for _, headers in received:
            assert headers["CF-Access-Client-Id"] == CREDS.client_id
            assert headers["CF-Access-Client-Secret"] == CREDS.client_secret
        if mode == "browser":
            assert context.pages[0].url == base + "/nested/landing"
    finally:
        context.close()


@pytest.mark.parametrize("mode", ["api", "browser"])
def test_redirect_loop_is_bounded_and_reported(browser, origins, tmp_path, mode):
    base, received, redirects = origins()
    redirects["/loop"] = "/loop"
    context = browser.new_context()
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        if mode == "api":
            findings = exercise(context, base, "/loop", mode, tmp_path)
            assert any("redirect limit" in f.detail for f in findings)
        else:
            with pytest.raises(walk.ProdRequestError, match="redirect limit"):
                exercise(context, base, "/loop", mode, tmp_path)
        assert len(received) == walk.MAX_PROD_REDIRECTS + 1
    finally:
        context.close()


@pytest.mark.parametrize("mode", ["api", "browser"])
def test_later_redirect_cannot_escape_origin(browser, origins, tmp_path, mode):
    base, received, redirects = origins()
    other, destination_log, _ = origins()
    redirects.update({"/first": "/second", "/second": other + "/landing"})
    context = browser.new_context()
    context.add_cookies([{"name": "CF_Authorization", "value": "local-cookie", "url": base}])
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        try:
            result = exercise(context, base, "/first", mode, tmp_path)
        except walk.ProdRequestError:
            result = None
        assert len(received) == 2
        assert destination_log == []
        assert mode == "browser" or any("redirect refused" in f.detail for f in result)
    finally:
        context.close()


class FakePage:
    """No browser: goto is scripted, and the guard's redirect map is real."""

    def __init__(self, script):
        self.context = SimpleNamespace(_portal_redirects={})
        self.calls = []
        self._script = script

    def goto(self, url, wait_until=None):
        self.calls.append(url)
        return self._script(self, url)


def test_navigate_portal_follows_recorded_redirect_when_goto_returns_normally():
    # A Chromium build that treats the guard's 204 as a completed navigation
    # returns from goto instead of raising; the recorded target must still be
    # followed, or the walker stops on a blank page and its checks pass.
    blank, final = object(), object()

    def script(page, url):
        if url == "https://portal.example/first":
            page.context._portal_redirects[page] = "https://portal.example/second"
            return blank
        return final

    page = FakePage(script)
    assert walk.navigate_portal(page, "https://portal.example/first") is final
    assert page.calls == ["https://portal.example/first", "https://portal.example/second"]
    assert page not in page.context._portal_redirects


def test_navigate_portal_returns_response_when_no_redirect_was_recorded():
    response = object()
    page = FakePage(lambda page, url: response)
    assert walk.navigate_portal(page, "https://portal.example/") is response
    assert page.calls == ["https://portal.example/"]
    assert page not in page.context._portal_redirects


def test_navigate_portal_redirect_limit_applies_when_goto_returns_normally():
    def script(page, url):
        page.context._portal_redirects[page] = "https://portal.example/loop"
        return object()

    page = FakePage(script)
    with pytest.raises(walk.ProdRequestError, match="redirect limit") as exc:
        walk.navigate_portal(page, "https://portal.example/loop")
    assert exc.value.__suppress_context__
    assert len(page.calls) == walk.MAX_PROD_REDIRECTS + 1
    assert page not in page.context._portal_redirects


def test_browser_final_url_resolves_relative_resources_and_keeps_cookie(browser, origins):
    base, received, redirects = origins()
    redirects["/first"] = "/nested/html"
    context = browser.new_context()
    context.add_cookies([{"name": "CF_Authorization", "value": "local-cookie", "url": base}])
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        page = context.new_page()
        walk.navigate_portal(page, base + "/first")
        assert page.url == base + "/nested/html"
        assert page.locator("img").get_attribute("src") == "relative.png"
        assert [path for path, _ in received] == ["/first", "/nested/html", "/nested/relative.png"]
        for _, headers in received:
            lowered = {k.lower(): v for k, v in headers.items()}
            assert lowered["cookie"] == "CF_Authorization=local-cookie"
            assert lowered["cf-access-client-secret"] == CREDS.client_secret
    finally:
        context.close()


def test_external_browser_load_has_no_headers_or_domain_cookie(browser, origins):
    base, _, _ = origins()
    other, received, _ = origins()
    context = browser.new_context()
    context.add_cookies([{"name": "CF_Authorization", "value": "local-cookie", "url": base}])
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        context.new_page().goto(other + "/landing")
        assert received
        for _, headers in received:
            lowered = {k.lower(): v for k, v in headers.items()}
            assert not lowered.get("cookie")
            assert "cf-access-client-id" not in lowered
            assert "cf-access-client-secret" not in lowered
    finally:
        context.close()


@pytest.mark.parametrize("target", [
    "http://portal.example/path", "https://portal.example:8443/path",
    "https://portal.example.evil/path", "https://user@portal.example/path",
    "https://portal.example\\@evil.example/path", "file:///tmp/path",
])
def test_redirect_origin_check_rejects_scheme_port_and_ambiguous_urls(target):
    class Response:
        status = 302
        headers = {"location": target}

    with pytest.raises(walk.ProdRequestError, match="redirect refused"):
        walk._redirect_target(Response(), "https://portal.example/start", "https://portal.example")


def test_default_port_and_host_case_are_same_origin():
    assert walk.prod_request_headers("https://PORTAL.example:443/end",
                                     "https://portal.example", CREDS) == CREDS.headers()


def test_api_transport_error_cannot_expose_headers():
    class Context:
        class request:
            @staticmethod
            def get(*args, **kwargs):
                raise PlaywrightError("failed\nCall log: " + str(CREDS.headers()))

    with pytest.raises(walk.ProdRequestError) as exc:
        walk.fetch_portal(Context(), "https://portal.example/a", "https://portal.example",
                          CREDS.headers())
    assert str(exc.value) == "portal request failed"
    assert exc.value.__suppress_context__


def test_prod_cli_never_prints_header_bearing_exception(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv(walk.PROD_CLIENT_ID_ENV, CREDS.client_id)
    monkeypatch.setenv(walk.PROD_CLIENT_SECRET_ENV, CREDS.client_secret)

    def fail(*args, **kwargs):
        raise PlaywrightError("failed\nCall log: " + str(CREDS.headers()) + "cookie=local-cookie")

    monkeypatch.setattr(walk, "run_prod_walk", fail)
    args = SimpleNamespace(base_url="https://portal.example")
    assert walk._main_prod(args, ["/"], tmp_path) == 3
    output = capsys.readouterr()
    assert "prod walk stopped" in output.err
    for secret in (*CREDS.secrets(), "local-cookie", "Call log", "Traceback"):
        assert secret not in output.err + output.out
