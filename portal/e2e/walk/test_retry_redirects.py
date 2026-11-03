"""PAT-2285 with PAT-2293: a 429 retry stays inside the redirect containment.

Local only: placeholder credentials and loopback receivers, never the
environment's credentials or a live URL. The prod walker retries a 429 once
(PAT-2285). That retry must go through the same per-hop origin check as the
first attempt (PAT-2293), must never follow a Location sent with the 429
itself, and must never hand the service headers to another origin. The
receiver on the other origin is the oracle: it must see no request at all.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from e2e.walk import walk

CREDS = walk.ProdCredentials("local-id-placeholder", "local-secret-placeholder")


@pytest.fixture
def origins():
    """Start loopback receivers. `script[path]` is a list of (status, headers)
    played in order, one per request to that path, the last one repeating.
    Every request is logged with its headers."""
    servers = []

    def serve():
        received, script = [], {}
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with lock:
                    received.append((self.path, dict(self.headers.items())))
                    count = sum(1 for path, _ in received if path == self.path)
                plays = script.get(self.path) or [(200, {})]
                status, headers = plays[min(count, len(plays)) - 1]
                body = b"<html><body><p>Overview</p></body></html>" if status == 200 else b""
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}", received, script

    yield serve
    for server in servers:
        server.shutdown()
        server.server_close()


def _carries_service_token(headers):
    lowered = {k.lower(): v for k, v in headers.items()}
    return (lowered.get("cf-access-client-id") == CREDS.client_id
            and lowered.get("cf-access-client-secret") == CREDS.client_secret)


def _recording_pacing(sleeps):
    return walk.Pacing(sleep=sleeps.append, error_backoff=0.0)


def _throttled_then_escaping(other):
    """A 429 that itself names the other origin, then a 302 to it on retry."""
    return [(429, {"Retry-After": "0", "Location": other + "/landing"}),
            (302, {"Location": other + "/landing"})]


def test_probe_retry_after_a_429_refuses_a_cross_origin_redirect(browser, origins, tmp_path):
    base, source_log, script = origins()
    other, destination_log, _ = origins()
    script["/start"] = _throttled_then_escaping(other)
    sleeps = []
    context = browser.new_context()
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        findings = walk._walk_one(
            context, base, base + "/start", "/start", "light", 1440, tmp_path, {},
            probe_headers=CREDS.headers(), secrets=CREDS.secrets(),
            pacing=_recording_pacing(sleeps), service_identity=True)
    finally:
        context.close()
    assert destination_log == [], "the retry followed a redirect off the portal origin"
    # The retry was the same authenticated request to the same URL, after
    # the 429's Retry-After, and the 302 it got was refused.
    assert [path for path, _ in source_log] == ["/start", "/start"]
    assert all(_carries_service_token(headers) for _, headers in source_log)
    assert sleeps == [0.0]
    assert [f.check for f in findings] == ["status"], findings
    assert "redirect refused" in findings[0].detail
    report = " ".join(f.detail for f in findings)
    assert CREDS.client_secret not in report and CREDS.client_id not in report


def test_link_check_retry_after_a_429_refuses_a_cross_origin_redirect(browser, origins):
    base, source_log, script = origins()
    other, destination_log, _ = origins()
    script["/software/history"] = _throttled_then_escaping(other)
    context = browser.new_context()
    try:
        findings = walk.check_internal_links(
            context, {base + "/software/history": ("/software", 1440, "light")},
            pacing=_recording_pacing([]), base_url=base, headers=CREDS.headers(),
            service_identity=True, secrets=CREDS.secrets())
    finally:
        context.close()
    assert destination_log == [], "the retry followed a redirect off the portal origin"
    assert [path for path, _ in source_log] == ["/software/history"] * 2
    assert all(_carries_service_token(headers) for _, headers in source_log)
    assert [f.check for f in findings] == ["link"], findings
    assert "redirect refused" in findings[0].detail


def test_a_persistent_429_is_rate_limited_and_its_location_is_never_followed(
        browser, origins, tmp_path):
    base, source_log, script = origins()
    other, destination_log, _ = origins()
    script["/start"] = [(429, {"Retry-After": "0", "Location": other + "/landing"})]
    context = browser.new_context()
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        findings = walk._walk_one(
            context, base, base + "/start", "/start", "light", 1440, tmp_path, {},
            probe_headers=CREDS.headers(), secrets=CREDS.secrets(),
            pacing=_recording_pacing([]), service_identity=True)
    finally:
        context.close()
    assert destination_log == []
    assert len(source_log) == 2  # retried once, not hammered
    assert [f.check for f in findings] == ["rate-limited"], findings


def test_a_retried_429_still_follows_a_same_origin_redirect_with_the_token(browser, origins):
    base, source_log, script = origins()
    script["/start"] = [(429, {"Retry-After": "0"}), (302, {"Location": "/landing"})]
    context = browser.new_context()
    try:
        response = walk.fetch_portal(context, base + "/start", base, CREDS.headers(),
                                     pacing=_recording_pacing([]))
        assert response.status == 200
        response.dispose()
    finally:
        context.close()
    assert [path for path, _ in source_log] == ["/start", "/start", "/landing"]
    assert all(_carries_service_token(headers) for _, headers in source_log)


def test_page_load_retry_after_a_429_stays_inside_the_browser_guard(browser, origins, tmp_path):
    base, source_log, script = origins()
    other, destination_log, _ = origins()
    # The probe is fine; the first navigation is throttled and names the
    # other origin; the retried navigation is redirected there.
    script["/start"] = [(200, {}), *_throttled_then_escaping(other)]
    context = browser.new_context(service_workers="block")
    context.add_cookies([{"name": "CF_Authorization", "value": "local-cookie", "url": base}])
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        findings = walk._walk_one(
            context, base, base + "/start", "/start", "light", 1440, tmp_path, {},
            probe_headers=CREDS.headers(), secrets=CREDS.secrets(),
            pacing=_recording_pacing([]), service_identity=True)
    finally:
        context.close()
    assert destination_log == [], "the page-load retry left the portal origin"
    assert [path for path, _ in source_log] == ["/start"] * 3
    assert all(_carries_service_token(headers) for _, headers in source_log)
    assert findings and all(f.check == "status" for f in findings), findings
    assert list(tmp_path.glob("*.png")) == []


def test_the_unguarded_fetch_refuses_a_production_context(browser, origins):
    # fetch_paced takes no headers, but a prod context's cookie jar holds the
    # portal session, so it must not be usable there at all.
    base, received, _ = origins()
    context = browser.new_context()
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        with pytest.raises(walk.ProdRequestError, match="unguarded fetch refused"):
            walk.fetch_paced(context, base + "/start", pacing=_recording_pacing([]))
    finally:
        context.close()
    assert received == []


def test_every_redirect_hop_and_retry_is_paced(browser, origins):
    base, source_log, script = origins()
    script["/a"] = [(302, {"Location": "/b"})]
    script["/b"] = [(429, {"Retry-After": "0"}), (200, {})]
    sleeps = []
    pacing = walk.Pacing(interval=1.0, slow_step=1.0, sleep=sleeps.append, clock=lambda: 0.0)
    context = browser.new_context()
    try:
        walk.fetch_portal(context, base + "/a", base, CREDS.headers(), pacing=pacing).dispose()
    finally:
        context.close()
    assert [path for path, _ in source_log] == ["/a", "/b", "/b"]
    # /a goes first; /b waits a full interval; its 429 widens the interval to
    # 2s and waits out Retry-After (0s); the retry then waits the new interval.
    assert sleeps == [1.0, 0.0, 2.0]


def test_every_browser_redirect_hop_is_paced(browser, origins):
    base, source_log, script = origins()
    script["/a"] = [(302, {"Location": "/b"})]
    sleeps = []
    pacing = walk.Pacing(interval=1.0, sleep=sleeps.append, clock=lambda: 0.0)
    context = browser.new_context(service_workers="block")
    walk.install_prod_guard(context, base, CREDS, [])
    try:
        page = context.new_page()
        walk.navigate_portal(page, base + "/a", pacing=pacing)
        assert page.url == base + "/b"
    finally:
        context.close()
    assert [path for path, _ in source_log] == ["/a", "/b"]
    assert sleeps == [1.0]
