"""PAT-2285: nothing the walker writes carries a credential, a JWT or the
Access session cookie, whole or cut short.

A walker crash once printed CF-Access-Client-Id, the client secret and the
CF_Authorization JWT into a session transcript. The walker's redaction
therefore scrubs, before anything is shortened: the service token's two
values, any JWT-shaped string (three base64url segments, the first starting
`eyJ`), and the value of every CF_Authorization cookie seen in the walker's
context. These tests feed Playwright-style errors carrying all of them into
each place the walker writes text: the CLI line, progress, finding details,
the summary and walk-report.json. Placeholders only; no real credential, and
every server is a local fixture.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from playwright.sync_api import Error as PlaywrightError

from e2e.walk import walk

FAKE_ID = "local-id-placeholder"
FAKE_SECRET = "local-secret-placeholder"
FAKE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.c2ln"
# Deliberately not JWT-shaped: only the cookie scrub can catch it.
FAKE_COOKIE = "local-session-cookie-placeholder"

# A value cut at a truncation boundary leaks its prefix, so the prefixes are
# forbidden too, not just the whole values.
FORBIDDEN = (FAKE_JWT, "eyJhbG", "eyJzdWIiOiJ4In0", FAKE_ID, FAKE_ID[:9],
             FAKE_SECRET, FAKE_SECRET[:10], FAKE_COOKIE, FAKE_COOKIE[:12])

PREFIX = "APIRequestContext.get: "


def creds():
    return walk.ProdCredentials(FAKE_ID, FAKE_SECRET)


def assert_clean(text):
    for piece in FORBIDDEN:
        assert piece not in text, f"{piece!r} survived in {text!r}"


def straddling(token, limit=200, prefix=PREFIX):
    """A first line on which `token` straddles the `limit`-character cut."""
    pad = limit - len(prefix) - len(token) // 2
    return f"{prefix}{'x' * pad}{token} end"


def playwright_error(first_line):
    """Shaped like Playwright's: a message line, then a call log carrying the
    request's headers and cookie."""
    return PlaywrightError(
        f"{first_line}\nCall log:\n  - cookie: CF_Authorization={FAKE_JWT}\n"
        f"  - cf-access-client-id: {FAKE_ID}\n  - cf-access-client-secret: {FAKE_SECRET}\n"
        f"  - cookie: CF_Authorization={FAKE_COOKIE}")


FIRST_LINES = {
    "all-on-the-first-line": (f"{PREFIX}refused CF_Authorization={FAKE_JWT} "
                              f"id={FAKE_ID} secret={FAKE_SECRET}"),
    "jwt-straddles-the-cut": straddling(FAKE_JWT),
    "secret-straddles-the-cut": straddling(FAKE_SECRET),
    "id-straddles-the-cut": straddling(FAKE_ID),
}


@pytest.fixture
def portal():
    """A local 'portal' that answers 200 to anything."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body><p>Overview</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def prod_env(monkeypatch):
    monkeypatch.setenv(walk.PROD_CLIENT_ID_ENV, FAKE_ID)
    monkeypatch.setenv(walk.PROD_CLIENT_SECRET_ENV, FAKE_SECRET)


# The redaction itself

def test_redact_scrubs_jwt_shaped_strings_and_leaves_other_text_alone():
    unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
    text = f"cookie CF_Authorization={FAKE_JWT}; also {unsigned} and version 1.2.3 eyJ"
    out = walk.redact(text, ())
    assert_clean(out)
    assert unsigned not in out
    assert "version 1.2.3 eyJ" in out  # not a JWT: left alone


# The CLI line

@pytest.mark.parametrize("first_line", FIRST_LINES.values(), ids=FIRST_LINES.keys())
def test_the_cli_line_carries_no_credential_jwt_or_cookie(
        monkeypatch, capsys, prod_env, tmp_path, first_line):
    def crash(*args, **kwargs):
        raise playwright_error(first_line)

    monkeypatch.setattr(walk, "run_prod_walk", crash)
    code = walk.main(["--prod", "--routes", "/", "--out-dir", str(tmp_path)])
    output = capsys.readouterr()
    assert code == 3
    assert "prod walk stopped" in output.err
    assert "Call log" not in output.err + output.out
    assert_clean(output.err + output.out)


def test_the_cli_line_scrubs_a_session_cookie_the_walk_saw(
        monkeypatch, capsys, prod_env, browser, portal, tmp_path):
    """The cookie is not JWT-shaped, so only learning it from the context
    catches it; the walk dies after the cookie is set, as a real crash would."""
    def crash_after_login(context, base_url, *args, **kwargs):
        context.add_cookies([{"name": "CF_Authorization", "value": FAKE_COOKIE,
                              "url": base_url}])
        raise playwright_error(f"{PREFIX}failed with CF_Authorization={FAKE_COOKIE}")

    def run(base_url, creds, routes, **kwargs):
        return walk.walk_prod_routes(browser, base_url, creds, routes, kwargs["out_dir"],
                                     kwargs["pacing"])

    monkeypatch.setattr(walk, "_walk_one", crash_after_login)
    monkeypatch.setattr(walk, "run_prod_walk", run)
    code = walk.main(["--prod", "--routes", "/", "--base-url", portal,
                      "--out-dir", str(tmp_path)])
    output = capsys.readouterr()
    assert code == 3
    assert_clean(output.err + output.out)


# Finding details and walk-report.json

@pytest.mark.parametrize("first_line", FIRST_LINES.values(), ids=FIRST_LINES.keys())
def test_a_probe_error_finding_and_the_report_carry_none_of_them(
        monkeypatch, tmp_path, first_line):
    def fail(*args, **kwargs):
        raise playwright_error(first_line)

    monkeypatch.setattr(walk, "fetch_paced", fail)
    secrets = creds().secrets()
    findings = walk._walk_one(
        None, "https://portal.example.test", "https://portal.example.test/devices",
        "/devices", "light", 1280, tmp_path, {}, secrets=secrets)
    assert findings
    assert_clean(" ".join(f.detail for f in findings))
    assert_clean(walk.write_report(findings, tmp_path, secrets=secrets).read_text())


def test_link_findings_progress_and_report_scrub_the_session_cookie_and_jwt(
        monkeypatch, browser, portal, tmp_path):
    def log_in_and_collect_a_link(context, base_url, url, route, theme, width, shots, owner,
                                  **kwargs):
        # Cloudflare Access sets CF_Authorization on the first authenticated
        # response; the fixture stands in for it.
        context.add_cookies([{"name": "CF_Authorization", "value": FAKE_COOKIE,
                              "url": base_url}])
        owner[base_url + "/software/history"] = (route, width, theme)
        return []

    def fail(*args, **kwargs):
        raise playwright_error(f"{PREFIX}failed CF_Authorization={FAKE_COOKIE} {FAKE_JWT}")

    monkeypatch.setattr(walk, "_walk_one", log_in_and_collect_a_link)
    monkeypatch.setattr(walk, "fetch_portal", fail)
    walker_creds = creds()
    messages = []
    findings = walk.walk_prod_routes(
        browser, portal, walker_creds, ["/software"], tmp_path,
        pacing=walk.Pacing(error_backoff=0.0), progress=messages.append)
    assert any(f.check == "link" for f in findings), findings
    assert_clean(" ".join(f.detail for f in findings))
    assert_clean(" ".join(messages))
    report = walk.write_report(findings, tmp_path, secrets=walker_creds.secrets())
    assert_clean(report.read_text())


def test_the_prod_summary_and_report_carry_no_jwt(monkeypatch, capsys, prod_env, tmp_path):
    finding = walk.Finding(
        fingerprint="wk-status-x-1440-light", check="status", route=f"/x?t={FAKE_JWT}",
        width=1440, theme="light", severity="high",
        detail=f"/x?t={FAKE_JWT} returned status 500 (expected 2xx)")
    monkeypatch.setattr(walk, "run_prod_walk", lambda *a, **k: [finding])
    code = walk.main(["--prod", "--routes", "/", "--out-dir", str(tmp_path)])
    output = capsys.readouterr()
    assert code == 1
    assert_clean(output.out + output.err)
    assert_clean((tmp_path / "walk-report.json").read_text())


# Every other place a finding shortens text

def test_console_findings_scrub_before_cutting_at_300(tmp_path):
    long_url = "https://portal.example.test/x?" + "a" * (300 - 45 - len("failed request: "))
    failed = [f"GET {long_url}&t={FAKE_JWT} -> net::ERR_FAILED"]
    errors = [f"Uncaught: session {FAKE_JWT} rejected"]
    findings = walk.check_console(errors, failed, "/", 1440, "light")
    assert len(findings) == 2
    assert_clean(" ".join(f.detail for f in findings))
    assert_clean(walk.write_report(findings, tmp_path).read_text())


def test_console_findings_scrub_a_credential_before_cutting_at_300():
    message = "GET https://portal.example.test/x?" + "a" * 250 + f"&s={FAKE_SECRET} -> x"
    findings = walk.check_console([], [message], "/", 1440, "light",
                                  secrets=creds().secrets())
    assert_clean(" ".join(f.detail for f in findings))


def test_readonly_findings_scrub_before_cutting_at_300():
    entry = "POST https://portal.example.test/x?" + "a" * 250 + f"&t={FAKE_JWT}"
    findings = walk.check_readonly([entry], "/", 1440, "light")
    assert_clean(" ".join(f.detail for f in findings))


@pytest.mark.parametrize("check,word", [("copy", "fleet"), ("leak", "PAT-1234")])
def test_page_text_findings_scrub_before_cutting_at_120(browser, check, word):
    text = f"{word} " + "a" * (120 - len(word) - 1 - len(FAKE_JWT) // 2) + FAKE_JWT + " end"
    page = browser.new_page()
    try:
        page.set_content(f"<html><body><p>{text}</p></body></html>")
        run = walk.check_copy if check == "copy" else walk.check_leak
        findings = run(page, "/", 1440, "light")
    finally:
        page.close()
    assert findings, f"the fixture should trip the {check} check"
    assert_clean(" ".join(f.detail for f in findings))


def test_page_text_findings_scrub_a_credential_before_cutting_at_120(browser):
    text = "fleet " + "a" * (120 - 6 - len(FAKE_SECRET) // 2) + FAKE_SECRET + " end"
    page = browser.new_page()
    try:
        page.set_content(f"<html><body><p>{text}</p></body></html>")
        findings = walk.check_copy(page, "/", 1440, "light", secrets=creds().secrets())
    finally:
        page.close()
    assert findings
    assert_clean(" ".join(f.detail for f in findings))


def test_learned_cookie_values_join_the_secrets_but_not_the_repr(browser, portal):
    walker_creds = creds()
    context = browser.new_context()
    try:
        context.add_cookies([{"name": "CF_Authorization", "value": FAKE_COOKIE, "url": portal},
                             {"name": "unrelated", "value": "keep-me", "url": portal}])
        walk.learn_session_cookies(context, walker_creds)
    finally:
        context.close()
    assert FAKE_COOKIE in walker_creds.secrets()
    assert "keep-me" not in walker_creds.secrets()
    assert FAKE_COOKIE not in repr(walker_creds) and FAKE_COOKIE not in str(walker_creds)
    assert walker_creds == creds()  # learning a cookie is not a different identity


def test_redaction_is_not_fooled_by_a_secret_inside_another():
    # The longer value is replaced first, so no fragment of it survives.
    outer = FAKE_SECRET + "-suffix"
    out = walk.redact(f"a {outer} b", (FAKE_SECRET, outer))
    assert "suffix" not in out and FAKE_SECRET not in out
