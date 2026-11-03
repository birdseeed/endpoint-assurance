"""PAT-2105: the PAT-2008 Origin + CSRF guard on every state-changing route.

POST /reports/generate, POST /reports/schedule and POST /install/enrolment
each ask the platform to do something on the caller's behalf (generate a
report, change the report schedule, mint an enrolment token). A cross-site
page must not be able to make a signed-in browser do any of them, so each
now goes through main._guarded_form exactly as POST /software/approvals
does. Every refusal below also asserts the stub platform saw no write.

The last tests enumerate app.routes, so a future POST/PUT/PATCH/DELETE
route that forgets the guard fails here without anyone adding a test.
"""

import asyncio
import json
from urllib.parse import urlencode

import pytest

import main
from tests.conftest import STUB_STATE

ORIGIN = "https://testserver"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# route -> (form fields for a request that would succeed, write counter,
# expected success status)
ROUTES = {
    "/reports/generate": ([("report_type", "patch-status")],
                          lambda: STUB_STATE["generate_calls"], 303),
    "/reports/schedule": ([("report_type", "executive-summary"), ("cadence", "daily"),
                           ("hour_utc", "7"), ("enabled", "on")],
                          lambda: (len(STUB_STATE["schedule_puts"])
                                   + len(STUB_STATE["typed_schedule_puts"])), 303),
    "/install/enrolment": ([], lambda: STUB_STATE["enrolment_calls"], 200),
    "/install/enrolment-keys": ([("label", "Intune rollout"), ("max_devices", "50")],
                                lambda: len(STUB_STATE["enrolment_key_create_posts"]), 200),
    "/install/enrolment-keys/6d75459e-1111-4111-8111-111111111111/revoke": (
        [], lambda: len(STUB_STATE["enrolment_key_revoke_posts"]), 303),
}


def _post(client, token, path, fields, *, origin=ORIGIN, csrf=True, referer=None):
    body = list(fields)
    if csrf is True:
        body.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        body.append(("csrf_token", csrf))
    elif isinstance(csrf, list):
        body.extend(("csrf_token", value) for value in csrf)
    headers = {"Cf-Access-Jwt-Assertion": token,
               "Content-Type": "application/x-www-form-urlencoded"}
    if origin is not None:
        headers["Origin"] = origin
    if referer is not None:
        headers["Referer"] = referer
    return client.post(path, content=urlencode(body), headers=headers,
                       follow_redirects=False)


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


# ── Each route: valid request succeeds, every bad one is refused ─────────

@pytest.mark.parametrize("path", ROUTES)
def test_valid_same_origin_request_with_token_succeeds(client, token, path):
    fields, writes, ok_status = ROUTES[path]
    resp = _post(client, token, path, fields)
    assert resp.status_code == ok_status, resp.text[:400]
    assert writes() == 1


@pytest.mark.parametrize("path", ROUTES)
def test_same_origin_referer_without_origin_succeeds(client, token, path):
    fields, writes, ok_status = ROUTES[path]
    resp = _post(client, token, path, fields, origin=None, referer=f"{ORIGIN}/reports")
    assert resp.status_code == ok_status, resp.text[:400]
    assert writes() == 1


@pytest.mark.parametrize("path", ROUTES)
@pytest.mark.parametrize("csrf,label", [
    (False, "missing"),
    ("0" * 64, "bad"),
    ("", "empty"),
    ("not-a-token", "garbage"),
])
def test_missing_or_bad_token_is_refused(client, token, path, csrf, label):
    fields, writes, _ = ROUTES[path]
    resp = _post(client, token, path, fields, csrf=csrf)
    assert resp.status_code == 403, label
    assert "This page has expired" in resp.text
    assert writes() == 0


@pytest.mark.parametrize("path", ROUTES)
def test_token_from_another_session_is_refused(client, token, make_token, path):
    fields, writes, _ = ROUTES[path]
    other = make_token(email="bob@tenant-a.example", exp_delta=900)
    assert other != token
    resp = _post(client, token, path, fields, csrf=main._csrf_token(other))
    assert resp.status_code == 403
    assert writes() == 0


@pytest.mark.parametrize("path", ROUTES)
def test_duplicate_token_fields_are_refused(client, token, path):
    fields, writes, _ = ROUTES[path]
    good = main._csrf_token(token)
    resp = _post(client, token, path, fields, csrf=[good, good])
    assert resp.status_code == 403
    assert writes() == 0


@pytest.mark.parametrize("path", ROUTES)
@pytest.mark.parametrize("origin", [
    "https://evil.example",                 # cross-origin
    "null",                                 # opaque origin
    "http://testserver",                    # http on a non-local host
    "https://testserver.evil.example",
])
def test_bad_origin_is_refused_even_with_a_valid_token(client, token, path, origin):
    fields, writes, _ = ROUTES[path]
    resp = _post(client, token, path, fields, origin=origin)
    assert resp.status_code == 403
    assert "did not come from the portal page itself" in resp.text
    assert writes() == 0


@pytest.mark.parametrize("path", ROUTES)
def test_no_origin_and_no_referer_is_refused(client, token, path):
    fields, writes, _ = ROUTES[path]
    resp = _post(client, token, path, fields, origin=None)
    assert resp.status_code == 403
    assert writes() == 0


@pytest.mark.parametrize("path", ROUTES)
def test_cross_site_referer_without_origin_is_refused(client, token, path):
    fields, writes, _ = ROUTES[path]
    resp = _post(client, token, path, fields, origin=None, referer="https://evil.example/x")
    assert resp.status_code == 403
    assert writes() == 0


@pytest.mark.parametrize("path", ROUTES)
def test_oversized_body_is_refused_before_anything_else(client, token, path):
    fields, writes, _ = ROUTES[path]
    padding = [("pad", "x" * (main.STATE_CHANGE_MAX_BODY_BYTES + 1))]
    resp = _post(client, token, path, fields + padding, origin="https://evil.example")
    assert resp.status_code == 413
    assert writes() == 0


# ── The forms carry the token ────────────────────────────────────────────

def _hidden(token):
    return f'<input type="hidden" name="csrf_token" value="{main._csrf_token(token)}">'


def test_reports_forms_carry_the_session_token(client, token):
    html = client.get("/reports", headers={"Cf-Access-Jwt-Assertion": token}).text
    field = _hidden(token)
    generate = html.index('action="/reports/generate"')
    assert field in html[generate:html.index("</form>", generate)]
    schedule = html.index('action="/reports/schedule"')
    assert field in html[schedule:html.index("</form>", schedule)]


def test_install_forms_carry_the_session_token(client, token):
    field = _hidden(token)
    before = client.get("/install", headers={"Cf-Access-Jwt-Assertion": token}).text
    start = before.index('action="/install/enrolment"')
    assert field in before[start:before.index("</form>", start)]
    # The post-generation page's "Generate a new one" form posts again.
    after = _post(client, token, "/install/enrolment", []).text
    start = after.index('action="/install/enrolment"')
    assert field in after[start:after.index("</form>", start)]


# ── No unsafe-method route can skip the guard ────────────────────────────

def _unsafe_routes():
    out = []
    for route in main.app.routes:
        methods = set(getattr(route, "methods", None) or ()) - SAFE_METHODS
        for method in sorted(methods):
            out.append((method, route.path))
    return out


def test_every_known_state_changing_route_is_enumerated():
    """The guard enumeration below is only meaningful if it finds routes."""
    assert set(_unsafe_routes()) >= {
        ("POST", "/software/approvals"), ("POST", "/reports/generate"),
        ("POST", "/reports/schedule"), ("POST", "/install/enrolment"),
    }


@pytest.mark.parametrize("method,path", _unsafe_routes())
def test_every_unsafe_route_refuses_a_cross_origin_request(client, token, method, path):
    resp = client.request(
        method, path.replace("{", "").replace("}", ""),
        content=urlencode([("csrf_token", main._csrf_token(token))]),
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": "https://evil.example",
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False)
    assert resp.status_code == 403, f"{method} {path} is not behind _guarded_form"
    assert "did not come from the portal page itself" in resp.text


@pytest.mark.parametrize("method,path", _unsafe_routes())
def test_every_unsafe_route_refuses_a_missing_token(client, token, method, path):
    resp = client.request(
        method, path.replace("{", "").replace("}", ""),
        content="", headers={"Cf-Access-Jwt-Assertion": token, "Origin": ORIGIN,
                             "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False)
    assert resp.status_code == 403, f"{method} {path} is not behind _guarded_form"
    assert "This page has expired" in resp.text


# ── Upstream calls from async routes run off the event loop ──────────────

APPROVAL_FIELDS = [("state", "approved"), ("item", json.dumps({
    "type": "application", "platform": "macos",
    "identifier": "com.example.mysteryapp", "name": "MysteryApp"}))]


@pytest.mark.parametrize("path,fields", [
    *((path, ROUTES[path][0]) for path in ROUTES),
    ("/software/approvals", APPROVAL_FIELDS),
])
def test_upstream_calls_never_run_on_the_event_loop(client, token, monkeypatch, path, fields):
    """requests is blocking: called on the loop thread from an async route it
    stalls every other request on the worker. Each upstream call records
    whether an event loop is running in its own thread, then proceeds."""
    calls = []

    def watch(name, real):
        def wrapper(*args, **kwargs):
            try:
                asyncio.get_running_loop()
                on_loop = True
            except RuntimeError:
                on_loop = False
            calls.append((name, on_loop))
            return real(*args, **kwargs)
        return wrapper

    for name in ("get_json", "post_json", "put_json"):
        monkeypatch.setattr(main.upstream, name, watch(name, getattr(main.upstream, name)))
    resp = _post(client, token, path, fields)
    assert resp.status_code in (200, 303), resp.text[:400]
    assert calls, "expected the route to call the platform"
    assert [name for name, on_loop in calls if on_loop] == []
