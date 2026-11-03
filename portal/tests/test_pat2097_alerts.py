"""PAT-2097: the unapproved-software alert lifecycle (open, acknowledged,
resolved, re-opened) - GET /software/alerts (list, filtered and paginated),
GET /software/alerts/{id} (detail + history), and the portal's second
governance write, POST /software/alerts/{id}/acknowledge, behind the same
_guarded_form (Origin + CSRF) and admin role check PAT-2008/PAT-2105 use.

Reuses tests/conftest.py's ALERTS/ALERT_HISTORY fixtures and stub server
(StubPlatformHandler's software-alerts handling) rather than inventing a
second copy of the platform contract.
"""

import asyncio
from urllib.parse import urlencode

import pytest

import main
from tests.conftest import STUB_STATE

# Same reasoning as PAT-2008/PAT-2105's own tests: _same_origin requires
# https for every host except a genuinely local one, and the TestClient's
# default "testserver" host is not exempt.
ORIGIN = "https://testserver"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path="/software/alerts"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers=_headers(token))


RETURN_TO = [("return_to", "/software/alerts")]


def _post(client, token, path, fields, *, origin=ORIGIN, csrf=True, referer=None):
    body = list(fields)
    if csrf is True:
        body.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        body.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    if referer is not None:
        headers["Referer"] = referer
    STUB_STATE["expected_jwt"] = token
    return client.post(path, content=urlencode(body), headers=headers, follow_redirects=False)


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


# ── List rendering ─────────────────────────────────────────────────────────

def test_list_renders_real_rows_open_first(client, token):
    resp = _get(client, token, "/software/alerts?status=all")
    assert resp.status_code == 200
    body = resp.text
    assert "Tor Browser" in body
    assert "ShadyCoupons" in body
    assert "LegacyLedger" in body
    # Open, then acknowledged, then resolved (contract order + stub sort).
    assert body.index("Tor Browser") < body.index("ShadyCoupons") < body.index("LegacyLedger")
    assert "acme-mbp-frontdesk" in body  # device hostname
    # PAT-2155: the All tab shows a compact status + one "Last updated"
    # column, not the per-status Acknowledged/Resolved detail - that detail
    # lives on the matching tab (and on each alert's own detail page).
    resolved_body = _get(client, token, "/software/alerts?status=resolved").text
    assert "Product approved." in resolved_body  # resolved_reason


def test_list_empty_state(client, token):
    STUB_STATE["alerts_data"] = []
    resp = _get(client, token, "/software/alerts?status=all")
    assert resp.status_code == 200
    assert "No alerts match this filter" in resp.text


def test_overview_link_and_counts_appear(client, token):
    STUB_STATE["overview_data"] = {
        "tenant_name": "Acme Trust Ltd", "generated_at": "2026-09-24T10:00:00Z",
        "devices_total": 3, "devices_reporting_24h": 3,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "patch_status": {"up_to_date": 3, "pending": 0, "failed": 0},
        "unapproved_alerts_open": 2, "unapproved_alerts_acknowledged": 1,
    }
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "2 unapproved software alerts open, 1 acknowledged" in resp.text
    assert 'href="/software/alerts"' in resp.text


def test_overview_omits_alert_item_when_counts_unavailable(client, token):
    # unapproved_alerts_open/acknowledged absent entirely - must render as
    # genuinely unknown, never a false "0 open" (root AGENTS.md).
    resp = _get(client, token, "/")
    assert resp.status_code == 200
    assert "unapproved software alert" not in resp.text


# ── Filters pass through ───────────────────────────────────────────────────

def test_status_filter_passes_through(client, token):
    _get(client, token, "/software/alerts?status=resolved")
    assert STUB_STATE["alert_list_requests"][-1]["status"] == "resolved"


def test_all_status_omits_the_status_param(client, token):
    _get(client, token, "/software/alerts?status=all")
    assert "status" not in STUB_STATE["alert_list_requests"][-1]


def test_product_and_device_filters_pass_through(client, token):
    path = "/software/alerts?status=all&product=application:macos:x&device=dev-1"
    resp = _get(client, token, path)
    req = STUB_STATE["alert_list_requests"][-1]
    assert req["product_key"] == "application:macos:x"
    assert req["device_id"] == "dev-1"
    # Table narrows to matches only.
    assert "Tor Browser" not in resp.text  # doesn't match this product_key


def test_unknown_status_falls_back_to_open(client, token):
    resp = _get(client, token, "/software/alerts?status=bogus")
    assert resp.status_code == 200
    assert STUB_STATE["alert_list_requests"][-1]["status"] == "open"


def test_paging_computes_offset(client, token):
    # Only 3 fixture alerts, so a real page 2 has no rows and the route
    # redirects back to page 1 (same PAT-1201 shape as /findings) - disable
    # redirect-following so the recorded request is page 2's own, not the
    # page-1 request the redirect makes next.
    resp = client.get("/software/alerts?status=all&page=2", headers=_headers(token),
                       follow_redirects=False)
    assert resp.status_code == 302
    assert STUB_STATE["alert_list_requests"][-1]["offset"] == str(main.ALERT_PAGE_SIZE)


def test_empty_page_past_the_last_row_redirects_to_page_one(client, token):
    resp = _get(client, token, "/software/alerts?status=all&page=2")
    assert resp.status_code == 200
    assert "page=2" not in str(resp.url)


# ── Detail + history render and escape ──────────────────────────────────────

def test_detail_renders_history(client, token):
    resp = _get(client, token, "/software/alerts/2")
    assert resp.status_code == 200
    assert "ShadyCoupons" in resp.text
    assert "Raised with the service desk" in resp.text
    assert "alice@tenant-a.example" in resp.text


def test_detail_404_for_unknown_id(client, token):
    resp = _get(client, token, "/software/alerts/999999")
    assert resp.status_code == 404


def test_detail_404_for_non_numeric_id(client, token):
    resp = _get(client, token, "/software/alerts/not-a-number")
    assert resp.status_code == 404


def test_history_note_and_reason_are_escaped(client, token):
    STUB_STATE["alert_history_overrides"] = {
        1: [{"id": 1, "from": None, "to": "open", "actor_kind": "system", "actor": None,
             "reason": None, "note": None, "at": "2026-09-24T14:05:02Z"},
            {"id": 2, "from": "open", "to": "acknowledged", "actor_kind": "portal_user",
             "actor": "<img src=x onerror=alert(1)>@tenant-a.example",
             "reason": "<script>alert(2)</script>",
             "note": "<b>bold note</b>", "at": "2026-09-24T15:00:00Z"}],
    }
    resp = _get(client, token, "/software/alerts/1")
    assert resp.status_code == 200
    assert "<script>alert(2)</script>" not in resp.text
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in resp.text
    assert "<b>bold note</b>" not in resp.text
    assert "&lt;b&gt;bold note&lt;/b&gt;" in resp.text
    assert "<img src=x onerror=alert(1)>" not in resp.text


# ── Acknowledge: admin, guard, note ─────────────────────────────────────────

def test_admin_sees_acknowledge_control_viewer_does_not(client, token):
    # PAT-2155: the Acknowledge control (and its whole Actions column) only
    # renders on the Open tab now - acknowledging only ever applies to an
    # open alert (can_acknowledge = status == 'open').
    STUB_STATE["portal_role"] = "admin"
    admin_body = _get(client, token, "/software/alerts?status=open").text
    assert 'action="/software/alerts/1/acknowledge"' in admin_body

    STUB_STATE["portal_role"] = "viewer"
    viewer_body = _get(client, token, "/software/alerts?status=open").text
    assert 'action="/software/alerts/1/acknowledge"' not in viewer_body
    assert "An administrator on your account can acknowledge" in viewer_body


def test_acknowledge_posts_the_right_id_and_note(client, token):
    resp = _post(client, token, "/software/alerts/1/acknowledge",
                 [("note", "Raised a ticket"), ("return_to", "/software/alerts?status=open")])
    assert resp.status_code == 303, resp.text[:300]
    post = STUB_STATE["alert_acknowledge_posts"][-1]
    assert post["alert_id"] == "1"
    assert post["body"] == {"note": "Raised a ticket"}
    location = resp.headers["location"]
    assert location.startswith("/software/alerts?status=open")
    assert "#alert-result" in location


def test_acknowledge_with_no_note_sends_no_body(client, token):
    _post(client, token, "/software/alerts/1/acknowledge", RETURN_TO)
    post = STUB_STATE["alert_acknowledge_posts"][-1]
    assert post["body"] == {}


def test_acknowledge_note_over_limit_is_refused_before_the_platform_call(client, token):
    resp = _post(client, token, "/software/alerts/1/acknowledge",
                 [("note", "x" * 1001), ("return_to", "/software/alerts")])
    assert resp.status_code == 303
    assert STUB_STATE["alert_acknowledge_posts"] == []
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "at most 1000 characters" in follow.text


def test_acknowledge_redirects_and_shows_success_notice(client, token):
    resp = _post(client, token, "/software/alerts/1/acknowledge",
                 [("return_to", "/software/alerts?status=open")])
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "Alert acknowledged." in follow.text


def test_viewer_post_is_refused_and_never_reaches_the_platform(client, token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _post(client, token, "/software/alerts/1/acknowledge", RETURN_TO)
    assert resp.status_code == 403
    assert "administrator" in resp.text
    assert STUB_STATE["alert_acknowledge_posts"] == []


# ── 409 (resolved) and 404 ───────────────────────────────────────────────────

def test_already_resolved_alert_returns_409_message(client, token):
    resp = _post(client, token, "/software/alerts/3/acknowledge", RETURN_TO)
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "already been resolved" in follow.text
    post = STUB_STATE["alert_acknowledge_posts"][-1]
    assert post["alert_id"] == "3"


def test_unknown_alert_id_returns_not_found_message(client, token):
    resp = _post(client, token, "/software/alerts/987654/acknowledge", RETURN_TO)
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "could not be found" in follow.text


def test_idempotent_acknowledge_of_an_already_acknowledged_alert(client, token):
    resp = _post(client, token, "/software/alerts/2/acknowledge", RETURN_TO)
    assert resp.status_code == 303
    follow = client.get(resp.headers["location"], headers=_headers(token))
    assert "was already acknowledged" in follow.text


# ── The guard (Origin/CSRF) - belt and braces on top of the shared
#    test_pat2105_csrf.py route walk, which auto-discovers this route ──────

def test_cross_origin_acknowledge_is_refused(client, token):
    resp = _post(client, token, "/software/alerts/1/acknowledge",
                 RETURN_TO, origin="https://evil.example")
    assert resp.status_code == 403
    assert "did not come from the portal page itself" in resp.text
    assert STUB_STATE["alert_acknowledge_posts"] == []


def test_missing_csrf_token_is_refused(client, token):
    resp = _post(client, token, "/software/alerts/1/acknowledge",
                 RETURN_TO, csrf=False)
    assert resp.status_code == 403
    assert "This page has expired" in resp.text
    assert STUB_STATE["alert_acknowledge_posts"] == []


def test_route_is_registered_and_would_be_caught_by_the_pat2105_route_walk():
    routes = {(m, r.path) for r in main.app.routes for m in getattr(r, "methods", None) or ()}
    assert ("POST", "/software/alerts/{alert_id}/acknowledge") in routes


# ── The alert_id path parameter is str, not int - see the route's own
#    docstring: an int converter would 422 before the guard ever runs ──────

def test_non_numeric_alert_id_still_refuses_cross_origin_before_touching_alert_id(client, token):
    resp = client.post(
        "/software/alerts/not-a-number/acknowledge",
        content=urlencode([("csrf_token", main._csrf_token(token))]),
        headers=_headers(token, **{"Origin": "https://evil.example",
                                    "Content-Type": "application/x-www-form-urlencoded"}),
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert "did not come from the portal page itself" in resp.text


# ── Upstream calls run off the event loop (PAT-2105 discipline) ────────────

def test_acknowledge_upstream_calls_never_run_on_the_event_loop(client, token, monkeypatch):
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

    for name in ("get_json", "post_json"):
        monkeypatch.setattr(main.upstream, name, watch(name, getattr(main.upstream, name)))
    resp = _post(client, token, "/software/alerts/1/acknowledge", RETURN_TO)
    assert resp.status_code == 303
    assert calls, "expected the route to call the platform"
    assert [n for n, on_loop in calls if on_loop] == []
