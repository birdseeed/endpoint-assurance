"""PAT-2010: New Software and Unapproved & Unreviewed Software (drift)
reports, consuming PAT-2009's GET /v1/portal/software/new,
GET /v1/portal/software/drift and GET /v1/portal/software/approved
(contracts/portal-api.md "Software governance reporting (PAT-2009)").

Covers (STAGE 1 - all of these are expected to fail until the feature is
built):
  - both report pages rendering real and empty data
  - an upstream failure rendering an honest "could not be read" state, never
    an empty table that implies there is nothing new (root AGENTS.md -
    absence requires authority)
  - quick approve/unapprove from a New Software row, through the existing
    POST /software/approvals write (PAT-2008) with CSRF
  - the CSV downloads for both reports plus the approved-list export button,
    with correct content type and formula-injection escaping
  - the /software callout ("N new since your last review") whose count
    always equals the report's own total, hidden at 0 or on error
  - the new-software notification toggle (admin-only, reusing the
    /ai-tooling toggle's own POST /ai-tooling/notifications code path),
    read-only for a viewer
  - /reports linking both new pages
  - the PAT-2105 CSRF route enumeration still passing (no new POST route is
    introduced by this ticket - both writes reuse existing guarded routes)
"""

import json
import re
from urllib.parse import urlencode

import main
from tests.conftest import (
    NEW_SOFTWARE_CSV,
    NEW_SOFTWARE_REPORT,
    NEW_SOFTWARE_REPORT_EMPTY,
    SOFTWARE_APPROVED_CSV,
    SOFTWARE_DRIFT_CSV,
    SOFTWARE_DRIFT_REPORT_EMPTY,
    STUB_STATE,
)

ORIGIN = "https://testserver"


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _post(client, token, path, fields, *, origin=ORIGIN, csrf=True, follow=False):
    body = list(fields)
    if csrf is True:
        body.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        body.append(("csrf_token", csrf))
    headers = {"Cf-Access-Jwt-Assertion": token,
              "Content-Type": "application/x-www-form-urlencoded"}
    if origin is not None:
        headers["Origin"] = origin
    return client.post(path, content=urlencode(body), headers=headers, follow_redirects=follow)


# ── New Software report ────────────────────────────────────────────────────

def test_new_software_report_renders_populated_data(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/new-software")
    assert resp.status_code == 200
    body = resp.text
    assert "New Tool" in body
    assert "acme-win-accounts" in body  # first_device.hostname
    assert "1" in body  # device_count somewhere on the row
    assert "Unreviewed" in body
    # A row with a confirmed identifier is addressable.
    assert "vendor.newtool" in body
    assert 'action="/software/approvals"' in body
    # A name-only row (no product_key) cannot be marked - locked, not
    # silently hidden, and not offered a control (root AGENTS.md: absence
    # requires authority is also "never claim you can act on what you
    # cannot identify").
    assert "Legacy Tool" in body
    assert "cannot be marked" in body


def test_new_software_report_renders_empty_data(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["new_software_data"] = NEW_SOFTWARE_REPORT_EMPTY
    resp = _get(client, token, "/reports/new-software")
    assert resp.status_code == 200
    body = resp.text
    assert "New Tool" not in body
    # A trustworthy zero reads as an explicit, confirmed empty state.
    assert "no new software" in body.lower() or "nothing new" in body.lower()
    assert "could not be read" not in body.lower()
    assert "temporarily unavailable" not in body.lower()


def test_new_software_report_error_state_is_not_rendered_as_empty(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["new_software_status"] = 500
    resp = _get(client, token, "/reports/new-software")
    assert resp.status_code == 502
    body = resp.text.lower()
    # Must not read like the trustworthy empty state above.
    assert "no new software" not in body
    assert "nothing new" not in body
    assert "temporarily unavailable" in body or "could not" in body


def test_new_software_report_links_from_reports_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/new-software"' in resp.text


# ── Software drift report ──────────────────────────────────────────────────

def test_software_drift_report_renders_populated_data(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software-drift")
    assert resp.status_code == 200
    body = resp.text
    assert "Bad App" in body
    assert "openssl@3" in body
    assert "acme-mbp-frontdesk" in body  # top device
    # 26-week trend rendered as an inline SVG, no chart library (root
    # AGENTS.md / repo AGENTS.md stack section).
    assert "<svg" in body
    assert "<script src=\"https://" not in body  # no chart library CDN


def test_trend_draws_a_polyline_with_two_or_more_recorded_weeks(client, make_token):
    """The stub's default drift fixture now records two weeks (the current
    one plus the week before), so the trend chart should draw a real line,
    not just a floating last-point marker or the sparse-data text state."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software-drift")
    assert resp.status_code == 200
    body = resp.text
    assert "<polyline" in body
    assert "Trend starts" not in body
    assert "No weekly snapshot recorded yet" not in body
    # Legend swatches use the real series colours, not a generic grey, and
    # there is no stray separator dot between the two legend items.
    assert 'class="legend-dot legend-dot--bad"' in body
    assert 'class="legend-dot legend-dot--warn"' in body
    assert "&middot;" not in body


def test_trend_shows_sparse_state_with_fewer_than_two_recorded_weeks(client, make_token):
    """SOFTWARE_DRIFT_REPORT_EMPTY's trend records only the current week (one
    recorded week), so the chart must not draw an empty SVG with a floating
    dot - it renders a short text state naming the real first-recorded-week
    date instead."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["software_drift_data"] = SOFTWARE_DRIFT_REPORT_EMPTY
    resp = _get(client, token, "/reports/software-drift")
    assert resp.status_code == 200
    body = resp.text
    assert "<polyline" not in body
    assert "Trend starts 21 Sep 2026" in body
    assert "One weekly snapshot so far" in body


def test_software_drift_report_renders_empty_data(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["software_drift_data"] = SOFTWARE_DRIFT_REPORT_EMPTY
    resp = _get(client, token, "/reports/software-drift")
    assert resp.status_code == 200
    body = resp.text
    assert "Bad App" not in body
    assert "no unapproved" in body.lower() or "nothing unapproved" in body.lower()
    assert "could not be read" not in body.lower()
    assert "temporarily unavailable" not in body.lower()


def test_software_drift_report_error_state_is_not_rendered_as_empty(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["software_drift_status"] = 500
    resp = _get(client, token, "/reports/software-drift")
    assert resp.status_code == 502
    body = resp.text.lower()
    assert "no unapproved" not in body
    assert "nothing unapproved" not in body
    assert "temporarily unavailable" in body or "could not" in body


def test_software_drift_report_links_from_reports_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/software-drift"' in resp.text


# ── Quick approve/unapprove from the New Software report row ──────────────

def test_quick_approve_from_new_software_report_posts_through_software_approvals(
        client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "admin"
    item = json.dumps({
        "type": "application", "platform": "windows",
        "identifier": "vendor.newtool", "name": "New Tool",
    })
    resp = _post(client, token, "/software/approvals", [
        ("state", "approved"), ("item", item),
        ("return_to", "/reports/new-software"),
    ])
    assert resp.status_code == 303
    # Lands back on the report page it was posted from, not a generic
    # fallback - the same return_to discipline PAT-2008's other callers
    # (Overview's New software card, /ai-tooling) already follow.
    assert resp.headers["location"].startswith("/reports/new-software")
    assert STUB_STATE["approval_puts"], "no write reached the platform"
    sent = STUB_STATE["approval_puts"][-1]
    assert sent["jwt"] == token
    assert sent["body"]["state"] == "approved"
    assert sent["body"]["items"][0]["identifier"] == "vendor.newtool"
    # Tenant is never in the body - it comes from the forwarded JWT only.
    assert "tenant" not in sent["body"] and "tenant_id" not in sent["body"]


def test_quick_unapprove_requires_csrf(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    item = json.dumps({
        "type": "application", "platform": "windows",
        "identifier": "vendor.newtool", "name": "New Tool",
    })
    resp = _post(client, token, "/software/approvals", [
        ("state", "unapproved"), ("item", item),
        ("return_to", "/reports/new-software"),
    ], csrf=False)
    assert resp.status_code == 403
    assert not STUB_STATE["approval_puts"], "write reached the platform with no CSRF token"


# ── CSV downloads ───────────────────────────────────────────────────────────

def test_new_software_csv_download(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/new-software.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == NEW_SOFTWARE_CSV
    # Formula-injection escaping: a spreadsheet-hostile cell arrives already
    # prefixed with "'" and must reach the browser unmangled.
    assert "'=cmd" in resp.text


def test_software_drift_csv_download(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software-drift.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == SOFTWARE_DRIFT_CSV
    assert "'=cmd" in resp.text


def test_approved_software_csv_download(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports/software/approved.csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.text == SOFTWARE_APPROVED_CSV
    assert "'=cmd" in resp.text


def test_approved_software_export_button_is_on_reports_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert 'href="/reports/software/approved.csv"' in resp.text


# ── /software callout ───────────────────────────────────────────────────────

def test_software_callout_shows_when_new_software_count_positive(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["new_software_data"] = NEW_SOFTWARE_REPORT  # total: 2
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    match = re.search(r"(\d+)\s+new since your last review", resp.text, re.IGNORECASE)
    assert match, "callout not found on /software"
    assert match.group(1) == "2"
    # PAT-2255: the callout opens the review queue, and still offers the
    # report.
    assert "data-review-queue-link" in resp.text
    assert 'href="/reports/new-software"' in resp.text


def test_software_callout_hidden_at_zero(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["new_software_data"] = NEW_SOFTWARE_REPORT_EMPTY  # total: 0
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "since your last review" not in resp.text.lower()


def test_software_callout_hidden_on_upstream_error(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["new_software_status"] = 500
    resp = _get(client, token, "/software")
    # The rest of /software is unaffected by this supplementary read failing.
    assert resp.status_code == 200
    body = resp.text.lower()
    assert "since your last review" not in body
    assert "0 new" not in body


def test_software_callout_counts_the_new_products_still_unreviewed(client, make_token):
    """PAT-2255 superseded PAT-2010's "the callout reads the report's own
    total": the callout is now the entry to the review queue, so it counts
    what that queue holds - the products the same GET /v1/portal/software/
    new response lists that are still Unreviewed, as the platform reports
    each one's state - and the queue heading it opens repeats that figure.
    A product already decided since the last review is new, but not
    waiting on anyone, so it is not counted."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    products = NEW_SOFTWARE_REPORT["products"]
    STUB_STATE["new_software_data"] = {**NEW_SOFTWARE_REPORT, "total": 3, "products": [
        *products, {**products[0], "name": "Decided Tool", "identifier": "vendor.decided",
                    "product_key": "application:windows:vendor.decided",
                    "approval_state": "approved"}]}
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    match = re.search(r"(\d+)\s+new since your last review", resp.text, re.IGNORECASE)
    assert match, "callout not found on /software"
    assert match.group(1) == "2"


# ── Settings: new-software notification toggle (admin-only) ────────────────

def test_notification_toggle_visible_and_writable_for_admin(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "admin"
    resp = _get(client, token, "/reports/new-software")
    assert resp.status_code == 200
    body = resp.text
    assert 'action="/ai-tooling/notifications"' in body
    assert 'name="setting" value="new_software_enabled"' in body
    assert "<input type=\"checkbox\"" in body


def test_notification_toggle_read_only_for_viewer(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, token, "/reports/new-software")
    assert resp.status_code == 200
    body = resp.text
    # A viewer sees the current setting, never a form that could change it.
    assert 'name="setting" value="new_software_enabled"' not in body


def test_notification_toggle_put_forwards_jwt_with_no_tenant_and_returns_to_the_report(
        client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "admin"
    resp = _post(client, token, "/ai-tooling/notifications", [
        ("setting", "new_software_enabled"), ("enabled", "on"),
        ("return_to", "/reports/new-software"),
    ])
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/reports/new-software")
    assert STUB_STATE["software_notification_puts"], "no write reached the platform"
    put = STUB_STATE["software_notification_puts"][-1]
    assert put["jwt"] == token
    assert put["body"] == {"new_software_enabled": True}
    assert "tenant" not in put["body"] and "tenant_id" not in put["body"]


def test_notification_toggle_refused_for_viewer(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "viewer"
    resp = _post(client, token, "/ai-tooling/notifications", [
        ("setting", "new_software_enabled"), ("enabled", "on"),
        ("return_to", "/reports/new-software"),
    ])
    assert resp.status_code == 403
    assert not STUB_STATE["software_notification_puts"], "viewer write reached the platform"


def test_notification_toggle_return_to_is_an_exact_match_allowlist(client, make_token):
    """PAT-2010 security requirement: return_to is never followed as a
    client-supplied URL. Only the two literal internal paths are honoured;
    everything else - an absolute URL, a protocol-relative host, a backslash
    trick, or the allowlisted path with a smuggled query string appended -
    falls back to /ai-tooling, the toggle's original, unconditional
    destination. A weaker check (safe_return_to()'s path-prefix-plus-query
    style, or _approval_return_to()'s path-only allowlist that still keeps
    the query string) would let the last case through with the malicious
    query intact - this asserts the stricter, exact-match behaviour instead."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "admin"
    rejected = [
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "/reports/new-software?x=https://evil",
    ]
    for value in rejected:
        resp = _post(client, token, "/ai-tooling/notifications", [
            ("setting", "new_software_enabled"), ("enabled", "on"),
            ("return_to", value),
        ])
        assert resp.status_code == 303, value
        location = resp.headers["location"]
        assert location.startswith("/ai-tooling"), (value, location)
        assert not location.startswith("/reports/new-software"), (value, location)
        assert "evil" not in location.split("#")[0].split("?")[0], (value, location)


def test_notification_toggle_return_to_allows_the_exact_allowlisted_paths(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["portal_role"] = "admin"
    for value in ("/ai-tooling", "/reports/new-software"):
        resp = _post(client, token, "/ai-tooling/notifications", [
            ("setting", "new_software_enabled"), ("enabled", "on"),
            ("return_to", value),
        ])
        assert resp.status_code == 303, value
        assert resp.headers["location"].startswith(value), value


# ── CSRF enumeration is unaffected (no new POST route is introduced) ──────

def test_no_new_unsafe_route_was_introduced():
    """This ticket reuses POST /software/approvals and POST /ai-tooling/
    notifications for both writes rather than adding a third route, so
    tests/test_pat2105_csrf.py's app.routes enumeration needs no update -
    confirmed here directly against the live route table."""
    safe = {"GET", "HEAD", "OPTIONS"}
    unsafe_paths = {
        route.path for route in main.app.routes
        if set(getattr(route, "methods", None) or ()) - safe
    }
    assert "/reports/new-software" not in unsafe_paths
    assert "/reports/software-drift" not in unsafe_paths
    assert unsafe_paths & {"/software/approvals", "/ai-tooling/notifications"} == {
        "/software/approvals", "/ai-tooling/notifications"}
