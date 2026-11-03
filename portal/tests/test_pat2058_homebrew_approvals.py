"""PAT-2058: Homebrew formulae and casks join the same approval model as
applications and browser extensions - approve, unapprove, ignore or reset to
unreviewed, through the same PUT /v1/portal/software-approvals write route
PAT-2008 already guards (Origin, CSRF, admin role, strict item schema).

This file only covers what is new here: the Homebrew item shape (name/tap,
no platform/identifier), the Homebrew tab's own controls and counts, and
the "no alert" copy rule the platform contract states explicitly for a
Homebrew decision. The shared guard behaviour (cross-origin, bad CSRF,
oversized body, bulk cap, ...) is already exercised end to end against the
same route in tests/test_pat2008_software_approvals.py and is not repeated
here.
"""

import html as html_module
import json
import re
from urllib.parse import urlencode, urlsplit

import main
from tests.conftest import STUB_STATE

ORIGIN = "https://testserver"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path="/homebrew"):
    return client.get(path, headers=_headers(token))


def _post(client, token, fields, origin=ORIGIN, csrf=True, follow=False):
    body = list(fields)
    # Homebrew's own hidden return_to field always carries "/homebrew" (the
    # page the rendered form was on) - APPROVAL_RETURN_PATHS's default
    # without one is "/software", so a test that omits it here would prove
    # nothing about /homebrew's own return path.
    if not any(k == "return_to" for k, _ in body):
        body.append(("return_to", "/homebrew"))
    if csrf is True:
        body.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        body.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    return client.post("/software/approvals", content=urlencode(body), headers=headers,
                       follow_redirects=follow)


def _flash(client, token, response):
    assert response.status_code == 303, response.text[:400]
    location = response.headers["location"]
    assert urlsplit(location).path == "/homebrew"
    return client.get(location, headers=_headers(token))


def _row(html, name):
    for match in re.finditer(r"<tr[^>]*>.*?</tr>", html, re.DOTALL):
        row = match.group(0)
        if f">{name}<" in row:
            return row
    raise AssertionError(f"no row found for {name!r}")


def _row_item(row):
    match = re.search(r'<input type="hidden" name="item" value="([^"]*)">', row)
    assert match, "no item field found in row"
    return json.loads(html_module.unescape(match.group(1)))


# ── Counts on the summary strip ───────────────────────────────────────────

def test_unreviewed_and_unapproved_counts_render(client, make_token):
    resp = _get(client, make_token())
    assert resp.status_code == 200
    body = resp.text
    # HOMEBREW_SUMMARY fixture: unreviewed_count 2, unapproved_count 1 - each
    # tile's own label is immediately followed by its own value, so this
    # does not just prove "2" and "1" appear somewhere on the page.
    unreviewed = re.search(
        r'kpi__label">Unreviewed</div>\s*<div class="kpi__value[^"]*">(\d+)</div>', body)
    unapproved = re.search(
        r'kpi__label">Unapproved</div>\s*<div class="kpi__value[^"]*">(\d+)</div>', body)
    assert unreviewed and unreviewed.group(1) == "2"
    assert unapproved and unapproved.group(1) == "1"
    assert "isn't tracked" not in body
    assert "Approving or flagging Homebrew packages isn't available yet" not in body


# ── Who sees controls ──────────────────────────────────────────────────────

def test_admin_sees_bulk_and_row_controls(client, make_token):
    token = make_token()
    resp = _get(client, token)
    html = resp.text
    assert 'id="approval-form"' in html
    assert 'value="approved" data-bulk-submit' in html
    assert 'value="unapproved" data-bulk-submit' in html
    assert 'value="ignored" data-bulk-submit' in html
    assert 'value="unreviewed" data-bulk-submit' in html
    assert "Reset to unreviewed" in html
    formula_row = _row(html, "openssl@3")
    assert 'class="approval-select"' in formula_row
    assert ">Approve</option>" in formula_row
    assert ">Unapprove</option>" in formula_row
    assert ">Ignore</option>" in formula_row
    # Already unreviewed - resetting to the state it is already in is not
    # offered.
    assert ">Reset to unreviewed</option>" not in formula_row
    cask_row = _row(html, "firefox")
    assert 'class="approval-select"' in cask_row


def test_unapproved_row_offers_reset_to_unreviewed_not_unapprove_again(client, make_token):
    html = _get(client, make_token()).text
    row = _row(html, "readline")
    assert ">Unapprove</option>" not in row
    assert ">Approve</option>" in row
    assert ">Ignore</option>" in row
    assert ">Reset to unreviewed</option>" in row


def test_viewer_sees_no_controls(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    resp = _get(client, make_token())
    assert resp.status_code == 200
    html = resp.text
    assert 'id="approval-form"' not in html
    assert 'class="approval-select"' not in html
    assert "csrf_token" not in html
    assert "An administrator on your account can change them." in html
    row = _row(html, "openssl@3")
    assert "approval__btn" not in row
    # PAT-2255: history opens from the package name (the product detail).
    assert re.search(r'<a href="/software/history\?[^"]*" data-history-drawer>openssl@3</a>', row)


def test_role_unavailable_hides_controls_but_keeps_the_page(client, make_token):
    STUB_STATE["me_status"] = 500
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert 'id="approval-form"' not in resp.text
    assert "your account role could not be checked" in resp.text
    assert "openssl@3" in resp.text


# ── Writes: the platform receives the right item, identity and state ──────

def test_single_row_unapprove_posts_homebrew_formula_item(client, make_token):
    token = make_token()
    html = _get(client, token).text
    row = _row(html, "openssl@3")
    item = json.dumps(_row_item(row))
    resp = _post(client, token, [("state", "unapproved"), ("item", item)])
    assert resp.status_code == 303
    put = STUB_STATE["approval_puts"][0]
    assert put["body"] == {
        "state": "unapproved",
        "items": [{"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"}],
    }


def test_single_row_reset_to_unreviewed_posts_correct_state(client, make_token):
    token = make_token()
    html = _get(client, token).text
    row = _row(html, "readline")
    item = json.dumps(_row_item(row))
    resp = _post(client, token, [("state", "unreviewed"), ("item", item)])
    assert resp.status_code == 303
    put = STUB_STATE["approval_puts"][0]
    assert put["body"]["state"] == "unreviewed"
    assert put["body"]["items"] == [
        {"type": "homebrew_formula", "name": "readline", "tap": "homebrew/core"}]


def test_cask_row_posts_homebrew_cask_item(client, make_token):
    token = make_token()
    html = _get(client, token).text
    row = _row(html, "firefox")
    item = json.dumps(_row_item(row))
    resp = _post(client, token, [("state", "approved"), ("item", item)])
    assert resp.status_code == 303
    put = STUB_STATE["approval_puts"][0]
    assert put["body"]["items"] == [
        {"type": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"}]


def test_bulk_mixed_formula_and_cask_written_in_one_call(client, make_token):
    token = make_token()
    formula_item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    cask_item = json.dumps({"type": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"})
    resp = _post(client, token, [
        ("state", "ignored"), ("item", formula_item), ("item", cask_item),
        ("reason", "Estate cleanup"),
    ])
    assert resp.status_code == 303
    put = STUB_STATE["approval_puts"][0]
    assert put["body"]["state"] == "ignored"
    assert put["body"]["reason"] == "Estate cleanup"
    assert put["body"]["items"] == [
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"},
        {"type": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"},
    ]


def test_write_redirects_back_to_homebrew(client, make_token):
    token = make_token()
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "unapproved"), ("item", item)])
    assert resp.status_code == 303
    assert urlsplit(resp.headers["location"]).path == "/homebrew"


def test_written_state_is_reflected_on_reload(client, make_token):
    token = make_token()
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "unapproved"), ("item", item)])
    page = _flash(client, token, resp)
    row = _row(page.text, "openssl@3")
    assert 'data-approval-state="unapproved"' in row


# ── Viewer and CSRF guards, reusing the shared write route's own gate ─────

def test_viewer_post_is_refused_before_any_platform_write(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "approved"), ("item", item)])
    assert resp.status_code == 403
    assert "Only an administrator on your account can change approval state" in resp.text
    assert STUB_STATE["approval_puts"] == []


def test_missing_csrf_token_is_refused(client, make_token):
    token = make_token()
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "approved"), ("item", item)], csrf=False)
    assert resp.status_code == 403
    assert "This page has expired" in resp.text
    assert STUB_STATE["approval_puts"] == []


def test_malformed_homebrew_item_is_refused(client, make_token):
    token = make_token()
    for bad in (
        json.dumps({"type": "homebrew_formula", "name": ""}),
        json.dumps({"type": "homebrew_formula", "name": "openssl@3", "platform": "macos"}),
        json.dumps({"type": "homebrew_cask", "name": "firefox", "identifier": "x"}),
    ):
        resp = _post(client, token, [("state", "approved"), ("item", bad)])
        assert resp.status_code == 400, bad
    assert STUB_STATE["approval_puts"] == []


# ── Platform refusal renders a message, not a crash ────────────────────────

def test_platform_403_renders_a_message(client, make_token):
    token = make_token()
    STUB_STATE["approval_put_error"] = (
        403, {"error": "admin_role_required", "message": "admin only"})
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "approved"), ("item", item)])
    page = _flash(client, token, resp).text
    assert "Only an administrator on your account can change approval state." in page


def test_platform_unconfirmed_identity_refusal_names_the_package(client, make_token):
    token = make_token()
    STUB_STATE["approval_put_error"] = (422, {
        "error": "unconfirmed_identity",
        "message": "not a confirmed identity",
        "items": [{"index": 0, "code": "unconfirmed_identity",
                   "message": "not observed in this estate"}],
    })
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "approved"), ("item", item)])
    page = _flash(client, token, resp).text
    assert "Some products do not have a confirmed identity yet" in page
    assert "openssl@3: not observed in this estate" in page


# ── No alert copy anywhere on the tab (contract: Homebrew never alerts) ───

def test_no_alert_copy_on_the_homebrew_tab(client, make_token):
    resp = _get(client, make_token())
    body = resp.text
    main_html = body[body.index("<main"):]
    assert "alert" not in main_html.lower()


def test_no_alert_copy_after_a_write_even_if_the_platform_sent_one(client, make_token):
    """The platform contract says resolved_alerts is always 0 for a
    Homebrew result, but this proves the portal template structurally
    omits the "resolved" alert sentence for /homebrew rather than merely
    happening to render a zero - the same defence-in-depth /software's own
    approval-result notice does not need, because it is allowed to mention
    alerts."""
    token = make_token()
    STUB_STATE["approval_put_extra"] = {"resolved_alerts": 3}
    item = json.dumps(
        {"type": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"})
    resp = _post(client, token, [("state", "unapproved"), ("item", item)])
    page = _flash(client, token, resp)
    main_html = page.text[page.text.index("<main"):]
    assert "alert" not in main_html.lower()
