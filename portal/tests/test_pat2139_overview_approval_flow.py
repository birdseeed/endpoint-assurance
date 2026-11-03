"""PAT-2139: every product still waiting on a decision must stay reachable
on /software, and a write must land the customer where they were working.

Two independent causes were found, both reproduced here against the
un-fixed behaviour they replace:

1. The write redirect. _approval_return_to used to accept only "/software"
   while the Overview's New software form posted return_to="/". PAT-2139
   made "/" a return path so an approval from the Overview stayed on it.
   PAT-2254 (Andy, 28 September 2026) then moved software review out of the
   Overview altogether: the card is read only and links into /software, so
   "/" is no longer a return path. The tests below now pin that (a stale
   form posting return_to="/" is sent to /software, and the Overview
   ignores a stale post-write notice); tests/test_pat2254_overview_truthful
   covers the Overview rendering no controls.

2. Undecided products silently falling off /software. /software merges an
   unpaginated (but platform-capped) applications/extensions read with a
   *paginated* inventory read (GET /v1/portal/software, limit/offset); an
   inventory-only product (no matching governance row) only ever reaches
   the page if it happens to fall inside whichever inventory page was
   fetched. The portal's own default page size used to be 100, well under
   a realistic ~150-product estate - see
   test_inventory_only_undecided_product_beyond_old_default_page_is_now_reachable
   for the reproduction against that old default.
"""

import json
from urllib.parse import urlencode

import main
from tests.conftest import SOFTWARE_INVENTORY, STUB_STATE

ORIGIN = "https://testserver"


def _get(client, token, path="/"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _post(client, token, fields, origin=ORIGIN, follow=False):
    body = [*fields, ("csrf_token", main._csrf_token(token))]
    headers = {"Cf-Access-Jwt-Assertion": token,
               "Content-Type": "application/x-www-form-urlencoded"}
    if origin is not None:
        headers["Origin"] = origin
    STUB_STATE["expected_jwt"] = token
    return client.post("/software/approvals", content=urlencode(body), headers=headers,
                       follow_redirects=follow)


# ── Cause 1: the write redirect ─────────────────────────────────────────

def test_approval_return_to_allows_software_only():
    """_approval_return_to is the single gate every approval write's
    redirect goes through - it accepts the /software family and still
    refuses anything else (open-redirect defence unchanged). PAT-2254: the
    Overview is no longer a destination."""
    assert main._approval_return_to("/software") == "/software"
    assert main._approval_return_to("/software?type=application") == (
        "/software?type=application")
    assert main._approval_return_to("/software?approval=waiting&type=extension") == (
        "/software?approval=waiting&type=extension")
    # approval_result is always stripped so a stale token can't be replayed
    # in the next redirect.
    assert main._approval_return_to("/software?approval_result=stale") == "/software"
    # Anything else - the Overview, and a bare open-redirect attempt - falls
    # back to /software.
    assert main._approval_return_to("/") == "/software"
    # The path is replaced, the query rides along (it is only ever a
    # /software query then).
    assert main._approval_return_to("/?view=all") == "/software?view=all"
    assert main._approval_return_to("/evil") == "/software"
    assert main._approval_return_to("//evil.example.com") == "/software"
    assert main._approval_return_to("") == "/software"


def test_stale_overview_form_post_lands_on_software(client, make_token):
    """A form rendered by an older Overview still posts return_to="/". The
    write itself is unchanged; the redirect now lands on /software, where
    the same signed notice renders."""
    token = make_token()
    STUB_STATE["portal_role"] = "admin"
    item = json.dumps({
        "type": "application", "platform": "macos",
        "identifier": "com.example.mysteryapp", "name": "MysteryApp",
    })
    resp = _post(client, token, [
        ("state", "approved"), ("item", item), ("return_to", "/"),
    ])
    assert resp.status_code == 303, resp.text[:400]
    location = resp.headers["location"]
    assert location.startswith("/software?"), location


def test_overview_does_not_render_a_post_write_notice(client, make_token):
    """The notice belongs to the page the write returns to (/software). The
    Overview no longer reads it, so a stale or crafted approval_result
    parameter renders nothing there."""
    token = make_token()
    flash_token = main._sign_flash(token, {
        "state": "approved", "requested": 1, "changed": 1,
        "protected": [], "resolved_alerts": None,
    })
    resp = _get(client, token, f"/?approval_result={flash_token}")
    assert resp.status_code == 200
    assert 'id="approval-result"' not in resp.text
    assert "1 of 1 product changed to Approved." not in resp.text


# ── Cause 2: undecided products silently falling off /software ─────────

def _inventory_product(name, identifier, index):
    return {
        "name": name, "names": [name], "identifier": identifier, "platform": "macos",
        "versions": ["1.0"], "unknown_version_installation_count": 0,
        "device_count": 1, "installation_count": 1,
        "evidence_at": "2026-09-20T11:00:00Z", "last_used_at": None,
        "metered_installation_count": 1, "unmetered_installation_count": 0,
        "stale_installation_count": 0, "unused_installation_count": 0,
        "usage_state": "unmetered", "removal_candidate": False,
        "canonical_key": None, "canonical_name": None,
        "team_id": None, "product_key": f"application:macos:{identifier}",
        # policy_state null: no governance row resolves for this product at
        # all (contracts/portal-api.md GET /v1/portal/software) - an
        # ordinary "known identity, no decision yet" undecided row.
        "policy_state": None,
        "cve_assessment": {"state": "not_assessed", "last_matched_at": None,
                           "finding_count": None},
    }


def test_inventory_only_undecided_product_beyond_old_default_page_is_now_reachable(
    client, make_token,
):
    """Reproduction: an estate with more inventory-only products than the
    portal's own default page size used to request (100). "ZZFindMe" is
    product #120 (0-indexed 119) - inside the platform's own 500-row max,
    but past the portal's old default limit=100, so the old default page
    never included it and it was unreachable anywhere on /software: not in
    the rendered table, and not findable by the page's own client-side
    search since that only searches rows already in the DOM.

    Red on current main (SOFTWARE_INVENTORY_DEFAULT_LIMIT=100): "ZZFindMe"
    is absent from the default (query-string-free) /software response."""
    products = [_inventory_product(f"Filler{i:04d}", f"com.example.filler{i:04d}", i)
                for i in range(119)]
    products.append(_inventory_product("ZZFindMe", "com.example.zzfindme", 119))
    STUB_STATE["software_inventory_data"] = {**SOFTWARE_INVENTORY, "products": products}
    token = make_token()
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "ZZFindMe" in resp.text
    # Confirm it actually landed in the "Waiting on a decision" bucket, not
    # merely printed somewhere incidental on the page.
    tr_start = resp.text.rindex("<tr", 0, resp.text.index("ZZFindMe"))
    tr = resp.text[tr_start:resp.text.index("</tr>", tr_start)]
    assert 'data-filter-decision="waiting"' in tr


def test_default_inventory_request_now_matches_the_platform_max(client, make_token):
    """Direct assertion on the fix itself, independent of fixture size:
    the default (no ?limit=) request the portal forwards upstream now asks
    for the platform's own max page (500), not the old, easily-exceeded
    100."""
    token = make_token()
    _get(client, token, "/software")
    request = STUB_STATE["software_inventory_requests"][-1]
    assert request["limit"] == 500
    assert main.SOFTWARE_INVENTORY_DEFAULT_LIMIT == main.SOFTWARE_INVENTORY_MAX_LIMIT == 500
