"""PAT-2093: the overview's "New software" card - new_software from
GET /v1/portal/overview (contracts/portal-api.md "New software by
urgency"), sorted by urgency, with per-level counts (Not assessed kept
distinct from Low), an honest empty state keyed off window_days, a null or
malformed block rendering no card and no fake zero, and the same PAT-2008
approval write path (POST /software/approvals, same _guarded_form guard,
same lock rules) reused for admin controls - never a second write path.
PAT-2254 removed those controls from the Overview: the card is read only and
software review lives in /software, so the control and lock-rule tests that
lived here moved out with them (the write route and its guards stay covered
by tests/test_pat2008_software_approvals.py and the /software page tests;
tests/test_pat2254_overview_truthful.py asserts the Overview renders none).

Reuses tests/conftest.py's OVERVIEW/STUB_STATE fixtures and stub server
rather than inventing a second copy of the platform contract.
"""

from tests.conftest import OVERVIEW, STUB_STATE


def _get(client, token, path="/"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _product(name, urgency, **fields):
    base = {
        "name": name, "platform": "macos", "identifier": f"com.example.{name.lower()}",
        "team_id": "ABCDE12345", "product_key": f"application:macos:com.example.{name.lower()}",
        "approval_state": "unreviewed", "first_seen_at": "2026-09-23T08:00:00Z",
        "device_count": 1, "urgency": urgency,
        "reasons": [{"code": "signing_unknown", "level": urgency,
                    "detail": f"{name} has a {urgency} finding"}],
    }
    base.update(fields)
    return base


def _new_software(**fields):
    base = {
        "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
        "until": "2026-09-24T12:00:00Z", "window_days": 14, "last_review_at": None,
        "total": 0, "counts": {"critical": 0, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
        "truncated": False, "limit": 50, "products": [],
    }
    base.update(fields)
    return base


def _overview_with(new_software):
    return {**OVERVIEW, "new_software": new_software}


# ── Rendering: sort order, counts, reasons ─────────────────────────────────

def test_card_renders_real_rows_sorted_by_urgency(client, make_token):
    # Deliberately fed out of urgency order (medium, critical, low, high,
    # not_assessed) - the card must still render critical, high,
    # not_assessed, medium, low, proving the portal sorts rather than
    # trusting upstream order.
    products = [
        _product("MediumTool", "medium"),
        _product("CriticalTool", "critical"),
        _product("LowTool", "low"),
        _product("HighTool", "high"),
        _product("NotAssessedTool", "not_assessed"),
    ]
    STUB_STATE["overview_data"] = _overview_with(_new_software(total=5, products=products))
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    body = resp.text
    assert "New software" in body
    for name in ("CriticalTool", "HighTool", "NotAssessedTool", "MediumTool", "LowTool"):
        assert name in body
    order = [body.index(n) for n in
             ("CriticalTool", "HighTool", "NotAssessedTool", "MediumTool", "LowTool")]
    assert order == sorted(order)


def test_counts_appear_and_not_assessed_is_distinct_from_low(client, make_token):
    new_software = _new_software(
        total=5,
        counts={"critical": 1, "high": 2, "not_assessed": 3, "medium": 0, "low": 4},
        products=[_product("X", "critical")],
    )
    STUB_STATE["overview_data"] = _overview_with(new_software)
    resp = _get(client, make_token())
    body = resp.text
    ns_start = body.index("New software")
    card = body[ns_start:body.index("</section>", ns_start)]
    # "Not assessed" (3) and "Low" (4) are each their own kpi item, not
    # merged - both labels and both values are present in the card.
    assert "Not assessed" in card
    assert "Low" in card
    assert ">3<" in card
    assert ">4<" in card


# ── PAT-2159: hidden only on a successful zero read; a failed or
#    untrustworthy read renders the card with its own unavailable line and
#    is never hidden (absence requires authority) ──────────────────────────

def test_zero_counts_with_a_successful_read_hides_the_card_entirely(client, make_token):
    STUB_STATE["overview_data"] = _overview_with(
        _new_software(window_days=21, total=0, products=[]))
    resp = _get(client, make_token())
    body = resp.text
    assert "New software" not in body
    assert "No new software" not in body
    assert "could not be read" not in body


def test_nonzero_total_shows_the_card_even_with_zero_urgency_counts(client, make_token):
    # The hide/show decision keys off `total` - the platform's own "how
    # many new products" aggregate - not the separate urgency `counts`
    # breakdown, so a read that sets one but not the other (as most of
    # this file's fixtures do, via _new_software()'s own zeroed default)
    # never mistakes a real find for a confirmed-zero read.
    products = [_product("StillNewTool", "critical")]
    STUB_STATE["overview_data"] = _overview_with(
        _new_software(window_days=14, total=1, products=products))
    resp = _get(client, make_token())
    assert "New software" in resp.text
    assert "StillNewTool" in resp.text


# ── Absence: null / missing / malformed ─────────────────────────────────────

def test_null_new_software_block_renders_unavailable_not_a_fake_zero(client, make_token):
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": None}
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "New software" in resp.text
    assert "New software could not be read for this estate right now." in resp.text
    assert "No new software" not in resp.text


def test_missing_new_software_key_renders_unavailable(client, make_token):
    # Older platform build: the key is absent entirely, not just null.
    overview = dict(OVERVIEW)
    assert "new_software" not in overview
    STUB_STATE["overview_data"] = overview
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "New software could not be read for this estate right now." in resp.text


def test_malformed_new_software_block_renders_unavailable(client, make_token):
    STUB_STATE["overview_data"] = _overview_with({"window_days": "not-a-number", "products": []})
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "New software could not be read for this estate right now." in resp.text


def test_malformed_product_entry_takes_the_whole_block_unavailable(client, make_token):
    products = [_product("GoodTool", "high"), {"name": "BadTool", "urgency": "not-a-level"}]
    STUB_STATE["overview_data"] = _overview_with(_new_software(total=2, products=products))
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "New software could not be read for this estate right now." in resp.text
    assert "GoodTool" not in resp.text


# ── Approval controls: viewer vs admin, lock rules, escaping ───────────────

def test_viewer_sees_no_controls(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    products = [_product("ViewerTool", "critical")]
    STUB_STATE["overview_data"] = _overview_with(_new_software(total=1, products=products))
    resp = _get(client, make_token())
    body = resp.text
    assert "ViewerTool" in body
    assert "approval-row-form" not in body
    assert "Set state" not in body
    assert '<th>Approval</th>' not in body


def test_row_without_product_key_still_renders_read_only(client, make_token):
    # A row with no usable identity used to lock its controls with "cannot be
    # marked". The Overview has no controls now; the row still shows, links
    # into /software, and carries no form or lock text.
    products = [_product("NoIdentity", "high", identifier=None, team_id=None, product_key=None)]
    STUB_STATE["overview_data"] = _overview_with(_new_software(total=1, products=products))
    resp = _get(client, make_token())
    body = resp.text
    assert "NoIdentity" in body
    row = body[body.index("NoIdentity"):body.index("</tr>", body.index("NoIdentity"))]
    assert "approval-row-form" not in row
    assert "cannot be marked" not in row
    assert 'href="/software?search=NoIdentity"' in body


def test_reasons_are_escaped(client, make_token):
    products = [_product(
        "XSSTool", "critical",
        reasons=[{"code": "unsigned", "level": "critical",
                 "detail": "<script>alert(1)</script> & \"quoted\""}],
    )]
    STUB_STATE["overview_data"] = _overview_with(_new_software(total=1, products=products))
    resp = _get(client, make_token())
    body = resp.text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_product_links_to_software_page_with_search(client, make_token):
    products = [_product("Link Me & Co", "critical")]
    STUB_STATE["overview_data"] = _overview_with(_new_software(total=1, products=products))
    resp = _get(client, make_token())
    assert 'href="/software?search=Link%20Me%20%26%20Co"' in resp.text


