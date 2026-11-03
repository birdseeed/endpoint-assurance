"""PAT-2254: the Overview stops showing a customer things that are wrong or
that belong elsewhere.

Found by walking the live Overview on 28 September 2026:

1. The page title was the tenant's platform name, "Endpoint Assurance cycle
   2026-09-03 (PAT-1301)": an internal delivery label and a Linear ticket id.
   The title is now "Overview"; the tenant name is the subline and is
   cleaned of internal identifiers before it renders.
2. The same awaiting-decision figure read 128 in Top 3 actions and 140 on
   the Software awaiting approval card. Top 3, the at-a-glance line and the
   card now read one value.
3. The Reporting and agent health card showed a bare "3" over "4 reporting
   . 0 not reporting". The headline now says what it counts and agrees with
   the coverage panel's collection-issue line.
4. Software review lives in /software (Andy, 28 September 2026): the
   Overview has no Set state / Apply controls, and every software count and
   row links into /software with filter query params.

Reuses tests/conftest.py's OVERVIEW/OVERVIEW_CARDS/STUB_STATE fixtures and
the PAT-2093 helpers rather than a second copy of the platform contract.
"""

import copy
import html
import re
from urllib.parse import parse_qs, urlsplit

import main
from tests.conftest import (
    OVERVIEW,
    OVERVIEW_CARDS,
    OVERVIEW_CARDS_MIXED,
    OVERVIEW_CARDS_ZERO,
    STUB_STATE,
)
from tests.test_pat2093_new_software import _get, _new_software, _product

LEAKY_TENANT_NAME = "Endpoint Assurance cycle 2026-09-03 (PAT-1301)"
INTERNAL_ID_RE = re.compile(r"PAT-\d+")


def _overview(**fields):
    STUB_STATE["overview_data"] = {**OVERVIEW, **fields}


def _card_block(body: str, key: str) -> str:
    match = re.search(rf'<a[^>]*data-card="{re.escape(key)}"[^>]*>.*?</a>', body, re.DOTALL)
    if not match:
        match = re.search(rf'<div[^>]*data-card="{re.escape(key)}"[^>]*>.*?</div>', body, re.DOTALL)
    assert match, f'no data-card="{key}" element in the rendered page'
    return match.group(0)


def _headline(block: str) -> str:
    match = re.search(r'<span class="ov-card__headline">([^<]*)</span>', block)
    assert match, "card has no headline span"
    return match.group(1).strip()


def _without_code(body: str) -> str:
    """The page as a customer can read it: markup and attribute values
    stay (a `title` or `aria-label` is customer-visible), inline script and
    style blocks and HTML comments go (developer comments, never rendered;
    the walker's own leak check reads rendered text the same way)."""
    body = re.sub(r"<(script|style)\b.*?</\1>", "", body, flags=re.DOTALL | re.IGNORECASE)
    return re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)


def _cards(**overrides):
    """OVERVIEW_CARDS with the given card keys replaced (deep copy: the
    module fixture is shared across the suite)."""
    data = copy.deepcopy(OVERVIEW_CARDS)
    data["cards"].update(overrides)
    return data


def _hrefs(body: str) -> list[str]:
    return [html.unescape(h) for h in re.findall(r'href="([^"]*)"', body)]


def _section(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    return body[start:body.index(end_marker, start)]


# ── 1. Title and internal identifiers ─────────────────────────────────────

def test_title_is_overview_and_no_internal_identifier_renders(client, make_token):
    _overview(tenant_name=LEAKY_TENANT_NAME)
    resp = _get(client, make_token())
    assert resp.status_code == 200
    body = resp.text
    assert "<h1>Overview</h1>" in body
    assert "<title>Overview" in body
    shipped = _without_code(body)
    assert not INTERNAL_ID_RE.search(shipped), INTERNAL_ID_RE.search(shipped)
    assert "cycle 2026-09-03" not in shipped
    assert "Snapshot generated" in body


def test_tenant_name_and_snapshot_time_are_the_subline(client, make_token):
    _overview(tenant_name="Acme Trust Ltd")
    body = _get(client, make_token()).text
    head = re.search(r'<div class="page-head">.*?<p class="meta">.*?</p>', body, re.DOTALL).group(0)
    assert "<h1>Overview</h1>" in head
    assert "Acme Trust Ltd" in head
    assert head.index("Acme Trust Ltd") > head.index("<h1>Overview</h1>")
    assert "Snapshot generated" in head and "(UTC)" in head


def test_missing_tenant_name_falls_back_to_your_estate(client, make_token):
    _overview(tenant_name="")
    body = _get(client, make_token()).text
    assert "<h1>Overview</h1>" in body
    assert "Your estate" in body


def test_customer_facing_tenant_name_strips_internal_identifiers():
    clean = main._customer_facing_tenant_name
    assert clean(LEAKY_TENANT_NAME) == "Endpoint Assurance"
    assert clean("Acme Trust Ltd") == "Acme Trust Ltd"
    assert clean("Acme (PAT-42) Ltd") == "Acme Ltd"
    assert clean("Acme Ltd [PAT-1301]") == "Acme Ltd"
    assert clean("Acme Ltd PAT-1301") == "Acme Ltd"
    assert clean("Acme 0e89e4bb-fbc6-49ec-a7fc-bcd28680691b Ltd") == "Acme Ltd"
    # Nothing left after cleaning, or nothing to begin with: the neutral
    # fallback, never an empty heading and never the raw value.
    assert clean("(PAT-1301)") == "Your estate"
    assert clean("") == "Your estate"
    assert clean(None) == "Your estate"
    assert clean(12345) == "Your estate"


# ── 2. One awaiting-decision count ────────────────────────────────────────

def _top3_count(body: str):
    m = re.search(r"Decide on (\d+) products? waiting for an approval decision", body)
    return int(m.group(1)) if m else None


def _glance_count(body: str):
    m = re.search(r"(\d+) products? waiting on an approval decision\.", body)
    return int(m.group(1)) if m else None


def test_awaiting_decision_count_is_identical_in_top3_glance_and_card(client, make_token):
    # Default fixtures: the portal's own applications + extensions read finds
    # 3 waiting (a floor: it cannot see inventory-only products), the
    # platform's Software awaiting approval card says 9. Before PAT-2254 the
    # page showed both. One value now: the platform's complete figure.
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    body = _get(client, make_token()).text
    card_value = OVERVIEW_CARDS["cards"]["software_awaiting_approval"]["values"]["products"]
    assert card_value == 9
    assert _top3_count(body) == card_value
    assert _glance_count(body) == card_value
    assert int(_headline(_card_block(body, "software_awaiting_approval"))) == card_value


def test_awaiting_decision_count_follows_the_card_for_a_live_shaped_gap(client, make_token):
    # The live defect: 128 in Top 3, 140 on the card.
    cards = _cards()
    cards["cards"]["software_awaiting_approval"]["values"] = {"products": 140, "devices": 60}
    STUB_STATE["overview_cards_data"] = cards
    body = _get(client, make_token()).text
    assert _top3_count(body) == 140
    assert _glance_count(body) == 140
    assert int(_headline(_card_block(body, "software_awaiting_approval"))) == 140


def _awaiting_card(state, products, reason=None):
    card = copy.deepcopy(OVERVIEW_CARDS["cards"]["software_awaiting_approval"])
    card["state"] = state
    card["completeness"] = {"complete": state in ("value", "zero"), "reason": reason}
    card["values"] = {"products": products, "devices": 3}
    return _cards(software_awaiting_approval=card)


def test_partial_awaiting_decision_figure_is_shared_as_a_floor(client, make_token):
    STUB_STATE["overview_cards_data"] = _awaiting_card("partial", 5, "truncated")
    body = _get(client, make_token()).text
    assert int(_headline(_card_block(body, "software_awaiting_approval"))) == 5
    assert _top3_count(body) == 5
    assert _glance_count(body) == 5


def test_partial_zero_never_claims_that_nothing_is_waiting(client, make_token):
    # A partial card at zero is an incomplete read, not a clean one: the
    # glance line is dropped and Top 3 says it may be incomplete.
    STUB_STATE["overview_cards_data"] = _awaiting_card("partial", 0, "truncated")
    body = _get(client, make_token()).text
    assert "No products are waiting on an approval decision." not in body
    assert _top3_count(body) is None
    assert _glance_count(body) is None


def test_awaiting_decision_zero_is_zero_everywhere(client, make_token):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_ZERO
    body = _get(client, make_token()).text
    assert _headline(_card_block(body, "software_awaiting_approval")) == "0"
    assert _top3_count(body) is None  # no action invented from a zero
    assert "No products are waiting on an approval decision." in body


def test_awaiting_decision_falls_back_to_one_shared_floor_when_the_card_has_no_number(
    client, make_token,
):
    # The card is unavailable (a state word, never a digit), so Top 3 and the
    # glance line read the portal's own count, and still agree with each
    # other.
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_MIXED
    body = _get(client, make_token()).text
    block = _card_block(body, "software_awaiting_approval")
    assert not re.search(r"\d", _headline(block))
    assert _top3_count(body) is not None
    assert _top3_count(body) == _glance_count(body)


def test_awaiting_decision_falls_back_when_the_cards_read_is_down(client, make_token):
    STUB_STATE["mode"] = "cards500"
    body = _get(client, make_token()).text
    assert "Estate summary is temporarily unavailable" in body
    assert _top3_count(body) is not None
    assert _top3_count(body) == _glance_count(body)


# ── 3. Reporting and agent health ─────────────────────────────────────────

def _agent_health_cards(degraded, state="value"):
    card = copy.deepcopy(OVERVIEW_CARDS["cards"]["agent_health"])
    card["state"] = state
    card["completeness"] = {"complete": state in ("value", "zero"), "reason": None}
    card["values"] = {
        "devices_degraded": degraded, "devices_reporting": 4, "devices_not_reporting": 0,
        "oldest_successful_ingest": "2026-12-15T09:00:00Z",
    }
    return _cards(agent_health=card)


def test_agent_health_headline_says_what_it_counts_and_matches_the_coverage_line(
    client, make_token,
):
    _overview(devices_degraded=3)
    STUB_STATE["overview_cards_data"] = _agent_health_cards(3)
    body = _get(client, make_token()).text
    block = _card_block(body, "agent_health")
    assert _headline(block) == "3"
    unit = re.search(r'<span class="ov-card__unit">([^<]*)</span>', block)
    assert unit, "the headline figure needs a label saying what it counts"
    assert unit.group(1).strip() == "with collection issues"
    assert "4 reporting" in block
    # The coverage panel's own line, from the overview read model.
    line = re.search(
        r'<span class="pill pill-warn">(\d+)</span> devices? reporting a collection issue', body)
    assert line, "coverage panel collection-issue line missing"
    assert int(line.group(1)) == int(_headline(block)) == 3


def test_agent_health_headline_label_is_singular_for_one(client, make_token):
    _overview(devices_degraded=1)
    STUB_STATE["overview_cards_data"] = _agent_health_cards(1)
    block = _card_block(_get(client, make_token()).text, "agent_health")
    assert _headline(block) == "1"
    assert '<span class="ov-card__unit">with a collection issue</span>' in block


def test_agent_health_zero_degraded_still_says_what_it_counts(client, make_token):
    _overview(devices_degraded=0)
    STUB_STATE["overview_cards_data"] = _agent_health_cards(0)
    block = _card_block(_get(client, make_token()).text, "agent_health")
    assert _headline(block) == "0"
    assert '<span class="ov-card__unit">with collection issues</span>' in block


def test_agent_health_without_a_figure_carries_no_label(client, make_token):
    # unknown / unavailable cards show a state word, never a number, so a
    # unit beside it would label nothing.
    for fixture in (OVERVIEW_CARDS_ZERO, OVERVIEW_CARDS_MIXED):
        STUB_STATE["overview_cards_data"] = fixture
        block = _card_block(_get(client, make_token()).text, "agent_health")
        assert "ov-card__unit" not in block


def test_only_agent_health_has_a_headline_label(client, make_token):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    body = _get(client, make_token()).text
    assert body.count('class="ov-card__unit"') == 1


# ── 4. No approval controls on the Overview ───────────────────────────────

def _software_overview(n=3):
    products = [
        _product("CriticalTool", "critical"),
        _product("HighTool", "high"),
        _product("UnratedTool", "not_assessed"),
    ][:n]
    _overview(new_software=_new_software(
        total=len(products),
        counts={"critical": 1, "high": 1, "not_assessed": 1, "medium": 0, "low": 0},
        products=products,
    ))


def test_overview_renders_no_approval_controls_for_an_admin(client, make_token):
    STUB_STATE["portal_role"] = "admin"
    _software_overview()
    body = _get(client, make_token()).text
    assert "CriticalTool" in body  # the rows are still there, read only
    for marker in (
        "approval-row-form", "data-approval-row", "Set state", 'action="/software/approvals"',
        'name="item"', "<th>Approval</th>", "approval__btn", 'name="state"',
        "administrator on your account can approve",
    ):
        assert marker not in body, marker
    assert ">Apply<" not in body


def test_overview_renders_no_approval_controls_for_a_viewer(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    _software_overview()
    body = _get(client, make_token()).text
    assert "CriticalTool" in body
    assert "approval-row-form" not in body and "Set state" not in body
    assert "<th>Approval</th>" not in body


def test_overview_makes_no_role_read(client, make_token):
    # The role read only existed to decide whether to draw the controls.
    STUB_STATE["portal_role"] = "admin"
    _software_overview()
    before = STUB_STATE["me_requests"]
    _get(client, make_token())
    assert STUB_STATE["me_requests"] == before


def test_overview_keeps_urgency_strip_and_top_rows_read_only(client, make_token):
    _software_overview()
    body = _get(client, make_token()).text
    card = _section(body, 'id="new-software-heading"', "</section>")
    for label in ("Critical", "High", "Not assessed", "Medium", "Low"):
        assert f">{label}<" in card
    for name in ("CriticalTool", "HighTool", "UnratedTool"):
        assert name in card
    assert "<form" not in card


# ── 5. Every software count and row links into a filtered /software ───────

ALLOWED_SOFTWARE_PARAMS = {"type", "approval", "search", "new_days", "urgency"}
URGENCY_VALUES = {"critical", "high", "not_assessed", "medium", "low"}


def _software_filter_links(body: str) -> list[str]:
    return [h for h in _hrefs(body) if h.startswith("/software?")]


def test_new_software_strip_counts_link_to_the_matching_filtered_view(client, make_token):
    _software_overview()
    body = _get(client, make_token()).text
    card = _section(body, 'id="new-software-heading"', "</section>")
    links = _hrefs(card)
    for level in ("critical", "high", "not_assessed", "medium", "low"):
        assert f"/software?new_days=14&urgency={level}" in links, level
    # Each strip item is a link wrapping its own label and figure.
    assert card.count('<a class="kpi__item"') == 5


def test_new_software_rows_and_foot_link_into_software(client, make_token):
    _software_overview()
    body = _get(client, make_token()).text
    card = _section(body, 'id="new-software-heading"', "</section>")
    links = _hrefs(card)
    for name in ("CriticalTool", "HighTool", "UnratedTool"):
        assert f"/software?search={name}" in links, name
    assert "/software?new_days=14" in links  # the "see all" link
    assert "View software governance" not in card


def test_top3_and_glance_awaiting_decision_links_are_filtered(client, make_token):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    body = _get(client, make_token()).text
    top3 = _section(body, "Top 3 actions", "Your estate at a glance")
    glance = _section(body, "Your estate at a glance", "What we can see")
    decide = re.search(
        r'<a href="([^"]+)">Decide on \d+ products? waiting for an approval decision</a>', top3)
    assert decide and html.unescape(decide.group(1)) == "/software?approval=waiting"
    view = re.search(r'waiting on an approval decision\. <a href="([^"]+)">', glance)
    assert view and html.unescape(view.group(1)) == "/software?approval=waiting"


def test_software_awaiting_approval_card_links_to_the_waiting_filter(client, make_token):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    block = _card_block(_get(client, make_token()).text, "software_awaiting_approval")
    assert 'href="/software?approval=waiting"' in block


def test_risk_cards_decision_links_land_on_the_filtered_view(client, make_token):
    _software_overview()
    body = _get(client, make_token()).text
    high_risk = _section(body, 'id="high-risk-heading"', 'id="extension-risk-heading"')
    assert 'href="/software?approval=waiting"' in high_risk
    assert "Review software waiting on a decision" in high_risk
    extensions = _section(body, 'id="extension-risk-heading"', 'id="new-software-heading"')
    assert 'href="/software?type=extension&amp;approval=waiting"' in extensions
    assert re.search(r"Decide on \d+|Review \d+ decisions?", extensions)


def test_high_risk_card_counts_and_rows_link_into_software(client, make_token):
    products = [_product(f"Risky{i}", "critical") for i in range(5)]
    _overview(new_software=_new_software(
        total=5, counts={"critical": 5, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        products=products,
    ))
    body = _get(client, make_token()).text
    card = _section(body, 'id="high-risk-heading"', 'id="extension-risk-heading"')
    links = _hrefs(card)
    # The "more" action no longer scrolls to the Overview's own table: it
    # opens the same items filtered in /software.
    assert "/software?new_days=14&urgency=critical,high" in links
    assert "#new-software-heading" not in links
    assert "/software?search=Risky0" in links
    assert "/software?new_days=14&urgency=critical" in links  # the Critical pill


def test_extension_rows_link_into_software(client, make_token):
    body = _get(client, make_token()).text
    card = _section(body, 'id="extension-risk-heading"', 'id="new-software-heading"')
    rows = re.findall(r'<li class="risk-list__row">.*?</li>', card, re.DOTALL)
    assert rows, "fixture has no elevated extension rows"
    for row in rows:
        assert 'href="/software?type=extension&amp;search=' in row


def test_high_risk_ov_card_links_to_the_high_and_critical_window(client, make_token):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    block = _card_block(_get(client, make_token()).text, "high_risk_software")
    assert 'href="/software?new_days=14&amp;urgency=critical,high"' in block


def test_every_overview_software_filter_link_uses_only_known_params(client, make_token):
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    _software_overview()
    body = _get(client, make_token()).text
    links = _software_filter_links(body)
    assert links, "expected filtered /software links on the Overview"
    for link in links:
        query = parse_qs(urlsplit(link).query, keep_blank_values=True)
        assert set(query) <= ALLOWED_SOFTWARE_PARAMS, link
        for value in query.get("approval", []):
            assert set(value.split(",")) <= set(main.SOFTWARE_APPROVAL_FILTER_KEYS), link
        for value in query.get("urgency", []):
            assert set(value.split(",")) <= URGENCY_VALUES, link
        for value in query.get("type", []):
            assert value in ("application", "extension"), link
        for value in query.get("new_days", []):
            assert value.isdigit() and int(value) > 0, link


def test_no_overview_link_is_empty_whatever_the_new_software_read_says(client, make_token):
    # A count that has nothing to open (a clean read, or none at all) renders
    # as plain text; it must never become a link to href="" (the same page).
    empty = _new_software(window_days=14, total=0, products=[])
    for new_software in (None, empty, "malformed"):
        _overview(new_software=new_software)
        body = _without_code(_get(client, make_token()).text)
        assert 'href=""' not in body
        assert 'href="None"' not in body
    _software_overview()
    body = _without_code(_get(client, make_token()).text)
    assert 'href=""' not in body


def test_software_filter_url_helper():
    url = main._software_filter_url
    assert url() == "/software"
    assert url(approval="waiting") == "/software?approval=waiting"
    assert url(type_="extension", approval="waiting") == (
        "/software?type=extension&approval=waiting")
    assert url(new_days=14, urgency="critical,high") == (
        "/software?new_days=14&urgency=critical,high")
    assert url(search="Link Me & Co") == "/software?search=Link%20Me%20%26%20Co"
    # An unrecognised urgency or a non-positive window is dropped, never
    # reflected into a link.
    assert url(urgency="bogus") == "/software"
    assert url(new_days=0) == "/software"
    assert url(new_days=True) == "/software"


# ── Dead code the removed controls used ───────────────────────────────────

def test_the_overview_is_no_longer_an_approval_return_path():
    # Only the Overview's New software form posted return_to="/". With it
    # gone, a stale form posting it falls back to /software like any other
    # unlisted path.
    assert main._approval_return_to("/") == "/software"
    assert main._approval_return_to("/software?approval=waiting") == (
        "/software?approval=waiting")
