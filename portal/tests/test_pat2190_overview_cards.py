"""PAT-2190: the Overview information cards, backed by the platform's
GET /v1/portal/overview/cards (PAT-2207; contracts/portal-api.md
"overview/cards"). These tests are written against main.py/overview.html
before either has been touched for this ticket, so every one of them is
expected to fail red right now - most on a missing `data-card` marker, not
on an exception, because /v1/portal/overview/cards is never called yet.

This file also pins the design the implementation (stage 2) must match, so
there is one place stage 1 and stage 2 agree rather than each guessing:

Card -> filtered route (never a route that doesn't exist, per AGENTS.md's
Routes list, and never a fake query parameter - the orchestrator review verified each
one against the actual consuming code, not assumed):
    devices                      -> /devices
    os_updates                   -> /devices (no update-specific filtered
                                     view exists; the roster's own Updates
                                     column is the closest real view)
    vulnerabilities               -> /findings#cve-findings (real anchor id
                                      in templates/findings.html)
    cis_posture                   -> /findings#cis-compliance-findings (ditto)
    browser_extensions            -> /software?type=extension (main.py's
                                      software() reads `type`, seeds the Type
                                      select's initial value)
    high_risk_software            -> /software
    software_awaiting_approval    -> /software?approval=waiting
                                      (main.py's _software_approval_filter
                                      reads `approval`, seeding the Approval
                                      dropdown's data-initial, which
                                      static/js/portal.js's initApprovals
                                      applies as the active row filter on
                                      load - verified empirically, not just
                                      by reading the source)
    exceptions_review             -> /exceptions
    agent_health                  -> /devices?view=not_reporting_24h (routes
                                      to templates/devices_reporting_gap.html)
    recent_activity                -> no link at all. The contract makes this
                                      card permanently unavailable
                                      (not_yet_supported) until PAT-2197, and
                                      /whats-new is the product changelog,
                                      not estate activity, so there is no
                                      real destination to send a customer to.
                                      Rendered as a plain, non-interactive,
                                      non-focusable block instead of a link -
                                      see test_recent_activity_card_is_non_
                                      interactive below.

Placement (orchestrator ruling, superseding the earlier Andy-review
placement): PAT-2160's shipped 1280x800 fold guarantee for Top 3 actions and
Needs attention holds, so the cards render AFTER Needs attention and before
the first detailed chart or evidence section (here, the High-risk software/
Browser extensions row) - order is welcome/Top-3 -> coverage-hero -> Needs
attention -> cards -> everything else.

Markup contract the templates must satisfy:
  - A wrapping `<section class="overview-cards" ...>` renders after the
    welcome block and before every other section (see placement above).
  - Each of the nine interactive cards is exactly one `<a data-card="{key}"
    class="ov-card ov-card--{state}" href="{link}">` - one link, one
    accessible name, per PAT-2190's keyboard/screen-reader acceptance
    criterion. recent_activity is a `<div>`, not an `<a>` - no href, not
    focusable, still readable in normal document order. The class carries
    the exact contract `state` value, so a test (or a future widget,
    PAT-2189) can always tell which of the five states rendered without
    parsing prose.
  - Each card has one headline (a single figure, or for unknown/unavailable
    a short neutral state word - never a multi-clause sentence and never a
    digit for those two states) and at most one supporting line (a short
    stat breakdown when complete, the plain-English reason otherwise).
  - `value`/`zero` cards may show a number; `unknown`/`unavailable`/
    `partial` never show a bare number standing in for a real count, and
    never carry `ov-card--value` or `ov-card--zero` (root AGENTS.md -
    absence requires authority - and PAT-2190's own "never infer a healthy
    state from missing data").
  - A `partial`/`unknown`/`unavailable` card's reason is rendered as one of
    OVERVIEW_CARD_REASON_TEXT's plain-English sentences below, never the
    raw snake_case code from the wire contract.
  - When the whole /v1/portal/overview/cards call fails (5xx, 404, timeout),
    no `data-card` marker renders at all - the existing Overview content
    renders exactly as before, plus one `overview-cards__unavailable`
    message, never a stack of zeros standing in for cards that could not be
    read.
"""

import copy
import re

import main
from tests.conftest import (
    OVERVIEW_CARDS,
    OVERVIEW_CARDS_MIXED,
    OVERVIEW_CARDS_ZERO,
    STUB_STATE,
)

CARD_ORDER = [
    "devices", "os_updates", "vulnerabilities", "cis_posture",
    "browser_extensions", "high_risk_software", "software_awaiting_approval",
    "exceptions_review", "agent_health", "recent_activity",
]

CARD_LABELS = {
    "devices": "Devices",
    "os_updates": "OS update status",
    "vulnerabilities": "Vulnerabilities",
    "cis_posture": "CIS posture",
    "browser_extensions": "Browser extensions",
    "high_risk_software": "High-risk software",
    "software_awaiting_approval": "Software awaiting approval",
    "exceptions_review": "Exceptions nearing review",
    "agent_health": "Reporting and agent health",
    "recent_activity": "Recent activity",
}

CARD_LINKS = {
    "devices": "/devices",
    "os_updates": "/devices",
    "vulnerabilities": "/findings#cve-findings",
    "cis_posture": "/findings#cis-compliance-findings",
    "browser_extensions": "/software?type=extension",
    # PAT-2254: the card's own window (14 days in every fixture), critical
    # and high. new_days and urgency are the two names PAT-2255 makes
    # /software honour; type and approval are consumed today (below).
    "high_risk_software": "/software?new_days=14&urgency=critical,high",
    "software_awaiting_approval": "/software?approval=waiting",
    "exceptions_review": "/exceptions",
    "agent_health": "/devices?view=not_reporting_24h",
    # recent_activity deliberately absent: Orchestrator review correction - the
    # platform marks this card permanently unavailable, and /whats-new (the
    # product changelog) is not estate activity, so there is no real
    # destination. It renders as a non-interactive, non-focusable block
    # instead (test_recent_activity_card_is_non_interactive below).
}

# Plain-English text that must stand in for each bounded reason code -
# copied verbatim from PAT-2190's own worked example ("estate_too_large
# becomes 'Your estate is too large to assess here'"). The raw code must
# never appear in the rendered page.
OVERVIEW_CARD_REASON_TEXT = {
    "query_failed": "could not be read right now",
    "source_not_migrated": "not available for your estate yet",
    "not_yet_supported": "not supported yet",
    "not_modelled": "not tracked yet",
    "no_update_evidence": "no update evidence has been collected yet",
    "version_evidence_pending": "partial version evidence",
    "no_completed_match_run": "vulnerability check has not completed yet",
    "no_evaluations": "no compliance checks have been recorded yet",
    "estate_too_large": "Your estate is too large to assess here",
    "truncated": "the real number may be higher",
    "coverage_incomplete": "coverage of your estate is incomplete",
    "devices_not_reporting": "some devices have not reported",
    "no_devices": "no devices are currently known",
}

# Every code the implementation knows, not just this file's copy, so a new
# reason code in main.py is still checked for raw-code leakage.
RAW_REASON_CODES = sorted(set(OVERVIEW_CARD_REASON_TEXT) | set(main.OVERVIEW_CARD_REASON_TEXT))


def _get(client, token, path="/"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _card_block(html: str, key: str) -> str:
    """The one element carrying data-card="{key}", so assertions can be
    scoped to a single card instead of the whole page. Nine cards are one
    <a>...</a>; recent_activity is a plain <div>...</div> (the orchestrator review
    correction: it has no real destination, so it is non-interactive and
    non-focusable rather than a link that goes nowhere useful) - tried as
    an anchor first, falling back to a div."""
    match = re.search(
        rf'<a[^>]*data-card="{re.escape(key)}"[^>]*>.*?</a>', html, re.DOTALL,
    )
    if not match:
        match = re.search(
            rf'<div[^>]*data-card="{re.escape(key)}"[^>]*>.*?</div>', html, re.DOTALL,
        )
    assert match, f"no data-card=\"{key}\" element found in rendered page"
    return match.group(0)


def _card_href(block: str) -> str:
    match = re.search(r'href="([^"]*)"', block)
    assert match, "card element carries no href"
    return match.group(1).replace("&amp;", "&")


def _card_classes(block: str) -> list[str]:
    match = re.search(r'class="([^"]*)"', block)
    assert match, "card element carries no class"
    return match.group(1).split()


def _overview_cards_region(html: str) -> str:
    match = re.search(
        r'<section[^>]*class="overview-cards[^"]*"[^>]*>.*?</section>', html, re.DOTALL,
    )
    assert match, "no <section class=\"overview-cards\"> region found"
    return match.group(0)


# ── Populated fixture: all ten cards, correct links, above existing content ─
def test_all_ten_cards_render_with_data_card_markers(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    assert resp.status_code == 200
    for key in CARD_ORDER:
        _card_block(resp.text, key)


def test_each_card_links_to_its_named_filtered_route(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    for key, expected_href in CARD_LINKS.items():
        block = _card_block(resp.text, key)
        assert _card_href(block) == expected_href, key


def test_card_links_resolve_to_real_pages(client, make_token):
    """Never link to a route that doesn't exist (PAT-2190 acceptance)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    assert resp.status_code == 200
    for href in set(CARD_LINKS.values()):
        target = href.split("#", 1)[0]
        r = _get(client, token, target)
        assert r.status_code < 400, f"{href} -> {r.status_code}"


def test_overview_cards_section_renders_after_needs_attention_before_detail(client, make_token):
    """Placement (orchestrator ruling): PAT-2160's shipped 1280x800 fold
    guarantee for Top 3 actions and Needs attention holds, so the cards
    never sit between the welcome block and Needs attention - they render
    after Needs attention and before the first detailed chart or evidence
    section (here, the High-risk software/Browser extensions row)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    cards_pos = resp.text.find('class="overview-cards"')
    assert cards_pos != -1, "overview-cards section missing"
    welcome_pos = resp.text.find("Top 3 actions")
    coverage_pos = resp.text.find("What we can see of your estate")
    attention_pos = resp.text.find("Needs attention")
    detail_pos = resp.text.find("High-risk software")
    assert welcome_pos != -1 and coverage_pos != -1 and attention_pos != -1 and detail_pos != -1
    assert welcome_pos < coverage_pos < attention_pos, "PAT-2160 order must be unchanged"
    assert attention_pos < cards_pos, "cards must render after Needs attention"
    assert cards_pos < detail_pos, (
        "cards must render before the first detailed chart/evidence section"
    )


def test_value_card_shows_its_figures(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    devices_block = _card_block(resp.text, "devices")
    assert "ov-card--value" in _card_classes(devices_block)
    for n in ("6", "2", "1"):
        assert n in devices_block
    vuln_block = _card_block(resp.text, "vulnerabilities")
    assert "2" in vuln_block and "5" in vuln_block


# ── Zero state: an honest, real "0" - never rendered as a silent healthy ───
# ── absence, never confused with unknown/unavailable ───────────────────────
def test_zero_cards_carry_zero_class_and_a_real_zero_headline(client, make_token):
    """Correction to stage 1 (the orchestrator's card-hierarchy review): the original
    version of this test required the literal word "checked" somewhere on
    the card. The approved hierarchy is one headline figure plus at most one
    short supporting line, with no room for that extra state word without
    it becoming second prose in the headline slot - which the orchestrator review
    explicitly ruled out. Zero's real distinguishing signal under the new
    hierarchy is that the headline is a genuine "0" (the same contract-zero
    figure the platform sent), never blank and never a neutral state word -
    that is what a customer actually sees, and unknown/unavailable can never
    produce a digit here (see the two tests below), so a real "0" cannot be
    mistaken for either of them."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_ZERO
    resp = _get(client, token)
    for key in ("devices", "vulnerabilities", "browser_extensions",
                "high_risk_software", "software_awaiting_approval", "exceptions_review"):
        block = _card_block(resp.text, key)
        assert "ov-card--zero" in _card_classes(block), key
        headline = re.search(r'<span class="ov-card__headline">([^<]*)</span>', block)
        assert headline, f"{key} zero card has no headline span"
        assert headline.group(1).strip() == "0", f"{key} zero card headline must be a real 0"


def test_unavailable_cards_never_render_a_number_or_healthy_tone(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_ZERO
    resp = _get(client, token)
    for key in ("os_updates", "recent_activity"):
        block = _card_block(resp.text, key)
        classes = _card_classes(block)
        assert "ov-card--unavailable" in classes, key
        assert "ov-card--value" not in classes and "ov-card--zero" not in classes, key
        assert "ok-text" not in block and "pill-ok" not in block, key
        assert "not available" in block.lower() or "not currently available" in block.lower()


def test_unknown_cards_never_render_a_number_or_healthy_tone(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_ZERO
    resp = _get(client, token)
    for key in ("cis_posture", "agent_health"):
        block = _card_block(resp.text, key)
        classes = _card_classes(block)
        assert "ov-card--unknown" in classes, key
        assert "ov-card--value" not in classes and "ov-card--zero" not in classes, key
        assert "ok-text" not in block and "pill-ok" not in block, key
        assert "not known" in block.lower() or "not yet known" in block.lower()


# ── Mixed unknown/unavailable/partial spread ───────────────────────────────
def test_mixed_fixture_every_card_class_matches_its_contract_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_MIXED
    resp = _get(client, token)
    for key, card in OVERVIEW_CARDS_MIXED["cards"].items():
        block = _card_block(resp.text, key)
        assert f"ov-card--{card['state']}" in _card_classes(block), key


def test_partial_card_states_its_reason_in_plain_english(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_MIXED
    resp = _get(client, token)
    block = _card_block(resp.text, "browser_extensions")  # partial / truncated
    assert OVERVIEW_CARD_REASON_TEXT["truncated"] in block
    assert "truncated" not in block  # raw code must never render
    # A partial card's real floor figure still shows, it just says so.
    assert "3" in block


def test_unavailable_card_uses_the_tickets_own_worked_reason_example(client, make_token):
    """PAT-2190's own copy example: estate_too_large -> 'Your estate is too
    large to assess here'."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_MIXED
    resp = _get(client, token)
    block = _card_block(resp.text, "software_awaiting_approval")
    assert "Your estate is too large to assess here" in block
    assert "estate_too_large" not in block


def test_no_raw_reason_code_ever_rendered(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_MIXED
    resp = _get(client, token)
    region = _overview_cards_region(resp.text)
    for code in RAW_REASON_CODES:
        assert code not in region, f"raw reason code {code!r} leaked into rendered cards"


def test_no_not_licensed_state_invented(client, make_token):
    """The contract has exactly five states; the portal must not invent a
    sixth "not licensed" state (PAT-2190 explicit instruction)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for fixture in (OVERVIEW_CARDS, OVERVIEW_CARDS_ZERO, OVERVIEW_CARDS_MIXED):
        STUB_STATE["overview_cards_data"] = fixture
        resp = _get(client, token)
        assert "not licensed" not in resp.text.lower()
        assert "coming soon" not in resp.text.lower()


# ── Tenant isolation: JWT forwarded verbatim, no tenant identifier sent ────
def test_cards_endpoint_called_with_forwarded_jwt_and_no_tenant_param(client, make_token):
    token = make_token(email="isolation-check@tenant-a.example")
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    assert resp.status_code == 200
    requests_seen = STUB_STATE["overview_cards_requests"]
    assert len(requests_seen) == 1, (
        "expected exactly one call to /v1/portal/overview/cards per page load"
    )
    call = requests_seen[0]
    assert call["jwt"] == token
    assert call["query"] == {}, "no tenant or other identifier may ride the query string"


# ── Failure isolation: the endpoint failing must not take the page down ───
def _assert_overview_still_renders_with_one_unavailable_state(resp):
    assert resp.status_code == 200
    assert "Needs attention" in resp.text  # existing overview content intact
    assert "Top 3 actions" in resp.text
    assert 'data-card="devices"' not in resp.text, (
        "a failed cards read must render no cards at all, never a stack of zeros"
    )
    region = _overview_cards_region(resp.text)
    assert "overview-cards__unavailable" in region
    assert "unavailable" in region.lower()
    assert "PAT-" not in region
    assert "coming soon" not in region.lower()


def test_cards_upstream_500_degrades_to_one_summary_unavailable_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "cards500"
    resp = _get(client, token)
    _assert_overview_still_renders_with_one_unavailable_state(resp)


def test_card_value_outside_contract_degrades_not_500(client, make_token):
    """A null count (outside the contract) must degrade the summary to the
    one honest unavailable state, never 500 the whole Overview."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    bad = copy.deepcopy(OVERVIEW_CARDS)
    bad["cards"]["vulnerabilities"]["state"] = "value"
    bad["cards"]["vulnerabilities"]["values"] = {"critical": None, "high": 5}
    STUB_STATE["overview_cards_data"] = bad
    resp = _get(client, token)
    _assert_overview_still_renders_with_one_unavailable_state(resp)


def test_cards_upstream_404_degrades_to_one_summary_unavailable_state(client, make_token):
    """404 because the platform isn't deployed yet (PAT-2190's own example)
    must degrade exactly like a 500, not surface a generic error page."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "cards404"
    resp = _get(client, token)
    _assert_overview_still_renders_with_one_unavailable_state(resp)


def test_cards_upstream_timeout_degrades_to_one_summary_unavailable_state(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "cards_timeout"
    resp = _get(client, token)
    _assert_overview_still_renders_with_one_unavailable_state(resp)


# ── recent_activity: non-interactive, since it has no real destination ────
def test_recent_activity_card_is_non_interactive(client, make_token):
    """Orchestrator review correction: recent_activity must NOT link to
    /whats-new (the product changelog, not estate activity), and the
    contract makes it permanently unavailable (not_yet_supported) until
    PAT-2197 - so it has nothing real to link to at all. It renders as a
    plain block: no <a>, no href, no tabindex, so it never enters the tab
    order, while its text stays in normal document order for a screen
    reader."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS
    resp = _get(client, token)
    block = _card_block(resp.text, "recent_activity")
    assert block.startswith("<div"), "recent_activity must not be a link"
    assert "href=" not in block
    assert "tabindex" not in block
    assert "/whats-new" not in block
    assert "recent activity" in block.lower()


# ── Every card link is a real, consumed filter, never a fake parameter ────
def test_every_card_link_is_consumed_by_its_target_route_or_anchor(client, make_token):
    """the orchestrator review: verify against the actual route/template, not assume.
    A query-string link is only accepted once the target page demonstrably
    reacts to it (the relevant control shows as selected/initialised); a
    fragment link is only accepted once the anchor id genuinely exists in
    the rendered target page. Either way this is checked against a live
    render, not a static grep, so a future refactor that quietly drops the
    param or renames the anchor fails this test."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS

    def render(path):
        r = _get(client, token, path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"
        return r.text

    # Fragment links: the anchor id must exist in the target page.
    findings_html = render("/findings")
    assert 'id="cve-findings"' in findings_html
    assert 'id="cis-compliance-findings"' in findings_html

    # Query-param links: the target page must show the param was applied.
    ext_html = render("/software?type=extension")
    assert 'data-row-filter="kind" data-query-param="type"' in ext_html
    assert 'value="extension" selected' in ext_html

    waiting_html = render("/software?approval=waiting")
    assert 'data-row-filter="decision"' in waiting_html
    assert 'data-initial="waiting"' in waiting_html
    assert 'name="approval" value="waiting"' in waiting_html and "checked" in waiting_html

    gap_html = render("/devices?view=not_reporting_24h")
    assert "Not reporting in 24 hours" in gap_html

    # No-param links: just real, working pages.
    for path in ("/devices", "/software", "/exceptions"):
        render(path)

    # recent_activity carries no link at all (see
    # test_recent_activity_card_is_non_interactive).
    assert set(CARD_LINKS) == set(CARD_ORDER) - {"recent_activity"}
