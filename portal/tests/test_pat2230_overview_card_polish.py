"""PAT-2230: Overview card polish, four defects found on production with
real data (2026-09-28):

1. CIS posture headline rendered the raw platform float
   (37.09677419354838...) unrounded - overflowed the card and caused a
   whole-page horizontal scrollbar at 1162px in both themes. Fixed: one
   decimal place, rounded half-up (never banker's rounding), trailing
   ".0" trimmed.
2. Every `value`/`zero` card painted a green left accent purely because
   the card's *state* was complete, regardless of what the figures
   actually said - "146 vulnerabilities", "14 elevated extensions" and
   "96 awaiting approval" all read as healthy. Fixed: a content `tone`
   (`ov-card--tone-bad|warn|ok|neutral`) derived from the card's own
   values, independent of `state`. `ok` (green) is reserved for the six
   risk cards, and only when their own relevant count is genuinely zero
   in a complete state.
3. `os_updates` in the `partial` state showed a headline of "0" (the
   pending-count floor), reading as "nothing behind" when the real
   picture was incomplete. Fixed: the headline becomes the state word
   "Partial" and the support line carries the known figures plus the
   reason, for `os_updates` only.
4. Vertical rhythm: label/headline/support/freshness now align across a
   row (freshness pinned to the card bottom, support clamped to 2 lines).

Written before main.py/portal.css/overview.html are touched for this
ticket, so every test here is expected to fail red - most on an overflow
in the raw CIS headline, an unconditional `ov-card--tone-ok` (a class
that doesn't exist yet, so its absence assertions are the ones expected
to flip), or a bare "0" in the os_updates partial headline.
"""

import copy
import re

import main
from tests.conftest import OVERVIEW_CARDS, OVERVIEW_CARDS_MIXED, OVERVIEW_CARDS_ZERO, STUB_STATE

CARD_ORDER = [
    "devices", "os_updates", "vulnerabilities", "cis_posture",
    "browser_extensions", "high_risk_software", "software_awaiting_approval",
    "exceptions_review", "agent_health", "recent_activity",
]

# A production-shaped fixture: the exact defect numbers from the ticket
# (146 vulnerabilities = 72 critical + 74 high, 14 elevated extensions, 96
# products awaiting approval), the long CIS float that caused the
# horizontal-scrollbar defect, and an os_updates card genuinely partial
# with a pending floor of 0 (the "reads as nothing behind" defect).
OVERVIEW_CARDS_PAT2230 = copy.deepcopy(OVERVIEW_CARDS)
OVERVIEW_CARDS_PAT2230["cards"]["cis_posture"]["values"]["score"] = 37.096774193548384
OVERVIEW_CARDS_PAT2230["cards"]["vulnerabilities"]["values"] = {"critical": 72, "high": 74}
OVERVIEW_CARDS_PAT2230["cards"]["browser_extensions"]["state"] = "value"
OVERVIEW_CARDS_PAT2230["cards"]["browser_extensions"]["completeness"]["complete"] = True
OVERVIEW_CARDS_PAT2230["cards"]["browser_extensions"]["values"] = {"elevated": 14, "total": 40}
OVERVIEW_CARDS_PAT2230["cards"]["software_awaiting_approval"]["values"] = {
    "products": 96, "devices": 40,
}
OVERVIEW_CARDS_PAT2230["cards"]["os_updates"]["reason"] = "version_evidence_pending"
OVERVIEW_CARDS_PAT2230["cards"]["os_updates"]["completeness"]["reason"] = "version_evidence_pending"
OVERVIEW_CARDS_PAT2230["cards"]["os_updates"]["values"] = {
    "up_to_date": 0, "pending": 0, "unknown": 12,
}


def _get(client, token, path="/"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _card_block(html: str, key: str) -> str:
    match = re.search(
        rf'<a[^>]*data-card="{re.escape(key)}"[^>]*>.*?</a>', html, re.DOTALL,
    )
    if not match:
        match = re.search(
            rf'<div[^>]*data-card="{re.escape(key)}"[^>]*>.*?</div>', html, re.DOTALL,
        )
    assert match, f'no data-card="{key}" element found in rendered page'
    return match.group(0)


def _card_classes(block: str) -> list[str]:
    match = re.search(r'class="([^"]*)"', block)
    assert match, "card element carries no class"
    return match.group(1).split()


def _headline_text(block: str) -> str:
    match = re.search(r'<span class="ov-card__headline">([^<]*)</span>', block)
    assert match, "card has no headline span"
    return match.group(1).strip()


# ── 1. CIS score rounding ──────────────────────────────────────────────────
def test_cis_headline_rounds_long_float_to_one_decimal_half_up():
    assert main._format_cis_score(37.096774193548384) == "37.1"


def test_cis_headline_trims_trailing_zero():
    assert main._format_cis_score(84.0) == "84"


def test_cis_headline_rendered_on_the_live_page(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    resp = _get(client, token)
    block = _card_block(resp.text, "cis_posture")
    assert _headline_text(block) == "37.1"
    assert "37.09677419354838" not in block


# ── 2. Tone: state alone must never paint green ────────────────────────────
def test_vulnerabilities_with_146_gets_tone_bad_never_tone_ok(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    resp = _get(client, token)
    block = _card_block(resp.text, "vulnerabilities")
    classes = _card_classes(block)
    assert "ov-card--tone-bad" in classes
    assert "ov-card--tone-ok" not in classes


def test_zero_state_vulnerabilities_gets_tone_ok(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_ZERO
    resp = _get(client, token)
    block = _card_block(resp.text, "vulnerabilities")
    assert "ov-card--tone-ok" in _card_classes(block)


def test_extensions_with_14_elevated_gets_tone_warn(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    resp = _get(client, token)
    block = _card_block(resp.text, "browser_extensions")
    classes = _card_classes(block)
    assert "ov-card--tone-warn" in classes
    assert "ov-card--tone-ok" not in classes


def test_awaiting_approval_with_96_gets_tone_warn(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    resp = _get(client, token)
    block = _card_block(resp.text, "software_awaiting_approval")
    classes = _card_classes(block)
    assert "ov-card--tone-warn" in classes
    assert "ov-card--tone-ok" not in classes


def test_cis_posture_is_always_tone_neutral(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    fixtures = (OVERVIEW_CARDS, OVERVIEW_CARDS_ZERO, OVERVIEW_CARDS_MIXED, OVERVIEW_CARDS_PAT2230)
    for fixture in fixtures:
        STUB_STATE["overview_cards_data"] = fixture
        resp = _get(client, token)
        block = _card_block(resp.text, "cis_posture")
        classes = _card_classes(block)
        assert "ov-card--tone-neutral" in classes, fixture["cards"]["cis_posture"]["state"]
        assert "ov-card--tone-ok" not in classes
        assert "ov-card--tone-bad" not in classes
        assert "ov-card--tone-warn" not in classes


def test_exceptions_overdue_gets_tone_bad_over_due_soon(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    fixture = copy.deepcopy(OVERVIEW_CARDS_PAT2230)
    fixture["cards"]["exceptions_review"]["state"] = "value"
    fixture["cards"]["exceptions_review"]["completeness"]["complete"] = True
    fixture["cards"]["exceptions_review"]["values"] = {
        "review_overdue": 3, "review_due_soon": 2, "no_review_date": 0,
        "unaccepted": 0, "total": 5,
    }
    STUB_STATE["overview_cards_data"] = fixture
    resp = _get(client, token)
    block = _card_block(resp.text, "exceptions_review")
    assert "ov-card--tone-bad" in _card_classes(block)


def test_agent_health_degraded_gets_tone_warn(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS  # agent_health devices_degraded=1
    resp = _get(client, token)
    block = _card_block(resp.text, "agent_health")
    assert "ov-card--tone-warn" in _card_classes(block)


def test_devices_silent_plus_unknown_gets_tone_warn_never_ok(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS  # devices silent=1, unknown=1
    resp = _get(client, token)
    block = _card_block(resp.text, "devices")
    classes = _card_classes(block)
    assert "ov-card--tone-warn" in classes
    assert "ov-card--tone-ok" not in classes, "devices is never in the ok-eligible set"


def test_unknown_and_unavailable_cards_stay_tone_neutral(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_MIXED
    resp = _get(client, token)
    for key, card in OVERVIEW_CARDS_MIXED["cards"].items():
        if card["state"] not in ("unknown", "unavailable"):
            continue
        block = _card_block(resp.text, key)
        assert "ov-card--tone-neutral" in _card_classes(block), key


# ── 3. os_updates partial headline ─────────────────────────────────────────
def test_partial_os_updates_headline_is_partial_word_not_a_bare_zero(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    resp = _get(client, token)
    block = _card_block(resp.text, "os_updates")
    assert _headline_text(block) == "Partial"
    headline_span = re.search(r'<span class="ov-card__headline">[^<]*</span>', block).group(0)
    assert not re.search(r">\s*0\s*<", headline_span), "headline must not be a bare 0"


def test_partial_os_updates_support_carries_the_known_figure_and_reason(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS_PAT2230
    resp = _get(client, token)
    block = _card_block(resp.text, "os_updates")
    support = re.search(r'<span class="ov-card__support"[^>]*>([^<]*)</span>', block)
    assert support, "os_updates partial card must keep a support line"
    text = support.group(1)
    assert "0 pending" in text
    assert main.OVERVIEW_CARD_REASON_TEXT["version_evidence_pending"] in text


def test_other_partial_cards_headline_unchanged_by_this_special_case(client, make_token):
    """Only os_updates gets the "Partial" headline word - a different
    partial card still shows its own figure."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["overview_cards_data"] = OVERVIEW_CARDS  # agent_health is partial here
    resp = _get(client, token)
    block = _card_block(resp.text, "agent_health")
    assert _headline_text(block) != "Partial"


# ── No card ever shows ok while its own risk count is > 0 ─────────────────
_RISK_FIELD = {
    "vulnerabilities": lambda v: v.get("critical", 0) + v.get("high", 0),
    "browser_extensions": lambda v: v.get("elevated", 0),
    "high_risk_software": lambda v: v.get("critical", 0) + v.get("high", 0),
    "software_awaiting_approval": lambda v: v.get("products", 0),
    "exceptions_review": lambda v: v.get("review_overdue", 0) + v.get("review_due_soon", 0),
    "agent_health": lambda v: v.get("devices_degraded", 0),
}


def test_no_card_ever_shows_tone_ok_while_its_risk_count_is_positive(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    fixtures = [OVERVIEW_CARDS, OVERVIEW_CARDS_ZERO, OVERVIEW_CARDS_MIXED, OVERVIEW_CARDS_PAT2230]
    for fixture in fixtures:
        STUB_STATE["overview_cards_data"] = fixture
        resp = _get(client, token)
        for key, get_count in _RISK_FIELD.items():
            card = fixture["cards"][key]
            values = card.get("values")
            if not values:
                continue
            count = get_count(values)
            if count <= 0:
                continue
            block = _card_block(resp.text, key)
            assert "ov-card--tone-ok" not in _card_classes(block), (
                f"{key} shows tone-ok with a positive risk count ({count})"
            )
