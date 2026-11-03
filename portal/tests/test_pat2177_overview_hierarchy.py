"""PAT-2177: the Overview shifts from onboarding CIS remediation to continuous
software and extension review.

Covers the hierarchy (evidence freshness first, then the ongoing-review
cards, then New software), the High-risk software card (built only from the
platform's PAT-2093 urgency and reasons, scoped to its window), the Browser
extensions card (platform risk_level and approval_state, with a missing
risk_level counted as not assessed rather than normal) and CIS compressing
to a compact posture card only when the evidence is current and nothing
critical or high is failing.

Reuses tests/conftest.py's OVERVIEW/STUB_STATE fixtures and the PAT-2093
test helpers rather than a second copy of the platform contract.
"""

import main
from tests.conftest import OVERVIEW, STUB_STATE
from tests.test_pat2093_new_software import _get, _new_software, _product


def _overview(**fields):
    STUB_STATE["overview_data"] = {**OVERVIEW, **fields}


# ── Hierarchy ─────────────────────────────────────────────────────────────

def test_freshness_comes_first_then_review_cards_then_new_software(client, make_token):
    _overview(new_software=_new_software(
        total=1, counts={"critical": 1, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        products=[_product("RiskyTool", "critical")],
    ))
    body = _get(client, make_token()).text
    order = [body.index(marker) for marker in (
        "What we can see of your estate",
        'id="attention-heading"',
        'id="high-risk-heading"',
        'id="extension-risk-heading"',
        'id="new-software-heading"',
    )]
    assert order == sorted(order)


# ── High-risk software ────────────────────────────────────────────────────

def test_high_risk_card_shows_compact_rows_devices_and_window(client, make_token):
    # PAT-2231: the preview row is one compact line - severity pill + name
    # on the left, a short muted "N devices (dot) first seen ..." meta line
    # on the right - never the old nested per-reason bullet list. Findings
    # detail (why it is rated critical/high) belongs on /software, not
    # repeated on the Overview.
    _overview(new_software=_new_software(
        window_days=14, total=2,
        counts={"critical": 1, "high": 1, "not_assessed": 2, "medium": 0, "low": 0},
        products=[
            _product("RiskyTool", "critical", device_count=12, first_seen_at="2026-09-23T08:00:00Z",
                      reasons=[{"code": "unsigned", "level": "critical", "detail": "Unsigned"}]),
            _product("OtherTool", "high", device_count=3),
        ],
    ))
    body = _get(client, make_token()).text
    card = body[body.index('id="high-risk-heading"'):body.index('id="extension-risk-heading"')]
    assert "Newly found in the last 14 days" in card
    assert ">2<" in card
    assert "on 15 devices" in card
    assert 'class="risk-list risk-list--compact"' in card
    assert "12 devices" in card and "first seen 23 Sep 2026" in card
    # The per-reason bullet detail stays off the Overview entirely.
    assert "Unsigned" not in card
    # Not assessed is surfaced, never folded into low risk.
    assert "2 not assessed" in card
    assert "not counted as low risk" in card


def test_high_risk_unavailable_is_never_a_clean_zero(client, make_token):
    _overview(new_software=None)
    body = _get(client, make_token()).text
    card = body[body.index('id="high-risk-heading"'):body.index('id="extension-risk-heading"')]
    assert "Software risk could not be read" in card
    assert "not a confirmed absence" in card
    assert "warrant investigation" not in card


def test_high_risk_view_counts_come_from_platform_counts_when_truncated():
    view = main._high_risk_software_view({
        "status": "data", "window_days": 7, "truncated": True,
        "counts": {"critical": 5, "high": 4, "not_assessed": 0},
        "products": [{"urgency": "critical", "device_count": 2, "name": "A"},
                     {"urgency": "medium", "device_count": 9, "name": "B"}],
    })
    assert view["count"] == 9
    assert view["devices"] == 2
    assert view["devices_is_floor"] is True
    assert view["more"] == 8


def test_high_risk_view_clear_when_nothing_critical_or_high():
    view = main._high_risk_software_view({
        "status": "data", "window_days": 7, "truncated": False,
        "counts": {"critical": 0, "high": 0, "not_assessed": 1},
        "products": [{"urgency": "not_assessed", "device_count": 1, "name": "A"}],
    })
    assert view["status"] == "clear"
    assert view["not_assessed"] == 1


def test_high_risk_view_caps_preview_at_top_n_even_with_more_risky_products():
    # PAT-2231: the card-markup redesign relies on this cap to keep the
    # preview list short and comparable in length to the extensions
    # preview - five risky products in, only OVERVIEW_RISK_TOP_N shown.
    products = [
        {"urgency": "critical", "device_count": 1, "name": f"Tool{i}"} for i in range(5)
    ]
    view = main._high_risk_software_view({
        "status": "data", "window_days": 7, "truncated": False,
        "counts": {"critical": 5, "high": 0, "not_assessed": 0},
        "products": products,
    })
    assert len(view["products"]) == main.OVERVIEW_RISK_TOP_N == 3
    assert view["more"] == 2


def test_high_risk_primary_action_folds_the_remainder_when_preview_is_capped():
    # PAT-2231 review: the old standalone "And N more in the newly found
    # list below" paragraph is folded into the one primary action instead
    # of sitting as a second line.
    products = [
        {"urgency": "critical", "device_count": 1, "name": f"Tool{i}"} for i in range(5)
    ]
    view = main._high_risk_software_view({
        "status": "data", "window_days": 7, "truncated": False,
        "counts": {"critical": 5, "high": 0, "not_assessed": 0},
        "products": products,
    })
    assert view["more"] == 2
    # PAT-2254: opens the same products in /software rather than scrolling
    # to the Overview's own (now read only) table.
    assert view["primary_action"] == {
        "text": "View 2 more high-risk products",
        "href": "/software?new_days=7&urgency=critical,high",
    }


def test_high_risk_primary_action_is_fixed_when_nothing_is_left_over():
    # Only when there is no overflow beyond the top-N preview does the
    # card fall back to the fixed action every other status also uses -
    # unlike Browser extensions', High-risk's fallback never varies with
    # the card's own count.
    unavailable = main._high_risk_software_view({"status": "unavailable"})
    clear = main._high_risk_software_view({"status": "empty"})
    data_within_top_n = main._high_risk_software_view({
        "status": "data", "window_days": 7, "truncated": False,
        "counts": {"critical": 1, "high": 0, "not_assessed": 0},
        "products": [{"urgency": "critical", "device_count": 1, "name": "A"}],
    })
    expected = {
        "text": "Review software waiting on a decision",
        "href": "/software?approval=waiting",
    }
    assert unavailable["primary_action"] == expected
    assert clear["primary_action"] == expected
    assert data_within_top_n["primary_action"] == expected


def test_high_risk_unavailable_view_carries_no_headline_figure():
    # PAT-2231: unknown stays unknown - an unavailable read must never
    # carry a count/devices field a template could render as a fabricated
    # "0 products warrant investigation".
    view = main._high_risk_software_view({"status": "unavailable"})
    assert "count" not in view
    assert "devices" not in view
    assert "counts" not in view


# ── Browser extensions ────────────────────────────────────────────────────

def test_extension_view_uses_platform_risk_level_and_keeps_unknown_distinct():
    view = main._extension_risk_view([
        {"name": "Wide", "risk_level": "elevated", "approval_state": "unreviewed",
         "device_count": 9, "browser": "chrome"},
        {"name": "Fine", "risk_level": "normal", "approval_state": "approved", "device_count": 40},
        {"name": "Mystery", "approval_state": "approved", "device_count": 2},
    ])
    assert view["status"] == "data"
    assert view["elevated"] == 1
    assert view["elevated_devices"] == 9
    assert view["waiting"] == 1
    assert view["unassessed"] == 1
    assert view["top"][0]["name"] == "Wide"
    assert view["top"][0]["decision"] == "Waiting on a decision"


def test_extension_view_unavailable_when_read_failed():
    assert main._extension_risk_view(None) == {"status": "unavailable"}


def test_extension_view_unavailable_carries_no_headline_figure():
    # PAT-2231: same "never a fabricated zero" contract as High-risk
    # software - an unavailable read carries no elevated/waiting/top
    # field a template could render as a clean count.
    view = main._extension_risk_view(None)
    assert "elevated" not in view
    assert "waiting" not in view
    assert "top" not in view
    assert "primary_action" not in view


def test_extension_view_caps_preview_at_top_n_and_reports_the_remainder():
    # PAT-2231: five elevated-risk extensions in, only the top N preview
    # (matching High-risk's own cap), with "more" naming the remainder -
    # folded into the "View all N extensions" primary action rather than
    # a second standalone line.
    rows = [
        {"name": f"Ext{i}", "risk_level": "elevated", "approval_state": "approved",
         "device_count": 1} for i in range(5)
    ]
    view = main._extension_risk_view(rows)
    assert len(view["top"]) == main.OVERVIEW_RISK_TOP_N == 3
    assert view["more"] == 2


def test_extension_primary_action_counts_waiting_decisions():
    rows = [
        {"name": "A", "risk_level": "elevated", "approval_state": "unreviewed", "device_count": 1},
        {"name": "B", "risk_level": "normal", "approval_state": "unreviewed", "device_count": 1},
        {"name": "C", "risk_level": "normal", "approval_state": "approved", "device_count": 1},
    ]
    view = main._extension_risk_view(rows)
    assert view["waiting"] == 2
    assert view["primary_action"] == {
        "text": "Review 2 decisions",
        "href": "/software?type=extension&approval=waiting",
    }


def test_extension_card_uses_compact_rows_not_a_stats_grid(client, make_token):
    # PAT-2231: both cards' preview rows share the identical compact shape
    # now - no nested reasons list, no separate three-tile stats grid.
    _overview()
    body = _get(client, make_token()).text
    card = body[body.index('id="extension-risk-heading"'):]
    card = card[:card.index("</section>")]
    assert 'class="risk-list risk-list--compact"' in card
    assert 'class="risk-list__row"' in card
    assert "risk-list__reasons" not in card
    assert "risk-stats" not in card


def test_high_risk_card_end_to_end_folds_the_remainder_into_the_action(client, make_token):
    # PAT-2231 review, exercised through the real page rather than just the
    # view function: no standalone "and N more" paragraph anywhere in the
    # card, and the primary action names the remainder instead.
    _overview(new_software=_new_software(
        window_days=7, total=5,
        counts={"critical": 5, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        products=[_product(f"Tool{i}", "critical") for i in range(5)],
    ))
    body = _get(client, make_token()).text
    card = body[body.index('id="high-risk-heading"'):body.index('id="extension-risk-heading"')]
    assert "more in the newly found list" not in card
    assert "View 2 more high-risk products" in card
    assert 'href="/software?new_days=7&amp;urgency=critical,high"' in card


def test_extension_card_drills_into_filtered_software(client, make_token):
    # PAT-2231: the footer collapses to one primary action - "Review N
    # decisions" pointing at the waiting filter once there is something
    # to decide on (the default fixture has one: MysteryHelper is
    # unreviewed), rather than the old two-link "View browser extensions
    # (dot) Decide on N" footer.
    _overview()
    body = _get(client, make_token()).text
    card = body[body.index('id="extension-risk-heading"'):]
    card = card[:card.index("</section>")]
    assert 'href="/software?type=extension&amp;approval=waiting"' in card
    assert "Review 1 decision" in card


def test_extension_card_primary_action_is_view_all_when_nothing_waiting(client, make_token):
    # PAT-2231 review: "View all N extensions" folds in the total count so
    # the card needs no separate "and N more" line - the same shape
    # High-risk's own "View N more high-risk products" action takes.
    view = main._extension_risk_view([
        {"name": "Fine", "risk_level": "normal", "approval_state": "approved", "device_count": 3},
    ])
    assert view["primary_action"] == {
        "text": "View all 1 extension", "href": "/software?type=extension",
    }


def test_extension_card_view_all_pluralises_the_total():
    view = main._extension_risk_view([
        {"name": "Fine", "risk_level": "normal", "approval_state": "approved", "device_count": 3},
        {"name": "Other", "risk_level": "normal", "approval_state": "approved", "device_count": 1},
    ])
    assert view["primary_action"] == {
        "text": "View all 2 extensions", "href": "/software?type=extension",
    }


# ── CIS compaction ────────────────────────────────────────────────────────

def test_cis_stays_full_while_critical_or_high_checks_fail(client, make_token):
    _overview(findings_open={"critical": 1, "high": 0, "medium": 0, "low": 0})
    body = _get(client, make_token()).text
    assert 'id="cis-compact-heading"' not in body
    assert "<details" not in body.split("CIS Level 1 score")[0][-200:]
    assert "Failing CIS checks by severity" in body


def test_cis_compresses_when_healthy_and_detail_stays_one_click_away(client, make_token):
    _overview(findings_open={"critical": 0, "high": 0, "medium": 2, "low": 1})
    body = _get(client, make_token()).text
    assert 'id="cis-compact-heading"' in body
    assert "No critical or high CIS checks failing." in body
    assert "2 medium and 1 low still open." in body
    detail = body[body.index('<details class="card cis-detail">'):]
    assert "How CIS control coverage explains this score" in detail
    assert "Failing CIS checks by severity" in detail


def test_stale_evidence_is_never_compressed_as_healthy(client, make_token):
    _overview(findings_open={"critical": 0, "high": 0, "medium": 0, "low": 0},
              devices_total=12, devices_reporting_24h=0)
    body = _get(client, make_token()).text
    assert 'id="cis-compact-heading"' not in body
    assert "This score is historical, not current posture." in body
