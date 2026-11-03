"""PAT-2160: the Overview's "Your estate at a glance" facts and "Top 3
actions" ranking, above the "Needs attention" pill card (PAT-2159).

Deterministic, no LLM (Andy's ruling on this ticket). Unit-level coverage
of the pure building blocks (group_cve_fixes, _cve_action_source,
_software_waiting_view, _estate_glance_view, rank_top_actions) lives here,
each exercised directly rather than only through a rendered page, so the
ranking order, the cap of 3, the fixed-version grouping, its no-fixed-
version fallback, and "no action from absent data" are all provable
independent of HTTP/template plumbing. A handful of integration checks at
the end confirm the whole thing wires up through GET / against the shared
stub fixtures.
"""

import main
from tests.conftest import (
    APPLICATIONS,
    EXTENSIONS,
    OVERVIEW,
    OVERVIEW_CARDS_ZERO,
    STUB_STATE,
)


def _get(client, token, path="/"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── group_cve_fixes ─────────────────────────────────────────────────────

def test_group_cve_fixes_groups_by_app_and_picks_the_most_covered():
    findings = [
        {"app": "ExampleBrowser", "fixed_version": "125.0.0", "devices_affected": 3,
         "cve_id": "CVE-1"},
        {"app": "ExampleBrowser", "fixed_version": "125.0.0", "devices_affected": 4,
         "cve_id": "CVE-2"},
        {"app": "ExampleBrowser", "fixed_version": "125.0.0", "devices_affected": 2,
         "cve_id": "CVE-3"},
        {"app": "ArchiveTool", "fixed_version": "3.5", "devices_affected": 9,
         "cve_id": "CVE-4"},
    ]
    group = main.group_cve_fixes(findings)
    assert group == {
        "kind": "fix", "app": "ExampleBrowser", "fixed_version": "125.0.0",
        "devices": 4, "cve_count": 3,
    }


def test_group_cve_fixes_device_count_is_the_max_not_a_sum():
    findings = [
        {"app": "Foo", "fixed_version": "2.0", "devices_affected": 5, "cve_id": "CVE-1"},
        {"app": "Foo", "fixed_version": "2.0", "devices_affected": 3, "cve_id": "CVE-2"},
    ]
    group = main.group_cve_fixes(findings)
    assert group["devices"] == 5  # not 8 - never double-counts a device


def test_group_cve_fixes_falls_back_to_review_when_fixed_version_missing():
    findings = [
        {"app": "ArchiveTool", "fixed_version": "", "devices_affected": 1, "cve_id": "CVE-1"},
        {"app": "ArchiveTool", "fixed_version": None, "devices_affected": 2, "cve_id": "CVE-2"},
    ]
    group = main.group_cve_fixes(findings)
    assert group["kind"] == "review"
    assert group["app"] == "ArchiveTool"
    assert group["fixed_version"] is None
    assert group["cve_count"] == 2


def test_group_cve_fixes_falls_back_to_review_when_fixed_version_disagrees():
    findings = [
        {"app": "Foo", "fixed_version": "1.0", "devices_affected": 1, "cve_id": "CVE-1"},
        {"app": "Foo", "fixed_version": "2.0", "devices_affected": 1, "cve_id": "CVE-2"},
    ]
    group = main.group_cve_fixes(findings)
    assert group["kind"] == "review"  # no single version can be honestly recommended


def test_group_cve_fixes_ties_break_on_product_name():
    findings = [
        {"app": "Zeta", "fixed_version": "1.0", "devices_affected": 1, "cve_id": "CVE-1"},
        {"app": "Alpha", "fixed_version": "1.0", "devices_affected": 1, "cve_id": "CVE-2"},
    ]
    group = main.group_cve_fixes(findings)
    assert group["app"] == "Alpha"


def test_group_cve_fixes_skips_rows_with_no_usable_app_name():
    findings = [{"app": None, "fixed_version": "1.0", "devices_affected": 1, "cve_id": "CVE-1"}]
    assert main.group_cve_fixes(findings) is None


def test_group_cve_fixes_empty_input_returns_none():
    assert main.group_cve_fixes([]) is None


# ── _cve_action_source ──────────────────────────────────────────────────

def test_cve_action_source_unavailable_when_cve_attention_unavailable():
    src = main._cve_action_source(
        {"available": False, "critical": 0, "high": 0}, False, True, [],
    )
    assert src == {"available": False, "candidate": None}


def test_cve_action_source_unavailable_when_not_fresh():
    src = main._cve_action_source(
        {"available": True, "critical": 1, "high": 0}, False, True, [],
    )
    assert src == {"available": False, "candidate": None}


def test_cve_action_source_available_but_no_candidate_when_zero():
    src = main._cve_action_source(
        {"available": True, "critical": 0, "high": 0}, True, True, [],
    )
    assert src == {"available": True, "candidate": None}


def test_cve_action_source_groups_when_findings_read_is_complete():
    rows = [
        {"app": "ExampleBrowser", "severity": "high", "fixed_version": "125.0.0",
         "devices_affected": 3, "cve_id": "CVE-1"},
    ]
    src = main._cve_action_source(
        {"available": True, "critical": 0, "high": 1}, True, True, rows,
    )
    assert src["available"] is True
    assert src["candidate"]["kind"] == "fix"
    assert src["candidate"]["app"] == "ExampleBrowser"


def test_cve_action_source_falls_back_to_ungrouped_review_when_fetch_failed():
    src = main._cve_action_source(
        {"available": True, "critical": 1, "high": 2}, True, False, [],
    )
    assert src["available"] is True
    assert src["candidate"] == {
        "kind": "review", "app": None, "fixed_version": None,
        "devices": None, "cve_count": 3,
    }


def test_cve_action_source_falls_back_to_ungrouped_review_when_fetch_incomplete():
    # PAT-2454: the caller (overview) reports whether it read every critical
    # and high row (_read_critical_high_findings). A partial read cannot be
    # trusted to name the single biggest group, however many rows it holds.
    rows = [{"app": "Foo", "severity": "high", "fixed_version": "1.0",
             "devices_affected": 1, "cve_id": "CVE-1"}]
    src = main._cve_action_source(
        {"available": True, "critical": 2, "high": 3}, True, False, rows,
    )
    assert src["candidate"] == {
        "kind": "review", "app": None, "fixed_version": None,
        "devices": None, "cve_count": 5,
    }


# ── _software_waiting_view ──────────────────────────────────────────────

def test_software_waiting_view_counts_undecided_apps_and_extensions(monkeypatch):
    def fake_get_json(path, jwt_token, **kwargs):
        if path == "/v1/portal/applications":
            return APPLICATIONS
        if path == "/v1/portal/extensions":
            return EXTENSIONS
        raise AssertionError(path)

    monkeypatch.setattr(main.upstream, "get_json", fake_get_json)
    result = main._software_waiting_view("tok")
    # tests/test_software.py's own documented default: waiting=3 from
    # APPLICATIONS/EXTENSIONS alone (this deliberately does not also read
    # the /v1/portal/software inventory merge software() layers on top -
    # see _software_waiting_view's docstring).
    assert result == {"available": True, "count": 3}


def test_software_waiting_view_unavailable_on_upstream_failure(monkeypatch):
    def fake_get_json(path, jwt_token, **kwargs):
        raise main.upstream.UpstreamError("error", "boom")

    monkeypatch.setattr(main.upstream, "get_json", fake_get_json)
    result = main._software_waiting_view("tok")
    assert result == {"available": False, "count": 0}


# ── _estate_glance_view ──────────────────────────────────────────────────
#
# Andy's ruling (2026-09-25, "Actions only, trim duplicates"): the glance
# list is trimmed to facts the "Needs attention" card below it does not
# already carry - device count (bare total, no reporting-loss clause),
# CVE assessment coverage, and software waiting on a decision. Confirmed
# CVE counts and open Unapproved alerts are dropped from this function
# entirely (they stay on Needs attention, via cve_attention/alert_counts
# feeding _attention_view, unchanged).

def _coverage(total, reporting):
    return main.coverage_geometry(total, reporting)


def test_glance_devices_line_is_a_bare_count_with_no_reporting_loss_clause():
    lines = main._estate_glance_view(
        _coverage(12, 10), main._tenant_cve_assessment_view(None), True,
        {"available": False},
    )
    # Reporting loss (the "2 not reporting" clause) is Needs attention's
    # job now - the glance line states nothing but the total.
    assert lines[0]["text"] == "12 devices."
    assert lines[0]["link"] == "/devices"


def test_glance_devices_line_omitted_when_total_unknown():
    lines = main._estate_glance_view(
        _coverage(None, None), main._tenant_cve_assessment_view(None), True,
        {"available": False},
    )
    assert lines == []


def test_glance_cve_coverage_line_and_unavailable_state():
    assessment = main._tenant_cve_assessment_view({
        "assessed_products": 11, "not_assessed_products": 68, "pending_products": 0,
    })
    lines = main._estate_glance_view(
        _coverage(None, None), assessment, False, {"available": False},
    )
    assert "11 of 79 installed products assessed for CVEs (14%)" in lines[0]["text"]
    assert "not yet assessed, not clean" in lines[0]["text"]

    unavailable = main._estate_glance_view(
        _coverage(None, None), assessment, True, {"available": False},
    )
    assert unavailable == []  # stale/unavailable source -> omitted, never a stale figure shown


def test_glance_software_waiting_line():
    lines = main._estate_glance_view(
        _coverage(None, None), main._tenant_cve_assessment_view(None), True,
        {"available": True, "count": 4},
    )
    assert lines == [{
        "text": "4 products waiting on an approval decision.",
        "link": "/software?approval=waiting", "link_label": "View software",
    }]


def test_glance_software_waiting_zero_reads_as_clean_not_omitted():
    lines = main._estate_glance_view(
        _coverage(None, None), main._tenant_cve_assessment_view(None), True,
        {"available": True, "count": 0},
    )
    assert lines == [{
        "text": "No products are waiting on an approval decision.",
        "link": "/software?approval=waiting", "link_label": "View software",
    }]


def test_glance_returns_at_most_three_lines():
    lines = main._estate_glance_view(
        _coverage(12, 10),
        main._tenant_cve_assessment_view({
            "assessed_products": 1, "not_assessed_products": 1, "pending_products": 0,
        }), False,
        {"available": True, "count": 2},
    )
    assert len(lines) == 3


def test_glance_never_duplicates_needs_attention_facts():
    """The glance block must never restate a fact Needs attention already
    carries: no confirmed-CVE-count wording, no Unapproved-alert wording,
    and no reporting-loss clause on the device line - regardless of which
    sources are available."""
    lines = main._estate_glance_view(
        _coverage(12, 5),  # reporting loss exists (7 missing)
        main._tenant_cve_assessment_view({
            "assessed_products": 1, "not_assessed_products": 1, "pending_products": 0,
        }), False,
        {"available": True, "count": 3},
    )
    texts = " ".join(line["text"] for line in lines)
    assert "not reporting" not in texts
    assert "confirmed" not in texts.lower()
    assert "unapproved" not in texts.lower()
    assert "alert" not in texts.lower()
    # The three kept facts are still present.
    assert "12 devices." in texts
    assert "assessed for CVEs" in texts
    assert "waiting on an approval decision" in texts


# ── rank_top_actions ─────────────────────────────────────────────────────

def _no_action_sources(**overrides):
    sources = {
        "reporting_loss": {"available": True, "count": 0},
        "cve_action": {"available": True, "candidate": None},
        "cis_high": {"available": True, "count": 0},
        "unapproved_alerts": {"available": True, "count": 0},
        "software_waiting": {"available": True, "count": 0},
        "cve_coverage": {"available": True, "pct": 90},
    }
    sources.update(overrides)
    return sources


def test_rank_top_actions_nothing_needs_action_when_all_fresh_and_zero():
    result = main.rank_top_actions(**_no_action_sources())
    assert result == {"actions": [], "all_fresh": True}


def test_rank_top_actions_no_action_from_unavailable_source():
    result = main.rank_top_actions(**_no_action_sources(
        reporting_loss={"available": False, "count": 5},  # count present but source not available
    ))
    assert result["actions"] == []  # never invented from an unavailable/stale source
    assert result["all_fresh"] is False


def test_rank_top_actions_fixed_priority_order_and_cap_of_three():
    result = main.rank_top_actions(
        reporting_loss={"available": True, "count": 2},
        cve_action={"available": True, "candidate": {
            "kind": "review", "app": "Foo", "fixed_version": None,
            "devices": None, "cve_count": 3,
        }},
        cis_high={"available": True, "count": 5},
        unapproved_alerts={"available": True, "count": 1},
        software_waiting={"available": True, "count": 4},
        cve_coverage={"available": True, "pct": 20},
    )
    assert len(result["actions"]) == 3
    assert result["actions"][0]["text"] == "Check why 2 devices stopped reporting"
    assert result["actions"][1]["text"] == "Review 3 critical or high CVEs in Foo"
    assert result["actions"][2]["text"] == "Review 5 failing high CIS checks"
    # Lower-priority rules (4/5/6) never displace the top 3, however large
    # their own counts are.
    assert "Unapproved" not in str(result["actions"])
    assert "waiting for an approval" not in str(result["actions"])
    assert "coverage" not in str(result["actions"])


def test_rank_top_actions_lower_priority_rules_fill_in_when_higher_ones_are_quiet():
    result = main.rank_top_actions(**_no_action_sources(
        unapproved_alerts={"available": True, "count": 2},
        software_waiting={"available": True, "count": 6},
        cve_coverage={"available": True, "pct": 35},
    ))
    assert [a["text"] for a in result["actions"]] == [
        "Decide on 2 open Unapproved software alerts",
        "Decide on 6 products waiting for an approval decision",
        "Review CVE assessment coverage (35%)",
    ]


def test_rank_top_actions_cve_coverage_only_fires_below_fifty_percent():
    at_threshold = main.rank_top_actions(**_no_action_sources(
        cve_coverage={"available": True, "pct": 50},
    ))
    assert at_threshold["actions"] == []

    below_threshold = main.rank_top_actions(**_no_action_sources(
        cve_coverage={"available": True, "pct": 49},
    ))
    assert len(below_threshold["actions"]) == 1


def test_rank_top_actions_cve_fix_candidate_wording():
    # Andy's ruling (2026-09-25): the device count is the largest single
    # devices_affected value, not a true per-device union (see
    # group_cve_fixes's docstring) - "at least N" words it as the floor
    # it actually is, never a claimed exact figure.
    result = main.rank_top_actions(**_no_action_sources(
        cve_action={"available": True, "candidate": {
            "kind": "fix", "app": "ExampleBrowser", "fixed_version": "125.0.0",
            "devices": 3, "cve_count": 6,
        }},
    ))
    assert result["actions"][0]["text"] == (
        "Update ExampleBrowser to 125.0.0 on at least 3 devices to fix 6 critical or high CVEs"
    )
    assert result["actions"][0]["link"] == "/findings#cve-findings"


def test_rank_top_actions_cve_fix_candidate_wording_singular_device():
    result = main.rank_top_actions(**_no_action_sources(
        cve_action={"available": True, "candidate": {
            "kind": "fix", "app": "SoloApp", "fixed_version": "2.0.0",
            "devices": 1, "cve_count": 2,
        }},
    ))
    assert result["actions"][0]["text"] == (
        "Update SoloApp to 2.0.0 on at least 1 device to fix 2 critical or high CVEs"
    )


def test_rank_top_actions_cve_wording_singular_and_plural_say_critical_or_high():
    def text(kind, n):
        result = main.rank_top_actions(**_no_action_sources(
            cve_action={"available": True, "candidate": {
                "kind": kind, "app": "Foo", "fixed_version": "2.0" if kind == "fix" else None,
                "devices": 1, "cve_count": n,
            }},
        ))
        return result["actions"][0]["text"]

    assert text("review", 1) == "Review 1 critical or high CVE in Foo"
    assert text("review", 2) == "Review 2 critical or high CVEs in Foo"
    assert text("fix", 1) == "Update Foo to 2.0 on at least 1 device to fix 1 critical or high CVE"
    assert text("fix", 2) == "Update Foo to 2.0 on at least 1 device to fix 2 critical or high CVEs"


def test_rank_top_actions_cve_global_fallback_wording_has_no_product_named():
    result = main.rank_top_actions(**_no_action_sources(
        cve_action={"available": True, "candidate": {
            "kind": "review", "app": None, "fixed_version": None,
            "devices": None, "cve_count": 4,
        }},
    ))
    assert result["actions"][0]["text"] == "Review 4 critical or high CVEs"


# ── Integration: rendered through GET / against the shared stub ─────────

def test_default_fixture_renders_glance_and_actions(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Top 3 actions" in body
    assert "Your estate at a glance" in body
    # Actions render first/left in source order (the headline).
    assert body.index("Top 3 actions") < body.index("Your estate at a glance")
    # Default OVERVIEW/FINDINGS/APPLICATIONS/EXTENSIONS fixtures: 12 total
    # devices (bare count, no reporting-loss clause - that's Needs
    # attention's job now); CVE assessment 180/595 (30%); 9 products
    # waiting on a decision. PAT-2254: that is the Software awaiting approval
    # card's own figure (OVERVIEW_CARDS), not the 3 the portal's
    # APPLICATIONS/EXTENSIONS read alone finds (tests/test_software.py) -
    # the glance line, Top 3 actions and the card read one value; see
    # tests/test_pat2254_overview_truthful.py.
    assert "12 devices." in body
    assert "180 of 595 installed products assessed for CVEs (30%)" in body
    assert "9 products waiting on an approval decision." in body
    # Dropped from the glance block (still shown, worded differently, on
    # Needs attention below).
    glance_block = body.split("Your estate at a glance")[1].split("Needs attention")[0]
    assert "not reporting" not in glance_block
    # Reporting loss ranks first among the actions.
    assert "Check why 1 device stopped reporting" in body


def test_nothing_needs_action_with_a_clean_fresh_estate(client, make_token, monkeypatch):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "devices_total": 5,
        "devices_reporting_24h": 5,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "cve_attention": {"available": True, "critical": 0, "high": 0},
        "unapproved_alerts_open": 0,
        "unapproved_alerts_acknowledged": 0,
    })
    monkeypatch.setitem(STUB_STATE, "findings_data", [])
    monkeypatch.setitem(STUB_STATE, "cve_assessment_data", {
        "last_feed_sync_at": "2026-09-22T01:04:12Z",
        "last_full_match_at": "2026-09-22T01:09:40Z",
        "queued_observations": 0,
        "assessed_products": 10, "pending_products": 0, "not_assessed_products": 0,
    })

    real_get_json = main.upstream.get_json

    def empty_applications(path, jwt_token, **kwargs):
        if path == "/v1/portal/applications":
            return {"total": 0, "truncated": False, "estate_too_large": False, "applications": []}
        if path == "/v1/portal/extensions":
            return {"total": 0, "truncated": False, "extensions": []}
        return real_get_json(path, jwt_token, **kwargs)

    monkeypatch.setattr(main.upstream, "get_json", empty_applications)
    # PAT-2254: the awaiting-decision figure follows the platform's card, so
    # a clean estate has to say so there too.
    monkeypatch.setitem(STUB_STATE, "overview_cards_data", OVERVIEW_CARDS_ZERO)
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert "Nothing needs action right now." in response.text


def test_glance_line_is_omitted_not_zero_when_devices_total_missing(
    client, make_token, monkeypatch,
):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": None, "devices_reporting_24h": None,
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    # Scope to the glance column itself (now the second column, after
    # "Top 3 actions") - the rest of the page (the existing coverage hero)
    # legitimately shows "0 of 0 devices" for a tenant with no known
    # device total; this glance line must simply be absent, not restate
    # that as a fabricated fact of its own.
    # PAT-2177 moved the coverage hero directly under the welcome block, so
    # the glance column now ends where that card begins.
    block = response.text.split("Your estate at a glance")[1]
    block = block.split("What we can see of your estate")[0]
    assert "device" not in block.lower()
