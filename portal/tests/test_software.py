"""PAT-1742: /software consumes GET /v1/portal/applications (PAT-1727)
alongside GET /v1/portal/extensions, so approved/mandatory/undecided
applications appear next to browser extensions instead of only the
unapproved-only picture /v1/portal/unapproved-apps could ever give. Every
row now also carries evidence_basis (PAT-1725) and removal_state (PAT-1726).

Default fixture (tests/conftest.py):
  APPLICATIONS (8 rows, total=8, not truncated):
    TorrentBox    unapproved  identifier_match  -> not wanted
    GhostApp      unapproved  unknown  (0 installs) -> not wanted
    PhantomTool   unapproved  unknown  (0 installs) -> not wanted
    MysteryApp    undecided   identifier_match  -> waiting
    GuessWho      undecided   name_match_only   -> waiting
    Slack         approved    identifier_match  -> approved
    CorpVPN       mandatory   identifier_match  -> approved (grouped with
                                                   approved, PAT-1742 ruling)
    OddPolicy     legacy_quarantine identifier_match -> unrecognised (PAT-2008:
                  "unmanaged" is now the stored form of Ignore, see below)
  EXTENSIONS (4 rows, total=4, not truncated):
    ShadyCoupons  unapproved  removal_state=requested     -> not wanted
    TeamChat      approved                                -> approved
    MysteryHelper unreviewed                               -> waiting
    OldTheme      ignored                                  -> Ignored group (PAT-2008)

So, from APPLICATIONS/EXTENSIONS alone: waiting=3, not_wanted=4, approved=3,
ignored=1, unrecognised=1, total=12 (8 applications + 4 extensions).

PAT-2120: /software merges in SOFTWARE_INVENTORY (tests/conftest.py,
GET /v1/portal/software - application-only, PAT-2104) by exact
(platform, identifier) - see main.py's _software_identity_key docstring.
None of its six products (ArchiveTool/MeteringGap/PartialEvidence/
OldMetering/UsedTool/UnknownEvidence, one per platform usage state; PAT-2326
added UsedTool) share an identifier with an APPLICATIONS row
in this default fixture (only MysteryApp carries a real identifier, and it
doesn't match any inventory product), so all six render as their own,
unmatched rows - inventory carries no policy_state in this fixture, which
defaults to the "waiting" bucket (main.py's _inventory_group). So on the
default fixture: waiting=3+6=9, not_wanted=4, approved=3, ignored=1,
unrecognised=1, total_products=18 (14 applications + 4 extensions).
tests/test_pat2008_software_approvals.py covers the merge itself (a
matching identifier on both sides) with its own fixtures.

PAT-1839: every application and extension row above also carries
decided_by/decided_at/justification (see the per-row comments in
conftest.py) - a mix of fully populated, decided_at-only (the permanent
application-policy-row shape, decided_by always null there) and fully
null (genuinely undecided) rows, across both kinds and all four rendered
groups (waiting/not_wanted/approved/unrecognised).
"""

import html as html_lib
import re
from urllib.parse import parse_qs, urlsplit

from tests.conftest import (
    APPLICATIONS,
    EXTENSIONS,
    PROTECTED_SOFTWARE,
    SOFTWARE_INVENTORY,
    STUB_STATE,
)


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _inventory_row(html, name):
    marker = html.find(name)
    assert marker >= 0, f"inventory row for {name!r} was not rendered"
    start = html.rfind("<tr", 0, marker)
    end = html.find("</tr>", marker)
    assert start >= 0 and end >= 0, f"inventory row for {name!r} was malformed"
    return html[start:end + len("</tr>")]


def _group_start(html, group):
    """Position of the first row in decision bucket `group`
    (waiting/not_wanted/approved/ignored/unrecognised) - PAT-2120 replaced
    the five separate <h2> group cards this file used to order-check
    against with one table whose rows carry data-filter-decision, still
    rendered in that same waiting/not_wanted/approved/ignored/unrecognised
    order (main.py's groups dict)."""
    marker = f'data-filter-decision="{group}"'
    pos = html.index(marker)
    return html.rindex("<tr", 0, pos)


def test_software_inventory_renders_dated_evidence_and_cve_assessment(client, make_token):
    """PAT-1870/PAT-2028, carried into the PAT-2120 merge: a product matched
    to GET /v1/portal/software shows its dated evidence and CVE assessment
    on the same merged row. PAT-2120's column decision (Andy, 2026-09-25)
    dropped the separate Usage evidence column and its removal-candidate
    copy from the page entirely - ArchiveTool's usage_state/removal_candidate
    fields are still in the fixture (the endpoint still returns them) but
    nothing on /software reads or renders them any more."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _inventory_row(resp.text, "ArchiveTool")
    assert "20 Sep 2026" in row  # evidence_at
    assert "No known CVEs" in row
    assert "Removal candidate" not in resp.text
    assert "metered, 0 unmetered" not in resp.text


def test_software_inventory_forwards_bounded_search_and_pagination(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?search=Archive&limit=1&offset=1&type=application")
    assert resp.status_code == 200
    request = STUB_STATE["software_inventory_requests"][-1]
    assert request == {"limit": 1, "offset": 1, "search": "Archive", "jwt": token}
    # A no-result inventory slice offers a query-preserving previous link so
    # dated evidence for the rest of the estate is still reachable; the
    # existing policy tab selection also survives. PAT-2120 retired the
    # dedicated inventory search box (one search input now, over the whole
    # merged table client-side) but the server-side search/pagination
    # contract itself - and its query-preserving links - is unchanged.
    previous = re.search(r'<a class="btn btn-small" href="([^"]*)">Previous</a>', resp.text)
    assert previous, "no query-preserving Previous link"
    query = parse_qs(urlsplit(html_lib.unescape(previous.group(1))).query)
    assert query == {"search": ["Archive"], "limit": ["1"], "offset": ["0"],
                     "type": ["application"]}


def test_software_inventory_beyond_end_offset_still_shows_the_rest_of_the_table(
    client, make_token,
):
    """PAT-2120: an inventory offset past its own end no longer means an
    empty page - the merged table's governance rows (never paginated) still
    render in full; only the dated-evidence enrichment for that offset
    slice is empty. A query-preserving previous link is still offered."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?limit=1&offset=50")
    assert resp.status_code == 200
    assert "TorrentBox" in resp.text
    assert "Dated software evidence is temporarily unavailable." not in resp.text
    assert "offset=49" in resp.text


def test_software_inventory_contract_violations_fail_soft_to_policy_view(
    client, make_token, monkeypatch, caplog,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    base = dict(SOFTWARE_INVENTORY["products"][0])
    malformed_products = []
    bad_state = dict(base)
    bad_state["usage_state"] = "partly_unused"
    malformed_products.append(bad_state)
    bad_candidate = dict(base)
    bad_candidate["metered_installation_count"] = 1
    malformed_products.append(bad_candidate)
    with caplog.at_level("WARNING", logger="portal.auth"):
        for product in malformed_products:
            monkeypatch.setitem(
                STUB_STATE, "software_inventory_data",
                {**SOFTWARE_INVENTORY, "products": [product]},
            )
            resp = _get(client, token, "/software")
            assert resp.status_code == 200
            assert "Dated software evidence is temporarily unavailable." in resp.text
            assert "TorrentBox" in resp.text
            assert "ShadyCoupons" in resp.text
            assert "Removal candidate:" not in resp.text
    warnings = [record.getMessage() for record in caplog.records]
    assert warnings == [
        "portal.software_inventory.fail_soft kind=error",
        "portal.software_inventory.fail_soft kind=error",
    ]
    assert token not in " ".join(warnings)


def test_software_inventory_early_empty_page_fails_soft_to_policy_view(
    client, make_token, monkeypatch,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "mode", "software_early_empty")
    resp = _get(client, token, "/software?limit=1&offset=0")
    assert resp.status_code == 200
    assert "Dated software evidence is temporarily unavailable." in resp.text
    assert "TorrentBox" in resp.text
    assert "ShadyCoupons" in resp.text


def test_software_inventory_unavailable_or_malformed_keeps_policy_view(
    client, make_token, monkeypatch,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for mode in ("software500", "software_malformed"):
        monkeypatch.setitem(STUB_STATE, "mode", mode)
        resp = _get(client, token, "/software")
        assert resp.status_code == 200
        assert "Dated software evidence is temporarily unavailable." in resp.text
        # The pre-existing governance data remains visible and usable.
        assert "TorrentBox" in resp.text
        assert "ShadyCoupons" in resp.text


def test_unapproved_apps_redirects_to_software(client, make_token):
    """PAT-1643: /unapproved-apps merged into /software. Kept as a 301 (not
    removed outright) so existing bookmarks and report deep links still land
    somewhere real."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = client.get("/unapproved-apps", headers={"Cf-Access-Jwt-Assertion": token},
                       follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "/software"


def test_extensions_redirects_to_software(client, make_token):
    """PAT-1643: /extensions merged into /software, same 301 treatment."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = client.get("/extensions", headers={"Cf-Access-Jwt-Assertion": token},
                       follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers["location"] == "/software"


def test_software_never_shows_retired_tier_vocabulary(client, make_token):
    """Root AGENTS.md: buyer-facing tiers were retired 2026-09-01 (PAT-1566).
    GET /v1/portal/applications still carries enforcement_tier
    (report/app_management/managed on the fixture data), but the portal must
    never surface it, labelled or not - no "Policy tier" column, no toolbar
    hint about it, and none of the raw values anywhere in the rendered
    page."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "Policy tier" not in resp.text
    # Word-boundary match: "patch" and "managed" are also substrings of
    # unrelated page copy/asset names (e.g. base.html's
    # "patched-portal-theme" localStorage key), so a bare `in` check would
    # false-positive.
    for tier in ("report_deploy", "app_management", "managed", "patch"):
        assert re.search(rf"\b{tier}\b", resp.text) is None, tier


def test_software_merges_applications_and_extensions_by_group(client, make_token):
    """PAT-1742 acceptance criterion: applications from every policy state
    (not just unapproved) and extensions land together in one grouped
    table, each row carrying its own type."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    # Waiting: undecided applications (new) plus unreviewed extensions.
    assert "MysteryApp" in resp.text
    assert "GuessWho" in resp.text
    assert "MysteryHelper" in resp.text
    # Not wanted: unapproved applications plus unapproved extensions.
    assert "TorrentBox" in resp.text
    assert "GhostApp" in resp.text
    assert "PhantomTool" in resp.text
    assert "ShadyCoupons" in resp.text
    # Approved: approved applications, mandatory applications, and approved
    # extensions all land in the same group.
    assert "Slack" in resp.text
    assert "CorpVPN" in resp.text
    assert "TeamChat" in resp.text
    # Every row shows its own type, application or extension.
    assert "Application" in resp.text
    assert "Extension" in resp.text
    # Waiting renders before the not-wanted/approved cards (page order).
    assert resp.text.index("MysteryApp") < resp.text.index("TorrentBox")


def test_software_undecided_application_never_reads_as_approved(client, make_token):
    """undecided/unreviewed must land in Waiting, never in Approved (PAT-1643
    acceptance criterion, extended to applications by PAT-1742)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert resp.text.index("MysteryApp") < _group_start(resp.text, "not_wanted")
    assert resp.text.index("MysteryApp") < _group_start(resp.text, "approved")


def test_software_mandatory_application_groups_with_approved(client, make_token):
    """PAT-1742 (Andy ruling): a mandatory policy is a stronger form of
    approved, not a separate customer-facing group - CorpVPN (mandatory)
    lands in the same Approved bucket as Slack (approved)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert _group_start(resp.text, "approved") < resp.text.index("CorpVPN")
    assert resp.text.index("CorpVPN") < _group_start(resp.text, "unrecognised")


def test_software_ignored_kept_out_of_groups(client, make_token):
    """PAT-1643, reshaped by PAT-2008: ignored products are kept out of
    waiting/not-wanted/approved. They now carry their own "ignored"
    data-filter-decision bucket, with the same controls as every other row,
    instead of a one-line list."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "OldTheme")
    assert 'data-filter-decision="ignored"' in row


def test_software_unrecognised_policy_state_renders_visibly(client, make_token):
    """Non-author review finding (carried over from PAT-1643): a policy /
    approval state outside the documented values must never silently vanish
    (absence requires authority, root AGENTS.md). The default fixture's
    OddPolicy application (policy_state=legacy_quarantine) must render, visibly
    unclassified, and never count as approved or waiting."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "OddPolicy")
    assert 'data-filter-decision="unrecognised"' in row
    assert "State not recognised" in resp.text


def test_software_unrecognised_extension_approval_state_renders_visibly(
    client, make_token, monkeypatch,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    weird = dict(EXTENSIONS["extensions"][0])
    weird["extension_id"] = "weird-ext-id"
    weird["name"] = "WeirdState"
    weird["approval_state"] = "pending_migration"
    monkeypatch.setitem(EXTENSIONS, "extensions", [*EXTENSIONS["extensions"], weird])
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "WeirdState")
    assert 'data-filter-decision="unrecognised"' in row


def test_software_header_total_from_real_totals(client, make_token):
    """The list holds 18 rows: 8 applications + 4 extensions plus every
    SOFTWARE_INVENTORY product with no matching governance row (6 - see
    this file's module docstring), the ignored extension and the
    unrecognised application included. PAT-2255: that figure is stated
    plainly in the Type dropdown ("at least 18" was the defect-8 mix of a
    governance total and inventory-only rows), and the headline reads the
    Overview's own awaiting-decision figure instead (9 in the card fixture)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert ">All types (18)</option>" in _type_select(resp.text)
    assert "9 products waiting on an approval decision" in resp.text.replace(
        "<strong>", "").replace("</strong>", "")
    assert "at least 18" not in resp.text


def test_software_type_shown_with_icon_and_label(client, make_token):
    """PAT-1742: type must be unmistakable - an inline icon plus a text
    label, not just a plain grey pill."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert 'class="type-tag type-tag--app"' in resp.text
    assert 'class="type-tag type-tag--ext"' in resp.text
    assert "<svg" in resp.text


def _type_select(html):
    """The Type <select> block (PAT-2163) - from the filter bar's <select
    id="software-search-type"...> tag to its closing </select>, so tests can
    check option markup without depending on exact attribute line-wrapping."""
    start = html.index('<select id="software-search-type"')
    end = html.index("</select>", start) + len("</select>")
    return html[start:end]


def test_software_default_view_is_the_all_state(client, make_token):
    """PAT-1798, reshaped by PAT-2163: plain /software (no ?type=) is the
    "All" filter state - every application and extension row renders, and
    the Type dropdown starts on "All types"."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "TorrentBox" in resp.text
    assert "ShadyCoupons" in resp.text
    select = _type_select(resp.text)
    assert 'data-row-filter="kind"' in select
    assert 'data-query-param="type"' in select
    assert 'data-initial=""' in select
    assert '<option value="" selected>All types' in select


def test_software_type_filter_application_seeds_initial_tab_not_row_removal(client, make_token):
    """PAT-1798, reshaped by PAT-2163: the Type filter is client-side over
    the row set already fetched - ?type=application no longer strips
    extension rows out of the response, it only seeds which option the
    Type dropdown starts selected on (data-initial). static/js/portal.js
    does the actual hiding, keyed off each row's data-filter-kind."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=application")
    assert resp.status_code == 200
    assert "TorrentBox" in resp.text
    assert "MysteryApp" in resp.text
    assert "Slack" in resp.text
    # Extensions still render - the browser hides them, the server doesn't.
    assert "ShadyCoupons" in resp.text
    assert "MysteryHelper" in resp.text
    assert "TeamChat" in resp.text
    select = _type_select(resp.text)
    assert 'data-row-filter="kind"' in select
    assert 'data-query-param="type"' in select
    assert 'data-initial="application"' in select
    assert '<option value="application" selected>Applications' in select
    # Per-type counts stay unfiltered so switching options is possible. 14
    # applications: the 8 APPLICATIONS fixture rows plus the 6
    # SOFTWARE_INVENTORY products with no matching governance row (inventory
    # is application-only - see this file's module docstring).
    assert "Extensions (4)" in select
    assert "Applications (14)" in select


def test_software_type_filter_extension_seeds_initial_tab_not_row_removal(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=extension")
    assert resp.status_code == 200
    assert "ShadyCoupons" in resp.text
    assert "MysteryHelper" in resp.text
    assert "TeamChat" in resp.text
    # Applications still render - the browser hides them, the server doesn't.
    assert "TorrentBox" in resp.text
    assert "MysteryApp" in resp.text
    assert "Slack" in resp.text
    select = _type_select(resp.text)
    assert 'data-row-filter="kind"' in select
    assert 'data-query-param="type"' in select
    assert 'data-initial="extension"' in select
    assert '<option value="extension" selected>Extensions' in select
    assert "Applications (14)" in select
    assert "Extensions (4)" in select


def test_software_type_filter_invalid_value_shows_everything(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=bogus")
    assert resp.status_code == 200
    assert "TorrentBox" in resp.text
    assert "ShadyCoupons" in resp.text
    # An unrecognised value falls back to the "All" state, same as no
    # query string at all - it must never seed a filter on a value the
    # client-side script doesn't know how to match against data-filter-kind.
    select = _type_select(resp.text)
    assert 'data-initial=""' in select
    assert '<option value="" selected>All types' in select
    # It is never used to build the Type dropdown's own options either -
    # only the fixed application/extension/"" values ever appear as an
    # <option value="...">.
    assert '<option value="bogus"' not in resp.text


def test_software_rows_carry_data_kind_for_client_side_filtering(client, make_token):
    """PAT-1798/PAT-1843: every row, in every policy-state group, carries data-filter-kind
    so the segmented filter can hide non-matching rows client-side without
    a new endpoint or another upstream call."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200

    def kind_of(name: str) -> str:
        pos = 0
        while True:
            tr_start = resp.text.index("<tr ", pos)
            tr_end = resp.text.index("</tr>", tr_start)
            row = resp.text[tr_start:tr_end]
            if name in row:
                match = re.search(r'data-filter-kind="([^"]+)"', row)
                assert match, f"no data-filter-kind on the row containing {name!r}"
                return match.group(1)
            pos = tr_end + len("</tr>")

    # Waiting.
    assert kind_of("MysteryApp") == "application"
    assert kind_of("MysteryHelper") == "extension"
    # Not wanted.
    assert kind_of("TorrentBox") == "application"
    assert kind_of("ShadyCoupons") == "extension"
    # Approved.
    assert kind_of("Slack") == "application"
    assert kind_of("TeamChat") == "extension"


def test_software_evidence_basis_labels_render(client, make_token):
    """PAT-1725 set the evidence basis per row; PAT-2255 (defect 4) takes the
    internal "Identifier match" wording out of the list. What the customer
    needs from the basis is whether a row can be marked, and why not: a
    name-only or no-evidence row still says so, in its lock line. Never
    "version confirmed" (identity evidence only, root AGENTS.md: CVE and
    usage claims require evidence)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "Identifier match" not in resp.text
    assert "Name match only" not in resp.text
    assert "Known by its name only" in _row(resp.text, "GuessWho")
    assert "No device evidence confirms" in _row(resp.text, "PhantomTool")
    assert "version confirmed" not in resp.text.lower()
    # The old page-level disclaimer is gone now that rows carry their own
    # basis.
    assert "not yet confirmed" not in resp.text.lower()


def test_software_application_removal_not_available_never_reads_not_requested(client, make_token):
    """PAT-1726 / contracts/portal-api.md: an application's removal_state is
    always "not_available" (no removal data model exists) and must render
    as "no removal pathway", never "not requested" - that would falsely
    claim removal is a capability this application could have used."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "TorrentBox")
    # PAT-2255: the permanent "no removal pathway" line is no news on a
    # one-line row, so it is not shown; it must still never read as a
    # removal that was not requested.
    assert "Not requested" not in row
    assert "not requested" not in row.lower()


def test_software_extension_removal_state_renders_distinctly(client, make_token):
    """An extension's removal_state vocabulary (requested/not_requested/...)
    is distinct from an application's not_available - ShadyCoupons
    (removal_state=requested) must read differently from an application row
    in the same Not wanted table."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "ShadyCoupons")
    # PAT-2255: carried on the Unapproved state's tooltip, not a line.
    assert re.search(r'class="pill pill-state[^"]*" title="[^"]*Removal requested', row)
    assert "No removal pathway" not in row


def test_software_empty_state(client, make_token, monkeypatch):
    """No applications and no extension telemetry, and no inventory either,
    must render the merged table's own empty-state copy, not an error or a
    blank table (PAT-2120: one table replaces the old per-group empty
    messages with one, next to the one table it describes)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(APPLICATIONS, "applications", [])
    monkeypatch.setitem(APPLICATIONS, "total", 0)
    monkeypatch.setitem(EXTENSIONS, "extensions", [])
    monkeypatch.setitem(EXTENSIONS, "total", 0)
    monkeypatch.setitem(STUB_STATE, "software_inventory_data",
                        {**SOFTWARE_INVENTORY, "products": []})
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "No products match this search." in resp.text
    assert 'data-filter-decision="waiting"' not in resp.text


def test_software_empty_decision_buckets_are_hidden_not_a_stale_count(
    client, make_token, monkeypatch,
):
    """With no applications or extension telemetry, only the six
    SOFTWARE_INVENTORY products remain (all unmatched, all in the Waiting
    bucket - see this file's module docstring). PAT-2163: a zero-count
    Approval option is left out of the dropdown entirely (never a stale
    carried-over count, and never a "(0)" a customer would have to page
    through) - only Waiting on a decision, the one with real rows, renders."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(APPLICATIONS, "applications", [])
    monkeypatch.setitem(APPLICATIONS, "total", 0)
    monkeypatch.setitem(EXTENSIONS, "extensions", [])
    monkeypatch.setitem(EXTENSIONS, "total", 0)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    dropdown = resp.text[resp.text.index('<details class="filter-dropdown"'):]
    dropdown = dropdown[:dropdown.index("</details>")]
    for label in ("Unapproved", "Approved", "Ignored", "State not recognised"):
        assert label not in dropdown
    assert ">Unreviewed (6)<" in dropdown


def test_software_apps_upstream_error_renders_error_page(client, make_token):
    """/software depends on two upstream calls; a platform-wide 503 must
    still degrade to the friendly error page, never a crash."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "down503"
    resp = _get(client, token, "/software")
    assert resp.status_code == 503
    assert "not yet enabled" in resp.text.lower()


def test_software_applications_upstream_404_renders_error_page(client, make_token):
    """A 404 from just GET /v1/portal/applications must still degrade the
    whole /software page gracefully (fail soft to the shared error page,
    same as an extensions-only failure already does), since the page can't
    tell its full software-governance story with only half its data."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "applications404"
    resp = _get(client, token, "/software")
    assert resp.status_code == 404
    assert "could not be found" in resp.text.lower()


def test_software_extensions_upstream_404_renders_error_page(client, make_token, monkeypatch):
    """A 404 from just the extensions endpoint must still degrade the whole
    /software page gracefully, since the page can't tell its full story
    with only half its data."""
    from tests.conftest import StubPlatformHandler

    original = StubPlatformHandler.do_GET

    def do_get(self):
        if self.path == "/v1/portal/extensions":
            self._send(404, {"error": "not found"})
            return
        original(self)

    monkeypatch.setattr(StubPlatformHandler, "do_GET", do_get)
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 404
    assert "could not be found" in resp.text.lower()


def test_software_extensions_truncated_rendering_is_honest(client, make_token, monkeypatch):
    """The extensions cap (500 rows) is reported via truncated + total; the
    page must say so rather than imply completeness."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(EXTENSIONS, "truncated", True)
    monkeypatch.setitem(EXTENSIONS, "total", 512)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "This list is partial: it holds the first 4 of 512 browser extensions" in resp.text


def test_software_extensions_truncated_with_invalid_total_shows_at_least(
    client, make_token, monkeypatch,
):
    """When truncated is true but the platform's total is missing or
    invalid, falling back to the shown-row count would understate the real
    total. PAT-2255: the page says the platform did not report the total,
    in words, rather than "at least N" or a precise-looking figure it
    cannot vouch for."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(EXTENSIONS, "truncated", True)
    monkeypatch.setitem(EXTENSIONS, "total", None)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "it holds the first 4 browser extensions" in resp.text
    assert "did not report how many there are in all" in resp.text
    assert "of 4 browser extensions" not in resp.text
    assert "at least" not in resp.text.split("This list is partial", 1)[1][:300]


def test_software_applications_truncated_rendering_is_honest(client, make_token, monkeypatch):
    """PAT-1727: undecided applications are capped at 500 too; truncated +
    total on the applications response must be surfaced the same honest
    way as the extensions cap. PAT-2255: the shown count is the 8 rows the
    applications read returned, the same population the platform's total
    (600) counts; the 6 inventory-only rows the merge adds are not part of
    that total, and mixing the two was defect 8's "at least" figure."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(APPLICATIONS, "truncated", True)
    monkeypatch.setitem(APPLICATIONS, "total", 600)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "This list is partial: it holds the first 8 of 600 applications" in resp.text


def test_software_untruncated_shows_no_partial_note(client, make_token):
    """The default fixture is complete (truncated false on both endpoints);
    the page must not show a 'showing the first N' note or claim to be
    partial."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "This list is partial" not in resp.text
    assert "This list is partial" not in resp.text


def test_software_extensions_estate_too_large_is_distinct_from_empty(
    client, make_token, monkeypatch,
):
    """PAT-1643 acceptance criterion: an empty extensions list caused by the
    platform's fail-closed estate-too-large branch must never look like an
    empty list because there is nothing there. To isolate the extension
    failure, applications are trimmed to a not-wanted-only row so Waiting
    and Approved are extension-sourced for this test."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(APPLICATIONS, "applications", [dict(APPLICATIONS["applications"][0])])
    monkeypatch.setitem(APPLICATIONS, "total", 1)
    monkeypatch.setitem(EXTENSIONS, "estate_too_large", True)
    monkeypatch.setitem(EXTENSIONS, "truncated", True)
    monkeypatch.setitem(EXTENSIONS, "total", 0)
    monkeypatch.setitem(EXTENSIONS, "extensions", [])
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "too large to summarise" in resp.text.lower()
    assert "TorrentBox" in resp.text  # applications-only row is unaffected
    assert "Nothing is waiting on a decision" not in resp.text
    assert "Nothing is approved yet" not in resp.text


def test_software_applications_estate_too_large_is_distinct_from_empty(
    client, make_token, monkeypatch,
):
    """PAT-1727's fail-closed branch only withholds undecided applications;
    approved/unapproved/mandatory policy rows are unaffected and must keep
    rendering normally."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(APPLICATIONS, "estate_too_large", True)
    monkeypatch.setitem(APPLICATIONS, "truncated", True)
    monkeypatch.setitem(APPLICATIONS, "applications", [
        a for a in APPLICATIONS["applications"] if a["policy_state"] != "undecided"
    ])
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "too large to group" in resp.text.lower()
    assert "TorrentBox" in resp.text  # unapproved policy row unaffected
    assert "Slack" in resp.text  # approved policy row unaffected
    # Extension-sourced waiting row still there, so it's not an ordinary
    # empty state either way, but the point is the withheld-banner shows.
    assert "MysteryHelper" in resp.text


def test_software_unexpected_shape_renders_error_not_empty(client, make_token):
    """PAT-888 discipline applied to /software: a malformed applications
    payload is a platform contract violation, not a clean empty estate."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "malformed"
    resp = _get(client, token, "/software")
    assert resp.status_code != 200
    assert "temporarily unavailable" in resp.text.lower()
    assert "nothing is waiting on a decision" not in resp.text.lower()


def test_software_row_confirm_needed_unless_identifier_match():
    """PAT-1742 review: only an identifier match skips "Ask us to confirm
    first". Name-match-only, unknown, missing and unrecognised evidence all
    require confirmation, so no decision is offered on unconfirmed identity."""
    from main import _software_row

    def confirm(basis):
        return _software_row("X", "application", 1, basis, "not_available")["confirm_needed"]

    assert confirm("identifier_match") is False
    for basis in ("name_match_only", "unknown", "", "something_new"):
        assert confirm(basis) is True, basis


def _row(resp_text: str, name: str, occurrence: int = 0) -> str:
    """The `occurrence`-th (0-indexed) <tr>...</tr> in the merged table
    that contains `name` - scans actual table rows only, one at a time, so
    a name that also happens to match inside the Publisher filter's
    <select> (PAT-2120 moved the filters above the table, so a raw
    substring match like "Slack" inside "Slack Technologies, Inc." can sit
    before any row at all) is never mistaken for a row."""
    count = -1
    pos = 0
    while True:
        tr_start = resp_text.index("<tr ", pos)
        tr_end = resp_text.index("</tr>", tr_start)
        row = resp_text[tr_start:tr_end]
        if name in row:
            count += 1
            if count == occurrence:
                return row
        pos = tr_end + len("</tr>")


# PAT-1821: GET /v1/portal/protected-software badges an application row when
# it exact-matches (case/whitespace-insensitive) either the entry's bare
# product_name or "vendor product_name" - see main.py's
# _protected_software_index for why this is strict-exact rather than a
# substring match. Never a filter: rows, counts and grouping are unaffected.


def test_software_protected_application_shows_category_badge(client, make_token):
    """CorpVPN's name exact-matches PROTECTED_SOFTWARE's product_name
    ("CorpVPN") directly - it must render the pill badge carrying the
    console's own category label ("Security", from category "security")."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "CorpVPN")
    assert 'class="pill pill-ok"' in row
    assert "Security" in row
    # The badge is additive - CorpVPN's other fields are still there.
    assert ">Approved</span>" in row


def test_software_unprotected_application_shows_no_badge(client, make_token):
    """Slack has no entry in PROTECTED_SOFTWARE - its row must render no
    protected pill, even though it sits in the same Approved table as the
    badged CorpVPN row."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "Slack")
    assert "pill-ok" not in row


def test_software_protected_match_uses_vendor_plus_product_name(client, make_token, monkeypatch):
    """GuardianEDR only appears vendor-prefixed on a device ("Aegis
    GuardianEDR"), never bare - exercises the second candidate form the
    index builds (see _protected_software_index)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    vendor_prefixed = dict(APPLICATIONS["applications"][0])
    vendor_prefixed.update({"name": "Aegis GuardianEDR", "identifier": "aegis-guardian"})
    monkeypatch.setitem(
        APPLICATIONS, "applications", [*APPLICATIONS["applications"], vendor_prefixed],
    )
    monkeypatch.setitem(APPLICATIONS, "total", APPLICATIONS["total"] + 1)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "Aegis GuardianEDR")
    assert 'class="pill pill-ok"' in row
    assert "EDR" in row


def test_software_protected_match_never_a_substring_guess(client, make_token, monkeypatch):
    """False-positive guard (PAT-1821 design constraint): a protected entry
    whose product_name is a substring of an unrelated application's name
    must never badge that application. "ZoneAlarm Extreme Defender" is not
    "Defender" and must not be marked protected just because it contains
    the word."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(
        STUB_STATE, "protected_data",
        {"products": [{"vendor": "Microsoft", "product_name": "Defender", "category": "security"}]},
    )
    decoy = dict(APPLICATIONS["applications"][0])
    decoy.update({"name": "ZoneAlarm Extreme Defender", "identifier": "zonealarm-decoy"})
    monkeypatch.setitem(APPLICATIONS, "applications", [*APPLICATIONS["applications"], decoy])
    monkeypatch.setitem(APPLICATIONS, "total", APPLICATIONS["total"] + 1)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "ZoneAlarm Extreme Defender")
    assert "pill-ok" not in row


def test_software_extension_rows_are_never_badged_even_on_exact_name_match(
    client, make_token, monkeypatch,
):
    """PAT-1821: protected-software is application-only on the platform
    today. Even an extension whose name exact-matches a protected
    product_name must not be badged - only the application row for the
    same name gets the pill."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    twin_extension = dict(EXTENSIONS["extensions"][1])  # TeamChat, approved
    twin_extension.update({"extension_id": "corpvpn-ext-twin", "name": "CorpVPN"})
    monkeypatch.setitem(EXTENSIONS, "extensions", [*EXTENSIONS["extensions"], twin_extension])
    monkeypatch.setitem(EXTENSIONS, "total", EXTENSIONS["total"] + 1)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    # First occurrence is the application row (badged); second is the
    # extension row just added (must not be).
    app_row = _row(resp.text, "CorpVPN", occurrence=0)
    ext_row = _row(resp.text, "CorpVPN", occurrence=1)
    assert 'class="pill pill-ok"' in app_row
    assert "pill-ok" not in ext_row
    assert 'data-filter-kind="extension"' in ext_row


def test_software_protected_badge_never_changes_row_count_or_grouping(client, make_token):
    """The protected-software call is a disposition badge only - it must
    never filter rows, change which group they land in, or change the
    estate totals. Same assertions as the pre-PAT-1821 grouping/total
    tests above, run again with the protected-software fixture live, to
    prove the new call is additive."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert ">All types (18)</option>" in _type_select(resp.text)
    assert _group_start(resp.text, "approved") < resp.text.index("CorpVPN")
    assert _group_start(resp.text, "unrecognised") > resp.text.index("CorpVPN")


def test_software_protected_software_upstream_failure_does_not_break_page(
    client, make_token, monkeypatch,
):
    """PAT-1821: GET /v1/portal/protected-software is an enhancement to
    existing rows, not primary page data. Its failure (representative here
    as a 500; software()'s try/except around the call is keyed on
    upstream.UpstreamError generically, so a 503/429/timeout takes the
    identical code path) must never take down /software - applications and
    extensions still render, just without any protected badges."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "mode", "protected500")
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "TorrentBox" in resp.text
    assert "ShadyCoupons" in resp.text
    assert "CorpVPN" in resp.text
    row = _row(resp.text, "CorpVPN")
    assert "pill-ok" not in row


def test_software_protected_software_malformed_response_does_not_break_page(
    client, make_token, monkeypatch,
):
    """A platform contract drift on protected-software (neither documented
    shape) must degrade the same way an outright failure does - no badges,
    rest of the page intact - never surface as a 500 or an empty page."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "protected_data", {"unexpected": "shape"})
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "CorpVPN" in resp.text
    row = _row(resp.text, "CorpVPN")
    assert "pill-ok" not in row


def test_protected_software_index_matches_bare_and_vendor_prefixed_names():
    """Unit-level check of the matching index itself (main.py PAT-1821):
    both candidate forms resolve, case/whitespace-insensitively."""
    from main import _protected_match, _protected_software_index

    index = _protected_software_index(PROTECTED_SOFTWARE["products"])
    assert _protected_match("CorpVPN", index)["category"] == "security"
    assert _protected_match("  corpvpn  ", index)["category"] == "security"
    # Both forms resolve: bare product_name, and vendor-prefixed.
    assert _protected_match("GuardianEDR", index)["category"] == "edr"
    assert _protected_match("Aegis GuardianEDR", index)["category"] == "edr"
    assert _protected_match("Unrelated Product", index) is None


def test_protected_software_index_never_substring_matches():
    """Design constraint carried in the code comment: a product_name that
    is a substring of an unrelated name must not match."""
    from main import _protected_match, _protected_software_index

    index = _protected_software_index(
        [{"vendor": "Microsoft", "product_name": "Defender", "category": "security"}]
    )
    assert _protected_match("ZoneAlarm Extreme Defender", index) is None
    assert _protected_match("Defender Plus", index) is None
    assert _protected_match("Defender", index) is not None


def test_software_row_protected_fields_default_unset():
    """A row built with no protected_category (the extension-loop case, or
    an unmatched application) must read as unprotected, not as
    'confirmed not protected' - absence requires authority."""
    from main import _software_row

    row = _software_row("X", "application", 1, "identifier_match", "not_available")
    assert row["protected"] is False
    assert row["protected_category"] is None
    assert row["protected_label"] is None


def test_software_row_decision_provenance_defaults():
    """A row built with no decision fields at all must read as genuinely
    undecided, not as a missing/blank value - absence requires authority."""
    from main import _software_row

    row = _software_row("X", "application", 1, "identifier_match", "not_available")
    assert row["has_decision"] is False
    assert row["decided_by"] is None
    assert row["decided_by_label"] == "Not recorded"
    assert row["decided_at"] is None
    assert row["justification"] is None


def test_software_decision_provenance_fully_populated_renders(client, make_token):
    """GuessWho (waiting, application, undecided-row triage lookup) carries
    all three fields - the person, the formatted date and the
    justification must all render in its row."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "GuessWho")
    assert "priya@example.com" in row
    assert "20 Aug 2026" in row
    assert "Name-only match, held pending identifier confirmation." in row
    assert "Who decided was not recorded" not in row


def test_software_decision_provenance_application_policy_row_actor_not_recorded(
    client, make_token,
):
    """TorrentBox is the permanent application-policy-row shape: decided_at
    and justification are populated but decided_by is always null, so the
    row must fall back to "not recorded" rather than rendering a blank
    or a raw None."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "TorrentBox")
    assert "Who decided was not recorded" in row
    assert "01 Dec 2026" in row
    assert "Peer-to-peer client, not permitted on the estate." in row
    assert "None" not in row


def test_software_decision_provenance_omits_empty_justification(client, make_token):
    """CorpVPN has a decision date but no justification recorded - the
    Justification line must be omitted entirely, never rendered as
    "Justification: None"."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "CorpVPN")
    assert "Who decided was not recorded" in row
    assert "02 Oct 2026" in row
    assert "Justification" not in row


def test_software_decision_provenance_undecided_renders_plainly(client, make_token):
    """MysteryApp has no decision record at all (all three fields null) -
    this is a legitimate state, not a bug, and must render the plain word
    "Undecided" rather than a blank cell or an empty disclosure."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "MysteryApp")
    # PAT-2255: provenance is the approval state's tooltip.
    assert "No decision recorded yet" in row
    assert "<details" not in row


def test_software_decision_provenance_extension_populated(client, make_token):
    """ShadyCoupons (not wanted, extension) sources decided_by from
    tenant_extension_policies.approved_by - unlike an application policy
    row, it CAN carry a real value, and it must render verbatim."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "ShadyCoupons")
    assert "admin@example.com" in row
    assert "15 Jul 2026" in row
    assert "Elevated risk, blocked pending review." in row


def test_software_decision_provenance_extension_undecided(client, make_token):
    """MysteryHelper (waiting, extension, unreviewed) has no decision
    record - same "Undecided" treatment as an application row, so the
    behaviour holds across both kinds, not just applications."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "MysteryHelper")
    assert "No decision recorded yet" in row


def test_software_decision_provenance_unrecognised_group_renders(client, make_token):
    """OddPolicy sits in the "state not recognised" group - decision
    provenance must still render there, not just in waiting/not_wanted/
    approved."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "OddPolicy")
    assert "Who decided was not recorded" in row
    assert "11 Sep 2026" in row


# PAT-1832: version_count and macOS codesign signing state (team_id/
# signed_by/notarized), added to GET /v1/portal/applications (all four
# new fields) and GET /v1/portal/extensions (version_count only) by
# PAT-1799. version_count is an exact, always-confident distinct-version
# count (0 only when device_count is 0, never null). The signing fields
# are application-only - extensions never carry them, not even as null -
# and signed_by null means genuinely unknown (also the permanent shape of
# every Windows row today, PAT-1828), never "Unsigned".


def test_installs_label_zero_versions_omits_suffix():
    from main import _installs_label

    assert _installs_label(0, 0) == "0 devices"


def test_installs_label_one_version_omits_suffix():
    from main import _installs_label

    assert _installs_label(5, 1) == "5 devices"
    assert _installs_label(1, 1) == "1 device"


def test_installs_label_multiple_versions_states_the_count():
    from main import _installs_label

    assert _installs_label(4, 2) == "4 devices on 2 versions"


def test_signing_state_extension_never_computed_even_if_fields_supplied():
    """Defence in depth: even if a caller mistakenly threaded signing
    fields onto an extension row, _software_row must not surface them -
    extensions never carry signing data, not even a null placeholder."""
    from main import _software_row

    row = _software_row(
        "X", "extension", 1, "identifier_match", "not_available",
        version_count=1, team_id="ABC", signed_by="Someone", notarized=True,
    )
    assert row["signing_state"] is None
    assert row["signing_label"] is None
    assert row["signing_pill_class"] is None


def test_signing_state_application_unknown_never_reads_as_unsigned():
    from main import _software_row

    row = _software_row(
        "X", "application", 1, "identifier_match", "not_available",
        signed_by=None, notarized=None,
    )
    assert row["signing_state"] == "unknown"
    assert row["signing_label"] == "Unknown"
    assert "Unsigned" not in row["signing_label"]


def test_signing_state_application_explicit_false_distinct_from_genuinely_unknown():
    # notarized is a real platform tri-state (notarizedTriState in
    # app_policy_drift.go): True = at least one device confirmed notarized,
    # False = at least one device explicitly reported notarized=false with
    # none confirming true (real negative evidence), None = no device
    # carried a notarized signal at all (no evidence either way). These
    # must render as two distinct labels -- collapsing them would claim
    # positive knowledge ("not notarized") the platform doesn't have for
    # the None case.
    from main import _software_row

    explicit_false = _software_row(
        "X", "application", 1, "identifier_match", "not_available",
        signed_by="Acme", notarized=False,
    )
    genuinely_unknown = _software_row(
        "Y", "application", 1, "identifier_match", "not_available",
        signed_by="Acme", notarized=None,
    )
    assert explicit_false["signing_state"] == "not_notarized"
    assert explicit_false["signing_label"] == "Signed, not notarized"
    assert genuinely_unknown["signing_state"] == "notarization_unknown"
    assert genuinely_unknown["signing_label"] == "Signed, notarization unknown"
    assert explicit_false["signing_label"] != genuinely_unknown["signing_label"]


def test_signing_state_application_notarized():
    from main import _software_row

    row = _software_row(
        "X", "application", 1, "identifier_match", "not_available",
        signed_by="Acme", notarized=True,
    )
    assert row["signing_state"] == "notarized"
    assert row["signing_label"] == "Signed & notarized"


def test_software_version_count_zero_omits_suffix(client, make_token):
    """GhostApp has 0 devices and version_count 0 - must read as "0
    devices", never "0 devices on 0 versions"."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "GhostApp")
    assert "0 devices" in row
    assert "on 0 versions" not in row


def test_software_version_count_one_omits_suffix(client, make_token):
    """MysteryApp has 5 devices on exactly 1 version - "on 1 version"
    reads as noise and must not appear."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "MysteryApp")
    assert "5 devices" in row
    assert "on 1 version" not in row
    installs_cell = row.split('data-label="Installs"', 1)[1].split("</td>", 1)[0]
    assert "version" not in installs_cell
    assert "Installed versions: Not reported" in row


def test_software_version_count_multiple_states_versions(client, make_token):
    """TorrentBox has 4 devices on 2 distinct versions - both numbers must
    render together, legibly."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "TorrentBox")
    assert "4 devices on 2 versions" in row


def test_software_extension_version_count_multiple(client, make_token):
    """ShadyCoupons (extension) has 2 devices on 2 versions - the same
    version-count rendering applies to extensions, not just applications."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "ShadyCoupons")
    assert "2 devices on 2 versions" in row


def test_software_extension_version_count_one_omits_suffix(client, make_token):
    """TeamChat (extension) has 5 devices on exactly 1 version."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "TeamChat")
    assert "5 devices" in row
    assert "on 1 version" not in row


def test_software_signed_and_notarized_badge_renders(client, make_token):
    """TorrentBox is signed and notarized - a clear positive signal, and
    the identity (signed_by + team_id) is kept as real forensic information
    rather than discarded once the badge state is decided."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "TorrentBox")
    assert 'class="signing signing--notarized"' in row
    assert "Signed &amp; notarized" in row
    assert "Torrent Software LLC" in row
    assert "TORR12345X" in row


def test_software_signed_not_notarized_badge_renders_for_explicit_false(client, make_token):
    """CorpVPN is signed with notarized explicitly False."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "CorpVPN")
    assert 'class="signing signing--not_notarized"' in row
    assert "Signed, not notarized" in row
    assert "Acme Networks" in row


def test_software_notarization_unknown_badge_distinct_from_explicit_false(client, make_token):
    """PhantomTool is signed but notarized is genuinely unknown (null, not
    false) - it must read a distinct "notarization unknown" badge, never
    the same "signed, not notarized" label an explicit false gets (that
    would claim positive knowledge the platform doesn't have), and never
    crash on a missing value."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "PhantomTool")
    assert 'class="signing signing--notarization_unknown"' in row
    assert "Signed, notarization unknown" in row
    assert "Signed, not notarized" not in row
    assert "Phantom Co" in row


def test_software_unknown_signing_never_reads_as_unsigned(client, make_token):
    """MysteryApp has no signing evidence at all (a genuine macOS gap, not
    a Windows row) - it must render "Unknown", never "Unsigned"."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "MysteryApp")
    assert 'class="signing signing--unknown"' in row
    assert "Unknown" in row


def test_software_windows_row_unknown_signing_is_the_documented_gap(client, make_token):
    """GuessWho is a Windows-platform row - team_id/signed_by/notarized are
    permanently null there (PAT-1828, the current Windows collector never
    reports them). This must render the same honest "Unknown" state as any
    other unknown row, never a Windows-specific "Unsigned" fallback."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "GuessWho")
    assert 'class="signing signing--unknown"' in row
    assert "Unknown" in row


def test_software_unrecognised_group_signing_badge_renders(client, make_token):
    """OddPolicy sits in the "state not recognised" group - the signing
    badge must still render there, not just in waiting/not_wanted/
    approved."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    row = _row(resp.text, "OddPolicy")
    assert 'class="signing signing--unknown"' in row


def test_software_extension_rows_never_show_a_signing_badge(client, make_token):
    """Extensions carry no signing data at all - not even a null
    placeholder - so no extension row may render any of the three signing
    pill states, in any group."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    for ext in EXTENSIONS["extensions"]:
        if ext["approval_state"] == "ignored":
            continue  # rendered only in the quiet fourth-line list, no row
        row = _row(resp.text, ext["name"])
        assert "pill-signed-ok" not in row
        assert "pill-signed-warn" not in row
        assert "pill-signed-unknown" not in row


def test_software_unsigned_never_appears_anywhere_on_the_page(client, make_token):
    """"Unsigned" is never the right word for a null signing field - it
    claims positive knowledge (this software was checked and found
    unsigned) the platform doesn't have. Only "Unknown" is honest."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    assert "Unsigned" not in resp.text
