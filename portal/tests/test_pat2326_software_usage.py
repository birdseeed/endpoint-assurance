"""PAT-2326: usage on /software, and a usage filter.

PAT-1870 showed the platform's usage verdict (Used, Unused, Not metered) per
product with its last-used date; the PAT-2120 redesign dropped it, leaving
only a tooltip that the narrow layouts never show, so there was no
tenant-wide way to see unused software. This puts the verdict back on each
row (Evidence cell, under the date; the Installs tooltip carries it too, since
the Evidence column is hidden below 1680px) and adds `?usage=unused,used,
unmetered` to the filter state, the filter bar and the URL.

The rules under test:

  * the row renders the platform's `usage_state` as sent and never
    reconstructs a verdict (Unused with its last use, Used with its date, Not
    metered, and the platform's own label for mixed, stale and unknown);
  * the filter compares that one field. Not metered, mixed, stale, unknown,
    and a row the platform said nothing about (a governance-only row, an
    unreadable inventory) are never "unused";
  * the filter is the URL: it seeds the bar, survives paging, round-trips
    through chips, and an unreadable inventory leaves it out of force with a
    notice rather than presenting an unfiltered list as filtered.

The stub inventory (tests/conftest.py SOFTWARE_INVENTORY) carries one product
per usage state: ArchiveTool unused, UsedTool used, MeteringGap unmetered,
PartialEvidence mixed, OldMetering stale, UnknownEvidence unknown.
"""

import copy
import html
import re
from urllib.parse import parse_qs, urlsplit

from tests.conftest import DEVICE_SOFTWARE, SOFTWARE_INVENTORY, STUB_STATE
from tests.test_pat2255_software_review import (
    _active_filters,
    _filter_bar,
    _get,
    _row,
    _row_hidden,
    _rows,
    _visible,
    _visible_names,
)

USAGE_LINE_RE = re.compile(
    r'<span class="cell-subtle cell-usage cell-usage--(\w+)" title="([^"]*)">'
    r'(.*?)</span>(?=\s*</td>)',
    re.DOTALL,
)
ALL_INVENTORY_NAMES = {
    "ArchiveTool", "UsedTool", "MeteringGap", "PartialEvidence", "OldMetering",
    "UnknownEvidence",
}


def _plain(fragment: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", fragment)).strip()


def _usage_line(body: str, name: str):
    """(tone, title, visible text) of a row's usage line, or None when it has
    none."""
    match = USAGE_LINE_RE.search(_row(body, name))
    if match is None:
        return None
    return match.group(1), html.unescape(match.group(2)), _plain(match.group(3))


def _usage_attr(body: str, name: str) -> str:
    match = re.search(r'data-filter-usage="([^"]*)"', _row(body, name))
    assert match, f"{name} row has no data-filter-usage attribute"
    return match.group(1)


def _inventory_with(**changes_by_name):
    """A copy of the stub inventory with fields overridden per product name."""
    data = copy.deepcopy(SOFTWARE_INVENTORY)
    for product in data["products"]:
        for key, value in changes_by_name.get(product["name"], {}).items():
            if value is _DROP:
                product.pop(key, None)
            else:
                product[key] = value
    return data


_DROP = object()


# ── 1. Every usage state renders what the platform said ───────────────────

def test_each_usage_state_renders_the_platforms_verdict(client, make_token):
    body = _get(client, make_token()).text
    assert _usage_line(body, "ArchiveTool") == (
        "warn", "Unused · last used 01 Nov 2026", "Unused · last used 01 Nov 2026")
    assert _usage_line(body, "UsedTool") == (
        "ok", "Used · 19 Sep 2026", "Used · 19 Sep 2026")
    assert _usage_line(body, "MeteringGap") == (
        "muted", "Not metered", "Not metered")
    assert _usage_line(body, "PartialEvidence") == (
        "muted", "Mixed evidence", "Mixed evidence")
    assert _usage_line(body, "OldMetering") == (
        "warn", "Stale evidence", "Stale evidence")
    assert _usage_line(body, "UnknownEvidence") == (
        "muted", "Unknown evidence", "Unknown evidence")


def test_unused_without_a_launch_timestamp_says_no_use_recorded(client, make_token):
    """The platform sends a null last_used_at for an authoritatively
    never-launched product; the line says that, and does not invent a date."""
    STUB_STATE["software_inventory_data"] = _inventory_with(
        ArchiveTool={"last_used_at": None})
    body = _get(client, make_token()).text
    assert _usage_line(body, "ArchiveTool")[2] == "Unused · no use recorded"


def test_used_without_a_last_use_date_says_only_used(client, make_token):
    STUB_STATE["software_inventory_data"] = _inventory_with(
        UsedTool={"last_used_at": None})
    body = _get(client, make_token()).text
    assert _usage_line(body, "UsedTool")[2] == "Used"


def test_a_last_use_date_is_kept_on_one_line(client, make_token):
    """The date is a nowrap span (the walker's `break` check and rubric L13
    both want a date-shaped string on one line)."""
    body = _get(client, make_token()).text
    line = USAGE_LINE_RE.search(_row(body, "ArchiveTool")).group(3)
    assert '<span class="nowrap">01 Nov 2026</span>' in line


def test_a_row_the_platform_said_nothing_about_has_no_usage_line(client, make_token):
    """Governance-only rows (no matching inventory product) carry no verdict.
    They must read as nothing at all, never as Unused."""
    body = _get(client, make_token()).text
    for name in ("MysteryApp", "Slack", "TorrentBox", "ShadyCoupons"):
        assert _usage_line(body, name) is None, name
        assert _usage_attr(body, name) == "none", name
        assert "Unused" not in _plain(_row(body, name)), name


def test_the_installs_tooltip_carries_the_usage_line(client, make_token):
    """The Evidence column is hidden below 1680px, so the always-visible
    Installs cell's tooltip says it too."""
    body = _get(client, make_token()).text
    match = re.search(r'<span class="cell-line" title="([^"]*)"', _row(body, "ArchiveTool"))
    assert "Usage: Unused · last used 01 Nov 2026" in html.unescape(match.group(1))
    match = re.search(r'<span class="cell-line" title="([^"]*)"', _row(body, "MysteryApp"))
    assert "Usage" not in html.unescape(match.group(1))


def test_usage_wording_has_no_em_dash_or_ticket_reference(client, make_token):
    body = _get(client, make_token()).text
    for name in ALL_INVENTORY_NAMES:
        line = _usage_line(body, name)
        assert "—" not in line[2] and "PAT-" not in line[2], name


# ── 2. The filter uses the platform's usage_state and nothing else ────────

def test_usage_unused_shows_only_the_platforms_unused_products(client, make_token):
    """Red on main before this ticket: `usage` was ignored, so every row was
    visible."""
    body = _get(client, make_token(), "/software?usage=unused").text
    assert _visible_names(body) == ["ArchiveTool"]
    hidden = {
        re.search(r'class="product-name[^"]*"[^>]*>([^<]*)<', row).group(1)
        for row in _rows(body) if _row_hidden(row)
    }
    # Not metered, used, mixed, stale, unknown and every governance-only row
    # are excluded, never read as unused.
    assert {"MeteringGap", "UsedTool", "PartialEvidence", "OldMetering",
            "UnknownEvidence", "MysteryApp", "Slack", "TorrentBox"} <= hidden


def test_usage_used_and_unmetered_each_show_only_their_own(client, make_token):
    token = make_token()
    used = _get(client, token, "/software?usage=used").text
    assert _visible_names(used) == ["UsedTool"]
    unmetered = _get(client, token, "/software?usage=unmetered").text
    assert _visible_names(unmetered) == ["MeteringGap"]


def test_several_usage_words_are_a_union_read_like_approval(client, make_token):
    token = make_token()
    comma = _get(client, token, "/software?usage=unused,used").text
    repeated = _get(client, token, "/software?usage=unused&usage=used").text
    assert set(_visible_names(comma)) == {"ArchiveTool", "UsedTool"}
    assert set(_visible_names(repeated)) == {"ArchiveTool", "UsedTool"}


def test_every_row_carries_its_usage_state_for_the_browser_side_filter(client, make_token):
    body = _get(client, make_token()).text
    assert {name: _usage_attr(body, name) for name in ALL_INVENTORY_NAMES} == {
        "ArchiveTool": "unused", "UsedTool": "used", "MeteringGap": "unmetered",
        "PartialEvidence": "mixed", "OldMetering": "stale", "UnknownEvidence": "unknown",
    }


def test_the_usage_filter_composes_with_the_other_filters(client, make_token):
    token = make_token()
    body = _get(client, token, "/software?usage=unused&type=extension").text
    assert _visible_names(body) == []
    body = _get(client, token, "/software?usage=unused&type=application").text
    assert _visible_names(body) == ["ArchiveTool"]
    body = _get(client, token, "/software?usage=unused&approval=approved").text
    assert _visible_names(body) == []


def test_a_product_that_is_only_partly_unused_is_not_unused(client, make_token):
    """The platform calls a product unused only when every installation is
    fresh, metered and unused; a mixed one (some unused installations) is
    not in the filter however many of its installations are unused."""
    body = _get(client, make_token(), "/software?usage=unused").text
    assert "PartialEvidence" not in _visible_names(body)
    assert _usage_attr(body, "PartialEvidence") == "mixed"


# ── 3. Missing evidence is never unused ───────────────────────────────────

def test_a_product_with_no_usage_state_fails_the_read_soft_and_is_never_unused(
        client, make_token):
    """The inventory contract requires usage_state; a product without one
    makes the whole evidence read unavailable (the established fail-soft),
    so no row can read Unused, and the usage filter says it is not in force
    instead of hiding everything or showing an unfiltered list as filtered."""
    STUB_STATE["software_inventory_data"] = _inventory_with(
        ArchiveTool={"usage_state": _DROP})
    body = _get(client, make_token(), "/software?usage=unused").text
    text = _visible(body)
    assert USAGE_LINE_RE.search(body) is None
    assert "Unused" not in text
    assert "Usage could not be read right now" in text
    assert "usage" not in _active_filters(body)
    assert 'data-row-filter="usage"' not in body
    # Not in force: the list is the full list, and it says why.
    assert "MysteryApp" in _visible_names(body)


def test_an_unreadable_inventory_leaves_the_usage_filter_out_of_force(client, make_token):
    STUB_STATE["mode"] = "software500"
    body = _get(client, make_token(), "/software?usage=unused").text
    text = _visible(body)
    assert "Usage could not be read right now" in text
    assert "usage" not in _active_filters(body)
    assert USAGE_LINE_RE.search(body) is None
    assert "Unused" not in text
    assert not [r for r in _rows(body) if _row_hidden(r)]


def test_the_usage_notice_is_absent_when_the_inventory_read_worked(client, make_token):
    body = _get(client, make_token(), "/software?usage=unused").text
    assert "Usage could not be read" not in _visible(body)
    assert "usage" in _active_filters(body)


# ── 4. The filter is the URL ──────────────────────────────────────────────

def test_usage_seeds_the_bar_chips_and_active_filters(client, make_token):
    body = _get(client, make_token(), "/software?usage=unused,used").text
    assert "usage" in _active_filters(body)
    bar = _filter_bar(body)
    fieldset = re.search(r'<fieldset[^>]*data-row-filter="usage"[^>]*>', bar).group(0)
    assert 'data-query-param="usage"' in fieldset
    assert 'data-initial="unused,used"' in fieldset
    assert re.search(r'name="usage" value="unused" checked', bar)
    assert re.search(r'name="usage" value="used" checked', bar)
    assert not re.search(r'name="usage" value="unmetered" checked', bar)
    chips = re.findall(r'<a class="filter-chip" href="([^"]*)">([^<]*)<', bar)
    assert [label for _href, label in chips] == ["Unused", "Used"]


def test_usage_chips_remove_one_word_and_clear_all_drops_the_filter(client, make_token):
    body = _get(client, make_token(), "/software?approval=waiting&usage=unused,used").text
    bar = _filter_bar(body)
    chips = dict(
        (label, html.unescape(href)) for href, label in
        re.findall(r'<a class="filter-chip" href="([^"]*)">([^<]*)<', bar))
    assert parse_qs(urlsplit(chips["Unused"]).query) == {
        "approval": ["waiting"], "usage": ["used"]}
    assert parse_qs(urlsplit(chips["Used"]).query) == {
        "approval": ["waiting"], "usage": ["unused"]}
    clear = re.search(r'<a class="filter-chip filter-chip--clear" href="([^"]*)"', bar).group(1)
    assert clear == "/software"


def test_the_round_trip_is_stable(client, make_token):
    """The URL a chip removes down to is itself a valid, stable state."""
    token = make_token()
    first = _get(client, token, "/software?usage=unused,used").text
    href = html.unescape(re.search(
        r'<a class="filter-chip" href="([^"]*)">Unused<', _filter_bar(first)).group(1))
    second = _get(client, token, href).text
    assert href == "/software?usage=used"
    assert _visible_names(second) == ["UsedTool"]


def test_unknown_usage_words_are_dropped_not_reflected(client, make_token):
    token = make_token()
    body = _get(client, token, "/software?usage=bogus").text
    # The bar's return_to carries the address bar as typed (re-validated on
    # every write); the page itself never shows the word.
    assert "bogus" not in _visible(body)
    assert 'class="filter-chips"' not in body
    assert "usage" not in _active_filters(body)
    assert not [r for r in _rows(body) if _row_hidden(r)]
    body = _get(client, token, "/software?usage=unused,mixed,stale,unknown").text
    assert _visible_names(body) == ["ArchiveTool"]
    assert 'data-initial="unused"' in _filter_bar(body)


def test_usage_options_carry_counts_of_the_rows_the_list_holds(client, make_token):
    body = _get(client, make_token()).text
    bar = _filter_bar(body)
    assert "<span>Unused (1)</span>" in bar
    assert "<span>Used (1)</span>" in bar
    assert "<span>Not metered or no evidence (1)</span>" in bar
    # Only the three words a person can act on are offered.
    assert bar.count('name="usage"') == 3


def test_a_zero_count_usage_option_is_left_out_unless_selected(client, make_token):
    STUB_STATE["software_inventory_data"] = _inventory_with(
        UsedTool={"usage_state": "mixed", "unused_installation_count": 1})
    token = make_token()
    plain = _filter_bar(_get(client, token).text)
    assert 'name="usage" value="used"' not in plain
    assert 'name="usage" value="unused"' in plain
    selected = _filter_bar(_get(client, token, "/software?usage=used").text)
    assert 'name="usage" value="used" checked' in selected
    assert "<span>Used (0)</span>" in selected


def test_paging_carries_the_usage_filter_and_says_what_it_covers(client, make_token):
    """The platform pages the inventory, and usage lives on it. Next and
    Previous keep the filter, and the page says which slice of the evidence
    its verdicts come from so a filtered list is never read as the whole
    estate's."""
    token = make_token()
    body = _get(client, token, "/software?usage=unused&limit=2").text
    text = _visible(body)
    assert "this page of it holds products 1 to 2 of 6" in text
    nav = body[body.index("inventory-pagination"):]
    next_href = html.unescape(re.search(r'href="([^"]*)">Next<', nav).group(1))
    assert parse_qs(urlsplit(next_href).query) == {
        "usage": ["unused"], "limit": ["2"], "offset": ["2"]}
    follow = _get(client, token, next_href).text
    assert "products 3 to 4 of 6" in _visible(follow)
    # A single page of evidence needs no such line.
    assert "this page of it holds" not in _visible(
        _get(client, token, "/software?usage=unused").text)
    # And without the filter there is nothing to qualify.
    assert "this page of it holds" not in _visible(
        _get(client, token, "/software?limit=2").text)


# ── 5. What was already there still works ─────────────────────────────────

def test_a_page_with_no_usage_filter_hides_nothing(client, make_token):
    body = _get(client, make_token()).text
    assert not [r for r in _rows(body) if _row_hidden(r)]
    assert "usage" not in _active_filters(body)
    assert "Usage could not be read" not in _visible(body)


def test_the_more_filters_panel_keeps_its_minimum_devices_field(client, make_token):
    bar = _filter_bar(_get(client, make_token()).text)
    assert "data-filter-min-devices" in bar
    assert bar.index("data-filter-min-devices") < bar.index('data-row-filter="usage"')


def test_the_usage_group_is_not_a_second_details_dropdown(client, make_token):
    """The approval popover is the bar's only `details[data-row-filter]`;
    the e2e suites select it by exactly that, so the usage group is a
    fieldset in the More filters panel."""
    bar = _filter_bar(_get(client, make_token()).text)
    assert len(re.findall(r"<details[^>]*data-row-filter", bar)) == 1


# ── 6. No usage evidence (PAT-2327's no_evidence_installation_count) ──────
#
# The platform counts installations on metered devices with no recorded last
# use as `no_evidence_installation_count`. They are never unused, and a
# product made only of them (or of them and unmetered installations) is
# `unmetered`. The portal says "No usage evidence" for those and keeps "Not
# metered" for devices that do not meter at all. An older platform omits the
# field, and then nothing changes.

def _no_evidence(count, **more):
    return _inventory_with(MeteringGap={"no_evidence_installation_count": count, **more})


def test_a_product_with_no_evidence_installations_says_no_usage_evidence(client, make_token):
    STUB_STATE["software_inventory_data"] = _no_evidence(1)
    body = _get(client, make_token()).text
    assert _usage_line(body, "MeteringGap") == (
        "muted", "No usage evidence", "No usage evidence")
    assert _usage_attr(body, "MeteringGap") == "unmetered"
    assert "Not metered" not in _plain(_row(body, "MeteringGap"))
    match = re.search(r'<span class="cell-line" title="([^"]*)"', _row(body, "MeteringGap"))
    assert "Usage: No usage evidence" in html.unescape(match.group(1))


def test_no_evidence_alongside_unmetered_installations_still_says_no_usage_evidence(
        client, make_token):
    """MeteringGap's one installation is unmetered; give it a second, on a
    metered device with no recorded use. The platform's count is the rule."""
    STUB_STATE["software_inventory_data"] = _no_evidence(
        1, installation_count=2, unmetered_installation_count=1,
        metered_installation_count=1)
    body = _get(client, make_token()).text
    assert _usage_line(body, "MeteringGap")[2] == "No usage evidence"


def test_an_absent_or_zero_no_evidence_count_keeps_not_metered(client, make_token):
    token = make_token()
    absent = _get(client, token).text
    assert "no_evidence_installation_count" not in SOFTWARE_INVENTORY["products"][1]
    assert _usage_line(absent, "MeteringGap")[2] == "Not metered"
    STUB_STATE["software_inventory_data"] = _no_evidence(0)
    zero = _get(client, token).text
    assert _usage_line(zero, "MeteringGap")[2] == "Not metered"


def test_no_evidence_never_changes_a_verdict_that_is_not_unmetered(client, make_token):
    """The count only chooses between two readings of `unmetered`. A product
    the platform calls mixed, or unused, reads as the platform said."""
    STUB_STATE["software_inventory_data"] = _inventory_with(
        PartialEvidence={"no_evidence_installation_count": 1},
        ArchiveTool={"no_evidence_installation_count": 1},
    )
    body = _get(client, make_token()).text
    assert _usage_line(body, "PartialEvidence")[2] == "Mixed evidence"
    assert _usage_line(body, "ArchiveTool")[2] == "Unused · last used 01 Nov 2026"


def test_the_unmetered_filter_includes_no_evidence_products_and_says_so(client, make_token):
    token = make_token()
    STUB_STATE["software_inventory_data"] = _no_evidence(1)
    body = _get(client, token, "/software?usage=unmetered").text
    assert _visible_names(body) == ["MeteringGap"]
    bar = _filter_bar(body)
    assert "<span>Not metered or no evidence (1)</span>" in bar
    chips = re.findall(r'<a class="filter-chip" href="([^"]*)">([^<]*)<', bar)
    assert [label for _href, label in chips] == ["Not metered or no evidence"]
    # ...and it is still not unused.
    unused = _get(client, token, "/software?usage=unused").text
    assert "MeteringGap" not in _visible_names(unused)


def test_a_malformed_no_evidence_count_fails_the_read_soft_not_the_page(client, make_token):
    """A present but impossible count is a contract fault: the evidence read
    is unavailable, as for any other bad count, and nothing reads as unused."""
    token = make_token()
    for bad in (-1, "1", True, 1.5):
        STUB_STATE["software_inventory_data"] = _no_evidence(bad)
        resp = _get(client, token, "/software?usage=unused")
        assert resp.status_code == 200, bad
        assert "Dated software evidence is temporarily unavailable" in _visible(resp.text), bad
        assert USAGE_LINE_RE.search(resp.text) is None, bad


def test_the_device_software_tab_says_no_usage_evidence_too(client, make_token, monkeypatch):
    token = make_token()
    products = copy.deepcopy(DEVICE_SOFTWARE["products"])
    not_metered = next(p for p in products if p["name"] == "NotMeteredApp")
    not_metered["no_evidence_installation_count"] = 1
    monkeypatch.setitem(DEVICE_SOFTWARE, "products", products)
    page = _get(client, token, "/devices/dev-mac-001/software").text
    row = re.search(
        r"<tr>(?:(?!</tr>).)*NotMeteredApp(?:(?!</tr>).)*</tr>", page, re.DOTALL).group(0)
    assert "No usage evidence" in row
    assert "Not metered" not in row
    assert "Unused" not in row


def test_the_device_software_tab_keeps_not_metered_when_the_field_is_absent(
        client, make_token):
    page = _get(client, make_token(), "/devices/dev-mac-001/software").text
    row = re.search(
        r"<tr>(?:(?!</tr>).)*NotMeteredApp(?:(?!</tr>).)*</tr>", page, re.DOTALL).group(0)
    assert "Not metered" in row
    assert "No usage evidence" not in row
