"""PAT-2163: /software's filter bar - a Type <select> and an Approval
checkbox <details> popover (templates/_macros.html's filter_bar macro)
replacing the two rows of segmented-tab boxes that used to eat ~540px of a
phone screen before any software showed (Andy, live, 2026-09-25, screenshot
on PAT-2163).

Covers what test_software.py and test_pat2008_software_approvals.py don't
already: `?approval=` comma-list parsing (main.py's
_software_approval_filter), the legacy `?decision=` single-value alias,
zero-count options being left out of the dropdowns, unknown values being
ignored (never reflected unescaped), the active-filter chips' remove URLs,
and the approval-write return-path carrying the new params while staying
path-restricted (main.py's _approval_return_to - PAT-2008's own
test_return_to_cannot_leave_the_software_page already guards the generic
path restriction; this file adds the type/approval-specific coverage the
ticket's Done-when calls out as security-relevant).

Red-proof: every assertion below fails against origin/main (11c5cc8) -
main.py has no _software_approval_filter/_software_filter_bar_view/
`?approval=` handling at all yet, and templates/software.html still renders
the old two-segmented-control markup this file's HTML assertions don't
match. See the ticket report for the captured red output.
"""

import html
import json
import re
from urllib.parse import parse_qs, urlsplit

import main
from tests.conftest import EXTENSIONS, STUB_STATE


def _headers(token):
    return {"Cf-Access-Jwt-Assertion": token}


def _get(client, token, path="/software"):
    return client.get(path, headers=_headers(token))


def _type_select(page_html):
    """The Type <select>...</select> block (PAT-2163)."""
    start = page_html.index('<select id="software-search-type"')
    end = page_html.index("</select>", start) + len("</select>")
    return page_html[start:end]


def _approval_dropdown(page_html):
    """The Approval <details>...</details> block (PAT-2163) - checked
    against, not the whole page, so a chip or pill elsewhere on the page
    that happens to share an option's label text can't produce a false
    pass/fail."""
    start = page_html.index('<details class="filter-dropdown"')
    end = page_html.index("</details>", start) + len("</details>")
    return page_html[start:end]


def _chips(page_html):
    """Every rendered filter chip as (href, label_text), in document order,
    "Clear all" included. The href is HTML-unescaped (Jinja autoescapes the
    `&` joining two query params to `&amp;` in the attribute, same as any
    browser's own attribute parser would undo before using it as a URL)."""
    block_start = page_html.index('<div class="filter-chips"')
    block_end = page_html.index("</div>", block_start) + len("</div>")
    block = page_html[block_start:block_end]
    return [(html.unescape(href), label) for href, label in
            re.findall(r'<a class="filter-chip[^"]*" href="([^"]*)">([^<]*)', block)]


# ── ?approval= parsing: comma list, repeated params, dedup, order ────────

def test_approval_comma_list_selects_multiple_groups(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?approval=waiting,not_wanted")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial="waiting,not_wanted"' in dropdown
    assert '<input type="checkbox" name="approval" value="waiting" checked>' in dropdown
    assert '<input type="checkbox" name="approval" value="not_wanted" checked>' in dropdown
    assert '<input type="checkbox" name="approval" value="approved" checked>' not in dropdown


def test_approval_repeated_params_same_as_comma_list(client, make_token):
    """A plain HTML form with several checked boxes of the same name posts
    one `approval=` per box (no JS) - main.py must read that the same way
    as the JS layer's single comma-joined param."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?approval=waiting&approval=not_wanted")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial="waiting,not_wanted"' in dropdown


def test_approval_dedupes_repeated_value(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?approval=not_wanted,waiting,not_wanted")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    # Only two boxes end up checked - "not_wanted" given twice is not
    # double-counted - rendered in the dropdown's own fixed display order
    # (main.py's SOFTWARE_APPROVAL_FILTER_OPTIONS), which the given-order
    # dedup above still feeds correctly either way.
    assert 'data-initial="waiting,not_wanted"' in dropdown
    assert dropdown.count(" checked>") == 2


# ── legacy ?decision= alias (PAT-1798's old single-select) ───────────────

def test_legacy_decision_param_maps_into_approval(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?decision=waiting")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial="waiting"' in dropdown
    assert '<input type="checkbox" name="approval" value="waiting" checked>' in dropdown


def test_legacy_decision_all_means_no_filter(client, make_token):
    """The old segmented control's "All" tab posted ?decision=all (never a
    real group key) - must land on the unfiltered state, not a filter on
    the literal string "all"."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?decision=all")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial=""' in dropdown


def test_new_approval_param_wins_over_legacy_decision_when_both_present(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?decision=ignored&approval=waiting")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial="waiting"' in dropdown


# ── unknown values ignored, never reflected unescaped ─────────────────────

def test_unknown_approval_values_are_dropped_not_reflected(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?approval=waiting,<script>alert(1)</script>,bogus")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial="waiting"' in dropdown
    assert "<script>alert(1)</script>" not in resp.text
    assert "bogus" not in dropdown


def test_all_unknown_approval_values_falls_back_to_unfiltered(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?approval=nonsense")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert 'data-initial=""' in dropdown


# ── zero-count options are left out (never a stale/misleading "(0)") ─────

def test_zero_count_approval_option_is_hidden(client, make_token, monkeypatch):
    """OldTheme is the fixture's only ignored-bucket row (see
    test_software.py's module docstring); with it removed, "ignored" has
    zero rows and its checkbox must not render at all."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(
        EXTENSIONS, "extensions",
        [e for e in EXTENSIONS["extensions"] if e.get("name") != "OldTheme"],
    )
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert "Ignored" not in dropdown
    assert 'name="approval" value="ignored"' not in dropdown
    # The non-zero groups are unaffected. (PAT-2255: the options use the
    # one approval vocabulary a row shows - Unreviewed, not "Waiting on a
    # decision".)
    assert "Unreviewed" in dropdown
    assert "Approved" in dropdown


def test_zero_count_type_option_is_hidden(client, make_token, monkeypatch):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(EXTENSIONS, "extensions", [])
    monkeypatch.setitem(EXTENSIONS, "total", 0)
    resp = _get(client, token, "/software")
    assert resp.status_code == 200
    select = _type_select(resp.text)
    assert "Extensions" not in select
    assert "Applications" in select
    assert "All types" in select


def test_a_selected_zero_count_option_stays_visible(client, make_token, monkeypatch):
    """Filtering a group down to zero rows (e.g. an approval filter combined
    with a search that happens to leave nothing) must not make the active
    filter itself vanish from its own dropdown - a customer could no longer
    see what they picked, or remove it via the chip that still points at
    it. Zeroing "ignored" out entirely, then asking for exactly that group,
    proves the currently-selected option survives the zero-count hide."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(
        EXTENSIONS, "extensions",
        [e for e in EXTENSIONS["extensions"] if e.get("name") != "OldTheme"],
    )
    resp = _get(client, token, "/software?approval=ignored")
    assert resp.status_code == 200
    dropdown = _approval_dropdown(resp.text)
    assert '<input type="checkbox" name="approval" value="ignored" checked>' in dropdown
    assert "Ignored (0)" in dropdown


# ── chips: correct remove URLs, other params untouched ────────────────────

def test_chips_render_for_type_and_each_approval_value(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=application&approval=waiting,not_wanted")
    assert resp.status_code == 200
    chips = _chips(resp.text)
    labels = [label for _, label in chips]
    assert "Applications" in labels
    assert "Unreviewed" in labels
    assert "Unapproved" in labels
    assert "Clear all" in labels


def test_type_chip_remove_url_drops_only_type(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=application&approval=waiting,not_wanted")
    chips = dict((label, href) for href, label in _chips(resp.text))
    href = chips["Applications"]
    parsed = parse_qs(urlsplit(href).query)
    assert urlsplit(href).path == "/software"
    assert "type" not in parsed
    assert parsed["approval"] == ["waiting,not_wanted"]


def test_approval_chip_remove_url_drops_only_that_value(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?type=application&approval=waiting,not_wanted")
    chips = dict((label, href) for href, label in _chips(resp.text))
    href = chips["Unreviewed"]
    parsed = parse_qs(urlsplit(href).query)
    assert parsed["type"] == ["application"]
    assert parsed["approval"] == ["not_wanted"]


def test_clear_all_drops_every_filter_but_keeps_unrelated_params(client, make_token):
    """PAT-2163 (orchestrator follow-up): Publisher and minimum-devices
    joined the filter bar, so Clear all now drops those too, alongside
    type/approval/decision/unreviewed. PAT-2255: search is part of the
    filter state now (read from the URL into the search box), so Clear all
    drops it too; a param the bar does not own (the inventory page size)
    rides through untouched."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(
        client, token,
        "/software?type=application&approval=waiting&publisher=Acme"
        "&min_devices=3&unreviewed=1&search=Archive&limit=50",
    )
    chips = dict((label, href) for href, label in _chips(resp.text))
    href = chips["Clear all"]
    parsed = parse_qs(urlsplit(href).query)
    assert "type" not in parsed
    assert "approval" not in parsed
    assert "publisher" not in parsed
    assert "min_devices" not in parsed
    assert "unreviewed" not in parsed
    assert "search" not in parsed
    assert parsed["limit"] == ["50"]


def test_no_active_filters_means_no_chips(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software")
    assert '<div class="filter-chips"' not in resp.text


# ── the approval-write return path (security-relevant) ───────────────────

def test_return_to_preserves_type_and_approval_together():
    raw = "/software?type=application&approval=waiting,not_wanted"
    result = main._approval_return_to(raw)
    # urlencode re-escapes the comma inside the approval value to %2C - a
    # different valid encoding of the exact same query, not a dropped or
    # mangled value (parse_qs decodes either form identically).
    assert urlsplit(result).path == "/software"
    assert parse_qs(urlsplit(result).query) == parse_qs(urlsplit(raw).query)


def test_return_to_preserves_type_and_approval_alongside_other_filters():
    raw = "/software?type=extension&approval=ignored&publisher=Acme&min_devices=3&unreviewed=1"
    result = main._approval_return_to(raw)
    assert urlsplit(result).path == "/software"
    assert parse_qs(urlsplit(result).query) == parse_qs(urlsplit(raw).query)


def test_return_to_strips_only_the_approval_result_token():
    raw = "/software?type=application&approval=waiting&approval_result=abc123"
    result = main._approval_return_to(raw)
    assert result == "/software?type=application&approval=waiting"


def test_return_to_with_type_and_approval_still_cannot_leave_the_software_page():
    """PAT-2008's test_return_to_cannot_leave_the_software_page already
    guards the generic path restriction; this repeats it specifically with
    the new type/approval params riding along, since those are exactly what
    an attacker-crafted return_to on a filtered view would carry."""
    for target in (
        "https://evil.example/?type=application&approval=waiting",
        "//evil.example/software?type=application&approval=waiting",
        "/devices?type=application&approval=waiting",
        "\\\\evil.example?type=application&approval=waiting",
    ):
        result = main._approval_return_to(target)
        parsed = urlsplit(result)
        assert parsed.path == "/software", target
        assert not parsed.netloc, target
        assert parsed.scheme == "", target


def test_approval_write_from_a_filtered_view_lands_back_on_it(client, make_token):
    """End to end: an admin approving from a filtered /software view is
    redirected back to that same filtered view (type + approval both),
    exactly as _approval_return_to promises above."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    return_to = "/software?type=application&approval=waiting"
    resp = client.post(
        "/software/approvals",
        content=(
            f"csrf_token={main._csrf_token(token)}&return_to={return_to.replace('&', '%26')}"
            "&state=approved&item=" + json.dumps({
                "type": "application", "platform": "macos",
                "identifier": "com.example.mysteryapp",
            })
        ),
        headers={
            **_headers(token), "Origin": "https://testserver",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith(
        "/software?type=application&approval=waiting&approval_result="
    )


# ── orchestrator follow-up: Publisher + minimum-devices join the bar ──────

def test_publisher_option_list_renders_all_publishers_and_unknown(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token)
    assert resp.status_code == 200
    start = resp.text.index('<select id="software-search-publisher"')
    end = resp.text.index("</select>", start) + len("</select>")
    select = resp.text[start:end]
    assert '<option value="" selected>All publishers</option>' in select
    assert '<option value="__unknown__">Publisher not known</option>' in select
    # Publisher comes from the macOS signing identity - a title, not a
    # standalone paragraph on the page (moved off .toolbar-hint).
    assert 'title="Publisher comes from the macOS signing identity' in select
    assert "Publisher comes from the macOS signing identity" not in resp.text[:start]


def test_publisher_query_value_selects_and_chips(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?publisher=Acme%20Networks")
    assert resp.status_code == 200
    start = resp.text.index('<select id="software-search-publisher"')
    end = resp.text.index("</select>", start) + len("</select>")
    assert '<option value="Acme Networks" selected>Acme Networks</option>' in resp.text[start:end]
    chips = dict((label, href) for href, label in _chips(resp.text))
    assert chips["Publisher: Acme Networks"]
    parsed = parse_qs(urlsplit(chips["Publisher: Acme Networks"]).query)
    assert "publisher" not in parsed


def test_min_devices_field_is_inside_more_filters_and_chips(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?min_devices=5")
    assert resp.status_code == 200
    more_start = resp.text.index("More filters")
    more_end = resp.text.index("</details>", more_start)
    more_block = resp.text[more_start:more_end]
    assert 'data-filter-min-devices' in more_block
    assert 'value="5"' in more_block
    chips = dict((label, href) for href, label in _chips(resp.text))
    assert chips["At least 5 devices"]
    parsed = parse_qs(urlsplit(chips["At least 5 devices"]).query)
    assert "min_devices" not in parsed


def test_min_devices_singular_device_label(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/software?min_devices=1")
    chips = dict((label, href) for href, label in _chips(resp.text))
    assert "At least 1 device" in chips
    assert "At least 1 devices" not in chips


# ── orchestrator follow-up: "Unreviewed only" removed, Select all shown ──

def test_unreviewed_checkbox_no_longer_renders(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token)
    assert "data-filter-unreviewed" not in resp.text
    assert "Unreviewed only" not in resp.text


def test_select_all_shown_is_in_the_table_header(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token)
    thead_start = resp.text.index("<thead>")
    thead_end = resp.text.index("</thead>")
    thead = resp.text[thead_start:thead_end]
    assert 'data-select-visible' in thead
    # Not the old standalone toolbar checkbox location.
    assert "software-filters" not in resp.text


def test_viewer_sees_no_select_column(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    assert "data-select-visible" not in resp.text
    assert '<col class="software-col-select">' not in resp.text


# ── orchestrator follow-up: bulk bar hidden until something is selected ──

def test_bulk_bar_carries_the_js_progressive_enhancement_hook(client, make_token):
    """The CSS hides .bulk-bar.js-bulk:not(.is-active); js-bulk is only ever
    added by static/js/portal.js at runtime, so the server-rendered markup
    itself must not carry that class - a JS-less browser keeps the bar
    visible (portal.css's own comment on this rule)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token)
    start = resp.text.index('id="approval-form"')
    tag_end = resp.text.index(">", start)
    opening_tag = resp.text[resp.text.rindex("<form", 0, start):tag_end]
    assert "js-bulk" not in opening_tag
    assert "is-active" not in opening_tag


# ── orchestrator's live desktop screenshot: extension Platform + type tag ─

def test_extension_platform_column_shows_browser_not_no_platform(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token)
    assert resp.status_code == 200
    row_start = resp.text.index("ShadyCoupons")
    row_end = resp.text.index("</tr>", row_start)
    row = resp.text[row_start:row_end]
    assert "Chrome" in row
    assert "No platform" not in row


def test_extension_with_unknown_browser_reads_browser_extension(client, make_token, monkeypatch):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    weird = dict(EXTENSIONS["extensions"][0])
    weird["extension_id"] = "no-browser-ext-id"
    weird["name"] = "NoBrowserExt"
    weird["browser"] = "opera"  # not in APPROVAL_BROWSERS/BROWSER_DISPLAY_LABELS
    monkeypatch.setitem(EXTENSIONS, "extensions", [*EXTENSIONS["extensions"], weird])
    resp = _get(client, token)
    row_start = resp.text.index("NoBrowserExt")
    row_end = resp.text.index("</tr>", row_start)
    row = resp.text[row_start:row_end]
    assert "Browser extension" in row
    assert "No platform" not in row


def test_extension_type_tag_is_muted_not_signal_orange(client, make_token):
    """Andy's live desktop review: the orange (--uv-deep) Extension tag read
    as a warning, not a neutral type label - portal-rubric.md T6 (signal
    orange for action/selection only, never status)."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    css_text = (root / "static" / "css" / "portal.css").read_text()
    match = re.search(r"\.type-tag--ext\s*\{([^}]*)\}", css_text)
    assert match, "no .type-tag--ext rule found"
    assert "--uv-deep" not in match.group(1)
    assert "var(--mute)" in match.group(1)


def test_empty_approval_param_does_not_block_the_legacy_decision_param():
    # Review finding: `?approval=&decision=waiting` used to read the empty
    # approval value as "given", so the legacy mapping never ran.
    from starlette.requests import Request

    import main

    req = Request({"type": "http", "query_string": b"approval=&decision=waiting", "headers": []})
    assert main._software_approval_filter(req) == ["waiting"]
