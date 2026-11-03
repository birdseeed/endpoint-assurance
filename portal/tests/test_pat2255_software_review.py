"""PAT-2255: /software is the review workspace (Andy's ruling of 28 September
2026: software review is done in the Software section, and PAT-2254 links
every Overview software count into a filtered /software).

Found walking the live page on 28 September 2026. Each block below is one
of the ticket's defects or review-flow requirements:

  1. one awaiting-decision count, the same source the Overview reads,
     stated plainly (no "at least" in the headline or any dropdown);
  2. one approval state per row, with signing as its own labelled column;
  3/4. no raw identifiers or "Identifier match" in the list; identifiers
     move to the product detail under a labelled "Identifiers" section;
  5. the "N new since your last review" banner opens a review queue with
     the right count;
  7. every filter is read from the URL, including the PAT-2254 Overview
     links (`new_days`, `urgency`) and `search`;
  8. the count does not move when the fail-soft inventory read fails;
  9/10. /homebrew uses the same filter bar, and a blank CVE cell never
     reads as clean;
  review flow: an approval write returns to the same filtered URL with the
     next row as the anchor.

Reuses tests/conftest.py's stub platform and fixtures throughout.
"""

import copy
import html
import json
import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlsplit

import main
from tests.conftest import (
    APPLICATIONS,
    HOMEBREW_FORMULAE,
    NEW_SOFTWARE_REPORT,
    OVERVIEW,
    OVERVIEW_CARDS,
    STUB_STATE,
)
from tests.test_pat2093_new_software import _new_software, _product

MSI_CODE = "{AC76BA86-1033-FF00-7760-BC15014EA700}"
# A hedged count: "at least 137 products", "All types (at least 137)". The
# "On at least N devices" filter label is a control, not a count.
HEDGED_COUNT_RE = re.compile(
    r"at least \d+ (?:products?|applications?|extensions?)|\(at least \d+\)", re.IGNORECASE)
AWAITING_RE = re.compile(r"(\d+) products? waiting (?:on|for) an approval decision")


def _get(client, token, path="/software"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


class _VisibleText(HTMLParser):
    """Text a customer can read: text nodes outside script/style, plus the
    title/aria-label/alt/placeholder attributes (the walker's own leak check
    reads the same set). Hidden-input values and data-* attributes are not
    customer-visible and are left out."""

    SKIP = {"script", "style", "template"}

    def __init__(self, attributes=True):
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0
        self._attributes = attributes

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        for name, value in attrs if self._attributes else ():
            if name in ("title", "aria-label", "alt", "placeholder") and value:
                self.parts.append(value)

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def _visible(body: str, attributes: bool = True) -> str:
    parser = _VisibleText(attributes)
    parser.feed(body)
    return " ".join(parser.parts)


def _rows(body: str) -> list[str]:
    return re.findall(r"<tr\b[^>]*data-approval-row[^>]*>.*?</tr>", body, re.DOTALL)


def _row(body: str, name: str) -> str:
    for row in _rows(body):
        if re.search(rf">\s*{re.escape(name)}\s*<", row):
            return row
    raise AssertionError(f"no row for {name!r}")


def _row_open_tag(row: str) -> str:
    return row[: row.index(">") + 1]


def _row_hidden(row: str) -> bool:
    tag = _row_open_tag(row)
    return "row-hide-filter" in tag or "row-hide-search" in tag


def _visible_names(body: str) -> list[str]:
    names = []
    for row in _rows(body):
        if _row_hidden(row):
            continue
        match = re.search(r'class="product-name[^"]*"[^>]*>([^<]*)<', row)
        assert match, "row has no product-name element"
        names.append(html.unescape(match.group(1)).strip())
    return names


def _approval_cell(row: str) -> str:
    match = re.search(r'<td class="cell-approval[^"]*".*?</td>', row, re.DOTALL)
    assert match, "row has no approval cell"
    return match.group(0)


def _filter_bar(body: str) -> str:
    start = body.index("data-filter-bar")
    start = body.rindex("<div", 0, start)
    return body[start:]


def _active_filters(body: str) -> set[str]:
    match = re.search(r'data-active-filters="([^"]*)"', body)
    assert match, "filter bar carries no data-active-filters attribute"
    return {f for f in match.group(1).split(",") if f}


def _apps_with(*rows):
    data = copy.deepcopy(APPLICATIONS)
    data["applications"].extend(rows)
    data["total"] = len(data["applications"])
    return data


def _undecided_app(name, identifier, platform="windows", **fields):
    row = {
        "type": "application", "name": name, "identifier": identifier,
        "platform": platform, "policy_state": "undecided", "enforcement_tier": "",
        "device_count": 3, "evidence_basis": "identifier_match",
        "identifier_matched_devices": 0, "name_matched_devices": 0,
        "removal_state": "not_available", "decided_by": None, "decided_at": None,
        "justification": None, "version_count": 1, "team_id": None,
        "signed_by": None, "notarized": None,
    }
    row.update(fields)
    return row


def _cards_with_products(n, state="value"):
    data = copy.deepcopy(OVERVIEW_CARDS)
    data["cards"]["software_awaiting_approval"]["state"] = state
    data["cards"]["software_awaiting_approval"]["values"] = {"products": n, "devices": 3}
    if state == "partial":
        data["cards"]["software_awaiting_approval"]["completeness"] = {
            "complete": False, "reason": "coverage_incomplete"}
    return data


# ── 1. One count, the same source as the Overview ─────────────────────────

def test_software_headline_and_overview_read_one_awaiting_figure(client, make_token):
    """The shared test PAT-2254 asked for: the Overview (Top 3 and the
    at-a-glance line) and /software's headline read the same figure, the
    platform card's values.products (9 in the default fixture), never the
    portal's own applications + extensions floor."""
    token = make_token()
    overview = _get(client, token, "/")
    software = _get(client, token, "/software")
    assert overview.status_code == 200 and software.status_code == 200
    overview_figures = set(AWAITING_RE.findall(_visible(overview.text)))
    software_figures = set(AWAITING_RE.findall(_visible(software.text)))
    assert overview_figures == {"9"}, overview_figures
    assert software_figures == {"9"}, software_figures


def test_software_and_overview_share_the_floor_when_the_card_is_unavailable(
        client, make_token):
    """Cards read fails: both pages fall back to the same governance floor
    (MysteryApp, GuessWho and MysteryHelper: 3), and /software says where
    its figure came from instead of presenting a floor as the estate-wide
    number."""
    token = make_token()
    STUB_STATE["mode"] = "cards500"
    overview = _get(client, token, "/")
    software = _get(client, token, "/software")
    assert set(AWAITING_RE.findall(_visible(overview.text))) == {"3"}
    assert set(AWAITING_RE.findall(_visible(software.text))) == {"3"}
    assert "estate-wide figure is not available" in _visible(software.text)


def test_card_figure_is_stated_plainly_with_its_scope(client, make_token):
    token = make_token()
    STUB_STATE["overview_cards_data"] = _cards_with_products(140)
    body = _get(client, token).text
    text = _visible(body)
    assert "140 products waiting on an approval decision" in text
    assert not HEDGED_COUNT_RE.search(text)
    # The card also counts Homebrew packages and AI tools, which this list
    # does not show, so the page says where they are reviewed.
    assert "Homebrew" in text and "AI Tooling" in text


def test_partial_card_figure_gets_a_muted_reason_line_not_at_least(client, make_token):
    token = make_token()
    STUB_STATE["overview_cards_data"] = _cards_with_products(12, state="partial")
    body = _get(client, token).text
    text = _visible(body)
    assert "12 products waiting on an approval decision" in text
    assert not HEDGED_COUNT_RE.search(text)
    assert re.search(r'<p class="meta meta--note"[^>]*>[^<]*report', body), (
        "a partial figure must carry one muted line saying why")


def test_no_at_least_in_headline_or_type_dropdown_when_totals_are_partial(
        client, make_token):
    """The applications read is truncated and carries no usable total: the
    old page said "at least 17 products" and "All types (at least 17)"."""
    token = make_token()
    apps = copy.deepcopy(APPLICATIONS)
    apps.pop("total")
    apps["truncated"] = True
    STUB_STATE["applications_data"] = apps
    body = _get(client, token).text
    assert not HEDGED_COUNT_RE.search(_visible(body))
    type_select = body[body.index('<select id="software-search-type"'):]
    type_select = type_select[: type_select.index("</select>")]
    assert "at least" not in type_select


# ── 8. The count does not move between loads ──────────────────────────────

def test_headline_does_not_move_when_the_inventory_read_fails(client, make_token):
    """Defect 8's root cause: the old headline was the governance total
    when the fail-soft inventory read failed, and the shown-row count (with
    inventory-only rows, flagged "at least") when it succeeded, so a slow or
    failed /v1/portal/software read moved the figure between loads."""
    token = make_token()
    ok = _get(client, token).text
    STUB_STATE["mode"] = "software500"
    failed = _get(client, token).text
    assert AWAITING_RE.findall(_visible(ok)) == AWAITING_RE.findall(_visible(failed))
    assert "may be missing" in _visible(failed)


def test_rows_render_in_a_deterministic_order(client, make_token):
    token = make_token()
    first = _visible_names(_get(client, token).text)
    apps = copy.deepcopy(APPLICATIONS)
    apps["applications"].reverse()
    STUB_STATE["applications_data"] = apps
    second = _visible_names(_get(client, token).text)
    assert first == second


# ── 2. One approval state per row; signing is its own column ──────────────

def test_each_row_shows_exactly_one_approval_state(client, make_token):
    token = make_token()
    body = _get(client, token).text
    assert _rows(body)
    for row in _rows(body):
        states = re.findall(r'class="pill pill-state[^"]*"', row)
        assert len(states) == 1, row
        assert "pill-state" in _approval_cell(row)
    # Who decided and why is the state pill's tooltip now, not a line of
    # its own under the name.
    text = _visible(body, attributes=False)
    assert "Undecided" not in text
    assert "Decided " not in text


def test_state_labels_are_the_four_approval_states(client, make_token):
    token = make_token()
    body = _get(client, token).text

    def state(name):
        cell = _approval_cell(_row(body, name))
        return re.search(r'class="pill pill-state[^"]*"[^>]*>([^<]*)<', cell).group(1)

    assert state("MysteryApp") == "Unreviewed"
    assert state("Slack") == "Approved"
    assert state("CorpVPN") == "Approved"  # mandatory is a form of approved
    assert state("TorrentBox") == "Unapproved"
    assert state("OldTheme") == "Ignored"


def test_signing_is_a_labelled_column_never_an_approval_looking_pill(client, make_token):
    token = make_token()
    body = _get(client, token).text
    assert re.search(r"<th[^>]*>Signing</th>", body)
    row = _row(body, "MysteryApp")
    signing = re.search(r'<td class="cell-signing"[^>]*>.*?</td>', row, re.DOTALL)
    assert signing, "row has no signing cell"
    assert "Unknown" in signing.group(0)
    assert "pill" not in signing.group(0)
    assert "pill-signed" not in row


# ── 3/4. No identifiers or match detail in the list ───────────────────────

def test_no_guid_identifier_or_identifier_match_in_the_list(client, make_token):
    token = make_token()
    STUB_STATE["applications_data"] = _apps_with(
        _undecided_app("Adobe Acrobat Reader", MSI_CODE))
    body = _get(client, token).text
    text = _visible(body)
    assert "AC76BA86" not in text
    assert "Identifier match" not in text
    assert "Name match only" not in text
    assert "Reviewed identity" not in text
    assert "No removal pathway" not in text


def test_product_detail_shows_identifiers_under_a_labelled_section(client, make_token):
    token = make_token()
    STUB_STATE["applications_data"] = _apps_with(
        _undecided_app("Adobe Acrobat Reader", MSI_CODE))
    body = _get(client, token).text
    row = _row(body, "Adobe Acrobat Reader")
    href = html.unescape(re.search(r'class="product-name[^"]*" href="([^"]*)"', row).group(1))
    assert href.startswith("/software/history?")
    detail = _get(client, token, href + "&partial=1").text
    assert ">Identifiers<" in detail
    assert MSI_CODE in detail
    assert "Windows" in detail


def test_locked_row_with_an_identifier_still_opens_its_detail(client, make_token):
    """A mandatory policy row cannot be marked, but its identifier still
    belongs in the product detail, not nowhere."""
    token = make_token()
    STUB_STATE["applications_data"] = _apps_with({
        **_undecided_app("MandatoryTool", "com.example.mandatory", platform="macos"),
        "policy_state": "mandatory", "policy_team_id": None, "decided_at": "2026-10-02T08:00:00Z",
    })
    body = _get(client, token).text
    row = _row(body, "MandatoryTool")
    assert re.search(r'class="product-name[^"]*" href="/software/history\?', row)


# ── 5. The banner opens the review queue with the right count ─────────────

def _queue_fixture():
    """New Tool (windows, vendor.newtool) is both a new product since the
    last review and an undecided application row."""
    STUB_STATE["applications_data"] = _apps_with(
        _undecided_app("New Tool", "vendor.newtool"))


def test_banner_links_to_the_review_queue_with_the_queue_count(client, make_token):
    token = make_token()
    _queue_fixture()
    body = _get(client, token).text
    match = re.search(r'<a[^>]*href="([^"]*)"[^>]*data-review-queue-link[^>]*>', body)
    assert match, "the new-since-review banner is not a link into the queue"
    href = html.unescape(match.group(1))
    query = parse_qs(urlsplit(href).query)
    assert query["approval"] == ["waiting"]
    assert query["new_since"] == [NEW_SOFTWARE_REPORT["since"]]
    # Both new products are still Unreviewed on the platform, so the banner
    # and the queue heading it opens both say 2.
    assert "2 new since your last review" in _visible(body)


def test_review_queue_filters_to_new_unreviewed_rows_and_states_the_count(client, make_token):
    token = make_token()
    _queue_fixture()
    since = NEW_SOFTWARE_REPORT["since"]
    body = _get(client, token, f"/software?new_since={since}&approval=waiting").text
    assert "Reviewing 2 new products" in _visible(body)
    assert _visible_names(body) == ["New Tool"]
    # The pinned window is sent upstream, so approving one product (which
    # moves "last review" to now) does not empty the queue under the
    # customer mid-review.
    sent = [r["query"].get("since") for r in STUB_STATE["new_software_requests"]]
    assert since in sent
    assert "new_since" in _active_filters(body)


def test_review_queue_names_unmatched_products_rather_than_dropping_them(client, make_token):
    token = make_token()
    _queue_fixture()
    since = NEW_SOFTWARE_REPORT["since"]
    body = _get(client, token, f"/software?new_since={since}&approval=waiting").text
    # Legacy Tool is name-only: it cannot be matched to a row, and the page
    # says so rather than silently shrinking the queue.
    assert "1 of them could not be matched" in _visible(body)


def test_review_queue_count_drops_as_products_are_decided(client, make_token):
    """The queue is pinned to its window, so a decided product stays in the
    platform's list with its new state and simply stops counting."""
    token = make_token()
    _queue_fixture()
    STUB_STATE["new_software_data"] = {**NEW_SOFTWARE_REPORT, "products": [
        {**NEW_SOFTWARE_REPORT["products"][0], "approval_state": "approved"},
        NEW_SOFTWARE_REPORT["products"][1],
    ]}
    since = NEW_SOFTWARE_REPORT["since"]
    body = _get(client, token, f"/software?new_since={since}&approval=waiting").text
    assert "Reviewing 1 new product" in _visible(body)


# ── 7. Every filter is read from the URL ──────────────────────────────────

def test_search_param_fills_the_box_and_filters_the_rows(client, make_token):
    token = make_token()
    STUB_STATE["applications_data"] = _apps_with(
        _undecided_app("Microsoft Visual C++ 2015-2022 Redistributable (x64)",
                       "{57A73DF6-4BA9-4C1D-BBBB-517289FF6C13}"))
    body = _get(client, token, "/software?search=Visual+C%2B%2B").text
    box = re.search(r'<input type="search" id="software-search"[^>]*>', body).group(0)
    assert 'value="Visual C++"' in html.unescape(box)
    assert _visible_names(body) == ["Microsoft Visual C++ 2015-2022 Redistributable (x64)"]
    assert "search" in _active_filters(body)


def test_type_approval_publisher_and_devices_seed_the_bar(client, make_token):
    token = make_token()
    body = _get(client, token, "/software?type=extension&approval=waiting").text
    assert _visible_names(body) == ["MysteryHelper"]
    assert {"type", "approval"} <= _active_filters(body)


def _new_software_block(*products):
    counts = {level: 0 for level in main.NEW_SOFTWARE_URGENCY_LEVELS}
    for p in products:
        counts[p["urgency"]] += 1
    return _new_software(products=list(products), total=len(products), counts=counts)


def _urgency_fixture():
    """MysteryApp (macos, com.example.mysteryapp) is a critical new product
    on the Overview; ArchiveTool (an inventory-only row) is a low one."""
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software_block(
        _product("MysteryApp", "critical"),
        _product("ArchiveTool", "low", identifier="com.acme.archive"),
    )}


def test_urgency_param_filters_to_the_overview_urgency_levels(client, make_token):
    token = make_token()
    _urgency_fixture()
    # Everything the Overview rates is inside its own window, so the
    # first-seen read (new_days) holds the same products.
    STUB_STATE["new_software_data"] = {**NEW_SOFTWARE_REPORT, "products": [
        {**p, "identity_basis": "identifier"}
        for p in STUB_STATE["overview_data"]["new_software"]["products"]]}
    body = _get(client, token, "/software?new_days=14&urgency=critical,high").text
    assert _visible_names(body) == ["MysteryApp"]
    assert {"new_days", "urgency"} <= _active_filters(body)
    chips = _visible(_filter_bar(body))
    assert "Critical" in chips and "High" in chips


def test_new_days_param_asks_the_platform_for_that_window(client, make_token):
    token = make_token()
    STUB_STATE["new_software_data"] = {**NEW_SOFTWARE_REPORT, "since_basis": "query"}
    _queue_fixture()
    before = datetime.now(UTC)
    body = _get(client, token, "/software?new_days=14").text
    sent = [r["query"].get("since") for r in STUB_STATE["new_software_requests"]]
    window = [s for s in sent if s and s != NEW_SOFTWARE_REPORT["since"]]
    assert window, sent
    since = datetime.fromisoformat(window[0].replace("Z", "+00:00"))
    assert abs((before - since) - timedelta(days=14)) < timedelta(minutes=5)
    assert _visible_names(body) == ["New Tool"]
    assert "First seen in the last 14 days" in _visible(_filter_bar(body))


def test_unreadable_urgency_source_is_said_not_silently_unfiltered(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "overview500"
    body = _get(client, token, "/software?urgency=critical").text
    assert "could not be read" in _visible(body)
    assert "urgency" not in _active_filters(body)


def test_invalid_filter_values_are_dropped_not_reflected(client, make_token):
    token = make_token()
    body = _get(
        client, token,
        "/software?new_days=abc&urgency=%3Cscript%3E&new_since=nope").text
    assert "<script>" not in body.split("<body", 1)[1].split("<script", 1)[0]
    assert not ({"new_days", "urgency", "new_since"} & _active_filters(body))


def test_every_overview_software_link_opens_a_filtered_software_view(client, make_token):
    """PAT-2254's Overview links carry type/approval/search/new_days/urgency;
    each must open /software in a filter state that is not the unfiltered
    default, and every parameter it carries must be one the page applied."""
    token = make_token()
    _urgency_fixture()
    overview = _get(client, token, "/").text
    links = sorted({html.unescape(h) for h in re.findall(r'href="(/software\?[^"]*)"', overview)})
    assert links, "the Overview rendered no filtered /software links"
    param_to_filter = {"type": "type", "approval": "approval", "search": "search",
                       "new_days": "new_days", "urgency": "urgency"}
    for link in links:
        active = _active_filters(_get(client, token, link).text)
        assert active, f"{link} opened the unfiltered default"
        for param in parse_qs(urlsplit(link).query):
            assert param_to_filter[param] in active, f"{link}: {param} was not applied"


def test_filter_url_builder_and_parser_agree_on_names():
    url = main._software_filter_url(
        type_="extension", approval="waiting", new_days=14, urgency="critical,high",
        search="Visual C++")
    query = parse_qs(urlsplit(url).query)
    assert set(query) == {"type", "approval", "new_days", "urgency", "search"}
    assert main.SOFTWARE_NEW_DAYS_PARAM == "new_days"
    assert main.SOFTWARE_URGENCY_PARAM == "urgency"


# ── Review flow: back to the same filtered view, next row in view ─────────

def _post_approval(client, token, return_to, anchor=None):
    STUB_STATE["expected_jwt"] = token
    item = {"type": "application", "platform": "macos",
            "identifier": "com.example.mysteryapp", "name": "MysteryApp"}
    body = [("csrf_token", main._csrf_token(token)), ("return_to", return_to),
            ("state", "approved"), ("item", json.dumps(item))]
    if anchor is not None:
        body.append(("return_anchor", anchor))
    return client.post(
        "/software/approvals", content=urlencode(body), follow_redirects=False,
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": "https://testserver",
                 "Content-Type": "application/x-www-form-urlencoded"})


def test_approval_returns_to_the_filtered_url_with_the_next_row_anchor(client, make_token):
    token = make_token()
    resp = _post_approval(client, token, "/software?approval=waiting&type=application",
                          anchor="sw-0123456789ab")
    assert resp.status_code == 303
    location = resp.headers["location"]
    parts = urlsplit(location)
    assert parts.path == "/software"
    query = parse_qs(parts.query)
    assert query["approval"] == ["waiting"] and query["type"] == ["application"]
    assert parts.fragment == "sw-0123456789ab"


def test_a_malformed_anchor_falls_back_to_the_result_notice(client, make_token):
    token = make_token()
    resp = _post_approval(client, token, "/software?approval=waiting",
                          anchor='x"><script>alert(1)</script>')
    assert resp.status_code == 303
    assert urlsplit(resp.headers["location"]).fragment == "approval-result"


def test_each_row_form_names_the_next_visible_row(client, make_token):
    token = make_token()
    body = _get(client, token, "/software?approval=waiting").text
    visible = [r for r in _rows(body) if not _row_hidden(r)]
    assert len(visible) >= 2
    ids = [re.search(r'id="(sw-[0-9a-f]{12})"', _row_open_tag(r)).group(1) for r in visible]
    checked = 0
    for i, row in enumerate(visible[:-1]):
        anchor = re.search(r'name="return_anchor" value="([^"]*)"', row)
        if anchor is None:
            continue  # a locked row has no form
        assert anchor.group(1) == ids[i + 1], row[:200]
        checked += 1
    assert checked, "no markable row to check"


# ── 9/10. Homebrew: the same filter bar, and no blank CVE cells ───────────

def test_homebrew_uses_the_filter_bar_not_segmented_tabs(client, make_token):
    token = make_token()
    body = _get(client, token, "/homebrew").text
    assert "data-filter-bar" in body
    assert 'class="view-tabs"' not in body


def test_homebrew_filter_state_is_read_from_the_url(client, make_token):
    token = make_token()
    body = _get(client, token, "/homebrew?kind=formula&approval=unapproved&deps=all").text
    assert {"kind", "approval", "deps"} <= _active_filters(body)
    visible = [r for r in re.findall(r"<tr\b[^>]*data-approval-row[^>]*>.*?</tr>", body, re.DOTALL)
               if not _row_hidden(r)]
    assert len(visible) == 1 and "readline" in visible[0]


def test_homebrew_cve_cell_is_never_blank(client, make_token):
    """No Homebrew response carries an assessment state, so a package with
    no matched findings is "Not yet assessed", never an empty cell that
    reads as clean (absence requires authority)."""
    token = make_token()
    body = _get(client, token, "/homebrew").text
    for row in re.findall(r"<tr\b[^>]*data-approval-row[^>]*>.*?</tr>", body, re.DOTALL):
        cve = re.search(r'<td class="cell-cve"[^>]*>(.*?)</td>', row, re.DOTALL)
        assert cve, row
        assert _visible(cve.group(1)).strip(), f"blank CVE cell: {row[:200]}"
    assert "Not yet assessed" in _visible(body)
    assert "None found" not in _visible(body)


def test_homebrew_none_found_only_when_the_platform_marks_it_assessed(client, make_token):
    token = make_token()
    formulae = copy.deepcopy(HOMEBREW_FORMULAE)
    formulae["formulae"][0]["cve_assessment"] = {
        "state": "assessed", "finding_count": 0, "last_matched_at": "2026-09-23T10:00:00Z"}
    STUB_STATE["homebrew_formulae_data"] = formulae
    body = _get(client, token, "/homebrew?deps=all").text
    row = next(r for r in re.findall(r"<tr\b[^>]*data-approval-row[^>]*>.*?</tr>", body, re.DOTALL)
               if "openssl@3" in r)
    assert "None found" in _visible(row)
