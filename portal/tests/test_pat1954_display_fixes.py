"""PAT-1954: UTC timestamps, bounded CVE cell, devices table overflow, card alignment."""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE
from tests.test_devices_groups import GROUPED_DEVICES

ROOT = Path(__file__).resolve().parent.parent


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── humandate: always UTC ────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-20T12:30:53+01:00", "20 Sep 2026 11:30"),  # British Summer Time
        ("2026-09-20T11:30:53Z", "20 Sep 2026 11:30"),
        ("2026-09-20T11:30:53+00:00", "20 Sep 2026 11:30"),
        ("2026-09-20T06:30:53-05:00", "20 Sep 2026 11:30"),
        ("2026-09-20T11:30:53.123456+00:00", "20 Sep 2026 11:30"),
        ("2026-09-20T11:30:53", "20 Sep 2026 11:30"),  # naive string is already UTC
        ("2026-09-20 11:30:53", "20 Sep 2026 11:30"),
    ],
)
def test_humandate_with_time_is_converted_to_utc(value, expected):
    assert main.humandate(value, True) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-21T00:30:00+01:00", "20 Sep 2026"),  # crosses midnight backwards
        ("2026-09-20T23:30:00-05:00", "21 Sep 2026"),  # crosses midnight forwards
        ("2026-09-20T23:30:00Z", "20 Sep 2026"),
        ("2026-09-20T23:30:00+00:00", "20 Sep 2026"),
        ("2026-09-20T23:30:00", "20 Sep 2026"),
    ],
)
def test_humandate_date_only_uses_the_utc_date(value, expected):
    assert main.humandate(value) == expected
    assert main.humandate(value, False) == expected


def test_humandate_converts_datetime_objects():
    bst = timezone(timedelta(hours=1))
    aware = datetime(2026, 9, 20, 12, 30, 53, tzinfo=bst)
    assert main.humandate(aware, True) == "20 Sep 2026 11:30"
    assert main.humandate(datetime(2026, 9, 21, 0, 30, tzinfo=bst)) == "20 Sep 2026"
    assert main.humandate(datetime(2026, 9, 20, 11, 30, tzinfo=UTC), True) == "20 Sep 2026 11:30"
    # A naive datetime is treated as UTC, not shifted by the host's zone.
    assert main.humandate(datetime(2026, 9, 20, 11, 30), True) == "20 Sep 2026 11:30"


def test_humandate_empty_and_unparseable_values_keep_their_behaviour():
    for empty in (None, "", 0):
        assert main.humandate(empty) == "-"
        assert main.humandate(empty, True) == "-"
    assert main.humandate("not a timestamp") == "not a timestamp"
    assert main.humandate("not a timestamp", True) == "not a timestamp"


def test_humandate_filter_is_registered_for_templates():
    assert main.templates.env.filters["humandate"] is main.humandate


def test_device_detail_shows_last_seen_in_utc_when_api_sends_bst(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["last_seen"] = "2026-09-20T12:30:53+01:00"
    STUB_STATE["device_detail_data"] = detail

    resp = _get(client, token, "/devices/dev-mac-001")

    assert resp.status_code == 200
    # PAT-2324: the date sits in a nowrap span (PAT-2298), so a long platform
    # label and build number in the page head cannot break it across lines.
    assert 'last seen <span class="nowrap">20 Sep 2026</span> 11:30 (UTC)' in resp.text
    assert "12:30" not in resp.text


# ── device detail: bounded CVE cell ──────────────────────────────────────
def _detail_with_cves(counts):
    detail = deepcopy(DEVICE_DETAIL)
    detail["apps_with_findings"] = []
    for app, count in counts.items():
        detail["apps_with_findings"].append({
            "app": app, "version": "1.0", "max_severity": "high",
            "match_confidence": "version_confirmed", "fixed_version": "2.0",
            "cve_ids": [f"CVE-2019-{5000 + n}" for n in range(count)],
        })
    return detail


def _app_row(html, app):
    for row in re.findall(r"<tr>.*?</tr>", html, flags=re.S):
        if f"<td>{app}</td>" in row:
            return row
    raise AssertionError(f"no table row for {app}")


def test_cve_cell_shows_three_ids_and_folds_the_rest_into_a_details_disclosure(
    client, make_token,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail_with_cves({"BigApp": 25})

    resp = _get(client, token, "/devices/dev-mac-001/vulnerabilities")
    row = _app_row(resp.text, "BigApp")

    assert row.count("<details") == 1
    before, _, after = row.partition("<details")
    visible_ids = re.findall(r">(CVE-2019-\d+)</a>", before)
    assert visible_ids == ["CVE-2019-5000", "CVE-2019-5001", "CVE-2019-5002"]
    assert "<summary>22 more CVEs</summary>" in after
    # All 25 are in the document, in the original order, each unbreakable.
    all_ids = re.findall(r">(CVE-2019-\d+)</a>", row)
    assert all_ids == [f"CVE-2019-{5000 + n}" for n in range(25)]
    anchors = re.findall(r"<a [^>]*>CVE-2019-\d+</a>", row)
    assert len(anchors) == 25
    assert all('class="cve-id"' in anchor for anchor in anchors)
    assert all('href="https://nvd.nist.gov/vuln/detail/CVE-2019-' in a for a in anchors)
    # The disclosure holds exactly the folded IDs, and needs no JavaScript.
    assert len(re.findall(r">CVE-2019-\d+</a>", after)) == 22
    assert "<script" not in row


def test_cve_cell_with_four_ids_says_one_more_cve(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail_with_cves({"FourApp": 4})

    row = _app_row(_get(client, token, "/devices/dev-mac-001/vulnerabilities").text, "FourApp")

    assert "<summary>1 more CVE</summary>" in row


def test_cve_cell_with_two_or_three_ids_has_no_disclosure(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail_with_cves({"SmallApp": 2, "ThreeApp": 3})

    resp = _get(client, token, "/devices/dev-mac-001/vulnerabilities")

    for app, count in (("SmallApp", 2), ("ThreeApp", 3)):
        row = _app_row(resp.text, app)
        assert "<details" not in row and "more CVE" not in row
        assert len(re.findall(r'class="cve-id"', row)) == count


def test_cve_cell_without_ids_renders_a_dash(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail_with_cves({"NoCveApp": 0})

    row = _app_row(_get(client, token, "/devices/dev-mac-001/vulnerabilities").text, "NoCveApp")

    assert 'class="cve-id"' not in row and "<details" not in row
    assert re.search(r'<td class="mono cve-cell">-</td>', row)


def test_cve_ids_cannot_wrap_and_the_column_has_a_minimum_width():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    assert re.search(r"\.data-table td a\.cve-id \{[^}]*white-space: nowrap", css)
    assert re.search(r"\.cve-item \{[^}]*white-space: nowrap", css)
    assert re.search(r"\.cve-cell \{[^}]*min-width: \d+px", css)


# ── device detail: cards align to the top ────────────────────────────────
def test_device_detail_grid_top_aligns_cards():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    assert re.search(r"\.grid-two \{[^}]*align-items: start", css)


def test_device_detail_grid_is_one_full_width_track_that_cannot_widen_the_page():
    """The six-column findings table needs about 820px plus card padding, more than
    any two-track split of the 1120px page column can give it beside a usable
    Summary card, so the grid is a single minmax(0, 1fr) track at every width."""
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    rule = re.search(r"^\.grid-two \{([^}]*)\}", css, flags=re.M).group(1)
    assert "grid-template-columns: minmax(0, 1fr)" in rule
    assert "auto-fit" not in rule and "minmax(340px" not in rule
    assert "align-items: start" in rule
    assert re.search(r"\.grid-two > \.card \{ min-width: 0; \}", css)
    # Nothing in the responsive section touches this grid's tracks, so no
    # breakpoint re-splits it.
    assert ".grid-two" not in css[css.index("/* ── Responsive"):]
    # PAT-2164: Applications with open findings (the table this grid exists
    # for) moved to the Vulnerabilities tab - it is used there only now.
    users = [t.name for t in (ROOT / "templates").glob("*.html") if "grid-two" in t.read_text()]
    assert users == ["device_vulnerabilities.html"]


def test_findings_table_uses_tighter_cell_padding_inside_the_grid():
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    assert re.search(
        r"\.grid-two \.data-table th, \.grid-two \.data-table td \{[^}]*"
        r"padding-left: 12px; padding-right: 12px;",
        css,
    )
    # The bounded CVE cell keeps its minimum width and unbreakable IDs.
    assert re.search(r"\.cve-cell \{[^}]*min-width: 170px", css)
    assert re.search(r"\.data-table td a\.cve-id \{[^}]*white-space: nowrap", css)


def test_summary_card_dropped_the_duplicate_open_findings_row():
    # PAT-2141 follow-up (Andy's live feedback, 25 Sept 2026): the figure
    # moved to the top-of-page Issues count strip tile (which now links to
    # the Compliance tab) instead of appearing twice on the page -
    # supersedes this test's original "deliberately unchanged" assertion.
    detail = (ROOT / "templates" / "device_detail.html").read_text()
    assert "<dt>Open findings</dt>" not in detail
    # PAT-2164: the count strip itself moved into templates/_macros.html's
    # device_page_head macro, shared by every device tab route.
    macros = (ROOT / "templates" / "_macros.html").read_text()
    assert 'class="card kpi count-strip"' not in macros
    assert 'class="devices-toolbar device-tab-bar"' in macros
    assert 'class="device-tab-label' in macros


# ── devices table: overflow container and wrapping badges ────────────────
def test_devices_table_sits_in_a_named_focusable_scroll_container(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["devices_data"] = GROUPED_DEVICES

    resp = _get(client, token, "/devices")

    assert resp.status_code == 200
    assert re.search(
        r'<div class="table-scroll" role="region" aria-label="Devices table" tabindex="0">\s*'
        r'<table class="data-table device-table table-stack"',
        resp.text,
    )


def test_stale_badges_keep_their_full_text_in_the_markup(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["devices_data"] = GROUPED_DEVICES

    resp = _get(client, token, "/devices")

    assert resp.text.count('<span class="pill pill-warn">Encryption evidence stale</span>') >= 1
    assert resp.text.count('<span class="pill pill-warn">Update evidence stale</span>') >= 1


def test_devices_table_css_lets_headers_wrap_and_never_wraps_pills():
    """PAT-2092: headers still wrap inside their cells (now via the shared
    .data-table th rule rather than a per-table override - see that rule's
    own comment), but pills no longer wrap at all: PAT-2070's per-table
    "pill { white-space: normal }" overrides broke mid-word ("CRITI/CAL")
    once combined with the old blanket overflow-wrap: anywhere, so pills
    inherit the base .pill rule's white-space: nowrap unmodified.
    Second pass: headers must never break mid-word at all (not even at
    the point a column genuinely can't fit one - that reads as a signal
    to widen the column, not something to paper over), so .data-table th
    no longer sets overflow-wrap: break-word either, and device-table's
    own blanket "td { overflow-wrap: anywhere }" is gone too - it broke
    ordinary short words ("Wind/ows") the same way. Hostname is the one
    device-table cell that can be a genuinely long unbroken value, so it
    alone keeps a scoped .cell-anywrap class (see device_table() in
    _macros.html)."""
    css = (ROOT / "static" / "css" / "portal.css").read_text()
    assert re.search(r"\.data-table th \{[^}]*white-space: normal", css)
    assert not re.search(r"\.data-table th \{[^}]*overflow-wrap", css)
    assert ".device-table .pill { white-space: normal; overflow-wrap: normal; }" in css
    assert re.search(r"^\.pill \{[^}]*white-space: nowrap", css, flags=re.M)
    assert re.search(r"\.device-table \.last-seen \{[^}]*white-space: normal", css)
    assert not re.search(r"\.device-table td \{", css)
    assert re.search(r"\.cell-anywrap \{[^}]*overflow-wrap: anywhere", css)
    # Fixed pixel columns: wide enough for the longest single word in each
    # (PLATFORM, FINDINGS, "Windows"). PAT-2092, second pass: Hostname was
    # briefly min-width-only (giving it the container's spare width was
    # the fix for the actions-gap bug), but measurement showed a
    # min-width-only column does not reliably get its own min-width
    # respected in this Chromium build either (exception-table's Product
    # column, given the identical treatment, rendered at 117px against a
    # declared 180px min-width) - every column, hostname included, now has
    # a real width, and relies on table-layout: fixed's proven uniform
    # stretch (confirmed on device-table itself) to grow every column,
    # including hostname, the rest of the way to fill a wider container.
    widths = {
        name: int(px)
        for name, px in re.findall(r"\.device-col-(\w+) \{ width: (\d+)px; \}", css)
    }
    assert set(widths) == {
        "hostname", "platform", "os", "score",
        "encryption", "updates", "seen", "actions",
    }
    assert widths["platform"] >= 96 and widths["os"] >= 165
    # All identity and evidence columns are primary; the action fits the same budget.
    assert sum(widths.values()) <= 966


# ── cache busting ────────────────────────────────────────────────────────
def test_portal_css_version_is_bumped_for_this_change():
    """PAT-2237: the cache-buster is now derived from portal.css's own
    content hash (static_url()) rather than a hand-bumped literal per
    ticket, so there is no longer a per-ticket string to assert or to
    check isn't a stale predecessor's."""
    base = (ROOT / "templates" / "base.html").read_text()
    assert "{{ static_url('css/portal.css') }}" in base
    assert "portal.css?v=" not in base
