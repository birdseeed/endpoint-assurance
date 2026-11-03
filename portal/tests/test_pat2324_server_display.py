"""Servers are told apart from workstations on /devices, the device page and
the Devices CSV (PAT-2324).

Andy, 30 September 2026: "Servers need to be differentiated from Desktops".
HOMESERVER (Windows Server 2022) read exactly like WINDOWS11 (Windows 11):
Platform "Windows" and a bare build number. The platform now sends
`device_class` ("server", "workstation" or "unknown"; a Mac is always
"workstation") and `os_caption` (for example "Microsoft Windows Server 2022
Standard") on the roster rows and on the device response.

Three states are covered throughout: a server, a workstation, and a platform
that has not deployed the fields yet (or sends "unknown"), which must render
exactly as before. A server has no CIS score (there is no server benchmark
yet: the platform scores a server only against class-agnostic rules), so its
Score cell never shows a percentage and the device page says so.

Layout (column widths, wrapping, the walker's `cells` and `break` checks) is
browser territory: e2e/test_pat2324_server_display.py.
"""

import csv
import html
import io
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE, platform_shaped_detail

SERVER_ROW = "acme-win-dc1"
WORKSTATION_ROW = "acme-win-accounts"
MAC_ROW = "acme-mbp-frontdesk"
SERVER_NOTE = (
    "Servers are not scored against a CIS benchmark yet. "
    "Their failing checks come from Patched's baseline checks."
)
DEVICE_PAGE_NOTE = "Not available for servers yet"


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


def _recent_iso(days=0.05):
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(device_id, hostname, platform, os_version, **over):
    row = {
        "device_id": device_id, "hostname": hostname, "platform": platform,
        "os_version": os_version, "last_seen": _recent_iso(),
        "cis_score": 91, "findings_open": 2, "encryption_ok": True,
        "patch_pending": None,
        "cve_assessment": {
            "state": "not_assessed", "last_matched_at": None, "finding_count": None,
            "assessed_products": 0, "pending_products": 0, "not_assessed_products": 1,
        },
    }
    row.update(over)
    return row


def _set_roster(*rows):
    STUB_STATE["devices_data"] = {"devices": list(rows)}


def _row_html(body, hostname):
    """The <tr> of #device-table that holds `hostname`."""
    for match in re.finditer(r"<tr[^>]*>.*?</tr>", body, re.S):
        if hostname in match.group(0) and "<td" in match.group(0):
            return match.group(0)
    raise AssertionError(f"no device-table row for {hostname}")


def _cells(row_html):
    """The <td> elements of one row, tags kept, in order."""
    return re.findall(r"<td\b.*?</td>", row_html, re.S)


def _text(fragment):
    """Visible text of a fragment, entities decoded, whitespace collapsed."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


# ── 1. The caption becomes a short name only when the whole caption parses ──
@pytest.mark.parametrize(
    ("caption", "expected"),
    [
        ("Microsoft Windows Server 2022 Standard", "Server 2022"),
        ("Microsoft Windows Server 2022 Datacenter", "Server 2022"),
        ("Microsoft Windows Server 2019 Standard", "Server 2019"),
        ("Microsoft Windows Server 2016 Datacenter", "Server 2016"),
        ("Microsoft Windows Server 2012 R2 Standard", "Server 2012 R2"),
        ("Microsoft Windows Server 2025 Standard Evaluation", "Server 2025"),
        ("Microsoft Windows Server 2022", "Server 2022"),
        ("Windows Server 2022 Standard", "Server 2022"),
        ("Microsoft Windows 11 Enterprise", "Windows 11"),
        ("Microsoft Windows 11 Pro", "Windows 11"),
        ("Microsoft Windows 11 Education", "Windows 11"),
        ("Microsoft Windows 11 Home", "Windows 11"),
        ("Microsoft Windows 10 Pro", "Windows 10"),
        ("Microsoft Windows 10 Enterprise LTSC", "Windows 10"),
        ("Microsoft Windows 10 Pro for Workstations", "Windows 10"),
        ("microsoft windows 11 pro", "Windows 11"),
        ("  Microsoft Windows 11 Pro  ", "Windows 11"),
    ],
)
def test_a_recognised_caption_becomes_a_short_name(caption, expected):
    assert main.windows_short_name(caption) == expected


@pytest.mark.parametrize(
    "caption",
    [
        None, "", "   ", 11, ["Microsoft Windows 11 Pro"], {"caption": "Windows 11"},
        # Not Windows, or not a release this file knows.
        "macOS Sequoia 15.5", "Ubuntu 24.04 LTS", "Microsoft Office 2021",
        "Microsoft Windows", "Microsoft Windows Server", "Windows Server",
        "Microsoft Windows Vista Business", "Microsoft Windows XP Professional",
        "Microsoft Windows 2022 Standard",
        # A release with words after it that are not editions: no partial name.
        "Microsoft Windows Server 2022 Datacenter: Azure Edition",
        "Microsoft Windows 10 IoT Enterprise LTSC",
        "Microsoft Windows 11 Enterprise multi-session",
        "Microsoft Windows 11 Pro for Hackers",
        "Microsoft Windows Server 2022 Standard (Insider Preview)",
        "Microsoft Windows Server 20221 Standard",
        "Microsoft Windows Server 2022Standard",
        "x" * 200,
    ],
)
def test_an_unrecognised_caption_gives_no_name_rather_than_a_partial_one(caption):
    assert main.windows_short_name(caption) is None


# ── 2. The device type view ─────────────────────────────────────────────────
def test_device_type_view_for_a_server_workstation_and_mac():
    server = main.device_type_view({
        "platform": "Windows", "device_class": "server",
        "os_caption": "Microsoft Windows Server 2022 Standard"})
    assert server == {"kind": "server", "label": "Server", "is_server": True,
                      "platform_label": "Windows Server", "os_name": "Server 2022"}

    workstation = main.device_type_view({
        "platform": "windows", "device_class": "workstation",
        "os_caption": "Microsoft Windows 11 Enterprise"})
    assert workstation == {"kind": "workstation", "label": "Workstation",
                           "is_server": False, "platform_label": None,
                           "os_name": "Windows 11"}

    mac = main.device_type_view({"platform": "macOS", "device_class": "workstation",
                                 "os_caption": None})
    assert mac["kind"] == "workstation" and mac["os_name"] is None
    assert mac["platform_label"] is None


@pytest.mark.parametrize(
    "device",
    [
        {}, None, "server", [],
        {"platform": "Windows"},
        {"platform": "Windows", "device_class": None, "os_caption": None},
        {"platform": "Windows", "device_class": "unknown"},
        {"platform": "Windows", "device_class": ""},
        {"platform": "Windows", "device_class": "Server"},
        {"platform": "Windows", "device_class": "desktop"},
        {"platform": "Windows", "device_class": ["server"]},
        {"platform": "Windows", "device_class": True},
        {"platform": "Windows", "device_class": {"server": True}},
    ],
)
def test_unknown_absent_and_malformed_classes_are_no_class_at_all(device):
    view = main.device_type_view(device)
    assert view["kind"] is None and view["label"] is None
    assert view["is_server"] is False and view["platform_label"] is None


def test_a_server_that_is_not_windows_keeps_its_platform_label():
    view = main.device_type_view({"platform": "Linux", "device_class": "server",
                                  "os_caption": "Microsoft Windows Server 2022 Standard"})
    assert view["is_server"] is True
    assert view["platform_label"] is None  # not Windows: the caption is not read either
    assert view["os_name"] is None


def test_the_caption_of_a_non_windows_device_is_never_read():
    view = main.device_type_view({"platform": "macOS", "device_class": "workstation",
                                  "os_caption": "Microsoft Windows 11 Enterprise"})
    assert view["os_name"] is None


# ── 3. /devices: a server row ───────────────────────────────────────────────
def test_a_server_row_reads_windows_server_without_a_server_pill(client, token):
    body = _get(client, token, "/devices").text
    row = _row_html(body, SERVER_ROW)
    cells = _cells(row)

    assert 'data-device-class="server"' in row
    # Hostname cell carries only the link.
    assert _text(cells[0]) == SERVER_ROW
    assert "device-type-pill" not in body
    assert "data-value" not in cells[0]
    # Platform cell.
    assert _text(cells[1]) == "Windows Server"
    # OS version cell: the short name, the build under it, whole.
    assert _text(cells[2]) == "Server 2022 10.0.20348.5499"
    assert '<span class="os-name">Server 2022</span>' in cells[2]
    assert '<span class="os-build">10.0.20348.5499</span>' in cells[2]
    assert 'title="Microsoft Windows Server 2022 Standard &middot; 10.0.20348.5499"' in cells[2]


def test_a_server_row_has_no_cis_percentage_and_says_why_once(client, token):
    body = _get(client, token, "/devices").text
    score_cell = _cells(_row_html(body, SERVER_ROW))[4]

    assert _text(score_cell) == "n/a 4 failing"
    assert "%" not in score_cell
    assert 'title="No server benchmark"' in score_cell
    assert 'aria-label="No server benchmark"' in score_cell
    # It sorts as no score, never as the platform's number.
    assert 'data-value=""' in score_cell
    # The failing checks figure is the platform's, unchanged.
    assert "4 failing" in _text(score_cell)
    # One footnote for the whole table.
    assert body.count("data-server-score-note") == 1
    assert SERVER_NOTE.replace("'", "&#39;") in body or SERVER_NOTE in body


def test_a_server_with_no_score_still_reads_na_not_a_dash(client, token):
    _set_roster(_row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499",
                     device_class="server", cis_score=None,
                     os_caption="Microsoft Windows Server 2022 Standard"))
    row = _row_html(_get(client, token, "/devices").text, "HOMESERVER")

    assert _text(_cells(row)[4]) == "n/a 2 failing"


def test_a_server_sorts_by_hostname_alone(client, token):
    row = _row_html(_get(client, token, "/devices").text, SERVER_ROW)

    assert "data-value" not in _cells(row)[0]
    assert _text(_cells(row)[0]) == SERVER_ROW


# ── 4. /devices: workstations, Macs and the fields being absent ────────────
def test_a_windows_workstation_row_reads_windows_11_and_keeps_its_score(client, token):
    body = _get(client, token, "/devices").text
    row = _row_html(body, WORKSTATION_ROW)
    cells = _cells(row)

    assert 'data-device-class="workstation"' in row
    assert "device-type-pill" not in row
    assert _text(cells[0]) == WORKSTATION_ROW
    assert _text(cells[1]) == "Windows"
    assert _text(cells[2]) == "Windows 11 10.0.26200.8457"
    assert _text(cells[4]) == "31% 6 failing"
    assert "score-none" not in row


def test_a_mac_row_is_unchanged(client, token):
    row = _row_html(_get(client, token, "/devices").text, MAC_ROW)
    cells = _cells(row)

    assert _text(cells[1]) == "macOS"
    assert _text(cells[2]) == "15.5"
    assert 'class="cell-os-named"' in cells[2]
    assert 'class="os-name"' not in row
    assert _text(cells[4]) == "91% 1 failing"
    assert "device-type-pill" not in row


def _absent_roster():
    return [
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499"),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.8457"),
        _row("dev-mac-901", "MacBook-Pro", "macOS", "15.5"),
    ]


def _unknown_roster():
    return [
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499",
             device_class="unknown", os_caption=None),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.8457",
             device_class="unknown", os_caption=None),
        _row("dev-mac-901", "MacBook-Pro", "macOS", "15.5",
             device_class="unknown", os_caption=None),
    ]


@pytest.mark.parametrize("roster", [_absent_roster, _unknown_roster],
                         ids=["fields-absent", "class-unknown"])
def test_with_the_fields_absent_or_unknown_the_page_reads_as_it_did(client, token, roster):
    """A platform that has not deployed PAT-2324's fields (or one that cannot
    tell) gives a page with no server or workstation markup at all."""
    _set_roster(*roster())
    body = _get(client, token, "/devices").text

    server_row = _row_html(body, "HOMESERVER")
    cells = _cells(server_row)
    assert _text(cells[0]) == "HOMESERVER"
    assert _text(cells[1]) == "Windows"
    assert _text(cells[2]) == "10.0.20348.5499"
    assert 'title="10.0.20348.5499"' in cells[2]
    assert _text(cells[4]) == "91% 2 failing"
    assert _text(_cells(_row_html(body, "WINDOWS11"))[1]) == "Windows"
    assert _text(_cells(_row_html(body, "MacBook-Pro"))[1]) == "macOS"

    for marker in ("device-type-pill", 'class="os-name"', "score-none",
                   "data-device-class", "data-server-score-note", "No server benchmark",
                   "Server"):
        assert marker not in body, marker


def test_a_server_beside_workstations_leaves_the_workstation_rows_alone(client, token):
    _set_roster(*_absent_roster()[1:],
                _row("dev-win-903", "HOMESERVER", "Windows", "10.0.20348.5499",
                     device_class="server",
                     os_caption="Microsoft Windows Server 2022 Standard"))
    body = _get(client, token, "/devices").text

    assert _text(_cells(_row_html(body, "WINDOWS11"))[1]) == "Windows"
    assert _text(_cells(_row_html(body, "WINDOWS11"))[4]) == "91% 2 failing"
    assert _text(_cells(_row_html(body, "HOMESERVER"))[1]) == "Windows Server"


def test_a_caption_that_does_not_parse_falls_back_to_the_bare_build(client, token):
    _set_roster(
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499",
             device_class="server",
             os_caption="Microsoft Windows Server 2022 Datacenter: Azure Edition"),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.8457",
             device_class="workstation", os_caption="Microsoft Windows 11 Insider Preview"),
    )
    body = _get(client, token, "/devices").text

    for hostname, build in (("HOMESERVER", "10.0.20348.5499"), ("WINDOWS11", "10.0.26200.8457")):
        cell = _cells(_row_html(body, hostname))[2]
        assert _text(cell) == build
        assert f'<span class="os-build">{build}</span>' in cell
    # The class still shows: only the name fell back.
    assert _text(_cells(_row_html(body, "HOMESERVER"))[1]) == "Windows Server"


def test_a_caption_with_no_build_shows_the_name_alone(client, token):
    _set_roster(_row("dev-win-901", "HOMESERVER", "Windows", "",
                     device_class="server",
                     os_caption="Microsoft Windows Server 2022 Standard"))
    cell = _cells(_row_html(_get(client, token, "/devices").text, "HOMESERVER"))[2]

    assert _text(cell) == "Server 2022 Not reported"
    assert "os-build" in cell


def test_a_non_windows_server_keeps_its_platform_without_a_pill(client, token):
    _set_roster(_row("dev-lin-901", "acme-lin-01", "Linux", "24.04", device_class="server"))
    cells = _cells(_row_html(_get(client, token, "/devices").text, "acme-lin-01"))

    assert _text(cells[0]) == "acme-lin-01"
    assert _text(cells[1]) == "Linux"


# ── 5. The other tables that share the macro ───────────────────────────────
def test_the_stale_view_marks_servers_too(client, token):
    _set_roster(_row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499",
                     device_class="server", last_seen=_recent_iso(20),
                     os_caption="Microsoft Windows Server 2022 Standard"))
    body = _get(client, token, "/devices?view=stale&stale_days=7").text
    cells = _cells(_row_html(body, "HOMESERVER"))

    assert _text(cells[1]) == "Windows Server"
    assert _text(cells[4]) == "n/a 2 failing"
    assert body.count("data-server-score-note") == 1


# ── 6. Search ───────────────────────────────────────────────────────────────
def test_the_search_text_of_a_server_row_holds_server_and_a_workstation_does_not(client, token):
    """The search box matches a row's visible text (static/js/portal.js
    searchText falls back to textContent when a row has no data-search), so
    "server" finds a server through its Platform cell and its
    OS name, and does not find a workstation or a Mac. The browser test types
    it; this pins the text it would match."""
    body = _get(client, token, "/devices").text

    assert "server" in _text(_row_html(body, SERVER_ROW)).lower()
    for hostname in (WORKSTATION_ROW, MAC_ROW, "acme-mbp-storeroom"):
        assert "server" not in _text(_row_html(body, hostname)).lower(), hostname
    assert "data-search" not in _row_html(body, SERVER_ROW)


# ── 7. Copy ─────────────────────────────────────────────────────────────────
def test_the_new_copy_is_plain_and_never_names_a_workstation_benchmark(client, token):
    body = _get(client, token, "/devices").text
    detail = _get(client, token, "/devices/dev-win-101").text

    for page in (body, detail):
        assert "workstation benchmark" not in page.lower()
        assert "—" not in page
        assert "fleet" not in page.lower()
    assert "—" not in SERVER_NOTE and "—" not in DEVICE_PAGE_NOTE


# ── 8. The device page ──────────────────────────────────────────────────────
def _summary(body):
    start = body.index('id="device-assurance"')
    return body[start:body.index("</section>", start)]


def _kv(summary):
    return {_text(dt): _text(dd) for dt, dd in re.findall(
        r"<dt>(.*?)</dt><dd>(.*?)</dd>", summary, re.S)}


def test_the_device_page_of_a_server_shows_type_release_and_no_cis_percentage(client, token):
    body = _get(client, token, "/devices/dev-win-101").text
    kv = _kv(_summary(body))

    assert kv["Type"] == "Server"
    assert kv["Windows version"] == "Server 2022 · 10.0.20348.5499"
    assert kv["CIS Level 1 score"] == DEVICE_PAGE_NOTE
    assert "%" not in _summary(body).split("Disk encryption")[0]
    # The failing checks figure is unchanged: the platform's own findings_open.
    assert re.search(r'<span class="device-tab-label [^"]*">Compliance \(4 failing\)</span>', body)
    # The page head names the platform as the list does.
    assert re.search(r'<p class="meta">Windows Server &middot; <span class="nowrap">'
                     r'10\.0\.20348\.5499</span>', body)


def test_the_device_page_of_a_workstation_shows_type_release_and_its_score(client, token):
    body = _get(client, token, "/devices/dev-win-002").text
    kv = _kv(_summary(body))

    assert kv["Type"] == "Workstation"
    assert kv["Windows version"] == "Windows 11 · 11 24H2"
    assert re.fullmatch(r"\d+%", kv["CIS Level 1 score"])
    assert DEVICE_PAGE_NOTE not in body
    assert re.search(r'<p class="meta">Windows &middot; ', body)


def test_the_device_page_of_a_mac_shows_workstation_and_no_release_row(client, token):
    body = _get(client, token, "/devices/dev-mac-001").text
    kv = _kv(_summary(body))

    assert kv["Type"] == "Workstation"
    assert "Windows version" not in kv
    assert kv["CIS Level 1 score"].endswith("%")


def _serve_flat(**device_fields):
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(last_seen=_recent_iso())
    for key in ("device_class", "os_caption"):
        flat.pop(key, None)
    flat.update(device_fields)
    STUB_STATE["device_detail_data"] = flat


def test_the_device_page_with_the_fields_absent_has_no_type_row(client, token):
    _serve_flat()
    body = _get(client, token, "/devices/dev-mac-001").text
    kv = _kv(_summary(body))

    assert "Type" not in kv and "Windows version" not in kv
    assert kv["CIS Level 1 score"] == "65%"
    assert DEVICE_PAGE_NOTE not in body
    assert re.search(r'<p class="meta">macOS &middot; ', body)


@pytest.mark.parametrize("value", ["unknown", None, "", "desktop", ["server"]])
def test_an_unknown_class_gets_no_type_row(client, token, value):
    _serve_flat(device_class=value)
    kv = _kv(_summary(_get(client, token, "/devices/dev-mac-001").text))

    assert "Type" not in kv
    assert kv["CIS Level 1 score"] == "65%"


def test_the_platform_shaped_response_carries_the_fields_under_device(client, token):
    """Production nests device fields under `device`; the portal reads both."""
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(platform="Windows", os_version="10.0.20348.5499", last_seen=_recent_iso())
    STUB_STATE["device_detail_data"] = platform_shaped_detail(
        flat, device_class="server", os_caption="Microsoft Windows Server 2019 Datacenter")
    assert "device_class" in STUB_STATE["device_detail_data"]["device"]

    kv = _kv(_summary(_get(client, token, "/devices/dev-mac-001").text))

    assert kv["Type"] == "Server"
    assert kv["Windows version"] == "Server 2019 · 10.0.20348.5499"
    assert kv["CIS Level 1 score"] == DEVICE_PAGE_NOTE


def test_every_device_tab_names_a_server_in_its_page_head(client, token):
    # The Software tab is left out: the stub has no software list for this
    # device, so that tab answers with its own not-found page, not the head.
    for path in ("", "/hardware", "/vulnerabilities", "/compliance", "/evidence"):
        response = _get(client, token, f"/devices/dev-win-101{path}")
        assert response.status_code == 200, path
        assert re.search(r'<p class="meta">Windows Server &middot; ', response.text), path


# ── 9. The Devices CSV ──────────────────────────────────────────────────────
def _csv(client, token, path="/devices.csv"):
    rows = list(csv.reader(io.StringIO(_get(client, token, path).text)))
    header = rows[0]
    return header, {r[0]: dict(zip(header, r, strict=True)) for r in rows[1:]}


def test_the_csv_gains_a_trailing_type_column(client, token):
    header, by_host = _csv(client, token)

    assert header[-1] == "type"
    assert header[:9] == list(main.CSV_COLUMNS[:9])  # nothing before it moved
    assert by_host[SERVER_ROW]["type"] == "server"
    assert by_host[WORKSTATION_ROW]["type"] == "workstation"
    assert by_host[MAC_ROW]["type"] == "workstation"
    # The retired Macs in the fixture carry no class: empty, not "unknown".
    assert by_host["acme-mbp-retired"]["type"] == ""


def test_the_csv_leaves_a_servers_cis_score_empty_and_keeps_the_rest(client, token):
    _, by_host = _csv(client, token)
    server = by_host[SERVER_ROW]

    assert server["cis_score"] == ""
    assert server["platform"] == "Windows"
    assert server["os_version"] == "10.0.20348.5499"
    assert by_host[WORKSTATION_ROW]["cis_score"] == "31"
    assert by_host[MAC_ROW]["cis_score"] == "91"


def test_the_csv_type_is_empty_when_the_fields_are_absent_or_unknown(client, token):
    unknown = _unknown_roster()[0]
    unknown.update(device_id="dev-win-909", hostname="UNKNOWN-CLASS")
    _set_roster(*_absent_roster(), unknown)
    _, by_host = _csv(client, token)

    assert {h: r["type"] for h, r in by_host.items()} == {
        "HOMESERVER": "", "WINDOWS11": "", "MacBook-Pro": "", "UNKNOWN-CLASS": ""}
    assert by_host["HOMESERVER"]["cis_score"] == "91"


def test_the_stale_csv_carries_the_type_too(client, token):
    _set_roster(_row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499",
                     device_class="server", last_seen=_recent_iso(20)))
    header, by_host = _csv(client, token, "/devices.csv?stale_days=7")

    assert header[-1] == "type" and by_host["HOMESERVER"]["type"] == "server"


# ── 10. The What's new entry ────────────────────────────────────────────────
def test_the_whats_new_entry_says_it_plainly(client, token):
    entry = next(e for e in main.CHANGELOG_ENTRIES
                 if e["title"] == "Servers are now marked on the Devices page")
    body = entry["body"]

    assert entry["date"] == "2026-09-30" and entry["link"] == "/devices"
    assert "not scored against a CIS benchmark" in body
    assert "workstation benchmark" not in body
    assert "—" not in body and "fleet" not in body.lower() and "PAT-" not in body
