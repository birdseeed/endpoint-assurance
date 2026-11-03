"""Device type and reporting-state filters compose without JavaScript."""
import html
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.conftest import STUB_STATE
from tests.test_pat2324_server_display import _get, _recent_iso, _row, _set_roster


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


@pytest.fixture
def roster():
    _set_roster(
        _row("server", "SERVER", "Windows", "2022", device_class="server"),
        _row("workstation", "WORKSTATION", "macOS", "15", device_class="workstation"),
        _row("quiet", "QUIET", "macOS", "15", device_class="workstation", days_stale=5),
        _row("unknown", "UNKNOWN", "Windows", "10", device_class="unknown"),
    )
    # The platform bucket is derived from last_seen, not the optional days field.
    STUB_STATE["devices_data"]["devices"][2]["last_seen"] = _recent_iso(5)


def _nav(body, label):
    return re.search(r'<nav[^>]*aria-label="' + label + r'".*?</nav>', body, re.S)[0]


@pytest.mark.parametrize("kind,ids", [
    ("all", {"server", "workstation", "quiet", "unknown"}),
    ("server", {"server"}), ("workstation", {"workstation", "quiet"}),
    ("unknown", {"unknown"}), ("invalid", {"server", "workstation", "quiet", "unknown"}),
])
def test_type_is_filtered_server_side(client, token, roster, kind, ids):
    response = _get(client, token, f"/devices?type={kind}")
    assert response.status_code == 200
    assert {d["device_id"] for d in response.context["devices"]} == ids
    assert "device-type-pill" not in response.text


def test_counts_links_and_kpis_compose(client, token, roster):
    response = _get(client, token,
                    "/devices?type=server&view=quiet&stale_days=14&list_group=matched")
    body = response.text
    state = _nav(body, "Device reporting state")
    types = _nav(body, "Device type")
    assert "Reporting normally (1)" in state and "Quiet 3–14 days (0)" in state
    assert "Servers (0)" in types and "Workstations (1)" in types
    assert "Unknown type" not in types
    for nav, parameter, value in [(state, "type", "server"), (types, "view", "quiet")]:
        for href in re.findall(r'href="([^"]+)"', nav):
            query = parse_qs(urlsplit(html.unescape(href)).query)
            assert query[parameter] == [value]
            assert query["stale_days"] == ["14"] and query["list_group"] == ["matched"]
    assert response.context["total"] == 4
    assert len(response.context["quiet"]) == 1  # KPI source is estate-wide.
    assert "No servers in this reporting state." in body


def test_zero_options_hidden_but_selected_retained(client, token):
    _set_roster(_row("s", "SERVER", "Windows", "2022", device_class="server"))
    nav = _nav(_get(client, token, "/devices").text, "Device type")
    assert "Workstations" not in nav and "Unknown type" not in nav
    nav = _nav(_get(client, token, "/devices?type=workstation").text, "Device type")
    assert "Workstations (0)" in nav
    nav = _nav(_get(client, token, "/devices?type=unknown").text, "Device type")
    assert "Unknown type" not in nav


def test_unknown_option_and_invalid_type_default(client, token, roster):
    body = _get(client, token, "/devices?type=invalid").text
    nav = _nav(body, "Device type")
    assert "Unknown type (1)" in nav
    assert re.search(r'aria-current="true"[^>]*>All types', nav)


def test_special_views_also_filter_type(client, token, roster):
    for view in ("stale", "not_reporting_24h"):
        response = _get(client, token, f"/devices?view={view}&type=server&stale_days=7")
        assert response.context["devices"] == []


def test_reconciliation_is_unfiltered_and_links_preserve_type(client, token, roster):
    response = _get(client, token, "/devices?type=server")
    assert "ghost-01" in response.text
    assert response.context["device_list"]["never_seen_total"] == 2
    links = re.findall(r'class="ov-card dl-tile[^>]*href="([^"]+)"', response.text)
    assert len(links) == 3
    assert all(parse_qs(urlsplit(html.unescape(link)).query)["type"] == ["server"]
               for link in links)
