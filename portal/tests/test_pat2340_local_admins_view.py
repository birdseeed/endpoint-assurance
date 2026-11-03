"""Shared first-paint / filtered-download contract, not only URL plumbing."""

import copy
import csv
import io
import re

import pytest

from tests.conftest import LOCAL_ADMINS_DATA, STUB_STATE


def get(client, make_token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": make_token()})


def visible_rows(body):
    return [
        row
        for row in re.findall(r"<tr\b[^>]*>.*?</tr>", body, re.S)
        if "data-filter-view=" in row and "row-hide-" not in row.split(">", 1)[0]
    ]


def csv_rows(response):
    assert response.status_code == 200
    return list(csv.DictReader(io.StringIO(response.text)))


@pytest.mark.parametrize(
    "view,query,expected",
    [
        (
            "account",
            "platform=windows&principal_type=user&search=acme&sort=name&direction=desc",
            ["ACME\\bob", "ACME\\Administrator"],
        ),
        (
            "device",
            "platform=windows&principal_type=group&sort=hostname&direction=desc",
            ["acme-win-dc1"],
        ),
        ("device", "unknown=yes&sort=hostname&direction=desc", ["acme-win-unreadable"]),
    ],
)
def test_first_paint_matches_filtered_csv_in_order(client, make_token, view, query, expected):
    query = f"view={view}&{query}"
    body = get(client, make_token, "/local-admins?" + query).text
    rows = visible_rows(body)
    assert len(rows) == len(expected)
    for row, name in zip(rows, expected, strict=True):
        assert name in row
    exported = csv_rows(get(client, make_token, "/local-admins.csv?scope=view&" + query))
    assert [row["account" if view == "account" else "hostname"] for row in exported] == expected


def test_multi_value_membership_is_or_within_and_across_fields(client, make_token):
    data = copy.deepcopy(LOCAL_ADMINS_DATA)
    data["devices"][1]["principals"].append(copy.deepcopy(data["devices"][0]["principals"][0]))
    STUB_STATE["local_admins_data"] = data
    # alice spans both platforms; device has user AND group AND unresolved.
    response = get(client, make_token, "/local-admins.csv?scope=view&platform=windows&search=alice")
    rows = csv_rows(response)
    assert [row["account"] for row in rows] == ["alice"]
    assert rows[0]["device_count"] == "2"
    response = get(
        client,
        make_token,
        "/local-admins.csv?scope=view&view=device&platform=windows&principal_type=user,group&unknown=no",
    )
    assert [row["hostname"] for row in csv_rows(response)] == ["acme-win-dc1"]


@pytest.mark.parametrize(
    "sort,expected",
    [
        ("count", ["acme-mbp-frontdesk", "acme-win-dc1", "acme-win-unreadable"]),
        ("hostname", ["acme-mbp-frontdesk", "acme-win-dc1", "acme-win-unreadable"]),
    ],
)
def test_numeric_and_text_order_keep_unknown_last(client, make_token, sort, expected):
    rows = csv_rows(
        get(client, make_token, f"/local-admins.csv?scope=view&view=device&sort={sort}")
    )
    assert [r["hostname"] for r in rows] == expected
    rows = csv_rows(
        get(
            client,
            make_token,
            f"/local-admins.csv?scope=view&view=device&sort={sort}&direction=desc",
        )
    )
    reverse = expected[:2][::-1] + expected[2:] if sort == "count" else expected[::-1]
    assert [r["hostname"] for r in rows] == reverse


@pytest.mark.parametrize(
    "value", ["=1+1", "+SUM(1)", "-1+2", "@SUM(1)", "\tformula", "\rformula", "\nformula", "  =1+1"]
)
def test_every_export_neutralises_spreadsheet_formulas(client, make_token, value):
    data = copy.deepcopy(LOCAL_ADMINS_DATA)
    data["devices"][0]["hostname"] = value
    data["devices"][0]["principals"][0]["name"] = value
    STUB_STATE["local_admins_data"] = data
    for query, key in [
        ("", "principal_name"),
        ("?scope=view", "account"),
        ("?scope=view&view=device", "hostname"),
    ]:
        rows = csv_rows(get(client, make_token, "/local-admins.csv" + query))
        assert any(row[key] == "'" + value for row in rows)
        assert not any(row[key] == value for row in rows)


@pytest.mark.parametrize(
    "metadata",
    [
        {"truncated": True},
        {"total": 1000},
        {"has_more": True},
        {"next_cursor": "next"},
        {"offset": 10},
    ],
)
def test_never_downloads_a_partial_envelope(client, make_token, metadata):
    STUB_STATE["local_admins_data"] = {**copy.deepcopy(LOCAL_ADMINS_DATA), **metadata}
    for path in ["/local-admins.csv", "/local-admins.csv?scope=view", "/local-admins"]:
        response = get(client, make_token, path)
        assert response.status_code >= 500
        assert "text/csv" not in response.headers["content-type"]


def test_full_estate_not_capped_at_a_page(client, make_token):
    data = copy.deepcopy(LOCAL_ADMINS_DATA)
    data["devices"] = []
    for i in range(1007):
        d = copy.deepcopy(LOCAL_ADMINS_DATA["devices"][0])
        d.update(device_id=f"d-{i}", hostname=f"host-{i:04d}")
        data["devices"].append(d)
    STUB_STATE["local_admins_data"] = data
    rows = csv_rows(
        get(client, make_token, "/local-admins.csv?scope=view&view=device&direction=desc")
    )
    assert len(rows) == 1007
    assert rows[0]["hostname"] == "host-1006"
    assert rows[-1]["hostname"] == "host-0000"


@pytest.mark.parametrize(
    "path",
    [
        "/local-admins?view=device",
        "/local-admins.csv?scope=view&view=account",
        "/local-admins.csv?scope=view&view=device",
    ],
)
def test_role_refusal_and_unavailable_stay_closed(client, make_token, path):
    STUB_STATE["portal_role"] = "viewer"
    assert get(client, make_token, path).status_code == 403
    STUB_STATE["portal_role"] = "admin"
    STUB_STATE["local_admins_status"] = 500
    response = get(client, make_token, path)
    assert response.status_code >= 500
    assert "Domain Admins" not in response.text


def test_unknown_filter_no_matching_accounts_is_explicit_on_first_paint(client, make_token):
    response = get(client, make_token, "/local-admins?unknown=yes&search=missing")
    assert not visible_rows(response.text)
    assert re.search(
        r"<p[^>]*data-filter-empty(?![^>]*\bhidden)[^>]*>No accounts match", response.text
    )
    assert (
        csv_rows(get(client, make_token, "/local-admins.csv?scope=view&unknown=yes&search=missing"))
        == []
    )


@pytest.mark.parametrize(
    "view,sort",
    [
        ("account", "type"),
        ("account", "device_count"),
        ("account", "device_list"),
        ("device", "platform"),
        ("device", "limit"),
        ("device", "membership"),
    ],
)
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_each_sort_matches_first_paint(client, make_token, view, sort, direction):
    query = f"view={view}&sort={sort}&direction={direction}"
    page = get(client, make_token, "/local-admins?" + query)
    rows = visible_rows(page.text)
    exported = csv_rows(get(client, make_token, "/local-admins.csv?scope=view&" + query))
    assert len(rows) == len(exported)
    for row, item in zip(rows, exported, strict=True):
        assert item["account" if view == "account" else "hostname"] in row
    assert f'aria-sort="{"ascending" if direction == "asc" else "descending"}"' in page.text


def test_csv_preserves_mixed_builtin_and_partial_evidence(client, make_token):
    import json

    data = copy.deepcopy(LOCAL_ADMINS_DATA)
    another = copy.deepcopy(data["devices"][1])
    another.update(device_id="other", hostname="another-windows", collection_status="partial")
    another["principals"][0]["account_state"] = "enabled"
    data["devices"].append(another)
    STUB_STATE["local_admins_data"] = data
    accounts = csv_rows(
        get(client, make_token, "/local-admins.csv?scope=view&search=Administrator")
    )
    assert len(accounts) == 1
    account = accounts[0]
    assert account["device_count"] == "2"
    assert "disabled" in account["notes"] and "enabled" in account["notes"]
    details = json.loads(account["devices_json"])
    assert {d["account_state"] for d in details} == {"enabled", "disabled"}
    assert {d["collection_status"] for d in details} == {"complete", "partial"}
    devices = csv_rows(
        get(client, make_token, "/local-admins.csv?scope=view&view=device&search=another")
    )
    principals = json.loads(devices[0]["principals_json"])
    assert {p["principal_type"] for p in principals} == {"user", "group", "unresolved"}
    assert devices[0]["collection_status"] == "partial"


def test_multiselect_repeated_form_values_and_invalid_sort_are_safe(client, make_token):
    query = "platform=windows&platform=macos&sort=invalid&direction=invalid"
    rows = csv_rows(get(client, make_token, "/local-admins.csv?scope=view&" + query))
    assert len(rows) == 5
    assert [r["account"] for r in rows] == sorted([r["account"] for r in rows], key=str.casefold)
