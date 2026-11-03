"""PAT-1865: portal device roster and CSV must consume every platform page."""

import csv
import io
from datetime import UTC, datetime, timedelta

from tests.conftest import STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _devices(count, stale_from=None):
    now = datetime.now(UTC)
    rows = []
    for index in range(count):
        days_ago = 10 if stale_from is not None and index >= stale_from else 1
        rows.append({
            "device_id": f"device-{index:04d}",
            "hostname": f"endpoint-{index:04d}",
            "platform": "macOS",
            "os_version": "15.6",
            "last_seen": (now - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cis_score": 90,
            "findings_open": 0,
            "encryption_ok": True,
            "patch_pending": False,
        })
    return rows


def test_devices_page_walks_entire_platform_roster_and_forwards_jwt(client, make_token):
    rows = _devices(501)
    STUB_STATE["devices_data"] = {"devices": rows}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=normal")

    assert response.status_code == 200
    assert "endpoint-0000" in response.text
    assert "endpoint-0500" in response.text
    assert STUB_STATE["device_request_offsets"] == [0, 500]
    assert STUB_STATE["device_request_jwts"] == [token, token]


def test_devices_csv_contains_each_device_once_beyond_platform_page_limit(client, make_token):
    rows = _devices(501)
    STUB_STATE["devices_data"] = {"devices": rows}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    assert response.status_code == 200
    exported = list(csv.reader(io.StringIO(response.text)))
    hostnames = [row[0] for row in exported[1:]]
    assert len(hostnames) == 501
    assert len(set(hostnames)) == 501
    assert hostnames[0] == "endpoint-0000"
    assert hostnames[-1] == "endpoint-0500"


def test_devices_stale_filter_applies_after_later_pages_are_aggregated(client, make_token):
    STUB_STATE["devices_data"] = {"devices": _devices(501, stale_from=500)}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=stale&stale_days=7")

    assert response.status_code == 200
    assert "endpoint-0500" in response.text
    assert "endpoint-0499" not in response.text


def test_devices_csv_returns_no_partial_download_when_second_page_fails(client, make_token):
    STUB_STATE["devices_data"] = {"devices": _devices(501)}
    STUB_STATE["devices_page_statuses"] = {500: 503}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    # Preserve the portal's established treatment of an upstream 503 while
    # proving no CSV response was begun before page two completed.
    assert response.status_code == 503
    assert not response.headers.get("content-disposition")
    assert "endpoint-0000" not in response.text


def test_devices_rejects_non_advancing_or_malformed_pagination_metadata(client, make_token):
    rows = _devices(501)
    STUB_STATE["devices_data"] = {"devices": rows}
    STUB_STATE["devices_page_responses"] = {
        500: {"total": 501, "limit": 500, "offset": 0, "devices": [rows[500]]},
    }
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    assert response.status_code == 502
    assert "endpoint-0000" not in response.text


def test_devices_rejects_missing_pagination_metadata_before_csv_starts(client, make_token):
    STUB_STATE["devices_page_responses"] = {
        0: {"devices": _devices(1)},
    }
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    assert response.status_code == 502
    assert not response.headers.get("content-disposition")
    assert "endpoint-0000" not in response.text
