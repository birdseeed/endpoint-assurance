"""Unknown update evidence uses the approved, platform-neutral copy.

The platform owns OS-verdict freshness. A recently reporting Windows device
can have patch_pending=None because its OS verdict is missing, unknown or
stale. These tests supply that projection, not raw OS reports or a portal
freshness calculation. Device last_seen staleness is a separate caveat.
"""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from html import unescape

import pytest

from tests.conftest import DEVICE_DETAIL, STUB_STATE, platform_shaped_detail

APPROVED_NOTE = "This device hasn't reported a recent update state."
OLD_NOTE = "Patched does not show update state for Windows devices yet."
MISSING = object()


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


def _recent_iso(days=0.02):
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render(client, token, surface, platform, state, stale=False):
    last_seen = _recent_iso(days=20 if stale else 0.02)
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(platform=platform, last_seen=last_seen, encryption_ok=True)
    if state is MISSING:
        flat.pop("patch_pending", None)
    else:
        flat["patch_pending"] = state
    STUB_STATE["device_detail_data"] = platform_shaped_detail(flat)
    row = {
        "device_id": "dev-mac-001", "hostname": "update-copy-device",
        "platform": platform, "os_version": "15.5" if platform == "macOS" else "10.0.26200",
        "last_seen": last_seen, "cis_score": 91, "findings_open": 2,
        "encryption_ok": True,
        "cve_assessment": {"state": "not_assessed", "finding_count": None},
    }
    if state is not MISSING:
        row["patch_pending"] = state
    STUB_STATE["devices_data"] = {"devices": [row]}
    path = ("/devices?view=stale&stale_days=7" if stale else "/devices?view=normal")
    if surface == "detail":
        path = "/devices/dev-mac-001"
    response = client.get(path, headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == 200
    body = unescape(response.text)
    if surface == "roster":
        match = next(
            m for m in re.finditer(r"<tr[^>]*>.*?</tr>", body, re.S)
            if "update-copy-device" in m.group(0) and "<td" in m.group(0)
        )
        update_cell = re.findall(r"<td[^>]*>(.*?)</td>", match.group(0), re.S)[6]
    else:
        match = re.search(r"<dt>Update state</dt><dd>(.*?)</dd>", body, re.S)
        assert match, "missing Summary update state"
        update_cell = match.group(1)
    return body, update_cell


@pytest.mark.parametrize("surface", ["roster", "detail"])
@pytest.mark.parametrize("platform,state", [
    pytest.param("Windows", None, id="windows-stale-os-verdict-projection"),
    pytest.param("Windows", MISSING, id="windows-missing-state"),
    pytest.param("macOS", None, id="mac-null-state"),
    pytest.param("macOS", MISSING, id="mac-missing-state"),
    pytest.param("Windows", "unknown", id="windows-nonboolean"),
    pytest.param("macOS", 0, id="mac-nonboolean-zero"),
])
def test_nonboolean_update_state_uses_approved_copy_on_both_surfaces(
    client, token, surface, platform, state,
):
    body, cell = _render(client, token, surface, platform, state)

    assert APPROVED_NOTE in body
    assert OLD_NOTE not in body
    assert "Not shown" not in cell
    assert "Up to date" not in cell
    assert "Updates pending" not in cell
    assert "pill-ok" not in cell
    assert "Update evidence stale" not in cell  # last_seen is recent


@pytest.mark.parametrize("surface", ["roster", "detail"])
@pytest.mark.parametrize("platform", ["Windows", "macOS"])
@pytest.mark.parametrize("state,label,tone", [
    (False, "Up to date", "pill-ok"),
    (True, "Updates pending", "pill-warn"),
])
def test_boolean_update_state_keeps_its_verdict_without_an_unknown_note(
    client, token, surface, platform, state, label, tone,
):
    body, cell = _render(client, token, surface, platform, state)

    assert label in cell
    assert tone in cell
    assert APPROVED_NOTE not in body
    assert OLD_NOTE not in body
    assert "Not shown" not in cell


@pytest.mark.parametrize("surface", ["roster", "detail"])
@pytest.mark.parametrize("platform", ["Windows", "macOS"])
@pytest.mark.parametrize("state", [False, True])
def test_stale_device_caveat_still_overrides_boolean_update_state(
    client, token, surface, platform, state,
):
    body, cell = _render(client, token, surface, platform, state, stale=True)

    assert "Update evidence stale" in cell
    assert "Encryption evidence stale" in body
    assert "Up to date" not in cell
    assert "Updates pending" not in cell
    assert APPROVED_NOTE not in body


@pytest.mark.parametrize("path", ["/devices", "/devices/dev-mac-001"])
def test_update_state_surfaces_still_require_authentication(client, path):
    assert client.get(path).status_code == 401
