"""PAT-2342: Update currency preserves the platform's unknown bucket.

Prepared before implementation. Exercise the authenticated Overview response,
including both CIS layout branches, rather than reading template source.
"""

import copy
import html
import re

import pytest

from tests.conftest import OVERVIEW, STUB_STATE

HISTORICAL_CAVEAT = (
    "No device has reported in the last 24 hours. "
    "Update status is historical, not current."
)
LAYOUTS = ("compact-current", "full-current", "full-stale")
MISSING = object()


def _render_band(client, make_token, monkeypatch, layout, patch):
    data = copy.deepcopy(OVERVIEW)
    data["devices_total"] = 12
    data["devices_reporting_24h"] = 0 if layout == "full-stale" else 11
    data["findings_open"] = {
        "critical": 0, "high": 1 if layout == "full-current" else 0,
        "medium": 5, "low": 2,
    }
    data["patch_status"] = patch
    monkeypatch.setitem(STUB_STATE, "overview_data", data)
    token = make_token()
    monkeypatch.setitem(STUB_STATE, "expected_jwt", token)
    response = client.get("/", headers={"Cf-Access-Jwt-Assertion": token})
    assert response.status_code == 200
    body = response.text
    assert ('class="card cis-compact"' in body) == (layout == "compact-current")
    bands = re.findall(r'<section\b[^>]*>\s*<h2>Update currency</h2>(.*?)</section>',
                       body, re.DOTALL)
    assert len(bands) == 1, "exactly one Update currency band must be rendered"
    band = bands[0]
    assert (HISTORICAL_CAVEAT in band) == (layout == "full-stale")
    cells = re.findall(
        r'<div class="stat"><span class="stat-num([^\"]*)">([^<]*)</span>'
        r'<span class="stat-name">([^<]*)</span></div>', band,
    )
    values = {label: html.unescape(value).strip() for _, value, label in cells}
    tones = {label: tone.strip() for tone, _, label in cells}
    return values, tones


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("patch", [
    {"up_to_date": 4, "pending": 2, "failed": 1, "unknown": 5},
    {"up_to_date": 0, "pending": 0, "failed": 0, "unknown": 12},
    {"up_to_date": 9, "pending": 2, "failed": 1, "unknown": 0},
], ids=["mixed", "all-unknown", "explicit-zero"])
def test_update_currency_shows_authoritative_unknown_and_preserves_other_counts(
    client, make_token, monkeypatch, layout, patch,
):
    values, tones = _render_band(client, make_token, monkeypatch, layout, patch)
    assert values == {
        "Up to date": str(patch["up_to_date"]),
        "Pending": str(patch["pending"]),
        "Failed": str(patch["failed"]),
        "Unknown": str(patch["unknown"]),
    }
    assert tones["Up to date"] == "ok-text"
    assert tones["Pending"] == "warn-text"
    assert tones["Failed"] == "bad-text"
    assert not {"ok-text", "warn-text", "bad-text"}.intersection(tones["Unknown"].split())


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("unknown", [
    MISSING, None, -1, True, False, "0", "5", 1.5, [], {},
], ids=["missing", "null", "negative", "true", "false", "zero-string",
        "count-string", "float", "list", "object"])
def test_unavailable_unknown_is_distinct_from_authoritative_zero(
    client, make_token, monkeypatch, layout, unknown,
):
    patch = {"up_to_date": 9, "pending": 2, "failed": 1}
    if unknown is not MISSING:
        patch["unknown"] = unknown
    values, tones = _render_band(client, make_token, monkeypatch, layout, patch)
    assert "Unknown" in values, "missing or invalid unknown must stay visible"
    assert values["Unknown"], "unavailable count requires an explicit visible state"
    assert values["Unknown"] not in {"0", "-1", "True", "False", "5", "1.5", "[]", "{}",
                                      "None"}
    assert not any(character.isdigit() for character in values["Unknown"])
    assert values["Up to date"] == "9"
    assert values["Pending"] == "2"
    assert values["Failed"] == "1"
    assert not {"ok-text", "warn-text", "bad-text"}.intersection(tones["Unknown"].split())
