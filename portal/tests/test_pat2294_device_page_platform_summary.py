"""The device page reads the platform's own summary figures (PAT-2294).

`GET /v1/portal/devices/{id}` now returns `device.findings_open`,
`device.encryption_ok` and `device.patch_pending`, computed by the same code
as the `/v1/portal/devices` roster row (contracts/portal-api.md in the
platform repo). Before that the device page could not see them, so it counted
its own Failing checks from the signals list and showed no Windows update
state at all. Now:

- the Failing checks tile shows the platform's `findings_open` when it is a
  real count, and falls back to counting the signals when it is not (an older
  platform, a stub), so the list and the page read one figure;
- the tile's colour still comes from the open signals' own severities;
- Summary shows a real update state for a Windows device whose `patch_pending`
  is a boolean, and the "not shown" note only when it is not.

The responses below use the platform's real shape (device fields under
`device`) as well as the flat shape the older fixtures use, because the
portal reads both and production sends the first.
"""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

import main
from tests.conftest import (
    DEVICE_DETAIL,
    DEVICE_DETAIL_DEV_WIN_002,
    DEVICES,
    STUB_STATE,
    platform_shaped_detail,
)

UNKNOWN_NOTE = "This device hasn't reported a recent update state."
TILE = re.compile(
    r'<span class="device-tab-label ([^"]*)">Compliance \(([^<]*)\)</span>')


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


def _recent_iso(days=0.02):
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signals(passing=0, failing=0, errored=0, not_applicable=0, severity="medium"):
    rows = []
    for kind, count in (("pass", passing), ("fail", failing), ("error", errored),
                        ("not_applicable", not_applicable)):
        for n in range(count):
            rows.append({
                "rule_id": f"cis_{kind}_{n}", "title": f"{kind} check {n}",
                "severity": severity, "status": kind, "advisory": "",
            })
    return rows


def _detail(signals=None, platform="macOS", **device_fields):
    """A fresh (not stale) detail response in the platform's real shape."""
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(platform=platform, last_seen=_recent_iso())
    if signals is not None:
        flat["compliance_signals"] = signals
    return platform_shaped_detail(flat, **device_fields)


def _serve(detail):
    STUB_STATE["device_detail_data"] = detail
    return detail


def _tile(body):
    match = TILE.search(body)
    assert match, "no Compliance count on the page"
    return match.group(2).removesuffix(" failing"), match.group(1)


def _summary(body):
    start = body.index('id="device-assurance"')
    return body[start:body.index("</section>", start)]


# ── 1. Failing checks: the platform figure wins ─────────────────────────────
def test_tile_shows_the_platforms_findings_open_not_the_signal_count(client, token):
    # The signals hold one failing check; the platform says seven.
    _serve(_detail(_signals(passing=3, failing=1, not_applicable=5), findings_open=7))

    body = _get(client, token, "/devices/dev-mac-001").text

    assert _tile(body)[0] == "7"
    # The Compliance tab count reads the same figure as the tile.
    assert "Compliance (7 failing)" in body


def test_tile_takes_the_platform_figure_from_a_flat_response_too(client, token):
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(last_seen=_recent_iso(), findings_open=7,
                compliance_signals=_signals(passing=3, failing=1))
    _serve(flat)

    assert _tile(_get(client, token, "/devices/dev-mac-001").text)[0] == "7"


def test_tile_is_the_same_on_every_device_tab(client, token):
    _serve(_detail(_signals(failing=1), findings_open=7))

    for path in ("", "/hardware", "/software", "/vulnerabilities", "/compliance", "/evidence"):
        body = _get(client, token, f"/devices/dev-mac-001{path}").text
        assert _tile(body)[0] == "7", path


def test_list_and_device_page_show_one_findings_figure(client, token):
    roster = deepcopy(DEVICES["devices"][0])
    roster.update(hostname="acme-mbp-frontdesk", last_seen=_recent_iso(), findings_open=7)
    STUB_STATE["devices_data"] = {"devices": [roster]}
    _serve(_detail(_signals(passing=2, failing=1), findings_open=7))

    listed = _get(client, token, "/devices?view=normal").text
    row = next(m.group(0) for m in re.finditer(r"<tr[^>]*>.*?</tr>", listed, re.S)
               if "acme-mbp-frontdesk" in m.group(0) and "<td" in m.group(0))
    cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)

    assert '<span class="device-checks">7 failing</span>' in cells[4]
    assert _tile(_get(client, token, "/devices/dev-mac-001").text)[0] == "7"


def test_stub_device_whose_signals_disagree_with_the_platform_shows_the_platform_figure(
    client, token,
):
    """dev-win-002 is served the way the platform sends it: six failing
    according to its roster row, while its signals hold one failing check.
    This guards the fixture as much as the code: if the two ever agree, this
    stops proving that the platform figure wins."""
    roster = next(r for r in DEVICES["devices"] if r["device_id"] == "dev-win-002")
    signals = DEVICE_DETAIL_DEV_WIN_002["compliance_signals"]
    assert DEVICE_DETAIL_DEV_WIN_002["device"]["findings_open"] == roster["findings_open"] == 6
    assert main._device_issues_tile_view(signals, False)["value"] != 6

    body = _get(client, token, "/devices/dev-win-002").text

    assert _tile(body)[0] == "6"


# ── 1b. Tone stays with the signals ─────────────────────────────────────────
@pytest.mark.parametrize("severity,tone", [
    ("critical", "bad-text"), ("high", "bad-text"),
    ("medium", "warn-text"), ("low", "mute-text"),
])
def test_tone_comes_from_the_open_signals_severity_and_the_number_from_the_platform(
    severity, tone,
):
    signals = [{"status": "fail", "severity": severity}, {"status": "pass", "severity": "critical"}]

    tile = main._device_issues_tile_view(signals, False, 7)

    assert tile == {"value": 7, "tone": tone, "is_count": True, "stale": False}


def test_tone_on_the_page_follows_the_signals_while_the_number_is_the_platforms(client, token):
    _serve(_detail(_signals(passing=2, failing=1, severity="medium"), findings_open=7))

    assert _tile(_get(client, token, "/devices/dev-mac-001").text) == ("7", "warn-text")


def test_a_platform_count_with_no_open_signal_to_explain_it_stays_bad_not_muted():
    signals = [{"status": "pass", "severity": "low"}, {"status": "not_applicable"}]

    tile = main._device_issues_tile_view(signals, False, 3)

    assert tile == {"value": 3, "tone": "bad-text", "is_count": True, "stale": False}


def test_a_platform_zero_is_a_muted_zero_even_when_signals_list_a_failure():
    # The platform leaves out a failing result with no observed value
    # (unreadable evidence), so its zero is the list's zero as well.
    signals = [{"status": "fail", "severity": "critical"}]

    tile = main._device_issues_tile_view(signals, False, 0)

    assert tile == {"value": 0, "tone": "mute-text", "is_count": True, "stale": False}


def test_a_stale_device_keeps_the_platform_count_and_the_stale_caveat():
    signals = [{"status": "fail", "severity": "high"}]

    tile = main._device_issues_tile_view(signals, True, 4)

    assert tile == {"value": 4, "tone": "bad-text", "is_count": True, "stale": True}


def test_no_signals_and_a_platform_zero_still_reads_not_available():
    # A zero with nothing evaluated does not prove the device healthy.
    tile = main._device_issues_tile_view([], False, 0)

    assert tile == {"value": "Not available", "tone": "mute-text",
                    "is_count": False, "stale": False}


def test_no_signals_but_a_platform_count_shows_the_count():
    tile = main._device_issues_tile_view([], False, 2)

    assert tile["value"] == 2 and tile["is_count"] is True


# ── 1c. Fallback when the platform figure is not usable ─────────────────────
def test_tile_falls_back_to_counting_signals_when_findings_open_is_absent(client, token):
    detail = _detail(_signals(passing=3, failing=2, errored=1, not_applicable=4))
    del detail["device"]["findings_open"]
    _serve(detail)

    body = _get(client, token, "/devices/dev-mac-001").text

    assert _tile(body)[0] == "3"
    assert "Compliance (3 failing)" in body


def test_fallback_on_a_flat_response_without_the_field(client, token):
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(last_seen=_recent_iso(), compliance_signals=_signals(failing=2, passing=1))
    del flat["findings_open"]
    _serve(flat)

    assert _tile(_get(client, token, "/devices/dev-mac-001").text)[0] == "2"


@pytest.mark.parametrize("value", [
    None, "7", 7.0, 7.5, True, False, -1, [], {"high": 1},
], ids=repr)
def test_only_a_real_non_negative_integer_replaces_the_signal_count(value):
    signals = _signals(failing=2, passing=1)

    tile = main._device_issues_tile_view(signals, False, main._platform_findings_open(
        {"findings_open": value}))

    assert tile["value"] == 2


def test_platform_findings_open_accepts_zero_and_positive_integers_only():
    assert main._platform_findings_open({"findings_open": 0}) == 0
    assert main._platform_findings_open({"findings_open": 12}) == 12
    assert main._platform_findings_open({}) is None
    assert main._platform_findings_open(None) is None


def test_a_junk_findings_open_on_the_page_falls_back_and_does_not_break_it(client, token):
    _serve(_detail(_signals(failing=2, passing=1), findings_open="many"))

    response = _get(client, token, "/devices/dev-mac-001")

    assert response.status_code == 200
    assert _tile(response.text)[0] == "2"


# ── 2. Summary: update state and encryption ─────────────────────────────────
def test_windows_device_that_is_up_to_date_shows_that_and_no_not_shown_note(client, token):
    _serve(_detail(_signals(failing=1), platform="Windows", patch_pending=False,
                   encryption_ok=True))

    body = _get(client, token, "/devices/dev-mac-001").text
    summary = _summary(body)

    assert 'pill-ok">Up to date' in summary
    assert UNKNOWN_NOTE not in body
    assert "Update state not reported" not in body


def test_windows_device_with_updates_outstanding_shows_that(client, token):
    _serve(_detail(_signals(failing=1), platform="Windows", patch_pending=True))

    body = _get(client, token, "/devices/dev-mac-001").text

    assert 'pill-warn">Updates pending' in _summary(body)
    assert UNKNOWN_NOTE not in body


def test_windows_device_with_no_update_state_shows_the_note_once(client, token):
    _serve(_detail(_signals(failing=1), platform="Windows", patch_pending=None))

    body = _get(client, token, "/devices/dev-mac-001").text

    assert body.count(UNKNOWN_NOTE) == 1
    assert "Up to date" not in _summary(body)
    assert "Update state not reported" not in body


def test_windows_device_that_omits_the_field_shows_the_note_too(client, token):
    detail = _detail(_signals(failing=1), platform="Windows")
    del detail["device"]["patch_pending"]
    _serve(detail)

    assert _get(client, token, "/devices/dev-mac-001").text.count(UNKNOWN_NOTE) == 1


def test_mac_with_no_update_state_uses_the_same_neutral_note(client, token):
    _serve(_detail(_signals(failing=1), platform="macOS", patch_pending=None))

    body = _get(client, token, "/devices/dev-mac-001").text

    assert body.count(UNKNOWN_NOTE) == 1


def test_mac_with_a_boolean_update_state_shows_it(client, token):
    _serve(_detail(_signals(failing=1), patch_pending=True))

    assert 'pill-warn">Updates pending' in _summary(
        _get(client, token, "/devices/dev-mac-001").text)


@pytest.mark.parametrize("value,expected", [
    (True, 'pill-ok">Encrypted'),
    (False, 'pill-bad">Not encrypted'),
    (None, 'pill-muted">Not assessed'),
])
def test_summary_shows_the_platforms_disk_encryption_state(client, token, value, expected):
    _serve(_detail(_signals(failing=1), encryption_ok=value))

    assert expected in _summary(_get(client, token, "/devices/dev-mac-001").text)


def test_stale_device_reads_evidence_stale_not_the_platforms_boolean(client, token):
    detail = _detail(_signals(failing=1), encryption_ok=True, patch_pending=False)
    detail["device"]["last_seen"] = "2026-07-02T09:58:00Z"
    _serve(detail)

    summary = _summary(_get(client, token, "/devices/dev-mac-001").text)

    assert "Encryption evidence stale" in summary
    assert "Update evidence stale" in summary
    assert "Up to date" not in summary


def test_stub_windows_device_has_no_update_state_and_says_so_once(client, token):
    # dev-win-002's roster row has patch_pending null, and its detail stub
    # carries the same value (real shape, nested under `device`).
    assert DEVICE_DETAIL_DEV_WIN_002["device"]["patch_pending"] is None

    body = _get(client, token, "/devices/dev-win-002").text

    assert "Update evidence stale" in body
    assert UNKNOWN_NOTE not in body
