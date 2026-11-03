"""Devices list and device page tell the truth and read cleanly (Windows
update state, CIS figures, fonts, version strings, /alerts).

Found walking the live /devices and a device page with Andy on 28 Sept 2026,
plus the first authenticated prod walk on 29 Sept:

1. Both Windows devices read "Update state not reported" on every row. The
   Windows agent does send its OS-update verdict (os_update), but the
   platform's roster derives patch_pending only from the macOS-only
   pending_updates list, so it is null for every Windows device. The portal
   cannot make that a real answer, so a Windows row with no update state
   shows a dash and the page carries one muted note, never a pill per row.
   A Mac row with no update state keeps its pill (Windows/macOS parity: the
   Mac collector does report it, so null there really is "not reported").
2. The list said "38 / 35 open findings" and the device page "58 CIS issues"
   for the same Mac. The list's count is failing plus errored checks; the
   device page counted every non-pass signal, not_applicable included. One
   definition now: a failing check is a fail or error result.
3. The CIS score was a bare red number: it now carries its unit and no tone.
5. Identification block: monospace only for identifiers.
9. /alerts redirects to /software/alerts, query string kept.

Layout (overlap, mid-string version breaks, the theme toggle) is browser
territory: e2e/test_pat2256_devices_layout.py.
"""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE

UNKNOWN_NOTE = "This device hasn't reported a recent update state."


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


def _recent_iso(days=0.02):
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


def _device_row_html(body, hostname):
    """The <tr> of #device-table that holds `hostname`."""
    for match in re.finditer(r"<tr[^>]*>.*?</tr>", body, re.S):
        if hostname in match.group(0) and "<td" in match.group(0):
            return match.group(0)
    raise AssertionError(f"no device-table row for {hostname}")


def _cells(row_html):
    return re.findall(r"<td[^>]*>(.*?)</td>", row_html, re.S)


# ── 1. Windows update state ─────────────────────────────────────────────────
def test_windows_rows_with_no_update_state_show_one_note_not_a_pill_each(client, token):
    _set_roster(
        _row("dev-win-901", "HOMESERVER", "Windows", "10.0.20348.5499"),
        _row("dev-win-902", "WINDOWS11", "Windows", "10.0.26200.8457"),
        _row("dev-mac-901", "acme-mbp-ok", "macOS", "15.5", patch_pending=False),
    )

    body = _get(client, token, "/devices?view=normal").text

    assert "Update state not reported" not in body
    assert body.count('data-update-state-note>') == 1
    assert body.count(UNKNOWN_NOTE) == 3  # two titles and one table note
    # The Mac row's real answer is untouched.
    assert 'pill-ok">Up to date' in _device_row_html(body, "acme-mbp-ok")


def test_a_mac_row_with_no_update_state_uses_the_same_neutral_note(
    client, token,
):
    _set_roster(_row("dev-mac-902", "acme-mbp-null", "macOS", "15.5", patch_pending=None))

    body = _get(client, token, "/devices?view=normal").text

    assert "Update state not reported" not in body
    assert body.count(UNKNOWN_NOTE) == 2  # row title and table note


def test_a_windows_row_that_does_report_an_update_state_still_shows_it(client, token):
    _set_roster(
        _row("dev-win-903", "WIN-REPORTS", "Windows", "10.0.26200.8457", patch_pending=True),
    )

    body = _get(client, token, "/devices?view=normal").text

    assert 'pill-warn">Updates pending' in _device_row_html(body, "WIN-REPORTS")
    assert UNKNOWN_NOTE not in body


def test_device_page_summary_for_a_windows_device_with_no_update_state(client, token):
    detail = deepcopy(DEVICE_DETAIL)
    detail.update(platform="Windows", os_version="10.0.26200.8457", last_seen=_recent_iso())
    detail.pop("patch_pending", None)
    STUB_STATE["device_detail_data"] = detail

    body = _get(client, token, "/devices/dev-mac-001").text

    assert "Update state not reported" not in body
    assert body.count(UNKNOWN_NOTE) == 1


def test_device_page_summary_for_a_mac_with_no_update_state_uses_neutral_note(client, token):
    detail = deepcopy(DEVICE_DETAIL)
    detail.update(last_seen=_recent_iso())  # a stale device reads "evidence stale" instead
    detail.pop("patch_pending", None)
    STUB_STATE["device_detail_data"] = detail

    body = _get(client, token, "/devices/dev-mac-001").text

    assert body.count(UNKNOWN_NOTE) == 1


# ── 2 + 3. CIS figures: one definition, labelled, neutral ───────────────────
def _signals(passing, failing, errored, not_applicable):
    rows = []
    for kind, count in (("pass", passing), ("fail", failing), ("error", errored),
                        ("not_applicable", not_applicable)):
        for n in range(count):
            rows.append({
                "rule_id": f"cis_macos_{kind}_{n}", "title": f"{kind} check {n}",
                "severity": "medium", "status": kind, "advisory": "",
            })
    return rows


def _mac_with_known_cis_figures():
    """One Mac, the way the real platform describes it: the roster's score is
    pass / (pass + fail + error) and its findings_open is fail + error; the
    device page carries the same score and the full per-check list, which
    also holds not_applicable results."""
    passing, failing, errored, not_applicable = 38, 57, 5, 20
    score = passing * 100 / (passing + failing + errored)
    _set_roster(_row(
        "dev-mac-001", "MacBook-Pro", "macOS", "15.5",
        cis_score=score, findings_open=failing + errored, patch_pending=False,
    ))
    detail = deepcopy(DEVICE_DETAIL)
    detail.update(
        hostname="MacBook-Pro", cis_score=score, last_seen=_recent_iso(),
        compliance_signals=_signals(passing, failing, errored, not_applicable),
        # PAT-2294: the platform sends the roster's own findings_open here too.
        findings_open=failing + errored,
    )
    STUB_STATE["device_detail_data"] = detail
    return score, failing + errored


def _list_figures(body):
    row = _device_row_html(body, "MacBook-Pro")
    score = re.search(r'<span class="score[^"]*">([^<]*)</span>', row).group(1)
    failing = re.search(r'<span class="device-checks">(\d+) failing</span>', row).group(1)
    return score, failing


def _page_figures(body):
    strip = re.search(
        r'<span class="device-tab-label[^"]*">Compliance \((\d+) failing\)</span>',
        body)
    summary = re.search(r"<dt>CIS Level 1 score</dt><dd>([^<]*)</dd>", body)
    return summary.group(1), strip.group(1)


def test_list_and_device_page_show_the_same_cis_figures_for_the_same_device(client, token):
    score, failing = _mac_with_known_cis_figures()

    list_score, list_failing = _list_figures(_get(client, token, "/devices?view=normal").text)
    page_score, page_failing = _page_figures(_get(client, token, "/devices/dev-mac-001").text)

    assert list_score == page_score == f"{round(score)}%"
    assert list_failing == page_failing == str(failing)


def test_list_labels_the_score_as_a_percentage_and_the_count_as_failing_checks(client, token):
    _mac_with_known_cis_figures()

    body = _get(client, token, "/devices?view=normal").text

    assert "<th data-sort=\"num\">CIS / checks</th>" in body
    assert "62 failing" in body
    assert "Open findings" not in body
    assert '<span class="score">38%</span>' in body


def test_cis_score_in_the_list_carries_no_red_amber_or_green_tone(client, token):
    _set_roster(
        _row("dev-mac-911", "low-score", "macOS", "15.5", cis_score=12),
        _row("dev-mac-912", "mid-score", "macOS", "15.5", cis_score=70),
        _row("dev-mac-913", "high-score", "macOS", "15.5", cis_score=95),
    )

    body = _get(client, token, "/devices?view=normal").text

    for hostname in ("low-score", "mid-score", "high-score"):
        cell = re.search(r'<span class="score([^"]*)">', _device_row_html(body, hostname))
        assert cell and cell.group(1) == "", f"{hostname}: score is toned ({cell.group(1)!r})"


def test_a_missing_cis_score_stays_a_dash_not_0_percent(client, token):
    _set_roster(_row("dev-mac-914", "no-score", "macOS", "15.5", cis_score=None))

    body = _get(client, token, "/devices?view=normal").text

    assert '<span class="score">Not assessed</span>' in body
    assert "0%" not in _device_row_html(body, "no-score")


def test_device_page_summary_score_carries_its_unit(client, token):
    body = _get(client, token, "/devices/dev-mac-001").text

    assert "<dt>CIS Level 1 score</dt><dd>65%</dd>" in body


def test_not_applicable_is_never_a_failing_check():
    signals = _signals(passing=3, failing=2, errored=1, not_applicable=10)

    tile = main._device_issues_tile_view(signals, False)

    assert tile["value"] == 3 and tile["is_count"] is True


def test_only_not_applicable_and_pass_results_make_a_real_zero():
    signals = _signals(passing=4, failing=0, errored=0, not_applicable=6)

    tile = main._device_issues_tile_view(signals, False)

    assert tile["value"] == 0 and tile["is_count"] is True


def test_compliance_tab_shows_not_applicable_as_muted_not_as_a_failure(client, token):
    detail = deepcopy(DEVICE_DETAIL)
    detail["compliance_signals"] = _signals(passing=1, failing=1, errored=0, not_applicable=1)
    STUB_STATE["device_detail_data"] = detail

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert 'pill-muted">Not applicable' in body
    assert 'pill-bad">Not_applicable' not in body
    assert 'pill-bad">Fail' in body


# ── 5. Identification block fonts ───────────────────────────────────────────
def test_identification_block_uses_monospace_only_for_identifiers(client, token):
    body = _get(client, token, "/devices/dev-mac-001").text
    block = body[body.index('id="identification"'):body.index('id="retirement"')]

    monospace = re.findall(r'<dt>([^<]*)</dt><dd class="mono">', block)
    assert monospace == ["Serial", "Model identifier"]
    # The freshness line above the list is prose, not an identifier.
    assert 'class="mono">Observed' not in block
    # Everything else in the list is present, in sans.
    for label in ("Computer name", "Architecture", "Operating system", "Agent version",
                  "First seen", "Last seen"):
        assert f"<dt>{label}</dt><dd>" in block


# ── 7. Version-shaped strings never break ───────────────────────────────────
def test_os_version_cells_are_marked_unbreakable_and_keep_the_full_value(client, token):
    _set_roster(_row("dev-win-921", "HOMESERVER", "Windows", "10.0.20348.5499"))

    row = _device_row_html(_get(client, token, "/devices?view=normal").text, "HOMESERVER")

    assert 'data-label="OS version" class="cell-os-named"' in row
    assert 'title="10.0.20348.5499"' in row
    assert '<span class="os-build">10.0.20348.5499</span>' in row


def test_cell_version_rule_forbids_wrapping_and_never_lets_the_text_spill():
    css = (main.STATIC_DIR / "css" / "portal.css").read_text()
    rule = re.search(r"\.cell-version\s*\{([^}]*)\}", css)

    assert rule, ".cell-version has no rule"
    assert "white-space: nowrap" in rule.group(1)
    assert "overflow: hidden" in rule.group(1)
    assert "text-overflow: ellipsis" in rule.group(1)


# ── 9. /alerts ──────────────────────────────────────────────────────────────
def test_alerts_redirects_to_the_software_alerts_page(client, token):
    resp = client.get("/alerts", headers={"Cf-Access-Jwt-Assertion": token},
                      follow_redirects=False)

    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/software/alerts"


def test_alerts_redirect_keeps_the_query_string(client, token):
    resp = client.get("/alerts?status=acknowledged&device=dev-mac-001",
                      headers={"Cf-Access-Jwt-Assertion": token}, follow_redirects=False)

    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/software/alerts?status=acknowledged&device=dev-mac-001"


def test_alerts_redirect_lands_on_the_real_page(client, token):
    resp = client.get("/alerts?status=acknowledged",
                      headers={"Cf-Access-Jwt-Assertion": token}, follow_redirects=True)

    assert resp.status_code == 200
    assert "<h1>Alerts</h1>" in resp.text


def test_alerts_redirect_is_not_reachable_without_a_session(client):
    resp = client.get("/alerts", follow_redirects=False)

    assert resp.status_code == 401
    assert "location" not in resp.headers


# ── What's new ──────────────────────────────────────────────────────────────
def test_whats_new_has_a_fixed_entry_for_this_change():
    entries = [e for e in main.CHANGELOG_ENTRIES
               if e["tag"] == "Fixed" and e["link"] == "/devices"
               and "update state" in e["body"].lower()]

    assert entries, "no Fixed /devices entry about update state in data/changelog.json"
