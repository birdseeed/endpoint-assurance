"""A rule whose value could not be read is "Not assessed" on the Compliance tab.

`GET /v1/portal/devices/{id}` sends each rule result as `{rule_id, title,
severity, status, advisory, undetermined}`. `undetermined` is true exactly
when `status` is `fail` only because nothing was observed (an unreadable
value). The Devices roster and the device page already say "Not assessed" for
that device's disk encryption, so the Compliance tab must too, and its
failing count must not include the row.

Only a JSON `true` counts. A platform that predates the field sends no
`undetermined` at all, and such a row behaves exactly as it always did.
"""

import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

import main
from tests.conftest import (
    DEVICE_DETAIL,
    INSURANCE_EVIDENCE,
    STUB_STATE,
    platform_shaped_detail,
)

NOT_ASSESSED_PILL = '<span class="pill pill-muted">Not assessed</span>'
FAIL_PILL = '<span class="pill pill-bad">Fail</span>'
NOT_ENCRYPTED_PILL = '<span class="pill pill-bad">Not encrypted</span>'
TILE = re.compile(
    r'<span class="device-tab-label ([^"]*)">Compliance \(([^<]*)\)</span>')

ENCRYPTION_TITLE = "BitLocker protects the system drive"


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


@pytest.fixture
def token(make_token):
    value = make_token()
    STUB_STATE["expected_jwt"] = value
    return value


def _recent_iso(days=0.02):
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rule(title, status="fail", severity="high", **extra):
    return {
        "rule_id": title.lower().replace(" ", "_"), "title": title,
        "severity": severity, "status": status, "advisory": "", **extra,
    }


def _serve(signals, *, keep_findings_open=True, **device_fields):
    """A fresh detail response in the platform's real shape, served for
    dev-mac-001. `keep_findings_open=False` leaves the platform's figure out,
    which is what sends the page to its fallback count."""
    flat = deepcopy(DEVICE_DETAIL)
    flat.update(last_seen=_recent_iso(), compliance_signals=signals)
    detail = platform_shaped_detail(flat, **device_fields)
    if not keep_findings_open:
        del detail["device"]["findings_open"]
    STUB_STATE["device_detail_data"] = detail
    return detail


def _status_cell(body, title):
    rows = [chunk for chunk in body.split("<tr>") if f'data-label="Control">{title}' in chunk]
    assert len(rows) == 1, f"expected one row titled {title!r}, found {len(rows)}"
    cell = re.search(r'<td data-label="Status">(.*?)</td>', rows[0], re.S)
    assert cell, "no Status cell"
    return cell.group(1)


def _severity_cell(body, title):
    row = next(chunk for chunk in body.split("<tr>") if f'data-label="Control">{title}' in chunk)
    return re.search(r'<td data-label="Severity">(.*?)</td>', row, re.S).group(1)


def _tile(body):
    match = TILE.search(body)
    assert match, "no Compliance count on the page"
    return match.group(2).removesuffix(" failing"), match.group(1)


def _summary_encryption(body):
    start = body.index("<dt>Disk encryption</dt>")
    return body[start:body.index("</dd>", start)]


def _roster_encryption(body, hostname):
    row = next(chunk for chunk in body.split("<tr") if f">{hostname}</a>" in chunk)
    return re.search(r'data-label="Encryption"[^>]*>(.*?)</td>', row, re.S).group(1).strip()


# ── 1. The status cell ──────────────────────────────────────────────────────
def test_undetermined_rule_reads_not_assessed_with_the_neutral_pill(client, token):
    _serve([_rule(ENCRYPTION_TITLE, undetermined=True)])

    body = _get(client, token, "/devices/dev-mac-001/compliance").text
    cell = _status_cell(body, ENCRYPTION_TITLE)

    assert cell == NOT_ASSESSED_PILL
    assert "pill-bad" not in cell
    assert "Fail" not in cell
    # The severity pill is untouched.
    assert _severity_cell(body, ENCRYPTION_TITLE) == '<span class="pill pill-high">High</span>'


def test_observed_failure_still_reads_fail_with_the_failing_pill(client, token):
    _serve([_rule(ENCRYPTION_TITLE, undetermined=False)])

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert _status_cell(body, ENCRYPTION_TITLE) == FAIL_PILL


@pytest.mark.parametrize("extra", [
    pytest.param({}, id="field-missing-older-platform"),
    pytest.param({"undetermined": "true"}, id="string-true"),
    pytest.param({"undetermined": 1}, id="number-one"),
    pytest.param({"undetermined": None}, id="null"),
    pytest.param({"undetermined": "yes"}, id="string-yes"),
    pytest.param({"undetermined": ["x"]}, id="list"),
])
def test_anything_but_a_json_true_renders_exactly_as_before(client, token, extra):
    _serve([_rule(ENCRYPTION_TITLE, **extra)])

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert _status_cell(body, ENCRYPTION_TITLE) == FAIL_PILL


def test_other_statuses_are_unchanged_beside_an_undetermined_row(client, token):
    _serve([
        _rule("Passing check", status="pass", undetermined=False),
        _rule("Not applicable check", status="not_applicable", undetermined=False),
        _rule("Erroring check", status="error", undetermined=False),
        _rule(ENCRYPTION_TITLE, undetermined=True),
    ])

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert _status_cell(body, "Passing check") == '<span class="pill pill-ok">Pass</span>'
    assert _status_cell(body, "Not applicable check") == (
        '<span class="pill pill-muted">Not applicable</span>')
    assert _status_cell(body, "Erroring check") == '<span class="pill pill-bad">Error</span>'
    assert _status_cell(body, ENCRYPTION_TITLE) == NOT_ASSESSED_PILL


# ── 2. The fixture devices carry all three cases ────────────────────────────
def test_fixture_devices_cover_undetermined_observed_and_no_field(client, token):
    # dev-win-101: roster encryption_ok is null, its rule is undetermined.
    body = _get(client, token, "/devices/dev-win-101/compliance").text
    assert _status_cell(body, ENCRYPTION_TITLE) == NOT_ASSESSED_PILL
    assert _roster_encryption(_get(client, token, "/devices?view=normal").text,
                              "acme-win-dc1") == NOT_ASSESSED_PILL

    # dev-win-002: roster encryption_ok is false, its rule is an observed failure.
    body = _get(client, token, "/devices/dev-win-002/compliance").text
    assert _status_cell(body, ENCRYPTION_TITLE) == FAIL_PILL
    assert _roster_encryption(_get(client, token, "/devices?view=normal").text,
                              "acme-win-accounts") == NOT_ENCRYPTED_PILL

    # dev-mac-001: an older platform's rows, no `undetermined` field anywhere.
    assert all("undetermined" not in s for s in DEVICE_DETAIL["compliance_signals"])
    body = _get(client, token, "/devices/dev-mac-001/compliance").text
    assert _status_cell(body, "Firewall enabled") == FAIL_PILL
    assert _status_cell(body, "Automatic software updates enabled") == (
        '<span class="pill pill-ok">Pass</span>')


# ── 3. Roster, device page and Compliance tab agree ─────────────────────────
@pytest.mark.parametrize("encryption_ok,undetermined,roster_and_summary,tab_status", [
    pytest.param(None, True, 'pill-muted">Not assessed', NOT_ASSESSED_PILL, id="unreadable"),
    pytest.param(False, False, 'pill-bad">Not encrypted', FAIL_PILL, id="observed-off"),
])
def test_roster_device_page_and_compliance_tab_agree(
        client, token, encryption_ok, undetermined, roster_and_summary, tab_status):
    STUB_STATE["devices_data"] = {"devices": [{
        "device_id": "dev-mac-001", "hostname": "agree-host", "platform": "Windows",
        "os_version": "10.0.26200.8457", "last_seen": _recent_iso(), "cis_score": 50,
        "findings_open": 1 if encryption_ok is False else 0,
        "encryption_ok": encryption_ok, "patch_pending": False,
    }]}
    _serve([_rule(ENCRYPTION_TITLE, undetermined=undetermined)],
           encryption_ok=encryption_ok,
           findings_open=1 if encryption_ok is False else 0)

    roster = _roster_encryption(_get(client, token, "/devices?view=normal").text, "agree-host")
    summary = _summary_encryption(_get(client, token, "/devices/dev-mac-001").text)
    tab = _status_cell(_get(client, token, "/devices/dev-mac-001/compliance").text,
                       ENCRYPTION_TITLE)

    assert roster_and_summary in roster
    assert roster_and_summary in summary
    assert tab == tab_status


# ── 4. The failing count and the tab label ──────────────────────────────────
def test_fallback_count_leaves_out_an_undetermined_row(client, token):
    _serve([
        _rule("Observed one", undetermined=False),
        _rule("Observed two"),
        _rule(ENCRYPTION_TITLE, undetermined=True),
        _rule("Passing check", status="pass"),
    ], keep_findings_open=False)

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert _tile(body)[0] == "2"
    assert "Compliance (2 failing)" in body


def test_fallback_count_still_counts_a_row_with_no_undetermined_field(client, token):
    _serve([_rule("Observed one"), _rule("Observed two"), _rule("Observed three")],
           keep_findings_open=False)

    assert _tile(_get(client, token, "/devices/dev-mac-001/compliance").text)[0] == "3"


def test_fallback_count_for_only_undetermined_rows_is_zero_not_a_failure(client, token):
    _serve([_rule(ENCRYPTION_TITLE, undetermined=True)], keep_findings_open=False)

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert _tile(body) == ("0", "mute-text")
    assert _status_cell(body, ENCRYPTION_TITLE) == NOT_ASSESSED_PILL


def test_platform_findings_open_is_never_changed_by_an_undetermined_row(client, token):
    _serve([_rule("Observed one"), _rule(ENCRYPTION_TITLE, undetermined=True)],
           findings_open=7)

    body = _get(client, token, "/devices/dev-mac-001/compliance").text

    assert _tile(body)[0] == "7"
    assert "Compliance (7 failing)" in body


def test_an_undetermined_row_does_not_set_the_count_tone(client, token):
    # One observed low failure and one unreadable critical rule: the count's
    # colour comes from the failing check only, in both counting paths.
    signals = [
        _rule("Observed low", severity="low", undetermined=False),
        _rule(ENCRYPTION_TITLE, severity="critical", undetermined=True),
    ]
    _serve(signals, keep_findings_open=False)
    assert _tile(_get(client, token, "/devices/dev-mac-001/compliance").text) == (
        "1", "mute-text")

    _serve(signals, findings_open=1)
    assert _tile(_get(client, token, "/devices/dev-mac-001/compliance").text) == (
        "1", "mute-text")


def test_tile_view_counts_only_exact_json_true_as_undetermined():
    signals = [
        _rule("a", undetermined=True),
        _rule("b", undetermined="true"),
        _rule("c", undetermined=1),
        _rule("d", undetermined=None),
        _rule("e"),
    ]

    tile = main._device_issues_tile_view(signals, False)

    assert tile["value"] == 4
    assert tile["is_count"] is True


# ── 5. The insurance evidence pack names the devices that are off ───────────
def test_insurance_pack_renders_the_disk_encryption_naming_sentence(client, token):
    resp = _get(client, token, "/reports/insurance-evidence")
    assert resp.status_code == 200
    page = resp.text
    block = page[page.index('id="q-disk_encryption"'):page.index('id="q-patching_speed"')]

    disk = next(q for q in INSURANCE_EVIDENCE["questions"] if q["id"] == "disk_encryption")
    sentence = "Encryption is turned off on: acme-win-accounts."
    assert sentence in disk["answer_text"]
    assert sentence in block
    # The platform's text is rendered as it is, not rebuilt by the portal.
    assert disk["answer_text"] in block


def test_insurance_pack_disk_encryption_counts_add_up():
    disk = next(q for q in INSURANCE_EVIDENCE["questions"] if q["id"] == "disk_encryption")
    counts = disk["answer"]["counts"]

    assert counts["not_encrypted"] == 1
    assert counts["devices_in_scope"] == (
        counts["encrypted"] + counts["not_encrypted"]
        + counts["no_evidence"] + counts["not_reporting"])
    assert counts["no_evidence"] + counts["not_reporting"] == disk["unknown_devices"]
    assert "1 device reports encryption turned off." in disk["answer_text"]
