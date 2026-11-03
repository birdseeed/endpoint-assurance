"""PAT-1642/PAT-1843: /devices grouped by reporting state.

Groups 1-3 (silent / quiet / reporting normally) are derived from real
/v1/portal/devices data via the existing, unmodified annotate_staleness /
days_since maths (PAT-701) - these tests only add new group-boundary and
page-structure coverage on top of that, they never re-derive the day maths
itself (see tests/test_stale_csv.py for the pinned boundary tests).

Groups 4/5 (reconciled against a customer-supplied device list) do not
exist yet (PAT-1595, unbuilt) - the gap card tests below assert the page
is honest about that instead of inventing zeros or a coverage percentage.
"""

import re
from datetime import UTC, datetime, timedelta

import main
from tests.conftest import NO_DEVICE_LIST, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _iso_days_ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# Fixture roster used by tests in this file: one device in each of the
# three real groups, plus a never-reported device (last_seen: None), so the
# "silent" group's full table and its mailto action links get real coverage
# (the shared conftest.DEVICES fixture has no device past 14 days silent).
GROUPED_DEVICES = {
    "devices": [
        {
            "device_id": "dev-normal-1", "hostname": "acme-normal-1",
            "platform": "macOS", "os_version": "15.5",
            "last_seen": _iso_days_ago(1), "cis_score": 90,
            "findings_open": 0, "encryption_ok": True, "patch_pending": False,
        },
        {
            "device_id": "dev-quiet-1", "hostname": "acme-quiet-1",
            "platform": "Windows", "os_version": "11 24H2",
            "last_seen": _iso_days_ago(5), "cis_score": 70,
            "findings_open": 1, "encryption_ok": True, "patch_pending": False,
        },
        {
            "device_id": "dev-silent-1", "hostname": "acme-silent-1",
            "platform": "macOS", "os_version": "14.7",
            "last_seen": _iso_days_ago(21), "cis_score": 40,
            "findings_open": 3, "encryption_ok": False, "patch_pending": True,
        },
        {
            "device_id": "dev-silent-2", "hostname": "acme-silent-never",
            "platform": "Windows", "os_version": "11 23H2",
            "last_seen": None, "cis_score": None,
            "findings_open": 0, "encryption_ok": False, "patch_pending": False,
        },
    ]
}


def _set_grouped_roster():
    STUB_STATE["devices_data"] = GROUPED_DEVICES


# ── bucket_group: pure function, boundaries per the ticket's own spec ────
def test_bucket_group_boundaries():
    assert main.bucket_group(None) == "silent"
    assert main.bucket_group(15) == "silent"
    assert main.bucket_group(14) == "quiet"  # "3 to 14" is inclusive of 14
    assert main.bucket_group(3) == "quiet"
    assert main.bucket_group(2) == "normal"
    assert main.bucket_group(0) == "normal"


# ── Default page: honest counts, no invented denominator ─────────────────
def test_default_page_shows_raw_count_with_no_denominator(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert ">6<" in resp.text  # the six conftest.DEVICES fixture rows (PAT-2324 added a server)
    # Never a fabricated "N of M" denominator or coverage percentage (root
    # AGENTS.md: CVE and usage claims require evidence; same discipline
    # applied here to device coverage). URL-encoded mailto links legitimately
    # contain percent signs, so assert against rendered percentage text.
    # PAT-2256: the CIS score column is a labelled percentage (its unit is
    # part of the figure, and it is a device's own score, not a coverage
    # claim), so only those spans are exempt from the search.
    without_scores = re.sub(r'<span class="score">[^<]*</span>', "", resp.text)
    assert re.search(r">\s*\d+(?:\.\d+)?%\s*<", without_scores) is None
    assert re.search(r"\d+\s*(?:of|/)\s*\d+", resp.text) is None


def test_default_page_has_one_horizontal_reporting_control_then_gap(client, make_token):
    _set_grouped_roster()
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    silent_pos = resp.text.index("Silent over 14 days (2)")
    quiet_pos = resp.text.index("Quiet 3–14 days (1)")
    normal_pos = resp.text.index("Reporting normally (1)")
    gap_pos = resp.text.index("Your device list")
    assert silent_pos < quiet_pos < normal_pos < gap_pos
    assert resp.text.count('data-row-filter="view"') == 1
    # PAT-1957: the default landing view is Reporting normally, not Silent.
    assert 'data-initial="normal"' in resp.text


def test_default_page_renders_all_server_bucketed_rows_with_actions(client, make_token):
    _set_grouped_roster()
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    # All device states share one table. Each row carries the authoritative
    # server bucket consumed by the client-side reporting-state control.
    assert "acme-silent-1" in resp.text
    assert "acme-silent-never" in resp.text
    assert "Never reported" in resp.text
    assert "acme-quiet-1" in resp.text
    assert "acme-normal-1" in resp.text
    assert resp.text.count('data-filter-view="silent"') == 2
    assert resp.text.count('data-filter-view="quiet"') == 1
    assert resp.text.count('data-filter-view="normal"') == 1
    # PAT-2135: every affordance retires the device directly, self-service -
    # never a mailto link to a Patched specialist (rubric C1). The rail's
    # own support link is a genuine mailto (PAT-454); device-row actions
    # are not.
    assert "Ask us to check" not in resp.text
    assert "Tell us it's gone" not in resp.text
    assert 'action="/devices/retirement"' in resp.text
    assert "Retire device" in resp.text
    assert "Retiring a device does not delete it here on its own" in resp.text


def test_default_page_tabs_show_unambiguous_counts_and_bookmark_links(client, make_token):
    _set_grouped_roster()
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert 'href="/devices?view=quiet"' in resp.text
    assert 'href="/devices?view=normal"' in resp.text
    assert 'href="/devices?view=silent"' in resp.text
    assert "Known devices" in resp.text
    assert "Reporting to us" not in resp.text


# ── The device-list card: honest with no list, and a real self-service
#    upload once one exists (PAT-2135) ─────────────────────────────────────
def test_gap_card_names_both_missing_groups_honestly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_list_data"] = NO_DEVICE_LIST
    resp = _get(client, token, "/devices")
    assert resp.status_code == 200
    assert "No device list on file yet." in resp.text
    assert "devices you expect but have not seen" in resp.text
    assert "devices reporting to Patched that are not on your list" in resp.text
    # Self-service upload, not a mailto request to a specialist (rubric C1).
    assert "Send us a device list" not in resp.text
    assert 'action="/devices/device-list"' in resp.text
    assert 'enctype="multipart/form-data"' in resp.text


# ── ?view=quiet / ?view=normal seed the same-page client view ─────────────
def test_view_quiet_seeds_filter_while_retaining_all_server_rows(client, make_token):
    _set_grouped_roster()
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices?view=quiet")
    assert resp.status_code == 200
    assert 'data-initial="quiet"' in resp.text
    assert 'data-filter-tab="quiet" class="tab-active"' in resp.text
    assert "acme-quiet-1" in resp.text
    assert "acme-silent-1" in resp.text
    assert "acme-normal-1" in resp.text


def test_view_normal_seeds_filter_while_retaining_all_server_rows(client, make_token):
    _set_grouped_roster()
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices?view=normal")
    assert resp.status_code == 200
    assert 'data-initial="normal"' in resp.text
    assert 'data-filter-tab="normal" class="tab-active"' in resp.text
    assert "acme-normal-1" in resp.text
    assert "acme-quiet-1" in resp.text
    assert "acme-silent-1" in resp.text


# ── Existing ?view=stale&stale_days=N contract is untouched ──────────────
def test_view_stale_contract_still_reachable_from_new_page(client, make_token):
    """PAT-701's browse-by-threshold mode is independent of the new fixed
    group boundaries above and keeps working unmodified."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/devices?view=stale&stale_days=7")
    assert resp.status_code == 200
    assert "acme-mbp-storeroom" in resp.text
