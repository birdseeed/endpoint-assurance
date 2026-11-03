"""PAT-2164: the device page's sections behind horizontal tabs (Overview,
Hardware, Software, Vulnerabilities, Compliance, Evidence), superseding the
single long scroll PAT-2141 built.

Covers: each tab route renders only its own section(s), the shared head
(tab bar with counts) renders identically everywhere and deep-links to
the right tab, tab counts (including the "unknown never reads as 0" rule),
404 for an unknown tab path, not-found for a foreign/unknown device on
every tab route, and that the Software tab's strict-UUID approval return
path is untouched by the new routes (must not be loosened to also accept
them). Data-level guarantees for the sections themselves (identity/hardware
absence handling, CVE assessment states, compliance lifecycle, evidence
chips) already live in their own PAT-1868/1879/2025/2099/2141 test files,
now pointed at the tab each section moved to - this file is about the tab
mechanism itself.
"""

from copy import deepcopy

import main
from tests.conftest import (
    DEVICE_DETAIL,
    DEVICE_EXTENSIONS,
    DEVICE_SOFTWARE,
    DEVICE_SOFTWARE_UUID_ID,
    STUB_STATE,
)

DEVICE_ID = "dev-mac-001"

TAB_PATHS = {
    "overview": f"/devices/{DEVICE_ID}",
    "hardware": f"/devices/{DEVICE_ID}/hardware",
    "software": f"/devices/{DEVICE_ID}/software",
    "vulnerabilities": f"/devices/{DEVICE_ID}/vulnerabilities",
    "compliance": f"/devices/{DEVICE_ID}/compliance",
    "evidence": f"/devices/{DEVICE_ID}/evidence",
}


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Each tab renders its own sections, and not the others' ────────────────
# One marker string per tab that only that tab's own section renders, and
# one it must never leak.
TAB_OWN_MARKER = {
    "overview": 'id="device-card-title"',
    "hardware": 'id="hardware"',
    "software": "device-software-table",
    "vulnerabilities": "Applications with open findings",
    "compliance": 'id="compliance-signals"',
    "evidence": 'id="evidence-collection-title"',
}


def test_each_tab_renders_its_own_marker_and_no_other_tabs_marker(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for tab, path in TAB_PATHS.items():
        resp = _get(client, token, path)
        assert resp.status_code == 200, tab
        body = resp.text
        assert TAB_OWN_MARKER[tab] in body, f"{tab} is missing its own marker"
        for other_tab, marker in TAB_OWN_MARKER.items():
            if other_tab == tab:
                continue
            # "hardware" (id="hardware") and "compliance-signals" markers
            # are deliberately exact-id matches so a chip/link elsewhere
            # referencing the same word (e.g. an evidence chip's "Hardware
            # health: battery" label) never false-positives this check.
            assert marker not in body, f"{tab} leaked {other_tab}'s marker ({marker!r})"


def test_overview_has_identity_summary_and_collection_issues_only(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["agent_health_degraded"] = [
        {"kind": "tcc_denied", "subject": "browser_extensions",
         "reason": "full_disk_access_missing", "first_seen": "2026-09-20T09:00:00Z",
         "last_seen": "2026-09-24T09:00:00Z", "count": 1},
    ]
    STUB_STATE["device_detail_data"] = detail

    resp = _get(client, token, TAB_PATHS["overview"])
    body = resp.text
    assert "Identification" in body
    assert 'id="device-assurance"' in body
    assert ">Summary<" not in body
    assert "Collection issues" in body
    assert 'id="hardware"' not in body  # Hardware
    assert "CVE assessment" not in body  # Vulnerabilities
    assert 'id="compliance-signals"' not in body  # Compliance
    assert "Evidence collection" not in body  # Evidence


def test_evidence_tab_also_shows_collection_issues(client, make_token):
    # PAT-2164's own tab-content mapping lists "collection-issues detail"
    # under Evidence too, alongside Overview - the same table, not dropped.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["agent_health_degraded"] = [
        {"kind": "tcc_denied", "subject": "mcp_servers",
         "reason": "full_disk_access_missing", "first_seen": "2026-09-20T09:00:00Z",
         "last_seen": "2026-09-24T09:00:00Z", "count": 1},
    ]
    STUB_STATE["device_detail_data"] = detail

    resp = _get(client, token, TAB_PATHS["evidence"])
    body = resp.text
    assert "Evidence collection" in body
    assert "Collection issues" in body
    assert "MCP servers could not be read" in body


# ── Shared head renders identically on every tab ───────────────────────────
def test_every_tab_shares_the_same_head(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for _tab, path in TAB_PATHS.items():
        resp = _get(client, token, path)
        body = resp.text
        assert "acme-mbp-frontdesk" in body  # hostname, <h1>
        assert 'class="card kpi count-strip"' not in body
        assert "Vulnerabilities (2)" in body
        assert "Compliance (1 failing)" in body
        assert "Software (5)" in body
        assert 'class="devices-toolbar device-tab-bar"' in body


def test_deep_links_point_at_the_right_tabs(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, TAB_PATHS["overview"])
    body = resp.text
    assert f'href="/devices/{DEVICE_ID}/vulnerabilities"' in body
    assert f'href="/devices/{DEVICE_ID}/compliance"' in body
    assert f'href="/devices/{DEVICE_ID}/software"' in body
    for tab, path in TAB_PATHS.items():
        assert f'href="{path}"' in body, tab

    evidence_body = _get(client, token, TAB_PATHS["evidence"]).text
    # PAT-2141's evidence chip now deep-links across tabs rather than to an
    # in-page #hardware anchor on the same page.
    assert f'href="/devices/{DEVICE_ID}/hardware#hardware"' in evidence_body


def test_active_tab_is_marked_current(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for _tab, path in TAB_PATHS.items():
        body = _get(client, token, path).text
        assert 'aria-current="page"' in body
        active_href = f'href="{path}"'
        assert active_href in body


# ── Tab counts ──────────────────────────────────────────────────────────
def test_vulnerabilities_and_compliance_tabs_carry_real_counts(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    body = _get(client, token, TAB_PATHS["overview"]).text
    # DEVICE_DETAIL: 2 CVE findings, 1 open (failing) compliance signal.
    assert "Vulnerabilities (2)" in body
    assert "Compliance (1 failing)" in body


def test_software_tab_carries_the_combined_total(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    body = _get(client, token, TAB_PATHS["overview"]).text
    # DEVICE_SOFTWARE fixture products + DEVICE_EXTENSIONS rows.
    apps_total = len(DEVICE_SOFTWARE["products"])
    ext_total = len(DEVICE_EXTENSIONS["extensions"])
    assert f"Software ({apps_total + ext_total})" in body


def test_unknown_vulnerabilities_count_shows_no_number_never_zero(client, make_token):
    # dev-mac-002/003/dev-win-002 all use DEVICE_DETAIL_ALL_NOT_ASSESSED's
    # cve_assessment (state "not_assessed") - never a real count.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    body = _get(client, token, "/devices/dev-mac-002").text
    assert "Vulnerabilities (Not assessed)" in body
    assert "Vulnerabilities (0)" not in body
    for char in "0123456789":
        assert f"Vulnerabilities ({char}" not in body


def test_unknown_software_total_shows_unavailable_never_zero(client, make_token):
    # dev-mac-002 is not one of the stub's known software/extensions device
    # ids, so both totals fail soft to None - the tile must say so, not 0.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    body = _get(client, token, "/devices/dev-mac-002").text
    assert "Software (Unavailable)" in body
    assert "Software (0)" not in body


def test_unknown_compliance_count_shows_no_number_never_zero(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["compliance_signals"] = []
    # PAT-2294: nothing evaluated means the platform counts none failing, and
    # a zero with no signals behind it must still not read as a clean device.
    detail["findings_open"] = 0
    STUB_STATE["device_detail_data"] = detail

    body = _get(client, token, TAB_PATHS["overview"]).text
    assert "Compliance (Not available)" in body
    assert "Compliance (0 failing)" not in body
    assert "failing" not in body


def test_zero_is_a_real_count_and_still_shown(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["compliance_signals"] = [
        {"rule_id": "cis-1.1", "title": "Automatic software updates enabled",
         "severity": "high", "status": "pass", "advisory": ""},
    ]
    detail["cve_assessment"] = {
        "state": "assessed", "last_matched_at": "2026-07-02T09:00:00Z",
        "finding_count": 0, "assessed_products": 1, "pending_products": 0,
        "not_assessed_products": 0,
        "products": [{"app": "CleanApp", "versions": ["1.0"], "state": "assessed",
                       "last_matched_at": "2026-07-02T09:00:00Z", "finding_count": 0}],
    }
    detail["apps_with_findings"] = []
    # PAT-2294: the platform sends findings_open with the signals it describes.
    detail["findings_open"] = 0
    STUB_STATE["device_detail_data"] = detail

    body = _get(client, token, TAB_PATHS["overview"]).text
    assert "Vulnerabilities (0)" in body
    assert "Compliance (0 failing)" in body


# ── Routing guards ──────────────────────────────────────────────────────
def test_unknown_tab_path_is_a_404(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, f"/devices/{DEVICE_ID}/bogus-tab")
    assert resp.status_code == 404


def test_unknown_device_is_not_found_on_every_tab(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for tab, path in TAB_PATHS.items():
        unknown_path = path.replace(DEVICE_ID, "dev-mac-999")
        resp = _get(client, token, unknown_path)
        if tab == "software":
            assert resp.status_code == 404, tab
            assert "That device could not be found in your estate." in resp.text
        else:
            assert resp.status_code == 404, tab
            assert "That item could not be found in your estate." in resp.text


def test_malformed_device_id_is_not_found_on_every_tab(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for tab, path in TAB_PATHS.items():
        malformed_path = path.replace(DEVICE_ID, "Not_Valid")
        resp = _get(client, token, malformed_path)
        assert resp.status_code == 404, tab


def test_foreign_tenant_shaped_device_is_not_found_on_every_tab(client, make_token):
    # A plausibly-shaped id the stub simply doesn't serve reads identically
    # to a genuinely unknown one - device_id can never be an existence oracle.
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for tab, path in TAB_PATHS.items():
        other_tenant_path = path.replace(DEVICE_ID, "dev-mac-other-tenant")
        resp = _get(client, token, other_tenant_path)
        assert resp.status_code == 404, tab


# ── Approval return-path guard is untouched by the new routes ─────────────
def test_approval_return_to_still_accepts_only_the_software_tab_path():
    accepted = main._approval_return_to(f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software")
    assert accepted == f"/devices/{DEVICE_SOFTWARE_UUID_ID}/software"


def test_approval_return_to_rejects_every_new_tab_path():
    # PAT-2164's own rule: the guard must not be loosened for the new tabs.
    for tab in ("hardware", "vulnerabilities", "compliance", "evidence"):
        rejected = main._approval_return_to(f"/devices/{DEVICE_SOFTWARE_UUID_ID}/{tab}")
        assert rejected == "/software", tab


def test_approval_return_to_rejects_the_bare_overview_uuid_path():
    rejected = main._approval_return_to(f"/devices/{DEVICE_SOFTWARE_UUID_ID}")
    assert rejected == "/software"


# ── _device_tab_definitions (unit level) ───────────────────────────────────
def test_tab_definitions_unknown_counts_show_no_number():
    tabs = main._device_tab_definitions(
        "dev-mac-001", "overview",
        {"value": "Checking", "tone": "mute-text", "is_count": False, "stale": False},
        {"value": "Not available", "tone": "mute-text", "is_count": False, "stale": False},
        (None, None),
    )
    by_key = {t["key"]: t for t in tabs}
    for key in ("vulnerabilities", "compliance", "software"):
        assert by_key[key]["count_display"] is None, key


def test_tab_definitions_real_counts_and_urls():
    tabs = main._device_tab_definitions(
        "dev-mac-001", "vulnerabilities",
        {"value": 2, "tone": "bad-text", "is_count": True, "stale": False},
        {"value": 1, "tone": "bad-text", "is_count": True, "stale": False},
        (79, 3),
    )
    by_key = {t["key"]: t for t in tabs}
    assert by_key["vulnerabilities"]["count_display"] == "2"
    assert by_key["compliance"]["count_display"] == "1 failing"
    assert by_key["software"]["count_display"] == "82"
    assert by_key["vulnerabilities"]["current"] is True
    assert by_key["overview"]["current"] is False
    assert by_key["overview"]["url"] == "/devices/dev-mac-001"
    assert by_key["hardware"]["url"] == "/devices/dev-mac-001/hardware"
    assert by_key["software"]["url"] == "/devices/dev-mac-001/software"
    assert by_key["vulnerabilities"]["url"] == "/devices/dev-mac-001/vulnerabilities"
    assert by_key["compliance"]["url"] == "/devices/dev-mac-001/compliance"
    assert by_key["evidence"]["url"] == "/devices/dev-mac-001/evidence"


def test_tab_definitions_zero_counts_are_real_not_hidden():
    tabs = main._device_tab_definitions(
        "dev-mac-001", "overview",
        {"value": 0, "tone": "mute-text", "is_count": True, "stale": False},
        {"value": 0, "tone": "mute-text", "is_count": True, "stale": False},
        (0, 0),
    )
    by_key = {t["key"]: t for t in tabs}
    assert by_key["vulnerabilities"]["count_display"] == "0"
    assert by_key["compliance"]["count_display"] == "0 failing"
    assert by_key["software"]["count_display"] == "0"
