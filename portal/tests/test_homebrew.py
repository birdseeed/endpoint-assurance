"""Homebrew tab (PAT-1999): rendering against the stubbed PAT-2013 platform
API in tests/conftest.py (HOMEBREW_* fixtures, /v1/portal/homebrew/* stub
routes). Read-only - there is no write path to test because the platform
does not carry Homebrew approval state yet (see main.py's homebrew()
docstring)."""

import csv
import io

from tests.conftest import STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Auth ────────────────────────────────────────────────────────────────
def test_homebrew_requires_auth(client):
    resp = client.get("/homebrew")
    assert resp.status_code == 401


def test_homebrew_device_detail_requires_auth(client):
    resp = client.get("/homebrew/devices/hb-mac-01")
    assert resp.status_code == 401


# ── Renders from fixture data ─────────────────────────────────────────────
def test_homebrew_tab_renders_summary_and_sections(client, make_token):
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    assert "openssl@3" in body
    assert "readline" in body
    assert "firefox" in body
    assert "acme/tools" in body
    assert "mac-01" in body
    # KPI strip uses the platform's own totals, not a portal recomputation.
    assert "1 of 2" in body  # devices_with_homebrew of macos_device_count


def test_homebrew_nav_item_present_and_active(client, make_token):
    resp = _get(client, make_token(), "/homebrew")
    assert 'href="/homebrew" class="rail__item active"' in resp.text


# ── Dependency toggle ──────────────────────────────────────────────────────
def test_dependency_toggle_hides_dependency_only_by_default(client, make_token):
    resp = _get(client, make_token(), "/homebrew")
    body = resp.text
    # openssl@3 was installed on request; readline only as a dependency.
    assert 'data-filter-dep="on_request"' in body
    assert 'data-filter-dep="dependency"' in body
    # The segmented control's initial/default selection is on-request, so a
    # dependency-only row starts filtered out client-side.
    assert 'data-row-filter="dep"' in body
    assert 'data-initial="on_request"' in body
    assert 'data-default-value="on_request"' in body


# ── Third-party taps flagged ───────────────────────────────────────────────
def test_third_party_tap_is_flagged(client, make_token):
    resp = _get(client, make_token(), "/homebrew")
    body = resp.text
    idx = body.index("acme/tools")
    assert "Third-party" in body[idx:idx + 400]


# ── Cask linked to an app is not double counted ───────────────────────────
def test_linked_cask_points_at_software_instead_of_double_counting(client, make_token):
    resp = _get(client, make_token(), "/homebrew")
    body = resp.text
    assert "/software?search=Firefox" in body
    assert "View Firefox in Software" in body


def test_linked_app_name_without_app_suffix_is_kept_as_is(client, make_token):
    # A cask row whose app_names entry does not end in ".app" must be used
    # verbatim, not have its last four characters sliced off regardless.
    STUB_STATE["homebrew_casks_data"] = {"casks": [{
        "token": "shortname-cask", "tap": "homebrew/cask", "device_count": 1,
        "installation_count": 1, "linked_app_device_count": 1, "app_names": ["OBS"],
    }]}
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    assert "View OBS in Software" in resp.text


# ── Empty states ────────────────────────────────────────────────────────
def test_no_macs_in_estate_empty_state(client, make_token):
    STUB_STATE["homebrew_summary_data"] = {
        **{"generated_at": "2026-09-23T12:00:00Z"},
        "macos_device_count": 0, "devices_with_homebrew": 0,
        "device_status": {
            "complete": 0, "partial": 0, "not_present": 0, "failed": 0,
            "not_reported": 0,
        },
        "formula_count": 0, "cask_count": 0, "tap_count": 0, "third_party_tap_count": 0,
    }
    resp = _get(client, make_token(), "/homebrew")
    assert "No Macs in this estate yet" in resp.text


def test_no_homebrew_found_empty_state_distinct_from_not_reported(client, make_token):
    STUB_STATE["homebrew_summary_data"] = {
        "generated_at": "2026-09-23T12:00:00Z",
        "macos_device_count": 2, "devices_with_homebrew": 0,
        "device_status": {
            "complete": 0, "partial": 0, "not_present": 2, "failed": 0,
            "not_reported": 0,
        },
        "formula_count": 0, "cask_count": 0, "tap_count": 0, "third_party_tap_count": 0,
    }
    resp = _get(client, make_token(), "/homebrew")
    body = resp.text
    assert "None of the Macs that have reported in have Homebrew installed" in body
    assert "not yet reported" not in body


def test_not_reported_is_a_coverage_gap_not_an_absence_claim(client, make_token):
    STUB_STATE["homebrew_summary_data"] = {
        "generated_at": "2026-09-23T12:00:00Z",
        "macos_device_count": 2, "devices_with_homebrew": 0,
        "device_status": {
            "complete": 0, "partial": 0, "not_present": 0, "failed": 0,
            "not_reported": 2,
        },
        "formula_count": 0, "cask_count": 0, "tap_count": 0, "third_party_tap_count": 0,
    }
    resp = _get(client, make_token(), "/homebrew")
    body = resp.text
    assert "No Mac in your estate has Homebrew installed" not in body
    assert "not yet reported" in body
    assert "coverage gap" in body


def test_older_platform_missing_homebrew_api_renders_not_available(client, make_token):
    STUB_STATE["mode"] = "homebrew_not_found"
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    assert "Homebrew data isn't available yet" in resp.text
    assert "mean no Mac has Homebrew installed" in resp.text


# ── Graceful degradation of individual sections ───────────────────────────
def test_formulae_section_degrades_without_taking_down_the_page(client, make_token):
    STUB_STATE["mode"] = "homebrew_formulae_fail"
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    assert "Formulae are temporarily unavailable" in body
    # Casks and taps, fetched independently, still render.
    assert "firefox" in body
    assert "acme/tools" in body


def test_missing_optional_fields_do_not_crash_the_page(client, make_token):
    STUB_STATE["homebrew_formulae_data"] = {"formulae": [{"name": "bare-formula"}]}
    STUB_STATE["homebrew_casks_data"] = {"casks": [{"token": "bare-cask"}]}
    STUB_STATE["homebrew_taps_data"] = {"taps": [{"name": "bare/tap"}]}
    STUB_STATE["homebrew_devices_data"] = {"devices": [{"hostname": "bare-mac"}]}
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    assert "bare-formula" in body
    assert "bare-cask" in body
    assert "bare/tap" in body
    assert "bare-mac" in body


# ── CSV export ──────────────────────────────────────────────────────────
def test_csv_export_lists_formulae_and_casks(client, make_token):
    resp = _get(client, make_token(), "/homebrew.csv")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0][0] == "kind"
    kinds_names = {(r[0], r[1]) for r in rows[1:]}
    assert ("formula", "openssl@3") in kinds_names
    assert ("formula", "readline") in kinds_names
    assert ("cask", "firefox") in kinds_names


def test_csv_export_requires_auth(client):
    resp = client.get("/homebrew.csv")
    assert resp.status_code == 401


def _make_formula(i):
    return {
        "name": f"formula-{i:04d}", "tap": "homebrew/core", "third_party_tap": False,
        "versions": ["1.0"], "device_count": 1, "installation_count": 1,
        "on_request_device_count": 1, "dependency_device_count": 0,
        "first_seen_at": "2026-09-01T10:00:00Z", "evidence_at": "2026-09-23T11:00:00Z",
    }


def test_csv_export_pages_past_500_and_exports_everything(client, make_token):
    # 620 formulae is more than one page (500) but well under the safety
    # ceiling, so the export must page through and return every row rather
    # than stopping at the first page like the CSV used to.
    STUB_STATE["homebrew_formulae_data"] = {
        "formulae": [_make_formula(i) for i in range(620)],
    }
    resp = _get(client, make_token(), "/homebrew.csv")
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.text)))
    formula_rows = [r for r in rows[1:] if r[0] == "formula"]
    assert len(formula_rows) == 620
    names = {r[1] for r in formula_rows}
    assert "formula-0000" in names
    assert "formula-0619" in names
    # No estate this size hits the safety ceiling, so no notice row.
    assert not any(r[0] == "notice" for r in rows)


def test_homebrew_page_shows_showing_n_of_total_note(client, make_token):
    STUB_STATE["homebrew_formulae_data"] = {
        "formulae": [_make_formula(i) for i in range(620)],
    }
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    assert "Showing 500 of 620 formulae" in resp.text


# ── PAT-2043 (second half): CVE column and findings filter ────────────────
def test_formula_with_high_confidence_findings_shows_count_and_highest_severity(
    client, make_token,
):
    STUB_STATE["homebrew_formulae_data"] = {"formulae": [{
        "name": "openssl@3", "tap": "homebrew/core", "third_party_tap": False,
        "versions": ["3.0.1"], "device_count": 2, "installation_count": 2,
        "on_request_device_count": 2, "dependency_device_count": 0,
    }]}
    STUB_STATE["findings_data"] = [
        {"cve_id": "CVE-2026-9001", "severity": "critical", "cvss": 9.8,
         "app": "openssl@3 (Homebrew formula)", "version": "3.0.1",
         "devices_affected": 2, "first_seen": "2026-12-20T04:00:00Z", "summary": "",
         "source": "homebrew_formula", "confidence_tier": "high",
         "install_reasons": ["on_request"]},
        {"cve_id": "CVE-2026-9002", "severity": "high", "cvss": 7.5,
         "app": "openssl@3 (Homebrew formula)", "version": "3.0.1",
         "devices_affected": 2, "first_seen": "2026-12-20T04:00:00Z", "summary": "",
         "source": "homebrew_formula", "confidence_tier": "high",
         "install_reasons": ["on_request"]},
    ]
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    idx = body.index("homebrew-formulae-table")
    row = body[idx:body.index("Taps beyond core")]
    assert "2 CVEs (Critical)" in row
    assert "possible" not in row


def test_cask_with_only_low_tier_findings_shows_possible_never_confirmed(client, make_token):
    STUB_STATE["homebrew_casks_data"] = {"casks": [{
        "token": "firefox", "tap": "homebrew/cask", "third_party_tap": False,
        "versions": ["HEAD"], "device_count": 1, "installation_count": 1,
        "linked_app_device_count": 0, "app_names": [],
    }]}
    STUB_STATE["findings_data"] = [
        {"cve_id": "CVE-2026-9101", "severity": "high", "cvss": 7.0,
         "app": "firefox (Homebrew cask)", "version": "HEAD",
         "devices_affected": 1, "first_seen": "2026-12-20T04:00:00Z", "summary": "",
         "source": "homebrew_cask", "confidence_tier": "low",
         "install_reasons": ["dependency"]},
    ]
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    idx = body.index("homebrew-casks-table")
    row = body[idx:body.index("homebrew-formulae-table")]
    assert "1 possible" in row
    # Never rendered as a confirmed-severity pill - only the muted
    # "possible" note.
    for severity in ("critical", "high", "medium", "low"):
        assert f"pill-{severity}" not in row


def test_findings_filter_marks_packages_without_findings_as_none(client, make_token):
    STUB_STATE["homebrew_formulae_data"] = {"formulae": [
        {"name": "with-findings", "tap": "homebrew/core", "device_count": 1,
         "on_request_device_count": 1},
        {"name": "no-findings", "tap": "homebrew/core", "device_count": 1,
         "on_request_device_count": 1},
    ]}
    STUB_STATE["findings_data"] = [
        {"cve_id": "CVE-2026-9201", "severity": "medium", "cvss": 5.0,
         "app": "with-findings (Homebrew formula)", "version": "1.0",
         "devices_affected": 1, "first_seen": "2026-12-20T04:00:00Z", "summary": "",
         "source": "homebrew_formula", "confidence_tier": "high",
         "install_reasons": ["on_request"]},
    ]
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    # PAT-2255: the toggle is the shared filter bar's Findings select under
    # More filters: default "" (any), second option filters to "has".
    assert 'data-row-filter="cve"' in body
    assert 'data-query-param="findings" data-default-value="" data-initial=""' in body
    # PAT-2058 widened the row's own opening <tr ...> tag (it now also
    # carries the approval filter/state attributes) and inserted the
    # select-checkbox cell, whose JSON `value` attribute can run well past
    # a fixed 200-char window - so this finds the row's own <tr ...> tag
    # directly rather than assuming a fixed distance back from the name.
    with_idx = body.index("with-findings")
    with_tr = body.rindex("<tr ", 0, with_idx)
    assert 'data-filter-cve="has"' in body[with_tr:with_idx]
    no_idx = body.index("no-findings")
    no_tr = body.rindex("<tr ", 0, no_idx)
    assert 'data-filter-cve="none"' in body[no_tr:no_idx]


def test_cve_findings_fetch_failure_still_renders_the_tab(client, make_token):
    STUB_STATE["mode"] = "findings500"
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    # The rest of the tab renders as normal - only the CVE column degrades.
    assert "openssl@3" in body
    assert "firefox" in body
    assert "CVE counts are temporarily unavailable from the platform." in body


def test_cve_aggregation_keys_formulae_and_casks_separately(client, make_token):
    # The same package name exists as both a formula and a cask; a
    # high-confidence formula finding must never bleed into the cask's
    # count, and vice versa - (source, name) is the aggregation key, not
    # name alone.
    STUB_STATE["homebrew_formulae_data"] = {"formulae": [{
        "name": "shared-name", "tap": "homebrew/core", "device_count": 1,
        "on_request_device_count": 1,
    }]}
    STUB_STATE["homebrew_casks_data"] = {"casks": [{
        "token": "shared-name", "tap": "homebrew/cask", "device_count": 1,
    }]}
    STUB_STATE["findings_data"] = [
        {"cve_id": "CVE-2026-9301", "severity": "critical", "cvss": 9.5,
         "app": "shared-name (Homebrew formula)", "version": "1.0",
         "devices_affected": 1, "first_seen": "2026-12-20T04:00:00Z", "summary": "",
         "source": "homebrew_formula", "confidence_tier": "high",
         "install_reasons": ["on_request"]},
        {"cve_id": "CVE-2026-9302", "severity": "low", "cvss": 2.0,
         "app": "shared-name (Homebrew cask)", "version": "1.0",
         "devices_affected": 1, "first_seen": "2026-12-20T04:00:00Z", "summary": "",
         "source": "homebrew_cask", "confidence_tier": "low",
         "install_reasons": ["dependency"]},
    ]
    resp = _get(client, make_token(), "/homebrew")
    assert resp.status_code == 200
    body = resp.text
    casks_idx = body.index("homebrew-casks-table")
    formulae_idx = body.index("homebrew-formulae-table")
    taps_idx = body.index("Taps beyond core")
    # Casks render before Formulae in the page, so bound each slice by the
    # next section rather than a fixed length - a short table must not let
    # one section's assertions accidentally read into the next one's markup.
    cask_section = body[casks_idx:formulae_idx]
    formula_section = body[formulae_idx:taps_idx]
    assert "1 CVE (Critical)" in formula_section
    assert "possible" not in formula_section
    assert "1 possible" in cask_section
    for severity in ("critical", "high", "medium", "low"):
        assert f"pill-{severity}" not in cask_section


# ── Per-device drill-down ──────────────────────────────────────────────────
def test_device_drill_down_renders_entries(client, make_token):
    resp = _get(client, make_token(), "/homebrew/devices/hb-mac-01")
    assert resp.status_code == 200
    body = resp.text
    assert "mac-01" in body
    assert "firefox" in body
    assert "143.0" in body
    assert "On request" in body


def test_device_drill_down_unknown_device_is_404(client, make_token):
    resp = _get(client, make_token(), "/homebrew/devices/does-not-exist")
    assert resp.status_code == 404
