"""PAT-1951: overview prioritises urgent evidence gaps and CIS failures."""

from datetime import UTC, datetime, timedelta

import main
from tests.conftest import OVERVIEW, STUB_STATE


def _get(client, token, path="/"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def test_all_reporting_lost_caveats_historical_posture_and_keeps_cis_distinct(
    client, make_token, monkeypatch
):
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW,
        "devices_total": 1,
        "devices_reporting_24h": 0,
        "cis_score_current": 65,
        "findings_open": {"critical": 0, "high": 1, "medium": 5, "low": 0},
        "patch_status": {"up_to_date": 1, "pending": 0, "failed": 0},
    })
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token)

    assert response.status_code == 200
    assert main.static_url("css/portal.css") in response.text
    assert "Needs attention" in response.text
    assert "1 device not reporting in 24 hours" in response.text
    assert "Snapshot generated" in response.text
    assert "Current estate posture cannot be confirmed." in response.text
    assert "CIS checks failing" in response.text
    assert "0 critical" in response.text
    assert "1 high" in response.text
    assert "Latest recorded counts" in response.text
    # D4: CVE attention stays its own row, with its own message, never
    # blended into the CIS row or its count.
    assert "Confirmed CVEs" in response.text
    assert "CVE attention is not yet available for this estate." in response.text
    assert 'href="/devices?view=not_reporting_24h"' in response.text
    assert "This score is historical, not current posture." in response.text
    assert "Update status is historical, not current." in response.text
    assert "Oldest successful ingest:" in response.text
    assert "Continuous coverage since" not in response.text
    assert response.text.index("Needs attention") < response.text.index(
        "How CIS control coverage explains this score"
    )
    assert response.text.index("CIS Level 1 score") < response.text.index(
        "How CIS control coverage explains this score"
    )


def test_reporting_gap_roster_is_timestamp_precise_and_shows_last_seen(
    client, make_token, monkeypatch
):
    old = "2026-09-19T10:15:00Z"
    fresh = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setitem(STUB_STATE, "devices_data", {"devices": [
        {"device_id": "late", "hostname": "acme-late", "platform": "Windows",
         "os_version": "11", "last_seen": old, "cis_score": 65,
         "findings_open": 0, "encryption_ok": True, "patch_pending": False},
        {"device_id": "fresh", "hostname": "acme-fresh", "platform": "macOS",
         "os_version": "15", "last_seen": fresh, "cis_score": 65,
         "findings_open": 0, "encryption_ok": True, "patch_pending": False},
    ]})
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=not_reporting_24h")

    assert response.status_code == 200
    assert "acme-late" in response.text
    assert "19 Sep 2026 10:15 UTC" in response.text
    assert "last reported values, not current verification" in response.text
    assert "acme-fresh" not in response.text
    now = datetime(2026, 9, 21, 10, 15, tzinfo=UTC)
    assert main.is_reporting_gap((now - timedelta(hours=24)).isoformat(), now)
    just_recent = (now - timedelta(hours=24) + timedelta(seconds=1)).isoformat()
    assert not main.is_reporting_gap(just_recent, now)


def test_partial_and_healthy_coverage_keep_attention_truthful(client, make_token, monkeypatch):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": 4, "devices_reporting_24h": 3,
        "findings_open": {"critical": 0, "high": 0, "medium": 5, "low": 0},
    })
    partial = _get(client, token)
    assert "1 device not reporting in 24 hours" in partial.text
    assert "Current assurance evidence may be incomplete." in partial.text
    assert "This score is historical, not current posture." not in partial.text
    assert "Latest recorded counts" not in partial.text

    # All zero, CIS evidence fresh, and CVE attention available and zero
    # too: the only combination that is a genuine "Nothing needs attention".
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": 4, "devices_reporting_24h": 4,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "cve_attention": {"available": True, "critical": 0, "high": 0},
    })
    healthy = _get(client, token)
    assert "Nothing needs attention." in healthy.text
    assert 'class="pill pill-muted">0 critical' in healthy.text

    # Same clean CIS/reporting picture, but CVE attention was never
    # available: the merged card must never present an overall all-clear
    # off a source it could not read (root AGENTS.md - absence requires
    # authority) - the CVE row's own honest caveat stays instead.
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": 4, "devices_reporting_24h": 4,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    })
    cve_unknown = _get(client, token)
    assert "Nothing needs attention." not in cve_unknown.text
    assert "CVE attention is not yet available for this estate." in cve_unknown.text


def test_empty_estate_and_control_coverage_failure_do_not_create_an_all_clear(
    client, make_token, monkeypatch
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    monkeypatch.setitem(STUB_STATE, "overview_data", {
        **OVERVIEW, "devices_total": 0, "devices_reporting_24h": 0,
        "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    })
    monkeypatch.setitem(STUB_STATE, "mode", "coverage500")

    response = _get(client, token)

    assert response.status_code == 200
    assert (
        "No known devices are currently returned, so no current estate posture can be confirmed."
        in response.text
    )
    assert "CIS control coverage is temporarily unavailable." in response.text
    assert "Nothing needs attention." not in response.text
