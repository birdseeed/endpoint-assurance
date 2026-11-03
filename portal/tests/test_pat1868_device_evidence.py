"""PAT-1868: device-detail evidence is section-scoped and fails soft."""

from copy import deepcopy

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE


def _get(client, token):
    # PAT-2164: evidence collection facts and chips moved to their own tab.
    return client.get(
        "/devices/dev-mac-001/evidence", headers={"Cf-Access-Jwt-Assertion": token})


def _detail(evidence):
    detail = deepcopy(DEVICE_DETAIL)
    if evidence is not None:
        detail["evidence"] = evidence
    return detail


def _evidence(**overrides):
    evidence = {
        "observed_at": "2026-09-19T09:10:11Z",
        "received_at": "2026-09-19T09:12:13Z",
        "sections": {
            "certificates": "complete",
            "hardware_health": {
                "battery": "complete", "storage": "complete", "disks": "complete",
            },
        },
        "authority": "section_scoped",
        "freshness": "fresh",
    }
    evidence.update(overrides)
    return evidence


def test_complete_section_scoped_evidence_shows_named_sections_and_distinct_times(
    client, make_token,
):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail(_evidence())

    response = _get(client, token)

    assert response.status_code == 200
    assert "Observed at" in response.text and "19 Sep 2026 09:10" in response.text
    assert "Received at" in response.text and "19 Sep 2026 09:12" in response.text
    assert "Section scoped" in response.text
    assert "Fresh</span>" in response.text
    assert response.text.count(">Complete</span>") == 4
    assert "Hardware health: battery" in response.text
    assert "Absence can only be supported within a named complete collection." in response.text


def test_partial_presence_only_and_unavailable_remain_distinct(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail(_evidence(
        sections={
            "certificates": "partial",
            "hardware_health": {
                "battery": "unavailable", "storage": "partial", "disks": "complete",
            },
        },
        authority="presence_only",
        freshness="unknown",
    ))

    response = _get(client, token)

    assert "Presence only" in response.text
    assert ">Partial</span>" in response.text
    assert ">Unavailable</span>" in response.text
    assert ">Unknown</span>" in response.text


def test_missing_legacy_and_malformed_additive_fields_are_explicitly_unknown(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    STUB_STATE["device_detail_data"] = _detail(None)
    response = _get(client, token)
    assert response.status_code == 200
    assert response.text.count(">Unknown</span>") >= 6
    assert "Observed at</dt><dd class=\"mono\">Unknown" in response.text

    STUB_STATE["device_detail_data"] = _detail(_evidence(
        observed_at="not-a-time", received_at=12, sections="complete",
        authority=True, freshness="later",
    ))
    response = _get(client, token)
    assert response.status_code == 200
    assert response.text.count(">Unknown</span>") >= 6
    assert "not-a-time" not in response.text


def test_stale_is_not_collapsed_into_unknown_or_fresh(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail(_evidence(
        authority="stale", freshness="stale",
    ))

    response = _get(client, token)

    assert response.status_code == 200
    assert response.text.count(">Stale</span>") == 2


def test_normalise_device_evidence_rejects_malformed_values_independently():
    evidence = main.normalise_device_evidence({
        "observed_at": "2026-09-19T09:10:11Z",
        "received_at": "2026-09-19T09:12:13",  # timezone required by RFC 3339
        "sections": {"certificates": "complete", "hardware_health": {"battery": "bad"}},
        "authority": "section_scoped", "freshness": "fresh",
    })

    assert evidence["observed_at"] == "2026-09-19T09:10:11Z"
    assert evidence["received_at"] is None
    assert [(entry["name"], entry["status"]) for entry in evidence["sections"]] == [
        ("Certificates", "complete"), ("Hardware health: battery", "unknown"),
        ("Hardware health: storage", "unknown"), ("Hardware health: disks", "unknown"),
    ]
