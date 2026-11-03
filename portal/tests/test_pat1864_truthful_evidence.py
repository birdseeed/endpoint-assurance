"""PAT-1864: nullable or stale device evidence must not become a health claim."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _reported_at(days_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _device(device_id, encryption_ok, patch_pending, days_ago=1):
    return {
        "device_id": device_id,
        "hostname": device_id,
        "platform": "macOS",
        "os_version": "15.6",
        "last_seen": _reported_at(days_ago),
        "cis_score": 90,
        "findings_open": 0,
        "encryption_ok": encryption_ok,
        "patch_pending": patch_pending,
    }


def _detail(encryption_ok, patch_pending, days_ago=1):
    detail = deepcopy(DEVICE_DETAIL)
    detail["last_seen"] = _reported_at(days_ago)
    detail["encryption_ok"] = encryption_ok
    detail["patch_pending"] = patch_pending
    return detail


def test_normalise_assurance_boolean_accepts_only_real_boolean_evidence():
    assert main.normalise_assurance_boolean(True) is True
    assert main.normalise_assurance_boolean(False) is False
    assert main.normalise_assurance_boolean(None) is None
    assert main.normalise_assurance_boolean("false") is None
    assert main.normalise_assurance_boolean(0) is None


def test_single_device_staleness_uses_the_same_boundary_and_normalisation():
    now = datetime(2026, 9, 19, tzinfo=UTC)
    device = _device("threshold-state", None, None, days_ago=8)
    device["last_seen"] = (now - timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")

    main.annotate_device_staleness(device, 7, now)
    assert device["is_stale"] is True
    assert device["encryption_ok"] is None
    assert device["patch_pending"] is None

    main.annotate_device_staleness(device, 30, now)
    assert device["is_stale"] is False


def test_csv_assurance_values_preserve_current_unknown_and_stale_precedence():
    assert main.assurance_csv_value(True, False) == "yes"
    assert main.assurance_csv_value(False, False) == "no"
    assert main.assurance_csv_value(None, False) == "unknown"
    assert main.assurance_csv_value(True, True) == "stale"
    assert main.assurance_csv_value(False, True) == "stale"


def test_shared_badge_maps_patch_pending_boolean_to_the_correct_assurance_state():
    badge = main.templates.env.get_template("_macros.html").module.assurance_badge

    encryption_true = badge(
        True, "Encrypted", "pill-ok", "Not encrypted", "pill-bad", "Not assessed", "Encryption"
    )
    encryption_false = badge(
        False, "Encrypted", "pill-ok", "Not encrypted", "pill-bad", "Not assessed", "Encryption"
    )
    updates_true = badge(
        True,
        "Updates pending",
        "pill-warn",
        "Up to date",
        "pill-ok",
        "Update state not reported",
        "Update",
    )
    updates_false = badge(
        False,
        "Updates pending",
        "pill-warn",
        "Up to date",
        "pill-ok",
        "Update state not reported",
        "Update",
    )

    assert 'pill-ok">Encrypted' in encryption_true
    assert 'pill-bad">Not encrypted' in encryption_false
    assert 'pill-warn">Updates pending' in updates_true
    assert 'pill-ok">Up to date' in updates_false


def test_roster_distinguishes_true_false_null_and_partial_evidence(client, make_token):
    STUB_STATE["devices_data"] = {"devices": [
        _device("true-state", True, False),
        _device("false-state", False, True),
        _device("null-state", None, None),
        _device("partial-state", "unreadable", None),
    ]}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=normal")

    assert response.status_code == 200
    assert 'pill-ok">Encrypted' in response.text
    assert 'pill-bad">Not encrypted' in response.text
    assert 'pill-warn">Updates pending' in response.text
    assert 'pill-ok">Up to date' in response.text
    assert response.text.count("Not assessed") == 2
    assert response.text.count("This device hasn't reported a recent update state.") == 3


def test_stale_roster_evidence_is_qualified_not_current_or_definitive(client, make_token):
    STUB_STATE["devices_data"] = {"devices": [
        _device("stale-state", True, False, days_ago=8),
    ]}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=stale&stale_days=7")

    assert response.status_code == 200
    assert "Encryption evidence stale" in response.text
    assert "Update evidence stale" in response.text
    assert "Encrypted</span>" not in response.text
    assert "Up to date</span>" not in response.text
    assert "Not encrypted</span>" not in response.text
    assert "Pending</span>" not in response.text


def test_stale_roster_link_preserves_selected_threshold(client, make_token):
    STUB_STATE["devices_data"] = {"devices": [
        _device("stale-state", True, False, days_ago=31),
    ]}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices?view=stale&stale_days=30")

    assert response.status_code == 200
    assert 'href="/devices/stale-state?stale_days=30"' in response.text


def test_detail_uses_the_shared_truthful_evidence_states(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    STUB_STATE["device_detail_data"] = _detail(True, False)
    response = _get(client, token, "/devices/dev-mac-001")
    assert 'pill-ok">Encrypted' in response.text
    assert 'pill-ok">Up to date' in response.text

    STUB_STATE["device_detail_data"] = _detail(False, True)
    response = _get(client, token, "/devices/dev-mac-001")
    assert 'pill-bad">Not encrypted' in response.text
    assert 'pill-warn">Updates pending' in response.text

    STUB_STATE["device_detail_data"] = _detail(None, "missing")
    response = _get(client, token, "/devices/dev-mac-001")
    assert "Not assessed" in response.text
    assert "This device hasn't reported a recent update state." in response.text

    STUB_STATE["device_detail_data"] = _detail(True, False, days_ago=8)
    response = _get(client, token, "/devices/dev-mac-001")
    assert "Encryption evidence stale" in response.text
    assert "Update evidence stale" in response.text
    assert "Encrypted</span>" not in response.text
    assert "Up to date</span>" not in response.text

    response = _get(client, token, "/devices/dev-mac-001?stale_days=30")
    assert 'pill-ok">Encrypted' in response.text
    assert 'pill-ok">Up to date' in response.text


def test_csv_preserves_unknown_as_unknown_not_no(client, make_token):
    STUB_STATE["devices_data"] = {"devices": [_device("unknown-csv", None, None)]}
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get(client, token, "/devices.csv")

    assert response.status_code == 200
    assert "unknown-csv,macOS,15.6" in response.text
    # PAT-2025: cve_assessment_state is a new column - this device fixture
    # carries no cve_assessment key, which degrades to not_assessed. PAT-2324
    # added the trailing `type` column after it; this fixture has no
    # device_class, so that cell is empty.
    assert response.text.rstrip().endswith(",90,unknown,unknown,not_assessed,")
