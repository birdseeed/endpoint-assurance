"""PAT-2141: the device page shows the platform's additive identity/hardware
blocks (contracts/portal-api.md "identity and hardware (PAT-2141)") instead
of silently sitting on data it already collects.

PAT-2164 follow-up: Identification (Overview tab) and Hardware (its own
Hardware tab) are on separate pages now, superseding the "merged into one
Device card" structure this file originally pinned - they can no longer sit
side by side on one page at all, so those layout assertions moved to
e2e/test_pat2141_device_identity_hardware.py's compute/battery-pairing test,
the one pairing that does still coexist on a single page (the Hardware tab).
See that file for the layout assertions (card order, the Hardware card's
height) that need a real browser; this file covers the data-level
guarantees that don't.

Three scenarios, per root AGENTS.md's "absence requires authority" and this
ticket's own Done-when criteria:

1. Full data (dev-mac-001, DEVICE_DETAIL_IDENTITY/DEVICE_DETAIL_HARDWARE in
   tests/conftest.py) renders real values.
2. not_collected (dev-mac-003, DEVICE_DETAIL_ALL_NOT_ASSESSED's
   DEVICE_DETAIL_IDENTITY_NOT_COLLECTED/DEVICE_DETAIL_HARDWARE_NOT_COLLECTED)
   renders "Not collected" explicitly - never a blank, never "0 GB" or
   "0 cycles" standing in for absent data.
3. Both blocks entirely absent from the upstream response (an older
   platform build that predates this ticket) - the page still renders 200,
   raises nothing, and shows no value for either tab.
"""

from copy import deepcopy

import main  # noqa: F401 - imported for parity with the rest of this suite
from tests.conftest import DEVICE_DETAIL, STUB_STATE


def _get_overview(client, token, device_id="dev-mac-001"):
    return client.get(
        f"/devices/{device_id}", headers={"Cf-Access-Jwt-Assertion": token})


def _get_hardware(client, token, device_id="dev-mac-001"):
    return client.get(
        f"/devices/{device_id}/hardware", headers={"Cf-Access-Jwt-Assertion": token})


# ── 1. Full data renders real values ───────────────────────────────────────
def test_full_identity_renders_real_values_on_overview(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_overview(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Identification" in body
    assert "C02XL0GTJGH5" in body  # serial
    assert "Mac16,1" in body  # hardware_model, labelled "Model identifier"
    assert "Model identifier" in body
    assert "Alice&#39;s MacBook Pro" in body or "Alice's MacBook Pro" in body
    assert "arm64" in body
    assert "macOS 15.5 (24F74)" in body
    assert "0.19.23" in body


def test_full_hardware_renders_real_values_on_hardware_tab(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Hardware" in body
    assert "Apple M2" in body and "8 cores" in body
    assert "16 GB" in body
    assert "disk0" in body and "Verified" in body
    assert "Internal" in body and "SSD" in body
    assert "93%" in body  # volume used_pct
    assert "Normal" in body  # battery condition
    assert "30" in body  # cycle_count
    assert "100%" in body  # max_capacity_pct


def test_identification_is_its_own_card_on_overview(client, make_token):
    """PAT-2164: Identification is the Overview tab's Device card - Evidence
    collection (the other half of the old merged card) moved to its own
    Evidence tab, so this card carries identity fields only now."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_overview(client, token)

    assert response.status_code == 200
    body = response.text
    assert 'class="card device-card"' in body
    assert 'id="device-card-title"' in body
    assert ">Device<" in body
    assert "evidence-card" not in body
    assert "hardware-stack" not in body
    # Evidence collection's own facts/chips do not leak onto this tab.
    assert "Evidence collection" not in body


def test_hardware_groups_are_paired_on_the_hardware_tab(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_hardware(client, token)

    assert response.status_code == 200
    assert 'class="hardware-group hardware-group--pair"' in response.text


def test_full_hardware_volume_past_90_percent_gets_warning_styling(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_hardware(client, token)

    assert 'volume-used--warn' in response.text


def test_smart_not_supported_is_not_alarming(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["hardware"]["disks"]["items"] = [
        {"device": "disk1", "smart_status": "Not Supported",
         "internal": False, "solid_state": False},
    ]
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert "Not Supported" in response.text
    assert "pill-warn\">Not Supported" not in response.text
    assert 'pill-muted">Not Supported' in response.text


def test_smart_failing_gets_warning_styling(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["hardware"]["disks"]["items"] = [
        {"device": "disk1", "smart_status": "Failing", "internal": True, "solid_state": False},
    ]
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert 'pill-warn">Failing' in response.text


def test_battery_condition_other_than_normal_gets_warning_styling(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["hardware"]["battery"]["condition"] = "Service Recommended"
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert 'pill-warn">Service Recommended' in response.text


# ── 2. not_collected renders explicitly, never blank/zero ─────────────────
def test_not_collected_identity_states_it_explicitly(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_overview(client, token, "dev-mac-003")

    assert response.status_code == 200
    body = response.text
    assert "Identification" in body
    assert "This device has not sent an inventory report yet." in body


def test_not_collected_hardware_states_it_explicitly_never_blank_or_zero(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    response = _get_hardware(client, token, "dev-mac-003")

    assert response.status_code == 200
    body = response.text
    assert "Hardware" in body
    # Every hardware sub-block states its own not-collected status, not a
    # shared blanket sentence, and never a fabricated zero standing in for
    # missing data. cpu and memory share one combined message when both are
    # not_collected (device_hardware.html), so this is 4, not 5 - the
    # Identification tab's own "Not collected." (a 5th, on the Overview tab
    # instead) is what made the pre-PAT-2164 combined-page count 5.
    assert body.count("Not collected.") >= 4  # cpu+memory (combined)/disks/volumes/battery
    assert "0 GB" not in body
    assert "0 cores" not in body
    assert "0 cycles" not in body
    assert ">0<" not in body


# ── 3. Blocks entirely absent from the response fail soft ─────────────────
def test_identity_entirely_absent_fails_soft(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    del detail["identity"]
    del detail["hardware"]
    STUB_STATE["device_detail_data"] = detail

    response = _get_overview(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Identification is not available on this device page yet." in body
    # None of the real, full-data values leak through from a stale render.
    assert "C02XL0GTJGH5" not in body


def test_hardware_entirely_absent_fails_soft(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    del detail["identity"]
    del detail["hardware"]
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Hardware information is not available on this device page yet." in body
    assert "Mac16,1" not in body
    assert "Apple M2" not in body


def test_identity_and_hardware_missing_and_malformed_never_500(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for override in (None, "not-a-dict", 42, [], {}):
        detail = deepcopy(DEVICE_DETAIL)
        if override is None:
            del detail["identity"]
            del detail["hardware"]
        else:
            detail["identity"] = override
            detail["hardware"] = override
        STUB_STATE["device_detail_data"] = detail

        assert _get_overview(client, token).status_code == 200
        assert _get_hardware(client, token).status_code == 200
