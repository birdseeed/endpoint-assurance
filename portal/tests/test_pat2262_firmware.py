"""PAT-2262: the device Hardware tab shows the platform's additive
`firmware` block (contracts/portal-api.md "firmware (PAT-2262)") - BIOS,
system and baseboard identity read straight off the device, observation
only, never a verdict on whether it is current, outdated or vulnerable.

Four render states per root AGENTS.md's "absence requires authority" and
this ticket's own Done-when criteria: not_reported (including the block
missing from the response entirely - an older platform build), unavailable,
partial and complete - plus the macOS-specific not_reported wording, the
release-date age computation and its boundaries, and a banned-words check
that the section never states a verdict.
"""

from copy import deepcopy

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE

NOT_REPORTED_AGENT_TEXT = "This device's agent doesn't report firmware details yet."
NOT_REPORTED_MACOS_TEXT = (
    "Firmware is updated with macOS on Mac, so it follows the macOS version shown above."
)
UNAVAILABLE_TEXT = "The agent could not read firmware details on this device."
BANNED_WORDS = ("vulnerable", "outdated", "out of date", "old bios")


def _get_hardware(client, token, device_id="dev-mac-001"):
    return client.get(
        f"/devices/{device_id}/hardware", headers={"Cf-Access-Jwt-Assertion": token})


def _assert_no_banned_words(body: str):
    lowered = body.lower()
    for word in BANNED_WORDS:
        assert word not in lowered, f"banned claim word {word!r} found in rendered Firmware section"


# ── not_reported: key missing entirely (older platform) ───────────────────
def test_missing_firmware_key_on_macos_shows_macos_wording(client, make_token):
    """DEVICE_DETAIL (dev-mac-001, platform macOS) carries no "firmware" key
    at all - exactly the older-platform-build shape this ticket must fail
    soft on."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    assert "firmware" not in DEVICE_DETAIL

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert NOT_REPORTED_MACOS_TEXT in body
    assert NOT_REPORTED_AGENT_TEXT not in body
    _assert_no_banned_words(body)


def test_missing_firmware_key_on_windows_shows_agent_wording(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    assert "firmware" not in detail
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert NOT_REPORTED_AGENT_TEXT in body
    assert NOT_REPORTED_MACOS_TEXT not in body
    _assert_no_banned_words(body)


# ── not_reported: status explicit on the wire ──────────────────────────────
def test_explicit_not_reported_status_on_windows(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = {
        "status": "not_reported", "reported_at": None, "observed_at": None,
        "errors": [], "bios": None, "system": None, "baseboard": None,
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert NOT_REPORTED_AGENT_TEXT in body
    _assert_no_banned_words(body)


# ── unavailable ─────────────────────────────────────────────────────────────
def test_unavailable_with_no_prior_data_shows_only_the_unavailable_line(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = {
        "status": "unavailable",
        "reported_at": "2026-09-29T09:00:00Z", "observed_at": "2026-09-29T08:59:40Z",
        "errors": ["bios_query_failed", "system_query_failed", "baseboard_query_failed"],
        "bios": None, "system": None, "baseboard": None,
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert UNAVAILABLE_TEXT in body
    assert ">BIOS<" not in body
    assert ">System<" not in body
    assert ">Baseboard<" not in body
    assert "Not read" not in body
    _assert_no_banned_words(body)


def test_unavailable_report_never_blanks_an_earlier_read(client, make_token):
    """contracts/portal-api.md: "an unavailable report never blanks values
    an earlier one read" - the current report failed, but bios/system/
    baseboard still carry an older, real reading."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = {
        "status": "unavailable",
        "reported_at": "2026-09-29T09:00:00Z", "observed_at": "2026-09-29T08:59:40Z",
        "errors": ["bios_query_failed"],
        "bios": {
            "status": "complete", "reported_at": "2026-09-20T09:00:00Z",
            "manufacturer": "LENOVO", "version": "N3HET82W (1.54 )",
            "smbios_version": "3.2", "release_date": "2023-05-12", "release_date_raw": None,
        },
        "system": {"status": "complete", "reported_at": "2026-09-20T09:00:00Z",
                    "manufacturer": "LENOVO", "model": "20XW0026UK"},
        "baseboard": {"status": "complete", "reported_at": "2026-09-20T09:00:00Z",
                      "manufacturer": "LENOVO", "product": None},
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert UNAVAILABLE_TEXT in body
    assert "LENOVO" in body
    assert "20XW0026UK" in body
    assert "Not read" in body  # baseboard.product
    _assert_no_banned_words(body)


# ── partial: show what was read, "Not read" for the rest ──────────────────
def test_partial_shows_read_fields_and_not_read_for_missing(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = {
        "status": "partial",
        "reported_at": "2026-09-28T09:00:00Z", "observed_at": "2026-09-28T08:59:40Z",
        "errors": ["system_query_failed"],
        "bios": {
            "status": "partial", "reported_at": "2026-09-28T09:00:00Z",
            "manufacturer": "Dell Inc.", "version": None,
            "smbios_version": None, "release_date": None, "release_date_raw": None,
        },
        "system": None,
        "baseboard": {"status": "partial", "reported_at": "2026-09-28T09:00:00Z",
                      "manufacturer": None, "product": "0J1XPP"},
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Dell Inc." in body
    assert "0J1XPP" in body
    assert body.count("Not read") >= 4  # bios version/smbios/release + baseboard manufacturer
    _assert_no_banned_words(body)


# ── complete: every field, including the computed release age ────────────
def test_complete_renders_every_field_with_release_age(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = {
        "status": "complete",
        "reported_at": "2026-09-28T09:00:00Z", "observed_at": "2026-09-28T08:59:40Z",
        "errors": [],
        "bios": {
            "status": "complete", "reported_at": "2026-09-28T09:00:00Z",
            "manufacturer": "LENOVO", "version": "N3HET82W (1.54 )",
            "smbios_version": "3.2", "release_date": "2022-03-15", "release_date_raw": None,
        },
        "system": {"status": "complete", "reported_at": "2026-09-28T09:00:00Z",
                    "manufacturer": "LENOVO", "model": "20XW0026UK"},
        "baseboard": {"status": "complete", "reported_at": "2026-09-28T09:00:00Z",
                      "manufacturer": "LENOVO", "product": "LNVNB161216"},
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert "LENOVO" in body
    assert "N3HET82W (1.54 )" in body
    assert "3.2" in body
    assert "Released March 2022, 4 years old" in body
    assert "20XW0026UK" in body
    assert "LNVNB161216" in body
    assert "28 Sep 2026 09:00" in body  # a section's own reported_at, humandate(true)
    assert "Not read" not in body
    _assert_no_banned_words(body)


def test_release_date_raw_shown_without_computed_age_when_unparseable(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    detail = deepcopy(DEVICE_DETAIL)
    detail["platform"] = "Windows"
    detail["firmware"] = {
        "status": "complete",
        "reported_at": "2026-09-28T09:00:00Z", "observed_at": "2026-09-28T08:59:40Z",
        "errors": [],
        "bios": {
            "status": "complete", "reported_at": "2026-09-28T09:00:00Z",
            "manufacturer": "LENOVO", "version": "1.0", "smbios_version": "3.2",
            "release_date": None, "release_date_raw": "03/15/22",
        },
        "system": None, "baseboard": None,
    }
    STUB_STATE["device_detail_data"] = detail

    response = _get_hardware(client, token)

    assert response.status_code == 200
    body = response.text
    assert "Released 03/15/22" in body
    assert "years old" not in body
    assert "less than a year old" not in body


# ── malformed input never 500s ─────────────────────────────────────────────
def test_firmware_missing_and_malformed_never_500(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    for override in (None, "not-a-dict", 42, [], {}):
        detail = deepcopy(DEVICE_DETAIL)
        if override is None:
            detail.pop("firmware", None)
        else:
            detail["firmware"] = override
        STUB_STATE["device_detail_data"] = detail

        response = _get_hardware(client, token)
        assert response.status_code == 200
        _assert_no_banned_words(response.text)


# ── unit-level: normalise_firmware fails soft on garbage ───────────────────
def test_normalise_firmware_treats_absence_and_garbage_as_not_reported():
    for raw in (None, "not-a-dict", 42, [], {}):
        view = main.normalise_firmware(raw)
        assert view["status"] == "not_reported"
        assert view["bios"]["present"] is False
        assert view["system"]["present"] is False
        assert view["baseboard"]["present"] is False
        assert view["any_section_present"] is False


# ── unit-level: release-date age boundaries ────────────────────────────────
def test_release_age_boundaries(monkeypatch):
    import main as m

    class _FixedDateTime(m.datetime):
        @classmethod
        def now(cls, tz=None):
            return m.datetime(2026, 9, 29, tzinfo=m.UTC)

    monkeypatch.setattr(m, "datetime", _FixedDateTime)

    # Released today: 0 years.
    label, age = m._firmware_release_view("2026-09-29", None)
    assert label == "September 2026"
    assert age == "less than a year old"

    # One day short of a year: still under a year.
    label, age = m._firmware_release_view("2025-09-30", None)
    assert age == "less than a year old"

    # Exactly one year ago: singular wording.
    label, age = m._firmware_release_view("2025-09-29", None)
    assert age == "1 year old"

    # One day over a year: two years have not yet elapsed.
    label, age = m._firmware_release_view("2025-09-28", None)
    assert age == "1 year old"

    # Exactly four years ago.
    label, age = m._firmware_release_view("2022-09-29", None)
    assert label == "September 2022"
    assert age == "4 years old"

    # Unparseable release_date falls back to release_date_raw verbatim, no age.
    label, age = m._firmware_release_view("not-a-date", "March 2021 (unparsed)")
    assert label == "March 2021 (unparsed)"
    assert age is None

    # Neither present renders neither.
    label, age = m._firmware_release_view(None, None)
    assert label is None
    assert age is None
