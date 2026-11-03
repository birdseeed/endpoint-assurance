"""PAT-2099: device-detail "Collection issues" section for
agent_health_degraded (contracts/portal-api.md "agent_health_degraded
(PAT-2099)"). Approved customer copy must render verbatim for the four
documented macOS Full Disk Access subjects, an unrecognised kind/reason/
subject degrades to a neutral generic line, and the section disappears
entirely when the list is empty or absent (older platform)."""

from copy import deepcopy

import main
from tests.conftest import DEVICE_DETAIL, STUB_STATE


def _get(client, token):
    return client.get("/devices/dev-mac-001", headers={"Cf-Access-Jwt-Assertion": token})


def _detail(agent_health_degraded=None, omit=False):
    detail = deepcopy(DEVICE_DETAIL)
    if not omit:
        detail["agent_health_degraded"] = agent_health_degraded
    return detail


def _entry(**overrides):
    entry = {
        "kind": "tcc_denied",
        "subject": "browser_extensions",
        "reason": "full_disk_access_missing",
        "first_seen": "2026-09-20T09:00:00Z",
        "last_seen": "2026-09-24T09:00:00Z",
        "count": 5,
    }
    entry.update(overrides)
    return entry


APPROVED_SENTENCES = {
    "browser_extensions": (
        "Browser extensions could not be read because macOS Full Disk Access "
        "is not granted to Patched."
    ),
    "mcp_servers": (
        "MCP servers could not be read because macOS Full Disk Access "
        "is not granted to Patched."
    ),
    "ide_extensions": (
        "IDE extensions could not be read because macOS Full Disk Access "
        "is not granted to Patched."
    ),
    "package_managers": (
        "Package managers could not be read because macOS Full Disk Access "
        "is not granted to Patched."
    ),
}


def test_all_four_subjects_render_the_approved_sentence_and_guide_link(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail([
        _entry(subject=subject) for subject in APPROVED_SENTENCES
    ])

    response = _get(client, token)

    assert response.status_code == 200
    assert "Collection issues" in response.text
    for sentence in APPROVED_SENTENCES.values():
        assert sentence in response.text
    assert response.text.count(
        'href="https://docs.patched.im/getting-started" target="_blank" '
        'rel="noopener noreferrer">Full Disk Access guide</a>'
    ) == len(APPROVED_SENTENCES)
    # PAT-2298: the date is held together in a nowrap span; the time follows it.
    assert '<span class="nowrap">20 Sep 2026</span> 09:00' in response.text
    assert '<span class="nowrap">24 Sep 2026</span> 09:00' in response.text


def test_unknown_kind_reason_pair_renders_generic_line_with_no_link(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail([
        _entry(kind="something_else", reason="unknown_reason", subject="package_managers"),
    ])

    response = _get(client, token)

    assert response.status_code == 200
    # Jinja autoescapes the apostrophe in this copy to &#39; in rendered HTML.
    assert "Part of this device&#39;s inventory could not be collected (package_managers)." \
        in response.text
    assert "Full Disk Access guide" not in response.text
    for sentence in APPROVED_SENTENCES.values():
        assert sentence not in response.text


def test_unrecognised_subject_also_renders_generic_line(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail([
        _entry(subject="future_subject_type"),
    ])

    response = _get(client, token)

    assert response.status_code == 200
    assert "Part of this device&#39;s inventory could not be collected (future_subject_type)." \
        in response.text


def test_empty_list_renders_no_section(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail([])

    response = _get(client, token)

    assert response.status_code == 200
    assert "Collection issues" not in response.text


def test_missing_field_renders_no_section(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["device_detail_data"] = _detail(omit=True)

    response = _get(client, token)

    assert response.status_code == 200
    assert "Collection issues" not in response.text


def test_hostile_subject_string_is_autoescaped(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    hostile = '<script>alert(1)</script>'
    STUB_STATE["device_detail_data"] = _detail([
        _entry(kind="tcc_denied", reason="full_disk_access_missing", subject=hostile),
    ])

    response = _get(client, token)

    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_agent_health_degraded_view_normalises_malformed_entries():
    rows = main._agent_health_degraded_view([
        {"kind": "tcc_denied", "reason": "full_disk_access_missing",
         "subject": "browser_extensions", "first_seen": "2026-09-20T09:00:00Z",
         "last_seen": "2026-09-24T09:00:00Z", "count": 5},
        {"kind": "tcc_denied", "reason": "full_disk_access_missing",
         "subject": "unknown_subject"},
        {"subject": ""},
        {"subject": None},
        "not-a-dict",
        {"kind": "tcc_denied", "reason": "full_disk_access_missing",
         "subject": "mcp_servers", "first_seen": 123, "last_seen": None},
    ])

    assert len(rows) == 3
    assert rows[0]["message"] == (
        "Browser extensions could not be read because macOS Full Disk Access "
        "is not granted to Patched."
    )
    assert rows[0]["guide_url"] == "https://docs.patched.im/getting-started"
    assert rows[1]["message"] == (
        "Part of this device's inventory could not be collected (unknown_subject)."
    )
    assert rows[1]["guide_url"] is None
    assert rows[2]["first_seen"] is None and rows[2]["last_seen"] is None


def test_agent_health_degraded_view_handles_missing_or_non_list_input():
    assert main._agent_health_degraded_view(None) == []
    assert main._agent_health_degraded_view([]) == []
    assert main._agent_health_degraded_view({"not": "a list"}) == []
