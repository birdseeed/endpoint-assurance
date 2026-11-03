"""Synthetic operator sequence; no real login, installer, mail or offboard proof."""

import pytest

import main
from tests.conftest import PDF_BYTES, STUB_STATE
from tests.test_pat2093_new_software import _new_software
from tests.test_pat2251_enrolment_keys import _create, _get, _post


def test_empty_estate_then_key_report_feedback_and_retirement(client, make_token):
    token = make_token()
    STUB_STATE.update({
        "devices_data": [], "findings_data": [], "enrolment_keys_data": [],
        "overview_data": {
            "tenant_name": "Disposable beta fixture", "devices_total": 0,
            "devices_reporting_24h": 0, "devices_degraded": 0,
            "cis_score_current": None, "cis_trend": [],
            "findings_open": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "patch_status": {}, "new_software": _new_software(),
        },
    })
    for path in ("/", "/devices", "/findings", "/install", "/reports", "/support"):
        response = _get(client, token, path)
        assert response.status_code == 200, path
        assert "Traceback" not in response.text
    assert "Disposable beta fixture" in _get(client, token, "/").text
    assert "Nothing newly found" in _get(client, token, "/").text
    assert len(_get(client, token, "/devices.csv").text.splitlines()) == 1

    created = _create(client, token, label="Disposable beta", max_devices="2",
                      expires_in_days="1")
    assert created.status_code == 200
    assert created.headers["cache-control"] == "no-store"
    assert "pek_teststubkey0001" in created.text
    assert "pek_teststubkey0001" not in _get(client, token).text
    key_id = STUB_STATE["enrolment_keys_data"][0]["key_id"]
    assert _post(client, token, f"/install/enrolment-keys/{key_id}/revoke", []).status_code == 303
    assert STUB_STATE["enrolment_keys_data"][0]["status"] == "revoked"

    generated = _post(client, token, "/reports/generate", [("report_type", "patch-status")])
    assert generated.status_code == 303
    assert STUB_STATE["generate_posts"] == [{"report_type": "patch-status"}]
    # This PDF is pre-existing stub bytes, not the output of the queued job.
    downloaded = _get(client, token, "/reports/rep-0001/download")
    assert downloaded.content == PDF_BYTES
    assert downloaded.headers["content-length"] == str(len(PDF_BYTES))

    STUB_STATE["feedback_enabled"] = True
    response = client.post("/feedback", headers={
        "Cf-Access-Jwt-Assertion": token, "Origin": "https://testserver",
        "Accept": "application/json",
    }, data={"csrf_token": main._csrf_token(token), "type": "feature",
             "severity": "blocking", "title": "Synthetic beta feedback",
             "description": "Fixture rehearsal only", "route": "/reports"})
    assert response.status_code == 201
    assert response.json()["reference"] == "FB-0001"
    assert len(STUB_STATE["feedback_posts"]) == 1
    support = _get(client, token, "/support")
    assert f"mailto:{main.SUPPORT_EMAIL}" in support.text

    # Existing synthetic device, not a freshly installed beta endpoint.
    retired = _post(client, token, "/devices/retirement", [
        ("device_id", "dev-mac-001"), ("retired", "true"),
        ("reason", "Synthetic beta closed"),
    ])
    assert retired.status_code == 303
    assert STUB_STATE["retirement_puts"][-1]["body"]["retired"] is True
    assert STUB_STATE["retirement_overrides"]["dev-mac-001"] is not None


@pytest.mark.parametrize("new_software", [None, {"unexpected": "shape"}])
def test_partial_overview_is_not_a_verified_empty_read(client, make_token, new_software):
    STUB_STATE["overview_data"] = {
        "tenant_name": "Partial fixture", "devices_total": 0,
        "devices_reporting_24h": 0, "new_software": new_software,
    }
    response = _get(client, make_token(), "/")
    assert response.status_code == 200
    assert "Nothing newly found" not in response.text


@pytest.mark.parametrize(("mode", "status", "message"), [
    ("auth401", 401, "Session expired"),
    ("forbidden403", 403, "isn't linked to an estate yet"),
    ("down503", 503, "not yet enabled"),
])
def test_rehearsal_stops_on_upstream_access_failure(client, make_token, mode, status, message):
    STUB_STATE["mode"] = mode
    response = _get(client, make_token(), "/")
    assert response.status_code == status
    assert message.lower() in response.text.lower()
    assert STUB_STATE["generate_calls"] == 0
    assert STUB_STATE["enrolment_key_create_posts"] == []
