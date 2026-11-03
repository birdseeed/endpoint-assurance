"""PAT-1847: catalogue-backed, tenant-safe portal reports."""

import main
from tests.conftest import STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _post(client, token, path, data):
    # PAT-2105: a real form post carries the page's Origin and CSRF token.
    return client.post(path, headers={"Cf-Access-Jwt-Assertion": token,
                                      "Origin": "https://testserver"},
                       data={**data, "csrf_token": main._csrf_token(token)},
                       follow_redirects=False)


def test_reports_render_only_platform_catalogue_and_friendly_history(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "Executive Estate Summary" in resp.text
    assert "Patch &amp; Update Status" in resp.text
    assert 'name="report_type" value="executive-summary"' in resp.text
    assert 'name="report_type" value="patch-status"' in resp.text
    assert "rep-0001</td>" not in resp.text


def test_selected_catalogue_type_is_posted_to_generation(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _post(client, token, "/reports/generate", {"report_type": "patch-status"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/reports?generated=1"
    assert STUB_STATE["generate_posts"] == [{"report_type": "patch-status"}]


def test_catalogue_validation_failure_returns_to_the_relevant_form(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["mode"] = "catalogue500"

    generated = _post(client, token, "/reports/generate", {"report_type": "patch-status"})
    assert generated.status_code == 303
    assert "generate_type=patch-status" in generated.headers["location"]
    assert "generate_error=" in generated.headers["location"]
    assert STUB_STATE["generate_posts"] == []
    generated_page = _get(client, token, generated.headers["location"])
    assert "Could not request the report" in generated_page.text

    scheduled = _post(client, token, "/reports/schedule", {
        "report_type": "patch-status", "cadence": "daily", "hour_utc": "7", "enabled": "on",
    })
    assert scheduled.status_code == 303
    assert "schedule_type=patch-status" in scheduled.headers["location"]
    assert "schedule_error=" in scheduled.headers["location"]
    assert STUB_STATE["typed_schedule_puts"] == []
    scheduled_page = _get(client, token, scheduled.headers["location"])
    assert "Could not save the schedule" in scheduled_page.text


def test_catalogue_cache_is_short_lived_and_exact_jwt_scoped(client, make_token):
    first_token = make_token(email="alice@tenant-a.example")
    STUB_STATE["expected_jwt"] = first_token
    assert _get(client, first_token, "/reports").status_code == 200
    assert STUB_STATE["catalogue_request_jwts"] == [first_token]

    # The form submission reuses its own short-lived catalogue validation,
    # avoiding a second upstream read before the platform's typed write.
    assert _post(client, first_token, "/reports/generate", {
        "report_type": "patch-status",
    }).status_code == 303
    assert STUB_STATE["catalogue_request_jwts"] == [first_token]

    # A distinct assertion, even for a different caller, cannot reuse it.
    second_token = make_token(email="bob@tenant-b.example")
    STUB_STATE["expected_jwt"] = second_token
    assert _post(client, second_token, "/reports/generate", {
        "report_type": "patch-status",
    }).status_code == 303
    assert STUB_STATE["catalogue_request_jwts"] == [first_token, second_token]


def test_forged_or_stale_type_is_not_forwarded(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token

    resp = _post(client, token, "/reports/generate", {"report_type": "internal-only"})
    assert resp.status_code == 303
    assert "generate_error=" in resp.headers["location"]
    assert STUB_STATE["generate_posts"] == []

    resp = _post(client, token, "/reports/schedule", {
        "report_type": "../internal-only", "cadence": "daily",
        "hour_utc": "7", "enabled": "on",
    })
    assert resp.status_code == 303
    assert "schedule_error=" in resp.headers["location"]
    assert STUB_STATE["typed_schedule_puts"] == []


def test_typed_schedule_uses_selected_platform_path_and_keeps_type_after_save(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _post(client, token, "/reports/schedule", {
        "report_type": "patch-status", "cadence": "weekly", "weekday": "1",
        "hour_utc": "7", "enabled": "on",
    })
    assert resp.status_code == 303
    assert resp.headers["location"] == "/reports?schedule_saved=1&schedule_type=patch-status"
    assert STUB_STATE["typed_schedule_puts"] == [("patch-status", {
        "cadence": "weekly", "weekday": 1, "hour_utc": 7, "enabled": True,
    })]


def test_selected_type_uses_its_own_schedule_not_another_reports(client, make_token):
    token = make_token()
    STUB_STATE["schedules"] = [
        {"configured": True, "report_type": "executive-summary", "enabled": True,
         "cadence": "daily", "hour_utc": 4},
        {"configured": True, "report_type": "patch-status", "enabled": False,
         "cadence": "monthly", "month_day": 31, "hour_utc": 23},
    ]
    resp = _get(client, token, "/reports?schedule_type=patch-status")
    assert resp.status_code == 200
    assert "Patch &amp; Update Status" in resp.text
    assert "Monthly on day 31 at 23:00 UTC" in resp.text
    assert "Paused" in resp.text
    assert "Daily at 04:00 UTC" not in resp.text


def test_catalogue_or_schedules_failure_does_not_invent_report_types(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "schedule500"
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "Scheduling is not available right now" in resp.text
    assert 'name="report_type" value="patch-status"' in resp.text

    STUB_STATE["catalogue"] = {"unexpected": "shape"}
    main._clear_report_catalogue_cache()
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "Report choices are not available right now" in resp.text
    assert 'name="report_type" value="patch-status"' not in resp.text
