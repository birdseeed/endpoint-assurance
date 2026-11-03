"""PAT-703: the Scheduled reports card and its proxied schedule writes.

The stub platform (conftest) records every PUT body and asserts the CF Access
JWT arrives verbatim, mirroring the real trust model: the portal never sends
a tenant identifier; the platform derives it from the verified JWT.
"""

import main
from tests.conftest import STUB_STATE


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _post_schedule(client, token, data, **kwargs):
    # PAT-2105: a real form post carries the page's Origin and CSRF token.
    return client.post(
        "/reports/schedule",
        headers={"Cf-Access-Jwt-Assertion": token, "Origin": "https://testserver"},
        data={**data, "csrf_token": main._csrf_token(token)},
        follow_redirects=False,
        **kwargs,
    )


# ── Auth required ──────────────────────────────────────────────────────────
def test_schedule_post_requires_auth(client):
    resp = client.post("/reports/schedule",
                       data={"cadence": "daily", "hour_utc": "7", "enabled": "on"},
                       follow_redirects=False)
    assert resp.status_code == 401
    assert STUB_STATE["schedule_puts"] == []


def test_schedule_card_needs_auth_like_the_rest_of_the_page(client):
    assert client.get("/reports").status_code == 401


# ── Card rendering ─────────────────────────────────────────────────────────
def test_reports_page_shows_unconfigured_schedule_card(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "Scheduled reports" in resp.text
    assert "Save schedule" in resp.text
    # Sensible defaults pre-selected: weekly, Monday, 07:00 UTC, enabled.
    assert '<option value="weekly" selected' in resp.text.replace("  ", " ")


def test_reports_page_shows_configured_schedule(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["schedules"] = [{
        "configured": True, "report_type": "executive-summary", "enabled": True,
        "cadence": "weekly", "weekday": 1, "month_day": None, "hour_utc": 7,
        "last_run_at": None, "next_run_at": "2026-07-06T07:00:00Z",
        "updated_at": "2026-07-03T12:00:00Z",
    }]
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "Weekly on Monday at 07:00 UTC" in resp.text
    assert "Next run" in resp.text and "06 Jul 2026 07:00" in resp.text


def test_reports_page_shows_paused_schedule(client, make_token):
    token = make_token()
    STUB_STATE["schedules"] = [{
        "configured": True, "report_type": "executive-summary", "enabled": False,
        "cadence": "monthly", "weekday": None, "month_day": 31, "hour_utc": 23,
        "last_run_at": "2026-12-30T23:00:05Z", "next_run_at": "2027-01-31T23:00:00Z",
        "updated_at": "2026-07-03T12:00:00Z",
    }]
    resp = _get(client, token, "/reports")
    assert resp.status_code == 200
    assert "Paused" in resp.text
    assert "Monthly on day 31 at 23:00 UTC" in resp.text
    assert "Last run" in resp.text
    # Paused schedules advertise no next run.
    assert "Next run" not in resp.text


def test_schedule_fetch_failure_degrades_not_breaks(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "schedule500"
    resp = _get(client, token, "/reports")
    # Reports history still renders; the card degrades gracefully.
    assert resp.status_code == 200
    assert "rep-0001" in resp.text
    assert "Scheduling is not available right now" in resp.text
    assert "Save schedule" not in resp.text


# ── Submission proxies a PUT upstream with the caller's JWT ────────────────
def test_save_weekly_schedule_puts_upstream(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token  # stub 401s if the JWT is not verbatim
    resp = _post_schedule(client, token, {
        "cadence": "weekly", "weekday": "1", "month_day": "15",
        "hour_utc": "7", "enabled": "on",
    })
    assert resp.status_code == 303
    assert resp.headers["location"] == "/reports?schedule_saved=1"
    assert STUB_STATE["schedule_puts"] == [{
        "cadence": "weekly", "weekday": 1, "hour_utc": 7, "enabled": True,
    }]  # month_day for a weekly cadence is never sent upstream


def test_save_monthly_disabled_schedule(client, make_token):
    token = make_token()
    resp = _post_schedule(client, token, {
        "cadence": "monthly", "month_day": "31", "hour_utc": "23",
    })  # no "enabled" checkbox -> disabled
    assert resp.status_code == 303
    assert STUB_STATE["schedule_puts"] == [{
        "cadence": "monthly", "month_day": 31, "hour_utc": 23, "enabled": False,
    }]


def test_save_daily_schedule_sends_no_day_fields(client, make_token):
    token = make_token()
    resp = _post_schedule(client, token, {
        "cadence": "daily", "weekday": "1", "month_day": "15",
        "hour_utc": "0", "enabled": "on",
    })
    assert resp.status_code == 303
    assert STUB_STATE["schedule_puts"] == [{
        "cadence": "daily", "hour_utc": 0, "enabled": True,
    }]


# ── Validation failures ────────────────────────────────────────────────────
def test_non_numeric_hour_rejected_before_upstream(client, make_token):
    token = make_token()
    resp = _post_schedule(client, token, {
        "cadence": "daily", "hour_utc": "sevenish", "enabled": "on",
    })
    assert resp.status_code == 303
    assert "schedule_error=" in resp.headers["location"]
    assert STUB_STATE["schedule_puts"] == []


def test_upstream_400_reason_shown_next_to_form(client, make_token):
    token = make_token()
    resp = _post_schedule(client, token, {
        "cadence": "hourly", "hour_utc": "7", "enabled": "on",
    })
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "schedule_error=" in location

    follow = _get(client, token, location)
    assert follow.status_code == 200
    assert "Could not save the schedule" in follow.text
    assert "cadence must be one of" in follow.text


def test_upstream_503_renders_not_enabled_page(client, make_token):
    token = make_token()
    STUB_STATE["mode"] = "down503"
    resp = _post_schedule(client, token, {
        "cadence": "daily", "hour_utc": "7", "enabled": "on",
    })
    assert resp.status_code == 503
