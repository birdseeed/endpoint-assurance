"""Real HTTP upstream + production middleware, never a substitute route handler."""
import hashlib
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient
from tests.pat1966_support import CATEGORIES, PROXY, assert_owner, feed, isolated_app, stamp, upstream

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def harness(tmp_path, monkeypatch):
    with upstream() as (url, remote):
        with isolated_app(tmp_path, monkeypatch, url) as (dashboard, db, reads):
            # No context manager: startup/collectors/init_db must never run.
            client = TestClient(dashboard.app)
            yield client, dashboard, db, remote, reads
            client.close()


def request(harness):
    return harness[0].get(PROXY, headers=BEARER)


def check(response, key):
    assert response.status_code == 200, response.text
    return next(c for c in response.json()["checks"] if c["id"] == key)


def seed(harness, sql, values=()):
    assert_owner()
    with sqlite3.connect(harness[2]) as db:
        db.execute(sql, values)


def test_fixture_contract_control():
    body = feed()
    assert [c["id"] for c in body["checks"]] == [key for key, _ in CATEGORIES]
    assert body["coverage"] == "partial"
    assert {e["deep_link"] for e in body["exceptions"]} == {"/console#ops", "/console#automations"}
    assert all(e["since"] is None for e in body["exceptions"])
    assert any(e["tenant_id"] is None for e in body["exceptions"])


@pytest.mark.parametrize("credential", [None, "bad", "expired"])
def test_existing_auth_control_rejects_without_upstream(harness, credential):
    client, dashboard, _, remote, _ = harness
    if credential == "bad":
        client.cookies.set(dashboard.SESSION_COOKIE, "invalid")
    if credential == "expired":
        client.cookies.set(dashboard.SESSION_COOKIE, dashboard._session_encode("owner@example.test", int(time.time()) - 60))
    assert client.get(PROXY).status_code == 401
    assert remote["requests"] == []


@pytest.mark.parametrize("role", ["owner", "consultant"])
def test_actual_signed_session_can_read_but_consultant_owner_gate_remains(harness, role):
    client, dashboard, _, remote, _ = harness
    client.cookies.set(dashboard.SESSION_COOKIE, dashboard._session_encode(role + "@example.test", int(time.time()) + 300))
    assert client.get(PROXY).status_code == 200
    assert remote["requests"] == [("GET", "/admin/service-exceptions")]
    if role == "consultant":
        assert client.get("/admin/logs").status_code == 403
        assert client.post(PROXY).status_code == 403


def test_fixed_upstream_and_readonly_local_projection(harness):
    before = hashlib.sha256(harness[2].read_bytes()).hexdigest()
    response = harness[0].get(PROXY + "?tenant_id=other&path=https://example.invalid/private", headers=BEARER)
    assert response.status_code == 200, response.text
    assert harness[3]["requests"] == [("GET", "/admin/service-exceptions")]
    assert response.headers.get("cache-control") == "no-store"
    body = response.json()
    assert body["coverage"] == "partial"
    assert [c["id"] for c in body["checks"]] == [key for key, _ in CATEGORIES]
    assert body["exceptions"] == harness[3]["body"]["exceptions"]
    assert hashlib.sha256(harness[2].read_bytes()).hexdigest() == before


@pytest.mark.parametrize("key", [key for key, _ in CATEGORIES])
def test_independent_unavailable_category_is_never_healthy_zero(harness, key):
    remote = harness[3]
    target = next(c for c in remote["body"]["checks"] if c["id"] == key)
    target.update(availability="unavailable", result="unavailable", checked_at=None,
                  last_success_at=None, next_expected_at=None, observations=[])
    remote["body"]["exceptions"] = [e for e in remote["body"]["exceptions"] if e["check_id"] != key]
    row = check(request(harness), key)
    assert row["result"] in ("unknown", "unavailable")
    assert row["last_success_at"] is None
    assert row["next_expected_at"] is None
    assert row["reason"] and row["next_action"]


def test_per_job_success_is_not_aggregated_into_fake_recovery(harness):
    row = check(request(harness), "scheduled_jobs")
    assert row["last_success_at"] is None
    assert row["next_expected_at"] is None
    assert row["observations"] == harness[3]["body"]["checks"][1]["observations"]
    assert any(e["check_id"] == "scheduled_jobs" for e in request(harness).json()["exceptions"])


def test_true_empty_retains_partial_coverage(harness):
    harness[3]["body"] = feed(False)
    response = request(harness)
    assert response.status_code == 200, response.text
    assert response.json()["exceptions"] == []
    assert response.json()["coverage"] == "partial"
    assert any(c["result"] == "unavailable" for c in response.json()["checks"])


@pytest.mark.parametrize("failure", ["503", "invalid_json", "missing_checks", "null_exceptions"])
def test_failed_upstream_cannot_become_successful_empty(harness, failure):
    remote = harness[3]
    if failure == "503":
        remote["status"] = 503
        remote["body"] = {"error": "private upstream credentials must not escape"}
    elif failure == "invalid_json":
        remote["raw"] = b"not JSON"
    elif failure == "missing_checks":
        del remote["body"]["checks"]
    else:
        remote["body"]["exceptions"] = None
    response = request(harness)
    assert response.status_code in (502, 503), response.text
    assert "private upstream credentials" not in response.text
    assert response.json().get("error") or response.json().get("degraded")


@pytest.mark.parametrize("field,value", [
    ("deep_link", "https://example.invalid/steal"), ("deep_link", "//example.invalid/steal"),
    ("deep_link", "/console#tenant/other"), ("deep_link", "javascript:alert(1)"),
    ("tenant_id", {"id": "other"}), ("tenant_id", "../other"), ("check_id", "unsupported_future_source"),
    ("evidence_at", None), ("evidence_at", "invalid"), ("evidence_at", "2999-01-01T00:00:00Z"),
])
def test_invalid_exception_is_rejected_or_quarantined(harness, field, value):
    harness[3]["body"]["exceptions"][0][field] = value
    response = request(harness)
    assert response.status_code != 404, "Real RED: service exception proxy absent"
    if response.status_code == 200:
        body = response.json()
        assert not any(e["id"] == "scheduled_jobs:health_signals_recompute" for e in body["exceptions"])
        assert next(c for c in body["checks"] if c["id"] == "scheduled_jobs")["result"] in ("unknown", "unavailable")
    else:
        assert response.status_code in (502, 503)


@pytest.mark.parametrize("name,key", [("email_delivery", "outgoing_email"),
    ("tick_email_delivery_check", "scheduled_jobs"), ("deploy_drift", "version_checks"),
    ("maintenance_prod01", "server_health")])
def test_actual_local_check_evidence_is_joined_without_private_reason(harness, name, key):
    at = stamp()
    seed(harness, "INSERT INTO check_statuses VALUES (?,?,?,?)", (name, "degraded", "PRIVATE actor@example.test /root/key token", at))
    row = check(request(harness), key)
    assert row["availability"] != "unavailable"
    assert row["result"] != "ok"
    assert at in json.dumps(row), "Actual source time must be retained, not replaced by request time"
    assert "PRIVATE" not in json.dumps(row)
    assert any("check_statuses" in sql for sql in harness[4])


@pytest.mark.parametrize("at", [None, "bad-time", "2999-01-01T00:00:00Z", "2000-01-01T00:00:00Z"])
def test_bad_or_expired_local_success_cannot_prove_current_health(harness, at):
    seed(harness, "INSERT INTO check_statuses VALUES (?,?,?,?)", ("email_delivery", "ok", "configured", at))
    assert check(request(harness), "outgoing_email")["result"] in ("unknown", "unavailable", "stale")


def test_report_attempt_is_not_recipient_delivery_and_private_columns_do_not_escape(harness):
    at = stamp()
    seed(harness, "INSERT INTO report_send_audit_log VALUES (?,?,?,?,?,?,?,?,?,?)",
         ("attempt-fixture", at, "PRIVATE actor", "tenant-alder", "Alder", "assurance", "PRIVATE recipient", "billing", "failed", "PRIVATE /root/key credential"))
    response = request(harness)
    row = check(response, "reports")
    assert row["availability"] != "unavailable"
    assert at in json.dumps(row)
    assert "PRIVATE" not in response.text
    assert any("report_send_audit_log" in sql for sql in harness[4])
    assert row["last_success_at"] is None
    assert "delivery" in row["reason"].lower() and any(word in row["reason"].lower() for word in ("unknown", "unavailable", "not", "does not"))


def test_sql_read_failure_stays_unknown_even_when_legacy_getter_returns_empty(harness):
    seed(harness, "DROP TABLE check_statuses")
    assert harness[1]._get_check_statuses() == [], "Control demonstrates legacy swallowed read error"
    response = request(harness)
    for key in ("outgoing_email", "version_checks", "server_health"):
        row = check(response, key)
        assert row["result"] in ("unknown", "unavailable")
        assert row["last_success_at"] is None
        assert any(word in row["reason"].lower() for word in ("read", "unavailable", "unknown"))
    assert any(e["check_id"] == "scheduled_jobs" for e in response.json()["exceptions"])


def test_loopback_http_control_existing_proxy_reaches_real_stub(harness):
    harness[3]["body"] = {"service_health": {}}
    response = harness[0].get("/admin/health/proxy", headers=BEARER)
    assert response.status_code == 200
    assert harness[3]["requests"] == [("GET", "/admin/health"), ("GET", "/admin/automations")]


def test_owned_db_guard_control_denies_mutation_and_foreign_path(harness, tmp_path):
    with pytest.raises(AssertionError, match="non-owned DB"):
        harness[1]._open_db_connection(tmp_path / "foreign.db")
    # mode=ro independently denies a write, without exercising the harness's
    # mutation assertion (which deliberately makes test teardown fail).
    conn = sqlite3.connect(harness[2].as_uri() + "?mode=ro", uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("INSERT INTO check_statuses VALUES ('x','ok','','')")
    finally:
        conn.close()


def test_successful_send_attempt_still_does_not_establish_recipient_delivery(harness):
    at = stamp()
    seed(harness, "INSERT INTO report_send_audit_log VALUES (?,?,?,?,?,?,?,?,?,?)",
         ("sent-fixture", at, "PRIVATE actor", "tenant-alder", "Alder", "assurance", "PRIVATE recipient", "billing", "sent", "PRIVATE provider response"))
    response = request(harness)
    row = check(response, "reports")
    assert row["result"] in ("unknown", "unavailable")
    assert at in json.dumps(row)
    assert "PRIVATE" not in response.text
    assert "delivery" in row["reason"].lower()


def test_uncontracted_private_upstream_fields_are_not_forwarded(harness):
    body = harness[3]["body"]
    body["credentials"] = "PRIVATE credential"
    body["checks"][1]["job_output"] = "PRIVATE job output"
    body["exceptions"][0]["actor_email"] = "PRIVATE actor"
    response = request(harness)
    assert response.status_code != 404, "Real RED: proxy absent"
    assert "PRIVATE" not in response.text
    assert response.status_code in (200, 502, 503)
