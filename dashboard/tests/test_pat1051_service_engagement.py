"""PAT-1051 consultancy engagement contract and Account UI."""

import os
import sys
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}
EVIDENCE_CONTRACTS = json.loads(
    (Path(__file__).parent / "fixtures" / "pat1051_evidence_contracts.json").read_text()
)


def _cookie(email):
    token = dashboard._session_encode(email, int(time.time()) + 3600)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "dashboard.db"
    monkeypatch.setattr(shared, "DB_PATH", db_path)
    monkeypatch.setattr(dashboard, "DB_PATH", db_path)
    dashboard.init_db()
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, billing_tier, agent_config_tier, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "Acme", "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "patch", "patch", "2026-08-15T00:00:00Z"),
        )
    with TestClient(dashboard.app) as test_client:
        yield test_client


def _payload(**overrides):
    data = {
        "service_name": "Managed Patching",
        "named_specialist": "Andy Bridson",
        "service_cadence": "Monthly posture review",
        "posture_review_status": "scheduled",
        "next_review_date": "2026-09-01",
        "plan_status": "active",
        "plan_start_date": "2026-08-01",
        "plan_summary": "Reduce patch exposure and make evidence reviewable.",
        "decisions": ["Prioritise browser patching"],
        "owners": ["Patched: evidence review", "Customer IT: deployment window"],
        "exceptions": ["Legacy finance app until vendor release"],
        "project_links": [{"label": "90-day plan", "url": "https://linear.app/patched/project/plan"}],
        "escalation_links": [{"label": "Intune discovery", "url": "https://linear.app/patched/issue/PAT-2"}],
    }
    data.update(overrides)
    return data


class _PlatformTenantAbsent:
    status_code = 404
    headers = {"content-type": "application/json; charset=utf-8"}

    def json(self):
        return {"error": "tenant not found"}


def test_service_engagement_round_trip_is_separate_from_technical_tier(client):
    before = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/account", headers=BEARER).json()
    response = client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    assert response.status_code == 200
    saved = response.json()["engagement"]
    assert saved["service_name"] == "Managed Patching"
    assert saved["plan_status"] == "active"
    assert saved["decisions"] == ["Prioritise browser patching"]
    assert saved["project_links"][0]["url"].startswith("https://linear.app/")
    readback = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER)
    assert readback.json()["engagement"] == saved
    after = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/account", headers=BEARER).json()
    assert after["billing_tier"] == before["billing_tier"] == "patch"
    assert after["agent_config_tier"] == before["agent_config_tier"] == "patch"


@pytest.mark.parametrize("service_name", ["Report & Deploy", "Full Management", "endpoint assurance", ""])
def test_service_name_accepts_only_customer_catalogue_names(client, service_name):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(service_name=service_name),
    )
    assert response.status_code == 400


def test_service_links_are_links_only_and_fail_closed(client):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(project_links=[{"label": "Not a task", "url": "javascript:alert(1)"}]),
    )
    assert response.status_code == 400
    assert "absolute http or https URL" in response.json()["error"]


@pytest.mark.parametrize(
    "project_links",
    [
        [{"label": "Plan | phase one", "url": "https://example.test/plan"}],
        [{"label": "Plan", "url": "https://example.test/plan|raw"}],
    ],
)
def test_link_textarea_separator_cannot_appear_in_labels_or_urls(client, project_links):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(project_links=project_links),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "project_links labels and URLs must not contain |"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("named_specialist", 7),
        ("service_cadence", {"every": "month"}),
        ("plan_summary", ["not", "text"]),
        ("next_review_date", 20260901),
        ("posture_review_status", False),
        ("posture_review_status", 0),
        ("plan_status", []),
        ("plan_status", {}),
        ("project_links", [{"label": ["not", "text"], "url": "https://example.test"}]),
    ],
)
def test_text_and_link_label_fields_reject_non_strings(client, field, value):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(**{field: value}),
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("decisions", ["Approve browser patching\nInjected owner"], "decisions entries must not contain line breaks"),
        ("project_links", [{"label": "Plan\r\nInjected", "url": "https://example.test/plan"}], "project_links labels must not contain line breaks"),
        ("project_links", [{"label": "Plan", "url": "https://example.test/plan\nInjected"}], "project_links URLs must not contain line breaks"),
    ],
)
def test_line_entries_and_link_labels_reject_embedded_line_breaks(client, field, value, message):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(**{field: value}),
    )
    assert response.status_code == 400
    assert response.json()["error"] == message


@pytest.mark.parametrize(
    "value", ["2026-09-01T00:00:00", "20260901", "2026-9-01", "2026-02-30"]
)
def test_service_dates_require_exact_yyyy_mm_dd(client, value):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(next_review_date=value),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "next_review_date must be YYYY-MM-DD"


def test_malformed_json_returns_400(client):
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers={**BEARER, "Content-Type": "application/json"},
        content=b'{"service_name":',
    )
    assert response.status_code == 400
    assert response.json() == {"error": "request body must be valid JSON"}


def test_unknown_tenant_is_not_created_as_crm_side_effect(client):
    response = client.put("/admin/tenants/d6bbd8fc-91e5-5087-ba03-f54b1cec8b13/service-engagement", headers=BEARER, json=_payload())
    assert response.status_code == 404


@pytest.mark.usefixtures("network_down")
def test_no_service_state_and_confirmed_removal_preserve_technical_tier(client):
    empty = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER)
    assert empty.json() == {"engagement": None}
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    removed = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers={**BEARER, "X-Confirm-Resource": "Acme", "X-Audit-Reason": "Wrong tenant snapshot"},
    )
    assert removed.status_code == 200
    assert removed.json() == {"deleted": True, "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"}
    assert client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER).json() == {"engagement": None}
    account = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/account", headers=BEARER).json()
    assert account["billing_tier"] == "patch"
    assert account["agent_config_tier"] == "patch"
    with dashboard.get_db() as db:
        audit = db.execute(
            "SELECT before_value, after_value FROM admin_audit_log "
            "WHERE method='DELETE' AND path='/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement'"
        ).fetchone()
    assert json.loads(audit["before_value"])["service_name"] == "Managed Patching"
    assert json.loads(audit["after_value"]) is None


@pytest.mark.usefixtures("network_down")
def test_internal_engagement_auth_role_and_tenant_scope(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    assert client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement").status_code == 401
    consultant = _cookie("consultant@patched.im")
    assert client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=consultant).status_code == 200
    current = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=consultant
    ).json()["engagement"]
    assert client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=consultant,
        json=_payload(expected_updated_at=current["updated_at"]),
    ).status_code == 200
    assert client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers={**consultant, "X-Confirm-Resource": "Acme"},
    ).status_code == 403
    monkeypatch.setattr(
        dashboard, "_imp_get",
        lambda request: {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "write_mode": False},
    )
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=_cookie("owner@patched.im")
    ).status_code == 200
    assert client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers=_cookie("owner@patched.im"), json=_payload(),
    ).status_code == 403
    assert client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers={**_cookie("owner@patched.im"), "X-Confirm-Resource": "Acme"},
    ).status_code == 403
    monkeypatch.setattr(
        dashboard, "_imp_get",
        lambda request: {"tenant_id": "tenant-other", "write_mode": True},
    )
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=_cookie("owner@patched.im")
    ).status_code == 403
    assert client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers=_cookie("owner@patched.im"), json=_payload(),
    ).status_code == 403


def test_service_route_has_its_own_read_only_impersonation_write_denial(monkeypatch):
    request = object()
    monkeypatch.setattr(
        dashboard, "_imp_get",
        lambda incoming: {"tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "write_mode": False},
    )
    assert dashboard._service_engagement_scope_error(request, "fd46eac4-17e8-51ae-bb80-aba4a343c3ac") is None
    denied = dashboard._service_engagement_scope_error(
        request, "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", require_write=True
    )
    assert denied.status_code == 403


@pytest.mark.usefixtures("network_down")
def test_service_removal_requires_exact_server_side_confirmation(client):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    missing = client.delete("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER)
    mismatch = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers={**BEARER, "X-Confirm-Resource": "Wrong customer"},
    )
    assert missing.status_code == 428
    assert mismatch.status_code == 409
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


@pytest.mark.parametrize(
    ("payload", "route"),
    [
        ({"summary": {"total": 1}}, "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/needs-attention"),
        ({"total": 40, "records": [{"id": "one-page"}]}, "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/report-records"),
        ({"total": 2, "apps": [{"id": "partial-page"}]}, "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/metering"),
    ],
)
def test_shared_evidence_proxies_preserve_partial_and_paged_consumers(
    client, monkeypatch, payload, route
):
    class Upstream:
        status_code = 200
        content = b"json"

        def json(self):
            return payload

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Upstream())
    response = client.get(route, headers=BEARER)
    assert response.status_code == 200
    assert response.json() == payload


def test_metering_proxy_requests_the_uncapped_complete_endpoint(client, monkeypatch):
    seen = {}

    class Upstream:
        status_code = 200
        content = b"json"

        def json(self):
            return EVIDENCE_CONTRACTS["metering"]

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen["kwargs"] = kwargs
        return Upstream()

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    response = client.get("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/metering", headers=BEARER)
    assert response.status_code == 200
    assert seen["url"].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/metering")
    assert "params" not in seen["kwargs"]
    body = response.json()
    assert body["total"] == len(body["apps"])


def test_report_proxy_forwards_the_upstream_pagination_contract(client, monkeypatch):
    seen = {}

    class Upstream:
        status_code = 200
        content = b"json"

        def json(self):
            return {"page": 3, "per_page": 100, "total": 250, "records": []}

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen["params"] = kwargs.get("params")
        return Upstream()

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    response = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/report-records?page=3&per_page=100", headers=BEARER
    )
    assert response.status_code == 200
    assert seen["url"].endswith("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/report-records")
    assert seen["params"] == {"page": "3", "per_page": "100"}


def test_service_snapshot_survives_repeated_database_initialisation(client):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    dashboard.init_db()
    dashboard.init_db()
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"]["service_name"] == "Managed Patching"


def test_service_initialisation_has_no_global_fk_or_snapshot_deletion():
    source = Path(dashboard.__file__).read_text()
    get_db_source = source[source.index("def get_db():") : source.index("def init_db():")]
    assert "foreign_keys" not in get_db_source
    service_schema = source[source.index("CREATE TABLE IF NOT EXISTS service_engagements") :]
    service_schema = service_schema[: service_schema.index("# PAT-1103")]
    assert "FOREIGN KEY" not in service_schema
    assert "DELETE FROM service_engagements" not in service_schema


def test_service_put_uses_optimistic_concurrency_and_audits_before_after(client):
    created = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload()
    ).json()["engagement"]
    token = created["updated_at"]
    updated_response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(expected_updated_at=token, plan_summary="Updated by the current editor."),
    )
    assert updated_response.status_code == 200
    updated = updated_response.json()["engagement"]
    assert updated["plan_summary"] == "Updated by the current editor."
    stale = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(expected_updated_at=token, plan_summary="Stale overwrite"),
    )
    assert stale.status_code == 409
    assert stale.json()["engagement"]["plan_summary"] == "Updated by the current editor."
    with dashboard.get_db() as db:
        rows = db.execute(
            "SELECT outcome, before_value, after_value FROM admin_audit_log "
            "WHERE method='PUT' AND path='/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement' ORDER BY ts"
        ).fetchall()
    successful_update = next(row for row in rows if row["before_value"])
    before = json.loads(successful_update["before_value"])
    after = json.loads(successful_update["after_value"])
    assert successful_update["outcome"] == "allowed"
    assert before["updated_at"] == token
    assert after["plan_summary"] == "Updated by the current editor."
    assert rows[-1]["outcome"] == "rejected_409"


def test_service_put_rowcount_guard_catches_update_after_initial_read(client, monkeypatch):
    created = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload()
    ).json()["engagement"]

    def concurrent_update(db, tenant_id):
        db.execute(
            "UPDATE service_engagements SET plan_summary=?, updated_at=? WHERE tenant_id=?",
            ("Concurrent writer won", "2026-08-15T23:59:59+00:00", tenant_id),
        )

    monkeypatch.setattr(dashboard, "_SERVICE_ENGAGEMENT_BEFORE_WRITE_HOOK", concurrent_update)
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER,
        json=_payload(expected_updated_at=created["updated_at"], plan_summary="Stale writer"),
    )
    assert response.status_code == 409
    assert response.json()["engagement"]["plan_summary"] == "Concurrent writer won"


def test_service_put_rowcount_guard_fails_closed_when_expected_version_is_null(client, monkeypatch):
    def concurrent_insert(db, tenant_id):
        db.execute(
            "INSERT INTO service_engagements "
            "(tenant_id, service_name, posture_review_status, plan_status, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                tenant_id, "Endpoint Assurance", "not_started", "not_started",
                "2026-08-15T23:59:59+00:00",
            ),
        )

    monkeypatch.setattr(dashboard, "_SERVICE_ENGAGEMENT_BEFORE_WRITE_HOOK", concurrent_insert)
    response = client.put(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload()
    )
    assert response.status_code == 409
    assert response.json()["engagement"]["service_name"] == "Endpoint Assurance"
    assert response.json()["engagement"]["updated_at"] == "2026-08-15T23:59:59+00:00"


@pytest.mark.usefixtures("network_down")
def test_successful_tenant_purge_removes_snapshot_and_recreated_same_tenant_is_clean(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Upstream:
        status_code = 200

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    purged = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert purged.status_code == 200
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json() == {"engagement": None}
    with dashboard.get_db() as db:
        db.execute("DELETE FROM clients WHERE tenant_id=?", ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac",))
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, billing_tier, agent_config_tier, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("c2", "Recreated Acme", "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "report", "report", "2026-08-16T00:00:00Z"),
        )
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json() == {"engagement": None}


@pytest.mark.usefixtures("network_down")
def test_purge_cleanup_conditional_delete_guard_refuses_lost_update(client, monkeypatch):
    """A write racing the post-purge local cleanup must not be silently
    discarded by an unconditional DELETE: _delete_service_engagement_for_
    purged_tenant now guards its DELETE on the exact updated_at it read
    (same version-qualified predicate as orphan repair) and raises — rolling
    back its own transaction, deleting nothing — rather than blowing away a
    row that changed underneath it. The purge itself still succeeds (the
    platform is authoritative for the tenant); local cleanup instead reports
    failed/snapshot-preserved exactly like any other cleanup exception, so
    an operator can inspect and repair it via the orphan flow afterwards.
    """
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    def concurrent_write(db, tenant_id):
        db.execute(
            "UPDATE service_engagements SET updated_at=? WHERE tenant_id=?",
            ("2026-08-16T00:00:02+00:00", tenant_id),
        )

    monkeypatch.setattr(dashboard, "_SERVICE_ENGAGEMENT_PURGE_CLEANUP_HOOK", concurrent_write)

    class Upstream:
        status_code = 200

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 200
    assert response.headers["X-Patched-Local-Cleanup"] == "service-engagement-failed"
    # Not deleted — the guard refused to fire on a stale version match.
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


@pytest.mark.usefixtures("network_down")
def test_successful_tenant_purge_audits_full_deleted_snapshot(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Upstream:
        status_code = 200

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**_cookie("owner@patched.im"), "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 200
    assert response.json() == {"purged": True, "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"}
    with dashboard.get_db() as db:
        audit = db.execute(
            "SELECT actor_email, role, outcome, before_value, after_value "
            "FROM admin_audit_log WHERE method='DELETE' "
            "AND path='/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge' ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    assert audit["actor_email"] == "owner@patched.im"
    assert audit["role"] == "owner"
    assert audit["outcome"] == "allowed"
    before = json.loads(audit["before_value"])
    assert before["service_name"] == "Managed Patching"
    assert before["decisions"] == ["Prioritise browser patching"]
    assert before["project_links"] == _payload()["project_links"]
    assert json.loads(audit["after_value"]) is None


@pytest.mark.usefixtures("network_down")
def test_reversible_tenant_offboard_preserves_snapshot_for_restore(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Upstream:
        status_code = 204

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    removed = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
        headers={**BEARER, "X-Confirm-Resource": "Acme"},
    )
    assert removed.status_code == 204
    restored = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"]
    assert restored["service_name"] == "Managed Patching"
    assert restored["plan_summary"] == _payload()["plan_summary"]


@pytest.mark.usefixtures("network_down")
def test_successful_upstream_purge_remains_authoritative_when_local_cleanup_fails(
    client, monkeypatch, capsys
):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Upstream:
        status_code = 200

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    monkeypatch.setattr(
        dashboard,
        "_delete_service_engagement_for_purged_tenant",
        lambda tenant_id: (_ for _ in ()).throw(dashboard.sqlite3.OperationalError("database is locked")),
    )
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 200
    assert response.headers["X-Patched-Local-Cleanup"] == "service-engagement-failed"
    diagnostic = capsys.readouterr().err
    assert "[CRITICAL tenant-delete]" in diagnostic
    assert "tenant_id=fd46eac4-17e8-51ae-bb80-aba4a343c3ac" in diagnostic
    assert "database is locked" in diagnostic
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


@pytest.mark.usefixtures("network_down")
def test_async_202_purge_does_not_delete_local_snapshot(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Accepted:
        status_code = 202

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Accepted())
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 202
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


def test_cleanup_critical_log_escapes_tenant_line_breaks(monkeypatch, capsys):
    monkeypatch.setattr(
        dashboard,
        "_delete_service_engagement_for_purged_tenant",
        lambda tenant_id: (_ for _ in ()).throw(dashboard.sqlite3.OperationalError("locked")),
    )
    headers, before, cleaned = dashboard._cleanup_service_engagement_after_tenant_delete(
        "safe\r\nINJECT"
    )
    diagnostic = capsys.readouterr().err
    assert headers == {"X-Patched-Local-Cleanup": "service-engagement-failed"}
    assert before is None
    assert cleaned is False
    assert "tenant_id=safe\\r\\nINJECT" in diagnostic
    assert "\nINJECT" not in diagnostic


def test_orphan_repair_requires_authoritative_absence_and_is_audited(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: _PlatformTenantAbsent()
    )
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 200
    assert response.json() == {"deleted": True, "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "repair": "orphan"}
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json() == {"engagement": None}
    with dashboard.get_db() as db:
        audit = db.execute(
            "SELECT outcome, before_value, after_value FROM admin_audit_log "
            "WHERE path='/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan'"
        ).fetchone()
    assert audit["outcome"] == "allowed"
    assert json.loads(audit["before_value"])["service_name"] == "Managed Patching"
    assert json.loads(audit["after_value"]) is None


def test_owner_can_preview_platform_absent_orphan_after_client_row_is_gone(client, monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    with dashboard.get_db() as db:
        db.execute("DELETE FROM clients WHERE tenant_id=?", ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac",))
    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: _PlatformTenantAbsent()
    )

    response = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers=_cookie("owner@patched.im"),
    )
    assert response.status_code == 200
    # Full consultancy-engagement snapshot, surfaced pre-confirmation — must
    # never be cached by an intermediary or the browser's own disk cache.
    assert response.headers["cache-control"] == "no-cache, no-store, must-revalidate"
    assert response.headers["pragma"] == "no-cache"
    body = response.json()
    assert body["platform_absent"] is True
    assert body["repair_available"] is True
    assert body["engagement"]["service_name"] == "Managed Patching"
    assert body["engagement"]["owners"] == _payload()["owners"]
    with dashboard.get_db() as db:
        audit = db.execute(
            "SELECT actor_email, role, outcome, before_value, after_value "
            "FROM admin_audit_log WHERE method='GET' "
            "AND path='/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan' "
            "ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    assert audit["actor_email"] == "owner@patched.im"
    assert audit["role"] == "owner"
    assert audit["outcome"] == "allowed"
    assert json.loads(audit["before_value"])["plan_summary"] == _payload()["plan_summary"]
    assert json.loads(audit["after_value"]) == {"read_only": True}


def test_orphan_preview_is_owner_only_and_fails_closed_on_noncanonical_404(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    denied = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers=_cookie("consultant@patched.im"),
    )
    assert denied.status_code == 403

    class Gateway404:
        status_code = 404
        headers = {"content-type": "text/html"}

        def json(self):
            return {"error": "tenant not found"}

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Gateway404())
    refused = client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers=_cookie("owner@patched.im"),
    )
    assert refused.status_code == 503


def test_orphan_repair_refuses_live_or_unprovable_platform_tenant(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Present:
        status_code = 200
        content = b'{}'

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Present())
    present = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert present.status_code == 409

    class Unavailable:
        status_code = 503
        content = b""

        def json(self):
            raise ValueError("unavailable")

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Unavailable())
    unavailable = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert unavailable.status_code == 503
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


def test_platform_absence_uses_authoritative_tenant_lookup_only(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen["kwargs"] = kwargs
        return _PlatformTenantAbsent()

    monkeypatch.setattr(dashboard.http, "get", fake_get)
    assert dashboard._platform_confirms_tenant_absent("tenant/one") is True
    assert seen["url"].endswith("/admin/tenants/tenant%2Fone/allowlist")
    assert "params" not in seen["kwargs"]


@pytest.mark.parametrize(
    ("content_type", "payload"),
    [
        ("text/html", {"error": "tenant not found"}),
        ("application/json", {"error": "not found"}),
        ("application/json", {"error": "tenant not found", "via": "gateway"}),
        (None, {"error": "tenant not found"}),
    ],
)
def test_platform_absence_rejects_noncanonical_404s(monkeypatch, content_type, payload):
    class Response:
        status_code = 404
        headers = {"content-type": content_type} if content_type else {}

        def json(self):
            return payload

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Response())
    assert dashboard._platform_confirms_tenant_absent("fd46eac4-17e8-51ae-bb80-aba4a343c3ac") is None


def test_platform_absence_rejects_invalid_json_404(monkeypatch):
    class Response:
        status_code = 404
        headers = {"content-type": "application/json"}

        def json(self):
            raise ValueError("gateway body")

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Response())
    assert dashboard._platform_confirms_tenant_absent("fd46eac4-17e8-51ae-bb80-aba4a343c3ac") is None


@pytest.mark.parametrize("status_code", [200, 403])
def test_platform_tenant_specific_lookup_proves_presence(monkeypatch, status_code):
    class Response:
        headers = {}

    Response.status_code = status_code
    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Response())
    assert dashboard._platform_confirms_tenant_absent("fd46eac4-17e8-51ae-bb80-aba4a343c3ac") is False


def test_orphan_repair_refuses_snapshot_changed_during_platform_io(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    def concurrent_put(tenant_id):
        with dashboard.get_db() as db:
            db.execute(
                "UPDATE service_engagements SET plan_summary=?, updated_at=? WHERE tenant_id=?",
                ("Concurrent PUT", "2026-08-16T00:00:00+00:00", tenant_id),
            )

    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: _PlatformTenantAbsent()
    )
    monkeypatch.setattr(
        dashboard, "_SERVICE_ENGAGEMENT_ORPHAN_AFTER_PROOF_HOOK", concurrent_put
    )
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 409
    assert response.json()["engagement"]["plan_summary"] == "Concurrent PUT"
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"]["plan_summary"] == "Concurrent PUT"


def test_orphan_conditional_delete_rowcount_guard_refuses_lost_update(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: _PlatformTenantAbsent()
    )
    def concurrent_update(db, tenant_id):
        db.execute(
            "UPDATE service_engagements SET updated_at=? WHERE tenant_id=?",
            ("2026-08-16T00:00:01+00:00", tenant_id),
        )

    monkeypatch.setattr(
        dashboard, "_SERVICE_ENGAGEMENT_ORPHAN_BEFORE_DELETE_HOOK", concurrent_update
    )
    refused = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert refused.status_code == 409
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


def test_orphan_repair_never_treats_a_collection_200_as_absence(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Partial:
        status_code = 200
        content = b'{"tenants":[]}'

        def json(self):
            return {"tenants": []}

    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Partial())
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 409


@pytest.mark.usefixtures("network_down")
def test_orphan_repair_remains_owner_only_confirmed_and_outside_impersonation(
    client, monkeypatch
):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    consultant = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**_cookie("consultant@patched.im"), "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert consultant.status_code == 403
    missing_confirm = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers=_cookie("owner@patched.im"),
    )
    assert missing_confirm.status_code == 428

    impersonation = {
        "session_id": "imp-1", "tenant_id": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac", "actor_email": "owner@patched.im",
        "write_mode": True, "started_at": "2026-08-15T00:00:00Z",
        "expires_at": "2099-08-15T01:00:00+00:00",
    }
    token = dashboard._imp_encode(impersonation)
    owner_cookie = _cookie("owner@patched.im")["Cookie"]
    denied = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={
            "Cookie": f"{owner_cookie}; {dashboard.IMP_COOKIE}={token}",
            "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac",
        },
    )
    assert denied.status_code == 403


@pytest.mark.usefixtures("network_down")
def test_ordinary_delete_keeps_missing_client_404_but_repair_can_recover(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())
    with dashboard.get_db() as db:
        db.execute("DELETE FROM clients WHERE tenant_id=?", ("fd46eac4-17e8-51ae-bb80-aba4a343c3ac",))
    ordinary = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert ordinary.status_code == 404

    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: _PlatformTenantAbsent()
    )
    repaired = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement/orphan",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert repaired.status_code == 200


@pytest.mark.usefixtures("network_down")
def test_failed_tenant_purge_preserves_snapshot(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Upstream:
        status_code = 503

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    purged = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert purged.status_code == 503
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"]["service_name"] == "Managed Patching"


@pytest.mark.usefixtures("network_down")
def test_redirected_tenant_purge_preserves_snapshot(client, monkeypatch):
    client.put("/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER, json=_payload())

    class Upstream:
        status_code = 302

    monkeypatch.setattr(dashboard.http, "delete", lambda *args, **kwargs: Upstream())
    response = client.delete(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/purge",
        headers={**BEARER, "X-Confirm-Resource": "fd46eac4-17e8-51ae-bb80-aba4a343c3ac"},
    )
    assert response.status_code == 302
    assert client.get(
        "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/service-engagement", headers=BEARER
    ).json()["engagement"] is not None


def test_purge_repair_button_stays_disabled_until_a_preview_succeeds():
    """The operator must actually see the retained snapshot before the
    destructive repair action becomes clickable — not just have the option
    to preview it. Covers both layers: the button ships disabled in markup,
    _purgeOpen re-disables it on every open, only a successful preview
    response re-enables it, and _purgeRepairOrphan itself refuses to fire
    if it's somehow invoked while still disabled.
    """
    console = (dashboard.BASE / "templates" / "console.html").read_text()
    assert '<button class="lc-btn-danger owner-only" type="button" id="purge-repair-btn" disabled onclick="_purgeRepairOrphan()">' in console
    open_fn = console[console.index("function _purgeOpen"):console.index("function _purgeClose")]
    assert "document.getElementById('purge-repair-btn').disabled = true;" in open_fn
    preview_fn = console[console.index("function _purgePreviewOrphan"):console.index("function _purgeRepairOrphan")]
    assert "if (repairBtn) repairBtn.disabled = true;" in preview_fn
    assert "if (repairBtn) repairBtn.disabled = false;" in preview_fn
    repair_fn = console[console.index("function _purgeRepairOrphan"):console.index("// ── Customers list filter")]
    assert "if (!tid || !_serviceUI || (repairBtn && repairBtn.disabled)) return;" in repair_fn


def test_service_engagement_ui_is_retired_while_its_backend_contract_remains():
    console = (dashboard.BASE / "templates" / "console.html").read_text()
    assert 'data-account-view-button="service"' not in console
    assert 'data-retired-surface="service-engagement"' in console
    assert "/admin/tenants/{tenant_id}/service-engagement" in {
        route.path for route in dashboard.app.routes
    }
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"


def test_tenant_entry_does_not_activate_retired_service_ui():
    console = (dashboard.BASE / "templates" / "console.html").read_text()
    enter_start = console.index("function enterTenant")
    enter = console[enter_start : enter_start + 5000]
    assert "_serviceTenantChanged" not in enter


def test_service_handlers_are_wired_to_tested_controller_transitions():
    console = (dashboard.BASE / "templates" / "console.html").read_text()
    save = console[console.index("function _serviceSave"):console.index("function _serviceRemove")]
    finalizer = save[save.index(".finally(function()") :]
    assert "button.disabled = _serviceUI ? !_serviceUI.canSave() : false;" in finalizer
    assert "button.textContent = 'Save engagement';" in finalizer
    activate = console[console.index("function _serviceActivate"):console.index("function _serviceSave")]
    assert "_serviceLoadOutcomes(tid, endpoint, activation.outcomes)" in activate
    outcomes = console[console.index("function _serviceLoadOutcomes"):console.index("function _serviceActivate")]
    assert "_serviceShowOutcomesLoading();" in outcomes
    assert "_serviceFetchAllReports(endpoint)" in outcomes
    assert "err && err.status === 409" in save
    assert "conflictDraft(submittedDraft" in save
    assert "if (_serviceUI && !_serviceUI.canSave())" in save
    assert "_serviceShowConflict(conflict);" in save
    assert "_serviceExpectedUpdatedAt = conflict.draft.expected_updated_at" not in save
    assert "_serviceActivate()" not in save[save.index("err && err.status === 409"):]
    remove = console[console.index("function _serviceRemove"):console.index("function _supportAccessLoad")]
    assert remove.count("_serviceMutationCompletion(tid, generation, ['engagement', 'outcomes'])") == 2
    assert "_serviceUI.removeComplete(tid, _servicePopulate);" in remove
    start = console[console.index("function _serviceStart"):console.index("function _serviceRenderLinks")]
    assert "_serviceUI.startDraft(tid, draft, _servicePopulate, _serviceRenderOutcomeItems)" in start
    controller = console[console.index("function _serviceApplyRetryState"):console.index("function _serviceMessage")]
    assert "_serviceController.retry(targets)" in controller
    assert "_serviceModule.settleCompletion" in controller
    assert "_serviceController.activate(tid)" in activate
    view_select = console[console.index("function _acctViewSelect"):console.index("function _acctArrangePanels")]
    assert "_serviceActivate();" in view_select
    assert "_serviceController.retry" not in view_select


def test_outcomes_use_owned_retry_state_and_bounded_complete_report_pagination():
    console = (dashboard.BASE / "templates" / "console.html").read_text()
    fetch = console[
        console.index("function _serviceFetchAllReports"):
        console.index("function _serviceActivate")
    ]
    assert "maxRecords = 2000" in fetch
    assert "maxPages = 25" in fetch
    assert "per_page=100" in fetch
    assert "appendReportPage" in fetch
    assert "nextReportPage" in fetch
    assert "completeThroughCutoff" in fetch
    loading = console[
        console.index("function _serviceShowOutcomesLoading"):
        console.index("function _serviceFetchAllReports")
    ]
    assert "host.replaceChildren();" in loading
    assert "Loading evidence" in loading


def test_consultant_can_maintain_service_snapshot_but_not_tiers():
    assert dashboard._consultant_write_allowed("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/service-engagement") is True
    assert dashboard._consultant_write_allowed("PUT", "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/subscription-tier") is False
