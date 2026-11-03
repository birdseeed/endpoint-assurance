"""PAT-1847 dashboard consumer contract for the platform report registry."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402


BEARER = {"Authorization": "Bearer test-key"}


class Response:
    def __init__(self, status_code=200, payload=None, content=b"PDF"):
        self.status_code = status_code
        self.payload = payload
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    def json(self):
        return self.payload


def entry(report_type="executive-summary", scope="tenant", path=None):
    if path is None:
        path = (
            "/admin/reports/executive-summary/{tenantID}.pdf"
            if scope == "tenant"
            else "/admin/reports/{deviceID}/compliance.pdf"
        )
    return {
        "type": report_type,
        "label": report_type.replace("-", " ").title(),
        "description": "Platform-owned report metadata.",
        "default_frequency": "monthly" if scope == "tenant" else "ad_hoc",
        "customer_facing": scope == "tenant",
        "subject_scope": scope,
        "admin_pdf_path": path,
    }


def catalogue(*entries):
    return {"reports": list(entries)}


@pytest.fixture(autouse=True)
def reset_catalogue_cache():
    dashboard._REPORT_CATALOGUE_CACHE.update(
        entries=None, fetched_at=0.0, failure_reason=None, failure_at=0.0,
    )
    yield
    dashboard._REPORT_CATALOGUE_CACHE.update(
        entries=None, fetched_at=0.0, failure_reason=None, failure_at=0.0,
    )


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as test_client:
        yield test_client


def test_catalogue_success_is_bounded_cached_and_keeps_platform_metadata(monkeypatch):
    calls = []
    clock = iter((100.0, 101.0, 100.0 + dashboard._REPORT_CATALOGUE_TTL_SECONDS + 1))

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return Response(payload=catalogue(entry(), entry("device-compliance", "device")))

    monkeypatch.setattr(dashboard.http, "get", get)
    monkeypatch.setattr(dashboard.time, "monotonic", lambda: next(clock))
    first = dashboard._report_catalogue()
    second = dashboard._report_catalogue()
    third = dashboard._report_catalogue()

    assert first is second
    assert third is not first
    assert len(calls) == 2
    assert calls[0][1]["headers"]["User-Agent"] == "Patched-Dashboard/1.0"
    assert first[0]["admin_pdf_path"] == "/admin/reports/executive-summary/{tenantID}.pdf"


def test_catalogue_failure_uses_short_bounded_negative_cache(monkeypatch):
    calls = []
    clock = iter((100.0, 101.0, 100.0 + dashboard._REPORT_CATALOGUE_FAILURE_TTL_SECONDS + 1))

    def get(url, **kwargs):
        calls.append(url)
        return Response(status_code=503, payload={"error": "unavailable"})

    monkeypatch.setattr(dashboard.http, "get", get)
    monkeypatch.setattr(dashboard.time, "monotonic", lambda: next(clock))

    for _ in range(3):
        with pytest.raises(dashboard.ReportCatalogueUnavailable):
            dashboard._report_catalogue()

    assert len(calls) == 2
    assert dashboard._REPORT_CATALOGUE_CACHE["entries"] is None


@pytest.mark.parametrize("payload", [
    {},
    catalogue(entry(), entry()),
    catalogue(entry(scope="organisation")),
    catalogue(entry(path="/admin/reports/executive-summary/{deviceID}.pdf")),
    catalogue(entry(path="/admin/reports/%2e%2e/secret/{tenantID}.pdf")),
    catalogue(entry(path="/admin/reports/report%2Fextra/{tenantID}.pdf")),
    catalogue(entry(path="/admin/reports/report%5Cextra/{tenantID}.pdf")),
    catalogue(
        entry("tenant-a", "tenant", "/admin/reports/shared/{tenantID}.pdf"),
        entry("tenant-b", "tenant", "/admin/reports/shared/{tenantID}.pdf"),
    ),
    catalogue(
        entry("shared", "tenant", "/admin/reports/shared/{tenantID}.pdf"),
        entry("other", "tenant", "/admin/reports/shared/{tenantID}.pdf"),
    ),
])
def test_malformed_duplicate_unknown_scope_or_ambiguous_reference_fails_closed(monkeypatch, payload):
    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Response(payload=payload))
    with pytest.raises(dashboard.ReportCatalogueUnavailable):
        dashboard._report_catalogue()
    assert dashboard._REPORT_CATALOGUE_CACHE["entries"] is None


def test_catalogue_upstream_auth_failure_is_explicit_not_a_local_fallback(client, monkeypatch):
    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: Response(status_code=401, payload={"error": "unauthorized"}),
    )
    with pytest.raises(dashboard.ReportCatalogueUnavailable):
        dashboard._report_catalogue()

    response = client.get("/admin/tenants/2bbd50ac-5eb7-5977-b56a-742b62c69604/reports-config", headers=BEARER)
    assert response.status_code == 503
    assert response.json()["degraded"] is True


def test_subject_template_substitution_encodes_slashes_as_one_platform_segment():
    tenant = entry()
    device = entry("device-compliance", "device")

    # The platform/FastAPI contract treats each substituted subject as one
    # path segment, even when its identifier itself contains a slash.
    assert dashboard._report_platform_path(tenant, tenant_id="tenant/a") == "/admin/reports/executive-summary/tenant%2Fa.pdf"
    assert dashboard._report_platform_path(device, device_id="device/a") == "/admin/reports/device%2Fa/compliance.pdf"
    with pytest.raises(ValueError):
        dashboard._report_platform_path(tenant, device_id="device-a")
    with pytest.raises(ValueError):
        dashboard._report_platform_path(device, tenant_id="tenant-a")


def test_generic_proxy_uses_registry_path_for_tenant_and_device(client, monkeypatch):
    calls = []
    registry = catalogue(
        entry(),
        entry("cve-report", "tenant", "/admin/reports/cve/{tenantID}.pdf"),
        entry("device-compliance", "device"),
    )

    def get(url, **kwargs):
        calls.append(url)
        if url.endswith("/admin/reports/catalogue"):
            return Response(payload=registry)
        return Response(content=b"%PDF-1.7")

    monkeypatch.setattr(dashboard.http, "get", get)
    tenant_response = client.get("/admin/reports/executive-summary/fd46eac4-17e8-51ae-bb80-aba4a343c3ac", headers=BEARER)
    legacy_response = client.get("/admin/reports/cve/c7113275-c767-5e19-bec2-eadd833e313e", headers=BEARER)
    device_response = client.get("/admin/reports/device-compliance/device-1", headers=BEARER)

    assert tenant_response.status_code == legacy_response.status_code == device_response.status_code == 200
    assert calls[-3].endswith("/admin/reports/executive-summary/fd46eac4-17e8-51ae-bb80-aba4a343c3ac.pdf")
    assert calls[-2].endswith("/admin/reports/cve/c7113275-c767-5e19-bec2-eadd833e313e.pdf")
    assert calls[-1].endswith("/admin/reports/device-1/compliance.pdf")
    with dashboard.get_db() as db:
        device_delivery = db.execute(
            "SELECT tenant_id, subject_scope, subject_id, report_type FROM report_deliveries "
            "WHERE subject_scope='device'"
        ).fetchone()
    assert dict(device_delivery) == {
        "tenant_id": "",
        "subject_scope": "device",
        "subject_id": "device-1",
        "report_type": "device-compliance",
    }
    audit_rows = client.get("/admin/reports", headers=BEARER)
    assert audit_rows.status_code == 200
    device_audit_row = next(row for row in audit_rows.json() if row["subject_scope"] == "device")
    assert device_audit_row["tenant_id"] == ""
    assert device_audit_row["subject_id"] == "device-1"


def test_reports_config_shows_only_tenant_definitions(client, monkeypatch):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at) VALUES (?,?,?,?)",
            ("client-1847", "Acme", "c940504e-2d0f-57c6-8770-9c9981e51c81", datetime.now(timezone.utc).isoformat()),
        )
    monkeypatch.setattr(
        dashboard.http, "get", lambda *args, **kwargs: Response(payload=catalogue(entry(), entry("device-compliance", "device"))),
    )
    response = client.get("/admin/tenants/c940504e-2d0f-57c6-8770-9c9981e51c81/reports-config", headers=BEARER)

    assert response.status_code == 200
    assert [row["type"] for row in response.json()] == ["executive-summary"]


def test_catalogue_outage_marks_report_tick_degraded(monkeypatch):
    now = datetime.now(timezone.utc)
    statuses = []

    def unavailable():
        raise dashboard.ReportCatalogueUnavailable("platform report catalogue returned 503")

    monkeypatch.setattr(dashboard, "_report_catalogue", unavailable)
    monkeypatch.setattr(
        dashboard,
        "_record_check_status",
        lambda name, status, reason, observed_at: statuses.append((name, status, reason, observed_at)),
    )

    dashboard._run_tick("report-tick", lambda: dashboard._run_report_tick(now), now)

    assert statuses == [
        ("tick_report_tick", "degraded", "platform catalogue unavailable: platform report catalogue returned 503", now)
    ]


def test_catalogue_outage_leaves_due_subscription_for_next_hourly_retry(client, monkeypatch):
    now = datetime.now(timezone.utc)
    tenant_id = "tenant-retry"
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, primary_contact_email, created_at) VALUES (?,?,?,?,?)",
            ("client-retry", "Retry Co", tenant_id, "reports@example.test", now.isoformat()),
        )
        db.execute(
            "INSERT INTO report_subscriptions (tenant_id, report_type, enabled, frequency) VALUES (?,?,?,?)",
            (tenant_id, "executive-summary", 1, "monthly"),
        )

    def unavailable():
        raise dashboard.ReportCatalogueUnavailable("platform report catalogue returned 503")

    monkeypatch.setattr(dashboard, "_report_catalogue", unavailable)
    assert dashboard._run_report_tick(now) == "platform catalogue unavailable: platform report catalogue returned 503"
    with dashboard.get_db() as db:
        assert db.execute(
            "SELECT last_sent_at FROM report_subscriptions WHERE tenant_id=? AND report_type=?",
            (tenant_id, "executive-summary"),
        ).fetchone()["last_sent_at"] is None

    monkeypatch.setattr(dashboard, "_report_catalogue", lambda: (entry(),))
    monkeypatch.setattr(dashboard.http, "get", lambda *args, **kwargs: Response(content=b"%PDF-1.7"))
    monkeypatch.setattr(dashboard, "_send_email", lambda *args, **kwargs: True)
    monkeypatch.setattr(dashboard, "email_delivery_status", lambda: "configured")
    dashboard._run_report_tick(now + timedelta(hours=1))

    with dashboard.get_db() as db:
        sent_at = db.execute(
            "SELECT last_sent_at FROM report_subscriptions WHERE tenant_id=? AND report_type=?",
            (tenant_id, "executive-summary"),
        ).fetchone()["last_sent_at"]
        delivery = db.execute(
            "SELECT subject_scope, subject_id, status FROM report_deliveries WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
    assert sent_at is not None
    assert dict(delivery) == {"subject_scope": "tenant", "subject_id": tenant_id, "status": "sent"}
