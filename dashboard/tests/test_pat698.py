"""
PAT-698 — cross-tenant triage Home, surfaced telemetry panels, and cleanup.

Covers:
  * build_triage_queue() ranks/sorts cross-tenant signals critical→info and folds
    in every signal source (unit test of the pure server-side helper).
  * /api/home/triage degrades gracefully (upstream unreachable → empty, no error).
  * PAT-956 supersedes the global item queue with tenant-level attention.
  * Device-detail ships the patch-outcome / provenance container.
  * Customers list ships the agent-version-drift container.
  * Device-health rows carry the pending-reboot chip helper.
  * Cleanup: dashboard.html gone; CVE mock scaffolding gone; stub metrics not
    surfaced.

Run with: pytest tests/test_pat698.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


@pytest.fixture
def console_html(client):
    r = client.get("/console")
    assert r.status_code == 200
    return r.text


# ── build_triage_queue: ranking + source coverage ────────────────────────────

def _sample():
    tenants = [
        {"id": "t1", "name": "Alpha", "device_count": 20, "active_last_7d": 5,
         "crit_high_fail_count": 7, "new_apps_awaiting_decision": 2, "compliance_pct": 60},
        {"id": "t2", "name": "Beta", "device_count": 4, "active_last_7d": 3,
         "crit_high_fail_count": 0, "new_apps_awaiting_decision": 0, "compliance_pct": 95},
    ]
    health = {"service_health": {
        "cert_expiry": [
            {"name": "api.x", "days_left": 5, "tenant_id": "t1"},
            {"name": "old", "days_left": 40},   # >30d → excluded
        ],
        "ingestion_freshness": {"stalest_tenant": {
            "tenant_id": "t2", "tenant_name": "Beta", "hours_stale": 60}},
    }}
    na = {"t1": {"items": [
        {"category": "blocked", "app_name": "Zoom", "device_name": "Mac1",
         "failure_reason": "signer_mismatch"}],
        "summary": {"blocked": 1}}}
    freshness = {"active_max_days": 7, "silent_min_days": 30}
    return tenants, health, na, freshness


def test_triage_sorted_critical_first():
    q = dashboard.build_triage_queue(*_sample())
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    sevs = [order[i["severity"]] for i in q]
    assert sevs == sorted(sevs)
    assert q[0]["severity"] == "critical"


def test_triage_folds_every_source():
    q = dashboard.build_triage_queue(*_sample())
    kinds = {i["kind"] for i in q}
    for expected in ("silent_devices", "blocked_patch", "cert_expiry",
                     "ingestion_lag", "cis_findings", "apps_review"):
        assert expected in kinds, (expected, kinds)


def test_triage_apps_review_targets_software_policy():
    q = dashboard.build_triage_queue(*_sample())
    apps_review = [i for i in q if i["kind"] == "apps_review"]
    assert apps_review and apps_review[0]["tab"] == "software-catalogue"


def test_triage_blocked_patch_carries_failure_reason():
    q = dashboard.build_triage_queue(*_sample())
    blocked = [i for i in q if i["kind"] == "blocked_patch"]
    assert blocked and "signer_mismatch" in blocked[0]["detail"]
    assert blocked[0]["tab"] == "needs-attention"


def test_triage_expired_cert_excluded_beyond_30d():
    q = dashboard.build_triage_queue(*_sample())
    certs = [i for i in q if i["kind"] == "cert_expiry"]
    assert len(certs) == 1  # only the 5-day cert, not the 40-day one
    assert certs[0]["severity"] == "critical"


def test_triage_rows_have_drill_targets():
    q = dashboard.build_triage_queue(*_sample())
    for i in q:
        assert "tenant_name" in i and "tab" in i and "title" in i


def test_triage_stub_metrics_never_surfaced():
    # reports_generated / catalogue_job are stubs upstream — they must never
    # appear as triage items even if present in the health payload.
    tenants, health, na, freshness = _sample()
    health["service_health"]["reports_generated"] = 0
    health["service_health"]["catalogue_job"] = {"status": "stub"}
    q = dashboard.build_triage_queue(tenants, health, na, freshness)
    blob = repr(q)
    assert "reports_generated" not in blob
    assert "catalogue_job" not in blob


def test_triage_empty_inputs_yield_empty_queue():
    assert dashboard.build_triage_queue([], {}, {}, None) == []


# ── /api/home/triage: graceful degradation ───────────────────────────────────

@pytest.mark.usefixtures("network_down")
def test_home_triage_endpoint_degrades_gracefully(client):
    # Every upstream fails (the network_down fixture makes the platform API
    # unreachable); the endpoint must still return 200 with an empty queue and
    # all-false sources.
    r = client.get("/api/home/triage",
                   headers={"Authorization": "Bearer test-key"})
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["sources"] == {"tenants": False, "health": False,
                               "needs_attention": False, "agent_health": False}


# ── Home: PAT-956 tenant-level triage ────────────────────────────────────────

def test_home_global_item_queue_removed(console_html):
    assert 'id="home-triage"' not in console_html
    assert 'id="home-triage-content"' not in console_html
    assert "Action Queue" not in console_html
    assert "_loadHomeTriage" not in console_html


def test_home_tenant_attention_leads_operations(console_html):
    assert console_html.index('id="home-service-exceptions"') < console_html.index('id="home-health-rows"')
    assert "Service exceptions" in console_html
    assert 'id="service-exceptions-heading"' in console_html
    assert "_triageDrill" in console_html


# ── Surfaced telemetry panels ────────────────────────────────────────────────

def test_device_detail_patch_outcome_container(console_html):
    assert 'id="dd-patch-outcomes-section"' in console_html
    assert 'id="dd-patch-outcomes-table"' in console_html
    assert 'id="dd-patch-outcomes-empty"' in console_html
    assert "_ddRenderPatchOutcomes" in console_html
    # provenance columns
    for col in ("Outcome", "Detail"):
        assert col in console_html


def test_agent_drift_container_on_customers_list(console_html):
    assert 'id="cl-agent-drift"' in console_html
    assert "_loadAgentDrift" in console_html
    assert "Agent Version Drift" in console_html


def test_device_health_reboot_chip_helper(console_html):
    assert "_dhRebootPending" in console_html
    assert "_dhRebootChipHtml" in console_html
    assert "Reboot pending" in console_html


# ── Cleanup assertions ───────────────────────────────────────────────────────

def test_dashboard_html_removed():
    path = os.path.join(os.path.dirname(__file__), "..", "templates", "dashboard.html")
    assert not os.path.exists(path)


def test_cve_mock_scaffolding_removed(console_html):
    assert "CVE_FINDINGS_USE_MOCK" not in console_html
    assert "_cveMockList" not in console_html
    assert "_cveMockDevices" not in console_html
    assert 'id="cve-mock-banner"' not in console_html
    # live CVE path intact
    assert "fetchTenantCveFindings" in console_html
    assert "_cveActivate" in console_html
