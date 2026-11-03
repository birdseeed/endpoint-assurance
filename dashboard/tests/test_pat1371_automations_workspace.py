"""PAT-1371 automation workspace contracts: honest triggers and compact UI."""
import os
import time
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

from fastapi.testclient import TestClient
import main as dashboard

BEARER = {"Authorization": "Bearer test-key"}


def test_unsupported_automation_trigger_never_contacts_upstream():
    with TestClient(dashboard.app) as client, patch.object(dashboard.http, "post") as upstream:
        response = client.post("/admin/automations/mirror_pipeline/trigger", headers=BEARER)
    assert response.status_code == 404
    assert upstream.call_count == 0


def test_legacy_trigger_is_quarantined_before_confirmation_or_proxying():
    with TestClient(dashboard.app) as client, patch.object(dashboard.http, "post") as upstream:
        response = client.post("/admin/automations/installomator_sync/trigger", headers=BEARER)
    assert response.status_code == 410
    assert response.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert upstream.call_count == 0


def test_confirmed_owner_trigger_remains_quarantined_before_upstream_operation():
    upstream_response = SimpleNamespace(status_code=200, content=b'{"status":"success"}', json=lambda: {"status": "success"})
    with TestClient(dashboard.app) as client, patch.object(dashboard.http, "post", return_value=upstream_response) as upstream:
        response = client.post("/admin/automations/installomator_sync/trigger", headers={**BEARER, "X-Confirm-Resource": "installomator_sync"})
    assert response.status_code == 410
    assert response.json() == dashboard._LEGACY_EXECUTION_QUARANTINE_BODY
    assert upstream.call_count == 0


def test_consultant_cannot_trigger_quarantined_automation_or_contact_upstream(monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    token = dashboard._session_encode("consultant@patched.im", int(time.time()) + 600)
    with TestClient(dashboard.app) as client, patch.object(dashboard.http, "post") as upstream:
        client.cookies.set(dashboard.SESSION_COOKIE, token)
        response = client.post("/admin/automations/installomator_sync/trigger", headers={"X-Confirm-Resource": "installomator_sync"})
    assert response.status_code == 403
    assert upstream.call_count == 0


def test_automations_page_uses_single_evidence_table_and_race_guard():
    page = open("templates/console.html", encoding="utf-8").read()
    css = open("static/css/console.css", encoding="utf-8").read()
    assert 'id="auto-tbody"' in page
    assert 'PatchedConsoleAutomations.summarize' in page
    assert "var _autoRunsRequest = 0" in page
    assert "if (requestId !== _autoRunsRequest) return;" in page
    assert "encodeURIComponent(jobName)" in page
    assert "_esc(detail)" in page
    assert "_esc(j.job_name || '')" in page
    assert "PatchedConsoleAutomations.safeRunStatus(r.status)" in page
    assert "<caption>Automation evidence, including quarantined legacy job history" in page
    assert "<span>Scheduled</span>" in page
    assert "No run evidence" in page
    assert "a.lifecycleLabel" in page
    assert "Not scheduled:" in page
    assert "Every nullh" not in page
    assert "function _autoTrigger" not in page
    assert "auto-trigger" not in page
    assert ".auto-badge-quarantined,.auto-badge-retired" in css
    assert ".auto-quarantined strong,.auto-retired strong" in css
    assert "auto-cards" not in page


def test_legacy_trigger_remains_declared_for_quarantine_and_history_reads():
    source = open("main.py", encoding="utf-8").read()
    assert 'job_name != "installomator_sync"' in source
    assert 'r"^/admin/automations/installomator_sync/trigger$"' in source
    assert '"POST",  r"^/admin/automations/installomator_sync/trigger$"' in source
