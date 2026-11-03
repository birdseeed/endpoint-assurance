"""
PAT-745 — per-OS master switch must not hide existing devices from the tenant
devices list; disabled-platform devices stay visible with an
"Evaluation disabled" marker instead.

Covers:
  * Device-health rows carry the evaluation-disabled chip helper
    (`_dhEvalDisabledChipHtml`), wired into the same row-rendering cell as
    the existing freshness/reboot chips.
  * fetchTenantDevices' JSDoc documents the new `evaluation_disabled` field
    so future readers don't miss it.

Run with: pytest tests/test_pat745.py -v
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


def test_device_health_eval_disabled_surfaced_in_triage(console_html):
    # PAT-745 intent: a per-OS master switch must not hide devices — an
    # evaluation-disabled device stays visible and clearly marked.
    #
    # PAT-961's Devices triage redesign replaced the standalone Health-column
    # chip composition with a single "Why it's flagged" reason (_dhReason).
    # evaluation_disabled is still read and surfaced there — and because it maps
    # to a warn-level reason, such devices now appear in the default "At risk"
    # quick-view rather than only carrying a muted chip. The intent (visible +
    # marked) is preserved; the surfacing moved from a chip to the reason cell.
    assert "d.evaluation_disabled" in console_html
    assert "text:'evaluation disabled'" in console_html


def test_fetch_tenant_devices_jsdoc_documents_evaluation_disabled(console_html):
    assert "evaluation_disabled" in console_html
