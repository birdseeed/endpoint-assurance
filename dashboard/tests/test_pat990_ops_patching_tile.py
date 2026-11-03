"""
PAT-990: surface the PAT-989 maintenance-drift facts (patch/reboot/timer
drift across prod-01/api-01/portal-01) on the Ops panel's new "Patching"
tile, via a new `maintenance` key on `GET /api/ops/data`.

This is a local, cheap read of the check_statuses rows the PAT-989
scheduler tick (_run_maintenance_drift_check_tick) already records --
/api/ops/data must never re-fetch the boxes' facts live, same convention
as versions.dashboard reporting _ops_dashboard_version() rather than
re-deriving it per request.

Covers:
  * all three maintenance_* rows present -> reported in a fixed, readable
    order (prod-01, api-01, portal-01), each with box/state/reason/
    evaluated_at passed straight through from check_statuses.
  * a missing row (scheduler tick hasn't run since deploy) -> reported as
    that box's own entry with state "unconfigured", never silently
    dropped from the array -- the empty-vs-never-evaluated distinction
    this whole initiative exists to preserve.
  * state/reason/evaluated_at pass through unmodified for both ok and
    degraded rows.

Run with: pytest tests/test_pat990_ops_patching_tile.py -v
"""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BEARER = {"Authorization": "Bearer test-key"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()

    # Isolate this test from every other data source api_ops_data() pulls
    # from -- none of it is under test here, and letting it hit real
    # network (PATCHED_API_INTERNAL, TLS cert probes) would make the test
    # slow and flaky. Fail fast and locally instead.
    def _no_network(url, timeout=None, verify=None):
        raise ConnectionError("network disabled in test")

    monkeypatch.setattr(dashboard.http, "get", _no_network)
    monkeypatch.setattr(dashboard, "_ops_cert_expiry", lambda hostname, port=443: None)
    monkeypatch.setattr(dashboard, "_ops_get_systemctl_prop", lambda unit, *props: {})

    with TestClient(dashboard.app) as value:
        yield value


def _maintenance(client):
    response = client.get("/api/ops/data", headers=BEARER)
    assert response.status_code == 200
    body = response.json()
    assert "maintenance" in body
    return body["maintenance"]


def test_all_three_rows_present_ordered_and_labeled(client):
    now = datetime.now(timezone.utc)
    dashboard._record_check_status(
        "maintenance_prod01", "ok", "confirmed healthy as of " + now.isoformat(), now,
    )
    dashboard._record_check_status(
        "maintenance_api01", "degraded", "security update pending: 3 packages", now,
    )
    dashboard._record_check_status(
        "maintenance_portal01", "unconfigured", "app.patched.im/healthz: unreachable", now,
    )

    maint = _maintenance(client)

    assert len(maint) == 3
    assert [m["box"] for m in maint] == ["prod-01", "api-01", "portal-01"]

    by_box = {m["box"]: m for m in maint}
    assert by_box["prod-01"]["state"] == "ok"
    assert by_box["prod-01"]["reason"] == "confirmed healthy as of " + now.isoformat()
    assert by_box["prod-01"]["evaluated_at"] is not None

    assert by_box["api-01"]["state"] == "degraded"
    assert by_box["api-01"]["reason"] == "security update pending: 3 packages"

    assert by_box["portal-01"]["state"] == "unconfigured"
    assert by_box["portal-01"]["reason"] == "app.patched.im/healthz: unreachable"


def test_missing_row_reported_as_unconfigured_not_omitted(client):
    now = datetime.now(timezone.utc)
    # Only seed two of the three -- maintenance_api01 is deliberately never
    # recorded, simulating a fresh deploy the scheduler tick hasn't ticked
    # since yet.
    dashboard._record_check_status("maintenance_prod01", "ok", "confirmed healthy", now)
    dashboard._record_check_status("maintenance_portal01", "ok", "confirmed healthy", now)

    maint = _maintenance(client)

    assert len(maint) == 3
    by_box = {m["box"]: m for m in maint}
    assert by_box["prod-01"]["state"] == "ok"
    assert by_box["portal-01"]["state"] == "ok"

    missing = by_box["api-01"]
    assert missing["state"] == "unconfigured"
    assert missing["evaluated_at"] is None
    assert missing["reason"]  # non-empty, names the gap
    assert "maintenance_api01" in missing["reason"]


def test_no_rows_at_all_reports_all_three_unconfigured(client):
    maint = _maintenance(client)

    assert len(maint) == 3
    assert [m["box"] for m in maint] == ["prod-01", "api-01", "portal-01"]
    for m in maint:
        assert m["state"] == "unconfigured"
        assert m["evaluated_at"] is None
        assert m["reason"]
