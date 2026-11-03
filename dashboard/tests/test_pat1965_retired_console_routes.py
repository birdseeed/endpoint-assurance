"""PAT-1965 keeps retired console screens from deleting their API contracts."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402


def test_retired_console_surface_routes_remain_registered():
    routes = {route.path for route in dashboard.app.routes}

    # The UI may retire these workflows, but integrations and historical
    # operator tooling still depend on their backend contracts.
    for route in {
        "/admin/tenants/{tenant_id}/service-engagement",
        "/admin/tenants/{tenant_id}/apps",
        "/admin/tenants/{tenant_id}/app-control",
        "/admin/tenants/{tenant_id}/enforcement-audit",
        "/admin/tenants/{tenant_id}/runbook-notes",
        "/admin/billing/summary",
        "/admin/billing/renewals",
        "/api/leads",
        "/admin/tenants/{tenant_id}/protected-software",
        "/admin/tenants/{tenant_id}/removal-campaigns",
    }:
        assert route in routes

    # PAT-2249 went further for the catalogue: its console screen was already
    # retired here, and its backend routes are now removed too.
    assert "/admin/catalogue" not in routes
