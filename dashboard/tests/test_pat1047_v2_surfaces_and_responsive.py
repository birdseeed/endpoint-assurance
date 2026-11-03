"""PAT-1047 v2 — full surface reachability, navigation mapping, identity/RBAC
contract survival, and responsive no-horizontal-tab-stack behaviour.

Complements test_pat955_expanded_sidebar.py (global-rail/context-nav
structure) and test_pat1047_console_rewrite.py (shell regression coverage)
with an exhaustive walk of every surface named in
docs/design/pat-1047/SURFACE_INVENTORY.md, so a destination silently dropped
during the v2 rewrite fails a test even if no other file happens to name it.
"""

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
THEME_CSS = (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")
CONSOLE_CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


# ── All active global surfaces reachable ────────────────────────────────────

GLOBAL_SURFACES = [
    ("home", "consoleNav('home')"),
    ("customers-list", "consoleNav('customers-list')"),
    ("ops", "consoleNav('ops')"),                 # Service Health · Infrastructure
    ("automations", "consoleNav('automations')"), # Service Health · Automations
    ("truth", "consoleNav('truth')"),
    ("credentials", "consoleNav('credentials')"), # Admin Tools · Credentials
    ("docs", "consoleNav('docs')"),               # Admin Tools · Docs
    ("homebrew-review", "consoleNav('homebrew-review')"),
    ("software-identities", "consoleNav('software-identities')"),  # Intelligence (PAT-2404)
    ("software-alerts", "consoleNav('software-alerts')"),
    ("logs", "consoleNav('logs')"),               # Admin Tools · Logs
    ("reports", "consoleNav('reports')"),         # Admin Tools · Reports
]


@pytest.mark.parametrize("section, onclick", GLOBAL_SURFACES)
def test_global_surface_has_a_working_nav_entry_point(section, onclick):
    assert 'id="section-%s"' % section in HTML
    assert onclick in HTML


def test_all_twelve_active_global_surfaces_covered():
    assert len(GLOBAL_SURFACES) == 12


# ── All active tenant data-tab surfaces reachable via the customer workflow nav ──

TENANT_SURFACES = {
    "overview": "priorities",
    "device-health": "devices",
    "disposition-queue": "devices",
    "device-lifecycle": "devices",
    "software-catalogue": "software-governance",
    "browser-extensions": "software-governance",
    "protected-software": "software-governance",
    "removal-campaigns": "software-governance",
    "compliance-status": "assurance",
    "cis-controls": "assurance",
    "cve-findings": "assurance",
    "reports": "evidence",
    "evidence-issued": "evidence",
    "software-metering": "evidence",
    "shadow-it": "evidence",
    "account": "customer-setup",
    "customer-access": "customer-setup",
    "deploy-agent": "customer-setup",
    "webhooks": "customer-setup",
}


def test_all_nineteen_active_tenant_surfaces_covered():
    assert len(TENANT_SURFACES) == 19


@pytest.mark.parametrize("tab", sorted(TENANT_SURFACES))
def test_tenant_data_tab_panel_exists(tab):
    assert 'id="tab-%s"' % tab in HTML


def test_tenant_data_tabs_present_in_the_tenant_tabs_js_array():
    start = HTML.index("const _TENANT_TABS = [")
    end = HTML.index("];", start)
    arr = HTML[start:end]
    for tab in TENANT_SURFACES:
        assert "'%s'" % tab in arr


def test_workload_map_assigns_every_tenant_tab_to_its_documented_group():
    # _WORKLOAD_TABS is the single navigation-mapping source of truth for the
    # customer workflow nav — cross-check it against SURFACE_INVENTORY.md's
    # documented group assignment for all 19 tabs, not just the ones each
    # group's own test happens to name.
    start = HTML.index("const _WORKLOAD_TABS = {")
    end = HTML.index("\n};", start)
    obj_src = HTML[start:end]
    groups = dict(re.findall(r"'([a-z-]+)':\s*\[([^\]]*)\]", obj_src))
    parsed = {
        group: [t.strip().strip("'") for t in tabs.split(",") if t.strip()]
        for group, tabs in groups.items()
    }
    tab_to_group = {}
    for group, tabs in parsed.items():
        for t in tabs:
            tab_to_group[t] = group

    assert tab_to_group == TENANT_SURFACES, (
        "customer workflow group assignment drifted from SURFACE_INVENTORY.md:\n"
        "  expected: %r\n  actual:   %r" % (TENANT_SURFACES, tab_to_group)
    )


def test_stale_governance_links_retain_policy_and_legacy_deployment_uses_evidence():
    tenant = HTML[HTML.index("function enterTenant("):HTML.index("function tenantTab(")]
    switch = HTML[HTML.index("function tenantTab("):HTML.index("function _applyTenantTab(")]
    tabs = HTML[HTML.index("const _TENANT_TABS = ["):HTML.index("];", HTML.index("const _TENANT_TABS = ["))]
    assert "'patch-deploy'" not in tabs
    assert "'software-catalogue'" in tabs
    assert "PatchedConsoleGovernance.canonicalTenantTab(tab, tenant)" in tenant
    assert "PatchedConsoleGovernance.canonicalTenantTab(tab, _consoleState.tenantData)" in switch
    assert "const _QUARANTINED_SECTIONS = ['catalogue']" in HTML


# ── Device workspace: all 7 destinations reachable ──────────────────────────

DEVICE_SURFACES = ["overview", "inventory", "hardware", "software", "patching", "compliance", "activity"]


@pytest.mark.parametrize("ddtab", DEVICE_SURFACES)
def test_device_destination_panel_and_nav_button_exist(ddtab):
    assert 'id="ddtab-%s"' % ddtab in HTML
    assert 'data-ddtab="%s"' % ddtab in HTML
    assert "onclick=\"_ddTab('%s');return false;\"" % ddtab in HTML


def test_all_seven_device_destinations_covered():
    assert len(DEVICE_SURFACES) == 7


# ── Identity / RBAC contract survives the shell rewrite ────────────────────

def test_owner_only_gate_markup_survives_in_new_shell(client):
    r = client.get("/console")
    assert r.status_code == 200
    body = r.text
    # Logs is owner-only and now lives in the context navigator, not the old
    # single rail — the gating class and JS mechanism must be unchanged.
    ctx_start = body.index('<nav class="context-nav" id="context-nav"')
    ctx_end = body.index("</nav>", body.rindex('id="nav-section-customer"'))
    ctx = body[ctx_start:ctx_end]
    assert 'id="nav-logs" class="owner-only"' in ctx
    assert "function _applyRoleGate()" in body
    assert "document.body.classList.toggle('role-consultant', _isConsultant());" in body
    # Device revoke/delete stay owner-only and guarded in the new device
    # workspace exactly as before.
    assert 'id="dd-revoke-btn" class="owner-only"' in body
    assert 'id="dd-delete-btn" class="owner-only btn-del"' in body


def test_role_and_identity_render_exactly_once(client):
    r = client.get("/console")
    body = r.text
    # PAT-1047 v2 removes the dead hidden sidebar-identity duplicate — role
    # chip markup must render exactly once (the topbar identity menu).
    assert body.count("si-role-chip si-role-") == 1
    assert 'id="sidebar-identity"' not in body


# ── Responsive: no horizontal tab stack survives at any width ──────────────

def test_no_horizontal_workload_or_device_tab_bar_remains():
    # Structural rule (REDESIGN_V2.md): "Do not recreate a left rail plus
    # horizontal page tabs plus horizontal sub-tabs."
    assert 'class="tab-bar"' not in HTML
    assert 'id="workload-tabbar"' not in HTML
    assert 'id="tenant-workload-nav"' not in HTML
    assert re.search(r'class="tab-bar\b', HTML) is None


def test_customer_workflow_and_device_nav_are_vertical_not_horizontal():
    assert 'class="cwf-nav"' in HTML
    assert "flex-direction: column" in THEME_CSS  # .cwf-nav
    assert 'class="ddw-nav"' in HTML
    assert ".ddw-nav {" in THEME_CSS


def test_global_and_context_nav_both_become_drawers_at_phone_width():
    assert "@media (max-width: 900px)" in THEME_CSS
    narrow_start = THEME_CSS.index("@media (max-width: 900px)")
    narrow_block = THEME_CSS[narrow_start:THEME_CSS.index("@media", narrow_start + 1)]
    assert ".global-rail, .context-nav {" in narrow_block
    assert "body.nav-open .global-rail, body.nav-open .context-nav { transform: translateX(0); }" in narrow_block


def test_customers_use_full_width_table_and_device_workspace_stacks_at_narrow_widths():
    assert 'id="cl-content" class="cl-content"' in HTML
    assert 'id="cl-inspector"' not in HTML
    assert ".cl-table-shell { width: 100%; }" in CONSOLE_CSS
    assert ".device-workspace { flex-direction: column; }" in CONSOLE_CSS
    assert ".ddw-nav { flex-direction: row" in CONSOLE_CSS


def test_work_list_detail_and_signals_are_keyboard_operable():
    assert "function _bindSelectableRows(tbody, onSelect)" in HTML
    assert "e.key === 'Enter' || e.key === ' '" in HTML
    assert "e.key !== 'ArrowDown' && e.key !== 'ArrowUp'" in HTML
    assert '<button type="button" class="signal-row"' in HTML
    assert 'role="button" tabindex="0">' not in HTML
