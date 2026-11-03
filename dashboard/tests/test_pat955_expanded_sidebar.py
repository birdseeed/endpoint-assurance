"""PAT-955/PAT-1047 v2: global rail + context navigator structure.

PAT-1047 v2 (docs/design/pat-1047/REDESIGN_V2.md) replaces the old
always-all-visible single rail (#sidebar-app-nav, PAT-955's original subject)
with a readable global rail (Service overview/Tenants/Operations/Intelligence) plus
a 280px context navigator whose content changes with the selected
destination or customer (_applyContextNav() in console.html). Only applicable
context-nav groups are shown at a time — the material change from both the old
rail and from PAT-1047 v1's horizontal workload tab bar + secondary sub-tab
bars, which are also retired by this ticket.
"""

import re as _re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _html():
    return (ROOT / "templates" / "console.html").read_text(encoding="utf-8")


def test_global_rail_has_exactly_four_destinations():
    html = _html()
    start = html.index('<nav class="global-rail" id="global-rail"')
    end = html.index("</nav>", start)
    rail = html[start:end]

    for grail_id, label in (
        ("grail-work", "Service overview"),
        ("grail-customers", "Tenants"),
        ("grail-operations", "Operations"),
        ("grail-intelligence", "Intelligence"),
    ):
        assert 'id="%s"' % grail_id in rail
        assert label in rail
    assert rail.count('class="grail-item') == 4


def test_context_nav_groups_are_conditionally_shown_not_always_expanded():
    """The defining change from PAT-955: no group is always visible — exactly
    the applicable Operations groups or tenant/Intelligence group are active."""
    html = _html()
    start = html.index('<nav class="context-nav" id="context-nav"')
    end = html.index("</nav>", html.rindex('id="nav-section-customer"'))
    nav = html[start:]

    assert '<div class="nav-section" id="nav-section-ops">' in nav
    assert '<div class="nav-section" id="nav-section-admin">' in nav
    assert '<div class="nav-section ctxnav-customer" id="nav-section-customer">' in nav
    assert '<div class="nav-section-label"><span class="icon" data-icon="settings"></span> Service Health</div>' in nav
    assert '<div class="nav-section-label"><span class="icon" data-icon="lock"></span> Admin Tools</div>' in nav

    assert 'id="nav-section-intelligence"' in nav
    assert 'id="nav-homebrew-review"' in nav
    assert "var inIntelligence = section === 'homebrew-review' || section === 'software-identities';" in html
    assert "classList.toggle('active', inIntelligence)" in html
    assert "!(inOps || inAdmin || inCustomer || inIntelligence)" in html
    assert "function _applyContextNav(section)" in html
    assert "opsGroup.classList.toggle('active', inOps || inAdmin);" in html
    assert "adminGroup.classList.toggle('active', inOps || inAdmin);" in html
    assert "custGroup.classList.toggle('active', inCustomer);" in html
    assert ".context-nav .nav-section { display: none; }" in (ROOT / "static" / "css" / "theme.css").read_text(encoding="utf-8")


def test_global_rail_is_persistent_not_swapped():
    """The old sidebar-swap (#sidebar-app-nav hidden in tenant context, a
    separate #sidebar-tenant-nav shown instead) is gone. There is exactly one
    global rail and one context navigator, always visible (context navigator
    collapses to zero width, it is not removed/hidden-for-tenant)."""
    html = _html()
    assert '<nav id="sidebar-tenant-nav"' not in html
    assert 'id="sidebar-app-nav"' not in html
    assert "document.getElementById('global-rail').style.display" not in html
    assert "Swap sidebar between app nav and tenant nav" not in html


def test_customer_workflow_nav_replaces_horizontal_workload_bar():
    html = _html()
    assert 'id="workload-tabbar"' not in html
    assert 'id="tenant-workload-nav"' not in html

    start = html.index('<nav class="cwf-nav" id="cwf-nav"')
    end = html.index("\n        </nav>", start)
    nav = html[start:end]

    for workload, label in (
        ("priorities", "Priorities"),
        ("devices", "Devices"),
            ("software-governance", "Software governance"),
        ("assurance", "Assurance"),
        ("evidence", "Evidence"),
        ("customer-setup", "Customer setup"),
    ):
        assert 'data-workload="%s"' % workload in nav
        assert "onclick=\"tenantWorkload('%s');return false;\"" % workload in nav
        assert label in nav

    # Sub-tab bars are static markup (not JS-generated) — every data-tab
    # value stays directly present in the page source. PAT-1609 gave Devices
    # its own sub-nav once it grew a second destination (disposition-queue).
    for bar_id in ("subtabbar-devices", "subtabbar-software-governance", "subtabbar-evidence", "subtabbar-customer-setup"):
        assert 'id="%s"' % bar_id in nav


def test_cwf_nav_active_state_targets_new_structure():
    html = _html()
    assert "document.querySelectorAll('#cwf-nav .cwf-group-btn')" in html
    assert "document.querySelectorAll('#cwf-nav .tnav-link')" in html


def test_customer_switcher_moved_to_topbar_not_removed():
    """The tenant-only switcher lives in the always-visible top-bar customer
    selector — it must still exist, just not inside a tenant-only sidebar."""
    html = _html()
    assert 'id="tw-switcher"' in html
    topbar_start = html.index('<div class="topbar-customer" id="topbar-customer">')
    topbar_end = html.index("</div>", topbar_start)
    assert 'id="tw-switcher"' in html[topbar_start:topbar_end]


def test_tenant_identity_block_not_duplicated_outside_tenant_head():
    html = _html()
    start = html.index('<nav class="cwf-nav" id="cwf-nav"')
    end = html.index("\n        </nav>", start)
    nav = html[start:end]

    assert 'class="sidebar-tenant-id"' not in nav
    assert 'id="stn-name"' not in nav
    assert 'id="stn-tier"' not in nav
    assert 'id="stn-fleet"' not in nav

    # The tenant header remains the one place the canonical fields render;
    # the context-nav customer identity block (ctxnav-cust-*) is a genuine
    # second, functionally distinct location (persists while scrolling the
    # workflow nav), not a hidden test-compat duplicate — see
    # test_pat1047_console_rewrite.py's hidden-duplicate-identity assertion.
    assert "document.getElementById('ctx-client-name')" in html
    assert "document.getElementById('ctx-client-tier')" in html
    assert "document.getElementById('ctx-client-fleet')" in html


# ── PAT-1009/PAT-1047 v2 review: enforce the full destination contract ─────
# The substring assertions above check only that each expected data-tab is
# present somewhere — dropping or renaming a destination, duplicating one, or
# pairing a data-tab with another tab's handler would all pass silently
# without this stricter, exhaustive check.


def _cwf_nav_region():
    html = _html()
    start = html.index('<nav class="cwf-nav" id="cwf-nav"')
    end = html.index("\n        </nav>", start)
    return html[start:end]


EXPECTED_TENANT_DESTINATIONS = {
    "overview", "device-health", "disposition-queue", "device-lifecycle", "compliance-status",
    "account", "customer-access", "deploy-agent",
    "browser-extensions", "software-catalogue", "protected-software", "removal-campaigns", "webhooks",
    "reports", "evidence-issued", "software-metering", "shadow-it",
}


def test_every_tenant_destination_is_present_exactly_once():
    nav = _cwf_nav_region()
    tabs = _re.findall(r'data-tab="([a-z-]+)"', nav)
    assert len(tabs) == len(set(tabs)), "duplicate data-tab in the customer workflow nav: %r" % (
        sorted({t for t in tabs if tabs.count(t) > 1}),)
    assert set(tabs) == EXPECTED_TENANT_DESTINATIONS, (
        "customer workflow nav destinations drifted.\n  missing: %r\n  unexpected: %r"
        % (sorted(EXPECTED_TENANT_DESTINATIONS - set(tabs)),
           sorted(set(tabs) - EXPECTED_TENANT_DESTINATIONS)))


def test_each_data_tab_matches_its_own_click_handler():
    """A data-tab paired with another tab's tenantTab()/tenantWorkload()
    argument routes the user somewhere other than where the highlight says
    they are."""
    nav = _cwf_nav_region()
    pairs = _re.findall(
        r'data-tab="([a-z-]+)"[^>]*?onclick="tenant(?:Tab|Workload)\(\'([a-z-]+)\'',
        nav,
    )
    assert pairs, "no data-tab/tenantTab pairs parsed — the markup shape changed"
    # tenantWorkload(workload) routes via the workload map, not a direct 1:1
    # tab argument — everything else must match exactly.
    mismatched = [
        (tab, arg) for tab, arg in pairs
        if arg not in (tab, "priorities", "devices", "software-governance", "assurance", "evidence", "customer-setup")
    ]
    assert not mismatched, "data-tab does not match its click handler argument: %r" % (mismatched,)


def test_workload_tabs_js_map_matches_new_group_taxonomy():
    html = _html()
    assert "'priorities':     ['overview']" in html
    assert "'devices':        ['device-health', 'disposition-queue', 'device-lifecycle']" in html
    assert "'software-governance': ['software-catalogue', 'browser-extensions', 'protected-software', 'removal-campaigns']" in html
    assert "'assurance':      ['compliance-status', 'cis-controls', 'cve-findings']" in html
    assert "'evidence':       ['reports', 'evidence-issued', 'software-metering', 'shadow-it']" in html
    assert "'customer-setup': ['account', 'customer-access', 'deploy-agent', 'webhooks']" in html
