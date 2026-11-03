from pathlib import Path

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def test_shadow_it_uses_truthful_compact_workspace():
    assert "Evidence and policy, not endpoint action." in TEMPLATE
    assert "Needs review" in TEMPLATE
    assert "Exceptions" in TEMPLATE
    assert "Search applications or machines" in TEMPLATE
    for column in ("Application", "Why flagged", "Category", "Machines", "Last observed", "Policy", "Action"):
        assert f"<th>{column}</th>" in TEMPLATE
    assert "No shadow IT apps detected on this tenant." not in TEMPLATE
    assert "_sitTenantRender" not in TEMPLATE


def test_shadow_it_loads_both_policy_and_catalogue_evidence():
    assert "'/admin/tenants/' + tenantId + '/app-policy-drift'" in TEMPLATE
    assert "'/admin/tenants/' + tenantId + '/app-policies'" in TEMPLATE
    assert "'/admin/shadow-it/findings/' + tenantId" in TEMPLATE
    assert "PatchedConsoleShadowIT.merge" in TEMPLATE
    assert "policy only and does not change the application on endpoints" in TEMPLATE


def test_shadow_it_interactions_are_in_browser_loaded_helper():
    assert 'console-shadow-it.js?v={{ console_build_id }}' in TEMPLATE
    assert (ROOT / "static" / "js" / "console-shadow-it.js").exists()
    assert (ROOT / "tests" / "js" / "console-shadow-it.test.js").exists()


def test_shadow_it_review_action_targets_the_policy_decision_workspace():
    row = TEMPLATE[TEMPLATE.index("function _sitRowHtml"):TEMPLATE.index("function _sitDetailHtml")]
    assert "tenantTab(\\'software-catalogue\\')" in row
    assert "tenantTab(\\'app-control\\')" not in row


def test_shadow_it_density_and_build_advance():
    # PAT-1615: header/cell chrome (including the 7px cell padding) now comes
    # from the shared .rdx-table (PAT-1601), applied to #sit-table in the
    # markup, rather than a dedicated #sit-table td rule.
    assert 'id="sit-table" class="rdx-table"' in TEMPLATE
    assert "#sit-table { width:100%; min-width:760px;" in CSS
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
