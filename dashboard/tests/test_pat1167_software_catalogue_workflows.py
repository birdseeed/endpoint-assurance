"""PAT-1481: tenant software governance retains policy-only workflows."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def test_three_first_class_views_and_review_is_default():
    catalogue = HTML[HTML.index('id="tab-software-catalogue"') : HTML.index('<!-- /#tab-software-catalogue -->')]
    assert 'class="sc-view-tab active" id="sc-view-review"' in HTML
    assert "Needs review" in HTML
    assert 'id="sc-view-installed"' in HTML
    assert 'id="sc-view-available"' not in catalogue
    assert 'id="sc-view-drift"' in HTML
    # PAT-2249: the PAT-1548 read-only Execution policies sub-view was removed
    # with the tenant execution-policy store it read.
    assert 'id="sc-view-execution"' not in HTML
    assert 'id="sc-panel-execution"' not in HTML
    assert "var _scView            = 'review'" in HTML
    assert "['review', 'installed', 'drift']" in HTML
    assert 'aria-pressed="true"' in HTML
    assert 'role="tablist"' not in catalogue


def test_each_view_renders_only_its_own_row_source():
    render = HTML[HTML.index("function _scRenderTable()") : HTML.index("function _scUpdateViewCounts")]
    assert "if (_scView === 'review')" in render
    assert "else if (_scView === 'installed')" in render
    assert "if (_scView === 'drift')" in render
    assert "unresolvedInstalled.forEach" in render


def test_filters_are_contextual_and_suggestion_is_folded_into_status():
    assert 'id="sc-status-filter"' in HTML
    assert "function _scStatusOptions()" in HTML
    assert "Suggested approve" in HTML
    assert "Suggested defer" in HTML
    assert "suggested.style.display = 'none'" in HTML


def test_policy_view_is_explicitly_non_actuating():
    assert "Policy only, not endpoint execution." in HTML
    # PAT-2299: the execution path is retired, not waiting on a new catalogue.
    assert "The software execution path is retired. Patched records policy only." in HTML
    assert "macOS execution policy is not yet available" not in HTML
    catalogue = HTML[HTML.index('id="tab-software-catalogue"') : HTML.index('<!-- /#tab-software-catalogue -->')]
    assert "Require on estate</label>" not in catalogue
    assert "Uninstall from estate" not in catalogue


def test_policy_drift_is_first_class_and_not_collapsed():
    drift = HTML[HTML.index('id="drift-panel"') : HTML.index('<!-- /#tab-software-catalogue -->')]
    assert 'class="apo-header"' in drift
    assert 'id="drift-body"' in drift
    assert 'style="display:none;"' not in drift.split('id="drift-body"', 1)[1][:80]
    assert "Required app missing" in HTML
    assert "required missing" in HTML


def test_dense_installed_rows_retain_policy_actions_without_execution_controls():
    row = HTML[HTML.index("function _scInstalledManage") : HTML.index("function _scCatalogueManage")]
    assert "Set policy" in HTML
    assert "Mark unapproved" in row
    assert "_scInstalledAppPolicyClick" in row
    assert "Uninstall from estate" not in row


def test_catalogue_policy_actions_normalise_both_to_api_any_platform():
    policy_click = HTML[HTML.index("function _scCatPolicyClick") : HTML.index("function _scCatMandatoryToggle")]
    mandatory_toggle = HTML[HTML.index("function _scCatMandatoryToggle") : HTML.index("// ── Allowlist staging")]
    expected = "PatchedConsoleGovernance.policyPlatform"

    assert expected in policy_click
    assert expected in mandatory_toggle


def test_platform_policy_staging_uses_exact_mutation_and_preserves_identity():
    staging = HTML[HTML.index("function _scStageAppPolicy") : HTML.index("function _scInstalledAppPolicyClick")]
    save = HTML[HTML.index("function _scSave()") : HTML.index("function _scDiscard()")]

    assert "PatchedConsoleGovernance.policyMutation" in HTML
    assert "existingId: plan.exact ? plan.exact.id : null" in staging
    assert "identity: plan.identity" in staging
    assert "Object.assign({}, e.identity" in save
    assert "'/app-policies/' + e.existingId" in save


def test_catalogue_views_fit_and_have_visible_keyboard_focus():
    assert ".sc-view-tabs" in CSS
    assert "grid-template-columns: repeat(4" in CSS
    assert ".sc-view-tab:focus-visible" in CSS
    assert '#as-table[data-view="installed"] th:first-child' in CSS


def test_tenant_change_resets_drift_and_ignores_stale_response():
    load = HTML[HTML.index("function _scLoad()") : HTML.index("function _apoLoadPolicies")]
    drift = HTML[HTML.index("function _driftLoad") : HTML.index("function _driftTypeBadge")]
    assert "_scDriftCount      = 0" in load
    assert "if (tid !== _consoleState.tenantId) return;" in drift
    assert "_scDriftCount = 0" in drift


def test_deferred_apps_do_not_match_unreviewed_filter():
    new_filter = HTML[HTML.index("function _scPassNewAppFilter") : HTML.index("function _scInstalledRow")]
    assert "_asActiveStatus === 'unreviewed' && a.decision === 'defer'" in new_filter


def test_details_dialog_escape_and_focus_restoration():
    assert 'onkeydown="_scDetailsKeydown(event)"' in HTML
    details = HTML[HTML.index("function _scDetailsOpen") : HTML.index("function _scNewAppRow")]
    assert "_scDetailsOpener = btn" in details
    assert "event.key === 'Escape'" in details
    assert "event.key !== 'Tab'" in details
    assert "_scDetailsOpener.focus()" in details
