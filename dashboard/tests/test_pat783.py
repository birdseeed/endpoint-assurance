"""PAT-783/PAT-167: New Apps triage is folded into Software Catalogue."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


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


def _extract_fn(text, name):
    start = text.index("function " + name + "(")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError("unbalanced braces for " + name)


def test_new_apps_no_longer_have_first_class_tenant_tab(console_html):
    # PAT-1047 v2: the tenant nav is no longer a horizontal workload tab bar
    # — it's the vertical customer workflow nav (#cwf-nav) in the context
    # navigator. "new-apps" must not appear as a data-tab destination there.
    nav_start = console_html.index('id="cwf-nav"')
    nav_end = console_html.index("\n        </nav>", nav_start)
    tenant_nav = console_html[nav_start:nav_end]

    assert 'data-tab="new-apps"' not in tenant_nav
    assert 'id="tab-new-apps"' not in console_html
    assert "'new-apps'" not in console_html[
        console_html.index("const _TENANT_TABS"): console_html.index("const _NAV_MAP")
    ]
    assert "PatchedConsoleGovernance.canonicalTenantTab(tab, _consoleState.tenantData)" in console_html


def test_console_redirects_to_build_rev(client):
    r = client.get("/console", follow_redirects=False)
    assert r.status_code in (301, 302, 307, 308)
    assert r.headers["location"] == "/console/" + dashboard.CONSOLE_BUILD_ID


def test_theme_js_redirects_stale_console_path():
    theme_path = os.path.join(os.path.dirname(__file__), "..", "static", "js", "theme.js")
    with open(theme_path, encoding="utf-8") as f:
        theme_js = f.read()

    # theme.js no longer keeps its own copy of CONSOLE_BUILD_ID. Holding a
    # second copy in lock-step by hand failed twice (PAT-966, and again on
    # 2026-07-25): when main.py was bumped and theme.js was not, the server
    # redirected /console to the new build id while theme.js redirected back
    # to the stale one — an infinite loop that flashes, worst on mobile.
    # It now derives the id from its own ?v= query, which console.html renders
    # from main.py, so the two cannot drift. See tests/test_console_build_id.py.
    assert "redirectConsoleIfStale" in theme_js
    assert "consoleBuildId" in theme_js
    assert "window.location.replace('/console/' + buildId" in theme_js
    assert "CONSOLE_BUILD_ID = '" not in theme_js


def test_new_apps_are_loaded_into_software_catalogue(console_html):
    load_fn = _extract_fn(console_html, "_scLoad")
    load_new_fn = _extract_fn(console_html, "_scLoadNewApps")
    render_fn = _extract_fn(console_html, "_scRenderTable")

    assert "_scLoadNewApps(tid).then(function() { _scRenderTable(); });" in load_fn
    assert "/new-apps?status=all" in load_new_fn
    assert "newAppRequestState(tid, ++_scNewAppsGeneration)" in load_new_fn
    assert "canApplyNewAppResponse(_scNewAppsRequest, request, _consoleState.tenantId)" in load_new_fn
    assert "_scNewAppsFetch = PatchedConsoleGovernance.newAppFetchState(tid, 'ready')" in load_new_fn
    assert "tenantId: String(tid)" in load_new_fn
    assert "return !a.decision || a.decision === 'defer';" in load_new_fn
    assert "rows.push({ name: a.name || '', kind: 'new_app', data: a });" in render_fn
    assert "if (newAppIdentities[_scPolicyKey(a.name, a.platform)]) return;" in render_fn


def test_cached_inventory_retries_discarded_new_apps_response(console_html):
    activate_fn = _extract_fn(console_html, "_scActivate")
    assert "needsNewAppReload(_scNewAppsFetch, tid)" in activate_fn
    assert "_scLoadNewApps(tid).then(function() { _scRenderTable(); });" in activate_fn


def test_catalogue_new_app_sort_control_covers_pat783_fields(console_html):
    filter_start = console_html.index('<div class="as-filter-row">')
    filter_end = console_html.index("<!-- Unified inventory + catalogue table -->", filter_start)
    filter_html = console_html[filter_start:filter_end]

    assert 'id="sc-sort-select"' in filter_html
    assert 'onchange="_scSetSort(this.value)"' in filter_html
    assert 'onclick="_scToggleSortDir()"' in filter_html
    for value in ("name", "platform", "identity", "publisher", "first_seen", "devices", "suggested"):
        assert f'<option value="{value}">' in filter_html


def test_catalogue_sort_uses_typed_new_app_values(console_html):
    sort_value_fn = _extract_fn(console_html, "_scRowSortValue")
    sort_rows_fn = _extract_fn(console_html, "_scSortRows")
    suggested_rank_fn = _extract_fn(console_html, "_scSuggestedRank")
    set_sort_fn = _extract_fn(console_html, "_scSetSort")
    update_control_fn = _extract_fn(console_html, "_scUpdateSortControl")

    assert "d.app_identity" in sort_value_fn
    assert "d.publisher_signature" in sort_value_fn
    assert "Date.parse(d.first_seen || '') || 0" in sort_value_fn
    assert "d.host_count || 0" in sort_value_fn
    assert "_scSuggestedRank(d.suggested_action)" in sort_value_fn
    assert "Array.isArray(av) && Array.isArray(bv)" in sort_rows_fn
    assert "Number(av) - Number(bv)" in sort_rows_fn
    for action in ("approve", "approve_no_patch", "defer", "remove"):
        assert action in suggested_rank_fn
    assert "_scSortCol === 'first_seen' ? false : true" in set_sort_fn
    assert "Newest" in update_control_fn
    assert "9-0" in update_control_fn


def test_catalogue_has_new_app_filter_badges_and_actions(console_html):
    assert "data-status=\"new_apps\"" in console_html
    assert "_scPassNewAppFilter" in console_html
    assert "_scNewAppRow" in console_html
    assert "_scNewAppManage" in console_html
    assert "new_pending" in console_html
    assert "new_deferred" in console_html

    actions_fn = _extract_fn(console_html, "_scNewAppManage")
    for decision in ("Approve", "Mark unapproved", "Defer"):
        assert decision in actions_fn
    assert "_scNewAppApproveClick" in actions_fn
    assert "_scNewAppUnapproveClick" in actions_fn
    # PAT-797: single-row Defer now routes through a confirmation dialog
    # (_scNewAppDeferClick) rather than calling _napDecide inline.
    assert "_scNewAppDeferClick" in actions_fn
    assert "Remove" not in actions_fn
    assert "Review" in actions_fn

    assert "Uninstall from estate" not in actions_fn
    assert "Approve, no patch" not in actions_fn


def test_new_app_review_records_policy_without_execution(console_html):
    policy_helper_fn = _extract_fn(console_html, "_scSetAppPolicy")
    approve_fn = _extract_fn(console_html, "_scNewAppApproveClick")
    unapprove_fn = _extract_fn(console_html, "_scNewAppUnapproveClick")

    assert "/app-policies" in policy_helper_fn
    assert "PatchedConsoleGovernance.policyUpsertPayload(plan, policy)" in policy_helper_fn
    assert "app_management" not in policy_helper_fn
    assert "policyAuthorised: true" in approve_fn
    assert "policyAuthorised: true" in unapprove_fn

    assert "_scSetAppPolicy(tid, {" in approve_fn
    assert "app_identity: btn.getAttribute('data-app-identity')" in approve_fn
    assert "}, 'approved')" in approve_fn
    assert "_napDecide(tid, id, 'approve', { policyAuthorised: true })" in approve_fn

    assert "_scSetAppPolicy(tid, {" in unapprove_fn
    assert "app_identity: btn.getAttribute('data-app-identity')" in unapprove_fn
    assert "}, 'unapproved')" in unapprove_fn
    assert "_napDecide(tid, id, 'unapprove', { rethrow: true, policyAuthorised: true })" in unapprove_fn

    bulk_fn = _extract_fn(console_html, "_scBulkActionApp")
    assert bulk_fn.count("policyAuthorised: true") == 2
    assert "does not block, remove or install software" in unapprove_fn
    assert "_scSetAllowlistEnforcement" not in approve_fn


def test_decision_refreshes_catalogue_and_preserves_backend_api(console_html):
    decide_fn = _extract_fn(console_html, "_napDecide")

    assert "/new-apps/' + encodeURIComponent(id)" in decide_fn
    assert "PatchedConsoleGovernance.newAppDecision(decision)" in decide_fn
    assert "JSON.stringify({ decision: upstreamDecision" in decide_fn
    assert "_consoleState.activeTab === 'software-catalogue'" in decide_fn
    assert "_scReload();" in decide_fn


def test_new_app_visual_treatment_css_present():
    css_path = os.path.join(os.path.dirname(__file__), "..", "static", "css", "console.css")
    with open(css_path, encoding="utf-8") as f:
        css = f.read()

    assert ".sc-new-app-row td:first-child" in css
    assert ".as-badge.st-new-pending" in css
    assert ".as-badge.st-new-deferred" in css
    assert ".sc-new-app-row td:first-child" in css
    assert ".sc-manage-btn.primary" in css
    assert ".sc-action-menu" in css
    assert ".as-sort-ctrl" in css


def test_catalogue_actions_column_stays_in_table_flow():
    css_path = os.path.join(os.path.dirname(__file__), "..", "static", "css", "console.css")
    with open(css_path, encoding="utf-8") as f:
        css = f.read()

    actions_rule_start = css.index("#as-table th:last-child")
    actions_rule_end = css.index("}", actions_rule_start)
    actions_rule = css[actions_rule_start:actions_rule_end]

    assert "position: sticky" not in actions_rule
    assert "box-shadow" not in actions_rule
    assert "min-width: 0" in actions_rule
    assert "table-layout: fixed" in css
    assert "min-width: 1180px" not in css
    assert ".as-col-actions" in css
    # PAT-797: a select-column was added for bulk triage, narrowing the app
    # column from 34% to 31% so the row still totals 100%.
    assert "#as-table .as-col-select  { width: 3%; }" in css
    assert "#as-table .as-col-app     { width: 31%; }" in css
    assert "#as-table .as-col-policy  { width: 20%; }" in css
    assert ".as-action-row" not in css


def test_catalogue_policy_is_read_only_with_manage_menu(console_html):
    css_path = os.path.join(os.path.dirname(__file__), "..", "static", "css", "console.css")
    with open(css_path, encoding="utf-8") as f:
        css = f.read()

    header_start = console_html.index('<table id="as-table" class="rdx-table rdx-table--compact">')
    header_end = console_html.index("</thead>", header_start)
    table_head = console_html[header_start:header_end]
    assert "<th>Removal</th>" not in table_head
    assert "<th>Policy</th>" in table_head
    assert "<th>Actions</th>" in table_head

    assert "_scPolicySegment" not in console_html
    assert "_scCatPolicySegment" not in console_html
    assert "_scPolicyPill" in console_html
    assert "_scInstalledManage" in console_html
    assert "_scCatalogueManage" in console_html
    assert "_scNewAppManage" in console_html
    assert "sc-menu-check" in console_html
    assert "data-policy=\"approved\"" in console_html
    assert "data-policy=\"unapproved\"" in console_html
    assert "data-policy=\"uninstall\"" not in console_html
    assert "Uninstall policy" not in console_html
    assert "data-policy=\"unmanaged\"" in console_html
    policy_actions = _extract_fn(console_html, "_scInstalledManage")
    assert "Require on estate" not in policy_actions
    assert "Uninstall from estate" not in policy_actions
    assert ".sc-menu-check" in css
    assert ".sc-action-menu" in css
    assert "#as-table .as-col-os      { width: 9%; }" in css
    assert "#as-table .as-col-status  { width: 16%; }" in css
