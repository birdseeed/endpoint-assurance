"""Regression coverage for PAT-1160's truthful customer Updates workflow."""

import json
from pathlib import Path
import subprocess

import main as dashboard


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
CSS = (ROOT / "static" / "css" / "console.css").read_text()


def _function(name: str) -> str:
    start = HTML.index(f"function {name}(")
    brace = HTML.index("{", start)
    depth = 0
    for index in range(brace, len(HTML)):
        if HTML[index] == "{":
            depth += 1
        elif HTML[index] == "}":
            depth -= 1
            if depth == 0:
                return HTML[start:index + 1]
    raise AssertionError(f"unbalanced function {name}")


def _node_json(source: str, expression: str):
    result = subprocess.run(
        ["node", "-e", f"{source}\nconsole.log(JSON.stringify({expression}));"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def _node_json_async(source: str, expression: str):
    result = subprocess.run(
        ["node", "-e", source + "\n(async function(){\n" + expression + "\n})()"
         ".then(value => console.log(JSON.stringify(value)))"
         ".catch(error => { console.error(error); process.exit(1); });"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def _workspace() -> str:
    start = HTML.index('data-retired-surface="patch-deploy"')
    end = HTML.index('</template>', start)
    return HTML[start:end]


def test_updates_workspace_is_not_a_customer_destination():
    nav = HTML[HTML.index('id="cwf-nav"'):HTML.index('</nav>', HTML.index('id="cwf-nav"'))]
    assert 'data-tab="patch-deploy"' not in nav
    tabs = HTML[HTML.index("const _TENANT_TABS = ["):HTML.index("];", HTML.index("const _TENANT_TABS = ["))]
    assert "'patch-deploy'" not in tabs
    assert "PatchedConsoleGovernance.canonicalTenantTab(tab, _consoleState.tenantData)" in _function("tenantTab")


def test_updates_table_fits_the_desktop_content_column():
    assert ".pd-table { width: 100%; min-width: 0;" in CSS
    assert "table-layout: fixed" in CSS
    assert ".pd-table th:nth-child(7) { width: 12%; }" in CSS
    assert ".pd-table .vs-bar { display: none; }" in CSS
    assert "@media (max-width: 732px)" in CSS
    assert ".pd-table { min-width: 720px; }" in CSS
    assert ".pd-table { min-width: 840px" not in CSS
    assert "update_available:'Update'" in _function("_pdStateChip")


def test_missing_optional_evidence_never_becomes_confirmed_update():
    fn = _function("_pdEvidenceState")
    fixtures = [
        {"evidence_state": "update_available", "update_available": True},
        {"evidence_state": "current", "update_available": False},
        {"evidence_state": "not_catalogued"},
        {"evidence_state": "evidence_unavailable"},
        {"update_available": True},
        {"update_available": False},
        {},
    ]
    result = _node_json(fn, f"{json.dumps(fixtures)}.map(_pdEvidenceState)")
    assert result == [
        "update_available", "current", "not_catalogued", "evidence_unavailable",
        "evidence_unavailable", "evidence_unavailable", "evidence_unavailable",
    ]


def test_truthful_state_guard_kills_boolean_fallback_mutant():
    fn = _function("_pdEvidenceState")
    mutant = fn.replace(
        "return 'evidence_unavailable';",
        "return a.update_available ? 'update_available' : 'current';",
    )
    assert mutant != fn
    real = _node_json(fn, "_pdEvidenceState({update_available:true})")
    mutated = _node_json(mutant, "_pdEvidenceState({update_available:true})")
    assert real == "evidence_unavailable"
    assert mutated == "update_available"


def test_updates_summary_filters_search_and_counts_are_truthful():
    workspace = _workspace()
    for element_id in (
        "pd-update-count", "pd-current-count", "pd-unavailable-count", "pd-total-count",
        "pd-filter-updates", "pd-filter-current", "pd-filter-unavailable", "pd-filter-all",
        "pd-search", "pd-visible-count",
    ):
        assert f'id="{element_id}"' in workspace
    render = _function("_pdRender")
    assert "_pdEvidenceGroup(a)" in render
    assert "if (_pdFilter !== 'all'" in render
    assert "if (!_pdSearch) return true" in render
    assert "devices.map(function(d)" in render
    assert "visible.length + ' shown'" in render


def test_update_table_exposes_evidence_contract_without_a_rollout_action():
    workspace = _workspace()
    updates = workspace[workspace.index('id="pd-panel-updates"'):workspace.index('id="pd-panel-rollouts"')]
    for heading in ("Application", "Installed", "Verified target", "Affected devices", "Policy", "State"):
        assert f">{heading}<" in updates
    # PAT-2249: the "Start rollout" action matched updates against the retired
    # catalogue review model and called a create route PAT-2246 had already
    # removed from the platform, so the column and its prompt are gone.
    assert ">Action<" not in updates
    render = _function("_pdRender")
    for field in ("platform", "version_spread", "target_version", "catalog_label", "updates_enabled"):
        assert f"a.{field}" in render
    assert "_pdDeviceNamesHtml(a)" in render
    assert "_pdStateChip(a)" in render
    assert "_pdRolloutActionHtml" not in HTML
    assert "_pdRolloutPromptFromButton" not in HTML


def test_all_affected_device_names_are_accessibly_retained():
    affected = _function("_pdAffectedDevices")
    names = _function("_pdDeviceNamesHtml")
    assert "Array.isArray(a.devices)" in affected
    assert "d.update_state" in affected
    assert "names.length <= 3" in names
    assert '<details class="pd-device-disclosure">' in names
    assert "names.map(function(name)" in names
    assert "<li>" in names


def test_rollouts_only_show_real_cards_and_have_explicit_empty_state():
    workspace = _workspace()
    rollouts = workspace[workspace.index('id="pd-panel-rollouts"'):workspace.index('id="pd-panel-policy"')]
    assert 'id="pdr-rollouts-list"' in rollouts
    assert 'id="pdr-rollouts-empty"' in rollouts
    assert "No active rollouts" in rollouts
    render = _function("_pdrRenderRollouts")
    assert "rollouts.length === 0" in render
    assert "empty.style.display = ''" in render
    assert "pdr-rollout-card" in render


def test_three_configured_bands_map_to_internal_canary_and_agent_ga():
    bands = _node_json(_function("_pdrBands"), "_pdrBands(3)")
    assert bands == [
        {"label": "Internal", "agent_ring": 0},
        {"label": "Canary", "agent_ring": 1},
        {"label": "GA", "agent_ring": 3},
    ]
    summary = _function("_pdrRenderBandSummary")
    assert "cfg.percentages || [10,30,60]" in summary
    assert "d.effective_ring" in summary
    assert "deviceCount" in summary
    assert "pdr-band-card" in summary
    rendered = _node_json(
        "var output={innerHTML:''}; var document={getElementById:()=>output};\n"
        + _function("_pdrBands") + "\n" + summary,
        "(() => { _pdrRenderBandSummary("
        "{ring_count:3,percentages:[10,30,60]},"
        "[{effective_ring:0},{effective_ring:1},{effective_ring:3},{computed_ring:3}]"
        "); return output.innerHTML; })()",
    )
    assert "Internal" in rendered and "10%" in rendered and "1 device" in rendered
    assert "Canary" in rendered and "30%" in rendered
    assert "GA" in rendered and "60%" in rendered and "2 devices" in rendered


def test_all_selectable_band_counts_follow_agent_ring_contract():
    bands_fn = _function("_pdrBands")
    assert _node_json(bands_fn, "_pdrBands(2)") == [
        {"label": "Internal", "agent_ring": 0},
        {"label": "GA", "agent_ring": 3},
    ]
    assert [band["agent_ring"] for band in _node_json(bands_fn, "_pdrBands(4)")] == [0, 1, 2, 3]
    five = _node_json(bands_fn, "_pdrBands(5)")
    assert [band["agent_ring"] for band in five] == [0, 1, 2, 2, 3]
    assert five[2]["shared_assignment"] is True
    assert five[3]["shared_assignment"] is True


def test_five_band_summary_does_not_double_count_shared_ring_devices():
    summary = _function("_pdrRenderBandSummary")
    rendered = _node_json(
        "var output={innerHTML:''}; var document={getElementById:()=>output};\n"
        + _function("_pdrBands") + "\n" + summary,
        "(() => { _pdrRenderBandSummary("
        "{ring_count:5,percentages:[5,10,20,25,40]},"
        "[{effective_ring:2},{effective_ring:2}]"
        "); return output.innerHTML; })()",
    )
    assert rendered.count("Shared device assignment") == 2
    assert "2 devices" not in rendered
    assert "agent ring 4" not in rendered


def test_policy_contains_assignments_and_preserves_guarded_writes():
    workspace = _workspace()
    policy_start = workspace.index('id="pd-panel-policy"')
    activity_start = workspace.index('id="pd-panel-activity"')
    policy = workspace[policy_start:activity_start]
    assert 'id="pdr-band-summary"' in policy
    assert 'id="pdr-devices-section"' in policy
    assert "Device assignments" in policy
    assert '<details class="pdr-advanced">' in policy
    assert "Advanced safety thresholds" in policy
    save = _function("_pdrSave")
    override = _function("_pdrSetOverride")
    rollout = _function("_pdrRolloutAction")
    assert "dangerConfirm" in save
    assert "dangerConfirm" in override
    assert "method: 'PUT'" in save and "method: 'PUT'" in override
    assert "method: 'POST'" in rollout


def test_activity_is_direct_provenance_with_explicit_agent_empty_state():
    workspace = _workspace()
    activity = workspace[workspace.index('id="pd-panel-activity"'):]
    assert "Agent-reported activity" in activity
    assert 'id="pd-prov-content"' in activity
    assert "pd-prov-toggle" not in activity
    assert "pdr-devices-section" not in activity
    load = _function("_pdLoadProvenance")
    assert "No agent-reported activity for this tenant yet" in load
    assert "data.records || []" in load


def test_provenance_uses_updates_generation_not_ring_loader_order():
    load = _function("_pdLoadProvenance")
    source = r"""
var elements = {
  'pd-prov-loading': {style:{}},
  'pd-prov-error': {style:{}, textContent:''},
  'pd-prov-content': {innerHTML:''}
};
var document = {getElementById:function(id){return elements[id];}};
var _consoleState = {tenantId:'tenant-a'};
var _pdLoadEpoch = 1;
var _pdProvenanceRecords = null;
var _pdrRolloutsLast = [{id:'rollout'}];
var rolloutRenders = [];
var pending = {};
function adminFetch(url) {
  return new Promise(function(resolve, reject) { pending[url] = {resolve:resolve,reject:reject}; });
}
function _pdrRenderRollouts(_rollouts, records) { rolloutRenders.push(records.map(function(r){return r.hostname;})); }
function _escHtml(value) { return String(value == null ? '' : value); }
function _fmtTs(value) { return String(value || ''); }
""" + load
    result = _node_json_async(source, r"""
_pdLoadProvenance('tenant-a', 1);
pending['/admin/tenants/tenant-a/provenance'].resolve({records:[{
  hostname:'mac-a', action:'installed', app:'Chrome', version:'140', received_at:'now'
}]});
await new Promise(function(resolve){setImmediate(resolve);});
var normal = {
  records:_pdProvenanceRecords.map(function(r){return r.hostname;}),
  loading:elements['pd-prov-loading'].style.display,
  rendered:elements['pd-prov-content'].innerHTML.indexOf('mac-a') !== -1,
  rolloutRenders:rolloutRenders.slice()
};

_pdLoadEpoch = 2;
_consoleState.tenantId = 'tenant-a';
_pdLoadProvenance('tenant-a', 2);
var staleA = pending['/admin/tenants/tenant-a/provenance'];
_pdLoadEpoch = 3;
_consoleState.tenantId = 'tenant-b';
_pdLoadProvenance('tenant-b', 3);
pending['/admin/tenants/tenant-b/provenance'].resolve({records:[{
  hostname:'mac-b', action:'installed', app:'Chrome', version:'140', received_at:'now'
}]});
await new Promise(function(resolve){setImmediate(resolve);});
staleA.resolve({records:[{hostname:'stale-a', action:'failed', app:'Chrome', version:'140'}]});
await new Promise(function(resolve){setImmediate(resolve);});
return {
  normal:normal,
  currentRecords:_pdProvenanceRecords.map(function(r){return r.hostname;}),
  stalePainted:elements['pd-prov-content'].innerHTML.indexOf('stale-a') !== -1,
  currentPainted:elements['pd-prov-content'].innerHTML.indexOf('mac-b') !== -1,
  finalRolloutRender:rolloutRenders[rolloutRenders.length - 1]
};
""")
    assert result == {
        "normal": {
            "records": ["mac-a"],
            "loading": "none",
            "rendered": True,
            "rolloutRenders": [["mac-a"]],
        },
        "currentRecords": ["mac-b"],
        "stalePainted": False,
        "currentPainted": True,
        "finalRolloutRender": ["mac-b"],
    }


def test_updates_surface_is_compact_responsive_and_build_is_bumped():
    for selector in (
        "#tab-patch-deploy", ".pd-summary", ".pd-controls", ".pd-table-wrap",
        ".pdr-band-summary", ".pdr-advanced", ".pd-activity-body",
    ):
        assert selector in CSS
    assert "overflow-x: auto" in CSS
    assert "@media (max-width: 732px)" in CSS
    assert "@media (max-width: 430px)" in CSS
    assert dashboard.CONSOLE_BUILD_ID == "2026-10-04-pat2404"
