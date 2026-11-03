"""PAT-1170 browser-extension workflow and capability-truthfulness tests."""

import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()


def _last_function(name: str) -> str:
    start = HTML.rindex(f"function {name}(")
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
        ["node", "-e", f"{source}\nPromise.resolve({expression}).then(value => console.log(JSON.stringify(value)));"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_console_has_four_distinct_extension_views_and_review_default():
    with TestClient(dashboard.app) as client:
        html = client.get("/console").text
    for view in ("review", "inventory", "restricted", "removals"):
        assert f'data-bx-view="{view}"' in html
    assert "var _bxView = 'review'" in html
    assert "Elevated access" in html
    assert "High Risk" not in html
    assert ">Unapprove<" not in html


def test_console_is_truthful_when_extension_control_is_disabled():
    with TestClient(dashboard.app) as client:
        html = client.get("/console").text
    assert 'id="bx-control-banner"' in html
    assert "Policy decisions are recorded, but are not enforced" in html
    assert "only after every captured endpoint profile reports removal evidence" in html
    assert "_bxControlEnabled()" in html


def test_removal_state_logic_executes_and_never_infers_completion():
    source = "var _consoleState={tenantData:{app_control_enabled:false}};" + _last_function("_bxControlEnabled") + _last_function("_bxRemovalState")
    jobs = [{}, {"fulfilled": True}, {"cancelled_at": "now"}, {"state": "queued"}]
    result = _node_json(source, f"{json.dumps(jobs)}.map(_bxRemovalState)")
    assert result == ["blocked", "completed", "cancelled", "queued"]


def test_real_tenant_capability_blocks_and_allows_removal_modal():
    source = """
var _consoleState={tenantData:{app_control_enabled:false}};
var _bxSorted=[{id:'ext-1',name:'Example',browser:'chrome'}];
var _bxRemoveTarget=null, _bxModalReturnFocus=null;
var elements={};
function element(id) { return elements[id] || (elements[id]={style:{display:'none'},value:'',textContent:'',disabled:false,focus:function(){}}); }
var document={activeElement:null,getElementById:element,getElementsByName:function(){return [];},querySelector:function(){return {focus:function(){}};}};
""" + _last_function("_bxControlEnabled") + _last_function("_bxRemoveOpen")
    result = _node_json(
        source,
        "(()=>{_bxRemoveOpen(0);var blocked={target:_bxRemoveTarget,display:element('modal-bx-remove').style.display};"
        "_consoleState.tenantData.app_control_enabled=true;_bxRemoveOpen(0);"
        "return {blocked:blocked,allowed:{target:_bxRemoveTarget.id,display:element('modal-bx-remove').style.display}};})()",
    )
    assert result == {
        "blocked": {"target": None, "display": "none"},
        "allowed": {"target": "ext-1", "display": "flex"},
    }


def _policy_submit_result(entry, target="unapproved", reject=None):
    source = """
var calls=[];
var _consoleState={tenantId:'fd46eac4-17e8-51ae-bb80-aba4a343c3ac'};
var _bxPolicyTarget=ENTRY;
var _bxNotesByEntry={17:'review note'};
var elements={
  'bx-detail':{style:{display:''}},
  'bx-policy-error':{style:{display:'none'},textContent:''}
};
var buttons=[{disabled:false},{disabled:false}];
var document={
  getElementById:function(id){return elements[id] || (elements[id]={style:{display:'none'},textContent:''});},
  querySelectorAll:function(){return buttons;}
};
var closed=0, detailClosed=0, loads=[];
function _bxPolicyClose(){closed++;}
function _bxCloseDetail(){detailClosed++; elements['bx-detail'].style.display='none';}
function _bxLoad(tid){loads.push(tid);}
function adminErrorText(err){return err.message || String(err);}
function adminFetch(url,opts){calls.push({url:url,opts:opts}); return REJECTION;}
""".replace("ENTRY", json.dumps(entry)).replace(
        "REJECTION",
        f"Promise.reject({json.dumps(reject)})" if reject else "Promise.resolve({})",
    ) + _last_function("_bxPolicySubmit")
    expression = (
        f"(async()=>{{_bxPolicySubmit({json.dumps(target)},buttons[0]);await new Promise(r=>setTimeout(r,0));"
        "return {calls:calls,closed:closed,detailClosed:detailClosed,loads:loads,"
        "disabled:buttons.map(b=>b.disabled),error:elements['bx-policy-error']};})()"
    )
    return _node_json_async(source, expression)


def test_policy_create_executes_expected_endpoint_payload_and_refresh():
    result = _policy_submit_result({"id": "ext/one", "name": "Example", "browser": "chrome"}, "approved")
    assert result["calls"] == [{
        "url": "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/extension-policies",
        "opts": {
            "method": "POST",
            "body": json.dumps({
                "browser": "chrome", "extension_id": "ext/one",
                "name": "Example", "policy": "approved",
            }, separators=(",", ":")),
        },
    }]
    assert result["closed"] == 1
    assert result["detailClosed"] == 1
    assert result["loads"] == ["fd46eac4-17e8-51ae-bb80-aba4a343c3ac"]
    assert result["disabled"] == [False, False]


def test_policy_update_executes_expected_endpoint_payload_and_surfaces_failure():
    result = _policy_submit_result(
        {"id": "ext-one", "name": "Example", "browser": "edge", "_entryId": 17},
        "ignored",
        {"status": 500, "message": "upstream failed"},
    )
    assert result["calls"] == [{
        "url": "/admin/tenants/fd46eac4-17e8-51ae-bb80-aba4a343c3ac/extension-policies/17",
        "opts": {
            "method": "PUT",
            "body": json.dumps({"policy": "ignored", "notes": "review note"}, separators=(",", ":")),
        },
    }]
    assert result["closed"] == 0
    assert result["detailClosed"] == 0
    assert result["loads"] == []
    assert result["disabled"] == [False, False]
    assert result["error"]["style"]["display"] == ""
    assert result["error"]["textContent"] == "Failed to save decision: upstream failed"


def test_policy_update_conflict_closes_and_reloads_current_state():
    result = _policy_submit_result(
        {"id": "ext-one", "_entryId": 17},
        "unapproved",
        {"status": 409, "message": "conflict"},
    )
    assert result["closed"] == 1
    assert result["loads"] == ["fd46eac4-17e8-51ae-bb80-aba4a343c3ac"]
    assert result["error"]["style"]["display"] == "none"


def test_removal_load_failure_is_visible_and_cross_tenant_failure_is_ignored():
    load = _last_function("_bxLoad")
    render = _last_function("_bxRenderRemovals")
    assert "_bxRemovalsError = res[2].error" in load
    assert "seq !== _bxReqSeq" in load
    assert "Removal jobs could not be loaded" in render


def test_removal_history_query_is_forwarded():
    upstream = MagicMock()
    upstream.status_code = 200
    upstream.content = b'{"requests":[]}'
    upstream.json.return_value = {"requests": []}
    upstream.text = '{"requests":[]}'
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return upstream

    with TestClient(dashboard.app) as client, patch.object(dashboard.http, "get", side_effect=fake_get):
        response = client.get(
            "/admin/tenants/a5effb0c-c4c3-5d57-af50-5c7fd102599e/extension-removals?include_history=true",
            headers={"Authorization": "Bearer test-key"},
        )
    assert response.status_code == 200
    assert captured["params"] == {"include_history": "true"}


def test_extension_table_is_compact_and_scope_copy_is_estate_accurate():
    with TestClient(dashboard.app) as client:
        html = client.get("/console").text
    inventory_table = html[html.index('id="bx-table"'):html.index('id="bx-detail"')]
    assert "<th>Version</th>" not in inventory_table
    assert "Matching profile:" in html
    assert "Matching user:" in html
    assert "Entire estate:" in html
    css = (ROOT / "static" / "css" / "console.css").read_text()
    assert "#bx-table { table-layout:fixed; }" in css


def test_removal_job_id_uses_escaped_data_attribute():
    render = _last_function("_bxRenderRemovals")
    assert 'data-rid="\' + _escHtml(String(r.id))' in render


def test_removal_jobs_use_the_same_compact_table_language_as_extension_views():
    with TestClient(dashboard.app) as client:
        html = client.get("/console").text
    removals = html[html.index('id="bx-removals"'):html.index('id="bx-table-wrap"')]
    assert "Removal jobs</div>" not in removals
    assert "A job is complete only after every captured endpoint profile reports removal evidence." in removals
    for heading in ("Extension", "Browser", "Scope", "Progress", "Requested", "Status"):
        assert f"<th>{heading}</th>" in removals
    assert ">Action</th>" in removals
    assert 'id="bx-removals-table" class="rdx-table"' in removals
    assert 'id="bx-removals-list"' in removals
    css = (ROOT / "static" / "css" / "console.css").read_text()
    # PAT-1615: header/cell chrome (font, padding, uppercase, hover) now comes
    # from the shared .rdx-table (PAT-1601) applied in the markup above —
    # only layout and column widths stay bx-removals-table-specific.
    assert "#bx-removals-table { width:100%; table-layout:fixed; }" in css
    assert "#bx-removals-table th:nth-child(5) { width:15%; }" in css
    assert "#bx-removals-table th:nth-child(7) { width:14%; }" in css
    assert ".bx-removal-row .bx-act-btn { margin-right:0; }" in css
    assert ".bx-removal-requested-date { white-space:nowrap; }" in css
    assert "#bx-removals-table td::before" in css
    assert "#bx-removals-table td[colspan] { display:block; }" in css
    assert "#bx-removals-table td[colspan]::before { content:none; }" in css


def test_removal_rows_keep_blocked_reason_and_cancel_handler_in_secondary_cells():
    source = """
var _bxView='removals';
var _bxRemovals=[{id:'job-1',browser:'chrome',extension_id:'ext-1',scope:'all_devices',targets_completed:0,targets_total:1,requested_at:'2026-08-13T10:00:00Z'}];
var _bxRemovalsError=null;
var _consoleState={tenantData:{app_control_enabled:false}};
var elements={
  'bx-removals':{style:{display:'none'}},
  'bx-removals-list':{innerHTML:''},
  'bx-removals-count':{textContent:''}
};
var document={getElementById:function(id){return elements[id];}};
function _escHtml(value){return String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;');}
function _bxResolveExtName(){return {name:'Example extension'};}
function _bxBrowserTag(browser){return '<span>' + _escHtml(browser) + '</span>';}
function _fmtTs(){return '28/07/2026 18:10';}
""" + _last_function("_bxControlEnabled") + _last_function("_bxScopeLabel") + _last_function("_bxRemovalState") + _last_function("_bxRenderRemovals")
    result = _node_json(source, "(()=>{_bxRenderRemovals();return elements['bx-removals-list'].innerHTML;})()")
    assert '<tr class="bx-removal-row">' in result
    assert 'data-label="Status"' in result
    assert '<span class="bx-removal-requested-date">28/07/2026</span> 18:10' in result
    assert 'Extension control is off; this request has not been sent to endpoints.' in result
    assert 'data-rid="job-1"' in result
    assert 'onclick="_bxRemoveCancel(this.dataset.rid)"' in result


def test_removal_error_and_empty_states_use_full_width_table_rows():
    source = """
var _bxView='removals';
var _bxRemovals=[];
var _bxRemovalsError=null;
var elements={
  'bx-removals':{style:{display:'none'}},
  'bx-removals-list':{innerHTML:''},
  'bx-removals-count':{textContent:''}
};
var document={getElementById:function(id){return elements[id];}};
""" + _last_function("_bxRenderRemovals")
    result = _node_json(source, "(()=>{_bxRenderRemovals();var empty=elements['bx-removals-list'].innerHTML;_bxRemovalsError={message:'failed'};_bxRenderRemovals();return {empty:empty,error:elements['bx-removals-list'].innerHTML};})()")
    assert result["empty"] == '<tr><td colspan="7" class="empty-state">No removal jobs have been requested.</td></tr>'
    assert result["error"] == '<tr><td colspan="7" class="console-error">Removal jobs could not be loaded. Refresh before making any removal decision.</td></tr>'


def test_completed_removal_rows_show_plain_none_when_no_action_is_available():
    source = """
var _bxView='removals';
var _bxRemovals=[{id:'job-2',browser:'edge',extension_id:'ext-2',scope:'all_devices',fulfilled:true,targets_completed:1,targets_total:1,requested_at:'2026-08-13T10:00:00Z'}];
var _bxRemovalsError=null;
var _consoleState={tenantData:{app_control_enabled:true}};
var elements={
  'bx-removals':{style:{display:'none'}},
  'bx-removals-list':{innerHTML:''},
  'bx-removals-count':{textContent:''}
};
var document={getElementById:function(id){return elements[id];}};
function _escHtml(value){return String(value);}
function _bxResolveExtName(){return {name:'Completed extension'};}
function _bxBrowserTag(browser){return browser;}
function _fmtTs(){return '13 Aug';}
""" + _last_function("_bxControlEnabled") + _last_function("_bxScopeLabel") + _last_function("_bxRemovalState") + _last_function("_bxRenderRemovals")
    result = _node_json(source, "(()=>{_bxRenderRemovals();return elements['bx-removals-list'].innerHTML;})()")
    assert '<span class="bx-removal-sub">None</span>' in result
    assert "Cancel job" not in result
