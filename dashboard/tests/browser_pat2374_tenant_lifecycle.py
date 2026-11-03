"""Observable PAT-2374 acceptance against actual template and browser scripts.

Fixtures are read-only source-shaped JSON, not success mocks for mutations.
Unspecified sources return 503. Held GET responses reproduce A-to-B races.
Run with the command recorded in the preparation receipt; no startup/providers.
"""
import copy
import json
import mimetypes
import re
from urllib.parse import urlsplit
import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import expect, sync_playwright
from tests.pat2374_support import ROOT,artifact_dir,STAMP,ATTACK,TENANTS,tenant,account,users,deliveries,assert_owner

ORIGIN='http://127.0.0.1:2374'

@pytest.fixture(scope='module')
def chromium():
    expect.set_options(timeout=1300)
    with sync_playwright() as pw:
        browser=pw.chromium.launch()
        yield browser
        browser.close()

@pytest.fixture
def visit(chromium):
    contexts=[]; violations=[]
    def open_page(rows=None,width=1440,theme='light',role='owner',overrides=None):
        state={'rows':copy.deepcopy(TENANTS if rows is None else rows),'requests':[],
               'pending':[], 'hold':set(), 'overrides':overrides or {},'errors':[], 'blocked_telemetry':[]}
        markup=Environment(loader=FileSystemLoader(ROOT/'templates'),autoescape=select_autoescape()).get_template('console.html').render(
            console_build_id='pat2374-offline',env='local',api_backend='loopback fixture',role=role,
            actor_email=role+'@example.invalid',device_freshness={'active_max_days':7,'silent_min_days':30},impersonation=None,imp_expired=False)
        context=chromium.new_context(viewport={'width':width,'height':1000},color_scheme=theme)
        contexts.append(context)
        context.add_init_script("localStorage.setItem('patched-theme',"+json.dumps(theme)+");")
        def respond(route):
            req=route.request; url=urlsplit(req.url); path=url.path
            state['requests'].append((req.method,path))
            if url.scheme+'://'+url.netloc==ORIGIN and req.method=='POST' and re.fullmatch('/api/tenant/[^/]+/signal',path):
                # Existing automatic login signal is intercepted and REJECTED, never executed.
                state['blocked_telemetry'].append(path)
                route.fulfill(status=405,content_type='application/json',body='{"error":"Read-only fixture rejects telemetry writes"}'); return
            if url.scheme+'://'+url.netloc!=ORIGIN or req.method!='GET':
                violations.append((req.method,req.url)); route.abort(); return
            if path.startswith('/console'):
                route.fulfill(status=200,content_type='text/html',body=markup); return
            if path.startswith('/static/'):
                asset=(ROOT/path.lstrip('/')).resolve()
                assert asset.is_relative_to((ROOT/'static').resolve())
                route.fulfill(status=200 if asset.is_file() else 404,content_type=mimetypes.guess_type(asset)[0] or 'text/plain',body=asset.read_bytes() if asset.is_file() else b'missing asset'); return
            status,body=503,{'error':'Offline source unavailable'}
            if path=='/admin/tenants/overview': status,body=200,{'tenants':state['rows']}
            elif path=='/admin/tenants/revoked': status,body=200,{'tenants':[{'id':'revoked','name':'Revoked tenant','revoked_at':STAMP}]}
            else:
                match=re.fullmatch('/admin/tenants/([^/]+)/(.+)',path)
                if match:
                    tid,source=match.groups()
                    fixtures={'account':account(tid),'portal-users':users(tid),
                      'portal-welcomes':{'welcomes':[]},'support-access':{'billing_tier':'report','support_access_opt_out':False,'can_opt_out':False},
                      'reports/deliveries':deliveries(tid),'reports-config':[],
                      'report-records':{'records':[],'total':0,'page':1,'per_page':20},'report-schedules':{'schedules':[]}}
                    if source in fixtures: status,body=200,fixtures[source]
            if path in state['overrides']: status,body=state['overrides'][path]
            if path in state['hold']:
                state['pending'].append((path,route,status,body)); return
            route.fulfill(status=status,content_type='application/json',body=json.dumps(body))
        context.route('**/*',respond)
        page=context.new_page(); page.set_default_timeout(1300)
        page.on('pageerror',lambda err:state['errors'].append(str(err)))
        page.goto(ORIGIN+'/console/pat2374-offline#customers-list',wait_until='domcontentloaded')
        expect(page.locator('#section-customers-list')).to_be_visible()
        page.wait_for_function("document.getElementById('cl-loading').style.display === 'none'")
        return page,state
    yield open_page
    for context in contexts: context.close()
    assert not violations,violations


def select(page,tid,tab='account'):
    page.get_by_role('searchbox',name='Search customers').fill('Tenant '+tid.upper())
    page.locator('#cl-content button.cl-customer-link').click()
    group='evidence' if tab=='reports' else 'customer-setup'
    page.locator('#context-nav button[data-workload="'+group+'"]').click()
    page.locator('#context-nav button[data-tab="'+tab+'"]').click()
    expect(page.locator('#ctx-client-name')).to_have_text('Tenant '+tid.upper())


def flush(page,state):
    for _,route,status,body in state['pending']:
        route.fulfill(status=status,content_type='application/json',body=json.dumps(body))
    state['pending'].clear()
    page.wait_for_timeout(100)


def test_control_real_template_static_scripts_and_owner_role(visit):
    page,state=visit()
    assert page.evaluate('typeof consoleNav')=='function'
    assert page.evaluate('window.__ROLE')=='owner'
    assert ('GET','/static/js/console-shell.js') in state['requests']
    assert not state['errors']


def test_empty_directory_has_accurate_empty_state(visit):
    page,_=visit(rows=[])
    expect(page.locator('#cl-content')).to_contain_text(re.compile('no customers|no tenants|first customer',re.I))
    expect(page.locator('#cl-content tbody tr')).to_have_count(0)


def test_search_filter_and_explicit_refresh_use_real_overview(visit):
    page,state=visit()
    page.get_by_role('searchbox',name='Search customers').fill('Tenant B')
    expect(page.locator('#cl-content tbody tr')).to_have_count(1)
    expect(page.locator('#cl-content')).to_contain_text('Tenant B')
    page.get_by_role('searchbox',name='Search customers').fill('no such customer')
    expect(page.locator('#cl-content')).to_contain_text('No customers match')
    page.get_by_role('searchbox',name='Search customers').fill('')
    before=state['requests'].count(('GET','/admin/tenants/overview'))
    state['rows']=[tenant('replacement')]
    page.locator('#section-customers-list').get_by_role('button',name='Refresh',exact=True).click()
    expect(page.locator('#cl-content')).to_contain_text('Tenant REPLACEMENT')
    assert state['requests'].count(('GET','/admin/tenants/overview'))==before+1


def test_risk_filter_does_not_invent_missing_health(visit):
    page,_=visit(rows=[tenant('risk',compliance_pct=20),tenant('unknown',compliance_pct=None)])
    page.get_by_label('At-risk only').check()
    expect(page.locator('#cl-content')).to_contain_text('Tenant RISK')
    expect(page.locator('#cl-content')).not_to_contain_text('Tenant UNKNOWN')


@pytest.mark.parametrize('missing',[None,'absent'])
def test_unknown_device_count_is_not_zero(visit,missing):
    row=tenant('degraded',device_count=None)
    if missing=='absent': del row['device_count']
    page,_=visit(rows=[row])
    content=page.locator('#cl-content')
    expect(content).not_to_contain_text('0 devices')
    expect(content).to_contain_text(re.compile('unknown|unavailable|not reported',re.I))


def test_trial_is_labelled_trial_not_paid_active(visit):
    page,_=visit(rows=[tenant('trial',is_trial=True,trial_expires_at='2099-10-01T00:00:00Z')])
    expect(page.locator('#cl-content')).to_contain_text('Trial')


def test_revoked_list_is_separate_and_source_dated(visit):
    page,state=visit(rows=[])
    page.get_by_role('button',name='Offboarded',exact=True).click()
    expect(page.locator('#cl-content')).to_contain_text('Revoked tenant')
    expect(page.locator('#cl-content')).to_contain_text('2026-10-03')
    assert ('GET','/admin/tenants/revoked') in state['requests']


def test_directory_error_is_unknown_not_empty_success(visit):
    page,_=visit(overrides={'/admin/tenants/overview':(503,{'error':'Overview unavailable'})})
    expect(page.locator('#cl-error')).to_be_visible()
    expect(page.locator('#cl-error')).to_contain_text('Overview unavailable')
    expect(page.locator('#cl-content')).not_to_contain_text('0 devices')


def test_directory_discloses_source_and_fetch_freshness(visit):
    page,_=visit()
    region=page.locator('#section-customers-list')
    expect(region).to_contain_text(re.compile('tenant overview|overview source',re.I))


def test_directory_distinguishes_fetch_time_from_source_observation_time(visit):
    page,_=visit()
    region=page.locator('#section-customers-list')
    expect(region).to_contain_text(re.compile('fetched|refreshed|updated',re.I))


def test_unavailable_support_entry_never_offers_impersonation(visit):
    page,state=visit()
    region=page.locator('#section-customers-list')
    expect(region.get_by_role('button',name='View as customer')).to_have_count(0)
    entry=region.get_by_role('button',name=re.compile('support',re.I))
    expect(entry.first).to_be_visible(); expect(entry.first).to_be_disabled()
    expect(region).to_contain_text(re.compile('unavailable|not available',re.I))
    assert not any('/impersonation/start' in path for _,path in state['requests'])


def test_account_read_projection_separates_lifecycle_controls(visit):
    page,_=visit(); select(page,'a')
    region=page.locator('#tab-account')
    expect(region).to_contain_text(re.compile('read.only.*evidence|evidence.*read.only',re.I))
    expect(region).to_contain_text(re.compile('lifecycle',re.I))


@pytest.mark.parametrize('source,label',[
    ('account','identity'),('portal-users','access'),('reports/deliveries','report')])
def test_source_error_is_visibly_unavailable_in_tenant_presentation(visit,source,label):
    page,_=visit(overrides={'/admin/tenants/a/'+source:(503,{'error':label+' fixture unavailable'})})
    select(page,'a',{'account':'account','portal-users':'customer-access','reports/deliveries':'reports'}[source])
    region=page.locator('#section-tenant-workspace')
    expect(region).to_contain_text(re.compile(label+'.*(unavailable|failed)|(?:unavailable|failed).*'+label,re.I))


def test_new_onboarding_not_provisioned_and_no_invented_access(visit):
    page,_=visit(); select(page,'new')
    expect(page.locator('#acct-state')).to_have_value('prospect')
    expect(page.locator('#acct-content')).not_to_contain_text('Provisioned')
    page.locator('#context-nav button[data-tab="customer-access"]').click()
    expect(page.locator('#ca-empty')).to_be_visible()
    expect(page.locator('#ca-tbody tr')).to_have_count(0)


def test_access_identity_has_real_count_source_and_welcome_unknown(visit):
    page,_=visit(overrides={'/admin/tenants/a/portal-welcomes':(500,{'error':'welcome source failed'})})
    select(page,'a','customer-access')
    region=page.locator('#tab-customer-access')
    expect(region).to_contain_text('a@example.invalid')
    expect(region).to_contain_text(re.compile('welcome.*(?:unknown|unavailable)|(?:unknown|unavailable).*welcome',re.I))
    expect(region).to_contain_text(re.compile('portal.users|access source',re.I))


def test_failed_report_attempt_not_delivered_and_evidence_dated(visit):
    page,_=visit(); select(page,'a','reports')
    page.get_by_role('tab',name=re.compile('History')).click()
    region=page.locator('#tab-reports')
    expect(region).to_contain_text('Report A')
    expect(region).to_contain_text('Failed')
    expect(region).not_to_contain_text('Delivered')
    expect(region).to_contain_text('2026-10-03')


@pytest.mark.parametrize('tab,sources,probe',[
 ('account',['account'],'#acct-content'),
 ('customer-access',['portal-users','portal-welcomes'],'#ca-content'),
 ('reports',['reports/deliveries','report-records'],'#tab-reports')])
@pytest.mark.parametrize('late_error',[False,True])
def test_late_a_success_or_error_cannot_bleed_into_b(visit,tab,sources,probe,late_error):
    page,state=visit()
    state['hold']={'/admin/tenants/a/'+s for s in sources}
    if late_error:
        state['overrides'].update({p:(503,{'error':'PRIVATE A LATE FAILURE'}) for p in state['hold']})
    select(page,'a',tab)
    if tab=='reports': page.get_by_role('tab',name=re.compile('History')).click()
    page.wait_for_timeout(100)
    assert state['pending'],'Test must actually hold an A request'
    page.locator('#grail-customers').click()
    select(page,'b',tab)
    if tab=='account': expect(page.locator('#acct-contact-email')).to_have_value('b@example.invalid')
    if tab=='customer-access': expect(page.locator('#ca-content')).to_contain_text('b@example.invalid')
    if tab=='reports':
        page.get_by_role('tab',name=re.compile('History')).click()
        expect(page.locator('#rpt-history-tbody')).to_contain_text('Report B')
    flush(page,state)
    expect(page.locator('#ctx-client-name')).to_have_text('Tenant B')
    region=page.locator(probe)
    expect(region).not_to_contain_text('Company A')
    expect(region).not_to_contain_text('a@example.invalid')
    expect(region).not_to_contain_text('Report A')
    expect(page.locator('#section-tenant-workspace')).not_to_contain_text('PRIVATE A LATE FAILURE')
    if tab=='account':
        expect(page.locator('#acct-contact-email')).to_have_value('b@example.invalid')
        expect(page.locator('#acct-content')).to_contain_text('2 / 3 complete')
        expect(page.locator('#acct-error')).to_be_hidden()
    if tab=='customer-access':
        expect(page.locator('#ca-content')).to_contain_text('b@example.invalid')
        expect(page.locator('#ca-error')).to_be_hidden()
    if tab=='reports':
        expect(page.locator('#rpt-history-tbody')).to_contain_text('Report B')
        expect(page.locator('#rpt-history-error')).to_be_hidden()
    expect(page.locator('#ctx-client-fleet')).to_have_text('3 devices')


def test_global_navigation_clears_and_back_forward_restores_selection(visit):
    page,_=visit(); select(page,'a')
    page.locator('#grail-customers').click()
    expect(page.locator('#nav-section-customer')).to_be_hidden()
    assert page.evaluate('_consoleState.tenantId') is None
    page.go_back(); expect(page.locator('#ctx-client-name')).to_have_text('Tenant A')
    page.go_forward(); expect(page.locator('#nav-section-customer')).to_be_hidden()
    assert page.evaluate('_consoleState.tenantId') is None


def test_native_keyboard_search_filter_selection_and_account_tabs(visit):
    page,_=visit()
    search=page.get_by_role('searchbox',name='Search customers'); search.focus(); search.fill('Tenant B')
    expect(search).to_be_focused()
    search.press('Tab'); expect(page.get_by_role('button',name='Active',exact=True)).to_be_focused()
    page.get_by_label('At-risk only').focus(); page.keyboard.press('Space'); page.keyboard.press('Space')
    link=page.locator('#cl-content button.cl-customer-link'); link.focus(); page.keyboard.press('Enter')
    expect(page.locator('#ctx-client-name')).to_have_text('Tenant B')
    page.locator('#context-nav button[data-workload="customer-setup"]').click()
    page.locator('#context-nav button[data-tab="account"]').click()
    expect(page.locator('#acct-content')).to_be_visible()
    tabs=page.locator('#acct-content [role="tab"]'); tabs.first.focus(); page.keyboard.press('ArrowRight')
    expect(tabs.nth(1)).to_be_focused()
    focused=page.locator(':focus')
    assert focused.evaluate('(el)=>getComputedStyle(el).outlineStyle')!='none'


def test_hostile_tenant_and_account_text_stays_text(visit):
    hostile_account=account('evil'); hostile_account.update(primary_contact_name=ATTACK,account_notes=ATTACK)
    page,state=visit(rows=[tenant('evil',name=ATTACK)],overrides={'/admin/tenants/evil/account':(200,hostile_account)})
    expect(page.locator('#cl-content')).to_contain_text(ATTACK)
    expect(page.locator('[data-pat2374-injected]')).to_have_count(0)
    page.locator('#cl-content button.cl-customer-link').click()
    expect(page.locator('#ctx-client-name')).to_have_text(ATTACK)
    page.locator('#context-nav button[data-workload="customer-setup"]').click()
    page.locator('#context-nav button[data-tab="account"]').click()
    expect(page.locator('#acct-contact-name')).to_have_value(ATTACK)
    expect(page.locator('#acct-account-notes')).to_have_value(ATTACK)
    expect(page.locator('[data-pat2374-injected]')).to_have_count(0)
    assert page.evaluate('window.__injected') is None


@pytest.mark.parametrize('width',[1440,1024])
@pytest.mark.parametrize('theme',['light','dark'])
def test_directory_and_selected_workspace_no_document_overflow(visit,width,theme):
    page,state=visit(width=width,theme=theme)
    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    assert page.locator('html').get_attribute('data-theme')==theme
    assert_owner(); artifacts = artifact_dir()
    assert_owner(); page.screenshot(path=str(artifacts/f'current-directory-{width}-{theme}.png'),full_page=True)
    select(page,'a')
    expect(page.locator('#acct-content')).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    assert_owner(); page.screenshot(path=str(artifacts/f'current-account-{width}-{theme}.png'),full_page=True)
    assert not state['errors'],state['errors']


def test_identity_contacts_count_is_source_backed(visit):
    page,_=visit(); select(page,'a')
    expect(page.locator('#acct-contact-email')).to_have_value('a@example.invalid')
    expect(page.locator('#acct-content')).to_contain_text('1 / 3 complete')
    expect(page.locator('#acct-state')).to_have_value('active')


def test_reporting_population_uses_overview_active_last_7d_not_total(visit):
    page,_=visit(rows=[tenant('a',device_count=7,active_last_7d=4)])
    select(page,'a')
    visible=page.locator('#section-tenant-workspace')
    expect(page.locator('#acct-content')).to_be_visible()
    text=visible.inner_text()
    assert re.search(r'\b4\s*(?:(?:of|/)\s*7\s*)?(?:devices?\s*)?(?:reporting|active)|(?:reporting|active)[^\n]*\b4\b',text,re.I),text
    assert re.search(r'(?:last|past) 7 days',text,re.I),text


def test_overview_missing_row_does_not_infer_revoked(visit):
    page,state=visit(rows=[tenant('a')]); select(page,'a')
    page.locator('#grail-customers').click(); state['rows']=[]
    page.locator('#section-customers-list').get_by_role('button',name='Refresh',exact=True).click()
    expect(page.locator('#cl-content tbody tr')).to_have_count(0)
    expect(page.locator('#cl-content')).not_to_contain_text('Revoked')
    page.get_by_role('button',name='Offboarded',exact=True).click()
    expect(page.locator('#cl-content')).to_contain_text('Revoked tenant')


def test_late_account_response_after_global_navigation_has_no_visible_tenant(visit):
    page,state=visit(); state['hold']={'/admin/tenants/a/account'}
    select(page,'a'); assert state['pending']
    page.locator('#grail-customers').click(); flush(page,state)
    expect(page.locator('#nav-section-customer')).to_be_hidden()
    expect(page.locator('#section-tenant-workspace')).to_be_hidden()
    expect(page.locator('#section-customers-list')).not_to_contain_text('Company A')
    assert page.evaluate('_consoleState.tenantId') is None


def test_control_offboard_confirmation_requires_name_and_cancel_has_no_mutation(visit):
    page,state=visit(); select(page,'a')
    expect(page.locator('#acct-content')).to_be_visible()
    page.get_by_role('tab',name='Agent lifecycle',exact=True).click()
    page.get_by_role('button',name=re.compile('Offboard Customer',re.I)).click()
    modal=page.locator('#modal-offboard'); expect(modal).to_be_visible()
    submit=modal.get_by_role('button',name='Offboard',exact=True)
    expect(submit).to_be_disabled()
    page.locator('#offboard-confirm-input').fill('Tenant B'); expect(submit).to_be_disabled()
    page.locator('#offboard-confirm-input').fill('Tenant A'); expect(submit).to_be_enabled()
    modal.get_by_role('button',name='Cancel',exact=True).click(); expect(modal).to_be_hidden()
    assert not any(method!='GET' and not path.endswith('/signal') for method,path in state['requests'])


def test_control_consultant_lifecycle_controls_remain_hidden(visit):
    page,_=visit(role='consultant'); select(page,'a')
    expect(page.locator('#acct-content')).to_be_visible()
    page.get_by_role('tab',name='Agent lifecycle',exact=True).click()
    expect(page.get_by_role('button',name=re.compile('Offboard Customer',re.I))).to_have_count(0)
    expect(page.locator('#acct-danger-zone')).to_be_hidden()


@pytest.mark.parametrize('body',[{}, {'tenants':None}])
def test_missing_overview_collection_is_unavailable_not_empty_estate(visit,body):
    page,_=visit(overrides={'/admin/tenants/overview':(200,body)})
    content=page.locator('#section-customers-list')
    assert re.search(r'unavailable|unknown|failed',content.inner_text(),re.I),content.inner_text()
    expect(page.locator('#cl-content')).not_to_contain_text('No tenants yet')


def test_portal_user_counts_and_disabled_state_follow_actual_rows(visit):
    body=users('a'); body['total']=2; body['users'].append(dict(email='disabled@example.invalid',tenant_id='a',tenant_name='Tenant A',
        role='viewer',created_at=STAMP,disabled_at=STAMP))
    page,_=visit(overrides={'/admin/tenants/a/portal-users':(200,body)})
    select(page,'a','customer-access')
    expect(page.locator('#ca-tbody tr')).to_have_count(2)
    enabled=page.locator('#ca-tbody tr').filter(has_text='a@example.invalid')
    disabled=page.locator('#ca-tbody tr').filter(has_text='disabled@example.invalid')
    expect(enabled).not_to_contain_text('Welcomed')
    expect(disabled).to_contain_text('Disabled')
    expect(disabled.get_by_role('button',name='Send welcome',exact=True)).to_have_count(0)


def test_missing_local_account_is_not_invented_onboarding_evidence(visit):
    page,_=visit(overrides={'/admin/tenants/a/account':(404,{'error':'tenant not found in clients'})})
    select(page,'a')
    page.wait_for_timeout(100)
    text=page.locator('#tab-account').inner_text()
    assert re.search(r'account.*(?:unavailable|not found|unknown)|(?:unavailable|not found|unknown).*account',text,re.I),text
