"""Additional read-only race/partial-source cases; frozen acceptance is unchanged."""
import re
import pytest
from playwright.sync_api import expect
from tests import browser_pat2374_tenant_lifecycle as acceptance

chromium = acceptance.chromium
visit = acceptance.visit
select = acceptance.select
flush = acceptance.flush
from tests.pat2374_support import account, users, deliveries, tenant


@pytest.mark.parametrize('tab,source,probe,old,new', [
    ('account', 'account', '#acct-contact-email', 'a@example.invalid', 'latest@example.invalid'),
    ('customer-access', 'portal-users', '#ca-content', 'a@example.invalid', 'latest@example.invalid'),
    ('reports', 'reports/deliveries', '#rpt-history-tbody', 'Report A', 'Latest report'),
])
def test_return_to_a_rejects_its_previous_visit(visit, tab, source, probe, old, new):
    page, state = visit()
    path = '/admin/tenants/a/' + source
    state['hold'] = {path}
    select(page, 'a', tab)
    page.wait_for_timeout(60)
    assert state['pending']
    page.locator('#grail-customers').click()
    select(page, 'b', tab)
    state['hold'] = set()
    body = account('a') if tab == 'account' else users('a') if tab == 'customer-access' else deliveries('a')
    if tab == 'account': body['primary_contact_email'] = new
    elif tab == 'customer-access': body['users'][0]['email'] = new
    else: body[0]['report_type'] = new
    state['overrides'][path] = (200, body)
    page.locator('#grail-customers').click()
    select(page, 'a', tab)
    if tab == 'reports': page.get_by_role('tab', name=re.compile('History')).click()
    region = page.locator(probe)
    if tab == 'account': expect(region).to_have_value(new)
    else: expect(region).to_contain_text(new)
    flush(page, state)
    if tab == 'account': expect(region).to_have_value(new)
    else:
        expect(region).to_contain_text(new)
        expect(region).not_to_contain_text(old)
    assert not state['errors']


@pytest.mark.parametrize('source,body,tab,probe', [
    ('portal-users', {}, 'customer-access', '#ca-error'),
    ('portal-users', {'users': None}, 'customer-access', '#ca-error'),
    ('account', {}, 'account', '#acct-error'),
    ('reports/deliveries', {}, 'reports', '#rpt-history-error'),
    ('report-records', {'records': None}, 'reports', '#rpt-records-error'),
])
def test_malformed_success_is_unavailable(visit, source, body, tab, probe):
    page, _ = visit(overrides={'/admin/tenants/a/' + source: (200, body)})
    select(page, 'a', tab)
    if tab == 'reports': page.get_by_role('tab', name=re.compile('History')).click()
    expect(page.locator(probe)).to_be_visible()
    expect(page.locator(probe)).to_contain_text(re.compile('unavailable|failed', re.I))


def test_report_attempts_load_when_configuration_is_unavailable(visit):
    page, _ = visit(overrides={'/admin/tenants/a/reports-config': (503, {'error': 'configuration unavailable'})})
    select(page, 'a', 'reports')
    page.get_by_role('tab', name=re.compile('History')).click()
    expect(page.locator('#rpt-history-tbody')).to_contain_text('Report A')
    expect(page.locator('#rpt-history-tbody')).to_contain_text('Failed')


def test_late_active_directory_refresh_does_not_overwrite_revoked_list(visit):
    page, state = visit()
    state['hold'] = {'/admin/tenants/overview'}
    page.locator('#section-customers-list').get_by_role('button', name='Refresh', exact=True).click()
    page.wait_for_timeout(60)
    assert state['pending']
    page.get_by_role('button', name='Offboarded', exact=True).click()
    expect(page.locator('#cl-content')).to_contain_text('Revoked tenant')
    flush(page, state)
    expect(page.locator('#cl-content')).to_contain_text('Revoked tenant')
    expect(page.locator('#cl-content')).not_to_contain_text('Tenant A')


def test_unknown_health_has_no_warning_stripe_and_trial_without_expiry_is_trial(visit):
    page, _ = visit(rows=[tenant('a', compliance_pct=None, is_trial=True, trial_expires_at=None)])
    expect(page.locator('#cl-content tr[data-tenant-id="a"]')).to_have_attribute('data-health-bucket', 'unknown')
    expect(page.locator('#cl-content')).to_contain_text('Trial; expiry unknown')


def test_initial_directory_fetch_has_actual_fetch_time_despite_parallel_switcher_read(visit):
    page, state = visit()
    expect(page.locator('#cl-freshness')).to_contain_text('Fetched ')
    expect(page.locator('#cl-freshness')).not_to_contain_text('Not fetched')
    assert state['requests'].count(('GET', '/admin/tenants/overview')) == 1
