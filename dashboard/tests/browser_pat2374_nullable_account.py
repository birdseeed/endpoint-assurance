"""Nullable lifecycle evidence and local save payloads, with every request intercepted."""
import re

import pytest
from playwright.sync_api import expect
from tests import browser_pat2374_tenant_lifecycle as acceptance
from tests.pat2374_support import account

chromium = acceptance.chromium
visit = acceptance.visit
select = acceptance.select

ACCOUNT_PATH = '/admin/tenants/a/account'
SAVED_FIELDS = (
    'primary_contact_name', 'primary_contact_email', 'company_phone',
    'technical_contact_name', 'technical_contact_email', 'billing_contact_name',
    'billing_contact_email', 'onboarding_state', 'contract_renewal_date',
    'contract_notes', 'account_notes', 'app_control_enabled', 'billing_frequency',
)


def nullable_account():
    body = account('a')
    body['onboarding_state'] = None
    return body


def assert_no_account_writes(state):
    assert not any(method != 'GET' and path == ACCOUNT_PATH
                   for method, path in state['requests'])
    assert not state['errors'], state['errors']


def test_nullable_lifecycle_renders_real_contacts_and_unknown(visit):
    page, state = visit(overrides={ACCOUNT_PATH: (200, nullable_account())})
    select(page, 'a')
    expect(page.locator('#acct-content')).to_be_visible()
    expect(page.locator('#acct-error')).to_be_hidden()
    expect(page.locator('#acct-contact-name')).to_have_value('Contact A')
    expect(page.locator('#acct-contact-email')).to_have_value('a@example.invalid')
    expect(page.locator('#acct-summary-contacts')).to_contain_text('1 / 3 complete')
    expect(page.locator('#acct-summary-state')).to_have_text(re.compile('unknown', re.I))
    expect(page.locator('#acct-state option:checked')).to_have_text(re.compile('unknown', re.I))
    expect(page.locator('#acct-state')).not_to_have_value('prospect')
    expect(page.locator('#acct-summary-state')).not_to_contain_text('Prospect')
    assert_no_account_writes(state)


@pytest.mark.parametrize('view', ['profile', 'commercial'])
def test_unrelated_edit_preserves_nullable_lifecycle_and_other_account_fields(visit, view):
    body = nullable_account()
    page, state = visit(overrides={ACCOUNT_PATH: (200, body)})
    select(page, 'a')
    expect(page.locator('#acct-content')).to_be_visible()
    expected = {field: body[field] for field in SAVED_FIELDS}
    if view == 'profile':
        page.locator('#acct-contact-name').fill('Updated contact')
        expected['primary_contact_name'] = 'Updated contact'
    else:
        page.get_by_role('tab', name='Commercial', exact=True).click()
        page.locator('#acct-billing-freq').select_option('annual')
        expected['billing_frequency'] = 'annual'
    # Evaluate the real payload builder locally; never trigger a save/API mutation.
    payload = page.evaluate('(view) => _acctPayload(view)', view)
    assert 'onboarding_state' in payload
    assert payload['onboarding_state'] is None
    assert payload == expected
    assert_no_account_writes(state)


def test_explicit_lifecycle_choice_can_set_active_from_unknown(visit):
    page, state = visit(overrides={ACCOUNT_PATH: (200, nullable_account())})
    select(page, 'a')
    expect(page.locator('#acct-content')).to_be_visible()
    page.locator('#acct-state').select_option('active')
    payload = page.evaluate("_acctPayload('profile')")
    assert payload['onboarding_state'] == 'active'
    assert payload['primary_contact_email'] == 'a@example.invalid'
    assert_no_account_writes(state)


@pytest.mark.parametrize('status,body', [(200, {}), (404, {'error': 'tenant not found in clients'})])
def test_missing_account_source_remains_unavailable(visit, status, body):
    page, state = visit(overrides={ACCOUNT_PATH: (status, body)})
    select(page, 'a')
    expect(page.locator('#acct-error')).to_be_visible()
    expect(page.locator('#acct-error')).to_contain_text(re.compile('unavailable|not found', re.I))
    expect(page.locator('#acct-content')).to_be_hidden()
    assert_no_account_writes(state)


def test_known_prospect_remains_source_backed_prospect(visit):
    body = account('a')
    body['onboarding_state'] = 'prospect'
    page, state = visit(overrides={ACCOUNT_PATH: (200, body)})
    select(page, 'a')
    expect(page.locator('#acct-content')).to_be_visible()
    expect(page.locator('#acct-state')).to_have_value('prospect')
    expect(page.locator('#acct-summary-state')).to_have_text(re.compile('prospect', re.I))
    for view in ('profile', 'commercial'):
        payload = page.evaluate('(view) => _acctPayload(view)', view)
        assert payload == {field: body[field] for field in SAVED_FIELDS}
    assert_no_account_writes(state)
