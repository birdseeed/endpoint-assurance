"""Device investigation keeps collection actions and compact identity visible."""
from copy import deepcopy
from pathlib import Path

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from tests.conftest import DEVICE_DETAIL, STUB_STATE

EVIDENCE = Path.home() / '.claude/linear-runs/evidence/PAT-2339/codex-resume'


@pytest.mark.parametrize('theme', ['light', 'dark'])
@pytest.mark.parametrize('width', [1440, 1280, 390])
def test_compact_device_overview(browser, harness_url, theme, width):
    detail = deepcopy(DEVICE_DETAIL)
    detail['agent_health_degraded'] = [{
        'kind': 'tcc_denied', 'subject': 'browser_extensions',
        'reason': 'full_disk_access_missing', 'first_seen': '2026-09-29T10:00:00Z',
        'last_seen': '2026-09-30T10:00:00Z',
    }]
    STUB_STATE['device_detail_data'] = detail
    context = browser.new_context(color_scheme=theme, viewport={'width': width, 'height': 900})
    context.add_cookies([{
        'name': 'CF_Authorization', 'value': HARNESS_VALID_TOKEN, 'url': harness_url,
    }])
    try:
        page = context.new_page()
        page.goto(f'{harness_url}/devices/dev-mac-001', wait_until='networkidle')
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        phase = 'before' if page.locator('.count-strip').count() else 'after'
        page.screenshot(path=str(EVIDENCE / f'{phase}-{width}-{theme}.png'), full_page=True)
        assert page.locator('.count-strip').count() == 0, 'duplicate KPI strip'
        assert page.locator('.card h2', has_text='Summary').count() == 0
        identity = page.locator('#identification').bounding_box()
        assert identity['height'] <= (520 if width == 390 else 290), identity
        guide = page.get_by_role('link', name='Full Disk Access guide')
        assert guide.count() == 1
        assert guide.bounding_box()['y'] < (550 if width == 390 else 380)
        for value in ['C02XL0GTJGH5', 'Mac16,1', "Alice's MacBook Pro",
                      'arm64', '24F74', '0.19.23']:
            assert value in page.locator('#identification').inner_text()
        assert page.locator('.view-tabs a', has_text='Compliance (1 failing)').count() == 1
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        issue_dates = page.locator('.device-collection-alert details')
        issue_dates.locator('summary').click()
        for date in ['2026-09-29T10:00:00Z', '2026-09-30T10:00:00Z']:
            assert issue_dates.locator(f'time[datetime="{date}"]').is_visible()
        for date in ['2026-11-01T09:12:44Z', '2027-01-02T09:58:00Z',
                     '2026-07-02T09:40:42Z']:
            assert page.locator(f'#identification time[datetime="{date}"]').count() == 1
        assert guide.get_attribute('href').startswith('https://')
        page.locator('.retire-panel summary').click()
        form = page.locator('form[action="/devices/retirement"]')
        assert form.locator('input[name="csrf_token"]').input_value()
        assert form.locator('input[name="device_id"]').input_value() == 'dev-mac-001'
        assert form.get_by_role('button', name='Retire device').is_visible()
    finally:
        context.close()
        STUB_STATE['device_detail_data'] = None


@pytest.mark.parametrize('theme', ['light', 'dark'])
@pytest.mark.parametrize('width', [1440, 1280, 390])
@pytest.mark.parametrize('device_id,expected', [
    ('dev-win-002', ['Windows 11', 'Compliance (6 failing)', 'Update evidence stale']),
    ('dev-win-101', ['Server 2022', 'Not available for servers yet', 'Compliance (4 failing)']),
    ('dev-mac-003', ['Vulnerabilities (Not assessed)', 'Software (Unavailable)']),
    ('dev-mac-004', ['Retired', 'Written off after theft', 'Return to active']),
])
def test_compact_overview_preserves_other_device_states(
    browser, harness_url, theme, width, device_id, expected,
):
    context = browser.new_context(color_scheme=theme, viewport={'width': width, 'height': 900})
    context.add_cookies([{
        'name': 'CF_Authorization', 'value': HARNESS_VALID_TOKEN, 'url': harness_url,
    }])
    try:
        page = context.new_page()
        page.goto(f'{harness_url}/devices/{device_id}', wait_until='networkidle')
        body = page.locator('main').inner_text()
        for value in expected:
            assert value in body
        assert page.locator('.count-strip').count() == 0
        assert page.locator('.device-card #device-assurance').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        if device_id == 'dev-win-101':
            assert '%' not in page.locator('#device-assurance').inner_text()
        if device_id == 'dev-mac-004':
            page.locator('.retire-panel summary').click()
            assert page.locator('input[name="retired"]').input_value() == 'false'
            assert page.get_by_role('button', name='Return to active').is_visible()
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(EVIDENCE / f'{device_id}-{width}-{theme}.png'), full_page=True)
    finally:
        context.close()


@pytest.mark.parametrize('role', ['viewer', 'unavailable'])
def test_compact_retirement_still_refuses_controls_without_admin_role(
    browser, harness_url, role,
):
    previous_role, previous_status = STUB_STATE['portal_role'], STUB_STATE['me_status']
    STUB_STATE['portal_role'] = role
    STUB_STATE['me_status'] = 503 if role == 'unavailable' else None
    context = browser.new_context(viewport={'width': 390, 'height': 900})
    context.add_cookies([{
        'name': 'CF_Authorization', 'value': HARNESS_VALID_TOKEN, 'url': harness_url,
    }])
    try:
        page = context.new_page()
        page.goto(f'{harness_url}/devices/dev-mac-004', wait_until='networkidle')
        assert page.locator('form[action="/devices/retirement"]').count() == 0
        assert 'Retired' in page.locator('#retirement').inner_text()
        if role == 'unavailable':
            assert 'Your role could not be checked' in page.locator('#retirement').inner_text()
    finally:
        context.close()
        STUB_STATE['portal_role'], STUB_STATE['me_status'] = previous_role, previous_status
