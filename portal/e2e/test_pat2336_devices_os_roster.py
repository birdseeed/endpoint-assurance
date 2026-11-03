"""The roster exposes reported OS context without a viewport reveal tier."""
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from e2e.test_pat2324_server_display import (
    DOC_OVERFLOW_JS,
    _context,
    mixed_roster,  # noqa: F401
)
from tests.conftest import STUB_STATE


@pytest.mark.parametrize('width', [1440, 1280, 390])
@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_os_identity_and_compact_roster(browser, harness_url, mixed_roster, width, theme):  # noqa: F811
    rows = STUB_STATE['devices_data']['devices']
    rows[3]['os_version'] = None
    rows[3]['encryption_ok'] = None
    rows[4]['last_seen'] = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    rows[2]['os_version'] = '15.5 (24F74)'
    context = _context(browser, harness_url, viewport={'width': width, 'height': 1000})
    try:
        page = context.new_page()
        page.goto('/devices?view=normal', wait_until='networkidle')
        page.evaluate('(theme) => document.documentElement.dataset.theme = theme', theme)
        for hostname, version in [('HOMESERVER', '10.0.20348.5499'),
                                  ('WINDOWS11', '10.0.26200.9457'),
                                  ('MacBook-Pro', '15.5 (24F74)'),
                                  ('OLD-PLATFORM', 'Not reported')]:
            row = page.locator('#device-table tbody tr', has_text=hostname)
            value = row.locator('[data-label="OS version"]').get_by_text(version, exact=True)
            assert value.is_visible(), f'{hostname}: OS version hidden at {width}'
            assert value.evaluate("el => getComputedStyle(el).whiteSpace") == 'nowrap'
            assert value.evaluate('el => el.scrollWidth <= el.clientWidth + 1')
        assert page.evaluate(DOC_OVERFLOW_JS) <= 1
        assert page.locator('#device-table').evaluate(
            'el => el.parentElement.scrollWidth <= el.parentElement.clientWidth + 1')
        server = page.locator('#device-table tbody tr', has_text='HOMESERVER')
        assert server.get_by_text('n/a', exact=True).is_visible()
        assert '35 failing' in server.inner_text()
        assert 'Windows Server' in server.inner_text()
        assert 'Not reported' in server.locator('[data-label="Updates"]').inner_text()
        unknown = page.locator('#device-table tbody tr', has_text='OLD-PLATFORM')
        assert 'Not assessed' in unknown.inner_text()
        server.get_by_label('Retire HOMESERVER', exact=True).click()
        reason = server.get_by_label('Reason (optional)', exact=True)
        assert reason.is_visible()
        reason.fill('Review retirement')
        assert server.get_by_role('button', name='Retire device', exact=True).is_visible()
        assert page.evaluate(DOC_OVERFLOW_JS) <= 1
        server.get_by_label('Retire HOMESERVER', exact=True).click()
        page.locator('#device-search').fill('24F74')
        assert page.locator('#device-table tbody tr:visible').count() == 1
        page.locator('#device-search').fill('')
        page.evaluate('window.scrollTo(0, 0)')
        path = os.environ.get('PAT2336_SCREENSHOTS')
        if path:
            Path(path).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(path) / f'roster-{width}-{theme}.png'), full_page=True)
        page.goto('/devices?view=quiet&type=workstation&list_group=never_seen',
                  wait_until='networkidle')
        assert page.locator('#device-table tbody tr:visible').count() == 1
        assert 'acme-mbp-stale' in page.locator('#device-table tbody tr:visible').inner_text()
        quiet = page.locator('#device-table tbody tr:visible')
        assert 'Encryption evidence stale' in quiet.inner_text()
        assert page.locator('.kpi').first.inner_text().find('5') >= 0
        assert page.evaluate(DOC_OVERFLOW_JS) <= 1
    finally:
        context.close()


@pytest.mark.parametrize('width', [1440, 1280, 390])
def test_long_reported_build_remains_whole_and_readable(browser, harness_url, mixed_roster, width):  # noqa: F811
    build = '10.0.26200.9457.amd64fre.ge_release.240331-1435'
    STUB_STATE['devices_data']['devices'][1]['os_version'] = build
    context = _context(browser, harness_url, viewport={'width': width, 'height': 1000})
    try:
        page = context.new_page()
        page.goto('/devices', wait_until='networkidle')
        row = page.locator('#device-table tbody tr', has_text='WINDOWS11')
        cell = row.locator('[data-label="OS version"]')
        assert build in cell.get_attribute('title')
        value = cell.locator('.os-build')
        assert value.inner_text() == build
        assert value.is_visible()
        assert value.evaluate("el => getComputedStyle(el).whiteSpace") == 'nowrap'
        assert value.evaluate("el => getComputedStyle(el).overflowX") == 'auto'
        value.evaluate('el => el.scrollLeft = el.scrollWidth')
        assert value.evaluate('el => el.scrollLeft > 0')
        assert page.evaluate(DOC_OVERFLOW_JS) <= 1
    finally:
        context.close()
