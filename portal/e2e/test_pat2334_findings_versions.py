"""Installed finding context stays visible without hovering or horizontal scrolling."""

import copy
import os
from pathlib import Path

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN
from e2e.walk.walk import THEME_STORAGE_KEY, check_cells
from tests.conftest import FINDINGS, STUB_STATE

LONG_VERSION = '123.456.789.' * 12 + '\"<vendor>'


@pytest.mark.parametrize('theme', ['light', 'dark'])
@pytest.mark.parametrize('width', [1440, 1280, 390])
def test_installed_and_target_are_visible(browser, harness_url, monkeypatch, width, theme):
    rows = [copy.deepcopy(FINDINGS[0]) for _ in range(4)]
    rows[1]['version'] = '124.0.2'
    rows[1]['devices_affected'] = 2
    rows[2].pop('version')
    rows[2]['fixed_version'] = ''
    rows[3]['version'] = LONG_VERSION
    rows[3]['fixed_version'] = LONG_VERSION + '.fixed'
    monkeypatch.setitem(STUB_STATE, 'findings_data', rows)
    context = browser.new_context(viewport={'width': width, 'height': 900})
    context.add_cookies([{'name': 'CF_Authorization', 'value': HARNESS_VALID_TOKEN,
                         'url': harness_url}])
    context.add_init_script(
        f"localStorage.setItem('{THEME_STORAGE_KEY}', '{theme}')")
    try:
        page = context.new_page()
        page.goto(f'{harness_url}/findings', wait_until='networkidle')
        finding_rows = page.locator('#device-table > tbody > tr:not(.row-summary)')
        assert finding_rows.count() == 4
        # This assertion finds the actual installed evidence in the old template
        # too: before the fix its cell has display:none at desktop widths.
        installed = finding_rows.first.locator('td').filter(has_text='124.0.1')
        assert installed.is_visible(), 'installed affected version is hidden'
        versions = finding_rows.locator('.finding-versions')
        assert versions.count() == 4
        expected = [('124.0.1', '124.0.5'), ('124.0.2', '124.0.5'),
                    ('Not reported', 'latest vendor release'),
                    (LONG_VERSION, LONG_VERSION + '.fixed')]
        for index, (installed_value, target_value) in enumerate(expected):
            cell = versions.nth(index)
            assert cell.locator('.finding-installed').inner_text() == (
                f'Installed: {installed_value}')
            assert cell.locator('.finding-target').inner_text() == f'Target: {target_value}'
            for line in cell.locator('span').all():
                assert line.is_visible()
                geometry = line.evaluate('''el => {
                  const r = el.getBoundingClientRect();
                  return {x:r.x, right:r.right, width:r.width,
                    nowrap:getComputedStyle(el).whiteSpace,
                    height:r.height, lineHeight:parseFloat(getComputedStyle(el).lineHeight)};
                }''')
                assert geometry['x'] >= 0 and geometry['right'] <= width
                assert geometry['width'] > 0
                if line.get_attribute('class') != 'finding-target finding-target--fallback':
                    assert geometry['nowrap'] == 'nowrap'
                    assert geometry['height'] <= geometry['lineHeight'] + 1
            if index < 3:
                for line in cell.locator('span').all():
                    assert line.evaluate(
                        'el => el.scrollWidth <= el.clientWidth'), 'ordinary version clipped'
        assert versions.last.locator('.finding-installed').get_attribute('title') == (
            f'Installed: {LONG_VERSION}')
        assert page.locator('#device-table vendor').count() == 0
        assert finding_rows.nth(0).locator('[data-label="Devices"]').inner_text() == '3'
        assert finding_rows.nth(1).locator('[data-label="Devices"]').inner_text() == '2'
        assert page.locator('#device-table .row-summary').count() == 4
        assert not check_cells(page, '/findings', width, theme)
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        # Sort uses the shifted Devices index and retains each paired description.
        if width > 680:
            page.locator('#device-table th').filter(has_text='Devices').click()
            assert finding_rows.first.locator('[data-label="Devices"]').inner_text() == '2'
            assert finding_rows.first.locator('.finding-installed').inner_text() == (
                'Installed: 124.0.2')
            assert finding_rows.count() == 4
            assert page.locator('#device-table .row-summary').count() == 4
        evidence = os.environ.get('PAT2334_SCREENSHOTS')
        if evidence:
            page.screenshot(path=str(Path(evidence) / f'findings-{width}-{theme}.png'),
                            full_page=True)
    finally:
        context.close()
