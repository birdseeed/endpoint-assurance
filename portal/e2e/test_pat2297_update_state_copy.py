"""Neutral missing-update copy on both OSes, surfaces, widths and themes."""
import os
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from e2e.test_pat2324_server_display import DOC_OVERFLOW_JS, _context
from tests.conftest import DEVICE_DETAIL, STUB_STATE, platform_shaped_detail

NOTE = "This device hasn't reported a recent update state."


@pytest.mark.parametrize('width', [1440, 1280, 390])
@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_update_evidence_copy(browser, harness_url, width, theme):
    previous = {key: STUB_STATE.get(key) for key in ['devices_data', 'device_detail_data']}
    now = datetime.now(UTC).isoformat()
    context = _context(browser, harness_url, viewport={'width': width, 'height': 1000})
    try:
        page = context.new_page()
        for platform in ['Windows', 'macOS']:
            for state, label in [(None, 'Not reported'), (False, 'Up to date'),
                                 (True, 'Updates pending')]:
                row = {'device_id': 'dev-mac-001', 'hostname': 'update-copy-device',
                       'platform': platform, 'os_version': '15.5', 'last_seen': now,
                       'cis_score': 91, 'findings_open': 2, 'encryption_ok': True,
                       'patch_pending': state}
                STUB_STATE['devices_data'] = {'devices': [row]}
                detail = deepcopy(DEVICE_DETAIL)
                detail.update(row)
                STUB_STATE['device_detail_data'] = platform_shaped_detail(detail)
                for surface, url in [('roster', '/devices?view=normal'),
                                     ('detail', '/devices/dev-mac-001')]:
                    page.goto(url, wait_until='networkidle')
                    page.evaluate('(t) => document.documentElement.dataset.theme = t', theme)
                    if surface == 'roster':
                        cell = page.locator('#device-table [data-label="Updates"]')
                    else:
                        cell = page.locator(
                            '#device-assurance dt', has_text='Update state'
                        ).locator('xpath=following-sibling::dd[1]')
                    assert cell.is_visible()
                    if state is None:
                        if surface == 'roster':
                            assert cell.inner_text() == label
                            assert cell.locator('[title]').get_attribute('title') == NOTE
                            assert page.locator('[data-update-state-note]').inner_text() == NOTE
                        else:
                            assert cell.inner_text() == NOTE
                        assert cell.locator('.pill-ok, .pill-warn').count() == 0
                    else:
                        assert cell.inner_text() == label
                        tone = '.pill-ok' if state is False else '.pill-warn'
                        assert cell.locator(tone).count() == 1
                        assert NOTE not in page.locator('main').inner_text()
                    assert 'Not shown' not in cell.inner_text()
                    assert page.evaluate(DOC_OVERFLOW_JS) <= 1
                    if state is None and os.environ.get('PAT2297_SCREENSHOTS'):
                        directory = Path(os.environ['PAT2297_SCREENSHOTS'])
                        directory.mkdir(parents=True, exist_ok=True)
                        filename = f'{platform}-{surface}-{width}-{theme}.png'
                        page.screenshot(path=str(directory / filename), full_page=True)
    finally:
        STUB_STATE.update(previous)
        context.close()
