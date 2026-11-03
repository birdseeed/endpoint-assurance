"""PAT-2339 moves PAT-2141's counted links into the device tabs.

Keep the navigation, real-count, stale-caveat and phone-access guarantees
while rejecting the retired duplicate KPI strip.
"""

from e2e.conftest import HARNESS_VALID_TOKEN


def _context(browser, harness_url):
    context = browser.new_context(base_url=harness_url)
    context.add_cookies([{
        "name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": harness_url,
    }])
    return context


def test_counted_tabs_sit_above_the_device_card_at_1280(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        assert page.locator('.count-strip').count() == 0
        bar = page.locator('.device-tab-bar').bounding_box()
        card = page.locator('.device-card').bounding_box()
        assert bar['y'] + bar['height'] <= card['y']
    finally:
        context.close()


def test_clicking_cve_count_lands_on_the_vulnerabilities_tab(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.set_viewport_size({"width": 1280, "height": 900})
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        page.locator('[data-device-section="vulnerabilities"]').click()
        page.wait_for_load_state("networkidle")
        assert page.url == f"{harness_url}/devices/dev-mac-001/vulnerabilities"
        assert page.locator('.view-tabs a.tab-active[aria-current="page"]').inner_text() \
            .startswith("Vulnerabilities (2)")
        assert 0 <= page.locator('#cve-assessment').bounding_box()['y'] < 900
        page.go_back(wait_until="networkidle")
        assert page.url == f"{harness_url}/devices/dev-mac-001"
    finally:
        context.close()


def test_clicking_failing_count_lands_on_the_compliance_tab(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        page.locator('[data-device-section="compliance"]').click()
        page.wait_for_load_state("networkidle")
        assert page.url == f"{harness_url}/devices/dev-mac-001/compliance"
        assert page.locator('.view-tabs a.tab-active[aria-current="page"]').inner_text() \
            .startswith("Compliance (1 failing)")
        page.go_back(wait_until="networkidle")
        assert page.url == f"{harness_url}/devices/dev-mac-001"
    finally:
        context.close()


def test_tabs_keep_real_counts_and_a_visible_stale_caveat(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        for key, label in [('vulnerabilities', 'Vulnerabilities (2)'),
                           ('compliance', 'Compliance (1 failing)')]:
            tab = page.locator(f'[data-device-section="{key}"]')
            assert tab.locator('.device-tab-label').inner_text() == label
            caveat = tab.locator('.device-tab-caveat')
            assert caveat.inner_text() == 'Evidence stale'
            assert caveat.is_visible()
    finally:
        context.close()


def test_compliance_count_names_failing_checks(browser, harness_url):
    context = _context(browser, harness_url)
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        label = page.locator('[data-device-section="compliance"] .device-tab-label').inner_text()
        assert label == 'Compliance (1 failing)'
    finally:
        context.close()


def test_counted_tabs_scroll_inside_phone_width_without_javascript(browser, harness_url):
    context = browser.new_context(base_url=harness_url, java_script_enabled=False,
                                  viewport={'width': 390, 'height': 900})
    context.add_cookies([{
        'name': 'CF_Authorization', 'value': HARNESS_VALID_TOKEN, 'url': harness_url,
    }])
    try:
        page = context.new_page()
        page.goto(f"{harness_url}/devices/dev-mac-001", wait_until="networkidle")
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
        page.locator('[data-device-section="compliance"]').click()
        page.wait_for_load_state('networkidle')
        assert page.url.endswith('/compliance')
        assert page.locator('#compliance-signals').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    finally:
        context.close()
