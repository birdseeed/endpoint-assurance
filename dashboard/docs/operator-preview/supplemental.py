"""Additional local-only interaction/visual evidence; primary red/green test is unchanged."""
import functools
import json
import threading
from http.server import ThreadingHTTPServer
from playwright.sync_api import sync_playwright, expect
from acceptance import ROOT, EVIDENCE, QuietHandler

server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(ROOT)))
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
checks = []
try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={'width': 1024, 'height': 1000}, device_scale_factor=1)
        base = f'http://127.0.0.1:{server.server_port}'
        page.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') and route.request.method == 'GET' else route.abort())
        page.goto(base + '/index.html#tenants')
        page.get_by_label('Tenant state').select_option('Revoked')
        expect(page.locator('tbody tr')).to_have_count(1)
        expect(page.locator('tbody')).to_contain_text('Sample Delta')
        page.get_by_label('Search tenants').fill('missing sample')
        expect(page.get_by_role('heading', name='No matching tenants')).to_be_visible()
        checks.append('State filter and no-match search remain distinct from source failure')
        for route in ['tenant/alder', 'support/alder', 'operations', 'intelligence', 'service']:
            page.goto(base + '/index.html#' + route)
            page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
            page.screenshot(path=str(EVIDENCE / (route.replace('/', '-') + '-lower-1024.png')))
        page.goto(base + '/index.html#support/alder')
        page.get_by_role('button', name='Preview support request').click()
        expect(page.get_by_label('Support reference')).to_be_focused()
        page.get_by_role('button', name='Close preview').click()
        expect(page.get_by_role('dialog')).not_to_be_visible()
        page.get_by_role('button', name='Preview support request').click()
        page.keyboard.press('Shift+Tab')
        expect(page.get_by_role('button', name='Close preview')).to_be_focused()
        page.keyboard.press('Tab')
        expect(page.get_by_label('Support reference')).to_be_focused()
        for _ in range(10):
            page.keyboard.press('Tab')
            assert page.locator(':focus').evaluate("el => !!el.closest('dialog')")
        page.get_by_label('Support reference').fill('SAMPLE-42')
        page.get_by_label('Reason for access').fill('Synthetic support example')
        page.screenshot(path=str(EVIDENCE / 'support-dialog-1024.png'))
        page.get_by_role('button', name='Close preview').click()
        expect(page.get_by_role('dialog')).not_to_be_visible()
        expect(page.get_by_role('button', name='Preview support request')).to_be_focused()
        checks.append('Native dialog wraps keyboard focus and returns focus on close')
        browser.close()
    (EVIDENCE / 'supplemental.json').write_text(json.dumps({'checks': checks, 'synthetic_only': True}, indent=2) + '\n')
    print('\n'.join(checks))
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
