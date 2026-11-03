"""Production console browser checks with synthetic APIs and no application import.

Run: python tests/browser/pat2373_shell_navigation_repair.py
Uses the installed Playwright/Chromium and Jinja. No credentials, DB or providers.
All browser requests are intercepted; only console HTML and repository static
assets are served. Unspecified APIs fail explicitly rather than returning zero.
Existing section/tab IDs are retained. This is presentation evidence, not RBAC
or support-session verification. No screenshots/runtime claim is made on RED.
"""
import json
import mimetypes
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import expect, sync_playwright

expect.set_options(timeout=2000)

ROOT = Path(__file__).resolve().parents[2]
ORIGIN = "http://127.0.0.1:2373"
BUILD = "synthetic-pat2373"
TENANTS = [
    {"id": "sample-alder", "name": "Sample Alder & Co", "device_count": 0, "removal_capability": False},
    {"id": "sample-birch", "name": "Sample Birch", "device_count": 0, "removal_capability": False},
]


class ShellNavigationRepair(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()
        cls.template = Environment(
            loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape()
        ).get_template("console.html")
        print("Installed Chromium:", cls.browser.version)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.role = "owner"
        self.api_state = "ready"
        self.pending = []
        self.errors = []
        self.external = []
        self.requests = []
        self.context = self.browser.new_context(
            viewport={"width": 1440, "height": 1000}, color_scheme="light"
        )
        self.context.route("**/*", self.respond)
        self.page = self.context.new_page()
        self.page.set_default_timeout(2000)
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))

    def tearDown(self):
        self.context.close()
        self.assertEqual(self.external, [], "External requests must never leave this harness")
        self.assertEqual(self.errors, [], "Production console raised a browser error")

    def respond(self, route):
        request = route.request
        url = urlsplit(request.url)
        if f"{url.scheme}://{url.netloc}" != ORIGIN:
            self.external.append(request.url)
            route.abort()
            return
        path = url.path
        if path.startswith("/console"):
            html = self.template.render(
                console_build_id=BUILD, role=self.role, env="local",
                actor_email="operator@example.invalid", api_backend="synthetic-only",
                device_freshness={"active_max_days": 7, "silent_min_days": 30},
                impersonation=None, imp_expired=False,
            )
            route.fulfill(status=200, content_type="text/html", body=html)
            return
        if path.startswith("/static/") and request.method == "GET":
            asset = (ROOT / path.lstrip("/")).resolve()
            if not asset.is_relative_to((ROOT / "static").resolve()) or not asset.is_file():
                route.fulfill(status=404, body="Unknown local asset")
                return
            route.fulfill(status=200, content_type=mimetypes.guess_type(asset)[0] or "application/octet-stream", body=asset.read_bytes())
            return
        self.requests.append((request.method, path))
        status, data = 503, {"error": "Synthetic source unavailable"}
        if path == "/admin/tenants/overview":
            if self.api_state == "loading":
                self.pending.append(route)
                return
            if self.api_state != "error":
                status, data = 200, {"tenants": [] if self.api_state == "empty" else TENANTS}
        elif path == "/admin/homebrew/review":
            status, data = 200, {"reviews": []}
        elif path == "/admin/health/proxy":
            status, data = 200, {"service_health": {}}
        elif path == "/admin/automations":
            status, data = 200, {"jobs": []}
        elif path == "/admin/tenants/revoked":
            status, data = 200, {"tenants": []}
        elif path == "/api/ops/data":
            status, data = 200, {"hosts": []}
        elif re.fullmatch(r"/api/tenant/sample-(alder|birch)/signal", path) and request.method == "POST":
            # Existing incidental signal is fulfilled locally, never sent anywhere.
            status, data = 200, {"ok": True}
        route.fulfill(status=status, content_type="application/json", body=json.dumps(data))

    def visit(self, hash_value="home"):
        self.page.goto(f"{ORIGIN}/console/{BUILD}#{hash_value}")
        expect(self.page.locator(".console-section.active")).to_be_visible()

    def active(self):
        return self.page.locator(".console-section.active")

    def test_global_titles_match_visible_destination_labels(self):
        for route, label in [("ops", "Operations"), ("automations", "Scheduled jobs"), ("truth", "Check coverage")]:
            with self.subTest(route=route):
                self.visit(route)
                expect(self.active().get_by_role("heading", name=label, exact=True)).to_be_visible()
                expect(self.page).to_have_title(label + " · Patched.im Console")

    def test_user_tenant_tabs_push_and_back_forward_restore_without_duplicates(self):
        self.visit("tenant/sample-alder/account")
        expect(self.page.locator("#tw-switcher")).to_have_value("sample-alder")
        initial = self.page.evaluate("history.length")
        self.page.locator('#cwf-nav [data-workload="devices"]').click()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/device-health$"))
        self.page.locator('#subtabbar-devices [data-tab="device-lifecycle"]').click()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/device-lifecycle$"))
        self.page.go_back()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/device-health$"))
        expect(self.page.locator("#tab-device-health")).to_be_visible()
        self.page.go_back()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/account$"))
        expect(self.page.locator("#tab-account")).to_be_visible()
        self.page.go_forward()
        expect(self.page.locator("#tab-device-health")).to_be_visible()
        self.page.go_forward()
        expect(self.page.locator("#tab-device-lifecycle")).to_be_visible()
        self.page.locator('#subtabbar-devices [data-tab="device-lifecycle"]').click()
        self.assertEqual(self.page.evaluate("history.length"), initial + 2)

    def test_initial_reload_and_retired_alias_restore_replace_history(self):
        for alias, canonical in [("needs-attention", "device-health"), ("app-control", "overview"), ("protected-software", "software-catalogue")]:
            with self.subTest(alias=alias):
                self.visit("home")
                self.page.evaluate("consoleNav('ops')")
                initial = self.page.evaluate("history.length")
                self.page.evaluate("alias => { history.pushState(null, '', '#tenant/sample-alder/' + alias); _restoreShellRoute(); }", alias)
                expect(self.page).to_have_url(re.compile("#tenant/sample-alder/" + canonical + "$"))
                expect(self.page.locator("#tab-" + canonical)).to_be_visible()
                self.assertEqual(self.page.evaluate("history.length"), initial + 1)
                self.page.reload()
                expect(self.page.locator("#tab-" + canonical)).to_be_visible()
                self.assertEqual(self.page.evaluate("history.length"), initial + 1)
                self.page.go_back()
                expect(self.active()).to_have_attribute("id", "section-ops")
                self.page.go_forward()
                expect(self.page.locator("#tab-" + canonical)).to_be_visible()
                self.assertEqual(self.page.evaluate("history.length"), initial + 1)
                self.assertFalse(any(path.endswith('/' + alias) for _, path in self.requests))

    def test_direct_stale_tab_handler_replaces_alias_history(self):
        self.visit("tenant/sample-alder/account")
        expect(self.page.locator("#tab-account")).to_be_visible()
        initial = self.page.evaluate("history.length")
        self.page.evaluate("""() => {
            history.pushState(null, '', '#tenant/sample-alder/needs-attention');
            tenantTab('needs-attention');
        }""")
        expect(self.page.locator("#tab-device-health")).to_be_visible()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/device-health$"))
        self.assertEqual(self.page.evaluate("history.length"), initial + 1)
        self.page.go_back()
        expect(self.page.locator("#tab-account")).to_be_visible()

    def test_return_from_drill_in_creates_only_one_tab_history_entry(self):
        self.visit("tenant/sample-alder/account")
        expect(self.page.locator("#tab-account")).to_be_visible()
        self.page.evaluate("consoleNav('findings')")
        initial = self.page.evaluate("history.length")
        self.page.locator('#cwf-nav [data-workload="devices"]').click()
        expect(self.page.locator("#tab-device-health")).to_be_visible()
        self.assertEqual(self.page.evaluate("history.length"), initial + 1)
        self.page.go_back()
        expect(self.active()).to_have_attribute("id", "section-home")

    def test_new_user_tab_invalidates_delayed_history_restore(self):
        self.visit("tenant/sample-alder/account")
        expect(self.page.locator("#tab-account")).to_be_visible()
        self.page.evaluate("""() => {
            window.originalEnsure = _ensureTenants;
            _ensureTenants = () => new Promise(resolve => { window.releaseRestore = resolve; });
            history.pushState(null, '', '#tenant/sample-birch/account');
            _restoreShellRoute();
        }""")
        self.page.locator('#cwf-nav [data-workload="devices"]').click()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/device-health$"))
        self.page.evaluate("""async () => {
            _ensureTenants = window.originalEnsure;
            window.releaseRestore();
            await Promise.resolve(); await Promise.resolve();
        }""")
        expect(self.page.locator("#tw-switcher")).to_have_value("sample-alder")
        expect(self.page.locator("#tab-device-health")).to_be_visible()
        expect(self.page).to_have_url(re.compile(r"#tenant/sample-alder/device-health$"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
