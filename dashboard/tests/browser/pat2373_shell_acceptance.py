"""Production console browser checks with synthetic APIs and no application import.

Run: ../dashboard/venv/bin/python tests/browser/pat2373_shell_acceptance.py
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


class ShellAcceptance(unittest.TestCase):
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

    def test_approved_global_names_are_actual_visible_navigation(self):
        self.visit()
        nav = self.page.get_by_role("navigation", name="Global navigation")
        self.assertEqual([text.strip() for text in nav.locator("a:visible").all_text_contents()],
                         ["Service overview", "Tenants", "Operations", "Intelligence"])

    def test_server_environment_and_staff_role_are_always_visible(self):
        for role in ["owner", "consultant"]:
            self.role = role
            self.visit()
            for width in [1440, 1024]:
                self.page.set_viewport_size({"width": width, "height": 1000})
                header = self.page.locator("header.topbar")
                with self.subTest(role=role, width=width, context="staff role"):
                    expect(header.get_by_text(role.title(), exact=True)).to_be_visible()
                with self.subTest(role=role, width=width, context="environment"):
                    expect(header.get_by_text(re.compile(r"local", re.I))).to_be_visible()
            if role == "consultant":
                self.assertEqual(self.page.locator("#nav-logs:visible").count(), 0)

    def test_global_deep_links_restore_existing_sections(self):
        for section in ["customers-list", "ops", "homebrew-review", "automations", "truth", "reports", "docs", "credentials"]:
            with self.subTest(section=section):
                self.visit(section)
                expect(self.active()).to_have_attribute("id", "section-" + section)
                self.page.reload()
                expect(self.active()).to_have_attribute("id", "section-" + section)

    def test_global_navigation_creates_back_forward_history(self):
        self.visit()
        self.page.locator("#grail-customers").click()
        self.page.locator("#grail-operations").click()
        self.page.go_back()
        expect(self.active()).to_have_attribute("id", "section-customers-list")
        self.page.go_forward()
        expect(self.active()).to_have_attribute("id", "section-ops")

    def test_global_destination_clears_selected_tenant_context(self):
        self.visit("tenant/sample-alder/customer-access")
        expect(self.page.locator("#tw-switcher")).to_have_value("sample-alder")
        self.page.locator("#grail-operations").click()
        expect(self.page.locator("#tw-switcher")).to_have_value("")
        expect(self.page.locator("#tw-switcher option:checked")).to_have_text("All tenants")
        self.assertIsNone(self.page.evaluate("_consoleState.tenantId"))

    def test_keyboard_skip_route_focus_and_visible_focus_ring(self):
        self.visit()
        self.page.keyboard.press("Tab")
        skip = self.page.get_by_role("link", name=re.compile(r"Skip to (content|main)", re.I))
        expect(skip).to_be_focused()
        self.page.keyboard.press("Enter")
        expect(self.page.locator("main")).to_be_focused()
        self.page.locator("#grail-operations").focus()
        self.assertTrue(self.page.locator(":focus").evaluate(
            "el => getComputedStyle(el).outlineStyle !== 'none' && parseFloat(getComputedStyle(el).outlineWidth) >= 2"
        ))
        self.page.keyboard.press("Enter")
        expect(self.active()).to_have_attribute("id", "section-ops")
        self.assertTrue(self.active().evaluate("el => el.contains(document.activeElement)"))

    def test_actions_remain_inside_viewport_at_both_acceptance_widths(self):
        for width in [1440, 1024]:
            self.page.set_viewport_size({"width": width, "height": 1000})
            # Existing support/access entry only; no PAT-1967 session invented.
            for route in ["home", "customers-list", "tenant/sample-alder/account", "tenant/sample-alder/customer-access", "ops", "homebrew-review"]:
                with self.subTest(width=width, route=route):
                    self.visit(route)
                    if route.startswith("tenant/"):
                        expect(self.active()).to_have_attribute("id", "section-tenant-workspace")
                    else:
                        # Use real clicks too so layout checks run even before reload repair.
                        self.page.evaluate("section => consoleNav(section)", route)
                    self.assertTrue(self.page.evaluate("document.documentElement.scrollWidth <= innerWidth"))
                    for control in self.page.locator("header a, header button, header select, #global-rail a, .console-section.active a, .console-section.active button, .console-section.active input, .console-section.active select").all():
                        if control.is_visible():
                            box = control.bounding_box()
                            self.assertGreaterEqual(box["x"], -1, control.inner_text())
                            self.assertLessEqual(box["x"] + box["width"], width + 1, control.inner_text())

    def test_shared_loading_error_and_empty_are_distinct(self):
        self.api_state = "loading"
        self.visit("customers-list")
        expect(self.page.locator("#cl-loading")).to_be_visible()
        with self.subTest(state="loading"):
            expect(self.active()).to_have_attribute("aria-busy", "true")
        for route in self.pending:
            route.fulfill(status=503, content_type="application/json", body='{"error":"Synthetic source unavailable"}')
        self.pending.clear()
        expect(self.page.locator("#cl-error")).to_be_visible()
        with self.subTest(state="error"):
            expect(self.active()).to_have_attribute("aria-busy", "false")
        self.api_state = "empty"
        self.visit("customers-list")
        expect(self.page.locator("#cl-loading")).not_to_be_visible()
        expect(self.page.locator("#cl-error")).not_to_be_visible()
        expect(self.page.locator("#cl-content")).to_contain_text(re.compile(r"no (customers|tenants)", re.I))
        expect(self.active()).not_to_contain_text(re.compile(r"all systems healthy|service exceptions", re.I))

    def test_retired_and_capability_denied_routes_stay_closed(self):
        self.visit()
        self.page.evaluate("consoleNav('catalogue')")
        expect(self.active()).to_have_attribute("id", "section-home")
        for tab in ["app-control", "enforcement-audit", "runbook", "protected-software", "removal-campaigns"]:
            self.visit("tenant/sample-alder/" + tab)
            expect(self.page.locator("#tab-" + tab)).not_to_be_visible()
            # Retired backend compatibility reads are not retired UI activation.
            if tab in ["protected-software", "removal-campaigns"]:
                denied = [path for method, path in self.requests if path.startswith("/admin/tenants/sample-alder/" + tab)]
                self.assertEqual(denied, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
