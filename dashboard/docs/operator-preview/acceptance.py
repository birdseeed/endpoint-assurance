"""Local browser acceptance; serves only this directory, never imports the app."""
import functools
import hashlib
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def run():
    assert (ROOT / "index.html").exists(), "Requested operator preview does not exist"
    EVIDENCE.mkdir(exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(ROOT)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    checks, screenshots, network, errors = [], [], [], []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(viewport={"width": 1440, "height": 1000}, color_scheme="light", device_scale_factor=1)
            base = f"http://127.0.0.1:{server.server_port}"

            def guard(route):
                if not route.request.url.startswith(base + "/") or route.request.method != "GET":
                    network.append(route.request.url)
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", guard)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))

            def visit(route):
                page.goto(base + "/index.html#" + route)
                expect(page.locator("h1")).to_be_visible()

            visit("service")
            expect(page.get_by_text("Synthetic fixtures only", exact=False).first).to_be_visible()
            expect(page.get_by_label("Environment")).to_have_text("Local preview")
            expect(page.get_by_label("Staff role")).to_have_value("owner")
            page.keyboard.press("Tab")
            expect(page.get_by_role("link", name="Skip to content")).to_be_focused()
            page.keyboard.press("Enter")
            expect(page.locator("main")).to_be_focused()
            checks.append("Keyboard skip link reaches main")
            nav = page.get_by_role("navigation", name="Primary")
            nav.get_by_role("link", name="Tenants", exact=True).focus()
            page.keyboard.press("Enter")
            expect(page.locator("h1")).to_have_text("Tenants")
            page.get_by_label("Search tenants").fill("Sample Alder")
            expect(page.locator("tbody tr")).to_have_count(1)
            page.get_by_role("link", name="Sample Alder", exact=True).click()
            expect(page.locator("h1")).to_have_text("Sample Alder")
            page.get_by_label("Tenant context").select_option("birch")
            expect(page.locator("h1")).to_have_text("Sample Birch")
            expect(page.locator("main")).not_to_contain_text("Sample Alder")
            page.get_by_role("link", name="Support entry", exact=True).click()
            expect(page.locator("h1")).to_have_text("Support for Sample Birch")
            page.reload()
            expect(page.locator("h1")).to_have_text("Support for Sample Birch")
            checks.append("Search, tenant switch, support link and reload retain correct tenant")
            page.get_by_role("button", name="Preview support request").click()
            expect(page.get_by_role("dialog")).to_be_visible()
            expect(page.get_by_label("Support reference")).to_be_focused()
            page.get_by_label("Support reference").fill("SAMPLE-42")
            page.get_by_label("Reason for access").fill("Synthetic support example")
            page.get_by_label("Customer role to reproduce").select_option("viewer")
            expect(page.get_by_role("button", name="Start session (unavailable)")).to_be_disabled()
            page.keyboard.press("Escape")
            expect(page.get_by_role("dialog")).not_to_be_visible()
            expect(page.get_by_role("button", name="Preview support request")).to_be_focused()
            checks.append("Support dialog initial focus, Escape, return focus; unavailable session cannot start")
            visit("tenant/alder")
            page.get_by_label("Staff role").select_option("consultant")
            expect(page.get_by_role("button", name="Revoke access (preview only)")).to_have_count(0)
            expect(page.locator("main")).to_contain_text("Owner role required")
            page.get_by_label("Staff role").select_option("owner")
            expect(page.get_by_role("button", name="Revoke access (preview only)")).to_be_disabled()
            visit("intelligence")
            expect(page.locator("main")).not_to_contain_text("Sample Alder")
            expect(page.locator("main")).to_contain_text("Not yet available")
            checks.append("Consultant cannot see owner lifecycle actions; intelligence contains no tenant observations")
            for retired in ["billing", "catalogue", "patch-deploy", "app-control", "enforcement-audit", "runbook", "protected-software", "removal-campaigns"]:
                visit(retired)
                expect(page.locator("h1")).to_have_text("Preview route unavailable")
            checks.append("Retired and unsupported hashes never revive a screen")
            visit("service")
            for state, text in [("empty", "No exceptions in the available sources"), ("loading", "Loading sample evidence"), ("error", "Sample source failed"), ("degraded", "Last known sample evidence")]:
                page.get_by_label("Fixture state").select_option(state)
                expect(page.locator("main")).to_contain_text(text)
                expect(page.locator("main")).not_to_contain_text("All systems healthy")
                if state == "loading":
                    expect(page.locator("#content")).to_have_attribute("aria-busy", "true")
                if state == "error":
                    page.get_by_role("button", name="Retry sample").click()
                    expect(page.get_by_label("Fixture state")).to_have_value("ready")
            checks.append("Empty/loading/error/retry/degraded remain distinct from unavailable")
            for width in [1440, 1024]:
                page.set_viewport_size({"width": width, "height": 1000})
                for route in ["service", "tenants", "tenant/alder", "support/alder", "operations", "intelligence"]:
                    visit(route)
                    page.get_by_label("Fixture state").select_option("ready")
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Page overflow at {width}: {route}"
                    for control in page.locator("main a, main button, main input, main select").all():
                        if control.is_visible():
                            box = control.bounding_box()
                            assert box["x"] >= 0 and box["x"] + box["width"] <= width + 1, f"Clipped control: {route}"
                    name = f"{route.replace('/', '-')}-{width}.png"
                    page.screenshot(path=str(EVIDENCE / name))
                    screenshots.append(name)
                visit("service")
                for state in ["empty", "loading", "error", "degraded"]:
                    page.get_by_label("Fixture state").select_option(state)
                    name = f"service-{state}-{width}.png"
                    page.screenshot(path=str(EVIDENCE / name))
                    screenshots.append(name)
                nav.get_by_role("link", name="Tenants", exact=True).focus()
                page.keyboard.press("Tab")
                focused = page.locator(":focus")
                assert focused.evaluate("el => getComputedStyle(el).outlineStyle !== 'none' && parseFloat(getComputedStyle(el).outlineWidth) >= 2")
                name = f"keyboard-focus-{width}.png"
                page.screenshot(path=str(EVIDENCE / name))
                screenshots.append(name)
            assert not network, f"Forbidden requests: {network}"
            assert not errors, f"Browser errors: {errors}"
            checks.append("1440/1024 layouts, keyboard focus outline, zero external requests and zero JS errors")
            result = {"checks": checks, "screenshots": screenshots, "browser": browser.version, "viewport_heights": 1000, "synthetic_only": True, "acceptance_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
            (EVIDENCE / "acceptance.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    run()
