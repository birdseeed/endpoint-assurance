"""Synthetic public certificate forms in a real browser, local transport only."""

import json
import os
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from e2e.conftest import HARNESS_VALID_TOKEN, harness_process
from tests.conftest import StubPlatformHandler
from tests.test_pat2389_certificates import AGENT, API, CERT_ID, UPLOADED
from tests.test_pat2389_certificates import public_certificates as public_certificates


@pytest.fixture
def certificate_portal():
    state = {"role": "admin", "writes": []}

    class CertificatePlatform(StubPlatformHandler):
        def do_GET(self):
            if self.path == API:
                return self._send(200, [UPLOADED, AGENT])
            if self.path == "/v1/portal/me":
                return self._send(200, {"role": state["role"]})
            return super().do_GET()

        def _write(self):
            assert self.path in (API, f"{API}/{CERT_ID}")
            assert self.headers["Cf-Access-Jwt-Assertion"] == HARNESS_VALID_TOKEN
            length = int(self.headers.get("content-length", 0))
            raw = self.rfile.read(length)
            state["writes"].append((self.command, json.loads(raw) if raw else None))
            return self._send(200, UPLOADED)

        do_POST = _write
        do_PATCH = _write
        do_DELETE = _write

    server = ThreadingHTTPServer(("127.0.0.1", 0), CertificatePlatform)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with harness_process(f"http://127.0.0.1:{server.server_address[1]}") as url:
            yield url, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _context(browser, url, width=1280, theme="light"):
    context = browser.new_context(viewport={"width": width, "height": 900})
    context.route("**/*", lambda route: route.continue_() if (
        urlsplit(route.request.url).netloc == urlsplit(url).netloc) else route.abort())
    context.add_cookies([{"name": "CF_Authorization", "value": HARNESS_VALID_TOKEN, "url": url}])
    context.add_init_script(f"localStorage.setItem('patched-portal-theme', '{theme}')")
    return context


@pytest.mark.parametrize("width", [1440, 1280, 390])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_certificate_layout_and_native_forms(browser, certificate_portal, width, theme):
    url, _ = certificate_portal
    context = _context(browser, url, width, theme)
    try:
        page = context.new_page()
        response = page.goto(url + "/certificates")
        assert response.status == 200
        assert page.locator("html").get_attribute("data-theme") == theme
        page.locator(".certificate-upload > summary").click()
        page.locator(".certificate-evidence > summary").first.click()
        page.locator(".certificate-edit > summary").click()
        assert page.locator(".certificate-table tbody tr").count() == 2
        assert page.get_by_role("link", name="View device", exact=True).count() == 1
        assert page.locator("form[action$='/update']").count() == 1
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        for control in page.locator(".certificate-form input:visible").all():
            box = control.bounding_box()
            assert box["x"] >= 0 and box["x"] + box["width"] <= width + 1
        output = os.environ.get("PAT2389_SCREENSHOTS")
        if output:
            page.evaluate("window.scrollTo(0, 0)")
            page.screenshot(path=str(Path(output) / f"certificates-{width}-{theme}.png"),
                            full_page=True)
    finally:
        context.close()


def test_browser_upload_label_only_replace_remove_and_viewer(
    browser, certificate_portal, public_certificates
):
    url, state = certificate_portal
    context = _context(browser, url)
    try:
        page = context.new_page()
        page.goto(url + "/certificates")
        page.locator(".certificate-upload > summary").click()
        upload = page.locator("form[action='/certificates/upload']")
        upload.get_by_label("Label", exact=True).fill("Browser certificate")
        upload.get_by_label("Public certificate file").set_input_files({
            "name": "public.pem", "mimeType": "application/x-pem-file",
            "buffer": public_certificates["pem"],
        })
        upload.get_by_role("button", name="Upload certificate", exact=True).click()
        page.wait_for_url(url + "/certificates")
        assert state["writes"][-1][0] == "POST"
        page.locator(".certificate-edit > summary").click()
        edit = page.locator("form[action$='/update']")
        edit.get_by_label("Label", exact=True).fill("Renamed in browser")
        edit.get_by_role("button", name="Save certificate").click()
        page.wait_for_url(url + "/certificates")
        assert state["writes"][-1] == ("PATCH", {"label": "Renamed in browser"})
        page.locator(".certificate-edit > summary").click()
        edit.get_by_label("Replacement public certificate (optional)").set_input_files({
            "name": "public.der", "mimeType": "application/octet-stream",
            "buffer": public_certificates["der"],
        })
        edit.get_by_role("button", name="Save certificate").click()
        page.wait_for_url(url + "/certificates")
        assert "certificate" in state["writes"][-1][1]
        page.locator(".certificate-edit > summary").click()
        page.locator(".certificate-remove > summary").click()
        page.get_by_role("button", name="Remove certificate", exact=True).click()
        page.wait_for_url(url + "/certificates")
        assert state["writes"][-1] == ("DELETE", None)
        assert len(state["writes"]) == 4
        state["role"] = "viewer"
        page.reload()
        assert page.locator("form[action^='/certificates']").count() == 0
        assert page.locator(".certificate-table tbody tr").count() == 2
    finally:
        context.close()
